"""
SOC Lab — Phishing Email Analyzer
Parses .eml files, extracts IOCs (sender, originating IP, URLs)
and enriches them via the VirusTotal v3 API.

Author: Aurelio Avila
"""

import os
import re
import sys
import time
import base64
from datetime import datetime
from email import message_from_file

import requests
from dotenv import load_dotenv

# --- Configuration ------------------------------------------------------------

load_dotenv()
VT_API_KEY = os.environ.get("VT_API_KEY")

if not VT_API_KEY:
    sys.exit(
        "[FATAL] VT_API_KEY is missing. "
        "Copy .env.example to .env and set your VirusTotal API key."
    )

VT_BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": VT_API_KEY}
REQUEST_TIMEOUT = 15        # seconds — fail fast on network issues
URL_SCAN_DELAY = 15         # seconds — VT free tier = 4 req/min

# --- Email parsing ------------------------------------------------------------

def parse_email(filepath):
    """Open an .eml file and return relevant headers + the message object."""
    with open(filepath, "r", encoding="utf-8") as f:
        msg = message_from_file(f)

    headers = {
        "from": msg.get("From", "N/A"),
        "to": msg.get("To", "N/A"),
        "subject": msg.get("Subject", "N/A"),
        "date": msg.get("Date", "N/A"),
        "message_id": msg.get("Message-ID", "N/A"),
        "originating_ip": msg.get("X-Originating-IP", "N/A").strip("[]"),
        "received": msg.get("Received", "N/A"),
    }
    return headers, msg


def extract_urls(msg):
    """Extract URLs from both text/html and text/plain parts.
    Catches URLs in href attributes and in plain-text body.
    """
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/html", "text/plain"):
                payload = part.get_payload(decode=True)
                if payload:
                    body += payload.decode("utf-8", errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode("utf-8", errors="ignore")

    # URLs inside HTML href attributes
    href_urls = re.findall(r'href=["\']?(https?://[^\s"\'<>]+)', body)
    # URLs in plain text (covers text/plain body and stray links)
    plain_urls = re.findall(r'https?://[^\s"\'<>\)]+', body)

    # Deduplicate while preserving order
    seen = set()
    result = []
    for url in href_urls + plain_urls:
        url = url.rstrip(".,;:")  # strip trailing punctuation
        if url not in seen:
            seen.add(url)
            result.append(url)
    return result


# --- VirusTotal lookups -------------------------------------------------------

def vt_request(endpoint):
    """Generic VT v3 GET with error handling."""
    try:
        resp = requests.get(
            f"{VT_BASE_URL}/{endpoint}",
            headers=HEADERS,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.exceptions.RequestException as exc:
        return None, f"network error: {exc}"

    if resp.status_code == 200:
        return resp.json(), None
    if resp.status_code == 404:
        return None, "not found on VirusTotal"
    if resp.status_code == 429:
        return None, "rate limit exceeded (HTTP 429)"
    return None, f"HTTP {resp.status_code}"


def format_stats(data):
    """Format VT last_analysis_stats into a 'X/Y engines flagged' string."""
    if not data:
        return "N/A"
    try:
        stats = data["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(stats.values())
        return f"{malicious}/{total} engines flagged"
    except (KeyError, TypeError):
        return "N/A"


def check_ip(ip):
    if ip == "N/A" or not ip:
        return "no IP available", 0
    data, err = vt_request(f"ip_addresses/{ip}")
    if err:
        return err, 0
    malicious = _malicious_count(data)
    return format_stats(data), malicious


def check_url(url):
    # VT v3 requires URL identifiers to be base64-url encoded (no padding)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    data, err = vt_request(f"urls/{url_id}")
    if err:
        return err, 0
    malicious = _malicious_count(data)
    return format_stats(data), malicious


def _malicious_count(data):
    if not data:
        return 0
    try:
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return stats.get("malicious", 0) + stats.get("suspicious", 0)
    except (KeyError, TypeError):
        return 0


# --- Heuristic detection ------------------------------------------------------

def detect_suspicious(headers, urls):
    """Apply simple heuristic rules to flag suspicious indicators."""
    flags = []
    sender = headers["from"].lower()
    subject = headers["subject"].lower()

    # Typosquatting in sender (zero instead of letter O on a known brand)
    brands = ["microsoft", "google", "paypal", "amazon", "apple", "netflix"]
    for brand in brands:
        spoofed = brand.replace("o", "0")
        if spoofed in sender and brand not in sender:
            flags.append(f"Sender domain typosquatting suspected ({spoofed})")
            break

    # Suspicious URL patterns
    suspicious_tlds = (".xyz", ".top", ".click", ".tk", ".gq", ".cf")
    for url in urls:
        low = url.lower()
        if any(tld in low for tld in suspicious_tlds):
            flags.append(f"Suspicious TLD detected in URL: {url}")
            break

    for url in urls:
        if any(b.replace("o", "0") in url.lower() for b in brands):
            flags.append("URL contains typosquatted brand name")
            break

    # Urgency tactics in subject
    urgency_keywords = ["urgent", "immediate", "verify", "suspended",
                        "compromised", "action required", "account locked"]
    if any(k in subject for k in urgency_keywords):
        flags.append("Subject line uses urgency / fear tactics")

    return flags


# --- Report -------------------------------------------------------------------

def print_report(headers, urls, flags, ip_result, url_results, total_malicious):
    line = "=" * 72
    sep = "-" * 72
    print(line)
    print(" SOC PHISHING EMAIL ANALYSIS REPORT")
    print(" " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print(line)
    print(f" From            : {headers['from']}")
    print(f" To              : {headers['to']}")
    print(f" Subject         : {headers['subject']}")
    print(f" Date            : {headers['date']}")
    print(f" Originating IP  : {headers['originating_ip']}")
    print(sep)
    print(f" IP Reputation   : {ip_result}")
    print(sep)
    print(f" URLs found      : {len(urls)}")
    for i, url in enumerate(urls, start=1):
        print(f"  [{i}] {url}")
        print(f"      VT verdict: {url_results[i-1]}")
    print(sep)
    print(" Heuristic indicators:")
    if flags:
        for f in flags:
            print(f"  [!] {f}")
    else:
        print("  none")
    print(line)
    if total_malicious > 0 or flags:
        print(" VERDICT: PHISHING — escalate to Tier 2")
    else:
        print(" VERDICT: CLEAN")
    print(line)


# --- Main ---------------------------------------------------------------------

def main(eml_path):
    print(f"[*] Analyzing {eml_path} ...")
    headers, msg = parse_email(eml_path)
    urls = extract_urls(msg)
    flags = detect_suspicious(headers, urls)

    ip_result, ip_mal = check_ip(headers["originating_ip"])

    url_results = []
    total_url_mal = 0
    for i, url in enumerate(urls):
        result, mal = check_url(url)
        url_results.append(result)
        total_url_mal += mal
        # Respect VT free-tier rate limit between calls
        if i < len(urls) - 1:
            time.sleep(URL_SCAN_DELAY)

    total_malicious = ip_mal + total_url_mal
    print_report(headers, urls, flags, ip_result, url_results, total_malicious)


if __name__ == "__main__":
    eml_file = sys.argv[1] if len(sys.argv) > 1 else "sample_phishing.eml"
    main(eml_file)