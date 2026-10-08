# Incident Report — Phishing Email Triage

**Analyst:** Aurelio Avila
**Date:** 2026-05-04
**Severity:** High
**Status:** Confirmed phishing — escalated to Tier 2

---

## Summary

A user reported a suspicious email claiming to be from Microsoft Security,
urging immediate action to verify account credentials via an external link.
Static analysis of the `.eml` file and threat-intel enrichment via VirusTotal
confirmed the email as a credential-harvesting phishing attempt.

## Indicators of Compromise (IOCs)

| Type            | Value                                                       |
|-----------------|-------------------------------------------------------------|
| Sender          | security-alert@micros0ft-support.com                        |
| Originating IP  | 185.220.101.45                                              |
| Malicious URL   | http://login-micros0ft.xyz/verify?token=abc123              |
| Subject         | URGENT: Your account has been compromised — verify immediately |

## Suspicious Indicators

- **Typosquatting in sender domain**: `micros0ft` (zero) vs `microsoft` (letter O)
- **Suspicious TLD in URL**: `.xyz` is a low-cost TLD frequently abused for phishing
- **Typosquatting in URL**: `login-micros0ft.xyz` mimics Microsoft login portal
- **Urgency / fear tactics in subject**: "URGENT", "compromised", "verify immediately"
- **Short deadline pressure**: "24 hours" threat of permanent closure

## VirusTotal Enrichment

- **IP 185.220.101.45**: flagged by multiple engines (known Tor exit node, abused
  by threat actors for command-and-control and phishing infrastructure)
- **URL login-micros0ft.xyz**: flagged as phishing by several engines

## MITRE ATT&CK Mapping

- **T1566.002** — Phishing: Spearphishing Link
- **T1078** — Valid Accounts (intended outcome if credentials are harvested)

## Analyst Reasoning

The combination of brand impersonation, typosquatted infrastructure, fear-based
language, and external URL pointing to a non-Microsoft domain matches the
behavioural pattern of a credential-harvesting phishing campaign. The originating
IP belongs to a known abuse network, which removes residual ambiguity.

## Recommendations

1. **Block sender domain** `micros0ft-support.com` at the email gateway
2. **Block URL** `login-micros0ft.xyz` at the web proxy / DNS filter
3. **Add IP** `185.220.101.45` to the perimeter blocklist
4. **Notify the reporting user**: confirm phishing, no further action required
5. **Hunt for similar emails** in the past 30 days using sender domain and URL pattern
6. **User awareness reminder**: typosquatting patterns and urgency tactics

## Lessons Learned

- VirusTotal enrichment significantly accelerates triage when IOCs are well known
- Heuristic detection (typosquatting, suspicious TLDs, urgency language) catches
  many phishing attempts even before threat-intel lookup
- Plain-text body extraction is essential: many phishing emails embed the
  malicious URL in `text/plain` only