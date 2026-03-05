# LCKDWN Security Scanner

A **modern, AI-enhanced security scanner** for IT professionals and security teams.  
Analyze **domains, IPs, email addresses, and full email headers** to detect potential phishing attacks and other security risks.

---

## Features

- **Email Header Analysis** with AI-generated insights:
  - Detects SPF, DKIM, and DMARC misalignments.
  - Extracts true sending IPs.
  - Calculates **Risk Score** (0–5+) with explanation.
- **Domain Analysis**:
  - DNS records (A, MX, TXT).
  - WHOIS lookup.
  - Geolocation of domain servers.
- **IP Analysis**:
  - Reverse DNS (PTR).
  - ASN and ISP info.
  - Geolocation.
- **Email Address Analysis**:
  - Domain SPF check.
  - Technical email security info.
- **Modern Web Interface**:
  - Responsive, dark-mode inspired theme.
  - Risk scores and AI reasoning clearly displayed.
- **Privacy & Compliance**:
  - No sensitive data is stored.
  - Optional offline WHOIS & IP geolocation.
  - Suitable for CMMC, NIST, ITAR compliance review.

---

## Risk Score Interpretation

| Score | Meaning |
|-------|---------|
| 0     | Safe / Very low risk |
| 1–2   | Mild risk, suspicious elements |
| 3–4   | Medium risk, likely suspicious email |
| 5+    | High risk, probable phishing |

---

## Installation

1. **Clone the repository**:

```bash
git clone https://github.com/yourusername/lckdwn-security-scanner.git
cd lckdwn-security-scanner

