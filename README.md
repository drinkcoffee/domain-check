# domain-check

A command-line tool that investigates a domain name and produces a trustworthiness report.

## Installation

Create and activate a virtual environment, then install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python3 domain_check.py <domain>
```

Activate the virtual environment first if it isn't already active:

```bash
source .venv/bin/activate
```

You can pass a bare domain, a `www.` prefixed domain, or a full URL — the scheme and path are stripped automatically.

```bash
python domain_check.py example.com
python domain_check.py www.example.com
python domain_check.py https://example.com/some/path
```

To deactivate the virtual environment when done:

```bash
deactivate
```

### JSON output

Add `--json` to get machine-readable output instead of the formatted report:

```bash
python domain_check.py --json example.com
python domain_check.py --json example.com | jq '.trust_score'
```

### WHOIS fallback

Registration data is fetched via **RDAP** (HTTPS, port 443) by default. If RDAP is unavailable for a TLD, the script will return an error rather than silently fall back to the legacy port-43 WHOIS protocol, which sends data over unencrypted TCP.

To allow the fallback, pass `--allow-whois`:

```bash
python domain_check.py --allow-whois example.com
```

When the fallback is used, the report shows which source was used and why RDAP failed:

```
Source       : (via whois, RDAP failed: No RDAP server found for .tld)
```

> **Note:** `python-whois` (in `requirements.txt`) is only required if you intend to use `--allow-whois`.

## What it checks

| Section | Details |
|---|---|
| **WHOIS / Registration** | Creation date, expiry date, registrar, registrant country, name servers, domain age |
| **DNS Records** | A, AAAA, MX, NS, CAA, and TXT records; SPF and DMARC presence |
| **SSL / TLS** | Certificate validity, issuer, expiry date, Subject Alternative Names |
| **HTTP / HTTPS** | Status codes, redirect chain, security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options) |
| **IP / Hosting** | Resolved IP, reverse DNS, ISP, organisation, geographic location, hosting/datacenter flag |

## Trust score

Each check contributes to a **0–100 trust score** shown at the bottom of the report:

| Signal | Max points |
|---|---|
| Domain age | 20 |
| Registration expiry horizon | 10 |
| Registrar known | 5 |
| Valid SSL certificate | 15 |
| HTTP redirects to HTTPS | 5 |
| Security headers (HSTS, CSP, etc.) | 10 |
| Email security (MX + SPF + DMARC) | 10 |
| Registrant country visible | 5 |

A score of **75+** is generally trustworthy. **50–74** warrants caution. **Below 50** is a red flag.

## Example output

```
Checking github.com …

════════════════════════════════════════════════════════════
  Domain Trust Report: github.com
════════════════════════════════════════════════════════════

WHOIS / Registration
  Registrar    : MarkMonitor, Inc.
  Created      : 2007-10-09  (18y ago)
  Expires      : 2026-10-09
  Country      : US

DNS Records
  A records    : 140.82.114.4
  MX records   : 0 github-com.mail.protection.outlook.com
  SPF          : ✘
  DMARC        : ✔

SSL / TLS
  ✔  Certificate valid
  Issued by    : Sectigo Limited
  Expires      : 2026-06-03  (71 days)

HTTP / HTTPS
  HTTPS  : 200  https://github.com/
  HTTP   : 200  https://github.com/  ↳ redirected from http://

IP / Hosting
  IP address   : 140.82.114.4
  ISP          : GitHub, Inc.
  Location     : San Francisco, California, United States

────────────────────────────────────────────────────────────
  Trust score  : 91 / 100
────────────────────────────────────────────────────────────
  ✔  Domain is 18 years old (very established)
  ✔  Registration expires in 199 days
  ✔  Valid SSL certificate (issued by Sectigo Limited)
  ✔  HTTP redirects to HTTPS
  ✔  All key security headers present
  ⚠  Partial email security (MX present, missing SPF or DMARC)
════════════════════════════════════════════════════════════
```

## Requirements

- Python 3.8+
- [python-whois](https://pypi.org/project/python-whois/)
- [dnspython](https://pypi.org/project/dnspython/)
- [requests](https://pypi.org/project/requests/)
