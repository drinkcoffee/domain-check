#!/usr/bin/env python3
"""
domain_check.py — Assess the trustworthiness of a domain name.

Usage:
    python3 domain_check.py <domain>
    python3 domain_check.py --json <domain>    # JSON output
"""

import argparse
import json
import socket
import ssl
import sys
from datetime import datetime, timezone
from typing import Optional

# ── colour helpers ────────────────────────────────────────────────────────────

RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
RED    = "\033[31m"
CYAN   = "\033[36m"
DIM    = "\033[2m"

def ok(msg):    return f"{GREEN}✔{RESET}  {msg}"
def warn(msg):  return f"{YELLOW}⚠{RESET}  {msg}"
def bad(msg):   return f"{RED}✘{RESET}  {msg}"
def info(msg):  return f"{CYAN}ℹ{RESET}  {msg}"
def header(msg):return f"\n{BOLD}{CYAN}{msg}{RESET}"


# ── WHOIS / RDAP ──────────────────────────────────────────────────────────────

def _parse_rdap_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%fZ"):
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _rdap_base_url(tld: str) -> str:
    """Look up the RDAP server for a TLD using the IANA bootstrap registry."""
    import requests as req
    bootstrap = req.get("https://data.iana.org/rdap/dns.json", timeout=10).json()
    for tlds, servers in bootstrap.get("services", []):
        if tld.lower() in [t.lower() for t in tlds]:
            return servers[0].rstrip("/")
    raise ValueError(f"No RDAP server found for .{tld}")


def _check_whois_rdap(domain: str) -> dict:
    """Fetch registration data via RDAP (HTTPS/JSON, port 443)."""
    import requests as req

    tld = domain.rsplit(".", 1)[-1]
    base = _rdap_base_url(tld)
    url = f"{base}/domain/{domain}"
    headers = {"Accept": "application/rdap+json, application/json"}
    r = req.get(url, headers=headers, timeout=15, allow_redirects=True)
    r.raise_for_status()
    data = r.json()

    # Events → creation / expiration / last changed
    creation = expiration = updated = None
    for event in data.get("events", []):
        action = event.get("eventAction", "")
        dt = _parse_rdap_datetime(event.get("eventDate"))
        if action == "registration":
            creation = dt
        elif action == "expiration":
            expiration = dt
        elif action in ("last changed", "last update of RDAP database"):
            updated = dt

    # Registrar — entity with role "registrar"
    registrar = None
    country = None
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        vcard = entity.get("vcardArray", [None, []])[1]
        if "registrar" in roles and not registrar:
            for field in vcard:
                if field[0] == "fn":
                    registrar = field[3]
        if "registrant" in roles and not country:
            for field in vcard:
                if field[0] == "adr":
                    # vCard adr value: [pobox, ext, street, city, region, postal, country]
                    adr = field[3]
                    if isinstance(adr, list) and len(adr) >= 7:
                        country = adr[6] or None

    # Name servers
    name_servers = sorted({
        ns["ldhName"].lower().rstrip(".")
        for ns in data.get("nameservers", [])
        if ns.get("ldhName")
    }) or None

    status = data.get("status", [])

    now = datetime.now(timezone.utc)
    age_days = (now - creation).days if creation else None
    days_until_expiry = (expiration - now).days if expiration else None

    return {
        "registrar": registrar,
        "creation_date": creation.isoformat() if creation else None,
        "expiration_date": expiration.isoformat() if expiration else None,
        "updated_date": updated.isoformat() if updated else None,
        "country": country,
        "name_servers": name_servers,
        "age_days": age_days,
        "days_until_expiry": days_until_expiry,
        "status": status,
        "source": "rdap",
    }


def _check_whois_fallback(domain: str) -> dict:
    """Fallback to port-43 WHOIS via python-whois when RDAP is unavailable."""
    import whois

    def first(val):
        if isinstance(val, list):
            return val[0]
        return val

    w = whois.whois(domain)
    creation   = first(w.creation_date)
    expiration = first(w.expiration_date)
    updated    = first(w.updated_date)

    if creation and isinstance(creation, datetime) and creation.tzinfo is None:
        creation = creation.replace(tzinfo=timezone.utc)
    if expiration and isinstance(expiration, datetime) and expiration.tzinfo is None:
        expiration = expiration.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    age_days = (now - creation).days if isinstance(creation, datetime) else None
    days_until_expiry = (expiration - now).days if isinstance(expiration, datetime) else None
    country = w.country or (w.registrant_country if hasattr(w, "registrant_country") else None)

    return {
        "registrar": w.registrar,
        "creation_date": creation.isoformat() if isinstance(creation, datetime) else str(creation),
        "expiration_date": expiration.isoformat() if isinstance(expiration, datetime) else str(expiration),
        "updated_date": updated.isoformat() if isinstance(updated, datetime) else str(updated),
        "country": country,
        "name_servers": sorted({ns.lower().rstrip(".") for ns in (w.name_servers or [])}) or None,
        "age_days": age_days,
        "days_until_expiry": days_until_expiry,
        "status": w.status,
        "source": "whois",
    }


def check_whois(domain: str, allow_whois_fallback: bool = False) -> dict:
    try:
        return _check_whois_rdap(domain)
    except Exception as rdap_err:
        if not allow_whois_fallback:
            return {"error": f"RDAP lookup failed: {rdap_err}. Use --allow-whois to fall back to port-43 WHOIS."}
        try:
            result = _check_whois_fallback(domain)
            result["rdap_error"] = str(rdap_err)
            return result
        except Exception as whois_err:
            return {"error": f"RDAP: {rdap_err} | WHOIS: {whois_err}"}


# ── DNS ───────────────────────────────────────────────────────────────────────

def check_dns(domain: str) -> dict:
    try:
        import dns.resolver
        import dns.exception
    except ImportError:
        return {"error": "dnspython not installed"}

    result: dict = {}

    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CAA"):
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=10)
            if rtype == "MX":
                result[rtype] = sorted(
                    [f"{r.preference} {r.exchange.to_text().rstrip('.')}" for r in answers]
                )
            elif rtype == "TXT":
                result[rtype] = [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
            else:
                result[rtype] = sorted([r.to_text().rstrip(".") for r in answers])
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout,
                dns.resolver.NoNameservers):
            result[rtype] = []
        except Exception as e:
            result[rtype] = [f"error: {e}"]

    # Pull out notable TXT records
    txt_records = result.get("TXT", [])
    result["has_spf"]   = any(t.startswith("v=spf1") for t in txt_records)
    result["has_dmarc"] = False

    # Check _dmarc subdomain
    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=10)
        dmarc_records = [b"".join(r.strings).decode("utf-8", errors="replace") for r in dmarc_answers]
        result["has_dmarc"] = any(t.startswith("v=DMARC1") for t in dmarc_records)
        result["dmarc_record"] = dmarc_records[0] if dmarc_records else None
    except Exception:
        result["dmarc_record"] = None

    return result


# ── SSL ───────────────────────────────────────────────────────────────────────

def check_ssl(domain: str) -> dict:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError as e:
        return {"valid": False, "error": str(e)}
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {"valid": False, "error": f"Cannot connect: {e}"}
    except Exception as e:
        return {"valid": False, "error": str(e)}

    subject   = dict(x[0] for x in cert.get("subject", []))
    issuer    = dict(x[0] for x in cert.get("issuer", []))
    not_after = cert.get("notAfter")
    san_list  = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

    expiry_dt = None
    days_left = None
    if not_after:
        expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expiry_dt - datetime.now(timezone.utc)).days

    return {
        "valid": True,
        "subject_cn": subject.get("commonName"),
        "issuer_o": issuer.get("organizationName"),
        "issuer_cn": issuer.get("commonName"),
        "not_after": expiry_dt.isoformat() if expiry_dt else None,
        "days_until_expiry": days_left,
        "san": san_list,
        "wildcard": any(s.startswith("*") for s in san_list),
    }


# ── HTTP ──────────────────────────────────────────────────────────────────────

def check_http(domain: str) -> dict:
    try:
        import requests as req
    except ImportError:
        return {"error": "requests not installed"}

    result: dict = {}
    headers = {"User-Agent": "Mozilla/5.0 (compatible; domain-check/1.0)"}

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            r = req.get(url, headers=headers, timeout=10, allow_redirects=True)
            hops = [resp.url for resp in r.history] + [r.url]
            result[scheme] = {
                "status_code": r.status_code,
                "final_url": r.url,
                "redirect_chain": hops if len(hops) > 1 else [],
                "server": r.headers.get("Server"),
                "content_type": r.headers.get("Content-Type", "").split(";")[0],
                "security_headers": {
                    "strict_transport_security": "Strict-Transport-Security" in r.headers,
                    "content_security_policy":   "Content-Security-Policy"   in r.headers,
                    "x_frame_options":           "X-Frame-Options"           in r.headers,
                    "x_content_type_options":    "X-Content-Type-Options"    in r.headers,
                },
            }
        except req.exceptions.SSLError as e:
            result[scheme] = {"error": f"SSL error: {e}"}
        except req.exceptions.ConnectionError:
            result[scheme] = {"error": "connection refused / unreachable"}
        except req.exceptions.Timeout:
            result[scheme] = {"error": "timeout"}
        except Exception as e:
            result[scheme] = {"error": str(e)}

    return result


# ── IP / GEO ──────────────────────────────────────────────────────────────────

def check_ip(domain: str) -> dict:
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return {"error": "could not resolve"}

    result = {"ip": ip}

    # Reverse DNS
    try:
        rdns = socket.gethostbyaddr(ip)[0]
        result["reverse_dns"] = rdns
    except Exception:
        result["reverse_dns"] = None

    # Basic geo via ip-api.com (free, no key needed)
    try:
        import requests as req
        r = req.get(f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp,org,as,hosting",
                    timeout=5)
        if r.status_code == 200:
            data = r.json()
            result.update(data)
    except Exception:
        pass

    return result


# ── SCORING ───────────────────────────────────────────────────────────────────

def score(whois_data, dns_data, ssl_data, http_data) -> tuple[int, list[str]]:
    """Return (0-100 score, list of finding strings)."""
    points  = 0
    total   = 0
    signals = []

    def add(pts, max_pts, msg):
        nonlocal points, total
        points += pts
        total  += max_pts
        signals.append((pts, max_pts, msg))

    # Domain age
    age = whois_data.get("age_days")
    if age is not None:
        if age >= 365 * 5:
            add(20, 20, ok(f"Domain is {age // 365} years old (very established)"))
        elif age >= 365 * 2:
            add(15, 20, ok(f"Domain is {age // 365} years old"))
        elif age >= 365:
            add(10, 20, warn(f"Domain is only {age // 365} year(s) old — relatively new"))
        elif age >= 90:
            add(5,  20, warn(f"Domain is only {age} days old — fairly new"))
        else:
            add(0,  20, bad(f"Domain is only {age} days old — very recently registered"))
    else:
        add(0, 20, warn("Could not determine domain age"))

    # Expiry
    expiry = whois_data.get("days_until_expiry")
    if expiry is not None:
        if expiry > 365:
            add(10, 10, ok(f"Registration expires in {expiry} days (paid ahead)"))
        elif expiry > 90:
            add(7, 10, ok(f"Registration expires in {expiry} days"))
        elif expiry > 30:
            add(3, 10, warn(f"Registration expires in {expiry} days — soon"))
        else:
            add(0, 10, bad(f"Registration expires in {expiry} days — very soon!"))
    else:
        add(0, 10, warn("Could not determine expiry date"))

    # Registrar
    if whois_data.get("registrar"):
        add(5, 5, info(f"Registrar: {whois_data['registrar']}"))
    else:
        add(0, 5, warn("Registrar unknown"))

    # SSL
    if ssl_data.get("valid"):
        add(15, 15, ok(f"Valid SSL certificate (issued by {ssl_data.get('issuer_o') or ssl_data.get('issuer_cn')})"))
        ssl_exp = ssl_data.get("days_until_expiry")
        if ssl_exp and ssl_exp < 14:
            signals.append((0, 0, warn(f"SSL certificate expires in {ssl_exp} days!")))
    else:
        add(0, 15, bad(f"SSL issue: {ssl_data.get('error', 'unknown')}"))

    # HTTPS redirect
    https_ok = not http_data.get("https", {}).get("error")
    http_redirects_https = False
    http_info = http_data.get("http", {})
    if not http_info.get("error"):
        final = http_info.get("final_url", "")
        http_redirects_https = final.startswith("https://")

    if https_ok and http_redirects_https:
        add(5, 5, ok("HTTP redirects to HTTPS"))
    elif https_ok:
        add(3, 5, warn("HTTPS available but HTTP doesn't redirect to it"))
    else:
        add(0, 5, bad("HTTPS not available"))

    # Security headers
    sec_hdrs = http_data.get("https", {}).get("security_headers") or \
               http_data.get("http",  {}).get("security_headers") or {}
    hdr_score = sum(1 for v in sec_hdrs.values() if v)
    if hdr_score == 4:
        add(10, 10, ok("All key security headers present (HSTS, CSP, X-Frame-Options, X-Content-Type)"))
    elif hdr_score >= 2:
        add(5, 10, warn(f"{hdr_score}/4 security headers present"))
    else:
        add(0, 10, bad(f"Missing most security headers ({hdr_score}/4 present)"))

    # DNS email security
    has_mx    = bool(dns_data.get("MX"))
    has_spf   = dns_data.get("has_spf", False)
    has_dmarc = dns_data.get("has_dmarc", False)

    if has_mx and has_spf and has_dmarc:
        add(10, 10, ok("Email security configured (MX + SPF + DMARC)"))
    elif has_mx and (has_spf or has_dmarc):
        add(6, 10, warn("Partial email security (MX present, missing SPF or DMARC)"))
    elif has_mx:
        add(3, 10, warn("Has MX records but no SPF or DMARC"))
    else:
        add(5, 10, info("No MX records — domain likely not used for email"))

    # WHOIS country
    if whois_data.get("country"):
        add(5, 5, info(f"Registrant country: {whois_data['country']}"))
    else:
        add(0, 5, warn("Registrant country hidden / not available"))

    pct = round(points / total * 100) if total else 0
    return pct, signals


# ── PRINT ─────────────────────────────────────────────────────────────────────

def colour_score(s: int) -> str:
    if s >= 75: return f"{GREEN}{BOLD}{s}{RESET}"
    if s >= 50: return f"{YELLOW}{BOLD}{s}{RESET}"
    return f"{RED}{BOLD}{s}{RESET}"

def print_report(domain: str, whois_data: dict, dns_data: dict,
                 ssl_data: dict, http_data: dict, ip_data: dict,
                 trust_score: int, signals: list) -> None:

    print(f"\n{'═'*60}")
    print(f"{BOLD}  Domain Trust Report: {CYAN}{domain}{RESET}")
    print(f"{'═'*60}")

    # ── WHOIS ──
    print(header("WHOIS / Registration"))
    if whois_data.get("error"):
        print(f"  {warn('WHOIS lookup failed: ' + whois_data['error'])}")
    else:
        age = whois_data.get("age_days")
        age_str = f"{age // 365}y {age % 365}d" if age else "unknown"
        source = whois_data.get("source", "rdap")
        rdap_err = whois_data.get("rdap_error")
        source_str = f"{DIM} (via {source}" + (f", RDAP failed: {rdap_err[:60]}" if rdap_err else "") + f"){RESET}"
        print(f"  Source       :{source_str}")
        print(f"  Registrar    : {whois_data.get('registrar') or 'n/a'}")
        print(f"  Created      : {whois_data.get('creation_date') or 'n/a'}  ({age_str} ago)")
        print(f"  Expires      : {whois_data.get('expiration_date') or 'n/a'}")
        print(f"  Last updated : {whois_data.get('updated_date') or 'n/a'}")
        print(f"  Country      : {whois_data.get('country') or 'n/a'}")
        ns = whois_data.get("name_servers")
        if ns:
            print(f"  Name servers : {', '.join(ns[:3])}" + (" …" if len(ns) > 3 else ""))

    # ── DNS ──
    print(header("DNS Records"))
    if dns_data.get("error"):
        print(f"  {warn(dns_data['error'])}")
    else:
        a_recs = dns_data.get("A", [])
        print(f"  A records    : {', '.join(a_recs) or 'none'}")
        mx_recs = dns_data.get("MX", [])
        print(f"  MX records   : {', '.join(mx_recs[:3]) or 'none'}" +
              (" …" if len(mx_recs) > 3 else ""))
        ns_recs = dns_data.get("NS", [])
        print(f"  NS records   : {', '.join(ns_recs[:3]) or 'none'}" +
              (" …" if len(ns_recs) > 3 else ""))
        caa = dns_data.get("CAA", [])
        if caa:
            print(f"  CAA records  : {', '.join(caa[:3])}")
        spf_mark  = GREEN + "✔" + RESET if dns_data.get("has_spf")   else RED + "✘" + RESET
        dmarc_mark = GREEN + "✔" + RESET if dns_data.get("has_dmarc") else RED + "✘" + RESET
        print(f"  SPF          : {spf_mark}")
        print(f"  DMARC        : {dmarc_mark}")
        if dns_data.get("dmarc_record"):
            print(f"    {DIM}{dns_data['dmarc_record'][:80]}{RESET}")

    # ── SSL ──
    print(header("SSL / TLS"))
    if not ssl_data.get("valid"):
        print(f"  {bad(ssl_data.get('error', 'SSL not available'))}")
    else:
        print(f"  {ok('Certificate valid')}")
        print(f"  Issued to    : {ssl_data.get('subject_cn') or 'n/a'}")
        print(f"  Issued by    : {ssl_data.get('issuer_o') or ssl_data.get('issuer_cn') or 'n/a'}")
        print(f"  Expires      : {ssl_data.get('not_after') or 'n/a'}  "
              f"({ssl_data.get('days_until_expiry', '?')} days)")
        san = ssl_data.get("san", [])
        if san:
            print(f"  SANs         : {', '.join(san[:4])}" + (" …" if len(san) > 4 else ""))

    # ── HTTP ──
    print(header("HTTP / HTTPS"))
    for scheme in ("https", "http"):
        h = http_data.get(scheme, {})
        if h.get("error"):
            print(f"  {scheme.upper():5s}  : {warn(h['error'])}")
        else:
            chain = " → ".join(h.get("redirect_chain", []))
            chain_str = f"  {DIM}↳ {chain}{RESET}" if chain else ""
            print(f"  {scheme.upper():5s}  : {h.get('status_code')}  {h.get('final_url')}")
            if chain_str:
                print(chain_str)
            sec = h.get("security_headers", {})
            present = [k.replace("_", "-") for k, v in sec.items() if v]
            missing = [k.replace("_", "-") for k, v in sec.items() if not v]
            if present:
                print(f"  {DIM}  headers ✔ : {', '.join(present)}{RESET}")
            if missing:
                print(f"  {DIM}  headers ✘ : {', '.join(missing)}{RESET}")

    # ── IP / GEO ──
    print(header("IP / Hosting"))
    if ip_data.get("error"):
        print(f"  {warn(ip_data['error'])}")
    else:
        print(f"  IP address   : {ip_data.get('ip')}")
        if ip_data.get("reverse_dns"):
            print(f"  Reverse DNS  : {ip_data['reverse_dns']}")
        if ip_data.get("isp"):
            print(f"  ISP          : {ip_data['isp']}")
        if ip_data.get("org"):
            print(f"  Org          : {ip_data['org']}")
        if ip_data.get("country"):
            loc_parts = [ip_data.get("city"), ip_data.get("regionName"), ip_data.get("country")]
            print(f"  Location     : {', '.join(p for p in loc_parts if p)}")
        if ip_data.get("hosting"):
            print(f"  {warn('IP is flagged as hosting/datacenter by ip-api')}")

    # ── TRUST SCORE ──
    print(f"\n{'─'*60}")
    print(f"  Trust score  : {colour_score(trust_score)} / 100")
    print(f"{'─'*60}")
    for pts, max_pts, msg in signals:
        print(f"  {msg}")
    print(f"{'═'*60}\n")


# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    import contextlib

    parser = argparse.ArgumentParser(
        description="Check domain trustworthiness"
    )
    parser.add_argument("domain", help="Domain name to investigate (e.g. example.com)")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of formatted report")
    parser.add_argument("--allow-whois", action="store_true",
                        help="Fall back to port-43 WHOIS if RDAP is unavailable (sends data over unencrypted TCP)")
    args = parser.parse_args()

    domain = args.domain.lower().strip()
    # Strip scheme if provided
    for prefix in ("https://", "http://", "www."):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.split("/")[0]  # remove any path

    steps = [
        ("WHOIS lookup",       lambda: check_whois(domain, allow_whois_fallback=args.allow_whois)),
        ("DNS records",        lambda: check_dns(domain)),
        ("SSL certificate",    lambda: check_ssl(domain)),
        ("HTTP/HTTPS check",   lambda: check_http(domain)),
        ("IP & geolocation",   lambda: check_ip(domain)),
    ]

    results: dict = {}
    if not args.json:
        print(f"\n{DIM}Checking {domain} …{RESET}")

    for label, fn in steps:
        if not args.json:
            print(f"  {DIM}[…] {label}{RESET}", end="\r", flush=True)
        try:
            results[label] = fn()
        except Exception as e:
            results[label] = {"error": str(e)}
        if not args.json:
            print(f"  {GREEN}[✔]{RESET} {label}          ")

    whois_data = results["WHOIS lookup"]
    dns_data   = results["DNS records"]
    ssl_data   = results["SSL certificate"]
    http_data  = results["HTTP/HTTPS check"]
    ip_data    = results["IP & geolocation"]

    trust_score, signals = score(whois_data, dns_data, ssl_data, http_data)

    if args.json:
        out = {
            "domain": domain,
            "trust_score": trust_score,
            "whois": whois_data,
            "dns": dns_data,
            "ssl": ssl_data,
            "http": http_data,
            "ip": ip_data,
        }
        print(json.dumps(out, indent=2, default=str))
    else:
        print_report(domain, whois_data, dns_data, ssl_data, http_data, ip_data, trust_score, signals)


if __name__ == "__main__":
    main()
