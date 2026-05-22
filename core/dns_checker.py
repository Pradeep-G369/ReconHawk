# ReconHawk - DNS Security Checker
# Checks for missing SPF, DMARC, DKIM records
# Missing these = domain is vulnerable to email spoofing

import dns.resolver
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ─────────────────────────────────────────
# CHECK SPF RECORD
# SPF tells mail servers which IPs can send
# email on behalf of this domain
# ─────────────────────────────────────────
def check_spf(domain):
    print(f"\n[*] Checking SPF → {domain}")
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        for record in answers:
            txt = record.to_text().strip('"')
            if "v=spf1" in txt:
                print(f"    [+] SPF found: {txt[:80]}")
                return {"found": True, "record": txt, "severity": "NONE"}
        print(f"    [-] No SPF record found")
        return {"found": False, "record": None, "severity": "HIGH"}
    except Exception as e:
        print(f"    [-] SPF check failed: {e}")
        return {"found": False, "record": None, "severity": "HIGH"}


# ─────────────────────────────────────────
# CHECK DMARC RECORD
# DMARC tells receivers what to do with
# emails that fail SPF/DKIM checks
# ─────────────────────────────────────────
def check_dmarc(domain):
    print(f"[*] Checking DMARC → {domain}")
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, "TXT")
        for record in answers:
            txt = record.to_text().strip('"')
            if "v=DMARC1" in txt:
                print(f"    [+] DMARC found: {txt[:80]}")
                return {"found": True, "record": txt, "severity": "NONE"}
        print(f"    [-] No DMARC record found")
        return {"found": False, "record": None, "severity": "HIGH"}
    except Exception as e:
        print(f"    [-] DMARC check failed: {e}")
        return {"found": False, "record": None, "severity": "HIGH"}


# ─────────────────────────────────────────
# CHECK DKIM RECORD
# DKIM adds a digital signature to emails
# Common selectors tried automatically
# ─────────────────────────────────────────
def check_dkim(domain):
    print(f"[*] Checking DKIM → {domain}")
    common_selectors = [
        "default", "google", "mail", "email",
        "k1", "s1", "s2", "dkim", "selector1", "selector2"
    ]
    for selector in common_selectors:
        try:
            dkim_domain = f"{selector}._domainkey.{domain}"
            answers = dns.resolver.resolve(dkim_domain, "TXT")
            for record in answers:
                txt = record.to_text().strip('"')
                if "v=DKIM1" in txt:
                    print(f"    [+] DKIM found (selector={selector}): {txt[:60]}")
                    return {"found": True, "selector": selector,
                            "record": txt, "severity": "NONE"}
        except Exception:
            continue

    print(f"    [-] No DKIM record found")
    return {"found": False, "record": None, "severity": "MEDIUM"}


# ─────────────────────────────────────────
# CHECK ZONE TRANSFER
# A misconfigured DNS server allows anyone
# to download its entire zone file — critical
# ─────────────────────────────────────────
def check_zone_transfer(domain):
    print(f"[*] Checking zone transfer → {domain}")
    try:
        ns_records = dns.resolver.resolve(domain, "NS")
        for ns in ns_records:
            ns_host = str(ns.target)
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_host, domain, timeout=3))
                if zone:
                    print(f"    [!!!] ZONE TRANSFER ALLOWED on {ns_host} — CRITICAL")
                    return {"vulnerable": True, "nameserver": ns_host,
                            "severity": "CRITICAL"}
            except Exception:
                continue
        print(f"    [+] Zone transfer not allowed — secure")
        return {"vulnerable": False, "severity": "NONE"}
    except Exception as e:
        print(f"    [-] Zone transfer check failed: {e}")
        return {"vulnerable": False, "severity": "NONE"}


# ─────────────────────────────────────────
# MAIN FUNCTION
# ─────────────────────────────────────────
def run(domain):
    print("\n" + "="*50)
    print("  DNS SECURITY CHECKER")
    print("="*50)

    results = {
        "domain"        : domain,
        "spf"           : check_spf(domain),
        "dmarc"         : check_dmarc(domain),
        "dkim"          : check_dkim(domain),
        "zone_transfer" : check_zone_transfer(domain),
    }

    # Summary
    print("\n--- DNS Security Summary ---")
    checks = ["spf", "dmarc", "dkim"]
    for check in checks:
        status = "✓ Found" if results[check]["found"] else "✗ Missing"
        severity = results[check]["severity"]
        print(f"  {check.upper():<10} {status:<15} Severity: {severity}")

    zt = results["zone_transfer"]
    zt_status = "VULNERABLE" if zt["vulnerable"] else "Secure"
    print(f"  {'ZONE XFR':<10} {zt_status:<15} Severity: {zt['severity']}")

    return results


if __name__ == "__main__":
    test_domain = "vulnweb.com"
    results = run(test_domain)
