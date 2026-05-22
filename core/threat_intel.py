# ReconHawk - Threat Intelligence Module
# Pulls data from free tier APIs:
# Shodan  — internet-wide scan data for IP/host
# HIBP    — checks if emails from domain were breached
# Censys  — asset discovery and certificate data

import requests
import urllib3
import sys
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ─────────────────────────────────────────
# SHODAN — FREE TIER
# No key needed for basic DNS lookup
# API key needed for full host data
# ─────────────────────────────────────────
def shodan_lookup(domain):
    print(f"\n[*] Shodan lookup → {domain}")
    results = {
        "source" : "Shodan",
        "domain" : domain,
        "data"   : {},
        "findings": [],
    }

    try:
        # Free endpoint — DNS resolve only
        url = f"https://api.shodan.io/dns/resolve?hostnames={domain}"

        if config.SHODAN_API_KEY != "YOUR_SHODAN_API_KEY":
            url += f"&key={config.SHODAN_API_KEY}"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                ip   = data.get(domain, "")
                if ip:
                    results["data"]["ip"] = ip
                    print(f"    [+] Resolved IP: {ip}")

                    # Full host lookup with API key
                    host_url = (f"https://api.shodan.io/shodan/host/{ip}"
                                f"?key={config.SHODAN_API_KEY}")
                    host_resp = requests.get(host_url, timeout=10)

                    if host_resp.status_code == 200:
                        host_data = host_resp.json()
                        ports     = host_data.get("ports", [])
                        org       = host_data.get("org", "Unknown")
                        country   = host_data.get("country_name", "Unknown")
                        vulns     = host_data.get("vulns", {})

                        results["data"]["ports"]   = ports
                        results["data"]["org"]     = org
                        results["data"]["country"] = country
                        results["data"]["vulns"]   = list(vulns.keys())

                        print(f"    [+] Organisation : {org}")
                        print(f"    [+] Country      : {country}")
                        print(f"    [+] Open ports   : {ports}")

                        if vulns:
                            print(f"    [!] Shodan CVEs  : {list(vulns.keys())}")
                            results["findings"].append({
                                "severity": "HIGH",
                                "detail"  : f"Shodan reports known vulns: "
                                            f"{list(vulns.keys())}",
                            })
        else:
            # No API key — use free DNS lookup via hackertarget
            print(f"    [i] No Shodan API key — using free DNS lookup")
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            response = requests.get(url, timeout=10)

            if response.status_code == 200 and "error" not in response.text.lower():
                lines = response.text.strip().split("\n")
                hosts = []
                for line in lines[:10]:  # limit output
                    if "," in line:
                        hostname, ip = line.split(",", 1)
                        hosts.append({"hostname": hostname, "ip": ip})
                        print(f"    [+] {hostname} → {ip}")
                results["data"]["hosts"] = hosts
            else:
                print(f"    [-] Free lookup returned no results")

    except Exception as e:
        print(f"    [-] Shodan lookup failed: {e}")

    return results


# ─────────────────────────────────────────
# HIBP — Have I Been Pwned
# Free API — checks if a domain appears
# in known data breaches
# ─────────────────────────────────────────
def hibp_lookup(domain):
    print(f"\n[*] HIBP breach check → {domain}")
    results = {
        "source"  : "HIBP",
        "domain"  : domain,
        "breaches": [],
        "findings": [],
    }

    try:
        # Check breaches for domain (free endpoint)
        url = f"https://haveibeenpwned.com/api/v3/breaches"
        headers = {
            "User-Agent": "ReconHawk-Scanner/1.0",
        }

        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            all_breaches = response.json()

            # Filter breaches that include this domain
            domain_breaches = [
                b for b in all_breaches
                if domain.lower() in b.get("Domain", "").lower()
                or domain.lower() in b.get("Name", "").lower()
            ]

            if domain_breaches:
                for breach in domain_breaches:
                    info = {
                        "name"        : breach.get("Name", ""),
                        "breach_date" : breach.get("BreachDate", ""),
                        "pwn_count"   : breach.get("PwnCount", 0),
                        "data_classes": breach.get("DataClasses", []),
                    }
                    results["breaches"].append(info)
                    print(f"    [!] Breach found: {info['name']} "
                          f"({info['breach_date']}) — "
                          f"{info['pwn_count']:,} accounts")
                    print(f"        Data exposed: "
                          f"{', '.join(info['data_classes'][:5])}")

                results["findings"].append({
                    "severity": "HIGH",
                    "detail"  : f"{len(domain_breaches)} breach(es) found "
                                f"for {domain}",
                })
            else:
                print(f"    [+] No breaches found for {domain}")

        elif response.status_code == 429:
            print(f"    [-] HIBP rate limited — try again in 60 seconds")
        else:
            print(f"    [-] HIBP returned: {response.status_code}")

    except Exception as e:
        print(f"    [-] HIBP lookup failed: {e}")

    return results


# ─────────────────────────────────────────
# CENSYS — FREE TIER
# 250 queries/month
# Certificate and host discovery
# ─────────────────────────────────────────
def censys_lookup(domain):
    print(f"\n[*] Censys lookup → {domain}")
    results = {
        "source"  : "Censys",
        "domain"  : domain,
        "data"    : {},
        "findings": [],
    }

    try:
        if (config.CENSYS_API_ID != "YOUR_CENSYS_API_ID"
                and config.CENSYS_API_SECRET != "YOUR_CENSYS_SECRET"):

            # Search certificates for domain
            url = "https://search.censys.io/api/v2/certificates/search"
            auth = (config.CENSYS_API_ID, config.CENSYS_API_SECRET)
            params = {
                "q"        : f"parsed.names: {domain}",
                "per_page" : 5,
            }
            response = requests.get(
                url, auth=auth, params=params, timeout=10
            )

            if response.status_code == 200:
                data  = response.json()
                hits  = data.get("result", {}).get("hits", [])
                certs = []

                for hit in hits:
                    parsed = hit.get("parsed", {})
                    names  = parsed.get("names", [])
                    expiry = parsed.get("validity", {}).get("end", "")
                    issuer = parsed.get("issuer", {}).get("organization", [""])[0]
                    certs.append({
                        "names" : names,
                        "expiry": expiry,
                        "issuer": issuer,
                    })
                    print(f"    [+] Cert: {names[:3]} expires {expiry}")

                results["data"]["certificates"] = certs
            else:
                print(f"    [-] Censys returned: {response.status_code}")

        else:
            print(f"    [i] No Censys API key — skipping")
            print(f"    [i] Sign up free at censys.io to enable this")

    except Exception as e:
        print(f"    [-] Censys lookup failed: {e}")

    return results


# ─────────────────────────────────────────
# RUN ALL THREAT INTEL ON A DOMAIN
# ─────────────────────────────────────────
def run(domain):
    print("\n" + "="*50)
    print("  THREAT INTELLIGENCE")
    print("="*50)

    results = {
        "domain" : domain,
        "shodan" : shodan_lookup(domain),
        "hibp"   : hibp_lookup(domain),
        "censys" : censys_lookup(domain),
    }

    # Summary
    print(f"\n--- Threat Intel Summary for {domain} ---")

    shodan_hosts = len(results["shodan"]["data"].get("hosts", []))
    if shodan_hosts:
        print(f"  Shodan   : {shodan_hosts} hosts discovered")
    else:
        print(f"  Shodan   : No additional hosts found")

    breaches = len(results["hibp"]["breaches"])
    if breaches:
        print(f"  HIBP     : {breaches} breach(es) found — HIGH")
    else:
        print(f"  HIBP     : No breaches found")

    print(f"  Censys   : {'Enabled' if config.CENSYS_API_ID != 'YOUR_CENSYS_API_ID' else 'No API key'}")

    return results


if __name__ == "__main__":
    results = run("adobe.com")
