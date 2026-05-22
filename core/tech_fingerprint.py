# ReconHawk - Technology Fingerprinter
# Detects what tech stack a target runs
# WordPress, Drupal, Apache, Nginx, PHP versions etc.
# Each detected technology maps directly to CVE lookups

import requests
import urllib3
import re
import sys
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ─────────────────────────────────────────
# TECHNOLOGY SIGNATURES
# ─────────────────────────────────────────
TECH_SIGNATURES = {

    # Web Servers
    "Apache": {
        "headers" : {"server": r"apache"},
        "severity": "INFO",
        "category": "Web Server",
    },
    "Nginx": {
        "headers" : {"server": r"nginx"},
        "severity": "INFO",
        "category": "Web Server",
    },
    "IIS": {
        "headers" : {"server": r"microsoft-iis"},
        "severity": "INFO",
        "category": "Web Server",
    },
    "LiteSpeed": {
        "headers" : {"server": r"litespeed"},
        "severity": "INFO",
        "category": "Web Server",
    },

    # Programming Languages
    "PHP": {
        "headers" : {"x-powered-by": r"php/([\d.]+)"},
        "severity": "INFO",
        "category": "Language",
    },
    "ASP.NET": {
        "headers" : {"x-powered-by": r"asp\.net",
                     "x-aspnet-version": r".*"},
        "severity": "INFO",
        "category": "Language",
    },

    # CMS
    "WordPress": {
        "headers" : {},
        "body"    : [r"wp-content", r"wp-includes", r"/wp-json/"],
        "severity": "MEDIUM",
        "category": "CMS",
        "note"    : "WordPress sites have many known CVEs",
    },
    "Drupal": {
        "headers" : {"x-generator": r"drupal"},
        "body"    : [r"drupal", r"sites/default/files"],
        "severity": "MEDIUM",
        "category": "CMS",
    },
    "Joomla": {
        "headers" : {},
        "body"    : [r"joomla", r"/components/com_"],
        "severity": "MEDIUM",
        "category": "CMS",
    },

    # JavaScript Frameworks
    "jQuery": {
        "headers" : {},
        "body"    : [r"jquery[.-]([\d.]+)(\.min)?\.js"],
        "severity": "LOW",
        "category": "JS Framework",
    },
    "React": {
        "headers" : {},
        "body"    : [r"react(\.min)?\.js", r"__reactFiber"],
        "severity": "INFO",
        "category": "JS Framework",
    },
    "Angular": {
        "headers" : {},
        "body"    : [r"angular(\.min)?\.js", r"ng-version"],
        "severity": "INFO",
        "category": "JS Framework",
    },

    # Databases (exposed via errors or headers)
    "MySQL": {
        "headers" : {},
        "body"    : [r"mysql_fetch", r"MySQL server version"],
        "severity": "HIGH",
        "category": "Database",
        "note"    : "Database errors exposed in page — serious misconfiguration",
    },
    "PostgreSQL": {
        "headers" : {},
        "body"    : [r"PostgreSQL.*ERROR", r"pg_query"],
        "severity": "HIGH",
        "category": "Database",
    },

    # Cloud / CDN
    "Cloudflare": {
        "headers" : {"server": r"cloudflare", "cf-ray": r".*"},
        "severity": "INFO",
        "category": "CDN",
    },
    "AWS": {
        "headers" : {"x-amz-request-id": r".*",
                     "x-amz-cf-id"     : r".*"},
        "severity": "INFO",
        "category": "Cloud",
    },
}

# ─────────────────────────────────────────
# FINGERPRINT A SINGLE HOST
# ─────────────────────────────────────────
def fingerprint_host(host):
    print(f"\n[*] Tech fingerprinting → {host}")
    detected = []

    # Get the page
    response = None
    base_url = None

    for scheme in ["https", "http"]:
        try:
            url = f"{scheme}://{host}"
            response = requests.get(
                url,
                timeout=config.REQUEST_TIMEOUT,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "ReconHawk-Scanner/1.0"}
            )
            base_url = url
            break
        except Exception:
            continue

    if not response:
        print(f"    [-] Could not connect to {host}")
        return detected

    headers_lower = {k.lower(): v for k, v in response.headers.items()}
    body          = response.text.lower()

    # Check each technology signature
    for tech_name, sig in TECH_SIGNATURES.items():
        found   = False
        version = ""
        matches = []

        # Check headers
        for header_key, pattern in sig.get("headers", {}).items():
            header_val = headers_lower.get(header_key, "")
            if header_val:
                match = re.search(pattern, header_val, re.IGNORECASE)
                if match:
                    found = True
                    # Extract version if captured group exists
                    if match.lastindex:
                        version = match.group(1)
                    matches.append(f"Header:{header_key}={header_val[:50]}")

        # Check body patterns
        for pattern in sig.get("body", []):
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                found = True
                if match.lastindex:
                    version = match.group(1)
                matches.append(f"Body pattern:{pattern[:30]}")

        if found:
            result = {
                "technology": tech_name,
                "version"   : version,
                "category"  : sig.get("category", "Unknown"),
                "severity"  : sig.get("severity", "INFO"),
                "matches"   : matches,
                "note"      : sig.get("note", ""),
                "host"      : host,
            }
            detected.append(result)

            version_str = f" {version}" if version else ""
            note_str    = f" — {sig['note']}" if sig.get("note") else ""
            print(f"    [+] {tech_name}{version_str} "
                  f"[{sig['category']}]{note_str}")

    # Extra — extract exact server version from header
    server_header = headers_lower.get("server", "")
    if server_header:
        print(f"    [i] Server header: {server_header}")

    powered_by = headers_lower.get("x-powered-by", "")
    if powered_by:
        print(f"    [i] X-Powered-By: {powered_by}")

    if not detected:
        print(f"    [-] No technologies detected")

    return detected


# ─────────────────────────────────────────
# RUN ON ALL HOSTS
# ─────────────────────────────────────────
def run(hosts):
    print("\n" + "="*50)
    print("  TECHNOLOGY FINGERPRINTER")
    print("="*50)

    all_results = {}

    for host in hosts:
        detected = fingerprint_host(host)
        if detected:
            all_results[host] = detected

    print(f"\n--- Technology Summary ---")
    for host, techs in all_results.items():
        tech_names = [
            f"{t['technology']}"
            f"{' '+t['version'] if t['version'] else ''}"
            for t in techs
        ]
        print(f"  {host}:")
        print(f"    {', '.join(tech_names)}")

    return all_results


if __name__ == "__main__":
    test_hosts = ["scanme.nmap.org", "wordpress.com"]
    results = run(test_hosts)
