# ReconHawk - HTTP Security Header Analyzer
# Checks for missing or misconfigured security headers
# Missing headers = easy wins for attackers

import requests
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ─────────────────────────────────────────
# HEADERS WE CHECK + WHY THEY MATTER
# ─────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity"   : "HIGH",
        "description": "Missing HSTS — site can be downgraded to HTTP",
        "recommend"  : "max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "severity"   : "HIGH",
        "description": "Missing CSP — site vulnerable to XSS attacks",
        "recommend"  : "default-src 'self'",
    },
    "X-Frame-Options": {
        "severity"   : "MEDIUM",
        "description": "Missing X-Frame-Options — clickjacking possible",
        "recommend"  : "DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "severity"   : "MEDIUM",
        "description": "Missing X-Content-Type-Options — MIME sniffing possible",
        "recommend"  : "nosniff",
    },
    "Referrer-Policy": {
        "severity"   : "LOW",
        "description": "Missing Referrer-Policy — URL leakage possible",
        "recommend"  : "strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity"   : "LOW",
        "description": "Missing Permissions-Policy — browser features uncontrolled",
        "recommend"  : "geolocation=(), microphone=(), camera=()",
    },
    "X-XSS-Protection": {
        "severity"   : "LOW",
        "description": "Missing X-XSS-Protection — older browsers unprotected",
        "recommend"  : "1; mode=block",
    },
}

# ─────────────────────────────────────────
# ANALYZE HEADERS FOR A SINGLE URL
# ─────────────────────────────────────────
def analyze_url(url):
    results = {
        "url"     : url,
        "missing" : [],
        "present" : [],
        "score"   : 0,
        "grade"   : "",
        "headers" : {},
    }

    try:
        response = requests.get(
            url,
            timeout=config.REQUEST_TIMEOUT,
            verify=False,   # some test sites have bad certs
            allow_redirects=True,
            headers={"User-Agent": "ReconHawk-Scanner/1.0"}
        )

        results["status_code"] = response.status_code
        results["headers"]     = dict(response.headers)

        print(f"\n[*] Analyzing headers → {url} "
              f"(Status: {response.status_code})")

        # Check each security header
        for header, info in SECURITY_HEADERS.items():
            if header.lower() in [h.lower() for h in response.headers]:
                value = response.headers.get(header, "")
                results["present"].append({
                    "header"  : header,
                    "value"   : value,
                    "severity": "NONE",
                })
                print(f"    [✓] {header}: {value[:60]}")
            else:
                results["missing"].append({
                    "header"     : header,
                    "severity"   : info["severity"],
                    "description": info["description"],
                    "recommend"  : info["recommend"],
                })
                print(f"    [✗] MISSING {header} "
                      f"— {info['severity']} — {info['description']}")

        # Calculate grade
        total   = len(SECURITY_HEADERS)
        present = len(results["present"])
        score   = round((present / total) * 100)
        results["score"] = score

        if score >= 90:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 50:
            grade = "C"
        elif score >= 30:
            grade = "D"
        else:
            grade = "F"

        results["grade"] = grade
        print(f"\n    [→] Header Security Grade: {grade} ({score}%)")

    except requests.exceptions.SSLError:
        print(f"    [-] SSL error on {url} — trying HTTP")
    except requests.exceptions.ConnectionError:
        print(f"    [-] Could not connect to {url}")
    except Exception as e:
        print(f"    [-] Error analyzing {url}: {e}")

    return results


# ─────────────────────────────────────────
# RUN ON ALL DISCOVERED HOSTS
# ─────────────────────────────────────────
def run(hosts):
    print("\n" + "="*50)
    print("  HTTP HEADER SECURITY ANALYZER")
    print("="*50)

    # Suppress SSL warnings for test targets
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    all_results = {}

    for host in hosts:
        # Try HTTPS first, fall back to HTTP
        for scheme in ["https", "http"]:
            url = f"{scheme}://{host}"
            result = analyze_url(url)
            if result.get("status_code"):
                all_results[host] = result
                break

    # Summary
    print(f"\n--- Header Analysis Summary ---")
    for host, result in all_results.items():
        print(f"  {host:<35} Grade: {result.get('grade','?')} "
              f"({result.get('score',0)}%) — "
              f"{len(result['missing'])} missing headers")

    return all_results


if __name__ == "__main__":
    test_hosts = ["scanme.nmap.org", "vulnweb.com"]
    results = run(test_hosts)


# ─────────────────────────────────────────
# COOKIE SECURITY CHECKER
# Checks for missing Secure, HttpOnly,
# SameSite flags on cookies
# ─────────────────────────────────────────
def check_cookies(host):
    print(f"\n[*] Cookie security check → {host}")
    findings = []

    for scheme in ["https", "http"]:
        url = f"{scheme}://{host}"
        try:
            response = requests.get(
                url,
                timeout=config.REQUEST_TIMEOUT,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "ReconHawk-Scanner/1.0"}
            )

            cookies = response.headers.get("Set-Cookie", "")
            if not cookies:
                print(f"    [i] No cookies set by {host}")
                return findings

            # Check each flag
            flags = {
                "Secure"  : ("Secure"   in cookies, "HIGH",   "Cookie transmitted over HTTP — can be stolen"),
                "HttpOnly": ("HttpOnly" in cookies, "HIGH",   "Cookie accessible via JavaScript — XSS risk"),
                "SameSite": ("SameSite" in cookies, "MEDIUM", "Cookie sent on cross-site requests — CSRF risk"),
            }

            for flag, (present, severity, desc) in flags.items():
                if present:
                    print(f"    [✓] {flag} flag set")
                else:
                    findings.append({
                        "flag"    : flag,
                        "severity": severity,
                        "detail"  : desc,
                        "host"    : host,
                    })
                    print(f"    [✗] Missing {flag} — {severity} — {desc}")

            break

        except Exception:
            continue

    return findings
