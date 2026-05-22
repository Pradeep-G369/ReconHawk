# ReconHawk - WAF Detector
# Detects Web Application Firewalls by analyzing
# HTTP headers, cookies, and response behavior
# Knowing WAF presence helps pentesters adjust approach

import requests
import urllib3
import sys
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ─────────────────────────────────────────
# WAF SIGNATURES
# Each WAF leaves fingerprints in headers/cookies
# ─────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers" : ["cf-ray", "cf-cache-status", "cf-request-id"],
        "cookies" : ["__cfduid", "cf_clearance"],
        "server"  : ["cloudflare"],
    },
    "AWS WAF": {
        "headers" : ["x-amzn-requestid", "x-amz-cf-id", "x-amz-id-2"],
        "cookies" : ["aws-waf-token"],
        "server"  : ["awselb", "amazon"],
    },
    "Akamai": {
        "headers" : ["akamai-origin-hop", "x-akamai-transformed"],
        "cookies" : ["ak_bmsc", "bm_sz"],
        "server"  : ["akamai"],
    },
    "Sucuri": {
        "headers" : ["x-sucuri-id", "x-sucuri-cache"],
        "cookies" : [],
        "server"  : ["sucuri"],
    },
    "Imperva / Incapsula": {
        "headers" : ["x-iinfo", "x-cdn"],
        "cookies" : ["incap_ses", "visid_incap"],
        "server"  : ["incapsula", "imperva"],
    },
    "ModSecurity": {
        "headers" : ["x-modsecurity-action"],
        "cookies" : [],
        "server"  : ["mod_security", "modsecurity"],
    },
    "F5 BIG-IP ASM": {
        "headers" : ["x-cnection", "x-wa-info"],
        "cookies" : ["ts", "f5avr"],
        "server"  : ["big-ip", "f5"],
    },
    "Nginx WAF": {
        "headers" : [],
        "cookies" : [],
        "server"  : ["nginx"],
    },
}

# ─────────────────────────────────────────
# DETECT WAF ON A SINGLE HOST
# ─────────────────────────────────────────
def detect_waf(host):
    print(f"\n[*] WAF detection → {host}")
    result = {
        "host"       : host,
        "waf_detected": False,
        "waf_name"   : None,
        "confidence" : 0,
        "evidence"   : [],
        "severity"   : "INFO",
    }

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

            headers_lower = {
                k.lower(): v.lower()
                for k, v in response.headers.items()
            }
            cookies_lower = [
                c.lower() for c in response.cookies.keys()
            ]
            server = headers_lower.get("server", "")

            # Check each WAF signature
            for waf_name, signatures in WAF_SIGNATURES.items():
                matches   = 0
                evidence  = []

                # Check headers
                for header in signatures["headers"]:
                    if header.lower() in headers_lower:
                        matches += 1
                        evidence.append(f"Header: {header}")

                # Check cookies
                for cookie in signatures["cookies"]:
                    if cookie.lower() in cookies_lower:
                        matches += 1
                        evidence.append(f"Cookie: {cookie}")

                # Check server header
                for srv in signatures["server"]:
                    if srv.lower() in server:
                        matches += 1
                        evidence.append(f"Server: {server}")

                if matches > 0:
                    confidence = min(matches * 33, 99)
                    result["waf_detected"] = True
                    result["waf_name"]     = waf_name
                    result["confidence"]   = confidence
                    result["evidence"]     = evidence
                    print(f"    [!] WAF Detected: {waf_name} "
                          f"(confidence: {confidence}%)")
                    for e in evidence:
                        print(f"        → {e}")
                    break

            if not result["waf_detected"]:
                print(f"    [+] No WAF detected — direct server access likely")

            # Also check for 403/406/429 on malicious payload
            try:
                probe_url = f"{url}/?id=1' OR '1'='1"
                probe = requests.get(
                    probe_url,
                    timeout=config.REQUEST_TIMEOUT,
                    verify=False,
                    headers={"User-Agent": "ReconHawk-Scanner/1.0"}
                )
                if probe.status_code in [403, 406, 429, 501]:
                    print(f"    [!] WAF behavior detected — "
                          f"blocked SQLi probe (HTTP {probe.status_code})")
                    if not result["waf_detected"]:
                        result["waf_detected"] = True
                        result["waf_name"]     = "Unknown WAF"
                        result["confidence"]   = 50
                        result["evidence"].append(
                            f"Blocked SQLi probe with HTTP {probe.status_code}"
                        )
            except Exception:
                pass

            break  # got a response, no need to try other scheme

        except requests.exceptions.ConnectionError:
            continue
        except Exception as e:
            print(f"    [-] Error: {e}")
            continue

    return result


# ─────────────────────────────────────────
# RUN ON ALL HOSTS
# ─────────────────────────────────────────
def run(hosts):
    print("\n" + "="*50)
    print("  WAF DETECTOR")
    print("="*50)

    all_results = {}

    for host in hosts:
        result = detect_waf(host)
        all_results[host] = result

    print(f"\n--- WAF Detection Summary ---")
    for host, result in all_results.items():
        if result["waf_detected"]:
            print(f"  {host:<35} WAF: {result['waf_name']} "
                  f"({result['confidence']}% confidence)")
        else:
            print(f"  {host:<35} No WAF detected")

    return all_results


if __name__ == "__main__":
    test_hosts = ["cloudflare.com", "scanme.nmap.org", "vulnweb.com"]
    results = run(test_hosts)
