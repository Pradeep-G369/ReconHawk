# ReconHawk - CVE Lookup Engine
# Queries NVD API (free, no key needed) to find
# real CVEs for every service detected by port scanner

import requests
import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# ─────────────────────────────────────────
# SEARCH CVEs FOR A SINGLE SERVICE
# Takes service name + version from nmap
# Returns list of CVEs with scores
# ─────────────────────────────────────────
def search_cves(service, version="", max_results=5):
    results = []

    # Build search keyword
    keyword = service
    if version:
        keyword = f"{service} {version}"

    try:
        params = {
            "keywordSearch"  : keyword,
            "resultsPerPage" : max_results,
            "startIndex"     : 0,
        }

        response = requests.get(
            NVD_API_URL,
            params=params,
            timeout=15,
            headers={"User-Agent": "ReconHawk-Scanner/1.0"}
        )

        if response.status_code != 200:
            print(f"    [-] NVD API error: {response.status_code}")
            return results

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            cve  = vuln.get("cve", {})
            cve_id = cve.get("id", "Unknown")

            # Get description
            descriptions = cve.get("descriptions", [])
            desc = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    desc = d.get("value", "")[:200]
                    break

            # Get CVSS score — try v3.1 first, then v3.0, then v2
            score    = 0.0
            severity = "NONE"
            vector   = ""

            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
                score    = cvss.get("baseScore", 0.0)
                severity = cvss.get("baseSeverity", "NONE")
                vector   = cvss.get("vectorString", "")
            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0]["cvssData"]
                score    = cvss.get("baseScore", 0.0)
                severity = cvss.get("baseSeverity", "NONE")
                vector   = cvss.get("vectorString", "")
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]
                score    = cvss.get("baseScore", 0.0)
                severity = "MEDIUM" if score >= 4.0 else "LOW"
                vector   = cvss.get("vectorString", "")

            results.append({
                "cve_id"      : cve_id,
                "description" : desc,
                "score"       : score,
                "severity"    : severity,
                "vector"      : vector,
                "service"     : service,
                "version"     : version,
            })

        # NVD rate limit — 5 requests per 30 seconds without API key
        time.sleep(1)

    except requests.exceptions.RequestException as e:
        print(f"    [-] CVE lookup failed for {service}: {e}")
    except Exception as e:
        print(f"    [-] Unexpected error: {e}")

    return results


# ─────────────────────────────────────────
# PROCESS ALL PORTS FROM PORT SCANNER
# Takes port_scanner results dict
# Returns enriched results with CVEs
# ─────────────────────────────────────────
def run(scan_results):
    print("\n" + "="*50)
    print("  CVE LOOKUP ENGINE")
    print("="*50)

    all_cves = {}
    total_found = 0

    for host, ports in scan_results.items():
        print(f"\n[*] Looking up CVEs for → {host}")
        all_cves[host] = {}

        for port, info in ports.items():
            service = info.get("service", "")
            product = info.get("product", "")
            version = info.get("version", "")

            # Skip unknown or wrapped services
            if not service or service in ["tcpwrapped", "unknown"]:
                continue

            # Use product name if available (more specific)
            search_term = product if product else service

            print(f"  [*] Port {port} → searching CVEs for: "
                  f"{search_term} {version}")

            cves = search_cves(search_term, version)

            if cves:
                all_cves[host][port] = cves
                total_found += len(cves)
                for cve in cves:
                    print(f"      [{cve['severity']:<8}] {cve['cve_id']} "
                          f"Score: {cve['score']} — {cve['description'][:60]}...")
            else:
                print(f"      [-] No CVEs found")

    print(f"\n[✓] Total CVEs found: {total_found}")
    return all_cves


if __name__ == "__main__":
    # Simulate port scanner output for testing
    test_scan = {
        "scanme.nmap.org": {
            22: {
                "protocol": "tcp",
                "state"   : "open",
                "service" : "ssh",
                "product" : "OpenSSH",
                "version" : "6.6.1p1",
            },
            80: {
                "protocol": "tcp",
                "state"   : "open",
                "service" : "http",
                "product" : "Apache httpd",
                "version" : "2.4.7",
            },
        }
    }

    results = run(test_scan)

    print("\n--- CVE Summary ---")
    for host, ports in results.items():
        for port, cves in ports.items():
            print(f"\nPort {port}:")
            for cve in cves:
                print(f"  {cve['cve_id']} | {cve['severity']} | "
                      f"Score: {cve['score']}")
