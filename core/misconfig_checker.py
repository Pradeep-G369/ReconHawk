# ReconHawk - Misconfiguration Checker
# Finds exposed sensitive files, directories, and endpoints
# These are the first things real attackers check

import requests
import urllib3
import sys
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ─────────────────────────────────────────
# SENSITIVE PATHS TO CHECK
# Grouped by severity
# ─────────────────────────────────────────
SENSITIVE_PATHS = {
    "CRITICAL": [
        "/.git/HEAD",
        "/.git/config",
        "/.env",
        "/.env.backup",
        "/.env.local",
        "/config.php",
        "/wp-config.php",
        "/config/database.yml",
        "/database.yml",
        "/settings.py",
        "/local_settings.py",
        "/config.yml",
    ],
    "HIGH": [
        "/admin",
        "/admin/",
        "/administrator",
        "/phpmyadmin",
        "/phpMyAdmin",
        "/mysql",
        "/backup",
        "/backup.zip",
        "/backup.tar.gz",
        "/db_backup.sql",
        "/dump.sql",
        "/site.tar.gz",
        "/.htpasswd",
        "/.htaccess",
    ],
    "MEDIUM": [
        "/robots.txt",
        "/sitemap.xml",
        "/crossdomain.xml",
        "/clientaccesspolicy.xml",
        "/server-status",
        "/server-info",
        "/info.php",
        "/phpinfo.php",
        "/test.php",
        "/debug",
        "/console",
        "/actuator",
        "/actuator/env",
        "/actuator/health",
    ],
    "LOW": [
        "/readme.txt",
        "/README.md",
        "/CHANGELOG.md",
        "/LICENSE",
        "/install.php",
        "/setup.php",
        "/upload",
        "/uploads",
        "/files",
        "/tmp",
    ],
}

# ─────────────────────────────────────────
# CHECK A SINGLE HOST FOR MISCONFIGS
# ─────────────────────────────────────────
def check_host(host):
    print(f"\n[*] Misconfiguration check → {host}")
    findings = []

    # Determine base URL
    base_url = None
    for scheme in ["https", "http"]:
        try:
            test = requests.get(
                f"{scheme}://{host}",
                timeout=config.REQUEST_TIMEOUT,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "ReconHawk-Scanner/1.0"}
            )
            if test.status_code < 500:
                base_url = f"{scheme}://{host}"
                break
        except Exception:
            continue

    if not base_url:
        print(f"    [-] Could not connect to {host}")
        return findings

    print(f"    [+] Scanning {base_url}")

    # Check each path
    for severity, paths in SENSITIVE_PATHS.items():
        for path in paths:
            url = f"{base_url}{path}"
            try:
                response = requests.get(
                    url,
                    timeout=config.REQUEST_TIMEOUT,
                    verify=False,
                    allow_redirects=False,
                    headers={"User-Agent": "ReconHawk-Scanner/1.0"}
                )

                # 200 = exposed, 301/302 = redirects (still interesting)
                if response.status_code in [200, 301, 302, 403]:
                    content_len = len(response.content)

                    # Skip empty responses and login redirects for 403
                    if content_len < 10:
                        continue

                    finding = {
                        "url"        : url,
                        "path"       : path,
                        "status_code": response.status_code,
                        "severity"   : severity,
                        "size"       : content_len,
                        "host"       : host,
                    }

                    # Extra check for .git exposure
                    if ".git" in path and response.status_code == 200:
                        finding["severity"] = "CRITICAL"
                        finding["detail"]   = "Git repository exposed — source code leak"
                        print(f"    [!!!] CRITICAL — Git exposed: {url}")

                    # Extra check for .env exposure
                    elif ".env" in path and response.status_code == 200:
                        finding["severity"] = "CRITICAL"
                        finding["detail"]   = ".env file exposed — credentials leak"
                        print(f"    [!!!] CRITICAL — .env exposed: {url}")

                    else:
                        status_label = (
                            "EXPOSED" if response.status_code == 200
                            else f"HTTP {response.status_code}"
                        )
                        print(f"    [{severity:<8}] {status_label} — "
                              f"{path} ({content_len} bytes)")

                    findings.append(finding)

            except requests.exceptions.ConnectionError:
                continue
            except requests.exceptions.Timeout:
                continue
            except Exception:
                continue

    if not findings:
        print(f"    [✓] No misconfigurations found")
    else:
        print(f"    [→] Found {len(findings)} issues")

    return findings


# ─────────────────────────────────────────
# RUN ON ALL HOSTS
# ─────────────────────────────────────────
def run(hosts):
    print("\n" + "="*50)
    print("  MISCONFIGURATION CHECKER")
    print("="*50)

    all_findings = {}
    total = 0

    for host in hosts:
        findings = check_host(host)
        if findings:
            all_findings[host] = findings
            total += len(findings)

    print(f"\n--- Misconfiguration Summary ---")
    if all_findings:
        for host, findings in all_findings.items():
            critical = sum(1 for f in findings if f["severity"] == "CRITICAL")
            high     = sum(1 for f in findings if f["severity"] == "HIGH")
            medium   = sum(1 for f in findings if f["severity"] == "MEDIUM")
            low      = sum(1 for f in findings if f["severity"] == "LOW")
            print(f"  {host}")
            print(f"    Critical:{critical} High:{high} "
                  f"Medium:{medium} Low:{low}")
    else:
        print(f"  [✓] No misconfigurations found across all hosts")

    print(f"\n[✓] Total findings: {total}")
    return all_findings


if __name__ == "__main__":
    test_hosts = ["testphp.vulnweb.com", "scanme.nmap.org"]
    results = run(test_hosts)

    print("\n--- All Findings ---")
    for host, findings in results.items():
        print(f"\n{host}:")
        for f in findings:
            print(f"  [{f['severity']}] {f['path']} "
                  f"HTTP {f['status_code']} ({f['size']} bytes)")
