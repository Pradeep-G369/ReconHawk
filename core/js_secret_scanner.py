# ReconHawk - JavaScript Secret Scanner
# Crawls JS files on target and scans for exposed
# API keys, tokens, and hardcoded credentials

import requests
import urllib3
import re
import sys
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ─────────────────────────────────────────
# SECRET PATTERNS
# Regex patterns for common API keys/tokens
# ─────────────────────────────────────────
SECRET_PATTERNS = {
    "AWS Access Key"       : r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key"       : r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key"       : r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth"         : r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
    "Stripe Live Key"      : r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Test Key"      : r"sk_test_[0-9a-zA-Z]{24,}",
    "GitHub Token"         : r"ghp_[0-9a-zA-Z]{36}",
    "GitHub OAuth"         : r"gho_[0-9a-zA-Z]{36}",
    "Slack Token"          : r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
    "Slack Webhook"        : r"https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[a-zA-Z0-9]+",
    "Twilio API Key"       : r"SK[0-9a-fA-F]{32}",
    "SendGrid API Key"     : r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "Mailgun API Key"      : r"key-[0-9a-zA-Z]{32}",
    "Firebase URL"         : r"https://[a-z0-9-]+\.firebaseio\.com",
    "Firebase API Key"     : r"AIza[0-9A-Za-z\-_]{35}",
    "JWT Token"            : r"eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*",
    "Basic Auth in URL"    : r"https?://[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9\-\.]+",
    "Private Key"          : r"-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----",
    "Password in var"      : r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
    "API Key in var"       : r"(?i)(api_key|apikey|api-key)\s*[=:]\s*['\"][^'\"]{10,}['\"]",
    "Secret in var"        : r"(?i)(secret|token)\s*[=:]\s*['\"][^'\"]{10,}['\"]",
}

# ─────────────────────────────────────────
# FIND ALL JS FILES ON A HOST
# ─────────────────────────────────────────
def find_js_files(host):
    js_files = []

    for scheme in ["https", "http"]:
        base_url = f"{scheme}://{host}"
        try:
            response = requests.get(
                base_url,
                timeout=config.REQUEST_TIMEOUT,
                verify=False,
                allow_redirects=True,
                headers={"User-Agent": "ReconHawk-Scanner/1.0"}
            )

            # Find JS file references in HTML
            js_pattern = re.findall(
                r'src=["\']([^"\']*\.js[^"\']*)["\']',
                response.text, re.IGNORECASE
            )

            for js_path in js_pattern:
                if js_path.startswith("http"):
                    js_files.append(js_path)
                elif js_path.startswith("//"):
                    js_files.append(f"{scheme}:{js_path}")
                elif js_path.startswith("/"):
                    js_files.append(f"{base_url}{js_path}")
                else:
                    js_files.append(f"{base_url}/{js_path}")

            if js_files:
                break

        except Exception:
            continue

    return list(set(js_files))[:20]  # limit to 20 JS files


# ─────────────────────────────────────────
# SCAN A SINGLE JS FILE FOR SECRETS
# ─────────────────────────────────────────
def scan_js_file(js_url):
    findings = []
    try:
        response = requests.get(
            js_url,
            timeout=config.REQUEST_TIMEOUT,
            verify=False,
            headers={"User-Agent": "ReconHawk-Scanner/1.0"}
        )

        if response.status_code != 200:
            return findings

        content = response.text

        for secret_type, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            for match in matches:
                # Skip false positives — too short or placeholder values
                if len(str(match)) < 8:
                    continue
                if any(fp in str(match).lower() for fp in
                       ["example", "placeholder", "your_key",
                        "insert_here", "xxxxxxxx", "test123"]):
                    continue

                findings.append({
                    "url"        : js_url,
                    "type"       : secret_type,
                    "match"      : str(match)[:80],
                    "severity"   : "CRITICAL",
                    "host"       : js_url.split("/")[2],
                })
                print(f"    [!!!] CRITICAL — {secret_type} found in {js_url.split('/')[-1]}")
                print(f"          Match: {str(match)[:60]}...")

    except Exception as e:
        pass

    return findings


# ─────────────────────────────────────────
# RUN ON ALL HOSTS
# ─────────────────────────────────────────
def run(hosts):
    print("\n" + "="*50)
    print("  JS SECRET SCANNER")
    print("="*50)

    all_findings = {}
    total        = 0

    for host in hosts:
        print(f"\n[*] Scanning JS files → {host}")
        js_files = find_js_files(host)

        if not js_files:
            print(f"    [-] No JS files found on {host}")
            continue

        print(f"    [+] Found {len(js_files)} JS files — scanning for secrets")
        host_findings = []

        for js_url in js_files:
            findings = scan_js_file(js_url)
            host_findings.extend(findings)
            total += len(findings)

        if host_findings:
            all_findings[host] = host_findings
        else:
            print(f"    [✓] No secrets found in JS files")

    print(f"\n--- JS Secret Scanner Summary ---")
    if all_findings:
        for host, findings in all_findings.items():
            print(f"  {host}: {len(findings)} secret(s) found")
    else:
        print(f"  [✓] No secrets found across all hosts")

    print(f"\n[✓] Total secrets found: {total}")
    return all_findings


if __name__ == "__main__":
    test_hosts = ["scanme.nmap.org", "testphp.vulnweb.com"]
    results = run(test_hosts)
