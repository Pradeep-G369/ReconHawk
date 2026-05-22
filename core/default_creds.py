# ReconHawk - Default Credentials Checker
# Tests common default username/password combinations
# on login pages discovered during recon

import requests
import urllib3
import sys
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ─────────────────────────────────────────
# COMMON LOGIN ENDPOINTS TO CHECK
# ─────────────────────────────────────────
LOGIN_PATHS = [
    "/login",
    "/admin/login",
    "/admin",
    "/administrator",
    "/wp-login.php",
    "/phpmyadmin/",
    "/user/login",
    "/auth/login",
    "/panel",
    "/cpanel",
]

# ─────────────────────────────────────────
# LOAD CREDENTIALS FROM WORDLIST
# ─────────────────────────────────────────
def load_credentials():
    creds = []
    if os.path.exists(config.CREDS_PATH):
        with open(config.CREDS_PATH, "r") as f:
            for line in f:
                line = line.strip()
                if ":" in line:
                    user, pwd = line.split(":", 1)
                    creds.append((user.strip(), pwd.strip()))
    else:
        # Fallback hardcoded list
        creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("admin", "admin123"),
            ("root",  "root"),
            ("root",  "toor"),
            ("administrator", "administrator"),
            ("user",  "user"),
            ("guest", "guest"),
            ("test",  "test"),
        ]
    return creds


# ─────────────────────────────────────────
# FIND LOGIN PAGES ON A HOST
# ─────────────────────────────────────────
def find_login_pages(host):
    login_pages = []

    for scheme in ["https", "http"]:
        base_url = f"{scheme}://{host}"
        for path in LOGIN_PATHS:
            url = f"{base_url}{path}"
            try:
                response = requests.get(
                    url,
                    timeout=config.REQUEST_TIMEOUT,
                    verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": "ReconHawk-Scanner/1.0"}
                )
                if response.status_code == 200:
                    # Check if it looks like a login page
                    body = response.text.lower()
                    if any(keyword in body for keyword in
                           ["password", "login", "username",
                            "signin", "log in", "passwd"]):
                        login_pages.append({
                            "url"  : url,
                            "path" : path,
                        })
                        print(f"    [+] Login page found: {url}")
            except Exception:
                continue
        if login_pages:
            break  # found pages on this scheme, no need to try other

    return login_pages


# ─────────────────────────────────────────
# ATTEMPT DEFAULT CREDENTIALS ON A LOGIN PAGE
# Only uses form-based POST — safe and legal
# ─────────────────────────────────────────
def test_credentials(login_url, credentials):
    findings = []
    session  = requests.Session()

    # Common form field name variations
    user_fields = ["username", "user", "email", "login", "uname"]
    pass_fields = ["password", "pass", "passwd", "pwd"]

    # Get the login page first to grab any CSRF tokens
    try:
        page = session.get(
            login_url,
            timeout=config.REQUEST_TIMEOUT,
            verify=False,
            headers={"User-Agent": "ReconHawk-Scanner/1.0"}
        )
        original_len = len(page.text)
    except Exception:
        return findings

    for username, password in credentials:
        for ufield in user_fields:
            for pfield in pass_fields:
                try:
                    data = {
                        ufield: username,
                        pfield: password,
                    }
                    response = session.post(
                        login_url,
                        data=data,
                        timeout=config.REQUEST_TIMEOUT,
                        verify=False,
                        allow_redirects=True,
                        headers={"User-Agent": "ReconHawk-Scanner/1.0"}
                    )

                    # Heuristic — successful login usually:
                    # 1. Redirects to dashboard
                    # 2. Response length changes significantly
                    # 3. Contains welcome/dashboard keywords
                    body = response.text.lower()
                    success_keywords = [
                        "dashboard", "welcome", "logout",
                        "sign out", "profile", "my account"
                    ]
                    length_diff = abs(len(response.text) - original_len)

                    if (any(kw in body for kw in success_keywords)
                            and length_diff > 100):
                        findings.append({
                            "url"     : login_url,
                            "username": username,
                            "password": password,
                            "severity": "CRITICAL",
                            "detail"  : f"Default credentials work: "
                                        f"{username}:{password}",
                        })
                        print(f"    [!!!] CRITICAL — Default creds work: "
                              f"{username}:{password} at {login_url}")
                        return findings  # stop after first success

                except Exception:
                    continue

    return findings


# ─────────────────────────────────────────
# RUN ON ALL HOSTS
# ─────────────────────────────────────────
def run(hosts):
    print("\n" + "="*50)
    print("  DEFAULT CREDENTIALS CHECKER")
    print("="*50)

    credentials = load_credentials()
    print(f"[*] Loaded {len(credentials)} credential pairs")

    all_findings = {}
    total        = 0

    for host in hosts:
        print(f"\n[*] Checking default credentials → {host}")
        host_findings = []

        # Find login pages first
        login_pages = find_login_pages(host)

        if not login_pages:
            print(f"    [-] No login pages found on {host}")
            continue

        # Test credentials on each login page
        for page in login_pages:
            print(f"    [*] Testing {len(credentials)} credential pairs "
                  f"on {page['url']}")
            findings = test_credentials(page["url"], credentials)
            host_findings.extend(findings)
            total += len(findings)

        if host_findings:
            all_findings[host] = host_findings
        else:
            print(f"    [+] No default credentials worked on {host}")

    print(f"\n--- Default Credentials Summary ---")
    if all_findings:
        for host, findings in all_findings.items():
            for f in findings:
                print(f"  [CRITICAL] {f['url']} → {f['username']}:{f['password']}")
    else:
        print(f"  [✓] No default credentials found")

    print(f"\n[✓] Total findings: {total}")
    return all_findings


if __name__ == "__main__":
    # testphp.vulnweb.com is a deliberately vulnerable app
    # legal to test against
    test_hosts = ["testphp.vulnweb.com", "scanme.nmap.org"]
    results = run(test_hosts)
