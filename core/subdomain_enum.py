# ReconHawk - Subdomain Enumeration Engine
# Two methods: passive (certificate transparency) + active (brute force)
# Both are 100% free, no API key needed

import requests
import threading
import dns.resolver
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ─────────────────────────────────────────
# METHOD 1 — Certificate Transparency Logs
# Queries crt.sh (free, no key needed)
# Finds subdomains from SSL certificates
# ─────────────────────────────────────────
def passive_enum(domain):
    print(f"\n[*] Passive enumeration via crt.sh → {domain}")
    subdomains = set()

    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(url, timeout=config.REQUEST_TIMEOUT)

        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name = entry.get("name_value", "")
                # crt.sh sometimes returns wildcard and multi-line entries
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(f".{domain}") and "*" not in sub:
                        subdomains.add(sub)

        print(f"[+] crt.sh found {len(subdomains)} subdomains")

    except requests.exceptions.RequestException as e:
        print(f"[-] crt.sh failed: {e}")

    return subdomains


# ─────────────────────────────────────────
# METHOD 2 — Active Brute Force
# Tries subdomains from wordlist
# Uses DNS resolution to check if they exist
# ─────────────────────────────────────────
def active_enum(domain):
    print(f"\n[*] Active brute force enumeration → {domain}")
    found = set()
    lock  = threading.Lock()

    # Load wordlist
    if not os.path.exists(config.WORDLIST_PATH):
        print(f"[-] Wordlist not found at {config.WORDLIST_PATH}")
        return found

    with open(config.WORDLIST_PATH, "r") as f:
        words = [line.strip() for line in f if line.strip()]

    print(f"[*] Loaded {len(words)} words from wordlist")

    def resolve(word):
        target = f"{word}.{domain}"
        try:
            dns.resolver.resolve(target, "A")
            with lock:
                found.add(target)
                print(f"    [+] Found → {target}")
        except Exception:
            pass  # subdomain doesn't exist, skip silently

    # Use threads for speed
    threads = []
    for word in words:
        while threading.active_count() > config.SUBDOMAIN_THREADS:
            pass  # wait if too many threads active
        t = threading.Thread(target=resolve, args=(word,))
        t.daemon = True
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print(f"[+] Brute force found {len(found)} subdomains")
    return found


# ─────────────────────────────────────────
# MAIN FUNCTION — combines both methods
# Called by main.py
# ─────────────────────────────────────────
def run(domain):
    print("\n" + "="*50)
    print("  SUBDOMAIN ENUMERATION")
    print("="*50)

    passive_results = passive_enum(domain)
    active_results  = active_enum(domain)

    # Merge both results
    all_subdomains = passive_results.union(active_results)

    print(f"\n[✓] Total unique subdomains found: {len(all_subdomains)}")
    for sub in sorted(all_subdomains):
        print(f"    → {sub}")

    return sorted(all_subdomains)


# ─────────────────────────────────────────
# Quick test — run this file directly
# python3 core/subdomain_enum.py
# ─────────────────────────────────────────
if __name__ == "__main__":
    test_domain = "testphp.vulnweb.com"
    results = run(test_domain)
    print(f"\nFinal list: {results}")
