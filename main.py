# ReconHawk - Master Entry Point (v2.0 - Parallel Edition)
# Runs independent modules concurrently for 3x speed improvement
# Usage: python3 main.py --target domain.com
# Usage: python3 main.py --target domain.com --modules ports,cve,headers

import argparse
import sys
import os
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import config
from core          import subdomain_enum, port_scanner, cve_lookup
from core          import cvss_scorer, header_analyzer, ssl_checker
from core          import waf_detector, misconfig_checker, default_creds
from core          import tech_fingerprint, threat_intel
from database      import db_manager, diff_engine
from alerts        import alert_engine
from visualizations import attack_graph, port_heatmap

# ─────────────────────────────────────────────────────────
# ASCII BANNER  (Improvement 9 is built right in here)
# ─────────────────────────────────────────────────────────
BANNER = r"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║  ██║██╔══██╗██║    ██║██║ ██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████║███████║██║ █╗ ██║█████╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══██║██╔══██║██║███╗██║██╔═██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝
"""
SUBTITLE = "  Automated Reconnaissance & Attack Surface Intelligence Platform"
GITHUB   = "  github.com/Pradeep-G369/ReconHawk  |  Use only on targets you own"
DIVIDER  = "  " + "─" * 68

# ─────────────────────────────────────────────────────────
# ALL AVAILABLE MODULES
# ─────────────────────────────────────────────────────────
ALL_MODULES = [
    "subdomains", "ports", "dns", "cve", "cvss",
    "headers", "ssl", "waf", "tech", "misconfig",
    "creds", "intel", "alerts", "graphs", "report"
]

def print_banner():
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    print(f"{CYAN}{BOLD}{BANNER}{RESET}")
    print(f"{GREEN}{SUBTITLE}{RESET}")
    print(f"{YELLOW}{GITHUB}{RESET}")
    print(f"{GREEN}{DIVIDER}{RESET}\n")

def print_disclaimer():
    RED   = "\033[91m"
    RESET = "\033[0m"
    BOLD  = "\033[1m"
    print(f"{RED}{BOLD}{'='*70}")
    print("  LEGAL DISCLAIMER")
    print(f"{'='*70}{RESET}")
    print("  ReconHawk is for AUTHORIZED security testing ONLY.")
    print("  Only scan targets you own or have written permission to test.")
    print("  Unauthorized scanning may be illegal in your jurisdiction.")
    print(f"{RED}{BOLD}{'='*70}{RESET}\n")

def section(title):
    BLUE  = "\033[94m"
    BOLD  = "\033[1m"
    RESET = "\033[0m"
    print(f"\n{BOLD}{BLUE}{'━'*50}")
    print(f"  {title}")
    print(f"{'━'*50}{RESET}")

# ─────────────────────────────────────────────────────────
# PARSE --modules FLAG
# ─────────────────────────────────────────────────────────
def parse_modules(modules_arg):
    """
    --modules all          → run everything (default)
    --modules ports,cve    → run only those two
    --modules -ssl,-waf    → run all EXCEPT ssl and waf
    """
    if not modules_arg or modules_arg.strip().lower() == "all":
        return set(ALL_MODULES)

    parts = [p.strip().lower() for p in modules_arg.split(",")]

    # exclusion mode: all entries start with -
    if all(p.startswith("-") for p in parts):
        excluded = {p.lstrip("-") for p in parts}
        return set(ALL_MODULES) - excluded

    # inclusion mode
    selected = set()
    for p in parts:
        p = p.lstrip("-")
        if p in ALL_MODULES:
            selected.add(p)
        else:
            print(f"  [!] Unknown module '{p}' — skipping")
    return selected

# ─────────────────────────────────────────────────────────
# MAIN SCAN FUNCTION
# ─────────────────────────────────────────────────────────
def run_scan(domain, args):
    print_banner()
    print_disclaimer()

    # Which modules to run
    enabled = parse_modules(getattr(args, "modules", "all"))

    start_time = datetime.datetime.now()
    print(f"  [*] Target    : {domain}")
    print(f"  [*] Started   : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  [*] Modules   : {', '.join(sorted(enabled))}\n")

    # Init database
    db_manager.init_db()
    scan_id = db_manager.create_scan(domain)

    results = {}

    # ── PHASE 1: RECONNAISSANCE (run in parallel) ──────────
    section("PHASE 1 — RECONNAISSANCE  [Parallel]")
    print("  Running subdomain enum, port scan, and DNS check simultaneously...")

    phase1_results = {}

    def run_subdomains():
        if "subdomains" not in enabled:
            return "subdomains", []
        r = subdomain_enum.run(domain)
        db_manager.save_subdomains(scan_id, domain, r)
        return "subdomains", r

    def run_dns():
        if "dns" not in enabled:
            return "dns", {}
        r = {}
        from core import dns_checker
        r[domain] = dns_checker.run(domain)
        return "dns", r

    # Run subdomain enum first (port scan needs the results)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {
            executor.submit(run_subdomains): "subdomains",
            executor.submit(run_dns):        "dns",
        }
        for future in as_completed(futures):
            key, value = future.result()
            phase1_results[key] = value
            print(f"  [✓] {key} complete")

    subdomains = phase1_results.get("subdomains", [])
    results["subdomains"] = subdomains
    results["dns"]        = phase1_results.get("dns", {})

    # Port scan needs subdomains first, then runs
    scan_targets = subdomains[:5] if subdomains else [domain]

    if "ports" in enabled:
        print(f"  [*] Port scanning {len(scan_targets)} host(s)...")
        port_results = port_scanner.run(scan_targets)
        db_manager.save_ports(scan_id, port_results)
        results["ports"] = port_results
        print(f"  [✓] ports complete")
    else:
        results["ports"] = {}

    # ── PHASE 2: INTELLIGENCE (run in parallel) ────────────
    section("PHASE 2 — INTELLIGENCE  [Parallel]")
    print("  Running CVE lookup, header analysis, SSL, WAF, tech fingerprint simultaneously...")

    def run_cve():
        if "cve" not in enabled:
            return "cves", {}
        r = cve_lookup.run(results["ports"])
        db_manager.save_cves(scan_id, r)
        return "cves", r

    def run_headers():
        if "headers" not in enabled:
            return "headers", {}
        r = header_analyzer.run(scan_targets)
        for host, hdata in r.items():
            for missing in hdata.get("missing", []):
                db_manager.save_finding(
                    scan_id, host, "HTTP Headers",
                    missing["severity"], missing["header"],
                    missing["description"]
                )
        return "headers", r

    def run_ssl():
        if "ssl" not in enabled:
            return "ssl", {}
        r = ssl_checker.run(scan_targets)
        for host, sdata in r.items():
            for finding in sdata.get("findings", []):
                db_manager.save_finding(
                    scan_id, host, "SSL/TLS",
                    finding["severity"], finding["issue"],
                    finding.get("detail", "")
                )
        return "ssl", r

    def run_waf():
        if "waf" not in enabled:
            return "waf", {}
        r = waf_detector.run(scan_targets)
        return "waf", r

    def run_tech():
        if "tech" not in enabled:
            return "tech", {}
        r = tech_fingerprint.run(scan_targets)
        return "tech", r

    # All 5 Phase-2 tasks run at the same time
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(run_cve):     "cves",
            executor.submit(run_headers): "headers",
            executor.submit(run_ssl):     "ssl",
            executor.submit(run_waf):     "waf",
            executor.submit(run_tech):    "tech",
        }
        for future in as_completed(futures):
            key, value = future.result()
            results[key] = value
            print(f"  [✓] {key} complete")

    # CVSS scoring (depends on CVE results — runs after)
    if "cvss" in enabled and results.get("cves"):
        risk_summary = cvss_scorer.score_target(results["cves"])
        cvss_scorer.print_summary(risk_summary)
        db_manager.save_risk_score(scan_id, domain, risk_summary)
        results["risk"] = risk_summary
    else:
        results["risk"] = {}

    # ── PHASE 3: THREAT INTEL & MISCONFIG (parallel) ──────
    section("PHASE 3 — THREAT INTEL & MISCONFIG  [Parallel]")

    def run_misconfig():
        if "misconfig" not in enabled:
            return "misconfigs", {}
        r = misconfig_checker.run(scan_targets)
        for host, findings in r.items():
            for f in findings:
                db_manager.save_finding(
                    scan_id, host, "Misconfiguration",
                    f["severity"], f["path"],
                    f"HTTP {f['status_code']} — {f['path']}"
                )
        return "misconfigs", r

    def run_creds():
        if "creds" not in enabled:
            return "creds", {}
        r = default_creds.run(scan_targets)
        return "creds", r

    def run_intel():
        if "intel" not in enabled:
            return "threat_intel", {}
        r = threat_intel.run(domain)
        return "threat_intel", r

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(run_misconfig): "misconfigs",
            executor.submit(run_creds):     "creds",
            executor.submit(run_intel):     "threat_intel",
        }
        for future in as_completed(futures):
            key, value = future.result()
            results[key] = value
            print(f"  [✓] {key} complete")

    # ── PHASE 4: ALERTS ────────────────────────────────────
    section("PHASE 4 — ALERTS")
    if "alerts" in enabled:
        alert_engine.check_and_alert(
            scan_id,
            results.get("cves", {}),
            results.get("misconfigs", {})
        )

    # ── PHASE 5: VISUALIZATIONS & DATABASE ─────────────────
    section("PHASE 5 — VISUALIZATIONS & DATABASE")
    db_manager.complete_scan(
        scan_id,
        f"Score:{results.get('risk', {}).get('overall_score', 'N/A')} "
        f"CVEs:{results.get('risk', {}).get('total_cves', 0)}"
    )
    diff_engine.run(domain)

    if "graphs" in enabled:
        attack_graph.build_graph(
            domain,
            results.get("subdomains", []),
            results.get("ports", {}),
            results.get("cves", {})
        )
        port_heatmap.build_heatmap(
            domain,
            results.get("ports", {}),
            results.get("cves", {})
        )

    # ── SUMMARY ────────────────────────────────────────────
    end_time = datetime.datetime.now()
    duration = (end_time - start_time).seconds
    GREEN = "\033[92m"; BOLD = "\033[1m"; RESET = "\033[0m"
    print(f"\n{BOLD}{'='*70}")
    print("  SCAN COMPLETE")
    print(f"{'='*70}{RESET}")
    print(f"  Domain        : {domain}")
    print(f"  Scan ID       : {scan_id}")
    print(f"  Duration      : {duration}s  ({duration//60}m {duration%60}s)")
    print(f"  Subdomains    : {len(results.get('subdomains', []))}")
    print(f"  Hosts scanned : {len(results.get('ports', {}))}")
    print(f"  CVEs found    : {results.get('risk', {}).get('total_cves', 0)}")
    score = results.get('risk', {}).get('overall_score', 'N/A')
    sev   = results.get('risk', {}).get('overall_severity', 'N/A')
    print(f"  Risk score    : {score}/10  [{sev}]")
    print(f"  Graphs saved  : {config.GRAPHS_DIR}")
    print(f"  Alerts log    : {config.ALERTS_LOG}")
    print(f"  Database      : {config.DB_PATH}")
    print(f"\n{GREEN}  → Run: python3 dashboard/app.py")
    print(f"  → Open: http://127.0.0.1:5000{RESET}")
    print(f"{'='*70}\n")

    return results


# ─────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ReconHawk — Attack Surface Intelligence Platform",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python3 main.py --target vulnweb.com
  python3 main.py --target vulnweb.com --modules ports,cve,headers
  python3 main.py --target vulnweb.com --modules all
  python3 main.py --target vulnweb.com --modules -ssl,-waf
        """
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target domain to scan (e.g. vulnweb.com)"
    )
    parser.add_argument(
        "--modules", "-m",
        default="all",
        help=(
            "Modules to run (default: all)\n"
            "  Examples:\n"
            "    --modules all\n"
            "    --modules ports,cve,headers\n"
            "    --modules -ssl,-waf  (all except ssl and waf)\n"
            f"  Available: {', '.join(ALL_MODULES)}"
        )
    )
    args = parser.parse_args()
    run_scan(args.target, args)
