# ReconHawk - Master Entry Point
# Orchestrates all modules in the correct order
# Usage: python3 main.py --target domain.com

import argparse
import sys
import os
import datetime

import config
from core       import subdomain_enum, port_scanner, cve_lookup
from core       import cvss_scorer, header_analyzer, ssl_checker
from core       import waf_detector, misconfig_checker, default_creds
from core       import tech_fingerprint, threat_intel
from database   import db_manager, diff_engine
from alerts     import alert_engine
from visualizations import attack_graph, port_heatmap

BANNER = """
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║  ██║██╔══██╗██║    ██║██║ ██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████║███████║██║ █╗ ██║█████╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══██║██╔══██║██║███╗██║██╔═██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║  ██║██║  ██║╚███╔███╔╝██║  ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝
        Automated Reconnaissance & Attack Surface Intelligence Platform
                    github.com/YourUsername/ReconHawk
"""

def print_disclaimer():
    print("\n" + "="*70)
    print("  LEGAL DISCLAIMER")
    print("="*70)
    print("  ReconHawk is for authorized security testing only.")
    print("  Only scan targets you own or have written permission to test.")
    print("  Unauthorized scanning may be illegal in your jurisdiction.")
    print("="*70 + "\n")

def run_scan(domain, args):
    print(BANNER)
    print_disclaimer()

    start_time = datetime.datetime.now()
    print(f"[*] Target     : {domain}")
    print(f"[*] Start time : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Modules    : All enabled\n")

    # Init database
    db_manager.init_db()
    scan_id = db_manager.create_scan(domain)

    results = {}

    # ── Phase 1: Recon ──────────────────────────────
    print("\n" + "█"*50)
    print("  PHASE 1 — RECONNAISSANCE")
    print("█"*50)

    subdomains = subdomain_enum.run(domain)
    db_manager.save_subdomains(scan_id, domain, subdomains)
    results["subdomains"] = subdomains

    # Use top 5 subdomains to keep scan fast
    scan_targets = subdomains[:5] if subdomains else [domain]

    port_results = port_scanner.run(scan_targets)
    db_manager.save_ports(scan_id, port_results)
    results["ports"] = port_results

    dns_results = {}
    from core import dns_checker
    dns_results[domain] = dns_checker.run(domain)
    results["dns"] = dns_results

    # ── Phase 2: Intelligence ────────────────────────
    print("\n" + "█"*50)
    print("  PHASE 2 — INTELLIGENCE")
    print("█"*50)

    cve_results = cve_lookup.run(port_results)
    db_manager.save_cves(scan_id, cve_results)
    results["cves"] = cve_results

    risk_summary = cvss_scorer.score_target(cve_results)
    cvss_scorer.print_summary(risk_summary)
    db_manager.save_risk_score(scan_id, domain, risk_summary)
    results["risk"] = risk_summary

    header_results = header_analyzer.run(scan_targets)
    results["headers"] = header_results
    for host, hdata in header_results.items():
        for missing in hdata.get("missing", []):
            db_manager.save_finding(
                scan_id, host, "HTTP Headers",
                missing["severity"], missing["header"],
                missing["description"]
            )

    ssl_results = ssl_checker.run(scan_targets)
    results["ssl"] = ssl_results
    for host, sdata in ssl_results.items():
        for finding in sdata.get("findings", []):
            db_manager.save_finding(
                scan_id, host, "SSL/TLS",
                finding["severity"], finding["issue"],
                finding.get("detail", "")
            )

    waf_results = waf_detector.run(scan_targets)
    results["waf"] = waf_results

    tech_results = tech_fingerprint.run(scan_targets)
    results["tech"] = tech_results

    # ── Phase 3: Threat Intel & Misconfig ───────────
    print("\n" + "█"*50)
    print("  PHASE 3 — THREAT INTEL & MISCONFIG")
    print("█"*50)

    misconfig_results = misconfig_checker.run(scan_targets)
    results["misconfigs"] = misconfig_results
    for host, findings in misconfig_results.items():
        for f in findings:
            db_manager.save_finding(
                scan_id, host, "Misconfiguration",
                f["severity"], f["path"],
                f"HTTP {f['status_code']} — {f['path']}"
            )

    cred_results = default_creds.run(scan_targets)
    results["creds"] = cred_results

    threat_results = threat_intel.run(domain)
    results["threat_intel"] = threat_results

    # ── Phase 4: Alerts ──────────────────────────────
    print("\n" + "█"*50)
    print("  PHASE 4 — ALERTS")
    print("█"*50)
    alert_engine.check_and_alert(scan_id, cve_results, misconfig_results)

    # ── Phase 5: Visualizations ──────────────────────
    print("\n" + "█"*50)
    print("  PHASE 5 — VISUALIZATIONS")
    print("█"*50)
    attack_graph.build_graph(domain, subdomains, port_results, cve_results)
    port_heatmap.build_heatmap(domain, port_results, cve_results)

    # ── Phase 6: Diff ────────────────────────────────
    db_manager.complete_scan(
        scan_id,
        f"Score:{risk_summary['overall_score']} "
        f"CVEs:{risk_summary['total_cves']}"
    )
    diff_engine.run(domain)

    # ── Summary ──────────────────────────────────────
    end_time  = datetime.datetime.now()
    duration  = (end_time - start_time).seconds

    print("\n" + "="*70)
    print("  SCAN COMPLETE")
    print("="*70)
    print(f"  Domain         : {domain}")
    print(f"  Scan ID        : {scan_id}")
    print(f"  Duration       : {duration}s")
    print(f"  Subdomains     : {len(subdomains)}")
    print(f"  Hosts scanned  : {len(port_results)}")
    print(f"  CVEs found     : {risk_summary['total_cves']}")
    print(f"  Risk score     : {risk_summary['overall_score']}/10 "
          f"({risk_summary['overall_severity']})")
    print(f"  Graphs saved   : {config.GRAPHS_DIR}")
    print(f"  Alerts log     : {config.ALERTS_LOG}")
    print(f"  Database       : {config.DB_PATH}")
    print(f"\n  View results:")
    print(f"  → Run: python3 dashboard/app.py")
    print(f"  → Open: http://127.0.0.1:5000")
    print("="*70)

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ReconHawk — Attack Surface Intelligence Platform"
    )
    parser.add_argument(
        "--target", "-t",
        required=True,
        help="Target domain to scan (e.g. vulnweb.com)"
    )
    args = parser.parse_args()
    run_scan(args.target, args)
