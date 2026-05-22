# ReconHawk - Continuous Monitor
# Runs scans on a schedule using Python's schedule library
# Stores results in SQLite and diffs against previous scan

import schedule
import time
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

def run_scheduled_scan(domain):
    print(f"\n[MONITOR] Starting scheduled scan for {domain}")
    # Import here to avoid circular imports
    from core import subdomain_enum, port_scanner, cve_lookup
    from core import cvss_scorer, header_analyzer
    from database import db_manager, diff_engine
    from alerts  import alert_engine

    db_manager.init_db()
    scan_id    = db_manager.create_scan(domain)
    subdomains = subdomain_enum.run(domain)
    db_manager.save_subdomains(scan_id, domain, subdomains)

    port_results = port_scanner.run(subdomains[:3])
    db_manager.save_ports(scan_id, port_results)

    cve_results  = cve_lookup.run(port_results)
    db_manager.save_cves(scan_id, cve_results)

    score = cvss_scorer.score_target(cve_results)
    db_manager.save_risk_score(scan_id, domain, score)
    db_manager.complete_scan(scan_id, f"Score: {score['overall_score']}")

    alert_engine.check_and_alert(scan_id, cve_results, {})
    diff_engine.run(domain)

    print(f"[MONITOR] Scan complete for {domain}")


def start_monitor(domain, interval_hours=None):
    hours = interval_hours or config.SCAN_INTERVAL_HOURS
    print(f"[MONITOR] Scheduling scan every {hours} hours for {domain}")
    print(f"[MONITOR] Running first scan now...")

    run_scheduled_scan(domain)

    schedule.every(hours).hours.do(run_scheduled_scan, domain=domain)

    print(f"[MONITOR] Scheduler running. Press Ctrl+C to stop.")
    while True:
        schedule.run_pending()
        time.sleep(60)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        start_monitor(sys.argv[1])
    else:
        print("Usage: python3 scheduler/monitor.py <domain>")
