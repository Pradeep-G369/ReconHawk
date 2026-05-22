# ReconHawk - Diff Engine
# Compares current scan with previous scan
# Highlights new, resolved, and changed findings

import sqlite3
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from database import db_manager

def get_latest_two_scans(domain):
    conn = sqlite3.connect(config.DB_PATH)
    c    = conn.cursor()
    c.execute("""
        SELECT id, scan_date FROM scans
        WHERE domain=? AND status='complete'
        ORDER BY scan_date DESC LIMIT 2
    """, (domain,))
    rows = c.fetchall()
    conn.close()
    return rows


def diff_ports(old_scan_id, new_scan_id):
    conn = sqlite3.connect(config.DB_PATH)
    c    = conn.cursor()

    c.execute("SELECT host, port, service FROM ports WHERE scan_id=?",
              (old_scan_id,))
    old_ports = set(tuple(r) for r in c.fetchall())

    c.execute("SELECT host, port, service FROM ports WHERE scan_id=?",
              (new_scan_id,))
    new_ports = set(tuple(r) for r in c.fetchall())

    conn.close()

    return {
        "new"     : list(new_ports - old_ports),
        "resolved": list(old_ports - new_ports),
        "unchanged": list(old_ports & new_ports),
    }


def diff_cves(old_scan_id, new_scan_id):
    conn = sqlite3.connect(config.DB_PATH)
    c    = conn.cursor()

    c.execute("SELECT cve_id, severity FROM cves WHERE scan_id=?",
              (old_scan_id,))
    old_cves = set(tuple(r) for r in c.fetchall())

    c.execute("SELECT cve_id, severity FROM cves WHERE scan_id=?",
              (new_scan_id,))
    new_cves = set(tuple(r) for r in c.fetchall())

    conn.close()

    return {
        "new"     : list(new_cves - old_cves),
        "resolved": list(old_cves - new_cves),
        "unchanged": list(old_cves & new_cves),
    }


def diff_findings(old_scan_id, new_scan_id):
    conn = sqlite3.connect(config.DB_PATH)
    c    = conn.cursor()

    c.execute("SELECT title, severity FROM findings WHERE scan_id=?",
              (old_scan_id,))
    old_f = set(tuple(r) for r in c.fetchall())

    c.execute("SELECT title, severity FROM findings WHERE scan_id=?",
              (new_scan_id,))
    new_f = set(tuple(r) for r in c.fetchall())

    conn.close()

    return {
        "new"     : list(new_f - old_f),
        "resolved": list(old_f - new_f),
        "unchanged": list(old_f & new_f),
    }


def run(domain):
    print("\n" + "="*50)
    print("  SCAN DIFF ENGINE")
    print("="*50)

    scans = get_latest_two_scans(domain)

    if len(scans) < 2:
        print(f"[i] Need at least 2 completed scans to diff.")
        print(f"[i] Only {len(scans)} scan(s) found for {domain}")
        return {}

    new_scan_id  = scans[0][0]
    old_scan_id  = scans[1][0]
    new_date     = scans[0][1]
    old_date     = scans[1][1]

    print(f"[*] Comparing scan {old_scan_id} ({old_date[:10]}) "
          f"→ scan {new_scan_id} ({new_date[:10]})")

    port_diff    = diff_ports(old_scan_id, new_scan_id)
    cve_diff     = diff_cves(old_scan_id, new_scan_id)
    finding_diff = diff_findings(old_scan_id, new_scan_id)

    print(f"\n--- Port Changes ---")
    if port_diff["new"]:
        print(f"  NEW ports opened:")
        for p in port_diff["new"]:
            print(f"    [+] {p[0]} port {p[1]} ({p[2]})")
    if port_diff["resolved"]:
        print(f"  Ports closed since last scan:")
        for p in port_diff["resolved"]:
            print(f"    [-] {p[0]} port {p[1]} ({p[2]})")
    if not port_diff["new"] and not port_diff["resolved"]:
        print(f"  No port changes")

    print(f"\n--- CVE Changes ---")
    if cve_diff["new"]:
        print(f"  NEW CVEs found:")
        for c in cve_diff["new"]:
            print(f"    [+] {c[0]} ({c[1]})")
    if cve_diff["resolved"]:
        print(f"  CVEs no longer detected:")
        for c in cve_diff["resolved"]:
            print(f"    [-] {c[0]} ({c[1]})")
    if not cve_diff["new"] and not cve_diff["resolved"]:
        print(f"  No CVE changes")

    print(f"\n--- Finding Changes ---")
    if finding_diff["new"]:
        print(f"  NEW findings:")
        for f in finding_diff["new"]:
            print(f"    [+] {f[0]} ({f[1]})")
    if finding_diff["resolved"]:
        print(f"  Resolved findings:")
        for f in finding_diff["resolved"]:
            print(f"    [-] {f[0]} ({f[1]})")

    return {
        "ports"   : port_diff,
        "cves"    : cve_diff,
        "findings": finding_diff,
    }


if __name__ == "__main__":
    run("testdomain.com")
