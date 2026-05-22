# ReconHawk - Database Manager
# SQLite storage for all scan results
# Persists data between scans for diff engine

import sqlite3
import json
import datetime
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ─────────────────────────────────────────
# INITIALIZE DATABASE
# Creates all tables if they don't exist
# ─────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(config.DB_PATH)
    c    = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            domain      TEXT NOT NULL,
            scan_date   TEXT NOT NULL,
            status      TEXT DEFAULT 'running',
            summary     TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS subdomains (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id  INTEGER,
            domain   TEXT,
            subdomain TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS ports (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id   INTEGER,
            host      TEXT,
            port      INTEGER,
            protocol  TEXT,
            service   TEXT,
            product   TEXT,
            version   TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS cves (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER,
            host        TEXT,
            port        INTEGER,
            cve_id      TEXT,
            score       REAL,
            severity    TEXT,
            description TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER,
            host        TEXT,
            category    TEXT,
            severity    TEXT,
            title       TEXT,
            detail      TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS risk_scores (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id          INTEGER,
            domain           TEXT,
            overall_score    REAL,
            overall_severity TEXT,
            total_cves       INTEGER,
            critical_count   INTEGER,
            high_count       INTEGER,
            medium_count     INTEGER,
            low_count        INTEGER,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    conn.commit()
    conn.close()
    return True


# ─────────────────────────────────────────
# CREATE A NEW SCAN RECORD
# ─────────────────────────────────────────
def create_scan(domain):
    conn    = sqlite3.connect(config.DB_PATH)
    c       = conn.cursor()
    now     = datetime.datetime.now().isoformat()
    c.execute(
        "INSERT INTO scans (domain, scan_date, status) VALUES (?,?,?)",
        (domain, now, "running")
    )
    scan_id = c.lastrowid
    conn.commit()
    conn.close()
    print(f"[DB] New scan created — ID: {scan_id} for {domain}")
    return scan_id


# ─────────────────────────────────────────
# SAVE SUBDOMAINS
# ─────────────────────────────────────────
def save_subdomains(scan_id, domain, subdomains):
    conn = sqlite3.connect(config.DB_PATH)
    c    = conn.cursor()
    for sub in subdomains:
        c.execute(
            "INSERT INTO subdomains (scan_id, domain, subdomain) VALUES (?,?,?)",
            (scan_id, domain, sub)
        )
    conn.commit()
    conn.close()


# ─────────────────────────────────────────
# SAVE PORT SCAN RESULTS
# ─────────────────────────────────────────
def save_ports(scan_id, port_results):
    conn = sqlite3.connect(config.DB_PATH)
    c    = conn.cursor()
    for host, ports in port_results.items():
        for port, info in ports.items():
            c.execute("""
                INSERT INTO ports
                (scan_id, host, port, protocol, service, product, version)
                VALUES (?,?,?,?,?,?,?)
            """, (
                scan_id, host, port,
                info.get("protocol", ""),
                info.get("service",  ""),
                info.get("product",  ""),
                info.get("version",  ""),
            ))
    conn.commit()
    conn.close()


# ─────────────────────────────────────────
# SAVE CVE RESULTS
# ─────────────────────────────────────────
def save_cves(scan_id, cve_results):
    conn = sqlite3.connect(config.DB_PATH)
    c    = conn.cursor()
    for host, ports in cve_results.items():
        for port, cves in ports.items():
            for cve in cves:
                c.execute("""
                    INSERT INTO cves
                    (scan_id, host, port, cve_id, score, severity, description)
                    VALUES (?,?,?,?,?,?,?)
                """, (
                    scan_id, host, port,
                    cve.get("cve_id",      ""),
                    cve.get("score",       0.0),
                    cve.get("severity",    ""),
                    cve.get("description", ""),
                ))
    conn.commit()
    conn.close()


# ─────────────────────────────────────────
# SAVE GENERIC FINDINGS
# (misconfigs, headers, ssl, waf, etc)
# ─────────────────────────────────────────
def save_finding(scan_id, host, category, severity, title, detail=""):
    conn = sqlite3.connect(config.DB_PATH)
    c    = conn.cursor()
    c.execute("""
        INSERT INTO findings
        (scan_id, host, category, severity, title, detail)
        VALUES (?,?,?,?,?,?)
    """, (scan_id, host, category, severity, title, detail))
    conn.commit()
    conn.close()


# ─────────────────────────────────────────
# SAVE RISK SCORE SUMMARY
# ─────────────────────────────────────────
def save_risk_score(scan_id, domain, summary):
    conn = sqlite3.connect(config.DB_PATH)
    c    = conn.cursor()
    counts = summary.get("counts", {})
    c.execute("""
        INSERT INTO risk_scores
        (scan_id, domain, overall_score, overall_severity,
         total_cves, critical_count, high_count, medium_count, low_count)
        VALUES (?,?,?,?,?,?,?,?,?)
    """, (
        scan_id, domain,
        summary.get("overall_score",    0.0),
        summary.get("overall_severity", "NONE"),
        summary.get("total_cves",       0),
        counts.get("CRITICAL", 0),
        counts.get("HIGH",     0),
        counts.get("MEDIUM",   0),
        counts.get("LOW",      0),
    ))
    conn.commit()
    conn.close()


# ─────────────────────────────────────────
# MARK SCAN AS COMPLETE
# ─────────────────────────────────────────
def complete_scan(scan_id, summary_text=""):
    conn = sqlite3.connect(config.DB_PATH)
    c    = conn.cursor()
    c.execute(
        "UPDATE scans SET status=?, summary=? WHERE id=?",
        ("complete", summary_text, scan_id)
    )
    conn.commit()
    conn.close()


# ─────────────────────────────────────────
# GET ALL SCANS FOR A DOMAIN
# ─────────────────────────────────────────
def get_scans(domain=None):
    conn = sqlite3.connect(config.DB_PATH)
    c    = conn.cursor()
    if domain:
        c.execute(
            "SELECT * FROM scans WHERE domain=? ORDER BY scan_date DESC",
            (domain,)
        )
    else:
        c.execute("SELECT * FROM scans ORDER BY scan_date DESC")
    rows = c.fetchall()
    conn.close()
    return rows


# ─────────────────────────────────────────
# GET FULL SCAN DATA BY ID
# ─────────────────────────────────────────
def get_scan_data(scan_id):
    conn = sqlite3.connect(config.DB_PATH)
    c    = conn.cursor()

    c.execute("SELECT * FROM scans WHERE id=?",      (scan_id,))
    scan = c.fetchone()

    c.execute("SELECT * FROM subdomains WHERE scan_id=?", (scan_id,))
    subdomains = c.fetchall()

    c.execute("SELECT * FROM ports WHERE scan_id=?", (scan_id,))
    ports = c.fetchall()

    c.execute("SELECT * FROM cves WHERE scan_id=?",  (scan_id,))
    cves = c.fetchall()

    c.execute("SELECT * FROM findings WHERE scan_id=?", (scan_id,))
    findings = c.fetchall()

    c.execute("SELECT * FROM risk_scores WHERE scan_id=?", (scan_id,))
    risk = c.fetchone()

    conn.close()
    return {
        "scan"      : scan,
        "subdomains": subdomains,
        "ports"     : ports,
        "cves"      : cves,
        "findings"  : findings,
        "risk"      : risk,
    }


if __name__ == "__main__":
    init_db()
    print("[✓] Database initialized")
    scan_id = create_scan("testdomain.com")
    print(f"[✓] Test scan created: ID {scan_id}")
    complete_scan(scan_id, "Test complete")
    scans = get_scans()
    print(f"[✓] Total scans in DB: {len(scans)}")
