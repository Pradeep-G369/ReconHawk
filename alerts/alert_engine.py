# ReconHawk - Alert Engine
# Monitors scan results and generates alerts for critical findings
# Writes to alerts.log file + prints colored warnings to terminal
# Triggered automatically when Critical/High CVEs or misconfigs are found

import json
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ─────────────────────────────────────────────
# SEVERITY COLOR CODES (for terminal output)
# ─────────────────────────────────────────────
COLORS = {
    "CRITICAL" : "\033[91m",   # Red
    "HIGH"     : "\033[93m",   # Yellow
    "MEDIUM"   : "\033[94m",   # Blue
    "LOW"      : "\033[92m",   # Green
    "RESET"    : "\033[0m",
    "BOLD"     : "\033[1m",
}

def colorize(text, level):
    color = COLORS.get(level, "")
    reset = COLORS["RESET"]
    bold  = COLORS["BOLD"]
    return f"{bold}{color}{text}{reset}"

# ─────────────────────────────────────────────
# WRITE ALERT TO LOG FILE
# ─────────────────────────────────────────────
def write_alert_log(alert):
    """Append a single alert dict to alerts.log"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] [{alert['severity']}] {alert['type']} | {alert['target']} | {alert['message']}\n"
    
    with open(config.ALERTS_LOG, "a") as f:
        f.write(line)

# ─────────────────────────────────────────────
# CHECK CVE RESULTS FOR CRITICAL/HIGH
# ─────────────────────────────────────────────
def check_cve_alerts(cve_results, target):
    """
    cve_results: list of dicts from cve_lookup.py
    Each dict has: cve_id, description, cvss_score, severity
    """
    alerts = []
    
    print(f"\n[*] Checking CVE results for alerts → {target}")
    
    for cve in cve_results:
        severity = cve.get("severity", "NONE").upper()
        
        if severity in ["CRITICAL", "HIGH"]:
            alert = {
                "type"     : "CVE",
                "target"   : target,
                "severity" : severity,
                "message"  : f"{cve.get('cve_id', 'N/A')} — CVSS {cve.get('cvss_score', 'N/A')} — {cve.get('description', '')[:80]}",
            }
            alerts.append(alert)
            write_alert_log(alert)
            
            print(colorize(
                f"  [!] {severity} CVE: {cve.get('cve_id')} (CVSS {cve.get('cvss_score')}) on {target}",
                severity
            ))
    
    if not alerts:
        print(f"  [✓] No Critical/High CVEs found")
    
    return alerts

# ─────────────────────────────────────────────
# CHECK HEADER ANALYZER RESULTS
# ─────────────────────────────────────────────
def check_header_alerts(header_results, target):
    """
    header_results: dict from header_analyzer.py
    Contains: missing (list), grade (str), score (int)
    """
    alerts = []
    
    print(f"\n[*] Checking HTTP headers for alerts → {target}")
    
    missing = header_results.get("missing", [])
    score   = header_results.get("score", 100)
    
    # If score is very low = lots of missing security headers
    if score < 30:
        alert = {
            "type"     : "HTTP_HEADERS",
            "target"   : target,
            "severity" : "HIGH",
            "message"  : f"Very poor HTTP security headers — score {score}% — missing: {', '.join(missing[:5])}",
        }
        alerts.append(alert)
        write_alert_log(alert)
        print(colorize(f"  [!] HIGH: Very poor header security ({score}%) on {target}", "HIGH"))
    
    elif score < 60:
        alert = {
            "type"     : "HTTP_HEADERS",
            "target"   : target,
            "severity" : "MEDIUM",
            "message"  : f"Weak HTTP security headers — score {score}% — missing: {', '.join(missing[:5])}",
        }
        alerts.append(alert)
        write_alert_log(alert)
        print(colorize(f"  [!] MEDIUM: Weak header security ({score}%) on {target}", "MEDIUM"))
    
    else:
        print(f"  [✓] Header security acceptable ({score}%)")
    
    return alerts

# ─────────────────────────────────────────────
# CHECK SSL CERTIFICATE RESULTS
# ─────────────────────────────────────────────
def check_ssl_alerts(ssl_results, target):
    """
    ssl_results: dict from ssl_checker.py
    Contains: expired (bool), days_remaining (int), self_signed (bool), weak_cipher (bool)
    """
    alerts = []
    
    print(f"\n[*] Checking SSL/TLS for alerts → {target}")
    
    if not ssl_results or ssl_results.get("error"):
        print(f"  [-] SSL check failed or no data — skipping")
        return alerts
    
    # Expired certificate = CRITICAL
    if ssl_results.get("expired", False):
        alert = {
            "type"     : "SSL_CERTIFICATE",
            "target"   : target,
            "severity" : "CRITICAL",
            "message"  : f"SSL certificate is EXPIRED on {target}",
        }
        alerts.append(alert)
        write_alert_log(alert)
        print(colorize(f"  [!] CRITICAL: SSL certificate expired on {target}", "CRITICAL"))
    
    # Expiring soon (within 30 days) = HIGH
    days = ssl_results.get("days_remaining", 999)
    if isinstance(days, int) and 0 < days <= 30:
        alert = {
            "type"     : "SSL_CERTIFICATE",
            "target"   : target,
            "severity" : "HIGH",
            "message"  : f"SSL certificate expires in {days} days on {target}",
        }
        alerts.append(alert)
        write_alert_log(alert)
        print(colorize(f"  [!] HIGH: SSL expires in {days} days on {target}", "HIGH"))
    
    # Self-signed certificate = HIGH
    if ssl_results.get("self_signed", False):
        alert = {
            "type"     : "SSL_CERTIFICATE",
            "target"   : target,
            "severity" : "HIGH",
            "message"  : f"Self-signed SSL certificate detected on {target}",
        }
        alerts.append(alert)
        write_alert_log(alert)
        print(colorize(f"  [!] HIGH: Self-signed certificate on {target}", "HIGH"))
    
    if not alerts:
        print(f"  [✓] SSL certificate looks healthy")
    
    return alerts

# ─────────────────────────────────────────────
# CHECK DNS SECURITY RESULTS
# ─────────────────────────────────────────────
def check_dns_alerts(dns_results, target):
    """
    dns_results: dict from dns_checker.py
    Contains: spf, dmarc, dnssec etc.
    """
    alerts = []
    
    print(f"\n[*] Checking DNS security for alerts → {target}")
    
    spf   = dns_results.get("spf",   {})
    dmarc = dns_results.get("dmarc", {})
    
    if not spf.get("found", True):
        alert = {
            "type"     : "DNS_SECURITY",
            "target"   : target,
            "severity" : "HIGH",
            "message"  : f"No SPF record — domain vulnerable to email spoofing",
        }
        alerts.append(alert)
        write_alert_log(alert)
        print(colorize(f"  [!] HIGH: No SPF record on {target} — email spoofing possible", "HIGH"))
    
    if not dmarc.get("found", True):
        alert = {
            "type"     : "DNS_SECURITY",
            "target"   : target,
            "severity" : "HIGH",
            "message"  : f"No DMARC record — phishing/spoofing protection missing",
        }
        alerts.append(alert)
        write_alert_log(alert)
        print(colorize(f"  [!] HIGH: No DMARC record on {target}", "HIGH"))
    
    if not alerts:
        print(f"  [✓] DNS security records look good")
    
    return alerts

# ─────────────────────────────────────────────
# CHECK MISCONFIGURATION RESULTS
# ─────────────────────────────────────────────
def check_misconfig_alerts(misconfig_results, target):
    """
    misconfig_results: list of dicts from misconfig_checker.py
    Each dict has: path, severity, message
    """
    alerts = []
    
    print(f"\n[*] Checking misconfigurations for alerts → {target}")
    
    for finding in misconfig_results:
        severity = finding.get("severity", "LOW").upper()
        
        if severity in ["CRITICAL", "HIGH"]:
            alert = {
                "type"     : "MISCONFIGURATION",
                "target"   : target,
                "severity" : severity,
                "message"  : f"{finding.get('path', 'N/A')} — {finding.get('message', '')}",
            }
            alerts.append(alert)
            write_alert_log(alert)
            print(colorize(
                f"  [!] {severity}: Exposed {finding.get('path')} on {target}",
                severity
            ))
    
    if not alerts:
        print(f"  [✓] No critical/high misconfigurations found")
    
    return alerts

# ─────────────────────────────────────────────
# MASTER FUNCTION — runs all alert checks
# ─────────────────────────────────────────────
def run(target, scan_data):
    """
    scan_data: a dict with keys matching module names
    Example:
    {
        "cve"       : [...],
        "headers"   : {...},
        "ssl"       : {...},
        "dns"       : {...},
        "misconfig" : [...],
    }
    Returns: list of all alerts generated
    """
    print("\n" + "="*50)
    print("  ALERT ENGINE")
    print("="*50)
    print(f"[*] Target: {target}")
    print(f"[*] Alert log: {config.ALERTS_LOG}")
    
    all_alerts = []
    
    # Run each checker based on what data is available
    if "cve" in scan_data:
        all_alerts += check_cve_alerts(scan_data["cve"], target)
    
    if "headers" in scan_data:
        all_alerts += check_header_alerts(scan_data["headers"], target)
    
    if "ssl" in scan_data:
        all_alerts += check_ssl_alerts(scan_data["ssl"], target)
    
    if "dns" in scan_data:
        all_alerts += check_dns_alerts(scan_data["dns"], target)
    
    if "misconfig" in scan_data:
        all_alerts += check_misconfig_alerts(scan_data["misconfig"], target)
    
    # ── SUMMARY ──────────────────────────────
    print("\n" + "-"*50)
    print(f"--- Alert Summary for {target} ---")
    
    critical = [a for a in all_alerts if a["severity"] == "CRITICAL"]
    high     = [a for a in all_alerts if a["severity"] == "HIGH"]
    medium   = [a for a in all_alerts if a["severity"] == "MEDIUM"]
    
    print(colorize(f"  CRITICAL : {len(critical)}", "CRITICAL") if critical else f"  CRITICAL : 0")
    print(colorize(f"  HIGH     : {len(high)}",     "HIGH")     if high     else f"  HIGH     : 0")
    print(colorize(f"  MEDIUM   : {len(medium)}",   "MEDIUM")   if medium   else f"  MEDIUM   : 0")
    print(f"\n  Total alerts : {len(all_alerts)}")
    
    if all_alerts:
        print(f"\n  Full log saved → {config.ALERTS_LOG}")
    else:
        print(f"\n  [✓] No significant alerts — target looks clean")
    
    return all_alerts


# ─────────────────────────────────────────────
# STANDALONE TEST
# ─────────────────────────────────────────────
if __name__ == "__main__":
    # Simulate some scan results to test the alert engine
    test_target = "testphp.vulnweb.com"
    
    test_data = {
        "cve": [
            {
                "cve_id"      : "CVE-2021-44228",
                "description" : "Log4Shell RCE vulnerability in Apache Log4j",
                "cvss_score"  : 10.0,
                "severity"    : "CRITICAL",
            },
            {
                "cve_id"      : "CVE-2020-1234",
                "description" : "Medium severity XSS in some component",
                "cvss_score"  : 5.3,
                "severity"    : "MEDIUM",
            },
        ],
        "headers": {
            "score"   : 25,
            "grade"   : "F",
            "missing" : ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"],
        },
        "ssl": {
            "expired"       : False,
            "days_remaining": 45,
            "self_signed"   : False,
        },
        "dns": {
            "spf"  : {"found": False},
            "dmarc": {"found": False},
        },
        "misconfig": [
            {"path": "/.git/HEAD",  "severity": "CRITICAL", "message": "Git repo exposed"},
            {"path": "/.env",       "severity": "CRITICAL", "message": "Environment file exposed"},
            {"path": "/robots.txt", "severity": "LOW",      "message": "Robots.txt found"},
        ],
    }
    
    alerts = run(test_target, test_data)
