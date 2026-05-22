# ReconHawk - Alert Engine
# Logs critical findings to alerts.log
# Triggered automatically when CRITICAL CVEs found

import os
import sys
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

def write_alert(message, severity="CRITICAL"):
    os.makedirs(os.path.dirname(config.ALERTS_LOG), exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] [{severity}] {message}\n"
    with open(config.ALERTS_LOG, "a") as f:
        f.write(line)
    print(f"[ALERT] {line.strip()}")


def check_and_alert(scan_id, cve_results, misconfig_results):
    alerts = []

    # Alert on critical CVEs
    for host, ports in cve_results.items():
        for port, cves in ports.items():
            for cve in cves:
                if cve.get("severity") == "CRITICAL":
                    msg = (f"CRITICAL CVE {cve['cve_id']} "
                           f"(score {cve['score']}) on {host}:{port} "
                           f"— {cve['description'][:80]}")
                    write_alert(msg, "CRITICAL")
                    alerts.append(msg)
                elif cve.get("severity") == "HIGH":
                    msg = (f"HIGH CVE {cve['cve_id']} "
                           f"(score {cve['score']}) on {host}:{port}")
                    write_alert(msg, "HIGH")
                    alerts.append(msg)

    # Alert on critical misconfigs
    for host, findings in misconfig_results.items():
        for finding in findings:
            if finding.get("severity") == "CRITICAL":
                msg = (f"CRITICAL misconfig on {host}: "
                       f"{finding.get('path','unknown')}")
                write_alert(msg, "CRITICAL")
                alerts.append(msg)

    if not alerts:
        print("[ALERT] No critical findings to alert on")

    return alerts


if __name__ == "__main__":
    test_cves = {
        "scanme.nmap.org": {
            80: [{
                "cve_id"     : "CVE-2021-41773",
                "score"      : 9.8,
                "severity"   : "CRITICAL",
                "description": "Apache path traversal and RCE",
            }]
        }
    }
    check_and_alert(1, test_cves, {})
    print(f"[✓] Alert written to {config.ALERTS_LOG}")
