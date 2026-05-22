# ReconHawk - CVSS Scorer
# Maps CVSS scores to severity levels
# Calculates overall risk score for a target

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# ─────────────────────────────────────────
# MAP A SINGLE CVSS SCORE TO SEVERITY
# ─────────────────────────────────────────
def get_severity(score):
    score = float(score)
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    else:
        return "NONE"

# ─────────────────────────────────────────
# SEVERITY COLOR for dashboard/reports
# ─────────────────────────────────────────
def get_color(severity):
    colors = {
        "CRITICAL" : "#FF0000",
        "HIGH"     : "#FF6600",
        "MEDIUM"   : "#FFAA00",
        "LOW"      : "#00AA00",
        "NONE"     : "#888888",
    }
    return colors.get(severity, "#888888")

# ─────────────────────────────────────────
# SCORE AN ENTIRE TARGET
# Takes CVE lookup results
# Returns risk summary for the whole target
# ─────────────────────────────────────────
def score_target(cve_results):
    counts = {
        "CRITICAL" : 0,
        "HIGH"     : 0,
        "MEDIUM"   : 0,
        "LOW"      : 0,
        "NONE"     : 0,
    }

    all_scores  = []
    scored_cves = []

    for host, ports in cve_results.items():
        for port, cves in ports.items():
            for cve in cves:
                score    = float(cve.get("score", 0))
                severity = get_severity(score)
                counts[severity] += 1
                all_scores.append(score)

                scored_cves.append({
                    **cve,
                    "severity"      : severity,
                    "color"         : get_color(severity),
                    "host"          : host,
                    "port"          : port,
                })

    # Overall risk score — weighted average
    # Critical counts 4x, High 3x, Medium 2x, Low 1x
    weights = {
        "CRITICAL" : 4,
        "HIGH"     : 3,
        "MEDIUM"   : 2,
        "LOW"      : 1,
        "NONE"     : 0
    }

    weighted_sum  = sum(
        counts[sev] * weights[sev] for sev in counts
    )
    total_cves    = sum(counts.values())
    max_possible  = total_cves * 4 if total_cves > 0 else 1

    overall_score = round((weighted_sum / max_possible) * 10, 1)
    overall_sev   = get_severity(overall_score)

    summary = {
        "overall_score"   : overall_score,
        "overall_severity": overall_sev,
        "overall_color"   : get_color(overall_sev),
        "counts"          : counts,
        "total_cves"      : total_cves,
        "scored_cves"     : scored_cves,
        "avg_score"       : round(sum(all_scores) / len(all_scores), 1)
                            if all_scores else 0.0,
    }

    return summary


# ─────────────────────────────────────────
# PRINT RISK REPORT to terminal
# ─────────────────────────────────────────
def print_summary(summary):
    print("\n" + "="*50)
    print("  RISK SCORE SUMMARY")
    print("="*50)
    print(f"  Overall Risk Score : {summary['overall_score']} / 10")
    print(f"  Overall Severity   : {summary['overall_severity']}")
    print(f"  Total CVEs Found   : {summary['total_cves']}")
    print(f"  Average CVSS Score : {summary['avg_score']}")
    print()
    print(f"  CRITICAL  : {summary['counts']['CRITICAL']}")
    print(f"  HIGH      : {summary['counts']['HIGH']}")
    print(f"  MEDIUM    : {summary['counts']['MEDIUM']}")
    print(f"  LOW       : {summary['counts']['LOW']}")
    print("="*50)


# ─────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────
if __name__ == "__main__":
    # Simulate CVE lookup results
    test_cves = {
        "scanme.nmap.org": {
            80: [
                {"cve_id": "CVE-2021-44224", "score": 8.2,
                 "severity": "HIGH", "description": "Apache forward proxy flaw",
                 "vector": "NETWORK", "service": "http", "version": "2.4.7"},
                {"cve_id": "CVE-2021-41773", "score": 9.8,
                 "severity": "CRITICAL", "description": "Apache path traversal",
                 "vector": "NETWORK", "service": "http", "version": "2.4.49"},
            ],
            22: [
                {"cve_id": "CVE-2023-38408", "score": 5.3,
                 "severity": "MEDIUM", "description": "OpenSSH remote code exec",
                 "vector": "NETWORK", "service": "ssh", "version": "6.6.1"},
            ]
        }
    }

    summary = score_target(test_cves)
    print_summary(summary)

    print("\n--- Individual CVEs scored ---")
    for cve in summary["scored_cves"]:
        print(f"  {cve['cve_id']:<20} {cve['severity']:<10} "
              f"Score: {cve['score']}  Host: {cve['host']}")
