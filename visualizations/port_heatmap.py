# ReconHawk - Port Exposure Heatmap
# Seaborn heatmap showing port exposure across hosts

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

def build_heatmap(domain, port_results, cve_results=None):
    print(f"\n[*] Building port heatmap for {domain}")

    if not port_results:
        print("[-] No port data to visualize")
        return None

    # Collect all unique ports and hosts
    all_hosts = list(port_results.keys())
    all_ports = sorted(set(
        p for ports in port_results.values() for p in ports.keys()
    ))

    if not all_ports:
        print("[-] No open ports found")
        return None

    # Build matrix — value = risk score of port
    # 3 = critical, 2 = high, 1 = medium/low, 0 = closed
    matrix = []
    for host in all_hosts:
        row = []
        for port in all_ports:
            if port in port_results.get(host, {}):
                score = 1  # open, no CVE
                if cve_results and host in cve_results:
                    if port in cve_results[host]:
                        cves = cve_results[host][port]
                        max_sev = max(
                            (c.get("score", 0) for c in cves), default=0
                        )
                        if max_sev >= 9.0:
                            score = 4
                        elif max_sev >= 7.0:
                            score = 3
                        elif max_sev >= 4.0:
                            score = 2
                row.append(score)
            else:
                row.append(0)
        matrix.append(row)

    df = pd.DataFrame(
        matrix,
        index=all_hosts,
        columns=[str(p) for p in all_ports]
    )

    # Plot
    fig, ax = plt.subplots(figsize=(max(10, len(all_ports)), max(4, len(all_hosts))))
    fig.patch.set_facecolor("#1a1a2e")
    ax.set_facecolor("#1a1a2e")

    cmap = sns.color_palette(["#2d2d44", "#00AA00", "#FFAA00",
                              "#FF6600", "#FF0000"], as_cmap=True)

    sns.heatmap(
        df, ax=ax, cmap=cmap, vmin=0, vmax=4,
        linewidths=0.5, linecolor="#333355",
        annot=True, fmt="d",
        cbar_kws={"label": "Risk Level (0=closed, 1=open, 2=med, 3=high, 4=critical)"}
    )

    ax.set_title(f"Port Exposure Heatmap — {domain}",
                 color="white", fontsize=14, fontweight="bold", pad=15)
    ax.set_xlabel("Port", color="white", fontsize=11)
    ax.set_ylabel("Host", color="white", fontsize=11)
    ax.tick_params(colors="white")

    plt.xticks(rotation=45, ha="right")
    plt.yticks(rotation=0)
    plt.tight_layout()

    output_path = os.path.join(config.GRAPHS_DIR,
                               f"{domain}_port_heatmap.png")
    plt.savefig(output_path, dpi=150, bbox_inches="tight",
                facecolor="#1a1a2e")
    plt.close()

    print(f"[✓] Heatmap saved → {output_path}")
    return output_path


if __name__ == "__main__":
    test_ports = {
        "www.vulnweb.com": {
            80 : {"service": "http"},
            443: {"service": "https"},
            22 : {"service": "ssh"},
        },
        "rest.vulnweb.com": {
            80: {"service": "http"},
            21: {"service": "ftp"},
        }
    }
    test_cves = {
        "www.vulnweb.com": {
            80: [{"score": 9.8, "severity": "CRITICAL"}]
        }
    }
    path = build_heatmap("vulnweb.com", test_ports, test_cves)
    print(f"Heatmap saved: {path}")
