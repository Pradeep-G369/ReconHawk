# ReconHawk - Port Heatmap (Redesigned)
# Clean futuristic heatmap with risk annotations

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
import matplotlib.patches as mpatches
import numpy as np
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# Custom dark colormap — black → green → yellow → orange → red
RISK_COLORS = ["#0d1117", "#00AA66", "#FFAA00", "#FF6600", "#FF0000"]
RISK_LABELS = ["Closed", "Open", "Medium CVE", "High CVE", "Critical CVE"]

def build_heatmap(domain, port_results, cve_results=None):
    print(f"\n[*] Building port heatmap for {domain}")

    if not port_results:
        print("[-] No port data to visualize")
        return None

    all_hosts = list(port_results.keys())
    all_ports = sorted(set(
        p for ports in port_results.values() for p in ports.keys()
    ))

    if not all_ports:
        print("[-] No open ports found")
        return None

    # Build matrix
    matrix = []
    annotations = []

    for host in all_hosts:
        row      = []
        ann_row  = []
        for port in all_ports:
            if port in port_results.get(host, {}):
                service = port_results[host][port].get("service", "")
                score   = 1
                cve_id  = ""

                if cve_results and host in cve_results:
                    if port in cve_results[host]:
                        cves      = cve_results[host][port]
                        max_score = max((c.get("score", 0) for c in cves), default=0)
                        top_cve   = max(cves, key=lambda c: c.get("score", 0), default={})
                        cve_id    = top_cve.get("cve_id", "")[-8:] if top_cve else ""
                        if max_score >= 9.0:   score = 4
                        elif max_score >= 7.0: score = 3
                        elif max_score >= 4.0: score = 2

                row.append(score)
                label = f"{service}\n{cve_id}" if cve_id else service
                ann_row.append(label)
            else:
                row.append(0)
                ann_row.append("")
        matrix.append(row)
        annotations.append(ann_row)

    matrix_np = np.array(matrix, dtype=float)

    # ── Figure setup ────────────────────────────────
    n_ports = len(all_ports)
    n_hosts = len(all_hosts)
    fig_w   = max(14, n_ports * 1.8)
    fig_h   = max(6,  n_hosts * 1.5 + 3)

    fig, ax = plt.subplots(figsize=(fig_w, fig_h))
    fig.patch.set_facecolor("#0d1117")
    ax.set_facecolor("#0d1117")

    # Custom colormap
    cmap = mcolors.LinearSegmentedColormap.from_list(
        "reconhawk", RISK_COLORS, N=256
    )

    # Draw heatmap manually for full control
    im = ax.imshow(
        matrix_np,
        cmap=cmap, vmin=0, vmax=4,
        aspect="auto", interpolation="nearest"
    )

    # ── Grid lines ──────────────────────────────────
    ax.set_xticks(np.arange(-.5, n_ports, 1), minor=True)
    ax.set_yticks(np.arange(-.5, n_hosts, 1), minor=True)
    ax.grid(which="minor", color="#30363d", linewidth=1.5)
    ax.tick_params(which="minor", bottom=False, left=False)

    # ── Cell annotations ────────────────────────────
    for i in range(n_hosts):
        for j in range(n_ports):
            val  = matrix_np[i, j]
            text = annotations[i][j]
            if val > 0 and text:
                color = "white" if val >= 2 else "#c9d1d9"
                lines = text.split("\n")
                if len(lines) == 2:
                    ax.text(j, i - 0.12, lines[0],
                        ha="center", va="center",
                        fontsize=8, color=color,
                        fontweight="bold", fontfamily="monospace"
                    )
                    ax.text(j, i + 0.22, lines[1],
                        ha="center", va="center",
                        fontsize=6.5, color="#FFD700",
                        fontfamily="monospace"
                    )
                else:
                    ax.text(j, i, text,
                        ha="center", va="center",
                        fontsize=8, color=color,
                        fontweight="bold", fontfamily="monospace"
                    )
            elif val == 0:
                ax.text(j, i, "—",
                    ha="center", va="center",
                    fontsize=10, color="#30363d"
                )

    # ── Axes labels ─────────────────────────────────
    ax.set_xticks(range(n_ports))
    ax.set_xticklabels(
        [str(p) for p in all_ports],
        color="#8b949e", fontsize=9,
        fontfamily="monospace", rotation=45, ha="right"
    )
    ax.set_yticks(range(n_hosts))
    ax.set_yticklabels(
        all_hosts,
        color="#c9d1d9", fontsize=9,
        fontfamily="monospace"
    )

    ax.tick_params(left=False, bottom=False)
    for spine in ax.spines.values():
        spine.set_edgecolor("#30363d")

    # ── Port number header ──────────────────────────
    ax.set_xlabel("PORT NUMBER", color="#8b949e",
        fontsize=10, fontfamily="monospace",
        labelpad=10
    )
    ax.set_ylabel("TARGET HOST", color="#8b949e",
        fontsize=10, fontfamily="monospace",
        labelpad=10
    )

    # ── Title ───────────────────────────────────────
    ax.set_title(
        f"⬡  PORT EXPOSURE HEATMAP  ⬡\n{domain}",
        color="white", fontsize=14,
        fontweight="bold", fontfamily="monospace",
        pad=18
    )

    # ── Legend ──────────────────────────────────────
    legend_patches = [
        mpatches.Patch(facecolor=RISK_COLORS[i],
                       edgecolor="#444",
                       label=RISK_LABELS[i])
        for i in range(len(RISK_COLORS))
    ]
    legend = ax.legend(
        handles=legend_patches,
        loc="upper right",
        bbox_to_anchor=(1, -0.12),
        ncol=5,
        fontsize=8,
        facecolor="#161b22",
        edgecolor="#30363d",
        labelcolor="white",
        title="Risk Level",
        title_fontsize=8,
    )
    legend.get_title().set_color("#8b949e")

    # Watermark
    ax.text(0.01, -0.14, "ReconHawk — Attack Surface Intelligence",
        transform=ax.transAxes,
        fontsize=7, color="#30363d",
        ha="left", fontfamily="monospace"
    )

    plt.tight_layout(pad=2)

    output_path = os.path.join(
        config.GRAPHS_DIR, f"{domain}_port_heatmap.png"
    )
    plt.savefig(output_path, dpi=180,
        bbox_inches="tight",
        facecolor="#0d1117",
        edgecolor="none"
    )
    plt.close()
    print(f"[✓] Heatmap saved → {output_path}")
    return output_path


if __name__ == "__main__":
    test_ports = {
        "www.vulnweb.com" : {80: {"service": "http"}, 443: {"service": "https"}, 22: {"service": "ssh"}, 21: {"service": "ftp"}},
        "rest.vulnweb.com": {80: {"service": "http"}, 8080: {"service": "http-alt"}, 3306: {"service": "mysql"}},
    }
    test_cves = {
        "www.vulnweb.com" : {80: [{"score": 9.8, "severity": "CRITICAL", "cve_id": "CVE-2021-41773"}]},
        "rest.vulnweb.com": {80: [{"score": 7.5, "severity": "HIGH",     "cve_id": "CVE-2016-8743"}], 3306: [{"score": 9.0, "severity": "CRITICAL", "cve_id": "CVE-2020-14812"}]},
    }
    path = build_heatmap("vulnweb.com", test_ports, test_cves)
    print(f"Saved: {path}")
