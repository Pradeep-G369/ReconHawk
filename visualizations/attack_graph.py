# ReconHawk - Attack Surface Graph (Redesigned)
# Dark futuristic theme with clear node hierarchy

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.patheffects as pe
import networkx as nx
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

def build_graph(domain, subdomains, port_results, cve_results=None):
    print(f"\n[*] Building attack surface graph for {domain}")
    G = nx.DiGraph()

    # Add root domain
    G.add_node(domain, node_type="domain")

    # Add subdomains
    for sub in subdomains:
        G.add_node(sub, node_type="host")
        G.add_edge(domain, sub)

    # Add port nodes
    for host, ports in port_results.items():
        if host not in G:
            G.add_node(host, node_type="host")
            G.add_edge(domain, host)
        for port, info in ports.items():
            service   = info.get("service", "unknown")
            version   = info.get("version", "")[:15]
            port_label = f"{port}/{service}"

            # Determine risk color
            risk = "open"
            if cve_results and host in cve_results:
                if port in cve_results[host]:
                    cves = cve_results[host][port]
                    max_score = max((c.get("score", 0) for c in cves), default=0)
                    if max_score >= 9.0:   risk = "critical"
                    elif max_score >= 7.0: risk = "high"
                    elif max_score >= 4.0: risk = "medium"

            G.add_node(port_label, node_type="port", risk=risk, version=version)
            G.add_edge(host, port_label)

    # ── Layout ──────────────────────────────────────
    fig, ax = plt.subplots(figsize=(18, 12))
    fig.patch.set_facecolor("#0d1117")
    ax.set_facecolor("#0d1117")

    # Use hierarchical layout
    pos = nx.spring_layout(G, k=3.5, seed=42, iterations=100)

    # ── Draw edges ──────────────────────────────────
    nx.draw_networkx_edges(
        G, pos, ax=ax,
        edge_color="#30363d",
        arrows=True,
        arrowsize=15,
        arrowstyle="->",
        width=1.2,
        alpha=0.7,
        connectionstyle="arc3,rad=0.05"
    )

    # ── Draw nodes by type ──────────────────────────
    domain_nodes = [n for n in G.nodes() if G.nodes[n].get("node_type") == "domain"]
    host_nodes   = [n for n in G.nodes() if G.nodes[n].get("node_type") == "host"]
    port_nodes   = {
        "critical": [n for n in G.nodes() if G.nodes[n].get("node_type") == "port" and G.nodes[n].get("risk") == "critical"],
        "high"    : [n for n in G.nodes() if G.nodes[n].get("node_type") == "port" and G.nodes[n].get("risk") == "high"],
        "medium"  : [n for n in G.nodes() if G.nodes[n].get("node_type") == "port" and G.nodes[n].get("risk") == "medium"],
        "open"    : [n for n in G.nodes() if G.nodes[n].get("node_type") == "port" and G.nodes[n].get("risk") == "open"],
    }

    # Domain node — large purple glowing
    nx.draw_networkx_nodes(G, pos, ax=ax,
        nodelist=domain_nodes, node_size=4000,
        node_color="#7B2FBE", alpha=0.95,
        linewidths=3, edgecolors="#A855F7"
    )

    # Host nodes — blue
    nx.draw_networkx_nodes(G, pos, ax=ax,
        nodelist=host_nodes, node_size=2000,
        node_color="#1A73E8", alpha=0.9,
        linewidths=2, edgecolors="#60A5FA"
    )

    # Port nodes by risk
    colors = {
        "critical": ("#FF0000", "#FF6B6B", 1200),
        "high"    : ("#FF6600", "#FFA07A", 1000),
        "medium"  : ("#FFAA00", "#FFD700", 900),
        "open"    : ("#00AA66", "#34D399", 800),
    }
    for risk_level, (fill, edge, size) in colors.items():
        if port_nodes[risk_level]:
            nx.draw_networkx_nodes(G, pos, ax=ax,
                nodelist=port_nodes[risk_level],
                node_size=size,
                node_color=fill, alpha=0.9,
                linewidths=1.5, edgecolors=edge
            )

    # ── Labels ──────────────────────────────────────
    # Domain label
    domain_labels = {n: n for n in domain_nodes}
    nx.draw_networkx_labels(G, pos, ax=ax,
        labels=domain_labels,
        font_size=11, font_color="white",
        font_weight="bold",
        font_family="monospace"
    )

    # Host labels
    host_labels = {n: n.split(".")[0] for n in host_nodes}
    nx.draw_networkx_labels(G, pos, ax=ax,
        labels=host_labels,
        font_size=9, font_color="white",
        font_weight="bold"
    )

    # Port labels
    all_port_nodes = [n for n in G.nodes() if G.nodes[n].get("node_type") == "port"]
    port_labels = {n: n for n in all_port_nodes}
    nx.draw_networkx_labels(G, pos, ax=ax,
        labels=port_labels,
        font_size=8, font_color="white"
    )

    # ── Title & Legend ───────────────────────────────
    ax.set_title(
        f"⬡  ATTACK SURFACE MAP  ⬡\n{domain}",
        color="white", fontsize=16,
        fontweight="bold", fontfamily="monospace",
        pad=20
    )

    legend_items = [
        mpatches.Patch(facecolor="#7B2FBE", edgecolor="#A855F7", label="Root Domain"),
        mpatches.Patch(facecolor="#1A73E8", edgecolor="#60A5FA", label="Host / Subdomain"),
        mpatches.Patch(facecolor="#00AA66", edgecolor="#34D399", label="Open Port (safe)"),
        mpatches.Patch(facecolor="#FFAA00", edgecolor="#FFD700", label="Medium CVE"),
        mpatches.Patch(facecolor="#FF6600", edgecolor="#FFA07A", label="High CVE"),
        mpatches.Patch(facecolor="#FF0000", edgecolor="#FF6B6B", label="Critical CVE"),
    ]
    legend = ax.legend(
        handles=legend_items,
        loc="lower left",
        fontsize=9,
        facecolor="#161b22",
        edgecolor="#30363d",
        labelcolor="white",
        title="Node Types",
        title_fontsize=9,
    )
    legend.get_title().set_color("#8b949e")

    # Watermark
    ax.text(0.99, 0.01, "ReconHawk",
        transform=ax.transAxes,
        fontsize=8, color="#30363d",
        ha="right", va="bottom",
        fontfamily="monospace"
    )

    ax.axis("off")
    plt.tight_layout(pad=2)

    output_path = os.path.join(
        config.GRAPHS_DIR, f"{domain}_attack_graph.png"
    )
    plt.savefig(output_path, dpi=180,
        bbox_inches="tight",
        facecolor="#0d1117",
        edgecolor="none"
    )
    plt.close()
    print(f"[✓] Attack graph saved → {output_path}")
    return output_path


if __name__ == "__main__":
    test_subs  = ["www.vulnweb.com", "rest.vulnweb.com"]
    test_ports = {
        "www.vulnweb.com" : {80: {"service": "http",  "product": "Apache", "version": "2.4"}, 443: {"service": "https", "product": "Apache", "version": "2.4"}},
        "rest.vulnweb.com": {80: {"service": "http",  "product": "Apache", "version": "2.4"}, 22 : {"service": "ssh",   "product": "OpenSSH","version": "7.4"}},
    }
    test_cves = {
        "www.vulnweb.com": {80: [{"score": 9.8, "severity": "CRITICAL"}]},
        "rest.vulnweb.com": {80: [{"score": 7.5, "severity": "HIGH"}]},
    }
    path = build_graph("vulnweb.com", test_subs, test_ports, test_cves)
    print(f"Saved: {path}")
