# ReconHawk - Attack Surface Graph
# Visualizes subdomains, ports, and services
# as a node graph using NetworkX + Matplotlib

import matplotlib
matplotlib.use("Agg")  # non-interactive backend for server use
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import networkx as nx
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

SEVERITY_COLORS = {
    "CRITICAL": "#FF0000",
    "HIGH"    : "#FF6600",
    "MEDIUM"  : "#FFAA00",
    "LOW"     : "#00AA00",
    "NONE"    : "#4A90D9",
    "domain"  : "#7B2FBE",
    "host"    : "#1A73E8",
    "port"    : "#34A853",
}

def build_graph(domain, subdomains, port_results, cve_results=None):
    print(f"\n[*] Building attack surface graph for {domain}")
    G = nx.DiGraph()

    # Root domain node
    G.add_node(domain, node_type="domain", color=SEVERITY_COLORS["domain"])

    # Add subdomain nodes
    for sub in subdomains:
        G.add_node(sub, node_type="host", color=SEVERITY_COLORS["host"])
        G.add_edge(domain, sub)

    # Add port nodes
    for host, ports in port_results.items():
        if host not in G:
            G.add_node(host, node_type="host", color=SEVERITY_COLORS["host"])
            G.add_edge(domain, host)

        for port, info in ports.items():
            service   = info.get("service", "unknown")
            port_node = f"{host}:{port}\n({service})"

            # Color port by CVE severity if available
            color = SEVERITY_COLORS["port"]
            if cve_results and host in cve_results:
                if port in cve_results[host]:
                    cves = cve_results[host][port]
                    if any(c.get("severity") == "CRITICAL" for c in cves):
                        color = SEVERITY_COLORS["CRITICAL"]
                    elif any(c.get("severity") == "HIGH" for c in cves):
                        color = SEVERITY_COLORS["HIGH"]
                    elif any(c.get("severity") == "MEDIUM" for c in cves):
                        color = SEVERITY_COLORS["MEDIUM"]

            G.add_node(port_node, node_type="port", color=color)
            G.add_edge(host, port_node)

    # Draw
    plt.figure(figsize=(16, 10))
    plt.title(f"Attack Surface Map — {domain}", fontsize=16, fontweight="bold")

    pos    = nx.spring_layout(G, k=2, seed=42)
    colors = [G.nodes[n].get("color", "#888888") for n in G.nodes()]
    sizes  = []
    for n in G.nodes():
        ntype = G.nodes[n].get("node_type", "port")
        if ntype == "domain":
            sizes.append(3000)
        elif ntype == "host":
            sizes.append(1500)
        else:
            sizes.append(800)

    nx.draw_networkx_nodes(G, pos, node_color=colors,
                           node_size=sizes, alpha=0.9)
    nx.draw_networkx_edges(G, pos, edge_color="#CCCCCC",
                           arrows=True, arrowsize=15)
    nx.draw_networkx_labels(G, pos, font_size=7,
                            font_color="white", font_weight="bold")

    # Legend
    legend_items = [
        mpatches.Patch(color=SEVERITY_COLORS["domain"],   label="Root Domain"),
        mpatches.Patch(color=SEVERITY_COLORS["host"],     label="Host/Subdomain"),
        mpatches.Patch(color=SEVERITY_COLORS["port"],     label="Open Port"),
        mpatches.Patch(color=SEVERITY_COLORS["CRITICAL"], label="Critical CVE"),
        mpatches.Patch(color=SEVERITY_COLORS["HIGH"],     label="High CVE"),
        mpatches.Patch(color=SEVERITY_COLORS["MEDIUM"],   label="Medium CVE"),
    ]
    plt.legend(handles=legend_items, loc="upper left", fontsize=9)
    plt.axis("off")
    plt.tight_layout()

    # Save
    output_path = os.path.join(config.GRAPHS_DIR, f"{domain}_attack_graph.png")
    plt.savefig(output_path, dpi=150, bbox_inches="tight",
                facecolor="#1a1a2e")
    plt.close()

    print(f"[✓] Attack graph saved → {output_path}")
    return output_path


if __name__ == "__main__":
    test_subs  = ["www.vulnweb.com", "rest.vulnweb.com"]
    test_ports = {
        "www.vulnweb.com": {
            80 : {"service": "http",  "product": "Apache", "version": "2.4"},
            443: {"service": "https", "product": "Apache", "version": "2.4"},
        }
    }
    test_cves = {
        "www.vulnweb.com": {
            80: [{"cve_id": "CVE-2021-41773", "severity": "CRITICAL", "score": 9.8}]
        }
    }
    path = build_graph("vulnweb.com", test_subs, test_ports, test_cves)
    print(f"Graph saved at: {path}")
