# ReconHawk - Futuristic Attack Graph (Corrected Signature)
import networkx as nx
import matplotlib.pyplot as plt
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

def build_graph(domain, subdomains, port_results, cve_results):
    print("\n[*] Generating Futuristic Attack Graph...")
    G = nx.Graph()
    
    # 1. Add the main domain as the center node
    G.add_node(domain, type='domain', color='#ffffff', size=1500) # White center
    
    # 2. Link subdomains to the main domain
    if subdomains:
        for sub in subdomains:
            G.add_node(sub, type='host', color='#00f0ff', size=1000) # Neon Cyan
            G.add_edge(domain, sub, color='#00f0ff')
            
    # 3. Add ports and CVEs
    for host, ports in cve_results.items():
        # Ensure the host is in the graph (in case it wasn't in the subdomains list)
        if host not in G.nodes:
            G.add_node(host, type='host', color='#00f0ff', size=1000)
            G.add_edge(domain, host, color='#00f0ff')
            
        for port, cves in ports.items():
            port_node = f"{host}:{port}"
            G.add_node(port_node, type='port', color='#b026ff', size=700) # Neon Purple
            G.add_edge(host, port_node, color='#b026ff')
            
            for cve in cves:
                sev = cve.get('severity', 'LOW').upper()
                if sev == 'CRITICAL': cve_color = '#ff003c' # Neon Red
                elif sev == 'HIGH': cve_color = '#ff8a00'   # Neon Orange
                elif sev == 'MEDIUM': cve_color = '#fcee0a' # Neon Yellow
                else: cve_color = '#00ff00'                 # Neon Green
                
                G.add_node(cve['cve_id'], type='cve', color=cve_color, size=500)
                G.add_edge(port_node, cve['cve_id'], color=cve_color)
                
    if len(G.nodes) == 0:
        print(" [-] No attack paths to graph.")
        return None

    # --- FUTURISTIC STYLING ---
    plt.style.use("dark_background")
    fig, ax = plt.subplots(figsize=(14, 10))
    fig.patch.set_facecolor('#0a0a0f')
    ax.set_facecolor('#0a0a0f')
    
    pos = nx.spring_layout(G, k=0.6, seed=42)
    
    node_colors = [nx.get_node_attributes(G, 'color').get(node, '#ffffff') for node in G.nodes()]
    node_sizes = [nx.get_node_attributes(G, 'size').get(node, 500) for node in G.nodes()]
    edge_colors = [nx.get_edge_attributes(G, 'color').get(edge, '#ffffff') for edge in G.edges()]
    
    nx.draw_networkx_edges(G, pos, ax=ax, edge_color=edge_colors, alpha=0.6, width=2.0)
    nx.draw_networkx_nodes(G, pos, ax=ax, node_color=node_colors, node_size=node_sizes, edgecolors='white', linewidths=1.5)
    
    nx.draw_networkx_labels(G, pos, ax=ax, font_color='white', font_size=8, font_weight='bold')
    
    plt.title("/// RECONHAWK : THREAT_TOPOLOGY_MAP ///", color='#00f0ff', fontsize=18, fontweight='bold', pad=20)
    plt.axis('off')
    
    # Ensure directory exists before saving
    os.makedirs(config.GRAPHS_DIR, exist_ok=True)
    output_path = os.path.join(config.GRAPHS_DIR, "attack_graph.png")
    
    plt.tight_layout()
    plt.savefig(output_path, facecolor=fig.get_facecolor(), dpi=300)
    plt.close()
    
    print(f" [+] Attack graph saved to {output_path}")
    return output_path
