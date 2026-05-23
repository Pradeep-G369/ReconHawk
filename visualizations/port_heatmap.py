# ReconHawk - Futuristic Port Heatmap (Corrected Signature)
import seaborn as sns
import matplotlib.pyplot as plt
import pandas as pd
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

def build_heatmap(domain, port_results, cve_results):
    print("\n[*] Generating Matrix Port Heatmap...")
    data = []
    
    # Process port_results
    for host, ports in port_results.items():
        for port, info in ports.items():
            service_name = info.get('service', 'unknown')
            data.append({"Target": host, "Exposed Port": f"{port} ({service_name})", "Status": 1})
            
    if not data:
        print(" [-] No open ports to graph.")
        return None
        
    df = pd.DataFrame(data).pivot_table(index='Target', columns='Exposed Port', values='Status', fill_value=0)
    
    # --- FUTURISTIC STYLING ---
    plt.style.use("dark_background")
    fig, ax = plt.subplots(figsize=(12, 5))
    fig.patch.set_facecolor('#0a0a0f')
    ax.set_facecolor('#0a0a0f')
    
    # Custom Neon Cyan/Blue gradient
    cmap = sns.dark_palette("#00f0ff", as_cmap=True)
    
    sns.heatmap(df, cmap=cmap, linewidths=1.5, linecolor='#111111', 
                cbar=False, annot=True, annot_kws={"color": "white", "weight": "bold"}, ax=ax)
    
    ax.tick_params(colors='#00f0ff', labelsize=11)
    ax.xaxis.label.set_color('#b026ff')
    ax.yaxis.label.set_color('#b026ff')
    
    plt.title(f"/// EXPOSED_PORT_MATRIX : {domain} ///", color='#b026ff', fontsize=16, fontweight='bold', pad=20)
    plt.tight_layout()
    
    os.makedirs(config.GRAPHS_DIR, exist_ok=True)
    output_path = os.path.join(config.GRAPHS_DIR, "port_heatmap.png")
    plt.savefig(output_path, facecolor=fig.get_facecolor(), dpi=300)
    plt.close()
    
    print(f" [+] Heatmap saved to {output_path}")
    return output_path
