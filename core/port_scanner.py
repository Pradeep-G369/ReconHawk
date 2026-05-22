# ReconHawk - Port Scanner Engine
import nmap
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

def scan_host(host):
    print(f"\n[*] Port scanning → {host}")
    nm = nmap.PortScanner()
    results = {}

    try:
        nm.scan(
            hosts=host,
            arguments=f"-sV -T4 --top-ports {config.TOP_PORTS} --open",
            sudo=True
        )

        print(f"    [debug] hosts found: {nm.all_hosts()}")

        found_hosts = nm.all_hosts()
        if not found_hosts:
            print(f"[-] Host unreachable or no open ports → {host}")
            return results

        for scanned_host in found_hosts:
            for proto in nm[scanned_host].all_protocols():
                ports = nm[scanned_host][proto].keys()
                for port in sorted(ports):
                    service = nm[scanned_host][proto][port]
                    if service["state"] == "open":
                        results[port] = {
                            "protocol" : proto,
                            "state"    : service["state"],
                            "service"  : service.get("name", "unknown"),
                            "product"  : service.get("product", ""),
                            "version"  : service.get("version", ""),
                            "extrainfo": service.get("extrainfo", ""),
                        }
                        print(f"    [+] {port}/{proto} → {service.get('name','unknown')} "
                              f"{service.get('product','')} {service.get('version','')}")

    except nmap.PortScannerError as e:
        print(f"[-] Nmap error: {e}")
    except Exception as e:
        print(f"[-] Scan failed for {host}: {e}")

    return results


def run(hosts):
    print("\n" + "="*50)
    print("  PORT & SERVICE SCANNER")
    print("="*50)

    all_results = {}

    for host in hosts:
        result = scan_host(host)
        if result:
            all_results[host] = result

    print(f"\n[✓] Scan complete — {len(all_results)} hosts with open ports")
    total_ports = sum(len(v) for v in all_results.values())
    print(f"[✓] Total open ports found: {total_ports}")

    return all_results


if __name__ == "__main__":
    test_hosts = ["scanme.nmap.org"]
    results = run(test_hosts)

    print("\n--- Full Results ---")
    for host, ports in results.items():
        print(f"\n{host}:")
        for port, info in ports.items():
            print(f"  {port}/{info['protocol']} {info['service']} "
                  f"{info['product']} {info['version']}")
