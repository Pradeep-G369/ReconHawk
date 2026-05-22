# ReconHawk - SSL/TLS Certificate Analyzer
import ssl
import socket
import datetime
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

def check_ssl(host, port=443):
    print(f"\n[*] SSL/TLS check → {host}:{port}")
    results = {
        "host"           : host,
        "port"           : port,
        "has_ssl"        : False,
        "expired"        : False,
        "self_signed"    : False,
        "days_remaining" : 0,
        "protocol"       : None,
        "subject"        : {},
        "issuer"         : {},
        "valid_from"     : None,
        "valid_until"    : None,
        "findings"       : [],
    }

    try:
        # First connection — get protocol info
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode    = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                results["has_ssl"]  = True
                results["protocol"] = ssock.version()

        # Second connection — get full cert details
        context2 = ssl.create_default_context()
        context2.check_hostname = False
        context2.verify_mode    = ssl.CERT_OPTIONAL

        try:
            with socket.create_connection((host, port), timeout=8) as sock2:
                with context2.wrap_socket(sock2, server_hostname=host) as ssock2:
                    cert = ssock2.getpeercert()

                    if cert:
                        # Parse subject
                        subject_raw = cert.get("subject", ())
                        issuer_raw  = cert.get("issuer", ())
                        subject = {k: v for t in subject_raw for k, v in [t[0]]}
                        issuer  = {k: v for t in issuer_raw  for k, v in [t[0]]}

                        results["subject"] = subject
                        results["issuer"]  = issuer

                        cn  = subject.get("commonName", "unknown")
                        org = issuer.get("organizationName",
                              issuer.get("commonName", "unknown"))

                        print(f"    [+] Protocol : {results['protocol']}")
                        print(f"    [+] Subject  : {cn}")
                        print(f"    [+] Issuer   : {org}")

                        # Check expiry
                        expire_str = cert.get("notAfter", "")
                        if expire_str:
                            expire_date = datetime.datetime.strptime(
                                expire_str, "%b %d %H:%M:%S %Y %Z"
                            )
                            now  = datetime.datetime.utcnow()
                            diff = expire_date - now
                            results["valid_until"]    = expire_str
                            results["days_remaining"] = diff.days

                            if diff.days < 0:
                                results["expired"] = True
                                results["findings"].append({
                                    "issue"   : "Certificate expired",
                                    "severity": "CRITICAL",
                                    "detail"  : f"Expired {abs(diff.days)} days ago",
                                })
                                print(f"    [!!!] EXPIRED {abs(diff.days)} days ago — CRITICAL")
                            elif diff.days < 30:
                                results["findings"].append({
                                    "issue"   : "Certificate expiring soon",
                                    "severity": "HIGH",
                                    "detail"  : f"Expires in {diff.days} days",
                                })
                                print(f"    [!] Expiring in {diff.days} days — HIGH")
                            else:
                                print(f"    [+] Valid for {diff.days} more days")

                        # Check self-signed
                        if subject and issuer and subject == issuer:
                            results["self_signed"] = True
                            results["findings"].append({
                                "issue"   : "Self-signed certificate",
                                "severity": "HIGH",
                                "detail"  : "Not issued by trusted CA",
                            })
                            print(f"    [!] Self-signed — HIGH")
                        else:
                            print(f"    [+] Signed by trusted CA")

                        # Check weak protocol
                        proto = results["protocol"]
                        if proto in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
                            results["findings"].append({
                                "issue"   : f"Weak protocol: {proto}",
                                "severity": "HIGH",
                                "detail"  : f"{proto} is deprecated",
                            })
                            print(f"    [!] Weak protocol {proto} — HIGH")
                        else:
                            print(f"    [+] Protocol {proto} is acceptable")

                        if not results["findings"]:
                            print(f"    [✓] No SSL issues found")
                    else:
                        print(f"    [-] Could not retrieve cert details")

        except ssl.SSLError:
            # badssl.com expired certs fail verification — that's expected
            print(f"    [!] Certificate verification failed — likely expired or self-signed")
            results["findings"].append({
                "issue"   : "Certificate verification failed",
                "severity": "HIGH",
                "detail"  : "Could not verify certificate chain",
            })

    except ConnectionRefusedError:
        print(f"    [-] Port {port} closed — no SSL")
    except socket.timeout:
        print(f"    [-] Timed out")
    except Exception as e:
        print(f"    [-] Error: {e}")

    return results


def run(hosts):
    print("\n" + "="*50)
    print("  SSL/TLS CERTIFICATE ANALYZER")
    print("="*50)

    all_results = {}
    for host in hosts:
        result = check_ssl(host)
        all_results[host] = result

    print(f"\n--- SSL Summary ---")
    for host, result in all_results.items():
        if result["has_ssl"]:
            days     = result.get("days_remaining", 0)
            findings = len(result["findings"])
            proto    = result.get("protocol", "?")
            print(f"  {host:<35} Protocol: {proto:<10} "
                  f"Days left: {days:<6} Issues: {findings}")
        else:
            print(f"  {host:<35} No SSL detected")

    return all_results


if __name__ == "__main__":
    test_hosts = ["google.com", "expired.badssl.com", "self-signed.badssl.com"]
    results = run(test_hosts)
