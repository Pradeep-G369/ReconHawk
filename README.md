<div align="center">
### Automated Reconnaissance & Attack Surface Intelligence Platform

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Checks](https://img.shields.io/badge/Security%20Checks-18+-red?style=flat-square)
![Cost](https://img.shields.io/badge/Cost-Free-brightgreen?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=flat-square)

**The only free, open-source tool that combines recon, CVE mapping,
visualization, role-based dashboard, continuous monitoring,
and professional PDF reporting in one place.**

</div>

---

## What is ReconHawk?

ReconHawk is a Python-based security intelligence platform built for
bug bounty hunters, pentesters, sysadmins, and security students.
Point it at a domain and it automatically:

- Maps the entire attack surface (subdomains, ports, services)
- Finds real CVEs with CVSS scores for every service
- Checks SSL, DNS security, HTTP headers, misconfigurations
- Detects WAFs, tech stacks, default credentials, exposed files
- Pulls threat intelligence from Shodan and HIBP
- Generates visual attack graphs and port heatmaps
- Stores history in SQLite and diffs scans for changes
- Serves results in a role-based web dashboard
- Generates professional PDF pentest reports

**Cost: ₹0. Every tool and API used is free.**

---

## Features

| Feature | Description |
|---------|-------------|
| Subdomain Enumeration | Passive (crt.sh) + Active brute force |
| Port & Service Scanner | Nmap integration with version detection |
| CVE Lookup | NVD API — real CVEs with CVSS scores |
| Risk Scoring | Critical / High / Medium / Low with weighted scoring |
| HTTP Header Analysis | Grades security headers A–F |
| SSL/TLS Checker | Expiry, self-signed, weak protocol detection |
| WAF Detection | Cloudflare, AWS, Akamai, Imperva + 5 more |
| DNS Security | SPF, DMARC, DKIM, Zone Transfer checks |
| Misconfiguration Scan | 50+ paths checked (.git, .env, /admin, etc.) |
| Default Credentials | Tests common username/password combinations |
| Tech Fingerprinting | WordPress, Apache, PHP, React + 10 more |
| Threat Intelligence | Shodan + HIBP breach data (free tiers) |
| Attack Surface Graph | NetworkX + Matplotlib node visualization |
| Port Heatmap | Seaborn risk heatmap across all hosts |
| Role-based Dashboard | Analyst view + Manager/Executive view |
| Continuous Monitoring | Cron/schedule daily/weekly scans |
| Scan Diff Engine | New vs old findings comparison |
| PDF Reports | Professional pentest-style reports with ReportLab |

---

## Installation

```bash
# Clone the repository
git clone https://github.com/YourUsername/ReconHawk.git
cd ReconHawk

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install nmap (Kali Linux — usually pre-installed)
sudo apt install nmap -y
```

---

## Usage

```bash
# Full scan
sudo venv/bin/python3 main.py --target example.com

# Launch dashboard
python3 dashboard/app.py
# Open http://127.0.0.1:5000

# Generate PDF report
python3 reports/pdf_generator.py

# Continuous monitoring (every 24 hours)
python3 scheduler/monitor.py example.com
```

---

## Legal Practice Targets
scanme.nmap.org       — Nmap's official scan practice target
testphp.vulnweb.com   — Acunetix's deliberately vulnerable app
vulnweb.com           — Root domain for subdomain enumeration
---

## Project Structure
ReconHawk/
├── core/               # 13 scanning & intelligence modules
├── database/           # SQLite storage, history, diff engine
├── scheduler/          # Continuous monitoring
├── dashboard/          # Flask web dashboard
├── reports/            # PDF report generator
├── visualizations/     # Attack graphs and heatmaps
├── alerts/             # Critical finding alerts
├── wordlists/          # Subdomain and credential wordlists
├── output/             # Scan results, graphs, reports
├── main.py             # Master entry point
└── config.py           # Central configuration
---

## Dashboard Screenshots

| Analyst View | Manager View |
|-------------|-------------|
| Full CVE tables, port data, findings | Executive summary, risk chart, remediation checklist |

---

## ⚠️ Legal Disclaimer

ReconHawk is intended for authorized security testing only.
Only scan targets you own or have explicit written permission to test.
Unauthorized scanning may be illegal in your jurisdiction.
The authors assume no liability for misuse of this tool.

---

## Contributing

Pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

MIT License — see [LICENSE](LICENSE)

---

<div align="center">
Built with Python · Zero budget · Open source
</div>
