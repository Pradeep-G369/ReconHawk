<div align="center">

# 🦅 ReconHawk

### Automated Reconnaissance & Attack Surface Intelligence Platform

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Checks](https://img.shields.io/badge/Security%20Checks-18+-red?style=flat-square)
![Cost](https://img.shields.io/badge/Cost-Free-brightgreen?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=flat-square)
![Version](https://img.shields.io/badge/Version-2.0-blue?style=flat-square)

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
- Finds real CVEs with CVSS scores for every detected service
- Checks SSL, DNS security, HTTP headers, misconfigurations
- Detects WAFs, tech stacks, default credentials, exposed files
- Pulls threat intelligence from Shodan and HIBP
- Generates visual attack graphs and port heatmaps
- Stores history in SQLite and diffs scans for changes
- Serves results in a role-based web dashboard
- Generates professional PDF pentest reports

**Cost: ₹0. Every tool and API used is free.**

---

## What's New in v2.0

| Improvement | Details |
|---|---|
| ⚡ Parallel execution | Phase 1, 2, 3 modules run simultaneously — 3x faster |
| 🎯 `--modules` flag | Run only the checks you need |
| 🔍 JS Secret Scanner | Finds API keys and tokens in JavaScript files |
| 🍪 Cookie security checks | Detects missing Secure, HttpOnly, SameSite flags |
| 📌 Pinned dependencies | `requirements.txt` has exact version numbers |
| 🛡️ Offline host handling | Graceful skip for unreachable targets |
| 🎨 ASCII art banner | Colored terminal banner on every run |
| 🧪 Unit tests | `tests/` folder with pytest test suite |

---

## Features

| Feature | Description |
|---|---|
| Subdomain Enumeration | Passive (crt.sh) + Active brute force |
| Port & Service Scanner | Nmap integration with version detection |
| CVE Lookup | NVD API — real CVEs with CVSS scores |
| Risk Scoring | Critical / High / Medium / Low with CVSS |
| HTTP Header Analysis | Grades security headers A–F |
| SSL/TLS Checker | Expiry, self-signed, weak protocol detection |
| WAF Detection | Cloudflare, AWS, Akamai, Imperva + 5 more |
| DNS Security | SPF, DMARC, DKIM, Zone Transfer checks |
| Misconfiguration Scan | 50+ paths checked (.git, .env, /admin, etc.) |
| Default Credentials | Tests common username/password combinations |
| JS Secret Scanner | Finds API keys, tokens in JavaScript files |
| Cookie Security | Checks Secure, HttpOnly, SameSite flags |
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
git clone https://github.com/Pradeep-G369/ReconHawk.git
cd ReconHawk

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies (pinned versions)
pip install -r requirements.txt

# Install nmap (Kali Linux — usually pre-installed)
sudo apt install nmap -y
```

---

## Usage

### Full scan (all modules)
```bash
sudo venv/bin/python3 main.py --target example.com
```

### Selective scan — run only specific modules
```bash
# Only subdomain enum + port scan + CVE lookup
python3 main.py --target example.com --modules subdomains,ports,cve

# Only header and SSL checks (no port scanning needed)
python3 main.py --target example.com --modules headers,ssl,dns

# Everything EXCEPT ssl and waf (faster)
python3 main.py --target example.com --modules -ssl,-waf

# See all available modules
python3 main.py --help
```

### Available modules
subdomains  ports      dns        cve        cvss
headers     ssl        waf        tech       misconfig
creds       intel      alerts     graphs     report
### Launch the web dashboard
```bash
python3 dashboard/app.py
# Open http://127.0.0.1:5000
```

### Generate PDF report
```bash
python3 reports/pdf_generator.py
```

### Enable continuous monitoring (every 24 hours)
```bash
python3 scheduler/monitor.py example.com
```

### Run tests
```bash
pip install pytest
pytest tests/ -v
```

---

## Legal Practice Targets

Always test on targets you own or have permission to scan.
These are free legal practice targets:

| Target | Purpose |
|---|---|
| `scanme.nmap.org` | Port scanning practice (Nmap official) |
| `testphp.vulnweb.com` | Web vulnerability practice (Acunetix) |
| `vulnweb.com` | Root domain for subdomain enumeration |
| `hackthebox.com` | Create free account for lab machines |
| `tryhackme.com` | Create free account for guided labs |

---

## Getting Best Results

### 1. Add free API keys for deeper intelligence

Edit `config.py` and add:

**Shodan** (free account at shodan.io)
```python
SHODAN_API_KEY = "your_key_here"
```
Gives you: open ports from internet-wide scans, known vulnerabilities, geolocation.

**Censys** (free account at censys.io)
```python
CENSYS_API_ID     = "your_id_here"
CENSYS_API_SECRET = "your_secret_here"
```
Gives you: certificate discovery, asset enumeration.

### 2. Use a larger subdomain wordlist
```bash
# Default wordlist has 5000 words. For deeper results:
curl -o wordlists/subdomains.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt
```

### 3. Run with sudo for full port scanning
```bash
# Without sudo, nmap falls back to TCP connect scan (slower, less accurate)
sudo venv/bin/python3 main.py --target example.com
```

### 4. Generate PDF report after scan
```bash
python3 reports/pdf_generator.py
# Report saved to output/reports/
```

### 5. Enable continuous monitoring
```bash
# Monitor a domain every 24 hours
python3 scheduler/monitor.py example.com
# Results stored in SQLite. Dashboard shows diff between scans.
```

### 6. Check alerts log
```bash
cat output/alerts.log
# Or visit http://127.0.0.1:5000/alerts in the dashboard
```

---

## Dashboard Roles

| Role | URL | Best for |
|---|---|---|
| Overview | `/` | Quick summary of latest scan |
| Analyst | `/analyst/{scan_id}` | Security engineers, pentesters |
| Manager | `/manager/{scan_id}` | CTOs, IT managers, clients |

---

## Interpreting Results

### Risk Score
- `9.0–10.0` = CRITICAL — immediate action required
- `7.0–8.9`  = HIGH     — fix within 24 hours
- `4.0–6.9`  = MEDIUM   — plan remediation
- `0.1–3.9`  = LOW      — monitor and schedule

### Common Findings Explained

**Missing HSTS** — Site can be downgraded from HTTPS to HTTP by attacker.
Fix: Add `Strict-Transport-Security` header.

**Missing CSP** — Site is vulnerable to Cross-Site Scripting (XSS).
Fix: Add `Content-Security-Policy` header.

**Exposed .git** — Attacker can download your entire source code.
Fix: Block `.git` in web server config immediately.

**No SPF/DMARC** — Anyone can send emails pretending to be your domain.
Fix: Add SPF and DMARC DNS records.

**Self-signed cert** — Browser warnings, vulnerable to MITM attacks.
Fix: Use Let's Encrypt (free) to get a trusted certificate.

---

## Project Structure
ReconHawk/
├── core/               # 15 scanning & intelligence modules
│   ├── subdomain_enum.py
│   ├── port_scanner.py
│   ├── cve_lookup.py
│   ├── cvss_scorer.py
│   ├── header_analyzer.py  # includes cookie security checks
│   ├── ssl_checker.py
│   ├── waf_detector.py
│   ├── dns_checker.py
│   ├── misconfig_checker.py
│   ├── default_creds.py
│   ├── tech_fingerprint.py
│   ├── threat_intel.py
│   └── js_secret_scanner.py  ← NEW in v2.0
├── database/           # SQLite storage, history, diff engine
├── scheduler/          # Continuous monitoring
├── dashboard/          # Flask web dashboard
├── reports/            # PDF report generator
├── visualizations/     # Attack graphs and heatmaps
├── alerts/             # Critical finding alerts
├── tests/              # pytest unit tests  ← NEW in v2.0
├── wordlists/          # Subdomain and credential wordlists
├── output/             # Scan results, graphs, reports (auto-created)
├── main.py             # Master entry point
└── config.py           # Central configuration
---

## Troubleshooting

**Port scanner returns 0 results**
```bash
# Always use sudo for full scan capability
sudo venv/bin/python3 main.py --target example.com
```

**crt.sh returns 0 subdomains**
```bash
# Normal for small domains — use active brute force only
python3 main.py --target example.com --modules subdomains,ports
```

**NVD API returns no CVEs**
```bash
# NVD rate-limits without API key — get a free key at:
# https://nvd.nist.gov/developers/request-an-api-key
# Then add to config.py: NVD_API_KEY = "your_key"
```

**Module not found errors**
```bash
pip install -r requirements.txt
```

**Scan is slow**
```bash
# Use --modules to run only what you need
python3 main.py --target example.com --modules subdomains,ports,cve
```

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
<br>
github.com/Pradeep-G369/ReconHawk
</div>
