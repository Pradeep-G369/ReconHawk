# ReconHawk — Complete Usage Guide

## Quick Start

```bash
# Activate virtual environment
source venv/bin/activate

# Run a full scan (requires sudo for port scanning)
sudo venv/bin/python3 main.py --target example.com

# Launch dashboard
python3 dashboard/app.py

# Open browser
# http://127.0.0.1:5000
```

## Legal Targets for Practice

Always test on targets you own or have permission to scan.
These are free legal practice targets:

| Target | Purpose |
|--------|---------|
| scanme.nmap.org | Port scanning practice (Nmap official) |
| testphp.vulnweb.com | Web vulnerability practice (Acunetix) |
| vulnweb.com | Root domain for subdomain enum |
| hackthebox.com | Create free account for lab machines |
| tryhackme.com | Create free account for guided labs |

## Getting Best Results

### 1. Add free API keys for deeper intelligence

Edit `config.py` and add:

**Shodan (free account at shodan.io)**
```python
SHODAN_API_KEY = "your_key_here"
```
Gives you: open ports from internet-wide scans, known vulnerabilities, geolocation.

**Censys (free account at censys.io)**
```python
CENSYS_API_ID     = "your_id_here"
CENSYS_API_SECRET = "your_secret_here"
```
Gives you: certificate discovery, asset enumeration.

### 2. Use a larger subdomain wordlist

Default wordlist has 5000 words. For deeper results:
```bash
# Download larger wordlist (free)
curl -o wordlists/subdomains.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt
```

### 3. Run with sudo for full port scanning

Without sudo, nmap falls back to TCP connect scan (slower, less accurate).
```bash
sudo venv/bin/python3 main.py --target example.com
```

### 4. Generate PDF report after scan

```bash
python3 reports/pdf_generator.py
```
PDF is saved to `output/reports/`

### 5. Enable continuous monitoring

```bash
# Monitor a domain every 24 hours
python3 scheduler/monitor.py example.com
```
Results stored in SQLite. Dashboard shows diff between scans.

### 6. View attack graphs

After scan, graphs are saved to `output/graphs/`:
- `domain_attack_graph.png` — node graph of attack surface
- `domain_port_heatmap.png` — heatmap of port exposure

### 7. Check alerts

```bash
cat output/alerts.log
```
Or visit `http://127.0.0.1:5000/alerts` in the dashboard.

## Dashboard Roles

| Role | URL | Best for |
|------|-----|---------|
| Analyst | /analyst/{scan_id} | Security engineers, pentesters |
| Manager | /manager/{scan_id} | CTOs, IT managers, clients |

## Interpreting Results

### Risk Score
- 9.0–10.0 = CRITICAL — immediate action required
- 7.0–8.9  = HIGH     — fix within 24 hours
- 4.0–6.9  = MEDIUM   — fix within 7 days
- 0.1–3.9  = LOW      — fix within 30 days

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

## Troubleshooting

**Port scanner returns 0 results**
```bash
# Always use sudo
sudo venv/bin/python3 main.py --target example.com
```

**crt.sh timeout**
```bash
# Increase timeout in core/subdomain_enum.py line ~25
response = requests.get(url, timeout=20)
```

**NVD API returns no CVEs**
```bash
# NVD rate-limits without API key — get a free key at
# https://nvd.nist.gov/developers/request-an-api-key
# Then add to config.py: NVD_API_KEY = "your_key"
```

**Module not found errors**
```bash
# Reinstall all dependencies
pip install -r requirements.txt
```
