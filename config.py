# ReconHawk - Central Configuration
# All settings, API keys, and paths live here
# Every module imports from this file

import os

# ─────────────────────────────────────────
# TARGET
# ─────────────────────────────────────────
TARGET_DOMAIN = ""  # Set via CLI in main.py

# ─────────────────────────────────────────
# FREE API KEYS
# Sign up once, paste your key below
# ─────────────────────────────────────────
SHODAN_API_KEY  = "YOUR_SHODAN_API_KEY"   # shodan.io (free account)
CENSYS_API_ID   = "YOUR_CENSYS_API_ID"    # censys.io (free account)
CENSYS_API_SECRET = "YOUR_CENSYS_SECRET"  # censys.io (free account)
# NVD API and HIBP need no key for basic use

# ─────────────────────────────────────────
# PATHS
# ─────────────────────────────────────────
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR      = os.path.join(BASE_DIR, "output")
REPORTS_DIR     = os.path.join(BASE_DIR, "output", "reports")
GRAPHS_DIR      = os.path.join(BASE_DIR, "output", "graphs")
DB_PATH         = os.path.join(BASE_DIR, "output", "reconhawk.db")
ALERTS_LOG      = os.path.join(BASE_DIR, "output", "alerts.log")
WORDLIST_PATH   = os.path.join(BASE_DIR, "wordlists", "subdomains.txt")
CREDS_PATH      = os.path.join(BASE_DIR, "wordlists", "default_creds.txt")

# ─────────────────────────────────────────
# SCANNING SETTINGS
# ─────────────────────────────────────────
PORT_SCAN_TIMEOUT   = 2       # seconds per port
TOP_PORTS           = 1000    # how many ports to scan
SUBDOMAIN_THREADS   = 10      # parallel threads for subdomain brute force
REQUEST_TIMEOUT     = 5       # HTTP request timeout in seconds
MAX_RETRIES         = 2       # retry failed requests

# ─────────────────────────────────────────
# SEVERITY LEVELS (CVSS based)
# ─────────────────────────────────────────
SEVERITY = {
    "CRITICAL" : (9.0, 10.0),
    "HIGH"     : (7.0, 8.9),
    "MEDIUM"   : (4.0, 6.9),
    "LOW"      : (0.1, 3.9),
    "NONE"     : (0.0, 0.0),
}

# ─────────────────────────────────────────
# MONITORING SCHEDULE
# ─────────────────────────────────────────
SCAN_INTERVAL_HOURS = 24      # how often continuous monitor runs

# ─────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────
FLASK_HOST  = "127.0.0.1"
FLASK_PORT  = 5000
FLASK_DEBUG = False

# ─────────────────────────────────────────
# CREATE OUTPUT FOLDERS ON IMPORT
# ─────────────────────────────────────────
for _dir in [OUTPUT_DIR, REPORTS_DIR, GRAPHS_DIR]:
    os.makedirs(_dir, exist_ok=True)
