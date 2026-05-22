# ReconHawk - Flask Dashboard
# Role-based views: Analyst (deep) + Manager (summary)

from flask import Flask, render_template, request, jsonify, send_file
import sqlite3
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from database import db_manager

app = Flask(__name__)

# ─────────────────────────────────────────
# HOME — list all scans
# ─────────────────────────────────────────
@app.route("/")
def index():
    db_manager.init_db()
    conn = sqlite3.connect(config.DB_PATH)
    c    = conn.cursor()
    c.execute("SELECT * FROM scans ORDER BY scan_date DESC")
    scans = c.fetchall()
    conn.close()
    return render_template("index.html", scans=scans)


# ─────────────────────────────────────────
# ANALYST VIEW — full technical details
# ─────────────────────────────────────────
@app.route("/analyst/<int:scan_id>")
def analyst_view(scan_id):
    data = db_manager.get_scan_data(scan_id)
    return render_template("analyst.html", data=data, scan_id=scan_id)


# ─────────────────────────────────────────
# MANAGER VIEW — executive summary
# ─────────────────────────────────────────
@app.route("/manager/<int:scan_id>")
def manager_view(scan_id):
    data = db_manager.get_scan_data(scan_id)
    return render_template("manager.html", data=data, scan_id=scan_id)


# ─────────────────────────────────────────
# API — scan data as JSON for charts
# ─────────────────────────────────────────
@app.route("/api/scan/<int:scan_id>")
def api_scan(scan_id):
    data = db_manager.get_scan_data(scan_id)
    risk = data.get("risk")
    return jsonify({
        "scan_id"         : scan_id,
        "overall_score"   : risk[3] if risk else 0,
        "overall_severity": risk[4] if risk else "NONE",
        "total_cves"      : risk[5] if risk else 0,
        "critical"        : risk[6] if risk else 0,
        "high"            : risk[7] if risk else 0,
        "medium"          : risk[8] if risk else 0,
        "low"             : risk[9] if risk else 0,
        "ports"           : len(data.get("ports", [])),
        "subdomains"      : len(data.get("subdomains", [])),
        "findings"        : len(data.get("findings", [])),
    })


# ─────────────────────────────────────────
# GRAPH — serve generated graph images
# ─────────────────────────────────────────
@app.route("/graph/<filename>")
def serve_graph(filename):
    path = os.path.join(config.GRAPHS_DIR, filename)
    if os.path.exists(path):
        return send_file(path, mimetype="image/png")
    return "Graph not found", 404


# ─────────────────────────────────────────
# ALERTS — show alerts log
# ─────────────────────────────────────────
@app.route("/alerts")
def alerts():
    alert_lines = []
    if os.path.exists(config.ALERTS_LOG):
        with open(config.ALERTS_LOG, "r") as f:
            alert_lines = f.readlines()
    return render_template("alerts.html", alerts=alert_lines)


if __name__ == "__main__":
    db_manager.init_db()
    app.run(
        host =config.FLASK_HOST,
        port =config.FLASK_PORT,
        debug=True
    )
