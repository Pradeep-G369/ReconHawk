# ReconHawk - PDF Report Generator (Redesigned)
# Professional dark-themed pentest report

from reportlab.lib.pagesizes   import A4
from reportlab.lib.styles      import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units       import cm
from reportlab.lib             import colors
from reportlab.platypus        import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable, PageBreak, Image
)
from reportlab.lib.enums       import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.platypus        import KeepTogether
import datetime, os, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from database import db_manager
from reports  import remediation_data

# ── Colour palette ────────────────────────────────
BG       = colors.HexColor("#0d1117")
CARD     = colors.HexColor("#161b22")
BORDER   = colors.HexColor("#30363d")
ACCENT   = colors.HexColor("#58a6ff")
PURPLE   = colors.HexColor("#7B2FBE")
WHITE    = colors.HexColor("#e6edf3")
MUTED    = colors.HexColor("#8b949e")
C_CRIT   = colors.HexColor("#ff6b6b")
C_HIGH   = colors.HexColor("#ffa07a")
C_MED    = colors.HexColor("#ffd700")
C_LOW    = colors.HexColor("#90ee90")
C_NONE   = colors.HexColor("#8b949e")
C_GREEN  = colors.HexColor("#34d399")

SEV_MAP  = {
    "CRITICAL": C_CRIT,
    "HIGH"    : C_HIGH,
    "MEDIUM"  : C_MED,
    "LOW"     : C_LOW,
    "NONE"    : C_NONE,
    "INFO"    : ACCENT,
}

def sc(sev):
    return SEV_MAP.get(str(sev).upper(), C_NONE)

def styles():
    return {
        "cover_title": ParagraphStyle("ct",
            fontSize=32, textColor=WHITE,
            alignment=TA_CENTER, spaceAfter=8,
            fontName="Helvetica-Bold", leading=38
        ),
        "cover_sub": ParagraphStyle("cs",
            fontSize=13, textColor=MUTED,
            alignment=TA_CENTER, spaceAfter=6
        ),
        "section": ParagraphStyle("sec",
            fontSize=14, textColor=ACCENT,
            spaceBefore=16, spaceAfter=8,
            fontName="Helvetica-Bold"
        ),
        "body": ParagraphStyle("body",
            fontSize=10, textColor=WHITE,
            spaceAfter=4, leading=15
        ),
        "small": ParagraphStyle("sm",
            fontSize=8, textColor=MUTED, spaceAfter=2
        ),
        "mono": ParagraphStyle("mono",
            fontSize=9, textColor=C_GREEN,
            fontName="Courier", spaceAfter=2
        ),
        "label": ParagraphStyle("lbl",
            fontSize=9, textColor=MUTED,
            fontName="Helvetica-Bold"
        ),
    }

def hr(color=BORDER):
    return HRFlowable(
        width="100%", color=color,
        thickness=0.5, spaceAfter=8, spaceBefore=4
    )

def section_title(text, S):
    return [
        Paragraph(text, S["section"]),
        hr(ACCENT),
        Spacer(1, 0.2*cm),
    ]

def make_table(data, col_widths, header_bg=ACCENT,
               row_colors=None, style_extra=None):
    row_colors = row_colors or [CARD, BG]
    ts = [
        ("BACKGROUND",     (0,0), (-1,0),  header_bg),
        ("TEXTCOLOR",      (0,0), (-1,0),  colors.black),
        ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",       (0,0), (-1,-1), 8.5),
        ("GRID",           (0,0), (-1,-1), 0.3, BORDER),
        ("PADDING",        (0,0), (-1,-1), 6),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), row_colors),
        ("TEXTCOLOR",      (0,1), (-1,-1), WHITE),
        ("VALIGN",         (0,0), (-1,-1), "MIDDLE"),
    ]
    if style_extra:
        ts.extend(style_extra)
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle(ts))
    return t

def generate_report(scan_id, output_path=None):
    print(f"\n[*] Generating PDF report for scan #{scan_id}")

    data     = db_manager.get_scan_data(scan_id)
    scan     = data.get("scan")
    risk     = data.get("risk")
    ports    = data.get("ports",     [])
    cves     = data.get("cves",      [])
    findings = data.get("findings",  [])
    subs     = data.get("subdomains",[])

    if not scan:
        print("[-] Scan not found")
        return None

    domain    = scan[1]
    scan_date = scan[2][:19]
    S         = styles()

    if not output_path:
        fname       = f"{domain}_ReconHawk_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
        output_path = os.path.join(config.REPORTS_DIR, fname)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=1.8*cm, rightMargin=1.8*cm,
        topMargin=1.8*cm, bottomMargin=1.8*cm,
        title=f"ReconHawk Report — {domain}",
        author="ReconHawk v1.0",
    )
    story = []

    # ── COVER PAGE ────────────────────────────────
    story.append(Spacer(1, 1.5*cm))
    story.append(Paragraph("🦅 RECONHAWK", S["cover_title"]))
    story.append(Paragraph("Attack Surface Intelligence Report", S["cover_sub"]))
    story.append(Spacer(1, 0.3*cm))
    story.append(hr(PURPLE))
    story.append(Spacer(1, 0.8*cm))

    cover = [
        ["TARGET DOMAIN",  domain],
        ["SCAN DATE",      scan_date],
        ["SCAN ID",        f"#{scan_id}"],
        ["REPORT GENERATED", datetime.datetime.now().strftime("%Y-%m-%d %H:%M")],
        ["TOOL VERSION",   "ReconHawk v1.0"],
        ["CLASSIFICATION", "CONFIDENTIAL"],
    ]
    ct = Table(cover, colWidths=[5.5*cm, 11.5*cm])
    ct.setStyle(TableStyle([
        ("BACKGROUND",     (0,0), (0,-1), CARD),
        ("BACKGROUND",     (1,0), (1,-1), BG),
        ("TEXTCOLOR",      (0,0), (0,-1), MUTED),
        ("TEXTCOLOR",      (1,0), (1,-1), WHITE),
        ("FONTNAME",       (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE",       (0,0), (-1,-1), 9.5),
        ("GRID",           (0,0), (-1,-1), 0.4, BORDER),
        ("PADDING",        (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [CARD, BG]),
    ]))
    story.append(ct)
    story.append(Spacer(1, 0.8*cm))

    # Risk score banner
    if risk:
        score = risk[3]
        sev   = risk[4]
        color = sc(sev)
        risk_banner = Table(
            [[f"OVERALL RISK SCORE", f"{score} / 10", sev]],
            colWidths=[6*cm, 5*cm, 6*cm]
        )
        risk_banner.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), CARD),
            ("TEXTCOLOR",  (0,0), (0,0),  MUTED),
            ("TEXTCOLOR",  (1,0), (1,0),  color),
            ("TEXTCOLOR",  (2,0), (2,0),  color),
            ("FONTNAME",   (0,0), (-1,-1), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,-1), 14),
            ("ALIGN",      (0,0), (-1,-1), "CENTER"),
            ("GRID",       (0,0), (-1,-1), 0.5, BORDER),
            ("PADDING",    (0,0), (-1,-1), 14),
            ("LINEABOVE",  (0,0), (-1,0),  2, color),
            ("LINEBELOW",  (0,0), (-1,0),  2, color),
        ]))
        story.append(risk_banner)

    story.append(PageBreak())

    # ── EXECUTIVE SUMMARY ─────────────────────────
    story.extend(section_title("01  EXECUTIVE SUMMARY", S))

    if risk:
        total_hosts   = len(set(p[2] for p in ports)) if ports else 0
        summary_text  = (
            f"Security assessment conducted against <b>{domain}</b> on {scan_date}. "
            f"The automated scan identified <b>{risk[5]} CVEs</b> across "
            f"<b>{len(ports)} open ports</b> on <b>{total_hosts} host(s)</b>. "
            f"Overall risk rated <b>{risk[4]}</b> with a score of <b>{risk[3]}/10</b>. "
        )
        if risk[6] > 0:
            summary_text += f"<b>{risk[6]} CRITICAL</b> findings require immediate remediation. "
        if risk[7] > 0:
            summary_text += f"<b>{risk[7]} HIGH</b> findings should be addressed within 24 hours."
        story.append(Paragraph(summary_text, S["body"]))
        story.append(Spacer(1, 0.4*cm))

        # Stats grid
        stats = [
            ["METRIC",            "VALUE", "METRIC",         "VALUE"],
            ["Subdomains Found",  str(len(subs)),
             "Open Ports",        str(len(ports))],
            ["Hosts Scanned",     str(total_hosts),
             "Total CVEs",        str(risk[5])],
            ["Critical CVEs",     str(risk[6]),
             "High CVEs",         str(risk[7])],
            ["Medium CVEs",       str(risk[8]),
             "Other Findings",    str(len(findings))],
        ]
        sg = Table(stats, colWidths=[4.5*cm, 3*cm, 4.5*cm, 3*cm])
        sg_style = [
            ("BACKGROUND",     (0,0), (-1,0),  PURPLE),
            ("TEXTCOLOR",      (0,0), (-1,0),  WHITE),
            ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
            ("BACKGROUND",     (0,1), (0,-1),  CARD),
            ("BACKGROUND",     (2,1), (2,-1),  CARD),
            ("TEXTCOLOR",      (0,1), (-1,-1), WHITE),
            ("FONTNAME",       (0,1), (0,-1),  "Helvetica-Bold"),
            ("FONTNAME",       (2,1), (2,-1),  "Helvetica-Bold"),
            ("TEXTCOLOR",      (0,1), (0,-1),  MUTED),
            ("TEXTCOLOR",      (2,1), (2,-1),  MUTED),
            ("FONTSIZE",       (0,0), (-1,-1), 9),
            ("GRID",           (0,0), (-1,-1), 0.3, BORDER),
            ("PADDING",        (0,0), (-1,-1), 7),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [CARD, BG]),
        ]
        # Color CVE counts
        cve_color_map = {2: risk[6], 3: risk[7], 4: risk[8]}
        for row_i, (col_val, color_val) in [(2, (1, C_CRIT)), (3, (1, C_HIGH)), (4, (1, C_MED))]:
            sg_style.append(("TEXTCOLOR", (1,row_i),(1,row_i), color_val))
        sg.setStyle(TableStyle(sg_style))
        story.append(sg)

    story.append(PageBreak())

    # ── CVE FINDINGS ──────────────────────────────
    story.extend(section_title("02  CVE FINDINGS", S))

    if cves:
        cve_data = [["HOST", "PORT", "CVE ID", "SCORE", "SEVERITY", "DESCRIPTION"]]
        extra = []
        for i, c in enumerate(sorted(cves, key=lambda x: float(x[5] or 0), reverse=True), 1):
            cve_data.append([
                str(c[2])[:22],
                str(c[3]),
                str(c[4]),
                str(c[5]),
                str(c[6]),
                str(c[7])[:65],
            ])
            sev = str(c[6]).upper()
            extra.append(("TEXTCOLOR", (4,i),(4,i), sc(sev)))
            extra.append(("FONTNAME",  (4,i),(4,i), "Helvetica-Bold"))
            if sev == "CRITICAL":
                extra.append(("BACKGROUND", (0,i),(-1,i), colors.HexColor("#1a0a0a")))
            elif sev == "HIGH":
                extra.append(("BACKGROUND", (0,i),(-1,i), colors.HexColor("#1a0f0a")))

        story.append(make_table(
            cve_data,
            [3.5*cm, 1.5*cm, 2.8*cm, 1.5*cm, 2.2*cm, 5.5*cm],
            style_extra=extra
        ))
    else:
        story.append(Paragraph("No CVEs recorded for this scan.", S["body"]))

    story.append(PageBreak())

    # ── SECURITY FINDINGS ─────────────────────────
    story.extend(section_title("03  SECURITY FINDINGS", S))

    if findings:
        f_data  = [["HOST", "CATEGORY", "SEVERITY", "FINDING", "DETAIL"]]
        f_extra = []
        for i, f in enumerate(
            sorted(findings, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","NONE"].index(x[4]) if x[4] in ["CRITICAL","HIGH","MEDIUM","LOW","NONE"] else 5),
            1
        ):
            f_data.append([
                str(f[2])[:20],
                str(f[3]),
                str(f[4]),
                str(f[5])[:35],
                str(f[6])[:55],
            ])
            sev = str(f[4]).upper()
            f_extra.append(("TEXTCOLOR", (2,i),(2,i), sc(sev)))
            f_extra.append(("FONTNAME",  (2,i),(2,i), "Helvetica-Bold"))

        story.append(make_table(
            f_data,
            [3*cm, 2.8*cm, 2.2*cm, 4*cm, 5*cm],
            style_extra=f_extra
        ))
    else:
        story.append(Paragraph("No additional findings recorded.", S["body"]))

    story.append(PageBreak())

    # ── OPEN PORTS ────────────────────────────────
    story.extend(section_title("04  OPEN PORTS & SERVICES", S))

    if ports:
        p_data = [["HOST", "PORT", "PROTO", "SERVICE", "PRODUCT", "VERSION"]]
        for p in ports:
            p_data.append([
                str(p[2])[:22],
                str(p[3]),
                str(p[4]),
                str(p[5]),
                str(p[6])[:16],
                str(p[7])[:16],
            ])
        story.append(make_table(
            p_data,
            [4*cm, 1.8*cm, 1.8*cm, 2.5*cm, 3*cm, 3.9*cm]
        ))
    else:
        story.append(Paragraph("No open ports recorded.", S["body"]))

    story.append(PageBreak())

    # ── REMEDIATION CHECKLIST ─────────────────────
    story.extend(section_title("05  REMEDIATION CHECKLIST", S))
    story.append(Paragraph(
        "Address findings in priority order. Critical items must be resolved "
        "before proceeding to lower severity findings.",
        S["body"]
    ))
    story.append(Spacer(1, 0.3*cm))

    rem_data  = [["#", "REMEDIATION ACTION", "PRIORITY", "EFFORT"]]
    rem_extra = []
    for i, item in enumerate(remediation_data.GENERAL_CHECKLIST, 1):
        rem_data.append([
            str(i),
            item["item"],
            item["priority"],
            item["effort"],
        ])
        p = item["priority"]
        rem_extra.append(("TEXTCOLOR", (2,i),(2,i), sc(p)))
        rem_extra.append(("FONTNAME",  (2,i),(2,i), "Helvetica-Bold"))

    story.append(make_table(
        rem_data,
        [0.8*cm, 9*cm, 2.5*cm, 4.7*cm],
        style_extra=rem_extra
    ))

    story.append(PageBreak())

    # ── SUBDOMAINS ────────────────────────────────
    if subs:
        story.extend(section_title("06  DISCOVERED SUBDOMAINS", S))
        sub_data = [["#", "SUBDOMAIN", "SOURCE"]]
        for i, s in enumerate(subs, 1):
            sub_data.append([str(i), str(s[3]), "Enumeration"])
        story.append(make_table(
            sub_data, [1*cm, 10*cm, 6*cm]
        ))
        story.append(PageBreak())

    # ── DISCLAIMER & FOOTER ───────────────────────
    story.extend(section_title("LEGAL DISCLAIMER", S))
    story.append(Paragraph(
        "This report was generated by ReconHawk for authorized security testing "
        "purposes only. All findings are based on automated analysis and should "
        "be verified by a qualified security professional before remediation. "
        "Unauthorized use of this tool against systems you do not own or have "
        "explicit written permission to test may be illegal.",
        S["body"]
    ))
    story.append(Spacer(1, 0.5*cm))
    story.append(hr(BORDER))
    story.append(Paragraph(
        f"Generated by ReconHawk v1.0  •  "
        f"github.com/Pradeep-G369/ReconHawk  •  "
        f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}",
        S["small"]
    ))

    doc.build(story)
    print(f"[✓] PDF report saved → {output_path}")
    return output_path


if __name__ == "__main__":
    from database import db_manager as db
    db.init_db()
    scans = db.get_scans()
    if scans:
        path = generate_report(scans[0][0])
        print(f"Report: {path}")
        import subprocess
        subprocess.run(["xdg-open", path])
    else:
        print("No scans found. Run main.py first.")
