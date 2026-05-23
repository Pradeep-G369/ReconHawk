# ReconHawk - Cyberpunk PDF Generator (Corrected Signature)
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# Futuristic Color Palette
BG_COLOR = colors.HexColor("#0a0a0f")
TEXT_MAIN = colors.HexColor("#00f0ff")
TEXT_ALT = colors.HexColor("#c9d1d9")
ACCENT = colors.HexColor("#ff003c")
TABLE_BG = colors.HexColor("#12121a")

def draw_background(canvas, doc):
    """Draws a dark terminal background with a neon border on every page."""
    canvas.saveState()
    canvas.setFillColor(BG_COLOR)
    canvas.rect(0, 0, doc.pagesize[0], doc.pagesize[1], fill=True, stroke=False)
    
    # Neon Border
    canvas.setStrokeColor(TEXT_MAIN)
    canvas.setLineWidth(1)
    canvas.rect(0.3*inch, 0.3*inch, doc.pagesize[0]-0.6*inch, doc.pagesize[1]-0.6*inch)
    
    # Terminal Header
    canvas.setFillColor(ACCENT)
    canvas.setFont("Courier-Bold", 10)
    canvas.drawString(0.4*inch, doc.pagesize[1] - 0.5*inch, "SYSTEM // RECONHAWK // CLASSIFIED INTEL")
    canvas.restoreState()

def build_report(domain, risk_summary, heatmap_img=None, graph_img=None):
    print("\n[*] Generating Classified Cyberpunk PDF Report...")
    
    os.makedirs(config.REPORTS_DIR, exist_ok=True)
    output_path = os.path.join(config.REPORTS_DIR, f"{domain}_classified_report.pdf")
    
    doc = SimpleDocTemplate(output_path, pagesize=letter, topMargin=0.8*inch, bottomMargin=0.8*inch)
    elements = []
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('CyberTitle', fontName='Courier-Bold', fontSize=26, color=ACCENT, alignment=1, spaceAfter=30)
    h2_style = ParagraphStyle('CyberH2', fontName='Courier-Bold', fontSize=16, color=TEXT_MAIN, spaceAfter=15)
    body_style = ParagraphStyle('CyberBody', fontName='Courier', fontSize=11, color=TEXT_ALT, spaceAfter=10)

    # Title Page
    elements.append(Spacer(1, 2*inch))
    elements.append(Paragraph("/// TACTICAL INTELLIGENCE REPORT ///", title_style))
    elements.append(Spacer(1, 0.5*inch))
    elements.append(Paragraph(f"<b>TARGET:</b> {domain}", h2_style))
    elements.append(Paragraph(f"<b>RISK SCORE:</b> {risk_summary.get('overall_score', 'N/A')} / 10", body_style))
    elements.append(PageBreak())

    # Vuln Matrix Table
    elements.append(Paragraph("> VULNERABILITY_MATRIX", h2_style))
    data = [["SEVERITY", "VULNERABILITIES FOUND"]]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = risk_summary.get('counts', {}).get(sev, 0)
        data.append([sev, str(count)])
        
    t = Table(data, colWidths=[3*inch, 3*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), ACCENT),
        ('TEXTCOLOR', (0,0), (-1,0), BG_COLOR),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('FONTNAME', (0,0), (-1,-1), 'Courier-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,0), 12),
        ('BACKGROUND', (0,1), (-1,-1), TABLE_BG),
        ('TEXTCOLOR', (0,1), (-1,-1), TEXT_ALT),
        ('GRID', (0,0), (-1,-1), 1, TEXT_MAIN)
    ]))
    elements.append(t)
    elements.append(Spacer(1, 0.5*inch))

    # Add Graphs
    if heatmap_img and os.path.exists(heatmap_img):
        elements.append(Paragraph("> EXPOSED_PORT_TOPOLOGY", h2_style))
        elements.append(Image(heatmap_img, width=6.5*inch, height=2.8*inch))
        elements.append(Spacer(1, 0.3*inch))

    if graph_img and os.path.exists(graph_img):
        elements.append(Paragraph("> THREAT_VECTOR_ANALYSIS", h2_style))
        elements.append(Image(graph_img, width=6.5*inch, height=4.5*inch))

    doc.build(elements, onFirstPage=draw_background, onLaterPages=draw_background)
    print(f" [v] Classified Report generated: {output_path}")
    return output_path
