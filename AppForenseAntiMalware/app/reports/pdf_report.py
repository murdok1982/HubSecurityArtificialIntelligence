from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
import os
import json

def generate_pdf_report(case, output_path):
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    story.append(Paragraph(f"Malware Analysis Report: {case.original_filename}", styles['Title']))
    story.append(Spacer(1, 12))
    
    # Basic Info
    data = [
        ["Case ID", case.id],
        ["File Name", case.original_filename],
        ["File Size", f"{case.file_size} bytes"],
        ["MD5", case.md5],
        ["SHA256", case.sha256],
        ["Risk Score", f"{case.risk_score}/100"]
    ]
    t = Table(data)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.grey),
        ('TEXTCOLOR', (0, 0), (0, -1), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('BACKGROUND', (1, 0), (1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    story.append(t)
    story.append(Spacer(1, 24))
    
    # Static Analysis
    story.append(Paragraph("Static Analysis Results", styles['Heading2']))
    static_data = case.analysis_results.get("static", {})
    if static_data:
        p_text = f"Entropy: {static_data.get('entropy', 'N/A')}<br/>"
        story.append(Paragraph(p_text, styles['Normal']))
        
        pe_info = static_data.get("pe_info", {})
        if pe_info and "error" not in pe_info:
            story.append(Paragraph("PE Sections:", styles['Heading3']))
            section_data = [["Name", "Virtual Size", "Entropy"]]
            for sec in pe_info.get("sections", []):
                section_data.append([sec['name'], sec['virtual_size'], f"{sec['entropy']:.2f}"])
            t_sec = Table(section_data)
            t_sec.setStyle(TableStyle([('GRID', (0, 0), (-1, -1), 0.5, colors.grey)]))
            story.append(t_sec)
    else:
        story.append(Paragraph("No static analysis data available.", styles['Normal']))

    story.append(Spacer(1, 24))

    # YARA matches
    story.append(Paragraph("YARA Matches", styles['Heading2']))
    yara_data = case.analysis_results.get("yara", {})
    matches = yara_data.get("matches", [])
    if matches:
        for m in matches:
            story.append(Paragraph(f"- Rule: {m['rule']}", styles['Normal']))
    else:
        story.append(Paragraph("No YARA rule matches found.", styles['Normal']))
    
    story.append(Spacer(1, 24))
    
    # Dynamic Analysis
    story.append(Paragraph("Dynamic Analysis Results", styles['Heading2']))
    dynamic_data = case.analysis_results.get("dynamic", {})
    if dynamic_data:
        behavior = dynamic_data.get("behavior", {})
        if behavior:
            story.append(Paragraph("Processes Created:", styles['Heading3']))
            for proc in behavior.get("processes", []):
                story.append(Paragraph(f"- {proc}", styles['Normal']))
                
            story.append(Paragraph("Network Activity:", styles['Heading3']))
            for net in behavior.get("network", []):
                story.append(Paragraph(f"- {net}", styles['Normal']))
    else:
        story.append(Paragraph("No dynamic analysis data available.", styles['Normal']))

    doc.build(story)
    return output_path
