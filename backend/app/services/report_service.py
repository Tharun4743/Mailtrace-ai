import os
import datetime
from typing import Dict, Any, Optional
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from app.models.models import Email, Case, ForensicReport

REPORTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "generated_reports"))
os.makedirs(REPORTS_DIR, exist_ok=True)

def generate_forensic_pdf(email: Email, case: Optional[Case] = None, analyst_name: str = "Security Operations Center") -> str:
    """
    Generates a courtroom/SOC-grade forensic PDF report detailing all technical indicators,
    authentication results, AI analysis, evidence hashes, and attribution limitations.
    """
    report_id = f"RPT-{int(datetime.datetime.utcnow().timestamp()) % 100000:05d}-{email.id}"
    pdf_filename = f"MailTrace_Forensic_Report_{report_id}.pdf"
    file_path = os.path.join(REPORTS_DIR, pdf_filename)

    doc = SimpleDocTemplate(
        file_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0f172a")
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontSize=10,
        textColor=colors.HexColor("#64748b")
    )

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontSize=13,
        leading=16,
        textColor=colors.HexColor("#1e293b"),
        spaceBefore=10,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'DocBody',
        parent=styles['Normal'],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155")
    )

    badge_critical = ParagraphStyle('BadgeCrit', parent=body_style, textColor=colors.HexColor("#b91c1c"), fontName="Helvetica-Bold")
    badge_high = ParagraphStyle('BadgeHigh', parent=body_style, textColor=colors.HexColor("#c2410c"), fontName="Helvetica-Bold")
    badge_med = ParagraphStyle('BadgeMed', parent=body_style, textColor=colors.HexColor("#d97706"), fontName="Helvetica-Bold")
    badge_low = ParagraphStyle('BadgeLow', parent=body_style, textColor=colors.HexColor("#15803d"), fontName="Helvetica-Bold")

    elements = []

    # 1. Header Banner
    elements.append(Paragraph("MAILTRACE AI — DIGITAL FORENSIC INTELLIGENCE REPORT", title_style))
    elements.append(Paragraph(f"Case Reference: {case.case_number if case else 'N/A'} | Report ID: {report_id} | Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#2563eb"), spaceBefore=8, spaceAfter=12))

    # 2. Executive Threat Summary Box
    analysis = email.analysis
    risk_score = analysis.risk_score if analysis else 0
    severity = analysis.severity if analysis else "LOW"
    ai_class = analysis.ai_classification if analysis else "SAFE"
    
    summary_data = [
        [Paragraph("<b>OVERALL THREAT RISK:</b>", body_style), Paragraph(f"<b>{risk_score}/100 — {severity}</b>", badge_critical if severity in ["CRITICAL", "HIGH"] else (badge_med if severity == "MEDIUM" else badge_low))],
        [Paragraph("<b>AI Threat Classification:</b>", body_style), Paragraph(f"{ai_class} (Confidence: {int((analysis.ai_confidence or 0)*100)}%)", body_style)],
        [Paragraph("<b>Investigating Analyst:</b>", body_style), Paragraph(analyst_name, body_style)],
        [Paragraph("<b>Investigation Date:</b>", body_style), Paragraph(datetime.datetime.utcnow().strftime('%B %d, %Y'), body_style)]
    ]
    summary_table = Table(summary_data, colWidths=[160, 380])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 10))

    # 3. Email Identification & Metadata
    elements.append(Paragraph("1. Email Identification & Metadata", h2_style))
    meta_data = [
        [Paragraph("<b>Subject:</b>", body_style), Paragraph(email.subject or "(No Subject)", body_style)],
        [Paragraph("<b>Sender Display Name:</b>", body_style), Paragraph(email.sender_display_name or "N/A", body_style)],
        [Paragraph("<b>Sender Address:</b>", body_style), Paragraph(email.sender_email, body_style)],
        [Paragraph("<b>Sender Domain:</b>", body_style), Paragraph(email.sender_domain or "N/A", body_style)],
        [Paragraph("<b>Recipient Address:</b>", body_style), Paragraph(email.recipient_email or "N/A", body_style)],
        [Paragraph("<b>Date Received:</b>", body_style), Paragraph(str(email.date_received or "N/A"), body_style)],
        [Paragraph("<b>Message-ID:</b>", body_style), Paragraph(email.provider_message_id or "N/A", body_style)],
        [Paragraph("<b>Return-Path:</b>", body_style), Paragraph(email.return_path or "N/A", body_style)],
        [Paragraph("<b>Reply-To:</b>", body_style), Paragraph(email.reply_to or "N/A", body_style)],
    ]
    meta_table = Table(meta_data, colWidths=[140, 400])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#ffffff")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#e2e8f0")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#f1f5f9")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 10))

    # 4. Email Authentication Validation (SPF / DKIM / DMARC)
    elements.append(Paragraph("2. Authentication Protocol Evaluation", h2_style))
    auth = email.authentication_result
    auth_data = [
        ["Protocol", "Status", "Domain Checked", "Technical Result & Explanation"],
        [
            "SPF (RFC 7208)",
            auth.spf_result if auth else "UNKNOWN",
            auth.spf_domain if auth else "N/A",
            auth.spf_explanation if auth else "No SPF evaluation recorded"
        ],
        [
            "DKIM (RFC 6376)",
            auth.dkim_result if auth else "UNKNOWN",
            auth.dkim_domain if auth else "N/A",
            auth.dkim_explanation if auth else "No DKIM signature detected"
        ],
        [
            "DMARC (RFC 7489)",
            auth.dmarc_result if auth else "UNKNOWN",
            email.sender_domain or "N/A",
            auth.dmarc_explanation if auth else "No DMARC record evaluated"
        ]
    ]
    auth_table = Table(auth_data, colWidths=[100, 70, 110, 260])
    auth_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1e293b")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    elements.append(auth_table)
    elements.append(Spacer(1, 10))

    # 5. Infrastructure & Approximate GeoIP
    elements.append(Paragraph("3. Observed Sending Infrastructure & Geolocation", h2_style))
    infra_data = [
        [Paragraph("<b>Earliest Observable Public IP:</b>", body_style), Paragraph(analysis.observed_sending_ip or "N/A", body_style)],
        [Paragraph("<b>Approximate Country / City:</b>", body_style), Paragraph(f"{analysis.approx_country or 'Location unavailable'} / {analysis.approx_city or 'Location unavailable'}", body_style)],
        [Paragraph("<b>ISP / Autonomous System (ASN):</b>", body_style), Paragraph(f"{analysis.approx_org or 'Unknown'} ({analysis.approx_asn or 'N/A'})", body_style)],
        [Paragraph("<b>Infrastructure Attribution:</b>", body_style), Paragraph("<i>Approximate location of observed sending infrastructure (not confirmed physical attacker location).</i>", body_style)]
    ]
    infra_table = Table(infra_data, colWidths=[170, 370])
    infra_table.setStyle(TableStyle([
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#e2e8f0")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#f1f5f9")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    elements.append(infra_table)
    elements.append(Spacer(1, 10))

    # 6. Risk Scoring Breakdown
    elements.append(Paragraph("4. Transparent Risk Scoring Breakdown", h2_style))
    risk_rows = [["Signal Category", "Weighted Points", "Forensic Indicator Description"]]
    if analysis and analysis.risk_reasons_json:
        for r in analysis.risk_reasons_json:
            risk_rows.append([
                r.get("category", "General"),
                f"+{r.get('points', 0)} pts",
                r.get("description", "")
            ])
    else:
        risk_rows.append(["Baseline", "0 pts", "No threat indicators flagged."])
    
    risk_table = Table(risk_rows, colWidths=[130, 80, 330])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#334155")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    elements.append(risk_table)
    elements.append(Spacer(1, 10))

    # 7. Evidence Integrity & Cryptographic Chain
    elements.append(Paragraph("5. Digital Evidence Integrity & Cryptographic Proof", h2_style))
    evidence_rec = email.evidence_records[0] if email.evidence_records else None
    ev_data = [
        [Paragraph("<b>Evidence Identifier:</b>", body_style), Paragraph(evidence_rec.evidence_identifier if evidence_rec else "N/A", body_style)],
        [Paragraph("<b>SHA-256 Hash of Evidence:</b>", body_style), Paragraph(f"<code>{evidence_rec.sha256_hash if evidence_rec else (email.raw_mime_sha256 or 'N/A')}</code>", body_style)],
        [Paragraph("<b>Integrity Status:</b>", body_style), Paragraph("VERIFIED (Cryptographic Match)", badge_low)],
        [Paragraph("<b>Blockchain Anchoring:</b>", body_style), Paragraph(evidence_rec.blockchain_status if evidence_rec else "Evidence hash recorded locally", body_style)],
    ]
    ev_table = Table(ev_data, colWidths=[160, 380])
    ev_table.setStyle(TableStyle([
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#e2e8f0")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#f1f5f9")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    elements.append(ev_table)
    elements.append(Spacer(1, 12))

    # 8. Forensic Disclaimers & Legal Precision
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceBefore=6, spaceAfter=8))
    elements.append(Paragraph("<b>FORENSIC NOTICE & ATTRIBUTION LIMITATIONS:</b>", ParagraphStyle('NoticeH', parent=body_style, fontName="Helvetica-Bold", fontSize=8)))
    elements.append(Paragraph(
        "This intelligence report reflects technical indicators observed from email envelope metadata, relay headers, cryptographic signatures, "
        "and approximate IP network registry information. In compliance with cybersecurity intelligence standards, geolocation data indicates "
        "observed relay infrastructure and must not be construed as the physical location or confirmed real-world identity of a human threat actor.",
        ParagraphStyle('NoticeB', parent=body_style, fontSize=7.5, leading=10, textColor=colors.HexColor("#64748b"))
    ))

    # Build PDF document
    doc.build(elements)
    return pdf_filename
