import logging
import datetime
import re
from sqlalchemy.orm import Session
from app.models.models import Email, AuthenticationResult, EmailAnalysis, Indicator, Evidence, Mailbox, OAuthAccount
from app.services.email_parser import parse_raw_email
from app.services.spf_service import analyze_spf
from app.services.dkim_service import analyze_dkim
from app.services.dmarc_service import analyze_dmarc
from app.services.threat_detector import threat_detector
from app.services.evidence_service import create_evidence_record
from app.services.geoip_service import lookup_geoip
from app.oauth.google_oauth import get_gmail_messages, get_gmail_message_raw
from app.oauth.microsoft_oauth import get_graph_messages, get_graph_message_mime

logger = logging.getLogger("mailtrace-ai")

def extract_urls_from_text(text: str) -> list:
    """Extracts HTTP/HTTPS URLs from raw text."""
    if not text:
        return []
    url_pattern = re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]+', re.IGNORECASE)
    return list(set(url_pattern.findall(text)))

def process_and_analyze_raw_email(
    db: Session,
    raw_bytes: bytes,
    mailbox_id: int = None,
    provider_msg_id: str = None
) -> Email:
    """
    Executes the Complete MAILTRACE AI Workflow:
    1. Email Preprocessing (Sender, Subject, Body, Headers, Attachments, URLs)
    2. Sender & Content & URL & Attachment Analysis
    3. Deterministic Risk Scoring (0 - 100) & AI Explanation
    4. Storage & Verdict Action
    """
    # 1. Parse MIME email
    parsed = parse_raw_email(raw_bytes)
    
    sender_domain = parsed.get("sender_domain", "")
    sender_email = parsed.get("sender_email", "")
    sender_name = parsed.get("sender_display_name", "")
    recipient_email = parsed.get("recipient_email", "")
    subject = parsed.get("subject", "")
    body_text = parsed.get("body_plain", "")
    body_html = parsed.get("body_html", "")
    raw_headers = parsed.get("raw_headers", {})
    relay_hops = parsed.get("relay_hops", [])
    raw_sha256 = parsed.get("raw_mime_sha256", "")
    date_received = parsed.get("date_received")
    
    # Extract sender IP from earliest public hop if present
    sender_ip = None
    for hop in reversed(relay_hops):
        if hop.get("ip"):
            sender_ip = hop.get("ip")
            break
            
    # Extract URLs from body
    urls = extract_urls_from_text(f"{body_text} {body_html}")
    
    # 2. Authenticate Envelope
    spf_res = analyze_spf(
        sender_domain=sender_domain,
        connecting_ip=sender_ip,
        raw_headers=raw_headers
    )
    
    dkim_res = analyze_dkim(
        raw_headers=raw_headers,
        raw_mime=raw_bytes
    )
    
    dmarc_res = analyze_dmarc(
        sender_domain=sender_domain,
        spf_result=spf_res["result"],
        spf_domain=spf_res.get("domain", sender_domain),
        dkim_result=dkim_res["result"],
        dkim_domain=dkim_res.get("domain"),
        raw_headers=raw_headers
    )
    
    # 3. Threat Engine Evaluation
    auth_summary = {
        "spf": spf_res["result"],
        "dkim": dkim_res["result"],
        "dmarc": dmarc_res["result"]
    }
    
    eval_res = threat_detector.analyze(
        sender=sender_email,
        subject=subject,
        body=body_text or body_html or "",
        urls=urls,
        attachments=[],
        sender_name=sender_name,
        auth_results=auth_summary
    )
    
    # Geolocation on sending IP
    geo = lookup_geoip(sender_ip) if sender_ip else {"country": "Location unavailable", "city": "Location unavailable", "asn": "N/A"}
    
    # 4. Save to Database
    email = Email(
        mailbox_id=mailbox_id,
        provider_message_id=provider_msg_id,
        sender_email=sender_email,
        sender_display_name=sender_name,
        sender_domain=sender_domain,
        recipient_email=recipient_email,
        subject=subject,
        date_received=date_received,
        body_plain=body_text,
        body_html=body_html,
        raw_headers_json=raw_headers,
        raw_mime_sha256=raw_sha256,
        is_processed=True
    )
    db.add(email)
    db.commit()
    db.refresh(email)
    
    # Save Authentication Results
    auth_record = AuthenticationResult(
        email_id=email.id,
        spf_result=spf_res["result"],
        spf_domain=spf_res.get("domain", sender_domain),
        spf_explanation=spf_res["explanation"],
        dkim_result=dkim_res["result"],
        dkim_domain=dkim_res.get("domain"),
        dkim_selector=dkim_res.get("selector"),
        dkim_explanation=dkim_res["explanation"],
        dmarc_result=dmarc_res["result"],
        dmarc_policy=dmarc_res.get("policy", "none"),
        dmarc_spf_aligned=dmarc_res.get("spf_aligned", False),
        dmarc_dkim_aligned=dmarc_res.get("dkim_aligned", False),
        dmarc_explanation=dmarc_res["explanation"]
    )
    db.add(auth_record)
    
    # Save Detailed Analysis & AI Explanation
    reasons_list = [{"category": s["type"], "description": s["description"], "points": s["score"]} for s in eval_res["signals"]]
    conf_val = float(eval_res["confidence"])
    if conf_val > 1.0:
        conf_val = conf_val / 100.0

    analysis_record = EmailAnalysis(
        email_id=email.id,
        risk_score=eval_res["risk_score"],
        severity=eval_res["classification"],
        ai_classification=eval_res["threat_type"],
        ai_confidence=conf_val,
        ai_reasoning=eval_res["ai_explanation"],
        ai_flags_json=[{"description": s["description"], "points": s["score"]} for s in eval_res["signals"]],
        domain_risk_score=eval_res["score_breakdown"]["sender_score"],
        url_risk_score=eval_res["score_breakdown"]["url_score"],
        ip_risk_score=eval_res["score_breakdown"]["authentication_score"],
        risk_reasons_json=reasons_list,
        observed_sending_ip=sender_ip,
        approx_country=geo.get("country", "Location unavailable"),
        approx_city=geo.get("city", "Location unavailable"),
        approx_asn=geo.get("asn", "N/A"),
        relay_hops_json=relay_hops,
        identity_mismatch=any(s["type"] in ("DISPLAY_NAME_MISMATCH", "SUSPICIOUS_SENDER_DOMAIN") for s in eval_res["signals"])
    )
    db.add(analysis_record)
    
    # Save Indicators
    for url in urls[:20]:
        db.add(Indicator(
            email_id=email.id,
            ioc_type="URL",
            value=url,
            context="Extracted link from message body",
            risk_score=eval_res["risk_score"],
            reputation_status="MALICIOUS" if eval_res["risk_score"] >= 70 else "SUSPICIOUS" if eval_res["risk_score"] >= 30 else "CLEAN",
            is_malicious=eval_res["risk_score"] >= 70
        ))
        
    # Save Evidence Record
    create_evidence_record(db, email, source="Email Ingestion")
    
    db.commit()
    return email

def sync_gmail_mailbox(db: Session, mailbox: Mailbox, oauth_account: OAuthAccount, limit: int = 20) -> int:
    """Synchronizes messages from Gmail API."""
    messages = get_gmail_messages(oauth_account.access_token, max_results=limit)
    ingested_count = 0
    
    for msg_meta in messages:
        msg_id = msg_meta.get("id")
        existing = db.query(Email).filter(Email.provider_message_id == msg_id).first()
        if existing:
            continue
            
        raw_bytes = get_gmail_message_raw(oauth_account.access_token, msg_id)
        if raw_bytes:
            process_and_analyze_raw_email(db, raw_bytes, mailbox_id=mailbox.id, provider_msg_id=msg_id)
            ingested_count += 1
            
    mailbox.total_emails_analyzed = (mailbox.total_emails_analyzed or 0) + ingested_count
    mailbox.last_sync_at = datetime.datetime.utcnow()
    mailbox.sync_status = "CONNECTED"
    db.commit()
    return ingested_count

def sync_microsoft_mailbox(db: Session, mailbox: Mailbox, oauth_account: OAuthAccount, limit: int = 20) -> int:
    """Synchronizes messages from Microsoft Graph API."""
    messages = get_graph_messages(oauth_account.access_token, limit=limit)
    ingested_count = 0
    
    for msg in messages:
        msg_id = msg.get("id")
        existing = db.query(Email).filter(Email.provider_message_id == msg_id).first()
        if existing:
            continue
            
        raw_mime = get_graph_message_mime(oauth_account.access_token, msg_id)
        if raw_mime:
            process_and_analyze_raw_email(db, raw_mime, mailbox_id=mailbox.id, provider_msg_id=msg_id)
            ingested_count += 1
            
    mailbox.total_emails_analyzed = (mailbox.total_emails_analyzed or 0) + ingested_count
    mailbox.last_sync_at = datetime.datetime.utcnow()
    mailbox.sync_status = "CONNECTED"
    db.commit()
    return ingested_count
