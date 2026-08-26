import email
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
import re
import hashlib
from typing import Dict, Any, List, Optional, Tuple

def parse_raw_email(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Robustly parses raw RFC 822/5322 MIME email bytes.
    Extracts headers, bodies, received hops, and computes SHA-256 evidence hash.
    """
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    
    # Calculate SHA-256 of raw MIME
    raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    
    # Extract From & Display Name
    from_raw = msg.get("From", "")
    display_name, sender_email = parseaddr(from_raw)
    
    # Extract Sender Domain
    sender_domain = ""
    if "@" in sender_email:
        sender_domain = sender_email.split("@")[1].strip().lower()
        
    # Extract Recipient, CC, BCC
    to_raw = msg.get("To", "")
    _, recipient_email = parseaddr(to_raw)
    cc = msg.get("Cc", "")
    bcc = msg.get("Bcc", "")
    reply_to = msg.get("Reply-To", "")
    return_path = msg.get("Return-Path", "")
    subject = msg.get("Subject", "(No Subject)")
    
    # Date parsing
    date_received = None
    date_header = msg.get("Date")
    if date_header:
        try:
            date_received = parsedate_to_datetime(date_header)
        except Exception:
            date_received = None
            
    # Extract bodies
    body_plain = ""
    body_html = ""
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))
            
            if "attachment" not in content_disposition:
                if content_type == "text/plain" and not body_plain:
                    try:
                        body_plain = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
                    except Exception:
                        body_plain = str(part.get_payload())
                elif content_type == "text/html" and not body_html:
                    try:
                        body_html = part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
                    except Exception:
                        body_html = str(part.get_payload())
    else:
        content_type = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True).decode(msg.get_content_charset() or "utf-8", errors="replace")
        except Exception:
            payload = str(msg.get_payload())
            
        if content_type == "text/html":
            body_html = payload
            body_plain = strip_html_tags(payload)
        else:
            body_plain = payload

    # If plain body is empty but html exists, derive plain text
    if not body_plain and body_html:
        body_plain = strip_html_tags(body_html)

    # Collect all headers for preservation & forensic reference
    raw_headers = {}
    for header, value in msg.items():
        if header in raw_headers:
            if isinstance(raw_headers[header], list):
                raw_headers[header].append(value)
            else:
                raw_headers[header] = [raw_headers[header], value]
        else:
            raw_headers[header] = value

    # Parse Received Chain
    received_headers = msg.get_all("Received", [])
    relay_hops = parse_received_chain(received_headers)

    return {
        "sender_display_name": display_name or sender_email,
        "sender_email": sender_email.lower(),
        "sender_domain": sender_domain,
        "recipient_email": recipient_email.lower() if recipient_email else None,
        "cc": cc or None,
        "bcc": bcc or None,
        "reply_to": reply_to or None,
        "return_path": return_path or None,
        "subject": subject,
        "date_received": date_received,
        "body_plain": body_plain,
        "body_html": body_html,
        "raw_headers": raw_headers,
        "raw_mime_sha256": raw_sha256,
        "relay_hops": relay_hops
    }

def strip_html_tags(html_text: str) -> str:
    """Safely strip HTML tags for plain text NLP extraction."""
    clean = re.sub(r'<style.*?</style>', '', html_text, flags=re.DOTALL | re.IGNORECASE)
    clean = re.sub(r'<script.*?</script>', '', clean, flags=re.DOTALL | re.IGNORECASE)
    clean = re.sub(r'<[^<]+?>', ' ', clean)
    clean = re.sub(r'\s+', ' ', clean).strip()
    return clean

def parse_received_chain(received_headers: List[str]) -> List[Dict[str, Any]]:
    """
    Parses Received headers from newest (hop 0 - recipient server)
    to oldest (hop N - earliest sender MTA).
    """
    hops = []
    ip_pattern = re.compile(r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]')
    from_pattern = re.compile(r'from\s+([^\s;]+)', re.IGNORECASE)
    by_pattern = re.compile(r'by\s+([^\s;]+)', re.IGNORECASE)

    for idx, header in enumerate(received_headers):
        ip_match = ip_pattern.search(header)
        ip_addr = ip_match.group(1) if ip_match else None
        
        from_match = from_pattern.search(header)
        from_host = from_match.group(1) if from_match else None
        
        by_match = by_pattern.search(header)
        by_host = by_match.group(1) if by_match else None
        
        hops.append({
            "hop_index": idx + 1,
            "raw_header": header,
            "ip": ip_addr,
            "from_server": from_host,
            "by_server": by_host,
        })
        
    return hops
