import hashlib
import json
import datetime
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.models import Evidence, Email

def create_evidence_record(db: Session, email: Email, source: str = "OAUTH_INGESTION") -> Evidence:
    """
    Creates an immutable cryptographic evidence record by calculating the SHA-256 hash
    of the email's raw headers, content, and arrival metadata.
    """
    # Construct normalized evidence payload for hashing
    payload = {
        "provider_message_id": email.provider_message_id,
        "sender_email": email.sender_email,
        "recipient_email": email.recipient_email,
        "subject": email.subject,
        "date_received": email.date_received.isoformat() if email.date_received else None,
        "raw_headers": email.raw_headers_json,
        "raw_mime_sha256": email.raw_mime_sha256 or "",
        "body_plain": email.body_plain
    }
    
    canonical_json = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    calculated_hash = hashlib.sha256(canonical_json).hexdigest()
    
    evidence_id_str = f"EVD-{int(datetime.datetime.utcnow().timestamp()) % 100000:05d}-{email.id}"
    
    evidence = Evidence(
        email_id=email.id,
        evidence_identifier=evidence_id_str,
        sha256_hash=calculated_hash,
        source=source,
        original_size_bytes=len(canonical_json),
        is_verified=True,
        blockchain_anchor_hash=None,
        blockchain_status="Evidence hash recorded locally",
        created_at=datetime.datetime.utcnow()
    )
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    return evidence

def verify_evidence_integrity(db: Session, evidence_id: int) -> Dict[str, Any]:
    """
    Verifies that the stored email content and headers match the original SHA-256 hash.
    Detects any database tampering or evidence alteration.
    """
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not evidence:
        return {
            "is_valid": False,
            "calculated_hash": "",
            "stored_hash": "",
            "integrity_status": "EVIDENCE_NOT_FOUND",
            "details": f"Evidence record with ID {evidence_id} not found."
        }

    email = db.query(Email).filter(Email.id == evidence.email_id).first()
    if not email:
        return {
            "is_valid": False,
            "calculated_hash": "",
            "stored_hash": evidence.sha256_hash,
            "integrity_status": "EMAIL_RECORD_DELETED",
            "details": "Associated email entity was removed from database."
        }

    payload = {
        "provider_message_id": email.provider_message_id,
        "sender_email": email.sender_email,
        "recipient_email": email.recipient_email,
        "subject": email.subject,
        "date_received": email.date_received.isoformat() if email.date_received else None,
        "raw_headers": email.raw_headers_json,
        "raw_mime_sha256": email.raw_mime_sha256 or "",
        "body_plain": email.body_plain
    }
    canonical_json = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    recalculated_hash = hashlib.sha256(canonical_json).hexdigest()

    is_valid = (recalculated_hash == evidence.sha256_hash)
    
    return {
        "is_valid": is_valid,
        "calculated_hash": recalculated_hash,
        "stored_hash": evidence.sha256_hash,
        "integrity_status": "INTEGRITY_VERIFIED" if is_valid else "HASH_MISMATCH_TAMPER_DETECTED",
        "details": "Cryptographic integrity verified. Digital evidence matches original capture." if is_valid else "Warning: Content hash does not match original evidence record!"
    }
