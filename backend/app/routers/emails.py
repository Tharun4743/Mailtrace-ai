from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from sqlalchemy.orm import Session
from typing import List, Optional, Dict, Any
from pydantic import BaseModel

from app.database import get_db
from app.auth.deps import get_current_user
from app.models.models import User, Email, EmailAnalysis, AuthenticationResult, Indicator, Evidence
from app.schemas.schemas import EmailListItem, EmailDetailResponse
from app.services.email_ingestion import process_and_analyze_raw_email
from app.services.threat_detector import threat_detector

router = APIRouter(prefix="/emails", tags=["Emails"])

class AnalyzeEmailRequest(BaseModel):
    sender: str
    subject: str
    body: str
    urls: Optional[List[str]] = []
    attachments: Optional[List[Dict[str, Any]]] = []

class EmailActionRequest(BaseModel):
    action: str # "QUARANTINE" or "MARK_SAFE"

@router.get("", response_model=List[EmailListItem])
def get_emails(
    severity: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Email)
    if severity:
        query = query.filter(Email.severity == severity.upper())
    if search:
        query = query.filter(
            (Email.subject.ilike(f"%{search}%")) |
            (Email.sender_email.ilike(f"%{search}%")) |
            (Email.sender_display_name.ilike(f"%{search}%"))
        )
    return query.order_by(Email.date_received.desc().nullslast(), Email.created_at.desc()).offset(offset).limit(limit).all()

@router.get("/{email_id}", response_model=EmailDetailResponse)
def get_email_detail(
    email_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email record not found")
    return email

@router.post("/analyze")
def analyze_email_direct(
    payload: AnalyzeEmailRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Direct Real-Time Analysis API:
    Input: sender, subject, body, urls, attachments
    Output: Deterministic Risk Score (0-100), 5-Layer Breakdown, Threat Signals, and AI Explanation
    """
    res = threat_detector.analyze(
        sender=payload.sender,
        subject=payload.subject,
        body=payload.body,
        urls=payload.urls,
        attachments=payload.attachments
    )
    
    # Store into database as analyzed email record
    raw_content = f"From: {payload.sender}\nSubject: {payload.subject}\n\n{payload.body}".encode('utf-8')
    email = process_and_analyze_raw_email(db, raw_content)
    
    return {
        "email_id": email.id,
        "risk_score": res["risk_score"],
        "classification": res["classification"],
        "threat_type": res["threat_type"],
        "confidence": res["confidence"],
        "recommended_action": res["recommended_action"],
        "ml_threat_probability": res.get("ml_threat_probability", 0.0),
        "score_breakdown": res["score_breakdown"],
        "signals": res["signals"],
        "why_bullets": res["why_bullets"],
        "ai_explanation": res["ai_explanation"]
    }

@router.post("/{email_id}/action")
def update_email_action(
    email_id: int,
    payload: EmailActionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email record not found")
        
    action_type = payload.action.upper()
    if email.analysis:
        if action_type == "QUARANTINE":
            email.analysis.severity = "CRITICAL"
            email.analysis.risk_score = max(email.analysis.risk_score, 85)
        elif action_type == "MARK_SAFE":
            email.analysis.severity = "SAFE"
            email.analysis.risk_score = 0
        
    db.commit()
    return {"message": f"Email action updated to {action_type}", "email_id": email.id, "severity": email.severity}

@router.post("/upload-eml", response_model=EmailDetailResponse)
async def upload_eml(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    raw_bytes = await file.read()
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Empty file uploaded")
    email = process_and_analyze_raw_email(db, raw_bytes, mailbox_id=None, provider_msg_id="MANUAL-UPLOAD")
    return email
