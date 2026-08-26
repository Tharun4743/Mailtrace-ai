import os
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app.models.models import ForensicReport, Email, Case, User, AuditLog
from app.schemas.schemas import ReportResponse
from app.auth.deps import get_current_user
from app.services.report_service import generate_forensic_pdf, REPORTS_DIR

router = APIRouter(prefix="/reports", tags=["Forensic Reports"])

@router.get("", response_model=List[ReportResponse])
def list_reports(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    reports = db.query(ForensicReport).order_by(ForensicReport.created_at.desc()).all()
    return reports

@router.post("/email/{email_id}", response_model=ReportResponse)
def create_forensic_report(email_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    email = db.query(Email).filter(Email.id == email_id).first()
    if not email:
        raise HTTPException(status_code=404, detail="Email not found.")

    case = db.query(Case).filter(Case.email_id == email.id).first()
    
    analyst_name = current_user.full_name or current_user.username
    pdf_filename = generate_forensic_pdf(email=email, case=case, analyst_name=analyst_name)
    report_id_str = f"RPT-{int(os.path.getmtime(os.path.join(REPORTS_DIR, pdf_filename))) % 100000:05d}-{email.id}"

    new_report = ForensicReport(
        case_id=case.id if case else None,
        email_id=email.id,
        report_identifier=report_id_str,
        generated_by=analyst_name,
        pdf_filename=pdf_filename,
        summary=f"Forensic Intelligence Report for subject: '{email.subject}'",
        report_metadata_json={
            "risk_score": email.analysis.risk_score if email.analysis else 0,
            "severity": email.analysis.severity if email.analysis else "LOW",
            "sender": email.sender_email
        }
    )
    db.add(new_report)
    
    db.add(AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="FORENSIC_REPORT_GENERATED",
        target_type="REPORT",
        target_id=report_id_str,
        details_json={"pdf_filename": pdf_filename}
    ))
    db.commit()
    db.refresh(new_report)
    return new_report

@router.get("/download/{filename}")
def download_report_pdf(filename: str, current_user: User = Depends(get_current_user)):
    file_path = os.path.join(REPORTS_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Report file not found on disk.")
    return FileResponse(
        path=file_path,
        media_type="application/pdf",
        filename=filename
    )
