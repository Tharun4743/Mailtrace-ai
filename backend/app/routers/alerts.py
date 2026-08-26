from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from app.database import get_db
from app.models.models import Alert, User, AuditLog
from app.schemas.schemas import AlertResponse
from app.auth.deps import get_current_user

router = APIRouter(prefix="/alerts", tags=["Security Alerts"])

@router.get("", response_model=List[AlertResponse])
def list_alerts(
    unread_only: bool = Query(False),
    severity: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    query = db.query(Alert)
    if unread_only:
        query = query.filter(Alert.is_read == False)
    if severity:
        query = query.filter(Alert.severity == severity.upper())
        
    alerts = query.order_by(Alert.created_at.desc()).all()
    return alerts

@router.post("/{alert_id}/acknowledge", response_model=AlertResponse)
def acknowledge_alert(alert_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")

    alert.is_acknowledged = True
    alert.is_read = True
    alert.acknowledged_by = current_user.full_name or current_user.username

    db.add(AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="ALERT_ACKNOWLEDGED",
        target_type="ALERT",
        target_id=str(alert.id)
    ))
    db.commit()
    db.refresh(alert)
    return alert
