from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.models import User, SystemSetting, AuditLog
from app.schemas.schemas import SystemSettingUpdate
from app.auth.deps import get_current_user, require_role
from app.config import settings

router = APIRouter(prefix="/settings", tags=["System Settings"])

@router.get("")
def get_system_settings(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return {
        "virustotal_configured": bool(settings.VIRUSTOTAL_API_KEY),
        "abuseipdb_configured": bool(settings.ABUSEIPDB_API_KEY),
        "alienvault_otx_configured": bool(settings.ALIENVAULT_OTX_KEY),
        "google_oauth_configured": bool(settings.GOOGLE_CLIENT_ID and settings.GOOGLE_CLIENT_SECRET),
        "microsoft_oauth_configured": bool(settings.MICROSOFT_CLIENT_ID and settings.MICROSOFT_CLIENT_SECRET),
        "google_client_id_mask": f"{settings.GOOGLE_CLIENT_ID[:8]}...{settings.GOOGLE_CLIENT_ID[-4:]}" if settings.GOOGLE_CLIENT_ID else "Not Set",
        "microsoft_client_id_mask": f"{settings.MICROSOFT_CLIENT_ID[:8]}...{settings.MICROSOFT_CLIENT_ID[-4:]}" if settings.MICROSOFT_CLIENT_ID else "Not Set",
        "risk_threshold_low": settings.RISK_THRESHOLD_LOW,
        "risk_threshold_medium": settings.RISK_THRESHOLD_MEDIUM,
        "risk_threshold_high": settings.RISK_THRESHOLD_HIGH,
        "version": settings.VERSION
    }

@router.post("/update")
def update_system_settings(
    settings_in: SystemSettingUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(["ADMIN"]))
):
    if settings_in.virustotal_api_key is not None:
        settings.VIRUSTOTAL_API_KEY = settings_in.virustotal_api_key
    if settings_in.abuseipdb_api_key is not None:
        settings.ABUSEIPDB_API_KEY = settings_in.abuseipdb_api_key
    if settings_in.alienvault_otx_key is not None:
        settings.ALIENVAULT_OTX_KEY = settings_in.alienvault_otx_key
    if settings_in.google_client_id is not None:
        settings.GOOGLE_CLIENT_ID = settings_in.google_client_id
    if settings_in.google_client_secret is not None:
        settings.GOOGLE_CLIENT_SECRET = settings_in.google_client_secret
    if settings_in.microsoft_client_id is not None:
        settings.MICROSOFT_CLIENT_ID = settings_in.microsoft_client_id
    if settings_in.microsoft_client_secret is not None:
        settings.MICROSOFT_CLIENT_SECRET = settings_in.microsoft_client_secret

    db.add(AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="SYSTEM_SETTINGS_UPDATED",
        target_type="CONFIG"
    ))
    db.commit()
    return {"status": "SUCCESS", "message": "System settings updated successfully."}
