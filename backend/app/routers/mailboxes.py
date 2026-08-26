from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.models import Mailbox, User, AuditLog
from app.schemas.schemas import MailboxResponse
from app.auth.deps import get_current_user
from app.services.email_ingestion import sync_gmail_mailbox, sync_microsoft_mailbox

router = APIRouter(prefix="/mailboxes", tags=["Mailboxes"])

@router.get("", response_model=list[MailboxResponse])
def get_user_mailboxes(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    mailboxes = db.query(Mailbox).filter(Mailbox.user_id == current_user.id).all()
    return mailboxes

@router.post("/{mailbox_id}/sync")
def trigger_mailbox_sync(mailbox_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    mailbox = db.query(Mailbox).filter(
        Mailbox.id == mailbox_id,
        Mailbox.user_id == current_user.id
    ).first()
    if not mailbox:
        raise HTTPException(status_code=404, detail="Mailbox not found")

    synced_count = 0
    try:
        if mailbox.provider == "google":
            synced_count = sync_gmail_mailbox(db, mailbox, max_results=25)
        elif mailbox.provider == "microsoft":
            synced_count = sync_microsoft_mailbox(db, mailbox, max_results=25)
        else:
            raise HTTPException(status_code=400, detail="Unsupported provider for synchronization.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Synchronization failed: {str(e)}")

    db.add(AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="MAILBOX_MANUAL_SYNC",
        target_type="MAILBOX",
        target_id=str(mailbox.id),
        details_json={"synced_count": synced_count}
    ))
    db.commit()

    return {
        "status": "SUCCESS",
        "message": f"Successfully synchronized {synced_count} new messages.",
        "synced_count": synced_count
    }
