import secrets
import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.models import User, OAuthAccount, Mailbox, AuditLog
from app.schemas.schemas import OAuthInitResponse, OAuthCallbackRequest, ConnectedAccountResponse
from app.auth.deps import get_current_user
from app.oauth.google_oauth import generate_google_auth_url, exchange_google_code_for_tokens, revoke_google_token
from app.oauth.microsoft_oauth import generate_microsoft_auth_url, exchange_microsoft_code_for_tokens
from app.services.email_ingestion import sync_gmail_mailbox, sync_microsoft_mailbox
from app.config import settings

router = APIRouter(prefix="/oauth", tags=["OAuth Mailbox Integration"])

@router.get("/google/init", response_model=OAuthInitResponse)
def init_google_oauth(current_user: User = Depends(get_current_user)):
    state = secrets.token_urlsafe(16)
    auth_url = generate_google_auth_url(state=state)
    return {
        "authorization_url": auth_url,
        "state": state,
        "provider": "google"
    }

@router.post("/google/callback")
def google_oauth_callback(req: OAuthCallbackRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        token_info = exchange_google_code_for_tokens(req.code)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Google authorization failed: {str(e)}")

    user_email = token_info.get("email")
    if not user_email:
        raise HTTPException(status_code=400, detail="Unable to retrieve authenticated email address from Google.")

    # Find or create OAuth account
    oauth_acc = db.query(OAuthAccount).filter(
        OAuthAccount.user_id == current_user.id,
        OAuthAccount.provider == "google",
        OAuthAccount.email == user_email
    ).first()

    if not oauth_acc:
        oauth_acc = OAuthAccount(
            user_id=current_user.id,
            provider="google",
            provider_user_id=token_info.get("provider_user_id"),
            email=user_email,
            access_token=token_info.get("access_token"),
            refresh_token=token_info.get("refresh_token"),
            token_expiry=token_info.get("token_expiry"),
            scopes=token_info.get("scopes"),
            is_active=True,
            sync_status="CONNECTED"
        )
        db.add(oauth_acc)
        db.flush()
    else:
        oauth_acc.access_token = token_info.get("access_token")
        if token_info.get("refresh_token"):
            oauth_acc.refresh_token = token_info.get("refresh_token")
        oauth_acc.token_expiry = token_info.get("token_expiry")
        oauth_acc.is_active = True
        oauth_acc.sync_status = "CONNECTED"
        oauth_acc.error_message = None

    # Link Mailbox
    mailbox = db.query(Mailbox).filter(
        Mailbox.user_id == current_user.id,
        Mailbox.email_address == user_email
    ).first()

    if not mailbox:
        mailbox = Mailbox(
            user_id=current_user.id,
            oauth_account_id=oauth_acc.id,
            email_address=user_email,
            provider="google",
            display_name=f"Gmail ({user_email})",
            sync_status="IDLE",
            is_active=True
        )
        db.add(mailbox)
        db.flush()

    db.add(AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="OAUTH_GMAIL_CONNECTED",
        target_type="MAILBOX",
        target_id=str(mailbox.id)
    ))
    db.commit()

    # Trigger initial email synchronization (last 20 emails)
    synced_count = 0
    try:
        synced_count = sync_gmail_mailbox(db, mailbox, max_results=20)
    except Exception as e:
        print(f"Initial Gmail sync notice: {e}")

    return {
        "status": "SUCCESS",
        "message": f"Successfully connected Gmail mailbox for {user_email}.",
        "mailbox_id": mailbox.id,
        "synced_emails_count": synced_count
    }

@router.get("/microsoft/init", response_model=OAuthInitResponse)
def init_microsoft_oauth(current_user: User = Depends(get_current_user)):
    state = secrets.token_urlsafe(16)
    auth_url = generate_microsoft_auth_url(state=state)
    return {
        "authorization_url": auth_url,
        "state": state,
        "provider": "microsoft"
    }

@router.post("/microsoft/callback")
def microsoft_oauth_callback(req: OAuthCallbackRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    try:
        token_info = exchange_microsoft_code_for_tokens(req.code)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Microsoft authorization failed: {str(e)}")

    user_email = token_info.get("email")
    if not user_email:
        raise HTTPException(status_code=400, detail="Unable to retrieve authenticated email address from Microsoft.")

    oauth_acc = db.query(OAuthAccount).filter(
        OAuthAccount.user_id == current_user.id,
        OAuthAccount.provider == "microsoft",
        OAuthAccount.email == user_email
    ).first()

    if not oauth_acc:
        oauth_acc = OAuthAccount(
            user_id=current_user.id,
            provider="microsoft",
            provider_user_id=token_info.get("provider_user_id"),
            email=user_email,
            access_token=token_info.get("access_token"),
            refresh_token=token_info.get("refresh_token"),
            token_expiry=token_info.get("token_expiry"),
            scopes=token_info.get("scopes"),
            is_active=True,
            sync_status="CONNECTED"
        )
        db.add(oauth_acc)
        db.flush()
    else:
        oauth_acc.access_token = token_info.get("access_token")
        if token_info.get("refresh_token"):
            oauth_acc.refresh_token = token_info.get("refresh_token")
        oauth_acc.token_expiry = token_info.get("token_expiry")
        oauth_acc.is_active = True
        oauth_acc.sync_status = "CONNECTED"
        oauth_acc.error_message = None

    mailbox = db.query(Mailbox).filter(
        Mailbox.user_id == current_user.id,
        Mailbox.email_address == user_email
    ).first()

    if not mailbox:
        mailbox = Mailbox(
            user_id=current_user.id,
            oauth_account_id=oauth_acc.id,
            email_address=user_email,
            provider="microsoft",
            display_name=f"Microsoft 365 ({user_email})",
            sync_status="IDLE",
            is_active=True
        )
        db.add(mailbox)
        db.flush()

    db.add(AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="OAUTH_M365_CONNECTED",
        target_type="MAILBOX",
        target_id=str(mailbox.id)
    ))
    db.commit()

    synced_count = 0
    try:
        synced_count = sync_microsoft_mailbox(db, mailbox, max_results=20)
    except Exception as e:
        print(f"Initial Microsoft 365 sync notice: {e}")

    return {
        "status": "SUCCESS",
        "message": f"Successfully connected Microsoft 365 mailbox for {user_email}.",
        "mailbox_id": mailbox.id,
        "synced_emails_count": synced_count
    }

@router.get("/accounts", response_model=list[ConnectedAccountResponse])
def get_connected_accounts(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    accounts = db.query(OAuthAccount).filter(OAuthAccount.user_id == current_user.id).all()
    results = []
    for acc in accounts:
        # Sum analyzed count from mailboxes
        total_analyzed = sum([m.total_emails_analyzed for m in acc.mailboxes])
        results.append({
            "id": acc.id,
            "provider": acc.provider,
            "email": acc.email,
            "is_active": acc.is_active,
            "sync_status": acc.sync_status,
            "last_sync_at": acc.last_sync_at,
            "error_message": acc.error_message,
            "total_emails_analyzed": total_analyzed,
            "created_at": acc.created_at
        })
    return results

@router.delete("/disconnect/{account_id}")
def disconnect_account(account_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    account = db.query(OAuthAccount).filter(
        OAuthAccount.id == account_id,
        OAuthAccount.user_id == current_user.id
    ).first()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")

    if account.provider == "google" and account.access_token:
        revoke_google_token(account.access_token)

    account.is_active = False
    account.sync_status = "DISCONNECTED"
    account.access_token = None
    account.refresh_token = None
    
    db.add(AuditLog(
        user_id=current_user.id,
        username=current_user.username,
        action="OAUTH_ACCOUNT_DISCONNECTED",
        target_type="OAUTH_ACCOUNT",
        target_id=str(account.id)
    ))
    db.commit()
    return {"status": "SUCCESS", "message": "Account disconnected and tokens revoked successfully."}
