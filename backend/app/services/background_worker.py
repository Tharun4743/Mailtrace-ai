import asyncio
import logging
import datetime
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models.models import OAuthAccount, Mailbox, Email, Alert
from app.services.email_ingestion import process_and_analyze_raw_email
from app.services.notifications import notification_service
from app.oauth.google_oauth import get_gmail_messages, get_gmail_message_raw
from app.oauth.microsoft_oauth import get_graph_messages, get_graph_message_mime

logger = logging.getLogger("mailtrace-ai")

class MailboxMonitorWorker:
    """
    Automated Background Email Ingestion & Real-Time Monitoring Worker.
    Continuously monitors connected Google Workspace and Microsoft 365 mailboxes,
    deduplicates incoming messages, runs threat detection, and triggers instant alerts.
    """
    def __init__(self, poll_interval_seconds: int = 25):
        self.poll_interval = poll_interval_seconds
        self.is_running = False
        self._task = None

    def start(self):
        if not self.is_running:
            self.is_running = True
            self._task = asyncio.create_task(self._run_loop())
            logger.info("Automated Mailbox Monitor Worker started.")

    def stop(self):
        self.is_running = False
        if self._task:
            self._task.cancel()
            logger.info("Automated Mailbox Monitor Worker stopped.")

    async def _run_loop(self):
        while self.is_running:
            try:
                await self._poll_all_mailboxes()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error during mailbox polling cycle: {str(e)}")

            await asyncio.sleep(self.poll_interval)

    async def _poll_all_mailboxes(self):
        db: Session = SessionLocal()
        try:
            active_accounts = db.query(OAuthAccount).filter(OAuthAccount.is_active == True).all()
            if not active_accounts:
                return

            for account in active_accounts:
                try:
                    mailbox = db.query(Mailbox).filter(Mailbox.oauth_account_id == account.id).first()
                    if not mailbox:
                        continue

                    if account.provider == "google":
                        await self._sync_google_account(db, account, mailbox)
                    elif account.provider == "microsoft":
                        await self._sync_microsoft_account(db, account, mailbox)

                except Exception as acc_err:
                    logger.warning(f"Failed to poll mailbox {account.email}: {str(acc_err)}")
                    account.error_message = str(acc_err)
                    db.commit()

        finally:
            db.close()

    async def _sync_google_account(self, db: Session, account: OAuthAccount, mailbox: Mailbox):
        messages = get_gmail_messages(account.access_token, max_results=10)
        new_threats_found = 0

        for msg_meta in messages:
            msg_id = msg_meta.get("id")
            # Deduplication check
            existing = db.query(Email).filter(Email.provider_message_id == msg_id).first()
            if existing:
                continue

            raw_bytes = get_gmail_message_raw(account.access_token, msg_id)
            if raw_bytes:
                email = process_and_analyze_raw_email(db, raw_bytes, mailbox_id=mailbox.id, provider_msg_id=msg_id)
                mailbox.total_emails_analyzed = (mailbox.total_emails_analyzed or 0) + 1

                # If Suspicious or High Risk, dispatch immediate alert
                if email.analysis and email.analysis.risk_score >= 30:
                    new_threats_found += 1
                    alert = Alert(
                        email_id=email.id,
                        title=f"{email.analysis.severity} Threat Detected: {email.subject}",
                        severity=email.analysis.severity,
                        risk_score=email.analysis.risk_score,
                        message=email.analysis.ai_reasoning,
                        major_reasons_json=[f.get("description", "") for f in (email.analysis.ai_flags_json or [])]
                    )
                    db.add(alert)
                    db.commit()

                    # Broadcast real-time notification
                    await notification_service.broadcast_threat_alert({
                        "email_id": email.id,
                        "sender": email.sender_email,
                        "subject": email.subject,
                        "risk_score": email.analysis.risk_score,
                        "severity": email.analysis.severity,
                        "threat_type": email.analysis.ai_classification,
                        "reasoning": email.analysis.ai_reasoning
                    })

        mailbox.last_sync_at = datetime.datetime.utcnow()
        account.last_sync_at = datetime.datetime.utcnow()
        db.commit()

    async def _sync_microsoft_account(self, db: Session, account: OAuthAccount, mailbox: Mailbox):
        messages = get_graph_messages(account.access_token, limit=10)

        for msg in messages:
            msg_id = msg.get("id")
            # Deduplication check
            existing = db.query(Email).filter(Email.provider_message_id == msg_id).first()
            if existing:
                continue

            raw_mime = get_graph_message_mime(account.access_token, msg_id)
            if raw_mime:
                email = process_and_analyze_raw_email(db, raw_mime, mailbox_id=mailbox.id, provider_msg_id=msg_id)
                mailbox.total_emails_analyzed = (mailbox.total_emails_analyzed or 0) + 1

                if email.analysis and email.analysis.risk_score >= 30:
                    alert = Alert(
                        email_id=email.id,
                        title=f"{email.analysis.severity} Threat Detected: {email.subject}",
                        severity=email.analysis.severity,
                        risk_score=email.analysis.risk_score,
                        message=email.analysis.ai_reasoning,
                        major_reasons_json=[f.get("description", "") for f in (email.analysis.ai_flags_json or [])]
                    )
                    db.add(alert)
                    db.commit()

                    await notification_service.broadcast_threat_alert({
                        "email_id": email.id,
                        "sender": email.sender_email,
                        "subject": email.subject,
                        "risk_score": email.analysis.risk_score,
                        "severity": email.analysis.severity,
                        "threat_type": email.analysis.ai_classification,
                        "reasoning": email.analysis.ai_reasoning
                    })

        mailbox.last_sync_at = datetime.datetime.utcnow()
        account.last_sync_at = datetime.datetime.utcnow()
        db.commit()

mailbox_monitor = MailboxMonitorWorker(poll_interval_seconds=30)
