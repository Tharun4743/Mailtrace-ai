import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.config import settings
from app.database import engine, Base, get_db
from app.database import engine, Base, get_db, SessionLocal
from app.models.models import User, OAuthAccount
from app.services.initial_seeder import seed_initial_admin_users
from app.services.background_worker import mailbox_monitor
from app.services.notifications import notification_service

# Routers
from app.routers import (
    auth,
    emails,
    oauth,
    mailboxes,
    alerts,
    stats,
    settings as settings_router,
    reports
)

# Configure Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("mailtrace-ai")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Startup: initialize database schema
    logger.info("Initializing database schema...")
    Base.metadata.create_all(bind=engine)
    
    # 2. Seed default admin & analyst users if needed
    db = SessionLocal()
    try:
        seed_initial_admin_users(db)
    finally:
        db.close()
    
    # 3. Start automated background mailbox monitoring worker
    mailbox_monitor.start()
    
    yield
    
    # 4. Shutdown: stop background monitoring
    mailbox_monitor.stop()

app = FastAPI(
    title="MAILTRACE AI — Production Email Threat Detection Platform",
    description="Automated real-time email ingestion, 5-layer deterministic risk scoring, and threat alerting platform.",
    version="2.0.0",
    lifespan=lifespan
)

# CORS Configuration
origins = settings.ALLOWED_ORIGINS.split(",") if hasattr(settings, "ALLOWED_ORIGINS") else ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if origins != [""] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Routers
app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(emails.router, prefix=settings.API_V1_STR)
app.include_router(oauth.router, prefix=settings.API_V1_STR)
app.include_router(mailboxes.router, prefix=settings.API_V1_STR)
app.include_router(alerts.router, prefix=settings.API_V1_STR)
app.include_router(stats.router, prefix=settings.API_V1_STR)
app.include_router(settings_router.router, prefix=settings.API_V1_STR)
app.include_router(reports.router, prefix=settings.API_V1_STR)

# Real-time WebSocket Endpoint
@app.websocket("/api/v1/ws")
async def websocket_endpoint(websocket: WebSocket):
    await notification_service.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        notification_service.disconnect(websocket)
    except Exception:
        notification_service.disconnect(websocket)

# Production Health Check Endpoint
@app.get("/health")
def health_check(db: Session = Depends(get_db)):
    """
    Production health check reporting database, background monitor, and mailbox status.
    """
    db_status = "healthy"
    try:
        db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    connected_mailboxes = 0
    try:
        connected_mailboxes = db.query(OAuthAccount).filter(OAuthAccount.is_active == True).count()
    except Exception:
        pass

    return {
        "status": "healthy" if db_status == "healthy" else "degraded",
        "service": "MAILTRACE AI",
        "version": "2.0.0",
        "database": db_status,
        "background_monitor": "active" if mailbox_monitor.is_running else "inactive",
        "connected_mailboxes": connected_mailboxes,
        "deterministic_layers": [
            "Sender Reputation & Lookalikes (Max 20)",
            "Authentication SPF/DKIM/DMARC (Max 15)",
            "Content NLP & Phishing Intent (Max 25)",
            "Deceptive Link & URL Engine (Max 20)",
            "Attachment Safety Inspection (Max 20)"
        ]
    }
