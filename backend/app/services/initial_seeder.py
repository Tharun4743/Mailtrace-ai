import logging
from sqlalchemy.orm import Session
from app.models.models import User
from app.auth.security import get_password_hash

logger = logging.getLogger("mailtrace-ai")

def seed_initial_admin_users(db: Session):
    """
    Initializes default security administrator and analyst accounts for RBAC.
    """
    # 1. Create Default Administrator if not exists
    admin_user = db.query(User).filter(User.username == "admin").first()
    if not admin_user:
        admin_user = User(
            username="admin",
            email="admin@mailtrace.ai",
            hashed_password=get_password_hash("Admin@12345"),
            full_name="SOC Lead Administrator",
            role="ADMIN",
            is_active=True
        )
        db.add(admin_user)
        logger.info("Created default administrator user: admin")

    # 2. Create Default Lead Analyst if not exists
    analyst_user = db.query(User).filter(User.username == "analyst").first()
    if not analyst_user:
        analyst_user = User(
            username="analyst",
            email="analyst@mailtrace.ai",
            hashed_password=get_password_hash("Analyst@12345"),
            full_name="Senior Forensic Analyst",
            role="ANALYST",
            is_active=True
        )
        db.add(analyst_user)
        logger.info("Created default analyst user: analyst")
        
    db.commit()
