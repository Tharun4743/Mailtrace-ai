import logging
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from app.config import settings

logger = logging.getLogger("mailtrace-ai")

# Normalize database URL if legacy 'postgres://' scheme is used (e.g., Supabase / Neon / Render)
raw_db_url = settings.DATABASE_URL
if raw_db_url.startswith("postgres://"):
    raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)

# Configure connection arguments and engine parameters
if raw_db_url.startswith("sqlite"):
    engine = create_engine(
        raw_db_url,
        connect_args={"check_same_thread": False},
        pool_pre_ping=True
    )
else:
    # PostgreSQL production pooling configuration
    engine = create_engine(
        raw_db_url,
        pool_size=10,
        max_overflow=20,
        pool_timeout=30,
        pool_recycle=1800,
        pool_pre_ping=True
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """
    Automatically creates all database tables if they do not already exist,
    and seeds default security users (admin / analyst).
    """
    import app.models  # Ensure all SQLAlchemy models are registered on Base
    logger.info(f"Connecting to database and creating tables if not exists...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables initialized successfully.")
