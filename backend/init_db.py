import sys
import os
import logging

# Add backend directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.config import settings
from app.database import engine, Base, SessionLocal, init_db
from app.services.initial_seeder import seed_initial_admin_users
from sqlalchemy import text

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("mailtrace-init")

def initialize_database():
    """
    Connects to the configured database (PostgreSQL / SQLite),
    verifies connectivity, automatically creates all 15 tables,
    and seeds default security users.
    """
    db_type = "PostgreSQL" if "postgresql" in settings.DATABASE_URL or "postgres" in settings.DATABASE_URL else "SQLite"
    print("=" * 65)
    print(f"  MAILTRACE AI — Database Initialization ({db_type})")
    print("=" * 65)
    print(f"Target Database URL: {settings.DATABASE_URL.split('@')[-1] if '@' in settings.DATABASE_URL else settings.DATABASE_URL}")
    print()

    # 1. Test raw connection
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        print("✅ Database connection verified successfully.")
    except Exception as e:
        print(f"❌ Failed to connect to database: {str(e)}")
        print("Please check your DATABASE_URL in .env and ensure PostgreSQL server is running.")
        sys.exit(1)

    # 2. Create tables automatically
    try:
        print("Creating all tables if they do not exist...")
        init_db()
        print("✅ All 15 database tables created / verified successfully.")
    except Exception as e:
        print(f"❌ Failed to create tables: {str(e)}")
        sys.exit(1)

    # 3. Seed initial users
    db = SessionLocal()
    try:
        print("Seeding initial security administrator and analyst accounts...")
        seed_initial_admin_users(db)
        print("✅ Default accounts ready: 'admin' and 'analyst'.")
    finally:
        db.close()

    print()
    print("🎉 Database setup complete! You can now start the FastAPI server.")
    print("=" * 65)

if __name__ == "__main__":
    initialize_database()
