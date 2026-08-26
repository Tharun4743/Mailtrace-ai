import sys
import os

# Add backend directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.database import engine, Base, SessionLocal
from app.services.initial_seeder import seed_initial_admin_users

def reset_database():
    print("Dropping all existing database tables...")
    Base.metadata.drop_all(bind=engine)
    print("Creating clean database schema...")
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    try:
        print("Seeding initial security users (admin / analyst)...")
        seed_initial_admin_users(db)
        print("Database reset completed successfully. 0 mock/demo emails exist.")
    finally:
        db.close()

if __name__ == "__main__":
    reset_database()
