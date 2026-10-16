from database import engine, SessionLocal
from sqlalchemy import text
import bcrypt

def migrate():
    from models import Base
    Base.metadata.create_all(bind=engine)
    if engine.dialect.name == "postgresql":
        with engine.connect() as conn:
            conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'user';"))
            conn.execute(text("SELECT setval(pg_get_serial_sequence('users', 'id'), coalesce(max(id), 1)) FROM users;"))
            conn.commit()
        print("[+] DB migration: 'role' column confirmed & sequence synced.")
    else:
        print("[+] DB migration: tables and schema verified for " + engine.dialect.name)

    db = SessionLocal()
    try:
        from models import User
        # Ensure default admin user exists
        admin_user = db.query(User).filter(User.username == "admin").first()
        admin_pw_hash = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode("utf-8")
        if not admin_user:
            admin_user = User(
                username="admin",
                password_hash=admin_pw_hash,
                role="admin"
            )
            db.add(admin_user)
            print("[+] Created default admin user: 'admin' (password: 'admin123')")
        else:
            admin_user.role = "admin"
            admin_user.password_hash = admin_pw_hash
            print("[+] Updated admin user password and role to 'admin'")

        # Ensure default analyst user exists
        analyst_user = db.query(User).filter(User.username == "analyst").first()
        analyst_pw_hash = bcrypt.hashpw(b"analyst123", bcrypt.gensalt()).decode("utf-8")
        if not analyst_user:
            analyst_user = User(
                username="analyst",
                password_hash=analyst_pw_hash,
                role="user"
            )
            db.add(analyst_user)
            print("[+] Created default analyst user: 'analyst' (password: 'analyst123')")
        else:
            analyst_user.role = "user"
            analyst_user.password_hash = analyst_pw_hash
            print("[+] Updated analyst user password and role to 'user'")

        db.commit()
        print("[+] Auth migration complete.")
    finally:
        db.close()

if __name__ == "__main__":
    migrate()
