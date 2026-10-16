import os
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    pg_url = "postgresql+psycopg://admin:admin@localhost:5432/threattrail"
    try:
        test_engine = create_engine(pg_url, connect_args={"connect_timeout": 1})
        with test_engine.connect():
            pass
        test_engine.dispose()
        DATABASE_URL = pg_url
    except Exception:
        backend_dir = Path(__file__).resolve().parent
        if (backend_dir / "threattrail.db").exists() or backend_dir.name == "threattrail-backend":
            db_path = (backend_dir / "threattrail.db").resolve()
        elif (backend_dir / "threattrail-backend").exists():
            db_path = (backend_dir / "threattrail-backend" / "threattrail.db").resolve()
        else:
            db_path = (backend_dir / "threattrail.db").resolve()
        DATABASE_URL = f"sqlite:///{db_path.as_posix()}"

connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
engine = create_engine(DATABASE_URL, echo=False, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency that yields a DB session and closes it after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
