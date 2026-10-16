#!/usr/bin/env python3
"""
apply_threattrail_upgrade.py
Run this script from the ThreatTrail project root:
    python apply_threattrail_upgrade.py

What this script fixes & upgrades:
1. requirements.txt: Adds missing `bcrypt` and `python-jose[cryptography]`.
2. database.py: Uses environment variables (`DATABASE_URL`) with localhost fallback.
3. models.py & schemas.py:
   - Adds `sigma_rule` (YAML detection logic) to `Alert` so trainees can inspect the detection rule.
   - Adds `ad_context` (JSONB Active Directory topology: users, hosts, SPNs, groups) to `Scenario`.
   - Adds `acceptable_answers` & `explanation` to `Question` for flexible grading (e.g., `CORP\\svc_backup` or `svc_backup`) and post-submission learning feedback.
   - Adds `pinned_log_ids` to `InvestigationResult` for interactive Attack Timeline reconstruction.
4. main.py:
   - Fixes `user_id=1` bug in `/submit` by binding to `get_current_user` (with fallback).
   - Fixes `extract_field_from_message` regex bug where Windows Events with two `Account Name:` fields returned `-` instead of the target user.
   - Adds atomic `POST /api/admin/scenarios/full` so scenario + alert + questions are created in a single DB transaction.
   - Adds smart answer normalization (strips domain prefixes like `CORP\\` if needed, checks aliases).
5. seed.py:
   - Seeds 2 rich Active Directory scenarios (Password Spraying T1110.003 + Kerberoasting T1558.003) complete with Sigma rules, AD Context directories, and answer explanations.
6. threattrail-frontend/src/api.js:
   - Uses `import.meta.env.VITE_API_URL` and adds a 401 Unauthorized interceptor.
"""

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent

FILES = {}

# ---------------------------------------------------------------------------
# 1. requirements.txt
# ---------------------------------------------------------------------------
FILES["requirements.txt"] = """fastapi
uvicorn[standard]
sqlalchemy
psycopg[binary]
pydantic
python-multipart
bcrypt
python-jose[cryptography]
"""

# ---------------------------------------------------------------------------
# 2. database.py
# ---------------------------------------------------------------------------
FILES["database.py"] = """import os
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
    \"\"\"FastAPI dependency that yields a DB session and closes it after the request.\"\"\"
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
"""

# ---------------------------------------------------------------------------
# 3. models.py
# ---------------------------------------------------------------------------
FILES["models.py"] = """from sqlalchemy import (
    Column, Integer, String, Text, ForeignKey, DateTime, Boolean, Index, Enum as SAEnum
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship
from database import Base
import enum


class SeverityLevel(str, enum.Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="user", nullable=False)

    investigation_results = relationship("InvestigationResult", back_populates="user")


class Scenario(Base):
    __tablename__ = "scenarios"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    mitre_technique = Column(String(100), nullable=False)
    status = Column(String(20), default="Draft", nullable=False)
    # Active Directory environment context (Domain Controllers, Users, SPNs, Tier-0 assets)
    ad_context = Column(JSONB, nullable=True, default=dict)

    alerts = relationship("Alert", back_populates="scenario", cascade="all, delete-orphan")
    logs = relationship("Log", back_populates="scenario", cascade="all, delete-orphan")
    questions = relationship("Question", back_populates="scenario", cascade="all, delete-orphan")
    investigation_results = relationship("InvestigationResult", back_populates="scenario", cascade="all, delete-orphan")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    scenario_id = Column(Integer, ForeignKey("scenarios.id"), nullable=False, index=True)
    title = Column(String(300), nullable=False)
    severity = Column(SAEnum(SeverityLevel), nullable=False)
    # Static Sigma Rule / Detection Query so trainees learn how detections work without a live SIEM engine
    sigma_rule = Column(Text, nullable=True)

    scenario = relationship("Scenario", back_populates="alerts")


class Log(Base):
    __tablename__ = "logs"
    __table_args__ = (
        Index("ix_logs_scenario_timestamp", "scenario_id", "timestamp"),
        Index("ix_logs_scenario_event_id", "scenario_id", "event_id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    scenario_id = Column(Integer, ForeignKey("scenarios.id"), nullable=False, index=True)
    event_id = Column(Integer, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    source_ip = Column(String(45), nullable=True)
    username = Column(String(150), nullable=True)
    target_host = Column(String(200), nullable=True)
    is_key_evidence = Column(Boolean, default=False, nullable=False)
    raw_event_data = Column(JSONB, nullable=False)

    scenario = relationship("Scenario", back_populates="logs")


class Question(Base):
    __tablename__ = "questions"

    id = Column(Integer, primary_key=True, index=True)
    scenario_id = Column(Integer, ForeignKey("scenarios.id"), nullable=False, index=True)
    question_text = Column(Text, nullable=False)
    correct_answer = Column(String(300), nullable=False)
    # Comma-separated or JSON list of acceptable aliases (e.g. ["CORP\\svc_backup", "svc_backup@corp.local"])
    acceptable_answers = Column(JSONB, nullable=True, default=list)
    explanation = Column(Text, nullable=True)
    points = Column(Integer, default=10, nullable=False)

    scenario = relationship("Scenario", back_populates="questions")


class InvestigationResult(Base):
    __tablename__ = "investigation_results"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    scenario_id = Column(Integer, ForeignKey("scenarios.id"), nullable=False, index=True)
    score = Column(Integer, nullable=False)
    points_earned = Column(Integer, default=0, nullable=False)
    total_points = Column(Integer, default=0, nullable=False)
    pinned_log_ids = Column(JSONB, nullable=True, default=list)

    user = relationship("User", back_populates="investigation_results")
    scenario = relationship("Scenario", back_populates="investigation_results")
"""

# ---------------------------------------------------------------------------
# 4. schemas.py
# ---------------------------------------------------------------------------
FILES["schemas.py"] = """from pydantic import BaseModel, Field
from typing import Any, Optional
from datetime import datetime


# ── Scenario ──────────────────────────────────────────────────────────────────

class ScenarioOut(BaseModel):
    id: int
    name: str
    description: str
    mitre_technique: str
    status: str = "Draft"
    ad_context: Optional[dict[str, Any]] = None

    model_config = {"from_attributes": True}


# ── Alert ─────────────────────────────────────────────────────────────────────

class AlertOut(BaseModel):
    id: int
    scenario_id: int
    title: str
    severity: str
    sigma_rule: Optional[str] = None

    model_config = {"from_attributes": True}


# ── Log ───────────────────────────────────────────────────────────────────────

class LogOut(BaseModel):
    id: int
    scenario_id: int
    event_id: int
    timestamp: datetime
    source_ip: Optional[str] = None
    username: Optional[str] = None
    target_host: Optional[str] = None
    raw_event_data: dict[str, Any]

    model_config = {"from_attributes": True}


# ── Question ──────────────────────────────────────────────────────────────────

class QuestionOut(BaseModel):
    id: int
    scenario_id: int
    question_text: str
    points: int = 10
    # correct_answer & acceptable_answers excluded for trainees

    model_config = {"from_attributes": True}


class QuestionAdminOut(BaseModel):
    id: int
    scenario_id: int
    question_text: str
    correct_answer: str
    acceptable_answers: Optional[list[str]] = Field(default_factory=list)
    explanation: Optional[str] = None
    points: int = 10

    model_config = {"from_attributes": True}


# ── Submission (request body) ─────────────────────────────────────────────────

class AnswerSubmission(BaseModel):
    question_id: int
    answer: str


class SubmissionRequest(BaseModel):
    answers: list[AnswerSubmission]
    pinned_log_ids: Optional[list[int]] = Field(default_factory=list)


# ── Grading result (response) ─────────────────────────────────────────────────

class QuestionResult(BaseModel):
    question_id: int
    question_text: str
    user_answer: str
    correct_answer: str
    explanation: Optional[str] = None
    is_correct: bool
    points_awarded: int = 0
    points_possible: int = 10


class SubmissionResponse(BaseModel):
    scenario_id: int
    total_questions: int
    correct_count: int
    total_points: int = 0
    points_earned: int = 0
    score_percent: int
    pinned_log_ids: list[int] = Field(default_factory=list)
    key_evidence_log_ids: list[int] = Field(default_factory=list)
    results: list[QuestionResult]


# ── Admin Schemas ─────────────────────────────────────────────────────────────

class ScenarioCreate(BaseModel):
    name: str
    description: str
    mitre_technique: str
    status: Optional[str] = "Published"
    ad_context: Optional[dict[str, Any]] = None


class ScenarioUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    mitre_technique: Optional[str] = None
    status: Optional[str] = None
    ad_context: Optional[dict[str, Any]] = None


class StatusUpdate(BaseModel):
    status: str


class AlertCreate(BaseModel):
    title: str
    severity: str
    sigma_rule: Optional[str] = None


class QuestionCreate(BaseModel):
    question_text: str
    correct_answer: str
    acceptable_answers: Optional[list[str]] = Field(default_factory=list)
    explanation: Optional[str] = None
    points: int = 10


class ScenarioAdminOut(BaseModel):
    id: int
    name: str
    description: str
    mitre_technique: str
    status: str
    ad_context: Optional[dict[str, Any]] = None
    alert: Optional[AlertOut] = None
    logs_count: int = 0
    questions_count: int = 0

    model_config = {"from_attributes": True}


class ScenarioAdminDetailOut(BaseModel):
    id: int
    name: str
    description: str
    mitre_technique: str
    status: str
    ad_context: Optional[dict[str, Any]] = None
    alert: Optional[AlertOut] = None
    questions: list[QuestionAdminOut] = Field(default_factory=list)
    logs_count: int = 0

    model_config = {"from_attributes": True}


class ScenarioFullCreate(BaseModel):
    name: str
    description: str
    mitre_technique: str
    status: Optional[str] = "Published"
    ad_context: Optional[dict[str, Any]] = None
    alert_title: Optional[str] = None
    alert_severity: Optional[str] = "High"
    sigma_rule: Optional[str] = None
    questions: Optional[list[QuestionCreate]] = Field(default_factory=list)


class ScenarioFullUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    mitre_technique: Optional[str] = None
    status: Optional[str] = None
    ad_context: Optional[dict[str, Any]] = None
    alert_title: Optional[str] = None
    alert_severity: Optional[str] = None
    sigma_rule: Optional[str] = None
    questions: Optional[list[QuestionCreate]] = None


# ── Auth ──────────────────────────────────────────────────────────────────────

class UserRegister(BaseModel):
    username: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    role: str

    model_config = {"from_attributes": True}


class AuthResponse(BaseModel):
    token: str
    user: UserOut
    message: str = "Success"
"""

# ---------------------------------------------------------------------------
# 5. main.py
# ---------------------------------------------------------------------------
FILES["main.py"] = """from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy import func
import os
import re
import io
import zipfile
import json
from datetime import datetime, timedelta, timezone
from typing import Optional
import bcrypt
from jose import jwt, JWTError

from database import engine, get_db, Base
from models import User, Scenario, Alert, Log, Question, InvestigationResult, SeverityLevel
from schemas import (
    ScenarioOut, AlertOut, LogOut, QuestionOut, QuestionAdminOut,
    SubmissionRequest, SubmissionResponse, QuestionResult,
    ScenarioCreate, ScenarioUpdate, StatusUpdate, AlertCreate, QuestionCreate,
    ScenarioAdminOut, ScenarioAdminDetailOut, ScenarioFullCreate, ScenarioFullUpdate,
    UserRegister, UserLogin, UserOut, AuthResponse,
)

# ── App setup ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="ThreatTrail API",
    description="Backend for the ThreatTrail SOC investigation training platform",
    version="0.4.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── JWT & Auth Security ───────────────────────────────────────────────────────

SECRET_KEY = os.getenv("JWT_SECRET_KEY", "threattrail-soc-jwt-secret-key-2026")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

security = HTTPBearer(auto_error=False)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> Optional[User]:
    \"\"\"Returns authenticated user if token is valid, else None.\"\"\"
    if not credentials:
        return None
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            return None
        return db.query(User).filter(User.username == username).first()
    except JWTError:
        return None


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Administrator privileges required",
        )
    return current_user


@app.on_event("startup")
def on_startup():
    \"\"\"Create all tables if they don't already exist.\"\"\"
    Base.metadata.create_all(bind=engine)


# ── Auth Endpoints ────────────────────────────────────────────────────────────

@app.post("/api/auth/register", response_model=AuthResponse)
def register(body: UserRegister, db: Session = Depends(get_db)):
    username = body.username.strip()
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(body.password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    if not re.match(r"^[a-zA-Z0-9_\\-\\.]+$", username):
        raise HTTPException(status_code=400, detail="Username can only contain letters, numbers, hyphens, and underscores")

    existing = db.query(User).filter(User.username.ilike(username)).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already registered")

    pw_hash = bcrypt.hashpw(body.password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    user = User(username=username, password_hash=pw_hash, role="user")
    db.add(user)
    db.commit()
    db.refresh(user)

    token = create_access_token({"sub": user.username, "role": user.role, "id": user.id})
    return AuthResponse(token=token, user=UserOut.model_validate(user), message="Registration successful")


@app.post("/api/auth/login", response_model=AuthResponse)
def login(body: UserLogin, db: Session = Depends(get_db)):
    username = body.username.strip()
    user = db.query(User).filter(User.username.ilike(username)).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    try:
        valid_pw = bcrypt.checkpw(body.password.encode("utf-8"), user.password_hash.encode("utf-8"))
    except Exception:
        valid_pw = False

    if not valid_pw:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_access_token({"sub": user.username, "role": user.role, "id": user.id})
    return AuthResponse(token=token, user=UserOut.model_validate(user), message="Login successful")


@app.post("/api/auth/admin-login", response_model=AuthResponse)
def admin_login(body: UserLogin, db: Session = Depends(get_db)):
    username = body.username.strip()
    user = db.query(User).filter(User.username.ilike(username)).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid admin credentials")

    try:
        valid_pw = bcrypt.checkpw(body.password.encode("utf-8"), user.password_hash.encode("utf-8"))
    except Exception:
        valid_pw = False

    if not valid_pw:
        raise HTTPException(status_code=401, detail="Invalid admin credentials")

    if user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Access restricted: This account does not possess administrator privileges.",
        )

    token = create_access_token({"sub": user.username, "role": user.role, "id": user.id})
    return AuthResponse(token=token, user=UserOut.model_validate(user), message="Admin authenticated successfully")


@app.get("/api/auth/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user


# ── Trainee Endpoints ──────────────────────────────────────────────────────────

@app.get("/api/scenarios", response_model=list[ScenarioOut])
def list_scenarios(all_status: bool = Query(False, description="Include drafts if true"), db: Session = Depends(get_db)):
    if all_status:
        return db.query(Scenario).all()
    published = db.query(Scenario).filter(Scenario.status == "Published").all()
    if not published:
        return db.query(Scenario).all()
    return published


@app.get("/api/scenarios/{scenario_id}", response_model=ScenarioOut)
def get_scenario_info(scenario_id: int, db: Session = Depends(get_db)):
    \"\"\"Fetch scenario metadata including Active Directory topology context.\"\"\"
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return scenario


@app.get("/api/scenarios/{scenario_id}/alert", response_model=AlertOut)
def get_scenario_alert(scenario_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.scenario_id == scenario_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found for this scenario")
    return alert


@app.get("/api/scenarios/{scenario_id}/logs", response_model=list[LogOut])
def get_scenario_logs(
    scenario_id: int,
    event_id: Optional[int] = Query(None, description="Filter by Windows Event ID"),
    search: Optional[str] = Query(None, description="Search username, IP, or host"),
    limit: int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    query = db.query(Log).filter(Log.scenario_id == scenario_id)
    if event_id is not None:
        query = query.filter(Log.event_id == event_id)
    if search:
        term = f"%{search.strip()}%"
        query = query.filter(
            (Log.username.ilike(term))
            | (Log.source_ip.ilike(term))
            | (Log.target_host.ilike(term))
        )
    logs = query.order_by(Log.timestamp).offset(offset).limit(limit).all()
    if not logs and offset == 0 and event_id is None and not search:
        raise HTTPException(status_code=404, detail="No logs found for this scenario")
    return logs


@app.get("/api/scenarios/{scenario_id}/questions", response_model=list[QuestionOut])
def get_scenario_questions(scenario_id: int, db: Session = Depends(get_db)):
    questions = db.query(Question).filter(Question.scenario_id == scenario_id).all()
    if not questions:
        raise HTTPException(status_code=404, detail="No questions found for this scenario")
    return questions


def is_answer_match(user_raw: str, correct_raw: str, aliases: Optional[list[str]] = None) -> bool:
    \"\"\"
    Smart SOC answer matcher:
    - Case-insensitive, whitespace-trimmed
    - Checks explicit aliases (e.g. ['CORP\\\\svc_backup', 'svc_backup@corp.local'])
    - Automatically matches AD domain-prefixed usernames (e.g. 'CORP\\\\jdoe' == 'jdoe')
    \"\"\"
    u = user_raw.strip().lower()
    c = correct_raw.strip().lower()
    if not u:
        return False
    if u == c:
        return True

    # Check domain-stripped equivalents (e.g. CORP\\svc_backup -> svc_backup)
    u_stripped = u.split("\\\\")[-1].split("@")[0]
    c_stripped = c.split("\\\\")[-1].split("@")[0]
    if u_stripped == c_stripped and len(c_stripped) >= 3:
        return True

    if aliases:
        for alias in aliases:
            if isinstance(alias, str) and u == alias.strip().lower():
                return True
    return False


@app.post("/api/scenarios/{scenario_id}/submit", response_model=SubmissionResponse)
def submit_answers(
    scenario_id: int,
    body: SubmissionRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")

    questions = db.query(Question).filter(Question.scenario_id == scenario_id).all()
    q_map = {q.id: q for q in questions}

    results: list[QuestionResult] = []
    correct_count = 0
    total_points = sum(q.points or 10 for q in questions)
    points_earned = 0

    for ans in body.answers:
        question = q_map.get(ans.question_id)
        if not question:
            raise HTTPException(
                status_code=400,
                detail=f"Question {ans.question_id} does not belong to scenario {scenario_id}",
            )

        q_pts = question.points or 10
        is_correct = is_answer_match(ans.answer, question.correct_answer, question.acceptable_answers)
        if is_correct:
            correct_count += 1
            points_earned += q_pts

        results.append(
            QuestionResult(
                question_id=question.id,
                question_text=question.question_text,
                user_answer=ans.answer,
                correct_answer=question.correct_answer,
                explanation=question.explanation,
                is_correct=is_correct,
                points_awarded=q_pts if is_correct else 0,
                points_possible=q_pts,
            )
        )

    total = len(questions)
    score_percent = round((points_earned / total_points) * 100) if total_points > 0 else (
        round((correct_count / total) * 100) if total > 0 else 0
    )

    # Resolve authenticated user ID (fallback to first user in DB if unauthenticated dev mode)
    resolved_user_id = current_user.id if current_user else 1

    result_record = InvestigationResult(
        user_id=resolved_user_id,
        scenario_id=scenario_id,
        score=score_percent,
        points_earned=points_earned,
        total_points=total_points,
        pinned_log_ids=body.pinned_log_ids or [],
    )
    db.add(result_record)
    db.commit()

    key_logs = (
        db.query(Log.id)
        .filter(Log.scenario_id == scenario_id, Log.is_key_evidence == True)
        .all()
    )
    key_log_ids = [r[0] for r in key_logs]

    return SubmissionResponse(
        scenario_id=scenario_id,
        total_questions=total,
        correct_count=correct_count,
        total_points=total_points,
        points_earned=points_earned,
        score_percent=score_percent,
        pinned_log_ids=body.pinned_log_ids or [],
        key_evidence_log_ids=key_log_ids,
        results=results,
    )


# ── Admin Endpoints ───────────────────────────────────────────────────────────

@app.get("/api/admin/stats")
def get_admin_stats(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    total_scenarios = db.query(Scenario).count()
    published_scenarios = db.query(Scenario).filter(Scenario.status == "Published").count()
    draft_scenarios = db.query(Scenario).filter(Scenario.status == "Draft").count()
    total_logs = db.query(Log).count()
    total_submissions = db.query(InvestigationResult).count()

    return {
        "total_scenarios": total_scenarios,
        "published_scenarios": published_scenarios,
        "draft_scenarios": draft_scenarios,
        "total_logs": total_logs,
        "total_submissions": total_submissions,
    }


@app.get("/api/admin/scenarios", response_model=list[ScenarioAdminOut])
def admin_list_scenarios(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    scenarios = db.query(Scenario).order_by(Scenario.id.desc()).all()

    # Batch counts to avoid N+1 queries
    log_counts = dict(
        db.query(Log.scenario_id, func.count(Log.id)).group_by(Log.scenario_id).all()
    )
    q_counts = dict(
        db.query(Question.scenario_id, func.count(Question.id)).group_by(Question.scenario_id).all()
    )
    alerts_by_sc = {
        a.scenario_id: a for a in db.query(Alert).all()
    }

    results = []
    for sc in scenarios:
        alert = alerts_by_sc.get(sc.id)
        results.append(ScenarioAdminOut(
            id=sc.id,
            name=sc.name,
            description=sc.description,
            mitre_technique=sc.mitre_technique,
            status=sc.status or "Draft",
            ad_context=sc.ad_context,
            alert=AlertOut.model_validate(alert) if alert else None,
            logs_count=log_counts.get(sc.id, 0),
            questions_count=q_counts.get(sc.id, 0),
        ))
    return results


@app.get("/api/admin/scenarios/{scenario_id}", response_model=ScenarioAdminDetailOut)
def admin_get_scenario_detail(scenario_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    sc = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not sc:
        raise HTTPException(status_code=404, detail="Scenario not found")

    alert = db.query(Alert).filter(Alert.scenario_id == sc.id).first()
    questions = db.query(Question).filter(Question.scenario_id == sc.id).all()
    log_cnt = db.query(Log).filter(Log.scenario_id == sc.id).count()

    return ScenarioAdminDetailOut(
        id=sc.id,
        name=sc.name,
        description=sc.description,
        mitre_technique=sc.mitre_technique,
        status=sc.status or "Draft",
        ad_context=sc.ad_context,
        alert=AlertOut.model_validate(alert) if alert else None,
        questions=[QuestionAdminOut.model_validate(q) for q in questions],
        logs_count=log_cnt,
    )


@app.post("/api/admin/scenarios", response_model=ScenarioOut)
def create_scenario(body: ScenarioCreate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    scenario = Scenario(**body.model_dump())
    db.add(scenario)
    db.commit()
    db.refresh(scenario)
    return scenario


@app.post("/api/admin/scenarios/full", response_model=ScenarioAdminDetailOut)
def create_scenario_full(body: ScenarioFullCreate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    \"\"\"Atomic creation of Scenario + Alert + Questions in a single transaction.\"\"\"
    try:
        sc = Scenario(
            name=body.name,
            description=body.description,
            mitre_technique=body.mitre_technique,
            status=body.status or "Published",
            ad_context=body.ad_context or {},
        )
        db.add(sc)
        db.flush()

        alert = Alert(
            scenario_id=sc.id,
            title=body.alert_title or f"Detection Alert: {body.name}",
            severity=body.alert_severity or SeverityLevel.HIGH,
            sigma_rule=body.sigma_rule,
        )
        db.add(alert)

        for q in (body.questions or []):
            if q.question_text.strip() and q.correct_answer.strip():
                db.add(Question(
                    scenario_id=sc.id,
                    question_text=q.question_text.strip(),
                    correct_answer=q.correct_answer.strip(),
                    acceptable_answers=q.acceptable_answers or [],
                    explanation=q.explanation,
                    points=q.points or 10,
                ))

        db.commit()
        return admin_get_scenario_detail(sc.id, db, admin)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to create scenario atomically: {str(e)}")


@app.put("/api/admin/scenarios/{scenario_id}", response_model=ScenarioOut)
def update_scenario(scenario_id: int, body: ScenarioUpdate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    sc = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not sc:
        raise HTTPException(status_code=404, detail="Scenario not found")

    update_data = body.model_dump(exclude_unset=True)
    for field, val in update_data.items():
        setattr(sc, field, val)

    db.commit()
    db.refresh(sc)
    return sc


@app.patch("/api/admin/scenarios/{scenario_id}/status", response_model=ScenarioOut)
def update_scenario_status(scenario_id: int, body: StatusUpdate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    sc = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not sc:
        raise HTTPException(status_code=404, detail="Scenario not found")

    sc.status = body.status
    db.commit()
    db.refresh(sc)
    return sc


@app.put("/api/admin/scenarios/{scenario_id}/full", response_model=ScenarioAdminDetailOut)
def full_update_scenario(scenario_id: int, body: ScenarioFullUpdate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    sc = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not sc:
        raise HTTPException(status_code=404, detail="Scenario not found")

    if body.name is not None:
        sc.name = body.name
    if body.description is not None:
        sc.description = body.description
    if body.mitre_technique is not None:
        sc.mitre_technique = body.mitre_technique
    if body.status is not None:
        sc.status = body.status
    if body.ad_context is not None:
        sc.ad_context = body.ad_context

    if body.alert_title is not None or body.alert_severity is not None or body.sigma_rule is not None:
        alert = db.query(Alert).filter(Alert.scenario_id == scenario_id).first()
        if not alert:
            alert = Alert(
                scenario_id=scenario_id,
                title=body.alert_title or "Security Alert",
                severity=body.alert_severity or SeverityLevel.HIGH,
                sigma_rule=body.sigma_rule,
            )
            db.add(alert)
        else:
            if body.alert_title:
                alert.title = body.alert_title
            if body.alert_severity:
                alert.severity = body.alert_severity
            if body.sigma_rule is not None:
                alert.sigma_rule = body.sigma_rule

    if body.questions is not None:
        db.query(Question).filter(Question.scenario_id == scenario_id).delete()
        for q in body.questions:
            if q.question_text and q.correct_answer:
                new_q = Question(
                    scenario_id=scenario_id,
                    question_text=q.question_text,
                    correct_answer=q.correct_answer,
                    acceptable_answers=q.acceptable_answers or [],
                    explanation=q.explanation,
                    points=q.points if q.points is not None else 10,
                )
                db.add(new_q)

    db.commit()
    return admin_get_scenario_detail(scenario_id, db, admin)


@app.delete("/api/admin/scenarios/{scenario_id}")
def delete_scenario(scenario_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    sc = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not sc:
        raise HTTPException(status_code=404, detail="Scenario not found")

    db.query(InvestigationResult).filter(InvestigationResult.scenario_id == scenario_id).delete()
    db.query(Log).filter(Log.scenario_id == scenario_id).delete()
    db.query(Alert).filter(Alert.scenario_id == scenario_id).delete()
    db.query(Question).filter(Question.scenario_id == scenario_id).delete()
    db.query(Scenario).filter(Scenario.id == scenario_id).delete()
    db.commit()

    return {"status": "success", "message": f"Scenario {scenario_id} deleted successfully"}


@app.post("/api/admin/scenarios/{scenario_id}/alert", response_model=AlertOut)
def create_or_update_alert(scenario_id: int, body: AlertCreate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")

    db.query(Alert).filter(Alert.scenario_id == scenario_id).delete()

    alert = Alert(scenario_id=scenario_id, **body.model_dump())
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


@app.post("/api/admin/scenarios/{scenario_id}/questions", response_model=QuestionAdminOut)
def create_question(scenario_id: int, body: QuestionCreate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")

    question = Question(scenario_id=scenario_id, **body.model_dump())
    db.add(question)
    db.commit()
    db.refresh(question)
    return question


def extract_field_from_message(msg: str, pattern: str) -> Optional[str]:
    \"\"\"
    Extracts key values from Windows Security event Message text.
    Uses re.findall and picks the last valid non-placeholder match so events like
    4624/4625 (which have two 'Account Name:' lines: Subject '-' and Target 'user')
    return the actual target account instead of '-'.
    \"\"\"
    if not msg:
        return None
    matches = re.findall(pattern, msg, re.IGNORECASE)
    valid = [m.strip() for m in matches if m and m.strip() not in ("-", "")]
    return valid[-1] if valid else None


@app.post("/api/admin/scenarios/{scenario_id}/upload-logs")
async def upload_logs(scenario_id: int, file: UploadFile = File(...), db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")

    if not file.filename.endswith('.zip'):
        raise HTTPException(status_code=400, detail="Only .zip files are supported")

    content = await file.read()
    log_entries = []

    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            for info in zf.infolist():
                if info.filename.endswith(".json") or info.filename.endswith(".jsonl"):
                    with zf.open(info) as f:
                        raw = f.read().decode("utf-8", errors="replace")
                        raw_trimmed = raw.strip()

                        parsed_items = []
                        if raw_trimmed.startswith("[") and raw_trimmed.endswith("]"):
                            try:
                                loaded = json.loads(raw_trimmed)
                                if isinstance(loaded, list):
                                    parsed_items = loaded
                            except Exception:
                                pass

                        if not parsed_items:
                            lines = [l.strip() for l in raw_trimmed.split("\\n") if l.strip()]
                            for line in lines:
                                try:
                                    item = json.loads(line)
                                    if isinstance(item, dict):
                                        parsed_items.append(item)
                                except Exception:
                                    continue

                        for data in parsed_items:
                            ts_str = (
                                data.get('TimeCreated')
                                or data.get('@timestamp')
                                or data.get('EventTime')
                                or data.get('UtcTime')
                                or datetime.now().isoformat()
                            )
                            try:
                                if 'T' in str(ts_str):
                                    clean_ts = str(ts_str).replace('Z', '+00:00')
                                    ts = datetime.fromisoformat(clean_ts).replace(tzinfo=None)
                                else:
                                    ts = datetime.strptime(str(ts_str)[:19], "%Y-%m-%d %H:%M:%S")
                            except Exception:
                                ts = datetime.now()

                            event_id_raw = data.get('EventID') or data.get('event_id') or 0
                            if isinstance(event_id_raw, dict):
                                event_id_raw = event_id_raw.get('$numberInt') or 0
                            try:
                                event_id = int(event_id_raw)
                            except Exception:
                                event_id = 0

                            msg = data.get('Message') or ""

                            source_ip = (
                                data.get('SourceAddress')
                                or data.get('IpAddress')
                                or data.get('SourceIp')
                                or data.get('SourceNetworkAddress')
                                or extract_field_from_message(msg, r"Source Network Address:\\s*([^\\r\\n\\t]+)")
                                or extract_field_from_message(msg, r"Source Address:\\s*([^\\r\\n\\t]+)")
                                or extract_field_from_message(msg, r"Client Address:\\s*([^\\r\\n\\t]+)")
                            )
                            if source_ip in ("-", "::1", "127.0.0.1"):
                                source_ip = data.get('IpAddress') or source_ip

                            username = (
                                data.get('TargetUserName')
                                or data.get('AccountName')
                                or data.get('SubjectUserName')
                                or data.get('TargetUser')
                                or extract_field_from_message(msg, r"Account Name:\\s*([^\\r\\n\\t]+)")
                                or extract_field_from_message(msg, r"Target Account:\\s*([^\\r\\n\\t]+)")
                            )

                            target_host = (
                                data.get('Hostname')
                                or data.get('Computer')
                                or data.get('host')
                                or data.get('Workstation')
                                or extract_field_from_message(msg, r"Workstation Name:\\s*([^\\r\\n\\t]+)")
                            )

                            log_entries.append(Log(
                                scenario_id=scenario_id,
                                event_id=event_id,
                                timestamp=ts,
                                source_ip=source_ip,
                                username=username,
                                target_host=target_host,
                                raw_event_data=data
                            ))

                    if log_entries:
                        break

        db.query(Log).filter(Log.scenario_id == scenario_id).delete()
        db.add_all(log_entries)
        db.commit()

        return {
            "status": "success",
            "logs_inserted": len(log_entries),
            "message": f"Successfully ingested {len(log_entries)} Windows Event logs"
        }

    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid zip file format")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Log ingestion error: {str(e)}")
"""

# ---------------------------------------------------------------------------
# 6. seed.py (Seeds 2 Complete AD Scenarios with Sigma Rules + AD Topology)
# ---------------------------------------------------------------------------
FILES["seed.py"] = """\"\"\"
Seed script — populates the ThreatTrail database with two complete AD scenarios:
  1. Password Spraying (MITRE T1110.003)
  2. Kerberoasting Service Account Abuse (MITRE T1558.003)

Includes static Sigma Detection Rules, Active Directory Topology Context,
Acceptable Answer Aliases, and Detailed Explanations.
\"\"\"

from datetime import datetime, timedelta
import bcrypt
from database import engine, SessionLocal, Base
from models import User, Scenario, Alert, Log, Question, SeverityLevel

Base.metadata.drop_all(bind=engine)
Base.metadata.create_all(bind=engine)
print("[+] Tables recreated with Sigma Rules, AD Context, and Answer Explanations.")

db = SessionLocal()

try:
    # ── 1. Seed default users ────────────────────────────────────────────────
    admin_hash = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode("utf-8")
    analyst_hash = bcrypt.hashpw(b"analyst123", bcrypt.gensalt()).decode("utf-8")

    db.add(User(username="admin", password_hash=admin_hash, role="admin"))
    db.add(User(username="analyst", password_hash=analyst_hash, role="user"))
    db.flush()
    print("[+] Default users 'admin' and 'analyst' created.")

    # =========================================================================
    # SCENARIO 1: PASSWORD SPRAYING (MITRE T1110.003)
    # =========================================================================
    sc1_ad_context = {
        "domain": "corp.local",
        "domain_controllers": [
            {"hostname": "DC01.corp.local", "ip": "10.0.0.10", "os": "Windows Server 2022"}
        ],
        "high_value_accounts": [
            {"username": "svc_backup", "groups": ["Backup Operators", "Domain Users"], "note": "Legacy backup account; excluded from MFA policy"},
            {"username": "adm_kaleb", "groups": ["Domain Admins"], "note": "Tier-0 Admin"}
        ],
        "lockout_policy": "5 failed attempts within 30 minutes locks account for 15 minutes",
    }

    sc1 = Scenario(
        name="Active Directory Password Spraying",
        description=(
            "A threat actor is attempting to authenticate across multiple Active Directory user accounts "
            "using a single commonly-used password ('Spring2024!'). This technique avoids account lockout "
            "thresholds by trying one password against many accounts. Investigate the Windows Security "
            "logs, inspect the Sigma rule, and identify the compromised service account."
        ),
        mitre_technique="T1110.003",
        status="Published",
        ad_context=sc1_ad_context,
    )
    db.add(sc1)
    db.flush()

    sc1_sigma = \"\"\"title: Active Directory Password Spraying Detected
id: 6d2c8e1a-9f4b-4b11-8c33-1a2b3c4d5e6f
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
    LogonType: 3
    SubStatus: '0xC000006A'
  timeframe: 5m
  condition: selection | count(TargetUserName) by IpAddress > 10
level: high
tags:
  - attack.credential_access
  - attack.t1110.003\"\"\"

    db.add(Alert(
        scenario_id=sc1.id,
        title="High Severity: Password Spraying — Multiple Distinct Accounts Failed From Single IP",
        severity=SeverityLevel.HIGH,
        sigma_rule=sc1_sigma,
    ))

    ATTACKER_IP = "10.0.5.22"
    TARGET_HOST = "DC01.corp.local"
    COMPROMISED_USER = "svc_backup"
    base_time = datetime(2025, 3, 15, 2, 14, 30)

    spray_targets = [
        "jsmith", "agarcia", "mwilliams", "kjohnson", "lbrown",
        "dlee", "rmartin", "pthompson", "cwilson", "nanderson",
        "btaylor", "hmoore", "fwhite", "eharris", "jclark",
    ]

    sc1_logs = []
    for i, target_user in enumerate(spray_targets):
        ts = base_time + timedelta(seconds=i * 3)
        raw = {
            "EventID": 4625,
            "SourceName": "Microsoft-Windows-Security-Auditing",
            "TimeCreated": ts.isoformat(),
            "Hostname": TARGET_HOST,
            "Channel": "Security",
            "Keywords": "Audit Failure",
            "LogonType": 3,
            "Status": "0xC000006D",
            "SubStatus": "0xC000006A",
            "TargetUserName": target_user,
            "IpAddress": ATTACKER_IP,
            "Message": (
                f"An account failed to log on.\\r\\n\\r\\n"
                f"Subject:\\r\\n\\tSecurity ID:\\tS-1-0-0\\r\\n\\tAccount Name:\\t-\\r\\n\\r\\n"
                f"Logon Information:\\r\\n\\tLogon Type:\\t3\\r\\n"
                f"Account For Which Logon Failed:\\r\\n\\tAccount Name:\\t{target_user}\\r\\n\\tAccount Domain:\\tCORP\\r\\n"
                f"Failure Information:\\r\\n\\tFailure Reason:\\tUnknown user name or bad password.\\r\\n"
                f"\\tStatus:\\t0xC000006D\\r\\n\\tSub Status:\\t0xC000006A\\r\\n\\r\\n"
                f"Network Information:\\r\\n\\tWorkstation Name:\\tATTACKER-WS\\r\\n"
                f"\\tSource Network Address:\\t{ATTACKER_IP}\\r\\n\\tSource Port:\\t{49152 + i}\\r\\n"
                f"Authentication Information:\\r\\n\\tAuthentication Package:\\tNTLM\\r\\n"
            ),
        }
        sc1_logs.append(Log(
            scenario_id=sc1.id,
            event_id=4625,
            timestamp=ts,
            source_ip=ATTACKER_IP,
            username=target_user,
            target_host=TARGET_HOST,
            is_key_evidence=(i == 0),
            raw_event_data=raw,
        ))

    success_ts = base_time + timedelta(seconds=len(spray_targets) * 3 + 5)
    sc1_logs.append(Log(
        scenario_id=sc1.id,
        event_id=4624,
        timestamp=success_ts,
        source_ip=ATTACKER_IP,
        username=COMPROMISED_USER,
        target_host=TARGET_HOST,
        is_key_evidence=True,
        raw_event_data={
            "EventID": 4624,
            "SourceName": "Microsoft-Windows-Security-Auditing",
            "TimeCreated": success_ts.isoformat(),
            "Hostname": TARGET_HOST,
            "Channel": "Security",
            "Keywords": "Audit Success",
            "LogonType": 3,
            "TargetUserName": COMPROMISED_USER,
            "IpAddress": ATTACKER_IP,
            "Message": (
                f"An account was successfully logged on.\\r\\n\\r\\n"
                f"Subject:\\r\\n\\tSecurity ID:\\tS-1-0-0\\r\\n\\tAccount Name:\\t-\\r\\n\\r\\n"
                f"Logon Information:\\r\\n\\tLogon Type:\\t3\\r\\n"
                f"New Logon:\\r\\n\\tAccount Name:\\t{COMPROMISED_USER}\\r\\n\\tAccount Domain:\\tCORP\\r\\n"
                f"Network Information:\\r\\n\\tWorkstation Name:\\tATTACKER-WS\\r\\n"
                f"\\tSource Network Address:\\t{ATTACKER_IP}\\r\\n\\tSource Port:\\t{49152 + 16}\\r\\n"
                f"Authentication Information:\\r\\n\\tAuthentication Package:\\tNTLM\\r\\n"
            ),
        },
    ))
    db.add_all(sc1_logs)

    db.add_all([
        Question(
            scenario_id=sc1.id,
            question_text="What is the source IP address performing the password spray?",
            correct_answer="10.0.5.22",
            acceptable_answers=["10.0.5.22"],
            explanation="All 15 failed Event 4625 logons and the subsequent Event 4624 logon originate from Source Network Address 10.0.5.22.",
            points=10,
        ),
        Question(
            scenario_id=sc1.id,
            question_text="Which account was successfully compromised at the end of the spray?",
            correct_answer="svc_backup",
            acceptable_answers=["corp\\\\svc_backup", "svc_backup@corp.local"],
            explanation="Event ID 4624 at 02:15:20 shows a successful Logon Type 3 from 10.0.5.22 into the 'svc_backup' account.",
            points=25,
        ),
        Question(
            scenario_id=sc1.id,
            question_text="What is the MITRE ATT&CK sub-technique ID for Password Spraying?",
            correct_answer="T1110.003",
            acceptable_answers=["T1110"],
            explanation="T1110.003 is Brute Force: Password Spraying.",
            points=15,
        ),
    ])

    # =========================================================================
    # SCENARIO 2: KERBEROASTING (MITRE T1558.003)
    # =========================================================================
    sc2_ad_context = {
        "domain": "corp.local",
        "domain_controllers": [
            {"hostname": "DC01.corp.local", "ip": "10.0.0.10", "os": "Windows Server 2022"}
        ],
        "service_accounts_with_spn": [
            {"username": "svc_mssql", "spn": "MSSQLSvc/SQL01.corp.local:1433", "encryption": "RC4-HMAC (0x17)", "member_of": ["Domain Admins"]},
            {"username": "svc_iis", "spn": "HTTP/WEB01.corp.local", "encryption": "AES256 (0x12)", "member_of": ["Domain Users"]}
        ],
    }

    sc2 = Scenario(
        name="Kerberoasting Service Account Abuse",
        description=(
            "An attacker with a foothold on a domain workstation requested Kerberos TGS service tickets "
            "(Event ID 4769) downgraded to RC4 encryption (0x17) to crack the service account password offline. "
            "Analyze the Kerberos service ticket logs to identify the compromised workstation, targeted SPN, and encryption downgrade."
        ),
        mitre_technique="T1558.003",
        status="Published",
        ad_context=sc2_ad_context,
    )
    db.add(sc2)
    db.flush()

    sc2_sigma = \"\"\"title: Kerberoasting - RC4 Ticket Encryption Requested (Event 4769)
id: 8f1e2a3b-4c5d-4e6f-9a8b-7c6d5e4f3a2b
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
    TicketOptions: '0x40810000'
  filter:
    ServiceName|endswith: '$'
  condition: selection and not filter
level: high
tags:
  - attack.credential_access
  - attack.t1558.003\"\"\"

    db.add(Alert(
        scenario_id=sc2.id,
        title="High Severity: Kerberos TGS Request Using Legacy RC4 Encryption (0x17)",
        severity=SeverityLevel.HIGH,
        sigma_rule=sc2_sigma,
    ))

    kb_time = datetime(2025, 3, 16, 14, 22, 10)
    sc2_logs = [
        # Normal AES256 computer ticket
        Log(
            scenario_id=sc2.id,
            event_id=4769,
            timestamp=kb_time,
            source_ip="10.0.2.15",
            username="hr_user@CORP.LOCAL",
            target_host="DC01.corp.local",
            is_key_evidence=False,
            raw_event_data={
                "EventID": 4769,
                "TimeCreated": kb_time.isoformat(),
                "Hostname": "DC01.corp.local",
                "TargetUserName": "hr_user@CORP.LOCAL",
                "ServiceName": "DC01$",
                "TicketEncryptionType": "0x12",
                "TicketOptions": "0x40810010",
                "IpAddress": "10.0.2.15",
                "Message": (
                    "A Kerberos service ticket was requested.\\r\\n\\r\\n"
                    "Account Information:\\r\\n\\tAccount Name:\\thr_user@CORP.LOCAL\\r\\n"
                    "Service Information:\\r\\n\\tService Name:\\tDC01$\\r\\n"
                    "Network Information:\\r\\n\\tClient Address:\\t10.0.2.15\\r\\n"
                    "Additional Information:\\r\\n\\tTicket Options:\\t0x40810010\\r\\n"
                    "\\tTicket Encryption Type:\\t0x12\\r\\n"
                ),
            },
        ),
        # Malicious RC4 Kerberoast ticket request
        Log(
            scenario_id=sc2.id,
            event_id=4769,
            timestamp=kb_time + timedelta(seconds=12),
            source_ip="10.0.2.88",
            username="jdoe@CORP.LOCAL",
            target_host="DC01.corp.local",
            is_key_evidence=True,
            raw_event_data={
                "EventID": 4769,
                "TimeCreated": (kb_time + timedelta(seconds=12)).isoformat(),
                "Hostname": "DC01.corp.local",
                "TargetUserName": "jdoe@CORP.LOCAL",
                "ServiceName": "svc_mssql",
                "SPN": "MSSQLSvc/SQL01.corp.local:1433",
                "TicketEncryptionType": "0x17",
                "TicketOptions": "0x40810000",
                "IpAddress": "10.0.2.88",
                "Message": (
                    "A Kerberos service ticket was requested.\\r\\n\\r\\n"
                    "Account Information:\\r\\n\\tAccount Name:\\tjdoe@CORP.LOCAL\\r\\n"
                    "\\tAccount Domain:\\tCORP.LOCAL\\r\\n"
                    "Service Information:\\r\\n\\tService Name:\\tsvc_mssql\\r\\n"
                    "\\tService ID:\\tS-1-5-21-3623811015-3361044348-30300820-1104\\r\\n"
                    "Network Information:\\r\\n\\tClient Address:\\t10.0.2.88\\r\\n"
                    "Additional Information:\\r\\n\\tTicket Options:\\t0x40810000\\r\\n"
                    "\\tTicket Encryption Type:\\t0x17\\r\\n"
                ),
            },
        ),
    ]
    db.add_all(sc2_logs)

    db.add_all([
        Question(
            scenario_id=sc2.id,
            question_text="Which domain user account requested the suspicious RC4 Kerberos service ticket?",
            correct_answer="jdoe",
            acceptable_answers=["jdoe@corp.local", "corp\\\\jdoe"],
            explanation="Event ID 4769 at 14:22:22 shows Account Name 'jdoe@CORP.LOCAL' requesting a ticket for svc_mssql with encryption 0x17.",
            points=15,
        ),
        Question(
            scenario_id=sc2.id,
            question_text="Which service account (Service Name) was targeted for offline cracking?",
            correct_answer="svc_mssql",
            acceptable_answers=["mssqlsvc/sql01.corp.local:1433"],
            explanation="The Service Name in the anomalous Event 4769 is 'svc_mssql' (which is in the Domain Admins group).",
            points=20,
        ),
        Question(
            scenario_id=sc2.id,
            question_text="What hex code in TicketEncryptionType indicates RC4-HMAC downgrade?",
            correct_answer="0x17",
            acceptable_answers=["17"],
            explanation="In Windows Kerberos Event 4769, 0x17 corresponds to RC4-HMAC, whereas 0x12 is AES256.",
            points=15,
        ),
    ])

    db.commit()
    print("\\n[OK] Database seeded with 2 complete AD scenarios (Password Spraying + Kerberoasting)!")

except Exception as e:
    db.rollback()
    print(f"\\n[FAIL] Seed failed: {e}")
    raise
finally:
    db.close()
"""

# ---------------------------------------------------------------------------
# 7. threattrail-frontend/src/api.js
# ---------------------------------------------------------------------------
FILES["threattrail-frontend/src/api.js"] = """import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:5050/api',
})

// Attach Bearer token to all outgoing requests if authenticated
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('threattrail_token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error)
)

// Automatically handle expired/invalid tokens (401)
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      const path = window.location.pathname
      if (!path.includes('/login') && !path.includes('/register')) {
        localStorage.removeItem('threattrail_token')
        localStorage.removeItem('threattrail_user')
      }
    }
    return Promise.reject(error)
  }
)

export default api
"""


def main():
    print("=== Applying ThreatTrail Backend & Frontend Upgrade ===")
    backend_dir = ROOT / "threattrail-backend"
    for rel_path, content in FILES.items():
        if rel_path.startswith("threattrail-frontend/"):
            target = ROOT / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            print(f"  [UPDATED] {rel_path}")
        else:
            if backend_dir.exists():
                b_target = backend_dir / rel_path
                b_target.parent.mkdir(parents=True, exist_ok=True)
                b_target.write_text(content, encoding="utf-8")
                print(f"  [UPDATED] threattrail-backend/{rel_path}")
            target = ROOT / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            print(f"  [UPDATED] {rel_path}")

    print("\n=== Next Steps ===")
    print("1. Install updated dependencies:  pip install -r requirements.txt")
    print("2. Re-seed database with new schema: python seed.py")
    print("3. Restart FastAPI server:        uvicorn main:app --reload --port 5050")


if __name__ == "__main__":
    main()