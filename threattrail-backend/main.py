from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
import re
import io
import zipfile
import json
from datetime import datetime, timedelta
from typing import Optional
import bcrypt
from jose import jwt, JWTError

from database import engine, get_db, Base
from models import User, Scenario, Alert, Log, Question, InvestigationResult, SeverityLevel
from schemas import (
    ScenarioOut, AlertOut, LogOut, QuestionOut, QuestionAdminOut,
    SubmissionRequest, SubmissionResponse, QuestionResult,
    ScenarioCreate, ScenarioUpdate, StatusUpdate, AlertCreate, QuestionCreate,
    ScenarioAdminOut, ScenarioAdminDetailOut, ScenarioFullUpdate,
    UserRegister, UserLogin, UserOut, AuthResponse,
)

# ── App setup ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="ThreatTrail API",
    description="Backend for the ThreatTrail SOC investigation training platform",
    version="0.3.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── JWT & Auth Security ───────────────────────────────────────────────────────

SECRET_KEY = "threattrail-soc-jwt-secret-key-2026"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

security = HTTPBearer(auto_error=False)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
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


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: Administrator privileges required",
        )
    return current_user


@app.on_event("startup")
def on_startup():
    """Create all tables if they don't already exist."""
    Base.metadata.create_all(bind=engine)


# ── Auth Endpoints ────────────────────────────────────────────────────────────

@app.post("/api/auth/register", response_model=AuthResponse)
def register(body: UserRegister, db: Session = Depends(get_db)):
    """Register a new normal trainee/analyst account."""
    username = body.username.strip()
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(body.password) < 4:
        raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", username):
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
    """Standard user login for analysts and trainees."""
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
    """Admin-only portal login. Rejects normal users with 403."""
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
    """Retrieve details for the authenticated user session."""
    return current_user


# ── Trainee Endpoints ──────────────────────────────────────────────────────────

@app.get("/api/scenarios", response_model=list[ScenarioOut])
def list_scenarios(all_status: bool = Query(False, description="Include drafts if true"), db: Session = Depends(get_db)):
    """
    List attack scenarios.
    By default, trainees see Published scenarios only.
    """
    if all_status:
        return db.query(Scenario).all()
    published = db.query(Scenario).filter(Scenario.status == "Published").all()
    # Fallback if nothing published yet to prevent totally blank screens during dev
    if not published:
        return db.query(Scenario).all()
    return published


@app.get("/api/scenarios/{scenario_id}/alert", response_model=AlertOut)
def get_scenario_alert(scenario_id: int, db: Session = Depends(get_db)):
    """Fetch the predefined alert for a scenario."""
    alert = db.query(Alert).filter(Alert.scenario_id == scenario_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found for this scenario")
    return alert


@app.get("/api/scenarios/{scenario_id}/logs", response_model=list[LogOut])
def get_scenario_logs(scenario_id: int, db: Session = Depends(get_db)):
    """Fetch the curated Windows Event Logs for a scenario."""
    logs = (
        db.query(Log)
        .filter(Log.scenario_id == scenario_id)
        .order_by(Log.timestamp)
        .all()
    )
    if not logs:
        raise HTTPException(status_code=404, detail="No logs found for this scenario")
    return logs


@app.get("/api/scenarios/{scenario_id}/questions", response_model=list[QuestionOut])
def get_scenario_questions(scenario_id: int, db: Session = Depends(get_db)):
    """Fetch investigation questions (without correct answers)."""
    questions = db.query(Question).filter(Question.scenario_id == scenario_id).all()
    if not questions:
        raise HTTPException(status_code=404, detail="No questions found for this scenario")
    return questions


@app.post("/api/scenarios/{scenario_id}/submit", response_model=SubmissionResponse)
def submit_answers(scenario_id: int, body: SubmissionRequest, db: Session = Depends(get_db)):
    """
    Grade the user's answers against the database.
    Answer comparison is case-insensitive and stripped of whitespace.
    Returns a detailed breakdown of correct/incorrect answers plus a score.
    """
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
        is_correct = ans.answer.strip().lower() == question.correct_answer.strip().lower()
        if is_correct:
            correct_count += 1
            points_earned += q_pts

        results.append(
            QuestionResult(
                question_id=question.id,
                question_text=question.question_text,
                user_answer=ans.answer,
                correct_answer=question.correct_answer,
                is_correct=is_correct,
                points_awarded=q_pts if is_correct else 0,
                points_possible=q_pts,
            )
        )

    total = len(questions)
    score_percent = round((points_earned / total_points) * 100) if total_points > 0 else (
        round((correct_count / total) * 100) if total > 0 else 0
    )

    result_record = InvestigationResult(
        user_id=1,
        scenario_id=scenario_id,
        score=score_percent,
        points_earned=points_earned,
        total_points=total_points,
    )
    db.add(result_record)
    db.commit()

    return SubmissionResponse(
        scenario_id=scenario_id,
        total_questions=total,
        correct_count=correct_count,
        total_points=total_points,
        points_earned=points_earned,
        score_percent=score_percent,
        results=results,
    )


# ── Admin Endpoints ───────────────────────────────────────────────────────────

@app.get("/api/admin/stats")
def get_admin_stats(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """Get high level statistics for the Admin dashboard."""
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
    """List all scenarios with admin metadata (counts, alerts, status)."""
    scenarios = db.query(Scenario).order_by(Scenario.id.desc()).all()
    results = []
    for sc in scenarios:
        alert = db.query(Alert).filter(Alert.scenario_id == sc.id).first()
        log_cnt = db.query(Log).filter(Log.scenario_id == sc.id).count()
        q_cnt = db.query(Question).filter(Question.scenario_id == sc.id).count()

        results.append(ScenarioAdminOut(
            id=sc.id,
            name=sc.name,
            description=sc.description,
            mitre_technique=sc.mitre_technique,
            status=sc.status or "Draft",
            alert=AlertOut.model_validate(alert) if alert else None,
            logs_count=log_cnt,
            questions_count=q_cnt,
        ))
    return results


@app.get("/api/admin/scenarios/{scenario_id}", response_model=ScenarioAdminDetailOut)
def admin_get_scenario_detail(scenario_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """Fetch full scenario details including alert, questions (with answers), and log count."""
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
        alert=AlertOut.model_validate(alert) if alert else None,
        questions=[QuestionAdminOut.model_validate(q) for q in questions],
        logs_count=log_cnt,
    )


@app.post("/api/admin/scenarios", response_model=ScenarioOut)
def create_scenario(body: ScenarioCreate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """Create a new scenario."""
    scenario = Scenario(**body.model_dump())
    db.add(scenario)
    db.commit()
    db.refresh(scenario)
    return scenario


@app.put("/api/admin/scenarios/{scenario_id}", response_model=ScenarioOut)
def update_scenario(scenario_id: int, body: ScenarioUpdate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """Update scenario metadata."""
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
    """Toggle or set scenario status (e.g. 'Published' or 'Draft')."""
    sc = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not sc:
        raise HTTPException(status_code=404, detail="Scenario not found")

    sc.status = body.status
    db.commit()
    db.refresh(sc)
    return sc


@app.put("/api/admin/scenarios/{scenario_id}/full", response_model=ScenarioAdminDetailOut)
def full_update_scenario(scenario_id: int, body: ScenarioFullUpdate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """Update scenario metadata, alert, and questions in one atomic operation."""
    sc = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not sc:
        raise HTTPException(status_code=404, detail="Scenario not found")

    # 1. Update scenario basic fields
    if body.name is not None:
        sc.name = body.name
    if body.description is not None:
        sc.description = body.description
    if body.mitre_technique is not None:
        sc.mitre_technique = body.mitre_technique
    if body.status is not None:
        sc.status = body.status

    # 2. Update alert
    if body.alert_title is not None or body.alert_severity is not None:
        alert = db.query(Alert).filter(Alert.scenario_id == scenario_id).first()
        if not alert:
            alert = Alert(
                scenario_id=scenario_id,
                title=body.alert_title or "Security Alert",
                severity=body.alert_severity or SeverityLevel.HIGH,
            )
            db.add(alert)
        else:
            if body.alert_title:
                alert.title = body.alert_title
            if body.alert_severity:
                alert.severity = body.alert_severity

    # 3. Update questions if provided
    if body.questions is not None:
        db.query(Question).filter(Question.scenario_id == scenario_id).delete()
        for q in body.questions:
            if q.question_text and q.correct_answer:
                new_q = Question(
                    scenario_id=scenario_id,
                    question_text=q.question_text,
                    correct_answer=q.correct_answer,
                    points=q.points if q.points is not None else 10,
                )
                db.add(new_q)

    db.commit()
    return admin_get_scenario_detail(scenario_id, db, admin)


@app.delete("/api/admin/scenarios/{scenario_id}")
def delete_scenario(scenario_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """Delete a scenario and all associated alerts, logs, questions, and results."""
    sc = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not sc:
        raise HTTPException(status_code=404, detail="Scenario not found")

    # Explicit deletion of child entities to ensure clean deletion
    db.query(InvestigationResult).filter(InvestigationResult.scenario_id == scenario_id).delete()
    db.query(Log).filter(Log.scenario_id == scenario_id).delete()
    db.query(Alert).filter(Alert.scenario_id == scenario_id).delete()
    db.query(Question).filter(Question.scenario_id == scenario_id).delete()
    db.query(Scenario).filter(Scenario.id == scenario_id).delete()
    db.commit()

    return {"status": "success", "message": f"Scenario {scenario_id} deleted successfully"}


@app.post("/api/admin/scenarios/{scenario_id}/alert", response_model=AlertOut)
def create_or_update_alert(scenario_id: int, body: AlertCreate, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """Create or overwrite the alert for a scenario."""
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
    """Add a question to a scenario."""
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found")

    question = Question(scenario_id=scenario_id, **body.model_dump())
    db.add(question)
    db.commit()
    db.refresh(question)
    return question


def extract_field_from_message(msg: str, pattern: str) -> Optional[str]:
    """Helper to extract key values from standard Windows Security event Message text."""
    if not msg:
        return None
    match = re.search(pattern, msg, re.IGNORECASE)
    if match:
        val = match.group(1).strip()
        return val if val and val != "-" else None
    return None


@app.post("/api/admin/scenarios/{scenario_id}/upload-logs")
async def upload_logs(scenario_id: int, file: UploadFile = File(...), db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    """
    Ingest Windows Event logs from a ZIP archive containing JSON or JSONL files.
    Extracts timestamps, EventID, Source IP, Username, Host, and full raw payload.
    """
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
                        # Check if whole file is a single JSON array
                        if raw_trimmed.startswith("[") and raw_trimmed.endswith("]"):
                            try:
                                loaded = json.loads(raw_trimmed)
                                if isinstance(loaded, list):
                                    parsed_items = loaded
                            except Exception:
                                pass

                        # Otherwise parse line-delimited JSON
                        if not parsed_items:
                            lines = [l.strip() for l in raw_trimmed.split("\n") if l.strip()]
                            for line in lines:
                                try:
                                    item = json.loads(line)
                                    if isinstance(item, dict):
                                        parsed_items.append(item)
                                except Exception:
                                    continue

                        for data in parsed_items:
                            # 1. Timestamp extraction
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
                                    ts = datetime.fromisoformat(clean_ts)
                                else:
                                    ts = datetime.strptime(str(ts_str)[:19], "%Y-%m-%d %H:%M:%S")
                            except Exception:
                                ts = datetime.now()

                            # 2. Event ID
                            event_id_raw = data.get('EventID') or data.get('event_id') or 0
                            try:
                                event_id = int(event_id_raw)
                            except Exception:
                                event_id = 0

                            msg = data.get('Message') or ""

                            # 3. Source IP
                            source_ip = (
                                data.get('SourceAddress')
                                or data.get('IpAddress')
                                or data.get('SourceIp')
                                or data.get('SourceNetworkAddress')
                                or extract_field_from_message(msg, r"Source Network Address:\s*([^\r\n\t]+)")
                                or extract_field_from_message(msg, r"Source Address:\s*([^\r\n\t]+)")
                            )

                            # 4. Username / Account
                            username = (
                                data.get('TargetUserName')
                                or data.get('AccountName')
                                or data.get('SubjectUserName')
                                or data.get('TargetUser')
                                or extract_field_from_message(msg, r"Account Name:\s*([^\r\n\t]+)")
                                or extract_field_from_message(msg, r"Target Account:\s*([^\r\n\t]+)")
                            )

                            # 5. Hostname / Computer
                            target_host = (
                                data.get('Hostname')
                                or data.get('Computer')
                                or data.get('host')
                                or data.get('Workstation')
                                or extract_field_from_message(msg, r"Workstation Name:\s*([^\r\n\t]+)")
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

                    # Process the first valid JSON/JSONL dataset file in the zip
                    if log_entries:
                        break

        # Delete existing logs for this scenario
        db.query(Log).filter(Log.scenario_id == scenario_id).delete()

        # Batch insert logs
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
