from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Query, status
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
    """Returns authenticated user if token is valid, else None."""
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
    """Create all tables if they don't already exist."""
    Base.metadata.create_all(bind=engine)


# ── Auth Endpoints ────────────────────────────────────────────────────────────

@app.post("/api/auth/register", response_model=AuthResponse)
def register(body: UserRegister, db: Session = Depends(get_db)):
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
    """Fetch scenario metadata including Active Directory topology context."""
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
    search: Optional[str] = Query(None, description="Search username, IP, host, or raw event data"),
    key_evidence_only: bool = Query(False, description="Return only key evidence logs"),
    limit: int = Query(2000, ge=1, le=10000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    from sqlalchemy import cast, String as SAString
    query = db.query(Log).filter(Log.scenario_id == scenario_id)
    if event_id is not None:
        query = query.filter(Log.event_id == event_id)
    if key_evidence_only:
        query = query.filter(Log.is_key_evidence == True)
    if search:
        term = f"%{search.strip()}%"
        # Search structured columns + the full raw JSON text (cast to string)
        query = query.filter(
            (Log.username.ilike(term))
            | (Log.source_ip.ilike(term))
            | (Log.target_host.ilike(term))
            | (cast(Log.raw_event_data, SAString).ilike(term))
        )
    # Key evidence rows bubble up first, then chronological order
    logs = query.order_by(Log.is_key_evidence.desc(), Log.timestamp).offset(offset).limit(limit).all()
    if not logs and offset == 0 and event_id is None and not search and not key_evidence_only:
        raise HTTPException(status_code=404, detail="No logs found for this scenario")
    return logs


@app.get("/api/scenarios/{scenario_id}/questions", response_model=list[QuestionOut])
def get_scenario_questions(scenario_id: int, db: Session = Depends(get_db)):
    questions = db.query(Question).filter(Question.scenario_id == scenario_id).all()
    if not questions:
        raise HTTPException(status_code=404, detail="No questions found for this scenario")
    return questions


def is_answer_match(user_raw: str, correct_raw: str, aliases: Optional[list[str]] = None) -> bool:
    """
    Smart SOC answer matcher:
    - Case-insensitive, whitespace-trimmed
    - Checks explicit aliases (e.g. ['CORP\\svc_backup', 'svc_backup@corp.local'])
    - Automatically matches AD domain-prefixed usernames (e.g. 'CORP\\jdoe' == 'jdoe')
    """
    u = user_raw.strip().lower()
    c = correct_raw.strip().lower()
    if not u:
        return False
    if u == c:
        return True

    # Check domain-stripped equivalents (e.g. CORP\svc_backup -> svc_backup)
    u_stripped = u.split("\\")[-1].split("@")[0]
    c_stripped = c.split("\\")[-1].split("@")[0]
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
    """Atomic creation of Scenario + Alert + Questions in a single transaction."""
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
    """
    Extracts key values from Windows Security event Message text.
    Uses re.findall and picks the last valid non-placeholder match so events like
    4624/4625 (which have two 'Account Name:' lines: Subject '-' and Target 'user')
    return the actual target account instead of '-'.
    """
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
                            lines = [l.strip() for l in raw_trimmed.split("\n") if l.strip()]
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
                                or extract_field_from_message(msg, r"Source Network Address:\s*([^\r\n\t]+)")
                                or extract_field_from_message(msg, r"Source Address:\s*([^\r\n\t]+)")
                                or extract_field_from_message(msg, r"Client Address:\s*([^\r\n\t]+)")
                            )
                            if source_ip in ("-", "::1", "127.0.0.1"):
                                source_ip = data.get('IpAddress') or source_ip

                            username = (
                                data.get('TargetUserName')
                                or data.get('AccountName')
                                or data.get('SubjectUserName')
                                or data.get('TargetUser')
                                or extract_field_from_message(msg, r"Account Name:\s*([^\r\n\t]+)")
                                or extract_field_from_message(msg, r"Target Account:\s*([^\r\n\t]+)")
                            )

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
