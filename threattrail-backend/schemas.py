from pydantic import BaseModel
from typing import Any, Optional
from datetime import datetime


# ── Scenario ──────────────────────────────────────────────────────────────────

class ScenarioOut(BaseModel):
    id: int
    name: str
    description: str
    mitre_technique: str
    status: str = "Draft"

    model_config = {"from_attributes": True}


# ── Alert ─────────────────────────────────────────────────────────────────────

class AlertOut(BaseModel):
    id: int
    scenario_id: int
    title: str
    severity: str

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
    # NOTE: correct_answer is intentionally excluded — never sent to regular trainees

    model_config = {"from_attributes": True}


class QuestionAdminOut(BaseModel):
    id: int
    scenario_id: int
    question_text: str
    correct_answer: str
    points: int = 10

    model_config = {"from_attributes": True}


# ── Submission (request body) ─────────────────────────────────────────────────

class AnswerSubmission(BaseModel):
    """One answer from the user: question_id → their answer string."""
    question_id: int
    answer: str


class SubmissionRequest(BaseModel):
    """POST body for /api/scenarios/{id}/submit"""
    answers: list[AnswerSubmission]


# ── Grading result (response) ─────────────────────────────────────────────────

class QuestionResult(BaseModel):
    question_id: int
    question_text: str
    user_answer: str
    correct_answer: str
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
    results: list[QuestionResult]


# ── Admin Schemas ─────────────────────────────────────────────────────────────

class ScenarioCreate(BaseModel):
    name: str
    description: str
    mitre_technique: str
    status: Optional[str] = "Published"


class ScenarioUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    mitre_technique: Optional[str] = None
    status: Optional[str] = None


class StatusUpdate(BaseModel):
    status: str


class AlertCreate(BaseModel):
    title: str
    severity: str


class QuestionCreate(BaseModel):
    question_text: str
    correct_answer: str
    points: int = 10


class ScenarioAdminOut(BaseModel):
    id: int
    name: str
    description: str
    mitre_technique: str
    status: str
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
    alert: Optional[AlertOut] = None
    questions: list[QuestionAdminOut] = []
    logs_count: int = 0

    model_config = {"from_attributes": True}


class ScenarioFullUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    mitre_technique: Optional[str] = None
    status: Optional[str] = None
    alert_title: Optional[str] = None
    alert_severity: Optional[str] = None
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
