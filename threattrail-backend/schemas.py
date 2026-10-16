from pydantic import BaseModel, Field
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
    is_key_evidence: bool = False
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
