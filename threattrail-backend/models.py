from sqlalchemy import (
    Column, Integer, String, Text, ForeignKey, DateTime, Enum as SAEnum
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
    mitre_technique = Column(String(50), nullable=False)
    status = Column(String(20), default="Draft", nullable=False)

    alerts = relationship("Alert", back_populates="scenario", cascade="all, delete-orphan")
    logs = relationship("Log", back_populates="scenario", cascade="all, delete-orphan")
    questions = relationship("Question", back_populates="scenario", cascade="all, delete-orphan")
    investigation_results = relationship("InvestigationResult", back_populates="scenario", cascade="all, delete-orphan")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    scenario_id = Column(Integer, ForeignKey("scenarios.id"), nullable=False)
    title = Column(String(300), nullable=False)
    severity = Column(SAEnum(SeverityLevel), nullable=False)

    scenario = relationship("Scenario", back_populates="alerts")


class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    scenario_id = Column(Integer, ForeignKey("scenarios.id"), nullable=False)
    event_id = Column(Integer, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    source_ip = Column(String(45), nullable=True)
    username = Column(String(150), nullable=True)
    target_host = Column(String(200), nullable=True)
    raw_event_data = Column(JSONB, nullable=False)

    scenario = relationship("Scenario", back_populates="logs")


class Question(Base):
    __tablename__ = "questions"

    id = Column(Integer, primary_key=True, index=True)
    scenario_id = Column(Integer, ForeignKey("scenarios.id"), nullable=False)
    question_text = Column(Text, nullable=False)
    correct_answer = Column(String(300), nullable=False)
    points = Column(Integer, default=10, nullable=False)

    scenario = relationship("Scenario", back_populates="questions")


class InvestigationResult(Base):
    __tablename__ = "investigation_results"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    scenario_id = Column(Integer, ForeignKey("scenarios.id"), nullable=False)
    score = Column(Integer, nullable=False)
    points_earned = Column(Integer, default=0, nullable=False)
    total_points = Column(Integer, default=0, nullable=False)

    user = relationship("User", back_populates="investigation_results")
    scenario = relationship("Scenario", back_populates="investigation_results")
