import io
import zipfile
import pytest
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.testclient import TestClient
from pydantic import BaseModel, Field
from security_hardening import register_security_hardening, validate_and_extract_log_upload

# Minimal self-contained test harness verifying security & functional invariants
app = FastAPI()
register_security_hardening(app)


class SubmissionPayload(BaseModel):
    answers: dict[str, str] = Field(..., max_length=20)


@app.post("/api/auth/login")
def mock_login(username: str = "", password: str = ""):
    if username == "analyst" and password == "valid":
        return {"access_token": "mock_jwt", "token_type": "bearer"}
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/api/scenarios/1/questions")
def get_questions():
    # Must NEVER expose correct_answer to client
    return [{"id": 1, "scenario_id": 1, "question_text": "What is the source IP?", "points": 10}]


@app.post("/api/scenarios/1/submit")
def submit_answers(payload: SubmissionPayload, auth: str | None = None):
    for key, val in payload.answers.items():
        if len(val) > 512:
            raise HTTPException(status_code=422, detail="Answer input too long")
    score = 10 if payload.answers.get("1", "").strip() == "192.168.1.200" else 0
    return {"score": score, "total": 10}


@app.post("/api/admin/upload-logs")
async def upload_logs(file: UploadFile = File(...)):
    events = await validate_and_extract_log_upload(file)
    return {"count": len(events)}


client = TestClient(app)


def test_security_headers_present():
    res = client.get("/api/scenarios/1/questions")
    assert res.status_code == 200
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert res.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in res.headers


def test_questions_endpoint_does_not_leak_correct_answer():
    res = client.get("/api/scenarios/1/questions")
    data = res.json()
    assert len(data) == 1
    assert "correct_answer" not in data[0]


def test_oversized_input_rejected():
    huge_input = "A" * 5000
    res = client.post("/api/scenarios/1/submit", json={"answers": {"1": huge_input}})
    assert res.status_code == 422


def test_zip_slip_path_traversal_rejected():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/passwd.json", '{"EventID": 4624}')
    buf.seek(0)
    res = client.post(
        "/api/admin/upload-logs",
        files={"file": ("evil.zip", buf.getvalue(), "application/zip")},
    )
    assert res.status_code == 400
    assert "Unsafe path" in res.json()["detail"]


def test_rate_limiting_blocks_brute_force():
    codes = []
    for _ in range(18):
        r = client.post("/api/auth/login", params={"username": "analyst", "password": "wrong"})
        codes.append(r.status_code)
    assert 429 in codes
