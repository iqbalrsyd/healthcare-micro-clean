"""Unit tests for the security primitives shared across services."""
import os
import sys
import time
from pathlib import Path

import jwt
import pytest

SERVICE_DIR = Path(__file__).resolve().parents[1] / "services" / "auth"
sys.path.insert(0, str(SERVICE_DIR))


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x" * 48)
    monkeypatch.setenv("JWT_ISSUER", "healthcare-micro-clean")
    monkeypatch.setenv("JWT_AUDIENCE", "healthcare-internal")
    monkeypatch.setenv("JWT_EXPIRY_SECONDS", "60")
    yield


def test_issue_and_decode_token_roundtrip():
    from security import issue_token
    token = issue_token(subject="user-1", role="doctor", scopes=["read:patients"])
    payload = jwt.decode(
        token,
        os.environ["JWT_SECRET"],
        algorithms=["HS256"],
        audience=os.environ["JWT_AUDIENCE"],
        issuer=os.environ["JWT_ISSUER"],
    )
    assert payload["sub"] == "user-1"
    assert payload["role"] == "doctor"
    assert payload["scopes"] == ["read:patients"]


def test_token_rejects_wrong_audience():
    from security import issue_token
    token = issue_token(subject="user-1", role="doctor")
    with pytest.raises(jwt.InvalidAudienceError):
        jwt.decode(
            token,
            os.environ["JWT_SECRET"],
            algorithms=["HS256"],
            audience="someone-else",
            issuer=os.environ["JWT_ISSUER"],
        )


def test_token_rejects_expired(monkeypatch):
    from security import issue_token
    monkeypatch.setenv("JWT_EXPIRY_SECONDS", "1")
    token = issue_token(subject="user-1", role="doctor")
    time.sleep(1.2)
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(
            token,
            os.environ["JWT_SECRET"],
            algorithms=["HS256"],
            audience=os.environ["JWT_AUDIENCE"],
            issuer=os.environ["JWT_ISSUER"],
        )


def test_password_hash_and_verify():
    from security import hash_password, verify_password
    h = hash_password("correct horse battery staple")
    assert h != "correct horse battery staple"
    assert verify_password("correct horse battery staple", h) is True
    assert verify_password("wrong", h) is False


def test_password_rejects_short():
    from security import hash_password
    with pytest.raises(ValueError):
        hash_password("short")
