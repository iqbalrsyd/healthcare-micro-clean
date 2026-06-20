"""Unit tests for the auth service config validator."""
import os
import sys
from pathlib import Path

import pytest

SERVICE_DIR = Path(__file__).resolve().parents[1] / "services" / "auth"
sys.path.insert(0, str(SERVICE_DIR))

import config  # noqa: E402


def test_jwt_settings_require_secret(monkeypatch):
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.delenv("JWT_ISSUER", raising=False)
    monkeypatch.delenv("JWT_AUDIENCE", raising=False)
    with pytest.raises(config.ConfigError):
        config.get_jwt_settings()


def test_jwt_settings_reject_placeholder(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "replace-with-something")
    monkeypatch.setenv("JWT_ISSUER", "healthcare-micro-clean")
    monkeypatch.setenv("JWT_AUDIENCE", "healthcare-internal")
    with pytest.raises(config.ConfigError):
        config.get_jwt_settings()


def test_jwt_settings_reject_short_secret(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "short")
    monkeypatch.setenv("JWT_ISSUER", "healthcare-micro-clean")
    monkeypatch.setenv("JWT_AUDIENCE", "healthcare-internal")
    with pytest.raises(config.ConfigError):
        config.get_jwt_settings()


def test_jwt_settings_accept_strong_secret(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "x" * 48)
    monkeypatch.setenv("JWT_ISSUER", "healthcare-micro-clean")
    monkeypatch.setenv("JWT_AUDIENCE", "healthcare-internal")
    settings = config.get_jwt_settings()
    assert settings["algorithm"] == "HS256"
    assert settings["expiry_seconds"] == 3600


def test_db_settings_require_all(monkeypatch):
    monkeypatch.setenv("DB_HOST", "db")
    monkeypatch.setenv("DB_NAME", "auth")
    monkeypatch.setenv("DB_USER", "auth_app")
    monkeypatch.setenv("DB_PASSWORD", "real-password-1234")
    db = config.get_db_settings()
    assert db["host"] == "db"
    assert db["port"] == 5432
