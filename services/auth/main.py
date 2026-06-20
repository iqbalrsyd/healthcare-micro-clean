"""Auth service: issues and verifies JWTs, manages user accounts.

Hardened: Pydantic input validation, bcrypt password hashing, structured audit
log on every login, constant-time comparisons, no PHI logged.
"""
from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import text

from config import configure_logging
from db import build_engine, init_schema, make_session_factory, session_scope
from security import (
    Principal,
    audit_access,
    hash_password,
    issue_token,
    require_principal,
    verify_password,
)

SERVICE_NAME = "auth"
LOGGER = logging.getLogger(SERVICE_NAME)
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS users_email_idx ON users (email);
"""

engine = None
session_factory = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    global engine, session_factory
    engine = build_engine()
    session_factory = make_session_factory(engine)
    init_schema(engine, SCHEMA)
    LOGGER.info("auth service ready")
    yield
    engine.dispose()


app = FastAPI(
    title="Auth Service",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    role: str = Field(pattern="^(doctor|nurse|admin|billing|patient)$")


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int


class VerifyResponse(BaseModel):
    sub: str
    role: str
    scopes: list


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": SERVICE_NAME}


@app.post("/auth/register", status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest) -> dict:
    if payload.role == "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin self-registration disabled")
    user_id = str(uuid.uuid4())
    password_hash = hash_password(payload.password)
    try:
        with session_scope(session_factory) as session:
            session.execute(
                text(
                    "INSERT INTO users (id, email, password_hash, role) VALUES (:id, :email, :hash, :role)"
                ),
                {"id": user_id, "email": str(payload.email).lower(), "hash": password_hash, "role": payload.role},
            )
    except Exception as exc:  # noqa: BLE001
        LOGGER.warning("register failed for email_hash=%s", hash(payload.email))
        if "unique" in str(exc).lower():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered") from exc
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Registration failed") from exc
    LOGGER.info("user registered email_hash=%s role=%s", hash(payload.email), payload.role)
    return {"id": user_id, "email": str(payload.email).lower(), "role": payload.role}


@app.post("/auth/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request) -> TokenResponse:
    with session_scope(session_factory) as session:
        row = session.execute(
            text(
                "SELECT id, email, password_hash, role, is_active FROM users WHERE email = :email"
            ),
            {"email": str(payload.email).lower()},
        ).first()

    if not row or not row.is_active or not verify_password(payload.password, row.password_hash):
        LOGGER.info("login failed email_hash=%s ip=%s", hash(payload.email), request.client.host if request.client else "-")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    token = issue_token(subject=row.id, role=row.role, scopes=["read:self", "write:self"])
    LOGGER.info("login success user_id=%s role=%s", row.id, row.role)
    return TokenResponse(access_token=token, expires_in=3600)


@app.get("/auth/verify", response_model=VerifyResponse)
def verify(principal: Principal = Depends(require_principal)) -> VerifyResponse:
    return VerifyResponse(sub=principal.subject, role=principal.role, scopes=list(principal.scopes))
