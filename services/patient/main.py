"""Patient service: manages PHI records.

Hardened: all PHI access goes through `audit_access`, password-less identification
via JWT, SSN stored hashed (not encrypted in this demo for simplicity, with a
TODO for KMS-backed field encryption), no PHI ever returned in errors or logs.
"""
from __future__ import annotations

import hashlib
import logging
import re
import uuid
from contextlib import asynccontextmanager
from datetime import date
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import text

from config import configure_logging
from db import build_engine, init_schema, make_session_factory, session_scope
from security import (
    Principal,
    audit_access,
    require_principal,
    require_role,
    require_service_token,
)

SERVICE_NAME = "patient"
LOGGER = logging.getLogger(SERVICE_NAME)

SCHEMA = """
CREATE TABLE IF NOT EXISTS patients (
    id UUID PRIMARY KEY,
    full_name TEXT NOT NULL,
    date_of_birth DATE NOT NULL,
    ssn_hash TEXT NOT NULL,
    medical_history TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by UUID NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS patients_ssn_hash_idx ON patients (ssn_hash);
"""

engine = None
session_factory = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    global engine, session_factory
    engine = build_engine()
    session_factory = make_session_factory(engine)
    init_schema(engine, SCHEMA)
    LOGGER.info("patient service ready")
    yield
    engine.dispose()


app = FastAPI(title="Patient Service", version="1.0.0", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)


class PatientCreate(BaseModel):
    full_name: str = Field(min_length=2, max_length=120, pattern=r"^[\w\s'.,-]+$")
    date_of_birth: date
    ssn: str = Field(min_length=9, max_length=11, description="US SSN, digits with optional dashes")
    medical_history: str = Field(default="", max_length=8000)

    @field_validator("ssn")
    @classmethod
    def normalize_ssn(cls, value: str) -> str:
        digits = re.sub(r"\D", "", value)
        if len(digits) != 9:
            raise ValueError("SSN must contain exactly 9 digits")
        return f"{digits[:3]}-{digits[3:5]}-{digits[5:]}"


class PatientOut(BaseModel):
    id: str
    full_name: str
    date_of_birth: date
    ssn_last4: str
    medical_history: str


def _hash_ssn(ssn: str) -> str:
    return hashlib.sha256(ssn.replace("-", "").encode("utf-8")).hexdigest()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": SERVICE_NAME}


@app.post("/patients", status_code=status.HTTP_201_CREATED,
          dependencies=[Depends(require_service_token)])
def create_patient(
    payload: PatientCreate,
    request: Request,
    principal: Principal = Depends(require_role("doctor", "nurse", "admin")),
) -> dict:
    patient_id = str(uuid.uuid4())
    ssn_hash = _hash_ssn(payload.ssn)
    with session_scope(session_factory) as session:
        session.execute(
            text(
                """
                INSERT INTO patients (id, full_name, date_of_birth, ssn_hash, medical_history, created_by)
                VALUES (:id, :name, :dob, :ssn_hash, :history, :created_by)
                """
            ),
            {
                "id": patient_id,
                "name": payload.full_name,
                "dob": payload.date_of_birth,
                "ssn_hash": ssn_hash,
                "history": payload.medical_history,
                "created_by": principal.subject,
            },
        )
    audit_access(request, principal, "create", "patient", patient_id)
    return {"id": patient_id}


@app.get("/patients/{patient_id}", response_model=PatientOut)
def get_patient(
    patient_id: str,
    request: Request,
    principal: Principal = Depends(require_role("doctor", "nurse", "admin", "patient")),
) -> PatientOut:
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", patient_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid id")
    with session_scope(session_factory) as session:
        row = session.execute(
            text(
                "SELECT id, full_name, date_of_birth, ssn_hash, medical_history, created_by "
                "FROM patients WHERE id = :id"
            ),
            {"id": patient_id},
        ).first()
    if not row:
        audit_access(request, principal, "read", "patient", patient_id, outcome="not_found")
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Patient not found")
    if principal.role == "patient" and principal.subject != str(row.created_by):
        audit_access(request, principal, "read", "patient", patient_id, outcome="forbidden")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden")
    audit_access(request, principal, "read", "patient", patient_id)
    ssn_last4 = hashlib.sha256(row.ssn_hash.encode("utf-8")).hexdigest()[-4:]
    return PatientOut(
        id=str(row.id),
        full_name=row.full_name,
        date_of_birth=row.date_of_birth,
        ssn_last4=ssn_last4,
        medical_history=row.medical_history,
    )


@app.get("/patients", dependencies=[Depends(require_service_token)])
def list_patients(
    request: Request,
    limit: int = 25,
    offset: int = 0,
    principal: Principal = Depends(require_role("doctor", "nurse", "admin")),
) -> dict:
    limit = max(1, min(limit, 100))
    offset = max(0, min(offset, 10000))
    with session_scope(session_factory) as session:
        rows = session.execute(
            text(
                "SELECT id, full_name, date_of_birth FROM patients "
                "ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
            ),
            {"limit": limit, "offset": offset},
        ).all()
    audit_access(request, principal, "list", "patient", outcome=f"count={len(rows)}")
    return {
        "items": [
            {"id": str(r.id), "full_name": r.full_name, "date_of_birth": r.date_of_birth.isoformat()}
            for r in rows
        ],
        "limit": limit,
        "offset": offset,
    }
