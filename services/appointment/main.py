"""Appointment service: manages appointment scheduling.

Hardened: Pydantic input validation, parameterized SQL via SQLAlchemy text(),
JWT-based auth, audit log on every write, inter-service token check.
"""
from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
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

SERVICE_NAME = "appointment"
LOGGER = logging.getLogger(SERVICE_NAME)

SCHEMA = """
CREATE TABLE IF NOT EXISTS appointments (
    id UUID PRIMARY KEY,
    patient_id UUID NOT NULL,
    doctor TEXT NOT NULL,
    appointment_time TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL DEFAULT 'scheduled',
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS appointments_patient_idx ON appointments (patient_id);
CREATE INDEX IF NOT EXISTS appointments_time_idx ON appointments (appointment_time);
"""

engine = None
session_factory = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    global engine, session_factory
    engine = build_engine()
    session_factory = make_session_factory(engine)
    init_schema(engine, SCHEMA)
    LOGGER.info("appointment service ready")
    yield
    engine.dispose()


app = FastAPI(title="Appointment Service", version="1.0.0", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)


class AppointmentCreate(BaseModel):
    patient_id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    doctor: str = Field(min_length=2, max_length=120, pattern=r"^[\w\s'.,-]+$")
    appointment_time: datetime

    @field_validator("appointment_time")
    @classmethod
    def must_be_future(cls, value: datetime) -> datetime:
        if value <= datetime.utcnow().replace(tzinfo=value.tzinfo):
            raise ValueError("appointment_time must be in the future")
        return value


class AppointmentOut(BaseModel):
    id: str
    patient_id: str
    doctor: str
    appointment_time: datetime
    status: str


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": SERVICE_NAME}


@app.post("/appointments", status_code=status.HTTP_201_CREATED,
          dependencies=[Depends(require_service_token)])
def create_appointment(
    payload: AppointmentCreate,
    request: Request,
    principal: Principal = Depends(require_role("doctor", "nurse", "admin")),
) -> dict:
    appointment_id = str(uuid.uuid4())
    with session_scope(session_factory) as session:
        session.execute(
            text(
                """
                INSERT INTO appointments (id, patient_id, doctor, appointment_time, created_by)
                VALUES (:id, :patient, :doctor, :time, :created_by)
                """
            ),
            {
                "id": appointment_id,
                "patient": payload.patient_id,
                "doctor": payload.doctor,
                "time": payload.appointment_time,
                "created_by": principal.subject,
            },
        )
    audit_access(request, principal, "create", "appointment", appointment_id)
    return {"id": appointment_id, "status": "scheduled"}


@app.get("/appointments", response_model=list[AppointmentOut])
def list_appointments(
    request: Request,
    patient_id: Optional[str] = None,
    principal: Principal = Depends(require_role("doctor", "nurse", "admin")),
) -> list[AppointmentOut]:
    if patient_id is not None:
        if not patient_id or len(patient_id) > 64:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid patient_id")
        with session_scope(session_factory) as session:
            rows = session.execute(
                text(
                    "SELECT id, patient_id, doctor, appointment_time, status "
                    "FROM appointments WHERE patient_id = :pid ORDER BY appointment_time DESC LIMIT 100"
                ),
                {"pid": patient_id},
            ).all()
    else:
        with session_scope(session_factory) as session:
            rows = session.execute(
                text(
                    "SELECT id, patient_id, doctor, appointment_time, status "
                    "FROM appointments ORDER BY appointment_time DESC LIMIT 100"
                )
            ).all()
    audit_access(request, principal, "list", "appointment", outcome=f"count={len(rows)}")
    return [
        AppointmentOut(
            id=str(r.id),
            patient_id=str(r.patient_id),
            doctor=r.doctor,
            appointment_time=r.appointment_time,
            status=r.status,
        )
        for r in rows
    ]
