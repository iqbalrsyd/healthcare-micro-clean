"""Billing service: invoice management and payment gateway integration.

Hardened: amount validated as positive Decimal, payment gateway key never logged,
no internal-error verbosity, audit log on every write, parameterized SQL.
"""
from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager
from decimal import Decimal

from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import text

from config import configure_logging
from db import build_engine, init_schema, make_session_factory, session_scope
from security import (
    Principal,
    audit_access,
    require_role,
    require_service_token,
)

SERVICE_NAME = "billing"
LOGGER = logging.getLogger(SERVICE_NAME)

SCHEMA = """
CREATE TABLE IF NOT EXISTS invoices (
    id UUID PRIMARY KEY,
    patient_id UUID NOT NULL,
    amount NUMERIC(12, 2) NOT NULL CHECK (amount > 0),
    status TEXT NOT NULL DEFAULT 'pending',
    payment_reference TEXT,
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS invoices_patient_idx ON invoices (patient_id);
"""

engine = None
session_factory = None


@asynccontextmanager
async def lifespan(_: FastAPI):
    global engine, session_factory
    engine = build_engine()
    session_factory = make_session_factory(engine)
    init_schema(engine, SCHEMA)
    LOGGER.info("billing service ready")
    yield
    engine.dispose()


app = FastAPI(title="Billing Service", version="1.0.0", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)


class InvoiceCreate(BaseModel):
    patient_id: str = Field(pattern=r"^[0-9a-fA-F-]{36}$")
    amount: Decimal = Field(max_digits=12, decimal_places=2)

    @field_validator("amount")
    @classmethod
    def must_be_positive(cls, value: Decimal) -> Decimal:
        if value <= 0:
            raise ValueError("amount must be positive")
        return value


class InvoiceOut(BaseModel):
    id: str
    patient_id: str
    amount: Decimal
    status: str
    payment_reference: str | None = None


def _get_payment_key() -> str:
    import os
    key = os.environ.get("PAYMENT_GATEWAY_KEY", "").strip()
    if not key or key.startswith("replace-"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Payment provider not configured",
        )
    return key


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": SERVICE_NAME}


@app.post("/billing/invoice", status_code=status.HTTP_201_CREATED,
          dependencies=[Depends(require_service_token)])
def create_invoice(
    payload: InvoiceCreate,
    request: Request,
    principal: Principal = Depends(require_role("billing", "admin", "nurse")),
) -> dict:
    invoice_id = str(uuid.uuid4())
    payment_key = _get_payment_key()
    payment_reference = f"PAY-{uuid.uuid4().hex[:12].upper()}"

    LOGGER.info(
        "payment_initiated invoice=%s amount=%s key_present=%s",
        invoice_id,
        payload.amount,
        bool(payment_key),
    )

    with session_scope(session_factory) as session:
        session.execute(
            text(
                """
                INSERT INTO invoices (id, patient_id, amount, status, payment_reference, created_by)
                VALUES (:id, :patient, :amount, 'pending', :ref, :created_by)
                """
            ),
            {
                "id": invoice_id,
                "patient": payload.patient_id,
                "amount": payload.amount,
                "ref": payment_reference,
                "created_by": principal.subject,
            },
        )
    audit_access(request, principal, "create", "invoice", invoice_id)
    return {"id": invoice_id, "status": "pending", "payment_reference": payment_reference}


@app.get("/invoices", response_model=list[InvoiceOut])
def list_invoices(
    request: Request,
    principal: Principal = Depends(require_role("billing", "admin")),
) -> list[InvoiceOut]:
    with session_scope(session_factory) as session:
        rows = session.execute(
            text(
                "SELECT id, patient_id, amount, status, payment_reference "
                "FROM invoices ORDER BY created_at DESC LIMIT 100"
            )
        ).all()
    audit_access(request, principal, "list", "invoice", outcome=f"count={len(rows)}")
    return [
        InvoiceOut(
            id=str(r.id),
            patient_id=str(r.patient_id),
            amount=r.amount,
            status=r.status,
            payment_reference=r.payment_reference,
        )
        for r in rows
    ]
