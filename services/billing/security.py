"""Reusable security primitives: JWT verification, password hashing, audit logging.

Used by every service in the stack so that auth, audit, and cryptography are
implemented consistently and reviewed in one place.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets
import time
from dataclasses import dataclass
from typing import Iterable, Optional

import jwt
from fastapi import Depends, Header, HTTPException, Request, status
from passlib.context import CryptContext

from .config import get_jwt_settings, get_service_token

LOGGER = logging.getLogger(__name__)

PWD_CONTEXT = CryptContext(schemes=["bcrypt"], deprecated="auto")
ALLOWED_ROLES = {"doctor", "nurse", "admin", "billing", "patient"}


@dataclass(frozen=True)
class Principal:
    subject: str
    role: str
    scopes: tuple
    raw: dict


def hash_password(plaintext: str) -> str:
    if len(plaintext) < 12 or len(plaintext) > 128:
        raise ValueError("Password must be 12-128 characters long")
    return PWD_CONTEXT.hash(plaintext)


def verify_password(plaintext: str, password_hash: str) -> bool:
    try:
        return PWD_CONTEXT.verify(plaintext, password_hash)
    except ValueError:
        return False


def issue_token(*, subject: str, role: str, scopes: Iterable[str] = ()) -> str:
    settings = get_jwt_settings()
    now = int(time.time())
    payload = {
        "sub": str(subject),
        "role": role,
        "scopes": list(scopes),
        "iss": settings["issuer"],
        "aud": settings["audience"],
        "iat": now,
        "nbf": now,
        "exp": now + settings["expiry_seconds"],
        "jti": secrets.token_urlsafe(16),
    }
    return jwt.encode(payload, settings["secret"], algorithm=settings["algorithm"])


def _decode(token: str) -> dict:
    settings = get_jwt_settings()
    return jwt.decode(
        token,
        settings["secret"],
        algorithms=[settings["algorithm"]],
        audience=settings["audience"],
        issuer=settings["issuer"],
        options={"require": ["exp", "iat", "sub", "aud", "iss"]},
    )


def require_principal(
    authorization: Optional[str] = Header(default=None),
    x_service_token: Optional[str] = Header(default=None, alias="X-Service-Token"),
) -> Principal:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header",
            headers={"WWW-Authenticate": 'Bearer realm="healthcare"'},
        )
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = _decode(token)
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc

    role = payload.get("role", "")
    if role not in ALLOWED_ROLES:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Role not permitted")

    return Principal(
        subject=str(payload["sub"]),
        role=role,
        scopes=tuple(payload.get("scopes") or ()),
        raw=payload,
    )


def require_service_token(
    x_service_token: Optional[str] = Header(default=None, alias="X-Service-Token"),
) -> None:
    expected = get_service_token()
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Service-to-service token not configured",
        )
    if not x_service_token or not hmac.compare_digest(x_service_token, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid service token"
        )


def require_role(*roles: str):
    def _checker(principal: Principal = Depends(require_principal)) -> Principal:
        if principal.role not in roles and principal.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role"
            )
        return principal
    return _checker


def audit_access(
    request: Request,
    principal: Principal,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    outcome: str = "success",
) -> None:
    """Append a structured audit log entry for PHI/data access."""
    LOGGER.info(
        "audit action=%s service=%s resource=%s rid=%s subject=%s role=%s ip=%s outcome=%s ua=%s",
        action,
        request.url.path,
        resource_type,
        resource_id or "-",
        principal.subject,
        principal.role,
        request.client.host if request.client else "-",
        outcome,
        request.headers.get("user-agent", "-"),
    )


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def redact(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return base64.b16encode(digest).decode("ascii")[:16]
