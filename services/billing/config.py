"""Centralized environment loading and validation for FastAPI services.

All services import this to fail fast on missing required configuration.
"""
from __future__ import annotations

import logging
import os
import sys
from typing import Optional

LOGGER = logging.getLogger(__name__)

_PLACEHOLDER_PREFIXES = ("replace-", "REPLACE-")


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or insecure."""


def _require(name: str, *, allow_placeholder: bool = False) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"Required environment variable {name!r} is not set")
    if not allow_placeholder and any(value.startswith(p) for p in _PLACEHOLDER_PREFIXES):
        raise ConfigError(
            f"Environment variable {name!r} still uses a placeholder value"
        )
    return value


def _optional(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def get_jwt_settings() -> dict:
    secret = _require("JWT_SECRET")
    if len(secret.encode("utf-8")) < 32:
        raise ConfigError("JWT_SECRET must be at least 32 bytes long")
    return {
        "secret": secret,
        "algorithm": _optional("JWT_ALGORITHM", "HS256"),
        "issuer": _require("JWT_ISSUER"),
        "audience": _require("JWT_AUDIENCE"),
        "expiry_seconds": int(_optional("JWT_EXPIRY_SECONDS", "3600")),
    }


def get_db_settings(db_user_var: str = "DB_USER") -> dict:
    return {
        "host": _require("DB_HOST"),
        "port": int(_optional("DB_PORT", "5432")),
        "name": _require("DB_NAME"),
        "user": _require(db_user_var),
        "password": _require("DB_PASSWORD"),
    }


def get_service_token() -> Optional[str]:
    value = _optional("SERVICE_TOKEN_SECRET")
    if not value:
        return None
    if any(value.startswith(p) for p in _PLACEHOLDER_PREFIXES):
        raise ConfigError("SERVICE_TOKEN_SECRET still uses a placeholder value")
    return value


def configure_logging(service_name: str) -> None:
    level = logging.DEBUG if _optional("NODE_ENV", "production") != "production" else logging.INFO
    logging.basicConfig(
        level=level,
        format=f"%(asctime)s %(levelname)s [{service_name}] %(name)s: %(message)s",
        stream=sys.stdout,
    )
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
