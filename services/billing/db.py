"""Connection pool helper for PostgreSQL.

Each service creates a single SQLAlchemy engine in its lifespan handler and
acquires connections through it. The password is provided via env (validated
in config.py) and never logged.
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import get_db_settings

LOGGER = logging.getLogger(__name__)


def build_engine(*, db_user_var: str = "DB_USER", pool_size: int = 5, max_overflow: int = 2) -> Engine:
    settings = get_db_settings(db_user_var=db_user_var)
    url = (
        f"postgresql+psycopg://{settings['user']}:{settings['password']}"
        f"@{settings['host']}:{settings['port']}/{settings['name']}?sslmode=require"
    )
    return create_engine(
        url,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_pre_ping=True,
        pool_recycle=1800,
        future=True,
    )


def make_session_factory(engine: Engine) -> sessionmaker:
    return sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


@contextmanager
def session_scope(factory: sessionmaker) -> Iterator[Session]:
    session: Session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_schema(engine: Engine, ddl: str) -> None:
    with engine.begin() as conn:
        for statement in ddl.strip().split(";"):
            stmt = statement.strip()
            if stmt:
                conn.execute(text(stmt))
