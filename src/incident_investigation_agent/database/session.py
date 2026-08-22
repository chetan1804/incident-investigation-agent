from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from incident_investigation_agent.config.settings import settings
from incident_investigation_agent.database.base import Base

engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    future=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)


def create_db_and_tables() -> None:
    """Create database tables for the active connection."""
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    """Provide a per-request database session."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
