from __future__ import annotations

from collections.abc import Generator

from incident_investigation_agent.database.session import SessionLocal
from incident_investigation_agent.repositories.incident_repository import IncidentRepository
from incident_investigation_agent.services.incident_service import IncidentService


def get_repository() -> Generator[IncidentRepository, None, None]:
    session = SessionLocal()
    try:
        yield IncidentRepository(session)
    finally:
        session.close()


def get_incident_service() -> Generator[IncidentService, None, None]:
    session = SessionLocal()
    try:
        yield IncidentService(IncidentRepository(session))
    finally:
        session.close()
