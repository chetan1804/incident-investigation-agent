from __future__ import annotations

from collections.abc import Generator

from incident_investigation_agent.config.settings import settings
from incident_investigation_agent.database.session import SessionLocal
from incident_investigation_agent.repositories.incident_repository import IncidentRepository
from incident_investigation_agent.services.ai_analysis_service import (
    HypothesisGenerator,
    OpenAIHypothesisGenerator,
    UnavailableHypothesisGenerator,
)
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


def get_hypothesis_generator() -> HypothesisGenerator:
    if not settings.openai_api_key:
        return UnavailableHypothesisGenerator()
    return OpenAIHypothesisGenerator(
        api_key=settings.openai_api_key,
        model=settings.openai_model,
    )
