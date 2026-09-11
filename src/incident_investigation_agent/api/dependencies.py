from __future__ import annotations

from collections.abc import Generator
import hmac

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from incident_investigation_agent.config.settings import settings
from incident_investigation_agent.database.session import SessionLocal
from incident_investigation_agent.exceptions import (
    OperatorAuthenticationError,
    OperatorAuthenticationUnavailableError,
    OperatorAuthorizationError,
)
from incident_investigation_agent.repositories.incident_repository import IncidentRepository
from incident_investigation_agent.services.ai_analysis_service import (
    HypothesisGenerator,
    OpenAIHypothesisGenerator,
    UnavailableHypothesisGenerator,
)
from incident_investigation_agent.services.incident_service import IncidentService
operator_bearer = HTTPBearer(auto_error=False)


def _matches(candidate: str, configured: str | None) -> bool:
    return bool(configured) and hmac.compare_digest(candidate, configured)


def _operator_keys() -> tuple[str | None, str | None]:
    read_key = settings.ingestion_audit_read_api_key
    replay_key = settings.ingestion_audit_replay_api_key
    if read_key and replay_key and hmac.compare_digest(read_key, replay_key):
        raise OperatorAuthenticationUnavailableError(
            "Ingestion audit read and replay API keys must be different"
        )
    return read_key, replay_key


def require_ingestion_audit_reader(
    credentials: HTTPAuthorizationCredentials | None = Depends(operator_bearer),
) -> None:
    configured = _operator_keys()
    if not any(configured):
        raise OperatorAuthenticationUnavailableError(
            "Ingestion audit API authentication is not configured"
        )
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise OperatorAuthenticationError("A bearer token is required")
    matches = [_matches(credentials.credentials, token) for token in configured]
    if not any(matches):
        raise OperatorAuthenticationError("The bearer token is invalid")


def require_ingestion_replay_operator(
    credentials: HTTPAuthorizationCredentials | None = Depends(operator_bearer),
) -> None:
    read_key, replay_key = _operator_keys()
    if not replay_key:
        raise OperatorAuthenticationUnavailableError(
            "Ingestion replay API authentication is not configured"
        )
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise OperatorAuthenticationError("A bearer token is required")
    if _matches(credentials.credentials, replay_key):
        return
    if _matches(credentials.credentials, read_key):
        raise OperatorAuthorizationError(
            "The authenticated operator cannot replay ingestion deliveries"
        )
    raise OperatorAuthenticationError("The bearer token is invalid")


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
