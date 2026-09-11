from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from incident_investigation_agent.api.app import app
from incident_investigation_agent.api.dependencies import get_incident_service
from incident_investigation_agent.config.settings import settings
from incident_investigation_agent.database.base import Base
from incident_investigation_agent.repositories.incident_repository import IncidentRepository
from incident_investigation_agent.services.incident_service import IncidentService


@pytest.fixture
def db_session(tmp_path) -> Generator[Session, None, None]:
    """Give each test an isolated SQLite database."""
    test_engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(bind=test_engine)
    test_session_factory = sessionmaker(bind=test_engine, autoflush=False, autocommit=False)
    session = test_session_factory()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)
        test_engine.dispose()


@pytest.fixture
def client(db_session: Session) -> Generator[TestClient, None, None]:
    def override_incident_service() -> IncidentService:
        return IncidentService(IncidentRepository(db_session))

    app.dependency_overrides[get_incident_service] = override_incident_service
    previous_read_key = settings.ingestion_audit_read_api_key
    previous_replay_key = settings.ingestion_audit_replay_api_key
    settings.ingestion_audit_read_api_key = "test-audit-read-key"
    settings.ingestion_audit_replay_api_key = "test-audit-replay-key"
    try:
        with TestClient(app) as test_client:
            test_client.headers["authorization"] = "Bearer test-audit-replay-key"
            yield test_client
    finally:
        settings.ingestion_audit_read_api_key = previous_read_key
        settings.ingestion_audit_replay_api_key = previous_replay_key
        app.dependency_overrides.clear()
