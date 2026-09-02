from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from incident_investigation_agent.api.app import app
from incident_investigation_agent.api.dependencies import get_incident_service
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
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
