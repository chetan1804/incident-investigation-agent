from datetime import datetime

from incident_investigation_agent.database.base import Base
from incident_investigation_agent.database.session import SessionLocal, engine
from incident_investigation_agent.repositories.incident_repository import IncidentRepository


def setup_function() -> None:
    Base.metadata.create_all(bind=engine)


def teardown_function() -> None:
    Base.metadata.drop_all(bind=engine)


def test_incident_repository_can_create_and_lookup_incident() -> None:
    session = SessionLocal()
    try:
        repo = IncidentRepository(session)

        incident = repo.create_incident(
            service_name="payment-service",
            title="Checkout failures",
            summary="High checkout failure rate during payment processing",
            incident_id="INC-1001",
            severity="high",
            status="investigating",
            metadata_json={"region": "us-east-1"},
        )

        repo.create_log(
            service_name="payment-service",
            message="Payment provider timeout",
            level="ERROR",
            incident_id="INC-1001",
            trace_id="trace-123",
            metadata_json={"latency_ms": 8050},
        )

        repo.create_alert(
            service_name="payment-service",
            name="checkout_error_rate_spike",
            severity="critical",
            description="Checkout failure rate exceeded threshold",
            incident_id="INC-1001",
        )

        repo.create_deployment(
            service_name="payment-service",
            deployment_id="DEPLOY-120",
            version="v3.8",
            environment="production",
            status="success",
            notes="Updated payment timeout configuration",
            metadata_json={"commit": "a21d91"},
        )

        fetched = repo.get_incident_by_id("INC-1001")
        logs = repo.get_logs_for_incident("INC-1001")
        alerts = repo.get_related_alerts("INC-1001")
        deployments = repo.get_deployments_for_service("payment-service")

        assert fetched is not None
        assert fetched.title == "Checkout failures"
        assert len(logs) == 1
        assert logs[0].message == "Payment provider timeout"
        assert len(alerts) == 1
        assert alerts[0].name == "checkout_error_rate_spike"
        assert len(deployments) == 1
        assert deployments[0].deployment_id == "DEPLOY-120"
    finally:
        session.close()
