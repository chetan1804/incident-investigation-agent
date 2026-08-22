from incident_investigation_agent.database.base import Base
from incident_investigation_agent.database.session import SessionLocal, engine
from incident_investigation_agent.repositories.incident_repository import IncidentRepository
from incident_investigation_agent.services.incident_service import IncidentService


def setup_function() -> None:
    Base.metadata.create_all(bind=engine)


def teardown_function() -> None:
    Base.metadata.drop_all(bind=engine)


def test_incident_service_creates_and_fetches_incident_data() -> None:
    session = SessionLocal()
    try:
        service = IncidentService(IncidentRepository(session))

        service.create_incident(
            service_name="payment-service",
            title="Checkout failures",
            summary="Payment failures increased after deployment",
            incident_id="INC-2001",
            severity="high",
            status="investigating",
        )

        service.add_log(
            service_name="payment-service",
            message="Payment provider timeout",
            level="ERROR",
            incident_id="INC-2001",
            trace_id="trace-456",
        )

        service.add_alert(
            service_name="payment-service",
            name="error_rate_spike",
            severity="critical",
            description="Failure rate is above threshold",
            incident_id="INC-2001",
        )

        service.add_deployment(
            service_name="payment-service",
            deployment_id="DEPLOY-200",
            version="v3.9",
            environment="production",
            notes="Payment timeout configuration change",
        )

        incident = service.get_incident("INC-2001")
        logs = service.get_logs("INC-2001")
        alerts = service.get_alerts("INC-2001")
        deployments = service.get_deployments("payment-service")

        assert incident is not None
        assert incident.title == "Checkout failures"
        assert len(logs) == 1
        assert logs[0].level == "ERROR"
        assert len(alerts) == 1
        assert alerts[0].severity == "critical"
        assert len(deployments) == 1
        assert deployments[0].deployment_id == "DEPLOY-200"
    finally:
        session.close()
