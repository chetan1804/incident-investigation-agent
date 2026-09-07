from datetime import UTC, datetime

from sqlalchemy.orm import Session

from incident_investigation_agent.repositories.incident_repository import IncidentRepository
from incident_investigation_agent.services.incident_service import IncidentService


def test_incident_service_creates_and_fetches_incident_data(db_session: Session) -> None:
    service = IncidentService(IncidentRepository(db_session))
    incident_start = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)

    service.create_incident(
        service_name="payment-service",
        title="Checkout failures",
        summary="Payment failures increased after deployment",
        incident_id="INC-2001",
        severity="high",
        status="investigating",
        started_at=incident_start,
    )

    service.add_log(
        service_name="payment-service",
        message="Payment provider timeout",
        level="ERROR",
        incident_id="INC-2001",
        trace_id="trace-456",
        timestamp=datetime(2026, 8, 22, 12, 5, tzinfo=UTC),
    )

    service.add_alert(
        service_name="payment-service",
        name="error_rate_spike",
        severity="critical",
        description="Failure rate is above threshold",
        incident_id="INC-2001",
        fired_at=datetime(2026, 8, 22, 12, 2, tzinfo=UTC),
    )

    service.add_deployment(
        service_name="payment-service",
        deployment_id="DEPLOY-200",
        version="v3.9",
        environment="production",
        notes="Payment timeout configuration change",
        deployed_at=datetime(2026, 8, 22, 11, 50, tzinfo=UTC),
    )

    incident = service.get_incident("INC-2001")
    logs = service.get_logs("INC-2001")
    alerts = service.get_alerts("INC-2001")
    deployments = service.get_deployments("payment-service")
    investigation = service.investigate("INC-2001")

    assert incident is not None
    assert incident.title == "Checkout failures"
    assert len(logs) == 1
    assert logs[0].level == "ERROR"
    assert len(alerts) == 1
    assert alerts[0].severity == "critical"
    assert len(deployments) == 1
    assert deployments[0].deployment_id == "DEPLOY-200"
    assert investigation is not None
    assert investigation["signals"] == [
        "alert:error_rate_spike (critical)",
        "log:ERROR Payment provider timeout",
        "deployment:DEPLOY-200 (v3.9)",
    ]
    assert [signal["kind"] for signal in investigation["ranked_signals"]] == [
        "alert",
        "deployment",
        "log",
    ]
    assert len(investigation["root_cause_candidates"]) == 3


def test_investigation_only_correlates_evidence_inside_time_window(db_session: Session) -> None:
    service = IncidentService(IncidentRepository(db_session))
    incident_start = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
    service.create_incident(
        service_name="catalog-service",
        title="Catalog unavailable",
        summary="Catalog requests are failing",
        incident_id="INC-2002",
        started_at=incident_start,
    )

    service.add_log(
        service_name="catalog-service",
        message="Connection refused",
        level="ERROR",
        incident_id="INC-2002",
        timestamp=datetime(2026, 8, 22, 11, 55, tzinfo=UTC),
    )
    service.add_log(
        service_name="catalog-service",
        message="Old unrelated failure",
        level="ERROR",
        incident_id="INC-2002",
        timestamp=datetime(2026, 8, 22, 9, 0, tzinfo=UTC),
    )
    service.add_alert(
        service_name="catalog-service",
        name="catalog_error_rate",
        severity="critical",
        incident_id="INC-2002",
        fired_at=datetime(2026, 8, 22, 12, 10, tzinfo=UTC),
    )
    service.add_deployment(
        service_name="catalog-service",
        deployment_id="DEPLOY-IN-WINDOW",
        version="v2.0",
        deployed_at=datetime(2026, 8, 22, 11, 45, tzinfo=UTC),
    )
    service.add_deployment(
        service_name="catalog-service",
        deployment_id="DEPLOY-TOO-OLD",
        version="v1.9",
        deployed_at=datetime(2026, 8, 22, 9, 0, tzinfo=UTC),
    )
    service.add_deployment(
        service_name="catalog-service",
        deployment_id="DEPLOY-AFTER",
        version="v2.1",
        deployed_at=datetime(2026, 8, 22, 12, 5, tzinfo=UTC),
    )

    investigation = service.investigate("INC-2002", lookback_minutes=30, lookahead_minutes=15)

    assert investigation is not None
    assert investigation["evidence"] == {
        "logs": 1,
        "alerts": 1,
        "deployments": 1,
        "dependency_logs": 0,
        "dependency_alerts": 0,
        "dependency_deployments": 0,
    }
    assert investigation["recent_deployment"]["deployment_id"] == "DEPLOY-IN-WINDOW"
    assert all("TOO-OLD" not in signal["description"] for signal in investigation["ranked_signals"])
    assert all("DEPLOY-AFTER" not in signal["description"] for signal in investigation["ranked_signals"])
