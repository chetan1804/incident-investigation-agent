from fastapi.testclient import TestClient

from incident_investigation_agent.api.app import app
from incident_investigation_agent.database.base import Base
from incident_investigation_agent.database.session import engine


def setup_function() -> None:
    Base.metadata.create_all(bind=engine)


def teardown_function() -> None:
    Base.metadata.drop_all(bind=engine)


def test_incident_api_endpoints_work() -> None:
    client = TestClient(app)

    create_response = client.post(
        "/incidents",
        json={
            "service_name": "payment-service",
            "title": "Checkout failures",
            "summary": "Payment errors increased after deployment",
            "incident_id": "INC-3001",
            "severity": "high",
            "status": "investigating",
        },
    )

    assert create_response.status_code == 200
    payload = create_response.json()
    assert payload["incident_id"] == "INC-3001"
    assert payload["title"] == "Checkout failures"

    list_response = client.get("/incidents")
    assert list_response.status_code == 200
    assert [item["incident_id"] for item in list_response.json()] == ["INC-3001"]

    invalid_limit_response = client.get("/incidents?limit=0")
    assert invalid_limit_response.status_code == 422

    logs_response = client.get("/incidents/INC-3001/logs")
    assert logs_response.status_code == 200
    assert logs_response.json() == []

    alert_response = client.get("/incidents/INC-3001/alerts")
    assert alert_response.status_code == 200
    assert alert_response.json() == []

    get_response = client.get("/incidents/INC-3001")
    assert get_response.status_code == 200
    assert get_response.json()["incident_id"] == "INC-3001"

    deployments_response = client.get("/services/payment-service/deployments")
    assert deployments_response.status_code == 200
    assert deployments_response.json() == []

    investigation_response = client.get("/incidents/INC-3001/investigation")
    assert investigation_response.status_code == 200
    assert investigation_response.json()["evidence"] == {
        "logs": 0,
        "alerts": 0,
        "deployments": 0,
    }
    assert investigation_response.json()["recent_deployment"] is None

    invalid_response = client.post(
        "/incidents",
        json={"service_name": "payment-service", "title": "Missing fields"},
    )
    assert invalid_response.status_code == 422


def test_evidence_ingestion_feeds_investigation() -> None:
    client = TestClient(app)
    client.post(
        "/incidents",
        json={
            "service_name": "orders-service",
            "title": "Order failures",
            "summary": "Orders are failing",
            "incident_id": "INC-4001",
        },
    )

    log_response = client.post(
        "/logs",
        json={"service_name": "orders-service", "message": "Database timeout", "level": "ERROR", "incident_id": "INC-4001"},
    )
    alert_response = client.post(
        "/alerts",
        json={"service_name": "orders-service", "name": "order_failure_rate", "incident_id": "INC-4001"},
    )
    deployment_response = client.post(
        "/deployments",
        json={"service_name": "orders-service", "deployment_id": "DEPLOY-400", "version": "v4.0"},
    )

    assert log_response.status_code == 200
    assert alert_response.status_code == 200
    assert deployment_response.status_code == 200
    investigation = client.get("/incidents/INC-4001/investigation").json()
    assert investigation["evidence"] == {"logs": 1, "alerts": 1, "deployments": 1}
