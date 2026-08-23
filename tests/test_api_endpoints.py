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
