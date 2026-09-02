from fastapi.testclient import TestClient

def test_incident_api_endpoints_work(client: TestClient) -> None:
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

    assert create_response.status_code == 201
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


def test_evidence_ingestion_feeds_investigation(client: TestClient) -> None:
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

    assert log_response.status_code == 201
    assert alert_response.status_code == 201
    assert deployment_response.status_code == 201
    investigation = client.get("/incidents/INC-4001/investigation").json()
    assert investigation["evidence"] == {"logs": 1, "alerts": 1, "deployments": 1}


def test_evidence_rejects_unknown_incident_and_service_mismatch(client: TestClient) -> None:
    missing_response = client.post(
        "/logs",
        json={"service_name": "orders-service", "message": "Timeout", "incident_id": "INC-MISSING"},
    )
    assert missing_response.status_code == 404

    client.post(
        "/incidents",
        json={
            "service_name": "orders-service",
            "title": "Order failures",
            "summary": "Orders are failing",
            "incident_id": "INC-4002",
        },
    )
    mismatch_response = client.post(
        "/alerts",
        json={"service_name": "payments-service", "name": "error_rate", "incident_id": "INC-4002"},
    )
    assert mismatch_response.status_code == 409


def test_duplicate_identifiers_return_conflict(client: TestClient) -> None:
    incident_payload = {
        "service_name": "orders-service",
        "title": "Order failures",
        "summary": "Orders are failing",
        "incident_id": "INC-4003",
    }
    assert client.post("/incidents", json=incident_payload).status_code == 201
    assert client.post("/incidents", json=incident_payload).status_code == 409

    deployment_payload = {
        "service_name": "orders-service",
        "deployment_id": "DEPLOY-401",
        "version": "v4.1",
    }
    assert client.post("/deployments", json=deployment_payload).status_code == 201
    assert client.post("/deployments", json=deployment_payload).status_code == 409


def test_ingestion_preserves_source_timestamp(client: TestClient) -> None:
    client.post(
        "/incidents",
        json={
            "service_name": "orders-service",
            "title": "Order failures",
            "summary": "Orders are failing",
            "incident_id": "INC-4004",
        },
    )
    response = client.post(
        "/logs",
        json={
            "service_name": "orders-service",
            "message": "Timeout",
            "incident_id": "INC-4004",
            "timestamp": "2026-08-22T12:30:00Z",
        },
    )
    assert response.status_code == 201
    logs = client.get("/incidents/INC-4004/logs").json()
    assert logs[0]["timestamp"].startswith("2026-08-22T12:30:00")


def test_evidence_queries_return_not_found_for_unknown_incident(client: TestClient) -> None:
    assert client.get("/incidents/INC-MISSING/logs").status_code == 404
    assert client.get("/incidents/INC-MISSING/alerts").status_code == 404
