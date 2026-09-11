from datetime import UTC, datetime, timedelta
from hashlib import sha256
import hmac
import json

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from incident_investigation_agent.api.app import app
from incident_investigation_agent.api.dependencies import get_hypothesis_generator
from incident_investigation_agent.config.settings import settings
from incident_investigation_agent.exceptions import AIAnalysisError
from incident_investigation_agent.models.incident_models import IngestionDelivery
from incident_investigation_agent.services.ai_analysis_service import (
    AIAnalysis,
    AIHypothesis,
    RemediationSuggestion,
)


class FakeHypothesisGenerator:
    model = "test-model"
    prompt_version = "test_prompt_v1"
    prompt_sha256 = "a" * 64

    def generate(self, **kwargs) -> AIAnalysis:
        signal_id = kwargs["ranked_signals"][0]["signal_id"]
        return AIAnalysis(
            hypotheses=[
                AIHypothesis(
                    hypothesis="A recent failure signal likely explains the incident",
                    reasoning="The signal is close to incident start.",
                    confidence=0.78,
                    supporting_signals=[signal_id],
                )
            ],
            remediation_suggestions=[
                RemediationSuggestion(
                    action="Roll back the suspected change",
                    rationale="This is a reversible mitigation tied to the evidence.",
                    priority="immediate",
                    supporting_signals=[signal_id],
                )
            ],
        )


class PassingRegressionGenerator:
    model = "candidate-model"
    prompt_version = "candidate_prompt_v2"
    prompt_sha256 = "b" * 64

    def generate(self, **kwargs) -> AIAnalysis:
        signal_ids = [signal["signal_id"] for signal in kwargs["ranked_signals"]]
        return AIAnalysis(
            hypotheses=[
                AIHypothesis(
                    hypothesis="The correlated signals may explain the incident",
                    reasoning="Each supplied signal is relevant to the observed failure.",
                    confidence=0.7,
                    supporting_signals=signal_ids,
                )
            ],
            remediation_suggestions=[],
        )


class InvalidRegressionGenerator(PassingRegressionGenerator):
    def generate(self, **kwargs) -> AIAnalysis:
        raise AIAnalysisError("candidate returned ungrounded output")


class PartiallyPassingRegressionGenerator(PassingRegressionGenerator):
    model = "regressed-model"
    prompt_version = "candidate_prompt_v3"
    prompt_sha256 = "c" * 64

    def generate(self, **kwargs) -> AIAnalysis:
        if kwargs["incident_id"] == "REG-002":
            return AIAnalysis(hypotheses=[], remediation_suggestions=[])
        return super().generate(**kwargs)


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
        "metric_anomalies": 0,
        "dependency_logs": 0,
        "dependency_alerts": 0,
        "dependency_deployments": 0,
        "dependency_metric_anomalies": 0,
        "historical_incidents": 0,
        "trace_paths": 0,
        "trace_logs": 0,
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
            "started_at": "2026-08-22T12:00:00Z",
        },
    )

    log_response = client.post(
        "/logs",
        json={
            "service_name": "orders-service",
            "message": "Database timeout",
            "level": "ERROR",
            "incident_id": "INC-4001",
            "timestamp": "2026-08-22T12:05:00Z",
        },
    )
    alert_response = client.post(
        "/alerts",
        json={
            "service_name": "orders-service",
            "name": "order_failure_rate",
            "incident_id": "INC-4001",
            "fired_at": "2026-08-22T12:02:00Z",
        },
    )
    deployment_response = client.post(
        "/deployments",
        json={
            "service_name": "orders-service",
            "deployment_id": "DEPLOY-400",
            "version": "v4.0",
            "deployed_at": "2026-08-22T11:50:00Z",
        },
    )

    assert log_response.status_code == 201
    assert alert_response.status_code == 201
    assert deployment_response.status_code == 201
    investigation = client.get("/incidents/INC-4001/investigation").json()
    assert investigation["evidence"] == {
        "logs": 1,
        "alerts": 1,
        "deployments": 1,
        "metric_anomalies": 0,
        "dependency_logs": 0,
        "dependency_alerts": 0,
        "dependency_deployments": 0,
        "dependency_metric_anomalies": 0,
        "historical_incidents": 0,
        "trace_paths": 0,
        "trace_logs": 0,
    }
    assert investigation["correlation_window"]["lookback_minutes"] == 60
    assert investigation["scoring_method"] == "deterministic_v4"
    assert investigation["ranked_signals"]
    assert investigation["root_cause_candidates"]
    assert client.get(
        "/incidents/INC-4001/investigation?lookback_minutes=0"
    ).status_code == 422


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


def test_metric_anomalies_feed_incident_and_dependency_correlation(client: TestClient) -> None:
    client.post(
        "/incidents",
        json={
            "service_name": "checkout-service",
            "title": "Checkout latency",
            "summary": "Checkout latency increased",
            "incident_id": "INC-METRIC-1",
            "started_at": "2026-09-09T12:00:00Z",
        },
    )
    client.post(
        "/service-dependencies",
        json={
            "service_name": "checkout-service",
            "depends_on_service_name": "payments-service",
            "criticality": "high",
        },
    )
    client.post(
        "/service-dependencies",
        json={
            "service_name": "storefront-service",
            "depends_on_service_name": "checkout-service",
            "criticality": "medium",
        },
    )

    direct = client.post(
        "/metric-anomalies",
        json={
            "service_name": "checkout-service",
            "metric_name": "request_latency_p95",
            "observed_value": 1800,
            "baseline_value": 250,
            "unit": "ms",
            "severity": "critical",
            "incident_id": "INC-METRIC-1",
            "description": "Latency exceeded the normal band",
            "metadata_json": {"region": "ap-south-1"},
            "observed_at": "2026-09-09T12:02:00Z",
        },
    )
    upstream = client.post(
        "/metric-anomalies",
        json={
            "service_name": "payments-service",
            "metric_name": "connection_pool_saturation",
            "observed_value": 98,
            "baseline_value": 45,
            "unit": "%",
            "severity": "high",
            "observed_at": "2026-09-09T11:58:00Z",
        },
    )
    downstream = client.post(
        "/metric-anomalies",
        json={
            "service_name": "storefront-service",
            "metric_name": "checkout_abandonment_rate",
            "observed_value": 30,
            "baseline_value": 5,
            "unit": "%",
            "severity": "high",
            "observed_at": "2026-09-09T12:05:00Z",
        },
    )
    client.post(
        "/metric-anomalies",
        json={
            "service_name": "checkout-service",
            "metric_name": "old_cpu_usage",
            "observed_value": 99,
            "baseline_value": 20,
            "unit": "%",
            "incident_id": "INC-METRIC-1",
            "observed_at": "2026-09-09T09:00:00Z",
        },
    )

    assert direct.status_code == 201
    assert direct.json()["anomaly_id"].startswith("MA-")
    assert direct.json()["metadata_json"] == {"region": "ap-south-1"}
    assert upstream.status_code == 201
    assert downstream.status_code == 201

    listed = client.get("/incidents/INC-METRIC-1/metric-anomalies")
    assert listed.status_code == 200
    assert len(listed.json()) == 2

    investigation = client.get("/incidents/INC-METRIC-1/investigation").json()
    assert investigation["evidence"]["metric_anomalies"] == 1
    assert investigation["evidence"]["dependency_metric_anomalies"] == 2
    signals = {signal["signal_id"]: signal for signal in investigation["ranked_signals"]}
    assert signals[f"metric-anomaly:{direct.json()['anomaly_id']}"]["kind"] == "metric_anomaly"
    assert signals[f"metric-anomaly:{upstream.json()['anomaly_id']}"]["kind"] == "upstream_metric_anomaly"
    assert signals[f"metric-anomaly:{downstream.json()['anomaly_id']}"]["kind"] == "downstream_metric_anomaly"
    assert all("old_cpu_usage" not in signal["description"] for signal in signals.values())
    assert any(
        f"metric-anomaly:{upstream.json()['anomaly_id']}" in candidate["supporting_signals"]
        for candidate in investigation["root_cause_candidates"]
    )
    assert all(
        f"metric-anomaly:{downstream.json()['anomaly_id']}" not in candidate["supporting_signals"]
        for candidate in investigation["root_cause_candidates"]
    )

    missing = client.post(
        "/metric-anomalies",
        json={
            "service_name": "checkout-service",
            "metric_name": "cpu_usage",
            "observed_value": 90,
            "baseline_value": 30,
            "incident_id": "INC-MISSING",
        },
    )
    mismatch = client.post(
        "/metric-anomalies",
        json={
            "service_name": "payments-service",
            "metric_name": "cpu_usage",
            "observed_value": 90,
            "baseline_value": 30,
            "incident_id": "INC-METRIC-1",
        },
    )
    invalid_severity = client.post(
        "/metric-anomalies",
        json={
            "service_name": "checkout-service",
            "metric_name": "cpu_usage",
            "observed_value": 90,
            "baseline_value": 30,
            "severity": "urgent",
        },
    )
    assert missing.status_code == 404
    assert mismatch.status_code == 409
    assert invalid_severity.status_code == 422


def test_alertmanager_webhook_normalizes_batches_and_retries_idempotently(
    client: TestClient,
) -> None:
    client.post(
        "/incidents",
        json={
            "service_name": "payments-service",
            "title": "Payment availability",
            "summary": "Payment requests are failing",
            "incident_id": "INC-AM-1",
            "started_at": "2026-09-09T12:00:00Z",
        },
    )
    payload = {
        "version": "4",
        "receiver": "incident-agent",
        "commonLabels": {
            "service": "payments-service",
            "incident_id": "INC-AM-1",
            "severity": "high",
        },
        "commonAnnotations": {"summary": "Payments are degraded"},
        "alerts": [
            {
                "status": "firing",
                "labels": {"alertname": "PaymentErrorRate", "severity": "critical"},
                "annotations": {"description": "Error rate exceeded 20%"},
                "startsAt": "2026-09-09T11:58:00Z",
                "fingerprint": "alert-fingerprint-1",
            },
            {
                "status": "firing",
                "labels": {"alertname": "PaymentLatency"},
                "annotations": {},
                "startsAt": "2026-09-09T11:59:00Z",
            },
        ],
    }

    response = client.post("/ingestion/prometheus/alertmanager", json=payload)
    assert response.status_code == 202
    assert response.json()["source"] == "prometheus-alertmanager"
    assert response.json()["received"] == 2
    assert response.json()["alerts"][0]["status"] == "active"
    assert response.json()["alerts"][1]["source_event_id"].startswith("generated-")

    resolved_payload = {
        **payload,
        "alerts": [
            {
                **payload["alerts"][0],
                "status": "resolved",
                "annotations": {"description": "Error rate recovered"},
            }
        ],
    }
    retry = client.post(
        "/ingestion/prometheus/alertmanager", json=resolved_payload
    )
    assert retry.status_code == 202
    assert retry.json()["alerts"][0]["id"] == response.json()["alerts"][0]["id"]
    assert retry.json()["alerts"][0]["status"] == "resolved"

    alerts = client.get("/incidents/INC-AM-1/alerts").json()
    assert len(alerts) == 2
    updated = next(alert for alert in alerts if alert["source_event_id"] == "alert-fingerprint-1")
    assert updated["source"] == "prometheus-alertmanager"
    assert updated["status"] == "resolved"
    assert updated["description"] == "Error rate recovered"
    assert client.get("/incidents/INC-AM-1/investigation").json()["evidence"]["alerts"] == 2


def test_alertmanager_webhook_validates_normalization_context_before_ingestion(
    client: TestClient,
) -> None:
    missing_service = client.post(
        "/ingestion/prometheus/alertmanager",
        json={
            "alerts": [
                {
                    "labels": {"alertname": "NoService"},
                    "startsAt": "2026-09-09T12:00:00Z",
                }
            ]
        },
    )
    assert missing_service.status_code == 422

    unknown_incident = client.post(
        "/ingestion/prometheus/alertmanager",
        json={
            "commonLabels": {"service": "payments-service"},
            "alerts": [
                {
                    "labels": {"alertname": "FirstAlert"},
                    "startsAt": "2026-09-09T12:00:00Z",
                },
                {
                    "labels": {
                        "alertname": "SecondAlert",
                        "incident_id": "INC-UNKNOWN",
                    },
                    "startsAt": "2026-09-09T12:01:00Z",
                },
            ],
        },
    )
    assert unknown_incident.status_code == 404


def test_failed_ingestion_delivery_can_be_audited_and_safely_replayed(
    client: TestClient,
) -> None:
    payload = {
        "commonLabels": {
            "service": "payments-service",
            "incident_id": "INC-REPLAY-1",
        },
        "alerts": [
            {
                "labels": {"alertname": "PaymentErrors", "severity": "critical"},
                "startsAt": "2026-09-11T12:00:00Z",
                "fingerprint": "replay-alert-1",
            }
        ],
    }
    rejected = client.post("/ingestion/prometheus/alertmanager", json=payload)
    assert rejected.status_code == 404

    deliveries = client.get(
        "/ingestion-deliveries",
        params={"status": "failed", "source": "prometheus-alertmanager"},
    ).json()
    assert len(deliveries) == 1
    failed = deliveries[0]
    assert rejected.headers["x-ingestion-delivery-id"] == failed["delivery_id"]
    assert failed["status"] == "failed"
    assert failed["error_type"] == "ResourceNotFoundError"
    assert "INC-REPLAY-1" in failed["error_detail"]
    assert failed["payload_json"] == payload
    assert len(failed["payload_sha256"]) == 64
    assert failed["replayable"] is True

    client.post(
        "/incidents",
        json={
            "service_name": "payments-service",
            "title": "Payment errors",
            "summary": "Payment processing is failing",
            "incident_id": "INC-REPLAY-1",
            "started_at": "2026-09-11T12:00:00Z",
        },
    )
    replay = client.post(
        f"/ingestion-deliveries/{failed['delivery_id']}/replay"
    )
    assert replay.status_code == 200
    replay_body = replay.json()
    assert replay_body["delivery"]["status"] == "succeeded"
    assert replay_body["delivery"]["replay_of_delivery_id"] == failed["delivery_id"]
    assert replay_body["result"]["received"] == 1
    assert len(client.get("/incidents/INC-REPLAY-1/alerts").json()) == 1

    repeat = client.post(f"/ingestion-deliveries/{failed['delivery_id']}/replay")
    assert repeat.status_code == 200
    assert len(client.get("/incidents/INC-REPLAY-1/alerts").json()) == 1


def test_unauthenticated_github_delivery_is_audited_but_not_replayable(
    client: TestClient, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "github_webhook_secret", "configured-secret")
    rejected = client.post(
        "/ingestion/github/deployments",
        json={"action": "created"},
        headers={
            "x-github-event": "deployment",
            "x-hub-signature-256": "sha256=invalid",
        },
    )
    assert rejected.status_code == 403

    failed = client.get(
        "/ingestion-deliveries",
        params={"status": "failed", "source": "github-deployments"},
    ).json()[0]
    assert rejected.headers["x-ingestion-delivery-id"] == failed["delivery_id"]
    assert failed["error_type"] == "IngestionAuthenticationError"
    assert failed["replayable"] is False
    assert failed["request_metadata_json"] == {"content_type": "application/json"}

    replay = client.post(f"/ingestion-deliveries/{failed['delivery_id']}/replay")
    assert replay.status_code == 409


def test_malformed_ingestion_payload_is_audited_but_not_replayable(
    client: TestClient,
) -> None:
    rejected = client.post(
        "/v1/logs",
        content=b"{not-json",
        headers={"content-type": "application/json"},
    )
    assert rejected.status_code == 422

    delivery_id = rejected.headers["x-ingestion-delivery-id"]
    failed = client.get(f"/ingestion-deliveries/{delivery_id}").json()
    assert failed["status"] == "failed"
    assert failed["payload_json"] is None
    assert failed["error_type"] == "InvalidIngestionPayloadError"
    assert failed["replayable"] is False
    assert client.post(
        f"/ingestion-deliveries/{delivery_id}/replay"
    ).status_code == 409


def test_ingestion_audit_endpoints_enforce_reader_and_replay_roles(
    client: TestClient, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "ingestion_audit_read_api_key", None)
    monkeypatch.setattr(settings, "ingestion_audit_replay_api_key", None)
    assert client.get("/ingestion-deliveries").status_code == 503

    monkeypatch.setattr(
        settings, "ingestion_audit_read_api_key", "test-audit-read-key"
    )
    monkeypatch.setattr(
        settings, "ingestion_audit_replay_api_key", "test-audit-replay-key"
    )
    missing = client.get(
        "/ingestion-deliveries", headers={"authorization": ""}
    )
    invalid = client.get(
        "/ingestion-deliveries",
        headers={"authorization": "Bearer wrong-key"},
    )
    reader = client.get(
        "/ingestion-deliveries",
        headers={"authorization": "Bearer test-audit-read-key"},
    )
    forbidden_replay = client.post(
        "/ingestion-deliveries/ING-does-not-matter/replay",
        headers={"authorization": "Bearer test-audit-read-key"},
    )
    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    assert invalid.status_code == 401
    assert reader.status_code == 200
    assert forbidden_replay.status_code == 403


def test_sensitive_audit_fields_are_recursively_redacted(
    client: TestClient,
) -> None:
    payload = {
        "commonLabels": {
            "service": "payments-service",
            "incident_id": "INC-REDACTION-MISSING",
            "api_key": "must-not-be-stored",
        },
        "alerts": [
            {
                "labels": {"alertname": "PaymentErrors"},
                "annotations": {"password": "also-secret"},
                "startsAt": "2026-09-11T12:00:00Z",
            }
        ],
    }
    rejected = client.post("/ingestion/prometheus/alertmanager", json=payload)
    assert rejected.status_code == 404

    delivery = client.get(
        f"/ingestion-deliveries/{rejected.headers['x-ingestion-delivery-id']}"
    ).json()
    assert delivery["payload_redacted"] is True
    assert delivery["payload_json"]["commonLabels"]["api_key"] == "[REDACTED]"
    assert delivery["payload_json"]["alerts"][0]["annotations"]["password"] == "[REDACTED]"
    assert delivery["replayable"] is False
    assert "must-not-be-stored" not in json.dumps(delivery)
    assert "also-secret" not in json.dumps(delivery)


def test_audit_payload_retention_purges_replay_material(
    client: TestClient, db_session: Session, monkeypatch
) -> None:
    monkeypatch.setattr(settings, "ingestion_audit_payload_retention_days", 1)
    accepted = client.post(
        "/ingestion/prometheus/alertmanager",
        json={
            "commonLabels": {"service": "retention-service"},
            "alerts": [
                {
                    "labels": {"alertname": "RetentionAlert"},
                    "startsAt": "2026-09-11T12:00:00Z",
                }
            ],
        },
    )
    assert accepted.status_code == 202
    delivery_id = accepted.headers["x-ingestion-delivery-id"]
    delivery = db_session.scalar(
        select(IngestionDelivery).where(IngestionDelivery.delivery_id == delivery_id)
    )
    assert delivery is not None
    delivery.payload_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    db_session.commit()

    purge = client.post("/ingestion-deliveries/purge-expired")
    assert purge.status_code == 200
    assert purge.json() == {"purged_deliveries": 1}

    audited = client.get(f"/ingestion-deliveries/{delivery_id}").json()
    assert audited["payload_json"] is None
    assert audited["payload_purged_at"] is not None
    assert audited["replayable"] is False

    monkeypatch.setattr(settings, "ingestion_audit_payload_retention_days", 0)
    no_retention = client.post(
        "/ingestion/prometheus/alertmanager",
        json={
            "commonLabels": {"service": "retention-service"},
            "alerts": [
                {
                    "labels": {"alertname": "NoRetentionAlert"},
                    "startsAt": "2026-09-11T12:01:00Z",
                }
            ],
        },
    )
    assert no_retention.status_code == 202
    immediate = client.get(
        "/ingestion-deliveries/"
        + no_retention.headers["x-ingestion-delivery-id"]
    ).json()
    assert immediate["payload_json"] is None
    assert immediate["payload_purged_at"] is not None


def test_otlp_http_logs_normalize_structure_and_retry_idempotently(
    client: TestClient,
) -> None:
    client.post(
        "/incidents",
        json={
            "service_name": "orders-service",
            "title": "Order failures",
            "summary": "Order requests are failing",
            "incident_id": "INC-OTLP-1",
            "started_at": "2026-09-10T12:00:00Z",
        },
    )
    payload = {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {
                            "key": "service.name",
                            "value": {"stringValue": "orders-service"},
                        },
                        {
                            "key": "incident.id",
                            "value": {"stringValue": "INC-OTLP-1"},
                        },
                        {
                            "key": "service.version",
                            "value": {"stringValue": "v5.2"},
                        },
                    ]
                },
                "scopeLogs": [
                    {
                        "scope": {"name": "orders.logger", "version": "1.0"},
                        "logRecords": [
                            {
                                "timeUnixNano": "1789041480000000000",
                                "severityNumber": 17,
                                "severityText": "Error",
                                "body": {"stringValue": "Database deadline exceeded"},
                                "attributes": [
                                    {
                                        "key": "http.response.status_code",
                                        "value": {"intValue": "500"},
                                    }
                                ],
                                "traceId": "5b8efff798038103d269b633813fc60c",
                                "spanId": "0102040800000000",
                                "flags": 1,
                            },
                            {
                                "observedTimeUnixNano": "1789041540000000000",
                                "severityNumber": 9,
                                "body": {
                                    "kvlistValue": {
                                        "values": [
                                            {
                                                "key": "message",
                                                "value": {"stringValue": "Retry scheduled"},
                                            },
                                            {
                                                "key": "attempt",
                                                "value": {"intValue": "2"},
                                            },
                                        ]
                                    }
                                },
                            },
                        ],
                    }
                ],
            }
        ]
    }

    response = client.post("/v1/logs", json=payload)
    retry = client.post("/v1/logs", json=payload)
    assert response.status_code == 200
    assert response.json() == {}
    assert retry.status_code == 200

    logs = client.get("/incidents/INC-OTLP-1/logs").json()
    assert len(logs) == 2
    assert logs[0]["message"] == "Database deadline exceeded"
    assert logs[0]["level"] == "ERROR"
    assert logs[0]["trace_id"] == "5b8efff798038103d269b633813fc60c"
    assert logs[0]["timestamp"] == "2026-09-10T11:58:00"
    assert logs[0]["source"] == "opentelemetry-otlp"
    assert logs[0]["source_event_id"].startswith("log-")
    assert logs[0]["metadata_json"]["otel"]["log_attributes"] == {
        "http.response.status_code": 500
    }
    assert logs[0]["metadata_json"]["otel"]["scope"]["name"] == "orders.logger"
    assert logs[1]["message"] == '{"attempt":2,"message":"Retry scheduled"}'
    assert logs[1]["timestamp"] == "2026-09-10T11:59:00"

    investigation = client.get("/incidents/INC-OTLP-1/investigation").json()
    assert investigation["evidence"]["logs"] == 2
    assert any(
        signal["signal_id"] == f"log:{logs[0]['id']}"
        for signal in investigation["ranked_signals"]
    )


def test_otlp_http_logs_reject_invalid_context_before_ingestion(
    client: TestClient,
) -> None:
    missing_service = client.post(
        "/v1/logs",
        json={
            "resourceLogs": [
                {
                    "scopeLogs": [
                        {
                            "logRecords": [
                                {
                                    "timeUnixNano": "1789041480000000000",
                                    "body": {"stringValue": "No service context"},
                                }
                            ]
                        }
                    ]
                }
            ]
        },
    )
    assert missing_service.status_code == 422

    invalid_trace = client.post(
        "/v1/logs",
        json={
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [
                            {
                                "key": "service.name",
                                "value": {"stringValue": "orders-service"},
                            }
                        ]
                    },
                    "scopeLogs": [
                        {
                            "logRecords": [
                                {
                                    "body": {"stringValue": "Bad trace"},
                                    "traceId": "not-a-trace-id",
                                }
                            ]
                        }
                    ],
                }
            ]
        },
    )
    assert invalid_trace.status_code == 422

    unknown_incident = client.post(
        "/v1/logs",
        json={
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [
                            {
                                "key": "service.name",
                                "value": {"stringValue": "orders-service"},
                            },
                            {
                                "key": "incident.id",
                                "value": {"stringValue": "INC-UNKNOWN"},
                            },
                        ]
                    },
                    "scopeLogs": [
                        {
                            "logRecords": [
                                {"body": {"stringValue": "Unknown incident"}}
                            ]
                        }
                    ],
                }
            ]
        },
    )
    assert unknown_incident.status_code == 404


def test_signed_github_deployments_update_lifecycle_and_feed_investigation(
    client: TestClient, monkeypatch
) -> None:
    secret = "github-test-secret"
    monkeypatch.setattr(settings, "github_webhook_secret", secret)
    client.post(
        "/incidents",
        json={
            "service_name": "checkout-service",
            "title": "Checkout failures",
            "summary": "Checkout errors increased after deployment",
            "incident_id": "INC-GH-1",
            "started_at": "2026-09-10T12:00:00Z",
        },
    )
    deployment = {
        "id": 987654,
        "sha": "a21d91b7a4f5a0288cba9d00d467e5d42c7041aa",
        "ref": "main",
        "task": "deploy",
        "environment": "production",
        "description": "Deploy checkout release",
        "payload": {"service_name": "checkout-service"},
        "created_at": "2026-09-10T11:55:00Z",
        "updated_at": "2026-09-10T11:55:00Z",
    }
    base_payload = {
        "action": "created",
        "deployment": deployment,
        "repository": {
            "id": 1234,
            "name": "commerce-platform",
            "full_name": "example/commerce-platform",
        },
        "sender": {"login": "release-bot"},
    }

    def post_webhook(event: str, payload: dict, delivery_id: str):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        signature = "sha256=" + hmac.new(
            secret.encode("utf-8"), body, sha256
        ).hexdigest()
        return client.post(
            "/ingestion/github/deployments",
            content=body,
            headers={
                "content-type": "application/json",
                "x-github-event": event,
                "x-github-delivery": delivery_id,
                "x-hub-signature-256": signature,
            },
        )

    created = post_webhook("deployment", base_payload, "delivery-created")
    assert created.status_code == 200
    assert created.json()["status"] == "accepted"
    assert created.json()["deployment"] == {
        "deployment_id": "GH-987654",
        "service_name": "checkout-service",
        "version": "a21d91b7a4f5a0288cba9d00d467e5d42c7041aa",
        "environment": "production",
        "status": "created",
        "source": "github-deployments",
        "source_event_id": "example/commerce-platform:987654",
    }

    status_payload = {
        **base_payload,
        "deployment_status": {
            "id": 7654321,
            "state": "success",
            "description": "Deployment completed",
            "environment": "production",
            "log_url": "https://github.example/deployment/log",
            "environment_url": "https://checkout.example.com",
            "created_at": "2026-09-10T11:57:00Z",
        },
    }
    completed = post_webhook(
        "deployment_status", status_payload, "delivery-completed"
    )
    assert completed.status_code == 200
    assert completed.json()["deployment"]["status"] == "success"

    deployments = client.get("/services/checkout-service/deployments").json()
    assert len(deployments) == 1
    assert deployments[0]["deployment_id"] == "GH-987654"
    assert deployments[0]["status"] == "success"
    assert deployments[0]["source"] == "github-deployments"
    assert deployments[0]["notes"] == "Deployment completed"
    assert deployments[0]["metadata_json"]["github"]["delivery_id"] == "delivery-completed"
    assert deployments[0]["metadata_json"]["github"]["actor"] == "release-bot"

    investigation = client.get("/incidents/INC-GH-1/investigation").json()
    assert investigation["evidence"]["deployments"] == 1
    assert investigation["recent_deployment"]["deployment_id"] == "GH-987654"

    ping = post_webhook("ping", {"zen": "Keep it logically awesome."}, "delivery-ping")
    assert ping.status_code == 200
    assert ping.json() == {"event": "ping", "status": "ignored", "deployment": None}


def test_github_deployment_webhook_fails_closed_on_authentication(
    client: TestClient, monkeypatch
) -> None:
    body = b'{"action":"created"}'
    monkeypatch.setattr(settings, "github_webhook_secret", None)
    unavailable = client.post(
        "/ingestion/github/deployments",
        content=body,
        headers={"x-github-event": "deployment"},
    )
    assert unavailable.status_code == 503

    monkeypatch.setattr(settings, "github_webhook_secret", "configured-secret")
    missing_signature = client.post(
        "/ingestion/github/deployments",
        content=body,
        headers={"x-github-event": "deployment"},
    )
    invalid_signature = client.post(
        "/ingestion/github/deployments",
        content=body,
        headers={
            "x-github-event": "deployment",
            "x-hub-signature-256": "sha256=invalid",
        },
    )
    assert missing_signature.status_code == 403
    assert invalid_signature.status_code == 403


def test_service_dependencies_feed_cross_service_investigation(client: TestClient) -> None:
    client.post(
        "/incidents",
        json={
            "service_name": "checkout-service",
            "title": "Checkout failures",
            "summary": "Checkout requests fail",
            "incident_id": "INC-4100",
            "started_at": "2026-09-07T12:00:00Z",
        },
    )
    upstream_response = client.post(
        "/service-dependencies",
        json={
            "service_name": "checkout-service",
            "depends_on_service_name": "payments-service",
            "criticality": "high",
        },
    )
    downstream_response = client.post(
        "/service-dependencies",
        json={
            "service_name": "storefront-service",
            "depends_on_service_name": "checkout-service",
            "criticality": "medium",
        },
    )
    assert upstream_response.status_code == 201
    assert downstream_response.status_code == 201

    upstream_alert = client.post(
        "/alerts",
        json={
            "service_name": "payments-service",
            "name": "payment_error_rate",
            "severity": "critical",
            "fired_at": "2026-09-07T11:58:00Z",
        },
    ).json()
    upstream_log = client.post(
        "/logs",
        json={
            "service_name": "payments-service",
            "message": "Provider connection failed",
            "level": "ERROR",
            "timestamp": "2026-09-07T11:57:00Z",
        },
    ).json()
    downstream_alert = client.post(
        "/alerts",
        json={
            "service_name": "storefront-service",
            "name": "checkout_dependency_errors",
            "severity": "high",
            "fired_at": "2026-09-07T12:03:00Z",
        },
    ).json()
    upstream_deployment = client.post(
        "/deployments",
        json={
            "service_name": "payments-service",
            "deployment_id": "DEP-UPSTREAM-1",
            "version": "v9.1",
            "deployed_at": "2026-09-07T11:50:00Z",
        },
    ).json()
    client.post(
        "/logs",
        json={
            "service_name": "payments-service",
            "message": "Old unrelated failure",
            "level": "ERROR",
            "timestamp": "2026-09-07T09:00:00Z",
        },
    )

    investigation = client.get("/incidents/INC-4100/investigation").json()

    assert investigation["dependencies"] == {
        "upstream": [{"service_name": "payments-service", "criticality": "high"}],
        "downstream": [
            {"service_name": "storefront-service", "criticality": "medium"}
        ],
    }
    assert investigation["evidence"]["dependency_logs"] == 1
    assert investigation["evidence"]["dependency_alerts"] == 2
    assert investigation["evidence"]["dependency_deployments"] == 1
    signals_by_id = {
        signal["signal_id"]: signal for signal in investigation["ranked_signals"]
    }
    assert signals_by_id[f"alert:{upstream_alert['id']}"]["kind"] == "upstream_alert"
    assert signals_by_id[f"log:{upstream_log['id']}"]["kind"] == "upstream_log"
    assert signals_by_id[f"alert:{downstream_alert['id']}"]["kind"] == "downstream_alert"
    assert (
        signals_by_id[f"deployment:{upstream_deployment['deployment_id']}"]["kind"]
        == "upstream_deployment"
    )
    downstream_signal_id = f"alert:{downstream_alert['id']}"
    assert all(
        downstream_signal_id not in candidate["supporting_signals"]
        for candidate in investigation["root_cause_candidates"]
    )

    dependencies = client.get("/services/checkout-service/dependencies").json()
    assert len(dependencies) == 2
    assert client.post(
        "/service-dependencies",
        json={
            "service_name": "checkout-service",
            "depends_on_service_name": "payments-service",
        },
    ).status_code == 409
    assert client.post(
        "/service-dependencies",
        json={
            "service_name": "checkout-service",
            "depends_on_service_name": "checkout-service",
        },
    ).status_code == 409
    assert client.get("/services/missing-service/dependencies").status_code == 404


def test_confirmed_resolutions_feed_historical_incident_similarity(
    client: TestClient,
) -> None:
    client.post(
        "/incidents",
        json={
            "service_name": "payments-service",
            "title": "Payment provider timeout",
            "summary": "Checkout payments timed out when the provider pool was exhausted",
            "incident_id": "INC-HIST-1",
            "severity": "high",
            "started_at": "2026-08-01T12:00:00Z",
        },
    )
    client.post(
        "/logs",
        json={
            "service_name": "payments-service",
            "incident_id": "INC-HIST-1",
            "message": "Provider connection pool timeout",
            "level": "ERROR",
            "timestamp": "2026-08-01T12:02:00Z",
        },
    )
    resolution_response = client.post(
        "/incidents/INC-HIST-1/resolution",
        json={
            "root_cause": "The provider connection pool was undersized",
            "resolution_summary": "Increased the pool size and restarted workers",
            "resolution_confirmed_by": "primary-on-call",
            "resolved_at": "2026-08-01T13:00:00Z",
        },
    )
    assert resolution_response.status_code == 201
    assert resolution_response.json()["status"] == "resolved"
    resolved_incident = client.get("/incidents/INC-HIST-1").json()
    assert resolved_incident["resolution_summary"] == (
        "Increased the pool size and restarted workers"
    )
    assert resolved_incident["resolved_at"].startswith("2026-08-01T13:00:00")

    client.post(
        "/incidents",
        json={
            "service_name": "payments-service",
            "title": "Checkout payment timeout",
            "summary": "Provider pool connections are exhausted during checkout",
            "incident_id": "INC-CURRENT-1",
            "severity": "high",
            "started_at": "2026-09-08T12:00:00Z",
        },
    )
    client.post(
        "/logs",
        json={
            "service_name": "payments-service",
            "incident_id": "INC-CURRENT-1",
            "message": "Provider connection pool timeout",
            "level": "ERROR",
            "timestamp": "2026-09-08T12:01:00Z",
        },
    )

    investigation = client.get(
        "/incidents/INC-CURRENT-1/investigation",
        params={"historical_similarity_threshold": 0.1},
    ).json()

    assert investigation["evidence"]["historical_incidents"] == 1
    historical = investigation["historical_incidents"][0]
    assert historical["incident_id"] == "INC-HIST-1"
    assert historical["root_cause"] == "The provider connection pool was undersized"
    assert historical["resolution_confirmed_by"] == "primary-on-call"
    assert {"payment", "provider", "pool", "timeout"}.issubset(
        historical["matching_terms"]
    )
    historical_signal = next(
        signal
        for signal in investigation["ranked_signals"]
        if signal["signal_id"] == "incident:INC-HIST-1"
    )
    assert historical_signal["kind"] == "historical_incident"

    without_history = client.get(
        "/incidents/INC-CURRENT-1/investigation",
        params={"historical_incident_limit": 0},
    ).json()
    assert without_history["historical_incidents"] == []

    duplicate_resolution = client.post(
        "/incidents/INC-HIST-1/resolution",
        json={
            "root_cause": "Replacement",
            "resolution_summary": "Replacement",
            "resolution_confirmed_by": "operator",
        },
    )
    assert duplicate_resolution.status_code == 409
    assert client.post(
        "/incidents/INC-missing/resolution",
        json={
            "root_cause": "Unknown",
            "resolution_summary": "Unknown",
            "resolution_confirmed_by": "operator",
        },
    ).status_code == 404

    client.post(
        "/incidents",
        json={
            "service_name": "future-service",
            "title": "Future incident",
            "summary": "Timestamp validation",
            "incident_id": "INC-FUTURE-1",
            "started_at": "2026-09-08T12:00:00Z",
        },
    )
    invalid_timestamp = client.post(
        "/incidents/INC-FUTURE-1/resolution",
        json={
            "root_cause": "Clock mismatch",
            "resolution_summary": "Corrected the clock",
            "resolution_confirmed_by": "operator",
            "resolved_at": "2026-09-08T11:59:00Z",
        },
    )
    assert invalid_timestamp.status_code == 409


def test_trace_ids_reconstruct_cross_service_request_paths(client: TestClient) -> None:
    client.post(
        "/incidents",
        json={
            "service_name": "checkout-service",
            "title": "Checkout latency",
            "summary": "Checkout requests are timing out",
            "incident_id": "INC-TRACE-1",
            "started_at": "2026-09-08T12:00:00Z",
        },
    )
    client.post(
        "/logs",
        json={
            "service_name": "database-service",
            "message": "Query deadline exceeded",
            "level": "ERROR",
            "trace_id": "trace-checkout-1",
            "timestamp": "2026-09-08T11:58:00Z",
        },
    )
    client.post(
        "/logs",
        json={
            "service_name": "inventory-service",
            "message": "Loading inventory",
            "level": "INFO",
            "trace_id": "trace-checkout-1",
            "timestamp": "2026-09-08T11:59:00Z",
        },
    )
    client.post(
        "/logs",
        json={
            "service_name": "checkout-service",
            "incident_id": "INC-TRACE-1",
            "message": "Request timed out",
            "level": "ERROR",
            "trace_id": "trace-checkout-1",
            "timestamp": "2026-09-08T12:01:00Z",
        },
    )
    client.post(
        "/logs",
        json={
            "service_name": "unrelated-service",
            "message": "Unrelated request",
            "level": "ERROR",
            "trace_id": "trace-unrelated",
            "timestamp": "2026-09-08T12:00:00Z",
        },
    )

    investigation = client.get("/incidents/INC-TRACE-1/investigation").json()

    assert investigation["evidence"]["trace_paths"] == 1
    assert investigation["evidence"]["trace_logs"] == 3
    path = investigation["trace_paths"][0]
    assert path["trace_id"] == "trace-checkout-1"
    assert path["services"] == [
        "database-service",
        "inventory-service",
        "checkout-service",
    ]
    assert path["log_count"] == 3
    assert path["error_count"] == 2
    assert path["entries_truncated"] is False
    assert [entry["service_name"] for entry in path["entries"]] == path["services"]
    trace_signal = next(
        signal
        for signal in investigation["ranked_signals"]
        if signal["signal_id"] == "trace:trace-checkout-1"
    )
    assert trace_signal["kind"] == "trace_path"
    assert any(
        "trace:trace-checkout-1" in candidate["supporting_signals"]
        for candidate in investigation["root_cause_candidates"]
    )

    without_traces = client.get(
        "/incidents/INC-TRACE-1/investigation",
        params={"trace_path_limit": 0},
    ).json()
    assert without_traces["trace_paths"] == []
    assert without_traces["evidence"]["trace_logs"] == 0


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


def test_ai_analysis_returns_grounded_hypotheses_and_remediations(client: TestClient) -> None:
    app.dependency_overrides[get_hypothesis_generator] = FakeHypothesisGenerator
    client.post(
        "/incidents",
        json={
            "service_name": "checkout-service",
            "title": "Checkout unavailable",
            "summary": "Checkout requests are timing out",
            "incident_id": "INC-5001",
            "started_at": "2026-08-22T12:00:00Z",
        },
    )
    client.post(
        "/logs",
        json={
            "service_name": "checkout-service",
            "message": "Database connection timeout",
            "level": "ERROR",
            "incident_id": "INC-5001",
            "timestamp": "2026-08-22T12:01:00Z",
        },
    )

    response = client.post("/incidents/INC-5001/ai-analysis")

    assert response.status_code == 201
    payload = response.json()
    assert payload["analysis_id"].startswith("AIA-")
    assert payload["incident_id"] == "INC-5001"
    assert payload["model"] == "test-model"
    assert payload["prompt_version"] == "test_prompt_v1"
    assert payload["prompt_sha256"] == "a" * 64
    assert payload["ranked_signal_ids"] == ["log:1"]
    assert payload["hypotheses"][0]["supporting_signals"] == ["log:1"]
    assert payload["remediation_suggestions"][0]["priority"] == "immediate"
    assert payload["feedback"] == []

    list_response = client.get("/incidents/INC-5001/ai-analyses")
    assert list_response.status_code == 200
    assert [item["analysis_id"] for item in list_response.json()] == [payload["analysis_id"]]

    feedback_response = client.post(
        f"/ai-analyses/{payload['analysis_id']}/feedback",
        json={
            "hypothesis_index": 0,
            "rating": "accurate",
            "operator_name": "on-call-engineer",
            "comment": "Rollback restored checkout traffic.",
        },
    )
    assert feedback_response.status_code == 201
    assert feedback_response.json()["feedback_id"].startswith("AIF-")

    persisted = client.get("/incidents/INC-5001/ai-analyses").json()[0]
    assert persisted["feedback"][0]["rating"] == "accurate"
    assert persisted["feedback"][0]["hypothesis_index"] == 0


def test_ai_analysis_feedback_validates_analysis_and_hypothesis(client: TestClient) -> None:
    missing_response = client.post(
        "/ai-analyses/AIA-missing/feedback",
        json={
            "hypothesis_index": 0,
            "rating": "uncertain",
            "operator_name": "operator",
        },
    )
    assert missing_response.status_code == 404

    app.dependency_overrides[get_hypothesis_generator] = FakeHypothesisGenerator
    client.post(
        "/incidents",
        json={
            "service_name": "profile-service",
            "title": "Profiles unavailable",
            "summary": "Profile requests are failing",
            "incident_id": "INC-5003",
        },
    )
    client.post(
        "/alerts",
        json={
            "service_name": "profile-service",
            "name": "profile_error_rate",
            "severity": "critical",
            "incident_id": "INC-5003",
        },
    )
    analysis = client.post("/incidents/INC-5003/ai-analysis").json()

    invalid_response = client.post(
        f"/ai-analyses/{analysis['analysis_id']}/feedback",
        json={
            "hypothesis_index": 9,
            "rating": "inaccurate",
            "operator_name": "operator",
        },
    )
    assert invalid_response.status_code == 422
    assert "Hypothesis index 9" in invalid_response.json()["detail"]

    assert client.get("/incidents/INC-MISSING/ai-analyses").status_code == 404


def test_ai_evaluation_metrics_aggregate_and_filter_feedback(client: TestClient) -> None:
    app.dependency_overrides[get_hypothesis_generator] = FakeHypothesisGenerator
    client.post(
        "/incidents",
        json={
            "service_name": "catalog-service",
            "title": "Catalog unavailable",
            "summary": "Catalog requests fail",
            "incident_id": "INC-5004",
        },
    )
    client.post(
        "/alerts",
        json={
            "service_name": "catalog-service",
            "name": "catalog_error_rate",
            "severity": "high",
            "incident_id": "INC-5004",
        },
    )
    analysis = client.post("/incidents/INC-5004/ai-analysis").json()
    for rating in ("accurate", "partially_accurate", "uncertain"):
        response = client.post(
            f"/ai-analyses/{analysis['analysis_id']}/feedback",
            json={
                "hypothesis_index": 0,
                "rating": rating,
                "operator_name": f"operator-{rating}",
            },
        )
        assert response.status_code == 201

    response = client.get(
        "/ai-evaluations/metrics?prompt_version=test_prompt_v1&model=test-model"
    )

    assert response.status_code == 200
    metrics = response.json()
    assert metrics["filters"] == {
        "prompt_version": "test_prompt_v1",
        "model": "test-model",
    }
    assert metrics["total_analyses"] == 1
    assert metrics["analyses_with_feedback"] == 1
    assert metrics["total_hypotheses"] == 1
    assert metrics["hypotheses_with_feedback"] == 1
    assert metrics["feedback_coverage"] == 1.0
    assert metrics["total_feedback"] == 3
    assert metrics["decided_feedback"] == 2
    assert metrics["rating_counts"] == {
        "accurate": 1,
        "partially_accurate": 1,
        "inaccurate": 0,
        "uncertain": 1,
    }
    assert metrics["accuracy_score"] == 0.75

    empty_metrics = client.get(
        "/ai-evaluations/metrics?prompt_version=unknown"
    ).json()
    assert empty_metrics["total_analyses"] == 0
    assert empty_metrics["feedback_coverage"] == 0.0
    assert empty_metrics["accuracy_score"] is None


def test_ai_prompt_regression_run_is_evaluated_and_persisted(client: TestClient) -> None:
    app.dependency_overrides[get_hypothesis_generator] = PassingRegressionGenerator

    response = client.post("/ai-evaluations/regression-runs")

    assert response.status_code == 201
    run = response.json()
    assert run["run_id"].startswith("AIR-")
    assert run["dataset_version"] == "incident_analysis_v1"
    assert run["model"] == "candidate-model"
    assert run["prompt_version"] == "candidate_prompt_v2"
    assert run["passed"] is True
    assert run["total_cases"] == 2
    assert run["passed_cases"] == 2
    assert all(result["passed"] for result in run["results"])
    assert all(result["output"]["hypotheses"] for result in run["results"])

    list_response = client.get("/ai-evaluations/regression-runs")
    assert list_response.status_code == 200
    assert [item["run_id"] for item in list_response.json()] == [run["run_id"]]

    missing_response = client.post(
        "/ai-evaluations/regression-runs?dataset_version=missing"
    )
    assert missing_response.status_code == 404


def test_ai_prompt_regression_persists_invalid_output_as_failure(client: TestClient) -> None:
    app.dependency_overrides[get_hypothesis_generator] = InvalidRegressionGenerator

    response = client.post("/ai-evaluations/regression-runs")

    assert response.status_code == 201
    run = response.json()
    assert run["passed"] is False
    assert run["passed_cases"] == 0
    assert run["results"][0]["failures"] == ["candidate returned ungrounded output"]
    assert run["results"][0]["output"] is None


def test_ai_regression_comparison_and_quality_gate(client: TestClient) -> None:
    app.dependency_overrides[get_hypothesis_generator] = PassingRegressionGenerator
    baseline = client.post("/ai-evaluations/regression-runs").json()
    app.dependency_overrides[get_hypothesis_generator] = PartiallyPassingRegressionGenerator
    candidate = client.post("/ai-evaluations/regression-runs").json()

    comparison_response = client.get(
        f"/ai-evaluations/regression-runs/{candidate['run_id']}/comparison",
        params={"baseline_run_id": baseline["run_id"]},
    )

    assert comparison_response.status_code == 200
    comparison = comparison_response.json()
    assert comparison["baseline_pass_rate"] == 1.0
    assert comparison["candidate_pass_rate"] == 0.5
    assert comparison["pass_rate_delta"] == -0.5
    assert comparison["regressed_case_ids"] == ["alert_and_timeout_without_deployment"]
    assert comparison["improved_case_ids"] == []

    gate_url = f"/ai-evaluations/regression-runs/{candidate['run_id']}/quality-gate"
    failed_gate = client.post(
        gate_url,
        json={"baseline_run_id": baseline["run_id"]},
    )
    assert failed_gate.status_code == 412
    assert failed_gate.json()["passed"] is False
    assert len(failed_gate.json()["failures"]) == 3

    relaxed_gate = client.post(
        gate_url,
        json={
            "baseline_run_id": baseline["run_id"],
            "minimum_pass_rate": 0.5,
            "maximum_pass_rate_drop": 0.5,
            "maximum_regressed_cases": 1,
        },
    )
    assert relaxed_gate.status_code == 200
    assert relaxed_gate.json()["passed"] is True

    missing_comparison = client.get(
        f"/ai-evaluations/regression-runs/{candidate['run_id']}/comparison",
        params={"baseline_run_id": "AIR-missing"},
    )
    assert missing_comparison.status_code == 404

    self_comparison = client.get(
        f"/ai-evaluations/regression-runs/{candidate['run_id']}/comparison",
        params={"baseline_run_id": candidate["run_id"]},
    )
    assert self_comparison.status_code == 409


def test_ai_analysis_requires_configuration(client: TestClient) -> None:
    from incident_investigation_agent.services.ai_analysis_service import (
        UnavailableHypothesisGenerator,
    )

    app.dependency_overrides[get_hypothesis_generator] = UnavailableHypothesisGenerator
    client.post(
        "/incidents",
        json={
            "service_name": "search-service",
            "title": "Search degraded",
            "summary": "Search latency increased",
            "incident_id": "INC-5002",
        },
    )

    response = client.post("/incidents/INC-5002/ai-analysis")

    assert response.status_code == 503
    assert "OPENAI_API_KEY" in response.json()["detail"]
