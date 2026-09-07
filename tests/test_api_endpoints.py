from fastapi.testclient import TestClient

from incident_investigation_agent.api.app import app
from incident_investigation_agent.api.dependencies import get_hypothesis_generator
from incident_investigation_agent.exceptions import AIAnalysisError
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
    assert investigation["evidence"] == {"logs": 1, "alerts": 1, "deployments": 1}
    assert investigation["correlation_window"]["lookback_minutes"] == 60
    assert investigation["scoring_method"] == "deterministic_v1"
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
