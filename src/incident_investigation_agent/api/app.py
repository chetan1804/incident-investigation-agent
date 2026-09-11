from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from incident_investigation_agent.api.dependencies import (
    get_hypothesis_generator,
    get_incident_service,
    require_ingestion_audit_reader,
    require_ingestion_replay_operator,
)
from incident_investigation_agent.api.schemas import (
    AIAnalysisFeedbackCreateRequest,
    AIAnalysisFeedbackResponse,
    AIAnalysisResponse,
    AIEvaluationMetricsResponse,
    AIRegressionComparisonResponse,
    AIRegressionQualityGateRequest,
    AIRegressionQualityGateResponse,
    AIRegressionRunResponse,
    AlertmanagerIngestionResponse,
    AlertCreateRequest,
    DeploymentCreateRequest,
    IncidentCreateRequest,
    IncidentResolutionCreateRequest,
    IncidentResolutionResponse,
    IncidentResponse,
    InvestigationResponse,
    GitHubWebhookResponse,
    IngestionDeliveryResponse,
    IngestionPayloadPurgeResponse,
    IngestionReplayResponse,
    LogCreateRequest,
    MetricAnomalyCreateRequest,
    MetricAnomalyResponse,
    OtlpExportLogsResponse,
    ServiceDependencyCreateRequest,
    ServiceDependencyResponse,
)
from incident_investigation_agent.config.settings import settings
from incident_investigation_agent.exceptions import (
    AIAnalysisError,
    AIAnalysisUnavailableError,
    IngestionAuthenticationError,
    IngestionUnavailableError,
    InvalidFeedbackError,
    InvalidIngestionPayloadError,
    OperatorAuthenticationError,
    OperatorAuthenticationUnavailableError,
    OperatorAuthorizationError,
    ResourceConflictError,
    ResourceNotFoundError,
)
from incident_investigation_agent.models.incident_models import (
    AIAnalysisRecord,
    AIRegressionRun,
    IngestionDelivery,
    MetricAnomaly,
)
from incident_investigation_agent.services.ai_analysis_service import (
    PROMPT_VERSION,
    HypothesisGenerator,
)
from incident_investigation_agent.services.ai_regression_service import (
    AIRegressionComparisonService,
    AIRegressionService,
)
from incident_investigation_agent.services.alertmanager_adapter import AlertmanagerAdapter
from incident_investigation_agent.services.incident_service import IncidentService
from incident_investigation_agent.services.ingestion_delivery_service import IngestionDeliveryService
from incident_investigation_agent.services.github_deployment_adapter import (
    GitHubDeploymentAdapter,
)
from incident_investigation_agent.services.otlp_log_adapter import OtlpLogAdapter

app = FastAPI(title="Incident Investigation Agent", version="0.1.0")


def _serialize_ingestion_delivery(delivery: IngestionDelivery) -> dict:
    return {
        "delivery_id": delivery.delivery_id,
        "source": delivery.source,
        "source_delivery_id": delivery.source_delivery_id,
        "event_type": delivery.event_type,
        "status": delivery.status,
        "payload_sha256": delivery.payload_sha256,
        "payload_size_bytes": delivery.payload_size_bytes,
        "payload_json": delivery.payload_json,
        "payload_redacted": delivery.payload_redacted,
        "payload_expires_at": delivery.payload_expires_at,
        "payload_purged_at": delivery.payload_purged_at,
        "request_metadata_json": delivery.request_metadata_json,
        "result_json": delivery.result_json,
        "error_type": delivery.error_type,
        "error_detail": delivery.error_detail,
        "replayable": delivery.replayable,
        "replay_of_delivery_id": (
            delivery.replay_of.delivery_id if delivery.replay_of else None
        ),
        "created_at": delivery.created_at,
        "completed_at": delivery.completed_at,
    }


def _ingestion_error_headers(exc: Exception) -> dict[str, str] | None:
    delivery_id = getattr(exc, "ingestion_delivery_id", None)
    return {"X-Ingestion-Delivery-ID": delivery_id} if delivery_id else None


@app.exception_handler(ResourceNotFoundError)
def handle_not_found(_request: Request, exc: ResourceNotFoundError) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={"detail": str(exc)},
        headers=_ingestion_error_headers(exc),
    )


@app.exception_handler(ResourceConflictError)
def handle_conflict(_request: Request, exc: ResourceConflictError) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={"detail": str(exc)},
        headers=_ingestion_error_headers(exc),
    )


@app.exception_handler(AIAnalysisUnavailableError)
def handle_ai_unavailable(_request: Request, exc: AIAnalysisUnavailableError) -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"detail": str(exc)})


@app.exception_handler(AIAnalysisError)
def handle_ai_error(_request: Request, exc: AIAnalysisError) -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_502_BAD_GATEWAY, content={"detail": str(exc)})


@app.exception_handler(InvalidFeedbackError)
def handle_invalid_feedback(_request: Request, exc: InvalidFeedbackError) -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, content={"detail": str(exc)})


@app.exception_handler(InvalidIngestionPayloadError)
def handle_invalid_ingestion(
    _request: Request, exc: InvalidIngestionPayloadError
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": str(exc)},
        headers=_ingestion_error_headers(exc),
    )


@app.exception_handler(IngestionAuthenticationError)
def handle_ingestion_authentication(
    _request: Request, exc: IngestionAuthenticationError
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"detail": str(exc)},
        headers=_ingestion_error_headers(exc),
    )


@app.exception_handler(IngestionUnavailableError)
def handle_ingestion_unavailable(
    _request: Request, exc: IngestionUnavailableError
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": str(exc)},
        headers=_ingestion_error_headers(exc),
    )


@app.exception_handler(OperatorAuthenticationError)
def handle_operator_authentication(
    _request: Request, exc: OperatorAuthenticationError
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": str(exc)},
        headers={"WWW-Authenticate": "Bearer"},
    )


@app.exception_handler(OperatorAuthorizationError)
def handle_operator_authorization(
    _request: Request, exc: OperatorAuthorizationError
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"detail": str(exc)},
    )


@app.exception_handler(OperatorAuthenticationUnavailableError)
def handle_operator_authentication_unavailable(
    _request: Request, exc: OperatorAuthenticationUnavailableError
) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": str(exc)},
    )


def _serialize_ai_analysis(record: AIAnalysisRecord) -> dict:
    return {
        "analysis_id": record.analysis_id,
        "incident_id": record.incident.incident_id,
        "model": record.model,
        "prompt_version": record.prompt_version,
        "prompt_sha256": record.prompt_sha256,
        "correlation_window": record.correlation_window_json,
        "ranked_signal_ids": record.ranked_signal_ids_json,
        "hypotheses": record.hypotheses_json,
        "remediation_suggestions": record.remediation_suggestions_json,
        "feedback": [
            {
                "feedback_id": item.feedback_id,
                "analysis_id": record.analysis_id,
                "hypothesis_index": item.hypothesis_index,
                "rating": item.rating,
                "operator_name": item.operator_name,
                "comment": item.comment,
                "created_at": item.created_at,
            }
            for item in sorted(record.feedback, key=lambda feedback: feedback.created_at)
        ],
        "created_at": record.created_at,
    }


def _serialize_ai_regression_run(run: AIRegressionRun) -> dict:
    return {
        "run_id": run.run_id,
        "dataset_version": run.dataset_version,
        "model": run.model,
        "prompt_version": run.prompt_version,
        "prompt_sha256": run.prompt_sha256,
        "passed": run.passed,
        "total_cases": run.total_cases,
        "passed_cases": run.passed_cases,
        "results": run.results_json,
        "created_at": run.created_at,
    }


@app.get("/incidents", response_model=list[IncidentResponse])
def list_incidents(
    limit: int = Query(default=50, ge=1, le=100),
    incident_service: IncidentService = Depends(get_incident_service),
) -> list[IncidentResponse]:
    incidents = incident_service.list_incidents(limit=limit)
    return [
        IncidentResponse(
            incident_id=incident.incident_id,
            title=incident.title,
            summary=incident.summary,
            severity=incident.severity,
            status=incident.status,
            service_name=incident.service.name,
            started_at=incident.started_at,
            resolved_at=incident.resolved_at,
            root_cause=incident.root_cause,
            resolution_summary=incident.resolution_summary,
            resolution_confirmed_by=incident.resolution_confirmed_by,
        )
        for incident in incidents
    ]


@app.post("/incidents", status_code=status.HTTP_201_CREATED)
def create_incident(
    payload: IncidentCreateRequest,
    incident_service: IncidentService = Depends(get_incident_service),
) -> IncidentResponse:

    incident = incident_service.create_incident(
        service_name=payload.service_name,
        title=payload.title,
        summary=payload.summary,
        incident_id=payload.incident_id,
        severity=payload.severity.value,
        status=payload.status.value,
        metadata_json=payload.metadata_json,
        started_at=payload.started_at,
    )
    return IncidentResponse(
        incident_id=incident.incident_id,
        title=incident.title,
        summary=incident.summary,
        severity=incident.severity,
        status=incident.status,
        service_name=incident.service.name,
        started_at=incident.started_at,
    )


@app.post("/logs", status_code=status.HTTP_201_CREATED)
def create_log(
    payload: LogCreateRequest,
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    log = incident_service.add_log(**payload.model_dump())
    return {"id": log.id, "message": log.message, "level": log.level, "incident_id": payload.incident_id}


@app.post("/v1/logs", response_model=OtlpExportLogsResponse)
async def ingest_otlp_logs(
    request: Request,
    response: Response,
    incident_service: IncidentService = Depends(get_incident_service),
) -> OtlpExportLogsResponse:
    body = await request.body()
    audit = IngestionDeliveryService(incident_service)
    payload_json = audit.decode_json(body)
    delivery = audit.begin(
        source=OtlpLogAdapter.source,
        body=body,
        payload_json=payload_json,
        request_metadata={"content_type": request.headers.get("content-type")},
        replayable=payload_json is not None,
    )
    try:
        result = audit.process(delivery, payload_json)
    except Exception as exc:
        audit.fail(
            delivery,
            exc,
            replayable=(
                payload_json is not None
                and not isinstance(exc, InvalidIngestionPayloadError)
            ),
        )
        raise
    audit.succeed(delivery, result)
    response.headers["X-Ingestion-Delivery-ID"] = delivery.delivery_id
    return OtlpExportLogsResponse()


@app.post("/alerts", status_code=status.HTTP_201_CREATED)
def create_alert(
    payload: AlertCreateRequest,
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    alert = incident_service.add_alert(**payload.model_dump())
    return {"id": alert.id, "name": alert.name, "severity": alert.severity, "incident_id": payload.incident_id}


@app.post(
    "/ingestion/prometheus/alertmanager",
    response_model=AlertmanagerIngestionResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def ingest_alertmanager_webhook(
    request: Request,
    response: Response,
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    body = await request.body()
    audit = IngestionDeliveryService(incident_service)
    payload_json = audit.decode_json(body)
    delivery = audit.begin(
        source=AlertmanagerAdapter.source,
        body=body,
        payload_json=payload_json,
        request_metadata={"content_type": request.headers.get("content-type")},
        replayable=payload_json is not None,
    )
    try:
        result = audit.process(delivery, payload_json)
    except Exception as exc:
        audit.fail(
            delivery,
            exc,
            replayable=(
                payload_json is not None
                and not isinstance(exc, InvalidIngestionPayloadError)
            ),
        )
        raise
    audit.succeed(delivery, result)
    response.headers["X-Ingestion-Delivery-ID"] = delivery.delivery_id
    return result


def _serialize_metric_anomaly(
    anomaly: MetricAnomaly, incident_id: str | None = None
) -> dict:
    return {
        "anomaly_id": anomaly.anomaly_id,
        "service_name": anomaly.service.name,
        "metric_name": anomaly.metric_name,
        "observed_value": anomaly.observed_value,
        "baseline_value": anomaly.baseline_value,
        "unit": anomaly.unit,
        "severity": anomaly.severity,
        "incident_id": incident_id
        or (anomaly.incident.incident_id if anomaly.incident else None),
        "description": anomaly.description,
        "metadata_json": anomaly.metadata_json,
        "observed_at": anomaly.observed_at,
    }


@app.post(
    "/metric-anomalies",
    response_model=MetricAnomalyResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_metric_anomaly(
    payload: MetricAnomalyCreateRequest,
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    anomaly = incident_service.add_metric_anomaly(**payload.model_dump())
    return _serialize_metric_anomaly(anomaly, payload.incident_id)


@app.post("/deployments", status_code=status.HTTP_201_CREATED)
def create_deployment(
    payload: DeploymentCreateRequest,
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    deployment = incident_service.add_deployment(**payload.model_dump())
    return {
        "id": deployment.id,
        "deployment_id": deployment.deployment_id,
        "version": deployment.version,
        "service_name": payload.service_name,
    }


@app.post(
    "/ingestion/github/deployments",
    response_model=GitHubWebhookResponse,
)
async def ingest_github_deployment(
    request: Request,
    response: Response,
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    body = await request.body()
    event = request.headers.get("x-github-event")
    audit = IngestionDeliveryService(incident_service)
    payload_json = audit.decode_json(body)
    delivery = audit.begin(
        source=GitHubDeploymentAdapter.source,
        body=body,
        payload_json=payload_json,
        source_delivery_id=request.headers.get("x-github-delivery"),
        event_type=event,
        request_metadata={"content_type": request.headers.get("content-type")},
        replayable=False,
    )
    try:
        GitHubDeploymentAdapter.verify_signature(
            body=body,
            signature=request.headers.get("x-hub-signature-256"),
            secret=settings.github_webhook_secret,
        )
        result = audit.process(delivery, payload_json)
    except Exception as exc:
        audit.fail(
            delivery,
            exc,
            replayable=(
                payload_json is not None
                and not isinstance(
                    exc,
                    (
                        IngestionAuthenticationError,
                        IngestionUnavailableError,
                        InvalidIngestionPayloadError,
                    ),
                )
            ),
        )
        raise
    audit.succeed(delivery, result)
    response.headers["X-Ingestion-Delivery-ID"] = delivery.delivery_id
    return result


@app.get(
    "/ingestion-deliveries",
    response_model=list[IngestionDeliveryResponse],
)
def list_ingestion_deliveries(
    source: str | None = Query(default=None, max_length=64),
    delivery_status: str | None = Query(default=None, alias="status", max_length=32),
    limit: int = Query(default=50, ge=1, le=100),
    _operator: None = Depends(require_ingestion_audit_reader),
    incident_service: IncidentService = Depends(get_incident_service),
) -> list[dict]:
    records = IngestionDeliveryService(incident_service).list(
        source=source, status=delivery_status, limit=limit
    )
    return [_serialize_ingestion_delivery(item) for item in records]


@app.post(
    "/ingestion-deliveries/purge-expired",
    response_model=IngestionPayloadPurgeResponse,
)
def purge_expired_ingestion_payloads(
    _operator: None = Depends(require_ingestion_replay_operator),
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    purged = IngestionDeliveryService(incident_service).purge_expired()
    return {"purged_deliveries": purged}


@app.get(
    "/ingestion-deliveries/{delivery_id}",
    response_model=IngestionDeliveryResponse,
)
def get_ingestion_delivery(
    delivery_id: str,
    _operator: None = Depends(require_ingestion_audit_reader),
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    delivery = IngestionDeliveryService(incident_service).get(delivery_id)
    return _serialize_ingestion_delivery(delivery)


@app.post(
    "/ingestion-deliveries/{delivery_id}/replay",
    response_model=IngestionReplayResponse,
)
def replay_ingestion_delivery(
    delivery_id: str,
    _operator: None = Depends(require_ingestion_replay_operator),
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    audit = IngestionDeliveryService(incident_service)
    attempt, result = audit.replay(audit.get(delivery_id))
    return {"delivery": _serialize_ingestion_delivery(attempt), "result": result}


@app.post(
    "/service-dependencies",
    response_model=ServiceDependencyResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_service_dependency(
    payload: ServiceDependencyCreateRequest,
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    dependency = incident_service.create_service_dependency(**payload.model_dump())
    return {
        "dependency_id": dependency.dependency_id,
        "service_name": dependency.service.name,
        "depends_on_service_name": dependency.depends_on_service.name,
        "criticality": dependency.criticality,
        "created_at": dependency.created_at,
    }


@app.get("/incidents/{incident_id}", response_model=IncidentResponse)
def get_incident(
    incident_id: str,
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    incident = incident_service.get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    return {
        "incident_id": incident.incident_id,
        "title": incident.title,
        "summary": incident.summary,
        "severity": incident.severity.value,
        "status": incident.status.value,
        "service_name": incident.service.name,
        "started_at": incident.started_at,
        "resolved_at": incident.resolved_at,
        "root_cause": incident.root_cause,
        "resolution_summary": incident.resolution_summary,
        "resolution_confirmed_by": incident.resolution_confirmed_by,
    }


@app.post(
    "/incidents/{incident_id}/resolution",
    response_model=IncidentResolutionResponse,
    status_code=status.HTTP_201_CREATED,
)
def confirm_incident_resolution(
    incident_id: str,
    payload: IncidentResolutionCreateRequest,
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    incident = incident_service.confirm_incident_resolution(
        incident_id=incident_id,
        **payload.model_dump(),
    )
    return {
        "incident_id": incident.incident_id,
        "status": incident.status,
        "root_cause": incident.root_cause,
        "resolution_summary": incident.resolution_summary,
        "resolution_confirmed_by": incident.resolution_confirmed_by,
        "resolved_at": incident.resolved_at,
    }


@app.get("/incidents/{incident_id}/logs")
def get_incident_logs(
    incident_id: str,
    incident_service: IncidentService = Depends(get_incident_service),
) -> list[dict]:
    if incident_service.get_incident(incident_id) is None:
        raise ResourceNotFoundError(f"Incident '{incident_id}' was not found")
    logs = incident_service.get_logs(incident_id)
    return [
        {
            "id": log.id,
            "timestamp": log.timestamp.isoformat(),
            "level": log.level,
            "message": log.message,
            "trace_id": log.trace_id,
            "metadata_json": log.metadata_json,
            "source": log.source,
            "source_event_id": log.source_event_id,
        }
        for log in logs
    ]


@app.get("/incidents/{incident_id}/alerts")
def get_incident_alerts(
    incident_id: str,
    incident_service: IncidentService = Depends(get_incident_service),
) -> list[dict]:
    if incident_service.get_incident(incident_id) is None:
        raise ResourceNotFoundError(f"Incident '{incident_id}' was not found")
    alerts = incident_service.get_alerts(incident_id)
    return [
        {
            "id": alert.id,
            "name": alert.name,
            "severity": alert.severity,
            "description": alert.description,
            "status": alert.status,
            "source": alert.source,
            "source_event_id": alert.source_event_id,
        }
        for alert in alerts
    ]


@app.get(
    "/incidents/{incident_id}/metric-anomalies",
    response_model=list[MetricAnomalyResponse],
)
def get_incident_metric_anomalies(
    incident_id: str,
    incident_service: IncidentService = Depends(get_incident_service),
) -> list[dict]:
    if incident_service.get_incident(incident_id) is None:
        raise ResourceNotFoundError(f"Incident '{incident_id}' was not found")
    return [
        _serialize_metric_anomaly(anomaly, incident_id)
        for anomaly in incident_service.get_metric_anomalies(incident_id)
    ]


@app.get("/incidents/{incident_id}/investigation", response_model=InvestigationResponse)
def investigate_incident(
    incident_id: str,
    lookback_minutes: int = Query(default=settings.correlation_lookback_minutes, ge=1, le=1440),
    lookahead_minutes: int = Query(default=settings.correlation_lookahead_minutes, ge=0, le=1440),
    historical_incident_limit: int = Query(
        default=settings.historical_incident_limit, ge=0, le=20
    ),
    historical_similarity_threshold: float = Query(
        default=settings.historical_similarity_threshold, ge=0, le=1
    ),
    trace_path_limit: int = Query(default=settings.trace_path_limit, ge=0, le=50),
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    investigation = incident_service.investigate(
        incident_id,
        lookback_minutes=lookback_minutes,
        lookahead_minutes=lookahead_minutes,
        historical_incident_limit=historical_incident_limit,
        historical_similarity_threshold=historical_similarity_threshold,
        trace_path_limit=trace_path_limit,
    )
    if investigation is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return investigation


@app.post(
    "/incidents/{incident_id}/ai-analysis",
    response_model=AIAnalysisResponse,
    status_code=status.HTTP_201_CREATED,
)
def analyze_incident_with_ai(
    incident_id: str,
    lookback_minutes: int = Query(default=settings.correlation_lookback_minutes, ge=1, le=1440),
    lookahead_minutes: int = Query(default=settings.correlation_lookahead_minutes, ge=0, le=1440),
    historical_incident_limit: int = Query(
        default=settings.historical_incident_limit, ge=0, le=20
    ),
    historical_similarity_threshold: float = Query(
        default=settings.historical_similarity_threshold, ge=0, le=1
    ),
    trace_path_limit: int = Query(default=settings.trace_path_limit, ge=0, le=50),
    incident_service: IncidentService = Depends(get_incident_service),
    hypothesis_generator: HypothesisGenerator = Depends(get_hypothesis_generator),
) -> dict:
    investigation = incident_service.investigate(
        incident_id,
        lookback_minutes=lookback_minutes,
        lookahead_minutes=lookahead_minutes,
        historical_incident_limit=historical_incident_limit,
        historical_similarity_threshold=historical_similarity_threshold,
        trace_path_limit=trace_path_limit,
    )
    if investigation is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    ranked_signals = investigation["ranked_signals"][: settings.ai_max_ranked_signals]
    analysis = hypothesis_generator.generate(
        incident_id=incident_id,
        summary=investigation["summary"],
        severity=investigation["severity"],
        ranked_signals=ranked_signals,
    )
    record = incident_service.save_ai_analysis(
        incident_id=incident_id,
        model=hypothesis_generator.model,
        prompt_version=hypothesis_generator.prompt_version,
        prompt_sha256=hypothesis_generator.prompt_sha256,
        correlation_window=investigation["correlation_window"],
        ranked_signal_ids=[signal["signal_id"] for signal in ranked_signals],
        hypotheses=[item.model_dump() for item in analysis.hypotheses],
        remediation_suggestions=[
            item.model_dump() for item in analysis.remediation_suggestions
        ],
    )
    return _serialize_ai_analysis(record)


@app.get("/incidents/{incident_id}/ai-analyses", response_model=list[AIAnalysisResponse])
def list_ai_analyses(
    incident_id: str,
    incident_service: IncidentService = Depends(get_incident_service),
) -> list[dict]:
    if incident_service.get_incident(incident_id) is None:
        raise ResourceNotFoundError(f"Incident '{incident_id}' was not found")
    return [
        _serialize_ai_analysis(record)
        for record in incident_service.list_ai_analyses(incident_id)
    ]


@app.post(
    "/ai-analyses/{analysis_id}/feedback",
    response_model=AIAnalysisFeedbackResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_ai_analysis_feedback(
    analysis_id: str,
    payload: AIAnalysisFeedbackCreateRequest,
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    feedback = incident_service.add_ai_analysis_feedback(
        analysis_id=analysis_id,
        **payload.model_dump(),
    )
    return {
        "feedback_id": feedback.feedback_id,
        "analysis_id": analysis_id,
        "hypothesis_index": feedback.hypothesis_index,
        "rating": feedback.rating,
        "operator_name": feedback.operator_name,
        "comment": feedback.comment,
        "created_at": feedback.created_at,
    }


@app.get("/ai-evaluations/metrics", response_model=AIEvaluationMetricsResponse)
def get_ai_evaluation_metrics(
    prompt_version: str | None = Query(default=None, min_length=1, max_length=64),
    model: str | None = Query(default=None, min_length=1, max_length=128),
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    return incident_service.get_ai_evaluation_metrics(
        prompt_version=prompt_version,
        model=model,
    )


@app.post(
    "/ai-evaluations/regression-runs",
    response_model=AIRegressionRunResponse,
    status_code=status.HTTP_201_CREATED,
)
def run_ai_prompt_regression(
    dataset_version: str = Query(default=PROMPT_VERSION, min_length=1, max_length=64),
    incident_service: IncidentService = Depends(get_incident_service),
    hypothesis_generator: HypothesisGenerator = Depends(get_hypothesis_generator),
) -> dict:
    regression_service = AIRegressionService(
        incident_service.repository,
        hypothesis_generator,
    )
    return _serialize_ai_regression_run(regression_service.run(dataset_version))


@app.get(
    "/ai-evaluations/regression-runs",
    response_model=list[AIRegressionRunResponse],
)
def list_ai_prompt_regression_runs(
    limit: int = Query(default=50, ge=1, le=100),
    incident_service: IncidentService = Depends(get_incident_service),
) -> list[dict]:
    return [
        _serialize_ai_regression_run(run)
        for run in incident_service.list_ai_regression_runs(limit=limit)
    ]


@app.get(
    "/ai-evaluations/regression-runs/{candidate_run_id}/comparison",
    response_model=AIRegressionComparisonResponse,
)
def compare_ai_prompt_regression_runs(
    candidate_run_id: str,
    baseline_run_id: str = Query(min_length=1, max_length=64),
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    comparison_service = AIRegressionComparisonService(incident_service.repository)
    return comparison_service.compare(
        candidate_run_id=candidate_run_id,
        baseline_run_id=baseline_run_id,
    )


@app.post(
    "/ai-evaluations/regression-runs/{candidate_run_id}/quality-gate",
    response_model=AIRegressionQualityGateResponse,
    responses={
        status.HTTP_412_PRECONDITION_FAILED: {
            "model": AIRegressionQualityGateResponse,
            "description": "The candidate run failed one or more quality thresholds.",
        }
    },
)
def evaluate_ai_prompt_regression_quality_gate(
    candidate_run_id: str,
    payload: AIRegressionQualityGateRequest,
    response: Response,
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    comparison_service = AIRegressionComparisonService(incident_service.repository)
    result = comparison_service.evaluate_quality_gate(
        candidate_run_id=candidate_run_id,
        **payload.model_dump(),
    )
    if not result["passed"]:
        response.status_code = status.HTTP_412_PRECONDITION_FAILED
    return result


@app.get("/services/{service_name}/deployments")
def get_service_deployments(
    service_name: str,
    incident_service: IncidentService = Depends(get_incident_service),
) -> list[dict]:
    deployments = incident_service.get_deployments(service_name)
    return [
        {
            "id": deployment.id,
            "deployment_id": deployment.deployment_id,
            "version": deployment.version,
            "environment": deployment.environment,
            "status": deployment.status,
            "deployed_at": deployment.deployed_at.isoformat(),
            "notes": deployment.notes,
            "metadata_json": deployment.metadata_json,
            "source": deployment.source,
            "source_event_id": deployment.source_event_id,
        }
        for deployment in deployments
    ]


@app.get(
    "/services/{service_name}/dependencies",
    response_model=list[ServiceDependencyResponse],
)
def get_service_dependencies(
    service_name: str,
    incident_service: IncidentService = Depends(get_incident_service),
) -> list[dict]:
    dependencies = incident_service.list_service_dependencies(service_name)
    return [
        {
            "dependency_id": dependency.dependency_id,
            "service_name": dependency.service.name,
            "depends_on_service_name": dependency.depends_on_service.name,
            "criticality": dependency.criticality,
            "created_at": dependency.created_at,
        }
        for dependency in dependencies
    ]
