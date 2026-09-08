from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse

from incident_investigation_agent.api.dependencies import get_hypothesis_generator, get_incident_service
from incident_investigation_agent.api.schemas import (
    AIAnalysisFeedbackCreateRequest,
    AIAnalysisFeedbackResponse,
    AIAnalysisResponse,
    AIEvaluationMetricsResponse,
    AIRegressionComparisonResponse,
    AIRegressionQualityGateRequest,
    AIRegressionQualityGateResponse,
    AIRegressionRunResponse,
    AlertCreateRequest,
    DeploymentCreateRequest,
    IncidentCreateRequest,
    IncidentResolutionCreateRequest,
    IncidentResolutionResponse,
    IncidentResponse,
    InvestigationResponse,
    LogCreateRequest,
    ServiceDependencyCreateRequest,
    ServiceDependencyResponse,
)
from incident_investigation_agent.config.settings import settings
from incident_investigation_agent.exceptions import (
    AIAnalysisError,
    AIAnalysisUnavailableError,
    InvalidFeedbackError,
    ResourceConflictError,
    ResourceNotFoundError,
)
from incident_investigation_agent.models.incident_models import AIAnalysisRecord, AIRegressionRun
from incident_investigation_agent.services.ai_analysis_service import (
    PROMPT_VERSION,
    HypothesisGenerator,
)
from incident_investigation_agent.services.ai_regression_service import (
    AIRegressionComparisonService,
    AIRegressionService,
)
from incident_investigation_agent.services.incident_service import IncidentService

app = FastAPI(title="Incident Investigation Agent", version="0.1.0")


@app.exception_handler(ResourceNotFoundError)
def handle_not_found(_request: Request, exc: ResourceNotFoundError) -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": str(exc)})


@app.exception_handler(ResourceConflictError)
def handle_conflict(_request: Request, exc: ResourceConflictError) -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})


@app.exception_handler(AIAnalysisUnavailableError)
def handle_ai_unavailable(_request: Request, exc: AIAnalysisUnavailableError) -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"detail": str(exc)})


@app.exception_handler(AIAnalysisError)
def handle_ai_error(_request: Request, exc: AIAnalysisError) -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_502_BAD_GATEWAY, content={"detail": str(exc)})


@app.exception_handler(InvalidFeedbackError)
def handle_invalid_feedback(_request: Request, exc: InvalidFeedbackError) -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, content={"detail": str(exc)})


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


@app.post("/alerts", status_code=status.HTTP_201_CREATED)
def create_alert(
    payload: AlertCreateRequest,
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    alert = incident_service.add_alert(**payload.model_dump())
    return {"id": alert.id, "name": alert.name, "severity": alert.severity, "incident_id": payload.incident_id}


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
        }
        for alert in alerts
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
