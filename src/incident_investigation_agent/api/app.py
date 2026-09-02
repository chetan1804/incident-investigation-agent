from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse

from incident_investigation_agent.api.dependencies import get_incident_service
from incident_investigation_agent.api.schemas import (
    AlertCreateRequest,
    DeploymentCreateRequest,
    IncidentCreateRequest,
    IncidentResponse,
    InvestigationResponse,
    LogCreateRequest,
)
from incident_investigation_agent.config.settings import settings
from incident_investigation_agent.exceptions import ResourceConflictError, ResourceNotFoundError
from incident_investigation_agent.services.incident_service import IncidentService

app = FastAPI(title="Incident Investigation Agent", version="0.1.0")


@app.exception_handler(ResourceNotFoundError)
def handle_not_found(_request: Request, exc: ResourceNotFoundError) -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": str(exc)})


@app.exception_handler(ResourceConflictError)
def handle_conflict(_request: Request, exc: ResourceConflictError) -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})


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
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    investigation = incident_service.investigate(
        incident_id,
        lookback_minutes=lookback_minutes,
        lookahead_minutes=lookahead_minutes,
    )
    if investigation is None:
        raise HTTPException(status_code=404, detail="Incident not found")
    return investigation


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
