from __future__ import annotations

from fastapi import Depends, FastAPI, HTTPException

from incident_investigation_agent.api.dependencies import get_incident_service
from incident_investigation_agent.models.incident_models import Alert, Deployment, Incident, LogEntry
from incident_investigation_agent.services.incident_service import IncidentService

app = FastAPI(title="Incident Investigation Agent", version="0.1.0")


@app.post("/incidents")
def create_incident(
    payload: dict,
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    required_fields = {"service_name", "title", "summary", "incident_id"}
    missing = sorted(required_fields - set(payload.keys()))
    if missing:
        raise HTTPException(status_code=400, detail=f"Missing required fields: {missing}")

    incident = incident_service.create_incident(
        service_name=payload["service_name"],
        title=payload["title"],
        summary=payload["summary"],
        incident_id=payload["incident_id"],
        severity=payload.get("severity", "medium"),
        status=payload.get("status", "open"),
        metadata_json=payload.get("metadata_json"),
    )
    return {
        "incident_id": incident.incident_id,
        "title": incident.title,
        "summary": incident.summary,
        "severity": incident.severity.value,
        "status": incident.status.value,
        "service_name": incident.service.name,
    }


@app.get("/incidents/{incident_id}")
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
    }


@app.get("/incidents/{incident_id}/logs")
def get_incident_logs(
    incident_id: str,
    incident_service: IncidentService = Depends(get_incident_service),
) -> list[dict]:
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


@app.get("/incidents/{incident_id}/investigation")
def investigate_incident(
    incident_id: str,
    incident_service: IncidentService = Depends(get_incident_service),
) -> dict:
    investigation = incident_service.investigate(incident_id)
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
