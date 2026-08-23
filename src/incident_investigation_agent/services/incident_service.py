from __future__ import annotations

from typing import Any

from incident_investigation_agent.models.incident_models import Alert, Deployment, Incident, LogEntry
from incident_investigation_agent.repositories.incident_repository import IncidentRepository


class IncidentService:
    """Application service for the incident domain logic."""

    def __init__(self, repository: IncidentRepository):
        self.repository = repository

    def create_incident(
        self,
        *,
        service_name: str,
        title: str,
        summary: str,
        incident_id: str,
        severity: str = "medium",
        status: str = "open",
        metadata_json: dict[str, Any] | None = None,
    ) -> Incident:
        return self.repository.create_incident(
            service_name=service_name,
            title=title,
            summary=summary,
            incident_id=incident_id,
            severity=severity,
            status=status,
            metadata_json=metadata_json,
        )

    def get_incident(self, incident_id: str) -> Incident | None:
        return self.repository.get_incident_by_id(incident_id)

    def list_incidents(self, limit: int = 50) -> list[Incident]:
        return self.repository.list_incidents(limit=limit)

    def get_logs(self, incident_id: str) -> list[LogEntry]:
        return self.repository.get_logs_for_incident(incident_id)

    def get_alerts(self, incident_id: str) -> list[Alert]:
        return self.repository.get_related_alerts(incident_id)

    def get_deployments(self, service_name: str) -> list[Deployment]:
        return self.repository.get_deployments_for_service(service_name)

    def investigate(self, incident_id: str) -> dict[str, Any] | None:
        incident = self.get_incident(incident_id)
        if incident is None:
            return None

        logs = self.get_logs(incident_id)
        alerts = self.get_alerts(incident_id)
        deployments = self.get_deployments(incident.service.name)
        signals = [
            f"alert:{alert.name} ({alert.severity})"
            for alert in alerts
        ]
        signals.extend(
            f"log:{log.level} {log.message}"
            for log in logs
            if log.level.upper() in {"ERROR", "CRITICAL", "FATAL"}
        )
        if deployments:
            signals.append(
                f"deployment:{deployments[0].deployment_id} ({deployments[0].version})"
            )

        return {
            "incident_id": incident.incident_id,
            "summary": incident.summary,
            "severity": incident.severity.value,
            "status": incident.status.value,
            "evidence": {
                "logs": len(logs),
                "alerts": len(alerts),
                "deployments": len(deployments),
            },
            "signals": signals,
            "recent_deployment": (
                {
                    "deployment_id": deployments[0].deployment_id,
                    "version": deployments[0].version,
                    "deployed_at": deployments[0].deployed_at.isoformat(),
                }
                if deployments
                else None
            ),
        }

    def add_log(
        self,
        *,
        service_name: str,
        message: str,
        level: str = "INFO",
        incident_id: str | None = None,
        trace_id: str | None = None,
        metadata_json: dict[str, Any] | None = None,
    ) -> LogEntry:
        return self.repository.create_log(
            service_name=service_name,
            message=message,
            level=level,
            incident_id=incident_id,
            trace_id=trace_id,
            metadata_json=metadata_json,
        )

    def add_alert(
        self,
        *,
        service_name: str,
        name: str,
        severity: str = "warning",
        description: str | None = None,
        incident_id: str | None = None,
    ) -> Alert:
        return self.repository.create_alert(
            service_name=service_name,
            name=name,
            severity=severity,
            description=description,
            incident_id=incident_id,
        )

    def add_deployment(
        self,
        *,
        service_name: str,
        deployment_id: str,
        version: str,
        environment: str = "production",
        status: str = "success",
        notes: str | None = None,
        metadata_json: dict[str, Any] | None = None,
    ) -> Deployment:
        return self.repository.create_deployment(
            service_name=service_name,
            deployment_id=deployment_id,
            version=version,
            environment=environment,
            status=status,
            notes=notes,
            metadata_json=metadata_json,
        )
