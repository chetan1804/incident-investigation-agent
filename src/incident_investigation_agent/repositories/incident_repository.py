from __future__ import annotations

from datetime import datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from incident_investigation_agent.exceptions import ResourceConflictError, ResourceNotFoundError
from incident_investigation_agent.models.incident_models import Alert, Deployment, Incident, LogEntry, Service


class IncidentRepository:
    """Repository for basic incident-related database operations."""

    def __init__(self, session: Session):
        self.session = session

    def create_service(self, *, name: str, environment: str = "production", description: str | None = None) -> Service:
        service = self.session.scalar(select(Service).where(Service.name == name))
        if service is not None:
            return service

        service = Service(name=name, environment=environment, description=description)
        self.session.add(service)
        self.session.commit()
        self.session.refresh(service)
        return service

    def create_incident(
        self,
        *,
        service_name: str,
        title: str,
        summary: str,
        incident_id: str,
        severity: str = "medium",
        status: str = "open",
        metadata_json: dict | None = None,
    ) -> Incident:
        if self.get_incident_by_id(incident_id) is not None:
            raise ResourceConflictError(f"Incident '{incident_id}' already exists")

        service = self.create_service(name=service_name)
        incident = Incident(
            incident_id=incident_id,
            title=title,
            summary=summary,
            severity=severity,
            status=status,
            service_id=service.id,
            metadata_json=metadata_json,
        )
        self.session.add(incident)
        self._commit_or_conflict(f"Incident '{incident_id}' already exists")
        self.session.refresh(incident)
        return incident

    def get_incident_by_id(self, incident_id: str) -> Incident | None:
        statement = select(Incident).where(Incident.incident_id == incident_id).options()
        return self.session.scalar(statement)

    def list_incidents(self, limit: int = 50) -> list[Incident]:
        statement = select(Incident).order_by(Incident.created_at.desc()).limit(limit)
        return list(self.session.scalars(statement).all())

    def get_logs_for_incident(self, incident_id: str) -> list[LogEntry]:
        incident = self.get_incident_by_id(incident_id)
        if incident is None:
            return []

        statement = select(LogEntry).where(LogEntry.incident_id == incident.id).order_by(LogEntry.timestamp.asc())
        return list(self.session.scalars(statement).all())

    def get_related_alerts(self, incident_id: str) -> list[Alert]:
        incident = self.get_incident_by_id(incident_id)
        if incident is None:
            return []

        statement = select(Alert).where(Alert.incident_id == incident.id).order_by(Alert.fired_at.desc())
        return list(self.session.scalars(statement).all())

    def get_deployments_for_service(self, service_name: str) -> list[Deployment]:
        service = self.session.scalar(select(Service).where(Service.name == service_name))
        if service is None:
            return []

        statement = select(Deployment).where(Deployment.service_id == service.id).order_by(Deployment.deployed_at.desc())
        return list(self.session.scalars(statement).all())

    def create_log(
        self,
        *,
        service_name: str,
        message: str,
        level: str = "INFO",
        incident_id: str | None = None,
        trace_id: str | None = None,
        metadata_json: dict | None = None,
        timestamp: datetime | None = None,
    ) -> LogEntry:
        service, incident = self._resolve_evidence_context(service_name, incident_id)

        log_entry = LogEntry(
            service_id=service.id,
            incident_id=incident.id if incident else None,
            level=level,
            message=message,
            trace_id=trace_id,
            metadata_json=metadata_json,
            **({"timestamp": timestamp} if timestamp is not None else {}),
        )
        self.session.add(log_entry)
        self.session.commit()
        self.session.refresh(log_entry)
        return log_entry

    def create_alert(
        self,
        *,
        service_name: str,
        name: str,
        severity: str = "warning",
        description: str | None = None,
        incident_id: str | None = None,
        fired_at: datetime | None = None,
    ) -> Alert:
        service, incident = self._resolve_evidence_context(service_name, incident_id)

        alert = Alert(
            service_id=service.id,
            incident_id=incident.id if incident else None,
            name=name,
            severity=severity,
            description=description,
            **({"fired_at": fired_at} if fired_at is not None else {}),
        )
        self.session.add(alert)
        self.session.commit()
        self.session.refresh(alert)
        return alert

    def create_deployment(
        self,
        *,
        service_name: str,
        deployment_id: str,
        version: str,
        environment: str = "production",
        status: str = "success",
        notes: str | None = None,
        metadata_json: dict | None = None,
        deployed_at: datetime | None = None,
    ) -> Deployment:
        existing = self.session.scalar(select(Deployment).where(Deployment.deployment_id == deployment_id))
        if existing is not None:
            raise ResourceConflictError(f"Deployment '{deployment_id}' already exists")

        service = self.create_service(name=service_name)
        deployment = Deployment(
            service_id=service.id,
            deployment_id=deployment_id,
            version=version,
            environment=environment,
            status=status,
            notes=notes,
            metadata_json=metadata_json,
            **({"deployed_at": deployed_at} if deployed_at is not None else {}),
        )
        self.session.add(deployment)
        self._commit_or_conflict(f"Deployment '{deployment_id}' already exists")
        self.session.refresh(deployment)
        return deployment

    def _resolve_evidence_context(
        self, service_name: str, incident_id: str | None
    ) -> tuple[Service, Incident | None]:
        if incident_id is None:
            return self.create_service(name=service_name), None

        incident = self.get_incident_by_id(incident_id)
        if incident is None:
            raise ResourceNotFoundError(f"Incident '{incident_id}' was not found")
        if incident.service.name != service_name:
            raise ResourceConflictError(
                f"Incident '{incident_id}' belongs to service '{incident.service.name}', not '{service_name}'"
            )
        return incident.service, incident

    def _commit_or_conflict(self, message: str) -> None:
        try:
            self.session.commit()
        except IntegrityError as exc:
            self.session.rollback()
            raise ResourceConflictError(message) from exc
