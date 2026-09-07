from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from incident_investigation_agent.exceptions import (
    InvalidFeedbackError,
    ResourceConflictError,
    ResourceNotFoundError,
)
from incident_investigation_agent.models.incident_models import (
    AIAnalysisFeedback,
    AIAnalysisRecord,
    AIRegressionRun,
    Alert,
    Deployment,
    Incident,
    LogEntry,
    Service,
    ServiceDependency,
)


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
        started_at: datetime | None = None,
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
            **({"started_at": started_at} if started_at is not None else {}),
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

    def create_service_dependency(
        self,
        *,
        service_name: str,
        depends_on_service_name: str,
        criticality: str = "medium",
    ) -> ServiceDependency:
        if service_name == depends_on_service_name:
            raise ResourceConflictError("A service cannot depend on itself")
        service = self.create_service(name=service_name)
        upstream = self.create_service(name=depends_on_service_name)
        existing = self.session.scalar(
            select(ServiceDependency).where(
                ServiceDependency.service_id == service.id,
                ServiceDependency.depends_on_service_id == upstream.id,
            )
        )
        if existing is not None:
            raise ResourceConflictError(
                f"Dependency from '{service_name}' to '{depends_on_service_name}' already exists"
            )

        dependency = ServiceDependency(
            dependency_id=f"SD-{uuid4()}",
            service_id=service.id,
            depends_on_service_id=upstream.id,
            criticality=criticality,
        )
        self.session.add(dependency)
        self._commit_or_conflict(
            f"Dependency from '{service_name}' to '{depends_on_service_name}' already exists"
        )
        self.session.refresh(dependency)
        return dependency

    def list_service_dependencies(self, service_name: str) -> list[ServiceDependency]:
        service = self.session.scalar(select(Service).where(Service.name == service_name))
        if service is None:
            raise ResourceNotFoundError(f"Service '{service_name}' was not found")
        statement = (
            select(ServiceDependency)
            .where(
                (ServiceDependency.service_id == service.id)
                | (ServiceDependency.depends_on_service_id == service.id)
            )
            .options(
                selectinload(ServiceDependency.service),
                selectinload(ServiceDependency.depends_on_service),
            )
            .order_by(ServiceDependency.created_at.asc())
        )
        return list(self.session.scalars(statement).all())

    def get_logs_for_service(
        self,
        service_name: str,
        *,
        window_start: datetime,
        window_end: datetime,
    ) -> list[LogEntry]:
        statement = (
            select(LogEntry)
            .join(Service)
            .where(
                Service.name == service_name,
                LogEntry.timestamp >= window_start,
                LogEntry.timestamp <= window_end,
            )
            .order_by(LogEntry.timestamp.asc())
        )
        return list(self.session.scalars(statement).all())

    def get_alerts_for_service(
        self,
        service_name: str,
        *,
        window_start: datetime,
        window_end: datetime,
    ) -> list[Alert]:
        statement = (
            select(Alert)
            .join(Service)
            .where(
                Service.name == service_name,
                Alert.fired_at >= window_start,
                Alert.fired_at <= window_end,
            )
            .order_by(Alert.fired_at.asc())
        )
        return list(self.session.scalars(statement).all())

    def get_logs_for_incident(
        self,
        incident_id: str,
        *,
        window_start: datetime | None = None,
        window_end: datetime | None = None,
    ) -> list[LogEntry]:
        incident = self.get_incident_by_id(incident_id)
        if incident is None:
            return []

        statement = select(LogEntry).where(LogEntry.incident_id == incident.id)
        if window_start is not None:
            statement = statement.where(LogEntry.timestamp >= window_start)
        if window_end is not None:
            statement = statement.where(LogEntry.timestamp <= window_end)
        statement = statement.order_by(LogEntry.timestamp.asc())
        return list(self.session.scalars(statement).all())

    def get_related_alerts(
        self,
        incident_id: str,
        *,
        window_start: datetime | None = None,
        window_end: datetime | None = None,
    ) -> list[Alert]:
        incident = self.get_incident_by_id(incident_id)
        if incident is None:
            return []

        statement = select(Alert).where(Alert.incident_id == incident.id)
        if window_start is not None:
            statement = statement.where(Alert.fired_at >= window_start)
        if window_end is not None:
            statement = statement.where(Alert.fired_at <= window_end)
        statement = statement.order_by(Alert.fired_at.desc())
        return list(self.session.scalars(statement).all())

    def get_deployments_for_service(
        self,
        service_name: str,
        *,
        window_start: datetime | None = None,
        window_end: datetime | None = None,
    ) -> list[Deployment]:
        service = self.session.scalar(select(Service).where(Service.name == service_name))
        if service is None:
            return []

        statement = select(Deployment).where(Deployment.service_id == service.id)
        if window_start is not None:
            statement = statement.where(Deployment.deployed_at >= window_start)
        if window_end is not None:
            statement = statement.where(Deployment.deployed_at <= window_end)
        statement = statement.order_by(Deployment.deployed_at.desc())
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

    def create_ai_analysis(
        self,
        *,
        incident_id: str,
        model: str,
        prompt_version: str,
        prompt_sha256: str,
        correlation_window_json: dict,
        ranked_signal_ids_json: list[str],
        hypotheses_json: list[dict],
        remediation_suggestions_json: list[dict],
    ) -> AIAnalysisRecord:
        incident = self.get_incident_by_id(incident_id)
        if incident is None:
            raise ResourceNotFoundError(f"Incident '{incident_id}' was not found")

        record = AIAnalysisRecord(
            analysis_id=f"AIA-{uuid4()}",
            incident_id=incident.id,
            model=model,
            prompt_version=prompt_version,
            prompt_sha256=prompt_sha256,
            correlation_window_json=correlation_window_json,
            ranked_signal_ids_json=ranked_signal_ids_json,
            hypotheses_json=hypotheses_json,
            remediation_suggestions_json=remediation_suggestions_json,
        )
        self.session.add(record)
        self.session.commit()
        self.session.refresh(record)
        return record

    def get_ai_analysis(self, analysis_id: str) -> AIAnalysisRecord | None:
        return self.session.scalar(
            select(AIAnalysisRecord).where(AIAnalysisRecord.analysis_id == analysis_id)
        )

    def list_ai_analyses(self, incident_id: str) -> list[AIAnalysisRecord]:
        incident = self.get_incident_by_id(incident_id)
        if incident is None:
            return []
        statement = (
            select(AIAnalysisRecord)
            .where(AIAnalysisRecord.incident_id == incident.id)
            .order_by(AIAnalysisRecord.created_at.desc())
        )
        return list(self.session.scalars(statement).all())

    def list_ai_analyses_for_evaluation(
        self,
        *,
        prompt_version: str | None = None,
        model: str | None = None,
    ) -> list[AIAnalysisRecord]:
        """Return analysis snapshots and feedback used to calculate evaluation metrics."""
        statement = select(AIAnalysisRecord).options(selectinload(AIAnalysisRecord.feedback))
        if prompt_version is not None:
            statement = statement.where(AIAnalysisRecord.prompt_version == prompt_version)
        if model is not None:
            statement = statement.where(AIAnalysisRecord.model == model)
        statement = statement.order_by(AIAnalysisRecord.created_at.asc())
        return list(self.session.scalars(statement).all())

    def create_ai_analysis_feedback(
        self,
        *,
        analysis_id: str,
        hypothesis_index: int,
        rating: str,
        operator_name: str,
        comment: str | None = None,
    ) -> AIAnalysisFeedback:
        analysis = self.get_ai_analysis(analysis_id)
        if analysis is None:
            raise ResourceNotFoundError(f"AI analysis '{analysis_id}' was not found")
        if hypothesis_index >= len(analysis.hypotheses_json):
            raise InvalidFeedbackError(
                f"Hypothesis index {hypothesis_index} does not exist in analysis '{analysis_id}'"
            )

        feedback = AIAnalysisFeedback(
            feedback_id=f"AIF-{uuid4()}",
            analysis_id=analysis.id,
            hypothesis_index=hypothesis_index,
            rating=rating,
            operator_name=operator_name,
            comment=comment,
        )
        self.session.add(feedback)
        self.session.commit()
        self.session.refresh(feedback)
        return feedback

    def create_ai_regression_run(
        self,
        *,
        dataset_version: str,
        model: str,
        prompt_version: str,
        prompt_sha256: str,
        passed: bool,
        total_cases: int,
        passed_cases: int,
        results_json: list[dict],
    ) -> AIRegressionRun:
        run = AIRegressionRun(
            run_id=f"AIR-{uuid4()}",
            dataset_version=dataset_version,
            model=model,
            prompt_version=prompt_version,
            prompt_sha256=prompt_sha256,
            passed=passed,
            total_cases=total_cases,
            passed_cases=passed_cases,
            results_json=results_json,
        )
        self.session.add(run)
        self.session.commit()
        self.session.refresh(run)
        return run

    def list_ai_regression_runs(self, limit: int = 50) -> list[AIRegressionRun]:
        statement = (
            select(AIRegressionRun)
            .order_by(AIRegressionRun.created_at.desc())
            .limit(limit)
        )
        return list(self.session.scalars(statement).all())

    def get_ai_regression_run(self, run_id: str) -> AIRegressionRun | None:
        return self.session.scalar(
            select(AIRegressionRun).where(AIRegressionRun.run_id == run_id)
        )

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
