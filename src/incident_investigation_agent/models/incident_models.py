from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from sqlalchemy import DateTime, Enum as SAEnum, Float, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from incident_investigation_agent.database.base import Base


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp for database defaults."""
    return datetime.now(UTC)


class IncidentSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


class Service(Base):
    """Represents a production service that can have incidents and alerts."""

    __tablename__ = "services"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    environment: Mapped[str] = mapped_column(String(64), default="production")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    incidents: Mapped[list["Incident"]] = relationship(back_populates="service")
    deployments: Mapped[list["Deployment"]] = relationship(back_populates="service")
    logs: Mapped[list["LogEntry"]] = relationship(back_populates="service")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="service")
    metric_anomalies: Mapped[list["MetricAnomaly"]] = relationship(back_populates="service")


class ServiceDependency(Base):
    """A directed dependency where one service relies on another service."""

    __tablename__ = "service_dependencies"
    __table_args__ = (
        UniqueConstraint(
            "service_id",
            "depends_on_service_id",
            name="uq_service_dependencies_direction",
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    dependency_id: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), nullable=False, index=True)
    depends_on_service_id: Mapped[int] = mapped_column(
        ForeignKey("services.id"), nullable=False, index=True
    )
    criticality: Mapped[str] = mapped_column(String(32), default="medium", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)

    service: Mapped[Service] = relationship(foreign_keys=[service_id])
    depends_on_service: Mapped[Service] = relationship(foreign_keys=[depends_on_service_id])


class Incident(Base):
    """An operational incident with a summary and status."""

    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    incident_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[IncidentSeverity] = mapped_column(
        SAEnum(IncidentSeverity), default=IncidentSeverity.MEDIUM, nullable=False
    )
    status: Mapped[IncidentStatus] = mapped_column(
        SAEnum(IncidentStatus), default=IncidentStatus.OPEN, nullable=False
    )
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), nullable=False, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    root_cause: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolution_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolution_confirmed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    service: Mapped[Service] = relationship(back_populates="incidents")
    logs: Mapped[list["LogEntry"]] = relationship(back_populates="incident")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="incident")
    metric_anomalies: Mapped[list["MetricAnomaly"]] = relationship(back_populates="incident")
    ai_analyses: Mapped[list["AIAnalysisRecord"]] = relationship(back_populates="incident")


class LogEntry(Base):
    """Structured log record associated with a service and an incident."""

    __tablename__ = "logs"
    __table_args__ = (
        UniqueConstraint("source", "source_event_id", name="uq_logs_source_event"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), nullable=False, index=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    level: Mapped[str] = mapped_column(String(20), default="INFO")
    message: Mapped[str] = mapped_column(Text, nullable=False)
    trace_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    source: Mapped[str] = mapped_column(String(64), default="api", nullable=False)
    source_event_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    service: Mapped[Service] = relationship(back_populates="logs")
    incident: Mapped[Incident | None] = relationship(back_populates="logs")


class Deployment(Base):
    """Represents a deployment event for a service."""

    __tablename__ = "deployments"
    __table_args__ = (
        UniqueConstraint("source", "source_event_id", name="uq_deployments_source_event"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), nullable=False, index=True)
    deployment_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    environment: Mapped[str] = mapped_column(String(64), default="production")
    deployed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    status: Mapped[str] = mapped_column(String(32), default="success")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    source: Mapped[str] = mapped_column(String(64), default="api", nullable=False)
    source_event_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    service: Mapped[Service] = relationship(back_populates="deployments")


class Alert(Base):
    """Alert data associated with a service or incident."""

    __tablename__ = "alerts"
    __table_args__ = (
        UniqueConstraint("source", "source_event_id", name="uq_alerts_source_event"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), nullable=False, index=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="warning")
    fired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    status: Mapped[str] = mapped_column(String(32), default="active")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(64), default="api", nullable=False)
    source_event_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    service: Mapped[Service] = relationship(back_populates="alerts")
    incident: Mapped[Incident | None] = relationship(back_populates="alerts")


class MetricAnomaly(Base):
    """A time-series metric observation that deviates from its baseline."""

    __tablename__ = "metric_anomalies"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    anomaly_id: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id"), nullable=False, index=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True, index=True)
    metric_name: Mapped[str] = mapped_column(String(255), nullable=False)
    observed_value: Mapped[float] = mapped_column(Float, nullable=False)
    baseline_value: Mapped[float] = mapped_column(Float, nullable=False)
    unit: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[str] = mapped_column(String(32), default="warning", nullable=False)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, index=True
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    service: Mapped[Service] = relationship(back_populates="metric_anomalies")
    incident: Mapped[Incident | None] = relationship(back_populates="metric_anomalies")


class AIAnalysisRecord(Base):
    """An immutable snapshot of generated analysis and the evidence used for it."""

    __tablename__ = "ai_analyses"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    analysis_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id"), nullable=False, index=True)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(64), nullable=False)
    prompt_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    correlation_window_json: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    ranked_signal_ids_json: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    hypotheses_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    remediation_suggestions_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)

    incident: Mapped[Incident] = relationship(back_populates="ai_analyses")
    feedback: Mapped[list["AIAnalysisFeedback"]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )


class AIAnalysisFeedback(Base):
    """An operator assessment of one hypothesis in a persisted analysis."""

    __tablename__ = "ai_analysis_feedback"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    feedback_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("ai_analyses.id"), nullable=False, index=True)
    hypothesis_index: Mapped[int] = mapped_column(Integer, nullable=False)
    rating: Mapped[str] = mapped_column(String(32), nullable=False)
    operator_name: Mapped[str] = mapped_column(String(255), nullable=False)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)

    analysis: Mapped[AIAnalysisRecord] = relationship(back_populates="feedback")


class AIRegressionRun(Base):
    """An immutable result from evaluating one prompt/model against a dataset."""

    __tablename__ = "ai_regression_runs"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    run_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    dataset_version: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    model: Mapped[str] = mapped_column(String(128), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    prompt_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    passed: Mapped[bool] = mapped_column(nullable=False)
    total_cases: Mapped[int] = mapped_column(Integer, nullable=False)
    passed_cases: Mapped[int] = mapped_column(Integer, nullable=False)
    results_json: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)


class IngestionDelivery(Base):
    """Audit record for an external ingestion request or replay attempt."""

    __tablename__ = "ingestion_deliveries"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    delivery_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source_delivery_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    event_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    payload_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    payload_json: Mapped[dict[str, Any] | list[Any] | None] = mapped_column(JSON, nullable=True)
    request_metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    result_json: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    error_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    replayable: Mapped[bool] = mapped_column(default=False, nullable=False)
    replay_of_id: Mapped[int | None] = mapped_column(
        ForeignKey("ingestion_deliveries.id"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    replay_of: Mapped["IngestionDelivery | None"] = relationship(remote_side=[id])
