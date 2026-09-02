from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from incident_investigation_agent.models.incident_models import IncidentSeverity, IncidentStatus


class IncidentCreateRequest(BaseModel):
    service_name: str = Field(min_length=1, max_length=255)
    title: str = Field(min_length=1, max_length=255)
    summary: str = Field(min_length=1)
    incident_id: str = Field(min_length=1, max_length=64)
    severity: IncidentSeverity = IncidentSeverity.MEDIUM
    status: IncidentStatus = IncidentStatus.OPEN
    metadata_json: dict[str, Any] | None = None
    started_at: datetime | None = None


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    incident_id: str
    title: str
    summary: str
    severity: IncidentSeverity
    status: IncidentStatus
    service_name: str
    started_at: datetime


class EvidenceCounts(BaseModel):
    logs: int
    alerts: int
    deployments: int


class CorrelationWindowResponse(BaseModel):
    started_at: datetime
    window_start: datetime
    window_end: datetime
    lookback_minutes: int
    lookahead_minutes: int


class RankedSignalResponse(BaseModel):
    signal_id: str
    kind: str
    description: str
    observed_at: datetime
    confidence: float = Field(ge=0, le=1)
    reasoning: str


class RootCauseCandidateResponse(BaseModel):
    hypothesis: str
    confidence: float = Field(ge=0, le=1)
    supporting_signals: list[str]


class RecentDeploymentResponse(BaseModel):
    deployment_id: str
    version: str
    deployed_at: datetime


class InvestigationResponse(BaseModel):
    incident_id: str
    summary: str
    severity: IncidentSeverity
    status: IncidentStatus
    scoring_method: str
    correlation_window: CorrelationWindowResponse
    evidence: EvidenceCounts
    signals: list[str]
    ranked_signals: list[RankedSignalResponse]
    root_cause_candidates: list[RootCauseCandidateResponse]
    recent_deployment: RecentDeploymentResponse | None


class LogCreateRequest(BaseModel):
    service_name: str = Field(min_length=1, max_length=255)
    message: str = Field(min_length=1)
    level: str = Field(default="INFO", min_length=1, max_length=20)
    incident_id: str | None = Field(default=None, max_length=64)
    trace_id: str | None = Field(default=None, max_length=128)
    metadata_json: dict[str, Any] | None = None
    timestamp: datetime | None = None


class AlertCreateRequest(BaseModel):
    service_name: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    severity: str = Field(default="warning", min_length=1, max_length=32)
    description: str | None = None
    incident_id: str | None = Field(default=None, max_length=64)
    fired_at: datetime | None = None


class DeploymentCreateRequest(BaseModel):
    service_name: str = Field(min_length=1, max_length=255)
    deployment_id: str = Field(min_length=1, max_length=64)
    version: str = Field(min_length=1, max_length=64)
    environment: str = Field(default="production", min_length=1, max_length=64)
    status: str = Field(default="success", min_length=1, max_length=32)
    notes: str | None = None
    metadata_json: dict[str, Any] | None = None
    deployed_at: datetime | None = None
