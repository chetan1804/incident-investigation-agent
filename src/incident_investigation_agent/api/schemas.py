from __future__ import annotations

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


class IncidentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    incident_id: str
    title: str
    summary: str
    severity: IncidentSeverity
    status: IncidentStatus
    service_name: str