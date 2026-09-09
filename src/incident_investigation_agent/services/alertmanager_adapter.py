from __future__ import annotations

from hashlib import sha256
import json
from typing import TYPE_CHECKING, Any

from incident_investigation_agent.exceptions import (
    InvalidIngestionPayloadError,
    ResourceConflictError,
    ResourceNotFoundError,
)
from incident_investigation_agent.services.incident_service import IncidentService

if TYPE_CHECKING:
    from incident_investigation_agent.api.schemas import AlertmanagerWebhookRequest


class AlertmanagerAdapter:
    """Normalize Prometheus Alertmanager webhooks into alert evidence."""

    source = "prometheus-alertmanager"

    def __init__(self, incident_service: IncidentService):
        self.incident_service = incident_service

    def ingest(self, payload: AlertmanagerWebhookRequest) -> dict[str, Any]:
        normalized = [
            self._normalize(payload, index) for index in range(len(payload.alerts))
        ]
        self._validate_incident_links(normalized)

        alerts = [
            self.incident_service.add_alert(
                service_name=item["service_name"],
                name=item["name"],
                severity=item["severity"],
                status=item["status"],
                description=item["description"],
                incident_id=item["incident_id"],
                fired_at=item["fired_at"],
                source=self.source,
                source_event_id=item["source_event_id"],
            )
            for item in normalized
        ]
        return {
            "source": self.source,
            "received": len(alerts),
            "alerts": [
                {
                    "id": alert.id,
                    "source_event_id": alert.source_event_id,
                    "service_name": item["service_name"],
                    "incident_id": item["incident_id"],
                    "name": alert.name,
                    "status": alert.status,
                    "fired_at": alert.fired_at,
                }
                for alert, item in zip(alerts, normalized, strict=True)
            ],
        }

    def _normalize(
        self, payload: AlertmanagerWebhookRequest, index: int
    ) -> dict[str, Any]:
        alert = payload.alerts[index]
        labels = {**payload.common_labels, **alert.labels}
        annotations = {**payload.common_annotations, **alert.annotations}
        service_name = self._first(labels, "service", "service_name", "app", "job")
        if service_name is None:
            raise InvalidIngestionPayloadError(
                f"Alert at index {index} has no service, service_name, app, or job label"
            )
        name = self._first(labels, "alertname", "alert_name")
        if name is None:
            raise InvalidIngestionPayloadError(
                f"Alert at index {index} has no alertname label"
            )
        incident_id = self._first(labels, "incident_id", "incident")
        source_event_id = alert.fingerprint or self._fallback_event_id(
            labels=labels,
            starts_at=alert.starts_at.isoformat(),
        )
        return {
            "service_name": service_name,
            "incident_id": incident_id,
            "name": name,
            "severity": self._severity(labels.get("severity")),
            "status": "resolved" if alert.status == "resolved" else "active",
            "description": self._first(annotations, "description", "summary"),
            "fired_at": alert.starts_at,
            "source_event_id": source_event_id,
        }

    def _validate_incident_links(self, normalized: list[dict[str, Any]]) -> None:
        for item in normalized:
            incident_id = item["incident_id"]
            if incident_id is None:
                continue
            incident = self.incident_service.get_incident(incident_id)
            if incident is None:
                raise ResourceNotFoundError(f"Incident '{incident_id}' was not found")
            if incident.service.name != item["service_name"]:
                raise ResourceConflictError(
                    f"Incident '{incident_id}' belongs to service "
                    f"'{incident.service.name}', not '{item['service_name']}'"
                )

    @staticmethod
    def _first(values: dict[str, str], *keys: str) -> str | None:
        return next((values[key] for key in keys if values.get(key)), None)

    @staticmethod
    def _severity(value: str | None) -> str:
        normalized = (value or "warning").lower()
        aliases = {"info": "low", "warn": "warning", "page": "critical"}
        normalized = aliases.get(normalized, normalized)
        allowed = {"low", "medium", "warning", "high", "critical"}
        return normalized if normalized in allowed else "warning"

    @staticmethod
    def _fallback_event_id(*, labels: dict[str, str], starts_at: str) -> str:
        canonical = json.dumps(
            {"labels": labels, "starts_at": starts_at},
            sort_keys=True,
            separators=(",", ":"),
        )
        return f"generated-{sha256(canonical.encode('utf-8')).hexdigest()}"
