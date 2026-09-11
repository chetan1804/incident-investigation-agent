from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
from typing import Any

from fastapi.encoders import jsonable_encoder
from pydantic import ValidationError

from incident_investigation_agent.config.settings import settings
from incident_investigation_agent.exceptions import (
    InvalidIngestionPayloadError,
    ResourceConflictError,
    ResourceNotFoundError,
)
from incident_investigation_agent.models.incident_models import IngestionDelivery
from incident_investigation_agent.services.alertmanager_adapter import AlertmanagerAdapter
from incident_investigation_agent.services.github_deployment_adapter import GitHubDeploymentAdapter
from incident_investigation_agent.services.incident_service import IncidentService
from incident_investigation_agent.services.otlp_log_adapter import OtlpLogAdapter


class IngestionDeliveryService:
    """Persist delivery outcomes and execute authenticated payload replays."""

    supported_sources = {
        AlertmanagerAdapter.source,
        OtlpLogAdapter.source,
        GitHubDeploymentAdapter.source,
    }

    def __init__(self, incident_service: IncidentService):
        self.incident_service = incident_service
        self.repository = incident_service.repository

    @staticmethod
    def decode_json(body: bytes) -> dict[str, Any] | list[Any] | None:
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return value if isinstance(value, (dict, list)) else None

    def begin(
        self,
        *,
        source: str,
        body: bytes,
        payload_json: dict[str, Any] | list[Any] | None,
        source_delivery_id: str | None = None,
        event_type: str | None = None,
        request_metadata: dict[str, Any] | None = None,
        replayable: bool = False,
        replay_of_id: int | None = None,
    ) -> IngestionDelivery:
        now = datetime.now(UTC)
        self.repository.purge_expired_ingestion_payloads(now=now)
        retained_payload, payload_redacted = self._redact(payload_json)
        retention_days = settings.ingestion_audit_payload_retention_days
        payload_purged_at = now if retention_days == 0 else None
        if payload_purged_at is not None:
            retained_payload = None
        return self.repository.create_ingestion_delivery(
            source=source,
            source_delivery_id=source_delivery_id,
            event_type=event_type,
            payload_sha256=sha256(body).hexdigest(),
            payload_size_bytes=len(body),
            payload_json=retained_payload,
            payload_redacted=payload_redacted,
            payload_expires_at=now + timedelta(days=retention_days),
            payload_purged_at=payload_purged_at,
            request_metadata_json=request_metadata,
            replayable=(
                replayable
                and retained_payload is not None
                and not payload_redacted
            ),
            replay_of_id=replay_of_id,
        )

    def succeed(self, delivery: IngestionDelivery, result: dict[str, Any]) -> None:
        self.repository.finish_ingestion_delivery(
            delivery,
            status="succeeded",
            result_json=jsonable_encoder(result),
            replayable=False,
        )

    def fail(
        self,
        delivery: IngestionDelivery,
        exc: Exception,
        *,
        replayable: bool | None = None,
    ) -> None:
        self.repository.finish_ingestion_delivery(
            delivery,
            status="failed",
            error_type=type(exc).__name__,
            error_detail=str(exc) or "Request processing failed",
            replayable=replayable,
        )
        setattr(exc, "ingestion_delivery_id", delivery.delivery_id)

    def process(
        self,
        delivery: IngestionDelivery,
        payload_json: dict[str, Any] | list[Any] | None = None,
    ) -> dict[str, Any]:
        from incident_investigation_agent.api.schemas import (
            AlertmanagerWebhookRequest,
            GitHubDeploymentWebhookPayload,
            OtlpExportLogsRequest,
        )

        payload = payload_json if payload_json is not None else delivery.payload_json
        if payload is None:
            raise InvalidIngestionPayloadError("Request body must be a JSON object")
        try:
            if delivery.source == AlertmanagerAdapter.source:
                validated = AlertmanagerWebhookRequest.model_validate(payload)
                return AlertmanagerAdapter(self.incident_service).ingest(validated)
            if delivery.source == OtlpLogAdapter.source:
                validated = OtlpExportLogsRequest.model_validate(payload)
                count = OtlpLogAdapter(self.incident_service).ingest(validated)
                return {"accepted_log_records": count}
            if delivery.source == GitHubDeploymentAdapter.source:
                if delivery.event_type == "ping":
                    return {"event": "ping", "status": "ignored", "deployment": None}
                if not delivery.event_type:
                    raise InvalidIngestionPayloadError("X-GitHub-Event header is required")
                validated = GitHubDeploymentWebhookPayload.model_validate(payload)
                return GitHubDeploymentAdapter(self.incident_service).ingest(
                    event=delivery.event_type,
                    delivery_id=delivery.source_delivery_id,
                    payload=validated,
                )
        except ValidationError as exc:
            validation_details = "; ".join(
                f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
                for error in exc.errors(include_url=False, include_input=False)
            )
            raise InvalidIngestionPayloadError(
                f"Invalid {delivery.source} payload: {validation_details}"
            ) from exc
        raise InvalidIngestionPayloadError(
            f"Ingestion source '{delivery.source}' does not support replay"
        )

    def replay(self, original: IngestionDelivery) -> tuple[IngestionDelivery, dict[str, Any]]:
        if original.status != "failed":
            raise ResourceConflictError("Only failed ingestion deliveries can be replayed")
        if original.payload_redacted:
            raise ResourceConflictError(
                "This delivery cannot be replayed because sensitive fields were redacted"
            )
        if not original.replayable or original.payload_json is None:
            raise ResourceConflictError(
                "This delivery cannot be replayed because its payload was invalid or unauthenticated"
            )
        if original.source not in self.supported_sources:
            raise ResourceConflictError("This ingestion source does not support replay")

        body = json.dumps(
            original.payload_json, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        attempt = self.begin(
            source=original.source,
            body=body,
            payload_json=original.payload_json,
            source_delivery_id=original.source_delivery_id,
            event_type=original.event_type,
            request_metadata={"replay": True},
            replayable=True,
            replay_of_id=original.id,
        )
        try:
            result = self.process(attempt)
        except Exception as exc:
            self.fail(
                attempt,
                exc,
                replayable=not isinstance(exc, InvalidIngestionPayloadError),
            )
            raise
        self.succeed(attempt, result)
        return attempt, result

    def get(self, delivery_id: str) -> IngestionDelivery:
        self.purge_expired()
        delivery = self.repository.get_ingestion_delivery(delivery_id)
        if delivery is None:
            raise ResourceNotFoundError(
                f"Ingestion delivery '{delivery_id}' was not found"
            )
        return delivery

    def list(
        self,
        *,
        source: str | None = None,
        status: str | None = None,
        limit: int = 50,
    ) -> list[IngestionDelivery]:
        self.purge_expired()
        return self.repository.list_ingestion_deliveries(
            source=source, status=status, limit=limit
        )

    def purge_expired(self) -> int:
        return self.repository.purge_expired_ingestion_payloads(now=datetime.now(UTC))

    @staticmethod
    def _redact(
        payload: dict[str, Any] | list[Any] | None,
    ) -> tuple[dict[str, Any] | list[Any] | None, bool]:
        sensitive_fields = {
            field.strip().casefold()
            for field in settings.ingestion_audit_sensitive_fields.split(",")
            if field.strip()
        }

        def visit(value: Any) -> tuple[Any, bool]:
            if isinstance(value, dict):
                redacted: dict[str, Any] = {}
                changed = False
                for key, item in value.items():
                    if key.casefold() in sensitive_fields:
                        redacted[key] = "[REDACTED]"
                        changed = True
                    else:
                        redacted[key], child_changed = visit(item)
                        changed = changed or child_changed
                return redacted, changed
            if isinstance(value, list):
                redacted_items = []
                changed = False
                for item in value:
                    redacted_item, child_changed = visit(item)
                    redacted_items.append(redacted_item)
                    changed = changed or child_changed
                return redacted_items, changed
            return value, False

        return visit(payload)
