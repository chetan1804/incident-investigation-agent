from __future__ import annotations

from hashlib import sha256
import json
from typing import Any

from fastapi.encoders import jsonable_encoder
from pydantic import ValidationError

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
        return self.repository.create_ingestion_delivery(
            source=source,
            source_delivery_id=source_delivery_id,
            event_type=event_type,
            payload_sha256=sha256(body).hexdigest(),
            payload_size_bytes=len(body),
            payload_json=payload_json,
            request_metadata_json=request_metadata,
            replayable=replayable,
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

    def process(self, delivery: IngestionDelivery) -> dict[str, Any]:
        from incident_investigation_agent.api.schemas import (
            AlertmanagerWebhookRequest,
            GitHubDeploymentWebhookPayload,
            OtlpExportLogsRequest,
        )

        if delivery.payload_json is None:
            raise InvalidIngestionPayloadError("Request body must be a JSON object")
        try:
            if delivery.source == AlertmanagerAdapter.source:
                payload = AlertmanagerWebhookRequest.model_validate(delivery.payload_json)
                return AlertmanagerAdapter(self.incident_service).ingest(payload)
            if delivery.source == OtlpLogAdapter.source:
                payload = OtlpExportLogsRequest.model_validate(delivery.payload_json)
                count = OtlpLogAdapter(self.incident_service).ingest(payload)
                return {"accepted_log_records": count}
            if delivery.source == GitHubDeploymentAdapter.source:
                if delivery.event_type == "ping":
                    return {"event": "ping", "status": "ignored", "deployment": None}
                if not delivery.event_type:
                    raise InvalidIngestionPayloadError("X-GitHub-Event header is required")
                payload = GitHubDeploymentWebhookPayload.model_validate(delivery.payload_json)
                return GitHubDeploymentAdapter(self.incident_service).ingest(
                    event=delivery.event_type,
                    delivery_id=delivery.source_delivery_id,
                    payload=payload,
                )
        except ValidationError as exc:
            raise InvalidIngestionPayloadError(
                f"Invalid {delivery.source} payload: {exc}"
            ) from exc
        raise InvalidIngestionPayloadError(
            f"Ingestion source '{delivery.source}' does not support replay"
        )

    def replay(self, original: IngestionDelivery) -> tuple[IngestionDelivery, dict[str, Any]]:
        if original.status != "failed":
            raise ResourceConflictError("Only failed ingestion deliveries can be replayed")
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
        delivery = self.repository.get_ingestion_delivery(delivery_id)
        if delivery is None:
            raise ResourceNotFoundError(
                f"Ingestion delivery '{delivery_id}' was not found"
            )
        return delivery
