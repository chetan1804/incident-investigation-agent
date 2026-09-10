from __future__ import annotations

from hashlib import sha256
import hmac
import json
from typing import TYPE_CHECKING, Any

from incident_investigation_agent.exceptions import (
    IngestionAuthenticationError,
    IngestionUnavailableError,
    InvalidIngestionPayloadError,
)
from incident_investigation_agent.services.incident_service import IncidentService

if TYPE_CHECKING:
    from incident_investigation_agent.api.schemas import (
        GitHubDeploymentWebhookPayload,
    )


class GitHubDeploymentAdapter:
    """Verify and normalize GitHub deployment webhook events."""

    source = "github-deployments"

    def __init__(self, incident_service: IncidentService):
        self.incident_service = incident_service

    @staticmethod
    def verify_signature(
        *, body: bytes, signature: str | None, secret: str | None
    ) -> None:
        if not secret:
            raise IngestionUnavailableError(
                "GitHub webhook ingestion requires GITHUB_WEBHOOK_SECRET"
            )
        if not signature or not signature.startswith("sha256="):
            raise IngestionAuthenticationError(
                "GitHub webhook signature is missing or invalid"
            )
        expected = "sha256=" + hmac.new(
            secret.encode("utf-8"), body, sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise IngestionAuthenticationError("GitHub webhook signature did not match")

    def ingest(
        self,
        *,
        event: str,
        delivery_id: str | None,
        payload: GitHubDeploymentWebhookPayload,
    ) -> dict[str, Any]:
        if event not in {"deployment", "deployment_status"}:
            raise InvalidIngestionPayloadError(
                f"Unsupported GitHub webhook event '{event}'"
            )
        if event == "deployment_status" and payload.deployment_status is None:
            raise InvalidIngestionPayloadError(
                "GitHub deployment_status event has no deployment_status object"
            )

        deployment = payload.deployment
        deployment_payload = self._deployment_payload(deployment.payload)
        service_name = deployment_payload.get("service_name") or deployment_payload.get(
            "service"
        )
        if not isinstance(service_name, str) or not service_name:
            service_name = payload.repository.name

        github_status = payload.deployment_status
        status = github_status.state if github_status else "created"
        environment = (
            (github_status.environment if github_status else None)
            or deployment.environment
            or "production"
        )
        version = (deployment.sha or deployment.ref or "unknown")[:64]
        notes = (
            (github_status.description if github_status else None)
            or deployment.description
        )
        source_event_id = self._source_event_id(
            payload.repository.full_name, deployment.id
        )
        metadata = {
            "github": {
                "event": event,
                "delivery_id": delivery_id,
                "repository_id": payload.repository.id,
                "repository": payload.repository.full_name,
                "deployment_id": deployment.id,
                "deployment_status_id": github_status.id if github_status else None,
                "ref": deployment.ref,
                "sha": deployment.sha,
                "task": deployment.task,
                "actor": payload.sender.login if payload.sender else None,
                "log_url": github_status.log_url if github_status else None,
                "environment_url": (
                    github_status.environment_url if github_status else None
                ),
                "payload": deployment_payload,
            }
        }
        record = self.incident_service.add_deployment(
            service_name=service_name,
            deployment_id=f"GH-{deployment.id}",
            version=version,
            environment=environment,
            status=status,
            notes=notes,
            metadata_json=metadata,
            deployed_at=deployment.created_at,
            source=self.source,
            source_event_id=source_event_id,
        )
        return {
            "event": event,
            "status": "accepted",
            "deployment": {
                "deployment_id": record.deployment_id,
                "service_name": service_name,
                "version": record.version,
                "environment": record.environment,
                "status": record.status,
                "source": record.source,
                "source_event_id": record.source_event_id,
            },
        }

    @staticmethod
    def _deployment_payload(value: dict[str, Any] | str | None) -> dict[str, Any]:
        if isinstance(value, dict):
            return value
        if isinstance(value, str) and value:
            try:
                decoded = json.loads(value)
            except json.JSONDecodeError:
                return {}
            return decoded if isinstance(decoded, dict) else {}
        return {}

    @staticmethod
    def _source_event_id(repository: str, deployment_id: int) -> str:
        value = f"{repository}:{deployment_id}"
        if len(value) <= 255:
            return value
        return f"deployment-{sha256(value.encode('utf-8')).hexdigest()}"
