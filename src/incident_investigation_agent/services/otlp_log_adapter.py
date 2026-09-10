from __future__ import annotations

from datetime import UTC, datetime, timedelta
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
    from incident_investigation_agent.api.schemas import (
        OtlpExportLogsRequest,
        OtlpKeyValue,
    )


class OtlpLogAdapter:
    """Normalize OTLP/HTTP JSON log exports into log evidence."""

    source = "opentelemetry-otlp"
    maximum_records = 10_000

    def __init__(self, incident_service: IncidentService):
        self.incident_service = incident_service

    def ingest(self, payload: OtlpExportLogsRequest) -> int:
        normalized: list[dict[str, Any]] = []
        for resource_logs in payload.resource_logs:
            resource_attributes = self._attributes(resource_logs.resource.attributes)
            for scope_logs in resource_logs.scope_logs:
                for record in scope_logs.log_records:
                    normalized.append(
                        self._normalize(
                            record=record,
                            resource_attributes=resource_attributes,
                            scope=scope_logs.scope,
                            index=len(normalized),
                        )
                    )
                    if len(normalized) > self.maximum_records:
                        raise InvalidIngestionPayloadError(
                            f"OTLP export exceeds the {self.maximum_records} log record limit"
                        )

        self._validate_incident_links(normalized)
        for item in normalized:
            self.incident_service.add_log(**item)
        return len(normalized)

    def _normalize(
        self,
        *,
        record: Any,
        resource_attributes: dict[str, Any],
        scope: dict[str, Any] | None,
        index: int,
    ) -> dict[str, Any]:
        log_attributes = self._attributes(record.attributes)
        service_name = self._first(
            log_attributes,
            resource_attributes,
            keys=("service.name", "service_name", "service"),
        )
        if not isinstance(service_name, str) or not service_name:
            raise InvalidIngestionPayloadError(
                f"OTLP log record at index {index} has no service.name resource attribute"
            )
        incident_id = self._first(
            log_attributes,
            resource_attributes,
            keys=("incident.id", "incident_id"),
        )
        if incident_id is not None and not isinstance(incident_id, str):
            raise InvalidIngestionPayloadError(
                f"OTLP log record at index {index} has a non-string incident identifier"
            )

        trace_id = record.trace_id or None
        span_id = record.span_id or None
        self._validate_hex_id(trace_id, expected_length=32, field="traceId", index=index)
        self._validate_hex_id(span_id, expected_length=16, field="spanId", index=index)
        body = self._any_value(record.body) if record.body is not None else None
        message = self._message(body, record.event_name)
        timestamp = self._timestamp(
            record.time_unix_nano or record.observed_time_unix_nano,
            index=index,
        )
        metadata = {
            "otel": {
                "resource_attributes": resource_attributes,
                "log_attributes": log_attributes,
                "scope": scope,
                "span_id": span_id,
                "flags": record.flags,
                "event_name": record.event_name,
                "severity_number": record.severity_number,
                "severity_text": record.severity_text,
            }
        }
        event_identity = {
            "service_name": service_name,
            "time_unix_nano": str(
                record.time_unix_nano or record.observed_time_unix_nano or "0"
            ),
            "trace_id": trace_id,
            "span_id": span_id,
            "body": body,
            "severity_number": record.severity_number,
            "severity_text": record.severity_text,
            "event_name": record.event_name,
            "resource_attributes": resource_attributes,
            "attributes": log_attributes,
        }
        return {
            "service_name": service_name,
            "message": message,
            "level": self._level(record.severity_number, record.severity_text),
            "incident_id": incident_id,
            "trace_id": trace_id,
            "metadata_json": metadata,
            "timestamp": timestamp,
            "source": self.source,
            "source_event_id": self._event_id(event_identity),
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

    @classmethod
    def _attributes(cls, attributes: list[OtlpKeyValue]) -> dict[str, Any]:
        return {item.key: cls._any_value(item.value) for item in attributes}

    @classmethod
    def _any_value(cls, value: dict[str, Any] | None) -> Any:
        if not value:
            return None
        scalar_fields = (
            "stringValue",
            "boolValue",
            "intValue",
            "doubleValue",
            "bytesValue",
        )
        for field in scalar_fields:
            if field in value:
                raw = value[field]
                if field == "intValue":
                    try:
                        return int(raw)
                    except (TypeError, ValueError):
                        return raw
                return raw
        if "arrayValue" in value:
            return [
                cls._any_value(item)
                for item in value["arrayValue"].get("values", [])
            ]
        if "kvlistValue" in value:
            return {
                item["key"]: cls._any_value(item.get("value"))
                for item in value["kvlistValue"].get("values", [])
                if item.get("key")
            }
        return None

    @staticmethod
    def _first(
        primary: dict[str, Any],
        secondary: dict[str, Any],
        *,
        keys: tuple[str, ...],
    ) -> Any:
        for values in (primary, secondary):
            for key in keys:
                if key in values and values[key] not in (None, ""):
                    return values[key]
        return None

    @staticmethod
    def _message(body: Any, event_name: str | None) -> str:
        if isinstance(body, str) and body:
            return body
        if body is not None:
            return json.dumps(body, sort_keys=True, separators=(",", ":"))
        return event_name or "(empty OTLP log body)"

    @staticmethod
    def _level(severity_number: int, severity_text: str | None) -> str:
        if severity_number >= 21:
            return "FATAL"
        if severity_number >= 17:
            return "ERROR"
        if severity_number >= 13:
            return "WARN"
        if severity_number >= 9:
            return "INFO"
        if severity_number >= 5:
            return "DEBUG"
        if severity_number >= 1:
            return "TRACE"
        normalized = (severity_text or "INFO").upper()
        aliases = {
            "WARNING": "WARN",
            "ERR": "ERROR",
            "CRIT": "CRITICAL",
            "PANIC": "FATAL",
        }
        return aliases.get(normalized, normalized)

    @staticmethod
    def _timestamp(value: int | str | None, *, index: int) -> datetime | None:
        if value in (None, "", 0, "0"):
            return None
        try:
            nanoseconds = int(value)
            if nanoseconds < 0:
                raise ValueError
            seconds, remainder = divmod(nanoseconds, 1_000_000_000)
            return datetime.fromtimestamp(seconds, tz=UTC) + timedelta(
                microseconds=remainder // 1000
            )
        except (OverflowError, TypeError, ValueError) as exc:
            raise InvalidIngestionPayloadError(
                f"OTLP log record at index {index} has an invalid timestamp"
            ) from exc

    @staticmethod
    def _validate_hex_id(
        value: str | None, *, expected_length: int, field: str, index: int
    ) -> None:
        if value is None:
            return
        try:
            valid = len(value) == expected_length and int(value, 16) >= 0
        except ValueError:
            valid = False
        if not valid:
            raise InvalidIngestionPayloadError(
                f"OTLP log record at index {index} has an invalid {field}"
            )

    @staticmethod
    def _event_id(identity: dict[str, Any]) -> str:
        canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
        return f"log-{sha256(canonical.encode('utf-8')).hexdigest()}"
