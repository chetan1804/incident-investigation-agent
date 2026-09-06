from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from incident_investigation_agent.models.incident_models import (
    AIAnalysisFeedback,
    AIAnalysisRecord,
    AIRegressionRun,
    Alert,
    Deployment,
    Incident,
    LogEntry,
)
from incident_investigation_agent.repositories.incident_repository import IncidentRepository


class IncidentService:
    """Application service for the incident domain logic."""

    def __init__(self, repository: IncidentRepository):
        self.repository = repository

    def create_incident(
        self,
        *,
        service_name: str,
        title: str,
        summary: str,
        incident_id: str,
        severity: str = "medium",
        status: str = "open",
        metadata_json: dict[str, Any] | None = None,
        started_at: datetime | None = None,
    ) -> Incident:
        return self.repository.create_incident(
            service_name=service_name,
            title=title,
            summary=summary,
            incident_id=incident_id,
            severity=severity,
            status=status,
            metadata_json=metadata_json,
            started_at=started_at,
        )

    def get_incident(self, incident_id: str) -> Incident | None:
        return self.repository.get_incident_by_id(incident_id)

    def list_incidents(self, limit: int = 50) -> list[Incident]:
        return self.repository.list_incidents(limit=limit)

    def get_logs(self, incident_id: str) -> list[LogEntry]:
        return self.repository.get_logs_for_incident(incident_id)

    def get_alerts(self, incident_id: str) -> list[Alert]:
        return self.repository.get_related_alerts(incident_id)

    def get_deployments(self, service_name: str) -> list[Deployment]:
        return self.repository.get_deployments_for_service(service_name)

    def save_ai_analysis(
        self,
        *,
        incident_id: str,
        model: str,
        prompt_version: str,
        prompt_sha256: str,
        correlation_window: dict[str, Any],
        ranked_signal_ids: list[str],
        hypotheses: list[dict[str, Any]],
        remediation_suggestions: list[dict[str, Any]],
    ) -> AIAnalysisRecord:
        return self.repository.create_ai_analysis(
            incident_id=incident_id,
            model=model,
            prompt_version=prompt_version,
            prompt_sha256=prompt_sha256,
            correlation_window_json=correlation_window,
            ranked_signal_ids_json=ranked_signal_ids,
            hypotheses_json=hypotheses,
            remediation_suggestions_json=remediation_suggestions,
        )

    def get_ai_analysis(self, analysis_id: str) -> AIAnalysisRecord | None:
        return self.repository.get_ai_analysis(analysis_id)

    def list_ai_analyses(self, incident_id: str) -> list[AIAnalysisRecord]:
        return self.repository.list_ai_analyses(incident_id)

    def get_ai_evaluation_metrics(
        self,
        *,
        prompt_version: str | None = None,
        model: str | None = None,
    ) -> dict[str, Any]:
        records = self.repository.list_ai_analyses_for_evaluation(
            prompt_version=prompt_version,
            model=model,
        )
        metrics = self._aggregate_evaluation_metrics(records)
        metrics["filters"] = {"prompt_version": prompt_version, "model": model}
        return metrics

    def list_ai_regression_runs(self, limit: int = 50) -> list[AIRegressionRun]:
        return self.repository.list_ai_regression_runs(limit=limit)

    def add_ai_analysis_feedback(
        self,
        *,
        analysis_id: str,
        hypothesis_index: int,
        rating: str,
        operator_name: str,
        comment: str | None = None,
    ) -> AIAnalysisFeedback:
        return self.repository.create_ai_analysis_feedback(
            analysis_id=analysis_id,
            hypothesis_index=hypothesis_index,
            rating=rating,
            operator_name=operator_name,
            comment=comment,
        )

    @staticmethod
    def _aggregate_evaluation_metrics(records: list[AIAnalysisRecord]) -> dict[str, Any]:
        rating_counts = {
            "accurate": 0,
            "partially_accurate": 0,
            "inaccurate": 0,
            "uncertain": 0,
        }
        assessed_hypotheses: set[tuple[int, int]] = set()
        analyses_with_feedback = 0

        for record in records:
            if record.feedback:
                analyses_with_feedback += 1
            for feedback in record.feedback:
                if feedback.rating in rating_counts:
                    rating_counts[feedback.rating] += 1
                assessed_hypotheses.add((record.id, feedback.hypothesis_index))

        total_feedback = sum(rating_counts.values())
        decided_feedback = total_feedback - rating_counts["uncertain"]
        weighted_score = (
            rating_counts["accurate"] + 0.5 * rating_counts["partially_accurate"]
        )
        total_hypotheses = sum(len(record.hypotheses_json) for record in records)

        return {
            "filters": {"prompt_version": None, "model": None},
            "total_analyses": len(records),
            "analyses_with_feedback": analyses_with_feedback,
            "total_hypotheses": total_hypotheses,
            "hypotheses_with_feedback": len(assessed_hypotheses),
            "feedback_coverage": (
                round(len(assessed_hypotheses) / total_hypotheses, 4)
                if total_hypotheses
                else 0.0
            ),
            "total_feedback": total_feedback,
            "decided_feedback": decided_feedback,
            "rating_counts": rating_counts,
            "accuracy_score": (
                round(weighted_score / decided_feedback, 4) if decided_feedback else None
            ),
        }

    def investigate(
        self,
        incident_id: str,
        *,
        lookback_minutes: int = 60,
        lookahead_minutes: int = 30,
    ) -> dict[str, Any] | None:
        incident = self.get_incident(incident_id)
        if incident is None:
            return None

        started_at = self._as_utc(incident.started_at)
        window_start = started_at - timedelta(minutes=lookback_minutes)
        window_end = started_at + timedelta(minutes=lookahead_minutes)
        logs = self.repository.get_logs_for_incident(
            incident_id, window_start=window_start, window_end=window_end
        )
        alerts = self.repository.get_related_alerts(
            incident_id, window_start=window_start, window_end=window_end
        )
        deployments = self.repository.get_deployments_for_service(
            incident.service.name,
            window_start=window_start,
            window_end=started_at,
        )

        signals = [f"alert:{alert.name} ({alert.severity})" for alert in alerts]
        signals.extend(
            f"log:{log.level} {log.message}" for log in logs if self._is_error_log(log)
        )
        if deployments:
            signals.append(f"deployment:{deployments[0].deployment_id} ({deployments[0].version})")

        ranked_signals = self._rank_signals(
            logs=logs,
            alerts=alerts,
            deployments=deployments,
            started_at=started_at,
            lookback_minutes=lookback_minutes,
            lookahead_minutes=lookahead_minutes,
        )

        return {
            "incident_id": incident.incident_id,
            "summary": incident.summary,
            "severity": incident.severity.value,
            "status": incident.status.value,
            "scoring_method": "deterministic_v1",
            "correlation_window": {
                "started_at": started_at.isoformat(),
                "window_start": window_start.isoformat(),
                "window_end": window_end.isoformat(),
                "lookback_minutes": lookback_minutes,
                "lookahead_minutes": lookahead_minutes,
            },
            "evidence": {
                "logs": len(logs),
                "alerts": len(alerts),
                "deployments": len(deployments),
            },
            "signals": signals,
            "ranked_signals": ranked_signals,
            "root_cause_candidates": self._build_root_cause_candidates(ranked_signals),
            "recent_deployment": (
                {
                    "deployment_id": deployments[0].deployment_id,
                    "version": deployments[0].version,
                    "deployed_at": deployments[0].deployed_at.isoformat(),
                }
                if deployments
                else None
            ),
        }

    def _rank_signals(
        self,
        *,
        logs: list[LogEntry],
        alerts: list[Alert],
        deployments: list[Deployment],
        started_at: datetime,
        lookback_minutes: int,
        lookahead_minutes: int,
    ) -> list[dict[str, Any]]:
        ranked: list[dict[str, Any]] = []

        alert_weights = {"critical": 1.0, "high": 0.9, "warning": 0.7, "medium": 0.65, "low": 0.4}
        for alert in alerts:
            proximity, timing = self._proximity(
                alert.fired_at, started_at, lookback_minutes, lookahead_minutes
            )
            severity_weight = alert_weights.get(alert.severity.lower(), 0.55)
            ranked.append(
                {
                    "signal_id": f"alert:{alert.id}",
                    "kind": "alert",
                    "description": f"{alert.name} ({alert.severity})",
                    "observed_at": self._as_utc(alert.fired_at).isoformat(),
                    "confidence": round(0.65 * severity_weight + 0.35 * proximity, 2),
                    "reasoning": f"{alert.severity.title()} alert observed {timing} incident start.",
                }
            )

        log_weights = {"ERROR": 0.8, "CRITICAL": 0.95, "FATAL": 1.0}
        for log in logs:
            level = log.level.upper()
            if level not in log_weights:
                continue
            proximity, timing = self._proximity(
                log.timestamp, started_at, lookback_minutes, lookahead_minutes
            )
            ranked.append(
                {
                    "signal_id": f"log:{log.id}",
                    "kind": "log",
                    "description": f"{level} {log.message}",
                    "observed_at": self._as_utc(log.timestamp).isoformat(),
                    "confidence": round(0.65 * log_weights[level] + 0.35 * proximity, 2),
                    "reasoning": f"{level} log observed {timing} incident start.",
                }
            )

        for deployment in deployments:
            proximity, timing = self._proximity(
                deployment.deployed_at, started_at, lookback_minutes, lookahead_minutes
            )
            ranked.append(
                {
                    "signal_id": f"deployment:{deployment.deployment_id}",
                    "kind": "deployment",
                    "description": f"{deployment.deployment_id} ({deployment.version})",
                    "observed_at": self._as_utc(deployment.deployed_at).isoformat(),
                    "confidence": round(0.6 + 0.35 * proximity, 2),
                    "reasoning": f"Deployment completed {timing} incident start.",
                }
            )

        return sorted(ranked, key=lambda signal: (-signal["confidence"], signal["observed_at"]))

    @staticmethod
    def _build_root_cause_candidates(ranked_signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
        templates = {
            "deployment": "A recent deployment may have introduced the incident",
            "log": "The failure recorded in application logs may be a direct contributor",
            "alert": "The condition represented by the alert may be contributing to the incident",
        }
        candidates: list[dict[str, Any]] = []
        seen_kinds: set[str] = set()
        for signal in ranked_signals:
            kind = signal["kind"]
            if kind in seen_kinds:
                continue
            seen_kinds.add(kind)
            candidates.append(
                {
                    "hypothesis": f"{templates[kind]}: {signal['description']}",
                    "confidence": signal["confidence"],
                    "supporting_signals": [signal["signal_id"]],
                }
            )
        return candidates

    @classmethod
    def _proximity(
        cls,
        observed_at: datetime,
        started_at: datetime,
        lookback_minutes: int,
        lookahead_minutes: int,
    ) -> tuple[float, str]:
        observed_at = cls._as_utc(observed_at)
        delta_minutes = (observed_at - started_at).total_seconds() / 60
        direction = "after" if delta_minutes > 0 else "before"
        span = lookahead_minutes if delta_minutes > 0 else lookback_minutes
        proximity = max(0.0, 1 - abs(delta_minutes) / max(span, 1))
        return proximity, f"{abs(delta_minutes):.1f} minutes {direction}"

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @staticmethod
    def _is_error_log(log: LogEntry) -> bool:
        return log.level.upper() in {"ERROR", "CRITICAL", "FATAL"}

    def add_log(
        self,
        *,
        service_name: str,
        message: str,
        level: str = "INFO",
        incident_id: str | None = None,
        trace_id: str | None = None,
        metadata_json: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> LogEntry:
        return self.repository.create_log(
            service_name=service_name,
            message=message,
            level=level,
            incident_id=incident_id,
            trace_id=trace_id,
            metadata_json=metadata_json,
            timestamp=timestamp,
        )

    def add_alert(
        self,
        *,
        service_name: str,
        name: str,
        severity: str = "warning",
        description: str | None = None,
        incident_id: str | None = None,
        fired_at: datetime | None = None,
    ) -> Alert:
        return self.repository.create_alert(
            service_name=service_name,
            name=name,
            severity=severity,
            description=description,
            incident_id=incident_id,
            fired_at=fired_at,
        )

    def add_deployment(
        self,
        *,
        service_name: str,
        deployment_id: str,
        version: str,
        environment: str = "production",
        status: str = "success",
        notes: str | None = None,
        metadata_json: dict[str, Any] | None = None,
        deployed_at: datetime | None = None,
    ) -> Deployment:
        return self.repository.create_deployment(
            service_name=service_name,
            deployment_id=deployment_id,
            version=version,
            environment=environment,
            status=status,
            notes=notes,
            metadata_json=metadata_json,
            deployed_at=deployed_at,
        )
