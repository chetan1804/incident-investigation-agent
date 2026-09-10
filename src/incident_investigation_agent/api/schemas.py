from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

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
    resolved_at: datetime | None = None
    root_cause: str | None = None
    resolution_summary: str | None = None
    resolution_confirmed_by: str | None = None


class IncidentResolutionCreateRequest(BaseModel):
    root_cause: str = Field(min_length=1, max_length=4000)
    resolution_summary: str = Field(min_length=1, max_length=4000)
    resolution_confirmed_by: str = Field(min_length=1, max_length=255)
    resolved_at: datetime | None = None


class IncidentResolutionResponse(BaseModel):
    incident_id: str
    status: IncidentStatus
    root_cause: str
    resolution_summary: str
    resolution_confirmed_by: str
    resolved_at: datetime


class EvidenceCounts(BaseModel):
    logs: int
    alerts: int
    deployments: int
    metric_anomalies: int
    dependency_logs: int
    dependency_alerts: int
    dependency_deployments: int
    dependency_metric_anomalies: int
    historical_incidents: int
    trace_paths: int
    trace_logs: int


class DependencyServiceResponse(BaseModel):
    service_name: str
    criticality: str


class DependencyContextResponse(BaseModel):
    upstream: list[DependencyServiceResponse]
    downstream: list[DependencyServiceResponse]


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


class HistoricalIncidentResponse(BaseModel):
    incident_id: str
    title: str
    service_name: str
    severity: IncidentSeverity
    resolved_at: datetime
    root_cause: str
    resolution_summary: str
    resolution_confirmed_by: str
    similarity_score: float = Field(ge=0, le=1)
    matching_terms: list[str]


class TraceLogResponse(BaseModel):
    log_id: int
    service_name: str
    timestamp: datetime
    level: str
    message: str


class TracePathResponse(BaseModel):
    trace_id: str
    services: list[str]
    started_at: datetime
    ended_at: datetime
    log_count: int
    error_count: int
    confidence: float = Field(ge=0, le=1)
    entries_truncated: bool
    entries: list[TraceLogResponse]


class InvestigationResponse(BaseModel):
    incident_id: str
    summary: str
    severity: IncidentSeverity
    status: IncidentStatus
    scoring_method: str
    correlation_window: CorrelationWindowResponse
    evidence: EvidenceCounts
    dependencies: DependencyContextResponse
    signals: list[str]
    ranked_signals: list[RankedSignalResponse]
    historical_incidents: list[HistoricalIncidentResponse]
    trace_paths: list[TracePathResponse]
    root_cause_candidates: list[RootCauseCandidateResponse]
    recent_deployment: RecentDeploymentResponse | None


class AIHypothesisResponse(BaseModel):
    hypothesis: str
    reasoning: str
    confidence: float = Field(ge=0, le=1)
    supporting_signals: list[str]


class RemediationSuggestionResponse(BaseModel):
    action: str
    rationale: str
    priority: str
    supporting_signals: list[str]


class AIAnalysisResponse(BaseModel):
    analysis_id: str
    incident_id: str
    model: str
    prompt_version: str
    prompt_sha256: str
    correlation_window: CorrelationWindowResponse
    ranked_signal_ids: list[str]
    hypotheses: list[AIHypothesisResponse]
    remediation_suggestions: list[RemediationSuggestionResponse]
    feedback: list["AIAnalysisFeedbackResponse"]
    created_at: datetime


class AIAnalysisFeedbackCreateRequest(BaseModel):
    hypothesis_index: int = Field(ge=0)
    rating: Literal["accurate", "partially_accurate", "inaccurate", "uncertain"]
    operator_name: str = Field(min_length=1, max_length=255)
    comment: str | None = Field(default=None, max_length=2000)


class AIAnalysisFeedbackResponse(BaseModel):
    feedback_id: str
    analysis_id: str
    hypothesis_index: int
    rating: str
    operator_name: str
    comment: str | None
    created_at: datetime


class AIEvaluationFiltersResponse(BaseModel):
    prompt_version: str | None
    model: str | None


class AIRatingCountsResponse(BaseModel):
    accurate: int
    partially_accurate: int
    inaccurate: int
    uncertain: int


class AIEvaluationMetricsResponse(BaseModel):
    filters: AIEvaluationFiltersResponse
    total_analyses: int
    analyses_with_feedback: int
    total_hypotheses: int
    hypotheses_with_feedback: int
    feedback_coverage: float = Field(ge=0, le=1)
    total_feedback: int
    decided_feedback: int
    rating_counts: AIRatingCountsResponse
    accuracy_score: float | None = Field(default=None, ge=0, le=1)


class AIRegressionOutputResponse(BaseModel):
    hypotheses: list[AIHypothesisResponse]
    remediation_suggestions: list[RemediationSuggestionResponse]


class AIRegressionCaseResultResponse(BaseModel):
    case_id: str
    passed: bool
    failures: list[str]
    hypothesis_count: int
    remediation_count: int
    cited_signal_ids: list[str]
    output: AIRegressionOutputResponse | None


class AIRegressionRunResponse(BaseModel):
    run_id: str
    dataset_version: str
    model: str
    prompt_version: str
    prompt_sha256: str
    passed: bool
    total_cases: int
    passed_cases: int
    results: list[AIRegressionCaseResultResponse]
    created_at: datetime


class AIRegressionComparisonResponse(BaseModel):
    candidate_run_id: str
    baseline_run_id: str
    dataset_version: str
    candidate_pass_rate: float = Field(ge=0, le=1)
    baseline_pass_rate: float = Field(ge=0, le=1)
    pass_rate_delta: float = Field(ge=-1, le=1)
    regressed_case_ids: list[str]
    improved_case_ids: list[str]
    unchanged_failed_case_ids: list[str]


class AIRegressionQualityGateRequest(BaseModel):
    baseline_run_id: str = Field(min_length=1, max_length=64)
    minimum_pass_rate: float = Field(default=1.0, ge=0, le=1)
    maximum_pass_rate_drop: float = Field(default=0.0, ge=0, le=1)
    maximum_regressed_cases: int = Field(default=0, ge=0)


class AIRegressionQualityGateThresholdsResponse(BaseModel):
    minimum_pass_rate: float
    maximum_pass_rate_drop: float
    maximum_regressed_cases: int


class AIRegressionQualityGateResponse(BaseModel):
    passed: bool
    failures: list[str]
    thresholds: AIRegressionQualityGateThresholdsResponse
    comparison: AIRegressionComparisonResponse


class LogCreateRequest(BaseModel):
    service_name: str = Field(min_length=1, max_length=255)
    message: str = Field(min_length=1)
    level: str = Field(default="INFO", min_length=1, max_length=20)
    incident_id: str | None = Field(default=None, max_length=64)
    trace_id: str | None = Field(default=None, max_length=128)
    metadata_json: dict[str, Any] | None = None
    timestamp: datetime | None = None


class OtlpKeyValue(BaseModel):
    model_config = ConfigDict(extra="ignore")

    key: str = Field(min_length=1)
    value: dict[str, Any] = Field(default_factory=dict)


class OtlpResource(BaseModel):
    model_config = ConfigDict(extra="ignore")

    attributes: list[OtlpKeyValue] = Field(default_factory=list)


class OtlpLogRecord(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    time_unix_nano: int | str | None = Field(default=None, alias="timeUnixNano")
    observed_time_unix_nano: int | str | None = Field(
        default=None, alias="observedTimeUnixNano"
    )
    severity_number: int = Field(default=0, alias="severityNumber", ge=0, le=24)
    severity_text: str | None = Field(default=None, alias="severityText")
    body: dict[str, Any] | None = None
    attributes: list[OtlpKeyValue] = Field(default_factory=list)
    trace_id: str | None = Field(default=None, alias="traceId", max_length=32)
    span_id: str | None = Field(default=None, alias="spanId", max_length=16)
    flags: int | None = Field(default=None, ge=0)
    event_name: str | None = Field(default=None, alias="eventName")


class OtlpScopeLogs(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    scope: dict[str, Any] | None = None
    log_records: list[OtlpLogRecord] = Field(
        default_factory=list, alias="logRecords", max_length=10000
    )


class OtlpResourceLogs(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    resource: OtlpResource = Field(default_factory=OtlpResource)
    scope_logs: list[OtlpScopeLogs] = Field(
        default_factory=list, alias="scopeLogs", max_length=1000
    )


class OtlpExportLogsRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    resource_logs: list[OtlpResourceLogs] = Field(
        default_factory=list, alias="resourceLogs", max_length=1000
    )


class OtlpExportLogsResponse(BaseModel):
    pass


class AlertCreateRequest(BaseModel):
    service_name: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    severity: str = Field(default="warning", min_length=1, max_length=32)
    description: str | None = None
    incident_id: str | None = Field(default=None, max_length=64)
    fired_at: datetime | None = None


class AlertmanagerAlertPayload(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    status: Literal["firing", "resolved"] = "firing"
    labels: dict[str, str]
    annotations: dict[str, str] = Field(default_factory=dict)
    starts_at: datetime = Field(alias="startsAt")
    ends_at: datetime | None = Field(default=None, alias="endsAt")
    generator_url: str | None = Field(default=None, alias="generatorURL")
    fingerprint: str | None = Field(default=None, min_length=1, max_length=255)


class AlertmanagerWebhookRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    version: str | None = None
    status: Literal["firing", "resolved"] | None = None
    receiver: str | None = None
    group_labels: dict[str, str] = Field(default_factory=dict, alias="groupLabels")
    common_labels: dict[str, str] = Field(default_factory=dict, alias="commonLabels")
    common_annotations: dict[str, str] = Field(
        default_factory=dict, alias="commonAnnotations"
    )
    external_url: str | None = Field(default=None, alias="externalURL")
    alerts: list[AlertmanagerAlertPayload] = Field(min_length=1, max_length=1000)


class IngestedAlertResponse(BaseModel):
    id: int
    source_event_id: str
    service_name: str
    incident_id: str | None
    name: str
    status: str
    fired_at: datetime


class AlertmanagerIngestionResponse(BaseModel):
    source: str
    received: int
    alerts: list[IngestedAlertResponse]


class MetricAnomalyCreateRequest(BaseModel):
    service_name: str = Field(min_length=1, max_length=255)
    metric_name: str = Field(min_length=1, max_length=255)
    observed_value: float = Field(allow_inf_nan=False)
    baseline_value: float = Field(allow_inf_nan=False)
    unit: str | None = Field(default=None, max_length=64)
    severity: Literal["low", "medium", "warning", "high", "critical"] = "warning"
    incident_id: str | None = Field(default=None, max_length=64)
    description: str | None = Field(default=None, max_length=4000)
    metadata_json: dict[str, Any] | None = None
    observed_at: datetime | None = None


class MetricAnomalyResponse(BaseModel):
    anomaly_id: str
    service_name: str
    metric_name: str
    observed_value: float
    baseline_value: float
    unit: str | None
    severity: str
    incident_id: str | None
    description: str | None
    metadata_json: dict[str, Any] | None
    observed_at: datetime


class DeploymentCreateRequest(BaseModel):
    service_name: str = Field(min_length=1, max_length=255)
    deployment_id: str = Field(min_length=1, max_length=64)
    version: str = Field(min_length=1, max_length=64)
    environment: str = Field(default="production", min_length=1, max_length=64)
    status: str = Field(default="success", min_length=1, max_length=32)
    notes: str | None = None
    metadata_json: dict[str, Any] | None = None
    deployed_at: datetime | None = None


class GitHubRepositoryPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: int
    name: str = Field(min_length=1, max_length=255)
    full_name: str = Field(min_length=1, max_length=255)


class GitHubSenderPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    login: str | None = None


class GitHubDeploymentPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: int
    sha: str | None = None
    ref: str | None = None
    task: str | None = None
    environment: str | None = None
    description: str | None = None
    payload: dict[str, Any] | str | None = None
    created_at: datetime
    updated_at: datetime | None = None


class GitHubDeploymentStatusPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    id: int
    state: Literal[
        "error",
        "failure",
        "inactive",
        "in_progress",
        "queued",
        "pending",
        "success",
    ]
    description: str | None = None
    environment: str | None = None
    log_url: str | None = None
    environment_url: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class GitHubDeploymentWebhookPayload(BaseModel):
    model_config = ConfigDict(extra="ignore")

    action: str
    deployment: GitHubDeploymentPayload
    deployment_status: GitHubDeploymentStatusPayload | None = None
    repository: GitHubRepositoryPayload
    sender: GitHubSenderPayload | None = None


class GitHubDeploymentIngestionResult(BaseModel):
    deployment_id: str
    service_name: str
    version: str
    environment: str
    status: str
    source: str
    source_event_id: str


class GitHubWebhookResponse(BaseModel):
    event: str
    status: str
    deployment: GitHubDeploymentIngestionResult | None = None


class ServiceDependencyCreateRequest(BaseModel):
    service_name: str = Field(min_length=1, max_length=255)
    depends_on_service_name: str = Field(min_length=1, max_length=255)
    criticality: Literal["low", "medium", "high"] = "medium"


class ServiceDependencyResponse(BaseModel):
    dependency_id: str
    service_name: str
    depends_on_service_name: str
    criticality: str
    created_at: datetime
