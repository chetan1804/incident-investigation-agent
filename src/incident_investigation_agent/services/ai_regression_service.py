from __future__ import annotations

import json
import re
from importlib.resources import files
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from incident_investigation_agent.exceptions import (
    AIAnalysisError,
    ResourceConflictError,
    ResourceNotFoundError,
)
from incident_investigation_agent.models.incident_models import AIRegressionRun
from incident_investigation_agent.repositories.incident_repository import IncidentRepository
from incident_investigation_agent.services.ai_analysis_service import HypothesisGenerator

DATASET_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


class RegressionIncident(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: str
    summary: str
    severity: str


class RegressionExpectations(BaseModel):
    model_config = ConfigDict(extra="forbid")

    minimum_hypotheses: int = Field(ge=0)
    allowed_signal_ids: list[str]
    required_signal_ids: list[str]


class RegressionCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    case_id: str
    incident: RegressionIncident
    ranked_signals: list[dict[str, Any]]
    expectations: RegressionExpectations


class RegressionDataset(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dataset_version: str
    prompt_version: str
    cases: list[RegressionCase] = Field(min_length=1)


def load_regression_dataset(dataset_version: str) -> RegressionDataset:
    """Load and validate a bundled dataset without accepting arbitrary paths."""
    if not DATASET_NAME_PATTERN.fullmatch(dataset_version):
        raise ResourceNotFoundError(f"Regression dataset '{dataset_version}' was not found")

    resource = files("incident_investigation_agent.evaluation_datasets").joinpath(
        f"{dataset_version}.json"
    )
    if not resource.is_file():
        raise ResourceNotFoundError(f"Regression dataset '{dataset_version}' was not found")
    return RegressionDataset.model_validate(json.loads(resource.read_text(encoding="utf-8")))


class AIRegressionService:
    def __init__(
        self,
        repository: IncidentRepository,
        hypothesis_generator: HypothesisGenerator,
    ):
        self.repository = repository
        self.hypothesis_generator = hypothesis_generator

    def run(self, dataset_version: str) -> AIRegressionRun:
        dataset = load_regression_dataset(dataset_version)
        results = [self._evaluate_case(case) for case in dataset.cases]
        passed_cases = sum(result["passed"] for result in results)
        return self.repository.create_ai_regression_run(
            dataset_version=dataset.dataset_version,
            model=self.hypothesis_generator.model,
            prompt_version=self.hypothesis_generator.prompt_version,
            prompt_sha256=self.hypothesis_generator.prompt_sha256,
            passed=passed_cases == len(results),
            total_cases=len(results),
            passed_cases=passed_cases,
            results_json=results,
        )

    def _evaluate_case(self, case: RegressionCase) -> dict[str, Any]:
        try:
            analysis = self.hypothesis_generator.generate(
                incident_id=case.incident.incident_id,
                summary=case.incident.summary,
                severity=case.incident.severity,
                ranked_signals=case.ranked_signals,
            )
        except AIAnalysisError as exc:
            return {
                "case_id": case.case_id,
                "passed": False,
                "failures": [str(exc)],
                "hypothesis_count": 0,
                "remediation_count": 0,
                "cited_signal_ids": [],
                "output": None,
            }
        cited_signal_ids = {
            signal_id
            for item in [*analysis.hypotheses, *analysis.remediation_suggestions]
            for signal_id in item.supporting_signals
        }
        allowed = set(case.expectations.allowed_signal_ids)
        required = set(case.expectations.required_signal_ids)
        failures: list[str] = []

        if len(analysis.hypotheses) < case.expectations.minimum_hypotheses:
            failures.append(
                f"expected at least {case.expectations.minimum_hypotheses} hypotheses, "
                f"received {len(analysis.hypotheses)}"
            )
        unknown = sorted(cited_signal_ids - allowed)
        if unknown:
            failures.append(f"cited disallowed signals: {', '.join(unknown)}")
        missing = sorted(required - cited_signal_ids)
        if missing:
            failures.append(f"did not cite required signals: {', '.join(missing)}")

        return {
            "case_id": case.case_id,
            "passed": not failures,
            "failures": failures,
            "hypothesis_count": len(analysis.hypotheses),
            "remediation_count": len(analysis.remediation_suggestions),
            "cited_signal_ids": sorted(cited_signal_ids),
            "output": analysis.model_dump(),
        }


class AIRegressionComparisonService:
    """Compare immutable regression runs and evaluate CI quality thresholds."""

    def __init__(self, repository: IncidentRepository):
        self.repository = repository

    def compare(self, *, candidate_run_id: str, baseline_run_id: str) -> dict[str, Any]:
        candidate = self._get_run(candidate_run_id)
        baseline = self._get_run(baseline_run_id)
        if candidate.run_id == baseline.run_id:
            raise ResourceConflictError("Candidate and baseline regression runs must differ")
        if candidate.dataset_version != baseline.dataset_version:
            raise ResourceConflictError(
                "Regression runs must use the same dataset version"
            )
        if candidate.total_cases <= 0 or baseline.total_cases <= 0:
            raise ResourceConflictError("Regression runs must contain at least one case")

        candidate_cases = self._case_outcomes(candidate)
        baseline_cases = self._case_outcomes(baseline)
        if (
            len(candidate_cases) != candidate.total_cases
            or len(baseline_cases) != baseline.total_cases
        ):
            raise ResourceConflictError(
                "Regression runs contain duplicate or incomplete case results"
            )
        if candidate_cases.keys() != baseline_cases.keys():
            raise ResourceConflictError(
                "Regression runs do not contain the same dataset cases"
            )

        regressed = sorted(
            case_id
            for case_id, baseline_passed in baseline_cases.items()
            if baseline_passed and not candidate_cases[case_id]
        )
        improved = sorted(
            case_id
            for case_id, baseline_passed in baseline_cases.items()
            if not baseline_passed and candidate_cases[case_id]
        )
        unchanged_failed = sorted(
            case_id
            for case_id, baseline_passed in baseline_cases.items()
            if not baseline_passed and not candidate_cases[case_id]
        )
        baseline_pass_rate = baseline.passed_cases / baseline.total_cases
        candidate_pass_rate = candidate.passed_cases / candidate.total_cases
        return {
            "candidate_run_id": candidate.run_id,
            "baseline_run_id": baseline.run_id,
            "dataset_version": candidate.dataset_version,
            "candidate_pass_rate": candidate_pass_rate,
            "baseline_pass_rate": baseline_pass_rate,
            "pass_rate_delta": candidate_pass_rate - baseline_pass_rate,
            "regressed_case_ids": regressed,
            "improved_case_ids": improved,
            "unchanged_failed_case_ids": unchanged_failed,
        }

    def evaluate_quality_gate(
        self,
        *,
        candidate_run_id: str,
        baseline_run_id: str,
        minimum_pass_rate: float,
        maximum_pass_rate_drop: float,
        maximum_regressed_cases: int,
    ) -> dict[str, Any]:
        comparison = self.compare(
            candidate_run_id=candidate_run_id,
            baseline_run_id=baseline_run_id,
        )
        failures: list[str] = []
        if comparison["candidate_pass_rate"] < minimum_pass_rate:
            failures.append(
                f"candidate pass rate {comparison['candidate_pass_rate']:.4f} is below "
                f"minimum {minimum_pass_rate:.4f}"
            )
        if comparison["pass_rate_delta"] < -maximum_pass_rate_drop:
            failures.append(
                f"pass rate drop {abs(comparison['pass_rate_delta']):.4f} exceeds "
                f"maximum {maximum_pass_rate_drop:.4f}"
            )
        regression_count = len(comparison["regressed_case_ids"])
        if regression_count > maximum_regressed_cases:
            failures.append(
                f"regressed case count {regression_count} exceeds maximum "
                f"{maximum_regressed_cases}"
            )

        return {
            "passed": not failures,
            "failures": failures,
            "thresholds": {
                "minimum_pass_rate": minimum_pass_rate,
                "maximum_pass_rate_drop": maximum_pass_rate_drop,
                "maximum_regressed_cases": maximum_regressed_cases,
            },
            "comparison": comparison,
        }

    def _get_run(self, run_id: str) -> AIRegressionRun:
        run = self.repository.get_ai_regression_run(run_id)
        if run is None:
            raise ResourceNotFoundError(f"AI regression run '{run_id}' was not found")
        return run

    @staticmethod
    def _case_outcomes(run: AIRegressionRun) -> dict[str, bool]:
        return {result["case_id"]: result["passed"] for result in run.results_json}
