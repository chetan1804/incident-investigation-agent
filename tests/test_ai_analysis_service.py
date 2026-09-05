from types import SimpleNamespace

import pytest

from incident_investigation_agent.exceptions import AIAnalysisError
from incident_investigation_agent.services.ai_analysis_service import (
    AIAnalysis,
    AIHypothesis,
    OpenAIHypothesisGenerator,
)


class FakeResponses:
    def __init__(self, output: AIAnalysis):
        self.output = output
        self.request = None

    def parse(self, **kwargs):
        self.request = kwargs
        return SimpleNamespace(output_parsed=self.output)


def test_openai_generator_uses_structured_output_and_grounded_evidence() -> None:
    responses = FakeResponses(
        AIAnalysis(
            hypotheses=[
                AIHypothesis(
                    hypothesis="The deployment may have caused the errors",
                    reasoning="The deployment preceded the incident.",
                    confidence=0.72,
                    supporting_signals=["deployment:DEPLOY-1"],
                )
            ],
            remediation_suggestions=[],
        )
    )
    generator = OpenAIHypothesisGenerator(
        api_key="unused", model="test-model", client=SimpleNamespace(responses=responses)
    )
    signals = [
        {
            "signal_id": "deployment:DEPLOY-1",
            "kind": "deployment",
            "description": "DEPLOY-1 (v2)",
            "confidence": 0.8,
        }
    ]

    result = generator.generate(
        incident_id="INC-1",
        summary="Errors after deployment",
        severity="high",
        ranked_signals=signals,
    )

    assert result.hypotheses[0].supporting_signals == ["deployment:DEPLOY-1"]
    assert responses.request["text_format"] is AIAnalysis
    assert responses.request["store"] is False
    assert "deployment:DEPLOY-1" in responses.request["input"]


def test_openai_generator_rejects_unknown_signal_references() -> None:
    responses = FakeResponses(
        AIAnalysis(
            hypotheses=[
                AIHypothesis(
                    hypothesis="Unsupported theory",
                    reasoning="Not grounded.",
                    confidence=0.5,
                    supporting_signals=["log:missing"],
                )
            ],
            remediation_suggestions=[],
        )
    )
    generator = OpenAIHypothesisGenerator(
        api_key="unused", model="test-model", client=SimpleNamespace(responses=responses)
    )

    with pytest.raises(AIAnalysisError, match="log:missing"):
        generator.generate(
            incident_id="INC-1",
            summary="Errors",
            severity="high",
            ranked_signals=[{"signal_id": "log:1"}],
        )


def test_openai_generator_skips_provider_when_no_ranked_evidence() -> None:
    generator = OpenAIHypothesisGenerator(
        api_key="unused", model="test-model", client=SimpleNamespace(responses=None)
    )

    result = generator.generate(
        incident_id="INC-1", summary="Unknown issue", severity="medium", ranked_signals=[]
    )

    assert result == AIAnalysis(hypotheses=[], remediation_suggestions=[])
