import json
from pathlib import Path

from incident_investigation_agent.services.ai_analysis_service import PROMPT_VERSION


def test_prompt_regression_dataset_is_valid_and_grounded() -> None:
    dataset_path = Path(__file__).parent / "regression" / "incident_analysis_v1.json"
    dataset = json.loads(dataset_path.read_text())

    assert dataset["dataset_version"] == PROMPT_VERSION
    assert dataset["prompt_version"] == PROMPT_VERSION
    assert dataset["cases"]

    case_ids: set[str] = set()
    for case in dataset["cases"]:
        assert case["case_id"] not in case_ids
        case_ids.add(case["case_id"])

        signal_ids = {signal["signal_id"] for signal in case["ranked_signals"]}
        expectations = case["expectations"]
        assert expectations["minimum_hypotheses"] >= 1
        assert set(expectations["allowed_signal_ids"]) == signal_ids
        assert set(expectations["required_signal_ids"]).issubset(signal_ids)
