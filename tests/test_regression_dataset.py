from incident_investigation_agent.services.ai_analysis_service import PROMPT_VERSION
from incident_investigation_agent.services.ai_regression_service import load_regression_dataset


def test_prompt_regression_dataset_is_valid_and_grounded() -> None:
    dataset = load_regression_dataset(PROMPT_VERSION)

    assert dataset.dataset_version == PROMPT_VERSION
    assert dataset.prompt_version == PROMPT_VERSION
    assert dataset.cases

    case_ids: set[str] = set()
    for case in dataset.cases:
        assert case.case_id not in case_ids
        case_ids.add(case.case_id)

        signal_ids = {signal["signal_id"] for signal in case.ranked_signals}
        assert case.expectations.minimum_hypotheses >= 1
        assert set(case.expectations.allowed_signal_ids) == signal_ids
        assert set(case.expectations.required_signal_ids).issubset(signal_ids)
