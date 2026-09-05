from incident_investigation_agent.config.settings import settings


def test_default_settings_are_loaded() -> None:
    assert settings.app_name == "incident-investigation-agent"
    assert settings.environment in {"development", "production", "staging"}
    assert settings.api_port > 0
    assert settings.correlation_lookback_minutes > 0
    assert settings.correlation_lookahead_minutes >= 0
    assert settings.openai_model
    assert settings.ai_max_ranked_signals > 0
