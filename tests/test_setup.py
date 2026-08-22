from incident_investigation_agent.config.settings import settings


def test_default_settings_are_loaded() -> None:
    assert settings.app_name == "incident-investigation-agent"
    assert settings.environment in {"development", "production", "staging"}
    assert settings.api_port > 0
