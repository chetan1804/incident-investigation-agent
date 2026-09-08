from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = Field(default="incident-investigation-agent")
    environment: str = Field(default="development")
    log_level: str = Field(default="INFO")
    api_port: int = Field(default=8000)
    database_url: str = Field(default="sqlite:///./incident_investigation_agent.db")
    correlation_lookback_minutes: int = Field(default=60, ge=1, le=1440)
    correlation_lookahead_minutes: int = Field(default=30, ge=0, le=1440)
    historical_incident_limit: int = Field(default=5, ge=0, le=20)
    historical_similarity_threshold: float = Field(default=0.2, ge=0, le=1)
    openai_api_key: str | None = Field(default=None, repr=False)
    openai_model: str = Field(default="gpt-5-mini", min_length=1)
    ai_max_ranked_signals: int = Field(default=20, ge=1, le=100)


settings = Settings()
