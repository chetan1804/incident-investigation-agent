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


settings = Settings()
