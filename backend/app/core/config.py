from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AI Security Analyst"
    app_env: str = "development"
    database_url: str = "sqlite:///./ai_security_analyst.db"
    max_batch_rows: int = 5000
    max_batch_content_chars: int = 1_000_000
    brute_force_failure_threshold: int = 5
    brute_force_window_seconds: int = 300
    auth_followup_window_seconds: int = 300
    port_scan_unique_ports_threshold: int = 10
    port_scan_window_seconds: int = 300
    request_burst_threshold: int = 50
    request_burst_window_seconds: int = 60

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
