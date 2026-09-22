from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AI Security Analyst"
    app_env: str = "development"
    database_url: str = "sqlite:///./ai_security_analyst.db"

    max_batch_rows: int = 5000
    max_batch_content_chars: int = 1_000_000
    max_request_bytes: int = 2_000_000

    auth_enabled: bool = False
    analyst_api_key: str = ""
    admin_api_key: str = ""

    rate_limit_enabled: bool = False
    rate_limit_requests_per_minute: int = 120

    cors_allowed_origins: str = ""
    allowed_hosts: str = ""
    enable_api_docs: bool = False
    log_level: str = "INFO"

    brute_force_failure_threshold: int = 5
    brute_force_window_seconds: int = 300
    auth_followup_window_seconds: int = 300
    port_scan_unique_ports_threshold: int = 10
    port_scan_window_seconds: int = 300
    request_burst_threshold: int = 50
    request_burst_window_seconds: int = 60

    ai_provider: str = "disabled"
    ai_base_url: str = ""
    ai_api_key: str = ""
    ai_model: str = ""
    ai_timeout_seconds: float = 15.0
    ai_prompt_template_version: str = "v1"

    reputation_provider: str = "disabled"
    reputation_base_url: str = ""
    reputation_api_key: str = ""
    reputation_timeout_seconds: float = 10.0
    reputation_cache_ttl_seconds: int = 3600

    analytics_max_days: int = 90
    baseline_min_samples: int = 5
    anomaly_score_threshold: int = 60

    correlation_window_seconds: int = 1800
    correlation_group_key: str = "source_ip"
    correlation_min_threats: int = 2

    @property
    def cors_origins(self) -> list[str]:
        return [
            value.strip()
            for value in self.cors_allowed_origins.split(",")
            if value.strip()
        ]

    @property
    def trusted_hosts(self) -> list[str]:
        return [
            value.strip()
            for value in self.allowed_hosts.split(",")
            if value.strip()
        ]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
