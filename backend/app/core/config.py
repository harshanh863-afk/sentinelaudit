"""Application configuration loaded from environment variables."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    app_name: str = "SentinelAudit"
    app_version: str = "1.0.0"
    debug: bool = False

    database_url: str = "postgresql://sentinelaudit:sentinelaudit@localhost:5432/sentinelaudit"
    redis_url: str = "redis://localhost:6379/0"

    secret_key: str = "change-me-in-production"
    frontend_url: str = "http://localhost:5173"
    allowed_hosts: list[str] = ["*"]

    scanner_timeout: int = 30
    max_concurrent_scans: int = 5
    scan_results_ttl: int = 86400

    public_scan_max_per_hour: int = 5
    public_scan_timeout_seconds: int = 600


settings = Settings()
