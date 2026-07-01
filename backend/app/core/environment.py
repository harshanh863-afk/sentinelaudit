"""Environment validation and configuration management.

Ensures safe startup in production by validating all required config
and rejecting unsafe configurations.
"""

import os
import sys

_VALID_ENVIRONMENTS = {"development", "production", "testing"}


class EnvironmentConfig:
    """Validated environment configuration with strict production checks."""

    ENVIRONMENT: str
    DATABASE_URL: str
    REDIS_URL: str
    SECRET_KEY: str
    FRONTEND_URL: str
    DEBUG: bool

    def __init__(self):
        self.ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
        self.DATABASE_URL = os.getenv("DATABASE_URL", "")
        self.REDIS_URL = os.getenv("REDIS_URL", "")
        self.SECRET_KEY = os.getenv("SECRET_KEY", "")
        self.FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173")
        self.DEBUG = os.getenv("DEBUG", "").lower() in ("true", "1", "yes")

        errors: list[str] = []

        if self.ENVIRONMENT not in _VALID_ENVIRONMENTS:
            errors.append(
                f"ENVIRONMENT must be one of {', '.join(sorted(_VALID_ENVIRONMENTS))}, got '{self.ENVIRONMENT}'"
            )

        if self.ENVIRONMENT == "production":
            errors.extend(self._validate_production())

        if errors:
            print("ERROR: Environment validation failed:", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)
            sys.exit(1)

    def _validate_production(self) -> list[str]:
        errors: list[str] = []

        if not self.DATABASE_URL:
            errors.append("DATABASE_URL is required in production")
        if not self.REDIS_URL:
            errors.append("REDIS_URL is required in production")
        if not self.SECRET_KEY:
            errors.append("SECRET_KEY is required in production (min 32 characters)")
        elif len(self.SECRET_KEY) < 32:
            errors.append(f"SECRET_KEY is too short ({len(self.SECRET_KEY)} chars, minimum 32)")
        if not self.FRONTEND_URL or self.FRONTEND_URL == "http://localhost:5173":
            errors.append("FRONTEND_URL must be set to production domain in production")
        if self.FRONTEND_URL == "*":
            errors.append("Wildcard CORS (FRONTEND_URL=*) is not allowed in production")
        if self.DEBUG:
            errors.append("DEBUG must be false in production")

        return errors

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"


env_config = EnvironmentConfig()
