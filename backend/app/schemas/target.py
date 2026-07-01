from pydantic import field_validator

from app.schemas.common import SentinelSchema, TimestampMixin, UUIDMixin


class TargetCreate(SentinelSchema):
    url: str
    port: int | None = None
    tags: dict | None = None

    @field_validator("url")
    @classmethod
    def url_valid(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("url must start with http:// or https://")
        return v.rstrip("/")


class TargetUpdate(SentinelSchema):
    url: str | None = None
    port: int | None = None
    tags: dict | None = None


class TargetRead(UUIDMixin, TimestampMixin):
    project_id: str
    url: str
    host: str
    port: int | None
    tags: dict | None
