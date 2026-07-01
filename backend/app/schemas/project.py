from pydantic import field_validator

from app.schemas.common import SentinelSchema, TimestampMixin, UUIDMixin


class ProjectCreate(SentinelSchema):
    name: str
    description: str | None = None

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("name must not be empty")
        return v.strip()


class ProjectUpdate(SentinelSchema):
    name: str | None = None
    description: str | None = None


class ProjectRead(UUIDMixin, TimestampMixin):
    name: str
    description: str | None
    owner_id: str
