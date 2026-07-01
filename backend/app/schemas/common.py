import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class SentinelSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class PaginationParams(SentinelSchema):
    page: int = 1
    page_size: int = 50


class UUIDMixin(SentinelSchema):
    id: uuid.UUID


class TimestampMixin(SentinelSchema):
    created_at: datetime
    updated_at: datetime | None = None
