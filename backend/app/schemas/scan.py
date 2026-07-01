from datetime import datetime

from app.schemas.common import SentinelSchema, UUIDMixin
from app.models.enums import ScanStatus


class ScanCreate(SentinelSchema):
    target_id: str


class ScanRead(UUIDMixin):
    target_id: str
    status: ScanStatus
    risk_score: float | None
    started_at: datetime | None
    completed_at: datetime | None
    error: str | None
    progress: int | None
    progress_stage: str | None
    created_at: datetime
