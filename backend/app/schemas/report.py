from datetime import datetime

from app.schemas.common import SentinelSchema, UUIDMixin


class ReportCreate(SentinelSchema):
    project_id: str
    scan_ids: list[str]
    format: str
    file_path: str | None = None
    title: str | None = None


class ReportRead(UUIDMixin):
    project_id: str
    scan_ids: list
    format: str
    file_path: str | None
    title: str | None = None
    risk_score: float | None = None
    risk_rating: str | None = None
    findings_count: int | None = None
    severity_breakdown: dict | None = None
    generated_at: datetime | None = None


class ReportGenerateResponse(UUIDMixin):
    scan_id: str
    report_id: str
    status: str
    format: str
    message: str
