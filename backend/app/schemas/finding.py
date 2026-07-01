from app.schemas.common import SentinelSchema, UUIDMixin
from app.models.enums import FindingStatus, SeverityLevel


class FindingRead(UUIDMixin):
    scan_id: str
    rule_id: str | None
    severity: SeverityLevel
    status: FindingStatus
    passed: bool
    detail: str | None
