"""CVE data models."""

from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class CVERecord:
    cve_id: str
    cvss_score: float | None = None
    severity: str = "unknown"
    published_date: str | None = None
    fix_version: str | None = None
    exploit_available: bool = False
    description: str = ""
    references: list[str] = field(default_factory=list)
    source: str = ""


@dataclass
class CVEResult:
    cves: list[CVERecord] = field(default_factory=list)
    highest_cvss: float | None = None
    total_cves: int = 0
    cache_hit: bool = False
    error: str | None = None
