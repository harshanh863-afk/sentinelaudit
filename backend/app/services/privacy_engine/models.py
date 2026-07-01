"""Data models for the Privacy Assessment Engine."""

from dataclasses import dataclass, field


@dataclass
class PrivacyIssue:
    issue_id: str
    title: str
    description: str
    severity: str
    category: str
    affected_regulations: list[str] = field(default_factory=list)
    remediation: str = ""
    passed: bool = False


@dataclass
class PrivacyAssessmentReport:
    score: float = 0.0
    issues: list[PrivacyIssue] = field(default_factory=list)
    passed_controls: int = 0
    failed_controls: int = 0
    recommendations: list[str] = field(default_factory=list)
    gdpr_score: float = 0.0
    ccpa_score: float = 0.0
    coppa_score: float = 0.0
    cookie_score: float = 0.0
