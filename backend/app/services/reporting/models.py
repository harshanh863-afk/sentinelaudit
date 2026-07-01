"""Enhanced report data models for professional security assessment reporting."""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class ExecutiveSummary:
    security_score: float = 0.0
    risk_rating: str = "unknown"
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    compliance_score: float = 0.0
    frameworks_assessed: list[str] = field(default_factory=list)
    privacy_score: float = 0.0
    regulations_checked: list[str] = field(default_factory=list)


@dataclass
class FindingDetail:
    finding_id: uuid.UUID
    title: str
    severity: str
    status: str
    detail: str | None = None
    cvss_score: float | None = None
    evidence_summary: str | None = None
    evidence_hash: str | None = None
    remediation: str | None = None
    compliance: list[dict] = field(default_factory=list)
    impact: str = ""
    business_impact: str = ""
    risk_explanation: str = ""
    affected_component: str = ""
    false_positive_notes: str = ""
    cwe: list[dict] = field(default_factory=list)
    capec: list[dict] = field(default_factory=list)
    mitre_attack: list[dict] = field(default_factory=list)


@dataclass
class ComplianceSection:
    framework: str
    score: float = 0.0
    status: str = "not_assessed"
    passed: int = 0
    failed: int = 0
    partial: int = 0
    not_applicable: int = 0
    total: int = 0


@dataclass
class PrivacySection:
    privacy_score: float = 0.0
    gdpr_score: float = 0.0
    ccpa_score: float = 0.0
    coppa_score: float = 0.0
    cookie_score: float = 0.0
    detected_issues: int = 0
    recommendations: list[str] = field(default_factory=list)


@dataclass
class TechnicalAppendix:
    scanner_version: str = ""
    scan_duration_seconds: int = 0
    methodology: str = ""
    target_info: dict = field(default_factory=dict)
    assessment_limitations: list[str] = field(default_factory=list)
    scanner_modules: list[str] = field(default_factory=list)
    evidence_collected: list[str] = field(default_factory=list)


@dataclass
class ProfessionalReport:
    title: str
    client_name: str = ""
    target_url: str = ""
    scan_date: str = ""
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    executive_summary: ExecutiveSummary = field(default_factory=ExecutiveSummary)
    findings: list[FindingDetail] = field(default_factory=list)
    compliance_sections: list[ComplianceSection] = field(default_factory=list)
    privacy_section: PrivacySection | None = None
    appendix: TechnicalAppendix = field(default_factory=TechnicalAppendix)
    remediation_summary: str = ""


def severity_sort_key(finding: FindingDetail) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(finding.severity, 99)
