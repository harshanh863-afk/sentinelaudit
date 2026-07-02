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
    technical_score: float = 0.0
    business_risk: float = 0.0
    confidence_score: float = 0.0
    coverage_score: float = 0.0


@dataclass
class ManagementSummary:
    key_findings_overview: str = ""
    business_risks: list[str] = field(default_factory=list)
    strategic_recommendations: list[str] = field(default_factory=list)
    prioritized_actions: list[str] = field(default_factory=list)


@dataclass
class TechnicalSummary:
    overview: str = ""
    technical_findings: list[str] = field(default_factory=list)
    affected_components: list[str] = field(default_factory=list)
    attack_vectors: list[str] = field(default_factory=list)
    exploitation_complexity: str = ""


@dataclass
class TopRisk:
    title: str
    severity: str
    score: float
    impact: str
    remediation: str
    cvss_score: float | None = None


@dataclass
class SecurityStrength:
    category: str
    description: str
    controls: list[str] = field(default_factory=list)


@dataclass
class AttackSurfaceSummary:
    exposed_technologies: list[str] = field(default_factory=list)
    open_ports: list[str] = field(default_factory=list)
    third_party_services: list[str] = field(default_factory=list)
    attack_vectors_identified: list[str] = field(default_factory=list)
    risk_level: str = "unknown"


@dataclass
class RemediationStep:
    phase: str
    title: str
    description: str
    priority: str
    effort: str = "medium"


@dataclass
class PrioritizedRemediationRoadmap:
    immediate_steps: list[RemediationStep] = field(default_factory=list)
    short_term_steps: list[RemediationStep] = field(default_factory=list)
    medium_term_steps: list[RemediationStep] = field(default_factory=list)
    long_term_steps: list[RemediationStep] = field(default_factory=list)


@dataclass
class RiskHeatMapEntry:
    likelihood: str
    impact: str
    count: int = 0
    risk_level: str = "medium"


@dataclass
class RiskHeatMap:
    entries: list[RiskHeatMapEntry] = field(default_factory=list)
    overall_risk_level: str = "unknown"


@dataclass
class ScoreBreakdown:
    dimension: str
    score: float
    weight: float
    contribution: float
    details: str = ""


@dataclass
class SecurityScoreBreakdown:
    overall: float = 0.0
    dimensions: list[ScoreBreakdown] = field(default_factory=list)
    explanation: str = ""


@dataclass
class FindingTrend:
    period: str
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    total_count: int = 0
    average_score: float = 0.0


@dataclass
class FindingTrends:
    trends: list[FindingTrend] = field(default_factory=list)
    direction: str = "stable"
    percentage_change: float = 0.0


@dataclass
class ComplianceSummary:
    frameworks: list[dict] = field(default_factory=list)
    overall_compliance: float = 0.0
    gaps: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


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
    confidence: float | None = None
    confidence_label: str = ""
    cwe: list[dict] = field(default_factory=list)
    capec: list[dict] = field(default_factory=list)
    mitre_attack: list[dict] = field(default_factory=list)
    cves: list[dict] = field(default_factory=list)


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
    scanner_results: list[dict] = field(default_factory=list)
    evidence_collected: list[str] = field(default_factory=list)


@dataclass
class ProfessionalReport:
    title: str
    client_name: str = ""
    target_url: str = ""
    scan_date: str = ""
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    executive_summary: ExecutiveSummary = field(default_factory=ExecutiveSummary)
    management_summary: ManagementSummary = field(default_factory=ManagementSummary)
    technical_summary: TechnicalSummary = field(default_factory=TechnicalSummary)
    top_risks: list[TopRisk] = field(default_factory=list)
    security_strengths: list[SecurityStrength] = field(default_factory=list)
    attack_surface_summary: AttackSurfaceSummary = field(default_factory=AttackSurfaceSummary)
    remediation_roadmap: PrioritizedRemediationRoadmap = field(default_factory=PrioritizedRemediationRoadmap)
    risk_heat_map: RiskHeatMap = field(default_factory=RiskHeatMap)
    score_breakdown: SecurityScoreBreakdown = field(default_factory=SecurityScoreBreakdown)
    finding_trends: FindingTrends = field(default_factory=FindingTrends)
    compliance_summary: ComplianceSummary = field(default_factory=ComplianceSummary)
    findings: list[FindingDetail] = field(default_factory=list)
    compliance_sections: list[ComplianceSection] = field(default_factory=list)
    privacy_section: PrivacySection | None = None
    appendix: TechnicalAppendix = field(default_factory=TechnicalAppendix)
    remediation_summary: str = ""


def severity_sort_key(finding: FindingDetail) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(finding.severity, 99)
