"""Security Risk Intelligence Engine — orchestrates finding risk scoring, asset grading,
compliance posture, and risk explanation generation.

This is the top-level entry point for Phase 5 intelligence. It coordinates:
    1. RiskCalculator  — per-finding risk scoring with CVSS, confidence, severity
    2. GradeCalculator — asset-level security grade (A+ through F)
    3. ComplianceScorer — per-framework compliance posture calculation
    4. ExplanationEngine — deterministic risk explanations
"""

from app.services.risk_engine.models import (
    AssetRiskReport,
    ConfidenceLevel,
    CompliancePosture,
    RiskExplanation,
    SecurityGrade,
)
from app.services.risk_engine.risk_calculator import (
    RiskCalculator,
    RiskLevel,
    RiskScoreResult,
)
from app.services.risk_engine.grade_calculator import calculate_grade, grade_description
from app.services.risk_engine.compliance_scorer import (
    calculate_all_postures,
    overall_compliance_score,
)
from app.services.risk_engine.explanation_engine import generate_explanation

from app.models.enums import FindingStatus, SeverityLevel


class IntelligenceEngine:
    """Orchestrates full security risk intelligence processing."""

    def __init__(self, risk_calculator: type[RiskCalculator] = RiskCalculator):
        self._risk_calculator = risk_calculator

    def process_finding(
        self,
        severity: SeverityLevel,
        attack_vector: str = "network",
        status: FindingStatus = FindingStatus.NEW,
        compliance_count: int = 0,
        cvss_score: float | None = None,
        confidence: ConfidenceLevel | None = None,
    ) -> RiskScoreResult:
        return self._risk_calculator.calculate_finding(
            severity=severity,
            attack_vector=attack_vector,
            status=status,
            compliance_count=compliance_count,
            cvss_score=cvss_score,
            confidence=confidence,
        )

    def process_asset(
        self,
        findings: list[dict],
    ) -> AssetRiskReport:
        """Process all findings for an asset and produce the full intelligence report.

        Each dict in findings should contain:
            - severity: SeverityLevel (required)
            - attack_vector: str (optional, default 'network')
            - status: FindingStatus (optional, default NEW)
            - compliance_count: int (optional, default 0)
            - cvss_score: float | None (optional)
            - confidence: ConfidenceLevel | None (optional)
            - title: str (optional)
            - finding_type: str (optional)
            - remediation_hint: str (optional)
        """
        results: list[RiskScoreResult] = []
        explanations: list[RiskExplanation] = []

        for raw in findings:
            severity = raw.get("severity", SeverityLevel.INFO)
            result = self._risk_calculator.calculate_finding(
                severity=severity,
                attack_vector=raw.get("attack_vector", "network"),
                status=raw.get("status", FindingStatus.NEW),
                compliance_count=raw.get("compliance_count", 0),
                cvss_score=raw.get("cvss_score"),
                confidence=raw.get("confidence"),
            )
            results.append(result)

            title = raw.get("title", "Unknown finding")
            exp = generate_explanation(
                finding_title=title,
                severity=severity,
                confidence=raw.get("confidence"),
                finding_type=raw.get("finding_type"),
                remediation_hint=raw.get("remediation_hint"),
            )
            explanations.append(exp)

        overall = self._risk_calculator.calculate_overall(results)
        grade = calculate_grade(overall.score)
        dist = self._risk_calculator.severity_distribution(results)
        postures = calculate_all_postures(findings)

        explanations.sort(key=lambda e: (
            {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(e.finding_severity, 5)
        ))

        return AssetRiskReport(
            security_score=overall.score,
            risk_level=overall.level.value,
            security_grade=grade,
            total_findings=len(results),
            finding_breakdown=dist,
            compliance_posture=postures,
            top_risks=explanations[:10],
        )
