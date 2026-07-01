"""Risk scoring engine - converts findings into quantifiable security risk scores.

Formula:
    Overall Risk = severity_weight + cvss_contribution + exploitability_weight
                   + confidence_weight + compliance_weight
    Final score is clamped to [0, 100].

CVSS Contribution:
    When a CVSS score is provided, it adjusts the severity weight upward if
    CVSS is meaningfully higher than the severity-derived baseline.
"""

from dataclasses import dataclass
from enum import Enum

from app.models.enums import FindingStatus, SeverityLevel

from app.services.risk_engine.models import ConfidenceLevel


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class RiskScoreResult:
    score: float
    level: RiskLevel
    severity_weight: float = 0
    exploitability_weight: float = 0
    confidence_weight: float = 0
    compliance_weight: float = 0
    cvss_contribution: float = 0


# ------------------------------------------------------------------
# Weight tables
# ------------------------------------------------------------------

SEVERITY_WEIGHTS: dict[SeverityLevel, float] = {
    SeverityLevel.CRITICAL: 40,
    SeverityLevel.HIGH: 30,
    SeverityLevel.MEDIUM: 20,
    SeverityLevel.LOW: 10,
    SeverityLevel.INFO: 0,
}

EXPLOITABILITY_WEIGHTS: dict[str, float] = {
    "network": 25,
    "adjacent": 15,
    "local": 5,
    "physical": 0,
    "none": 0,
}

CONFIDENCE_STATUS_WEIGHTS: dict[FindingStatus, float] = {
    FindingStatus.CONFIRMED: 25,
    FindingStatus.NEW: 20,
    FindingStatus.RETEST_REQUIRED: 15,
    FindingStatus.ACCEPTED_RISK: 10,
    FindingStatus.FALSE_POSITIVE: 0,
    FindingStatus.FIXED: 0,
}

CONFIDENCE_LEVEL_WEIGHTS: dict[ConfidenceLevel, float] = {
    ConfidenceLevel.CONFIRMED: 25,
    ConfidenceLevel.HIGH: 20,
    ConfidenceLevel.MEDIUM: 12,
    ConfidenceLevel.LOW: 5,
}

COMPLIANCE_FRAMEWORK_WEIGHTS = {0: 0, 1: 5, 2: 10, 3: 15}

# When CVSS is available, blend it with the severity baseline.
# CVSS scores map roughly to severities: 9.0+ = critical, 7.0-8.9 = high,
# 4.0-6.9 = medium, 0.1-3.9 = low, 0 = info.
CVSS_SEVERITY_FLOORS: dict[SeverityLevel, float] = {
    SeverityLevel.CRITICAL: 9.0,
    SeverityLevel.HIGH: 7.0,
    SeverityLevel.MEDIUM: 4.0,
    SeverityLevel.LOW: 0.1,
    SeverityLevel.INFO: 0.0,
}


class RiskCalculator:
    """Calculates risk scores for findings and scan aggregates."""

    @staticmethod
    def calculate_finding(
        severity: SeverityLevel,
        attack_vector: str = "network",
        status: FindingStatus = FindingStatus.NEW,
        compliance_count: int = 0,
        cvss_score: float | None = None,
        confidence: ConfidenceLevel | None = None,
    ) -> RiskScoreResult:
        severity_w = SEVERITY_WEIGHTS.get(severity, 0)

        cvss_contribution = RiskCalculator._cvss_weight(cvss_score, severity)

        exploitability_w = EXPLOITABILITY_WEIGHTS.get(attack_vector.lower(), 10)

        if confidence is not None:
            confidence_w = CONFIDENCE_LEVEL_WEIGHTS.get(confidence, 10)
        else:
            confidence_w = CONFIDENCE_STATUS_WEIGHTS.get(status, 10)

        compliance_w = RiskCalculator._compliance_weight(compliance_count)

        raw = severity_w + cvss_contribution + exploitability_w + confidence_w + compliance_w
        score = min(100.0, max(0.0, float(raw)))

        level = RiskCalculator._risk_level(score)

        return RiskScoreResult(
            score=score,
            level=level,
            severity_weight=severity_w,
            exploitability_weight=exploitability_w,
            confidence_weight=confidence_w,
            compliance_weight=compliance_w,
            cvss_contribution=cvss_contribution,
        )

    @staticmethod
    def calculate_overall(findings: list[RiskScoreResult]) -> RiskScoreResult:
        if not findings:
            return RiskScoreResult(score=0.0, level=RiskLevel.INFO)

        avg_score = sum(f.score for f in findings) / len(findings)

        return RiskScoreResult(
            score=round(avg_score, 1),
            level=RiskCalculator._risk_level(avg_score),
        )

    @staticmethod
    def severity_distribution(findings: list[RiskScoreResult]) -> dict[str, int]:
        dist: dict[str, int] = {}
        for f in findings:
            lvl = f.level.value
            dist[lvl] = dist.get(lvl, 0) + 1
        return dist

    @staticmethod
    def _risk_level(score: float) -> RiskLevel:
        if score >= 90:
            return RiskLevel.CRITICAL
        if score >= 70:
            return RiskLevel.HIGH
        if score >= 40:
            return RiskLevel.MEDIUM
        if score >= 10:
            return RiskLevel.LOW
        return RiskLevel.INFO

    @staticmethod
    def _compliance_weight(count: int) -> float:
        if count >= 3:
            return 15
        if count >= 2:
            return 10
        if count >= 1:
            return 5
        return 0

    @staticmethod
    def _cvss_weight(cvss_score: float | None, severity: SeverityLevel) -> float:
        if cvss_score is None or cvss_score <= 0:
            return 0
        floor = CVSS_SEVERITY_FLOORS.get(severity, 0.0)
        if cvss_score > floor + 2.0:
            return 15
        if cvss_score > floor:
            return 8
        return 3
