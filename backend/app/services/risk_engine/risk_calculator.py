"""Enterprise Risk Engine — multi-dimensional security scoring.

Produces:
    Overall Score: weighted composite of all dimensions
    Technical Score: severity + CVSS + exploitability
    Business Risk: business impact + asset importance + internet exposure
    Confidence Score: average confidence across findings
    Coverage Score: percentage of rules evaluated
    Risk Distribution: severity counts with severity score

Overall formula:
    overall = (technical * 0.35 + business * 0.25 + confidence_score * 0.15
               + coverage * 0.15 + penalty_factor * 0.10)

Maintains backward compatibility with existing RiskScoreResult.
"""

from dataclasses import dataclass, field
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


@dataclass
class ScoreBreakdown:
    dimension: str
    score: float
    weight: float
    contribution: float
    details: str = ""


@dataclass
class EnterpriseRiskReport:
    overall_score: float
    overall_level: RiskLevel
    technical_score: float
    business_risk: float
    confidence_score: float
    coverage_score: float
    risk_distribution: dict[str, int]
    severity_score: float
    breakdowns: list[ScoreBreakdown] = field(default_factory=list)
    explanation: str = ""


# ------------------------------------------------------------------
# Weight tables (maintained from previous version)
# ------------------------------------------------------------------

SEVERITY_WEIGHTS: dict[SeverityLevel, float] = {
    SeverityLevel.CRITICAL: 40,
    SeverityLevel.HIGH: 30,
    SeverityLevel.MEDIUM: 20,
    SeverityLevel.LOW: 10,
    SeverityLevel.INFO: 0,
}

EXPLOITABILITY_WEIGHTS: dict[str, float] = {
    "network": 10,
    "adjacent": 6,
    "local": 3,
    "physical": 0,
    "none": 0,
}

CONFIDENCE_STATUS_WEIGHTS: dict[FindingStatus, float] = {
    FindingStatus.CONFIRMED: 20,
    FindingStatus.NEW: 15,
    FindingStatus.RETEST_REQUIRED: 10,
    FindingStatus.ACCEPTED_RISK: 5,
    FindingStatus.FALSE_POSITIVE: 0,
    FindingStatus.FIXED: 0,
}

CONFIDENCE_LEVEL_WEIGHTS: dict[ConfidenceLevel, float] = {
    ConfidenceLevel.CONFIRMED: 20,
    ConfidenceLevel.HIGH: 15,
    ConfidenceLevel.MEDIUM: 8,
    ConfidenceLevel.LOW: 3,
}

CVSS_SEVERITY_FLOORS: dict[SeverityLevel, float] = {
    SeverityLevel.CRITICAL: 9.0,
    SeverityLevel.HIGH: 7.0,
    SeverityLevel.MEDIUM: 4.0,
    SeverityLevel.LOW: 0.1,
    SeverityLevel.INFO: 0.0,
}

SEVERITY_OVERALL_MULTIPLIERS: dict[str, float] = {
    "critical": 5.0,
    "high": 3.0,
    "medium": 2.0,
    "low": 1.0,
    "info": 0.5,
}

BUSINESS_IMPACT_WEIGHTS: dict[str, float] = {
    "critical": 100.0,
    "high": 75.0,
    "medium": 50.0,
    "low": 25.0,
    "info": 0.0,
}


class RiskCalculator:
    """Multi-dimensional enterprise risk calculator."""

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
        exploitability_w = EXPLOITABILITY_WEIGHTS.get(attack_vector.lower(), 5)

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

        total_weight = 0.0
        weighted_sum = 0.0
        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = f.level.value
            mult = SEVERITY_OVERALL_MULTIPLIERS.get(sev, 1.0)
            weighted_sum += f.score * mult
            total_weight += mult
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        weighted_avg = weighted_sum / total_weight if total_weight > 0 else 0.0
        penalty = min(15.0, severity_counts.get("critical", 0) * 2 + severity_counts.get("high", 0) * 1)
        final_score = min(100.0, weighted_avg + penalty)

        return RiskScoreResult(
            score=round(final_score, 1),
            level=RiskCalculator._risk_level(final_score),
        )

    @staticmethod
    def calculate_enterprise(
        findings: list[dict],
        total_rules: int = 1,
        evaluated_rules: int = 0,
    ) -> EnterpriseRiskReport:
        """Produce a multi-dimensional enterprise risk report.

        Each finding dict should include:
            - severity (str): critical|high|medium|low|info
            - cvss_score (float, optional)
            - confidence (float, optional)
            - exploitability (str, optional): network|adjacent|local|physical|none
            - business_impact (str, optional): critical|high|medium|low|info
            - asset_importance (float, optional): 0.0 – 1.0
            - internet_exposed (bool, optional)
        """
        if not findings:
            return EnterpriseRiskReport(
                overall_score=0.0,
                overall_level=RiskLevel.INFO,
                technical_score=0.0,
                business_risk=0.0,
                confidence_score=0.0,
                coverage_score=0.0,
                risk_distribution={},
                severity_score=0.0,
            )

        # Technical Score (uses severity weight map)
        _TECH_SEV_WEIGHTS = {"critical": 40, "high": 30, "medium": 20, "low": 10, "info": 0}
        tech_scores = []
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            sev_w = _TECH_SEV_WEIGHTS.get(sev, 0)
            cvss = f.get("cvss_score") or 0
            cvss_w = min(25.0, cvss * 2.5)
            exploit = f.get("exploitability", "network")
            exp_w = EXPLOITABILITY_WEIGHTS.get(exploit.lower(), 5)
            tech_scores.append(min(100.0, sev_w + cvss_w + exp_w))
        technical_score = sum(tech_scores) / len(tech_scores) if tech_scores else 0.0

        # Business Risk
        biz_scores = []
        for f in findings:
            biz_impact = (f.get("business_impact") or f.get("severity") or "info").lower()
            biz_w = BUSINESS_IMPACT_WEIGHTS.get(biz_impact, 0)
            asset_imp = f.get("asset_importance", 0.5)
            internet_exp = 25.0 if f.get("internet_exposed", True) else 0.0
            biz_scores.append(min(100.0, biz_w * asset_imp + internet_exp))
        business_risk = sum(biz_scores) / len(biz_scores) if biz_scores else 0.0

        # Confidence Score
        conf_scores = [f.get("confidence", 0.5) for f in findings]
        confidence_score = (sum(conf_scores) / len(conf_scores)) * 100.0

        # Coverage Score
        coverage_score = min(100.0, (evaluated_rules / max(total_rules, 1)) * 100.0)

        # Risk Distribution
        dist: dict[str, int] = {}
        for f in findings:
            sev = (f.get("severity") or "info").lower()
            dist[sev] = dist.get(sev, 0) + 1

        # Severity Score (weighted by criticality)
        sev_weights = {"critical": 5, "high": 3, "medium": 2, "low": 1, "info": 0}
        total_w = sum(dist.get(s, 0) * w for s, w in sev_weights.items())
        max_w = len(findings) * 5
        severity_score = (total_w / max(max_w, 1)) * 100.0

        # Penalty factor (findings without evidence or confidence)
        low_conf = sum(1 for f in findings if (f.get("confidence") or 0) < 0.3)
        no_evidence = sum(1 for f in findings if not f.get("evidence"))
        penalty_factor = max(0.0, 100.0 - (low_conf * 5 + no_evidence * 3))

        # Overall (weighted composite)
        overall = (
            technical_score * 0.35
            + business_risk * 0.25
            + confidence_score * 0.15
            + coverage_score * 0.15
            + penalty_factor * 0.10
        )

        breakdowns = [
            ScoreBreakdown("Technical Score", technical_score, 0.35, technical_score * 0.35,
                           "Severity + CVSS + exploitability"),
            ScoreBreakdown("Business Risk", business_risk, 0.25, business_risk * 0.25,
                           "Business impact + asset importance + exposure"),
            ScoreBreakdown("Confidence Score", confidence_score, 0.15, confidence_score * 0.15,
                           "Average confidence across all findings"),
            ScoreBreakdown("Coverage Score", coverage_score, 0.15, coverage_score * 0.15,
                           "Percentage of rules evaluated"),
            ScoreBreakdown("Penalty Factor", penalty_factor, 0.10, penalty_factor * 0.10,
                           "Penalty for low-confidence or unevidenced findings"),
        ]

        explanation = RiskCalculator.explain_scoring(
            technical_score, business_risk, confidence_score,
            coverage_score, penalty_factor, overall,
        )

        return EnterpriseRiskReport(
            overall_score=round(overall, 1),
            overall_level=RiskCalculator._risk_level(overall),
            technical_score=round(technical_score, 1),
            business_risk=round(business_risk, 1),
            confidence_score=round(confidence_score, 1),
            coverage_score=round(coverage_score, 1),
            risk_distribution=dist,
            severity_score=round(severity_score, 1),
            breakdowns=breakdowns,
            explanation=explanation,
        )

    @staticmethod
    def explain_scoring(
        technical: float, business: float, confidence: float,
        coverage: float, penalty: float, overall: float,
    ) -> str:
        return (
            f"Overall Score ({overall:.1f}) = "
            f"Technical ({technical:.1f} × 0.35 = {technical * 0.35:.1f}) + "
            f"Business ({business:.1f} × 0.25 = {business * 0.25:.1f}) + "
            f"Confidence ({confidence:.1f} × 0.15 = {confidence * 0.15:.1f}) + "
            f"Coverage ({coverage:.1f} × 0.15 = {coverage * 0.15:.1f}) + "
            f"Penalty ({penalty:.1f} × 0.10 = {penalty * 0.10:.1f})"
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
            return 10
        if count >= 2:
            return 8
        if count >= 1:
            return 5
        return 0

    @staticmethod
    def _cvss_weight(cvss_score: float | None, severity: SeverityLevel) -> float:
        if cvss_score is None or cvss_score <= 0:
            return 0
        floor = CVSS_SEVERITY_FLOORS.get(severity, 0.0)
        if cvss_score > floor + 2.0:
            return 20
        if cvss_score > floor:
            return 10
        return 4
