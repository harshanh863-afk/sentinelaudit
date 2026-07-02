"""Tests for the risk scoring engine."""

import pytest

from app.models.enums import FindingStatus, SeverityLevel
from app.services.risk_engine import RiskCalculator, RiskLevel, IntelligenceEngine


class TestRiskLevels:
    """Risk level classification."""

    @pytest.mark.parametrize("score,expected", [
        (95, RiskLevel.CRITICAL),
        (90, RiskLevel.CRITICAL),
        (85, RiskLevel.HIGH),
        (70, RiskLevel.HIGH),
        (60, RiskLevel.MEDIUM),
        (40, RiskLevel.MEDIUM),
        (30, RiskLevel.LOW),
        (10, RiskLevel.LOW),
        (5, RiskLevel.INFO),
        (0, RiskLevel.INFO),
    ])
    def test_risk_level_thresholds(self, score, expected):
        assert RiskCalculator._risk_level(score) == expected


class TestFindingRisk:
    """Individual finding risk calculation."""

    def test_critical_finding_max_score(self):
        result = RiskCalculator.calculate_finding(
            severity=SeverityLevel.CRITICAL,
            attack_vector="network",
            status=FindingStatus.CONFIRMED,
            compliance_count=3,
        )
        # 40 + 10 + 20 + 10 = 80
        assert result.score == 80.0
        assert result.level == RiskLevel.HIGH

    def test_info_finding_min_score(self):
        result = RiskCalculator.calculate_finding(
            severity=SeverityLevel.INFO,
            attack_vector="none",
            status=FindingStatus.FIXED,
            compliance_count=0,
        )
        assert result.score == 0.0
        assert result.level == RiskLevel.INFO

    def test_high_severity_medium_complexity(self):
        result = RiskCalculator.calculate_finding(
            severity=SeverityLevel.HIGH,
            attack_vector="local",
            status=FindingStatus.NEW,
            compliance_count=1,
        )
        # 30 + 3 + 15 + 5 = 53
        assert result.score == 53.0
        assert result.level == RiskLevel.MEDIUM

    def test_finding_returns_weight_breakdown(self):
        result = RiskCalculator.calculate_finding(
            severity=SeverityLevel.HIGH,
            attack_vector="network",
            status=FindingStatus.CONFIRMED,
            compliance_count=2,
        )
        assert result.severity_weight == 30
        assert result.exploitability_weight == 10
        assert result.confidence_weight == 20
        assert result.compliance_weight == 8
        assert result.score == 68.0
        assert result.level == RiskLevel.MEDIUM

    def test_false_positive_zero_confidence(self):
        result = RiskCalculator.calculate_finding(
            severity=SeverityLevel.CRITICAL,
            attack_vector="network",
            status=FindingStatus.FALSE_POSITIVE,
        )
        # 40 + 10 + 0 + 0 = 50
        assert result.score == 50.0
        assert result.level == RiskLevel.MEDIUM

    def test_fixed_finding_zero_confidence(self):
        result = RiskCalculator.calculate_finding(
            severity=SeverityLevel.HIGH,
            attack_vector="network",
            status=FindingStatus.FIXED,
        )
        # 30 + 10 + 0 + 0 = 40
        assert result.score == 40.0

    def test_accepted_risk_has_low_confidence(self):
        result = RiskCalculator.calculate_finding(
            severity=SeverityLevel.HIGH,
            attack_vector="network",
            status=FindingStatus.ACCEPTED_RISK,
        )
        # 30 + 10 + 5 + 0 = 45
        assert result.score == 45.0
        assert result.level == RiskLevel.MEDIUM

    def test_attack_vector_physical_low_exploitability(self):
        result = RiskCalculator.calculate_finding(
            severity=SeverityLevel.CRITICAL,
            attack_vector="physical",
            status=FindingStatus.CONFIRMED,
        )
        # 40 + 0 + 20 + 0 = 60
        assert result.score == 60.0

    def test_compliance_count_weights(self):
        r0 = RiskCalculator.calculate_finding(SeverityLevel.LOW, compliance_count=0)
        r1 = RiskCalculator.calculate_finding(SeverityLevel.LOW, compliance_count=1)
        r2 = RiskCalculator.calculate_finding(SeverityLevel.LOW, compliance_count=2)
        r3 = RiskCalculator.calculate_finding(SeverityLevel.LOW, compliance_count=5)
        assert r0.compliance_weight == 0
        assert r1.compliance_weight == 5
        assert r2.compliance_weight == 8
        assert r3.compliance_weight == 10


class TestOverallRisk:
    """Aggregate risk calculation across multiple findings."""

    def test_empty_findings_returns_info(self):
        result = RiskCalculator.calculate_overall([])
        assert result.score == 0.0
        assert result.level == RiskLevel.INFO

    def test_single_finding(self):
        finding = RiskCalculator.calculate_finding(SeverityLevel.CRITICAL)
        result = RiskCalculator.calculate_overall([finding])
        assert result.score == finding.score
        assert result.level == finding.level

    def test_multiple_findings_weighted(self):
        f1 = RiskCalculator.calculate_finding(SeverityLevel.CRITICAL, attack_vector="network")
        f2 = RiskCalculator.calculate_finding(SeverityLevel.LOW, attack_vector="local")
        f3 = RiskCalculator.calculate_finding(SeverityLevel.INFO, attack_vector="none")
        result = RiskCalculator.calculate_overall([f1, f2, f3])
        assert result.score > 0
        assert result.level is not None


class TestSeverityDistribution:
    """Severity distribution calculation."""

    def test_distribution_counts(self):
        findings = [
            RiskCalculator.calculate_finding(SeverityLevel.CRITICAL),
            RiskCalculator.calculate_finding(SeverityLevel.HIGH),
            RiskCalculator.calculate_finding(SeverityLevel.HIGH),
            RiskCalculator.calculate_finding(SeverityLevel.LOW),
        ]
        dist = RiskCalculator.severity_distribution(findings)
        assert "medium" in dist
        assert "low" in dist

    def test_empty_distribution(self):
        assert RiskCalculator.severity_distribution([]) == {}


# ===================================================================
# Enhanced risk calculator: CVSS weighting
# ===================================================================

class TestCVSSWeighting:
    """CVSS score contribution to risk calculation."""

    def test_no_cvss_no_contribution(self):
        result = RiskCalculator.calculate_finding(SeverityLevel.HIGH)
        assert result.cvss_contribution == 0

    def test_cvss_zero_no_contribution(self):
        result = RiskCalculator.calculate_finding(SeverityLevel.HIGH, cvss_score=0.0)
        assert result.cvss_contribution == 0

    def test_cvss_greatly_exceeds_severity_floor(self):
        result = RiskCalculator.calculate_finding(
            SeverityLevel.LOW, cvss_score=8.5,
        )
        assert result.cvss_contribution == 20

    def test_cvss_moderately_exceeds_severity_floor(self):
        result = RiskCalculator.calculate_finding(
            SeverityLevel.MEDIUM, cvss_score=5.5,
        )
        assert result.cvss_contribution == 10

    def test_cvss_near_severity_floor_small_bonus(self):
        result = RiskCalculator.calculate_finding(
            SeverityLevel.CRITICAL, cvss_score=9.0,
        )
        assert result.cvss_contribution == 4

    def test_cvss_contribution_adds_to_total(self):
        result = RiskCalculator.calculate_finding(
            severity=SeverityLevel.HIGH,
            attack_vector="network",
            status=FindingStatus.CONFIRMED,
            compliance_count=2,
            cvss_score=9.5,
        )
        assert result.cvss_contribution == 20
        assert result.score > 80

    @staticmethod
    def test_cvss_weight_method():
        assert RiskCalculator._cvss_weight(None, SeverityLevel.HIGH) == 0
        assert RiskCalculator._cvss_weight(0.0, SeverityLevel.HIGH) == 0
        assert RiskCalculator._cvss_weight(9.5, SeverityLevel.LOW) == 20
        assert RiskCalculator._cvss_weight(4.0, SeverityLevel.MEDIUM) == 4


# ===================================================================
# Confidence level weighting
# ===================================================================

class TestConfidenceLevelWeighting:
    """ConfidenceLevel parameter for risk calculation."""

    def test_confidence_confirmed_highest(self):
        from app.services.risk_engine.models import ConfidenceLevel
        r = RiskCalculator.calculate_finding(
            SeverityLevel.LOW, confidence=ConfidenceLevel.CONFIRMED,
        )
        assert r.confidence_weight == 20

    def test_confidence_low_lowest(self):
        from app.services.risk_engine.models import ConfidenceLevel
        r = RiskCalculator.calculate_finding(
            SeverityLevel.LOW, confidence=ConfidenceLevel.LOW,
        )
        assert r.confidence_weight == 3

    def test_confidence_overrides_status(self):
        from app.services.risk_engine.models import ConfidenceLevel
        r = RiskCalculator.calculate_finding(
            SeverityLevel.LOW,
            confidence=ConfidenceLevel.LOW,
            status=FindingStatus.CONFIRMED,
        )
        assert r.confidence_weight == 3

    def test_no_confidence_falls_back_to_status(self):
        r = RiskCalculator.calculate_finding(
            SeverityLevel.LOW, status=FindingStatus.CONFIRMED,
        )
        assert r.confidence_weight == 20


# ===================================================================
# Grade calculation
# ===================================================================

class TestGradeCalculation:
    """Security grade A+ through F mapping."""

    def test_grade_a_plus(self):
        from app.services.risk_engine.grade_calculator import calculate_grade
        from app.services.risk_engine.models import SecurityGrade
        assert calculate_grade(100) == SecurityGrade.A_PLUS
        assert calculate_grade(99) == SecurityGrade.A_PLUS
        assert calculate_grade(95) == SecurityGrade.A_PLUS

    def test_grade_a(self):
        from app.services.risk_engine.grade_calculator import calculate_grade
        from app.services.risk_engine.models import SecurityGrade
        assert calculate_grade(94) == SecurityGrade.A
        assert calculate_grade(85) == SecurityGrade.A

    def test_grade_b(self):
        from app.services.risk_engine.grade_calculator import calculate_grade
        from app.services.risk_engine.models import SecurityGrade
        assert calculate_grade(84) == SecurityGrade.B
        assert calculate_grade(75) == SecurityGrade.B

    def test_grade_c(self):
        from app.services.risk_engine.grade_calculator import calculate_grade
        from app.services.risk_engine.models import SecurityGrade
        assert calculate_grade(74) == SecurityGrade.C
        assert calculate_grade(60) == SecurityGrade.C

    def test_grade_d(self):
        from app.services.risk_engine.grade_calculator import calculate_grade
        from app.services.risk_engine.models import SecurityGrade
        assert calculate_grade(59) == SecurityGrade.D
        assert calculate_grade(40) == SecurityGrade.D

    def test_grade_f(self):
        from app.services.risk_engine.grade_calculator import calculate_grade
        from app.services.risk_engine.models import SecurityGrade
        assert calculate_grade(39) == SecurityGrade.F
        assert calculate_grade(0) == SecurityGrade.F

    def test_grade_description_returns_string(self):
        from app.services.risk_engine.grade_calculator import grade_description
        from app.services.risk_engine.models import SecurityGrade
        for grade in SecurityGrade:
            desc = grade_description(grade)
            assert isinstance(desc, str)
            assert len(desc) > 10


# ===================================================================
# Compliance scoring
# ===================================================================

class TestComplianceScoring:
    """Framework compliance posture calculation."""

    def test_single_framework_all_passed(self):
        from app.services.risk_engine.compliance_scorer import calculate_compliance_posture
        posture = calculate_compliance_posture("owasp", 10, 10)
        assert posture.compliance_percentage == 100.0
        assert posture.passed_controls == 10
        assert posture.failed_controls == 0

    def test_single_framework_some_failed(self):
        from app.services.risk_engine.compliance_scorer import calculate_compliance_posture
        posture = calculate_compliance_posture("nist", 10, 6)
        assert posture.compliance_percentage == 60.0
        assert posture.failed_controls == 4

    def test_single_framework_zero_controls(self):
        from app.services.risk_engine.compliance_scorer import calculate_compliance_posture
        posture = calculate_compliance_posture("cis", 0, 0)
        assert posture.compliance_percentage == 100.0
        assert posture.failed_controls == 0

    def test_calculate_all_postures_no_findings(self):
        from app.services.risk_engine.compliance_scorer import calculate_all_postures
        assert calculate_all_postures([]) == {}

    def test_calculate_all_postures_with_findings(self):
        from app.services.risk_engine.compliance_scorer import calculate_all_postures
        findings = [
            {
                "compliance": [{"framework": "owasp", "control_id": "A1"}],
                "passed": False,
                "status": "new",
            },
            {
                "compliance": [{"framework": "nist", "control_id": "ID.AM-1"}],
                "passed": True,
            },
            {
                "compliance": [
                    {"framework": "owasp", "control_id": "A2"},
                    {"framework": "cis", "control_id": "4.1"},
                ],
                "passed": False,
                "status": "fixed",
            },
        ]
        postures = calculate_all_postures(findings)
        assert "owasp" in postures
        assert "nist" in postures
        assert "cis" in postures
        assert postures["owasp"].compliance_percentage == 50.0
        assert postures["nist"].compliance_percentage == 100.0
        assert postures["cis"].compliance_percentage == 100.0

    def test_overall_compliance_score_average(self):
        from app.services.risk_engine.compliance_scorer import (
            calculate_compliance_posture,
            overall_compliance_score,
        )
        postures = {
            "owasp": calculate_compliance_posture("owasp", 10, 10),
            "nist": calculate_compliance_posture("nist", 10, 5),
        }
        assert overall_compliance_score(postures) == 75.0

    def test_overall_compliance_score_empty(self):
        from app.services.risk_engine.compliance_scorer import overall_compliance_score
        assert overall_compliance_score({}) == 100.0


# ===================================================================
# Explanation engine
# ===================================================================

class TestExplanationEngine:
    """Deterministic risk explanation generation."""

    def test_explanation_contains_required_fields(self):
        from app.services.risk_engine.explanation_engine import generate_explanation
        from app.models.enums import SeverityLevel
        exp = generate_explanation("Missing CSP", SeverityLevel.HIGH, None)
        assert exp.finding_title == "Missing CSP"
        assert exp.finding_severity == "high"
        assert len(exp.why_it_matters) > 20
        assert len(exp.impact) > 10
        assert len(exp.priority) > 10
        assert len(exp.recommended_remediation) > 10

    def test_critical_severity_explanation(self):
        from app.services.risk_engine.explanation_engine import generate_explanation
        from app.models.enums import SeverityLevel
        exp = generate_explanation("RCE", SeverityLevel.CRITICAL, None)
        assert "immediately exploitable" in exp.why_it_matters.lower()

    def test_explanation_with_confidence(self):
        from app.services.risk_engine.explanation_engine import generate_explanation
        from app.services.risk_engine.models import ConfidenceLevel
        from app.models.enums import SeverityLevel
        exp = generate_explanation("XSS", SeverityLevel.HIGH, ConfidenceLevel.CONFIRMED)
        assert "immediate" in exp.priority.lower()

    def test_explanation_with_remediation_hint(self):
        from app.services.risk_engine.explanation_engine import generate_explanation
        from app.models.enums import SeverityLevel
        exp = generate_explanation("Custom", SeverityLevel.MEDIUM, None, remediation_hint="Apply patch ABC")
        assert "Apply patch ABC" in exp.recommended_remediation

    def test_explanation_type_based_remediation(self):
        from app.services.risk_engine.explanation_engine import generate_explanation
        from app.models.enums import SeverityLevel
        exp = generate_explanation("Weak Cipher Detected", SeverityLevel.HIGH, None, finding_type="weak_cipher")
        assert "cipher" in exp.recommended_remediation.lower()


# ===================================================================
# Intelligence Engine
# ===================================================================

class TestIntelligenceEngine:
    """End-to-end intelligence engine orchestrator."""

    def test_process_finding_returns_risk_result(self):
        from app.services.risk_engine.models import ConfidenceLevel
        engine = IntelligenceEngine()
        result = engine.process_finding(
            severity=SeverityLevel.CRITICAL,
            confidence=ConfidenceLevel.CONFIRMED,
        )
        assert result.score > 0
        assert result.level is not None

    def test_process_asset_empty_returns_grade_f(self):
        engine = IntelligenceEngine()
        report = engine.process_asset([])
        assert report.total_findings == 0
        assert report.security_score == 0.0
        assert report.security_grade.value == "F"
        assert report.risk_level == "info"

    def test_process_asset_with_findings(self):
        engine = IntelligenceEngine()
        findings = [
            {
                "severity": SeverityLevel.CRITICAL,
                "attack_vector": "network",
                "title": "SQL Injection",
                "finding_type": "injection",
            },
            {
                "severity": SeverityLevel.LOW,
                "attack_vector": "local",
                "title": "Info Leak",
                "finding_type": "disclosure",
            },
        ]
        report = engine.process_asset(findings)
        assert report.total_findings == 2
        assert report.security_grade.value in ("F", "D", "C")
        assert len(report.top_risks) == 2
        assert report.top_risks[0].finding_severity <= report.top_risks[1].finding_severity

    def test_process_asset_generates_explanations(self):
        engine = IntelligenceEngine()
        findings = [
            {
                "severity": SeverityLevel.CRITICAL,
                "title": "Remote Code Execution",
                "finding_type": "rce",
            },
        ]
        report = engine.process_asset(findings)
        assert len(report.top_risks) == 1
        assert "Remote Code Execution" in report.top_risks[0].finding_title

    def test_compliance_posture_in_report(self):
        engine = IntelligenceEngine()
        findings = [
            {
                "severity": SeverityLevel.HIGH,
                "compliance": [{"framework": "owasp", "control_id": "A1"}],
                "passed": False,
            },
        ]
        report = engine.process_asset(findings)
        assert "owasp" in report.compliance_posture
        assert report.compliance_posture["owasp"].compliance_percentage == 0.0

    def test_finding_breakdown_in_report(self):
        engine = IntelligenceEngine()
        findings = [
            {"severity": SeverityLevel.CRITICAL},
            {"severity": SeverityLevel.HIGH},
            {"severity": SeverityLevel.HIGH},
            {"severity": SeverityLevel.INFO},
        ]
        report = engine.process_asset(findings)
        assert sum(report.finding_breakdown.values()) == 4
