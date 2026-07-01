"""Tests for the Compliance Control Engine."""

import pytest

from app.services.compliance_engine import (
    AssessmentState,
    ControlAssessment,
    FrameworkAssessment,
    ComplianceAssessmentReport,
    FRAMEWORK_REGISTRY,
    get_control,
    get_framework,
    list_frameworks,
    assess_findings,
    assess_findings_for_framework,
    calculate_framework_score,
    calculate_all_scores,
    build_report,
)


# ===================================================================
# Framework registry
# ===================================================================

class TestFrameworkRegistry:
    """Framework and control definitions."""

    def test_all_38_frameworks_defined(self):
        assert len(FRAMEWORK_REGISTRY) == 38

    def test_expected_frameworks_present(self):
        expected = {
            "owasp", "owasp_asvs", "owasp_api",
            "nist", "nist_80053",
            "cis", "iso_27001", "pci_dss",
            "gdpr", "ccpa", "hipaa", "soc2", "coppa",
            "cwe_top_25",
            "http_sec", "tls_sec", "dns_sec", "cookie_sec",
            "owasp_mobile", "owasp_supply_chain", "owasp_headers",
            "owasp_proactive", "owasp_cheatsheets",
            "sans_top_25",
            "mitre_attack", "mitre_d3fend",
            "csa_ccm", "fedramp",
            "nist_privacy", "nist_ssdf",
            "iso_27701", "iso_22301",
            "eprivacy", "eu_cookie",
            "lgpd", "dpdp", "au_privacy", "cpra_expanded",
        }
        assert set(FRAMEWORK_REGISTRY.keys()) == expected

    def test_get_framework_returns_definition(self):
        fw = get_framework("owasp")
        assert fw is not None
        assert fw.name == "OWASP Top 10"
        assert fw.version == "2021"

    def test_get_framework_nonexistent(self):
        assert get_framework("nonexistent") is None

    def test_framework_has_controls(self):
        for key, fw in FRAMEWORK_REGISTRY.items():
            assert len(fw.controls) >= 3, f"{key} has fewer than 3 controls"

    def test_get_control_returns_definition(self):
        ctrl = get_control("owasp", "A01")
        assert ctrl is not None
        assert ctrl.control_id == "A01"
        assert ctrl.title == "Broken Access Control"

    def test_get_control_nonexistent_framework(self):
        assert get_control("nonexistent", "A1") is None

    def test_get_control_nonexistent_control(self):
        assert get_control("owasp", "Z99") is None

    def test_list_frameworks_returns_all(self):
        frameworks = list_frameworks()
        assert len(frameworks) == 38

    def test_framework_has_description(self):
        for fw in list_frameworks():
            assert len(fw.description) > 10


# ===================================================================
# Assessment engine
# ===================================================================

class TestAssessmentEngine:
    """Finding-to-control mapping and assessment states."""

    def test_empty_findings_returns_empty(self):
        assert assess_findings([]) == []

    def test_findings_without_compliance_mappings(self):
        findings = [{"severity": "high", "title": "Missing Header"}]
        assert assess_findings(findings) == []

    def test_single_finding_pass_state(self):
        findings = [{
            "compliance": [{"framework": "owasp", "control_id": "A5"}],
            "passed": True,
            "status": "fixed",
        }]
        results = assess_findings(findings)
        assert len(results) == 1
        assert results[0].state == AssessmentState.PASS
        assert results[0].control_id == "A5"
        assert results[0].framework == "owasp"

    def test_single_finding_fail_state(self):
        findings = [{
            "compliance": [{"framework": "owasp", "control_id": "A3"}],
            "passed": False,
            "status": "new",
        }]
        results = assess_findings(findings)
        assert len(results) == 1
        assert results[0].state == AssessmentState.FAIL

    def test_mixed_findings_partial_state(self):
        findings = [
            {
                "compliance": [{"framework": "nist", "control_id": "PR.PS"}],
                "passed": True,
                "status": "fixed",
            },
            {
                "compliance": [{"framework": "nist", "control_id": "PR.PS"}],
                "passed": False,
                "status": "new",
            },
        ]
        results = assess_findings(findings)
        assert len(results) == 1
        assert results[0].state == AssessmentState.PARTIAL

    def test_multiple_frameworks_in_results(self):
        findings = [
            {
                "compliance": [{"framework": "owasp", "control_id": "A1"}],
                "passed": False,
            },
            {
                "compliance": [{"framework": "nist", "control_id": "PR.AC"}],
                "passed": True,
            },
        ]
        results = assess_findings(findings)
        frameworks = {r.framework for r in results}
        assert "owasp" in frameworks
        assert "nist" in frameworks

    def test_unknown_framework_ignored(self):
        findings = [{
            "compliance": [{"framework": "unknown_fw", "control_id": "X1"}],
            "passed": False,
        }]
        assert assess_findings(findings) == []

    def test_unknown_control_ignored(self):
        findings = [{
            "compliance": [{"framework": "owasp", "control_id": "Z99"}],
            "passed": False,
        }]
        assert assess_findings(findings) == []

    def test_finding_with_multiple_compliance_mappings(self):
        findings = [{
            "compliance": [
                {"framework": "owasp", "control_id": "A3"},
                {"framework": "nist", "control_id": "PR.DS"},
            ],
            "passed": False,
        }]
        results = assess_findings(findings)
        assert len(results) == 2

    def test_assess_for_single_framework(self):
        findings = [
            {
                "compliance": [{"framework": "owasp", "control_id": "A1"}],
                "passed": False,
            },
            {
                "compliance": [{"framework": "nist", "control_id": "PR.AC"}],
                "passed": True,
            },
        ]
        results = assess_findings_for_framework(findings, "owasp")
        assert len(results) == 1
        assert results[0].framework == "owasp"

    def test_orm_style_object_assessment(self):
        class FakeFinding:
            compliance = [{"framework": "iso_27001", "control_id": "A.8.24"}]
            passed = False
            status = "new"

        results = assess_findings([FakeFinding()])
        assert len(results) == 1
        assert results[0].state == AssessmentState.FAIL

    def test_accepted_risk_counts_as_pass(self):
        findings = [{
            "compliance": [{"framework": "owasp", "control_id": "A2"}],
            "passed": False,
            "status": "accepted_risk",
        }]
        results = assess_findings(findings)
        assert results[0].state == AssessmentState.PASS


# ===================================================================
# Score calculator
# ===================================================================

class TestScoreCalculator:
    """Compliance percentage calculation per framework."""

    def test_calculate_framework_all_pass(self):
        assessments = [
            ControlAssessment("A1", "Test Control 1", "owasp", "test", AssessmentState.PASS),
            ControlAssessment("A2", "Test Control 2", "owasp", "test", AssessmentState.PASS),
        ]
        result = calculate_framework_score(assessments)
        assert result is not None
        assert result.score == 100.0
        assert result.passed == 2
        assert result.failed == 0

    def test_calculate_framework_all_fail(self):
        assessments = [
            ControlAssessment("A1", "Test", "owasp", "test", AssessmentState.FAIL),
            ControlAssessment("A2", "Test", "owasp", "test", AssessmentState.FAIL),
        ]
        result = calculate_framework_score(assessments)
        assert result.score == 0.0

    def test_calculate_framework_mixed(self):
        assessments = [
            ControlAssessment("A1", "Pass", "nist", "protect", AssessmentState.PASS),
            ControlAssessment("A2", "Fail", "nist", "protect", AssessmentState.FAIL),
            ControlAssessment("A3", "Partial", "nist", "protect", AssessmentState.PARTIAL),
        ]
        result = calculate_framework_score(assessments)
        # (1.0 + 0.5) / 3 = 0.5 → 50.0
        assert result.score == 50.0
        assert result.passed == 1
        assert result.failed == 1
        assert result.partial == 1

    def test_calculate_framework_not_applicable_excluded(self):
        assessments = [
            ControlAssessment("A1", "Pass", "owasp", "test", AssessmentState.PASS),
            ControlAssessment("A2", "NA", "owasp", "test", AssessmentState.NOT_APPLICABLE),
        ]
        result = calculate_framework_score(assessments)
        assert result.assessed_controls == 1
        assert result.score == 100.0

    def test_empty_assessments_returns_none(self):
        assert calculate_framework_score([]) is None

    def test_calculate_all_scores_groups_by_framework(self):
        assessments = [
            ControlAssessment("A1", "", "owasp", "", AssessmentState.PASS),
            ControlAssessment("C1", "", "nist", "", AssessmentState.FAIL),
            ControlAssessment("A2", "", "owasp", "", AssessmentState.FAIL),
        ]
        results = calculate_all_scores(assessments)
        assert len(results) == 2
        scores = {r.framework_key: r.score for r in results}
        assert "owasp" in scores
        assert "nist" in scores

    def test_build_report_returns_structured_output(self):
        assessments = [
            ControlAssessment("A1", "C1", "owasp", "test", AssessmentState.PASS),
            ControlAssessment("C1", "C2", "nist", "test", AssessmentState.FAIL),
        ]
        report = build_report(assessments)
        assert isinstance(report, ComplianceAssessmentReport)
        assert len(report.assessments) == 2
        assert 0 <= report.overall_score <= 100

    def test_build_report_empty_assessments(self):
        report = build_report([])
        assert report.assessments == []
        assert report.overall_score == 100.0


# ===================================================================
# End-to-end compliance assessment
# ===================================================================

class TestCompliancePipeline:
    """Full pipeline: findings → assessments → scores → report."""

    def test_full_pipeline_with_real_framework_mappings(self):
        findings = [
            {
                "compliance": [{"framework": "owasp", "control_id": "A3"}],
                "passed": False,
                "status": "new",
                "title": "Missing CSP",
            },
            {
                "compliance": [{"framework": "nist", "control_id": "PR.DS"}],
                "passed": False,
                "status": "open",
                "title": "Weak TLS",
            },
            {
                "compliance": [
                    {"framework": "owasp", "control_id": "A5"},
                    {"framework": "cis", "control_id": "4"},
                ],
                "passed": True,
                "status": "fixed",
                "title": "Server Version Disclosure",
            },
        ]
        assessments = assess_findings(findings)
        assert len(assessments) == 4

        report = build_report(assessments)
        assert len(report.assessments) == 3

        fw_scores = {a.framework_key: a.score for a in report.assessments}
        assert "owasp" in fw_scores
        assert "nist" in fw_scores
        assert "cis" in fw_scores

        # OWASP: A3=FAIL, A5=PASS → (0+1)/2 = 50%
        assert fw_scores["owasp"] == 50.0

        # NIST: PR.DS=FAIL → 0%
        assert fw_scores["nist"] == 0.0

        # CIS: 4=PASS → 100%
        assert fw_scores["cis"] == 100.0

    def test_pci_dss_mapping(self):
        findings = [{
            "compliance": [{"framework": "pci_dss", "control_id": "4.1"}],
            "passed": False,
            "status": "new",
        }]
        assessments = assess_findings(findings)
        assert len(assessments) == 1
        assert assessments[0].control_id == "4.1"
        assert assessments[0].state == AssessmentState.FAIL

    def test_gdpr_mapping(self):
        findings = [{
            "compliance": [{"framework": "gdpr", "control_id": "Art.32"}],
            "passed": True,
        }]
        assessments = assess_findings(findings)
        assert len(assessments) == 1
        assert assessments[0].state == AssessmentState.PASS

    def test_hipaa_ccpa_soc2_mappings(self):
        findings = [
            {
                "compliance": [{"framework": "hipaa", "control_id": "164.312(e)(1)"}],
                "passed": False,
            },
            {
                "compliance": [{"framework": "ccpa", "control_id": "1798.130"}],
                "passed": True,
            },
            {
                "compliance": [{"framework": "soc2", "control_id": "CC6.7"}],
                "passed": True,
            },
        ]
        assessments = assess_findings(findings)
        frameworks = {a.framework for a in assessments}
        assert "hipaa" in frameworks
        assert "ccpa" in frameworks
        assert "soc2" in frameworks

    def test_owasp_asvs_mapping(self):
        findings = [{
            "compliance": [{"framework": "owasp_asvs", "control_id": "V9"}],
            "passed": False,
        }]
        assessments = assess_findings(findings)
        assert len(assessments) == 1

    def test_iso_27001_mapping(self):
        findings = [{
            "compliance": [{"framework": "iso_27001", "control_id": "A.8.24"}],
            "passed": False,
        }]
        assessments = assess_findings(findings)
        assert len(assessments) == 1
        assert assessments[0].framework == "iso_27001"

    def test_all_10_frameworks_in_report(self):
        findings = []
        for fw_key in FRAMEWORK_REGISTRY:
            findings.append({
                "compliance": [{"framework": fw_key, "control_id": FRAMEWORK_REGISTRY[fw_key].controls[0].control_id}],
                "passed": True,
            })
        assessments = assess_findings(findings)
        report = build_report(assessments)
        assert len(report.assessments) == 38
