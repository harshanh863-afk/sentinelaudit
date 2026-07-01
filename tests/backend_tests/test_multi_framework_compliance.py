"""Tests for multi-framework compliance assessment covering all 38 frameworks."""

import pytest
from app.services.compliance_engine import (
    FRAMEWORK_REGISTRY, assess_findings, build_report,
    calculate_all_scores, ControlAssessment, AssessmentState,
    calculate_framework_score,
)


PHASE_B_FRAMEWORKS = [
    "owasp_mobile", "owasp_supply_chain", "owasp_headers",
    "owasp_proactive", "owasp_cheatsheets",
    "sans_top_25",
    "mitre_attack", "mitre_d3fend",
    "csa_ccm", "fedramp",
    "nist_privacy", "nist_ssdf",
    "iso_27701", "iso_22301",
    "eprivacy", "eu_cookie",
    "lgpd", "dpdp", "au_privacy", "cpra_expanded",
]


class TestMultiFrameworkCompliance:
    """Validates compliance assessment across all 38 frameworks."""

    def test_all_38_frameworks_have_minimum_controls(self):
        counts = {}
        for key, fw in FRAMEWORK_REGISTRY.items():
            counts[key] = len(fw.controls)
        for key, count in counts.items():
            assert count >= 3, f"{key} has only {count} controls"

    def test_phase_b_frameworks_all_present(self):
        for key in PHASE_B_FRAMEWORKS:
            assert key in FRAMEWORK_REGISTRY, f"Missing Phase B framework: {key}"

    def test_phase_b_frameworks_have_descriptions(self):
        for key in PHASE_B_FRAMEWORKS:
            fw = FRAMEWORK_REGISTRY[key]
            assert len(fw.description) > 10, f"{key} has short or empty description"

    def test_phase_b_frameworks_have_version(self):
        for key in PHASE_B_FRAMEWORKS:
            fw = FRAMEWORK_REGISTRY[key]
            assert fw.version, f"{key} has no version"

    def test_assess_all_38_frameworks_single_finding(self):
        findings = []
        for fw_key in FRAMEWORK_REGISTRY:
            ctrl = FRAMEWORK_REGISTRY[fw_key].controls[0]
            findings.append({
                "compliance": [{"framework": fw_key, "control_id": ctrl.control_id}],
                "passed": True,
                "status": "fixed",
            })
        assessments = assess_findings(findings)
        report = build_report(assessments)
        assert len(report.assessments) == 38

    def test_all_scores_100_when_all_pass(self):
        findings = []
        for fw_key in FRAMEWORK_REGISTRY:
            ctrl = FRAMEWORK_REGISTRY[fw_key].controls[0]
            findings.append({
                "compliance": [{"framework": fw_key, "control_id": ctrl.control_id}],
                "passed": True,
                "status": "fixed",
            })
        assessments = assess_findings(findings)
        scores = calculate_all_scores(assessments)
        for s in scores:
            assert s.score == 100.0, f"{s.framework_key} score {s.score} != 100"

    def test_all_scores_0_when_all_fail(self):
        findings = []
        for fw_key in FRAMEWORK_REGISTRY:
            ctrl = FRAMEWORK_REGISTRY[fw_key].controls[0]
            findings.append({
                "compliance": [{"framework": fw_key, "control_id": ctrl.control_id}],
                "passed": False,
                "status": "new",
            })
        assessments = assess_findings(findings)
        scores = calculate_all_scores(assessments)
        for s in scores:
            assert s.score == 0.0, f"{s.framework_key} score {s.score} != 0"

    def test_all_frameworks_respond_to_single_control(self):
        for fw_key in FRAMEWORK_REGISTRY:
            ctrl = FRAMEWORK_REGISTRY[fw_key].controls[0]
            assessments = assess_findings([{
                "compliance": [{"framework": fw_key, "control_id": ctrl.control_id}],
                "passed": True,
                "status": "fixed",
            }])
            assert len(assessments) == 1, f"{fw_key} returned {len(assessments)} assessments"
            assert assessments[0].framework == fw_key
            assert assessments[0].control_id == ctrl.control_id
            assert assessments[0].state == AssessmentState.PASS

    def test_mitre_attack_techniques_assessable(self):
        fw = FRAMEWORK_REGISTRY.get("mitre_attack")
        assert fw is not None
        web_techs = [c for c in fw.controls if "web" in c.category.lower() or "T" in c.control_id]
        assert len(web_techs) >= 2

    def test_owasp_mobile_controls_assessable(self):
        fw = FRAMEWORK_REGISTRY.get("owasp_mobile")
        assert fw is not None
        assert len(fw.controls) >= 8

    def test_owasp_supply_chain_controls(self):
        fw = FRAMEWORK_REGISTRY.get("owasp_supply_chain")
        assert fw is not None
        assert len(fw.controls) >= 3

    def test_owasp_headers_controls(self):
        fw = FRAMEWORK_REGISTRY.get("owasp_headers")
        assert fw is not None
        assert len(fw.controls) >= 5

    def test_sans_top_25_controls(self):
        fw = FRAMEWORK_REGISTRY.get("sans_top_25")
        assert fw is not None
        assert len(fw.controls) >= 20

    def test_csa_ccm_controls(self):
        fw = FRAMEWORK_REGISTRY.get("csa_ccm")
        assert fw is not None
        assert len(fw.controls) >= 5

    def test_fedramp_controls(self):
        fw = FRAMEWORK_REGISTRY.get("fedramp")
        assert fw is not None
        assert len(fw.controls) >= 5

    def test_nist_privacy_controls(self):
        fw = FRAMEWORK_REGISTRY.get("nist_privacy")
        assert fw is not None
        assert len(fw.controls) >= 5

    def test_nist_ssdf_controls(self):
        fw = FRAMEWORK_REGISTRY.get("nist_ssdf")
        assert fw is not None
        assert len(fw.controls) >= 5

    def test_iso_27701_controls(self):
        fw = FRAMEWORK_REGISTRY.get("iso_27701")
        assert fw is not None
        assert len(fw.controls) >= 5

    def test_iso_22301_controls(self):
        fw = FRAMEWORK_REGISTRY.get("iso_22301")
        assert fw is not None
        assert len(fw.controls) >= 4

    def test_eprivacy_controls(self):
        fw = FRAMEWORK_REGISTRY.get("eprivacy")
        assert fw is not None
        assert len(fw.controls) >= 3

    def test_eu_cookie_controls(self):
        fw = FRAMEWORK_REGISTRY.get("eu_cookie")
        assert fw is not None
        assert len(fw.controls) >= 3

    def test_lgpd_controls(self):
        fw = FRAMEWORK_REGISTRY.get("lgpd")
        assert fw is not None
        assert len(fw.controls) >= 3

    def test_dpdp_controls(self):
        fw = FRAMEWORK_REGISTRY.get("dpdp")
        assert fw is not None
        assert len(fw.controls) >= 3

    def test_au_privacy_controls(self):
        fw = FRAMEWORK_REGISTRY.get("au_privacy")
        assert fw is not None
        assert len(fw.controls) >= 3

    def test_cpra_expanded_controls(self):
        fw = FRAMEWORK_REGISTRY.get("cpra_expanded")
        assert fw is not None
        assert len(fw.controls) >= 3

    def test_mitre_d3fend_controls(self):
        fw = FRAMEWORK_REGISTRY.get("mitre_d3fend")
        assert fw is not None
        assert len(fw.controls) >= 3

    def test_owasp_proactive_controls(self):
        fw = FRAMEWORK_REGISTRY.get("owasp_proactive")
        assert fw is not None
        assert len(fw.controls) >= 5

    def test_owasp_cheatsheets_controls(self):
        fw = FRAMEWORK_REGISTRY.get("owasp_cheatsheets")
        assert fw is not None
        assert len(fw.controls) >= 3

    def test_total_control_count(self):
        total = sum(len(fw.controls) for fw in FRAMEWORK_REGISTRY.values())
        assert total >= 267

    def test_all_controls_have_ids(self):
        for key, fw in FRAMEWORK_REGISTRY.items():
            for ctrl in fw.controls:
                assert ctrl.control_id, f"{key} control missing control_id"
                assert ctrl.title, f"{key} control {ctrl.control_id} missing title"

    def test_phase_b_frameworks_have_categories(self):
        for key in PHASE_B_FRAMEWORKS:
            fw = FRAMEWORK_REGISTRY[key]
            for ctrl in fw.controls:
                assert ctrl.category, f"{key}/{ctrl.control_id} missing category"

    def test_score_calculation_with_mixed_results(self):
        assessments = [
            ControlAssessment("C1", "Test", "owasp_mobile", "mobile", AssessmentState.PASS),
            ControlAssessment("C2", "Test", "owasp_mobile", "mobile", AssessmentState.FAIL),
            ControlAssessment("C3", "Test", "owasp_mobile", "mobile", AssessmentState.PARTIAL),
        ]
        result = calculate_framework_score(assessments)
        assert result is not None
        assert result.score == 50.0
        assert result.passed == 1
        assert result.failed == 1
        assert result.partial == 1
