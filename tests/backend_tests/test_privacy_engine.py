"""Tests for the Privacy Assessment Engine."""

import pytest
from app.services.privacy_engine import PrivacyAssessmentEngine
from app.services.privacy_engine.models import PrivacyAssessmentReport, PrivacyIssue


class TestPrivacyAssessmentEngine:
    """Tests for PrivacyAssessmentEngine — cookie, GDPR, CCPA, COPPA assessment."""

    def test_empty_findings_produces_report(self):
        engine = PrivacyAssessmentEngine(findings=[], scan_evidence={})
        report = engine.assess()
        assert isinstance(report, PrivacyAssessmentReport)
        assert report.score < 100.0  # default privacy issues exist
        assert report.failed_controls >= 0

    def test_cookie_secure_passed_when_secure_found(self):
        findings = [{"category": "cookie_security", "detail": "Secure flag present"}]
        engine = PrivacyAssessmentEngine(findings=findings)
        report = engine.assess()
        cookie_issue = next((i for i in report.issues if i.issue_id == "PRIV-COOKIE-2"), None)
        assert cookie_issue is not None
        assert cookie_issue.passed is True

    def test_cookie_secure_failed_when_secure_missing(self):
        engine = PrivacyAssessmentEngine(findings=[], scan_evidence={})
        report = engine.assess()
        cookie_issue = next((i for i in report.issues if i.issue_id == "PRIV-COOKIE-2"), None)
        assert cookie_issue is not None
        assert cookie_issue.passed is False

    def test_hsts_passed_when_hsts_header_present(self):
        findings = [{"id": "HTTP-001", "detail": "Strict-Transport-Security present"}]
        engine = PrivacyAssessmentEngine(findings=findings)
        report = engine.assess()
        hsts_issue = next((i for i in report.issues if i.issue_id == "PRIV-COOKIE-3"), None)
        assert hsts_issue is not None
        assert hsts_issue.passed is True

    def test_http_only_passed_when_http_only_found(self):
        findings = [{"id": "COOKIE-001", "detail": "HttpOnly flag set"}]
        engine = PrivacyAssessmentEngine(findings=findings)
        report = engine.assess()
        http_only = next((i for i in report.issues if i.issue_id == "PRIV-COOKIE-4"), None)
        assert http_only is not None
        assert http_only.passed is True

    def test_gdpr_privacy_policy_passed(self):
        engine = PrivacyAssessmentEngine(findings=[], scan_evidence={"privacy_policy_detected": True})
        report = engine.assess()
        gdpr_priv = next((i for i in report.issues if i.issue_id == "PRIV-GDPR-1"), None)
        assert gdpr_priv is not None
        assert gdpr_priv.passed is True

    def test_gdpr_privacy_policy_failed(self):
        engine = PrivacyAssessmentEngine(findings=[], scan_evidence={"privacy_policy_detected": False})
        report = engine.assess()
        gdpr_priv = next((i for i in report.issues if i.issue_id == "PRIV-GDPR-1"), None)
        assert gdpr_priv is not None
        assert gdpr_priv.passed is False

    def test_gdpr_cookie_banner_passed(self):
        engine = PrivacyAssessmentEngine(findings=[], scan_evidence={"cookie_banner_detected": True})
        report = engine.assess()
        gdpr_banner = next((i for i in report.issues if i.issue_id == "PRIV-GDPR-2"), None)
        assert gdpr_banner is not None
        assert gdpr_banner.passed is True

    def test_gdpr_data_transparency_passed(self):
        engine = PrivacyAssessmentEngine(findings=[], scan_evidence={"data_collection_transparency": True})
        report = engine.assess()
        gdpr_trans = next((i for i in report.issues if i.issue_id == "PRIV-GDPR-3"), None)
        assert gdpr_trans is not None
        assert gdpr_trans.passed is True

    def test_ccpa_opt_out_link_passed(self):
        engine = PrivacyAssessmentEngine(findings=[], scan_evidence={"dns_link_detected": True})
        report = engine.assess()
        ccpa_opt = next((i for i in report.issues if i.issue_id == "PRIV-CCPA-1"), None)
        assert ccpa_opt is not None
        assert ccpa_opt.passed is True

    def test_ccpa_opt_out_failed(self):
        engine = PrivacyAssessmentEngine(findings=[], scan_evidence={"dns_link_detected": False, "opt_out_link_detected": False})
        report = engine.assess()
        ccpa_opt = next((i for i in report.issues if i.issue_id == "PRIV-CCPA-1"), None)
        assert ccpa_opt is not None
        assert ccpa_opt.passed is False

    def test_ccpa_opt_out_alt_key(self):
        engine = PrivacyAssessmentEngine(findings=[], scan_evidence={"opt_out_link_detected": True})
        report = engine.assess()
        ccpa_opt = next((i for i in report.issues if i.issue_id == "PRIV-CCPA-1"), None)
        assert ccpa_opt is not None
        assert ccpa_opt.passed is True

    def test_ccpa_privacy_policy_passed(self):
        engine = PrivacyAssessmentEngine(findings=[], scan_evidence={"privacy_policy_detected": True})
        report = engine.assess()
        ccpa_priv = next((i for i in report.issues if i.issue_id == "PRIV-CCPA-2"), None)
        assert ccpa_priv is not None
        assert ccpa_priv.passed is True

    def test_ccpa_consumer_rights_default_false(self):
        engine = PrivacyAssessmentEngine(findings=[], scan_evidence={})
        report = engine.assess()
        ccpa_rights = next((i for i in report.issues if i.issue_id == "PRIV-CCPA-3"), None)
        assert ccpa_rights is not None
        assert ccpa_rights.passed is False

    def test_coppa_children_privacy_default_false(self):
        engine = PrivacyAssessmentEngine(findings=[], scan_evidence={})
        report = engine.assess()
        coppa = next((i for i in report.issues if i.issue_id == "PRIV-COPPA-1"), None)
        assert coppa is not None
        assert coppa.passed is False

    def test_coppa_children_privacy_passed_with_policy(self):
        engine = PrivacyAssessmentEngine(findings=[], scan_evidence={"targets_children": False})
        report = engine.assess()
        coppa = next((i for i in report.issues if i.issue_id == "PRIV-COPPA-2"), None)
        assert coppa is not None
        assert coppa.passed is True

    def test_coppa_children_privacy_failed(self):
        engine = PrivacyAssessmentEngine(findings=[], scan_evidence={"targets_children": True, "privacy_policy_detected": False})
        report = engine.assess()
        coppa = next((i for i in report.issues if i.issue_id == "PRIV-COPPA-2"), None)
        assert coppa is not None
        assert coppa.passed is False

    def test_gdpr_subscore(self):
        engine = PrivacyAssessmentEngine(findings=[], scan_evidence={"privacy_policy_detected": True, "cookie_banner_detected": True, "data_collection_transparency": True})
        report = engine.assess()
        # GDPR subscore includes cookie issues that reference GDPR; default cookie consent and COPPA-1 always fail
        assert report.gdpr_score > 0

    def test_gdpr_subscore_partial(self):
        engine = PrivacyAssessmentEngine(findings=[], scan_evidence={"privacy_policy_detected": True, "cookie_banner_detected": False, "data_collection_transparency": False})
        report = engine.assess()
        # Only 1 of 8 GDPR-related issues pass (PRIV-GDPR-1)
        assert 0 < report.gdpr_score < 50.0

    def test_ccpa_subscore(self):
        engine = PrivacyAssessmentEngine(findings=[], scan_evidence={"dns_link_detected": True, "privacy_policy_detected": True})
        report = engine.assess()
        assert report.ccpa_score > 0

    def test_cookie_subscore(self):
        findings = [{"category": "cookie_security", "detail": "Secure"}, {"id": "HTTP-001", "detail": "Strict-Transport-Security"}, {"id": "COOKIE-001", "detail": "HttpOnly"}]
        engine = PrivacyAssessmentEngine(findings=findings)
        report = engine.assess()
        assert report.cookie_score > 0

    def test_coppa_subscore(self):
        engine = PrivacyAssessmentEngine(findings=[], scan_evidence={"targets_children": False})
        report = engine.assess()
        assert report.coppa_score > 0

    def test_full_privacy_report_structure(self):
        findings = [{"id": "HTTP-001", "detail": "Strict-Transport-Security present"}]
        evidence = {"privacy_policy_detected": True, "cookie_banner_detected": True}
        engine = PrivacyAssessmentEngine(findings=findings, scan_evidence=evidence)
        report = engine.assess()
        assert isinstance(report.score, float)
        assert isinstance(report.issues, list)
        assert all(isinstance(i, PrivacyIssue) for i in report.issues)
        assert isinstance(report.recommendations, list)
        assert report.passed_controls + report.failed_controls == len(report.issues)

    def test_recommendations_generated_on_failure(self):
        engine = PrivacyAssessmentEngine(findings=[], scan_evidence={})
        report = engine.assess()
        assert len(report.recommendations) > 0

    def test_recommendations_generated_for_hardcoded_failures(self):
        evidence = {"privacy_policy_detected": True, "cookie_banner_detected": True, "data_collection_transparency": True, "dns_link_detected": True, "opt_out_link_detected": True, "targets_children": False}
        findings = [{"category": "cookie_security", "detail": "Secure"}, {"id": "HTTP-001", "detail": "Strict-Transport-Security"}, {"id": "COOKIE-001", "detail": "HttpOnly"}]
        engine = PrivacyAssessmentEngine(findings=findings, scan_evidence=evidence)
        report = engine.assess()
        # PRIV-COOKIE-1 (consent), PRIV-CCPA-3 (rights), PRIV-COPPA-1 (children) are hardcoded failures
        assert len(report.recommendations) >= 2

    def test_cookie_consent_always_tested(self):
        engine = PrivacyAssessmentEngine(findings=[], scan_evidence={})
        report = engine.assess()
        consent = next((i for i in report.issues if i.issue_id == "PRIV-COOKIE-1"), None)
        assert consent is not None
        assert consent.passed is False
        assert "gdpr" in str(consent.affected_regulations).lower()
        assert "eprivacy" in str(consent.affected_regulations).lower()

    def test_issue_has_required_fields(self):
        engine = PrivacyAssessmentEngine(findings=[], scan_evidence={})
        report = engine.assess()
        for issue in report.issues:
            assert issue.issue_id
            assert issue.title
            assert issue.description
            assert issue.severity
            assert issue.category

    def test_report_has_all_subscores(self):
        engine = PrivacyAssessmentEngine(findings=[], scan_evidence={})
        report = engine.assess()
        assert report.gdpr_score >= 0
        assert report.ccpa_score >= 0
        assert report.coppa_score >= 0
        assert report.cookie_score >= 0
