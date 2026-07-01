"""Tests for Phase A: Security Intelligence Expansion.

Tests cover:
  - All 18 frameworks defined in expanded registry
  - Framework metadata (name, version, description)
  - New framework control lookups
  - Rule definition expansion (cvss_score, impact, evidence_description, cwe, capec)
  - CWE and CAPEC reference parsing
  - Finding-to-multiple-framework mappings
  - CVSS score propagation
  - Compliance engine with expanded frameworks
  - Report generation with new fields
"""

import uuid

import pytest
import yaml

from app.models.enums import SeverityLevel
from app.services.compliance_engine import (
    AssessmentState,
    ComplianceAssessmentReport,
    ControlAssessment,
    FRAMEWORK_REGISTRY,
    assess_findings,
    build_report,
    get_control,
    get_framework,
    list_frameworks,
)
from app.services.rule_engine import (
    ComplianceRef,
    CweRef,
    CapecRef,
    FindingBuilder,
    RuleDefinition,
    RuleLoader,
    RuleMatcher,
    ScannerObservation,
)
from app.services.rule_engine.rule_matcher import MatchResult


# ===================================================================
# Expanded Framework Registry Tests
# ===================================================================

class TestExpandedFrameworkRegistry:
    """All 18 frameworks with controls defined."""

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

    @pytest.mark.parametrize("key,expected_name", [
        ("owasp", "OWASP Top 10"),
        ("owasp_asvs", "OWASP Application Security Verification Standard"),
        ("owasp_api", "OWASP API Security Top 10"),
        ("nist", "NIST Cybersecurity Framework"),
        ("nist_80053", "NIST SP 800-53"),
        ("cis", "CIS Critical Security Controls"),
        ("iso_27001", "ISO/IEC 27001"),
        ("pci_dss", "Payment Card Industry Data Security Standard"),
        ("gdpr", "General Data Protection Regulation"),
        ("ccpa", "California Consumer Privacy Act / California Privacy Rights Act"),
        ("hipaa", "Health Insurance Portability and Accountability Act"),
        ("soc2", "Service Organization Control 2"),
        ("coppa", "Children's Online Privacy Protection Act"),
        ("cwe_top_25", "CWE Top 25 Most Dangerous Software Weaknesses"),
        ("http_sec", "HTTP Security Standards"),
        ("tls_sec", "TLS Security Standards"),
        ("dns_sec", "DNS Security Standards"),
        ("cookie_sec", "Cookie Security Standards"),
    ])
    def test_framework_name_and_version(self, key, expected_name):
        fw = get_framework(key)
        assert fw is not None
        assert fw.name == expected_name

    def test_each_framework_has_controls(self):
        for key, fw in FRAMEWORK_REGISTRY.items():
            assert len(fw.controls) >= 3, f"{key} has fewer than 3 controls"

    def test_each_framework_has_description(self):
        for fw in list_frameworks():
            assert len(fw.description) > 10

    def test_new_framework_controls_accessible(self):
        assert get_control("owasp_api", "API1") is not None
        assert get_control("owasp_api", "API10") is not None
        assert get_control("nist_80053", "AC-3") is not None
        assert get_control("nist_80053", "SI-10") is not None
        assert get_control("coppa", "312.2") is not None
        assert get_control("cwe_top_25", "CWE-79") is not None
        assert get_control("cwe_top_25", "CWE-918") is not None
        assert get_control("http_sec", "HDR-1") is not None
        assert get_control("tls_sec", "TLS-1") is not None
        assert get_control("dns_sec", "DNS-1") is not None
        assert get_control("cookie_sec", "COOKIE-1") is not None

    def test_backward_compatible_owasp_ids(self):
        assert get_control("owasp", "A1") is not None
        assert get_control("owasp", "A01") is not None
        assert get_control("owasp", "A5") is not None
        assert get_control("owasp", "A05") is not None
        assert get_control("owasp", "A10") is not None

    def test_nist_sp80053_si10_input_validation(self):
        ctrl = get_control("nist_80053", "SI-10")
        assert ctrl is not None
        assert "input" in ctrl.description.lower()


# ===================================================================
# CWE and CAPEC Knowledge Base Tests
# ===================================================================

class TestCWECAPECKnowledgeBase:
    """CWE Top 25 and CAPEC attack pattern references."""

    def test_cwe_top_25_has_25_controls(self):
        fw = get_framework("cwe_top_25")
        assert fw is not None
        assert len(fw.controls) >= 25

    def test_cwe_79_xss_present(self):
        ctrl = get_control("cwe_top_25", "CWE-79")
        assert ctrl is not None
        assert "Cross-Site" in ctrl.title

    def test_cwe_89_sql_injection_present(self):
        ctrl = get_control("cwe_top_25", "CWE-89")
        assert ctrl is not None
        assert "SQL" in ctrl.title

    def test_cwe_918_ssrf_present(self):
        ctrl = get_control("cwe_top_25", "CWE-918")
        assert ctrl is not None
        assert "SSRF" in ctrl.title or "Server-Side" in ctrl.title

    def test_cwe_352_csrf_present(self):
        ctrl = get_control("cwe_top_25", "CWE-352")
        assert ctrl is not None
        assert "CSRF" in ctrl.title or "Request" in ctrl.title

    def test_cwe_798_hardcoded_credentials_present(self):
        ctrl = get_control("cwe_top_25", "CWE-798")
        assert ctrl is not None
        assert "Hardcoded" in ctrl.title

    def test_cwe_200_information_exposure_present(self):
        ctrl = get_control("cwe_top_25", "CWE-200")
        assert ctrl is not None
        assert "Information" in ctrl.title


# ===================================================================
# Rule Definition Expansion Tests
# ===================================================================

class TestExpandedRuleDefinition:
    """cvss_score, impact, evidence_description, cwe, capec fields."""

    def test_rule_definition_has_new_fields(self):
        rule = RuleDefinition(
            rule_id="TEST-001",
            name="Test Rule",
            category="test",
            severity=SeverityLevel.HIGH,
            description="Test",
            remediation="Fix it",
            cvss_score=7.5,
            impact="Critical impact on data confidentiality",
            evidence_description="Evidence of the vulnerability",
            references=["https://example.com"],
            compliance=[ComplianceRef(framework="owasp", control_id="A1", control_name="Test")],
            cwe=[CweRef(cwe_id="CWE-79", name="XSS")],
            capec=[CapecRef(capec_id="CAPEC-63", name="Cross-Site Scripting")],
        )
        assert rule.cvss_score == 7.5
        assert rule.impact == "Critical impact on data confidentiality"
        assert rule.evidence_description == "Evidence of the vulnerability"
        assert len(rule.cwe) == 1
        assert rule.cwe[0].cwe_id == "CWE-79"
        assert len(rule.capec) == 1
        assert rule.capec[0].capec_id == "CAPEC-63"

    def test_cvss_score_optional_defaults_none(self):
        rule = RuleDefinition(
            rule_id="TEST-002", name="Test", category="test",
            severity=SeverityLevel.LOW, description="", remediation="",
        )
        assert rule.cvss_score is None
        assert rule.cwe == []
        assert rule.capec == []

    def test_cvss_score_float_parsing(self):
        rule = RuleDefinition(
            rule_id="TEST-003", name="CVSS Test", category="test",
            severity=SeverityLevel.CRITICAL, description="", remediation="",
            cvss_score=9.1,
        )
        assert rule.cvss_score == 9.1

    def test_multiple_cwe_refs(self):
        rule = RuleDefinition(
            rule_id="TEST-004", name="Multi-CWE", category="test",
            severity=SeverityLevel.MEDIUM, description="", remediation="",
            cwe=[
                CweRef(cwe_id="CWE-79", name="XSS"),
                CweRef(cwe_id="CWE-89", name="SQL Injection"),
                CweRef(cwe_id="CWE-352", name="CSRF"),
            ],
        )
        assert len(rule.cwe) == 3

    def test_multiple_capec_refs(self):
        rule = RuleDefinition(
            rule_id="TEST-005", name="Multi-CAPEC", category="test",
            severity=SeverityLevel.HIGH, description="", remediation="",
            capec=[
                CapecRef(capec_id="CAPEC-63", name="XSS"),
                CapecRef(capec_id="CAPEC-94", name="MITM"),
            ],
        )
        assert len(rule.capec) == 2


# ===================================================================
# YAML Rule Loading with Expanded Fields
# ===================================================================

class TestYamlRuleLoadingExpanded:
    """Loading YAML rules with cvss, cwe, capec fields."""

    @pytest.fixture
    def expanded_rules_dir(self, tmp_path):
        subdir = tmp_path / "security"
        subdir.mkdir()
        rule_file = subdir / "test_rules.yaml"
        rule_content = {
            "rules": [
                {
                    "id": "HTTP-XSS-001",
                    "name": "Missing XSS Protection",
                    "category": "http_security",
                    "severity": "high",
                    "cvss_score": 7.5,
                    "description": "XSS protection header missing.",
                    "impact": "Attackers can execute arbitrary JavaScript.",
                    "evidence_description": "No X-XSS-Protection header found.",
                    "remediation": "Add security headers.",
                    "references": ["https://example.com/xss"],
                    "compliance": [
                        {"framework": "owasp", "control_id": "A03", "control_name": "Injection"},
                        {"framework": "cwe_top_25", "control_id": "CWE-79", "control_name": "XSS"},
                    ],
                    "cwe": [
                        {"cwe_id": "CWE-79", "name": "Cross-Site Scripting"},
                    ],
                    "capec": [
                        {"capec_id": "CAPEC-63", "name": "Cross-Site Scripting"},
                        {"capec_id": "CAPEC-104", "name": "Cross Zone Scripting"},
                    ],
                },
                {
                    "id": "TLS-WEAK-001",
                    "name": "Weak TLS",
                    "category": "tls_analysis",
                    "severity": "high",
                    "cvss_score": 7.4,
                    "description": "Weak TLS version.",
                    "impact": "Traffic can be decrypted.",
                    "evidence_description": "TLS 1.0 supported.",
                    "remediation": "Disable old TLS.",
                    "compliance": [
                        {"framework": "nist", "control_id": "SC-8", "control_name": "Transmission"},
                    ],
                    "cwe": [
                        {"cwe_id": "CWE-326", "name": "Weak Encryption"},
                    ],
                    "capec": [
                        {"capec_id": "CAPEC-94", "name": "MITM"},
                    ],
                },
            ]
        }
        with open(rule_file, "w", encoding="utf-8") as f:
            yaml.dump(rule_content, f)
        return str(tmp_path)

    def test_load_rules_with_cvss(self, expanded_rules_dir):
        loader = RuleLoader(rules_path=expanded_rules_dir)
        rules = loader.load_all()
        assert len(rules) == 2
        cvss_scores = {r.rule_id: r.cvss_score for r in rules}
        assert cvss_scores["HTTP-XSS-001"] == 7.5
        assert cvss_scores["TLS-WEAK-001"] == 7.4

    def test_load_rules_with_impact_and_evidence(self, expanded_rules_dir):
        loader = RuleLoader(rules_path=expanded_rules_dir)
        rules = {r.rule_id: r for r in loader.load_all()}
        rule = rules["HTTP-XSS-001"]
        assert rule.impact == "Attackers can execute arbitrary JavaScript."
        assert rule.evidence_description == "No X-XSS-Protection header found."

    def test_load_rules_with_cwe_refs(self, expanded_rules_dir):
        loader = RuleLoader(rules_path=expanded_rules_dir)
        rules = {r.rule_id: r for r in loader.load_all()}
        rule = rules["HTTP-XSS-001"]
        assert len(rule.cwe) == 1
        assert rule.cwe[0].cwe_id == "CWE-79"
        assert rule.cwe[0].name == "Cross-Site Scripting"

    def test_load_rules_with_capec_refs(self, expanded_rules_dir):
        loader = RuleLoader(rules_path=expanded_rules_dir)
        rules = {r.rule_id: r for r in loader.load_all()}
        rule = rules["HTTP-XSS-001"]
        assert len(rule.capec) == 2
        capec_ids = {c.capec_id for c in rule.capec}
        assert "CAPEC-63" in capec_ids
        assert "CAPEC-104" in capec_ids

    def test_load_rules_with_cross_framework_compliance(self, expanded_rules_dir):
        loader = RuleLoader(rules_path=expanded_rules_dir)
        rules = {r.rule_id: r for r in loader.load_all()}
        rule = rules["HTTP-XSS-001"]
        frameworks = {c.framework for c in rule.compliance}
        assert "owasp" in frameworks
        assert "cwe_top_25" in frameworks

    def test_rule_without_optional_fields(self, expanded_rules_dir):
        loader = RuleLoader(rules_path=expanded_rules_dir)
        rules = {r.rule_id: r for r in loader.load_all()}
        rule = rules["TLS-WEAK-001"]
        assert len(rule.compliance) == 1
        assert rule.cvss_score == 7.4


# ===================================================================
# FindingBuilder with Expanded Fields
# ===================================================================

class TestFindingBuilderExpanded:
    """cvss_score, cwe, capec propagate from rules to findings."""

    def test_finding_builder_cvss_score(self):
        rule = RuleDefinition(
            rule_id="TEST-001", name="Test", category="test",
            severity=SeverityLevel.HIGH, description="", remediation="",
            cvss_score=7.5,
            cwe=[CweRef(cwe_id="CWE-79", name="XSS")],
            capec=[CapecRef(capec_id="CAPEC-63", name="Cross-Site Scripting")],
        )
        match = MatchResult(matched=True, rule=rule)
        obs = ScannerObservation(check_name="TEST", category="test", passed=False)
        finding = FindingBuilder.build(scan_id=uuid.uuid4(), match=match, observation=obs)

        assert finding is not None
        assert finding.cvss_score == 7.5
        assert len(finding.cwe) == 1
        assert finding.cwe[0]["cwe_id"] == "CWE-79"
        assert len(finding.capec) == 1
        assert finding.capec[0]["capec_id"] == "CAPEC-63"

    def test_finding_builder_no_cvss(self):
        rule = RuleDefinition(
            rule_id="TEST-002", name="Test", category="test",
            severity=SeverityLevel.LOW, description="", remediation="",
        )
        match = MatchResult(matched=True, rule=rule)
        obs = ScannerObservation(check_name="TEST", category="test", passed=True)
        finding = FindingBuilder.build(scan_id=uuid.uuid4(), match=match, observation=obs)

        assert finding is not None
        assert finding.cvss_score is None

    def test_finding_builder_evidence_description_and_impact(self):
        rule = RuleDefinition(
            rule_id="TEST-003", name="Test", category="test",
            severity=SeverityLevel.CRITICAL, description="", remediation="",
            impact="Critical data exposure",
            evidence_description="Evidence of the flaw",
        )
        match = MatchResult(matched=True, rule=rule)
        obs = ScannerObservation(check_name="TEST", category="test", passed=False)
        finding = FindingBuilder.build(scan_id=uuid.uuid4(), match=match, observation=obs)

        assert finding.impact == "Critical data exposure"
        assert finding.evidence_description == "Evidence of the flaw"


# ===================================================================
# Multi-Framework Compliance Mapping Tests
# ===================================================================

class TestMultiFrameworkCompliance:
    """Finding maps to multiple frameworks simultaneously."""

    def test_single_finding_maps_to_multiple_frameworks(self):
        findings = [{
            "compliance": [
                {"framework": "owasp", "control_id": "A05"},
                {"framework": "nist", "control_id": "PR.PS"},
                {"framework": "cis", "control_id": "16"},
                {"framework": "iso_27001", "control_id": "A.8.28"},
                {"framework": "pci_dss", "control_id": "6.1"},
                {"framework": "cwe_top_25", "control_id": "CWE-79"},
                {"framework": "http_sec", "control_id": "HDR-1"},
            ],
            "passed": False,
            "status": "new",
        }]
        results = assess_findings(findings)
        assert len(results) >= 7
        frameworks = {r.framework for r in results}
        assert "owasp" in frameworks
        assert "nist" in frameworks
        assert "cis" in frameworks
        assert "iso_27001" in frameworks
        assert "pci_dss" in frameworks
        assert "cwe_top_25" in frameworks
        assert "http_sec" in frameworks

    def test_same_control_across_multiple_triples(self):
        findings = [
            {
                "compliance": [
                    {"framework": "gdpr", "control_id": "Art.32"},
                    {"framework": "hipaa", "control_id": "164.312(e)(1)"},
                    {"framework": "soc2", "control_id": "CC6.7"},
                ],
                "passed": False,
            },
        ]
        results = assess_findings(findings)
        assert len(results) == 3

    def test_missing_csp_maps_across_all_standards(self):
        """A single finding (Missing CSP) maps to OWASP, NIST, CIS, ISO, CWE."""
        findings = [{
            "compliance": [
                {"framework": "owasp", "control_id": "A05"},
                {"framework": "nist", "control_id": "PR.PS"},
                {"framework": "nist_80053", "control_id": "SI-10"},
                {"framework": "cis", "control_id": "16"},
                {"framework": "iso_27001", "control_id": "A.8.28"},
                {"framework": "pci_dss", "control_id": "6.1"},
                {"framework": "cwe_top_25", "control_id": "CWE-79"},
            ],
            "passed": False,
        }]
        results = assess_findings(findings)
        frameworks = {r.framework for r in results}
        assert len(results) == 7
        assert frameworks == {"owasp", "nist", "nist_80053", "cis", "iso_27001", "pci_dss", "cwe_top_25"}

    def test_finding_no_compliance_returns_empty(self):
        findings = [{"severity": "high", "title": "Something", "passed": False}]
        assert assess_findings(findings) == []

    def test_finding_maps_to_18_frameworks_full_coverage(self):
        """A single finding that touches all 18 frameworks."""
        findings = [{
            "compliance": [
                {"framework": "owasp", "control_id": "A05"},
                {"framework": "owasp_asvs", "control_id": "V14"},
                {"framework": "owasp_api", "control_id": "API8"},
                {"framework": "nist", "control_id": "PR.PS"},
                {"framework": "nist_80053", "control_id": "CM-6"},
                {"framework": "cis", "control_id": "4"},
                {"framework": "iso_27001", "control_id": "A.8.9"},
                {"framework": "pci_dss", "control_id": "2.1"},
                {"framework": "gdpr", "control_id": "Art.32"},
                {"framework": "ccpa", "control_id": "1798.130"},
                {"framework": "hipaa", "control_id": "164.312(a)(1)"},
                {"framework": "soc2", "control_id": "CC6.1"},
                {"framework": "coppa", "control_id": "312.7"},
                {"framework": "cwe_top_25", "control_id": "CWE-200"},
                {"framework": "http_sec", "control_id": "HDR-4"},
                {"framework": "tls_sec", "control_id": "TLS-3"},
                {"framework": "dns_sec", "control_id": "DNS-5"},
                {"framework": "cookie_sec", "control_id": "COOKIE-1"},
            ],
            "passed": False,
        }]
        results = assess_findings(findings)
        assert len(results) == 18


# ===================================================================
# CVSS Integration Tests
# ===================================================================

class TestCVSSIntegration:
    """CVSS score handling throughout the pipeline."""

    def test_cvss_score_in_built_finding(self):
        rule = RuleDefinition(
            rule_id="HTTP-CRIT-001", name="Critical Vuln", category="http_security",
            severity=SeverityLevel.CRITICAL, description="Critical", remediation="Fix",
            cvss_score=9.8,
        )
        match = MatchResult(matched=True, rule=rule)
        obs = ScannerObservation(check_name="HTTP", category="http_security", passed=False)
        finding = FindingBuilder.build(scan_id=uuid.uuid4(), match=match, observation=obs)
        assert finding is not None
        assert finding.cvss_score == 9.8

    def test_cvss_v4_range(self):
        rule = RuleDefinition(
            rule_id="TEST-CVSS4", name="CVSS 4.0", category="test",
            severity=SeverityLevel.CRITICAL, description="", remediation="",
            cvss_score=10.0,
        )
        match = MatchResult(matched=True, rule=rule)
        obs = ScannerObservation(check_name="TEST", category="test", passed=False)
        finding = FindingBuilder.build(scan_id=uuid.uuid4(), match=match, observation=obs)
        assert finding.cvss_score == 10.0

    def test_cvss_score_in_passed_finding(self):
        rule = RuleDefinition(
            rule_id="TEST-PASS", name="Passed Check", category="test",
            severity=SeverityLevel.LOW, description="", remediation="",
            cvss_score=2.1,
        )
        match = MatchResult(matched=True, rule=rule)
        obs = ScannerObservation(check_name="TEST", category="test", passed=True)
        finding = FindingBuilder.build(scan_id=uuid.uuid4(), match=match, observation=obs)
        assert finding.cvss_score == 2.1


# ===================================================================
# Expanded Compliance Assessment Tests
# ===================================================================

class TestExpandedComplianceAssessment:
    """Full compliance pipeline with new frameworks."""

    def test_owasp_api_security_top_10_assessment(self):
        findings = [{
            "compliance": [{"framework": "owasp_api", "control_id": "API1"}],
            "passed": False,
        }]
        results = assess_findings(findings)
        assert len(results) == 1
        assert results[0].framework == "owasp_api"
        assert results[0].state == AssessmentState.FAIL

    def test_nist_sp80053_assessment(self):
        findings = [{
            "compliance": [{"framework": "nist_80053", "control_id": "SI-10"}],
            "passed": True,
        }]
        results = assess_findings(findings)
        assert len(results) == 1
        assert results[0].state == AssessmentState.PASS

    def test_coppa_assessment(self):
        findings = [{
            "compliance": [{"framework": "coppa", "control_id": "312.7"}],
            "passed": False,
        }]
        results = assess_findings(findings)
        assert len(results) == 1
        assert results[0].framework == "coppa"

    def test_cwe_top_25_assessment(self):
        findings = [{
            "compliance": [{"framework": "cwe_top_25", "control_id": "CWE-79"}],
            "passed": False,
        }]
        results = assess_findings(findings)
        assert len(results) == 1
        assert results[0].state == AssessmentState.FAIL

    def test_http_security_standards_assessment(self):
        findings = [{
            "compliance": [{"framework": "http_sec", "control_id": "HDR-1"}],
            "passed": True,
        }]
        results = assess_findings(findings)
        assert len(results) == 1
        assert results[0].framework == "http_sec"

    def test_tls_security_standards_assessment(self):
        findings = [{
            "compliance": [{"framework": "tls_sec", "control_id": "TLS-1"}],
            "passed": False,
        }]
        results = assess_findings(findings)
        assert len(results) == 1
        assert results[0].framework == "tls_sec"

    def test_dns_security_standards_assessment(self):
        findings = [{
            "compliance": [{"framework": "dns_sec", "control_id": "DNS-1"}],
            "passed": True,
        }]
        results = assess_findings(findings)
        assert len(results) == 1
        assert results[0].framework == "dns_sec"

    def test_cookie_security_standards_assessment(self):
        findings = [{
            "compliance": [{"framework": "cookie_sec", "control_id": "COOKIE-1"}],
            "passed": False,
        }]
        results = assess_findings(findings)
        assert len(results) == 1
        assert results[0].framework == "cookie_sec"


# ===================================================================
# Complete Report with All 18 Frameworks
# ===================================================================

class TestAllFrameworksInReport:
    """End-to-end report covering every framework."""

    def test_all_38_frameworks_in_single_report(self):
        findings = []
        for fw_key in FRAMEWORK_REGISTRY:
            fw = FRAMEWORK_REGISTRY[fw_key]
            findings.append({
                "compliance": [{"framework": fw_key, "control_id": fw.controls[0].control_id}],
                "passed": True,
                "status": "fixed",
            })
        assessments = assess_findings(findings)
        report = build_report(assessments)
        assert len(report.assessments) == 38
        assert isinstance(report, ComplianceAssessmentReport)

    def test_mixed_pass_fail_across_expanded_frameworks(self):
        findings = [
            {
                "compliance": [
                    {"framework": "owasp", "control_id": "A05"},
                    {"framework": "http_sec", "control_id": "HDR-1"},
                ],
                "passed": False,
            },
            {
                "compliance": [
                    {"framework": "nist_80053", "control_id": "SI-10"},
                    {"framework": "tls_sec", "control_id": "TLS-7"},
                ],
                "passed": True,
            },
        ]
        assessments = assess_findings(findings)
        assert len(assessments) == 4
        passed = [a for a in assessments if a.state == AssessmentState.PASS]
        failed = [a for a in assessments if a.state == AssessmentState.FAIL]
        assert len(passed) == 2
        assert len(failed) == 2

    def test_expanded_frameworks_score_calculation(self):
        findings = [
            {
                "compliance": [{"framework": "owasp", "control_id": "A05"}],
                "passed": True,
            },
            {
                "compliance": [{"framework": "owasp", "control_id": "A03"}],
                "passed": False,
            },
            {
                "compliance": [{"framework": "http_sec", "control_id": "HDR-1"}],
                "passed": True,
            },
            {
                "compliance": [{"framework": "http_sec", "control_id": "HDR-2"}],
                "passed": False,
            },
        ]
        assessments = assess_findings(findings)
        report = build_report(assessments)
        fw_scores = {a.framework_key: a.score for a in report.assessments}
        assert "owasp" in fw_scores
        assert "http_sec" in fw_scores
        # OWASP: 1 pass + 1 fail = 50%
        assert fw_scores["owasp"] == 50.0
        # HTTP: 1 pass + 1 fail = 50%
        assert fw_scores["http_sec"] == 50.0
