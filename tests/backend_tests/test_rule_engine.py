"""Tests for the rule engine: YAML loading, rule parsing, framework mapping, finding generation."""

import os
import uuid

import pytest
import yaml

from app.models.enums import SeverityLevel
from app.services.rule_engine import (
    FindingBuilder,
    RuleLoader,
    RuleMatcher,
    ScannerObservation,
)
from app.services.rule_engine.rule_loader import ComplianceRef, RuleDefinition
from app.services.rule_engine.rule_matcher import MatchResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def rules_dir(tmp_path):
    """Creates a temporary rules directory with a single YAML rule file."""
    subdir = tmp_path / "headers"
    subdir.mkdir()
    rule_file = subdir / "csp.yaml"
    rule_content = {
        "rules": [
            {
                "id": "HTTP-002",
                "name": "Missing CSP",
                "category": "http_security",
                "severity": "high",
                "description": "CSP header is missing.",
                "remediation": "Add CSP header.",
                "references": ["https://example.com/csp"],
                "compliance": [
                    {
                        "framework": "owasp",
                        "control_id": "A8",
                        "control_name": "Software and Data Integrity Failures",
                    },
                    {
                        "framework": "nist",
                        "control_id": "SI-10",
                        "control_name": "Information Input Validation",
                    },
                ],
            }
        ]
    }
    with open(rule_file, "w", encoding="utf-8") as f:
        yaml.dump(rule_content, f)
    return str(tmp_path)


@pytest.fixture
def sample_rules():
    """A small in-memory rule list for matcher and builder tests."""
    return [
        RuleDefinition(
            rule_id="HTTP-001",
            name="Missing HSTS",
            category="http_security",
            severity=SeverityLevel.MEDIUM,
            description="HSTS header missing.",
            remediation="Add HSTS header.",
            references=["https://example.com/hsts"],
            compliance=[
                ComplianceRef(framework="owasp", control_id="A3", control_name="Broken Auth"),
            ],
        ),
        RuleDefinition(
            rule_id="TLS-001",
            name="Weak TLS",
            category="tls_analysis",
            severity=SeverityLevel.HIGH,
            description="TLS 1.0/1.1 supported.",
            remediation="Disable old TLS.",
            references=[],
            compliance=[
                ComplianceRef(framework="nist", control_id="SC-8", control_name="Transmission Security"),
            ],
        ),
    ]


# ---------------------------------------------------------------------------
# RuleLoader tests
# ---------------------------------------------------------------------------

class TestRuleLoader:
    """YAML loading, parsing, directory walking, error handling."""

    def test_load_from_directory(self, rules_dir):
        loader = RuleLoader(rules_path=rules_dir)
        rules = loader.load_all()
        assert len(rules) == 1
        rule = rules[0]
        assert rule.rule_id == "HTTP-002"
        assert rule.name == "Missing CSP"
        assert rule.category == "http_security"
        assert rule.severity == SeverityLevel.HIGH
        assert len(rule.references) == 1
        assert len(rule.compliance) == 2

    def test_parse_rule_severity(self, rules_dir):
        loader = RuleLoader(rules_path=rules_dir)
        rules = loader.load_all()
        assert rules[0].severity == SeverityLevel.HIGH

    def test_load_nonexistent_directory_returns_empty(self):
        loader = RuleLoader(rules_path="/nonexistent/path")
        rules = loader.load_all()
        assert rules == []

    def test_load_empty_yaml(self, tmp_path):
        empty_file = tmp_path / "empty.yaml"
        empty_file.write_text("", encoding="utf-8")
        loader = RuleLoader(rules_path=str(tmp_path))
        rules = loader.load_all()
        assert rules == []

    def test_load_invalid_yaml(self, tmp_path):
        bad_file = tmp_path / "bad.yaml"
        bad_file.write_text("rules: [broken: yaml: : :", encoding="utf-8")
        loader = RuleLoader(rules_path=str(tmp_path))
        rules = loader.load_all()
        assert rules == []

    def test_skips_non_yaml_files(self, rules_dir, tmp_path):
        txt_file = tmp_path / "notes.txt"
        txt_file.write_text("not a rule file", encoding="utf-8")
        loader = RuleLoader(rules_path=str(tmp_path))
        rules = loader.load_all()
        assert all(r.rule_id != "" for r in rules)

    def test_default_rules_path_is_absolute(self):
        loader = RuleLoader()
        path = loader._default_rules_path()
        assert os.path.isabs(path)
        assert path.endswith("rules")

    def test_load_multiple_categories(self, tmp_path):
        hdr = tmp_path / "headers"
        tls = tmp_path / "tls"
        hdr.mkdir()
        tls.mkdir()
        for d, rid, cat in [(hdr, "HTTP-001", "http_security"), (tls, "TLS-001", "tls_analysis")]:
            with open(d / f"{rid.lower()}.yaml", "w") as f:
                yaml.dump({
                    "rules": [{
                        "id": rid, "name": rid, "category": cat,
                        "severity": "high", "description": "x", "remediation": "y",
                    }]
                }, f)
        loader = RuleLoader(rules_path=str(tmp_path))
        rules = loader.load_all()
        assert len(rules) == 2
        categories = {r.category for r in rules}
        assert categories == {"http_security", "tls_analysis"}


# ---------------------------------------------------------------------------
# RuleMatcher tests
# ---------------------------------------------------------------------------

class TestRuleMatcher:
    """Observation-to-rule matching logic."""

    def test_match_by_category_and_prefix(self, sample_rules):
        matcher = RuleMatcher(sample_rules)
        obs = ScannerObservation(check_name="HTTP", category="http_security", passed=False)
        result = matcher.match(obs)
        assert result.matched is True
        assert result.rule is not None
        assert result.rule.rule_id == "HTTP-001"

    def test_no_match_wrong_category(self, sample_rules):
        matcher = RuleMatcher(sample_rules)
        obs = ScannerObservation(check_name="DNS", category="dns_analysis", passed=True)
        result = matcher.match(obs)
        assert result.matched is False

    def test_match_returns_first_rule(self, sample_rules):
        matcher = RuleMatcher(sample_rules)
        obs = ScannerObservation(check_name="TLS", category="tls_analysis", passed=False)
        result = matcher.match(obs)
        assert result.matched is True
        assert result.rule.rule_id == "TLS-001"

    def test_match_with_passed_observation(self, sample_rules):
        matcher = RuleMatcher(sample_rules)
        obs = ScannerObservation(check_name="HTTP", category="http_security", passed=True)
        result = matcher.match(obs)
        assert result.matched is True
        assert result.rule.rule_id == "HTTP-001"

    def test_empty_rules(self):
        matcher = RuleMatcher([])
        obs = ScannerObservation(check_name="HTTP", category="http_security", passed=False)
        result = matcher.match(obs)
        assert result.matched is False


# ---------------------------------------------------------------------------
# FindingBuilder tests
# ---------------------------------------------------------------------------

class TestFindingBuilder:
    """Finding generation from matched rules."""

    def test_build_finding_from_match(self, sample_rules):
        scan_id = uuid.uuid4()
        rule = sample_rules[0]
        match = MatchResult(matched=True, rule=rule)
        obs = ScannerObservation(
            check_name="HTTP", category="http_security",
            passed=False, detail="HSTS header not found",
        )
        finding = FindingBuilder.build(scan_id=scan_id, match=match, observation=obs)

        assert finding is not None
        assert finding.scan_id == scan_id
        assert finding.severity == SeverityLevel.MEDIUM.value
        assert finding.passed is False
        assert "HSTS header not found" in finding.detail
        assert len(finding.compliance_mappings) == 1
        assert finding.compliance_mappings[0]["framework"] == "owasp"

    def test_build_passed_finding(self, sample_rules):
        scan_id = uuid.uuid4()
        rule = sample_rules[1]
        match = MatchResult(matched=True, rule=rule)
        obs = ScannerObservation(
            check_name="TLS", category="tls_analysis",
            passed=True, detail="TLS 1.3 enforced",
        )
        finding = FindingBuilder.build(scan_id=scan_id, match=match, observation=obs)

        assert finding is not None
        assert finding.passed is True
        assert finding.severity == SeverityLevel.HIGH.value

    def test_no_match_returns_none(self):
        scan_id = uuid.uuid4()
        match = MatchResult(matched=False)
        obs = ScannerObservation(check_name="DNS", category="dns_analysis", passed=True)
        finding = FindingBuilder.build(scan_id=scan_id, match=match, observation=obs)
        assert finding is None

    def test_compliance_mappings_inherited_from_rule(self, sample_rules):
        scan_id = uuid.uuid4()
        rule = sample_rules[1]
        match = MatchResult(matched=True, rule=rule)
        obs = ScannerObservation(
            check_name="TLS", category="tls_analysis", passed=False,
        )
        finding = FindingBuilder.build(scan_id=scan_id, match=match, observation=obs)

        assert len(finding.compliance_mappings) == 1
        mapping = finding.compliance_mappings[0]
        assert mapping["framework"] == "nist"
        assert mapping["control_id"] == "SC-8"
        assert mapping["control_name"] == "Transmission Security"

    def test_no_compliance_mappings(self):
        rule = RuleDefinition(
            rule_id="TEST-001", name="Test", category="test",
            severity=SeverityLevel.LOW, description="", remediation="",
        )
        match = MatchResult(matched=True, rule=rule)
        obs = ScannerObservation(check_name="TEST", category="test", passed=True)
        finding = FindingBuilder.build(
            scan_id=uuid.uuid4(), match=match, observation=obs,
        )
        assert finding.compliance_mappings == []


# ---------------------------------------------------------------------------
# End-to-end: load → match → build
# ---------------------------------------------------------------------------

class TestRuleEnginePipeline:
    """Integration-style test for the full rule processing pipeline."""

    def test_full_pipeline(self, rules_dir):
        scan_id = uuid.uuid4()

        # Load
        loader = RuleLoader(rules_path=rules_dir)
        rules = loader.load_all()
        assert len(rules) == 1

        # Match
        matcher = RuleMatcher(rules)
        obs = ScannerObservation(
            check_name="HTTP", category="http_security",
            passed=False, detail="CSP header missing",
        )
        match = matcher.match(obs)
        assert match.matched is True

        # Build
        finding = FindingBuilder.build(scan_id=scan_id, match=match, observation=obs)
        assert finding is not None
        assert finding.passed is False
        assert finding.detail == "CSP header missing"
        assert len(finding.compliance_mappings) == 2

        frameworks = {m["framework"] for m in finding.compliance_mappings}
        assert "owasp" in frameworks
        assert "nist" in frameworks

    def test_pipeline_no_match(self, rules_dir):
        scan_id = uuid.uuid4()
        loader = RuleLoader(rules_path=rules_dir)
        matcher = RuleMatcher(loader.load_all())
        obs = ScannerObservation(check_name="DNS", category="dns_analysis", passed=True)
        match = matcher.match(obs)
        finding = FindingBuilder.build(scan_id=scan_id, match=match, observation=obs)
        assert match.matched is False
        assert finding is None
