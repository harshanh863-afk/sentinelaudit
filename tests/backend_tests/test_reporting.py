"""Tests for reporting subsystem: evidence, lifecycle, risk, exporters."""

import uuid

import pytest

from app.models import Evidence, Finding, RiskScore, Scan, Target, Project, User
from app.models.enums import (
    AttackComplexity,
    AttackVector,
    FindingStatus,
    PrivilegesRequired,
    ScanStatus,
    SeverityLevel,
    UserInteraction,
)
from app.services.reporting import (
    FindingFormatter,
    JSONExporter,
    MarkdownExporter,
    ReportEngine,
)
from app.services.reporting.finding_formatter import FormattedFinding
from app.services.reporting.report_engine import ReportData


# ===================================================================
# 1. Evidence expansion
# ===================================================================

class TestEvidenceExpansion:
    """New evidence fields: request/response data, headers, body, screenshots."""

    def test_evidence_with_full_request_response(self, db_session):
        user = User(email="ev@example.com", password_hash="pwd", name="Ev")
        project = Project(name="P", owner=user)
        target = Target(url="https://x.com", host="x.com", project=project)
        scan = Scan(target=target)
        evidence = Evidence(
            scan=scan,
            type="http_trace",
            data={"method": "GET"},
            request_data="GET / HTTP/1.1\nHost: x.com",
            response_data="HTTP/1.1 200 OK",
            request_headers={"Host": "x.com", "User-Agent": "SentinelAudit"},
            response_headers={"Server": "nginx", "Content-Type": "text/html"},
            response_body="<html><body>OK</body></html>",
            screenshot_path="/screenshots/x.com.png",
            evidence_meta={"tool": "http_analyzer", "duration_ms": 120},
        )
        db_session.add(evidence)
        db_session.commit()

        saved = db_session.query(Evidence).first()
        assert saved.request_data == "GET / HTTP/1.1\nHost: x.com"
        assert saved.response_headers["Server"] == "nginx"
        assert saved.response_body == "<html><body>OK</body></html>"
        assert saved.screenshot_path == "/screenshots/x.com.png"
        assert saved.evidence_meta["duration_ms"] == 120

    def test_evidence_captured_at_timestamp(self, db_session):
        from datetime import datetime, timezone
        user = User(email="ts@example.com", password_hash="pwd", name="Ts")
        project = Project(name="P", owner=user)
        target = Target(url="https://y.com", host="y.com", project=project)
        scan = Scan(target=target)
        now = datetime.now(timezone.utc)
        evidence = Evidence(scan=scan, type="raw", data={}, captured_at=now)
        db_session.add(evidence)
        db_session.commit()

        saved = db_session.query(Evidence).first()
        assert saved.captured_at is not None

    def test_evidence_defaults(self, db_session):
        user = User(email="def@example.com", password_hash="pwd", name="Def")
        project = Project(name="P", owner=user)
        target = Target(url="https://z.com", host="z.com", project=project)
        scan = Scan(target=target)
        evidence = Evidence(scan=scan, type="default", data={})
        db_session.add(evidence)
        db_session.commit()

        saved = db_session.query(Evidence).first()
        assert saved.request_data is None
        assert saved.request_headers in (None, {})


# ===================================================================
# 2. Finding lifecycle
# ===================================================================

class TestFindingLifecycle:
    """New finding statuses and lifecycle transitions."""

    def test_finding_default_status_is_new(self, db_session):
        user = User(email="fl@example.com", password_hash="pwd", name="Fl")
        project = Project(name="P", owner=user)
        target = Target(url="https://a.com", host="a.com", project=project)
        scan = Scan(target=target)
        finding = Finding(scan=scan, severity=SeverityLevel.MEDIUM, passed=False)
        db_session.add(finding)
        db_session.commit()

        saved = db_session.query(Finding).first()
        assert saved.status == FindingStatus.NEW

    def test_all_finding_statuses(self, db_session):
        user = User(email="all@example.com", password_hash="pwd", name="All")
        project = Project(name="P", owner=user)
        target = Target(url="https://b.com", host="b.com", project=project)
        scan = Scan(target=target)
        for status in FindingStatus:
            finding = Finding(scan=scan, severity=SeverityLevel.LOW, passed=True, status=status)
            db_session.add(finding)
        db_session.commit()

        saved = db_session.query(Finding.status).distinct().all()
        saved_statuses = {s[0] for s in saved}
        assert saved_statuses == set(FindingStatus)

    def test_finding_new_fields(self, db_session):
        user = User(email="nf@example.com", password_hash="pwd", name="Nf")
        project = Project(name="P", owner=user)
        target = Target(url="https://c.com", host="c.com", project=project)
        scan = Scan(target=target)
        finding = Finding(
            scan=scan,
            title="Reflected XSS",
            finding_type="xss",
            severity=SeverityLevel.HIGH,
            status=FindingStatus.CONFIRMED,
            passed=False,
            detail="XSS in search parameter",
            cvss_score=7.5,
        )
        db_session.add(finding)
        db_session.commit()

        saved = db_session.query(Finding).first()
        assert saved.title == "Reflected XSS"
        assert saved.finding_type == "xss"
        assert saved.cvss_score == 7.5
        assert saved.status == FindingStatus.CONFIRMED

    def test_finding_status_values(self):
        assert FindingStatus.NEW.value == "new"
        assert FindingStatus.CONFIRMED.value == "confirmed"
        assert FindingStatus.FALSE_POSITIVE.value == "false_positive"
        assert FindingStatus.ACCEPTED_RISK.value == "accepted_risk"
        assert FindingStatus.FIXED.value == "fixed"
        assert FindingStatus.RETEST_REQUIRED.value == "retest_required"

    def test_invalid_finding_status_raises(self):
        with pytest.raises(ValueError):
            FindingStatus("open")


# ===================================================================
# 3. Risk scoring
# ===================================================================

class TestRiskScore:
    """CVSS risk score model."""

    def test_create_risk_score(self, db_session):
        user = User(email="rs@example.com", password_hash="pwd", name="Rs")
        project = Project(name="P", owner=user)
        target = Target(url="https://d.com", host="d.com", project=project)
        scan = Scan(target=target)
        finding = Finding(scan=scan, severity=SeverityLevel.CRITICAL, passed=False)
        risk = RiskScore(
            finding=finding,
            cvss_version="3.1",
            cvss_score=9.1,
            attack_vector=AttackVector.NETWORK,
            attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE,
            user_interaction=UserInteraction.NONE,
        )
        db_session.add(risk)
        db_session.commit()

        saved = db_session.query(RiskScore).first()
        assert saved.cvss_version == "3.1"
        assert saved.cvss_score == 9.1
        assert saved.attack_vector == AttackVector.NETWORK
        assert saved.attack_complexity == AttackComplexity.LOW
        assert saved.privileges_required == PrivilegesRequired.NONE
        assert saved.user_interaction == UserInteraction.NONE

    def test_risk_score_one_to_one_with_finding(self, db_session):
        user = User(email="o2o@example.com", password_hash="pwd", name="O2o")
        project = Project(name="P", owner=user)
        target = Target(url="https://e.com", host="e.com", project=project)
        scan = Scan(target=target)
        finding = Finding(scan=scan, severity=SeverityLevel.CRITICAL, passed=False)
        risk1 = RiskScore(
            finding=finding, cvss_score=9.0,
            attack_vector=AttackVector.NETWORK, attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE, user_interaction=UserInteraction.NONE,
        )
        db_session.add(risk1)
        db_session.commit()

        risk2 = RiskScore(
            finding=finding, cvss_score=8.0,
            attack_vector=AttackVector.NETWORK, attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE, user_interaction=UserInteraction.NONE,
        )
        db_session.add(risk2)
        with pytest.raises(Exception):
            db_session.commit()

    def test_risk_score_enums(self):
        assert AttackVector.NETWORK.value == "network"
        assert AttackComplexity.LOW.value == "low"
        assert PrivilegesRequired.NONE.value == "none"
        assert UserInteraction.NONE.value == "none"

    def test_finding_links_to_risk_score(self, db_session):
        user = User(email="flr@example.com", password_hash="pwd", name="Flr")
        project = Project(name="P", owner=user)
        target = Target(url="https://f.com", host="f.com", project=project)
        scan = Scan(target=target)
        finding = Finding(scan=scan, severity=SeverityLevel.CRITICAL, passed=False)
        risk = RiskScore(
            finding=finding, cvss_score=9.0,
            attack_vector=AttackVector.NETWORK, attack_complexity=AttackComplexity.LOW,
            privileges_required=PrivilegesRequired.NONE, user_interaction=UserInteraction.NONE,
        )
        db_session.add(finding)
        db_session.commit()

        saved_finding = db_session.query(Finding).first()
        assert saved_finding.risk_score is not None
        assert saved_finding.risk_score.cvss_score == 9.0


# ===================================================================
# 4. Finding formatter
# ===================================================================

class TestFindingFormatter:
    """FindingFormatter converts DB findings to output DTOs."""

    def test_format_basic_finding(self, db_session):
        user = User(email="ff@example.com", password_hash="pwd", name="Ff")
        project = Project(name="P", owner=user)
        target = Target(url="https://g.com", host="g.com", project=project)
        scan = Scan(target=target, status=ScanStatus.COMPLETED)
        finding = Finding(
            scan=scan,
            title="Missing CSP",
            severity=SeverityLevel.HIGH,
            status=FindingStatus.CONFIRMED,
            passed=False,
            detail="CSP header not found",
            cvss_score=6.5,
        )
        db_session.add(finding)
        db_session.commit()

        formatted = FindingFormatter.format(finding)
        assert isinstance(formatted, FormattedFinding)
        assert formatted.title == "Missing CSP"
        assert formatted.severity == "high"
        assert formatted.status == "confirmed"
        assert formatted.cvss_score == 6.5
        assert formatted.evidence_summary is None

    def test_format_many_findings(self, db_session):
        user = User(email="fm@example.com", password_hash="pwd", name="Fm")
        project = Project(name="P", owner=user)
        target = Target(url="https://h.com", host="h.com", project=project)
        scan = Scan(target=target)
        f1 = Finding(scan=scan, severity=SeverityLevel.HIGH, passed=False, title="A")
        f2 = Finding(scan=scan, severity=SeverityLevel.LOW, passed=True, title="B")
        db_session.add_all([f1, f2])
        db_session.commit()

        results = FindingFormatter.format_many([f1, f2])
        assert len(results) == 2
        assert results[0].title == "A"
        assert results[1].title == "B"


# ===================================================================
# 5. Report engine
# ===================================================================

class TestReportEngine:
    """Report data assembly."""

    def test_build_report_data(self, db_session):
        user = User(email="re@example.com", password_hash="pwd", name="Re")
        project = Project(name="P", owner=user)
        target = Target(url="https://i.com", host="i.com", project=project)
        scan = Scan(target=target, status=ScanStatus.COMPLETED, risk_score=0.35)
        finding = Finding(scan=scan, severity=SeverityLevel.CRITICAL, passed=False, title="XSS")
        db_session.add(finding)
        db_session.commit()

        report = ReportEngine.build(
            title="Security Assessment Report",
            target_url="https://i.com",
            scan_date="2024-01-17",
            risk_score=0.35,
            findings=[finding],
            executive_summary="Critical issue found.",
            methodology="Automated scan.",
            remediation_summary="Fix XSS.",
        )
        assert isinstance(report, ReportData)
        assert report.title == "Security Assessment Report"
        assert report.target_url == "https://i.com"
        assert report.risk_score == 0.35
        assert report.executive_summary == "Critical issue found."
        assert len(report.findings) == 1


# ===================================================================
# 6. JSON export
# ===================================================================

class TestJSONExport:
    """JSON report export."""

    def test_json_export_contains_all_sections(self):
        findings = [
            FormattedFinding(
                finding_id=uuid.uuid4(), title="XSS", severity="high",
                status="confirmed", detail="XSS found", cvss_score=7.5,
                evidence_summary="Input: <script>", compliance=[],
            )
        ]
        report = ReportEngine.build(
            title="Test Report", target_url="https://example.com",
            scan_date="2024-01-17", risk_score=0.5, findings=findings,
        )
        output = JSONExporter.export(report)
        assert '"title": "Test Report"' in output
        assert '"target_url": "https://example.com"' in output
        assert '"risk_score": 0.5' in output
        assert '"findings"' in output
        assert '">  import json' not in output  # not raw object

    def test_json_valid_syntax(self):
        import json
        findings = [
            FormattedFinding(
                finding_id=uuid.uuid4(), title="A", severity="low",
                status="new", detail=None, cvss_score=None,
                evidence_summary=None, compliance=[],
            )
        ]
        report = ReportEngine.build(
            title="Valid JSON", target_url="https://x.com",
            scan_date="2024-01-17", risk_score=0.0, findings=findings,
        )
        parsed = json.loads(JSONExporter.export(report))
        assert parsed["title"] == "Valid JSON"
        assert len(parsed["findings"]) == 1


# ===================================================================
# 7. Markdown export
# ===================================================================

class TestMarkdownExport:
    """Markdown report export."""

    def test_markdown_contains_sections(self):
        findings = [
            FormattedFinding(
                finding_id=uuid.uuid4(), title="SQLi", severity="critical",
                status="new", detail="SQL injection in login", cvss_score=9.0,
                evidence_summary="' OR 1=1 --", compliance=[
                    {"framework": "owasp", "control_id": "A1", "control_name": "Injection"},
                ],
            )
        ]
        report = ReportEngine.build(
            title="MD Report", target_url="https://example.com",
            scan_date="2024-01-17", risk_score=0.8, findings=findings,
            executive_summary="Critical SQL injection discovered.",
        )
        output = MarkdownExporter.export(report)
        assert "# MD Report" in output
        assert "**Target:** https://example.com" in output
        assert "**Risk Score:** 0.8" in output
        assert "## Executive Summary" in output
        assert "Critical SQL injection discovered." in output
        assert "## Findings" in output
        assert "### 1. SQLi" in output
        assert "**Severity:** critical" in output
        assert "**CVSS:** 9.0" in output
        assert "## Compliance Mapping" in output

    def test_markdown_no_findings(self):
        report = ReportEngine.build(
            title="Empty Report", target_url="https://example.com",
            scan_date="2024-01-17", risk_score=0.0, findings=[],
        )
        output = MarkdownExporter.export(report)
        assert "# Empty Report" in output
        assert "## Findings" not in output

    def test_markdown_content_type(self):
        assert MarkdownExporter.content_type() == "text/markdown"


# ===================================================================
# 8. Exporter content types
# ===================================================================

class TestExporterMetadata:
    """Content type reporting."""

    def test_json_content_type(self):
        assert JSONExporter.content_type() == "application/json"


# ===================================================================
# 9. Evidence hasher
# ===================================================================

class TestEvidenceHasher:
    """SHA-256 evidence hashing."""

    def test_hash_evidence_string(self):
        from app.services.reporting.evidence_hasher import hash_evidence, verify_evidence
        h = hash_evidence("test content")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_evidence_bytes(self):
        from app.services.reporting.evidence_hasher import hash_evidence_bytes
        h = hash_evidence_bytes(b"binary data")
        assert len(h) == 64

    def test_hash_evidence_dict(self):
        from app.services.reporting.evidence_hasher import hash_evidence_dict
        data = {"key": "value", "nested": {"a": 1}}
        h = hash_evidence_dict(data)
        assert len(h) == 64

    def test_hash_deterministic(self):
        from app.services.reporting.evidence_hasher import hash_evidence
        assert hash_evidence("hello") == hash_evidence("hello")
        assert hash_evidence("hello") != hash_evidence("world")

    def test_verify_evidence_match(self):
        from app.services.reporting.evidence_hasher import hash_evidence, verify_evidence
        content = "evidence content"
        h = hash_evidence(content)
        assert verify_evidence(content, h) is True

    def test_verify_evidence_mismatch(self):
        from app.services.reporting.evidence_hasher import verify_evidence
        assert verify_evidence("content", "deadbeef" * 16) is False


# ===================================================================
# 10. Professional report models
# ===================================================================

class TestProfessionalReportModels:
    """Dataclass models for professional reporting."""

    def test_executive_summary_defaults(self):
        from app.services.reporting.models import ExecutiveSummary
        es = ExecutiveSummary()
        assert es.security_score == 0.0
        assert es.risk_rating == "unknown"
        assert es.total_findings == 0
        assert es.critical_count == 0
        assert es.frameworks_assessed == []

    def test_executive_summary_full(self):
        from app.services.reporting.models import ExecutiveSummary
        es = ExecutiveSummary(
            security_score=85.0,
            risk_rating="High",
            total_findings=10,
            critical_count=2,
            high_count=3,
            frameworks_assessed=["OWASP Top 10", "NIST CSF"],
        )
        assert es.security_score == 85.0
        assert es.total_findings == 10
        assert len(es.frameworks_assessed) == 2

    def test_finding_detail_optional_fields(self):
        from app.services.reporting.models import FindingDetail
        import uuid
        fd = FindingDetail(finding_id=uuid.uuid4(), title="Test", severity="high", status="new")
        assert fd.detail is None
        assert fd.cvss_score is None
        assert fd.evidence_summary is None
        assert fd.evidence_hash is None
        assert fd.remediation is None
        assert fd.compliance == []

    def test_finding_detail_full(self):
        from app.services.reporting.models import FindingDetail
        import uuid
        fid = uuid.uuid4()
        fd = FindingDetail(
            finding_id=fid,
            title="SQL Injection",
            severity="critical",
            status="confirmed",
            detail="SQLi in login",
            cvss_score=9.0,
            evidence_summary="Request: OR 1=1",
            evidence_hash="a" * 64,
            remediation="Use parameterized queries",
            compliance=[{"framework": "owasp", "control_id": "A1"}],
        )
        assert fd.finding_id == fid
        assert fd.title == "SQL Injection"
        assert fd.cvss_score == 9.0
        assert fd.evidence_hash == "a" * 64
        assert fd.remediation == "Use parameterized queries"
        assert len(fd.compliance) == 1

    def test_compliance_section(self):
        from app.services.reporting.models import ComplianceSection
        cs = ComplianceSection(
            framework="PCI DSS 4.0",
            score=75.0,
            status="partial_compliance",
            passed=10,
            failed=3,
            partial=2,
            not_applicable=2,
            total=17,
        )
        assert cs.framework == "PCI DSS 4.0"
        assert cs.score == 75.0
        assert cs.passed == 10
        assert cs.failed == 3

    def test_technical_appendix(self):
        from app.services.reporting.models import TechnicalAppendix
        ta = TechnicalAppendix(
            scanner_version="2.0.0",
            scan_duration_seconds=3600,
            methodology="Automated scanning",
            target_info={"URL": "https://example.com", "Host": "example.com"},
            assessment_limitations=["No authenticated scan performed"],
        )
        assert ta.scanner_version == "2.0.0"
        assert ta.scan_duration_seconds == 3600
        assert len(ta.assessment_limitations) == 1
        assert ta.target_info["URL"] == "https://example.com"

    def test_professional_report_aggregation(self):
        from app.services.reporting.models import (
            ProfessionalReport, ExecutiveSummary, FindingDetail,
            ComplianceSection, TechnicalAppendix,
        )
        import uuid
        report = ProfessionalReport(
            title="Test Report",
            target_url="https://example.com",
            scan_date="2024-06-01",
            executive_summary=ExecutiveSummary(security_score=72.0, total_findings=5),
            findings=[
                FindingDetail(finding_id=uuid.uuid4(), title="XSS", severity="high", status="new"),
                FindingDetail(finding_id=uuid.uuid4(), title="Info", severity="info", status="fixed"),
            ],
            compliance_sections=[
                ComplianceSection(framework="OWASP Top 10", score=80.0, status="compliant", total=10),
            ],
            appendix=TechnicalAppendix(),
        )
        assert report.title == "Test Report"
        assert len(report.findings) == 2
        assert len(report.compliance_sections) == 1
        assert report.executive_summary.security_score == 72.0

    def test_severity_sort_key(self):
        from app.services.reporting.models import severity_sort_key, FindingDetail
        import uuid
        f_crit = FindingDetail(finding_id=uuid.uuid4(), title="C", severity="critical", status="new")
        f_info = FindingDetail(finding_id=uuid.uuid4(), title="I", severity="info", status="new")
        f_high = FindingDetail(finding_id=uuid.uuid4(), title="H", severity="high", status="new")
        assert severity_sort_key(f_crit) == 0
        assert severity_sort_key(f_high) == 1
        assert severity_sort_key(f_info) == 4
        assert severity_sort_key(f_crit) < severity_sort_key(f_info)


# ===================================================================
# 11. Professional HTML generator
# ===================================================================

class TestProfessionalHTMLGenerator:
    """Professional HTML report generation."""

    def test_generates_valid_html(self):
        from app.services.reporting.models import ProfessionalReport
        from app.services.reporting.professional_html import generate_professional_html
        report = ProfessionalReport(
            title="Security Assessment",
            target_url="https://example.com",
            scan_date="2024-06-01",
        )
        html = generate_professional_html(report)
        assert html.startswith("<!DOCTYPE html>")
        assert "</html>" in html
        assert "<title>Security Assessment</title>" in html

    def test_contains_cover_page(self):
        from app.services.reporting.models import ProfessionalReport
        from app.services.reporting.professional_html import generate_professional_html
        report = ProfessionalReport(
            title="My Report",
            target_url="https://test.com",
            scan_date="2024-06-01",
        )
        html = generate_professional_html(report)
        assert "SECURITY ASSESSMENT REPORT" in html
        assert "My Report" in html
        assert "https://test.com" in html

    def test_contains_findings_table(self):
        from app.services.reporting.models import ProfessionalReport, FindingDetail
        from app.services.reporting.professional_html import generate_professional_html
        import uuid
        report = ProfessionalReport(
            title="Test",
            target_url="https://test.com",
            scan_date="2024-06-01",
            findings=[
                FindingDetail(finding_id=uuid.uuid4(), title="SQLi", severity="critical", status="confirmed", cvss_score=9.0, detail="SQL injection"),
                FindingDetail(finding_id=uuid.uuid4(), title="XSS", severity="high", status="new", cvss_score=6.5),
            ],
        )
        html = generate_professional_html(report)
        assert "Findings by Severity" in html
        assert "SQLi" in html
        assert "XSS" in html
        assert "finding-card" in html

    def test_contains_compliance_section(self):
        from app.services.reporting.models import ProfessionalReport, ComplianceSection
        from app.services.reporting.professional_html import generate_professional_html
        report = ProfessionalReport(
            title="Test",
            target_url="https://test.com",
            scan_date="2024-06-01",
            compliance_sections=[
                ComplianceSection(framework="OWASP Top 10", score=85.0, status="compliant", passed=8, total=10),
            ],
        )
        html = generate_professional_html(report)
        assert "Compliance Summary" in html
        assert "OWASP Top 10" in html
        assert "85.0%" in html
        assert "class=\"compliance-table\"" in html

    def test_contains_severity_bar_css(self):
        from app.services.reporting.models import ProfessionalReport
        from app.services.reporting.professional_html import generate_professional_html
        report = ProfessionalReport(title="T", target_url="https://t.com", scan_date="2024-06-01")
        html = generate_professional_html(report)
        assert "sev-bar" in html
        assert "risk-bar" in html

    def test_empty_findings_shows_message(self):
        from app.services.reporting.models import ProfessionalReport
        from app.services.reporting.professional_html import generate_professional_html
        report = ProfessionalReport(title="T", target_url="https://t.com", scan_date="2024-06-01")
        html = generate_professional_html(report)
        assert "No findings were identified" in html

    def test_appendix_section(self):
        from app.services.reporting.models import ProfessionalReport, TechnicalAppendix
        from app.services.reporting.professional_html import generate_professional_html
        report = ProfessionalReport(
            title="T",
            target_url="https://t.com",
            scan_date="2024-06-01",
            appendix=TechnicalAppendix(
                scanner_version="2.0.0",
                scan_duration_seconds=120,
                methodology="Automated scan with 5 modules",
            ),
        )
        html = generate_professional_html(report)
        assert "Technical Appendix" in html
        assert "Scanner Version" in html
        assert "2.0.0" in html
        assert "120s" in html
        assert "Automated scan with 5 modules" in html


# ===================================================================
# 12. PDF generator
# ===================================================================

class TestPDFGenerator:
    """PDF report generation (HTML with @page rules)."""

    def test_generates_valid_pdf_html(self):
        from app.services.reporting.models import ProfessionalReport
        from app.services.reporting.pdf_generator import generate_pdf_html
        report = ProfessionalReport(title="PDF Test", target_url="https://p.com", scan_date="2024-06-01")
        html = generate_pdf_html(report)
        assert html.startswith("<!DOCTYPE html>")
        assert "@page" in html
        assert "size: A4" in html

    def test_contains_all_sections(self):
        from app.services.reporting.models import ProfessionalReport
        from app.services.reporting.pdf_generator import generate_pdf_html
        report = ProfessionalReport(title="PDF", target_url="https://p.com", scan_date="2024-06-01")
        html = generate_pdf_html(report)
        assert "SECURITY ASSESSMENT REPORT" in html
        assert "Executive Summary" in html
        assert "Risk Score Overview" in html
        assert "Technical Appendix" in html

    def test_pdf_exporter_content_type(self):
        from app.services.reporting.pdf_generator import PDFExporter as ProfessionalPDFExporter
        assert ProfessionalPDFExporter.content_type() == "text/html"

    def test_pdf_exporter_export(self):
        from app.services.reporting.models import ProfessionalReport
        from app.services.reporting.pdf_generator import PDFExporter as ProfessionalPDFExporter
        report = ProfessionalReport(title="PDF", target_url="https://p.com", scan_date="2024-06-01")
        html = ProfessionalPDFExporter.export(report)
        assert "@page" in html
        assert "Executive Summary" in html

    def test_pdf_exporter_raises_on_wrong_type(self):
        from app.services.reporting.pdf_generator import generate_pdf_html
        with pytest.raises((TypeError, AttributeError)):
            generate_pdf_html("not a report")


# ===================================================================
# 13. Enhanced JSON exporter
# ===================================================================

class TestEnhancedJSONExporter:
    """Professional JSON report export."""

    def test_exports_professional_report(self):
        import json
        from app.services.reporting.models import ProfessionalReport
        from app.services.reporting.exporters.json_exporter import JSONExporter
        report = ProfessionalReport(title="JSON Test", target_url="https://j.com", scan_date="2024-06-01")
        output = JSONExporter.export(report)
        parsed = json.loads(output)
        assert parsed["title"] == "JSON Test"
        assert parsed["target_url"] == "https://j.com"

    def test_exports_findings_with_uuids_as_strings(self):
        import json
        from app.services.reporting.models import ProfessionalReport, FindingDetail
        from app.services.reporting.exporters.json_exporter import JSONExporter
        import uuid
        fid = uuid.uuid4()
        report = ProfessionalReport(
            title="T", target_url="https://j.com", scan_date="2024-06-01",
            findings=[FindingDetail(finding_id=fid, title="XSS", severity="high", status="confirmed")],
        )
        parsed = json.loads(JSONExporter.export(report))
        assert parsed["findings"][0]["finding_id"] == str(fid)

    def test_exports_legacy_report_data(self):
        import json
        from app.services.reporting.exporters.json_exporter import JSONExporter
        from app.services.reporting.report_engine import ReportData
        report = ReportData(title="Legacy", target_url="https://l.com", scan_date="2024-06-01", risk_score=0.5)
        output = JSONExporter.export(report)
        parsed = json.loads(output)
        assert parsed["title"] == "Legacy"
        assert parsed["risk_score"] == 0.5


# ===================================================================
# 14. Report DB model (enhanced)
# ===================================================================

class TestEnhancedReportModel:
    """Enhanced Report model with professional fields."""

    def test_create_report_with_enhanced_fields(self, db_session):
        from app.models import Report, User, Project
        user = User(email="rptenh@example.com", password_hash="pwd", name="Rpt")
        project = Project(name="P", owner=user)
        db_session.add_all([user, project])
        db_session.flush()

        report = Report(
            project_id=project.id,
            scan_ids=[str(uuid.uuid4())],
            format="json",
            title="Professional Report",
            risk_score=72.5,
            risk_rating="Medium",
            findings_count=5,
            severity_breakdown={"critical": 1, "high": 2, "medium": 1, "low": 1, "info": 0},
        )
        db_session.add(report)
        db_session.commit()

        saved = db_session.query(Report).first()
        assert saved.title == "Professional Report"
        assert saved.risk_score == 72.5
        assert saved.risk_rating == "Medium"
        assert saved.findings_count == 5
        assert saved.severity_breakdown["critical"] == 1

    def test_report_nullable_fields_default_to_none(self, db_session):
        from app.models import Report, User, Project
        user = User(email="rptnull@example.com", password_hash="pwd", name="Rpt")
        project = Project(name="P", owner=user)
        db_session.add_all([user, project])
        db_session.flush()

        report = Report(project_id=project.id, scan_ids=[], format="html")
        db_session.add(report)
        db_session.commit()

        saved = db_session.query(Report).first()
        assert saved.title is None
        assert saved.risk_score is None
        assert saved.risk_rating is None
        assert saved.findings_count is None
        assert saved.severity_breakdown in (None, {})
        assert saved.generated_at is None

    def test_report_severity_breakdown_json(self, db_session):
        from app.models import Report, User, Project
        import json
        user = User(email="rptsev@example.com", password_hash="pwd", name="Rpt")
        project = Project(name="P", owner=user)
        db_session.add_all([user, project])
        db_session.flush()

        breakdown = {"critical": 2, "high": 1, "medium": 3, "low": 0, "info": 1}
        report = Report(
            project_id=project.id,
            scan_ids=[str(uuid.uuid4())],
            format="pdf",
            severity_breakdown=breakdown,
        )
        db_session.add(report)
        db_session.commit()

        saved = db_session.query(Report).first()
        assert saved.severity_breakdown == breakdown

    def test_report_links_to_project(self, db_session):
        from app.models import Report, User, Project
        user = User(email="rptproj@example.com", password_hash="pwd", name="Rpt")
        project = Project(name="Target Project", owner=user)
        db_session.add_all([user, project])
        db_session.flush()

        report = Report(project_id=project.id, scan_ids=[], format="json")
        db_session.add(report)
        db_session.commit()

        saved = db_session.query(Report).first()
        assert saved.project.name == "Target Project"


# ===================================================================
# 15. Enhanced report engine
# ===================================================================

class TestEnhancedReportEngine:
    """Professional report building via ReportEngine."""

    def test_build_professional_creates_professional_report(self):
        from app.services.reporting.report_engine import ReportEngine
        from app.services.reporting.models import ProfessionalReport
        report = ReportEngine.build_professional(
            title="Pro Report",
            target_url="https://example.com",
            scan_date="2024-06-01",
            risk_score=85.0,
            findings=[],
        )
        assert isinstance(report, ProfessionalReport)
        assert report.title == "Pro Report"
        assert report.executive_summary.risk_rating == "Critical"

    def test_build_professional_with_findings_counts_severity(self):
        from app.services.reporting.report_engine import ReportEngine
        from app.services.reporting.finding_formatter import FormattedFinding
        import uuid
        findings = [
            FormattedFinding(finding_id=uuid.uuid4(), title="Critical", severity="critical", status="new", detail=None, cvss_score=None, evidence_summary=None),
            FormattedFinding(finding_id=uuid.uuid4(), title="High", severity="high", status="confirmed", detail=None, cvss_score=None, evidence_summary=None),
            FormattedFinding(finding_id=uuid.uuid4(), title="Medium", severity="medium", status="new", detail=None, cvss_score=None, evidence_summary=None),
            FormattedFinding(finding_id=uuid.uuid4(), title="Low", severity="low", status="fixed", detail=None, cvss_score=None, evidence_summary=None),
            FormattedFinding(finding_id=uuid.uuid4(), title="Info", severity="info", status="new", detail=None, cvss_score=None, evidence_summary=None),
        ]
        report = ReportEngine.build_professional(
            title="Pro", target_url="https://x.com", scan_date="2024-06-01",
            risk_score=60.0, findings=findings,
        )
        assert report.executive_summary.total_findings == 5
        assert report.executive_summary.critical_count == 1
        assert report.executive_summary.high_count == 1
        assert report.executive_summary.medium_count == 1
        assert report.executive_summary.low_count == 1
        assert report.executive_summary.info_count == 1

    def test_build_professional_with_compliance_scores(self):
        from app.services.reporting.report_engine import ReportEngine
        compliance_scores = [
            {"framework": "OWASP Top 10", "score": 90.0, "status": "compliant", "passed": 9, "total": 10},
            {"framework": "PCI DSS 4.0", "score": 65.0, "status": "partial", "passed": 11, "failed": 3, "total": 17},
        ]
        report = ReportEngine.build_professional(
            title="Compliance Report", target_url="https://c.com", scan_date="2024-06-01",
            risk_score=50.0, findings=[], compliance_scores=compliance_scores,
        )
        assert len(report.compliance_sections) == 2
        assert report.compliance_sections[0].framework == "OWASP Top 10"
        assert report.compliance_sections[0].score == 90.0
        assert report.compliance_sections[1].score == 65.0
        assert len(report.executive_summary.frameworks_assessed) == 2

    def test_build_professional_with_optional_params(self):
        from app.services.reporting.report_engine import ReportEngine
        report = ReportEngine.build_professional(
            title="Full Report", target_url="https://f.com", scan_date="2024-06-01",
            risk_score=35.0, findings=[],
            methodology="NIST SP 800-115",
            executive_summary="Comprehensive assessment completed.",
            remediation_summary="Address all critical findings first.",
            scanner_version="2.0.0",
            scan_duration=300,
            client_name="ACME Corp",
        )
        assert report.appendix.scanner_version == "2.0.0"
        assert report.appendix.scan_duration_seconds == 300
        assert report.remediation_summary == "Address all critical findings first."
        assert report.executive_summary.risk_rating == "Low"

    def test_build_professional_with_evidence_hash_and_remediation(self):
        from app.services.reporting.report_engine import ReportEngine
        from app.services.reporting.finding_formatter import FormattedFinding
        import uuid
        findings = [
            FormattedFinding(
                finding_id=uuid.uuid4(), title="SQLi", severity="critical", status="confirmed",
                cvss_score=9.0, detail="SQL injection in login",
                evidence_summary="Request with OR 1=1",
                evidence_hash="a" * 64,
                remediation="Use parameterized queries",
                compliance=[{"framework": "owasp", "control_id": "A1"}],
            ),
        ]
        report = ReportEngine.build_professional(
            title="Ev Report", target_url="https://e.com", scan_date="2024-06-01",
            risk_score=90.0, findings=findings,
        )
        assert len(report.findings) == 1
        assert report.findings[0].evidence_hash == "a" * 64
        assert report.findings[0].remediation == "Use parameterized queries"
        assert len(report.findings[0].compliance) == 1


# ===================================================================
# 16. Risk rating utility
# ===================================================================

class TestRiskRating:
    """Risk rating from numerical score."""

    def test_critical_rating(self):
        from app.services.reporting import _risk_rating
        assert _risk_rating(100) == "Critical"
        assert _risk_rating(80) == "Critical"
        assert _risk_rating(85) == "Critical"

    def test_high_rating(self):
        from app.services.reporting import _risk_rating
        assert _risk_rating(79) == "High"
        assert _risk_rating(60) == "High"
        assert _risk_rating(65) == "High"

    def test_medium_rating(self):
        from app.services.reporting import _risk_rating
        assert _risk_rating(59) == "Medium"
        assert _risk_rating(40) == "Medium"
        assert _risk_rating(45) == "Medium"

    def test_low_rating(self):
        from app.services.reporting import _risk_rating
        assert _risk_rating(39) == "Low"
        assert _risk_rating(20) == "Low"

    def test_info_rating(self):
        from app.services.reporting import _risk_rating
        assert _risk_rating(19) == "Informational"
        assert _risk_rating(0) == "Informational"


# ===================================================================
# 17. Enhanced finding formatter
# ===================================================================

class TestEnhancedFindingFormatter:
    """Enhanced finding formatter with evidence hash and remediation."""

    def test_formatted_finding_has_evidence_hash(self):
        from app.services.reporting.finding_formatter import FormattedFinding
        import uuid
        ff = FormattedFinding(
            finding_id=uuid.uuid4(), title="T", severity="high", status="new",
            detail=None, cvss_score=None, evidence_summary=None,
            evidence_hash="abc123",
        )
        assert ff.evidence_hash == "abc123"

    def test_formatted_finding_has_remediation(self):
        from app.services.reporting.finding_formatter import FormattedFinding
        import uuid
        ff = FormattedFinding(
            finding_id=uuid.uuid4(), title="T", severity="high", status="new",
            detail=None, cvss_score=None, evidence_summary=None,
            remediation="Use parameterized queries",
        )
        assert ff.remediation == "Use parameterized queries"

    def test_format_with_evidence_data_hashes_it(self, db_session):
        from app.models import Evidence, Finding, Scan, Target, Project, User
        from app.models.enums import SeverityLevel
        from app.services.reporting.finding_formatter import FindingFormatter
        from app.services.reporting.evidence_hasher import hash_evidence_dict

        user = User(email="evhash@example.com", password_hash="pwd", name="Ev")
        project = Project(name="P", owner=user)
        target = Target(url="https://h.com", host="h.com", project=project)
        scan = Scan(target=target)
        finding = Finding(scan=scan, severity=SeverityLevel.HIGH, passed=False, title="XSS")
        evidence = Evidence(
            scan=scan, finding=finding,
            type="http_request",
            data={"method": "GET", "path": "/login", "payload": "<script>"},
        )
        db_session.add_all([user, project, target, scan, finding, evidence])
        db_session.commit()

        formatted = FindingFormatter.format(finding)
        expected_hash = hash_evidence_dict({"method": "GET", "path": "/login", "payload": "<script>"})
        assert formatted.evidence_hash == expected_hash


# ===================================================================
# 18. Integration — full professional pipeline
# ===================================================================

class TestProfessionalReportPipeline:
    """End-to-end: formatter → model → HTML generation."""

    def test_formatted_finding_to_professional_report_to_html(self):
        from app.services.reporting.finding_formatter import FormattedFinding
        from app.services.reporting.report_engine import ReportEngine
        from app.services.reporting.professional_html import generate_professional_html
        import uuid

        findings = [
            FormattedFinding(
                finding_id=uuid.uuid4(), title="Cross-Site Scripting", severity="high",
                status="confirmed", cvss_score=6.5, detail="XSS in search parameter",
                evidence_summary="Script injection", evidence_hash="a" * 64,
                remediation="Encode output",
                compliance=[{"framework": "owasp", "control_id": "A7", "control_name": "XSS"}],
            ),
            FormattedFinding(
                finding_id=uuid.uuid4(), title="Missing CSP Header", severity="medium",
                status="new", detail=None, cvss_score=5.0, evidence_summary=None,
            ),
        ]

        report = ReportEngine.build_professional(
            title="Integration Test Report",
            target_url="https://integration-test.com",
            scan_date="2024-06-15",
            risk_score=58.0,
            findings=findings,
            methodology="Automated assessment",
            scanner_version="1.0.0",
            scan_duration=180,
            client_name="TestCorp",
            compliance_scores=[
                {"framework": "OWASP Top 10", "score": 70.0, "status": "partial", "passed": 7, "total": 10},
            ],
        )

        assert report.title == "Integration Test Report"
        assert len(report.findings) == 2
        assert report.findings[0].title == "Cross-Site Scripting"
        assert report.findings[0].evidence_hash == "a" * 64
        assert report.findings[1].severity == "medium"
        assert len(report.compliance_sections) == 1
        assert report.compliance_sections[0].framework == "OWASP Top 10"

        html = generate_professional_html(report)
        assert "Integration Test Report" in html
        assert "Cross-Site Scripting" in html
        assert "Missing CSP Header" in html
        assert "OWASP Top 10" in html
        assert "70.0%" in html
        assert "Technical Appendix" in html
        assert "1.0.0" in html
        assert "180s" in html

    def test_full_pipeline_with_db_findings(self, db_session):
        from app.models import Evidence, Finding, Scan, Target, Project, User
        from app.models.enums import SeverityLevel, ScanStatus
        from app.services.reporting.finding_formatter import FindingFormatter
        from app.services.reporting.report_engine import ReportEngine
        from app.services.reporting.professional_html import generate_professional_html

        user = User(email="pipe@example.com", password_hash="pwd", name="Pipe")
        project = Project(name="PipeProject", owner=user)
        target = Target(url="https://pipeline-test.com", host="pipeline-test.com", project=project)
        scan = Scan(target=target, status=ScanStatus.COMPLETED, risk_score=75.0)
        f1 = Finding(scan=scan, severity=SeverityLevel.CRITICAL, passed=False, title="RCE", cvss_score=9.8)
        f2 = Finding(scan=scan, severity=SeverityLevel.HIGH, passed=False, title="SSRF", cvss_score=8.0)
        f3 = Finding(scan=scan, severity=SeverityLevel.LOW, passed=True, title="Info Leak", cvss_score=3.5)
        e1 = Evidence(scan=scan, finding=f1, type="http_request", data={"path": "/exec"})
        db_session.add_all([user, project, target, scan, f1, f2, f3, e1])
        db_session.commit()

        formatted = FindingFormatter.format_many([f1, f2, f3])
        assert len(formatted) == 3

        report = ReportEngine.build_professional(
            title="Pipeline Report",
            target_url=target.url,
            scan_date=scan.created_at.isoformat() if scan.created_at else "",
            risk_score=scan.risk_score or 0.0,
            findings=formatted,
        )

        assert report.executive_summary.total_findings == 3
        assert report.executive_summary.critical_count == 1
        assert report.executive_summary.high_count == 1
        assert report.executive_summary.low_count == 1
        assert report.findings[0].evidence_hash is not None

        html = generate_professional_html(report)
        assert "Pipeline Report" in html
        assert "RCE" in html
        assert "SSRF" in html
        assert "Info Leak" in html

    def test_json_export_of_professional_report(self):
        import json
        from app.services.reporting.report_engine import ReportEngine
        from app.services.reporting.exporters.json_exporter import JSONExporter

        report = ReportEngine.build_professional(
            title="JSON Pipeline",
            target_url="https://json-pipe.com",
            scan_date="2024-06-01",
            risk_score=42.0,
            findings=[],
        )
        output = JSONExporter.export(report)
        parsed = json.loads(output)
        assert parsed["title"] == "JSON Pipeline"
        assert parsed["executive_summary"]["security_score"] == 42.0
        assert parsed["executive_summary"]["risk_rating"] == "Medium"


# ===================================================================
# 19. Report schemas
# ===================================================================

class TestReportSchemas:
    """Pydantic schemas for reports."""

    def test_report_read_enhanced_fields(self):
        from app.schemas.report import ReportRead
        import uuid
        schema = ReportRead(
            id=uuid.uuid4(),
            project_id=str(uuid.uuid4()),
            scan_ids=[str(uuid.uuid4())],
            format="json",
            file_path="/tmp/report.json",
            title="Enhanced Report",
            risk_score=88.0,
            risk_rating="Critical",
            findings_count=12,
            severity_breakdown={"critical": 3, "high": 4},
        )
        assert schema.title == "Enhanced Report"
        assert schema.risk_score == 88.0
        assert schema.risk_rating == "Critical"
        assert schema.findings_count == 12

    def test_report_generate_response(self):
        from app.schemas.report import ReportGenerateResponse
        import uuid
        resp = ReportGenerateResponse(
            id=uuid.uuid4(),
            scan_id=str(uuid.uuid4()),
            report_id=str(uuid.uuid4()),
            status="generated",
            format="html",
            message="Report generated successfully.",
        )
        assert resp.status == "generated"
        assert resp.format == "html"


# ===================================================================
# 20. Exporter content type completeness
# ===================================================================

class TestExporterContentTypeCompleteness:
    """All exporters return correct content types."""

    def test_all_exporters_have_content_type(self):
        from app.services.reporting.exporters.json_exporter import JSONExporter
        from app.services.reporting.exporters.markdown_exporter import MarkdownExporter
        from app.services.reporting.pdf_generator import PDFExporter as ProfessionalPDFExporter
        assert JSONExporter.content_type() == "application/json"
        assert MarkdownExporter.content_type() == "text/markdown"
        assert ProfessionalPDFExporter.content_type() == "text/html"
