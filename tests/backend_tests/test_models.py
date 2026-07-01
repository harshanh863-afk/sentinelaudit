"""Tests for ORM models: creation, relationships, enum validation."""

import uuid

import pytest
from sqlalchemy.exc import IntegrityError

from app.models import (
    ComplianceMapping,
    Evidence,
    Finding,
    Project,
    Report,
    Rule,
    Scan,
    Target,
    User,
)
from app.models.enums import FindingStatus, ScanStatus, SeverityLevel


class TestUserModel:
    """User creation, unique constraint, relationships."""

    def test_create_user(self, db_session):
        user = User(email="test@example.com", password_hash="abc123", name="Test User")
        db_session.add(user)
        db_session.commit()

        saved = db_session.query(User).filter_by(email="test@example.com").first()
        assert saved is not None
        assert saved.name == "Test User"
        assert saved.is_active is True
        assert isinstance(saved.id, uuid.UUID)

    def test_email_unique_constraint(self, db_session):
        user1 = User(email="dup@example.com", password_hash="a", name="A")
        user2 = User(email="dup@example.com", password_hash="b", name="B")
        db_session.add(user1)
        db_session.commit()
        db_session.add(user2)
        with pytest.raises(IntegrityError):
            db_session.commit()

    def test_user_projects_relationship(self, db_session):
        user = User(email="owner@example.com", password_hash="pwd", name="Owner")
        project = Project(name="Test Project", owner=user)
        db_session.add(user)
        db_session.commit()

        saved = db_session.query(User).first()
        assert len(saved.projects) == 1
        assert saved.projects[0].name == "Test Project"


class TestProjectModel:
    """Project-target-scan cascade chain."""

    def test_create_project(self, db_session):
        user = User(email="p@example.com", password_hash="pwd", name="P")
        project = Project(name="My Project", owner=user)
        db_session.add(project)
        db_session.commit()

        saved = db_session.query(Project).first()
        assert saved.name == "My Project"
        assert saved.owner_id == user.id

    def test_project_targets_cascade(self, db_session):
        user = User(email="u@example.com", password_hash="pwd", name="U")
        project = Project(name="Project", owner=user)
        target = Target(url="https://example.com", host="example.com", project=project)
        db_session.add(project)
        db_session.commit()

        db_session.delete(project)
        db_session.commit()
        assert db_session.query(Target).count() == 0


class TestScanAndStatusEnum:
    """Scan status enum lifecycle."""

    def test_scan_default_status(self, db_session):
        user = User(email="s@example.com", password_hash="pwd", name="S")
        project = Project(name="P", owner=user)
        target = Target(url="https://x.com", host="x.com", project=project)
        scan = Scan(target=target)
        db_session.add(scan)
        db_session.commit()

        saved = db_session.query(Scan).first()
        assert saved.status == ScanStatus.QUEUED

    def test_scan_status_transition(self, db_session):
        user = User(email="t@example.com", password_hash="pwd", name="T")
        project = Project(name="P", owner=user)
        target = Target(url="https://y.com", host="y.com", project=project)
        scan = Scan(target=target, status=ScanStatus.RUNNING)
        db_session.add(scan)
        db_session.commit()

        saved = db_session.query(Scan).first()
        assert saved.status == ScanStatus.RUNNING

    def test_scan_target_relationship(self, db_session):
        user = User(email="r@example.com", password_hash="pwd", name="R")
        project = Project(name="P", owner=user)
        target = Target(url="https://z.com", host="z.com", project=project)
        scan = Scan(target=target, status=ScanStatus.COMPLETED, risk_score=0.25)
        db_session.add(scan)
        db_session.commit()

        saved = db_session.query(Scan).first()
        assert saved.target.url == "https://z.com"
        assert saved.target.host == "z.com"
        assert saved.risk_score == 0.25

    def test_invalid_scan_status_raises(self):
        with pytest.raises(ValueError):
            ScanStatus("invalid_status")


class TestFindingModel:
    """Finding with severity, status, and relationships."""

    def test_create_finding(self, db_session):
        user = User(email="f@example.com", password_hash="pwd", name="F")
        project = Project(name="P", owner=user)
        target = Target(url="https://a.com", host="a.com", project=project)
        scan = Scan(target=target, status=ScanStatus.COMPLETED)
        finding = Finding(
            scan=scan,
            severity=SeverityLevel.HIGH,
            status=FindingStatus.NEW,
            passed=False,
            detail="Missing security header",
        )
        db_session.add(finding)
        db_session.commit()

        saved = db_session.query(Finding).first()
        assert saved.severity == SeverityLevel.HIGH
        assert saved.status == FindingStatus.NEW
        assert saved.passed is False
        assert saved.detail == "Missing security header"

    def test_finding_severity_levels(self, db_session):
        for sev in SeverityLevel:
            finding = Finding(
                scan_id=uuid.uuid4(),
                rule_id=None,
                severity=sev,
                status=FindingStatus.NEW,
                passed=True,
            )
            # No commit needed — validating enum instantiation
            assert finding.severity == sev

    def test_finding_status_values(self):
        assert FindingStatus.NEW.value == "new"
        assert FindingStatus.CONFIRMED.value == "confirmed"
        assert FindingStatus.FALSE_POSITIVE.value == "false_positive"
        assert FindingStatus.FIXED.value == "fixed"

    def test_invalid_severity_raises(self):
        with pytest.raises(ValueError):
            SeverityLevel("nonexistent")


class TestEvidenceModel:
    """Evidence linked to scan and optionally to finding."""

    def test_evidence_scan_relationship(self, db_session):
        user = User(email="e@example.com", password_hash="pwd", name="E")
        project = Project(name="P", owner=user)
        target = Target(url="https://b.com", host="b.com", project=project)
        scan = Scan(target=target)
        evidence = Evidence(
            scan=scan,
            type="http_headers",
            data={"content-type": "text/html"},
        )
        db_session.add(evidence)
        db_session.commit()

        saved = db_session.query(Evidence).first()
        assert saved.type == "http_headers"
        assert saved.data["content-type"] == "text/html"

    def test_evidence_optional_finding(self, db_session):
        user = User(email="ev@example.com", password_hash="pwd", name="Ev")
        project = Project(name="P", owner=user)
        target = Target(url="https://c.com", host="c.com", project=project)
        scan = Scan(target=target)
        finding = Finding(
            scan=scan,
            severity=SeverityLevel.LOW,
            status=FindingStatus.NEW,
            passed=True,
        )
        evidence = Evidence(
            scan=scan,
            finding=finding,
            type="raw_response",
            data={"status": 200},
        )
        db_session.add(evidence)
        db_session.commit()

        assert evidence.finding_id == finding.id


class TestRuleModel:
    """Rule with unique business key and findings relationship."""

    def test_create_rule(self, db_session):
        rule = Rule(
            rule_id="HTTP-001",
            name="Missing HSTS",
            category="http_security",
            severity=SeverityLevel.MEDIUM,
            description="HSTS header not set",
            remediation="Add Strict-Transport-Security header",
        )
        db_session.add(rule)
        db_session.commit()

        saved = db_session.query(Rule).first()
        assert saved.rule_id == "HTTP-001"
        assert saved.severity == SeverityLevel.MEDIUM

    def test_rule_id_unique(self, db_session):
        r1 = Rule(rule_id="TLS-001", name="TLS Check", category="tls", severity=SeverityLevel.HIGH)
        r2 = Rule(rule_id="TLS-001", name="Duplicate", category="tls", severity=SeverityLevel.HIGH)
        db_session.add(r1)
        db_session.commit()
        db_session.add(r2)
        with pytest.raises(IntegrityError):
            db_session.commit()


class TestComplianceMappingModel:
    """Compliance mapping with unique constraint."""

    def test_create_mapping(self, db_session):
        user = User(email="cm@example.com", password_hash="pwd", name="Cm")
        project = Project(name="P", owner=user)
        target = Target(url="https://d.com", host="d.com", project=project)
        scan = Scan(target=target)
        finding = Finding(scan=scan, severity=SeverityLevel.HIGH, status=FindingStatus.NEW, passed=False)
        mapping = ComplianceMapping(
            finding=finding,
            framework="owasp_top_10",
            control_id="A1",
            control_name="Broken Access Control",
        )
        db_session.add(mapping)
        db_session.commit()

        saved = db_session.query(ComplianceMapping).first()
        assert saved.framework == "owasp_top_10"
        assert saved.control_id == "A1"


class TestReportModel:
    """Report linked to project."""

    def test_create_report(self, db_session):
        user = User(email="rp@example.com", password_hash="pwd", name="Rp")
        project = Project(name="P", owner=user)
        report = Report(
            project=project,
            scan_ids=[str(uuid.uuid4())],
            format="pdf",
            file_path="/reports/report.pdf",
        )
        db_session.add(report)
        db_session.commit()

        saved = db_session.query(Report).first()
        assert saved.format == "pdf"
        assert len(saved.scan_ids) == 1


class TestRelationshipIntegrity:
    """Verify the full relationship chain works end-to-end."""

    def test_full_chain(self, db_session):
        user = User(email="chain@example.com", password_hash="pwd", name="Chain")
        project = Project(name="Chain Project", owner=user)
        target = Target(url="https://chain.com", host="chain.com", project=project)
        scan = Scan(target=target, status=ScanStatus.COMPLETED, risk_score=0.42)
        rule = Rule(rule_id="VULN-001", name="XSS", category="vulnerability", severity=SeverityLevel.HIGH)
        finding = Finding(
            scan=scan,
            rule=rule,
            severity=SeverityLevel.HIGH,
            status=FindingStatus.CONFIRMED,
            passed=False,
            detail="Reflected XSS in search param",
        )
        evidence = Evidence(scan=scan, finding=finding, type="raw_response", data={"param": "search"})
        mapping = ComplianceMapping(
            finding=finding, framework="owasp_top_10", control_id="A7", control_name="XSS"
        )
        report = Report(project=project, scan_ids=[str(scan.id)], format="json")

        db_session.add(user)
        db_session.commit()

        # Traverse: User → Project → Target → Scan → Finding → Evidence
        saved_user = db_session.query(User).first()
        saved_project = saved_user.projects[0]
        saved_target = saved_project.targets[0]
        saved_scan = saved_target.scans[0]
        saved_finding = saved_scan.findings[0]
        saved_evidence = saved_finding.evidence[0]
        saved_mapping = saved_finding.compliance_mappings[0]
        saved_report = saved_project.reports[0]

        assert saved_user.email == "chain@example.com"
        assert saved_project.name == "Chain Project"
        assert saved_target.url == "https://chain.com"
        assert saved_scan.risk_score == 0.42
        assert saved_finding.detail == "Reflected XSS in search param"
        assert saved_evidence.type == "raw_response"
        assert saved_mapping.control_id == "A7"
        assert saved_report.format == "json"
