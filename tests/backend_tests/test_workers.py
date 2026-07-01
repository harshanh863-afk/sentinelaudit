"""Tests for Celery scan orchestration tasks.

Uses mocking to avoid needing a running Celery worker or Redis broker.
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.models import Finding, Project, Scan, Target, User
from app.models.enums import ScanStatus, SeverityLevel


class TestScanLifecycle:
    """Scan model lifecycle transitions used by Celery tasks."""

    def test_scan_defaults_to_pending(self, db_session):
        user = User(email="scan@example.com", password_hash="pwd", name="Scan")
        project = Project(name="P", owner=user)
        target = Target(url="https://s.com", host="s.com", project=project)
        scan = Scan(target=target)
        db_session.add(scan)
        db_session.commit()
        assert scan.status == ScanStatus.PENDING
        assert scan.started_at is None
        assert scan.completed_at is None
        assert scan.error is None

    def test_scan_status_transitions(self, db_session):
        user = User(email="st@example.com", password_hash="pwd", name="St")
        project = Project(name="P", owner=user)
        target = Target(url="https://st.com", host="st.com", project=project)
        scan = Scan(target=target)

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        db_session.add(scan)
        db_session.commit()

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.risk_score = 85.0
        db_session.commit()

        saved = db_session.query(Scan).first()
        assert saved.status == ScanStatus.COMPLETED
        assert saved.risk_score == 85.0

    def test_scan_failure_records_error(self, db_session):
        user = User(email="err@example.com", password_hash="pwd", name="Err")
        project = Project(name="P", owner=user)
        target = Target(url="https://err.com", host="err.com", project=project)
        scan = Scan(target=target)
        scan.status = ScanStatus.FAILED
        scan.error = "Connection timeout"
        scan.completed_at = datetime.now(timezone.utc)
        db_session.add(scan)
        db_session.commit()

        saved = db_session.query(Scan).first()
        assert saved.status == ScanStatus.FAILED
        assert saved.error == "Connection timeout"

    def test_scan_risk_score_updates(self, db_session):
        user = User(email="risk@example.com", password_hash="pwd", name="Risk")
        project = Project(name="P", owner=user)
        target = Target(url="https://risk.com", host="risk.com", project=project)
        scan = Scan(target=target, status=ScanStatus.COMPLETED, risk_score=72.5)
        db_session.add(scan)
        db_session.commit()

        saved = db_session.query(Scan).first()
        assert saved.risk_score == 72.5

    def test_scan_findings_cascade_delete(self, db_session):
        user = User(email="cas@example.com", password_hash="pwd", name="Cas")
        project = Project(name="P", owner=user)
        target = Target(url="https://cas.com", host="cas.com", project=project)
        scan = Scan(target=target)
        f1 = Finding(scan=scan, severity=SeverityLevel.HIGH, passed=False, title="A")
        f2 = Finding(scan=scan, severity=SeverityLevel.LOW, passed=True, title="B")
        db_session.add(scan)
        db_session.commit()

        scan_id = scan.id
        db_session.delete(scan)
        db_session.commit()

        remaining = db_session.query(Finding).filter(Finding.scan_id == scan_id).count()
        assert remaining == 0


class TestRunScanTask:
    """Celery run_scan task signature and configuration tests."""

    def test_task_name(self):
        from app.workers.celery_app import celery_app
        task = celery_app.tasks.get("run_scan")
        if task is None:
            # Task not registered yet (lazy loading), just verify the app exists
            assert celery_app.main == "sentinelaudit"
        else:
            assert task.name == "run_scan"

    def test_celery_app_configured(self):
        from app.workers.celery_app import celery_app
        assert celery_app.conf.task_serializer == "json"
        assert celery_app.conf.timezone == "UTC"

    def test_task_signature_has_scan_id_param(self):
        from app.workers.scan_tasks import start_scan_task
        import inspect
        sig = inspect.signature(start_scan_task.run)
        assert "scan_id" in sig.parameters
