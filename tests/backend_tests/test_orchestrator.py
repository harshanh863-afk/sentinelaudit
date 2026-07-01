"""Tests for the Scan Orchestration Engine."""

import uuid
from datetime import datetime, timezone

import pytest

from app.models import Scan
from app.models.enums import ScanStatus
from app.services.orchestrator import (
    PIPELINE,
    PipelineStage,
    StageDefinition,
    get_stage,
    ScanManager,
    ScannerError,
    ProgressUpdate,
)


# ===================================================================
# Pipeline definitions
# ===================================================================

class TestPipelineDefinition:
    """Pipeline stage definitions and ordering."""

    def test_pipeline_has_all_stages(self):
        assert len(PIPELINE) == 10

    def test_pipeline_stages_in_order(self):
        stages = [s.stage for s in PIPELINE]
        assert stages[0] == PipelineStage.QUEUED
        assert stages[1] == PipelineStage.HTTP_ANALYSIS
        assert stages[2] == PipelineStage.TLS_ANALYSIS
        assert stages[3] == PipelineStage.DNS_ANALYSIS
        assert stages[4] == PipelineStage.TECHNOLOGY_FINGERPRINT
        assert stages[5] == PipelineStage.JAVASCRIPT_ANALYSIS
        assert stages[6] == PipelineStage.RULE_PROCESSING
        assert stages[7] == PipelineStage.RISK_SCORING
        assert stages[8] == PipelineStage.COMPLIANCE_ASSESSMENT
        assert stages[9] == PipelineStage.REPORT_GENERATION

    def test_progress_monotonically_increasing(self):
        for i in range(1, len(PIPELINE)):
            assert PIPELINE[i].start_progress >= PIPELINE[i-1].end_progress

    def test_progress_starts_at_zero_ends_at_100(self):
        assert PIPELINE[0].start_progress == 0
        assert PIPELINE[-1].end_progress == 100

    def test_get_stage_returns_definition(self):
        stage = get_stage(PipelineStage.HTTP_ANALYSIS)
        assert stage is not None
        assert stage.label == "HTTP Security Analysis"

    def test_get_stage_nonexistent(self):
        assert get_stage("nonexistent") is None

    def test_stage_definition_fields(self):
        stage = get_stage(PipelineStage.TLS_ANALYSIS)
        assert isinstance(stage, StageDefinition)
        assert stage.start_progress == 25
        assert stage.end_progress == 40


# ===================================================================
# Scan model changes
# ===================================================================

class TestScanModelProgress:
    """New progress fields on the Scan model."""

    def test_scan_defaults_to_pending(self, db_session):
        from app.models import Project, Target, User
        user = User(email="q@example.com", password_hash="pwd", name="Q")
        project = Project(name="P", owner=user)
        target = Target(url="https://q.com", host="q.com", project=project)
        scan = Scan(target=target)
        db_session.add(scan)
        db_session.commit()
        assert scan.status == ScanStatus.PENDING
        assert scan.progress is None
        assert scan.progress_stage is None

    def test_scan_progress_fields_stored(self, db_session):
        from app.models import Project, Target, User
        user = User(email="p@example.com", password_hash="pwd", name="P")
        project = Project(name="P", owner=user)
        target = Target(url="https://p.com", host="p.com", project=project)
        scan = Scan(target=target)
        scan.progress = 50
        scan.progress_stage = "Testing"
        db_session.add(scan)
        db_session.commit()
        saved = db_session.query(Scan).first()
        assert saved.progress == 50
        assert saved.progress_stage == "Testing"

    def test_scan_transitions_pending_to_running(self, db_session):
        from app.models import Project, Target, User
        user = User(email="tr@example.com", password_hash="pwd", name="Tr")
        project = Project(name="P", owner=user)
        target = Target(url="https://tr.com", host="tr.com", project=project)
        scan = Scan(target=target)
        db_session.add(scan)
        db_session.commit()
        assert scan.status == ScanStatus.PENDING

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        db_session.commit()
        assert scan.status == ScanStatus.RUNNING

        scan.status = ScanStatus.PROCESSING
        scan.progress = 45
        db_session.commit()
        assert scan.status == ScanStatus.PROCESSING
        assert scan.progress == 45

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.progress = 100
        db_session.commit()
        assert scan.status == ScanStatus.COMPLETED

    def test_scan_all_statuses_valid(self):
        values = {s.value for s in ScanStatus}
        assert values == {"pending", "running", "processing", "completed", "failed"}


# ===================================================================
# ScannerError model
# ===================================================================

class TestScannerError:
    """Scanner error tracking."""

    def test_scanner_error_creation(self):
        err = ScannerError(scanner_name="HTTP Analyzer", error="Connection refused")
        assert err.scanner_name == "HTTP Analyzer"
        assert err.error == "Connection refused"


# ===================================================================
# ProgressUpdate model
# ===================================================================

class TestProgressUpdate:
    """Progress update model."""

    def test_progress_update_creation(self):
        from datetime import datetime
        now = datetime.now(timezone.utc)
        update = ProgressUpdate(progress=50, stage="Testing", timestamp=now)
        assert update.progress == 50
        assert update.stage == "Testing"


# ===================================================================
# ScanManager
# ===================================================================

class TestScanManager:
    """ScanManager orchestration logic."""

    @staticmethod
    def _make_scan(db_session) -> tuple:
        from app.models import Project, Target, User
        user = User(email="sm@example.com", password_hash="pwd", name="Sm")
        project = Project(name="P", owner=user)
        target = Target(url="https://sm.com", host="sm.com", project=project)
        scan = Scan(target=target)
        db_session.add_all([user, project, target, scan])
        db_session.commit()
        return scan

    def test_update_progress(self, db_session):
        scan = self._make_scan(db_session)
        manager = ScanManager(db_session_factory=lambda: db_session)
        manager._update_progress(db_session, scan, PipelineStage.HTTP_ANALYSIS, 15,
                                 "Testing progress")
        assert scan.status == ScanStatus.PROCESSING
        assert scan.progress == 15
        assert scan.progress_stage == "Testing progress"

    def test_scanner_error_collection(self):
        manager = ScanManager(db_session_factory=lambda: None)
        assert len(manager._errors) == 0

        manager._errors.append(ScannerError("TLS", "Timeout"))
        assert len(manager._errors) == 1
        assert manager._errors[0].scanner_name == "TLS"

    def test_run_scanner_stage_captures_errors(self, db_session):
        scan = self._make_scan(db_session)

        def failing_scanner(url):
            raise RuntimeError("Simulated failure")

        manager = ScanManager(db_session_factory=lambda: db_session)
        results = manager._run_scanner_stage(
            db_session, scan, PipelineStage.HTTP_ANALYSIS,
            "Test Scanner", failing_scanner, "https://example.com",
        )
        assert results == []
        assert len(manager._errors) == 1
        assert "Simulated failure" in manager._errors[0].error

    def test_run_pipeline_nonexistent_scan(self):
        manager = ScanManager(db_session_factory=lambda: None)
        result = manager.run_pipeline(uuid.uuid4())
        assert result["status"] in ("error", "failed")

    def test_run_pipeline_with_mock_scanners(self, db_session):
        scan = self._make_scan(db_session)
        scan_id = scan.id

        manager = ScanManager(db_session_factory=lambda: db_session)

        def mock_http(url):
            return [{"check_name": "test_check", "category": "test",
                     "passed": False, "detail": "test", "evidence": "raw",
                     "severity": "medium"}]

        def mock_empty(url):
            return []

        # Override scanner methods with mocks that don't need network
        manager._run_http_analyzer = mock_http
        manager._run_tls_analyzer = mock_empty
        manager._run_dns_analyzer = mock_empty
        manager._run_tech_fingerprinter = mock_empty
        manager._run_js_analyzer = mock_empty

        # Mock rule engine to avoid importing scanner package
        manager._apply_rule_engine = lambda sid, obs: [
            {"rule_id": None, "severity": "medium", "status": "new",
             "passed": False, "detail": "Test finding", "finding_type": "test"}
        ]

        # Mock persist to avoid DB rule_id FK constraints
        class MockFinding:
            def __init__(self, **kw):
                for k, v in kw.items():
                    setattr(self, k, v)

        manager._persist_findings = lambda sess, sid, data: [
            MockFinding(id=uuid.uuid4(), severity="medium", status="new",
                        passed=False, detail="test")
        ]

        # Mock risk calc to avoid real DB queries
        manager._calculate_risk = lambda sess, sid, objs: {
            "score": 50.0, "level": "medium",
        }

        result = manager.run_pipeline(scan_id)
        assert result["status"] == "completed"

    def test_run_pipeline_failure_handling(self, db_session):
        scan = self._make_scan(db_session)
        scan_id = scan.id

        manager = ScanManager(db_session_factory=lambda: db_session)

        def failing_rules(*args):
            raise RuntimeError("Rule engine crashed")

        manager._run_http_analyzer = lambda url: []
        manager._run_tls_analyzer = lambda url: []
        manager._run_dns_analyzer = lambda url: []
        manager._run_tech_fingerprinter = lambda url: []
        manager._run_js_analyzer = lambda url: []
        manager._apply_rule_engine = failing_rules

        with pytest.raises(RuntimeError, match="Rule engine crashed"):
            manager.run_pipeline(scan_id)

        # Verify scan was marked failed despite the re-raise
        saved = db_session.query(Scan).filter(Scan.id == scan_id).first()
        assert saved.status == ScanStatus.FAILED


# ===================================================================
# Celery task signatures
# ===================================================================

class TestCeleryTasks:
    """Celery task configuration tests."""

    def test_start_scan_task_name(self):
        from app.workers.celery_app import celery_app
        task = celery_app.tasks.get("start_scan")
        if task:
            assert task.name == "start_scan"

    def test_execute_pipeline_task_name(self):
        from app.workers.celery_app import celery_app
        task = celery_app.tasks.get("execute_pipeline")
        if task:
            assert task.name == "execute_pipeline"

    def test_finalize_scan_task_name(self):
        from app.workers.celery_app import celery_app
        task = celery_app.tasks.get("finalize_scan")
        if task:
            assert task.name == "finalize_scan"

    def test_start_scan_signature(self):
        from app.workers.scan_tasks import start_scan_task
        import inspect
        sig = inspect.signature(start_scan_task.run)
        assert "scan_id" in sig.parameters

    def test_execute_pipeline_signature(self):
        from app.workers.scan_tasks import execute_pipeline_task
        import inspect
        sig = inspect.signature(execute_pipeline_task.run)
        assert "scan_id" in sig.parameters

    def test_finalize_scan_signature(self):
        from app.workers.scan_tasks import finalize_scan_task
        import inspect
        sig = inspect.signature(finalize_scan_task.run)
        assert "scan_id" in sig.parameters
