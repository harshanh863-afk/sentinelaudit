"""Celery tasks for scan lifecycle management.

Uses the ScanManager orchestrator to coordinate the full pipeline.
Individual scanner failures are captured and do not abort the scan.
"""

import uuid
from datetime import datetime, timezone

from celery import Task

from app.models.enums import ScanStatus
from app.workers.celery_app import celery_app


class DatabaseTask(Task):
    """Base task with a lazy database session."""

    _db = None

    def after_return(self, status, retval, task_id, args, kwargs, einfo):
        if self._db is not None:
            self._db.close()
            self._db = None

    @property
    def db(self):
        if self._db is None:
            from app.db.session import SessionLocal
            self._db = SessionLocal()
        return self._db


@celery_app.task(
    bind=True,
    base=DatabaseTask,
    name="start_scan",
    max_retries=3,
    default_retry_delay=30,
)
def start_scan_task(self, scan_id: str) -> dict:
    """Create scan record and initiate the pipeline."""
    from app.models import Scan

    scan_uuid = uuid.UUID(scan_id)
    session = self.db

    scan = session.query(Scan).filter(Scan.id == scan_uuid).first()
    if not scan:
        return {"status": "error", "detail": "Scan not found"}

    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.now(timezone.utc)
    session.commit()

    # Dispatch the pipeline execution
    execute_pipeline_task.delay(scan_id)
    return {"status": "started", "scan_id": scan_id}


@celery_app.task(
    bind=True,
    base=DatabaseTask,
    name="execute_pipeline",
    max_retries=2,
    default_retry_delay=60,
    task_track_started=True,
)
def execute_pipeline_task(self, scan_id: str) -> dict:
    """Execute the full scanner pipeline via ScanManager."""
    from app.db.session import SessionLocal
    from app.services.orchestrator import ScanManager

    manager = ScanManager(db_session_factory=SessionLocal)
    result = manager.run_pipeline(uuid.UUID(scan_id))
    return result


@celery_app.task(
    bind=True,
    base=DatabaseTask,
    name="finalize_scan",
    max_retries=2,
    default_retry_delay=30,
)
def finalize_scan_task(self, scan_id: str) -> dict:
    """Finalize scan — ensure status is set if not already complete."""
    from app.models import Scan

    scan_uuid = uuid.UUID(scan_id)
    session = self.db

    scan = session.query(Scan).filter(Scan.id == scan_uuid).first()
    if not scan:
        return {"status": "error", "detail": "Scan not found"}

    if scan.status not in (ScanStatus.COMPLETED, ScanStatus.FAILED):
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.progress = 100
        session.commit()

    return {
        "status": scan.status.value,
        "scan_id": scan_id,
        "risk_score": scan.risk_score,
    }
