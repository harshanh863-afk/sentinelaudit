"""Celery tasks for scan lifecycle management.

Uses the ScanManager orchestrator to coordinate the full pipeline.
Individual scanner failures are captured and do not abort the scan.
"""

import logging
import uuid
from datetime import datetime, timezone

from app.db.session import SessionLocal
from app.models.enums import ScanStatus
from app.workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(
    bind=True,
    name="start_scan",
    max_retries=3,
    default_retry_delay=30,
)
def start_scan_task(self, scan_id: str) -> dict:
    """Create scan record and initiate the pipeline."""
    logger.info(f"TASK START: start_scan_task initialized for {scan_id}")

    with SessionLocal() as db:
        try:
            logger.info(f"TASK PROGRESS: Fetching scan record {scan_id} from DB")
            from app.models import Scan

            scan_uuid = uuid.UUID(scan_id)
            scan = db.query(Scan).filter(Scan.id == scan_uuid).first()
            if not scan:
                logger.error(f"TASK FAILED: Scan {scan_id} not found in DB")
                return {"status": "error", "detail": "Scan not found"}

            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.now(timezone.utc)
            db.commit()

            logger.info(f"TASK PROGRESS: Dispatching execute_pipeline for {scan_id}")
            execute_pipeline_task.delay(scan_id)
            logger.info(f"TASK SUCCESS: start_scan_task completed for {scan_id}")
            return {"status": "started", "scan_id": scan_id}
        except Exception as e:
            logger.error(f"TASK FAILED: Error in start_scan_task: {str(e)}", exc_info=True)
            raise e


@celery_app.task(
    bind=True,
    name="execute_pipeline",
    max_retries=2,
    default_retry_delay=60,
    task_track_started=True,
)
def execute_pipeline_task(self, scan_id: str) -> dict:
    """Execute the full scanner pipeline via ScanManager."""
    logger.info(f"TASK START: execute_pipeline_task initialized for {scan_id}")

    try:
        from app.services.orchestrator import ScanManager

        logger.info(f"TASK PROGRESS: Creating ScanManager for {scan_id}")
        manager = ScanManager(db_session_factory=SessionLocal)
        result = manager.run_pipeline(uuid.UUID(scan_id))
        logger.info(f"TASK SUCCESS: execute_pipeline_task completed for {scan_id}")
        return result
    except Exception as e:
        logger.error(f"TASK FAILED: Error in execute_pipeline_task: {str(e)}", exc_info=True)
        raise e


@celery_app.task(
    bind=True,
    name="finalize_scan",
    max_retries=2,
    default_retry_delay=30,
)
def finalize_scan_task(self, scan_id: str) -> dict:
    """Finalize scan — ensure status is set if not already complete."""
    logger.info(f"TASK START: finalize_scan_task initialized for {scan_id}")

    with SessionLocal() as db:
        try:
            from app.models import Scan

            scan_uuid = uuid.UUID(scan_id)
            scan = db.query(Scan).filter(Scan.id == scan_uuid).first()
            if not scan:
                logger.error(f"TASK FAILED: Scan {scan_id} not found in DB")
                return {"status": "error", "detail": "Scan not found"}

            if scan.status not in (ScanStatus.COMPLETED, ScanStatus.FAILED):
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.now(timezone.utc)
                scan.progress = 100
                db.commit()

            logger.info(f"TASK SUCCESS: finalize_scan_task completed for {scan_id}")
            return {
                "status": scan.status.value,
                "scan_id": scan_id,
                "risk_score": scan.risk_score,
            }
        except Exception as e:
            logger.error(f"TASK FAILED: Error in finalize_scan_task: {str(e)}", exc_info=True)
            raise e
