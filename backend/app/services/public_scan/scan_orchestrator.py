"""Orchestrates anonymous public scans.

Creates temporary project/target/scan for a public URL,
dispatches the Celery scan task, and returns the scan ID.
"""

import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.models import Project, Scan, Target
from app.models.enums import ScanStatus


PUBLIC_PROJECT_NAME = "Public Scans"


def _get_or_create_public_project(db: Session) -> Project:
    project = db.query(Project).filter(Project.name == PUBLIC_PROJECT_NAME).first()
    if not project:
        project = Project(name=PUBLIC_PROJECT_NAME, description="Anonymous public security assessments")
        db.add(project)
        db.commit()
        db.refresh(project)
    return project


def _extract_host(url: str) -> str:
    return urlparse(url).hostname or url


def create_public_scan(db: Session, target_url: str) -> Scan:
    project = _get_or_create_public_project(db)

    target = Target(
        project_id=project.id,
        url=target_url,
        host=_extract_host(target_url),
    )
    db.add(target)
    db.flush()

    scan = Scan(
        target_id=target.id,
        status=ScanStatus.QUEUED,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    from app.workers.scan_tasks import start_scan_task
    try:
        start_scan_task.delay(str(scan.id))
    except Exception:
        pass

    return scan
