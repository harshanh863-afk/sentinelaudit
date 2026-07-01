"""Scan management API endpoints."""

import json
import uuid
from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.models import Finding, Project, Scan, Target
from app.models.enums import ScanStatus
from app.schemas.finding import FindingRead
from app.schemas.scan import ScanCreate, ScanRead
from app.services.reporting import FindingFormatter, ReportEngine

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanRead, status_code=201)
def create_scan(body: ScanCreate, db: Session = Depends(get_db)):
    target_uuid = uuid.UUID(body.target_id)
    target = db.query(Target).filter(Target.id == target_uuid).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    scan = Scan(target_id=target.id, status=ScanStatus.PENDING)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Dispatch async scan via Celery
    try:
        from app.workers.scan_tasks import start_scan_task
        start_scan_task.delay(str(scan.id))
    except Exception:
        pass

    return ScanRead(
        id=scan.id,
        target_id=str(scan.target_id),
        status=scan.status,
        risk_score=scan.risk_score,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error=scan.error,
        progress=scan.progress,
        progress_stage=scan.progress_stage,
        created_at=scan.created_at,
    )


@router.get("/{scan_id}", response_model=ScanRead)
def get_scan(scan_id: uuid.UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanRead(
        id=scan.id,
        target_id=str(scan.target_id),
        status=scan.status,
        risk_score=scan.risk_score,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        error=scan.error,
        progress=scan.progress,
        progress_stage=scan.progress_stage,
        created_at=scan.created_at,
    )


@router.get("/{scan_id}/findings", response_model=list[FindingRead])
def get_scan_findings(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [
        FindingRead(
            id=f.id,
            scan_id=str(f.scan_id),
            rule_id=str(f.rule_id) if f.rule_id else None,
            severity=f.severity,
            status=f.status,
            passed=f.passed,
            detail=f.detail,
        )
        for f in findings
    ]


@router.get("/{scan_id}/report")
def get_scan_report(scan_id: uuid.UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    formatted = FindingFormatter.format_many(findings)

    report = ReportEngine.build(
        title=f"Security Assessment - {scan.target.url}",
        target_url=scan.target.url,
        scan_date=scan.created_at.isoformat() if scan.created_at else "",
        risk_score=scan.risk_score or 0.0,
        findings=formatted,
    )

    return Response(content=json.dumps(asdict(report), default=str), media_type="application/json")
