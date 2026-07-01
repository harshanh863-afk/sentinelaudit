"""Target management API endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import Project, Scan, Target
from app.schemas.scan import ScanRead
from app.schemas.target import TargetCreate, TargetRead

router = APIRouter(prefix="/targets", tags=["targets"])


@router.get("", response_model=list[TargetRead])
def list_targets(
    project_id: str | None = Query(None),
    db: Session = Depends(get_db),
):
    query = db.query(Target)
    if project_id:
        try:
            query = query.filter(Target.project_id == uuid.UUID(project_id))
        except ValueError:
            pass
    targets = query.order_by(Target.created_at.desc()).all()
    return [
        TargetRead(
            id=t.id,
            project_id=str(t.project_id) if t.project_id else "",
            url=t.url,
            host=t.host,
            port=t.port,
            tags=t.tags,
            created_at=t.created_at,
            updated_at=t.updated_at,
        )
        for t in targets
    ]


@router.get("/{target_id}", response_model=TargetRead)
def get_target(target_id: str, db: Session = Depends(get_db)):
    try:
        uid = uuid.UUID(target_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid target ID")
    target = db.query(Target).filter(Target.id == uid).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return TargetRead(
        id=target.id,
        project_id=str(target.project_id) if target.project_id else "",
        url=target.url,
        host=target.host,
        port=target.port,
        tags=target.tags,
        created_at=target.created_at,
        updated_at=target.updated_at,
    )


@router.get("/{target_id}/history", response_model=list[ScanRead])
def get_target_history(target_id: uuid.UUID, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    scans = (
        db.query(Scan)
        .filter(Scan.target_id == target_id)
        .order_by(Scan.created_at.desc())
        .limit(20)
        .all()
    )

    return [
        ScanRead(
            id=s.id,
            target_id=str(s.target_id),
            status=s.status,
            risk_score=s.risk_score,
            started_at=s.started_at,
            completed_at=s.completed_at,
            error=s.error,
            progress=s.progress,
            progress_stage=s.progress_stage,
            created_at=s.created_at,
        )
        for s in scans
    ]


@router.post("", response_model=TargetRead, status_code=201)
def create_target(body: TargetCreate, db: Session = Depends(get_db)):
    host = body.url.split("//")[-1].split("/")[0].split(":")[0]
    target = Target(
        url=body.url,
        host=host,
        port=body.port,
        tags=body.tags or {},
    )
    if body.tags and "project_id" in body.tags:
        target.project_id = uuid.UUID(body.tags["project_id"])
    db.add(target)
    db.commit()
    db.refresh(target)
    return TargetRead(
        id=target.id,
        project_id=str(target.project_id) if target.project_id else "",
        url=target.url,
        host=target.host,
        port=target.port,
        tags=target.tags,
        created_at=target.created_at,
        updated_at=target.updated_at,
    )
