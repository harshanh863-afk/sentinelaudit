"""Project management API endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import Project, Target, User
from app.schemas.project import ProjectCreate, ProjectRead, ProjectUpdate

router = APIRouter(prefix="/projects", tags=["projects"])

DEFAULT_USER_ID = "00000000-0000-0000-0000-000000000001"


@router.get("", response_model=list[ProjectRead])
def list_projects(db: Session = Depends(get_db)):
    projects = db.query(Project).order_by(Project.created_at.desc()).all()
    return [
        ProjectRead(
            id=p.id,
            name=p.name,
            description=p.description,
            owner_id=str(p.owner_id),
            created_at=p.created_at,
            updated_at=p.updated_at,
        )
        for p in projects
    ]


@router.post("", response_model=ProjectRead, status_code=201)
def create_project(body: ProjectCreate, db: Session = Depends(get_db)):
    owner_uuid = uuid.UUID(DEFAULT_USER_ID)
    owner = db.query(User).filter(User.id == owner_uuid).first()
    if not owner:
        owner = User(
            id=owner_uuid,
            email="default@sentinelaudit.io",
            password_hash="default",
            name="Default User",
        )
        db.add(owner)
        db.flush()

    project = Project(name=body.name, description=body.description, owner_id=owner.id)
    db.add(project)
    db.commit()
    db.refresh(project)
    return ProjectRead(
        id=project.id,
        name=project.name,
        description=project.description,
        owner_id=str(project.owner_id),
        created_at=project.created_at,
        updated_at=project.updated_at,
    )


@router.get("/{project_id}", response_model=ProjectRead)
def get_project(project_id: uuid.UUID, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    return ProjectRead(
        id=project.id,
        name=project.name,
        description=project.description,
        owner_id=str(project.owner_id),
        created_at=project.created_at,
        updated_at=project.updated_at,
    )


@router.put("/{project_id}", response_model=ProjectRead)
def update_project(project_id: uuid.UUID, body: ProjectUpdate, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if body.name is not None:
        project.name = body.name
    if body.description is not None:
        project.description = body.description
    db.commit()
    db.refresh(project)
    return ProjectRead(
        id=project.id,
        name=project.name,
        description=project.description,
        owner_id=str(project.owner_id),
        created_at=project.created_at,
        updated_at=project.updated_at,
    )


@router.delete("/{project_id}", status_code=204)
def delete_project(project_id: uuid.UUID, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    db.delete(project)
    db.commit()
    return None


@router.get("/{project_id}/targets", response_model=list)
def get_project_targets(project_id: uuid.UUID, db: Session = Depends(get_db)):
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    targets = (
        db.query(Target)
        .filter(Target.project_id == project_id)
        .order_by(Target.created_at.desc())
        .all()
    )
    return [
        {
            "id": str(t.id),
            "project_id": str(t.project_id),
            "url": t.url,
            "host": t.host,
            "port": t.port,
            "tags": t.tags,
            "created_at": t.created_at.isoformat() if t.created_at else None,
        }
        for t in targets
    ]


@router.get("/{project_id}/stats")
def get_project_stats(project_id: uuid.UUID, db: Session = Depends(get_db)):
    from app.models import Finding, Scan

    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    targets = db.query(Target).filter(Target.project_id == project_id).all()
    target_ids = [t.id for t in targets]

    scans = db.query(Scan).filter(Scan.target_id.in_(target_ids)).all() if target_ids else []
    total_findings = (
        db.query(Finding)
        .filter(Finding.scan_id.in_([s.id for s in scans]))
        .count()
        if scans
        else 0
    )

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    if scans:
        from sqlalchemy import func
        from app.models.enums import SeverityLevel

        results = (
            db.query(Finding.severity, func.count(Finding.id))
            .filter(Finding.scan_id.in_([s.id for s in scans]))
            .group_by(Finding.severity)
            .all()
        )
        for sev, cnt in results:
            label = sev.value if hasattr(sev, "value") else str(sev).lower()
            if label in severity_counts:
                severity_counts[label] = cnt

    return {
        "total_targets": len(targets),
        "total_scans": len(scans),
        "total_findings": total_findings,
        "severity_breakdown": severity_counts,
    }
