"""Findings API endpoints with search, filter, and pagination."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import Finding, Scan
from app.models.enums import FindingStatus, SeverityLevel
from app.schemas.finding import FindingRead

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("", response_model=dict)
def list_findings(
    db: Session = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    scan_id: str | None = Query(None),
    search: str | None = Query(None),
):
    query = db.query(Finding)

    if severity:
        try:
            sev_enum = SeverityLevel(severity)
            query = query.filter(Finding.severity == sev_enum)
        except ValueError:
            pass

    if status:
        try:
            status_enum = FindingStatus(status)
            query = query.filter(Finding.status == status_enum)
        except ValueError:
            pass

    if scan_id:
        try:
            query = query.filter(Finding.scan_id == uuid.UUID(scan_id))
        except ValueError:
            pass

    if search:
        search_term = f"%{search}%"
        query = query.filter(
            Finding.title.ilike(search_term) | Finding.detail.ilike(search_term)
        )

    total = query.count()
    findings = query.order_by(Finding.severity.asc()).offset(skip).limit(limit).all()

    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "items": [
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
        ],
    }


@router.get("/{finding_id}", response_model=dict)
def get_finding_detail(finding_id: uuid.UUID, db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    evidence = []
    for e in finding.evidence:
        evidence.append({
            "id": str(e.id),
            "type": e.type,
            "data": e.data,
            "request_data": e.request_data,
            "response_data": e.response_data,
            "request_headers": e.request_headers,
            "response_headers": e.response_headers,
            "response_body": e.response_body,
            "evidence_meta": e.evidence_meta,
        })

    compliance = []
    for cm in finding.compliance_mappings:
        compliance.append({
            "id": str(cm.id),
            "framework": cm.framework,
            "control_id": cm.control_id,
            "control_name": cm.control_name,
        })

    return {
        "id": str(finding.id),
        "scan_id": str(finding.scan_id),
        "rule_id": str(finding.rule_id) if finding.rule_id else None,
        "title": finding.title,
        "finding_type": finding.finding_type,
        "severity": finding.severity.value,
        "status": finding.status.value,
        "passed": finding.passed,
        "detail": finding.detail,
        "cvss_score": finding.cvss_score,
        "evidence": evidence,
        "compliance_mappings": compliance,
        "scan_url": finding.scan.target.url if finding.scan and finding.scan.target else None,
    }
