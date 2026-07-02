"""Export API endpoints — JSON, SARIF, CycloneDX, SPDX."""

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import Finding, Scan
from app.services.enterprise.exports import (
    CycloneDXExporter,
    JSONExporter,
    SARIFExporter,
    SPDXExporter,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/exports")


def _get_scan_and_findings(scan_id: str, db: Session):
    try:
        sid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid scan ID: {scan_id}")
    scan = db.query(Scan).filter(Scan.id == sid).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = db.query(Finding).filter(Finding.scan_id == sid).all()
    scan_dict = {
        "id": str(scan.id),
        "target_url": scan.target.url if scan.target else "",
        "status": scan.status.value if scan.status else "",
        "started_at": str(scan.started_at) if scan.started_at else "",
        "completed_at": str(scan.completed_at) if scan.completed_at else "",
        "risk_score": scan.risk_score,
    }
    finding_dicts = []
    for f in findings:
        evidence = {}
        if f.evidence:
            ev_list = f.evidence if isinstance(f.evidence, list) else [f.evidence]
            if ev_list and len(ev_list) > 0:
                evidence = ev_list[0].data if hasattr(ev_list[0], "data") else {}
        finding_dicts.append({
            "id": str(f.id),
            "title": f.title,
            "severity": f.severity.value if f.severity else "info",
            "status": f.status.value if f.status else "new",
            "detail": f.detail,
            "cvss_score": f.cvss_score,
            "confidence": f.confidence,
            "evidence": evidence,
            "rule_id": str(f.rule_id) if f.rule_id else None,
            "rule_business_id": f.finding_type,
        })
    return scan_dict, finding_dicts


@router.get("/json/{scan_id}")
def export_json(scan_id: str, db: Session = Depends(get_db)):
    scan_dict, finding_dicts = _get_scan_and_findings(scan_id, db)
    content = JSONExporter.export(scan_dict, finding_dicts)
    return PlainTextResponse(content, media_type="application/json",
                             headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.json"})


@router.get("/sarif/{scan_id}")
def export_sarif(scan_id: str, db: Session = Depends(get_db)):
    scan_dict, finding_dicts = _get_scan_and_findings(scan_id, db)
    content = SARIFExporter.export(scan_dict, finding_dicts)
    return PlainTextResponse(content, media_type="application/json",
                             headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.sarif"})


@router.get("/cyclonedx/{scan_id}")
def export_cyclonedx(scan_id: str, db: Session = Depends(get_db)):
    scan_dict, finding_dicts = _get_scan_and_findings(scan_id, db)
    content = CycloneDXExporter.export(scan_dict, finding_dicts)
    return PlainTextResponse(content, media_type="application/json",
                             headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.cdx.json"})


@router.get("/spdx/{scan_id}")
def export_spdx(scan_id: str, db: Session = Depends(get_db)):
    scan_dict, finding_dicts = _get_scan_and_findings(scan_id, db)
    content = SPDXExporter.export(scan_dict, finding_dicts)
    return PlainTextResponse(content, media_type="application/json",
                             headers={"Content-Disposition": f"attachment; filename=scan-{scan_id}.spdx.json"})
