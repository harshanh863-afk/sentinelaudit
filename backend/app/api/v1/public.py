"""Public scan API endpoints — anonymous website security assessment.

No authentication required.
"""

import json
import logging
import uuid
from dataclasses import asdict

logger = logging.getLogger(__name__)

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import Finding, Scan
from app.models.enums import ScanStatus
from app.services.public_scan import InMemoryRateLimiter, URLValidator, URLValidationError
from app.services.public_scan.scan_orchestrator import create_public_scan
from app.services.reporting import (
    FindingFormatter, ReportEngine,
    generate_professional_html,
)
from app.services.reporting.pdf_generator import PDFExporter as ProfessionalPDFExporter
from app.core.config import settings

router = APIRouter(prefix="/v1/public", tags=["public"])

def _compute_compliance_scores(formatted_findings: list) -> list[dict]:
    try:
        from app.services.compliance_engine import assess_findings, build_report
        assessments = assess_findings(formatted_findings)
        if assessments:
            assessment_report = build_report(assessments)
            return [
                {
                    "framework": fa.framework_key,
                    "score": fa.score,
                    "status": "compliant" if fa.score >= 80 else "non_compliant" if fa.score < 50 else "partially_compliant",
                    "passed": fa.passed,
                    "failed": fa.failed,
                    "partial": fa.partial,
                    "not_applicable": fa.not_applicable,
                    "total": fa.assessed_controls,
                }
                for fa in assessment_report.assessments
            ]
    except Exception:
        logger.warning("Compliance assessment skipped", exc_info=True)
    return []


rate_limiter = InMemoryRateLimiter(
    max_requests=settings.public_scan_max_per_hour,
    window_seconds=3600,
)


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.post("/scan", status_code=201)
def start_public_scan(body: dict, request: Request, db: Session = Depends(get_db)):
    client_ip = _get_client_ip(request)

    if not rate_limiter.is_allowed(client_ip):
        remaining = rate_limiter.remaining(client_ip)
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. {remaining} scans remaining this hour.",
        )

    target_url = body.get("target_url", "").strip()
    if not target_url:
        raise HTTPException(status_code=400, detail="target_url is required")
    if len(target_url) > 2048:
        raise HTTPException(status_code=400, detail="target_url exceeds maximum length (2048)")

    try:
        target_url = URLValidator.validate(target_url)
    except URLValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        scan = create_public_scan(db, target_url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")

    return {
        "scan_id": str(scan.id),
        "status": scan.status.value,
        "created_at": scan.created_at.isoformat() if scan.created_at else "",
    }


@router.get("/scan/{scan_id}")
def get_public_scan(scan_id: uuid.UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": str(scan.id),
        "status": scan.status.value,
        "progress": scan.progress or 0,
        "current_stage": scan.progress_stage or "",
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "error": scan.error,
        "risk_score": scan.risk_score,
        "target_url": scan.target.url if scan.target else "",
    }


@router.get("/report/{scan_id}")
def get_public_report(scan_id: uuid.UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan is not yet completed")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    formatted = FindingFormatter.format_many(findings)

    compliance_scores = _compute_compliance_scores(formatted)
    scanner_results = scan.scanner_results or []
    scanner_modules_list = [sr.get("name", "") for sr in scanner_results] if scanner_results else None

    professional = ReportEngine.build_professional(
        title=f"Security Assessment - {scan.target.url}",
        target_url=scan.target.url,
        scan_date=scan.created_at.isoformat() if scan.created_at else "",
        risk_score=scan.risk_score or 0.0,
        findings=formatted,
        scanner_version="1.0.0",
        scan_duration=0,
        compliance_scores=compliance_scores,
        scanner_results=scanner_results,
        scanner_modules=scanner_modules_list,
    )

    return Response(
        content=json.dumps(asdict(professional), default=str),
        media_type="application/json",
    )


@router.get("/report/{scan_id}/download/{report_format}")
def download_public_report(
    scan_id: uuid.UUID,
    report_format: str,
    db: Session = Depends(get_db),
):
    if report_format not in ("json", "html", "pdf"):
        raise HTTPException(status_code=400, detail="Unsupported format. Use json, html, or pdf.")

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Scan is not yet completed")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    formatted = FindingFormatter.format_many(findings)

    compliance_scores = _compute_compliance_scores(formatted)
    scanner_results = scan.scanner_results or []
    scanner_modules_list = [sr.get("name", "") for sr in scanner_results] if scanner_results else None

    professional = ReportEngine.build_professional(
        title=f"Security Assessment - {scan.target.url}",
        target_url=scan.target.url,
        scan_date=scan.created_at.isoformat() if scan.created_at else "",
        risk_score=scan.risk_score or 0.0,
        findings=formatted,
        scanner_version="1.0.0",
        scan_duration=0,
        compliance_scores=compliance_scores,
        scanner_results=scanner_results,
        scanner_modules=scanner_modules_list,
    )

    scan_id_str = str(scan_id)
    if report_format == "json":
        content = json.dumps(asdict(professional), default=str, indent=2)
        media_type = "application/json"
        filename = f"sentinel-report-{scan_id_str[:8]}.json"
    elif report_format == "html":
        content = generate_professional_html(professional)
        media_type = "text/html"
        filename = f"sentinel-report-{scan_id_str[:8]}.html"
    elif report_format == "pdf":
        pdf_html = generate_professional_html(professional)
        content = ProfessionalPDFExporter.export(pdf_html)
        media_type = "application/pdf"
        filename = f"sentinel-report-{scan_id_str[:8]}.pdf"

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
