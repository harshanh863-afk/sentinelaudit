"""Report management API endpoints — generation, download, and status."""

import json
import uuid
from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models import Finding, Project, Report, Scan
from app.models.enums import ScanStatus
from app.schemas.report import ReportGenerateResponse, ReportRead
from app.services.reporting import (
    FindingFormatter, JSONExporter, ReportEngine,
    generate_professional_html, generate_pdf_html,
)
from app.services.reporting.pdf_generator import PDFExporter as ProfessionalPDFExporter

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/{scan_id}", response_model=ReportRead)
def get_report_for_scan(scan_id: uuid.UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    report = db.query(Report).filter(Report.scan_ids.contains([str(scan_id)])).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found for this scan")
    return ReportRead(
        id=report.id,
        project_id=str(report.project_id),
        scan_ids=report.scan_ids,
        format=report.format,
        file_path=report.file_path,
        title=report.title,
        risk_score=report.risk_score,
        risk_rating=report.risk_rating,
        findings_count=report.findings_count,
        severity_breakdown=report.severity_breakdown,
        generated_at=report.generated_at,
    )


@router.post("/{scan_id}/generate", response_model=ReportGenerateResponse, status_code=201)
def generate_report(
    scan_id: uuid.UUID,
    report_format: str = "json",
    db: Session = Depends(get_db),
):
    if report_format not in ("json", "html", "pdf"):
        raise HTTPException(status_code=400, detail="Unsupported format. Use json, html, or pdf.")

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=400, detail=f"Cannot generate report for scan in status: {scan.status.value}")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    formatted = FindingFormatter.format_many(findings)

    # Count severity breakdown
    severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity).lower()
        if sev in severity_breakdown:
            severity_breakdown[sev] += 1

    project = db.query(Project).filter(Project.id == scan.target.project_id).first()
    project_id = project.id if project else scan.target.project_id

    report = Report(
        project_id=project_id,
        scan_ids=[str(scan_id)],
        format=report_format,
        title=f"Security Assessment - {scan.target.url}",
        risk_score=scan.risk_score or 0.0,
        risk_rating="Critical" if (scan.risk_score or 0) >= 80 else "High" if (scan.risk_score or 0) >= 60 else "Medium" if (scan.risk_score or 0) >= 40 else "Low" if (scan.risk_score or 0) >= 20 else "Informational",
        findings_count=len(formatted),
        severity_breakdown=severity_breakdown,
        generated_at=scan.completed_at,
        file_path=None,
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    return ReportGenerateResponse(
        id=report.id,
        scan_id=str(scan_id),
        report_id=str(report.id),
        status="generated",
        format=report_format,
        message=f"Report generated successfully in {report_format} format.",
    )


@router.get("/{scan_id}/download/{report_format}")
def download_report(
    scan_id: uuid.UUID,
    report_format: str,
    db: Session = Depends(get_db),
):
    if report_format not in ("json", "html", "pdf"):
        raise HTTPException(status_code=400, detail="Unsupported format. Use json, html, or pdf.")

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    formatted = FindingFormatter.format_many(findings)

    report_data = ReportEngine.build(
        title=f"Security Assessment - {scan.target.url}",
        target_url=scan.target.url,
        scan_date=scan.created_at.isoformat() if scan.created_at else "",
        risk_score=scan.risk_score or 0.0,
        findings=formatted,
    )

    if report_format == "json":
        content = JSONExporter.export(report_data)
        media_type = "application/json"
        filename = f"report-{scan_id}-{scan.target.host or 'scan'}.json"
    elif report_format == "html":
        professional = ReportEngine.build_professional(
            title=report_data.title,
            target_url=report_data.target_url,
            scan_date=report_data.scan_date,
            risk_score=report_data.risk_score,
            findings=formatted,
            methodology=report_data.methodology,
            executive_summary=report_data.executive_summary,
            remediation_summary=report_data.remediation_summary,
        )
        content = generate_professional_html(professional)
        media_type = "text/html"
        filename = f"report-{scan_id}-{scan.target.host or 'scan'}.html"
    elif report_format == "pdf":
        professional = ReportEngine.build_professional(
            title=report_data.title,
            target_url=report_data.target_url,
            scan_date=report_data.scan_date,
            risk_score=report_data.risk_score,
            findings=formatted,
            methodology=report_data.methodology,
            executive_summary=report_data.executive_summary,
            remediation_summary=report_data.remediation_summary,
        )
        content = generate_pdf_html(professional)
        media_type = "text/html"
        filename = f"report-{scan_id}-{scan.target.host or 'scan'}.html"

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
