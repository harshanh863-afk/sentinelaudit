"""Dashboard summary API endpoint."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.db.session import get_db
from app.models import Finding, Project, Scan, Target
from app.models.enums import ScanStatus, SeverityLevel

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
def get_dashboard_summary(db: Session = Depends(get_db)):
    total_projects = db.query(Project).count()
    total_targets = db.query(Target).count()
    total_scans = db.query(Scan).count()
    completed_scans = db.query(Scan).filter(Scan.status == ScanStatus.COMPLETED).count()
    failed_scans = db.query(Scan).filter(Scan.status == ScanStatus.FAILED).count()

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    severity_results = (
        db.query(Finding.severity, func.count(Finding.id))
        .group_by(Finding.severity)
        .all()
    )
    for sev, cnt in severity_results:
        label = sev.value if hasattr(sev, "value") else str(sev).lower()
        if label in severity_counts:
            severity_counts[label] = cnt

    total_findings = sum(severity_counts.values())

    avg_risk = db.query(func.avg(Scan.risk_score)).filter(Scan.risk_score.isnot(None)).scalar()
    avg_risk = round(float(avg_risk), 1) if avg_risk else 0.0

    recent_scans = (
        db.query(Scan)
        .order_by(Scan.created_at.desc())
        .limit(10)
        .all()
    )

    return {
        "total_projects": total_projects,
        "total_targets": total_targets,
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "failed_scans": failed_scans,
        "total_findings": total_findings,
        "severity_breakdown": severity_counts,
        "average_risk_score": avg_risk,
        "recent_scans": [
            {
                "id": str(s.id),
                "target_id": str(s.target_id),
                "status": s.status.value,
                "risk_score": s.risk_score,
                "progress": s.progress,
                "progress_stage": s.progress_stage,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "error": s.error,
            }
            for s in recent_scans
        ],
    }


@router.get("/compliance-overview")
def get_compliance_overview(db: Session = Depends(get_db)):
    from app.models import ComplianceMapping, Finding
    from app.models.enums import FindingStatus

    statuses = [FindingStatus.CONFIRMED, FindingStatus.NEW, FindingStatus.ACCEPTED_RISK]

    findings_with_mappings = (
        db.query(ComplianceMapping.framework, ComplianceMapping.control_id, Finding.status)
        .join(Finding, ComplianceMapping.finding_id == Finding.id)
        .filter(Finding.status.in_(statuses), Finding.passed == False)
        .distinct()
        .all()
    )

    framework_controls: dict[str, dict] = {}
    from app.services.compliance_engine import list_frameworks, get_framework

    frameworks = list_frameworks()

    for fw_key in frameworks:
        fw_def = get_framework(fw_key)
        if fw_def:
            framework_controls[fw_key] = {
                "name": fw_def.name,
                "total": len(fw_def.controls),
                "passed": len(fw_def.controls),
                "failed": 0,
                "score": 100.0,
            }

    for fw, ctrl_id, status in findings_with_mappings:
        if fw in framework_controls:
            framework_controls[fw]["failed"] += 1
            framework_controls[fw]["passed"] = max(
                0, framework_controls[fw]["total"] - framework_controls[fw]["failed"]
            )

    results = []
    for fw_key, data in framework_controls.items():
        total = data["total"]
        score = round((data["passed"] / total * 100), 1) if total > 0 else 0.0
        results.append({
            "framework_key": fw_key,
            "name": data["name"],
            "total_controls": total,
            "passed": data["passed"],
            "failed": data["failed"],
            "score": score,
        })

    avg_score = round(sum(r["score"] for r in results) / len(results), 1) if results else 0.0

    return {
        "frameworks": results,
        "overall_score": avg_score,
        "total_frameworks": len(results),
    }
