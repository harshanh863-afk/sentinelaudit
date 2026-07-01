"""Orchestrates report generation from scan data."""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.services.reporting.models import (
    ProfessionalReport, ExecutiveSummary, FindingDetail,
    ComplianceSection, TechnicalAppendix, PrivacySection,
)
from app.services.privacy_engine.models import PrivacyAssessmentReport


@dataclass
class ReportData:
    """Full report data structure passed to exporters.

    Enhanced with risk_rating and findings_count for Phase 8 professional reporting.
    """

    title: str
    target_url: str
    scan_date: str
    risk_score: float
    findings: list = field(default_factory=list)
    compliance_summary: dict = field(default_factory=dict)
    methodology: str = ""
    executive_summary: str = ""
    remediation_summary: str = ""
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    risk_rating: str = ""
    findings_count: int = 0


def _risk_rating(score: float) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    if score >= 20:
        return "Low"
    return "Informational"


class ReportEngine:
    """Builds ReportData/ProfessionalReport and delegates to the requested exporter."""

    @staticmethod
    def build(
        *,
        title: str,
        target_url: str,
        scan_date: str,
        risk_score: float,
        findings: list,
        methodology: str = "",
        executive_summary: str = "",
        remediation_summary: str = "",
    ) -> ReportData:
        compliance_summary: dict[str, list[str]] = {}
        for f in findings:
            mappings = getattr(f, "compliance_mappings", []) or getattr(f, "compliance", [])
            for cm in mappings:
                if isinstance(cm, dict):
                    framework = cm.get("framework", "")
                    control = cm.get("control_id", "")
                else:
                    framework = getattr(cm, "framework", "")
                    control = getattr(cm, "control_id", "")
                if framework:
                    compliance_summary.setdefault(framework, []).append(control)

        return ReportData(
            title=title,
            target_url=target_url,
            scan_date=scan_date,
            risk_score=risk_score,
            findings=findings,
            compliance_summary=compliance_summary,
            methodology=methodology,
            executive_summary=executive_summary,
            remediation_summary=remediation_summary,
        )

    @staticmethod
    def build_professional(
        *,
        title: str,
        target_url: str,
        scan_date: str,
        risk_score: float,
        findings: list,
        methodology: str = "",
        executive_summary: str = "",
        remediation_summary: str = "",
        scanner_version: str = "",
        scan_duration: int = 0,
        compliance_scores: list[dict] | None = None,
        client_name: str = "",
        privacy_assessment: PrivacyAssessmentReport | None = None,
        scanner_modules: list[str] | None = None,
        evidence_collected: list[str] | None = None,
    ) -> ProfessionalReport:
        rating = _risk_rating(risk_score)

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        finding_details = []
        for f in findings:
            sev = getattr(f, "severity", "info") or "info"
            sev = sev.lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

            finding_details.append(FindingDetail(
                finding_id=getattr(f, "finding_id", uuid.uuid4()),
                title=getattr(f, "title", "") or "",
                severity=sev,
                status=getattr(f, "status", "new") or "new",
                detail=getattr(f, "detail", None),
                cvss_score=getattr(f, "cvss_score", None),
                evidence_summary=getattr(f, "evidence_summary", None),
                evidence_hash=getattr(f, "evidence_hash", None),
                remediation=getattr(f, "remediation", None),
                compliance=getattr(f, "compliance", []) or [],
                impact=getattr(f, "impact", "") or "",
                business_impact=getattr(f, "business_impact", "") or "",
                risk_explanation=getattr(f, "risk_explanation", "") or "",
                affected_component=getattr(f, "affected_component", "") or "",
                false_positive_notes=getattr(f, "false_positive_notes", "") or "",
                cwe=getattr(f, "cwe", []) or [],
                capec=getattr(f, "capec", []) or [],
                mitre_attack=getattr(f, "mitre_attack", []) or [],
            ))

        exec_summary = ExecutiveSummary(
            security_score=risk_score,
            risk_rating=rating,
            total_findings=len(findings),
            critical_count=severity_counts["critical"],
            high_count=severity_counts["high"],
            medium_count=severity_counts["medium"],
            low_count=severity_counts["low"],
            info_count=severity_counts["info"],
        )

        compliance_sections = []
        if compliance_scores:
            for cs in compliance_scores:
                compliance_sections.append(ComplianceSection(
                    framework=cs.get("framework", "unknown"),
                    score=cs.get("score", 0.0),
                    status=cs.get("status", "not_assessed"),
                    passed=cs.get("passed", 0),
                    failed=cs.get("failed", 0),
                    partial=cs.get("partial", 0),
                    not_applicable=cs.get("not_applicable", 0),
                    total=cs.get("total", 0),
                ))
            exec_summary.frameworks_assessed = [cs.framework for cs in compliance_sections]

        privacy_section = None
        if privacy_assessment:
            privacy_section = PrivacySection(
                privacy_score=privacy_assessment.score,
                gdpr_score=privacy_assessment.gdpr_score,
                ccpa_score=privacy_assessment.ccpa_score,
                coppa_score=privacy_assessment.coppa_score,
                cookie_score=privacy_assessment.cookie_score,
                detected_issues=privacy_assessment.failed_controls,
                recommendations=privacy_assessment.recommendations[:10],
            )
            exec_summary.privacy_score = privacy_assessment.score
            unique_regs: set[str] = set()
            for issue in privacy_assessment.issues:
                unique_regs.update(r.lower() for r in issue.affected_regulations)
            exec_summary.regulations_checked = sorted(unique_regs)

        appendix = TechnicalAppendix(
            scanner_version=scanner_version,
            scan_duration_seconds=scan_duration,
            methodology=methodology,
            target_info={"URL": target_url},
            scanner_modules=scanner_modules or [],
            evidence_collected=evidence_collected or [],
        )

        return ProfessionalReport(
            title=title,
            client_name=client_name,
            target_url=target_url,
            scan_date=scan_date,
            executive_summary=exec_summary,
            findings=finding_details,
            compliance_sections=compliance_sections,
            privacy_section=privacy_section,
            appendix=appendix,
            remediation_summary=remediation_summary,
        )
