"""Formats Finding objects for report output."""

import uuid
from dataclasses import dataclass, field
from datetime import datetime

from app.services.reporting.evidence_hasher import hash_evidence_dict


@dataclass
class FormattedFinding:
    """A finding formatted for report inclusion."""

    finding_id: uuid.UUID
    title: str
    severity: str
    status: str
    detail: str | None
    cvss_score: float | None
    evidence_summary: str | None
    evidence_hash: str | None = None
    remediation: str | None = None
    confidence: float | None = None
    compliance: list[dict] = field(default_factory=list)
    impact: str = ""
    business_impact: str = ""
    risk_explanation: str = ""
    affected_component: str = ""
    false_positive_notes: str = ""
    cwe: list[dict] = field(default_factory=list)
    capec: list[dict] = field(default_factory=list)
    mitre_attack: list[dict] = field(default_factory=list)


class FindingFormatter:
    """Converts database Finding objects into FormattedFinding DTOs."""

    @staticmethod
    def format(finding) -> FormattedFinding:
        evidence = ""
        evidence_hash = None
        if finding.evidence:
            first = finding.evidence[0]
            evidence = first.type if first.type else ""
            if first.data:
                evidence_hash = hash_evidence_dict(first.data)

        return FormattedFinding(
            finding_id=finding.id,
            title=finding.title or finding.detail or "",
            severity=finding.severity.value,
            status=finding.status.value,
            detail=finding.detail,
            cvss_score=finding.cvss_score,
            evidence_summary=evidence or None,
            evidence_hash=evidence_hash,
            remediation=finding.rule.remediation if finding.rule and hasattr(finding.rule, 'remediation') else finding.detail,
            confidence=finding.confidence,
            compliance=[
                {"framework": m.framework, "control_id": m.control_id, "control_name": m.control_name}
                for m in finding.compliance_mappings
            ],
        )

    @staticmethod
    def format_many(findings: list) -> list[FormattedFinding]:
        return [FindingFormatter.format(f) for f in findings]
