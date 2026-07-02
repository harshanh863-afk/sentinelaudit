"""Converts matched rules and observations into domain Finding objects."""

import uuid
from dataclasses import dataclass, field

from app.models.enums import FindingStatus, SeverityLevel
from app.services.rule_engine.rule_matcher import MatchResult, ScannerObservation


@dataclass
class FindingData:
    """Data transfer object for a generated finding, ready for DB persistence."""

    scan_id: uuid.UUID
    rule_id: uuid.UUID | None
    severity: str
    status: str
    passed: bool
    detail: str | None
    rule_business_id: str | None = None
    title: str = ""
    cvss_score: float | None = None
    impact: str = ""
    evidence_description: str = ""
    evidence: dict | None = None
    business_impact: str = ""
    risk_explanation: str = ""
    affected_component: str = ""
    false_positive_notes: str = ""
    compliance_mappings: list[dict] = field(default_factory=list)
    cwe: list[dict] = field(default_factory=list)
    capec: list[dict] = field(default_factory=list)
    mitre_attack: list[dict] = field(default_factory=list)


class FindingBuilder:
    """Builds FindingData objects from matched rules and observations."""

    @staticmethod
    def build(
        scan_id: uuid.UUID,
        match: MatchResult,
        observation: ScannerObservation,
    ) -> FindingData | None:
        if not match.matched or not match.rule:
            return None

        rule = match.rule
        compliance_mappings = [
            {
                "framework": c.framework,
                "control_id": c.control_id,
                "control_name": c.control_name,
            }
            for c in rule.compliance
        ]

        cwe_mappings = [
            {"cwe_id": c.cwe_id, "name": c.name}
            for c in rule.cwe
        ]

        capec_mappings = [
            {"capec_id": c.capec_id, "name": c.name}
            for c in rule.capec
        ]

        mitre_attack_mappings = [
            {"technique_id": c.technique_id, "name": c.name}
            for c in rule.mitre_attack
        ]

        return FindingData(
            scan_id=scan_id,
            rule_id=None,
            rule_business_id=rule.rule_id,
            severity=rule.severity.value,
            status=FindingStatus.NEW.value,
            passed=observation.passed,
            detail=observation.detail or rule.description,
            title=rule.name,
            cvss_score=rule.cvss_score,
            impact=rule.impact,
            evidence_description=rule.evidence_description,
            evidence=observation.evidence,
            business_impact=rule.business_impact,
            risk_explanation=rule.risk_explanation,
            affected_component=rule.affected_component,
            false_positive_notes=rule.false_positive_notes,
            compliance_mappings=compliance_mappings,
            cwe=cwe_mappings,
            capec=capec_mappings,
            mitre_attack=mitre_attack_mappings,
        )
