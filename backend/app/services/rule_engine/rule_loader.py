"""Loads and parses YAML security rule definitions from the rules directory."""

import os
from dataclasses import dataclass, field

import yaml

from app.models.enums import SeverityLevel


@dataclass
class ComplianceRef:
    framework: str
    control_id: str
    control_name: str


@dataclass
class CweRef:
    cwe_id: str
    name: str


@dataclass
class CapecRef:
    capec_id: str
    name: str


@dataclass
class MitreAttackRef:
    technique_id: str
    name: str


@dataclass
class RuleDefinition:
    rule_id: str
    name: str
    category: str
    severity: SeverityLevel
    description: str
    remediation: str
    cvss_score: float | None = None
    impact: str = ""
    evidence_description: str = ""
    business_impact: str = ""
    risk_explanation: str = ""
    affected_component: str = ""
    false_positive_notes: str = ""
    references: list[str] = field(default_factory=list)
    compliance: list[ComplianceRef] = field(default_factory=list)
    cwe: list[CweRef] = field(default_factory=list)
    capec: list[CapecRef] = field(default_factory=list)
    mitre_attack: list[MitreAttackRef] = field(default_factory=list)


class RuleLoader:
    """Loads YAML rule files from a directory tree into RuleDefinition objects."""

    def __init__(self, rules_path: str | None = None):
        self.rules_path = rules_path or self._default_rules_path()

    @staticmethod
    def _default_rules_path() -> str:
        return os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "rules")

    def load_all(self) -> list[RuleDefinition]:
        rules: list[RuleDefinition] = []
        rules_dir = os.path.abspath(self.rules_path)
        if not os.path.isdir(rules_dir):
            return rules

        for root, _dirs, files in os.walk(rules_dir):
            for filename in sorted(files):
                if not filename.endswith((".yaml", ".yml")):
                    continue
                filepath = os.path.join(root, filename)
                rules.extend(self._load_file(filepath))

        return rules

    def _load_file(self, filepath: str) -> list[RuleDefinition]:
        try:
            with open(filepath, encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except (yaml.YAMLError, OSError):
            return []

        if not data or "rules" not in data:
            return []

        return [self._parse_rule(item) for item in data["rules"] if isinstance(item, dict)]

    @staticmethod
    def _parse_rule(item: dict) -> RuleDefinition:
        compliance_raw = item.get("compliance", []) or []
        compliance = [
            ComplianceRef(
                framework=c.get("framework", ""),
                control_id=c.get("control_id", ""),
                control_name=c.get("control_name", ""),
            )
            for c in compliance_raw
        ]

        cwe_raw = item.get("cwe", []) or []
        cwe = [
            CweRef(
                cwe_id=c.get("cwe_id", ""),
                name=c.get("name", ""),
            )
            for c in cwe_raw
        ]

        capec_raw = item.get("capec", []) or []
        capec = [
            CapecRef(
                capec_id=c.get("capec_id", ""),
                name=c.get("name", ""),
            )
            for c in capec_raw
        ]

        mitre_attack_raw = item.get("mitre_attack", []) or []
        mitre_attack = [
            MitreAttackRef(
                technique_id=c.get("technique_id", ""),
                name=c.get("name", ""),
            )
            for c in mitre_attack_raw
        ]

        cvss = item.get("cvss_score")
        cvss_score: float | None = None
        if cvss is not None:
            try:
                cvss_score = float(cvss)
            except (ValueError, TypeError):
                cvss_score = None

        return RuleDefinition(
            rule_id=str(item.get("id", "")),
            name=str(item.get("name", "")),
            category=str(item.get("category", "")),
            severity=SeverityLevel(item.get("severity", "info")),
            description=str(item.get("description", "")),
            remediation=str(item.get("remediation", "")),
            cvss_score=cvss_score,
            impact=str(item.get("impact", "")),
            evidence_description=str(item.get("evidence_description", "")),
            business_impact=str(item.get("business_impact", "")),
            risk_explanation=str(item.get("risk_explanation", "")),
            affected_component=str(item.get("affected_component", "")),
            false_positive_notes=str(item.get("false_positive_notes", "")),
            references=item.get("references", []) or [],
            compliance=compliance,
            cwe=cwe,
            capec=capec,
            mitre_attack=mitre_attack,
        )
