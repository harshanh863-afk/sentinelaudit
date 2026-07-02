"""Loads and parses YAML security rule definitions from the rules directory."""

import logging
import os
from dataclasses import dataclass, field

import yaml

from app.models.enums import SeverityLevel

logger = logging.getLogger(__name__)


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
class ConfidenceModifier:
    condition: str
    adjustment: float


@dataclass
class VerificationRequirement:
    step: str
    expected: str


@dataclass
class RemediationTemplate:
    environment: str
    steps: list[str]


@dataclass
class ExternalDoc:
    title: str
    url: str


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
    # Phase 9 new optional fields
    confidence_modifiers: list[ConfidenceModifier] = field(default_factory=list)
    required_evidence_types: list[str] = field(default_factory=list)
    verification_requirements: list[VerificationRequirement] = field(default_factory=list)
    attack_references: list[str] = field(default_factory=list)
    owasp_asvs: list[str] = field(default_factory=list)
    remediation_templates: list[RemediationTemplate] = field(default_factory=list)
    cve_references: list[str] = field(default_factory=list)
    external_documentation: list[ExternalDoc] = field(default_factory=list)


class RuleLoader:
    """Loads YAML rule files from a directory tree into RuleDefinition objects."""

    def __init__(self, rules_path: str | None = None):
        self.rules_path = rules_path or self._default_rules_path()
        resolved = os.path.abspath(self.rules_path)
        logger.info("RuleLoader initialized: rules_path=%s resolved=%s exists=%s",
                     self.rules_path, resolved, os.path.isdir(resolved))

    @staticmethod
    def _default_rules_path() -> str:
        here = os.path.dirname(os.path.abspath(__file__))
        current = here
        for _ in range(10):
            candidate = os.path.join(current, "rules")
            if os.path.isdir(candidate):
                return candidate
            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent
        return os.path.join(here, "..", "..", "..", "..", "rules")

    def load_all(self) -> list[RuleDefinition]:
        rules: list[RuleDefinition] = []
        rules_dir = os.path.abspath(self.rules_path)
        logger.info("RuleLoader.load_all: scanning %s (exists=%s)", rules_dir, os.path.isdir(rules_dir))

        if not os.path.isdir(rules_dir):
            logger.warning("RuleLoader.load_all: rules directory NOT FOUND at %s", rules_dir)
            logger.warning("RuleLoader.load_all: cwd=%s __file__=%s", os.getcwd(), __file__)
            return rules

        for root, _dirs, files in os.walk(rules_dir):
            for filename in sorted(files):
                if not filename.endswith((".yaml", ".yml")):
                    continue
                filepath = os.path.join(root, filename)
                logger.info("RuleLoader.load_all: loading %s", filepath)
                loaded = self._load_file(filepath)
                logger.info("RuleLoader.load_all: %s -> %d rules", filepath, len(loaded))
                rules.extend(loaded)

        logger.info("RuleLoader.load_all: total %d rules from %s", len(rules), rules_dir)
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

        # Phase 9 optional fields
        cm_raw = item.get("confidence_modifiers", []) or []
        confidence_modifiers = [
            ConfidenceModifier(
                condition=c.get("condition", ""),
                adjustment=float(c.get("adjustment", 0)),
            )
            for c in cm_raw
        ]

        required_evidence_types = item.get("required_evidence_types", []) or []

        vreq_raw = item.get("verification_requirements", []) or []
        verification_requirements = [
            VerificationRequirement(
                step=v.get("step", ""),
                expected=v.get("expected", ""),
            )
            for v in vreq_raw
        ]

        attack_references = item.get("attack_references", []) or []

        owasp_asvs = item.get("owasp_asvs", []) or []

        rt_raw = item.get("remediation_templates", []) or []
        remediation_templates = [
            RemediationTemplate(
                environment=r.get("environment", ""),
                steps=r.get("steps", []),
            )
            for r in rt_raw
        ]

        cve_references = item.get("cve_references", []) or []

        ed_raw = item.get("external_documentation", []) or []
        external_documentation = [
            ExternalDoc(
                title=e.get("title", ""),
                url=e.get("url", ""),
            )
            for e in ed_raw
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
            confidence_modifiers=confidence_modifiers,
            required_evidence_types=required_evidence_types,
            verification_requirements=verification_requirements,
            attack_references=attack_references,
            owasp_asvs=owasp_asvs,
            remediation_templates=remediation_templates,
            cve_references=cve_references,
            external_documentation=external_documentation,
        )
