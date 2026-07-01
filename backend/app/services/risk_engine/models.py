"""Data models for the Security Risk Intelligence Engine."""

from dataclasses import dataclass, field
from enum import Enum


class ConfidenceLevel(str, Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SecurityGrade(str, Enum):
    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


@dataclass
class CompliancePosture:
    framework: str
    total_controls: int
    passed_controls: int
    failed_controls: int
    compliance_percentage: float


@dataclass
class RiskExplanation:
    finding_title: str
    finding_severity: str
    why_it_matters: str
    impact: str
    priority: str
    recommended_remediation: str


@dataclass
class AssetRiskReport:
    security_score: float
    risk_level: str
    security_grade: SecurityGrade
    total_findings: int
    finding_breakdown: dict[str, int]
    compliance_posture: dict[str, CompliancePosture]
    top_risks: list[RiskExplanation] = field(default_factory=list)
