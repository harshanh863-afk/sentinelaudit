"""Data models for the Compliance Control Engine."""

from dataclasses import dataclass, field
from enum import Enum


class AssessmentState(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class ControlAssessment:
    control_id: str
    control_title: str
    framework: str
    category: str
    state: AssessmentState
    evidence: str = ""


@dataclass
class FrameworkAssessment:
    framework_key: str
    framework_name: str
    framework_version: str
    total_controls: int
    assessed_controls: int
    passed: int
    failed: int
    partial: int
    not_applicable: int
    score: float
    controls: list[ControlAssessment] = field(default_factory=list)


@dataclass
class ComplianceAssessmentReport:
    assessments: list[FrameworkAssessment]
    overall_score: float
