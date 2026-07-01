"""Compliance Control Engine — framework-agnostic compliance assessment.

Maps findings to framework controls, assesses each control, and calculates
compliance scores for 18+ supported frameworks:
    - OWASP Top 10, OWASP ASVS, OWASP API Security Top 10
    - NIST CSF 2.0, NIST SP 800-53
    - CIS Controls v8, ISO 27001, PCI DSS 4.0
    - GDPR, CCPA/CPRA, HIPAA, SOC 2, COPPA
    - CWE Top 25
    - HTTP Security, TLS Security, DNS Security, Cookie Security
"""

from app.services.compliance_engine.models import (
    AssessmentState,
    ComplianceAssessmentReport,
    ControlAssessment,
    FrameworkAssessment,
)
from app.services.compliance_engine.framework_registry import (
    FRAMEWORK_REGISTRY,
    FrameworkDefinition,
    get_control,
    get_framework,
    list_frameworks,
)
from app.services.compliance_engine.assessment_engine import (
    assess_findings,
    assess_findings_for_framework,
)
from app.services.compliance_engine.score_calculator import (
    calculate_framework_score,
    calculate_all_scores,
    build_report,
)

__all__ = [
    "AssessmentState",
    "ControlAssessment",
    "FrameworkAssessment",
    "ComplianceAssessmentReport",
    "FrameworkDefinition",
    "FRAMEWORK_REGISTRY",
    "get_control",
    "get_framework",
    "list_frameworks",
    "assess_findings",
    "assess_findings_for_framework",
    "calculate_framework_score",
    "calculate_all_scores",
    "build_report",
]
