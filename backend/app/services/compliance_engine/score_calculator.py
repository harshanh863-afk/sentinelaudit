"""Compliance score calculator — computes per-framework compliance percentages.

Formula per framework:
    score = (passed * 1.0 + partial * 0.5) / (total_assessed) * 100

Where:
    - passed controls count as 100%
    - partial controls count as 50%
    - failed controls count as 0%
    - not_applicable controls are excluded
"""

from app.services.compliance_engine.models import (
    AssessmentState,
    ComplianceAssessmentReport,
    ControlAssessment,
    FrameworkAssessment,
)
from app.services.compliance_engine.framework_registry import FRAMEWORK_REGISTRY


def calculate_framework_score(assessments: list[ControlAssessment]) -> FrameworkAssessment | None:
    """Calculate compliance score for all controls in one framework.

    Controls from multiple frameworks in the input list will produce
    undefined results — use only assessments from a single framework.
    """
    if not assessments:
        return None

    fw_key = assessments[0].framework
    definition = FRAMEWORK_REGISTRY.get(fw_key)
    if not definition:
        return None

    total = len(assessments)
    passed = sum(1 for a in assessments if a.state == AssessmentState.PASS)
    partial = sum(1 for a in assessments if a.state == AssessmentState.PARTIAL)
    failed = sum(1 for a in assessments if a.state == AssessmentState.FAIL)
    na = sum(1 for a in assessments if a.state == AssessmentState.NOT_APPLICABLE)
    assessed = total - na

    if assessed > 0:
        score = round((passed * 1.0 + partial * 0.5) / assessed * 100, 1)
    else:
        score = 100.0

    return FrameworkAssessment(
        framework_key=fw_key,
        framework_name=definition.name,
        framework_version=definition.version,
        total_controls=total,
        assessed_controls=assessed,
        passed=passed,
        failed=failed,
        partial=partial,
        not_applicable=na,
        score=score,
        controls=assessments,
    )


def calculate_all_scores(all_assessments: list[ControlAssessment]) -> list[FrameworkAssessment]:
    """Group assessments by framework and calculate scores."""
    grouped: dict[str, list[ControlAssessment]] = {}
    for a in all_assessments:
        grouped.setdefault(a.framework, []).append(a)

    results: list[FrameworkAssessment] = []
    for fw_key, assessments in grouped.items():
        result = calculate_framework_score(assessments)
        if result:
            results.append(result)

    results.sort(key=lambda r: r.score)
    return results


def build_report(
    all_assessments: list[ControlAssessment],
) -> ComplianceAssessmentReport:
    """Build the full compliance assessment report."""
    framework_scores = calculate_all_scores(all_assessments)

    if framework_scores:
        overall = round(sum(f.score for f in framework_scores) / len(framework_scores), 1)
    else:
        overall = 100.0

    return ComplianceAssessmentReport(
        assessments=framework_scores,
        overall_score=overall,
    )
