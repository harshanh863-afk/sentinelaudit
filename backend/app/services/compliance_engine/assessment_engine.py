"""Assessment engine — maps findings to controls and produces assessment results.

Each finding carries compliance mappings (framework → control_id). The engine
groups findings by (framework, control_id), determines the assessment state
based on finding status, and produces structured ControlAssessment results.
"""

from app.models.enums import FindingStatus

from app.services.compliance_engine.models import AssessmentState, ControlAssessment
from app.services.compliance_engine.framework_registry import (
    FRAMEWORK_REGISTRY,
    get_control,
)


def _mapping_framework(mapping) -> str:
    if isinstance(mapping, dict):
        return mapping.get("framework", "").lower()
    return getattr(mapping, "framework", "").lower()


def _mapping_control_id(mapping) -> str:
    if isinstance(mapping, dict):
        return mapping.get("control_id", "")
    return getattr(mapping, "control_id", "")


def _finding_is_passed(finding) -> bool:
    if isinstance(finding, dict):
        return bool(finding.get("passed", True)) or str(finding.get("status", "")).lower() in (
            "fixed", "false_positive", "accepted_risk",
        )
    return bool(getattr(finding, "passed", True)) or str(getattr(finding, "status", "")).lower() in (
        "fixed", "false_positive", "accepted_risk",
    )


def _get_compliance_mappings(finding) -> list:
    if isinstance(finding, dict):
        return finding.get("compliance_mappings") or finding.get("compliance", [])
    return getattr(finding, "compliance_mappings", None) or getattr(finding, "compliance", [])


def assess_findings(findings: list) -> list[ControlAssessment]:
    """Evaluate each (framework, control_id) pair across all findings.

    A control is:
        PASS   — at least one finding maps to it and is in a passed/fixed state
        FAIL   — at least one finding maps to it and is NOT in a passed state
        PARTIAL — multiple findings map with mixed pass/fail statuses
        NOT_APPLICABLE — no finding maps to the control (not included in output)

    Only controls defined in the framework registry are assessed.
    """
    control_states: dict[tuple[str, str], list[bool]] = {}

    for finding in findings:
        mappings = _get_compliance_mappings(finding)
        if not mappings:
            continue
        is_passed = _finding_is_passed(finding)
        for mapping in mappings:
            fw = _mapping_framework(mapping)
            ctrl_id = _mapping_control_id(mapping)

            if fw not in FRAMEWORK_REGISTRY:
                continue
            if not get_control(fw, ctrl_id):
                continue

            key = (fw, ctrl_id)
            if key not in control_states:
                control_states[key] = []
            control_states[key].append(is_passed)

    results: list[ControlAssessment] = []
    for (fw, ctrl_id), states in control_states.items():
        definition = get_control(fw, ctrl_id)
        if not definition:
            continue

        has_pass = any(states)
        has_fail = any(not s for s in states)
        all_pass = all(states)
        all_fail = all(not s for s in states)

        if len(states) > 1 and has_pass and has_fail:
            state = AssessmentState.PARTIAL
        elif all_pass:
            state = AssessmentState.PASS
        elif all_fail:
            state = AssessmentState.FAIL
        else:
            state = AssessmentState.FAIL

        evidence_parts = []
        if has_pass:
            evidence_parts.append(f"{states.count(True)} passed")
        if has_fail:
            evidence_parts.append(f"{states.count(False)} failed")

        results.append(ControlAssessment(
            control_id=ctrl_id,
            control_title=definition.title,
            framework=fw,
            category=definition.category,
            state=state,
            evidence="; ".join(evidence_parts) if evidence_parts else "Not assessed",
        ))

    return results


def assess_findings_for_framework(
    findings: list,
    framework_key: str,
) -> list[ControlAssessment]:
    """Assess findings and filter to a single framework."""
    all_assessments = assess_findings(findings)
    return [a for a in all_assessments if a.framework == framework_key]
