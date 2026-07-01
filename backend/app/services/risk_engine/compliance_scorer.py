"""Compliance scoring — calculates posture against security frameworks.

Supported frameworks:
    - OWASP (Top 10)
    - NIST CSF
    - CIS Controls
    - ISO 27001
    - PCI DSS
"""

from app.services.risk_engine.models import CompliancePosture

KNOWN_FRAMEWORKS = {"owasp", "nist", "cis", "iso_27001", "pci_dss"}


def calculate_compliance_posture(
    framework: str,
    total_controlled_findings: int,
    passed_findings: int,
) -> CompliancePosture:
    """Calculate compliance posture for a single framework.

    total_controlled_findings: number of findings that map to this framework.
    passed_findings: number of findings in a 'passed' or 'fixed' state.
    """
    failed = max(0, total_controlled_findings - passed_findings)
    if total_controlled_findings > 0:
        pct = round((passed_findings / total_controlled_findings) * 100, 1)
    else:
        pct = 100.0

    return CompliancePosture(
        framework=framework,
        total_controls=total_controlled_findings,
        passed_controls=passed_findings,
        failed_controls=failed,
        compliance_percentage=pct,
    )


def _findings_pass_status(finding) -> bool:
    """Determine if a finding is in a passed/compliant state.

    Handles both ORM object and dict inputs.
    """
    if isinstance(finding, dict):
        passed = finding.get("passed", True)
        status = str(finding.get("status", "")).lower()
    else:
        passed = getattr(finding, "passed", True)
        status = str(getattr(finding, "status", "")).lower()
    return bool(passed) or status in ("fixed", "false_positive", "accepted_risk")


def _get_mappings(finding) -> list:
    """Extract compliance mappings from a finding.

    Handles both ORM object and dict inputs.
    """
    if isinstance(finding, dict):
        return finding.get("compliance_mappings") or finding.get("compliance", [])
    return getattr(finding, "compliance_mappings", None) or getattr(finding, "compliance", [])


def calculate_all_postures(
    findings: list,
) -> dict[str, CompliancePosture]:
    """Calculate compliance posture for all known frameworks.

    Each finding is expected to have a 'compliance' or 'compliance_mappings'
    attribute that is a list of dicts with {'framework': ..., 'control_id': ...}.
    """
    framework_counts: dict[str, dict[str, int]] = {}
    for fw in KNOWN_FRAMEWORKS:
        framework_counts[fw] = {"total": 0, "passed": 0}

    for finding in findings:
        mappings = _get_mappings(finding)
        if not mappings:
            continue

        is_passed = _findings_pass_status(finding)

        for cm in mappings:
            if isinstance(cm, dict):
                fw = cm.get("framework", "").lower()
            else:
                fw = getattr(cm, "framework", "").lower()

            if fw in KNOWN_FRAMEWORKS:
                framework_counts[fw]["total"] += 1
                if is_passed:
                    framework_counts[fw]["passed"] += 1

    result: dict[str, CompliancePosture] = {}
    for fw, counts in framework_counts.items():
        if counts["total"] > 0:
            result[fw] = calculate_compliance_posture(
                fw, counts["total"], counts["passed"],
            )

    return result


def overall_compliance_score(postures: dict[str, CompliancePosture]) -> float:
    """Average compliance percentage across all frameworks with controls."""
    if not postures:
        return 100.0
    return round(
        sum(p.compliance_percentage for p in postures.values()) / len(postures),
        1,
    )
