"""Risk explanation engine — generates deterministic, human-readable explanations.

Produces structured explanations including:
    - Why the finding matters
    - Business impact
    - Priority
    - Recommended remediation

This architecture is designed for a future AI-driven explanation layer swap.
"""

from app.services.risk_engine.models import ConfidenceLevel, RiskExplanation
from app.models.enums import SeverityLevel

_SEVERITY_WHY_IT_MATTERS: dict[SeverityLevel, str] = {
    SeverityLevel.CRITICAL: (
        "This finding represents an immediately exploitable vulnerability that "
        "can lead to complete system compromise, data breach, or service disruption."
    ),
    SeverityLevel.HIGH: (
        "This finding poses a significant security risk that is likely exploitable "
        "and could result in unauthorized access, data leakage, or privilege escalation."
    ),
    SeverityLevel.MEDIUM: (
        "This finding indicates a security weakness that may be exploitable under "
        "specific conditions, potentially leading to limited information disclosure "
        "or partial system compromise."
    ),
    SeverityLevel.LOW: (
        "This finding represents a minor security concern or configuration weakness "
        "that has limited exploitability but should be addressed as part of defense in depth."
    ),
    SeverityLevel.INFO: (
        "This is an informational observation that does not pose an immediate "
        "security risk but provides useful context for security posture assessment."
    ),
}

_SEVERITY_IMPACTS: dict[SeverityLevel, str] = {
    SeverityLevel.CRITICAL: (
        "Confidentiality, integrity, and availability are at high risk. "
        "Successful exploitation can result in full system compromise."
    ),
    SeverityLevel.HIGH: (
        "Confidentiality or integrity is at significant risk. "
        "Exploitation may lead to unauthorized access or data exposure."
    ),
    SeverityLevel.MEDIUM: (
        "Limited impact on confidentiality or integrity. "
        "Exploitation requires specific conditions or user interaction."
    ),
    SeverityLevel.LOW: (
        "Minimal business impact. Exploitation is difficult or yields limited advantage."
    ),
    SeverityLevel.INFO: (
        "No direct security impact. Included for awareness and completeness."
    ),
}

_CONFIDENCE_PRIORITIES: dict[ConfidenceLevel, str] = {
    ConfidenceLevel.CONFIRMED: "Immediate — confirmed vulnerability requires urgent action.",
    ConfidenceLevel.HIGH: "High — strong evidence suggests a real vulnerability.",
    ConfidenceLevel.MEDIUM: "Medium — potential vulnerability warrants investigation.",
    ConfidenceLevel.LOW: "Low — weak evidence; verify before action.",
}


def _remediation_for(finding_title: str, severity: SeverityLevel, finding_type: str) -> str:
    """Generate deterministic remediation guidance based on finding characteristics."""
    type_lower = finding_type.lower() if finding_type else ""

    if "certificate" in type_lower or "tls" in type_lower:
        return "Renew and properly configure TLS certificates. Ensure certificates are from a trusted CA and match the hostname."
    if "spf" in type_lower or "dmarc" in type_lower or "dns" in type_lower:
        return "Review and harden DNS email authentication records. Implement strict SPF, DKIM, and DMARC policies."
    if "header" in type_lower or "csp" in type_lower or "hsts" in type_lower:
        return "Add missing security headers. Configure CSP, HSTS, X-Frame-Options, and other security headers."
    if "cookie" in type_lower:
        return "Set Secure, HttpOnly, and SameSite attributes on all cookies."
    if "secret" in type_lower or "credential" in type_lower:
        return "Remove hardcoded secrets from source code. Use environment variables or a secrets manager."
    if "eval" in type_lower or "dangerous" in type_lower:
        return "Replace dangerous JavaScript patterns (eval, innerHTML) with safe alternatives. Use Content Security Policy."
    if "source map" in type_lower:
        return "Disable source map generation in production builds or restrict access via web server configuration."
    if "server" in type_lower or "version" in type_lower or "fingerprint" in type_lower:
        return "Disable or obfuscate server version headers to reduce attack surface."
    if "cipher" in type_lower or "protocol" in type_lower:
        return "Disable weak ciphers and outdated protocol versions. Enable only TLS 1.2 and TLS 1.3 with strong ciphers."

    return "Review the finding and apply security best practices appropriate to the affected component."


def generate_explanation(
    finding_title: str,
    severity: SeverityLevel,
    confidence: ConfidenceLevel | None,
    finding_type: str | None = None,
    remediation_hint: str | None = None,
) -> RiskExplanation:
    why = _SEVERITY_WHY_IT_MATTERS.get(severity, "Review this finding for potential security impact.")
    impact = _SEVERITY_IMPACTS.get(severity, "Impact depends on the specific finding context.")

    if confidence is not None:
        priority = _CONFIDENCE_PRIORITIES.get(confidence, "Review priority based on context.")
    else:
        priority = _SEVERITY_IMPACTS.get(severity, "Priority depends on severity and context.")

    remediation = remediation_hint or _remediation_for(finding_title, severity, finding_type or "")

    return RiskExplanation(
        finding_title=finding_title,
        finding_severity=severity.value,
        why_it_matters=why,
        impact=impact,
        priority=priority,
        recommended_remediation=remediation,
    )
