"""Standardized scanner observation — the only output scanners produce."""

from dataclasses import dataclass, field


@dataclass
class ScannerObservation:
    """
    A single security observation produced by a scanner module.

    Scanners emit these only. The rule engine converts them to Findings.
    No database models are touched here.
    """

    observation_type: str
    """Semantic type: missing_security_header | insecure_cookie | info_disclosure | tls_issue | ..."""

    target: str
    """The URL or domain the observation applies to."""

    severity_hint: str
    """Suggested severity: critical | high | medium | low | info."""

    evidence: dict | None = field(default=None)
    """Raw data that caused the observation (response headers, cookies, etc.)."""

    metadata: dict | None = field(default=None)
    """Additional context: check_name, category, description, detail."""
