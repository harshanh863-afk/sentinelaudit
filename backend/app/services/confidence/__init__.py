"""Confidence scoring interface — placeholder for future implementation.

A confidence score represents how certain the scanner/analyst is that a
finding is a genuine security issue rather than a false positive.
"""

from enum import IntEnum
from typing import Protocol


class ConfidenceLevel(IntEnum):
    """Confidence level for a finding."""

    CONFIRMED = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    UNKNOWN = 0


class ConfidenceScorer(Protocol):
    """Interface for scoring confidence of findings.

    Implementations should evaluate factors such as:
    - Evidence quality (full request/response, certificate data, etc.)
    - Scanner specificity (targeted check vs broad heuristic)
    - False-positive rate history for the matched rule
    - Consistency across multiple scan passes
    """

    def score(self, *, observation_type: str, evidence: dict | None,
              rule_severity: str, metadata: dict | None) -> ConfidenceLevel:
        """Return a confidence level for a scanner observation."""
        ...
