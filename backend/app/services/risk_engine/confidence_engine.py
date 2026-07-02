"""Evidence-based confidence scoring engine.

Replaces the previous observation-type-based confidence with a
multi-factor model considering evidence completeness, scanner agreement,
version certainty, and false-positive probability.
"""

from enum import Enum


class Confidence(str, Enum):
    VERY_HIGH = "very_high"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ConfidenceEngine:
    """Calculates evidence-based confidence for findings."""

    # Weight factors for each dimension
    INDEPENDENT_OBSERVATIONS_MAX = 0.30
    EVIDENCE_COMPLETENESS = 0.20
    SCANNER_AGREEMENT = 0.20
    VERIFICATION_SUCCESS = 0.15
    SCANNER_RELIABILITY = 0.10
    VERSION_CERTAINTY = 0.15
    REQUEST_SUCCESS = 0.10
    FALSE_POSITIVE_PENALTY = 0.40

    @classmethod
    def calculate(
        cls,
        num_observations: int = 1,
        evidence_complete: bool = False,
        scanner_agreement: float = 0.0,
        verified: bool = False,
        scanner_reliability: float = 0.5,
        version_certainty: float = 0.0,
        request_success: bool = True,
        false_positive_probability: float = 0.0,
    ) -> tuple[float, Confidence]:
        """Calculate confidence score (0.0 – 1.0) and label.

        Each factor contributes up to its weight maximum. The base is 0.40
        (a single matched finding with basic evidence).
        """
        base = 0.40

        obs_factor = min(cls.INDEPENDENT_OBSERVATIONS_MAX, num_observations * 0.05)
        evidence_factor = cls.EVIDENCE_COMPLETENESS if evidence_complete else 0.0
        agreement_factor = scanner_agreement * cls.SCANNER_AGREEMENT
        verification_factor = cls.VERIFICATION_SUCCESS if verified else 0.0
        reliability_factor = scanner_reliability * cls.SCANNER_RELIABILITY
        version_factor = version_certainty * cls.VERSION_CERTAINTY
        request_factor = cls.REQUEST_SUCCESS if request_success else 0.0

        raw = (
            base
            + obs_factor
            + evidence_factor
            + agreement_factor
            + verification_factor
            + reliability_factor
            + version_factor
            + request_factor
        )

        fp_penalty = false_positive_probability * cls.FALSE_POSITIVE_PENALTY
        score = max(0.0, min(1.0, raw - fp_penalty))

        return score, cls._label(score)

    @classmethod
    def calculate_from_finding_data(cls, finding: dict) -> tuple[float, Confidence]:
        """Convenience: extract signals from a finding dict and compute confidence."""
        return cls.calculate(
            num_observations=finding.get("observation_count", 1),
            evidence_complete=cls._evidence_is_complete(finding),
            scanner_agreement=finding.get("scanner_agreement", 0.0),
            verified=finding.get("verified", False),
            scanner_reliability=finding.get("scanner_reliability", 0.5),
            version_certainty=cls._version_certainty(finding),
            request_success=finding.get("request_success", True),
            false_positive_probability=finding.get("false_positive_probability", 0.0),
        )

    @staticmethod
    def _label(score: float) -> Confidence:
        if score >= 0.90:
            return Confidence.VERY_HIGH
        if score >= 0.70:
            return Confidence.HIGH
        if score >= 0.40:
            return Confidence.MEDIUM
        return Confidence.LOW

    @staticmethod
    def _evidence_is_complete(finding: dict) -> bool:
        evidence = finding.get("evidence")
        if not evidence or not isinstance(evidence, dict):
            return False
        required_keys = finding.get("required_evidence_types", [])
        if not required_keys:
            return bool(evidence)
        return all(k in evidence for k in required_keys)

    @staticmethod
    def _version_certainty(finding: dict) -> float:
        version = (
            (finding.get("evidence") or {}).get("version")
            or finding.get("version")
        )
        if not version:
            return 0.0
        return 0.8 if len(version.split(".")) >= 2 else 0.3
