"""Matches scanner observations to rule definitions."""

from dataclasses import dataclass, field

from app.models.enums import SeverityLevel
from app.services.rule_engine.rule_loader import RuleDefinition


_OBSERVATION_RULE_PREFIX: dict[str, str] = {
    "missing_security_header": "HTTP",
    "insecure_cookie": "COOKIE",
    "server_info_disclosure": "HTTP",
    "tech_info_disclosure": "HTTP",
    "https_unreachable": "HTTP",
    "http_without_https": "HTTP",
    "missing_http_to_https_redirect": "HTTP",
    "expired_certificate": "TLS",
    "certificate_expiring_soon": "TLS",
    "certificate_hostname_mismatch": "TLS",
    "self_signed_certificate": "TLS",
    "certificate_chain_incomplete": "TLS",
    "weak_tls_protocol": "TLS",
    "weak_cipher_suite": "TLS",
    "tls_connection_failed": "TLS",
    "connection_failed": "TLS",
    "spf_allow_all": "DNS",
    "spf_neutral": "DNS",
    "spf_excessive_lookups": "DNS",
    "spf_no_hardfail": "DNS",
    "missing_spf_record": "DNS",
    "missing_dmarc_record": "DNS",
    "weak_dmarc_policy": "DNS",
    "missing_dkim_record": "DNS",
    "missing_dnssec": "DNS",
    "missing_caa_record": "DNS",
    "technology_detected": "TECH",
    "javascript_asset_discovered": "JS",
    "exposed_source_map": "JS",
    "potential_credential_exposure": "JS",
    "javascript_library_detected": "JS",
    "dangerous_javascript_pattern": "JS",
}

# Confidence level mapping by observation category prefix for scoring
_CONFIDENCE_BY_PREFIX: dict[str, float] = {
    "HTTP": 0.95,
    "COOKIE": 0.95,
    "TLS": 0.90,
    "DNS": 0.80,
    "TECH": 0.70,
    "JS": 0.65,
}


@dataclass
class ScannerObservation:
    """A raw observation emitted by a scanner check module."""

    check_name: str
    category: str
    passed: bool
    detail: str | None = None
    evidence: dict | None = None


@dataclass
class MatchResult:
    """The result of matching an observation against rules."""

    matched: bool
    rule: RuleDefinition | None = None
    confidence: float = 1.0


class RuleMatcher:
    """Matches a ScannerObservation against a collection of RuleDefinitions."""

    def __init__(self, rules: list[RuleDefinition]):
        self._index: dict[str, list[RuleDefinition]] = {}
        for rule in rules:
            self._index.setdefault(rule.category, []).append(rule)

    @staticmethod
    def _confidence_for(prefix: str) -> float:
        return _CONFIDENCE_BY_PREFIX.get(prefix, 0.5)

    def match(self, observation: ScannerObservation) -> MatchResult:
        candidates = self._index.get(observation.category, [])
        prefix = _OBSERVATION_RULE_PREFIX.get(observation.check_name)
        if not prefix:
            return MatchResult(matched=False)
        for rule in candidates:
            if rule.rule_id.startswith(prefix):
                confidence = self._confidence_for(prefix)
                return MatchResult(matched=True, rule=rule, confidence=confidence)
        return MatchResult(matched=False)
