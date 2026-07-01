"""Matches scanner observations to rule definitions."""

from dataclasses import dataclass, field

from app.models.enums import SeverityLevel
from app.services.rule_engine.rule_loader import RuleDefinition


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

    def match(self, observation: ScannerObservation) -> MatchResult:
        candidates = self._index.get(observation.category, [])
        for rule in candidates:
            if observation.check_name.startswith(rule.rule_id.split("-")[0]):
                return MatchResult(matched=True, rule=rule)
        return MatchResult(matched=False)
