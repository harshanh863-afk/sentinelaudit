"""Historical scan comparison engine.

Compares findings across two scans to identify:
  - New findings (in newer but not older)
  - Fixed findings (in older but not newer)
  - Changed findings (different severity or status)
  - Unchanged findings (same in both)
"""

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class ScanDiff:
    new_findings: list[dict] = field(default_factory=list)
    fixed_findings: list[dict] = field(default_factory=list)
    changed_findings: list[dict] = field(default_factory=list)
    unchanged_findings: list[dict] = field(default_factory=list)
    score_delta: float = 0.0
    summary: str = ""


class ScanComparer:
    """Compares findings between two scans to detect changes."""

    @staticmethod
    def compare(old_findings: list[dict], new_findings: list[dict]) -> ScanDiff:
        """Compare two sets of findings and produce a ScanDiff."""
        old_by_key = ScanComparer._index_by_rule(old_findings)
        new_by_key = ScanComparer._index_by_rule(new_findings)

        old_keys = set(old_by_key.keys())
        new_keys = set(new_by_key.keys())

        diff = ScanDiff()

        # New findings
        for key in new_keys - old_keys:
            diff.new_findings.append(new_by_key[key])

        # Fixed findings
        for key in old_keys - new_keys:
            diff.fixed_findings.append(old_by_key[key])

        # Changed / unchanged
        for key in old_keys & new_keys:
            old_f = old_by_key[key]
            new_f = new_by_key[key]
            if ScanComparer._is_changed(old_f, new_f):
                diff.changed_findings.append({
                    "rule_id": key,
                    "old": old_f,
                    "new": new_f,
                })
            else:
                diff.unchanged_findings.append(new_f)

        # Score delta
        old_score = ScanComparer._avg_score(old_findings)
        new_score = ScanComparer._avg_score(new_findings)
        diff.score_delta = round(new_score - old_score, 1)

        # Summary
        diff.summary = (
            f"Comparison: {len(diff.new_findings)} new, {len(diff.fixed_findings)} fixed, "
            f"{len(diff.changed_findings)} changed, {len(diff.unchanged_findings)} unchanged. "
            f"Score delta: {diff.score_delta:+.1f}"
        )

        return diff

    @staticmethod
    def _index_by_rule(findings: list[dict]) -> dict[str, dict]:
        result: dict[str, dict] = {}
        for f in findings:
            key = f.get("rule_business_id") or f.get("rule_id") or f.get("title", "")
            result[key] = f
        return result

    @staticmethod
    def _is_changed(old: dict, new: dict) -> bool:
        return (
            old.get("severity") != new.get("severity")
            or old.get("status") != new.get("status")
            or old.get("cvss_score") != new.get("cvss_score")
        )

    @staticmethod
    def _avg_score(findings: list[dict]) -> float:
        scores = [f.get("cvss_score") or 0 for f in findings if f.get("cvss_score") is not None]
        if not scores:
            severities = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}
            scores = [severities.get((f.get("severity") or "info").lower(), 0) for f in findings]
        return sum(scores) / len(scores) if scores else 0.0
