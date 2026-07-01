"""Finding deduplication interface — placeholder for future implementation.

Deduplication merges equivalent findings across scans of the same target
to prevent noise in reports and track the history of each unique issue.
"""

from dataclasses import dataclass
from typing import Protocol


@dataclass
class DedupKey:
    """Fingerprint used to identify equivalent findings across scans.

    Two findings are considered duplicates if they share the same
    DedupKey across scans of the same target.
    """

    rule_id: str
    evidence_fingerprint: str
    target_id: str


class DedupEngine(Protocol):
    """Interface for finding deduplication.

    Implementations should handle:
    - Cross-scan dedup (same finding in consecutive scans)
    - Evidence-based fingerprinting (same raw data = same finding)
    - Status propagation (re-opened, re-fixed, still open)
    - Merge strategies (keep oldest, keep most severe, etc.)
    """

    def fingerprint(self, *, observation_type: str,
                    evidence: dict | None) -> str:
        """Generate a deterministic fingerprint from observation data."""
        ...

    def is_duplicate(self, key: DedupKey) -> bool:
        """Check whether a finding with this key already exists."""
        ...
