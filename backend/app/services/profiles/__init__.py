"""Scan profile interface — placeholder for future implementation.

Scan profiles allow users to configure which checks run, at what intensity,
and with what authorization level. Profiles act as a policy layer between
the user's request and the scanner engine.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol


class ScanDepth(Enum):
    """How thorough the scan should be."""

    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


class AuthorizationLevel(Enum):
    """What level of testing is authorized."""

    PASSIVE_ONLY = "passive_only"
    ACTIVE_SAFE = "active_safe"
    FULL = "full"


@dataclass
class ScanProfile:
    """Configuration for a single scan execution.

    Extend this dataclass as new profile dimensions are added.
    Current dimensions are placeholders.
    """

    name: str = "default"
    depth: ScanDepth = ScanDepth.STANDARD
    authorization: AuthorizationLevel = AuthorizationLevel.PASSIVE_ONLY
    enabled_categories: list[str] = field(default_factory=lambda: [
        "tls_analysis", "http_security", "dns_analysis", "tech_fingerprint",
    ])
    rate_limit_ms: int = 100
    timeout_seconds: int = 30


class ProfileResolver(Protocol):
    """Interface for resolving which profile to use for a given target.

    Implementations should handle:
    - User-provided profile overrides
    - Target-type-based defaults (internal vs external)
    - Organisation-wide policy enforcement
    """

    def resolve(self, *, target_url: str, requested_profile: str | None = None) -> ScanProfile:
        ...
