"""Asset intelligence interface — placeholder for future implementation.

Asset intelligence enriches scan results with external context about the
target: ownership, technology stack history, known vulnerabilities,
reputation data, and related infrastructure.
"""

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class AssetEnrichment:
    """Contextual data attached to a target or finding.

    All fields are optional; an enrichment source provides what it can.
    """

    technologies: list[str] = field(default_factory=list)
    asn: str | None = None
    asn_org: str | None = None
    cloud_provider: str | None = None
    country: str | None = None
    known_vulnerabilities: list[str] = field(default_factory=list)
    reverse_dns: list[str] = field(default_factory=list)
    related_domains: list[str] = field(default_factory=list)
    source: str = "unknown"


class AssetIntelProvider(Protocol):
    """Interface for asset intelligence enrichment.

    Implementations can pull data from:
    - WHOIS / RDAP lookups
    - Shodan / Censys / similar internet scanners
    - Certificate Transparency logs
    - Passive DNS databases
    - Internal CMDB or asset register
    """

    async def enrich(self, *, hostname: str) -> AssetEnrichment:
        """Return enrichment data for the given hostname."""
        ...
