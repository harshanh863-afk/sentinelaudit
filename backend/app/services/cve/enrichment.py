"""CVE enrichment service — attaches CVE intelligence to findings with versions.

Gracefully degrades: never blocks scans, returns empty data on failure.
"""

import logging

from app.services.cve import CVEResolver, CVEResult

logger = logging.getLogger(__name__)


class CveEnrichmentService:
    """Enriches findings with CVE data when a software version is identified."""

    def __init__(self, resolver: CVEResolver | None = None):
        self._resolver = resolver or CVEResolver()

    async def enrich(self, findings: list[dict]) -> list[dict]:
        """Attach CVE intelligence to findings that have identified versions.

        Never blocks — catches all exceptions and returns findings unmodified
        if enrichment fails.
        """
        if not findings:
            return findings

        enriched = []
        for finding in findings:
            evidence = finding.get("evidence") or {}
            version = evidence.get("version") or finding.get("version")
            tech_name = (
                evidence.get("technology")
                or evidence.get("tech")
                or finding.get("title", "")
            )

            if version and tech_name:
                try:
                    cve_result: CVEResult = await self._resolver.resolve(
                        tech_name, version
                    )
                    if cve_result.cves:
                        finding["cves"] = [
                            {
                                "cve_id": c.cve_id,
                                "cvss_score": c.cvss_score,
                                "severity": c.severity,
                                "published_date": c.published_date,
                                "fix_version": c.fix_version,
                                "exploit_available": c.exploit_available,
                                "description": c.description,
                                "references": c.references,
                                "source": c.source,
                            }
                            for c in cve_result.cves
                        ]
                        finding["highest_cvss"] = cve_result.highest_cvss
                        finding["cve_cache_hit"] = cve_result.cache_hit
                        if cve_result.highest_cvss is not None:
                            current_cvss = finding.get("cvss_score")
                            if current_cvss is None or cve_result.highest_cvss > current_cvss:
                                finding["cvss_score"] = cve_result.highest_cvss
                except Exception:
                    logger.warning(
                        "CVE enrichment failed for %s@%s",
                        tech_name, version,
                        exc_info=True,
                    )
            enriched.append(finding)
        return enriched
