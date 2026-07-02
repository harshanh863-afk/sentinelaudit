"""Abstract CVE provider interface and implementations.

Designed so that multiple vulnerability intelligence providers
can be supported in the future (NVD, OSV, VulnDB, etc.).
"""

import abc
import json
import logging
import os
import time
from dataclasses import asdict

import httpx

from app.services.cve.models import CVERecord, CVEResult

logger = logging.getLogger(__name__)

_CACHE_DIR = os.path.join(os.path.dirname(__file__), ".cve_cache")
_CACHE_TTL = 3600  # 1 hour


class CVEProvider(abc.ABC):
    """Abstract base for CVE intelligence providers."""

    @abc.abstractmethod
    async def lookup(self, package: str, version: str) -> CVEResult:
        ...

    @property
    @abc.abstractmethod
    def name(self) -> str:
        ...


def _cache_key(package: str, version: str) -> str:
    return f"{package}@{version}".replace("/", "_").replace(":", "_")


def _read_cache(key: str) -> CVEResult | None:
    path = os.path.join(_CACHE_DIR, f"{key}.json")
    if not os.path.exists(path):
        return None
    try:
        age = time.time() - os.path.getmtime(path)
        if age > _CACHE_TTL:
            return None
        with open(path) as f:
            data = json.load(f)
        records = [CVERecord(**r) for r in data.get("cves", [])]
        return CVEResult(
            cves=records,
            highest_cvss=data.get("highest_cvss"),
            total_cves=len(records),
            cache_hit=True,
        )
    except Exception:
        return None


def _write_cache(key: str, result: CVEResult) -> None:
    os.makedirs(_CACHE_DIR, exist_ok=True)
    path = os.path.join(_CACHE_DIR, f"{key}.json")
    try:
        with open(path, "w") as f:
            json.dump({
                "cves": [asdict(r) for r in result.cves],
                "highest_cvss": result.highest_cvss,
            }, f)
    except Exception:
        pass


class NVDProvider(CVEProvider):
    """CVE lookup via NVD API 2.0 (public, no key required for basic use)."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: str | None = None, timeout: int = 15):
        self._api_key = api_key
        self._timeout = timeout

    @property
    def name(self) -> str:
        return "nvd"

    async def lookup(self, package: str, version: str) -> CVEResult:
        cache_key = _cache_key(package, version)
        cached = _read_cache(cache_key)
        if cached:
            return cached

        cpe = f"cpe:2.3:a:*:{package}:{version}:*:*:*:*:*:*:*"
        params: dict = {
            "cpeName": cpe,
            "resultsPerPage": 20,
        }
        headers = {}
        if self._api_key:
            headers["apiKey"] = self._api_key

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(self.BASE_URL, params=params, headers=headers)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            logger.warning("CVE lookup failed for %s@%s: %s", package, version, exc)
            return CVEResult(error=str(exc))

        vulnerabilities = data.get("vulnerabilities", [])
        records: list[CVERecord] = []
        for vuln in vulnerabilities:
            cve_item = vuln.get("cve", {})
            cve_id = cve_item.get("id", "")
            metrics = cve_item.get("metrics", {})
            cvss_v31 = metrics.get("cvssMetricV31", [])
            cvss_score = None
            severity = "unknown"
            if cvss_v31:
                cvss_data = cvss_v31[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = (cvss_data.get("baseSeverity") or "unknown").lower()

            published = cve_item.get("published")
            desc_text = ""
            descriptions = cve_item.get("descriptions", [])
            for d in descriptions:
                if d.get("lang") == "en":
                    desc_text = d.get("value", "")
                    break

            refs = [r.get("url", "") for r in cve_item.get("references", [])[:5]]

            records.append(CVERecord(
                cve_id=cve_id,
                cvss_score=float(cvss_score) if cvss_score is not None else None,
                severity=severity,
                published_date=published,
                description=desc_text[:500] if desc_text else "",
                references=refs,
                source=self.name,
            ))

        scores = [r.cvss_score for r in records if r.cvss_score is not None]
        result = CVEResult(
            cves=records,
            highest_cvss=max(scores) if scores else None,
            total_cves=len(records),
        )

        _write_cache(cache_key, result)
        return result


_OSV_ECOSYSTEM_MAP: dict[str, str] = {
    "nginx": "Linux",
    "apache": "Linux",
    "node.js": "npm",
    "express": "npm",
    "react": "npm",
    "angular": "npm",
    "vue.js": "npm",
    "next.js": "npm",
    "jquery": "npm",
    "bootstrap": "npm",
    "lodash": "npm",
    "axios": "npm",
    "moment.js": "npm",
    "django": "PyPI",
    "flask": "PyPI",
    "laravel": "Packagist",
    "php": "Linux",
    "wordpress": "WordPress",
    "drupal": "Drupal",
}


def _detect_ecosystem(package: str) -> str:
    return _OSV_ECOSYSTEM_MAP.get(package.lower(), "PyPI")


class OSVProvider(CVEProvider):
    """CVE lookup via OSV.dev API (free, no key required)."""

    BASE_URL = "https://api.osv.dev/v1/query"

    def __init__(self, timeout: int = 15):
        self._timeout = timeout

    @property
    def name(self) -> str:
        return "osv"

    async def lookup(self, package: str, version: str) -> CVEResult:
        cache_key = _cache_key(package, version)
        cached = _read_cache(cache_key)
        if cached:
            return cached

        ecosystem = _detect_ecosystem(package)
        payload = {
            "package": {"name": package, "ecosystem": ecosystem},
            "version": version,
        }

        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(self.BASE_URL, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            logger.warning("OSV lookup failed for %s@%s: %s", package, version, exc)
            return CVEResult(error=str(exc))

        vulns = data.get("vulns", [])
        records: list[CVERecord] = []
        for vuln in vulns:
            aliases = vuln.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln.get("id", ""))
            cvss_score = None
            severity = "unknown"
            db_specific = vuln.get("database_specific", {}) or {}
            severity_data = db_specific.get("severity", "")
            if severity_data:
                sev_lower = severity_data.lower()
                if "critical" in sev_lower:
                    severity = "critical"
                    cvss_score = 9.5
                elif "high" in sev_lower:
                    severity = "high"
                    cvss_score = 7.5
                elif "medium" in sev_lower:
                    severity = "medium"
                    cvss_score = 5.5

            published = vuln.get("published")
            desc_text = vuln.get("summary", "")
            refs = [r.get("url", "") for r in vuln.get("references", [])[:5]]

            records.append(CVERecord(
                cve_id=cve_id,
                cvss_score=cvss_score,
                severity=severity,
                published_date=published,
                description=desc_text[:500],
                references=refs,
                source=self.name,
            ))

        scores = [r.cvss_score for r in records if r.cvss_score is not None]
        result = CVEResult(
            cves=records,
            highest_cvss=max(scores) if scores else None,
            total_cves=len(records),
        )

        _write_cache(cache_key, result)
        return result


class CVEResolver:
    """Orchestrates CVE lookup across multiple providers with fallback.

    Never blocks the caller — returns empty result on any failure.
    """

    def __init__(self, providers: list[CVEProvider] | None = None):
        default_providers: list[CVEProvider] = [OSVProvider()]
        nvd_key = os.environ.get("NVD_API_KEY")
        if nvd_key:
            default_providers.insert(0, NVDProvider(api_key=nvd_key))
        self._providers = providers or default_providers

    async def resolve(self, package: str, version: str) -> CVEResult:
        for provider in self._providers:
            try:
                result = await provider.lookup(package, version)
                if result.cves:
                    return result
            except Exception:
                logger.warning("CVE provider %s failed for %s@%s", provider.name, package, version, exc_info=True)
        return CVEResult()
