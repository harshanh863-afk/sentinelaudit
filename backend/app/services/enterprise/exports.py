"""Export modules for security assessment data.

Supports:
  - JSON (full scan data)
  - SARIF 2.1.0 (for GitHub Security, Code Scanning tools)
  - CycloneDX 1.4 (SBOM format)
  - SPDX 2.3 (SBOM format)
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


class JSONExporter:
    """Exports scan data as structured JSON."""

    @staticmethod
    def export(scan: dict, findings: list[dict]) -> str:
        data = {
            "export_version": "1.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan": scan,
            "findings": findings,
            "summary": {
                "total_findings": len(findings),
                "critical": sum(1 for f in findings if (f.get("severity") or "").lower() == "critical"),
                "high": sum(1 for f in findings if (f.get("severity") or "").lower() == "high"),
                "medium": sum(1 for f in findings if (f.get("severity") or "").lower() == "medium"),
                "low": sum(1 for f in findings if (f.get("severity") or "").lower() == "low"),
                "info": sum(1 for f in findings if (f.get("severity") or "").lower() == "info"),
            },
        }
        return json.dumps(data, indent=2, default=str)


class SARIFExporter:
    """Exports findings in SARIF 2.1.0 format for GitHub/VS Code integration."""

    @staticmethod
    def export(scan: dict, findings: list[dict], tool_name: str = "SentinelAudit") -> str:
        sarif_log: dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Documents/Statements/Note/sarif-2.1.schema.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": tool_name,
                            "version": "2.0.0",
                            "informationUri": "https://github.com/sentinel-audit",
                            "rules": [],
                        }
                    },
                    "results": [],
                    "invocations": [
                        {
                            "executionSuccessful": scan.get("status") == "completed",
                            "startTimeUtc": scan.get("started_at", ""),
                            "endTimeUtc": scan.get("completed_at", ""),
                        }
                    ],
                }
            ],
        }

        run = sarif_log["runs"][0]
        rule_ids: set[str] = set()

        for f in findings:
            rule_id = f.get("rule_business_id") or f.get("rule_id", str(uuid.uuid4()))
            if rule_id not in rule_ids:
                rule_ids.add(rule_id)
                run["tool"]["driver"]["rules"].append({
                    "id": rule_id,
                    "name": f.get("title", ""),
                    "shortDescription": {"text": f.get("detail", "")[:200]},
                    "fullDescription": {"text": f.get("detail", "")},
                    "defaultConfiguration": {"level": "error"},
                    "helpUri": f.get("references", [None])[0] if f.get("references") else None,
                    "properties": {
                        "severity": f.get("severity", "info"),
                        "cvss": f.get("cvss_score"),
                        "cwe": [c.get("cwe_id", "") for c in (f.get("cwe") or [])],
                    },
                })

            result = {
                "ruleId": rule_id,
                "ruleIndex": list(rule_ids).index(rule_id),
                "level": "error" if f.get("severity") in ("critical", "high") else "warning",
                "message": {"text": f.get("detail", "") or f.get("title", "")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": scan.get("target_url", "")},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "properties": {
                    "severity": f.get("severity", "info"),
                    "confidence": f.get("confidence"),
                    "status": f.get("status", "new"),
                },
            }
            if f.get("cves"):
                result["relatedLocations"] = [
                    {"id": c["cve_id"], "message": {"text": c.get("description", "")[:100]}}
                    for c in f["cves"][:3]
                ]
            run["results"].append(result)

        return json.dumps(sarif_log, indent=2, default=str)


class CycloneDXExporter:
    """Exports findings in CycloneDX 1.4 BOM format."""

    @staticmethod
    def export(scan: dict, findings: list[dict]) -> str:
        components = []
        vulnerabilities = []

        for f in findings:
            evidence = f.get("evidence") or {}
            tech = evidence.get("technology") or f.get("title", "")
            version = evidence.get("version") or ""
            if tech:
                components.append({
                    "type": "library",
                    "name": tech,
                    "version": version or "unknown",
                    "purl": f"pkg:generic/{tech}@{version}" if version else f"pkg:generic/{tech}",
                    "bom-ref": f"pkg:{tech}",
                })

            vuln = {
                "id": f.get("rule_business_id") or str(uuid.uuid4()),
                "source": {"name": "SentinelAudit", "url": "https://github.com/sentinel-audit"},
                "ratings": [{
                    "source": {"name": "SentinelAudit"},
                    "severity": f.get("severity", "info").upper(),
                    "score": f.get("cvss_score", 0.0),
                    "method": "CVSSv3",
                }],
                "description": f.get("detail", "") or f.get("title", ""),
            }
            if f.get("cves"):
                vuln["id"] = f["cves"][0]["cve_id"]
                vuln["recommendation"] = f["cves"][0].get("fix_version")
            vulnerabilities.append(vuln)

        bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [{"vendor": "SentinelAudit", "name": "SentinelAudit", "version": "2.0.0"}],
                "properties": [{"name": "target", "value": scan.get("target_url", "")}],
            },
            "components": components,
            "vulnerabilities": vulnerabilities,
        }
        return json.dumps(bom, indent=2, default=str)


class SPDXExporter:
    """Exports findings in SPDX 2.3 SBOM format."""

    @staticmethod
    def export(scan: dict, findings: list[dict]) -> str:
        packages = []
        for f in findings:
            evidence = f.get("evidence") or {}
            tech = evidence.get("technology") or f.get("title", "")
            version = evidence.get("version") or "unknown"
            if tech:
                packages.append({
                    "SPDXID": f"SPDXRef-{tech.replace(' ', '-')}",
                    "name": tech,
                    "versionInfo": version,
                    "supplier": "NOASSERTION",
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                    "copyrightText": "NOASSERTION",
                })

        doc = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"SentinelAudit Scan - {scan.get('target_url', 'unknown')}",
            "creationInfo": {
                "created": datetime.now(timezone.utc).isoformat(),
                "creators": ["Tool: SentinelAudit-2.0.0"],
            },
            "documentNamespace": f"https://sentinel-audit/scan/{scan.get('id', 'unknown')}",
            "packages": packages,
        }
        return json.dumps(doc, indent=2, default=str)
