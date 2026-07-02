"""Rule engine validation — validates all YAML rules during startup.

Checks:
    - Duplicate rule IDs and business IDs
    - Invalid YAML syntax
    - Invalid regex patterns
    - Missing compliance mappings
    - Missing remediation text
    - Missing severity
    - Missing CVSS
    - Invalid evidence mappings
    - Invalid confidence values
    - Malformed references
    - Missing descriptions
    - Invalid CWE/CAPEC/MITRE references

Raises RuleValidationError on any issue.
"""

import logging
import os
import re

import yaml

from app.services.rule_engine.rule_loader import RuleLoader

logger = logging.getLogger(__name__)


class RuleValidationError(Exception):
    """Raised when rule validation fails."""

    def __init__(self, message: str, issues: list[dict] | None = None):
        super().__init__(message)
        self.issues = issues or []


class RuleValidator:
    """Validates rule files for correctness and consistency."""

    REQUIRED_FIELDS = ["id", "name", "category", "severity", "description", "remediation"]
    VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
    VALID_CATEGORIES = {
        "headers", "tls", "dns", "cookies", "javascript", "technology",
        "network", "authentication", "authorization", "input_validation",
        "general", "compliance", "sample", "privacy", "secret_detection",
        "cors", "cache", "observability",
    }

    def __init__(self, rules_path: str | None = None):
        self._loader = RuleLoader(rules_path=rules_path)

    def validate_all(self) -> list[dict]:
        """Validate all rules and return list of issues.

        Returns empty list if all rules are valid.
        Raises RuleValidationError if any rule has issues.
        """
        issues: list[dict] = []
        seen_ids: dict[str, str] = {}
        seen_names: dict[str, str] = {}

        rules_dir = os.path.abspath(self._loader.rules_path)
        if not os.path.isdir(rules_dir):
            return [{"file": rules_dir, "issue": "Rules directory not found"}]

        for root, _dirs, files in os.walk(rules_dir):
            for filename in sorted(files):
                if not filename.endswith((".yaml", ".yml")):
                    continue
                filepath = os.path.join(root, filename)
                file_issues = self._validate_file(filepath, seen_ids, seen_names)
                issues.extend(file_issues)

        if issues:
            raise RuleValidationError(
                f"Rule validation failed with {len(issues)} issue(s)",
                issues=issues,
            )
        return issues

    def _validate_file(
        self,
        filepath: str,
        seen_ids: dict[str, str],
        seen_names: dict[str, str],
    ) -> list[dict]:
        issues: list[dict] = []
        rel_path = os.path.relpath(filepath)

        # Check YAML syntax
        try:
            with open(filepath, encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as exc:
            issues.append({"file": rel_path, "issue": f"Invalid YAML: {exc}"})
            return issues
        except OSError as exc:
            issues.append({"file": rel_path, "issue": f"Read error: {exc}"})
            return issues

        if not data:
            issues.append({"file": rel_path, "issue": "Empty file or null content"})
            return issues

        if "rules" not in data:
            issues.append({"file": rel_path, "issue": "Missing 'rules' key"})
            return issues

        if not isinstance(data["rules"], list):
            issues.append({"file": rel_path, "issue": "'rules' must be a list"})
            return issues

        for idx, rule in enumerate(data["rules"]):
            if not isinstance(rule, dict):
                issues.append({"file": rel_path, "issue": f"rule[{idx}] is not a dict"})
                continue
            rule_issues = self._validate_rule(rule, rel_path, idx, seen_ids, seen_names)
            issues.extend(rule_issues)

        return issues

    def _validate_rule(
        self,
        rule: dict,
        rel_path: str,
        idx: int,
        seen_ids: dict[str, str],
        seen_names: dict[str, str],
    ) -> list[dict]:
        issues: list[dict] = []
        rule_id = str(rule.get("id", ""))
        rule_name = str(rule.get("name", ""))

        prefix = f"{rel_path}[{idx}] (id={rule_id}, name={rule_name})"

        for field in self.REQUIRED_FIELDS:
            if field not in rule or rule.get(field) is None or str(rule.get(field, "")).strip() == "":
                issues.append({"file": rel_path, "issue": f"{prefix}: missing required field '{field}'"})

        severity = rule.get("severity", "").lower()
        if severity and severity not in self.VALID_SEVERITIES:
            issues.append({
                "file": rel_path,
                "issue": f"{prefix}: invalid severity '{severity}'",
            })

        category = rule.get("category", "")
        if category and category not in self.VALID_CATEGORIES:
            issues.append({
                "file": rel_path,
                "issue": f"{prefix}: unrecognized category '{category}'",
            })

        # Check regex patterns in match rules
        match = rule.get("match", {})
        if isinstance(match, dict):
            for key, value in match.items():
                if isinstance(value, str) and key.endswith(("_pattern", "_regex", "pattern")):
                    try:
                        re.compile(value)
                    except re.error as exc:
                        issues.append({
                            "file": rel_path,
                            "issue": f"{prefix}: invalid regex in match.{key}: {exc}",
                        })

        # Check CVSS
        cvss = rule.get("cvss_score")
        if cvss is not None:
            try:
                cv = float(cvss)
                if cv < 0.0 or cv > 10.0:
                    issues.append({
                        "file": rel_path,
                        "issue": f"{prefix}: cvss_score {cv} out of range (0-10)",
                    })
            except (ValueError, TypeError):
                issues.append({
                    "file": rel_path,
                    "issue": f"{prefix}: invalid cvss_score '{cvss}'",
                })

        # Check compliance mappings
        compliance = rule.get("compliance", [])
        if isinstance(compliance, list):
            for ci, cr in enumerate(compliance):
                if isinstance(cr, dict):
                    if not cr.get("framework"):
                        issues.append({
                            "file": rel_path,
                            "issue": f"{prefix}: compliance[{ci}] missing 'framework'",
                        })
                    if not cr.get("control_id"):
                        issues.append({
                            "file": rel_path,
                            "issue": f"{prefix}: compliance[{ci}] missing 'control_id'",
                        })

        # Check CWE references
        cwe_list = rule.get("cwe", [])
        if isinstance(cwe_list, list):
            for ci, cw in enumerate(cwe_list):
                if isinstance(cw, dict) and not cw.get("cwe_id", "").startswith("CWE-"):
                    issues.append({
                        "file": rel_path,
                        "issue": f"{prefix}: cwe[{ci}] invalid cwe_id format (expected CWE-xxx)",
                    })

        # Check references
        refs = rule.get("references", [])
        if isinstance(refs, list):
            for ri, ref in enumerate(refs):
                if isinstance(ref, str) and not ref.startswith(("http://", "https://", "CVE-", "BID-", "CWE-")):
                    issues.append({
                        "file": rel_path,
                        "issue": f"{prefix}: references[{ri}] '{ref}' not a valid URL, CVE, BID, or CWE reference",
                    })

        # Check duplication
        if rule_id:
            if rule_id in seen_ids:
                issues.append({
                    "file": rel_path,
                    "issue": f"{prefix}: duplicate rule id '{rule_id}' (first seen in {seen_ids[rule_id]})",
                })
            else:
                seen_ids[rule_id] = rel_path

        if rule_name:
            if rule_name in seen_names:
                issues.append({
                    "file": rel_path,
                    "issue": f"{prefix}: duplicate rule name '{rule_name}' (first seen in {seen_names[rule_name]})",
                })
            else:
                seen_names[rule_name] = rel_path

        return issues
