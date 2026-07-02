"""Scan Manager — orchestrates the full security assessment pipeline.

Coordinates:
    1. Scanner execution (HTTP → TLS → DNS → Tech → JS)
    2. Rule engine — observations to findings
    3. Risk engine — findings to risk scores
    4. Compliance engine — findings to compliance posture
    5. Report generation

Individual scanner failures are captured and do not abort the scan.
"""

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from app.models.enums import FindingStatus, ScanStatus, SeverityLevel
from app.models.scan import Scan
from app.services.orchestrator.pipeline import (
    PIPELINE,
    PipelineStage,
    StageDefinition,
    get_stage,
)
from app.services.orchestrator.models import ScannerError

logger = logging.getLogger(__name__)


class ScanManager:
    """Orchestrates the full assessment pipeline for a single scan."""

    def __init__(self, db_session_factory: Any):
        self._session_factory = db_session_factory
        self._errors: list[ScannerError] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_pipeline(self, scan_id: uuid.UUID) -> dict:
        """Execute the complete assessment pipeline for a scan."""
        session = self._session_factory()
        if session is None:
            logger.error("PIPELINE FAILURE: session factory returned None")
            return {"status": "error", "detail": "Database session factory returned None"}
        try:
            scan = session.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return {"status": "error", "detail": "Scan not found"}

            if scan.started_at is None:
                scan.started_at = datetime.now(timezone.utc)

            self._update_progress(session, scan, PipelineStage.HTTP_ANALYSIS, 5,
                                  "Starting assessment")
            all_observations: list[dict] = []

            # ---- Scanner Pipeline ----
            all_observations.extend(self._run_scanner_stage(
                session, scan, PipelineStage.HTTP_ANALYSIS, "HTTP Analyzer",
                self._run_http_analyzer, scan.target.url,
            ))
            all_observations.extend(self._run_scanner_stage(
                session, scan, PipelineStage.TLS_ANALYSIS, "TLS Analyzer",
                self._run_tls_analyzer, scan.target.url,
            ))
            all_observations.extend(self._run_scanner_stage(
                session, scan, PipelineStage.DNS_ANALYSIS, "DNS Analyzer",
                self._run_dns_analyzer, scan.target.url,
            ))
            all_observations.extend(self._run_scanner_stage(
                session, scan, PipelineStage.TECHNOLOGY_FINGERPRINT,
                "Technology Fingerprinter",
                self._run_tech_fingerprinter, scan.target.url,
            ))
            all_observations.extend(self._run_scanner_stage(
                session, scan, PipelineStage.JAVASCRIPT_ANALYSIS,
                "JavaScript Analyzer",
                self._run_js_analyzer, scan.target.url,
            ))

            logger.info("PIPELINE: total observations collected = %d", len(all_observations))
            if all_observations:
                types = set(o.get("check_name") for o in all_observations)
                cats = set(o.get("category") for o in all_observations)
                logger.info("PIPELINE: observation types=%s categories=%s", sorted(types), sorted(cats))
            else:
                logger.warning("PIPELINE: ZERO observations collected from ALL scanners")

            # ---- Rule Engine ----
            self._update_progress(session, scan, PipelineStage.RULE_PROCESSING,
                                  80, "Processing observations through rules")
            findings_data = self._apply_rule_engine(scan_id, all_observations)

            logger.info("PIPELINE: findings_data from rule engine = %d", len(findings_data))

            # ---- Persist Findings ----
            finding_objs = self._persist_findings(session, scan_id, findings_data)
            session.flush()
            logger.info("PIPELINE: finding_objs after persist = %d", len(finding_objs))

            # ---- Risk Scoring ----
            self._update_progress(session, scan, PipelineStage.RISK_SCORING,
                                  88, "Calculating risk scores")
            overall_risk = self._calculate_risk(session, scan_id, finding_objs)
            scan.risk_score = overall_risk.get("score", 0.0)
            logger.info("PIPELINE: risk_score = %s", scan.risk_score)

            # ---- Compliance Assessment ----
            self._update_progress(session, scan, PipelineStage.COMPLIANCE_ASSESSMENT,
                                  93, "Assessing compliance posture")

            # ---- Report Generation ----
            self._update_progress(session, scan, PipelineStage.REPORT_GENERATION,
                                  97, "Generating report")

            # ---- Complete ----
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            scan.progress = 100
            scan.progress_stage = "complete"
            if self._errors:
                existing = scan.error or ""
                err_summary = "; ".join(f"{e.scanner_name}: {e.error}" for e in self._errors)
                scan.error = (existing + "; " + err_summary).strip("; ")
            session.commit()

            return {
                "status": "completed",
                "scan_id": str(scan_id),
                "findings_count": len(finding_objs),
                "risk_score": overall_risk.get("score", 0.0),
                "risk_level": overall_risk.get("level", "info"),
                "errors": len(self._errors),
            }

        except Exception as exc:
            logger.error(f"PIPELINE FAILURE: {str(exc)}", exc_info=True)
            if session is not None:
                try:
                    scan = session.query(Scan).filter(Scan.id == scan_id).first()
                    if scan:
                        scan.status = ScanStatus.FAILED
                        scan.error = str(exc)
                        scan.completed_at = datetime.now(timezone.utc)
                        session.commit()
                except Exception as inner_err:
                    logger.error(f"PIPELINE FAILURE: failed to persist error state: {str(inner_err)}", exc_info=True)
            self.cleanup_resources(session)
            raise exc

        finally:
            if session is not None:
                session.close()

    # ------------------------------------------------------------------
    # Timeout helper
    # ------------------------------------------------------------------

    async def run_with_timeout(self, scanner_fn, *args, timeout=60):
        try:
            return await asyncio.wait_for(scanner_fn(*args), timeout=timeout)
        except asyncio.TimeoutError:
            logger.error(f"SCANNER TIMEOUT: {scanner_fn.__name__} exceeded {timeout}s")
            raise

    # ------------------------------------------------------------------
    # Resource cleanup
    # ------------------------------------------------------------------

    def cleanup_resources(self, session):
        """Release any resources held during the pipeline."""
        logger.info("PIPELINE CLEANUP: releasing resources")

    # ------------------------------------------------------------------
    # Progress tracking
    # ------------------------------------------------------------------

    def _update_progress(
        self, session, scan: Scan, stage: PipelineStage,
        progress: int, label: str,
    ) -> None:
        scan.status = ScanStatus.PROCESSING
        scan.progress = progress
        scan.progress_stage = label
        session.commit()

    # ------------------------------------------------------------------
    # Scanner stages
    # ------------------------------------------------------------------

    def _run_scanner_stage(
        self, session, scan: Scan, stage: PipelineStage,
        label: str, scanner_fn, *args,
    ) -> list[dict]:
        stage_def = get_stage(stage)
        if not stage_def:
            logger.info("SCANNER_STAGE [%s]: no stage definition, returning []", label)
            return []
        self._update_progress(session, scan, stage, stage_def.start_progress, label)
        try:
            result = asyncio.run(scanner_fn(*args))
            logger.info("SCANNER_STAGE [%s]: returned %d observations", label, len(result))
            for i, obs in enumerate(result):
                logger.info("SCANNER_STAGE [%s] obs[%d]: check_name=%s category=%s severity=%s has_evidence=%s",
                            label, i, obs.get("check_name"), obs.get("category"),
                            obs.get("severity"), "yes" if obs.get("evidence") else "no")
            return result
        except Exception as exc:
            logger.error("SCANNER_STAGE [%s] ERROR: %s", label, str(exc), exc_info=True)
            self._errors.append(ScannerError(scanner_name=label, error=str(exc)))
            return []

    async def _run_http_analyzer(self, url: str) -> list[dict]:
        from sentinelaudit_scanner.checks.http_analyzer import HTTPAnalyzer
        analyzer = HTTPAnalyzer(timeout=30)
        logger.info("HTTP_ANALYZER: starting analyze(%s)", url)
        results = await self.run_with_timeout(analyzer.analyze, url, timeout=30)
        logger.info("HTTP_ANALYZER: raw results count=%d", len(results))
        out = [
            {
                "check_name": r.observation_type,
                "category": (r.metadata or {}).get("category", "http_security"),
                "passed": False,
                "detail": (r.metadata or {}).get("detail", ""),
                "evidence": r.evidence,
                "severity": (r.metadata or {}).get("severity", "medium"),
            }
            for r in results
        ]
        logger.info("HTTP_ANALYZER: returning %d formatted observations", len(out))
        return out

    async def _run_tls_analyzer(self, url: str) -> list[dict]:
        from sentinelaudit_scanner.checks.tls_analyzer import TLSAnalyzer
        inspector = TLSAnalyzer()
        logger.info("TLS_ANALYZER: starting analyze(%s)", url)
        results = await self.run_with_timeout(inspector.analyze, url)
        logger.info("TLS_ANALYZER: raw results count=%d", len(results))
        out = [
            {
                "check_name": r.observation_type,
                "category": (r.metadata or {}).get("category", "tls_analysis"),
                "passed": False,
                "detail": (r.metadata or {}).get("detail", ""),
                "evidence": r.evidence,
                "severity": (r.metadata or {}).get("severity", "high"),
            }
            for r in results
        ]
        logger.info("TLS_ANALYZER: returning %d formatted observations", len(out))
        return out

    async def _run_dns_analyzer(self, url: str) -> list[dict]:
        from sentinelaudit_scanner.checks.dns_analyzer import DNSAnalyzer
        from urllib.parse import urlparse
        host = urlparse(url).hostname or url
        analyzer = DNSAnalyzer()
        logger.info("DNS_ANALYZER: starting analyze(%s)", host)
        results = await self.run_with_timeout(analyzer.analyze, host)
        logger.info("DNS_ANALYZER: raw results count=%d", len(results))
        out = [
            {
                "check_name": r.observation_type,
                "category": (r.metadata or {}).get("category", "dns_analysis"),
                "passed": False,
                "detail": (r.metadata or {}).get("detail", ""),
                "evidence": r.evidence,
                "severity": (r.metadata or {}).get("severity", "medium"),
            }
            for r in results
        ]
        logger.info("DNS_ANALYZER: returning %d formatted observations", len(out))
        return out

    async def _run_tech_fingerprinter(self, url: str) -> list[dict]:
        from sentinelaudit_scanner.checks.technology_fingerprint import TechFingerprinter
        fingerprinter = TechFingerprinter()
        logger.info("TECH_FINGERPRINTER: starting fingerprint(%s)", url)
        results = await self.run_with_timeout(fingerprinter.fingerprint, url)
        logger.info("TECH_FINGERPRINTER: raw results count=%d", len(results))
        out = [
            {
                "check_name": r.observation_type,
                "category": "technology",
                "passed": False,
                "detail": (r.metadata or {}).get("detail", ""),
                "evidence": r.evidence,
                "severity": (r.metadata or {}).get("severity", "low"),
            }
            for r in results
        ]
        logger.info("TECH_FINGERPRINTER: returning %d formatted observations", len(out))
        return out

    async def _run_js_analyzer(self, url: str) -> list[dict]:
        from sentinelaudit_scanner.checks.javascript_analyzer import JavaScriptAnalyzer
        analyzer = JavaScriptAnalyzer()
        logger.info("JS_ANALYZER: starting analyze(%s)", url)
        results = await self.run_with_timeout(analyzer.analyze, url)
        logger.info("JS_ANALYZER: raw results count=%d", len(results))
        out = [
            {
                "check_name": r.observation_type,
                "category": "javascript",
                "passed": False,
                "detail": (r.metadata or {}).get("detail", ""),
                "evidence": r.evidence,
                "severity": (r.metadata or {}).get("severity", "medium"),
            }
            for r in results
        ]
        logger.info("JS_ANALYZER: returning %d formatted observations", len(out))
        return out

    # ------------------------------------------------------------------
    # Rule engine
    # ------------------------------------------------------------------

    def _apply_rule_engine(self, scan_id: uuid.UUID, observations: list[dict]) -> list[dict]:
        from app.services.rule_engine import RuleLoader, RuleMatcher
        from app.services.rule_engine.finding_builder import FindingBuilder
        from app.services.rule_engine.rule_matcher import ScannerObservation

        loader = RuleLoader()
        rules = loader.load_all()
        logger.info("RULE_ENGINE: loaded %d rules from %s", len(rules), loader.rules_path)
        matcher = RuleMatcher(rules)

        matched_count = 0
        no_match_count = 0
        findings_data: list[dict] = []
        for idx, obs_data in enumerate(observations):
            obs = ScannerObservation(
                check_name=obs_data.get("check_name", "unknown"),
                category=obs_data.get("category", "unknown"),
                passed=obs_data.get("passed", False),
                detail=obs_data.get("detail", ""),
                evidence=obs_data.get("evidence", ""),
            )
            match = matcher.match(obs)
            logger.info("RULE_ENGINE: obs[%d] check_name=%s category=%s matched=%s rule=%s",
                        idx, obs.check_name, obs.category,
                        match.matched, match.rule.rule_id if match.matched else "N/A")
            finding = FindingBuilder.build(
                scan_id=scan_id,
                match=match,
                observation=obs,
            )
            if finding:
                matched_count += 1
                findings_data.append({
                    "rule_id": finding.rule_id,
                    "rule_business_id": finding.rule_business_id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "status": finding.status,
                    "passed": finding.passed,
                    "detail": finding.detail,
                    "finding_type": obs_data.get("check_name", ""),
                    "cvss_score": finding.cvss_score,
                    "evidence": finding.evidence,
                    "impact": finding.impact,
                    "business_impact": finding.business_impact,
                    "risk_explanation": finding.risk_explanation,
                    "affected_component": finding.affected_component,
                    "false_positive_notes": finding.false_positive_notes,
                    "compliance_mappings": finding.compliance_mappings,
                    "cwe": finding.cwe,
                    "capec": finding.capec,
                    "mitre_attack": finding.mitre_attack,
                })
            else:
                no_match_count += 1
        logger.info("RULE_ENGINE: %d observations -> %d matched -> %d findings_data, %d no_match",
                    len(observations), matched_count, len(findings_data), no_match_count)
        return findings_data

    # ------------------------------------------------------------------
    # Finding persistence
    # ------------------------------------------------------------------

    def _persist_findings(self, session, scan_id: uuid.UUID, findings_data: list[dict]) -> list:
        from app.models import ComplianceMapping, Evidence, Finding, Rule
        from app.models.enums import FindingStatus, SeverityLevel

        logger.info("PERSIST: attempting to persist %d findings_data items", len(findings_data))
        rule_cache: dict[str, uuid.UUID | None] = {}
        objs = []
        for idx, fd in enumerate(findings_data):
            rule_id = fd.get("rule_id")
            rule_business_id = fd.get("rule_business_id")
            if rule_id is None and rule_business_id:
                if rule_business_id not in rule_cache:
                    rule_obj = session.query(Rule).filter(Rule.rule_id == rule_business_id).first()
                    rule_cache[rule_business_id] = rule_obj.id if rule_obj else None
                rule_id = rule_cache[rule_business_id]
                logger.info("PERSIST: finding[%d] rule_business_id=%s -> rule_id=%s",
                            idx, rule_business_id, rule_id)

            severity_val = fd.get("severity") or "info"
            try:
                sev_enum = SeverityLevel(severity_val)
            except Exception:
                logger.error("PERSIST: finding[%d] INVALID severity=%s, defaulting to info", idx, severity_val)
                sev_enum = SeverityLevel.INFO

            status_val = fd.get("status") or "new"
            try:
                status_enum = FindingStatus(status_val)
            except Exception:
                logger.error("PERSIST: finding[%d] INVALID status=%s, defaulting to new", idx, status_val)
                status_enum = FindingStatus.NEW

            finding = Finding(
                scan_id=scan_id,
                rule_id=rule_id,
                title=fd.get("title"),
                severity=sev_enum,
                status=status_enum,
                passed=fd.get("passed", False),
                detail=fd.get("detail"),
                finding_type=fd.get("finding_type", ""),
                cvss_score=fd.get("cvss_score"),
            )
            session.add(finding)
            session.flush()
            logger.info("PERSIST: finding[%d] created id=%s title=%s severity=%s", idx, finding.id, finding.title, finding.severity)

            evidence_raw = fd.get("evidence")
            if evidence_raw and isinstance(evidence_raw, dict):
                evidence = Evidence(
                    scan_id=scan_id,
                    finding_id=finding.id,
                    type=fd.get("finding_type", "observation"),
                    data=evidence_raw,
                )
                session.add(evidence)
                logger.info("PERSIST: evidence added for finding[%d]", idx)
            else:
                logger.info("PERSIST: no evidence dict for finding[%d] (evidence_raw type=%s)", idx, type(evidence_raw).__name__ if evidence_raw is not None else "None")

            cm_count = 0
            for cm in fd.get("compliance_mappings", []):
                mapping = ComplianceMapping(
                    finding_id=finding.id,
                    framework=cm.get("framework", ""),
                    control_id=cm.get("control_id", ""),
                    control_name=cm.get("control_name", ""),
                )
                session.add(mapping)
                cm_count += 1
            logger.info("PERSIST: finding[%d] -> %d compliance mappings added", idx, cm_count)

            objs.append(finding)
        session.flush()
        logger.info("PERSIST: total findings persisted in this batch: %d", len(objs))
        return objs

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def _calculate_risk(self, session, scan_id: uuid.UUID, finding_objs: list) -> dict:
        from app.models import Finding
        from app.services.risk_engine import RiskCalculator

        all_findings = session.query(Finding).filter(Finding.scan_id == scan_id).all()
        seen_ids = {f.id for f in all_findings}
        for f in finding_objs:
            if f.id not in seen_ids:
                all_findings.append(f)

        risk_results = [
            RiskCalculator.calculate_finding(
                severity=f.severity,
                attack_vector="network",
                status=f.status,
                cvss_score=f.cvss_score,
            )
            for f in all_findings
        ]
        overall = RiskCalculator.calculate_overall(risk_results)
        return {
            "score": overall.score,
            "level": overall.level.value,
        }
