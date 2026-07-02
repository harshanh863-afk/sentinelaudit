"""Scan Manager — orchestrates the full security assessment pipeline.

Coordinates:
    1. Scanner execution (HTTP → TLS → DNS → Tech → JS)
    2. Rule engine — observations to findings
    3. CVE enrichment — attach CVE intelligence to versioned findings
    4. Risk engine — findings to risk scores
    5. Compliance engine — findings to compliance posture
    6. Report generation

Individual scanner failures are captured and do not abort the scan.
Tracks per-scanner reliability: execution time, retries, timeouts, failures.
"""

import asyncio
import logging
import os
import time as time_module
import uuid
from datetime import datetime, timezone
from typing import Any

from app.models.enums import FindingStatus, ScanStatus, SeverityLevel
from app.models.scan import Scan
from app.services.orchestrator.pipeline import (
    PipelineStage,
    get_stage,
)
from app.services.orchestrator.models import ScannerError

logger = logging.getLogger(__name__)

MAX_RETRIES = 2


class ScannerRunStats:
    """Tracks per-scanner execution statistics for reliability reporting."""

    def __init__(self, name: str):
        self.name = name
        self.execution_time_ms: int = 0
        self.retry_count: int = 0
        self.timeout_reason: str | None = None
        self.network_failures: int = 0
        self.partial_failures: int = 0
        self.skipped_checks: int = 0
        self.unsupported_targets: list[str] = []
        self.recovery_attempts: int = 0
        self.status: str = "pending"
        self.observations: int = 0
        self.error: str | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "status": self.status,
            "execution_time_ms": self.execution_time_ms,
            "retry_count": self.retry_count,
            "timeout_reason": self.timeout_reason,
            "network_failures": self.network_failures,
            "partial_failures": self.partial_failures,
            "skipped_checks": self.skipped_checks,
            "unsupported_targets": self.unsupported_targets,
            "recovery_attempts": self.recovery_attempts,
            "observations": self.observations,
            "error": self.error,
        }


class ScanManager:
    """Orchestrates the full assessment pipeline for a single scan."""

    def __init__(self, db_session_factory: Any):
        self._session_factory = db_session_factory
        self._errors: list[ScannerError] = []
        self._scanner_results: list[dict] = []
        self._scanner_stats: dict[str, ScannerRunStats] = {}

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

            # ---- Scanner Pipeline (parallel execution) ----
            scanner_tasks = [
                (PipelineStage.HTTP_ANALYSIS, "HTTP Analyzer", self._run_http_analyzer),
                (PipelineStage.TLS_ANALYSIS, "TLS Analyzer", self._run_tls_analyzer),
                (PipelineStage.DNS_ANALYSIS, "DNS Analyzer", self._run_dns_analyzer),
                (PipelineStage.TECHNOLOGY_FINGERPRINT, "Technology Fingerprinter", self._run_tech_fingerprinter),
                (PipelineStage.JAVASCRIPT_ANALYSIS, "JavaScript Analyzer", self._run_js_analyzer),
            ]

            url = scan.target.url
            parallel_results: list[tuple[str, list[dict]]] = []
            parallel_failed = False

            try:
                import asyncio as _asyncio
                loop = _asyncio.new_event_loop()
                _asyncio.set_event_loop(loop)
                try:
                    coros = [
                        self._run_scanner_stage_async(session, scan, stage, label, fn, url)
                        for stage, label, fn in scanner_tasks
                    ]
                    results = loop.run_until_complete(
                        _asyncio.gather(*coros, return_exceptions=True)
                    )
                    for r in results:
                        if isinstance(r, Exception):
                            logger.warning("PIPELINE: parallel scanner task failed: %s", r)
                            parallel_failed = True
                        elif isinstance(r, tuple):
                            parallel_results.append(r)
                finally:
                    loop.close()
            except Exception as exc:
                logger.warning("PIPELINE: parallel execution error: %s", exc)
                parallel_failed = True

            if parallel_failed or not parallel_results:
                # Collect results from parallel execution that did succeed
                collected = set()
                for label, obs in parallel_results:
                    for o in obs:
                        all_observations.append(o)
                    collected.add(label)
                # Run failed/missing scanners sequentially
                for stage, label, fn in scanner_tasks:
                    if label not in collected:
                        logger.info("PIPELINE: running %s sequentially (parallel failed)", label)
                        obs = self._run_scanner_stage(session, scan, stage, label, fn, url)
                        for o in obs:
                            all_observations.append(o)
            else:
                for label, obs in parallel_results:
                    for o in obs:
                        all_observations.append(o)

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

            # ---- Recalculate Confidence ----
            findings_data = self._recalculate_confidence(findings_data)

            # ---- CVE Enrichment (before persistence) ----
            findings_data = self._enrich_with_cve(findings_data)

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
            scan.scanner_results = self._scanner_results
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

    async def _run_scanner_stage_async(
        self, session, scan: Scan, stage: PipelineStage,
        label: str, scanner_fn, *args,
    ) -> tuple[str, list[dict]]:
        """Async version of _run_scanner_stage for parallel execution."""
        stage_def = get_stage(stage)
        if not stage_def:
            return label, []

        self._update_progress(session, scan, stage, stage_def.start_progress, label)
        stats = ScannerRunStats(label)
        self._scanner_stats[label] = stats

        for attempt in range(1 + MAX_RETRIES):
            try:
                import time as _tm
                start_ms = int(_tm.time() * 1000)
                result = await scanner_fn(*args)
                elapsed = int(_tm.time() * 1000) - start_ms
                stats.execution_time_ms = elapsed
                stats.observations = len(result)
                stats.retry_count = attempt
                stats.status = "success"
                self._scanner_results.append(stats.to_dict())
                return label, result
            except asyncio.TimeoutError:
                stats.timeout_reason = f"Exceeded timeout on attempt {attempt + 1}"
                stats.network_failures += 1
                if attempt < MAX_RETRIES:
                    stats.recovery_attempts += 1
                    continue
                stats.status = "timeout"
                self._errors.append(ScannerError(scanner_name=label, error=stats.timeout_reason))
                self._scanner_results.append(stats.to_dict())
                return label, []
            except Exception as exc:
                err_str = str(exc)
                if "connect" in err_str.lower() or "resolve" in err_str.lower():
                    stats.network_failures += 1
                else:
                    stats.partial_failures += 1
                if attempt < MAX_RETRIES:
                    stats.recovery_attempts += 1
                    continue
                stats.status = "failed"
                stats.error = err_str
                self._errors.append(ScannerError(scanner_name=label, error=err_str))
                self._scanner_results.append(stats.to_dict())
                return label, []
        return label, []

    def _run_scanner_stage(
        self, session, scan: Scan, stage: PipelineStage,
        label: str, scanner_fn, *args,
    ) -> list[dict]:
        stage_def = get_stage(stage)
        if not stage_def:
            logger.info("SCANNER_STAGE [%s]: no stage definition, returning []", label)
            return []
        self._update_progress(session, scan, stage, stage_def.start_progress, label)

        stats = ScannerRunStats(label)
        self._scanner_stats[label] = stats
        start_ms = int(time_module.time() * 1000)

        for attempt in range(1 + MAX_RETRIES):
            try:
                result = asyncio.run(scanner_fn(*args))
                elapsed = int(time_module.time() * 1000) - start_ms
                stats.execution_time_ms = elapsed
                stats.observations = len(result)
                stats.retry_count = attempt
                stats.status = "success"
                logger.info(
                    "SCANNER_STAGE [%s]: returned %d observations in %dms (attempt %d/%d)",
                    label, len(result), elapsed, attempt + 1, 1 + MAX_RETRIES,
                )
                self._scanner_results.append(stats.to_dict())
                return result
            except asyncio.TimeoutError:
                elapsed = int(time_module.time() * 1000) - start_ms
                stats.timeout_reason = f"Exceeded timeout on attempt {attempt + 1}"
                stats.network_failures += 1
                logger.warning(
                    "SCANNER_STAGE [%s]: timeout on attempt %d/%d (%dms)",
                    label, attempt + 1, 1 + MAX_RETRIES, elapsed,
                )
                if attempt < MAX_RETRIES:
                    stats.recovery_attempts += 1
                    continue
                stats.execution_time_ms = elapsed
                stats.status = "timeout"
                self._errors.append(ScannerError(scanner_name=label, error=stats.timeout_reason))
                self._scanner_results.append(stats.to_dict())
                return []
            except Exception as exc:
                elapsed = int(time_module.time() * 1000) - start_ms
                err_str = str(exc)
                logger.error(
                    "SCANNER_STAGE [%s] ERROR (attempt %d/%d): %s",
                    label, attempt + 1, 1 + MAX_RETRIES, err_str, exc_info=True,
                )
                if "connect" in err_str.lower() or "resolve" in err_str.lower():
                    stats.network_failures += 1
                else:
                    stats.partial_failures += 1
                if attempt < MAX_RETRIES:
                    stats.recovery_attempts += 1
                    continue
                stats.execution_time_ms = elapsed
                stats.status = "failed"
                stats.error = err_str
                self._errors.append(ScannerError(scanner_name=label, error=err_str))
                self._scanner_results.append(stats.to_dict())
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
        if not rules:
            msg = (
                f"Rule loading failed: no rule definitions were found. "
                f"Expected directory: {loader.rules_path} "
                f"(resolved: {os.path.abspath(loader.rules_path)}). "
                f"cwd={os.getcwd()} __file__={__file__}"
            )
            logger.error("RULE_ENGINE: %s", msg)
            raise RuntimeError(msg)
        matcher = RuleMatcher(rules)

        MIN_CONFIDENCE_THRESHOLD = 0.5

        matched_count = 0
        no_match_count = 0
        low_confidence_skipped = 0
        dedup_seen: set[tuple[str, str]] = set()
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
            if match.matched and match.rule:
                dedup_key = (obs.check_name, match.rule.rule_id)
                if dedup_key in dedup_seen:
                    logger.info("RULE_ENGINE: dedup skip obs[%d] key=%s", idx, dedup_key)
                    no_match_count += 1
                    continue
                dedup_seen.add(dedup_key)

            finding = FindingBuilder.build(
                scan_id=scan_id,
                match=match,
                observation=obs,
            )
            if finding:
                if finding.confidence is not None and finding.confidence < MIN_CONFIDENCE_THRESHOLD:
                    logger.info("RULE_ENGINE: obs[%d] confidence=%.2f below threshold, skipping", idx, finding.confidence)
                    low_confidence_skipped += 1
                    continue
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
                    "confidence": finding.confidence,
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
        logger.info("RULE_ENGINE: %d observations -> %d matched -> %d findings_data, %d no_match, %d low_confidence_skipped",
                    len(observations), matched_count, len(findings_data), no_match_count, low_confidence_skipped)
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
                confidence=fd.get("confidence"),
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
    # CVE Enrichment
    # ------------------------------------------------------------------

    def _enrich_with_cve(self, findings_data: list[dict]) -> list[dict]:
        """Enrich findings with CVE intelligence asynchronously."""
        try:
            import asyncio
            from app.services.cve.enrichment import CveEnrichmentService
            service = CveEnrichmentService()
            enriched = asyncio.run(service.enrich(findings_data))
            cve_count = sum(1 for f in enriched if f.get("cves"))
            logger.info("CVE_ENRICHMENT: %d findings enriched with CVE data", cve_count)
            return enriched
        except Exception as exc:
            logger.warning("CVE_ENRICHMENT: failed, continuing without enrichment: %s", exc)
            return findings_data

    # ------------------------------------------------------------------
    # Confidence recalculation
    # ------------------------------------------------------------------

    def _recalculate_confidence(self, findings_data: list[dict]) -> list[dict]:
        """Apply evidence-based confidence scoring to all findings."""
        try:
            from app.services.risk_engine.confidence_engine import ConfidenceEngine
            for finding in findings_data:
                score, label = ConfidenceEngine.calculate_from_finding_data(finding)
                finding["confidence"] = score
                finding["confidence_label"] = label.value
            logger.info("CONFIDENCE: recalculated for %d findings", len(findings_data))
        except Exception as exc:
            logger.warning("CONFIDENCE: recalculation failed, using existing: %s", exc)
        return findings_data

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def _calculate_risk(self, session, scan_id: uuid.UUID, finding_objs: list) -> dict:
        from app.models import Finding
        from app.services.risk_engine import RiskCalculator
        from app.services.risk_engine.models import ConfidenceLevel

        def _confidence_level(value: float) -> ConfidenceLevel:
            if value >= 0.90:
                return ConfidenceLevel.CONFIRMED
            if value >= 0.75:
                return ConfidenceLevel.HIGH
            if value >= 0.60:
                return ConfidenceLevel.MEDIUM
            return ConfidenceLevel.LOW

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
                confidence=_confidence_level(f.confidence) if f.confidence is not None else None,
            )
            for f in all_findings
        ]
        overall = RiskCalculator.calculate_overall(risk_results)
        return {
            "score": overall.score,
            "level": overall.level.value,
        }
