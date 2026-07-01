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

            # ---- Rule Engine ----
            self._update_progress(session, scan, PipelineStage.RULE_PROCESSING,
                                  80, "Processing observations through rules")
            findings_data = self._apply_rule_engine(scan_id, all_observations)

            # ---- Persist Findings ----
            finding_objs = self._persist_findings(session, scan_id, findings_data)
            session.flush()

            # ---- Risk Scoring ----
            self._update_progress(session, scan, PipelineStage.RISK_SCORING,
                                  88, "Calculating risk scores")
            overall_risk = self._calculate_risk(session, scan_id, finding_objs)
            scan.risk_score = overall_risk.get("score", 0.0)

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
            return []
        self._update_progress(session, scan, stage, stage_def.start_progress, label)
        try:
            return asyncio.run(scanner_fn(*args))
        except Exception as exc:
            self._errors.append(ScannerError(scanner_name=label, error=str(exc)))
            return []

    async def _run_http_analyzer(self, url: str) -> list[dict]:
        from sentinelaudit_scanner.checks.http_analyzer import HTTPAnalyzer
        analyzer = HTTPAnalyzer(timeout=30)
        results = await self.run_with_timeout(analyzer.analyze, url, timeout=30)
        return [
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

    async def _run_tls_analyzer(self, url: str) -> list[dict]:
        from sentinelaudit_scanner.checks.tls_analyzer import TLSInspector
        inspector = TLSInspector()
        results = await self.run_with_timeout(inspector.analyze, url)
        return [
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

    async def _run_dns_analyzer(self, url: str) -> list[dict]:
        from sentinelaudit_scanner.checks.dns_analyzer import DNSAnalyzer
        from urllib.parse import urlparse
        host = urlparse(url).hostname or url
        analyzer = DNSAnalyzer()
        results = await self.run_with_timeout(analyzer.analyze, host)
        return [
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

    async def _run_tech_fingerprinter(self, url: str) -> list[dict]:
        from sentinelaudit_scanner.checks.technology_fingerprint import TechnologyFingerprinter
        fingerprinter = TechnologyFingerprinter()
        results = await self.run_with_timeout(fingerprinter.analyze, url)
        return [
            {
                "check_name": r.observation_type,
                "category": (r.metadata or {}).get("category", "technology_fingerprint"),
                "passed": False,
                "detail": (r.metadata or {}).get("detail", ""),
                "evidence": r.evidence,
                "severity": (r.metadata or {}).get("severity", "low"),
            }
            for r in results
        ]

    async def _run_js_analyzer(self, url: str) -> list[dict]:
        from sentinelaudit_scanner.checks.javascript_analyzer import JavaScriptAnalyzer
        analyzer = JavaScriptAnalyzer()
        results = await self.run_with_timeout(analyzer.analyze, url)
        return [
            {
                "check_name": r.observation_type,
                "category": (r.metadata or {}).get("category", "javascript_analysis"),
                "passed": False,
                "detail": (r.metadata or {}).get("detail", ""),
                "evidence": r.evidence,
                "severity": (r.metadata or {}).get("severity", "medium"),
            }
            for r in results
        ]

    # ------------------------------------------------------------------
    # Rule engine
    # ------------------------------------------------------------------

    def _apply_rule_engine(self, scan_id: uuid.UUID, observations: list[dict]) -> list[dict]:
        from app.services.rule_engine import RuleLoader, RuleMatcher
        from app.services.rule_engine.finding_builder import FindingBuilder
        from app.services.rule_engine.rule_matcher import ScannerObservation

        loader = RuleLoader()
        rules = loader.load_all()
        matcher = RuleMatcher(rules)

        findings_data: list[dict] = []
        for obs_data in observations:
            obs = ScannerObservation(
                check_name=obs_data.get("check_name", "unknown"),
                category=obs_data.get("category", "unknown"),
                passed=obs_data.get("passed", False),
                detail=obs_data.get("detail", ""),
                evidence=obs_data.get("evidence", ""),
            )
            match = matcher.match(obs)
            finding = FindingBuilder.build(
                scan_id=scan_id,
                match=match,
                observation=obs,
            )
            if finding:
                findings_data.append({
                    "rule_id": finding.rule_id,
                    "rule_business_id": finding.rule_business_id,
                    "severity": finding.severity,
                    "status": finding.status,
                    "passed": finding.passed,
                    "detail": finding.detail,
                    "finding_type": obs_data.get("check_name", ""),
                })
        return findings_data

    # ------------------------------------------------------------------
    # Finding persistence
    # ------------------------------------------------------------------

    def _persist_findings(self, session, scan_id: uuid.UUID, findings_data: list[dict]) -> list:
        from app.models import Finding, Rule
        from app.models.enums import FindingStatus, SeverityLevel

        rule_cache: dict[str, uuid.UUID | None] = {}
        objs = []
        for fd in findings_data:
            rule_id = fd.get("rule_id")
            rule_business_id = fd.get("rule_business_id")
            if rule_id is None and rule_business_id:
                if rule_business_id not in rule_cache:
                    rule_obj = session.query(Rule).filter(Rule.rule_id == rule_business_id).first()
                    rule_cache[rule_business_id] = rule_obj.id if rule_obj else None
                rule_id = rule_cache[rule_business_id]

            finding = Finding(
                scan_id=scan_id,
                rule_id=rule_id,
                severity=SeverityLevel(fd.get("severity", "info")),
                status=FindingStatus(fd.get("status", "new")),
                passed=fd.get("passed", False),
                detail=fd.get("detail"),
                finding_type=fd.get("finding_type", ""),
            )
            session.add(finding)
            objs.append(finding)
        session.flush()
        return objs

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def _calculate_risk(self, session, scan_id: uuid.UUID, finding_objs: list) -> dict:
        from app.models import Finding
        from app.services.risk_engine import RiskCalculator

        all_findings = session.query(Finding).filter(Finding.scan_id == scan_id).all()
        all_findings = list(set(all_findings) | set(finding_objs))

        risk_results = [
            RiskCalculator.calculate_finding(
                severity=f.severity,
                attack_vector="network",
                status=f.status,
            )
            for f in all_findings
        ]
        overall = RiskCalculator.calculate_overall(risk_results)
        return {
            "score": overall.score,
            "level": overall.level.value,
        }
