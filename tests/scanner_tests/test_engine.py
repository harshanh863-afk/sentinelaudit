"""Tests for the scanner engine."""

import asyncio

from sentinelaudit_scanner.core.engine import ScanEngine, ScanTarget


class TestScanEngine:
    """ScanEngine construction and basic orchestration."""

    def test_engine_initialises_empty(self):
        engine = ScanEngine()
        assert len(engine.checks) == 0

    def test_run_returns_report(self):
        engine = ScanEngine()
        target = ScanTarget(url="https://example.com", host="example.com")
        report = asyncio.run(engine.run(target))
        assert report.target.url == "https://example.com"
        assert report.risk_score == 0.0
