from dataclasses import dataclass, field
from typing import Protocol


class CheckResult:
    """Base protocol for all check results."""

    def __init__(self, passed: bool, severity: str, details: str | None = None):
        self.passed = passed
        self.severity = severity
        self.details = details


class SecurityCheck(Protocol):
    """Interface that all security checks must implement."""

    name: str
    description: str

    async def run(self, target: str) -> CheckResult:
        ...


@dataclass
class ScanTarget:
    url: str
    host: str
    port: int | None = None


@dataclass
class ScanReport:
    target: ScanTarget
    results: list[CheckResult] = field(default_factory=list)
    risk_score: float = 0.0


class ScanEngine:
    """Orchestrates the execution of security checks against a target."""

    def __init__(self):
        self.checks: list[SecurityCheck] = []

    def register(self, check: SecurityCheck) -> None:
        self.checks.append(check)

    async def run(self, target: ScanTarget) -> ScanReport:
        report = ScanReport(target=target)
        for check in self.checks:
            result = await check.run(target.url)
            report.results.append(result)
        report.risk_score = self._calculate_risk(report.results)
        return report

    @staticmethod
    def _calculate_risk(results: list[CheckResult]) -> float:
        if not results:
            return 0.0
        failed = sum(1 for r in results if not r.passed)
        return round(failed / len(results), 2)
