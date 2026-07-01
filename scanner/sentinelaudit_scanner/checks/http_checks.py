from sentinelaudit_scanner.core.engine import SecurityCheck, CheckResult


class HTTPSecurityChecker(SecurityCheck):
    """Evaluates HTTP security headers and configurations."""

    name = "http_security"
    description = "Checks for missing or misconfigured HTTP security headers"

    async def run(self, target: str) -> CheckResult:
        raise NotImplementedError
