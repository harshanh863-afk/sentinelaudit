from sentinelaudit_scanner.core.engine import SecurityCheck, CheckResult


class TechFingerprinter(SecurityCheck):
    """Identifies web technologies and their versions from HTTP responses."""

    name = "tech_fingerprint"
    description = "Identifies web frameworks, libraries, and server software"

    async def run(self, target: str) -> CheckResult:
        raise NotImplementedError
