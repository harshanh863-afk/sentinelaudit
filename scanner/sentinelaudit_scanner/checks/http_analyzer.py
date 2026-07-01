"""Passive HTTP security analyzer.

Produces ScannerObservation objects only — no database writes, no findings.
"""

from collections.abc import Sequence

import httpx

from sentinelaudit_scanner.models.observation import ScannerObservation

SECURITY_HEADERS = {
    "strict-transport-security": "Strict-Transport-Security",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


class HTTPAnalyzer:
    """Passive HTTP security analyzer.

    Performs read-only checks: HTTPS availability, security headers,
    cookie flags, and information disclosure.
    """

    def __init__(self, timeout: int = 30):
        self._timeout = timeout

    async def analyze(self, url: str) -> list[ScannerObservation]:
        observations: list[ScannerObservation] = []

        observations.extend(await self._check_https_availability(url))
        observations.extend(await self._check_security_headers(url))
        observations.extend(await self._check_cookie_security(url))
        observations.extend(await self._check_information_disclosure(url))

        return observations

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _client(**overrides) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            timeout=overrides.get("timeout", 30),
            follow_redirects=overrides.get("follow_redirects", True),
            verify=overrides.get("verify", False),
        )

    async def _fetch(
        self, url: str, follow_redirects: bool = True, method: str = "GET"
    ) -> httpx.Response | None:
        try:
            async with self._client(follow_redirects=follow_redirects) as client:
                return await client.request(method, url)
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError):
            return None

    # ------------------------------------------------------------------
    # 1. HTTPS availability
    # ------------------------------------------------------------------

    async def _check_https_availability(self, url: str) -> Sequence[ScannerObservation]:
        """Check HTTP reachability, HTTPS reachability, and HTTP→HTTPS redirect."""
        observations: list[ScannerObservation] = []
        base = url.rstrip("/").replace("https://", "http://").replace("http://", "")
        http_url = f"http://{base}"
        https_url = f"https://{base}"

        http_resp = await self._fetch(http_url, follow_redirects=False)
        https_resp = await self._fetch(https_url, follow_redirects=False)

        http_reachable = http_resp is not None
        https_reachable = https_resp is not None
        redirects_to_https = (
            http_resp is not None
            and http_resp.status_code in (301, 302, 307, 308)
            and "https://" in (http_resp.headers.get("location", ""))
        )

        if not https_reachable:
            observations.append(ScannerObservation(
                observation_type="https_unreachable",
                target=https_url,
                severity_hint="high",
                evidence={"status_code": None},
                metadata={"check": "https_availability", "category": "http_security",
                          "description": "HTTPS is not reachable on this target",
                          "detail": "Server did not respond on HTTPS"},
            ))

        if http_reachable and not https_reachable:
            observations.append(ScannerObservation(
                observation_type="http_without_https",
                target=http_url,
                severity_hint="critical",
                evidence={"status_code": http_resp.status_code if http_resp else None},
                metadata={"check": "https_availability", "category": "http_security",
                          "description": "HTTP is available but HTTPS is not",
                          "detail": "Traffic can be intercepted in plaintext"},
            ))

        if http_reachable and not redirects_to_https:
            observations.append(ScannerObservation(
                observation_type="missing_http_to_https_redirect",
                target=http_url,
                severity_hint="medium",
                evidence={"status_code": http_resp.status_code if http_resp else None,
                          "location": http_resp.headers.get("location") if http_resp else None},
                metadata={"check": "https_availability", "category": "http_security",
                          "description": "HTTP does not redirect to HTTPS",
                          "detail": "Clients can connect over unencrypted HTTP"},
            ))

        return observations

    # ------------------------------------------------------------------
    # 2. Security headers
    # ------------------------------------------------------------------

    async def _check_security_headers(self, url: str) -> Sequence[ScannerObservation]:
        """Check for missing security headers on the HTTPS response."""
        observations: list[ScannerObservation] = []
        https_url = url if url.startswith("https://") else url.replace("http://", "https://")

        resp = await self._fetch(https_url)
        if resp is None:
            return observations

        response_headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        for lower_name, display_name in SECURITY_HEADERS.items():
            if lower_name not in response_headers_lower:
                severity = "high" if lower_name in ("content-security-policy", "x-frame-options") else "medium"
                observations.append(ScannerObservation(
                    observation_type="missing_security_header",
                    target=https_url,
                    severity_hint=severity,
                    evidence={"header": display_name, "status_code": resp.status_code},
                    metadata={"check": "security_headers", "category": "http_security",
                              "description": f"Missing {display_name} header",
                              "detail": f"The {display_name} response header was not sent"},
                ))

        return observations

    # ------------------------------------------------------------------
    # 3. Cookie security
    # ------------------------------------------------------------------

    async def _check_cookie_security(self, url: str) -> Sequence[ScannerObservation]:
        """Analyze Set-Cookie headers for missing security attributes."""
        observations: list[ScannerObservation] = []
        https_url = url if url.startswith("https://") else url.replace("http://", "https://")

        resp = await self._fetch(https_url, follow_redirects=False)
        if resp is None:
            return observations

        set_cookie_headers = resp.headers.get_list("set-cookie")
        if not set_cookie_headers:
            return observations

        for cookie_value in set_cookie_headers:
            name = cookie_value.split("=", 1)[0] if "=" in cookie_value else cookie_value

            if "secure" not in cookie_value.lower():
                observations.append(ScannerObservation(
                    observation_type="insecure_cookie",
                    target=https_url,
                    severity_hint="high",
                    evidence={"cookie_name": name, "cookie_value": cookie_value,
                              "missing_attribute": "Secure"},
                    metadata={"check": "cookie_security", "category": "http_security",
                              "description": f"Cookie '{name}' missing Secure flag",
                              "detail": "Cookie can be sent over unencrypted HTTP"},
                ))

            if "httponly" not in cookie_value.lower():
                observations.append(ScannerObservation(
                    observation_type="insecure_cookie",
                    target=https_url,
                    severity_hint="medium",
                    evidence={"cookie_name": name, "cookie_value": cookie_value,
                              "missing_attribute": "HttpOnly"},
                    metadata={"check": "cookie_security", "category": "http_security",
                              "description": f"Cookie '{name}' missing HttpOnly flag",
                              "detail": "Cookie is accessible to client-side scripts"},
                ))

            if "samesite" not in cookie_value.lower():
                observations.append(ScannerObservation(
                    observation_type="insecure_cookie",
                    target=https_url,
                    severity_hint="low",
                    evidence={"cookie_name": name, "cookie_value": cookie_value,
                              "missing_attribute": "SameSite"},
                    metadata={"check": "cookie_security", "category": "http_security",
                              "description": f"Cookie '{name}' missing SameSite attribute",
                              "detail": "Cookie may be sent in cross-site requests"},
                ))

        return observations

    # ------------------------------------------------------------------
    # 4. Information disclosure
    # ------------------------------------------------------------------

    async def _check_information_disclosure(self, url: str) -> Sequence[ScannerObservation]:
        """Detect exposed server/technology headers."""
        observations: list[ScannerObservation] = []
        https_url = url if url.startswith("https://") else url.replace("http://", "https://")

        resp = await self._fetch(https_url)
        if resp is None:
            return observations

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        if "server" in headers_lower:
            server_val = headers_lower["server"]
            if server_val and not server_val.lower() in ("", "server"):
                observations.append(ScannerObservation(
                    observation_type="server_info_disclosure",
                    target=https_url,
                    severity_hint="low",
                    evidence={"header": "Server", "value": server_val},
                    metadata={"check": "info_disclosure", "category": "http_security",
                              "description": "Server header exposes software version",
                              "detail": f"Server: {server_val}"},
                ))

        if "x-powered-by" in headers_lower:
            xpb_val = headers_lower["x-powered-by"]
            observations.append(ScannerObservation(
                observation_type="tech_info_disclosure",
                target=https_url,
                severity_hint="low",
                evidence={"header": "X-Powered-By", "value": xpb_val},
                metadata={"check": "info_disclosure", "category": "http_security",
                          "description": "X-Powered-By header exposes technology stack",
                          "detail": f"X-Powered-By: {xpb_val}"},
            ))

        return observations
