"""Tests for the HTTPAnalyzer scanner module.

Uses httpx.MockTransport to simulate HTTP responses without network calls.
"""

from unittest.mock import ANY

import httpx
import pytest

from sentinelaudit_scanner.checks.http_analyzer import HTTPAnalyzer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _response(status_code=200, headers=None, body="", set_cookie=None, location=None):
    raw: list[tuple[str, str]] = []
    if headers:
        raw.extend((k, str(v)) for k, v in headers.items())
    if set_cookie:
        raw.extend(("set-cookie", c) for c in set_cookie)
    if location:
        raw.append(("location", location))
    return httpx.Response(status_code=status_code, headers=raw, text=body)


def _make_analyzer(handler) -> HTTPAnalyzer:
    """Return an HTTPAnalyzer whose _fetch uses the given handler."""

    class ControlledAnalyzer(HTTPAnalyzer):
        async def _fetch(self, url, follow_redirects=True, method="GET"):
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handler),
                follow_redirects=follow_redirects,
            ) as client:
                try:
                    return await client.request(method, url)
                except httpx.ConnectError:
                    return None

    return ControlledAnalyzer()


# ===================================================================
# 1. HTTPS availability
# ===================================================================

class TestHTTPSAvailability:
    """HTTP→HTTPS redirect and reachability checks."""

    @pytest.mark.asyncio
    async def test_http_redirects_to_https_no_issues(self):
        def handler(request):
            if request.url.scheme == "http":
                return _response(301, location="https://example.com/")
            return _response(200, headers={"Server": "nginx/1.20"})

        analyzer = _make_analyzer(handler)
        obs = await analyzer.analyze("https://example.com")
        https_issues = [o for o in obs if o.observation_type in (
            "https_unreachable", "http_without_https", "missing_http_to_https_redirect")]
        assert len(https_issues) == 0

    @pytest.mark.asyncio
    async def test_https_unreachable(self):
        def handler(request):
            if request.url.scheme == "https":
                raise httpx.ConnectError("Connection refused")
            return _response(200)

        analyzer = _make_analyzer(handler)
        obs = await analyzer.analyze("https://example.com")
        types = {o.observation_type for o in obs}
        assert "https_unreachable" in types
        assert "http_without_https" in types

    @pytest.mark.asyncio
    async def test_http_no_redirect_to_https(self):
        def handler(request):
            if request.url.scheme == "http":
                return _response(200)
            return _response(200)

        analyzer = _make_analyzer(handler)
        obs = await analyzer.analyze("https://example.com")
        assert any(o.observation_type == "missing_http_to_https_redirect" for o in obs)

    @pytest.mark.asyncio
    async def test_both_unreachable_reports_https_unreachable(self):
        def handler(request):
            raise httpx.ConnectError("All down")

        analyzer = _make_analyzer(handler)
        obs = await analyzer.analyze("https://example.com")
        assert any(o.observation_type == "https_unreachable" for o in obs)


# ===================================================================
# 2. Security headers
# ===================================================================

class TestSecurityHeaders:
    """Missing security header detection."""

    @pytest.mark.asyncio
    async def test_missing_csp_produces_observation(self):
        def handler(request):
            return _response(200, headers={"server": "apache"})

        analyzer = _make_analyzer(handler)
        obs = await analyzer.analyze("https://example.com")
        missing = [o for o in obs if o.observation_type == "missing_security_header"]
        assert any("Content-Security-Policy" in str(o.evidence) for o in missing)

    @pytest.mark.asyncio
    async def test_missing_hsts_produces_observation(self):
        def handler(request):
            return _response(200)

        analyzer = _make_analyzer(handler)
        obs = await analyzer.analyze("https://example.com")
        missing = [o for o in obs if o.observation_type == "missing_security_header"]
        assert any("Strict-Transport-Security" in str(o.evidence) for o in missing)

    @pytest.mark.asyncio
    async def test_all_headers_present_no_observations(self):
        def handler(request):
            return _response(200, headers={
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "referrer-policy": "strict-origin-when-cross-origin",
                "permissions-policy": "geolocation=()",
            })

        analyzer = _make_analyzer(handler)
        obs = await analyzer.analyze("https://example.com")
        missing = [o for o in obs if o.observation_type == "missing_security_header"]
        assert len(missing) == 0

    @pytest.mark.asyncio
    async def test_partial_headers_detects_only_missing(self):
        def handler(request):
            return _response(200, headers={
                "strict-transport-security": "max-age=31536000",
                "x-content-type-options": "nosniff",
            })

        analyzer = _make_analyzer(handler)
        obs = await analyzer.analyze("https://example.com")
        missing = [o for o in obs if o.observation_type == "missing_security_header"]
        missing_names = {o.evidence["header"] for o in missing}
        assert "Strict-Transport-Security" not in missing_names
        assert "X-Content-Type-Options" not in missing_names
        assert "Content-Security-Policy" in missing_names
        assert "X-Frame-Options" in missing_names

    @pytest.mark.asyncio
    async def test_https_unreachable_skips_header_checks(self):
        def handler(request):
            if request.url.scheme == "https":
                raise httpx.ConnectError("refused")
            return _response(200)

        analyzer = _make_analyzer(handler)
        obs = await analyzer.analyze("https://example.com")
        missing = [o for o in obs if o.observation_type == "missing_security_header"]
        assert len(missing) == 0


# ===================================================================
# 3. Cookie security
# ===================================================================

class TestCookieSecurity:
    """Insecure cookie attribute detection."""

    @pytest.mark.asyncio
    async def test_insecure_cookie_missing_secure_flag(self):
        def handler(request):
            return _response(200, set_cookie=["session_id=abc123"])

        analyzer = _make_analyzer(handler)
        obs = await analyzer.analyze("https://example.com")
        cookie_obs = [o for o in obs if o.observation_type == "insecure_cookie"]
        assert any("Secure" in str(o.evidence) for o in cookie_obs)

    @pytest.mark.asyncio
    async def test_insecure_cookie_missing_httponly(self):
        def handler(request):
            return _response(200, set_cookie=["token=xyz; Secure"])

        analyzer = _make_analyzer(handler)
        obs = await analyzer.analyze("https://example.com")
        cookie_obs = [o for o in obs if o.observation_type == "insecure_cookie"]
        assert any("HttpOnly" in str(o.evidence) for o in cookie_obs)

    @pytest.mark.asyncio
    async def test_insecure_cookie_missing_samesite(self):
        def handler(request):
            return _response(200, set_cookie=["id=42; Secure; HttpOnly"])

        analyzer = _make_analyzer(handler)
        obs = await analyzer.analyze("https://example.com")
        cookie_obs = [o for o in obs if o.observation_type == "insecure_cookie"]
        assert any("SameSite" in str(o.evidence) for o in cookie_obs)

    @pytest.mark.asyncio
    async def test_secure_cookie_no_observations(self):
        def handler(request):
            return _response(200, set_cookie=[
                "session=abc; Secure; HttpOnly; SameSite=Lax"
            ])

        analyzer = _make_analyzer(handler)
        obs = await analyzer.analyze("https://example.com")
        cookie_obs = [o for o in obs if o.observation_type == "insecure_cookie"]
        assert len(cookie_obs) == 0

    @pytest.mark.asyncio
    async def test_no_cookies_no_observations(self):
        def handler(request):
            return _response(200)

        analyzer = _make_analyzer(handler)
        obs = await analyzer.analyze("https://example.com")
        cookie_obs = [o for o in obs if o.observation_type == "insecure_cookie"]
        assert len(cookie_obs) == 0

    @pytest.mark.asyncio
    async def test_multiple_cookies_all_flagged(self):
        def handler(request):
            return _response(200, set_cookie=[
                "a=1", "b=2; Secure", "c=3; Secure; HttpOnly",
            ])

        analyzer = _make_analyzer(handler)
        obs = await analyzer.analyze("https://example.com")
        cookie_obs = [o for o in obs if o.observation_type == "insecure_cookie"]
        assert len(cookie_obs) >= 3


# ===================================================================
# 4. Information disclosure
# ===================================================================

class TestInformationDisclosure:
    """Server and technology header exposure."""

    @pytest.mark.asyncio
    async def test_server_header_exposure_produces_observation(self):
        def handler(request):
            return _response(200, headers={"Server": "Apache/2.4.49"})

        analyzer = _make_analyzer(handler)
        obs = await analyzer.analyze("https://example.com")
        assert any(o.observation_type == "server_info_disclosure" for o in obs)

    @pytest.mark.asyncio
    async def test_xpowered_by_exposure_produces_observation(self):
        def handler(request):
            return _response(200, headers={"X-Powered-By": "PHP/8.1"})

        analyzer = _make_analyzer(handler)
        obs = await analyzer.analyze("https://example.com")
        assert any(o.observation_type == "tech_info_disclosure" for o in obs)

    @pytest.mark.asyncio
    async def test_no_disclosure_headers_no_observations(self):
        def handler(request):
            return _response(200)

        analyzer = _make_analyzer(handler)
        obs = await analyzer.analyze("https://example.com")
        disclosure = [o for o in obs if o.observation_type in (
            "server_info_disclosure", "tech_info_disclosure")]
        assert len(disclosure) == 0


# ===================================================================
# 5. Secure website — no false positives
# ===================================================================

class TestSecureWebsite:
    """A well-configured site should produce zero observations."""

    @pytest.mark.asyncio
    async def test_secure_site_no_observations(self):
        def handler(request):
            if request.url.scheme == "http":
                return _response(301, location="https://example.com/")
            return _response(200, headers={
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "content-security-policy": "default-src 'self'",
                "x-frame-options": "DENY",
                "x-content-type-options": "nosniff",
                "referrer-policy": "strict-origin-when-cross-origin",
                "permissions-policy": "geolocation=()",
            }, set_cookie=["session=abc; Secure; HttpOnly; SameSite=Lax"])

        analyzer = _make_analyzer(handler)
        obs = await analyzer.analyze("https://example.com")
        assert len(obs) == 0


# ===================================================================
# 6. ScannerObservation structure validation
# ===================================================================

class TestObservationStructure:
    """Verify every observation carries the required fields."""

    @pytest.mark.asyncio
    async def test_all_observations_have_required_fields(self):
        def handler(request):
            return _response(200, headers={"Server": "Apache"},
                            set_cookie=["id=1"])

        analyzer = _make_analyzer(handler)
        obs = await analyzer.analyze("https://example.com")
        for o in obs:
            assert isinstance(o.observation_type, str), f"Missing type in {o}"
            assert isinstance(o.target, str), f"Missing target in {o}"
            assert isinstance(o.severity_hint, str), f"Missing severity in {o}"
            assert o.severity_hint in ("critical", "high", "medium", "low", "info")

    @pytest.mark.asyncio
    async def test_evidence_contains_raw_data(self):
        def handler(request):
            return _response(200, headers={"Server": "nginx/1.21"})

        analyzer = _make_analyzer(handler)
        obs = await analyzer.analyze("https://example.com")
        disc = [o for o in obs if o.observation_type == "server_info_disclosure"]
        if disc:
            assert "header" in disc[0].evidence
            assert "value" in disc[0].evidence

    @pytest.mark.asyncio
    async def test_metadata_contains_check_and_category(self):
        def handler(request):
            return _response(200)

        analyzer = _make_analyzer(handler)
        obs = await analyzer.analyze("https://example.com")
        for o in obs:
            assert o.metadata is not None
            assert "check" in o.metadata
            assert "category" in o.metadata
            assert "description" in o.metadata
