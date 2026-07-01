"""Tests for the TechFingerprinter scanner module.

Uses httpx.MockTransport to simulate HTTP responses without network calls.
"""

import httpx
import pytest

from sentinelaudit_scanner.checks.technology_fingerprint import TechFingerprinter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _response(status_code=200, headers=None, body="", set_cookie=None):
    raw: list[tuple[str, str]] = []
    if headers:
        raw.extend((k, str(v)) for k, v in headers.items())
    if set_cookie:
        raw.extend(("set-cookie", c) for c in set_cookie)
    return httpx.Response(status_code=status_code, headers=raw, text=body)


def _make_fingerprinter(handler) -> TechFingerprinter:
    """Return a TechFingerprinter whose _fetch uses the given handler."""

    class ControlledFingerprinter(TechFingerprinter):
        async def _fetch(self, url, follow_redirects=True):
            async with httpx.AsyncClient(
                transport=httpx.MockTransport(handler),
                follow_redirects=follow_redirects,
            ) as client:
                try:
                    return await client.get(url)
                except httpx.ConnectError:
                    return None

    return ControlledFingerprinter()


# ===================================================================
# 1. Server detection
# ===================================================================

class TestServerDetection:
    @pytest.mark.asyncio
    async def test_nginx_detected(self):
        def handler(request):
            return _response(200, headers={"Server": "nginx/1.20.1"})

        fp = _make_fingerprinter(handler)
        obs = await fp.fingerprint("https://example.com")
        techs = [o.evidence["technology"] for o in obs]
        assert "nginx" in techs

    @pytest.mark.asyncio
    async def test_apache_detected(self):
        def handler(request):
            return _response(200, headers={"Server": "Apache/2.4.49"})

        fp = _make_fingerprinter(handler)
        obs = await fp.fingerprint("https://example.com")
        techs = [o.evidence["technology"] for o in obs]
        assert "Apache" in techs

    @pytest.mark.asyncio
    async def test_iis_detected(self):
        def handler(request):
            return _response(200, headers={"Server": "Microsoft-IIS/10.0"})

        fp = _make_fingerprinter(handler)
        obs = await fp.fingerprint("https://example.com")
        techs = [o.evidence["technology"] for o in obs]
        assert "IIS" in techs

    @pytest.mark.asyncio
    async def test_no_server_header_no_detection(self):
        def handler(request):
            return _response(200)

        fp = _make_fingerprinter(handler)
        obs = await fp.fingerprint("https://example.com")
        assert len(obs) == 0


# ===================================================================
# 2. Framework detection (HTML patterns)
# ===================================================================

class TestFrameworkDetectionHTML:
    @pytest.mark.asyncio
    async def test_wordpress_detected(self):
        def handler(request):
            return _response(200, body='<meta name="generator" content="WordPress 6.4" />')

        fp = _make_fingerprinter(handler)
        obs = await fp.fingerprint("https://example.com")
        techs = [o.evidence["technology"] for o in obs]
        assert "WordPress" in techs

    @pytest.mark.asyncio
    async def test_react_detected(self):
        def handler(request):
            return _response(200, body='<div id="root" data-reactroot=""></div>')

        fp = _make_fingerprinter(handler)
        obs = await fp.fingerprint("https://example.com")
        techs = [o.evidence["technology"] for o in obs]
        assert "React" in techs

    @pytest.mark.asyncio
    async def test_angular_detected(self):
        def handler(request):
            return _response(200, body='<app-root ng-version="17.0.0"></app-root>')

        fp = _make_fingerprinter(handler)
        obs = await fp.fingerprint("https://example.com")
        techs = [o.evidence["technology"] for o in obs]
        assert "Angular" in techs

    @pytest.mark.asyncio
    async def test_django_detected(self):
        def handler(request):
            return _response(200, body='<input name="csrfmiddlewaretoken" value="abc">')

        fp = _make_fingerprinter(handler)
        obs = await fp.fingerprint("https://example.com")
        techs = [o.evidence["technology"] for o in obs]
        assert "Django" in techs

    @pytest.mark.asyncio
    async def test_nextjs_detected(self):
        def handler(request):
            return _response(200, body='<script>__NEXT_DATA__ = {}</script>')

        fp = _make_fingerprinter(handler)
        obs = await fp.fingerprint("https://example.com")
        techs = [o.evidence["technology"] for o in obs]
        assert "Next.js" in techs


# ===================================================================
# 3. Cookie-based detection
# ===================================================================

class TestCookieDetection:
    @pytest.mark.asyncio
    async def test_php_detected_via_cookie(self):
        def handler(request):
            return _response(200, set_cookie=["PHPSESSID=abc123"])

        fp = _make_fingerprinter(handler)
        obs = await fp.fingerprint("https://example.com")
        techs = [o.evidence["technology"] for o in obs]
        assert "PHP" in techs

    @pytest.mark.asyncio
    async def test_laravel_detected_via_cookie(self):
        def handler(request):
            return _response(200, set_cookie=["laravel_session=xyz"])

        fp = _make_fingerprinter(handler)
        obs = await fp.fingerprint("https://example.com")
        techs = [o.evidence["technology"] for o in obs]
        assert "Laravel" in techs

    @pytest.mark.asyncio
    async def test_wordpress_detected_via_cookie(self):
        def handler(request):
            return _response(200, set_cookie=["wordpress_logged_in_hash=abc"])

        fp = _make_fingerprinter(handler)
        obs = await fp.fingerprint("https://example.com")
        techs = [o.evidence["technology"] for o in obs]
        assert "WordPress" in techs


# ===================================================================
# 4. Infrastructure detection
# ===================================================================

class TestInfrastructureDetection:
    @pytest.mark.asyncio
    async def test_cloudflare_detected_via_cf_ray(self):
        def handler(request):
            return _response(200, headers={"cf-ray": "abc123", "Server": "cloudflare"})

        fp = _make_fingerprinter(handler)
        obs = await fp.fingerprint("https://example.com")
        techs = [o.evidence["technology"] for o in obs]
        assert "Cloudflare" in techs

    @pytest.mark.asyncio
    async def test_aws_cloudfront_detected(self):
        def handler(request):
            return _response(200, headers={"x-amz-cf-id": "abc123"})

        fp = _make_fingerprinter(handler)
        obs = await fp.fingerprint("https://example.com")
        techs = [o.evidence["technology"] for o in obs]
        assert "AWS CloudFront" in techs


# ===================================================================
# 5. X-Powered-By detection
# ===================================================================

class TestXPoweredByDetection:
    @pytest.mark.asyncio
    async def test_php_detected_via_xpowered(self):
        def handler(request):
            return _response(200, headers={"X-Powered-By": "PHP/8.1.0"})

        fp = _make_fingerprinter(handler)
        obs = await fp.fingerprint("https://example.com")
        techs = [o.evidence["technology"] for o in obs]
        assert "PHP" in techs

    @pytest.mark.asyncio
    async def test_aspnet_detected_via_xpowered(self):
        def handler(request):
            return _response(200, headers={"X-Powered-By": "ASP.NET"})

        fp = _make_fingerprinter(handler)
        obs = await fp.fingerprint("https://example.com")
        techs = [o.evidence["technology"] for o in obs]
        assert "ASP.NET" in techs


# ===================================================================
# 6. Multiple technologies
# ===================================================================

class TestMultipleTechnologies:
    @pytest.mark.asyncio
    async def test_multiple_techs_detected(self):
        def handler(request):
            return _response(
                200,
                headers={
                    "Server": "nginx/1.20",
                    "X-Powered-By": "PHP/8.1",
                    "cf-ray": "abc",
                },
                body='<meta name="generator" content="WordPress 6.4" />',
            )

        fp = _make_fingerprinter(handler)
        obs = await fp.fingerprint("https://example.com")
        techs = [o.evidence["technology"] for o in obs]
        assert "nginx" in techs
        assert "PHP" in techs
        assert "Cloudflare" in techs
        assert "WordPress" in techs

    @pytest.mark.asyncio
    async def test_connection_failure_returns_empty(self):
        def handler(request):
            raise httpx.ConnectError("refused")

        fp = _make_fingerprinter(handler)
        obs = await fp.fingerprint("https://example.com")
        assert len(obs) == 0


# ===================================================================
# 7. Structure validation
# ===================================================================

class TestObservationStructure:
    @pytest.mark.asyncio
    async def test_all_observations_have_required_fields(self):
        def handler(request):
            return _response(200, headers={"Server": "nginx/1.20"})

        fp = _make_fingerprinter(handler)
        obs = await fp.fingerprint("https://example.com")
        for o in obs:
            assert isinstance(o.observation_type, str)
            assert isinstance(o.target, str)
            assert isinstance(o.severity_hint, str)
            assert o.severity_hint in ("critical", "high", "medium", "low", "info")
            assert o.metadata is not None
            assert "check" in o.metadata
            assert "category" in o.metadata
            assert o.metadata["check"] == "technology_fingerprint"
