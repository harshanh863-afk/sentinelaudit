"""Tests for backend security hardening — headers, CORS, SSRF, rate limiting, request protection, health."""

import os
import sys

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.services.public_scan.url_validator import URLValidator, URLValidationError


# ── Security Headers ──────────────────────────────────────────────

class TestSecurityHeaders:
    """All responses must include OWASP-recommended security headers."""

    async def test_strict_transport_security_header(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health")
        hsts = response.headers.get("strict-transport-security", "")
        assert "max-age=31536000" in hsts
        assert "includeSubDomains" in hsts
        assert "preload" in hsts

    async def test_x_content_type_options_header(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health")
        assert response.headers.get("x-content-type-options") == "nosniff"

    async def test_x_frame_options_header(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health")
        assert response.headers.get("x-frame-options") == "DENY"

    async def test_referrer_policy_header(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health")
        assert response.headers.get("referrer-policy") == "strict-origin-when-cross-origin"

    async def test_permissions_policy_header(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health")
        policy = response.headers.get("permissions-policy", "")
        assert "camera=()" in policy
        assert "microphone=()" in policy
        assert "geolocation=()" in policy

    async def test_cache_control_header(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health")
        assert "no-store" in response.headers.get("cache-control", "")

    async def test_content_security_policy_header(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health")
        csp = response.headers.get("content-security-policy", "")
        assert "default-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp

    async def test_all_headers_present_on_error_response(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/nonexistent-route-xyz")
        assert response.status_code == 404
        assert "strict-transport-security" in response.headers
        assert "x-content-type-options" in response.headers
        assert "x-frame-options" in response.headers


# ── CORS ──────────────────────────────────────────────────────────

class TestCORS:
    """CORS must be restrictive in production, open in development."""

    async def test_cors_development_allows_any_origin(self):
        from app.core.environment import env_config
        if env_config.is_production:
            pytest.skip("This test only runs in development mode")
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.options(
                "/health",
                headers={
                    "Origin": "http://evil-site.com",
                    "Access-Control-Request-Method": "GET",
                },
            )
        allowed = response.headers.get("access-control-allow-origin", "")
        assert allowed is not None, "CORS origin header must be present"
        assert "*" in allowed or allowed == "http://evil-site.com"

    async def test_cors_allows_frontend_origin(self):
        from app.core.environment import env_config
        transport = ASGITransport(app=app)
        origin = env_config.FRONTEND_URL
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.options(
                "/health",
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET",
                },
            )
        allowed = response.headers.get("access-control-allow-origin", "")
        assert allowed is not None, "CORS origin header must be present"
        assert allowed == origin or allowed == "*"
        if env_config.is_production:
            assert "origin" in response.headers.get("vary", "").lower()

    async def test_cors_headers_include_credentials(self):
        from app.core.environment import env_config
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.options(
                "/health",
                headers={
                    "Origin": "http://localhost:5173",
                    "Access-Control-Request-Method": "GET",
                },
            )
        if env_config.is_production:
            assert response.headers.get("access-control-allow-credentials") == "true"
        else:
            assert response.headers.get("access-control-allow-credentials") is None
        methods = response.headers.get("access-control-allow-methods", "")
        assert "GET" in methods
        assert "POST" in methods
        headers_list = response.headers.get("access-control-allow-headers", "")
        assert headers_list is not None


# ── SSRF / URL Validation ─────────────────────────────────────────

class TestSSRFProtection:
    """URL validator must block SSRF-vulnerable targets."""

    def test_rejects_non_https(self):
        with pytest.raises(URLValidationError, match="Only HTTPS URLs are allowed"):
            URLValidator.validate("http://example.com")

    def test_rejects_localhost(self):
        with pytest.raises(URLValidationError):
            URLValidator.validate("https://localhost")

    def test_rejects_127_dot_0_dot_0_dot_1(self):
        with pytest.raises(URLValidationError):
            URLValidator.validate("https://127.0.0.1")

    def test_rejects_0_dot_0_dot_0_dot_0(self):
        with pytest.raises(URLValidationError):
            URLValidator.validate("https://0.0.0.0")

    def test_rejects_private_10_network(self):
        with pytest.raises(URLValidationError):
            URLValidator.validate("https://10.0.0.1")

    def test_rejects_private_172_16(self):
        with pytest.raises(URLValidationError):
            URLValidator.validate("https://172.16.0.1")

    def test_rejects_private_192_168(self):
        with pytest.raises(URLValidationError):
            URLValidator.validate("https://192.168.1.1")

    def test_rejects_cloud_metadata_ip(self):
        with pytest.raises(URLValidationError):
            URLValidator.validate("https://169.254.169.254")

    def test_rejects_cloud_metadata_ip_100_x(self):
        with pytest.raises(URLValidationError):
            URLValidator.validate("https://100.100.100.200")

    def test_rejects_ipv6_loopback(self):
        with pytest.raises(URLValidationError):
            URLValidator.validate("https://[::1]")

    def test_rejects_ipv6_unique_local(self):
        with pytest.raises(URLValidationError):
            URLValidator.validate("https://[fc00::1]")

    def test_rejects_ipv6_link_local(self):
        with pytest.raises(URLValidationError):
            URLValidator.validate("https://[fe80::1]")

    def test_rejects_domain_with_internal_suffix(self):
        with pytest.raises(URLValidationError, match="Internal hostname"):
            URLValidator.validate("https://app.internal")

    def test_rejects_domain_with_local_suffix(self):
        with pytest.raises(URLValidationError, match="Internal hostname"):
            URLValidator.validate("https://service.local")

    def test_rejects_reserved_tld_test(self):
        with pytest.raises(URLValidationError, match="Reserved TLD"):
            URLValidator.validate("https://example.test")

    def test_rejects_reserved_tld_example(self):
        with pytest.raises(URLValidationError, match="Reserved TLD"):
            URLValidator.validate("https://something.example")

    def test_rejects_internal_hostname_suffix(self):
        with pytest.raises(URLValidationError, match="Internal hostname"):
            URLValidator.validate("https://my-service.internal")

    def test_rejects_local_hostname_suffix(self):
        with pytest.raises(URLValidationError, match="Internal hostname"):
            URLValidator.validate("https://my-service.local")

    def test_rejects_consul_hostname(self):
        with pytest.raises(URLValidationError, match="Internal hostname"):
            URLValidator.validate("https://consul.service.consul")

    def test_rejects_metadata_google_hostname(self):
        with pytest.raises(URLValidationError):
            URLValidator.validate("https://metadata.google.internal")

    def test_accepts_valid_https_url(self):
        result = URLValidator.validate("https://example.com")
        assert result == "https://example.com"

    def test_accepts_valid_https_with_path(self):
        result = URLValidator.validate("https://example.com/path/to/page")
        assert result == "https://example.com/path/to/page"

    def test_accepts_subdomain(self):
        result = URLValidator.validate("https://www.example.com")
        assert result == "https://www.example.com"

    def test_redirect_validation_blocks_bad_target(self):
        assert URLValidator.validate_redirect_url("https://169.254.169.254") is False

    def test_redirect_validation_accepts_safe_target(self):
        assert URLValidator.validate_redirect_url("https://example.com") is True

    def test_max_redirect_chain_is_5(self):
        assert URLValidator.get_max_redirect_chain() == 5

    def test_rejects_empty_url(self):
        with pytest.raises(URLValidationError):
            URLValidator.validate("")

    def test_rejects_malformed_url(self):
        with pytest.raises(URLValidationError):
            URLValidator.validate("not-a-url")


# ── Request Protection ────────────────────────────────────────────

class TestRequestProtection:
    """Public endpoints must reject oversized payloads."""

    async def test_rejects_large_post_payload(self):
        transport = ASGITransport(app=app)
        large_data = "x" * (1024 * 101)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/api/v1/public/scan",
                json={"url": large_data},
            )
        assert response.status_code in (413, 422)

    async def test_accepts_normal_post_payload(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/api/v1/public/scan",
                json={"url": "https://example.com"},
            )
        assert response.status_code in (200, 201, 400, 422, 429)

    async def test_get_requests_not_size_limited(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health")
        assert response.status_code == 200


# ── Health Endpoints ──────────────────────────────────────────────

class TestHealthEndpoints:
    """Health endpoints must return correct statuses."""

    async def test_health_returns_healthy(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "timestamp" in data

    async def test_health_database_returns_status(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health/database")
        assert response.status_code in (200, 503)
        data = response.json()
        assert "detail" in data or "status" in data

    async def test_health_worker_returns_status(self):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.get("/health/worker")
        assert response.status_code in (200, 503)
        data = response.json()
        assert "status" in data
        assert "service" in data
