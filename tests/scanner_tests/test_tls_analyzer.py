"""Tests for the TLSAnalyzer scanner module.

Uses subclassing to mock TLS connections - no real network calls.
"""

import datetime

import pytest

from sentinelaudit_scanner.checks.tls_analyzer import TLSAnalyzer
from sentinelaudit_scanner.models.observation import ScannerObservation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cert(
    not_after: str | None = None,
    subject: tuple = ((("commonName", "example.com"),),),
    issuer: tuple = ((("organizationName", "Valid CA"),),),
    sans: list[str] | None = None,
) -> dict:
    cert = {
        "subject": subject,
        "issuer": issuer,
        "notAfter": not_after or "Jun  1 00:00:00 2099 GMT",
        "subjectAltName": tuple(("DNS", san) for san in (sans or ["example.com"])),
        "serialNumber": "1234",
    }
    return cert


def _make_connection(
    cert: dict | None = None,
    version: str = "TLSv1.3",
    cipher: tuple = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
) -> dict | None:
    if cert is None:
        return None
    return {"cert": cert, "version": version, "cipher": cipher}


def _make_analyzer(connection_result: dict | None) -> TLSAnalyzer:
    """Return a TLSAnalyzer whose _connect returns the given result."""

    class ControlledAnalyzer(TLSAnalyzer):
        async def _connect(self, hostname, port):
            return connection_result

    return ControlledAnalyzer()


# ===================================================================
# 1. Certificate expiry
# ===================================================================

class TestCertificateExpiry:
    """Certificate expiration detection."""

    @pytest.mark.asyncio
    async def test_valid_certificate_no_observations(self):
        future = "Jun  1 00:00:00 2099 GMT"
        cert = _make_cert(not_after=future)
        analyzer = _make_analyzer(_make_connection(cert=cert))
        obs = await analyzer.analyze("example.com")
        assert not any(o.observation_type == "expired_certificate" for o in obs)

    @pytest.mark.asyncio
    async def test_expired_certificate_produces_critical(self):
        past = "Jan  1 00:00:00 2020 GMT"
        cert = _make_cert(not_after=past)
        analyzer = _make_analyzer(_make_connection(cert=cert))
        obs = await analyzer.analyze("example.com")
        expired = [o for o in obs if o.observation_type == "expired_certificate"]
        assert len(expired) == 1
        assert expired[0].severity_hint == "critical"

    @pytest.mark.asyncio
    async def test_certificate_expiring_soon_produces_medium(self):
        near_future = (datetime.datetime.now(datetime.timezone.utc) +
                       datetime.timedelta(days=7)).strftime("%b %d %H:%M:%S %Y GMT")
        cert = _make_cert(not_after=near_future)
        analyzer = _make_analyzer(_make_connection(cert=cert))
        obs = await analyzer.analyze("example.com")
        expiring = [o for o in obs if o.observation_type == "certificate_expiring_soon"]
        assert len(expiring) == 1
        assert expiring[0].severity_hint == "medium"
        assert expiring[0].evidence["days_remaining"] <= 30

    @pytest.mark.asyncio
    async def test_far_future_certificate_no_expiry_warning(self):
        far = "Jun  1 00:00:00 2099 GMT"
        cert = _make_cert(not_after=far)
        analyzer = _make_analyzer(_make_connection(cert=cert))
        obs = await analyzer.analyze("example.com")
        assert not any(o.observation_type in ("expired_certificate", "certificate_expiring_soon")
                       for o in obs)


# ===================================================================
# 2. Hostname mismatch
# ===================================================================

class TestHostnameMismatch:
    """Certificate hostname validation."""

    @pytest.mark.asyncio
    async def test_matching_hostname_no_observation(self):
        cert = _make_cert(sans=["example.com"])
        analyzer = _make_analyzer(_make_connection(cert=cert))
        obs = await analyzer.analyze("example.com")
        assert not any(o.observation_type == "certificate_hostname_mismatch" for o in obs)

    @pytest.mark.asyncio
    async def test_mismatched_hostname_produces_observation(self):
        cert = _make_cert(sans=["wrong.com"],
                          subject=((("commonName", "wrong.com"),),))
        analyzer = _make_analyzer(_make_connection(cert=cert))
        obs = await analyzer.analyze("example.com")
        mismatch = [o for o in obs if o.observation_type == "certificate_hostname_mismatch"]
        assert len(mismatch) == 1
        assert mismatch[0].severity_hint == "high"

    @pytest.mark.asyncio
    async def test_wildcard_san_matches_subdomain(self):
        cert = _make_cert(sans=["*.example.com"])
        analyzer = _make_analyzer(_make_connection(cert=cert))
        obs = await analyzer.analyze("www.example.com")
        assert not any(o.observation_type == "certificate_hostname_mismatch" for o in obs)

    @pytest.mark.asyncio
    async def test_wildcard_does_not_match_wrong_domain(self):
        cert = _make_cert(sans=["*.example.com"])
        analyzer = _make_analyzer(_make_connection(cert=cert))
        obs = await analyzer.analyze("evil.com")
        assert any(o.observation_type == "certificate_hostname_mismatch" for o in obs)

    @pytest.mark.asyncio
    async def test_cn_fallback_when_no_san(self):
        cert = _make_cert(
            subject=((("commonName", "myserver.internal"),),),
            sans=[],
        )
        analyzer = _make_analyzer(_make_connection(cert=cert))
        obs = await analyzer.analyze("myserver.internal")
        assert not any(o.observation_type == "certificate_hostname_mismatch" for o in obs)

    @pytest.mark.asyncio
    async def test_cn_mismatch_when_no_san(self):
        cert = _make_cert(
            subject=((("commonName", "myserver.internal"),),),
            sans=[],
        )
        analyzer = _make_analyzer(_make_connection(cert=cert))
        obs = await analyzer.analyze("other.com")
        assert any(o.observation_type == "certificate_hostname_mismatch" for o in obs)


# ===================================================================
# 3. Self-signed certificate
# ===================================================================

class TestSelfSigned:
    """Self-signed certificate detection."""

    @pytest.mark.asyncio
    async def test_ca_signed_certificate_no_observation(self):
        cert = _make_cert(
            subject=((("commonName", "example.com"),),),
            issuer=((("organizationName", "Let's Encrypt"),),),
        )
        analyzer = _make_analyzer(_make_connection(cert=cert))
        obs = await analyzer.analyze("example.com")
        assert not any(o.observation_type == "self_signed_certificate" for o in obs)

    @pytest.mark.asyncio
    async def test_self_signed_produces_observation(self):
        same = ((("organizationName", "Self Inc"),),)
        cert = _make_cert(subject=same, issuer=same)
        analyzer = _make_analyzer(_make_connection(cert=cert))
        obs = await analyzer.analyze("example.com")
        self_signed = [o for o in obs if o.observation_type == "self_signed_certificate"]
        assert len(self_signed) == 1
        assert self_signed[0].severity_hint == "high"


# ===================================================================
# 4. Protocol version
# ===================================================================

class TestProtocolVersion:
    """Weak TLS protocol version detection."""

    @pytest.mark.asyncio
    async def test_tls_1_3_no_issue(self):
        cert = _make_cert()
        analyzer = _make_analyzer(_make_connection(cert=cert, version="TLSv1.3"))
        obs = await analyzer.analyze("example.com")
        assert not any(o.observation_type == "weak_tls_protocol" for o in obs)

    @pytest.mark.asyncio
    async def test_tls_1_2_no_issue(self):
        cert = _make_cert()
        analyzer = _make_analyzer(_make_connection(cert=cert, version="TLSv1.2"))
        obs = await analyzer.analyze("example.com")
        assert not any(o.observation_type == "weak_tls_protocol" for o in obs)

    @pytest.mark.asyncio
    async def test_tls_1_0_produces_observation(self):
        cert = _make_cert()
        analyzer = _make_analyzer(_make_connection(cert=cert, version="TLSv1.0"))
        obs = await analyzer.analyze("example.com")
        weak = [o for o in obs if o.observation_type == "weak_tls_protocol"]
        assert len(weak) == 1
        assert weak[0].severity_hint == "high"

    @pytest.mark.asyncio
    async def test_tls_1_1_produces_observation(self):
        cert = _make_cert()
        analyzer = _make_analyzer(_make_connection(cert=cert, version="TLSv1.1"))
        obs = await analyzer.analyze("example.com")
        weak = [o for o in obs if o.observation_type == "weak_tls_protocol"]
        assert len(weak) == 1
        assert weak[0].severity_hint == "high"


# ===================================================================
# 5. Cipher strength
# ===================================================================

class TestCipherStrength:
    """Weak cipher suite detection."""

    @pytest.mark.asyncio
    async def test_strong_cipher_no_issue(self):
        cert = _make_cert()
        analyzer = _make_analyzer(
            _make_connection(cert=cert, cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256))
        )
        obs = await analyzer.analyze("example.com")
        assert not any(o.observation_type == "weak_cipher_suite" for o in obs)

    @pytest.mark.asyncio
    async def test_rc4_cipher_produces_observation(self):
        cert = _make_cert()
        analyzer = _make_analyzer(
            _make_connection(cert=cert, cipher=("RC4-SHA", "TLSv1.2", 128))
        )
        obs = await analyzer.analyze("example.com")
        weak = [o for o in obs if o.observation_type == "weak_cipher_suite"]
        assert len(weak) == 1
        assert weak[0].severity_hint == "high"

    @pytest.mark.asyncio
    async def test_des_cipher_produces_observation(self):
        cert = _make_cert()
        analyzer = _make_analyzer(
            _make_connection(cert=cert, cipher=("DES-CBC3-SHA", "TLSv1.2", 112))
        )
        obs = await analyzer.analyze("example.com")
        assert any(o.observation_type == "weak_cipher_suite" for o in obs)

    @pytest.mark.asyncio
    async def test_null_cipher_produces_observation(self):
        cert = _make_cert()
        analyzer = _make_analyzer(
            _make_connection(cert=cert, cipher=("NULL-SHA", "TLSv1.2", 0))
        )
        obs = await analyzer.analyze("example.com")
        assert any(o.observation_type == "weak_cipher_suite" for o in obs)


# ===================================================================
# 6. Connection failure
# ===================================================================

class TestConnectionFailure:
    """TLS connection failure handling."""

    @pytest.mark.asyncio
    async def test_connection_failure_produces_critical(self):
        analyzer = _make_analyzer(None)
        obs = await analyzer.analyze("example.com")
        failed = [o for o in obs if o.observation_type == "connection_failed"]
        assert len(failed) == 1
        assert failed[0].severity_hint == "critical"

    @pytest.mark.asyncio
    async def test_connection_failure_returns_only_that(self):
        analyzer = _make_analyzer(None)
        obs = await analyzer.analyze("example.com")
        assert len(obs) == 1
        assert obs[0].observation_type == "connection_failed"


# ===================================================================
# 7. Structrue validation
# ===================================================================

class TestObservationStructure:
    """Verify every TLS observation carries the required fields."""

    @pytest.mark.asyncio
    async def test_all_observations_have_required_fields(self):
        cert = _make_cert(not_after="Jan  1 00:00:00 2020 GMT",
                          sans=["wrong.com"])
        analyzer = _make_analyzer(_make_connection(cert=cert, version="TLSv1.0",
                                                    cipher=("RC4-SHA", "TLSv1.0", 128)))
        obs = await analyzer.analyze("example.com")
        assert len(obs) > 0
        for o in obs:
            assert isinstance(o.observation_type, str)
            assert isinstance(o.target, str)
            assert isinstance(o.severity_hint, str)
            assert o.severity_hint in ("critical", "high", "medium", "low", "info")

    @pytest.mark.asyncio
    async def test_all_observations_have_metadata(self):
        cert = _make_cert(not_after="Jan  1 00:00:00 2020 GMT")
        analyzer = _make_analyzer(_make_connection(cert=cert))
        obs = await analyzer.analyze("example.com")
        for o in obs:
            assert o.metadata is not None
            assert "check" in o.metadata
            assert "category" in o.metadata
            assert o.metadata["category"] == "tls_analysis"
