"""Tests for the DNSAnalyzer scanner module.

Uses subclassing to mock DNS queries - no real network calls.
"""

import pytest

from sentinelaudit_scanner.checks.dns_analyzer import DNSAnalyzer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_analyzer(
    txt_results: dict[str, list[str]] | None = None,
    dkim_result: bool = False,
    dnssec_result: bool = False,
    caa_result: list[str] | None = None,
) -> DNSAnalyzer:
    """Return a DNSAnalyzer whose query methods return the given results."""

    class ControlledAnalyzer(DNSAnalyzer):
        async def _query_txt(self, domain, prefix=""):
            if txt_results is not None:
                all_records = txt_results.get(domain, [])
                if prefix:
                    return [r for r in all_records if prefix.lower() in r.lower()]
                return all_records
            return []

        async def _detect_dkim(self, domain):
            return dkim_result

        async def _check_dnssec(self, domain):
            return dnssec_result

        async def _query_caa(self, domain):
            return caa_result or []

    return ControlledAnalyzer()


# ===================================================================
# 1. SPF records
# ===================================================================

class TestSPF:
    """SPF record detection."""

    @pytest.mark.asyncio
    async def test_spf_present_no_observation(self):
        analyzer = _make_analyzer(
            txt_results={"example.com": ["v=spf1 include:_spf.google.com ~all"]}
        )
        obs = await analyzer.analyze("example.com")
        assert not any(o.observation_type == "missing_spf_record" for o in obs)

    @pytest.mark.asyncio
    async def test_missing_spf_produces_observation(self):
        analyzer = _make_analyzer(txt_results={"example.com": []})
        obs = await analyzer.analyze("example.com")
        missing = [o for o in obs if o.observation_type == "missing_spf_record"]
        assert len(missing) == 1
        assert missing[0].severity_hint == "medium"


# ===================================================================
# 2. DMARC records
# ===================================================================

class TestDMARC:
    """DMARC record detection."""

    @pytest.mark.asyncio
    async def test_dmarc_present_no_observation(self):
        analyzer = _make_analyzer(
            txt_results={"_dmarc.example.com": ["v=DMARC1; p=reject; rua=mailto:reports@example.com"]}
        )
        obs = await analyzer.analyze("example.com")
        assert not any(o.observation_type == "missing_dmarc_record" for o in obs)

    @pytest.mark.asyncio
    async def test_missing_dmarc_produces_observation(self):
        analyzer = _make_analyzer(txt_results={"_dmarc.example.com": []})
        obs = await analyzer.analyze("example.com")
        missing = [o for o in obs if o.observation_type == "missing_dmarc_record"]
        assert len(missing) == 1
        assert missing[0].severity_hint == "medium"

    @pytest.mark.asyncio
    async def test_dmarc_policy_none_produces_warning(self):
        analyzer = _make_analyzer(
            txt_results={"_dmarc.example.com": ["v=DMARC1; p=none; rua=mailto:reports@example.com"]}
        )
        obs = await analyzer.analyze("example.com")
        weak = [o for o in obs if o.observation_type == "weak_dmarc_policy"]
        assert len(weak) == 1
        assert weak[0].severity_hint == "low"

    @pytest.mark.asyncio
    async def test_dmarc_policy_quarantine_no_warning(self):
        analyzer = _make_analyzer(
            txt_results={"_dmarc.example.com": ["v=DMARC1; p=quarantine;"]}
        )
        obs = await analyzer.analyze("example.com")
        assert not any(o.observation_type == "weak_dmarc_policy" for o in obs)

    @pytest.mark.asyncio
    async def test_dmarc_policy_reject_no_warning(self):
        analyzer = _make_analyzer(
            txt_results={"_dmarc.example.com": ["v=DMARC1; p=reject;"]}
        )
        obs = await analyzer.analyze("example.com")
        assert not any(o.observation_type == "weak_dmarc_policy" for o in obs)


# ===================================================================
# 3. DKIM detection
# ===================================================================

class TestDKIM:
    """DKIM record detection."""

    @pytest.mark.asyncio
    async def test_dkim_present_no_observation(self):
        analyzer = _make_analyzer(
            txt_results={"example.com": ["v=spf1 ~all"]},
            dkim_result=True,
        )
        obs = await analyzer.analyze("example.com")
        assert not any(o.observation_type == "missing_dkim_record" for o in obs)

    @pytest.mark.asyncio
    async def test_missing_dkim_produces_observation(self):
        analyzer = _make_analyzer(
            txt_results={"example.com": ["v=spf1 ~all"]},
            dkim_result=False,
        )
        obs = await analyzer.analyze("example.com")
        missing = [o for o in obs if o.observation_type == "missing_dkim_record"]
        assert len(missing) == 1
        assert missing[0].severity_hint == "low"


# ===================================================================
# 4. DNSSEC
# ===================================================================

class TestDNSSEC:
    """DNSSEC status detection."""

    @pytest.mark.asyncio
    async def test_dnssec_enabled_no_observation(self):
        analyzer = _make_analyzer(
            txt_results={"example.com": ["v=spf1 ~all"]},
            dnssec_result=True,
        )
        obs = await analyzer.analyze("example.com")
        assert not any(o.observation_type == "missing_dnssec" for o in obs)

    @pytest.mark.asyncio
    async def test_missing_dnssec_produces_observation(self):
        analyzer = _make_analyzer(
            txt_results={"example.com": ["v=spf1 ~all"]},
            dnssec_result=False,
        )
        obs = await analyzer.analyze("example.com")
        missing = [o for o in obs if o.observation_type == "missing_dnssec"]
        assert len(missing) == 1
        assert missing[0].severity_hint == "medium"


# ===================================================================
# 5. CAA records
# ===================================================================

class TestCAA:
    """CAA record detection."""

    @pytest.mark.asyncio
    async def test_caa_present_no_observation(self):
        analyzer = _make_analyzer(
            txt_results={"example.com": ["v=spf1 ~all"]},
            caa_result=["issue letsencrypt.org"],
        )
        obs = await analyzer.analyze("example.com")
        assert not any(o.observation_type == "missing_caa_record" for o in obs)

    @pytest.mark.asyncio
    async def test_missing_caa_produces_observation(self):
        analyzer = _make_analyzer(
            txt_results={"example.com": ["v=spf1 ~all"]},
            caa_result=[],
        )
        obs = await analyzer.analyze("example.com")
        missing = [o for o in obs if o.observation_type == "missing_caa_record"]
        assert len(missing) == 1
        assert missing[0].severity_hint == "low"


# ===================================================================
# 6. SPF misconfiguration
# ===================================================================

class TestSPFMisconfiguration:
    """SPF misconfiguration detection."""

    @pytest.mark.asyncio
    async def test_spf_allow_all_produces_critical(self):
        analyzer = _make_analyzer(
            txt_results={"example.com": ["v=spf1 +all"]}
        )
        obs = await analyzer.analyze("example.com")
        assert any(o.observation_type == "spf_allow_all" for o in obs)
        allow_all = [o for o in obs if o.observation_type == "spf_allow_all"]
        assert len(allow_all) == 1
        assert allow_all[0].severity_hint == "critical"

    @pytest.mark.asyncio
    async def test_spf_neutral_produces_medium(self):
        analyzer = _make_analyzer(
            txt_results={"example.com": ["v=spf1 include:_spf.google.com ?all"]}
        )
        obs = await analyzer.analyze("example.com")
        neutral = [o for o in obs if o.observation_type == "spf_neutral"]
        assert len(neutral) == 1
        assert neutral[0].severity_hint == "medium"

    @pytest.mark.asyncio
    async def test_spf_excessive_lookups_produces_medium(self):
        includes = " ".join(f"include:_spf{i}.com" for i in range(12))
        spf = f"v=spf1 {includes} ~all"
        analyzer = _make_analyzer(
            txt_results={"example.com": [spf]}
        )
        obs = await analyzer.analyze("example.com")
        excessive = [o for o in obs if o.observation_type == "spf_excessive_lookups"]
        assert len(excessive) == 1
        assert excessive[0].severity_hint == "medium"
        assert excessive[0].evidence["lookup_count"] > 10

    @pytest.mark.asyncio
    async def test_spf_missing_hardfail_produces_low(self):
        analyzer = _make_analyzer(
            txt_results={"example.com": ["v=spf1 include:_spf.google.com ~all"]}
        )
        obs = await analyzer.analyze("example.com")
        no_hardfail = [o for o in obs if o.observation_type == "spf_no_hardfail"]
        assert len(no_hardfail) == 1
        assert no_hardfail[0].severity_hint == "low"

    @pytest.mark.asyncio
    async def test_spf_with_hardfail_no_misconfig_warnings(self):
        analyzer = _make_analyzer(
            txt_results={"example.com": ["v=spf1 include:_spf.google.com -all"]}
        )
        obs = await analyzer.analyze("example.com")
        misconfigs = [o for o in obs if o.observation_type.startswith("spf_")]
        assert not any(
            o.observation_type
            in ("spf_allow_all", "spf_neutral", "spf_excessive_lookups", "spf_no_hardfail")
            for o in misconfigs
        )


# ===================================================================
# 7. Fully secure domain
# ===================================================================

class TestSecureDomain:
    """A well-configured domain should produce zero observations."""

    @pytest.mark.asyncio
    async def test_fully_secure_domain_no_observations(self):
        analyzer = _make_analyzer(
            txt_results={
                "secure.com": ["v=spf1 include:_spf.google.com -all"],
                "_dmarc.secure.com": ["v=DMARC1; p=reject; rua=mailto:reports@secure.com"],
            },
            dkim_result=True,
            dnssec_result=True,
            caa_result=["issue letsencrypt.org"],
        )
        obs = await analyzer.analyze("secure.com")
        assert len(obs) == 0


# ===================================================================
# 8. Structure validation
# ===================================================================

class TestObservationStructure:
    """Verify every DNS observation carries the required fields."""

    @pytest.mark.asyncio
    async def test_all_observations_have_required_fields(self):
        analyzer = _make_analyzer(txt_results={}, dkim_result=False, dnssec_result=False, caa_result=[])
        obs = await analyzer.analyze("example.com")
        assert len(obs) > 0
        for o in obs:
            assert isinstance(o.observation_type, str)
            assert isinstance(o.target, str)
            assert isinstance(o.severity_hint, str)
            assert o.severity_hint in ("critical", "high", "medium", "low", "info")

    @pytest.mark.asyncio
    async def test_all_observations_have_metadata(self):
        analyzer = _make_analyzer(txt_results={})
        obs = await analyzer.analyze("example.com")
        for o in obs:
            assert o.metadata is not None
            assert "check" in o.metadata
            assert "category" in o.metadata
            assert o.metadata["category"] == "dns_analysis"
