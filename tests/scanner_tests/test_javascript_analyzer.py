"""Tests for the JavaScriptAnalyzer scanner module.

Uses subclassing to mock HTTP responses - no real network calls.
"""

import httpx
import pytest

from sentinelaudit_scanner.checks.javascript_analyzer import JavaScriptAnalyzer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _response(status_code=200, headers=None, body=""):
    raw: list[tuple[str, str]] = []
    if headers:
        raw.extend((k, str(v)) for k, v in headers.items())
    return httpx.Response(status_code=status_code, headers=raw, text=body)


def _make_analyzer(responses: dict[str, httpx.Response]) -> JavaScriptAnalyzer:
    """Return a JavaScriptAnalyzer whose _fetch returns the given responses.

    Map URL -> httpx.Response. URLs not in the map return None.
    """

    class ControlledAnalyzer(JavaScriptAnalyzer):
        async def _fetch(self, url):
            return responses.get(url)

    return ControlledAnalyzer()


# ===================================================================
# 1. JS asset discovery
# ===================================================================

class TestJSAssetDiscovery:
    @pytest.mark.asyncio
    async def test_discovers_external_scripts(self):
        html = """<html><head>
<script src="/js/app.js"></script>
<script src="https://cdn.example.com/lib.js"></script>
</head></html>"""
        main_resp = _response(200, body=html)
        analyzer = _make_analyzer({
            "https://example.com": main_resp,
        })
        obs = await analyzer.analyze("https://example.com")
        assets = [o for o in obs if o.observation_type == "javascript_asset_discovered"]
        assert len(assets) == 2
        urls = [o.evidence["url"] for o in assets]
        assert "https://example.com/js/app.js" in urls
        assert "https://cdn.example.com/lib.js" in urls

    @pytest.mark.asyncio
    async def test_no_scripts_no_observations(self):
        html = "<html><body><p>No scripts here</p></body></html>"
        main_resp = _response(200, body=html)
        analyzer = _make_analyzer({"https://example.com": main_resp})
        obs = await analyzer.analyze("https://example.com")
        assets = [o for o in obs if o.observation_type == "javascript_asset_discovered"]
        assert len(assets) == 0


# ===================================================================
# 2. Source map detection
# ===================================================================

class TestSourceMapDetection:
    @pytest.mark.asyncio
    async def test_source_map_detected_in_external_js(self):
        html = '<html><script src="/js/app.js"></script></html>'
        js_body = 'var x = 1;\n//# sourceMappingURL=app.js.map\n'
        analyzer = _make_analyzer({
            "https://example.com": _response(200, body=html),
            "https://example.com/js/app.js": _response(200, body=js_body),
        })
        obs = await analyzer.analyze("https://example.com")
        maps = [o for o in obs if o.observation_type == "exposed_source_map"]
        assert len(maps) >= 1
        assert "app.js.map" in maps[0].evidence["source_map_url"]

    @pytest.mark.asyncio
    async def test_source_map_detected_inline(self):
        html = '<html><script>\n//# sourceMappingURL=inline.map.js\n</script></html>'
        analyzer = _make_analyzer({
            "https://example.com": _response(200, body=html),
        })
        obs = await analyzer.analyze("https://example.com")
        maps = [o for o in obs if o.observation_type == "exposed_source_map"]
        assert len(maps) == 1

    @pytest.mark.asyncio
    async def test_no_source_map_no_observation(self):
        html = '<html><script src="/js/app.js"></script></html>'
        analyzer = _make_analyzer({
            "https://example.com": _response(200, body=html),
            "https://example.com/js/app.js": _response(200, body="var x = 1;"),
        })
        obs = await analyzer.analyze("https://example.com")
        maps = [o for o in obs if o.observation_type == "exposed_source_map"]
        assert len(maps) == 0


# ===================================================================
# 3. Secret pattern detection
# ===================================================================

class TestSecretPatternDetection:
    @pytest.mark.asyncio
    async def test_detects_google_api_key(self):
        html = '<html><script src="/js/config.js"></script></html>'
        js = 'const apiKey = "AIzaSyABC123DEF456GHI789JKL012MNO345PQR";'
        analyzer = _make_analyzer({
            "https://example.com": _response(200, body=html),
            "https://example.com/js/config.js": _response(200, body=js),
        })
        obs = await analyzer.analyze("https://example.com")
        secrets = [o for o in obs if o.observation_type == "potential_credential_exposure"]
        assert len(secrets) >= 1
        assert "Google API Key" in secrets[0].metadata["description"]

    @pytest.mark.asyncio
    async def test_detects_jwt_token(self):
        html = '<html><script src="/js/auth.js"></script></html>'
        js = 'const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNqP2RNM3sTXfRvL0PqJw0B3F1jL9x8y5v6Q7wE";'
        analyzer = _make_analyzer({
            "https://example.com": _response(200, body=html),
            "https://example.com/js/auth.js": _response(200, body=js),
        })
        obs = await analyzer.analyze("https://example.com")
        secrets = [o for o in obs if o.observation_type == "potential_credential_exposure"]
        assert any("JWT" in s.metadata["description"] for s in secrets)

    @pytest.mark.asyncio
    async def test_no_secrets_in_clean_code(self):
        html = '<html><script src="/js/app.js"></script></html>'
        js = 'const name = "hello"; function greet() { return "hi"; }'
        analyzer = _make_analyzer({
            "https://example.com": _response(200, body=html),
            "https://example.com/js/app.js": _response(200, body=js),
        })
        obs = await analyzer.analyze("https://example.com")
        secrets = [o for o in obs if o.observation_type == "potential_credential_exposure"]
        assert len(secrets) == 0


# ===================================================================
# 4. Library detection
# ===================================================================

class TestLibraryDetection:
    @pytest.mark.asyncio
    async def test_detects_react_from_script_url(self):
        html = '<html><script src="https://cdn.example.com/react.production.min.js"></script></html>'
        analyzer = _make_analyzer({
            "https://example.com": _response(200, body=html),
            "https://cdn.example.com/react.production.min.js": _response(200, body="React"),
        })
        obs = await analyzer.analyze("https://example.com")
        libs = [o for o in obs if o.observation_type == "javascript_library_detected"]
        assert any("React" in o.evidence["technology"] for o in libs)

    @pytest.mark.asyncio
    async def test_detects_jquery_from_url(self):
        html = '<html><script src="https://code.jquery.com/jquery-3.7.1.min.js"></script></html>'
        analyzer = _make_analyzer({
            "https://example.com": _response(200, body=html),
            "https://code.jquery.com/jquery-3.7.1.min.js": _response(200, body="jQuery"),
        })
        obs = await analyzer.analyze("https://example.com")
        libs = [o for o in obs if o.observation_type == "javascript_library_detected"]
        assert any("jQuery" in o.evidence["technology"] for o in libs)

    @pytest.mark.asyncio
    async def test_detects_vue_from_inline_global(self):
        html = '<html><script>var app = new Vue({ el: "#app" });</script></html>'
        analyzer = _make_analyzer({
            "https://example.com": _response(200, body=html),
        })
        obs = await analyzer.analyze("https://example.com")
        libs = [o for o in obs if o.observation_type == "javascript_library_detected"]
        assert any("Vue.js" in o.evidence["technology"] for o in libs)


# ===================================================================
# 5. Dangerous pattern detection
# ===================================================================

class TestDangerousPatternDetection:
    @pytest.mark.asyncio
    async def test_detects_eval(self):
        html = '<html><script src="/js/app.js"></script></html>'
        js = 'function process(input) { eval(input); }'
        analyzer = _make_analyzer({
            "https://example.com": _response(200, body=html),
            "https://example.com/js/app.js": _response(200, body=js),
        })
        obs = await analyzer.analyze("https://example.com")
        dangerous = [o for o in obs if o.observation_type == "dangerous_javascript_pattern"]
        assert any("eval" in o.metadata["description"].lower() for o in dangerous)

    @pytest.mark.asyncio
    async def test_detects_inner_html_assignment(self):
        html = '<html><script src="/js/ui.js"></script></html>'
        js = 'document.getElementById("output").innerHTML = userInput;'
        analyzer = _make_analyzer({
            "https://example.com": _response(200, body=html),
            "https://example.com/js/ui.js": _response(200, body=js),
        })
        obs = await analyzer.analyze("https://example.com")
        dangerous = [o for o in obs if o.observation_type == "dangerous_javascript_pattern"]
        assert any("innerHTML" in o.metadata["description"] for o in dangerous)

    @pytest.mark.asyncio
    async def test_detects_console_logging(self):
        html = '<html><script src="/js/app.js"></script></html>'
        js = 'console.log("Debug: user data", sensitiveInfo);'
        analyzer = _make_analyzer({
            "https://example.com": _response(200, body=html),
            "https://example.com/js/app.js": _response(200, body=js),
        })
        obs = await analyzer.analyze("https://example.com")
        dangerous = [o for o in obs if o.observation_type == "dangerous_javascript_pattern"]
        assert any("console" in o.metadata["description"].lower() for o in dangerous)

    @pytest.mark.asyncio
    async def test_clean_js_no_dangerous_patterns(self):
        html = '<html><script src="/js/app.js"></script></html>'
        js = 'function add(a, b) { return a + b; } const x = 42;'
        analyzer = _make_analyzer({
            "https://example.com": _response(200, body=html),
            "https://example.com/js/app.js": _response(200, body=js),
        })
        obs = await analyzer.analyze("https://example.com")
        dangerous = [o for o in obs if o.observation_type == "dangerous_javascript_pattern"]
        assert len(dangerous) == 0


# ===================================================================
# 6. Secure JS handling (no issues)
# ===================================================================

class TestSecureJSSite:
    @pytest.mark.asyncio
    async def test_secure_js_site_minimal_observations(self):
        html = """<html><head><title>Secure</title>
<link rel="stylesheet" href="/style.css">
</head><body><p>Hello</p></body></html>"""
        analyzer = _make_analyzer({
            "https://example.com": _response(200, body=html),
        })
        obs = await analyzer.analyze("https://example.com")
        # No scripts, no source maps, no secrets, no dangerous patterns
        dangerous = [o for o in obs if o.observation_type == "dangerous_javascript_pattern"]
        secrets = [o for o in obs if o.observation_type == "potential_credential_exposure"]
        maps = [o for o in obs if o.observation_type == "exposed_source_map"]
        assets = [o for o in obs if o.observation_type == "javascript_asset_discovered"]
        assert len(dangerous) == 0
        assert len(secrets) == 0
        assert len(maps) == 0
        assert len(assets) == 0


# ===================================================================
# 7. Structure validation
# ===================================================================

class TestObservationStructure:
    @pytest.mark.asyncio
    async def test_all_observations_have_required_fields(self):
        html = """<html><script src="/js/app.js"></script></html>"""
        js = 'eval("hello"); const key = "AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";'
        analyzer = _make_analyzer({
            "https://example.com": _response(200, body=html),
            "https://example.com/js/app.js": _response(200, body=js),
        })
        obs = await analyzer.analyze("https://example.com")
        assert len(obs) > 0
        for o in obs:
            assert isinstance(o.observation_type, str)
            assert isinstance(o.target, str)
            assert isinstance(o.severity_hint, str)
            assert o.severity_hint in ("critical", "high", "medium", "low", "info")
            assert o.metadata is not None
            assert "check" in o.metadata
            assert "category" in o.metadata

    @pytest.mark.asyncio
    async def test_connection_failure_returns_empty(self):
        analyzer = _make_analyzer({})
        obs = await analyzer.analyze("https://example.com")
        assert len(obs) == 0
