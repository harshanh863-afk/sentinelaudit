"""JavaScript security intelligence analyzer - passive JS analysis.

Produces ScannerObservation objects only - no database writes, no findings.
No exploitation. Intelligence gathering for authorized security assessments.
"""

import hashlib
import re
from urllib.parse import urljoin

import httpx

from sentinelaudit_scanner.models.observation import ScannerObservation

# Regex patterns for potential secrets (passive detection only)
_SECRET_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r'["\'](?:AIza[0-9A-Za-z\-_]{35})["\']'), "high",
     "Potential Google API Key"),
    (re.compile(r'["\'](?:sk_live_[0-9a-z]{32,})["\']'), "high",
     "Potential Stripe Secret Key"),
    (re.compile(r'["\'](?:pk_live_[0-9a-z]{32,})["\']'), "medium",
     "Potential Stripe Publishable Key"),
    (re.compile(r'["\'](?:AKIA[0-9A-Z]{16})["\']'), "high",
     "Potential AWS Access Key"),
    (re.compile(r'(?:eyJ[a-zA-Z0-9\-_]{10,}\.eyJ[a-zA-Z0-9\-_]{10,}\.[a-zA-Z0-9\-_]{10,})'),
     "high", "Potential JWT Token"),
    (re.compile(r'["\'](?:ghp_[0-9a-zA-Z]{36})["\']'), "high",
     "Potential GitHub Token"),
    (re.compile(r'["\'](?:gho_[0-9a-zA-Z]{36})["\']'), "high",
     "Potential GitHub OAuth Token"),
    (re.compile(r'["\'](?:xox[pbora]-[0-9a-zA-Z\-]{10,})["\']'), "high",
     "Potential Slack Token"),
    (re.compile(r'["\'](?:sk-[0-9a-zA-Z]{32,})["\']'), "high",
     "Potential OpenAI API Key"),
]

# Library detection via known script path patterns
_LIBRARY_SCRIPTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'react(?:[.-][a-zA-Z0-9]+)*\.js', re.I), "React"),
    (re.compile(r'react-dom(\.[a-z]+)?\.js', re.I), "React DOM"),
    (re.compile(r'angular(\.[a-z]+)?\.js', re.I), "Angular"),
    (re.compile(r'angular-core(\.[a-z]+)?\.js', re.I), "Angular"),
    (re.compile(r'vue(\.[a-z]+)?\.js', re.I), "Vue.js"),
    (re.compile(r'jquery[-.][0-9]', re.I), "jQuery"),
    (re.compile(r'lodash(\.[a-z]+)?\.js', re.I), "lodash"),
    (re.compile(r'bootstrap(\.[a-z]+)?\.js', re.I), "Bootstrap"),
    (re.compile(r'bootstrap(\.[a-z]+)?\.min\.js', re.I), "Bootstrap"),
    (re.compile(r'moment(\.[a-z]+)?\.js', re.I), "Moment.js"),
    (re.compile(r'chart(\.[a-z]+)?\.js', re.I), "Chart.js"),
    (re.compile(r'd3(\.[a-z]+)?\.js', re.I), "D3.js"),
    (re.compile(r'underscore(\.[a-z]+)?\.js', re.I), "Underscore"),
    (re.compile(r'axios(\.[a-z]+)?\.js', re.I), "Axios"),
]

# Library detection via inline JS window globals or HTML content
_LIBRARY_GLOBALS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'react\s*=\s*|\.createElement\b', re.I), "React"),
    (re.compile(r'angular\s*\.\s*(module|version)', re.I), "Angular"),
    (re.compile(r'new\s+Vue\b|Vue\s*\.\s*(component|directive)', re.I), "Vue.js"),
    (re.compile(r'jQuery\b|\$\.(ajax|each|extend)', re.I), "jQuery"),
    (re.compile(r'_\s*\.\s*(each|map|filter|reduce)\b', re.I), "Underscore/lodash"),
    (re.compile(r'moment\s*\(', re.I), "Moment.js"),
    (re.compile(r'Chart\s*\.\s*register|new\s+Chart\b', re.I), "Chart.js"),
]

# Dangerous JS patterns (passive detection - not exploitation)
_DANGEROUS_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r'\beval\s*\(', re.I), "high",
     "eval() usage - arbitrary code execution risk"),
    (re.compile(r'\bdocument\.write\s*\(', re.I), "medium",
     "document.write() usage - XSS risk with unsanitized input"),
    (re.compile(r'\.innerHTML\s*=', re.I), "medium",
     "innerHTML assignment - XSS risk"),
    (re.compile(r'\bsetTimeout\s*\(\s*["\']', re.I), "low",
     "String-based setTimeout - potential XSS vector"),
    (re.compile(r'\bsetInterval\s*\(\s*["\']', re.I), "low",
     "String-based setInterval - potential XSS vector"),
    (re.compile(r'new\s+Function\s*\(', re.I), "high",
     "Dynamic function constructor - arbitrary code execution risk"),
    (re.compile(r'debugger\b', re.I), "low",
     "Debugger statement in production code"),
    (re.compile(r'console\.(log|debug|warn|info)\b', re.I), "info",
     "Console logging in production code - information disclosure risk"),
]


class JavaScriptAnalyzer:
    """Passively analyzes JavaScript for security intelligence."""

    def __init__(self, timeout: int = 30):
        self._timeout = timeout

    async def analyze(self, url: str) -> list[ScannerObservation]:
        observations: list[ScannerObservation] = []

        resp = await self._fetch(url)
        if resp is None:
            return observations

        body = resp.text or ""
        base_url = url

        # 1. JS asset discovery
        script_urls = self._extract_script_urls(base_url, body)
        for script_url in script_urls:
            observations.append(self._script_asset(script_url))

            # 2. Source map detection (check each discovered script)
            script_body = await self._fetch(script_url)
            if script_body:
                sm_obs = self._check_source_map(script_url, script_body.text or "")
                if sm_obs:
                    observations.append(sm_obs)

                # 3. Secret pattern detection
                secret_obs = self._detect_secrets(script_url, script_body.text or "")
                observations.extend(secret_obs)

                # 4. Library detection
                lib_obs = self._detect_library_from_script(script_url, script_body.text or "")
                observations.extend(lib_obs)

                # 5. Dangerous pattern detection
                danger_obs = self._detect_dangerous_patterns(
                    script_url, script_body.text or ""
                )
                observations.extend(danger_obs)

        # Inline JS analysis (no separate script URL)
        if re.search(r'<script[^>]*>.*?</script>', body, re.DOTALL):
            # Source map in inline JS comments
            sm_obs = self._check_source_map(url, body)
            if sm_obs:
                observations.append(sm_obs)

            # Secrets in inline JS
            secret_obs = self._detect_secrets(url, body)
            observations.extend(secret_obs)

            # Libraries from inline JS globals
            lib_obs = self._detect_library_from_inline(body)
            observations.extend(lib_obs)

            # Dangerous patterns in inline JS
            danger_obs = self._detect_dangerous_patterns(url, body)
            observations.extend(danger_obs)

        return observations

    # ------------------------------------------------------------------
    # HTTP fetch (overridable in tests)
    # ------------------------------------------------------------------

    async def _fetch(self, url: str) -> httpx.Response | None:
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout, follow_redirects=True, verify=False
            ) as client:
                return await client.get(url)
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError):
            return None

    # ------------------------------------------------------------------
    # 1. JS asset discovery
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_script_urls(base_url: str, html: str) -> list[str]:
        urls: list[str] = []
        for m in re.finditer(
            r'<script[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']',
            html, re.I
        ):
            raw = m.group(1)
            full = urljoin(base_url, raw)
            if full not in urls:
                urls.append(full)
        return urls

    @staticmethod
    def _script_asset(url: str) -> ScannerObservation:
        return ScannerObservation(
            observation_type="javascript_asset_discovered",
            target=url,
            severity_hint="info",
            evidence={"url": url, "asset_type": "javascript"},
            metadata={
                "check": "js_asset_discovery",
                "category": "javascript_analysis",
                "description": "JavaScript asset discovered",
                "detail": f"External JavaScript asset: {url}",
            },
        )

    # ------------------------------------------------------------------
    # 2. Source map detection
    # ------------------------------------------------------------------

    @staticmethod
    def _check_source_map(source_url: str, body: str) -> ScannerObservation | None:
        m = re.search(
            r'//#\s*sourceMappingURL\s*=\s*(\S+)',
            body,
        )
        if m:
            map_path = m.group(1)
            return ScannerObservation(
                observation_type="exposed_source_map",
                target=source_url,
                severity_hint="medium",
                evidence={
                    "source_url": source_url,
                    "source_map_url": map_path,
                },
                metadata={
                    "check": "source_map_detection",
                    "category": "javascript_analysis",
                    "description": "Exposed JavaScript Source Map",
                    "detail": (
                        f"Source map reference found in {source_url}: {map_path}. "
                        "Source maps can expose original source code."
                    ),
                },
            )
        return None

    # ------------------------------------------------------------------
    # 3. Secret pattern detection
    # ------------------------------------------------------------------

    @classmethod
    def _detect_secrets(cls, source_url: str, body: str) -> list[ScannerObservation]:
        obs: list[ScannerObservation] = []
        for pattern, severity, label in _SECRET_PATTERNS:
            for m in pattern.finditer(body):
                matched = m.group(0).strip("\"'")
                obs.append(ScannerObservation(
                    observation_type="potential_credential_exposure",
                    target=source_url,
                    severity_hint=severity,
                    evidence={
                        "source_url": source_url,
                        "pattern_type": label,
                        "matched_fragment": matched[:40] + "..." if len(matched) > 40 else matched,
                        "position": m.start(),
                    },
                    metadata={
                        "check": "secret_detection",
                        "category": "javascript_analysis",
                        "description": f"Potential exposed credential: {label}",
                        "detail": (
                            f"A pattern matching '{label}' was detected in {source_url}. "
                            "This is a potential credential exposure and should be "
                            "manually reviewed."
                        ),
                    },
                ))
        return obs

    # ------------------------------------------------------------------
    # 4. Library detection
    # ------------------------------------------------------------------

    @classmethod
    def _detect_library_from_script(
        cls, source_url: str, body: str
    ) -> list[ScannerObservation]:
        obs: list[ScannerObservation] = []
        detected: set[str] = set()

        for p, lib_name in _LIBRARY_SCRIPTS:
            if p.search(source_url):
                if lib_name not in detected:
                    detected.add(lib_name)
                    obs.append(cls._library_observation(source_url, lib_name))

        for p, lib_name in _LIBRARY_GLOBALS:
            if p.search(body):
                if lib_name not in detected:
                    detected.add(lib_name)
                    obs.append(cls._library_observation(source_url, lib_name))

        # Compute script hash for evidence
        if body:
            sha = hashlib.sha256(body.encode()).hexdigest()
            # Attach hash to first observation if any
            if obs:
                obs[0].evidence["sha256"] = sha

        return obs

    @classmethod
    def _detect_library_from_inline(cls, body: str) -> list[ScannerObservation]:
        obs: list[ScannerObservation] = []
        detected: set[str] = set()

        for p, lib_name in _LIBRARY_GLOBALS:
            if p.search(body):
                if lib_name not in detected:
                    detected.add(lib_name)
                    obs.append(ScannerObservation(
                        observation_type="javascript_library_detected",
                        target="inline_script",
                        severity_hint="info",
                        evidence={"technology": lib_name, "source": "inline JS globals"},
                        metadata={
                            "check": "library_detection",
                            "category": "javascript_analysis",
                            "description": f"JavaScript library detected: {lib_name}",
                            "detail": f"Detected {lib_name} from inline script patterns",
                        },
                    ))
        return obs

    @staticmethod
    def _library_observation(source_url: str, lib_name: str) -> ScannerObservation:
        return ScannerObservation(
            observation_type="javascript_library_detected",
            target=source_url,
            severity_hint="info",
            evidence={"technology": lib_name, "source": source_url},
            metadata={
                "check": "library_detection",
                "category": "javascript_analysis",
                "description": f"JavaScript library detected: {lib_name}",
                "detail": f"Detected {lib_name} from {source_url}",
            },
        )

    # ------------------------------------------------------------------
    # 5. Dangerous pattern detection
    # ------------------------------------------------------------------

    @classmethod
    def _detect_dangerous_patterns(
        cls, source_url: str, body: str
    ) -> list[ScannerObservation]:
        obs: list[ScannerObservation] = []
        for pattern, severity, description in _DANGEROUS_PATTERNS:
            for m in pattern.finditer(body):
                context_start = max(0, m.start() - 40)
                context_end = min(len(body), m.end() + 40)
                context = body[context_start:context_end]
                obs.append(ScannerObservation(
                    observation_type="dangerous_javascript_pattern",
                    target=source_url,
                    severity_hint=severity,
                    evidence={
                        "source_url": source_url,
                        "pattern": pattern.pattern,
                        "position": m.start(),
                        "context": context.strip(),
                    },
                    metadata={
                        "check": "dangerous_pattern_detection",
                        "category": "javascript_analysis",
                        "description": f"Dangerous JS pattern: {description}",
                        "detail": f"Found '{pattern.pattern}' in {source_url}",
                    },
                ))
        return obs
