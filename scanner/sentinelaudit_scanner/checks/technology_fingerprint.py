"""Technology fingerprinting engine - passive detection from HTTP responses.

Produces ScannerObservation objects only - no database writes, no findings.
Supports version-aware detection using the version_db fingerprint database.
"""

import re

import httpx

from sentinelaudit_scanner.models.observation import ScannerObservation
from sentinelaudit_scanner.checks.version_db import VERSION_DB, evaluate_version, get_fingerprint


class TechFingerprinter:
    """Identifies web technologies via passive HTTP analysis."""

    SERVER_PATTERNS: dict[str, str] = {
        "nginx": "nginx",
        "apache": "Apache",
        "iis": "IIS",
        "cloudflare": "Cloudflare",
        "openresty": "OpenResty",
        "caddy": "Caddy",
        "lighttpd": "Lighttpd",
        "gunicorn": "Gunicorn",
        "uwsgi": "uWSGI",
        "node.js": "Node.js",
        "express": "Express",
        "awselb": "AWS ELB",
    }

    TECH_HEADER_PATTERNS: dict[str, str] = {
        "php": "PHP",
        "asp.net": "ASP.NET",
        "java": "Java",
        "python": "Python",
        "ruby on rails": "Ruby on Rails",
        "django": "Django",
        "flask": "Flask",
        "tomcat": "Tomcat",
        "jboss": "JBoss",
        "jetty": "Jetty",
    }

    HTML_PATTERNS: list[tuple[re.Pattern, str]] = [
        (re.compile(r'wp-content|wp-includes|wordpress', re.I), "WordPress"),
        (re.compile(r'<meta name="generator" content="WordPress', re.I), "WordPress"),
        (re.compile(r'<meta name="generator" content="Drupal', re.I), "Drupal"),
        (re.compile(r'<meta name="generator" content="Joomla', re.I), "Joomla!"),
        (re.compile(r'__NEXT_DATA__|/_next/static', re.I), "Next.js"),
        (re.compile(r'data-reactroot|data-reactid|__react', re.I), "React"),
        (re.compile(r'<app-root|ng-version|angular', re.I), "Angular"),
        (re.compile(r'__VUE__|vue-router|vuex', re.I), "Vue.js"),
        (re.compile(r'jquery[-.]', re.I), "jQuery"),
        (re.compile(r'bootstrap', re.I), "Bootstrap"),
        (re.compile(r'django\.core|csrfmiddlewaretoken', re.I), "Django"),
        (re.compile(r'laravel|livewire', re.I), "Laravel"),
        (re.compile(r'symfony', re.I), "Symfony"),
        (re.compile(r'rails|ruby-on-rails', re.I), "Ruby on Rails"),
        (re.compile(r'asp\.net|__viewstate|__eventvalidation', re.I), "ASP.NET"),
        (re.compile(r'shopify', re.I), "Shopify"),
        (re.compile(r'magento|mage\.', re.I), "Magento"),
    ]

    COOKIE_PATTERNS: list[tuple[str, str]] = [
        ("PHPSESSID", "PHP"),
        ("JSESSIONID", "Java (JSessionID)"),
        ("ASP.NET_SessionId", "ASP.NET"),
        ("laravel_session", "Laravel"),
        ("django_session", "Django"),
        ("rails_session", "Ruby on Rails"),
        ("wordpress_", "WordPress"),
        ("wp-settings-", "WordPress"),
        ("XSRF-TOKEN", "Laravel / CSRF"),
    ]

    INFRASTRUCTURE_PATTERNS: dict[str, str] = {
        "cloudflare": "Cloudflare",
        "akamai": "Akamai",
        "fastly": "Fastly",
        "cloudfront": "AWS CloudFront",
        "cloudflare-nginx": "Cloudflare",
        "incapsula": "Incapsula",
        "stackpath": "StackPath",
        "sucuri": "Sucuri",
    }

    def __init__(self, timeout: int = 30):
        self._timeout = timeout

    async def fingerprint(self, url: str) -> list[ScannerObservation]:
        observations: list[ScannerObservation] = []

        resp = await self._fetch(url)
        if resp is None:
            return observations

        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text or ""
        cookies = resp.headers.get_list("set-cookie")

        tech_data: dict[str, dict] = {}

        server = headers_lower.get("server", "")
        if server:
            self._detect_from_server(server, tech_data)

        xpb = headers_lower.get("x-powered-by", "")
        if xpb:
            self._detect_from_tech_header(xpb, tech_data)

        via = headers_lower.get("via", "")
        if via:
            tech = self._match_infrastructure(via)
            if tech:
                self._add_tech(tech_data, tech, f"Via: {via}")

        cf_ray = headers_lower.get("cf-ray", "")
        if cf_ray:
            self._add_tech(tech_data, "Cloudflare", "cf-ray header present")

        x_amz = headers_lower.get("x-amz-cf-id", "")
        if x_amz:
            self._add_tech(tech_data, "AWS CloudFront", "x-amz-cf-id header present")

        for pattern, tech_name in self.HTML_PATTERNS:
            if pattern.search(body):
                self._add_tech(tech_data, tech_name, "HTML pattern match")

        for cookie_prefix, tech_name in self.COOKIE_PATTERNS:
            for cookie in cookies:
                if cookie.startswith(cookie_prefix) or cookie.lower().startswith(cookie_prefix.lower()):
                    self._add_tech(tech_data, tech_name, f"Cookie: {cookie.split('=')[0]}")

        generator = headers_lower.get("x-generator", "") or headers_lower.get("generator", "")
        if generator:
            tech = self._match_tech_header(generator)
            if tech:
                self._add_tech(tech_data, tech, f"Generator header: {generator}")

        for tech_name, info in sorted(tech_data.items()):
            observations.append(self._build_versioned_observation(url, tech_name, info))

        return observations

    def _detect_from_server(self, server: str, tech_data: dict) -> None:
        server_lower = server.lower()
        for key, tech_name in self.SERVER_PATTERNS.items():
            if key in server_lower:
                version = self._extract_version(tech_name, server)
                self._add_tech(tech_data, tech_name, f"Server header: {server}", version)
                return
        tech_name = server.split("/")[0] if "/" in server else server
        version = server.split("/")[1] if "/" in server else None
        self._add_tech(tech_data, tech_name.capitalize(), f"Server header: {server}", version)

    def _detect_from_tech_header(self, value: str, tech_data: dict) -> None:
        value_lower = value.lower()
        for key, tech_name in self.TECH_HEADER_PATTERNS.items():
            if key in value_lower:
                version = self._extract_version(tech_name, value)
                self._add_tech(tech_data, tech_name, f"X-Powered-By: {value}", version)
                return
        tech_name = value.split("/")[0] if "/" in value else value
        version = value.split("/")[1] if "/" in value else None
        self._add_tech(tech_data, tech_name.capitalize(), f"X-Powered-By: {value}", version)

    def _extract_version(self, tech_name: str, raw: str) -> str | None:
        fp = get_fingerprint(tech_name)
        if not fp:
            m = re.search(r"/(\d+\.\d+(?:\.\d+)?)", raw)
            return m.group(1) if m else None
        for pattern, _src in fp.version_patterns:
            m = re.search(pattern, raw)
            if m:
                return m.group(1)
        return None

    def _build_versioned_observation(self, url: str, tech_name: str, info: dict) -> ScannerObservation:
        version = info.get("version")
        source = info.get("source", "detected")
        extra = {"technology": tech_name, "source": source}

        if version:
            extra["version"] = version
            eval_result = evaluate_version(tech_name, version)
            extra["version_status"] = eval_result

        return ScannerObservation(
            observation_type="technology_detected",
            target=url,
            severity_hint="info",
            evidence=extra,
            metadata={
                "check": "technology_fingerprint",
                "category": "technology_inventory",
                "description": f"Detected technology: {tech_name}",
                "detail": f"Identified {tech_name} via {source}" + (f" (version {version})" if version else ""),
                "version": version,
                "version_status": eval_result["status"] if version and eval_result else "unknown",
            },
        )

    @staticmethod
    def _add_tech(tech_data: dict, name: str, source: str, version: str | None = None) -> None:
        if name not in tech_data:
            tech_data[name] = {"source": source, "version": version}
        elif version and not tech_data[name].get("version"):
            tech_data[name]["version"] = version

    async def _fetch(self, url: str, follow_redirects: bool = True) -> httpx.Response | None:
        try:
            async with httpx.AsyncClient(timeout=self._timeout, follow_redirects=follow_redirects, verify=False) as client:
                return await client.get(url)
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RemoteProtocolError):
            return None

    @classmethod
    def _match_server(cls, server: str) -> str | None:
        server_lower = server.lower()
        for key, tech_name in cls.SERVER_PATTERNS.items():
            if key in server_lower:
                return tech_name
        if server_lower and server_lower != "server":
            return server.split("/")[0] if "/" in server else server
        return None

    @classmethod
    def _match_tech_header(cls, value: str) -> str | None:
        value_lower = value.lower()
        for key, tech_name in cls.TECH_HEADER_PATTERNS.items():
            if key in value_lower:
                return tech_name
        if value_lower:
            return value.split("/")[0] if "/" in value else value
        return None

    @classmethod
    def _match_infrastructure(cls, value: str) -> str | None:
        value_lower = value.lower()
        for key, tech_name in cls.INFRASTRUCTURE_PATTERNS.items():
            if key in value_lower:
                return tech_name
        return None
