"""Technology fingerprinting engine - passive detection from HTTP responses.

Produces ScannerObservation objects only - no database writes, no findings.
"""

import re

import httpx

from sentinelaudit_scanner.models.observation import ScannerObservation


class TechFingerprinter:
    """Identifies web technologies via passive HTTP analysis."""

    # Server -> technology mapping
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

    # X-Powered-By / header patterns
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

    # HTML patterns
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

    # Cookie patterns
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

    # Infrastructure indicators
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

        technologies: dict[str, str] = {}  # tech_name -> detection_source

        # 1. Server header
        server = headers_lower.get("server", "")
        if server:
            tech = self._match_server(server)
            if tech:
                technologies[tech] = f"Server header: {server}"

        # 2. X-Powered-By
        xpb = headers_lower.get("x-powered-by", "")
        if xpb:
            tech = self._match_tech_header(xpb)
            if tech:
                technologies[tech] = f"X-Powered-By: {xpb}"

        # 3. Other tech headers
        via = headers_lower.get("via", "")
        if via:
            tech = self._match_infrastructure(via)
            if tech:
                technologies[tech] = f"Via: {via}"

        cf_ray = headers_lower.get("cf-ray", "")
        if cf_ray:
            technologies["Cloudflare"] = "cf-ray header present"

        x_amz = headers_lower.get("x-amz-cf-id", "")
        if x_amz:
            technologies["AWS CloudFront"] = "x-amz-cf-id header present"

        # 4. HTML patterns
        for pattern, tech_name in self.HTML_PATTERNS:
            if pattern.search(body):
                if tech_name not in technologies:
                    technologies[tech_name] = "HTML pattern match"

        # 5. Cookie patterns
        for cookie_prefix, tech_name in self.COOKIE_PATTERNS:
            for cookie in cookies:
                if cookie.startswith(cookie_prefix) or cookie.lower().startswith(cookie_prefix.lower()):
                    if tech_name not in technologies:
                        technologies[tech_name] = f"Cookie: {cookie.split('=')[0]}"

        # 6. X-Generator
        generator = headers_lower.get("x-generator", "") or headers_lower.get("generator", "")
        if generator:
            tech = self._match_tech_header(generator)
            if tech and tech not in technologies:
                technologies[tech] = f"Generator header: {generator}"

        # Build observations
        for tech_name, source in sorted(technologies.items()):
            observations.append(ScannerObservation(
                observation_type="technology_detected",
                target=url,
                severity_hint="info",
                evidence={"technology": tech_name, "source": source},
                metadata={
                    "check": "technology_fingerprint",
                    "category": "technology_fingerprint",
                    "description": f"Detected technology: {tech_name}",
                    "detail": f"Identified {tech_name} via {source}",
                },
            ))

        return observations

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
