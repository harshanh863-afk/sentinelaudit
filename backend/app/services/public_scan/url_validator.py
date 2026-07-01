"""URL validation for public scan targets.

Rejects:
  - Non-HTTPS URLs
  - localhost / 127.0.0.1 / 0.0.0.0
  - Private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
  - Cloud metadata IPs (169.254.169.254, 100.100.100.200)
  - Internal network ranges
  - Reserved TLDs
  - DNS rebinding (post-resolution IP check)
  - Redirects to blocked targets (chain validation)

Safe scanning:
  - Passive checks only
  - No exploitation
  - No credential testing
  - No destructive requests
"""

import ipaddress
import re
import socket
from urllib.parse import urlparse


class URLValidationError(Exception):
    pass


_PRIVATE_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

_HOSTNAME_BLOCKLIST = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "169.254.169.254",
    "100.100.100.200",
    "metadata.google.internal",
]

_RESERVED_TLDS = {
    ".internal", ".local", ".localhost", ".test", ".example",
    ".invalid", ".arpa", ".home", ".corp", ".lan", ".onion",
}

_RE_SSRF_HOSTNAMES = re.compile(
    r"\.(internal|local|localhost|consul|corp|home|lan)$",
    re.IGNORECASE,
)

_MAX_REDIRECT_CHAIN = 5


class URLValidator:
    @staticmethod
    def validate(url: str) -> str:
        parsed = urlparse(url)

        if parsed.scheme not in ("https",):
            raise URLValidationError("Only HTTPS URLs are allowed")

        hostname = parsed.hostname or ""

        if hostname.lower() in _HOSTNAME_BLOCKLIST:
            raise URLValidationError(f"Target URL is not allowed: {hostname}")

        if _RE_SSRF_HOSTNAMES.search(hostname):
            raise URLValidationError(f"Internal hostname detected: {hostname}")

        for tld in _RESERVED_TLDS:
            if hostname.lower().endswith(tld):
                raise URLValidationError(f"Reserved TLD detected: {hostname}")

        try:
            ip = ipaddress.ip_address(hostname)
            for net in _PRIVATE_RANGES:
                if ip in net:
                    raise URLValidationError(f"Private IP range target is not allowed: {hostname}")
        except ValueError:
            pass

        resolved_ips = URLValidator._resolve_hostname(hostname)
        for resolved_ip in resolved_ips:
            try:
                ip_obj = ipaddress.ip_address(resolved_ip)
                for net in _PRIVATE_RANGES:
                    if ip_obj in net:
                        raise URLValidationError(
                            f"DNS rebinding detected: {hostname} resolves to {resolved_ip} (blocked range)"
                        )
            except ValueError:
                pass

        return url.strip()

    @staticmethod
    def _resolve_hostname(hostname: str) -> list[str]:
        try:
            return list(set(
                addr[4][0] for addr in socket.getaddrinfo(hostname, 443, socket.AF_INET)
            ))
        except (socket.gaierror, OSError):
            return []

    @staticmethod
    def validate_redirect_url(redirect_url: str) -> bool:
        """Validate a redirect target URL. Returns True if safe."""
        try:
            URLValidator.validate(redirect_url)
            return True
        except URLValidationError:
            return False

    @staticmethod
    def get_max_redirect_chain() -> int:
        return _MAX_REDIRECT_CHAIN

    @staticmethod
    def check_safe_scanning() -> None:
        """Ensure only passive checks are used (enforced at scanner level)."""
        pass
