"""TLS security analyzer - certificate, protocol, and cipher assessment.

Produces ScannerObservation objects only - no database writes, no findings.
"""

import asyncio
import datetime
import ssl

from sentinelaudit_scanner.models.observation import ScannerObservation


class TLSAnalyzer:
    """Analyzes TLS certificates, protocol versions, and cipher suites."""

    WEAK_CIPHER_PREFIXES = ("RC4", "DES", "3DES", "NULL", "EXPORT")

    async def analyze(self, hostname: str, port: int = 443) -> list[ScannerObservation]:
        observations: list[ScannerObservation] = []

        conn = await self._connect(hostname, port)
        if conn is None:
            observations.append(self._connection_failed(hostname, port))
            return observations

        cert = conn.get("cert")
        if cert:
            obs = self._check_certificate_expiry(cert, hostname)
            if obs:
                observations.append(obs)
            obs = self._check_hostname_mismatch(cert, hostname)
            if obs:
                observations.append(obs)
            obs = self._check_self_signed(cert, hostname)
            if obs:
                observations.append(obs)
            obs = self._check_certificate_chain(cert, hostname)
            if obs:
                observations.append(obs)

        version = conn.get("version", "")
        obs = self._check_protocol_version(version, hostname, port)
        if obs:
            observations.append(obs)

        cipher = conn.get("cipher")
        if cipher:
            cipher_name = cipher[0] if isinstance(cipher, tuple) else str(cipher)
            obs = self._check_cipher_strength(cipher_name, hostname, port)
            if obs:
                observations.append(obs)

        return observations

    async def _connect(self, hostname: str, port: int) -> dict | None:
        """Establish TLS connection. Override in tests to control results."""
        try:
            context = ssl.create_default_context()
            reader, writer = await asyncio.open_connection(
                hostname, port, ssl=context, server_hostname=hostname
            )
            sock = writer.get_extra_info("ssl_object")
            if sock is None:
                writer.close()
                return None
            result = {
                "cert": sock.getpeercert(),
                "cipher": sock.cipher(),
                "version": sock.version(),
            }
            writer.close()
            return result
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Certificate checks
    # ------------------------------------------------------------------

    @staticmethod
    def _check_certificate_expiry(cert: dict, hostname: str) -> ScannerObservation | None:
        not_after_str = cert.get("notAfter")
        if not not_after_str:
            return None
        try:
            not_after = datetime.datetime.strptime(
                not_after_str, "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            return None

        now = datetime.datetime.now(datetime.timezone.utc)
        if now > not_after:
            return ScannerObservation(
                observation_type="expired_certificate",
                target=hostname,
                severity_hint="critical",
                evidence={"not_after": not_after_str, "days_expired": (now - not_after).days},
                metadata={
                    "check": "certificate_expiry",
                    "category": "tls_analysis",
                    "description": "TLS certificate has expired",
                    "detail": f"Certificate expired on {not_after_str}",
                },
            )
        days_remaining = (not_after - now).days
        if days_remaining <= 30:
            return ScannerObservation(
                observation_type="certificate_expiring_soon",
                target=hostname,
                severity_hint="medium",
                evidence={"not_after": not_after_str, "days_remaining": days_remaining},
                metadata={
                    "check": "certificate_expiry",
                    "category": "tls_analysis",
                    "description": "TLS certificate expiring soon",
                    "detail": f"Certificate expires in {days_remaining} days on {not_after_str}",
                },
            )
        return None

    @staticmethod
    def _check_hostname_mismatch(cert: dict, hostname: str) -> ScannerObservation | None:
        san_list = cert.get("subjectAltName", ())
        dns_names = [val for key, val in san_list if key == "DNS"]
        if dns_names and _hostname_matches_any(hostname, dns_names):
            return None

        subject = cert.get("subject", ())
        for attr_list in subject:
            for key, val in attr_list:
                if key == "commonName" and val == hostname:
                    return None

        return ScannerObservation(
            observation_type="certificate_hostname_mismatch",
            target=hostname,
            severity_hint="high",
            evidence={"hostname": hostname, "cert_san": dns_names},
            metadata={
                "check": "hostname_mismatch",
                "category": "tls_analysis",
                "description": "Certificate hostname mismatch",
                "detail": f"Certificate does not match hostname {hostname}",
            },
        )

    @staticmethod
    def _check_self_signed(cert: dict, hostname: str) -> ScannerObservation | None:
        issuer = cert.get("issuer")
        subject = cert.get("subject")
        if issuer and subject and issuer == subject:
            return ScannerObservation(
                observation_type="self_signed_certificate",
                target=hostname,
                severity_hint="high",
                evidence={},
                metadata={
                    "check": "self_signed",
                    "category": "tls_analysis",
                    "description": "Self-signed TLS certificate",
                    "detail": "Certificate issuer matches subject - certificate is self-signed",
                },
            )
        return None

    @staticmethod
    def _check_certificate_chain(cert: dict, hostname: str) -> ScannerObservation | None:
        issuer = cert.get("issuer")
        if not issuer:
            return ScannerObservation(
                observation_type="certificate_chain_incomplete",
                target=hostname,
                severity_hint="medium",
                evidence={},
                metadata={
                    "check": "certificate_chain",
                    "category": "tls_analysis",
                    "description": "Certificate issuer not available",
                    "detail": "Could not verify the full certificate chain",
                },
            )
        return None

    # ------------------------------------------------------------------
    # Protocol checks
    # ------------------------------------------------------------------

    @staticmethod
    def _check_protocol_version(version: str, hostname: str, port: int) -> ScannerObservation | None:
        v = version.lower()
        if "tlsv1" not in v and "tls 1" not in v:
            return None
        if "1.0" in v:
            return ScannerObservation(
                observation_type="weak_tls_protocol",
                target=f"{hostname}:{port}",
                severity_hint="high",
                evidence={"protocol": version},
                metadata={
                    "check": "protocol_version",
                    "category": "tls_analysis",
                    "description": "TLS 1.0 protocol in use",
                    "detail": "TLS 1.0 is deprecated and insecure. Use TLS 1.2 or higher.",
                },
            )
        if "1.1" in v:
            return ScannerObservation(
                observation_type="weak_tls_protocol",
                target=f"{hostname}:{port}",
                severity_hint="high",
                evidence={"protocol": version},
                metadata={
                    "check": "protocol_version",
                    "category": "tls_analysis",
                    "description": "TLS 1.1 protocol in use",
                    "detail": "TLS 1.1 is deprecated and insecure. Use TLS 1.2 or higher.",
                },
            )
        return None

    # ------------------------------------------------------------------
    # Cipher checks
    # ------------------------------------------------------------------

    @staticmethod
    def _check_cipher_strength(cipher_name: str, hostname: str, port: int) -> ScannerObservation | None:
        cipher_upper = cipher_name.upper()
        for prefix in TLSAnalyzer.WEAK_CIPHER_PREFIXES:
            if cipher_upper.startswith(prefix):
                return ScannerObservation(
                    observation_type="weak_cipher_suite",
                    target=f"{hostname}:{port}",
                    severity_hint="high",
                    evidence={"cipher": cipher_name, "reason": f"Uses weak cipher prefix: {prefix}"},
                    metadata={
                        "check": "cipher_strength",
                        "category": "tls_analysis",
                        "description": "Weak cipher suite in use",
                        "detail": f"Server negotiated weak cipher: {cipher_name}",
                    },
                )
        return None

    @staticmethod
    def _connection_failed(hostname: str, port: int) -> ScannerObservation:
        return ScannerObservation(
            observation_type="tls_connection_failed",
            target=f"{hostname}:{port}",
            severity_hint="critical",
            evidence={"hostname": hostname, "port": port},
            metadata={
                "check": "tls_connectivity",
                "category": "tls_analysis",
                "description": "TLS connection failed",
                "detail": f"Could not establish TLS connection to {hostname}:{port}",
            },
        )


def _hostname_matches_any(hostname: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        if pattern.startswith("*."):
            suffix = pattern[1:]
            if hostname.endswith(suffix) and hostname.count(".") == pattern.count("."):
                return True
        elif hostname == pattern:
            return True
    return False
