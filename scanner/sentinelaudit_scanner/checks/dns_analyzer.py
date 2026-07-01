"""DNS security analyzer - SPF, DMARC, DKIM, DNSSEC, and CAA assessment.

Produces ScannerObservation objects only - no database writes, no findings.
"""

import asyncio
import re

from sentinelaudit_scanner.models.observation import ScannerObservation


class DNSAnalyzer:
    """Analyzes DNS security records: SPF, DMARC, DKIM, DNSSEC, CAA."""

    MAX_SPF_LOOKUPS = 10

    async def analyze(self, domain: str) -> list[ScannerObservation]:
        observations: list[ScannerObservation] = []

        spf = await self._query_txt(domain, "v=spf1")
        if not spf:
            observations.append(self._missing_spf(domain))
        else:
            spf_record = spf[0] if spf else ""
            misconfigs = self._check_spf_misconfiguration(domain, spf_record)
            observations.extend(misconfigs)

        dmarc = await self._query_txt(f"_dmarc.{domain}", "v=DMARC1")
        if not dmarc:
            observations.append(self._missing_dmarc(domain))
        elif dmarc:
            obs = self._check_dmarc_policy(domain, dmarc)
            if obs:
                observations.append(obs)

        has_dkim = await self._detect_dkim(domain)
        if not has_dkim:
            observations.append(self._missing_dkim(domain))

        has_dnssec = await self._check_dnssec(domain)
        if not has_dnssec:
            observations.append(self._missing_dnssec(domain))

        caa = await self._query_caa(domain)
        if not caa:
            observations.append(self._missing_caa(domain))

        return observations

    # ------------------------------------------------------------------
    # DNS query methods - override in tests
    # ------------------------------------------------------------------

    async def _query_txt(self, domain: str, prefix: str = "") -> list[str]:
        """Query TXT records for a domain."""
        try:
            records = await self._nslookup("TXT", domain)
            if prefix:
                return [r for r in records if prefix.lower() in r.lower()]
            return records
        except Exception:
            return []

    async def _detect_dkim(self, domain: str) -> bool:
        """Detect if DKIM records exist for common selectors."""
        selectors = ["default", "dkim", "mail", "google", "selector1", "selector2"]
        for sel in selectors:
            try:
                records = await self._nslookup("TXT", f"{sel}._domainkey.{domain}")
                if any("v=DKIM1" in r for r in records):
                    return True
            except Exception:
                continue
        return False

    async def _check_dnssec(self, domain: str) -> bool:
        """Check if DNSSEC is enabled (RRSIG or DNSKEY records exist)."""
        try:
            records = await self._nslookup("DNSKEY", domain)
            if records:
                return True
        except Exception:
            pass
        try:
            records = await self._nslookup("RRSIG", domain)
            if records:
                return True
        except Exception:
            pass
        return False

    async def _query_caa(self, domain: str) -> list[str]:
        """Query CAA records for a domain."""
        try:
            return await self._nslookup("CAA", domain)
        except Exception:
            return []

    async def _nslookup(self, record_type: str, domain: str) -> list[str]:
        """Perform a DNS lookup using nslookup subprocess."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "nslookup", "-type=" + record_type, domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            output = stdout.decode("utf-8", errors="replace")
            return self._parse_nslookup_output(output, record_type)
        except (asyncio.TimeoutError, FileNotFoundError):
            return []

    @staticmethod
    def _parse_nslookup_output(output: str, record_type: str) -> list[str]:
        records: list[str] = []
        for line in output.splitlines():
            line = line.strip()
            if record_type in ("TXT", "SPF"):
                m = re.search(r'text\s*=\s*"([^"]*)"', line, re.IGNORECASE)
                if m:
                    records.append(m.group(1))
            elif record_type == "CAA":
                m = re.search(r'CAA\s+\d+\s+(\w+)\s+"([^"]*)"', line, re.IGNORECASE)
                if m:
                    records.append(f"{m.group(1)} {m.group(2)}")
            elif record_type in ("DNSKEY", "RRSIG"):
                if record_type in line.upper():
                    records.append(line)
        return records

    # ------------------------------------------------------------------
    # SPF misconfiguration checks
    # ------------------------------------------------------------------

    @classmethod
    def _check_spf_misconfiguration(cls, domain: str, spf_record: str) -> list[ScannerObservation]:
        """Analyse SPF record for common misconfigurations."""
        obs: list[ScannerObservation] = []
        lower = spf_record.lower()

        # +all: allows any server to send mail as the domain
        if "+all" in lower:
            obs.append(cls._spf_allow_all(domain, spf_record))

        # ?all: neutral — no guidance, trivially bypassed
        if "?all" in lower:
            obs.append(cls._spf_neutral(domain, spf_record))

        # Count DNS lookups (include:, redirect=, exists:, ptr:).
        # RFC 7208 limits the total to 10.
        lookup_count = (
            lower.count("include:")
            + lower.count("redirect=")
            + lower.count("exists:")
            + lower.count("ptr:")
        )
        if lookup_count > cls.MAX_SPF_LOOKUPS:
            obs.append(cls._spf_excessive_lookups(domain, spf_record, lookup_count))

        # Missing -all (hard fail): SPF can still be bypassed.
        # Does not apply if +all or ?all is already present (those are
        # more specific misconfigurations).
        if "-all" not in lower and "+all" not in lower and "?all" not in lower:
            obs.append(cls._spf_no_hardfail(domain, spf_record))

        return obs

    @staticmethod
    def _spf_allow_all(domain: str, spf_record: str) -> ScannerObservation:
        return ScannerObservation(
            observation_type="spf_allow_all",
            target=domain,
            severity_hint="critical",
            evidence={"domain": domain, "spf_record": spf_record, "mechanism": "+all"},
            metadata={
                "check": "spf_misconfiguration",
                "category": "dns_analysis",
                "description": "SPF record allows all senders (+all)",
                "detail": "SPF record contains +all, allowing any server to send email as the domain",
            },
        )

    @staticmethod
    def _spf_neutral(domain: str, spf_record: str) -> ScannerObservation:
        return ScannerObservation(
            observation_type="spf_neutral",
            target=domain,
            severity_hint="medium",
            evidence={"domain": domain, "spf_record": spf_record, "mechanism": "?all"},
            metadata={
                "check": "spf_misconfiguration",
                "category": "dns_analysis",
                "description": "SPF record has neutral policy (?all)",
                "detail": "SPF record uses ?all which provides no guidance to receiving mail servers",
            },
        )

    @staticmethod
    def _spf_excessive_lookups(domain: str, spf_record: str,
                                lookup_count: int) -> ScannerObservation:
        return ScannerObservation(
            observation_type="spf_excessive_lookups",
            target=domain,
            severity_hint="medium",
            evidence={
                "domain": domain,
                "spf_record": spf_record,
                "lookup_count": lookup_count,
                "max_allowed": 10,
            },
            metadata={
                "check": "spf_misconfiguration",
                "category": "dns_analysis",
                "description": "SPF record exceeds DNS lookup limit",
                "detail": f"SPF record requires {lookup_count} lookups; RFC 7208 limit is 10",
            },
        )

    @staticmethod
    def _spf_no_hardfail(domain: str, spf_record: str) -> ScannerObservation:
        return ScannerObservation(
            observation_type="spf_no_hardfail",
            target=domain,
            severity_hint="low",
            evidence={"domain": domain, "spf_record": spf_record},
            metadata={
                "check": "spf_misconfiguration",
                "category": "dns_analysis",
                "description": "SPF record missing hard fail (-all)",
                "detail": "SPF record does not end with -all, allowing unauthorized servers to send mail",
            },
        )

    # ------------------------------------------------------------------
    # Observation factories (existing checks)
    # ------------------------------------------------------------------

    @staticmethod
    def _missing_spf(domain: str) -> ScannerObservation:
        return ScannerObservation(
            observation_type="missing_spf_record",
            target=domain,
            severity_hint="medium",
            evidence={"domain": domain, "record_type": "SPF"},
            metadata={
                "check": "spf_record",
                "category": "dns_analysis",
                "description": "Missing SPF record",
                "detail": f"No SPF record found for {domain}",
            },
        )

    @staticmethod
    def _missing_dmarc(domain: str) -> ScannerObservation:
        return ScannerObservation(
            observation_type="missing_dmarc_record",
            target=domain,
            severity_hint="medium",
            evidence={"domain": domain, "record_type": "DMARC"},
            metadata={
                "check": "dmarc_record",
                "category": "dns_analysis",
                "description": "Missing DMARC record",
                "detail": f"No DMARC record found for {domain}",
            },
        )

    @staticmethod
    def _check_dmarc_policy(domain: str, records: list[str]) -> ScannerObservation | None:
        for rec in records:
            if "p=none" in rec.lower():
                return ScannerObservation(
                    observation_type="weak_dmarc_policy",
                    target=domain,
                    severity_hint="low",
                    evidence={"domain": domain, "dmarc_record": rec},
                    metadata={
                        "check": "dmarc_policy",
                        "category": "dns_analysis",
                        "description": "Weak DMARC policy (p=none)",
                        "detail": "DMARC policy is set to 'none' - no protection against spoofing",
                    },
                )
        return None

    @staticmethod
    def _missing_dkim(domain: str) -> ScannerObservation:
        return ScannerObservation(
            observation_type="missing_dkim_record",
            target=domain,
            severity_hint="low",
            evidence={"domain": domain, "record_type": "DKIM"},
            metadata={
                "check": "dkim_record",
                "category": "dns_analysis",
                "description": "No DKIM record detected",
                "detail": f"No DKIM record found for {domain}",
            },
        )

    @staticmethod
    def _missing_dnssec(domain: str) -> ScannerObservation:
        return ScannerObservation(
            observation_type="missing_dnssec",
            target=domain,
            severity_hint="medium",
            evidence={"domain": domain, "record_type": "DNSSEC"},
            metadata={
                "check": "dnssec",
                "category": "dns_analysis",
                "description": "DNSSEC not enabled",
                "detail": f"Domain {domain} does not have DNSSEC enabled",
            },
        )

    @staticmethod
    def _missing_caa(domain: str) -> ScannerObservation:
        return ScannerObservation(
            observation_type="missing_caa_record",
            target=domain,
            severity_hint="low",
            evidence={"domain": domain, "record_type": "CAA"},
            metadata={
                "check": "caa_record",
                "category": "dns_analysis",
                "description": "Missing CAA record",
                "detail": f"No CAA record found for {domain}",
            },
        )
