# Security Assessment Methodology

## Assessment Scope

SentinelAudit performs **external posture assessments** focused on publicly accessible services. Each scan targets a single host or domain and evaluates the following layers:

| Layer | Checks | Category |
|-------|--------|----------|
| TLS/SSL | Certificate validity, protocol version, cipher strength, chain trust | `tls_analysis` |
| HTTP Security | Header presence (CSP, HSTS, X-Frame-Options), cookie flags, information disclosure | `http_security` |
| DNS Security | SPF, DMARC, DKIM, DNSSEC, CAA records | `dns_analysis` |
| Technology Stack | Server header, framework detection, infrastructure fingerprinting | `tech_fingerprint` |

Scans do **not** cover:
- Internal network segmentation testing
- Web application logic flaws (business logic, authorisation bypass)
- Social engineering or physical security
- Source code analysis or dependency scanning

## Passive vs Active Checks

### Passive Checks
Passive checks analyse responses from the target without sending malicious or intrusive payloads:
- TLS handshake inspection (protocol version, cipher negotiation, certificate fields)
- HTTP response header analysis
- DNS record queries (TXT, CNAME, MX, CAA, DNSKEY)
- Cookie attribute inspection
- Server header and framework fingerprinting

Passive checks are **safe to run against any target** without risk of service disruption.

### Active Checks (Future)
Active checks may send crafted payloads to identify vulnerabilities:
- Path traversal attempts
- Injection testing (XSS, SQLi, command injection)
- Authentication bypass probes

Active checks **require explicit authorisation** and are disabled by default. They must be enabled through scan profiles.

## Authorization Requirements

### Pre-Scan Authorization
Before running any scan, the user must confirm one of the following:
1. The target domain is owned or operated by the user's organisation
2. Written authorisation (e.g., bug bounty program, penetration testing agreement) covers the target
3. The target is a designated test environment explicitly authorised for security testing

### Scope Confirmation
Each scan profile includes a mandatory scope confirmation field. The scanner will refuse to run if:
- The target is not covered by an active authorisation record
- The target appears on a denylist (opt-out domains, government systems without explicit clearance)

### Rate Limiting
All checks implement automatic rate limiting and throttling to avoid denial-of-service conditions. Default intervals:
- DNS queries: 50ms between queries
- HTTP requests: 100ms between requests
- TLS handshakes: 200ms between handshakes

## Framework Alignment

SentinelAudit rules are mapped to the following industry frameworks:

### OWASP Application Security Verification Standard (ASVS)
- **A3**: Broken Authentication — TLS configuration, certificate validation
- **A4**: Insecure Design — Missing security controls (SPF, DMARC, CSP)
- **A5**: Security Misconfiguration — Weak ciphers, unnecessary header exposure
- **A6**: Vulnerable Components — Outdated technology detection

Mapping: Each rule's `compliance` section includes `framework: "owasp"` with the relevant ASVS control ID.

### NIST Cybersecurity Framework (CSF)
- **SC-7**: Boundary Protection — Email authentication (SPF, DMARC, DKIM)
- **SC-8(1)**: Cryptographic Protection — TLS protocol version and cipher strength
- **SC-12**: Cryptographic Key Management — Certificate lifecycle, CAA records
- **SC-20**: Secure Name/Address Resolution — DNSSEC
- **RA-5**: Vulnerability Scanning — Scan methodology and severity classification

### CIS Controls
- **Control 3.10**: Encrypt All Sensitive Information in Transit — TLS configuration, certificate validation
- **Control 3.11**: Email Security — SPF, DMARC, DKIM
- **Control 3.12**: DNS Security — DNSSEC
- **Control 4.1**: Secure Configuration — HTTP security headers, information disclosure

### ISO/IEC 27001
- **A.8.23**: Information Security — Email authentication and DNS security
- **A.8.25**: Cryptographic Controls — TLS protocols, ciphers, certificates

### PCI DSS v4.0
- **Requirement 4.1**: Use Strong Cryptography — TLS 1.2+, strong ciphers, certificate validity
- **Requirement 6.2**: Secure Configurations — HTTP security headers

### CWE (Common Weakness Enumeration)
- **CWE-295**: Improper Certificate Validation
- **CWE-297**: Improper Validation of Certificate with Host Mismatch
- **CWE-326**: Inadequate Encryption Strength
- **CWE-319**: Cleartext Transmission of Sensitive Information

## Severity Classification

| Level | Score Range | Description |
|-------|------------|-------------|
| Critical | 85–100 | Immediate risk: expired certificate, TLS connection failure |
| High | 65–84 | Significant risk: weak protocol, hostname mismatch, missing critical headers |
| Medium | 35–64 | Moderate risk: missing SPF/DMARC, expiring certificate, missing DNSSEC |
| Low | 5–34 | Minor risk: weak DMARC policy, information disclosure, missing CAA |
| Info | 0–4 | Informational: technology fingerprint, server header |

Severity scores are calculated using a weighted formula:
- **Base rule severity** (40% weight)
- **Exploitability** (30% weight) — how easily the finding can be exploited
- **Confidence** (20% weight) — how certain the scanner is about the finding
- **Compliance impact** (10% weight) — number and severity of compliance violations

## Limitations

1. **Point-in-time assessment**: Results reflect the target's state at the moment of scanning. Configurations may change.

2. **Passive-only detection**: The scanner does not exploit or verify vulnerabilities. A finding indicates a configuration observation, not confirmed exploitability.

3. **DNS recursion dependency**: DNS checks depend on the configured resolver. Results may differ based on resolver location and configuration.

4. **TLS handshake limitation**: The scanner connects using default TLS settings. Servers with client-certificate requirements or custom cipher order may not be fully assessed.

5. **False positive potential**: Some findings may be false positives due to:
   - WAF or reverse proxy interference
   - Custom application behaviour
   - Network-level controls not visible to the scanner

6. **No authentication testing**: The scanner does not test authenticated endpoints or session management.

7. **Scope boundaries**: The assessment covers only the specified target. Related infrastructure (CDN origins, subdomains) requires separate targets.
