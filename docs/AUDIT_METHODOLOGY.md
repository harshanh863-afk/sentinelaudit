# SentinelAudit Audit Methodology

## Overview

SentinelAudit performs **passive, non-intrusive security assessments** of public websites.
No exploitation, no authentication bypass, no destructive testing. All checks are performed
using publicly available information and standard protocol handshakes.

## Authorization Requirements

- Assessments must only be performed against targets you own or have written authorization to test
- Unauthorized scanning may violate computer fraud and abuse laws
- Always review and comply with the target's `robots.txt` and Terms of Service
- Rate limiting is applied to avoid impacting target availability

## Assessment Phases

### Phase 1: Information Gathering

**Objective:** Collect publicly available information about the target.

| Step | Technique | Information Obtained |
|------|-----------|---------------------|
| 1.1 | DNS Resolution | A/AAAA records, authoritative nameservers |
| 1.2 | DNS Record Analysis | SPF, DKIM, DMARC, MX, CAA, TXT records |
| 1.3 | Technology Detection | Web server, framework, CMS, CDN, analytics |
| 1.4 | HTTP Header Analysis | Server, security headers, cookies, caching |

**Scope:**
- Passive DNS queries (no zone transfers)
- HTTP request/response analysis
- No port scanning beyond standard web ports (80, 443)

### Phase 2: Security Configuration Review

**Objective:** Evaluate security configuration of the web server and TLS.

| Step | Technique | Assessment |
|------|-----------|------------|
| 2.1 | TLS Version Check | Supported TLS 1.2, 1.3; deprecated 1.0, 1.1 |
| 2.2 | Cipher Suite Analysis | Strength of accepted cipher suites |
| 2.3 | Certificate Validation | Expiry, hostname match, chain completeness, CA trust |
| 2.4 | Security Headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc. |
| 2.5 | Cookie Security | Secure, HttpOnly, SameSite attributes |

**Scope:**
- TLS handshake inspection (no deep packet inspection)
- No private key access or decryption
- Standard HTTP header observation

### Phase 3: Application Security Review

**Objective:** Identify common web application security weaknesses.

| Step | Technique | Assessment |
|------|-----------|------------|
| 3.1 | OWASP Top 10 Checks | Access control, crypto, injection, misconfiguration |
| 3.2 | JavaScript Analysis | Source map exposure, credential patterns, dangerous APIs |
| 3.3 | API Security | Endpoint discovery, authentication indicators |
| 3.4 | Dependency Check | Outdated libraries, known vulnerabilities |

**Scope:**
- Static analysis of client-side code only
- No SQL injection testing
- No authentication bypass attempts
- No fuzzing or brute force

### Phase 4: Compliance Assessment

**Objective:** Map findings to regulatory and standards frameworks.

| Framework | Controls Assessed | Assessment Method |
|-----------|------------------|-------------------|
| OWASP Top 10 | 10 categories | Finding-to-category mapping |
| OWASP ASVS | 14 verification levels | Control requirement matching |
| NIST CSF | 19 controls | Security function mapping |
| CIS Controls v8 | 18 safeguards | Control verification |
| ISO 27001 | 23 controls | Annex A control matching |
| PCI DSS 4.0 | 23 requirements | Requirement verification |
| GDPR | 10 articles | Privacy control assessment |
| HIPAA | 14 safeguards | Security rule mapping |
| SOC 2 | 13 criteria | Trust service criteria |
| + 28 more frameworks | Varies | Cross-reference engine |

**Scope:**
- Compliance is assessed against *detectable* controls only
- Some controls require internal audit (documentation, processes)
- Results indicate external security posture, not full compliance

### Phase 5: Risk Analysis

**Objective:** Quantify and prioritize identified risks.

| Factor | Methodology |
|--------|------------|
| CVSS Score | CVSS v3.1 base score calculation |
| Severity | Critical (9+), High (7-8.9), Medium (4-6.9), Low (1-3.9), Info (0) |
| Exploitability | Network accessibility, attack complexity, privileges required |
| Business Impact | Data exposure, service disruption, compliance penalties |
| Confidence Level | Confidence in detection accuracy |

**Risk Formula:**
```
risk_score = severity_weight + cvss_contribution + exploitability_weight
             + confidence_weight + compliance_weight
```

**Limitations:**
- CVSS scores are estimated based on observable characteristics
- Exploitability assessment is based on configuration, not active exploitation
- Business impact is a general estimate, not specific to the organization

## Assessment Types

### Quick Scan (2-3 minutes)
- DNS analysis
- TLS version and certificate check
- Security headers
- Basic technology detection

### Full Scan (5-10 minutes)
- All Quick Scan checks
- Comprehensive TLS analysis
- JavaScript analysis
- All security headers
- Cookie audit
- Framework detection
- Compliance mapping

### Bug Bounty Scan (10-15 minutes)
- All Full Scan checks
- Deep JavaScript analysis
- Source map inspection
- Detailed dependency checking
- Full compliance report

### Compliance Scan (15-20 minutes)
- All Full Scan checks
- All 38+ framework assessments
- Privacy assessment
- Detailed compliance report
- Remediation roadmap

## Data Collected

| Data Type | Collected | Stored | Retention |
|-----------|-----------|--------|-----------|
| DNS Records | Yes | Scan results | Deleted with scan |
| HTTP Headers | Yes | Anonymized | Deleted with scan |
| TLS Certificates | Public info only | Certificate metadata | Deleted with scan |
| JavaScript URLs | URLs only | URL list | Deleted with scan |
| Page Content | None | N/A | N/A |
| User Credentials | Never | N/A | N/A |
| Session Data | Never | N/A | N/A |
| PII | Never | N/A | N/A |

## Ethical Guidelines

1. **No Exploitation:** No attempt to exploit discovered vulnerabilities
2. **No Data Extraction:** No extraction of data beyond public metadata
3. **Rate Limiting:** Requests are rate-limited to prevent DoS
4. **Respect robots.txt:** Scanner respects crawl delay directives
5. **Transparency:** All scan activity is logged for accountability
6. **Consent:** Scans require explicit user initiation
7. **Non-Destructive:** No write operations, no state changes
8. **Privacy:** No collection of personal user data

## Report Structure

Every assessment generates a professional report containing:

1. **Cover Page** — Target, date, risk grade
2. **Executive Summary** — Overall score, critical/high counts, compliance %
3. **Risk Overview** — Severity distribution, compliance scores
4. **Technical Findings** — Grouped by severity with full details
5. **Compliance Section** — Per-framework scores and control assessment
6. **Privacy Section** — GDPR, CCPA, cookie compliance
7. **Technical Appendix** — Methodology, evidence, scanner details

## Disclaimer

SentinelAudit provides an **indication** of external security posture based on
passive observation. It cannot detect all vulnerabilities, and a clean report
does not guarantee the absence of security issues. Regular professional
penetration testing is recommended for comprehensive security assurance.
