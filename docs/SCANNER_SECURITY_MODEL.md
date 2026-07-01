# Scanner Security Model

## Threat Model

### Trust Assumptions
- Scanner operators are untrusted (public access)
- Scan targets may be malicious (redirect to internal networks)
- Network environment is shared (cloud deployment)

### Attack Surface

| Attack Vector | Target | Impact |
|---|---|---|
| SSRF via URL | Internal cloud metadata | Credential exfiltration |
| DNS rebinding | Internal services | Port scanning |
| Redirect chain | Cloud metadata endpoints | Instance metadata access |
| Malformed input | Scanner parsers | Denial of service |
| Large payloads | Report generator | Resource exhaustion |

## Mitigations

### 1. URL Validation (Input)

**Pre-scan validation:**
- HTTPS scheme required
- Block localhost, loopback, private IPs
- Block cloud metadata IPs (169.254.169.254, 100.100.100.200)
- Block internal hostname TLDs (.internal, .local, .consul)
- Block reserved TLDs (.arpa, .example, .invalid, .localhost, .test)

### 2. DNS Rebinding Protection

**Post-resolution validation:**
- Resolve hostname to IP addresses
- Check all resolved IPs against blocklist
- Block if any IP resolves to private/loopback/metadata range
- Set DNS TTL minimum to prevent rapid rebinding

### 3. Redirect Chain Protection

**During scanning:**
- Maximum 5 redirects allowed
- Validate each redirect target against blocklist
- Block redirects to non-HTTPS URLs
- Block redirects to internal IPs
- Track redirect history to detect loops

### 4. Request Safety

**Scanner-level protections:**
- HTTP GET requests only (no state-changing methods)
- No cookie/credential storage
- No form submission
- No JavaScript execution
- Configurable timeout per request (default 15s)
- Configurable timeout per scan (default 600s)
- Maximum response body size (1MB)

### 5. Resource Isolation

**Process-level protections:**
- Each scan runs in its own task
- Memory limits enforced at Celery worker level
- No filesystem access beyond temporary directory
- Database connection pool limits enforced
- Rate limiting per source IP (5 scans/hour)

## Architecture

```
Untrusted Input (User URL)
    |
    v
URL Validator (input validation)
    |
    v
DNS Resolution (rebinding check)
    |
    v
HTTP Scanner (redirect validation)
    |
    v
Remaining Analyzers (read-only)
    |
    v
Report Generator (no external access)
```

## Compliance

- OWASP A10 (SSRF) — mitigated by URL validation + redirect protection
- OWASP A03 (Injection) — mitigated by input validation + parameterized queries
- OWASP A05 (Security Misconfiguration) — mitigated by hardened CORS/headers
- OWASP A01 (Broken Access Control) — no authentication required (by design)
- CWE-918 (Server-Side Request Forgery) — primary mitigation target
- CWE-601 (URL Redirection) — mitigated by redirect chain validation

## Monitoring

All scanner operations are logged:
- Scan start/completion with duration
- URL validation decisions (allow/block)
- Redirect chain traversal
- Scanner errors with stack context
- Rate limit enforcement events
