# Public Scanner Security

This document describes the security measures implemented for SentinelAudit's public scanner.

## Rate Limiting

- **Max 5 scans per hour per IP address**
- Uses in-memory sliding window counter
- Falls back gracefully if Redis is unavailable
- Returns HTTP 429 with remaining count when exceeded
- Keyed by client IP (`X-Forwarded-For` header or direct remote address)

## Target URL Validation

All public scan targets are validated before any scanner runs:

| Blocked Pattern | Example | Reason |
|---|---|---|
| Non-HTTPS | `http://example.com` | Enforce encrypted transport |
| localhost | `http://localhost` | SSRF prevention |
| Loopback IP | `127.0.0.1`, `0.0.0.0` | SSRF prevention |
| Private IPv4 | `10.x.x.x`, `172.16-31.x.x`, `192.168.x.x` | Internal network protection |
| Cloud metadata | `169.254.169.254` | Cloud metadata SSRF |
| IPv6 private | `::1`, `fc00::/7` | IPv6 SSRF prevention |
| Internal hostnames | `*.internal`, `*.local` | DNS rebinding protection |

## Scan Timeout

- **Maximum execution time: 10 minutes (600 seconds)**
- Scans exceeding this timeout are terminated
- Configurable via `public_scan_timeout_seconds` setting

## Safe Scanning Rules

All public scans follow strict passive-only rules:

- **No exploitation** — scanners only observe and report
- **No credential testing** — no login attempts or brute force
- **No destructive requests** — no DELETE, PUT, PATCH, or state-changing methods
- **No content injection** — no form submission or comment posting
- **Read-only analysis** — HTTP GET requests only, DNS lookups, TLS handshakes

## Data Retention

- Scan results retained for 24 hours (configurable via `scan_results_ttl`)
- After retention period, findings and evidence are automatically purged
- Reports must be downloaded before expiry

## Monitoring

- All public scans are logged with timestamp, source IP, and target URL
- Rate limit violations are logged for abuse monitoring
- Failed validations are tracked for pattern analysis

## Responsible Disclosure

SentinelAudit performs passive security assessments only. If you discover a security issue through this tool:

1. Do not attempt further exploitation
2. Report the issue to the website owner following responsible disclosure practices
3. Use the generated report as evidence for your disclosure

## Limitations

- The scanner performs automated passive checks only
- Results are not a substitute for a professional penetration test
- Zero false positive guarantee is not provided
- Dynamic/SPA applications may have limited coverage
