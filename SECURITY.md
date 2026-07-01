# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.x     | ✅ Active development |

## Reporting a Vulnerability

SentinelAudit is a security assessment tool. If you discover a vulnerability
in SentinelAudit itself (not a target scanned by it), please report it
privately.

**Do not** open a public GitHub issue for security vulnerabilities.

Email: security@sentinelaudit.dev (placeholder — replace with actual contact)

Please include:
- Description of the vulnerability
- Steps to reproduce
- Affected version(s)
- Potential impact

You should receive a response within 48 hours. If the vulnerability is
confirmed, we will release a fix and credit the reporter.

## Scope

The following are in scope for security reports:
- The SentinelAudit FastAPI backend
- The SentinelAudit React frontend
- The scanner engine
- The rule engine and YAML rule definitions
- Deployment configuration and defaults

The following are out of scope:
- Third-party dependencies (report via their respective channels)
- Targets scanned by SentinelAudit (those are the assessed, not us)

## Safe Scanning

SentinelAudit performs only **passive** security checks:
- No exploitation
- No credential testing
- No destructive requests
- No denial-of-service

URL validation blocks SSRF, DNS rebinding, private network targets,
and cloud metadata endpoints. See `docs/SCANNER_SECURITY_MODEL.md`
for the full threat model.

## Security Headers

All API responses include:
- Strict-Transport-Security
- Content-Security-Policy
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy
- Cache-Control

## Deployment

See `docs/DEPLOYMENT.md` and `docs/DEPLOYMENT_CHECKLIST.md` for
production security configuration.
