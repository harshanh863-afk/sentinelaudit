# SentinelAudit — Session Summary

## Goal
Deliver SentinelAudit as a production-ready public website security assessment platform with passive scanning, risk/compliance/privacy intelligence, professional reporting, and anonymous user workflow, deployed on Render + Vercel.

## Constraints & Preferences
- No authentication, user accounts, teams, or dashboards — strictly public anonymous workflow
- Passive-only scanning: scanner emits `ScannerObservation` only; never touches DB
- YAML-based rules, data-driven, fully decoupled from Python code
- SQLAlchemy 2.0, UUID PKs, PostgreSQL, FastAPI, React 18 + TypeScript + Vite + TailwindCSS + shadcn/ui
- JavaScript analyzer is confidence-based only — no exploitation engine
- Rate limiting (5 scans/hour/IP), SSRF protections, environment validation blocks unsafe startup
- Single Docker container for free Render tier — uvicorn + Celery worker via `start.sh`, Celery uses `sqla+` / `db+` PostgreSQL transport
- Two placeholders remain: `change-me-in-production` in `config.py`, `https://your-backend.com` in `vercel.json`

## Progress

### Done
- **Phase A–D.2 (Architecture + Frontend + Backend + Security)**: Complete — 424 backend + 106 scanner tests passing
- **Phase E & F (Audit + Packaging)**: Complete — 39 issues found, 13 fixed; Docker, docs, deployment config done
- **Celery Redis→PostgreSQL migration**: Complete — `sqla+` broker, `db+` backend
- **ScanManager hardened**: `run_with_timeout()` async wrapper, `except Exception: raise exc`, `if session is None` guard  
- **Root cause fix (round 1)**: Rule matcher `startswith` bug fixed
- **Root cause fix (round 2)**: Scanner category mismatches fixed (`technology_fingerprint` → `technology`, `javascript_analysis` → `javascript`)
- **Root cause fix (round 3)**: Data persistence fixed — `title`, `cvss_score`, Evidence, ComplianceMapping now persisted
- **Root cause fix (round 4)**: Debug prints removed, `SeverityLevel(None)` crash fixed
- **Root cause fix (round 5) — THE REAL ROOT CAUSE**: Three class/method name bugs in `scan_manager.py`:
  - `TLSInspector` → `TLSAnalyzer` (class didn't exist)
  - `TechnologyFingerprinter` → `TechFingerprinter` (class didn't exist)
  - `fingerprinter.analyze` → `fingerprinter.fingerprint` (method didn't exist)
  - `started_at` NULL fallback added
- **Pipeline confirmed working**: 14 findings, risk 77.9 (high), 8s duration, 0 errors against example.com
- **Git commit + push**: All fixes pushed to `github.com/harshanh863-afk/sentinelaudit.git`

### Remaining (pre-existing, not blocking pipeline)
1. Dashboard compliance chart always shows 100%
2. PDF download returns HTML instead of PDF
3. Celery dispatch failure silently swallowed (no retry on send)
4. Compliance `passed` column defaults to `True`
5. IPv6 SSRF bypass via hex-encoded addresses
6. JSON rule `contains()` syntax wrong (should be `contains` not `contains()`)
7. Two placeholders need replacement before public release: `change-me-in-production`, `https://your-backend.com`

## Key Files
- `backend/app/services/orchestrator/scan_manager.py` — Scan orchestration (all 3 bugs fixed here)
- `backend/app/services/rule_engine/rule_matcher.py` — Observation→rule matching
- `backend/app/services/reporting/finding_formatter.py` — Finding formatting
- `rules/` — 39 YAML rule files across headers, cookies, tls, dns, technology, javascript
