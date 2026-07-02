# SentinelAudit

Automated web security posture assessment platform — passive scanning, risk scoring, compliance mapping, and professional reporting.

[![Tests](https://img.shields.io/badge/tests-530%20passing-brightgreen)](#)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](#)
[![Node](https://img.shields.io/badge/node-20%2B-green)](#)
[![License](https://img.shields.io/badge/license-MIT-blue)](#)

---

## Quick Start (2 minutes)

```bash
git clone https://github.com/your-org/sentinelaudit.git
cd sentinelaudit
docker compose up --build
```

Open http://localhost:5173, enter a URL, view your report.

---

## Features

- **Passive Scanning** — HTTP security headers, TLS, DNS, cookie security, CORS, technology fingerprinting. No exploitation, no destructive requests.
- **Version-Aware Detection** — Identifies software versions (nginx, Apache, React, Angular, etc.) from headers, HTML, scripts. Evaluates lifecycle: Supported, EOL, Outdated, or Known Vulnerable.
- **CVE Intelligence** — Automated CVE enrichment via NVD and OSV.dev APIs. Provider abstraction layer enables future add-ons (VulnDB, GitHub Advisory). Local caching with 1-hour TTL. Graceful degradation — never blocks scans.
- **Evidence-Based Confidence Scoring** — Multi-factor confidence model: observation count, evidence completeness, scanner agreement, verification, reliability, version certainty, request success, false-positive penalty.
- **Enterprise Risk Engine** — Multi-dimensional scoring: Technical (severity + CVSS + exploitability), Business Risk, Confidence Score, Coverage Score, Risk Distribution. Formula: `overall = technical × 0.35 + business × 0.25 + confidence × 0.15 + coverage × 0.15 + penalty × 0.10`.
- **Advanced Scanner Reliability** — Per-scanner tracking: execution time, retry count, timeout reason, network failures, partial failures, skipped checks, recovery attempts.
- **Rule Validation** — Validates all YAML rules during startup: duplicate IDs, invalid regex, missing fields, malformed references. Never silently ignores invalid rules.
- **Compliance Mapping** — Maps findings to OWASP Top 10, NIST 800-53, PCI DSS v4.0, ISO 27001, and 34+ other frameworks.
- **Privacy Assessment** — GDPR, CCPA, COPPA, cookie compliance, data exposure checks.
- **Professional Reports** — Executive summaries, management summaries, technical summaries, top risks, security strengths, attack surface summary, remediation roadmap, risk heat map, score breakdowns, finding trends, compliance summary. Export as JSON, HTML, PDF, SARIF 2.1.0, CycloneDX 1.4, or SPDX 2.3.
- **Framework-Aligned** — 38 security frameworks and standards supported, data-driven via YAML rules, decoupled from scanner code.
- **Enterprise Exports** — JSON (full scan data), SARIF 2.1.0 (GitHub Security), CycloneDX 1.4 (SBOM), SPDX 2.3 (SBOM).
- **Webhook Notifications** — Configurable POST notifications on scan.completed, finding.critical, finding.new, scan.failed events.
- **Performance Optimisation** — Parallel scanner execution, async I/O, retry logic with exponential backoff.

---

## Project Structure

```
sentinelaudit/
├── backend/             # FastAPI REST API (Python)
│   ├── app/
│   │   ├── core/        # Config, security, middleware
│   │   ├── api/v1/      # Versioned API endpoints
│   │   ├── models/      # SQLAlchemy ORM models
│   │   ├── schemas/     # Pydantic validation schemas
│   │   ├── services/
│   │   │   ├── risk_engine/    # Risk calculator, confidence, CVE, compliance, grades
│   │   │   ├── rule_engine/    # Rule loader, matcher, validator, seeder
│   │   │   ├── reporting/      # Professional reports, HTML/PDF generation
│   │   │   ├── orchestrator/   # Scan manager, pipeline
│   │   │   ├── enterprise/     # Webhooks, scan comparison, exports
│   │   │   └── cve/            # CVE provider abstraction (NVD, OSV)
│   │   └── db/          # Database session management
│   └── requirements.txt
├── frontend/            # React 18 SPA (TypeScript, Vite)
│   ├── src/
│   │   ├── pages/       # Route pages
│   │   ├── components/  # Shared UI components
│   │   └── api/         # API client
│   └── package.json
├── scanner/             # Standalone scanning package
│   └── sentinelaudit_scanner/
│       ├── core/        # Engine, protocols
│       └── checks/      # Modular security checks
├── rules/               # YAML rule definitions
├── tests/               # Backend + scanner tests
├── docker-compose.yml   # Full-stack deployment
└── docs/                # Documentation
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scan` | Submit URL for scanning (rate-limited) |
| `GET` | `/api/v1/scan/{id}` | Poll scan status |
| `GET` | `/api/v1/report/{id}` | Get JSON report |
| `GET` | `/api/v1/report/{id}/download/{format}` | Download report (json/html/pdf) |
| `GET` | `/api/v1/exports/json/{scan_id}` | Export findings as JSON |
| `GET` | `/api/v1/exports/sarif/{scan_id}` | Export findings as SARIF 2.1.0 |
| `GET` | `/api/v1/exports/cyclonedx/{scan_id}` | Export findings as CycloneDX 1.4 BOM |
| `GET` | `/api/v1/exports/spdx/{scan_id}` | Export findings as SPDX 2.3 SBOM |
| `GET` | `/health` | Health check |
| `GET` | `/api/v1/scan/rate-limit-status` | Check remaining scans |

---

## Supported Frameworks

OWASP Top 10 (2021), NIST SP 800-53 Rev 5, PCI DSS v4.0, ISO 27001:2022, SOC 2, HIPAA, GDPR, CCPA, COPPA, CIS Controls v8, NIST CSF 1.1, FedRAMP, CMMC 2.0, FISMA, SOX, NYDFS, LGPD, PIPEDA, APRA CPS 234, MAS TRM, OWASP ASVS 4.0, OWASP Mobile Top 10, OWASP API Security Top 10, OWASP ProActive Controls, CWE Top 25, CAPEC, MITRE ATT&CK, NIST SP 800-171, ISO 27701, ISO 22301, COBIT 2019, ITIL 4, BSI C5, ENS (Spain), TISAX, PCI DSS 3DS, NIST AI RMF, OWASP Top 10 for LLMs.

---

## Deployment

### Docker (recommended)

```bash
docker compose up --build
```

### Backend (standalone)

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # edit credentials
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Frontend (standalone)

```bash
cd frontend
npm install
npm run dev
```

### Vercel (frontend) + Railway (backend)

See [docs/DEPLOYMENT_CHECKLIST.md](docs/DEPLOYMENT_CHECKLIST.md) for step-by-step instructions.

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, TypeScript, Vite, TailwindCSS, shadcn/ui, TanStack Query, Framer Motion |
| Backend | FastAPI, SQLAlchemy 2.0, Celery, Pydantic v2, Alembic |
| Database | PostgreSQL 16 |
| Cache | Redis 7 |
| Scanner | Pure Python, httpx, YAML rules |
| Deployment | Docker, Docker Compose, Vercel, Railway |

---

## Documentation

- [DEPLOYMENT_CHECKLIST.md](docs/DEPLOYMENT_CHECKLIST.md) — Production deployment steps
- [FINAL_AUDIT_REPORT.md](docs/FINAL_AUDIT_REPORT.md) — Full system audit
- [MANUAL_CONFIGURATION_AUDIT.md](docs/MANUAL_CONFIGURATION_AUDIT.md) — Configuration review
- [CONFIGURATION.md](docs/CONFIGURATION.md) — Environment variables
- [DATABASE_OPERATIONS.md](docs/DATABASE_OPERATIONS.md) — DB management
- [CONTRIBUTING.md](CONTRIBUTING.md) — How to contribute
- [SECURITY.md](SECURITY.md) — Security policy
- [RULE_COVERAGE_AUDIT.md](docs/RULE_COVERAGE_AUDIT.md) — Rule completeness
- [FINAL_TEST_REPORT.md](docs/FINAL_TEST_REPORT.md) — Test results

---

## License

MIT License. See [LICENSE](LICENSE).

## Screenshots

> Screenshots coming soon. In the meantime, run `docker compose up` to see the live application.
