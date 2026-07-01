# SentinelAudit

Automated web security posture assessment platform — passive scanning, risk scoring, compliance mapping, and professional reporting.

[![Tests](https://img.shields.io/badge/tests-353%20passing-brightgreen)](#)
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
- **Risk Scoring** — CVSS-based severity, business impact, exploit likelihood, automated score calculation.
- **Compliance Mapping** — Maps findings to OWASP Top 10, NIST 800-53, PCI DSS v4.0, ISO 27001, and 34+ other frameworks.
- **Privacy Assessment** — GDPR, CCPA, COPPA, cookie compliance, data exposure checks.
- **Professional Reports** — Executive summaries, severity breakdowns, compliance tables, privacy scores, evidence with hashes. Export as JSON, HTML, or PDF (A4-formatted HTML with print CSS).
- **Framework-Aligned** — 38 security frameworks and standards supported, data-driven via YAML rules, decoupled from scanner code.

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
│   │   ├── services/    # Business logic
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
