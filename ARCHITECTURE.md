# Architecture

## Overview

SentinelAudit follows a modular, service-oriented architecture with four primary components:

```
User → Frontend (React) → API (FastAPI) → Scanner Engine → Checks
                                              ↓
                                         Rule Engine (YAML)
                                              ↓
                                         Report Generator
                                              ↓
                                         Database / Storage
```

## Component Design

### Backend (`backend/`)

FastAPI-based REST API responsible for:
- Authentication and authorization
- Scan job management (CRUD)
- Results aggregation and storage
- Report generation triggers
- API gateway for the frontend

Key modules:
- `app/core/` — Configuration, security, middleware
- `app/api/v1/` — Versioned API endpoints
- `app/models/` — SQLAlchemy ORM models
- `app/schemas/` — Pydantic validation schemas
- `app/services/` — Business logic layer
- `app/db/` — Database session management

### Frontend (`frontend/`)

React 18 single-page application with TypeScript. Serves as the user interface for:
- Creating and monitoring scans
- Viewing results and risk scores
- Generating and downloading reports
- Managing targets and configurations

### Scanner (`scanner/`)

Standalone Python package that can be used independently or orchestrated by the backend. Uses a plugin-style architecture:

- `ScanEngine` orchestrates check execution
- Each `SecurityCheck` implements a defined protocol
- Checks are independent, async, and composable
- Results are aggregated into a `ScanReport`

Check modules:
- `http_checks` — Security headers, HTTP methods, redirects
- `tls_checks` — Certificate validation, cipher analysis
- `dns_checks` — SPF, DMARC, DKIM, MX analysis
- `tech_fingerprint` — Technology detection via headers/HTML
- `vuln_checks` — Pattern-based vulnerability detection

### Rules (`rules/`)

YAML-based rule definitions decouple detection logic from check implementation. Each rule specifies:
- `id` — Unique rule identifier
- `name` — Human-readable name
- `category` — Maps to a check module
- `severity` — Critical/High/Medium/Low
- `description` — What the rule detects
- `remediation` — How to fix the issue
- `references` — External links for further reading

Rules are loaded at scan time and matched against check results.

### Reports (`reports/`)

Output directory for generated security reports. Supported formats will include PDF, HTML, and JSON.

## Data Flow

1. User submits a target URL via the frontend.
2. Backend creates a scan job and enqueues it.
3. Scanner engine loads applicable rules.
4. Each check module runs against the target.
5. Results are matched against rules for categorization.
6. Risk score is calculated based on severity and pass/fail ratio.
7. Results are persisted and returned to the frontend.
8. User can generate a formatted report.

## Infrastructure

- **PostgreSQL** — Primary data store for scan history and user data.
- **Redis** — Job queue (via Celery) and caching layer.
- **Docker Compose** — Local development and deployment orchestration.
