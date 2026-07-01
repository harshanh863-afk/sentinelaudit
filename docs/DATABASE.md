# Database Schema

## Overview

PostgreSQL is the primary data store. The schema is designed around audit-oriented workloads: scans are immutable records, findings are append-only, and reports are materialised views of scan results.

## Entity Relationship Summary

```
User ──1:N──> Project
Project ──1:N──> Target
Target ──1:N──> Scan
Scan ──1:N──> Finding
Scan ──1:N──> Evidence
Finding ──N:1──> Rule
Finding ──1:N──> Evidence
Finding ──1:N──> ComplianceMapping
Project ──1:N──> Report
```

## Enum Definitions

### ScanStatus

```python
PENDING   = "pending"
RUNNING   = "running"
COMPLETED = "completed"
FAILED    = "failed"
```

### SeverityLevel

```python
CRITICAL = "critical"
HIGH     = "high"
MEDIUM   = "medium"
LOW      = "low"
INFO     = "info"
```

### FindingStatus

```python
OPEN           = "open"
CONFIRMED      = "confirmed"
FALSE_POSITIVE = "false_positive"
REMEDIATED     = "remediated"
```

## Entity Definitions

### Users

| Column        | Type           | Notes                        |
|---------------|----------------|------------------------------|
| id            | UUID           | Primary key, default uuid4   |
| email         | VARCHAR(320)   | Unique, indexed              |
| password_hash | VARCHAR(128)   | bcrypt hash                  |
| name          | VARCHAR(255)   |                              |
| is_active     | BOOLEAN        | Default true                 |
| created_at    | TIMESTAMPTZ    | server_default = now()       |
| updated_at    | TIMESTAMPTZ    | onupdate = now()             |

- **Relationships**: `projects` — one-to-many with cascade delete

### Projects

| Column      | Type           | Notes                        |
|-------------|----------------|------------------------------|
| id          | UUID           | Primary key, default uuid4   |
| name        | VARCHAR(255)   |                              |
| description | TEXT           | Nullable                     |
| owner_id    | UUID           | FK → users.id, indexed       |
| created_at  | TIMESTAMPTZ    | server_default = now()       |
| updated_at  | TIMESTAMPTZ    | onupdate = now()             |

- **Relationships**: `owner` → User, `targets` (cascade), `reports` (cascade)

### Targets

| Column     | Type           | Notes                        |
|------------|----------------|------------------------------|
| id         | UUID           | Primary key, default uuid4   |
| project_id | UUID           | FK → projects.id, indexed    |
| url        | VARCHAR(2048)  | Normalised base URL          |
| host       | VARCHAR(255)   | Extracted hostname, indexed  |
| port       | INTEGER        | Nullable                     |
| tags       | JSONB          | Nullable, arbitrary metadata |
| created_at | TIMESTAMPTZ    | server_default = now()       |
| updated_at | TIMESTAMPTZ    | onupdate = now()             |

- **Relationships**: `project` → Project, `scans` (cascade)

### Scans

| Column       | Type           | Notes                        |
|--------------|----------------|------------------------------|
| id           | UUID           | Primary key, default uuid4   |
| target_id    | UUID           | FK → targets.id, indexed     |
| status       | ScanStatus     | Default "pending", indexed   |
| risk_score   | FLOAT          | Nullable, 0.0–1.0           |
| started_at   | TIMESTAMPTZ    | Nullable                     |
| completed_at | TIMESTAMPTZ    | Nullable                     |
| error        | TEXT           | Nullable, failure reason     |

- **Relationships**: `target` → Target, `findings` (cascade), `evidence` (cascade)

### Findings

| Column     | Type          | Notes                        |
|------------|---------------|------------------------------|
| id         | UUID          | Primary key, default uuid4   |
| scan_id    | UUID          | FK → scans.id, indexed       |
| rule_id    | UUID          | FK → rules.id, nullable, indexed |
| severity   | SeverityLevel | indexed                      |
| status     | FindingStatus | Default "open", indexed      |
| passed     | BOOLEAN       | true if the check passed     |
| detail     | TEXT          | Nullable, human-readable     |

- **Relationships**: `scan` → Scan, `rule` → Rule, `evidence` (cascade), `compliance_mappings` (cascade)

### Evidence

| Column     | Type           | Notes                        |
|------------|----------------|------------------------------|
| id         | UUID           | Primary key, default uuid4   |
| scan_id    | UUID           | FK → scans.id, indexed       |
| finding_id | UUID           | FK → findings.id, nullable, indexed |
| type       | VARCHAR(50)    | indexed (e.g. http_headers, certificate, dns_record) |
| data       | JSONB          | Arbitrary structured data    |

- **Relationships**: `scan` → Scan, `finding` → Finding (nullable)

### Rules

| Column      | Type           | Notes                        |
|-------------|----------------|------------------------------|
| id          | UUID           | Primary key, default uuid4   |
| rule_id     | VARCHAR(20)    | Business key (e.g. HTTP-001), UNIQUE, indexed |
| name        | VARCHAR(255)   |                              |
| category    | VARCHAR(50)    | indexed (e.g. http_security, tls_analysis) |
| severity    | SeverityLevel  |                              |
| description | TEXT           | Nullable                     |
| remediation | TEXT           | Nullable                     |
| created_at  | TIMESTAMPTZ    | server_default = now()       |
| updated_at  | TIMESTAMPTZ    | onupdate = now()             |

- **Relationships**: `findings` — one-to-many

### Compliance Mappings

| Column       | Type           | Notes                        |
|--------------|----------------|------------------------------|
| id           | UUID           | Primary key, default uuid4   |
| finding_id   | UUID           | FK → findings.id, indexed    |
| framework    | VARCHAR(50)    | indexed (e.g. owasp_top_10, nist_800_53) |
| control_id   | VARCHAR(50)    |                              |
| control_name | VARCHAR(255)   | Nullable                     |

- **Constraints**: UNIQUE(finding_id, framework, control_id)
- **Relationships**: `finding` → Finding

### Reports

| Column     | Type           | Notes                        |
|------------|----------------|------------------------------|
| id         | UUID           | Primary key, default uuid4   |
| project_id | UUID           | FK → projects.id, indexed    |
| scan_ids   | JSONB          | List of scan UUIDs           |
| format     | VARCHAR(10)    | pdf, html, json              |
| file_path  | VARCHAR(1024)  | Nullable                     |

- **Relationships**: `project` → Project

## Indexing Strategy

- **Foreign keys**: index on all `*_id` columns (already applied in migration)
- **Lookup columns**:
  - `users(email)` — unique
  - `rules(rule_id)` — unique
  - `targets(host)` — frequent host-based queries
  - `scans(status)` — pending-job queue lookups
  - `findings(severity)`, `findings(status)` — filtered queries
  - `evidence(type)` — evidence-type lookups
  - `compliance_mappings(framework)` — framework-based grouping

## Migration Strategy

Migrations use Alembic. The initial migration (`0001_initial_schema.py`) creates all nine tables and their enums.

```bash
cd backend
alembic upgrade head      # apply pending migrations
alembic revision --autogenerate -m "description"   # create new migration
```

## Source

Model definitions: `backend/app/models/`
Migration: `backend/alembic/versions/0001_initial_schema.py`
