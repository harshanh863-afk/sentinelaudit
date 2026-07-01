# Configuration Reference

## Overview

SentinelAudit uses environment variables for all configuration. The application
loads them via `pydantic-settings` (in `backend/app/core/config.py`) and validates
them at startup (in `backend/app/core/environment.py`).

A `.env` file in the `backend/` directory is supported in development.

---

## Environment Mode

| Variable      | Required | Default       | Valid Values                          |
|---------------|----------|---------------|---------------------------------------|
| `ENVIRONMENT` | No       | `development` | `development`, `production`, `testing` |

Production startup validates all required variables and rejects unsafe
configurations (debug mode, wildcard CORS, missing secrets).

---

## Required in Production

| Variable         | Required | Description                            | Production Recommendation                    |
|------------------|----------|----------------------------------------|----------------------------------------------|
| `DATABASE_URL`   | Yes      | PostgreSQL connection string           | Use a managed PostgreSQL (Railway, RDS, etc) |
| `REDIS_URL`      | Yes      | Redis connection string                | Use a managed Redis (Upstash, Redis Cloud)    |
| `SECRET_KEY`     | Yes      | Secret key for session signing         | Minimum 32 characters, use `openssl rand -hex 32` |
| `FRONTEND_URL`   | Yes      | Frontend origin for CORS               | Exact URL (e.g., `https://app.sentinelaudit.com`) |
| `ENVIRONMENT`    | No       | Must be `production`                   | Set to `production`                          |

`SECRET_KEY` must be at least 32 characters. `FRONTEND_URL` must not be `*`
(wildcard) in production.

---

## Optional Settings

| Variable                   | Default               | Description                                      |
|----------------------------|-----------------------|--------------------------------------------------|
| `DEBUG`                    | `false`               | Enable debug mode (rejected in production)       |
| `APP_NAME`                 | `SentinelAudit`       | Application name for API metadata                |
| `APP_VERSION`              | `1.0.0`               | Application version                              |
| `ALLOWED_HOSTS`            | `["*"]`               | Additional allowed hosts                         |
| `SCANNER_TIMEOUT`          | `30`                  | Scanner module timeout in seconds                |
| `MAX_CONCURRENT_SCANS`     | `5`                   | Maximum concurrent scan tasks                    |
| `SCAN_RESULTS_TTL`         | `86400`               | Scan result TTL in seconds (default: 24h)        |
| `PUBLIC_SCAN_MAX_PER_HOUR` | `5`                   | Max public scans per IP per hour                 |
| `PUBLIC_SCAN_TIMEOUT`      | `600`                 | Max scan runtime in seconds (default: 10 min)    |

---

## Example `.env` (Development)

```env
ENVIRONMENT=development
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/sentinelaudit
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=dev-secret-key-min-32-chars-long!!
FRONTEND_URL=http://localhost:5173
DEBUG=true
```

## Example `.env` (Production)

```env
ENVIRONMENT=production
DATABASE_URL=postgresql://user:password@host:5432/sentinelaudit
REDIS_URL=redis://user:password@host:6379
SECRET_KEY=<openssl rand -hex 32 output>
FRONTEND_URL=https://sentinelaudit.vercel.app
DEBUG=false
```

---

## Validation Behaviour

On startup, `backend/app/core/environment.py` runs these checks:

- `ENVIRONMENT` must be one of `development`, `production`, `testing`
- In production:
  - `DATABASE_URL` must not be empty
  - `REDIS_URL` must not be empty
  - `SECRET_KEY` must be >= 32 characters
  - `FRONTEND_URL` must not be the development default
  - `FRONTEND_URL` must not be `*` (wildcard)
  - `DEBUG` must not be `true`, `1`, or `yes`

If any check fails, the process exits immediately with an error message and
does not start the FastAPI server.

---

## CORS Behaviour

| Mode         | `allow_origins`               |
|--------------|-------------------------------|
| Development  | `*` (all origins)             |
| Production   | `[FRONTEND_URL]` (single origin) |

In production, only the configured frontend origin is allowed. Credentials,
all methods, and all headers are permitted as long as the origin matches.
