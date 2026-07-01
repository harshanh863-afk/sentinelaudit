# Deployment Guide

## Architecture Overview

```
Frontend (Vercel)
    |
    HTTPS
    |
Backend API (FastAPI) → PostgreSQL
    |                    Redis
    |
Celery Worker
    (Scanner + Engines)
```

## Prerequisites

- Node.js 18+
- Python 3.12+
- PostgreSQL 15+
- Redis 7+
- Vercel account (frontend)
- Cloud hosting account (backend: Railway/Render/Fly.io/AWS)

## Environment Variables

### Backend

| Variable | Required | Default | Description |
|---|---|---|---|
| `ENVIRONMENT` | Yes | `development` | `production` or `development` |
| `DATABASE_URL` | Yes | — | PostgreSQL connection string |
| `REDIS_URL` | Yes | — | Redis connection string |
| `SECRET_KEY` | Yes | — | Cryptographically random key (min 32 chars) |
| `FRONTEND_URL` | Production | `http://localhost:5173` | CORS allowed origin |
| `DEBUG` | No | `false` | Enable debug mode |
| `SCANNER_TIMEOUT` | No | `30` | HTTP request timeout (seconds) |
| `MAX_CONCURRENT_SCANS` | No | `5` | Max simultaneous scans |
| `SCAN_RESULTS_TTL` | No | `86400` | Result retention (seconds) |
| `PUBLIC_SCAN_MAX_PER_HOUR` | No | `5` | Rate limit per IP |
| `PUBLIC_SCAN_TIMEOUT_SECONDS` | No | `600` | Max scan duration |

### Frontend

| Variable | Required | Default | Description |
|---|---|---|---|
| `VITE_API_URL` | Production | `/api` | Backend API base URL |

## Deployment Steps

### 1. Database (PostgreSQL)

```sql
CREATE DATABASE sentinelaudit;
CREATE USER sentinelaudit WITH PASSWORD 'your-strong-password';
GRANT ALL PRIVILEGES ON DATABASE sentinelaudit TO sentinelaudit;
```

Run migrations:
```bash
alembic upgrade head
```

### 2. Redis

Standard Redis 7+ installation. Persistence recommended (AOF + RDB).

### 3. Backend (FastAPI + Celery)

**Option A: Railway**

```bash
# Configure via Railway dashboard:
DATABASE_URL=postgresql://...
REDIS_URL=redis://...
SECRET_KEY=your-random-secret-key
FRONTEND_URL=https://your-frontend.vercel.app
ENVIRONMENT=production
```

**Option B: Docker Compose**

```bash
docker-compose up -d
```

**Option C: Manual**

```bash
pip install -r backend/requirements.txt

# Run migrations
cd backend && alembic upgrade head

# Start API server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4

# Start Celery worker
celery -A app.workers.celery_app worker --loglevel=info --concurrency=2
```

### 4. Frontend (Vercel)

```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
cd frontend
vercel --prod
```

Configure environment variables in Vercel dashboard:
- `VITE_API_URL=https://your-backend.com/api`

## Health Checks

Once deployed, verify:

```bash
GET /health                    # Overall status
GET /health/database           # Database connectivity
GET /health/worker             # Celery worker status
```

Expected response:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "services": {
    "database": "ok",
    "worker": "ok"
  }
}
```

## Post-Deployment Verification

```bash
# 1. Start a scan
curl -X POST https://api.example.com/api/v1/public/scan \
  -H "Content-Type: application/json" \
  -d '{"target_url": "https://example.com"}'

# 2. Check scan status
curl https://api.example.com/api/v1/public/scan/{scan_id}

# 3. Get report
curl https://api.example.com/api/v1/public/report/{scan_id}

# 4. Download formats
curl https://api.example.com/api/v1/public/report/{scan_id}/download/pdf
curl https://api.example.com/api/v1/public/report/{scan_id}/download/html
curl https://api.example.com/api/v1/public/report/{scan_id}/download/json
```

## Scaling

### Horizontal Scaling (Multiple Workers)
- Deploy additional Celery worker instances
- Workers share Redis queue and PostgreSQL database
- FastAPI stateless — can scale horizontally behind load balancer

### Vertical Scaling
- Increase worker concurrency (--concurrency=4)
- Increase PostgreSQL connection pool size
- Allocate more memory for PDF generation

## Monitoring

- Health endpoints for basic status
- Structured JSON logs (stdout)
- Celery Flower for queue monitoring
- PostgreSQL pg_stat_activity for connection monitoring
