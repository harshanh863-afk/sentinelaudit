# Deployment Checklist

## Before Deployment

### Environment Variables

- [ ] Set `ENVIRONMENT=production`
- [ ] Set `DATABASE_URL` (PostgreSQL connection string)
- [ ] Set `REDIS_URL` (Redis connection string)
- [ ] Set `SECRET_KEY` (min 32 chars, use `openssl rand -hex 32`)
- [ ] Set `FRONTEND_URL` (exact URL, e.g., `https://app.sentinelaudit.com`)
- [ ] Verify `DEBUG=false`
- [ ] Verify `FRONTEND_URL` is not `*`
- [ ] Verify `SECRET_KEY` is >= 32 characters

### Database

- [ ] Provision PostgreSQL 14+ instance
- [ ] Run `alembic upgrade head` to apply migrations
- [ ] Verify database connection with `GET /health/database`
- [ ] Enable automated daily backups (7-day retention)
- [ ] Configure connection pooling (defaults: pool_size=10, max_overflow=10)

### Redis

- [ ] Provision Redis 6+ instance
- [ ] Verify Redis connection
- [ ] Configure maxmemory and eviction policy

---

## Deployment Steps

### 1. Backend (FastAPI)

**Option A: Railway / Render / Fly.io**

- [ ] Set all environment variables in platform dashboard
- [ ] Set build command: `cd backend && pip install -r requirements.txt`
- [ ] Set start command: `cd backend && uvicorn app.main:app --host 0.0.0.0 --port 8000`
- [ ] Deploy and verify health endpoint returns 200

**Option B: Docker**

- [ ] Build image: `docker build -f backend/Dockerfile -t sentinelaudit-api .`
- [ ] Run container with all env vars
- [ ] Verify health endpoint

**Option C: Manual**

- [ ] `cd backend`
- [ ] `pip install -r requirements.txt`
- [ ] `uvicorn app.main:app --host 0.0.0.0 --port 8000`

### 2. Celery Worker

- [ ] Deploy `sentinelaudit_scanner` package alongside worker
- [ ] Set start command:
  ```bash
  cd backend && celery -A app.workers.celery_app worker --loglevel=info --concurrency=4
  ```
- [ ] Verify worker connects to Redis
- [ ] Verify worker health via `GET /health/worker`

### 3. Frontend (Vercel)

- [ ] Connect GitHub repo to Vercel
- [ ] Set `VITE_API_URL` to production backend URL
- [ ] Set `SENTINEL_AUDIT_BACKEND_URL` for API proxy
- [ ] Deploy
- [ ] Verify SPA routing works (all paths → `index.html`)

---

## Post-Deployment Verification

### API Health

```bash
curl https://api.sentinelaudit.com/health
# Expected: {"status":"healthy","version":"1.0.0","timestamp":"..."}

curl https://api.sentinelaudit.com/health/database
# Expected: {"status":"healthy","service":"database"}

curl https://api.sentinelaudit.com/health/worker
# Expected: {"status":"healthy","service":"worker","workers":["..."]}
```

### Security Headers

```bash
curl -I https://api.sentinelaudit.com/health
# Verify:
#   strict-transport-security
#   content-security-policy
#   x-content-type-options: nosniff
#   x-frame-options: DENY
#   referrer-policy
#   permissions-policy
#   cache-control: no-store
```

### CORS

```bash
curl -X OPTIONS https://api.sentinelaudit.com/health \
  -H "Origin: https://app.sentinelaudit.com" \
  -H "Access-Control-Request-Method: GET"
# Expected: access-control-allow-origin: https://app.sentinelaudit.com
```

### SSRF / URL Validation

```bash
curl -X POST https://api.sentinelaudit.com/api/v1/public/scan \
  -H "Content-Type: application/json" \
  -d '{"target_url":"https://169.254.169.254"}'
# Expected: 400 error (blocked private IP)

curl -X POST https://api.sentinelaudit.com/api/v1/public/scan \
  -H "Content-Type: application/json" \
  -d '{"target_url":"https://example.com"}'
# Expected: 201 with scan_id
```

### Rate Limiting

```bash
for i in {1..6}; do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST \
    https://api.sentinelaudit.com/api/v1/public/scan \
    -H "Content-Type: application/json" \
    -d '{"target_url":"https://example.com"}'
done
# Expected: first 5 return 201, 6th returns 429
```

### End-to-End Scan

```bash
# Submit scan
SCAN_ID=$(curl -s -X POST https://api.sentinelaudit.com/api/v1/public/scan \
  -H "Content-Type: application/json" \
  -d '{"target_url":"https://example.com"}' | jq -r '.scan_id')

# Poll until complete
while true; do
  STATUS=$(curl -s https://api.sentinelaudit.com/api/v1/public/scan/$SCAN_ID | jq -r '.status')
  echo "Status: $STATUS"
  [ "$STATUS" = "completed" ] || [ "$STATUS" = "failed" ] && break
  sleep 2
done

# Download report
curl -o report.json https://api.sentinelaudit.com/api/v1/public/report/$SCAN_ID/download/json
curl -o report.html https://api.sentinelaudit.com/api/v1/public/report/$SCAN_ID/download/html
```

---

## Monitoring

- [ ] Set up uptime monitoring (e.g., Better Uptime, Pingdom)
- [ ] Monitor scan error rate (>5% flags investigation)
- [ ] Watch Redis memory usage under scan load
- [ ] Monitor PostgreSQL connection pool saturation
- [ ] Review structured JSON logs for anomalies

---

## Scaling

- [ ] Increase Celery `--concurrency` with more workers
- [ ] Increase PostgreSQL `pool_size` if connections exhausted
- [ ] Add Redis replica if scan queue backs up
- [ ] Switch to Redis-backed rate limiter if in-memory proves insufficient

---

## Rollback Plan

1. **Frontend:** Vercel instant rollback to previous deployment
2. **Backend:** Revert environment to previous version
3. **Database:** Restore from backup (`pg_restore`) if migration fails
4. **DNS:** Point to previous backend if needed
