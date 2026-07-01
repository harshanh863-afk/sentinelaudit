# Database Operations

## Overview

SentinelAudit uses PostgreSQL as its primary data store and SQLAlchemy 2.0
as the ORM. This document covers production database operations: connection
management, index strategy, migrations, backup, and recovery.

---

## Connection Pooling

SQLAlchemy's built-in connection pooling is configured in
`backend/app/db/session.py`.

| Setting       | Value | Notes                                  |
|---------------|-------|----------------------------------------|
| `pool_size`   | 10    | Concurrent connections kept in the pool |
| `max_overflow`| 10    | Additional connections allowed beyond pool_size |
| `pool_pre_ping`| true | Verify connections before use (prevents stale connections) |
| `pool_recycle`| 3600  | Recycle connections after 1 hour        |

**Production recommendations:**

- Pool size should match your worker count × threads per worker
- For Celery workers, each worker process maintains its own pool
- Monitor with `SELECT count(*) FROM pg_stat_activity WHERE application_name = 'sentinelaudit'`
- If using PgBouncer, set `pool_pre_ping=False` and let PgBouncer handle connection health

---

## Indexing Strategy

Current indexes (defined in `backend/app/models/`):

| Table                  | Column(s)        | Type       | Purpose                        |
|------------------------|------------------|------------|--------------------------------|
| `users`                | `email`          | UNIQUE     | Login lookup                   |
| `rules`                | `rule_id`        | UNIQUE     | Business key                   |
| `targets`              | `host`           | B-tree     | Host-based queries             |
| `scans`                | `status`         | B-tree     | Pending-job queue              |
| `findings`             | `severity`       | B-tree     | Severity filtering             |
| `findings`             | `status`         | B-tree     | Status filtering               |
| `evidence`             | `type`           | B-tree     | Evidence type lookups          |
| `compliance_mappings`  | `framework`      | B-tree     | Framework grouping             |
| All FK columns (`*_id`) | FK column       | B-tree     | Join performance               |

Maintenance:

```sql
-- Check for unused indexes
SELECT schemaname, tablename, indexname, idx_scan
FROM pg_stat_user_indexes
ORDER BY idx_scan ASC;

-- Reindex when bloat is detected
REINDEX INDEX CONCURRENTLY idx_findings_severity;
```

---

## Migration Process

Migrations use Alembic. Files are in `backend/alembic/versions/`.

**Create a migration:**

```bash
cd backend
alembic revision --autogenerate -m "description of change"
```

**Apply migrations:**

```bash
alembic upgrade head
```

**Rollback one step:**

```bash
alembic downgrade -1
```

### Production Migration Flow

1. Create migration and test locally
2. Run migration against staging database first
3. Take a base backup before applying to production
4. Apply migration during low-traffic window
5. Verify with health checks after migration
6. Monitor for errors in logs

Example safe command:

```bash
# Dry run first
alembic upgrade head --sql > dry_run.sql

# Apply for real
alembic upgrade head
```

---

## Backup Strategy

### Automated Backups

For managed PostgreSQL (Railway, RDS, etc.), enable automated daily backups
with a 7-day retention period.

### Manual Backup

```bash
pg_dump -h <host> -U <user> -d sentinelaudit -F c -f backup_$(date +%Y%m%d).dump
```

### Backup Verification

```bash
# Test backup integrity
pg_restore -l backup_20260101.dump > /dev/null && echo "Backup valid"

# Restore to a test database
createdb sentinelaudit_restore_test
pg_restore -d sentinelaudit_restore_test backup_20260101.dump
```

### Backup Schedule

| Frequency | Type        | Retention |
|-----------|-------------|-----------|
| Daily     | Full backup | 7 days    |
| Weekly    | Full backup | 4 weeks   |
| Monthly   | Full backup | 12 months |

---

## Recovery Strategy

### Point-in-Time Recovery (PITR)

Requires WAL archiving to be enabled on the PostgreSQL instance.

```bash
# Restore to a specific timestamp
pg_ctl -D /var/lib/postgresql/data stop
rm -rf /var/lib/postgresql/data
pg_basebackup -h <primary> -D /var/lib/postgresql/data -X stream
# Configure recovery.conf with restore_command and recovery_target_time
```

### Disaster Recovery

1. Provision a new PostgreSQL instance
2. Restore the most recent backup
3. Apply any WAL archives for PITR
4. Update `DATABASE_URL` in environment
5. Restart the application
6. Verify with health checks

```bash
# Full restore
createdb sentinelaudit
pg_restore -d sentinelaudit --clean --if-exists latest_backup.dump
alembic upgrade head
```

---

## Schema Overview

See [DATABASE.md](./DATABASE.md) for full schema documentation (tables,
columns, relationships, enums).

---

## Monitoring Queries

```sql
-- Active connections
SELECT count(*) FROM pg_stat_activity WHERE state = 'active';

-- Long-running queries
SELECT pid, now() - pg_stat_activity.query_start AS duration, query
FROM pg_stat_activity
WHERE state = 'active' AND now() - pg_stat_activity.query_start > interval '5 minutes';

-- Table sizes
SELECT relname, n_live_tup, n_dead_tup, pg_size_pretty(pg_total_relation_size(relid))
FROM pg_stat_user_tables
ORDER BY n_dead_tup DESC;

-- Connection pool usage
SELECT count(*) FILTER (WHERE state = 'active') AS active,
       count(*) FILTER (WHERE state = 'idle') AS idle
FROM pg_stat_activity;
```
