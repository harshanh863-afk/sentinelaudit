#!/bin/bash

echo "=== Launching Celery Worker Diagnostics ==="

(
    celery -A app.workers.celery_app worker --loglevel=info --concurrency=1 2>&1
    echo "CRITICAL: Celery worker process exited unexpectedly with exit code $?"
) &

sleep 3

echo "Starting FastAPI API Server..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
