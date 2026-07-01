#!/bin/bash

echo "Starting Celery Worker in background..."
celery -A app.workers.celery_app worker --loglevel=info --concurrency=1 > /tmp/celery.log 2>&1 &

sleep 2
echo "=== Celery Initialization Log Dump ==="
cat /tmp/celery.log
echo "======================================="

echo "Starting FastAPI API Server..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
