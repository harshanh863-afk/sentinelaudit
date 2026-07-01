#!/bin/bash

echo "=== Launching Lightweight Solo Task Execution Context ==="
PYTHONUNBUFFERED=1 celery -A app.workers.celery_app worker --loglevel=info --pool=solo --concurrency=1 &

sleep 2

echo "Starting FastAPI API Server..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
