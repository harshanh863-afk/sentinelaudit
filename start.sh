#!/bin/bash

echo "=== Launching Lightweight Solo Task Execution Context ==="
export PYTHONPATH=$PWD
export PYTHONUNBUFFERED=1

# Start Celery worker in the background safely using standard inheritance
celery -A app.workers.celery_app worker --pool=solo --concurrency=1 --loglevel=info --polling-interval=1.0 &

sleep 2

echo "Starting FastAPI API Server..."
# Remove 'exec' so the shell stays alive and collects logs from both stdout/stderr streams
uvicorn app.main:app --host 0.0.0.0 --port 8000
