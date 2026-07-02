#!/bin/bash

echo "=== Launching Lightweight Solo Task Execution Context ==="
export PYTHONPATH=$PWD
export PYTHONUNBUFFERED=1

# Start Celery with auto-restart on crash
(
  while true; do
    echo "--- Celery worker starting ---"
    celery -A app.workers.celery_app worker --pool=solo --concurrency=1 --loglevel=info --polling-interval=1.0
    EXIT_CODE=$?
    echo "CRITICAL: Celery worker exited with code $EXIT_CODE — restarting in 3s"
    sleep 3
  done
) &

sleep 2

echo "Starting FastAPI API Server..."
uvicorn app.main:app --host 0.0.0.0 --port 8000
