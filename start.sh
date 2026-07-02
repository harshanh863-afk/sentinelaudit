#!/bin/bash

echo "=== Launching Lightweight Solo Task Execution Context ==="
export PYTHONPATH=$PWD
export PYTHONUNBUFFERED=1

# Verify DATABASE_URL exists before starting
if [ -z "$DATABASE_URL" ]; then
  echo "FATAL: DATABASE_URL is not set!"
  exit 1
fi

# Start Celery with explicit environment check
(
  while true; do
    echo "--- Celery worker starting with Database: ${DATABASE_URL:0:20}... ---"
    celery -A app.workers.celery_app worker --pool=solo --concurrency=1 --loglevel=info --without-gossip --without-mingle
    EXIT_CODE=$?
    echo "CRITICAL: Celery worker exited with code $EXIT_CODE — restarting in 3s"
    sleep 3
  done
) &

sleep 5

echo "Starting FastAPI API Server..."
uvicorn app.main:app --host 0.0.0.0 --port 8000
