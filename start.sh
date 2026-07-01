#!/bin/bash

echo "Starting Celery Worker in background..."
stdbuf -oL -eL celery -A app.workers.celery_app worker --loglevel=info --concurrency=1 &

echo "Starting FastAPI API Server..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
