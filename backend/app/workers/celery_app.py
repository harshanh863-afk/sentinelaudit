"""Celery application configuration for async scan processing."""

import os

from celery import Celery

redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_ssl_config = {}
if redis_url.startswith("rediss://"):
    import ssl
    celery_ssl_config = {
        "broker_use_ssl": {
            "ssl_cert_reqs": ssl.CERT_NONE,
        },
        "redis_backend_use_ssl": {
            "ssl_cert_reqs": ssl.CERT_NONE,
        },
    }

celery_app = Celery(
    "sentinelaudit",
    broker=redis_url,
    backend=redis_url,
    **celery_ssl_config,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_soft_time_limit=int(os.getenv("SCANNER_TIMEOUT", "30")) * 2,
    task_time_limit=int(os.getenv("SCANNER_TIMEOUT", "30")) * 3,
)
