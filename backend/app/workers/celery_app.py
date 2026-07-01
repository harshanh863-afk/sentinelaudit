"""Celery application configuration for async scan processing."""
import os
from celery import Celery
from app.core.config import settings

DATABASE_URL = settings.database_url
if DATABASE_URL.startswith("postgresql+psycopg2://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql+psycopg2://", "postgresql://")

celery_app = Celery(
    "sentinelaudit",
    broker=f"sqla+{DATABASE_URL}",
    backend=f"db+{DATABASE_URL}",
    include=["app.workers.scan_tasks"],
)

celery_app.conf.update(
    task_track_started=True,
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

celery_app.conf.database_table_names = {
    'task': 'celery_taskmeta',
    'group': 'celery_groupmeta',
}

# Ensure Kombu database transport tables exist prior to polling
try:
    from sqlalchemy import create_engine
    from kombu.transport.sqlalchemy.models import metadata as kombu_metadata

    kombu_engine = create_engine(DATABASE_URL)
    kombu_metadata.create_all(kombu_engine)
    kombu_engine.dispose()
    print("=== Kombu transport tables initialized successfully ===")
except Exception as e:
    import logging
    logger = logging.getLogger(__name__)
    logger.error(f"Failed to explicitly declare Kombu SQLAlchemy tables: {str(e)}", exc_info=True)
