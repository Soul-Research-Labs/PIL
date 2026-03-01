"""Celery task queue configuration."""

from celery import Celery

from engine.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "zaseon",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["engine.pipeline.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=600,  # 10 min hard limit
    task_soft_time_limit=300,  # 5 min soft limit
    worker_prefetch_multiplier=1,  # Fair scheduling
    worker_max_tasks_per_child=50,  # Prevent memory leaks
    task_routes={
        "engine.pipeline.tasks.run_scan": {"queue": "scans"},
        "engine.pipeline.tasks.run_quickscan": {"queue": "quickscan"},
        "engine.pipeline.tasks.verify_findings": {"queue": "verification"},
        "engine.pipeline.tasks.generate_report": {"queue": "reports"},
        "engine.pipeline.tasks.run_soul_campaign": {"queue": "soul_fuzzer"},
        "engine.pipeline.tasks.run_soul_quickfuzz": {"queue": "soul_fuzzer"},
    },
)
