"""
Celery application configuration.
"""

from celery import Celery
from core.config import settings

celery_app = Celery(
    "antimalware_worker",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["workers.tasks"]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_routes={
        "workers.tasks.static_analysis_task": {"queue": "static"},
        "workers.tasks.dynamic_analysis_task": {"queue": "dynamic"},
        "workers.tasks.vt_lookup_task": {"queue": "triage"},
    },
    task_always_eager=settings.celery_task_always_eager
)

if __name__ == "__main__":
    celery_app.start()
