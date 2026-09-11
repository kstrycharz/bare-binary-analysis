"""Celery application and queue topology.

Queues are split by analyzer class on purpose (§4): Ghidra jobs are slow,
memory-hungry, and the most likely thing to hang. On a shared queue one wedged
Ghidra worker starves the string scanners that produce most findings, so they
get their own lanes and their own worker concurrency.
"""

from __future__ import annotations

from celery import Celery
from kombu import Queue

from core.config import get_settings

# Queue names are referenced by the worker command lines in docker-compose;
# keep them in one place so the two cannot drift.
QUEUE_CONTROL = "control"
QUEUE_UNPACK = "unpack"
QUEUE_STATIC = "static"
QUEUE_GHIDRA = "ghidra"
QUEUE_DYNAMIC = "dynamic"
QUEUE_LLM = "llm"

ALL_QUEUES = (
    QUEUE_CONTROL,
    QUEUE_UNPACK,
    QUEUE_STATIC,
    QUEUE_GHIDRA,
    QUEUE_DYNAMIC,
    QUEUE_LLM,
)


def create_celery() -> Celery:
    settings = get_settings()
    app = Celery("bare", broker=settings.redis_url, backend=settings.redis_url)

    app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
        task_acks_late=True,
        # A worker killed mid-analysis must not have its task silently retried
        # onto another worker: analyzer containers are not free, and a hung
        # artifact would be re-hung. The run state machine decides retries.
        task_reject_on_worker_lost=False,
        worker_prefetch_multiplier=1,
        broker_connection_retry_on_startup=True,
        task_queues=tuple(Queue(name) for name in ALL_QUEUES),
        task_default_queue=QUEUE_CONTROL,
        result_expires=60 * 60 * 24 * 7,
        beat_schedule={
            "reap-orphaned-containers": {
                "task": "bare.reap_containers",
                "schedule": float(settings.reaper_interval_seconds),
                "options": {"queue": QUEUE_CONTROL, "expires": 120},
            },
            # The counterpart to task_reject_on_worker_lost=False above: that
            # setting refuses to retry a lost task, and this decides what
            # becomes of the run instead. Without it a scan queued during a
            # worker restart is orphaned at `queued` for ever.
            "recover-orphaned-runs": {
                "task": "bare.recover_orphaned_runs",
                "schedule": float(settings.orphan_sweep_interval_seconds),
                "options": {"queue": QUEUE_CONTROL, "expires": 120},
            },
        },
    )
    # Lazy on purpose: `force=True` imports core.orchestrator.tasks while this
    # module is still initialising, and tasks.py imports `celery_app` back from
    # here — a circular import that fails at worker startup, not at import time
    # in a test. Celery resolves the deferred discovery on worker finalisation.
    app.autodiscover_tasks(["core.orchestrator"])
    return app


celery_app = create_celery()
