"""Celery wiring.

These are cheap and they matter: the failure mode they cover is a worker that
crash-loops on startup, which is invisible to every other test in the suite and
only shows up when someone runs the stack.
"""

from __future__ import annotations

from core.orchestrator.celery_app import (
    ALL_QUEUES,
    QUEUE_CONTROL,
    QUEUE_GHIDRA,
    QUEUE_STATIC,
    celery_app,
)


class TestTaskRegistration:
    def test_tasks_module_imports_without_a_circular_import(self) -> None:
        """`autodiscover_tasks(force=True)` imports tasks.py while celery_app.py
        is still initialising, and tasks.py imports back from it. That crashes
        the worker at startup and nothing else in the suite notices."""
        import core.orchestrator.tasks  # noqa: F401

        assert "bare.reap_containers" in celery_app.tasks

    def test_reaper_runs_on_the_control_queue(self) -> None:
        """Not on an analyzer queue: the sweep must still happen when every
        analyzer lane is saturated or wedged."""
        import core.orchestrator.tasks  # noqa: F401

        task = celery_app.tasks["bare.reap_containers"]
        assert task.queue == QUEUE_CONTROL


class TestQueueTopology:
    def test_every_declared_queue_exists(self) -> None:
        declared = {queue.name for queue in celery_app.conf.task_queues}
        assert declared == set(ALL_QUEUES)

    def test_slow_analyzers_have_their_own_lane(self) -> None:
        """Ghidra is the most likely thing to hang. On a shared queue one
        wedged job starves the string scanners that find most secrets."""
        assert QUEUE_GHIDRA != QUEUE_STATIC
        assert {QUEUE_GHIDRA, QUEUE_STATIC} <= set(ALL_QUEUES)

    def test_prefetch_is_one_so_a_long_job_does_not_hoard_work(self) -> None:
        assert celery_app.conf.worker_prefetch_multiplier == 1

    def test_beat_schedules_the_reaper_sweep(self) -> None:
        schedule = celery_app.conf.beat_schedule
        assert "reap-orphaned-containers" in schedule
        assert schedule["reap-orphaned-containers"]["task"] == "bare.reap_containers"


class TestSerialization:
    def test_only_json_is_accepted(self) -> None:
        """Pickle would let anything that can reach Redis execute code in the
        worker, which holds the Docker socket."""
        assert celery_app.conf.task_serializer == "json"
        assert celery_app.conf.accept_content == ["json"]
