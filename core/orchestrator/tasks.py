"""Celery tasks.

M0 ships the operational tasks only — the reaper sweep and a sandbox
smoke-test. The analysis stages (S0–S8) arrive from M1 onward as tasks in this
package, composed with Celery canvas graphs by the run state machine.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import structlog

from core.config import get_settings
from core.orchestrator.celery_app import QUEUE_CONTROL, celery_app

# Celery's autodiscovery imports <package>.tasks and nothing else, so the
# analysis tasks are re-exported here to get registered. Importing them at the
# bottom would be tidier but would not survive celery inspect registered.
from core.orchestrator.scan_tasks import (
    discover_rules_task,
    explain_finding_task,
    investigate_finding_task,
    scan_run,
    summarize_run_task,
    triage_run_task,
)
from core.sandbox import Reaper, SandboxSpec, driver_from_settings
from core.sandbox.images import analyzer_image

log = structlog.get_logger(__name__)

__all__ = [
    "discover_rules_task",
    "explain_finding_task",
    "investigate_finding_task",
    "reap_containers",
    "recover_orphaned_runs",
    "sandbox_smoke_test",
    "scan_run",
    "summarize_run_task",
    "triage_run_task",
]


def _driver() -> Any:
    return driver_from_settings()


def _active_run_ids() -> list[str] | None:
    """Runs the orchestrator currently considers in flight.

    Returns ``None`` until the ``runs`` table exists (M1). ``None`` means
    "liveness unknown", which the reaper handles by falling back to age-based
    cleanup only — conservative in the safe direction. This is a real
    behaviour, not a silent stub: nothing here pretends to know something it
    does not.
    """
    return None


@celery_app.task(name="bare.reap_containers", queue=QUEUE_CONTROL)
def reap_containers() -> dict[str, Any]:
    """Periodic sweep for containers a crashed orchestrator left behind."""
    settings = get_settings()
    driver = _driver()
    try:
        reaper = Reaper(driver, max_age=timedelta(hours=settings.reaper_max_age_hours))
        report = reaper.reap(_active_run_ids())
    except Exception as exc:
        # The sweep failing must not crash beat; it retries in five minutes.
        log.warning("reaper.sweep_failed", error=str(exc))
        return {"inspected": 0, "removed": 0, "error": str(exc)}
    finally:
        driver.close()

    if report.removed_count or report.failed:
        log.info(
            "reaper.sweep",
            inspected=report.inspected,
            removed=report.removed_count,
            failed=len(report.failed),
        )
    return {
        "inspected": report.inspected,
        "removed": report.removed_count,
        "failed": len(report.failed),
    }


@celery_app.task(name="bare.recover_orphaned_runs", queue=QUEUE_CONTROL)
def recover_orphaned_runs() -> dict[str, Any]:
    """Periodic sweep for runs whose Celery task was lost.

    The counterpart to `task_reject_on_worker_lost=False`: that setting stops a
    lost task being retried onto another worker, and this decides what happens
    to the run instead. Without it a scan queued during a worker restart sits
    at `queued` for ever with no error — observed on a 203 MB installer during
    a routine redeploy.

    Requeueing happens here rather than in the sweep so the broker stays the
    task's concern and `core.pipeline.recovery` stays testable without one.
    """
    settings = get_settings()
    from core.db import session_scope
    from core.pipeline.recovery import sweep_orphaned_runs

    try:
        with session_scope() as session:
            sweep = sweep_orphaned_runs(
                session,
                queued_grace_s=settings.orphan_queued_grace_seconds,
                running_timeout_s=settings.orphan_running_timeout_seconds,
                max_requeue_attempts=settings.orphan_max_requeue_attempts,
            )
            report = sweep.to_dict()
            requeue = list(sweep.requeued)
    except Exception as exc:
        # A failing sweep must not crash beat; it runs again next interval.
        log.warning("recovery.sweep_failed", error=str(exc))
        return {"inspected": 0, "requeued": [], "failed": [], "error": str(exc)}

    # Dispatch only after the transaction committed, so a run can never be
    # re-dispatched against an audit entry that was rolled back.
    for run_id in requeue:
        try:
            scan_run.delay(run_id)
        except Exception as exc:
            log.warning("recovery.redispatch_failed", run_id=run_id, error=str(exc))

    if report["requeued"] or report["failed"]:
        log.info("recovery.sweep", **report)
    return report


@celery_app.task(name="bare.sandbox_smoke_test", queue=QUEUE_CONTROL)
def sandbox_smoke_test(run_id: str, staging_dir: str, results_dir: str) -> dict[str, Any]:
    """Run the hello analyzer through the real driver.

    Used by ``bare sandbox hello`` and by the M0 acceptance check. It is
    the end-to-end proof that the boundary works before any analyzer depends
    on it.
    """
    from core.sandbox.spec import INPUT_DIR, OUTPUT_DIR, BindMount, MountMode

    driver = _driver()
    try:
        spec = SandboxSpec(
            image=analyzer_image("hello"),
            run_id=run_id,
            analyzer="hello",
            command=("--probe",),
            timeout_s=60,
            mounts=(
                BindMount(staging_dir, INPUT_DIR, MountMode.READ_ONLY),
                BindMount(results_dir, OUTPUT_DIR, MountMode.READ_WRITE),
            ),
        )
        result = driver.run(spec)
    finally:
        driver.close()

    return {
        "status": str(result.status),
        "exit_code": result.exit_code,
        "duration_s": round(result.duration_s, 2),
        "image_digest": result.image_digest,
        "error": result.error,
    }
