"""Recovering runs whose task was lost.

Celery is configured with ``task_reject_on_worker_lost=False`` on purpose: a
worker killed mid-analysis must not have its task silently retried onto another
worker, because analyzer containers are not free and a hung artifact would just
be re-hung. The comment that decision carries has always said "the run state
machine decides retries" — this module is that decision, which until now did
not exist.

Without it the failure is silent and permanent: a scan queued while a worker
restarts is acknowledged, dropped, and the run sits at ``queued`` for ever with
no error, no timeout, and a dashboard row that looks like it is about to start.
Observed in practice on a 203 MB installer during a routine redeploy.

The two cases are deliberately not treated alike:

* **Queued and never started.** No analyzer ran, nothing was consumed, and
  re-dispatching costs one message. These are requeued, a bounded number of
  times, because the honest state is "not attempted yet".
* **Running past every stage timeout.** A worker died mid-analysis, or the
  artifact hung something the watchdog could not reach. Re-running risks
  repeating whatever wedged it, so these fail with a diagnosis. That is
  ADR-0008's posture — a degraded result that says so beats a silent retry.

Attempts are counted from the audit log rather than a column, so the trail an
operator reads is the same one the sweep reasons about.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from core.models import AuditLog, Run, RunStage
from core.models.enums import AuditAction, RunStatus, StageStatus
from core.pipeline.stages import ENRICHMENT_ANALYZERS

log = structlog.get_logger(__name__)

# A queued run is only orphaned if it has been queued longer than a worker
# could plausibly take to pick it up. Short enough that a lost run is noticed
# within a coffee break, long enough that a busy queue is never mistaken for a
# broken one.
DEFAULT_QUEUED_GRACE_S = 300

# A running run is only orphaned once it has outlived every stage timeout with
# room to spare (unpack 900s + static 1800s), so a legitimately slow scan of a
# large installer is never killed by this sweep.
DEFAULT_RUNNING_TIMEOUT_S = 3600

# After this many requeues the problem is not transient. Failing loudly beats
# a run that reappears in the queue for ever.
DEFAULT_MAX_REQUEUE_ATTEMPTS = 2


@dataclass(slots=True)
class RecoverySweep:
    """What one sweep did. Returned so the task can log and dispatch."""

    requeued: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    inspected: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "inspected": self.inspected,
            "requeued": list(self.requeued),
            "failed": list(self.failed),
        }


def _requeue_attempts(session: Session, run_id: str) -> int:
    total = session.scalar(
        select(func.count())
        .select_from(AuditLog)
        .where(AuditLog.run_id == run_id, AuditLog.action == AuditAction.RUN_REQUEUED)
    )
    return int(total or 0)


def _naive_if_needed(moment: datetime, sample: datetime | None) -> datetime:
    """SQLite returns naive datetimes even from timezone-aware columns, so a
    UTC-aware ``now`` raises on comparison. Postgres does not, which is exactly
    why this would have been found in production rather than in a test."""
    if sample is not None and sample.tzinfo is None:
        return moment.replace(tzinfo=None)
    return moment


def sweep_orphaned_runs(
    session: Session,
    *,
    queued_grace_s: int = DEFAULT_QUEUED_GRACE_S,
    running_timeout_s: int = DEFAULT_RUNNING_TIMEOUT_S,
    max_requeue_attempts: int = DEFAULT_MAX_REQUEUE_ATTEMPTS,
    now: datetime | None = None,
) -> RecoverySweep:
    """Find runs whose task was lost and either requeue or fail them.

    Does not dispatch anything itself — it returns the ids to requeue so the
    Celery task owns the broker, and this stays testable without one.
    """
    moment = now or datetime.now(UTC)
    sweep = RecoverySweep()

    candidates = list(
        session.scalars(
            select(Run).where(Run.status.in_([RunStatus.QUEUED, RunStatus.RUNNING]))
        ).all()
    )
    sweep.inspected = len(candidates)

    for run in candidates:
        # `created_at` is always set, so age is always measurable; `started_at`
        # is preferred because a run that began work should be judged from when
        # it began, not from when it was submitted.
        anchor = run.started_at or run.created_at
        reference = _naive_if_needed(moment, anchor)
        age = reference - anchor

        if run.status == RunStatus.QUEUED and run.started_at is None:
            if age < timedelta(seconds=queued_grace_s):
                continue

            attempts = _requeue_attempts(session, run.id)
            if attempts >= max_requeue_attempts:
                _fail(
                    session,
                    run,
                    reference,
                    f"orphaned in the queue: no worker claimed it after "
                    f"{attempts} requeue attempts",
                )
                sweep.failed.append(run.id)
                continue

            session.add(
                AuditLog.record(
                    AuditAction.RUN_REQUEUED,
                    actor="recovery-sweep",
                    run_id=run.id,
                    reason="queued past the grace period with no worker",
                    age_seconds=int(age.total_seconds()),
                    attempt=attempts + 1,
                )
            )
            log.warning(
                "recovery.run_requeued",
                run_id=run.id,
                age_s=int(age.total_seconds()),
                attempt=attempts + 1,
            )
            sweep.requeued.append(run.id)
            continue

        if age >= timedelta(seconds=running_timeout_s):
            _fail(
                session,
                run,
                reference,
                f"orphaned mid-analysis: no progress for "
                f"{int(age.total_seconds())}s, past every stage timeout",
            )
            sweep.failed.append(run.id)

    return sweep


def _fail(session: Session, run: Run, moment: datetime, reason: str) -> None:
    """Mark a run failed with a reason a human can act on.

    The error text matters: "orphaned" tells an operator this was infrastructure
    rather than the artifact, which is a different investigation from a scan
    that genuinely blew up.
    """
    run.status = RunStatus.FAILED
    run.finished_at = moment
    run.error = reason
    session.add(
        AuditLog.record(
            AuditAction.RUN_ORPHANED,
            actor="recovery-sweep",
            run_id=run.id,
            reason=reason,
        )
    )
    log.warning("recovery.run_failed", run_id=run.id, reason=reason)


def fail_stale_enrichment_stages(
    session: Session, *, timeout_s: int, now: datetime | None = None
) -> list[str]:
    """Close enrichment stages that a dead worker left ``running``.

    The run sweep above cannot see them: an enrichment stage starts after its
    run is already terminal (ADR-0034), so no run is left queued or running to
    be found. Without this, a worker restarted in the middle of a Ghidra job
    leaves a stage that reads "running" for ever. Returns the stage ids closed.
    """
    moment = now or datetime.now(UTC)
    closed: list[str] = []
    stages = session.scalars(
        select(RunStage).where(
            RunStage.analyzer.in_(sorted(ENRICHMENT_ANALYZERS)),
            RunStage.status.in_([StageStatus.PENDING, StageStatus.RUNNING]),
        )
    ).all()
    for stage in stages:
        anchor = stage.started_at or stage.created_at
        reference = _naive_if_needed(moment, anchor)
        if reference - anchor < timedelta(seconds=timeout_s):
            continue
        stage.status = StageStatus.FAILED
        stage.finished_at = reference
        stage.error = "orphaned: the worker running this stage stopped before recording a result"
        closed.append(stage.id)
        log.warning(
            "recovery.stage_failed", run_id=stage.run_id, stage_id=stage.id, analyzer=stage.analyzer
        )
    return sorted(closed)
