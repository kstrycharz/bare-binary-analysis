"""The orphaned-run sweep.

Runs against a real schema in SQLite rather than mocks, because the thing being
tested is a decision made from timestamps and audit rows — exactly what a mock
would let drift.

The bug this exists for was silent and permanent: Celery is deliberately
configured not to retry a task lost with its worker, so a scan queued during a
worker restart was acknowledged, dropped, and left at `queued` for ever with no
error and no timeout. Observed on a 203 MB installer during a redeploy.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.models import AuditLog, Run
from core.models.base import Base
from core.models.enums import AuditAction, RunStatus
from core.pipeline.recovery import (
    DEFAULT_QUEUED_GRACE_S,
    DEFAULT_RUNNING_TIMEOUT_S,
    sweep_orphaned_runs,
)

NOW = datetime(2026, 8, 25, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as active:
        yield active
    engine.dispose()


def _run(
    session: Session,
    run_id: str,
    *,
    status: str,
    age_s: int,
    started_age_s: int | None = None,
) -> Run:
    created = NOW - timedelta(seconds=age_s)
    run = Run(
        id=run_id,
        status=status,
        profile="standard",
        attested_by="kyle",
        attestation_reference="SEC-1",
        attested_at=created,
        created_at=created,
    )
    if started_age_s is not None:
        run.started_at = NOW - timedelta(seconds=started_age_s)
    session.add(run)
    session.flush()
    return run


class TestQueuedRuns:
    def test_recent_queued_run_is_left_alone(self, session: Session) -> None:
        """A busy queue must never be mistaken for a broken one."""
        _run(session, "fresh", status=RunStatus.QUEUED, age_s=30)
        sweep = sweep_orphaned_runs(session, now=NOW)
        assert sweep.requeued == []
        assert sweep.failed == []

    def test_run_queued_past_the_grace_period_is_requeued(self, session: Session) -> None:
        _run(session, "orphan", status=RunStatus.QUEUED, age_s=DEFAULT_QUEUED_GRACE_S + 60)
        sweep = sweep_orphaned_runs(session, now=NOW)
        assert sweep.requeued == ["orphan"]
        assert sweep.failed == []

    def test_requeue_is_audited(self, session: Session) -> None:
        """Attempts are counted from the audit log, so the trail an operator
        reads is the one the sweep reasons about."""
        _run(session, "orphan", status=RunStatus.QUEUED, age_s=900)
        sweep_orphaned_runs(session, now=NOW)
        entries = session.query(AuditLog).filter_by(action=AuditAction.RUN_REQUEUED).all()
        assert len(entries) == 1
        assert entries[0].run_id == "orphan"
        assert entries[0].detail["attempt"] == 1

    def test_a_requeued_run_stays_queued(self, session: Session) -> None:
        """Requeueing is not a status change: nothing ran, so the honest state
        is still 'not attempted yet'."""
        run = _run(session, "orphan", status=RunStatus.QUEUED, age_s=900)
        sweep_orphaned_runs(session, now=NOW)
        assert run.status == RunStatus.QUEUED
        assert run.error is None

    def test_requeue_attempts_are_bounded(self, session: Session) -> None:
        """A run that reappears in the queue for ever is worse than one that
        fails with a reason."""
        _run(session, "orphan", status=RunStatus.QUEUED, age_s=900)
        for _ in range(2):
            sweep_orphaned_runs(session, now=NOW)

        sweep = sweep_orphaned_runs(session, now=NOW)
        assert sweep.requeued == []
        assert sweep.failed == ["orphan"]

    def test_run_failed_after_exhausting_attempts_says_why(self, session: Session) -> None:
        run = _run(session, "orphan", status=RunStatus.QUEUED, age_s=900)
        for _ in range(3):
            sweep_orphaned_runs(session, now=NOW)
        assert run.status == RunStatus.FAILED
        assert run.error is not None
        assert "orphaned" in run.error
        assert run.finished_at is not None

    def test_max_attempts_is_configurable(self, session: Session) -> None:
        _run(session, "orphan", status=RunStatus.QUEUED, age_s=900)
        sweep = sweep_orphaned_runs(session, now=NOW, max_requeue_attempts=0)
        assert sweep.requeued == []
        assert sweep.failed == ["orphan"]


class TestRunningRuns:
    def test_a_running_scan_within_its_timeout_is_untouched(self, session: Session) -> None:
        """Stage timeouts total 2700s. A large installer legitimately takes a
        long time, and this sweep must never be what kills it."""
        _run(
            session,
            "slow",
            status=RunStatus.RUNNING,
            age_s=2000,
            started_age_s=2000,
        )
        sweep = sweep_orphaned_runs(session, now=NOW)
        assert sweep.failed == []
        assert sweep.requeued == []

    def test_a_run_past_every_stage_timeout_is_failed(self, session: Session) -> None:
        run = _run(
            session,
            "wedged",
            status=RunStatus.RUNNING,
            age_s=DEFAULT_RUNNING_TIMEOUT_S + 120,
            started_age_s=DEFAULT_RUNNING_TIMEOUT_S + 120,
        )
        sweep = sweep_orphaned_runs(session, now=NOW)
        assert sweep.failed == ["wedged"]
        assert run.status == RunStatus.FAILED
        assert "orphaned mid-analysis" in (run.error or "")

    def test_a_running_run_is_never_requeued(self, session: Session) -> None:
        """A worker died mid-analysis. Re-running risks repeating whatever
        wedged it, so this fails rather than retries — ADR-0008's posture."""
        _run(
            session,
            "wedged",
            status=RunStatus.RUNNING,
            age_s=99_999,
            started_age_s=99_999,
        )
        sweep = sweep_orphaned_runs(session, now=NOW)
        assert sweep.requeued == []
        assert sweep.failed == ["wedged"]

    def test_age_is_measured_from_start_not_submission(self, session: Session) -> None:
        """A run submitted hours ago but started a minute ago is healthy."""
        _run(
            session,
            "just-started",
            status=RunStatus.RUNNING,
            age_s=99_999,
            started_age_s=60,
        )
        assert sweep_orphaned_runs(session, now=NOW).failed == []

    def test_failure_is_audited(self, session: Session) -> None:
        _run(session, "wedged", status=RunStatus.RUNNING, age_s=99_999, started_age_s=99_999)
        sweep_orphaned_runs(session, now=NOW)
        entries = session.query(AuditLog).filter_by(action=AuditAction.RUN_ORPHANED).all()
        assert len(entries) == 1
        assert entries[0].run_id == "wedged"


class TestScope:
    @pytest.mark.parametrize("status", [RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED])
    def test_terminal_runs_are_never_touched(self, session: Session, status: str) -> None:
        run = _run(session, "done", status=status, age_s=99_999, started_age_s=99_999)
        sweep = sweep_orphaned_runs(session, now=NOW)
        assert sweep.inspected == 0
        assert run.status == status

    def test_a_healthy_stack_reports_nothing(self, session: Session) -> None:
        _run(session, "a", status=RunStatus.QUEUED, age_s=10)
        _run(session, "b", status=RunStatus.RUNNING, age_s=60, started_age_s=60)
        sweep = sweep_orphaned_runs(session, now=NOW)
        assert sweep.to_dict() == {"inspected": 2, "requeued": [], "failed": []}

    def test_mixed_fleet_is_handled_in_one_pass(self, session: Session) -> None:
        _run(session, "fresh", status=RunStatus.QUEUED, age_s=10)
        _run(session, "orphan", status=RunStatus.QUEUED, age_s=900)
        _run(session, "wedged", status=RunStatus.RUNNING, age_s=99_999, started_age_s=99_999)
        _run(session, "healthy", status=RunStatus.RUNNING, age_s=120, started_age_s=120)

        sweep = sweep_orphaned_runs(session, now=NOW)
        assert sweep.inspected == 4
        assert sweep.requeued == ["orphan"]
        assert sweep.failed == ["wedged"]
