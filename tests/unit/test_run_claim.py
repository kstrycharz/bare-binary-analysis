"""Only one worker may scan a run.

Caught in the field, not in review. The orphan sweep requeued a run at age 399s
while its original task was still inside the static analyzer — the run had been
sitting at `queued` for the whole scan, because the RUNNING transition was
flushed inside the scan's single long transaction and never committed. A second
`scan_run` was dispatched for the same 213 MB artifact: two sets of analyzer
containers, racing to write the same rows.

Two defects, two fixes, and both are tested here because either alone leaves a
window. The transition is committed, so the run stops *looking* abandoned; and
the transition is a conditional UPDATE, so a duplicate delivery loses the race
instead of joining it. Celery is at-least-once by design, which means the
second fix has to hold even when the first one is working.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.models import Run
from core.models.base import Base
from core.models.enums import RunStatus
from core.pipeline.scan import _claim


@pytest.fixture
def sessions() -> Iterator[tuple[Session, Session]]:
    """Two sessions on one database — two workers, as it happens in production."""
    from sqlalchemy.pool import StaticPool

    # StaticPool so both sessions share one in-memory database; without it each
    # connection gets its own and the second worker "loses the race" against a
    # run it cannot see.
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as first, factory() as second:
        yield first, second


def _queued_run(session: Session) -> str:
    run = Run(
        status=RunStatus.QUEUED,
        attested_by="tester",
        attestation_reference="t",
        attested_at=datetime.now(UTC),
    )
    session.add(run)
    session.commit()
    return str(run.id)


class TestClaiming:
    def test_a_queued_run_can_be_claimed(self, sessions: tuple[Session, Session]) -> None:
        first, _ = sessions
        run_id = _queued_run(first)
        assert _claim(run_id, first) is True

    def test_the_second_worker_loses(self, sessions: tuple[Session, Session]) -> None:
        """The whole point. Without this, the requeued task runs a duplicate
        scan of the same artifact alongside the original."""
        first, second = sessions
        run_id = _queued_run(first)
        assert _claim(run_id, first) is True
        assert _claim(run_id, second) is False

    def test_the_claim_is_visible_to_other_connections_immediately(
        self, sessions: tuple[Session, Session]
    ) -> None:
        """A flush would satisfy the claim check within one session and still
        leave every other reader — the dashboard, the API, the orphan sweep —
        seeing `queued`. That is the bug that produced the duplicate."""
        first, second = sessions
        run_id = _queued_run(first)
        _claim(run_id, first)
        assert second.get(Run, run_id).status == RunStatus.RUNNING  # type: ignore[union-attr]

    def test_started_at_is_recorded_with_the_claim(self, sessions: tuple[Session, Session]) -> None:
        """The orphan sweep times a running run out from this. Claiming without
        it leaves a run that can never be recovered."""
        first, _ = sessions
        run_id = _queued_run(first)
        _claim(run_id, first)
        assert first.get(Run, run_id).started_at is not None  # type: ignore[union-attr]

    def test_a_finished_run_cannot_be_reclaimed(self, sessions: tuple[Session, Session]) -> None:
        """A re-delivery arriving after the scan finished must not restart it
        and overwrite a completed run's results."""
        first, _ = sessions
        run_id = _queued_run(first)
        run = first.get(Run, run_id)
        assert run is not None
        run.status = RunStatus.COMPLETED
        first.commit()
        assert _claim(run_id, first) is False

    def test_claiming_a_run_that_does_not_exist_is_false_not_an_exception(
        self, sessions: tuple[Session, Session]
    ) -> None:
        first, _ = sessions
        assert _claim("no-such-run", first) is False
