"""A run whose analyzers did not finish must not report as completed.

The field failure: the static analyzer failed an import, exited 1 in under a
second, and the scan recorded `status=completed, findings=0` for a 213 MB
installer. Nothing had been examined. The gate caught it — that is what
ADR-0018 is for — but the run, the API and the dashboard all said the artifact
was clean, and only the gate disagreed.

So these tests hold two things together: that a degraded stage changes the
run's own status, and that the gate and the run agree about which stages count
as degraded. Those two answers being derived separately is what allowed them to
diverge in the first place.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.models import Run, RunStage
from core.models.base import Base
from core.models.enums import RunStatus, StageStatus
from core.pipeline.gate import degraded_stages as gate_view
from core.pipeline.stages import degraded_stages, describe_degraded


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as active:
        yield active


def _run_with(session: Session, *stages: tuple[str, StageStatus]) -> str:
    run = Run(
        status=RunStatus.RUNNING,
        attested_by="tester",
        attestation_reference="t",
        attested_at=datetime.now(UTC),
    )
    session.add(run)
    session.flush()
    for analyzer, status in stages:
        session.add(RunStage(run_id=run.id, analyzer=analyzer, status=status))
    session.flush()
    return str(run.id)


class TestWhichStagesCount:
    @pytest.mark.parametrize(
        "status",
        [StageStatus.FAILED, StageStatus.TIMEOUT, StageStatus.OOM, StageStatus.TRUNCATED],
    )
    def test_every_incomplete_outcome_degrades(
        self, session: Session, status: StageStatus
    ) -> None:
        """TRUNCATED belongs here as much as FAILED: a partially unpacked
        artifact was partially examined, whatever the exit code said."""
        run_id = _run_with(session, ("static", status))
        assert len(degraded_stages(session, run_id)) == 1

    def test_a_clean_run_has_none(self, session: Session) -> None:
        run_id = _run_with(
            session, ("unpack", StageStatus.COMPLETED), ("static", StageStatus.COMPLETED)
        )
        assert degraded_stages(session, run_id) == []

    def test_a_skipped_stage_is_not_a_degraded_one(self, session: Session) -> None:
        """Skipping an analyzer that had nothing to do is a decision, not a
        failure — treating it as degradation makes every run inconclusive."""
        run_id = _run_with(session, ("dynamic", StageStatus.SKIPPED))
        assert degraded_stages(session, run_id) == []

    def test_ordering_is_stable(self, session: Session) -> None:
        """The description ends up in `run.error` and in the gate output; an
        unstable order makes two identical failures look like different ones."""
        run_id = _run_with(
            session,
            ("static", StageStatus.FAILED),
            ("unpack", StageStatus.TIMEOUT),
            ("recon", StageStatus.OOM),
        )
        assert describe_degraded(degraded_stages(session, run_id)) == [
            "recon (oom)",
            "static (failed)",
            "unpack (timeout)",
        ]


class TestTheGateAndTheRunAgree:
    def test_the_gate_sees_exactly_what_the_run_status_is_derived_from(
        self, session: Session
    ) -> None:
        """The regression guard. If these ever diverge, a run can be displayed
        as completed while the gate calls it inconclusive."""
        run_id = _run_with(
            session, ("static", StageStatus.FAILED), ("unpack", StageStatus.COMPLETED)
        )
        assert gate_view(session, run_id) == describe_degraded(degraded_stages(session, run_id))

    def test_the_gate_reports_the_failed_analyzer_by_name(self, session: Session) -> None:
        """"Scan incomplete" is not actionable; "static (failed)" is."""
        run_id = _run_with(session, ("static", StageStatus.FAILED))
        assert gate_view(session, run_id) == ["static (failed)"]


class TestRunStatus:
    def test_degraded_is_terminal(self) -> None:
        """Otherwise `bare scan` polls a finished run for ever."""
        assert RunStatus.DEGRADED.is_terminal

    def test_degraded_still_has_results_worth_reading(self) -> None:
        """The findings a degraded run *did* produce are real. It is the
        silence about the rest that is not evidence."""
        assert RunStatus.DEGRADED.produced_results
        assert not RunStatus.FAILED.produced_results
