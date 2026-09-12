"""The phase a running scan reports.

This is what the progress bar advances on, so it has to be derived from state
the pipeline actually wrote rather than from elapsed time. A bar that moves on
a clock tells the operator nothing about whether a five-minute static stage is
working or wedged, which is the only question they opened the page to answer.

The two phases with no stage row of their own — `index` and `report` — are the
ones worth testing hardest. They are the pipeline doing its own work between
analyzers, they take tens of seconds on a large installer, and before they were
named they were exactly the windows in which the UI appeared to hang.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from api.routers.runs import SCAN_PHASES, _expected_duration_s, _phase
from core.models import Artifact, Run, RunStage
from core.models.base import Base
from core.models.enums import ArtifactKind, RunStatus, StageStatus

NOW = datetime(2026, 8, 26, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as active:
        yield active


def _run(session: Session, status: RunStatus = RunStatus.RUNNING) -> Run:
    run = Run(
        status=status,
        attested_by="tester",
        attestation_reference="t",
        attested_at=NOW,
    )
    session.add(run)
    session.flush()
    return run


def _stages(session: Session, run: Run, **by_analyzer: StageStatus) -> list[RunStage]:
    made = []
    for analyzer, status in by_analyzer.items():
        stage = RunStage(run_id=run.id, analyzer=analyzer, status=status)
        session.add(stage)
        made.append(stage)
    session.flush()
    return made


class TestPhases:
    def test_no_stages_yet_is_queued(self, session: Session) -> None:
        run = _run(session)
        assert _phase(run, []) == "queued"

    def test_unpack_running(self, session: Session) -> None:
        run = _run(session)
        assert _phase(run, _stages(session, run, unpack=StageStatus.RUNNING)) == "unpack"

    def test_unpack_finished_and_static_not_started_is_index(self, session: Session) -> None:
        """The gap nobody names. On a 213 MB installer this is 69 000 artifact
        rows being written, and it looked like a hang."""
        run = _run(session)
        assert _phase(run, _stages(session, run, unpack=StageStatus.COMPLETED)) == "index"

    def test_static_running(self, session: Session) -> None:
        run = _run(session)
        stages = _stages(session, run, unpack=StageStatus.COMPLETED, static=StageStatus.RUNNING)
        assert _phase(run, stages) == "static"

    def test_static_finished_but_run_is_not_is_report(self, session: Session) -> None:
        """Evidence is being correlated into findings and the manifest written.
        Also slow, also previously invisible."""
        run = _run(session)
        stages = _stages(session, run, unpack=StageStatus.COMPLETED, static=StageStatus.COMPLETED)
        assert _phase(run, stages) == "report"

    @pytest.mark.parametrize(
        "status",
        [RunStatus.COMPLETED, RunStatus.DEGRADED, RunStatus.FAILED, RunStatus.CANCELLED],
    )
    def test_every_terminal_status_is_done(self, session: Session, status: RunStatus) -> None:
        """Including DEGRADED. A run whose analyzer failed is finished, and a
        progress panel that keeps spinning on it hides the report."""
        run = _run(session, status)
        stages = _stages(session, run, unpack=StageStatus.COMPLETED, static=StageStatus.FAILED)
        assert _phase(run, stages) == "done"

    def test_a_degraded_static_stage_still_reaches_report(self, session: Session) -> None:
        """A failed analyzer does not leave the bar stuck mid-scan while the
        pipeline finishes writing what it did get."""
        run = _run(session)
        stages = _stages(session, run, unpack=StageStatus.COMPLETED, static=StageStatus.FAILED)
        assert _phase(run, stages) == "report"

    def test_a_stage_row_that_has_not_started_does_not_advance_the_phase(
        self, session: Session
    ) -> None:
        """`RunStage.status` defaults to PENDING, and the row is committed
        before its container starts. Treating "exists" as "finished" reported
        `report` for the whole six-minute static scan — the bar sat one phase
        from the end while the work had barely begun. Caught by watching a real
        scan, which is the only place the default was ever visible."""
        run = _run(session)
        stages = _stages(session, run, unpack=StageStatus.COMPLETED, static=StageStatus.PENDING)
        assert _phase(run, stages) == "static"

    def test_a_pending_unpack_is_not_mistaken_for_a_finished_one(self, session: Session) -> None:
        run = _run(session)
        assert _phase(run, _stages(session, run, unpack=StageStatus.PENDING)) == "unpack"

    def test_every_phase_returned_is_one_the_client_knows(self, session: Session) -> None:
        """The bar maps phase names to positions. An unknown name would render
        the panel blank, so the two lists have to stay in step."""
        known = {key for key, _ in SCAN_PHASES}
        run = _run(session)
        cases = [
            [],
            _stages(session, run, unpack=StageStatus.RUNNING),
        ]
        for stages in cases:
            assert _phase(run, stages) in known


class TestExpectedDuration:
    """The only estimate worth showing is one drawn from the same bytes."""

    def _scan(self, session: Session, sha: str, status: RunStatus, seconds: int | None) -> Run:
        run = _run(session, status)
        if seconds is not None:
            run.started_at = NOW
            run.finished_at = NOW + timedelta(seconds=seconds)
        session.add(
            Artifact(
                run_id=run.id,
                name="installer.exe",
                path_in_tree="installer.exe",
                depth=0,
                sha256=sha,
                size_bytes=1024,
                kind=ArtifactKind.PE,
            )
        )
        session.flush()
        return run

    def test_a_first_scan_has_no_estimate(self, session: Session) -> None:
        """And the UI says so rather than inventing a number."""
        run = self._scan(session, "a" * 64, RunStatus.RUNNING, None)
        assert _expected_duration_s(session, run) is None

    def test_a_previous_scan_of_the_same_bytes_supplies_one(self, session: Session) -> None:
        self._scan(session, "b" * 64, RunStatus.COMPLETED, 492)
        current = self._scan(session, "b" * 64, RunStatus.RUNNING, None)
        assert _expected_duration_s(session, current) == 492

    def test_a_different_artifact_does_not(self, session: Session) -> None:
        """Scan time is dominated by how many files an artifact unpacks to, so
        an average across artifacts would be a number with no meaning."""
        self._scan(session, "c" * 64, RunStatus.COMPLETED, 492)
        current = self._scan(session, "d" * 64, RunStatus.RUNNING, None)
        assert _expected_duration_s(session, current) is None

    def test_a_failed_previous_run_is_not_used(self, session: Session) -> None:
        """It stopped early, so its duration is not how long the work takes."""
        self._scan(session, "e" * 64, RunStatus.FAILED, 12)
        current = self._scan(session, "e" * 64, RunStatus.RUNNING, None)
        assert _expected_duration_s(session, current) is None

    def test_the_run_does_not_estimate_from_itself(self, session: Session) -> None:
        run = self._scan(session, "f" * 64, RunStatus.COMPLETED, 100)
        assert _expected_duration_s(session, run) is None
