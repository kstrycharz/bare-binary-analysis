"""The run-list change stream behind the live Runs tab (bounty: `runs-live`).

The Runs page is a server component, and the bug this channel exists to fix
was that nothing ever re-requested it: a run started from the CLI or from a
colleague never appeared until someone hit reload. The contract tested here:

- the stream emits *only* when the ids-and-statuses fingerprint changes,
- the first frame is the baseline (`changed: false`) and later frames are not,
- a frame carries a count and a flag — never artifact names or findings, so an
  always-open channel across every dashboard tab cannot leak anything,
- and the route lives at `/api/runs/events`, not under a run id.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import core.db as db_module
from api.main import create_app
from api.routers.runs import _stream_run_list_events
from core.models import Run
from core.models.base import Base
from core.models.enums import RunStatus

NOW = datetime(2026, 9, 11, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def factory(monkeypatch: pytest.MonkeyPatch) -> Iterator[sessionmaker[Session]]:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    db_module.get_engine.cache_clear()
    db_module.get_sessionmaker.cache_clear()
    monkeypatch.setattr(db_module, "get_engine", lambda: engine)
    make: sessionmaker[Session] = sessionmaker(bind=engine, expire_on_commit=False)
    yield make
    db_module.get_sessionmaker.cache_clear()
    engine.dispose()


def _add(make: sessionmaker[Session], run_id: str, status: RunStatus) -> None:
    with make() as session:
        session.add(
            Run(
                id=run_id,
                status=status,
                attested_by="tester",
                attestation_reference="t",
                attested_at=NOW,
            )
        )
        session.commit()


async def _collect(stream: AsyncIterator[str], n: int) -> list[dict[str, object]]:
    out = []
    async for frame in stream:
        assert frame.startswith("data: ") and frame.endswith("\n\n")
        out.append(json.loads(frame[len("data: ") :]))
        if len(out) >= n:
            return out
    raise AssertionError(f"stream ended after {len(out)} frames, wanted {n}")


class TestFingerprint:
    async def test_quiet_stream_emits_one_baseline_and_stops(
        self, factory: sessionmaker[Session]
    ) -> None:
        """Nothing changing is the common case; it must cost one frame ever."""
        _add(factory, "run-1", RunStatus.QUEUED)
        frames = await _collect(_stream_run_list_events(ticks=8, poll_s=0), 1)
        assert frames == [{"changed": False, "runs": 1}]

    async def test_a_new_run_is_reported_as_changed(self, factory: sessionmaker[Session]) -> None:
        _add(factory, "run-1", RunStatus.RUNNING)
        stream = _stream_run_list_events(ticks=8, max_events=2, poll_s=0)
        baseline = await _collect(stream, 1)
        _add(factory, "run-2", RunStatus.QUEUED)
        changed = await _collect(stream, 1)
        assert baseline[0]["changed"] is False
        assert changed[0] == {"changed": True, "runs": 2}

    async def test_a_status_change_counts_even_with_the_same_ids(
        self, factory: sessionmaker[Session]
    ) -> None:
        """A completing run must wake the page, not just a starting one."""
        _add(factory, "run-1", RunStatus.QUEUED)
        stream = _stream_run_list_events(ticks=12, max_events=4, poll_s=0)
        await _collect(stream, 1)
        _add(factory, "run-2", RunStatus.QUEUED)
        await _collect(stream, 1)
        with factory() as session:
            session.get(Run, "run-2").status = RunStatus.COMPLETED
            session.commit()
        frames = await _collect(stream, 1)
        assert frames[0] == {"changed": True, "runs": 2}

    async def test_frames_never_carry_run_names(self, factory: sessionmaker[Session]) -> None:
        """Artifact names belong to the authenticated, redacted list endpoint.
        This channel is open in every tab for as long as the browser is."""
        _add(factory, "run-1", RunStatus.RUNNING)
        frames = await _collect(_stream_run_list_events(ticks=4, poll_s=0), 1)
        assert set(frames[0]) == {"changed", "runs"}


class TestRoute:
    def test_events_route_is_declared_before_the_run_id_route(self) -> None:
        """`/api/runs/events` must not fall through to `/{run_id}` and 404.

        FastAPI matches in declaration order. Checking the order directly is
        the deterministic version of a request that would otherwise block on
        the stream's first sleep.
        """
        paths = [getattr(r, "path", "") for r in create_app().routes]
        assert "/api/runs/events" in paths
        assert paths.index("/api/runs/events") < paths.index("/api/runs/{run_id}")
