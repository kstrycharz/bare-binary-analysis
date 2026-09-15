"""Analyzer output while a scan is still running (ADR-0033).

The retained log (ADR-0032) answers "why did that stage degrade?" after the
fact. These tests cover the question asked *during* a scan — "what is it doing
right now?" — and the one property that makes answering it safe: a snapshot
of a running stage is redacted exactly as the retained log will be, and never
exposes a secret the retained log would mask.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import api.routers.runs as runs_router
import core.db as db_module
import core.pipeline.logs as logs_module
from api.main import create_app
from core.auth import Scope
from core.models import Run, RunStage
from core.models.base import Base
from core.models.enums import RunStatus, StageStatus
from core.pipeline.logs import LiveStageLog, render_stage_log, stage_log_key, store_stage_log
from core.pipeline.tokens import create_token
from core.rules import load_rule_pack
from core.sandbox.base import SandboxStatus
from core.sandbox.docker_driver import DockerDriver, _ContainerHandle
from core.sandbox.images import analyzer_image
from core.sandbox.spec import INPUT_DIR, OUTPUT_DIR, BindMount, MountMode, SandboxSpec

RULES_DIR = Path(__file__).resolve().parents[2] / "detections"
NOW = datetime(2026, 9, 14, 12, 0, 0, tzinfo=UTC)

# Provably invalid and assembled, so no full key literal exists in the tree (§9).
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLZ"

KEY = stage_log_key("run-1", "stage-1")


@pytest.fixture(scope="module")
def pack() -> Any:
    return load_rule_pack(RULES_DIR)


class _Bucket:
    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}
        self.puts = 0
        self.fail = False

    def put_object(self, *, Bucket: str, Key: str, Body: bytes) -> None:  # noqa: N803
        if self.fail:
            raise RuntimeError("minio unreachable")
        self.puts += 1
        self.objects[Key] = Body

    def get_object(self, *, Bucket: str, Key: str) -> dict[str, Any]:  # noqa: N803
        class _Body:
            def __init__(self, data: bytes) -> None:
                self._data = data

            def read(self) -> bytes:
                return self._data

        return {"Body": _Body(self.objects[Key])}


class _Store:
    bucket = "bare-artifacts"

    def __init__(self) -> None:
        self.client = _Bucket()

    def ensure_bucket(self) -> None:
        pass

    def exists(self, key: str) -> bool:
        return key in self.client.objects


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


# --- rendering a snapshot ------------------------------------------------------


class TestLiveRender:
    def test_an_unfinished_line_is_held_back(self, pack: Any) -> None:
        """A process caught mid-write has printed the first half of a key, and
        half a key is a string no rule recognises — so none would mask it."""
        half = AWS_KEY[:12]
        document, _ = render_stage_log(
            f"scanning 3 files\nkey={half}".encode(), b"", pack=pack, live=True
        )
        assert "scanning 3 files" in document
        assert half not in document

    def test_a_finished_line_redacts_exactly_as_the_retained_log_will(self, pack: Any) -> None:
        stdout = f"loading key={AWS_KEY}\nstill going\n".encode()
        live, _ = render_stage_log(stdout, b"boom\n", pack=pack, live=True)
        final, _ = render_stage_log(stdout, b"boom\n", pack=pack)
        assert live == final
        assert AWS_KEY not in live

    def test_the_retained_log_keeps_an_unterminated_last_line(self, pack: Any) -> None:
        """Holding back is for a process still writing. One that has exited
        has finished its last line whether or not it printed a newline."""
        document, _ = render_stage_log(b"exit status 2", b"", pack=pack)
        assert "exit status 2" in document


# --- publishing snapshots --------------------------------------------------------


class TestLiveStageLog:
    def _live(self, pack: Any, clock: _Clock, store: _Store | None = None) -> tuple[_Store, Any]:
        store = store or _Store()
        live = LiveStageLog(
            store,  # type: ignore[arg-type]
            run_id="run-1",
            stage_id="stage-1",
            pack=pack,
            interval_s=5.0,
            clock=clock,
        )
        return store, live

    def test_publishes_redacted_where_the_retained_log_will_go(self, pack: Any) -> None:
        store, live = self._live(pack, _Clock())
        live(f"key={AWS_KEY}\n".encode(), b"")
        stored = store.client.objects[KEY].decode()
        assert stored.startswith("--- stdout ---")
        assert AWS_KEY not in stored

    def test_throttled_to_the_interval(self, pack: Any) -> None:
        clock = _Clock()
        store, live = self._live(pack, clock)
        live(b"one\n", b"")
        clock.now = 1.0
        live(b"one\ntwo\n", b"")
        assert store.client.puts == 1
        clock.now = 5.0
        live(b"one\ntwo\n", b"")
        assert store.client.puts == 2

    def test_output_that_has_not_changed_is_not_rewritten(self, pack: Any) -> None:
        clock = _Clock()
        store, live = self._live(pack, clock)
        live(b"one\n", b"")
        clock.now = 10.0
        live(b"one\n", b"")
        clock.now = 20.0
        live(b"one\npart", b"")  # grew, but only by a line that is held back
        assert store.client.puts == 1

    def test_an_expensive_snapshot_stretches_the_interval(
        self, pack: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A megabyte-printing analyzer must spend its time analysing, not
        being redacted for the benefit of someone watching."""
        clock = _Clock()
        real = logs_module.render_stage_log

        def slow(*args: Any, **kwargs: Any) -> tuple[str, bool]:
            clock.now += 3.0
            return real(*args, **kwargs)

        monkeypatch.setattr(logs_module, "render_stage_log", slow)
        store, live = self._live(pack, clock)
        live(b"one\n", b"")  # ends at t=3 having cost 3 s: next no sooner than t=15
        clock.now = 14.0
        live(b"one\ntwo\n", b"")
        assert store.client.puts == 1
        clock.now = 15.0
        live(b"one\ntwo\n", b"")
        assert store.client.puts == 2

    def test_a_bucket_failure_backs_off_and_never_raises(self, pack: Any) -> None:
        clock = _Clock()
        store, live = self._live(pack, clock)
        store.client.fail = True
        live(b"one\n", b"")
        store.client.fail = False
        clock.now = 29.0
        live(b"one\ntwo\n", b"")
        assert store.client.puts == 0
        clock.now = 30.0
        live(b"one\ntwo\n", b"")
        assert store.client.puts == 1

    def test_the_retained_log_replaces_the_last_snapshot(self, pack: Any) -> None:
        clock = _Clock()
        store, live = self._live(pack, clock)
        live(b"one\nexit", b"")
        assert "exit" not in store.client.objects[KEY].decode()
        store_stage_log(
            store,  # type: ignore[arg-type]
            run_id="run-1",
            stage_id="stage-1",
            stdout=b"one\nexit",
            stderr=b"",
            pack=pack,
        )
        assert "exit" in store.client.objects[KEY].decode()


# --- the driver offering output ----------------------------------------------------


class ReadTimeout(Exception):  # noqa: N818 - named like the requests exception docker-py raises
    pass


class _Container:
    id = "c0ffee"

    def __init__(self, *, timeouts: int, exit_code: int = 0, stdout: bytes = b"") -> None:
        self._timeouts = timeouts
        self._exit_code = exit_code
        self._stdout = stdout
        self.waits: list[float] = []
        self.attrs: dict[str, Any] = {"State": {"OOMKilled": False}}

    def wait(self, timeout: float) -> dict[str, int]:
        self.waits.append(timeout)
        if self._timeouts > 0:
            self._timeouts -= 1
            raise ReadTimeout("Read timed out.")
        return {"StatusCode": self._exit_code}

    def logs(self, *, stdout: bool, stderr: bool, timestamps: bool) -> bytes:
        return self._stdout if stdout else b""

    def start(self) -> None:
        pass

    def reload(self) -> None:
        pass

    def kill(self, signal: str) -> None:
        pass

    def remove(self, force: bool) -> None:
        pass


class TestContainerHandle:
    def test_without_a_consumer_the_deadline_is_one_wait(self) -> None:
        container = _Container(timeouts=0, exit_code=3)
        assert _ContainerHandle(container).wait(900) == 3
        assert container.waits == [900]

    def test_with_a_consumer_the_wait_is_sliced_and_each_slice_offers_output(self) -> None:
        container = _Container(timeouts=2, exit_code=3)
        ticks: list[int] = []
        handle = _ContainerHandle(container, on_tick=lambda: ticks.append(1), tick_s=2.0)
        assert handle.wait(900) == 3
        assert len(ticks) == 2
        assert all(waited <= 2.0 for waited in container.waits)

    def test_slicing_does_not_extend_the_deadline(self) -> None:
        class Hung(_Container):
            def wait(self, timeout: float) -> dict[str, int]:
                time.sleep(timeout)
                raise ReadTimeout("Read timed out.")

        ticks: list[int] = []
        handle = _ContainerHandle(Hung(timeouts=0), on_tick=lambda: ticks.append(1), tick_s=0.02)
        started = time.monotonic()
        assert handle.wait(0.1) is None
        assert time.monotonic() - started < 1.0
        assert ticks


@pytest.fixture
def driver_roots(tmp_path: Path) -> tuple[Path, Path]:
    run_root = tmp_path / "runs"
    (run_root / "run-1" / "staging").mkdir(parents=True)
    (run_root / "run-1" / "results").mkdir(parents=True)
    repo = tmp_path / "repo"
    (repo / "sandbox" / "profiles").mkdir(parents=True)
    (repo / "sandbox" / "profiles" / "analyzer.json").write_text(
        json.dumps({"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []}), encoding="utf-8"
    )
    return run_root, repo


def _driver(driver_roots: tuple[Path, Path], container: _Container) -> DockerDriver:
    class Client:
        class containers:  # noqa: N801 - mirrors the docker-py attribute
            @staticmethod
            def create(**kwargs: Any) -> _Container:
                return container

        class images:  # noqa: N801 - mirrors the docker-py attribute
            @staticmethod
            def get(image: str) -> Any:
                raise RuntimeError("no such image")

    run_root, repo = driver_roots
    return DockerDriver(run_root=run_root, repo_root=repo, client=Client())


def _spec(run_root: Path) -> SandboxSpec:
    return SandboxSpec(
        image=analyzer_image("hello"),
        run_id="run-1",
        analyzer="hello",
        mounts=(
            BindMount(str(run_root / "run-1" / "staging"), INPUT_DIR, MountMode.READ_ONLY),
            BindMount(str(run_root / "run-1" / "results"), OUTPUT_DIR, MountMode.READ_WRITE),
        ),
    )


class TestTheDriverOffersOutputWhileItRuns:
    def test_the_consumer_sees_output_before_the_container_exits(
        self, driver_roots: tuple[Path, Path]
    ) -> None:
        container = _Container(timeouts=1, stdout=b"working\n")
        seen: list[tuple[bytes, bytes]] = []
        result = _driver(driver_roots, container).run(
            _spec(driver_roots[0]), on_output=lambda out, err: seen.append((out, err))
        )
        assert result.status is SandboxStatus.COMPLETED
        assert seen == [(b"working\n", b"")]

    def test_a_consumer_that_raises_does_not_degrade_the_stage(
        self, driver_roots: tuple[Path, Path]
    ) -> None:
        """ADR-0008 for a side channel: a broken live view is not a broken analyzer."""

        def broken(out: bytes, err: bytes) -> None:
            raise RuntimeError("bucket on fire")

        container = _Container(timeouts=2, stdout=b"working\n")
        result = _driver(driver_roots, container).run(_spec(driver_roots[0]), on_output=broken)
        assert result.status is SandboxStatus.COMPLETED
        assert result.exit_code == 0
        assert result.stdout == b"working\n"


# --- reading a running stage's output -----------------------------------------------


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch, pack: Any) -> Iterator[tuple[TestClient, _Store, str]]:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    factory: sessionmaker[Session] = sessionmaker(bind=engine, expire_on_commit=False)
    db_module.get_engine.cache_clear()
    db_module.get_sessionmaker.cache_clear()
    monkeypatch.setattr(db_module, "get_engine", lambda: engine)

    store = _Store()
    monkeypatch.setattr(runs_router, "get_object_store", lambda: store)

    app = create_app()

    def _override() -> Iterator[Session]:
        session = factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[db_module.get_session] = _override

    def run(run_id: str, status: RunStatus) -> Run:
        return Run(
            id=run_id,
            status=status,
            attested_by="tester",
            attestation_reference="t",
            attested_at=NOW,
        )

    with factory() as setup:
        setup.add(run("run-live", RunStatus.RUNNING))
        setup.add(run("run-dead", RunStatus.FAILED))
        for stage_id, run_id, analyzer, status in (
            ("stage-running", "run-live", "static", StageStatus.RUNNING),
            ("stage-quiet", "run-live", "unpack", StageStatus.RUNNING),
            ("stage-orphan", "run-dead", "static", StageStatus.RUNNING),
            ("stage-lost", "run-dead", "unpack", StageStatus.FAILED),
        ):
            setup.add(RunStage(id=stage_id, run_id=run_id, analyzer=analyzer, status=status))
        setup.commit()
        admin = create_token(setup, name="admin-live", scope=Scope.ADMIN).token
        ci = create_token(setup, name="ci-live", scope=Scope.CI).token
        setup.commit()

    LiveStageLog(
        store,  # type: ignore[arg-type]
        run_id="run-live",
        stage_id="stage-running",
        pack=pack,
    )(f"loading {AWS_KEY}\nhalf-writ".encode(), b"")
    # A worker that died mid-stage leaves its last snapshot, and a failed
    # stage whose retained write failed can leave one too.
    for run_id, stage_id in (("run-dead", "stage-orphan"), ("run-dead", "stage-lost")):
        store.client.objects[stage_log_key(run_id, stage_id)] = b"--- stdout ---\nlast words\n"

    client = TestClient(app)
    client.headers["authorization"] = f"Bearer {admin}"
    yield client, store, ci
    db_module.get_sessionmaker.cache_clear()
    engine.dispose()


class TestTheEndpointWhileAStageRuns:
    def test_serves_the_snapshot_labelled_live_and_neutered(self, api: Any) -> None:
        client, _, _ = api
        response = client.get("/api/runs/run-live/stages/stage-running/logs")
        assert response.status_code == 200
        assert response.headers["x-bare-log-state"] == "live"
        assert response.headers["content-type"].startswith("text/plain")
        assert "sandbox" in response.headers["content-security-policy"]
        assert "loading" in response.text
        assert AWS_KEY not in response.text
        assert "half-writ" not in response.text

    def test_nothing_printed_yet_is_404_with_a_reason(self, api: Any) -> None:
        client, _, _ = api
        response = client.get("/api/runs/run-live/stages/stage-quiet/logs")
        assert response.status_code == 404
        assert "no output yet" in response.json()["detail"]

    def test_a_stage_left_running_by_a_dead_run_is_labelled_partial(self, api: Any) -> None:
        """Not "live": nothing is going to add to it."""
        client, _, _ = api
        response = client.get("/api/runs/run-dead/stages/stage-orphan/logs")
        assert response.status_code == 200
        assert response.headers["x-bare-log-state"] == "partial"

    def test_a_finished_stage_never_falls_back_to_a_snapshot(self, api: Any) -> None:
        """`log_key` stays the statement that a finished stage kept its log."""
        client, _, _ = api
        response = client.get("/api/runs/run-dead/stages/stage-lost/logs")
        assert response.status_code == 404
        assert "no log retained" in response.json()["detail"]

    def test_a_ci_token_cannot_watch_either(self, api: Any) -> None:
        client, _, ci = api
        response = client.get(
            "/api/runs/run-live/stages/stage-running/logs",
            headers={"authorization": f"Bearer {ci}"},
        )
        assert response.status_code == 403

    def test_the_progress_stream_carries_each_stage_id(self, api: Any) -> None:
        """The id is the address the progress panel reads a stage's log from."""
        client, _, _ = api
        body = client.get("/api/runs/run-dead/events").text
        payload = json.loads(body.removeprefix("data: ").strip())
        assert {stage["id"] for stage in payload["stages"]} == {"stage-orphan", "stage-lost"}
