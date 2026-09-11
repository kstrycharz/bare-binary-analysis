"""Driver translation from spec to Docker API arguments.

A driver that accepts a locked-down spec and then quietly drops half of it
would make every isolation test a lie. These tests assert the translation
itself, with no daemon involved.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from core.sandbox.base import SandboxStatus
from core.sandbox.docker_driver import DockerDriver, _is_timeout, _parse_docker_time
from core.sandbox.images import analyzer_image
from core.sandbox.spec import INPUT_DIR, OUTPUT_DIR, BindMount, MountMode, NetworkMode, SandboxSpec


@pytest.fixture
def run_root(tmp_path: Path) -> Path:
    root = tmp_path / "runs"
    (root / "run-1" / "staging").mkdir(parents=True)
    (root / "run-1" / "results").mkdir(parents=True)
    return root


@pytest.fixture
def repo_root(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "sandbox" / "profiles").mkdir(parents=True)
    (repo / "sandbox" / "profiles" / "analyzer.json").write_text(
        json.dumps({"defaultAction": "SCMP_ACT_ERRNO", "syscalls": []}),
        encoding="utf-8",
    )
    return repo


@pytest.fixture
def driver(run_root: Path, repo_root: Path) -> DockerDriver:
    return DockerDriver(run_root=run_root, repo_root=repo_root, client=object())


def make_spec(run_root: Path, **overrides: Any) -> SandboxSpec:
    base: dict[str, Any] = {
        "image": analyzer_image("hello"),
        "run_id": "run-1",
        "analyzer": "hello",
        "mounts": (
            BindMount(str(run_root / "run-1" / "staging"), INPUT_DIR, MountMode.READ_ONLY),
            BindMount(str(run_root / "run-1" / "results"), OUTPUT_DIR, MountMode.READ_WRITE),
        ),
    }
    return SandboxSpec(**{**base, **overrides})


class TestCreateKwargs:
    def test_isolation_flags_reach_the_daemon(self, driver: DockerDriver, run_root: Path) -> None:
        kwargs = driver._build_create_kwargs(make_spec(run_root))

        assert kwargs["network_mode"] == "none"
        assert kwargs["read_only"] is True
        assert kwargs["user"] == "10001:10001"
        assert kwargs["cap_drop"] == ["ALL"]
        assert kwargs["cap_add"] is None
        assert "no-new-privileges:true" in kwargs["security_opt"]
        assert kwargs["pids_limit"] == 512

    def test_seccomp_profile_is_inlined_not_referenced_by_path(
        self, driver: DockerDriver, run_root: Path
    ) -> None:
        """The Docker API needs the profile contents; a path silently yields no
        profile at all."""
        kwargs = driver._build_create_kwargs(make_spec(run_root))
        seccomp = next(o for o in kwargs["security_opt"] if o.startswith("seccomp="))
        payload = json.loads(seccomp.removeprefix("seccomp="))
        assert payload["defaultAction"] == "SCMP_ACT_ERRNO"

    def test_missing_seccomp_profile_is_fatal(self, run_root: Path, tmp_path: Path) -> None:
        driver = DockerDriver(run_root=run_root, repo_root=tmp_path / "nowhere", client=object())
        with pytest.raises(FileNotFoundError, match="refusing to run without it"):
            driver._build_create_kwargs(make_spec(run_root))

    def test_docker_auto_remove_is_never_set(self, driver: DockerDriver, run_root: Path) -> None:
        """We remove containers ourselves; --rm races log collection."""
        kwargs = driver._build_create_kwargs(make_spec(run_root))
        assert kwargs["auto_remove"] is False

    def test_swap_is_pinned_to_memory_limit(self, driver: DockerDriver, run_root: Path) -> None:
        """Allowing swap turns an OOM into an unbounded hang, which the
        watchdog then reports as a timeout — the wrong diagnosis."""
        kwargs = driver._build_create_kwargs(make_spec(run_root))
        assert kwargs["memswap_limit"] == kwargs["mem_limit"]

    def test_mounts_carry_the_right_modes(self, driver: DockerDriver, run_root: Path) -> None:
        kwargs = driver._build_create_kwargs(make_spec(run_root))
        modes = {v["bind"]: v["mode"] for v in kwargs["volumes"].values()}
        assert modes["/input"] == "ro"
        assert modes["/output"] == "rw"

    def test_tmpfs_options_are_rendered(self, driver: DockerDriver, run_root: Path) -> None:
        kwargs = driver._build_create_kwargs(make_spec(run_root))
        assert "noexec" in kwargs["tmpfs"]["/tmp"]
        assert kwargs["tmpfs"]["/work"].startswith("size=")

    def test_reaper_labels_are_attached(self, driver: DockerDriver, run_root: Path) -> None:
        kwargs = driver._build_create_kwargs(make_spec(run_root))
        assert kwargs["labels"]["bare.managed"] == "true"
        assert kwargs["labels"]["bare.run"] == "run-1"

    def test_sinkhole_networking_raises_rather_than_falling_back(
        self, driver: DockerDriver, run_root: Path
    ) -> None:
        """Silently downgrading to a bridge would hand the artifact real
        egress. Better to fail the analyzer."""
        spec = make_spec(run_root, network=NetworkMode.SINKHOLE)
        with pytest.raises(NotImplementedError, match="M5"):
            driver._build_create_kwargs(spec)


class TestMountConfinement:
    def test_rejects_sources_outside_the_run_root(
        self, driver: DockerDriver, run_root: Path, tmp_path: Path
    ) -> None:
        outside = tmp_path / "elsewhere"
        outside.mkdir()
        spec = SandboxSpec(
            image="x",
            run_id="run-1",
            analyzer="hello",
            mounts=(BindMount(str(outside), INPUT_DIR, MountMode.READ_ONLY),),
        )
        with pytest.raises(ValueError, match="outside the run root"):
            driver._validate_mounts(spec)

    def test_accepts_sources_inside_the_run_root(
        self, driver: DockerDriver, run_root: Path
    ) -> None:
        driver._validate_mounts(make_spec(run_root))


class TestHostPathTranslation:
    """The worker sees the run root at one path; the daemon sees it at another.

    Bind sources in a create request are resolved by the daemon on the host, so
    sending the worker's own view of the path yields an analyzer with an empty
    input directory and no error at all — the worst kind of bug.
    """

    def test_identity_when_no_host_root_is_configured(
        self, driver: DockerDriver, run_root: Path
    ) -> None:
        source = str(run_root / "run-1" / "staging")
        assert driver._to_host_path(source) == str(Path(source).resolve())

    def test_translates_onto_a_posix_host_root(self, run_root: Path, repo_root: Path) -> None:
        driver = DockerDriver(
            run_root=run_root,
            repo_root=repo_root,
            host_run_root="/srv/bare/runs",
            client=object(),
        )
        translated = driver._to_host_path(str(run_root / "run-1" / "staging"))
        assert translated == "/srv/bare/runs/run-1/staging"

    def test_translates_onto_a_windows_host_root_from_a_linux_worker(
        self, run_root: Path, repo_root: Path
    ) -> None:
        """A Linux worker driving Docker Desktop must emit backslashed paths;
        pathlib on the worker would happily produce a POSIX path the daemon
        cannot find."""
        driver = DockerDriver(
            run_root=run_root,
            repo_root=repo_root,
            host_run_root=r"C:\bare\runs",
            client=object(),
        )
        translated = driver._to_host_path(str(run_root / "run-1" / "results"))
        assert translated == r"C:\bare\runs\run-1\results"

    def test_translation_is_applied_to_the_create_request(
        self, run_root: Path, repo_root: Path
    ) -> None:
        driver = DockerDriver(
            run_root=run_root,
            repo_root=repo_root,
            host_run_root="/srv/runs",
            client=object(),
        )
        kwargs = driver._build_create_kwargs(make_spec(run_root))
        assert set(kwargs["volumes"]) == {
            "/srv/runs/run-1/staging",
            "/srv/runs/run-1/results",
        }


class TestFailureHandling:
    def test_create_failure_becomes_a_degraded_result_not_an_exception(
        self, run_root: Path, repo_root: Path
    ) -> None:
        """One analyzer that cannot start must never abort the whole run."""

        class ExplodingClient:
            class containers:  # noqa: N801 - mirrors the docker-py attribute
                @staticmethod
                def create(**kwargs: Any) -> Any:
                    raise RuntimeError("no such image")

        driver = DockerDriver(run_root=run_root, repo_root=repo_root, client=ExplodingClient())
        result = driver.run(make_spec(run_root))

        assert result.status is SandboxStatus.START_FAILED
        assert result.status.is_degraded
        assert result.ok is False
        assert result.error is not None and "no such image" in result.error

    def test_invalid_spec_raises_because_it_is_a_programmer_error(
        self, driver: DockerDriver, run_root: Path
    ) -> None:
        from core.sandbox.spec import SpecViolation

        with pytest.raises(SpecViolation):
            driver.run(make_spec(run_root, user="0:0"))


class TestDurationMeasurement:
    """Durations come from a monotonic clock, not from the wall-clock stamps.

    Observed in practice: Docker Desktop's VM corrected its clock mid-scan and
    a completed stage reported -42.4 seconds. A negative duration in a report
    looks like a broken product and undermines every other number next to it.
    """

    def test_duration_is_independent_of_wall_clock_stamps(self) -> None:
        from datetime import UTC, datetime, timedelta

        from core.sandbox.base import SandboxResult

        started = datetime.now(UTC)
        result = SandboxResult(
            spec=_bare_spec(),
            status=SandboxStatus.COMPLETED,
            exit_code=0,
            stdout=b"",
            stderr=b"",
            # Clock jumped backwards between start and finish.
            started_at=started,
            finished_at=started - timedelta(seconds=42),
            duration_s=1.25,
        )
        assert result.duration_s == 1.25

    def test_failure_clamps_a_negative_duration(self) -> None:
        from core.sandbox.base import SandboxResult

        result = SandboxResult.failure(
            _bare_spec(), SandboxStatus.START_FAILED, "boom", duration_s=-5.0
        )
        assert result.duration_s == 0.0

    def test_real_run_reports_a_non_negative_duration(
        self, run_root: Path, repo_root: Path
    ) -> None:
        class ExplodingClient:
            class containers:  # noqa: N801 - mirrors the docker-py attribute
                @staticmethod
                def create(**kwargs: Any) -> Any:
                    raise RuntimeError("no such image")

        driver = DockerDriver(run_root=run_root, repo_root=repo_root, client=ExplodingClient())
        result = driver.run(make_spec(run_root))
        assert result.duration_s >= 0.0


def _bare_spec() -> SandboxSpec:
    return SandboxSpec(image="x", run_id="run-1", analyzer="hello")


class TestHelpers:
    def test_timeout_detection_looks_through_the_exception_chain(self) -> None:
        class ReadTimeoutError(Exception):
            pass

        outer = RuntimeError("connection aborted")
        outer.__cause__ = ReadTimeoutError("read timed out")
        assert _is_timeout(outer) is True
        assert _is_timeout(RuntimeError("no such container")) is False

    @pytest.mark.parametrize(
        "value",
        [
            "2026-08-17T12:00:00.123456789Z",
            "2026-08-17T12:00:00Z",
            "2026-08-17T12:00:00.123456+00:00",
        ],
    )
    def test_docker_timestamps_parse_including_nanoseconds(self, value: str) -> None:
        parsed = _parse_docker_time(value)
        assert parsed.year == 2026
        assert parsed.tzinfo is not None

    def test_unparseable_timestamp_does_not_explode(self) -> None:
        assert _parse_docker_time("not a date").tzinfo is not None
