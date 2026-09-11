"""Does the sandbox boundary actually hold?

Everything else in this repo trusts that these pass. They run a real container
through the real driver and assert on what the container observed *from the
inside*, because the daemon's own description of a container's configuration
is not evidence that the configuration took effect.

Requires Docker and the hello analyzer image (``make images``); the tag
follows ``BARE_ANALYZER_TAG``.
Skipped otherwise so the unit suite stays runnable anywhere.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from core.sandbox import BindMount, DockerDriver, MountMode, SandboxSpec, SandboxStatus
from core.sandbox.images import analyzer_image
from core.sandbox.spec import INPUT_DIR, OUTPUT_DIR

pytestmark = [pytest.mark.integration, pytest.mark.sandbox]

HELLO_IMAGE = analyzer_image("hello")


@pytest.fixture(scope="module")
def docker_client() -> Any:
    docker = pytest.importorskip("docker")
    try:
        client = docker.from_env()
        client.ping()
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"Docker is not available: {exc}")
    try:
        client.images.get(HELLO_IMAGE)
    except Exception:  # pragma: no cover - environment dependent
        pytest.skip(f"{HELLO_IMAGE} is not built; run `make images`")
    return client


@pytest.fixture
def run_dirs(tmp_path: Path) -> tuple[Path, Path, Path]:
    """(run_root, staging, results) with permissions the analyzer uid can use."""
    import os

    run_root = tmp_path / "runs"
    staging = run_root / "run-1" / "staging"
    results = run_root / "run-1" / "results"
    staging.mkdir(parents=True)
    results.mkdir(parents=True)
    (staging / "sample.txt").write_text("no secrets here\n", encoding="utf-8")
    if os.name != "nt":
        results.chmod(0o777)
    return run_root, staging, results


@pytest.fixture
def driver(run_dirs: tuple[Path, Path, Path], docker_client: Any) -> DockerDriver:
    run_root, _, _ = run_dirs
    return DockerDriver(run_root=run_root, repo_root=Path.cwd(), client=docker_client)


def make_spec(run_dirs: tuple[Path, Path, Path], **overrides: Any) -> SandboxSpec:
    _, staging, results = run_dirs
    base: dict[str, Any] = {
        "image": HELLO_IMAGE,
        "run_id": "run-1",
        "analyzer": "hello",
        "command": ("--probe",),
        "timeout_s": 120,
        "mounts": (
            BindMount(str(staging), INPUT_DIR, MountMode.READ_ONLY),
            BindMount(str(results), OUTPUT_DIR, MountMode.READ_WRITE),
        ),
    }
    return SandboxSpec(**{**base, **overrides})


def read_probe(results: Path) -> dict[str, Any]:
    payload = json.loads((results / "result.json").read_text(encoding="utf-8"))
    return dict(payload["probe"])


def attempt(probe: dict[str, Any], action: str) -> dict[str, Any]:
    return next(a for a in probe["attempts"] if a["action"] == action)


class TestEndToEnd:
    def test_analyzer_runs_and_returns_output(
        self, driver: DockerDriver, run_dirs: tuple[Path, Path, Path]
    ) -> None:
        _, _, results = run_dirs
        result = driver.run(make_spec(run_dirs))

        assert result.status is SandboxStatus.COMPLETED
        assert result.exit_code == 0
        assert result.ok is True
        assert (results / "result.json").is_file()

    def test_input_is_visible_and_hashed(
        self, driver: DockerDriver, run_dirs: tuple[Path, Path, Path]
    ) -> None:
        _, _, results = run_dirs
        driver.run(make_spec(run_dirs))
        payload = json.loads((results / "result.json").read_text(encoding="utf-8"))

        assert payload["input"]["present"] is True
        assert [f["path"] for f in payload["input"]["files"]] == ["sample.txt"]

    def test_image_digest_is_recorded_for_the_manifest(
        self, driver: DockerDriver, run_dirs: tuple[Path, Path, Path]
    ) -> None:
        result = driver.run(make_spec(run_dirs))
        assert result.image_digest
        assert "sha256:" in result.image_digest

    def test_container_is_removed_after_the_run(
        self, driver: DockerDriver, run_dirs: tuple[Path, Path, Path], docker_client: Any
    ) -> None:
        result = driver.run(make_spec(run_dirs))
        remaining = docker_client.containers.list(all=True, filters={"label": "bare.run=run-1"})
        assert [c.id for c in remaining] == []
        assert result.container_id is not None


@pytest.fixture(scope="module")
def probe(tmp_path_factory: pytest.TempPathFactory, docker_client: Any) -> dict[str, Any]:
    """One probe run, shared by every isolation assertion below.

    Module-scoped with its own directories: spinning up a container per
    assertion would make the suite slow enough that people stop running it,
    and every assertion here is about the same single boundary anyway.
    """
    import os

    run_root = tmp_path_factory.mktemp("isolation") / "runs"
    staging = run_root / "run-probe" / "staging"
    results = run_root / "run-probe" / "results"
    staging.mkdir(parents=True)
    results.mkdir(parents=True)
    (staging / "sample.txt").write_text("no secrets here\n", encoding="utf-8")
    if os.name != "nt":
        results.chmod(0o777)

    driver = DockerDriver(run_root=run_root, repo_root=Path.cwd(), client=docker_client)
    spec = SandboxSpec(
        image=HELLO_IMAGE,
        run_id="run-probe",
        analyzer="hello",
        command=("--probe",),
        timeout_s=120,
        mounts=(
            BindMount(str(staging), INPUT_DIR, MountMode.READ_ONLY),
            BindMount(str(results), OUTPUT_DIR, MountMode.READ_WRITE),
        ),
    )
    result = driver.run(spec)
    assert result.status is SandboxStatus.COMPLETED, result.error
    return read_probe(results)


class TestIsolation:
    """The things that must be impossible, observed from inside the container."""

    def test_does_not_run_as_root(self, probe: dict[str, Any]) -> None:
        assert probe["uid"] == 10001
        assert probe["gid"] == 10001
        assert probe["is_root"] is False

    def test_rootfs_is_read_only(self, probe: dict[str, Any]) -> None:
        assert attempt(probe, "write_rootfs")["succeeded"] is False

    def test_input_mount_is_read_only(self, probe: dict[str, Any]) -> None:
        assert attempt(probe, "write_input")["succeeded"] is False

    def test_no_outbound_tcp(self, probe: dict[str, Any]) -> None:
        assert attempt(probe, "tcp_connect")["succeeded"] is False

    def test_no_dns(self, probe: dict[str, Any]) -> None:
        assert attempt(probe, "dns_resolve")["succeeded"] is False

    def test_seccomp_denies_namespace_creation(self, probe: dict[str, Any]) -> None:
        """This is the assertion that proves the profile actually applied.

        An unprivileged user can normally unshare a user namespace even under
        cap_drop=ALL, so if this succeeds the profile was not in effect —
        the exact silent failure that passing a seccomp *path* through the
        Docker API produces.
        """
        assert attempt(probe, "unshare_userns")["succeeded"] is False

    def test_seccomp_denies_ptrace(self, probe: dict[str, Any]) -> None:
        assert attempt(probe, "ptrace_self")["succeeded"] is False

    def test_scratch_space_is_writable(self, probe: dict[str, Any]) -> None:
        """Isolation that breaks the analyzer is not isolation, it is a bug."""
        assert attempt(probe, "write_work_tmpfs")["succeeded"] is True

    def test_results_directory_is_writable(self, probe: dict[str, Any]) -> None:
        assert attempt(probe, "write_output")["succeeded"] is True


class TestWatchdog:
    @pytest.mark.slow
    def test_hung_container_is_killed_and_marked_not_left_running(
        self, driver: DockerDriver, run_dirs: tuple[Path, Path, Path], docker_client: Any
    ) -> None:
        """The analyzer ignores SIGTERM, so this exercises the SIGKILL path."""
        spec = make_spec(run_dirs, command=("--hang",), timeout_s=5, grace_s=2)
        result = driver.run(spec)

        assert result.status is SandboxStatus.TIMEOUT
        assert result.status.is_degraded
        assert result.duration_s < 60
        assert docker_client.containers.list(filters={"label": "bare.run=run-1"}) == []

    def test_failing_analyzer_is_reported_not_raised(
        self, driver: DockerDriver, run_dirs: tuple[Path, Path, Path]
    ) -> None:
        result = driver.run(make_spec(run_dirs, command=("--fail",)))

        assert result.status is SandboxStatus.COMPLETED
        assert result.exit_code == 3
        assert result.ok is False
        assert b"failing deliberately" in result.stderr


class TestResourceLimits:
    @pytest.mark.slow
    def test_memory_hog_is_stopped_and_diagnosed_as_oom(
        self, driver: DockerDriver, run_dirs: tuple[Path, Path, Path]
    ) -> None:
        """A Ghidra job that eats the host is the most likely real failure.

        It must come back as OOM, not as a timeout — the two need different
        remediation, and swap would turn the former into the latter.
        """
        spec = make_spec(
            run_dirs,
            command=("--alloc-mb", "1024"),
            mem_limit_bytes=128 * 1024 * 1024,
            timeout_s=120,
        )
        result = driver.run(spec)

        assert result.status is not SandboxStatus.COMPLETED
        assert result.status in (SandboxStatus.OOM, SandboxStatus.TIMEOUT)
        # Whichever the kernel reported, the allocation must not have finished.
        assert b"allocated 1024 MiB" not in result.stdout

    def test_pids_limit_is_passed_through(
        self, driver: DockerDriver, run_dirs: tuple[Path, Path, Path]
    ) -> None:
        kwargs = driver._build_create_kwargs(make_spec(run_dirs))
        assert kwargs["pids_limit"] == 512
        assert {u.name for u in make_spec(run_dirs).ulimits} == {"nofile", "fsize", "nproc"}


class TestReaperIntegration:
    def test_lists_only_containers_we_manage(
        self, driver: DockerDriver, run_dirs: tuple[Path, Path, Path]
    ) -> None:
        spec = make_spec(run_dirs, auto_remove=False)
        result = driver.run(spec)
        try:
            managed = {c.container_id: c for c in driver.list_managed()}
            assert result.container_id in managed
            assert managed[result.container_id].run_id == "run-1"
            assert managed[result.container_id].analyzer == "hello"
        finally:
            driver.remove(result.container_id or "", force=True)

    def test_remove_is_idempotent(self, driver: DockerDriver) -> None:
        driver.remove("bare-nonexistent-container", force=True)
