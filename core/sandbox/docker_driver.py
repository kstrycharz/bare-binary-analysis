"""Docker implementation of :class:`~core.sandbox.base.SandboxDriver`.

Notes on decisions that are easy to get wrong and hard to notice:

* **We do not use Docker's ``--rm``/``auto_remove``.** It races log collection:
  the daemon can reap the container before we read its output, and you get an
  empty analyzer result with no error. Instead the driver removes the container
  itself in a ``finally``, and the reaper catches anything a crash leaks.
* **The seccomp profile is inlined, not referenced by path.** The Docker CLI
  reads profile files client-side; the API expects the JSON *contents* in
  ``security_opt``. Passing a path via the API silently yields no profile.
* **Mount sources are confined to the run root.** A bug in an analyzer
  definition must not be able to bind-mount ``/`` or the Docker socket.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import structlog

from core.sandbox.base import (
    DriverHealth,
    ManagedContainer,
    OutputCallback,
    SandboxDriver,
    SandboxResult,
    SandboxStatus,
)
from core.sandbox.spec import MountMode, NetworkMode, SandboxSpec
from core.sandbox.watchdog import WatchdogVerdict, enforce_deadline

log = structlog.get_logger(__name__)

MANAGED_LABEL = "bare.managed"
_MAX_LOG_BYTES = 8 * 1024 * 1024

# How often a running container's output is offered to an `on_output`
# consumer. The consumer throttles itself (ADR-0033); this only bounds how
# stale its view can get.
_OUTPUT_POLL_S = 2.0


class DockerUnavailable(RuntimeError):  # noqa: N818 - reads as a state, not an error type
    """The Docker daemon could not be reached or is misconfigured."""


@dataclass(slots=True)
class _ContainerHandle:
    """Adapts a docker-py container to the watchdog's ``ContainerHandle``."""

    container: Any
    on_tick: Callable[[], None] | None = None
    """Called between wait slices while the container runs; see `wait`."""
    tick_s: float = _OUTPUT_POLL_S

    def wait(self, timeout_s: float) -> int | None:
        if self.on_tick is None:
            return self._wait_once(timeout_s)
        # Sliced, so the output can be offered between slices. The watchdog's
        # deadline still holds: slices end on the monotonic clock rather than
        # by count, so a slow tick shortens what is left of the wait instead
        # of extending it.
        deadline = time.monotonic() + timeout_s
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            code = self._wait_once(min(remaining, self.tick_s))
            if code is not None:
                return code
            self.on_tick()

    def _wait_once(self, timeout_s: float) -> int | None:
        try:
            result = self.container.wait(timeout=timeout_s)
        except Exception as exc:  # docker-py surfaces timeouts as requests errors
            if _is_timeout(exc):
                return None
            raise
        code = result.get("StatusCode") if isinstance(result, dict) else None
        return int(code) if code is not None else None

    def terminate(self) -> None:
        _quiet(self.container.kill, signal="SIGTERM")

    def kill(self) -> None:
        _quiet(self.container.kill, signal="SIGKILL")


def _is_timeout(exc: BaseException) -> bool:
    """docker-py wraps read timeouts in several layers; sniff the whole chain."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        name = type(current).__name__
        if "Timeout" in name:
            return True
        current = current.__cause__ or current.__context__
    return "timed out" in str(exc).lower()


def _quiet(fn: Any, **kwargs: Any) -> None:
    """Best-effort call: the container may already be gone, which is fine."""
    try:
        fn(**kwargs)
    except Exception as exc:
        log.debug("docker.quiet_call_failed", fn=getattr(fn, "__name__", "?"), error=str(exc))


class DockerDriver(SandboxDriver):
    name = "docker"

    def __init__(
        self,
        *,
        run_root: Path,
        repo_root: Path | None = None,
        host_run_root: str | None = None,
        client: Any | None = None,
    ) -> None:
        """
        ``run_root`` is the only directory analyzers may see, as *this process*
        sees it; every bind mount source must resolve inside it.

        ``host_run_root`` is the same directory as the *Docker daemon* sees it.
        These differ whenever the orchestrator is itself containerised: the
        worker spawns analyzers as siblings through the host socket, and the
        daemon resolves their bind paths on the host, not inside the worker.
        Leave it unset when the two are the same (running on the host directly).

        This translation is why the run root does not need to be mounted at an
        identical path on both sides — which is impossible on Windows anyway,
        where a host path like ``C:\\runs`` cannot be a container path.
        """
        self._run_root = run_root.resolve()
        self._repo_root = (repo_root or Path.cwd()).resolve()
        self._host_run_root = host_run_root or None
        self._client = client
        self._seccomp_cache: dict[str, str] = {}

    # -- client ------------------------------------------------------------
    @property
    def client(self) -> Any:
        if self._client is None:
            try:
                import docker
            except ImportError as exc:  # pragma: no cover - dependency is pinned
                raise DockerUnavailable("the 'docker' package is not installed") from exc
            try:
                self._client = docker.from_env()
            except Exception as exc:
                raise DockerUnavailable(f"cannot reach the Docker daemon: {exc}") from exc
        return self._client

    def close(self) -> None:
        if self._client is not None:
            _quiet(self._client.close)

    # -- health ------------------------------------------------------------
    def health(self) -> DriverHealth:
        try:
            version = self.client.version()
        except Exception as exc:
            return DriverHealth(healthy=False, driver=self.name, detail=str(exc))

        warnings: list[str] = []
        try:
            info = self.client.info()
            if not info.get("SecurityOptions"):
                warnings.append("daemon reports no security options; seccomp may be disabled")
            elif not any("seccomp" in opt for opt in info.get("SecurityOptions", [])):
                warnings.append("seccomp is not among the daemon's security options")
        except Exception as exc:
            warnings.append(f"could not read daemon info: {exc}")

        return DriverHealth(
            healthy=True,
            driver=self.name,
            version=str(version.get("Version", "")),
            detail=f"api={version.get('ApiVersion', '?')}",
            warnings=tuple(warnings),
        )

    # -- run ---------------------------------------------------------------
    def run(self, spec: SandboxSpec, *, on_output: OutputCallback | None = None) -> SandboxResult:
        spec.validate()
        self._validate_mounts(spec)

        started_at = datetime.now(UTC)
        # Monotonic for elapsed time, wall clock for the audit timestamps. See
        # SandboxResult.duration_s for why these are not the same measurement.
        started_monotonic = time.monotonic()
        try:
            kwargs = self._build_create_kwargs(spec)
        except Exception as exc:
            return SandboxResult.failure(
                spec, SandboxStatus.START_FAILED, f"could not build container spec: {exc}"
            )

        try:
            container = self.client.containers.create(**kwargs)
        except Exception as exc:
            log.error("sandbox.create_failed", analyzer=spec.analyzer, error=str(exc))
            return SandboxResult.failure(
                spec,
                SandboxStatus.START_FAILED,
                str(exc),
                started_at=started_at,
                duration_s=time.monotonic() - started_monotonic,
            )

        container_id = str(container.id)
        digest = self._resolve_digest(spec.image)
        try:
            container.start()
        except Exception as exc:
            _quiet(container.remove, force=True)
            return SandboxResult.failure(
                spec,
                SandboxStatus.START_FAILED,
                str(exc),
                started_at=started_at,
                container_id=container_id,
                duration_s=time.monotonic() - started_monotonic,
            )

        log.info(
            "sandbox.started",
            run_id=spec.run_id,
            analyzer=spec.analyzer,
            container_id=container_id[:12],
            image=spec.image,
            timeout_s=spec.timeout_s,
        )

        handle = _ContainerHandle(
            container,
            on_tick=(
                None
                if on_output is None
                else partial(self._offer_output, spec, container, on_output)
            ),
        )
        try:
            outcome = enforce_deadline(handle, spec.timeout_s, spec.grace_s)
            stdout, stderr = self._collect_logs(container)
            oom = self._was_oom_killed(container)

            if oom:
                status = SandboxStatus.OOM
                error = "container was OOM-killed"
            elif outcome.verdict is WatchdogVerdict.EXITED:
                status = SandboxStatus.COMPLETED
                error = None
            else:
                status = SandboxStatus.TIMEOUT
                error = f"exceeded {spec.timeout_s}s deadline ({outcome.verdict})"

            result = SandboxResult(
                spec=spec,
                status=status,
                exit_code=outcome.exit_code,
                stdout=stdout,
                stderr=stderr,
                started_at=started_at,
                finished_at=datetime.now(UTC),
                container_id=container_id,
                image_digest=digest,
                error=error,
                duration_s=time.monotonic() - started_monotonic,
            )
        except Exception as exc:
            log.error(
                "sandbox.run_failed",
                run_id=spec.run_id,
                analyzer=spec.analyzer,
                error=str(exc),
            )
            result = SandboxResult.failure(
                spec,
                SandboxStatus.ERROR,
                str(exc),
                started_at=started_at,
                container_id=container_id,
                duration_s=time.monotonic() - started_monotonic,
            )
        finally:
            if spec.auto_remove:
                _quiet(container.remove, force=True)

        log.info(
            "sandbox.finished",
            run_id=spec.run_id,
            analyzer=spec.analyzer,
            status=result.status,
            exit_code=result.exit_code,
            duration_s=round(result.duration_s, 2),
        )
        return result

    # -- reaper support ----------------------------------------------------
    def list_managed(self) -> Sequence[ManagedContainer]:
        try:
            containers = self.client.containers.list(
                all=True, filters={"label": f"{MANAGED_LABEL}=true"}
            )
        except Exception as exc:
            raise DockerUnavailable(f"could not list containers: {exc}") from exc

        managed: list[ManagedContainer] = []
        for container in containers:
            attrs = container.attrs or {}
            labels = attrs.get("Config", {}).get("Labels") or {}
            managed.append(
                ManagedContainer(
                    container_id=str(container.id),
                    run_id=labels.get("bare.run", ""),
                    analyzer=labels.get("bare.analyzer", ""),
                    created_at=_parse_docker_time(attrs.get("Created")),
                    running=attrs.get("State", {}).get("Running", False),
                    name=str(getattr(container, "name", "")),
                )
            )
        return managed

    def remove(self, container_id: str, *, force: bool = True) -> None:
        try:
            container = self.client.containers.get(container_id)
        except Exception as exc:
            if _is_not_found(exc):
                return  # idempotent: already gone is success
            raise
        try:
            container.remove(force=force)
        except Exception as exc:
            if _is_not_found(exc):
                return
            raise

    # -- internals ---------------------------------------------------------
    def _validate_mounts(self, spec: SandboxSpec) -> None:
        for mount in spec.mounts:
            source = Path(mount.source).resolve()
            if not source.is_relative_to(self._run_root):
                raise ValueError(
                    f"mount source {source} is outside the run root {self._run_root}; "
                    "analyzers may only see per-run staging directories"
                )

    def _to_host_path(self, source: str) -> str:
        """Rewrite a local path into the path the Docker daemon will resolve.

        A no-op unless ``host_run_root`` was configured. The host root's own
        style decides how the result is joined: a Windows host reached from a
        Linux worker needs backslashes, and ``pathlib`` on the worker would
        happily produce a POSIX path that the daemon then fails to find.
        """
        resolved = Path(source).resolve()
        if self._host_run_root is None:
            return str(resolved)

        relative = resolved.relative_to(self._run_root)
        looks_like_windows = "\\" in self._host_run_root or (
            len(self._host_run_root) > 1 and self._host_run_root[1] == ":"
        )
        root: PureWindowsPath | PurePosixPath = (
            PureWindowsPath(self._host_run_root)
            if looks_like_windows
            else PurePosixPath(self._host_run_root)
        )
        return str(root.joinpath(*relative.parts))

    def _build_create_kwargs(self, spec: SandboxSpec) -> dict[str, Any]:
        from docker.types import Ulimit  # local import keeps import-time cost off the API

        security_opt = []
        if spec.no_new_privileges:
            security_opt.append("no-new-privileges:true")
        profile = self._load_seccomp(spec.seccomp_profile)
        if profile is not None:
            security_opt.append(f"seccomp={profile}")

        if spec.network is not NetworkMode.NONE:
            # Sinkhole networking arrives with dynamic analysis (M5). Failing
            # here is deliberate: silently falling back to a bridge would hand
            # an artifact real egress.
            raise NotImplementedError(
                f"network mode {spec.network} is not implemented; "
                "dynamic analysis with a sinkhole netns lands in M5"
            )

        return {
            "image": spec.image,
            "command": list(spec.command) or None,
            "environment": dict(spec.env),
            "user": spec.user,
            "network_mode": "none",
            "read_only": spec.read_only_rootfs,
            "cap_drop": list(spec.cap_drop),
            "cap_add": list(spec.cap_add) or None,
            "security_opt": security_opt,
            "tmpfs": {str(t.target): t.to_options() for t in spec.tmpfs},
            "volumes": {
                self._to_host_path(m.source): {
                    "bind": str(m.target),
                    "mode": "rw" if m.mode is MountMode.READ_WRITE else "ro",
                }
                for m in spec.mounts
            },
            "mem_limit": spec.mem_limit_bytes,
            "memswap_limit": spec.mem_limit_bytes,  # no swap: swapping hides OOM as a hang
            "nano_cpus": spec.nano_cpus,
            "pids_limit": spec.pids_limit,
            "ulimits": [
                Ulimit(name=u.name, soft=u.soft, hard=u.hard_or_soft) for u in spec.ulimits
            ],
            "labels": spec.labels,
            "detach": True,
            "auto_remove": False,  # see module docstring
            "tty": False,
            "stdin_open": False,
            "working_dir": "/work",
        }

    def _load_seccomp(self, profile_path: str | None) -> str | None:
        if profile_path is None:
            return None
        if profile_path in self._seccomp_cache:
            return self._seccomp_cache[profile_path]

        path = Path(profile_path)
        if not path.is_absolute():
            path = self._repo_root / path
        if not path.is_file():
            raise FileNotFoundError(f"seccomp profile {path} not found; refusing to run without it")
        # Parse then re-serialise: a malformed profile must fail here, loudly,
        # not be handed to the daemon which may or may not reject it.
        content = json.dumps(json.loads(path.read_text(encoding="utf-8")), separators=(",", ":"))
        self._seccomp_cache[profile_path] = content
        return content

    def _resolve_digest(self, image: str) -> str | None:
        try:
            attrs = self.client.images.get(image).attrs
        except Exception:
            return None
        repo_digests = attrs.get("RepoDigests") or []
        if repo_digests:
            return str(repo_digests[0])
        return str(attrs.get("Id") or "") or None

    def _collect_logs(self, container: Any) -> tuple[bytes, bytes]:
        def read(*, stdout: bool, stderr: bool) -> bytes:
            try:
                data = container.logs(stdout=stdout, stderr=stderr, timestamps=False)
            except Exception as exc:
                log.warning("sandbox.log_read_failed", error=str(exc))
                return b""
            raw = data.encode("utf-8", "replace") if isinstance(data, str) else bytes(data)
            if len(raw) > _MAX_LOG_BYTES:
                # A runaway analyzer must not be able to OOM the orchestrator
                # through its log stream.
                return raw[:_MAX_LOG_BYTES] + b"\n[bare: log truncated]\n"
            return raw

        return read(stdout=True, stderr=False), read(stdout=False, stderr=True)

    def _offer_output(self, spec: SandboxSpec, container: Any, on_output: OutputCallback) -> None:
        """Hand a live consumer the output so far. Never raises.

        A broken consumer — a bucket that is down, a redaction that throws —
        must not turn a healthy analyzer into a degraded stage, so its failure
        is logged here and the wait carries on (ADR-0008, ADR-0033).
        """
        try:
            stdout, stderr = self._collect_logs(container)
            on_output(stdout, stderr)
        except Exception as exc:
            log.warning(
                "sandbox.live_output_failed",
                run_id=spec.run_id,
                analyzer=spec.analyzer,
                error=str(exc),
            )

    def _was_oom_killed(self, container: Any) -> bool:
        try:
            container.reload()
            return bool((container.attrs or {}).get("State", {}).get("OOMKilled", False))
        except Exception:
            return False


def _is_not_found(exc: BaseException) -> bool:
    return type(exc).__name__ == "NotFound" or "404" in str(exc)


def _parse_docker_time(value: str | None) -> datetime:
    if not value:
        return datetime.now(UTC)
    # Docker emits RFC3339 with nanosecond precision, which fromisoformat
    # rejects before 3.11 and still dislikes at 9 digits; trim to microseconds.
    text = value.replace("Z", "+00:00")
    if "." in text:
        head, _, tail = text.partition(".")
        frac, sign, offset = _split_offset(tail)
        text = f"{head}.{frac[:6]}{sign}{offset}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return datetime.now(UTC)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _split_offset(tail: str) -> tuple[str, str, str]:
    for sign in ("+", "-"):
        if sign in tail:
            frac, _, offset = tail.partition(sign)
            return frac, sign, offset
    return tail, "", ""
