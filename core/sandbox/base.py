"""The sandbox driver interface.

Analyzer code never imports a concrete runtime. It asks a :class:`SandboxDriver`
to run a :class:`~core.sandbox.spec.SandboxSpec` and gets back a
:class:`SandboxResult`. That indirection is why Podman (rootless) and gVisor can
land later without touching a single analyzer — retrofitting it would mean
rewriting every analyzer, which is exactly the trap this interface avoids.
"""

from __future__ import annotations

import abc
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

from core.sandbox.spec import SandboxSpec

OutputCallback = Callable[[bytes, bytes], None]
"""Receives a running container's stdout and stderr *so far*.

Whole streams rather than deltas, so a consumer that skips a call loses
nothing, and capped exactly as the final :class:`SandboxResult` streams are.
It is called on the thread enforcing the container's deadline, so it must be
cheap or throttle itself (ADR-0033)."""


class SandboxStatus(StrEnum):
    """Terminal state of a container run.

    Only ``COMPLETED`` means the analyzer got to say what it found. Every other
    value is degraded: the run continues, the analyzer is marked, and the report
    says so rather than silently reporting "no findings".
    """

    COMPLETED = "completed"
    """Container exited on its own. Check ``exit_code`` for success/failure."""

    TIMEOUT = "timeout"
    """Wall-clock deadline hit; container was terminated by the watchdog."""

    OOM = "oom"
    """Kernel OOM-killed the container. Common with Ghidra on large binaries."""

    START_FAILED = "start_failed"
    """Image missing, spec rejected by the runtime, daemon unreachable."""

    ERROR = "error"
    """Driver-level failure after start (daemon died, log stream broke)."""

    @property
    def is_degraded(self) -> bool:
        return self is not SandboxStatus.COMPLETED


@dataclass(frozen=True, slots=True)
class SandboxResult:
    """Everything the orchestrator learns about one container run."""

    spec: SandboxSpec
    status: SandboxStatus
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    started_at: datetime
    finished_at: datetime
    container_id: str | None = None
    image_digest: str | None = None
    """Resolved ``sha256:...`` of the image that actually ran. Recorded in the
    run manifest — tags drift, digests do not (§2.5)."""
    error: str | None = None
    """Human-readable reason for a non-``COMPLETED`` status."""

    duration_s: float = 0.0
    """Elapsed time, measured with a **monotonic** clock.

    Deliberately a stored field rather than ``finished_at - started_at``.
    Wall-clock time can jump backwards — NTP correction, VM suspend and
    resume — and Docker Desktop's VM does it often enough that this produced a
    negative duration in practice. The timestamps stay for display and audit;
    the number a human reads comes from a clock that only moves forward.
    """

    @property
    def ok(self) -> bool:
        return self.status is SandboxStatus.COMPLETED and self.exit_code == 0

    @classmethod
    def failure(
        cls,
        spec: SandboxSpec,
        status: SandboxStatus,
        error: str,
        *,
        started_at: datetime | None = None,
        container_id: str | None = None,
        stdout: bytes = b"",
        stderr: bytes = b"",
        duration_s: float = 0.0,
    ) -> SandboxResult:
        now = datetime.now(UTC)
        return cls(
            spec=spec,
            status=status,
            exit_code=None,
            stdout=stdout,
            stderr=stderr,
            started_at=started_at or now,
            finished_at=now,
            container_id=container_id,
            error=error,
            duration_s=max(duration_s, 0.0),
        )


@dataclass(frozen=True, slots=True)
class ManagedContainer:
    """A container the reaper may be responsible for."""

    container_id: str
    run_id: str
    analyzer: str
    created_at: datetime
    running: bool
    name: str = ""


@dataclass(frozen=True, slots=True)
class DriverHealth:
    healthy: bool
    driver: str
    version: str = ""
    detail: str = ""
    warnings: tuple[str, ...] = field(default_factory=tuple)


class SandboxDriver(abc.ABC):
    """Runtime-agnostic container executor.

    Implementations must honour every field of the spec or refuse to run. A
    driver that silently ignores, say, ``pids_limit`` is worse than one that
    raises, because the isolation tests would pass against a boundary that
    isn't there.
    """

    name: str = "abstract"

    @abc.abstractmethod
    def run(self, spec: SandboxSpec, *, on_output: OutputCallback | None = None) -> SandboxResult:
        """Run one container to completion, timeout, or failure.

        Must not raise for analyzer-level failures — a crashed or hung analyzer
        is a :class:`SandboxResult` with a degraded status, because one bad
        analyzer must never fail the whole run. Raises only for programmer
        error (an invalid spec).

        ``on_output``, when given, is offered the container's output so far
        while it runs — the only view of an analyzer before its container is
        reaped (ADR-0033). It must never change the result: a consumer that
        raises is logged and ignored, and the deadline is enforced as if it
        were absent.
        """

    @abc.abstractmethod
    def health(self) -> DriverHealth:
        """Check the runtime is reachable and correctly configured."""

    @abc.abstractmethod
    def list_managed(self) -> Sequence[ManagedContainer]:
        """All containers labelled as ours, running or not. Used by the reaper."""

    @abc.abstractmethod
    def remove(self, container_id: str, *, force: bool = True) -> None:
        """Remove a container. Must be idempotent — already-gone is success."""

    def close(self) -> None:  # noqa: B027 - optional hook, deliberately not abstract
        """Release runtime client resources.

        Not abstract: a driver with no persistent client (the stubs, and any
        future in-process runtime) should not be forced to write an empty
        override just to satisfy the interface.
        """
