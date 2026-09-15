"""Placeholder drivers for runtimes we have committed to but not yet built.

These exist so the driver registry, config schema, and docs can reference
``podman`` and ``gvisor`` today, and so that selecting one fails immediately
and legibly rather than silently degrading to Docker. Per the working
agreement, nothing here pretends to work: every method raises.

Tracked in CLAUDE.md "Known issues & tech debt". Podman (rootless) is required
by many enterprises and is scheduled for M6; gVisor is a defence-in-depth
option for operators analysing third-party artifacts.
"""

from __future__ import annotations

from collections.abc import Sequence

from core.sandbox.base import (
    DriverHealth,
    ManagedContainer,
    OutputCallback,
    SandboxDriver,
    SandboxResult,
)
from core.sandbox.spec import SandboxSpec


class _UnimplementedDriver(SandboxDriver):
    name = "unimplemented"
    milestone = "?"

    def _fail(self) -> SandboxResult:
        raise NotImplementedError(
            f"the {self.name!r} sandbox driver is not implemented "
            f"(scheduled for {self.milestone}); use the 'docker' driver"
        )

    def run(self, spec: SandboxSpec, *, on_output: OutputCallback | None = None) -> SandboxResult:
        return self._fail()

    def health(self) -> DriverHealth:
        return DriverHealth(
            healthy=False,
            driver=self.name,
            detail=f"not implemented; scheduled for {self.milestone}",
        )

    def list_managed(self) -> Sequence[ManagedContainer]:
        self._fail()
        raise AssertionError("unreachable")

    def remove(self, container_id: str, *, force: bool = True) -> None:
        self._fail()


class PodmanDriver(_UnimplementedDriver):
    """Rootless Podman. Scheduled for M6.

    The docker-py API surface we use is close to Podman's compatibility
    socket, so this is expected to be a thin subclass of ``DockerDriver`` with
    a different socket path plus handling for rootless uid mapping — which is
    exactly the part that needs real testing, not a guess.
    """

    name = "podman"
    milestone = "M6"


class GvisorDriver(_UnimplementedDriver):
    """Docker with the ``runsc`` runtime. Scheduled for M6."""

    name = "gvisor"
    milestone = "M6"
