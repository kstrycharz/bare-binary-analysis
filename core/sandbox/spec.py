"""Typed sandbox specification.

Every analyzer container in BARE is described by a :class:`SandboxSpec`.
The spec is the *only* way to ask for a container: drivers accept a spec and
nothing else. This exists so that the isolation posture is declared in one
reviewable place rather than smeared across ``**kwargs`` at a dozen call sites,
and so that a test can assert "no analyzer ever gets network access" by
inspecting specs instead of by reading every analyzer module.

Defaults are the locked-down baseline from ARCHITECTURE.md. Analyzers override
resource limits (Ghidra needs more memory); they must not weaken isolation.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Self

# Non-root uid:gid baked into every analyzer image. Analyzer images MUST create
# this account; the driver refuses to run as root regardless of image default.
ANALYZER_UID = 10001
ANALYZER_GID = 10001

DEFAULT_TIMEOUT_S = 900
DEFAULT_GRACE_S = 10

# Where the driver always mounts the two well-known directories inside the
# container. Analyzer entrypoints read from INPUT_DIR and write to OUTPUT_DIR;
# nothing else is shared with the host.
INPUT_DIR = PurePosixPath("/input")
OUTPUT_DIR = PurePosixPath("/output")


class NetworkMode(StrEnum):
    """Container network attachment.

    ``NONE`` is the only value permitted for static analyzers. ``SINKHOLE`` is
    reserved for opt-in dynamic analysis (M5), where the container is attached
    to an isolated bridge whose sole reachable peer is the sinkhole container.
    There is deliberately no value meaning "the host's network".
    """

    NONE = "none"
    SINKHOLE = "sinkhole"


class MountMode(StrEnum):
    READ_ONLY = "ro"
    READ_WRITE = "rw"


@dataclass(frozen=True, slots=True)
class BindMount:
    """A host directory exposed inside the container.

    ``source`` is a host path (per-run staging or results directory). Drivers
    reject any source outside the configured run root, so a bug in an analyzer
    definition cannot mount ``/`` or the Docker socket.
    """

    source: str
    target: PurePosixPath
    mode: MountMode = MountMode.READ_ONLY


@dataclass(frozen=True, slots=True)
class TmpfsMount:
    """A writable in-memory filesystem. Analyzer scratch space lives here.

    Ownership is explicit, and it has to be: a tmpfs mount masks whatever the
    image did to the underlying directory, and Docker creates it root-owned and
    mode 0755. An image that carefully chowns ``/work`` to the analyzer user
    still ends up with a scratch directory the analyzer cannot write to — which
    looks like a broken analyzer, not a broken mount.
    """

    target: PurePosixPath
    size_bytes: int
    noexec: bool = True
    nosuid: bool = True
    nodev: bool = True
    uid: int = ANALYZER_UID
    gid: int = ANALYZER_GID
    mode: int = 0o770
    """Octal permission bits. 0770 rather than 1777: the container runs a
    single user, so world-writable buys nothing and reads badly in an audit."""

    def to_options(self) -> str:
        """Render as a Docker tmpfs option string (``size=...,noexec,...``)."""
        opts = [
            f"size={self.size_bytes}",
            f"mode={self.mode:o}",
            f"uid={self.uid}",
            f"gid={self.gid}",
        ]
        if self.noexec:
            opts.append("noexec")
        if self.nosuid:
            opts.append("nosuid")
        if self.nodev:
            opts.append("nodev")
        return ",".join(opts)


@dataclass(frozen=True, slots=True)
class Ulimit:
    name: str
    soft: int
    hard: int | None = None

    @property
    def hard_or_soft(self) -> int:
        return self.hard if self.hard is not None else self.soft


_GIB = 1024**3


def _default_tmpfs() -> tuple[TmpfsMount, ...]:
    # /tmp is noexec: analyzers must not stage and run helper binaries there.
    # /work allows exec because unpackers legitimately extract and inspect
    # executables, but stays nosuid+nodev.
    return (
        TmpfsMount(PurePosixPath("/tmp"), size_bytes=2 * _GIB, noexec=True),
        TmpfsMount(PurePosixPath("/work"), size_bytes=8 * _GIB, noexec=False),
    )


def _default_ulimits() -> tuple[Ulimit, ...]:
    return (
        Ulimit("nofile", soft=4096, hard=4096),
        Ulimit("fsize", soft=2 * _GIB, hard=2 * _GIB),
        Ulimit("nproc", soft=512, hard=512),
    )


@dataclass(frozen=True, slots=True)
class SandboxSpec:
    """A single analyzer container run.

    Immutable by design: build a base spec per analyzer, then use
    :meth:`with_overrides` to derive the per-run instance. Nothing mutates a
    spec after the orchestrator has recorded it in the run manifest.
    """

    # --- identity -----------------------------------------------------------
    image: str
    """Image reference. MUST be digest-pinned (``repo@sha256:...``) outside of
    local development; the run manifest records what actually ran."""

    run_id: str
    analyzer: str
    command: tuple[str, ...] = ()
    env: tuple[tuple[str, str], ...] = ()
    """Environment as sorted pairs, not a dict, so specs hash deterministically.
    Provider API keys are never placed here — analyzers have no egress and no
    business holding credentials."""

    # --- isolation ----------------------------------------------------------
    network: NetworkMode = NetworkMode.NONE
    read_only_rootfs: bool = True
    user: str = f"{ANALYZER_UID}:{ANALYZER_GID}"
    cap_drop: tuple[str, ...] = ("ALL",)
    cap_add: tuple[str, ...] = ()
    no_new_privileges: bool = True
    seccomp_profile: str | None = "sandbox/profiles/analyzer.json"
    """Path to a seccomp profile, relative to the repo root. ``None`` means the
    runtime default, which is weaker — only tests may use it."""

    # --- resources ----------------------------------------------------------
    mem_limit_bytes: int = 4 * _GIB
    nano_cpus: int = 2_000_000_000
    pids_limit: int = 512
    tmpfs: tuple[TmpfsMount, ...] = field(default_factory=_default_tmpfs)
    ulimits: tuple[Ulimit, ...] = field(default_factory=_default_ulimits)

    # --- lifecycle ----------------------------------------------------------
    timeout_s: int = DEFAULT_TIMEOUT_S
    grace_s: int = DEFAULT_GRACE_S
    auto_remove: bool = True
    """Driver removes the container once its output has been collected. This is
    *not* the Docker ``--rm`` flag, which races log collection; see ADR-0003."""

    # --- data ---------------------------------------------------------------
    mounts: tuple[BindMount, ...] = ()

    def with_overrides(self, **changes: object) -> Self:
        """Return a copy with fields replaced. Isolation fields are guarded."""
        forbidden = {"network", "read_only_rootfs", "user", "cap_drop", "no_new_privileges"}
        weakened = forbidden & changes.keys()
        if weakened:
            raise ValueError(
                f"refusing to weaken isolation via with_overrides: {sorted(weakened)}; "
                "construct a new SandboxSpec explicitly if this is really intended"
            )
        return replace(self, **changes)  # type: ignore[arg-type]

    @property
    def labels(self) -> dict[str, str]:
        """Labels the reaper uses to find orphaned containers."""
        return {
            "bare.run": self.run_id,
            "bare.analyzer": self.analyzer,
            "bare.managed": "true",
        }

    def validate(self) -> None:
        """Fail loudly on a spec that would run with a weakened boundary.

        Called by drivers before every run. This is the single chokepoint that
        enforces the §5 hard rule, so it is deliberately paranoid.
        """
        errors: list[str] = []

        if self.user in ("0:0", "root", "0", ""):
            errors.append("analyzers must not run as root")
        if "ALL" not in self.cap_drop:
            errors.append("cap_drop must include ALL")
        if self.cap_add:
            errors.append(f"cap_add is not permitted for analyzers: {list(self.cap_add)}")
        if not self.no_new_privileges:
            errors.append("no_new_privileges must be set")
        if not self.read_only_rootfs:
            errors.append("rootfs must be read-only")
        if self.timeout_s <= 0:
            errors.append("timeout_s must be positive")
        if self.grace_s < 0:
            errors.append("grace_s must not be negative")
        if self.pids_limit <= 0:
            errors.append("pids_limit must be positive")
        if self.mem_limit_bytes <= 0:
            errors.append("mem_limit_bytes must be positive")
        if not self.run_id or not self.analyzer:
            errors.append("run_id and analyzer are required for reaper labelling")

        for mount in self.mounts:
            src = mount.source.replace("\\", "/")
            if src.endswith("docker.sock") or "/var/run/docker" in src:
                errors.append("refusing to mount the Docker socket into an analyzer")
            if mount.target == OUTPUT_DIR and mount.mode is not MountMode.READ_WRITE:
                errors.append(f"{OUTPUT_DIR} must be writable")
            if mount.target == INPUT_DIR and mount.mode is not MountMode.READ_ONLY:
                errors.append(f"{INPUT_DIR} must be read-only")

        writable = [m.target for m in self.mounts if m.mode is MountMode.READ_WRITE]
        if len(writable) > 1:
            errors.append(f"at most one writable mount is allowed, got {writable}")

        if errors:
            raise SpecViolation(self, errors)


class SpecViolation(ValueError):  # noqa: N818 - reads better than SpecViolationError
    """A spec that would have run with a weakened isolation boundary."""

    def __init__(self, spec: SandboxSpec, errors: list[str]) -> None:
        self.spec = spec
        self.errors = errors
        joined = "; ".join(errors)
        super().__init__(f"invalid SandboxSpec for analyzer {spec.analyzer!r}: {joined}")
