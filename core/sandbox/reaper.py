"""Orphaned-container cleanup.

If the orchestrator crashes mid-run, its containers keep running, holding
memory and CPU that the next run needs. The reaper is the backstop: it runs
periodically, looks at everything labelled ``bare.managed``, and removes
whatever belongs to a run that is no longer active or that has outlived the
maximum age.

Deliberately conservative in one direction: it will never remove a container
whose run id is in the active set, no matter how old, because a legitimately
long Ghidra job must not be reaped out from under a live run. The watchdog owns
deadlines; the reaper owns orphans.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import structlog

from core.sandbox.base import ManagedContainer, SandboxDriver

log = structlog.get_logger(__name__)

DEFAULT_MAX_AGE = timedelta(hours=6)


@dataclass(frozen=True, slots=True)
class ReapReport:
    """What one reaper pass did. Surfaced in ops metrics, not in findings."""

    inspected: int
    removed: tuple[str, ...] = field(default_factory=tuple)
    failed: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    """``(container_id, error)`` for removals that did not succeed."""

    @property
    def removed_count(self) -> int:
        return len(self.removed)


class Reaper:
    def __init__(self, driver: SandboxDriver, *, max_age: timedelta = DEFAULT_MAX_AGE) -> None:
        self._driver = driver
        self._max_age = max_age

    def reap(
        self,
        active_run_ids: Iterable[str] | None,
        *,
        now: datetime | None = None,
    ) -> ReapReport:
        """Remove containers belonging to finished runs, or ones too old to trust.

        ``active_run_ids`` must be the authoritative set of runs the
        orchestrator currently considers in flight. Passing an incomplete set
        would reap live work, so callers read it from the database, never from
        in-process state that a crash could have lost.

        Pass ``None`` when liveness genuinely cannot be determined. That
        degrades the sweep to age-based reaping only — it will never remove a
        container that might belong to a live run, at the cost of leaving
        orphans around until they age out.
        """
        now = now or datetime.now(UTC)
        liveness_known = active_run_ids is not None
        active = set(active_run_ids or ())
        containers = list(self._driver.list_managed())

        removed: list[str] = []
        failed: list[tuple[str, str]] = []

        for container in containers:
            reason = self._reap_reason(container, active, now, liveness_known=liveness_known)
            if reason is None:
                continue
            try:
                self._driver.remove(container.container_id, force=True)
            except Exception as exc:  # driver-specific; never let one failure stop the sweep
                log.warning(
                    "reaper.remove_failed",
                    container_id=container.container_id,
                    run_id=container.run_id,
                    error=str(exc),
                )
                failed.append((container.container_id, str(exc)))
                continue
            log.info(
                "reaper.removed",
                container_id=container.container_id,
                run_id=container.run_id,
                analyzer=container.analyzer,
                reason=reason,
            )
            removed.append(container.container_id)

        return ReapReport(
            inspected=len(containers),
            removed=tuple(removed),
            failed=tuple(failed),
        )

    def _reap_reason(
        self,
        container: ManagedContainer,
        active: set[str],
        now: datetime,
        *,
        liveness_known: bool,
    ) -> str | None:
        age = now - container.created_at
        if age > self._max_age:
            # Age wins over liveness: something running for six hours has
            # escaped its watchdog, which means the watchdog is gone.
            return "max_age_exceeded"
        if liveness_known and container.run_id not in active:
            return "run_not_active"
        return None
