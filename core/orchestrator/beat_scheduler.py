"""The scheduler service with an honest heartbeat (bounty: `beat-healthcheck`).

`celery beat` answers no `inspect ping` — it is not a worker node — so a
wedged scheduler was visible only in logs, which compose's comment used to
say out loud. ADR-0033 records what changed.

The mechanism: a subclass of the persistent scheduler that touches a file
each time `tick()` returns. The tick loop sleeps at most
`Scheduler.max_interval` — Celery derives it from the *nearest* schedule entry
or `beat_max_loop_interval`, whichever is smaller — and measured on the real
image, beat idles with `maxinterval -> 5.00 minutes`. So the app config pins
`beat_max_loop_interval` (30 s) and this scheduler does one `touch()` per
tick: the heartbeat lands on a 30-second rhythm even when nothing is due.
That costs one syscall per tick and turns "beat is up" from a guess into a
file's mtime.

`tick()` is called immediately at loop start, so the file exists from the
first second of the first container start — no separate "started" stamp is
needed to keep the first healthcheck window honest.
"""

from __future__ import annotations

import os
from pathlib import Path

from celery.beat import PersistentScheduler

from core.config import get_settings

# Healthcheck contract. The tick loop is bounded by BEAT_MAX_LOOP_INTERVAL_S
# (wired in celery_app), so a heartbeat older than GRACE_S can only mean the
# loop is not ticking — wedged, blocked on a broker write, or stopped — not
# merely idle between sweeps.
BEAT_MAX_LOOP_INTERVAL_S = 30
GRACE_S = 4 * BEAT_MAX_LOOP_INTERVAL_S


def heartbeat_path() -> Path:
    """The heartbeat file: under the data volume, shared by the image's two
    beat processes (the scheduler and the healthcheck invocation) without any
    wiring between them. Env-overridable so tests can point both at a tmpdir.
    """
    override = os.environ.get("BARE_BEAT_HEARTBEAT")
    if override:
        return Path(override)
    return Path(get_settings().data_dir) / "beat" / "heartbeat"


class HeartbeatScheduler(PersistentScheduler):  # type: ignore[misc]
    """PersistentScheduler plus one touch() per tick.

    The ignore: celery ships no type information (pyproject's
    ignore_missing_imports), so the base is `Any` and strict mypy refuses the
    subclass declaration even though it is sound at runtime — the same
    thin-annotated-boundary stance as the driver code over docker-py.
    """

    def tick(self) -> float:
        interval = float(super().tick())  # Any by declaration; float() is the annotation
        self._touch()
        return interval

    @staticmethod
    def _touch() -> None:
        beat_dir = heartbeat_path()
        try:
            beat_dir.parent.mkdir(parents=True, exist_ok=True)
            with beat_dir.open("a"):
                os.utime(beat_dir, None)
        except OSError:
            # A heartbeat that cannot be written must not stop the scheduler
            # from scheduling: the sweeps it drives are load-bearing, the
            # proof of life is not. The healthcheck fails loudly instead —
            # a stale heartbeat is exactly the signal, whatever caused it.
            pass
