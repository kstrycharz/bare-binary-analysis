"""Whether the scheduler is still ticking (bounty: `beat-healthcheck`).

The counterpart to `core/orchestrator/health.py` for the one service neither
that module nor `celery inspect ping` can cover: beat answers no control
broadcast, and the slim image has no pgrep to fake a process check with.
Instead of trusting a process listing, this reads the heartbeat file that
`HeartbeatScheduler` touches once per tick (ADR-0033) and asks the only
question the healthcheck exists to answer: *has the tick loop run recently?*

Run as the compose healthcheck::

    python -m core.orchestrator.beat_health

It is deliberately about liveness, not correctness: a beat that is ticking
while its broker connection is broken will still pass this. That failure
mode is visible where it belongs — the queued work not arriving — and a
healthcheck that also probed Redis would just be `readyz` wearing a cape.
"""

from __future__ import annotations

import sys
import time

from core.orchestrator.beat_scheduler import GRACE_S, heartbeat_path


def heartbeat_age_s() -> float | None:
    """Seconds since the last tick touch, or None if there never was one."""
    try:
        return time.time() - heartbeat_path().stat().st_mtime
    except OSError:
        return None


def main() -> int:
    age = heartbeat_age_s()
    if age is None:
        sys.stderr.write(f"beat: no heartbeat at {heartbeat_path()} — scheduler never ticked\n")
        return 1
    if age > GRACE_S:
        sys.stderr.write(f"beat: heartbeat {age:.0f}s old (limit {GRACE_S}s) — wedged\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
