"""Beat's heartbeat: the write, the read, and the contract between them.

Bounty: beat-healthcheck. Beat answers no `celery inspect ping` (it is not a
worker node) and the slim image has no pgrep, so the check cannot ask the
process — it reads a file the scheduler touches per tick and asks how old it
is (ADR-0033). Three things are worth holding still with tests:

- the touch actually happens on the tick path, and a tick that cannot touch
  does not stop the scheduler from scheduling,
- the tick rhythm is genuinely bounded — `beat_max_loop_interval` is wired,
  because stock beat idles for minutes and a minute-granularity heartbeat
  proves nothing about the wedged-vs-idle question, and
- the age check has a floor: fresh passes, stale and missing fail, with a
  message naming which.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from core.orchestrator.beat_health import heartbeat_age_s, main
from core.orchestrator.beat_scheduler import (
    BEAT_MAX_LOOP_INTERVAL_S,
    GRACE_S,
    HeartbeatScheduler,
    heartbeat_path,
)
from core.orchestrator.celery_app import celery_app


@pytest.fixture(autouse=True)
def heartbeat_in_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    # Both processes of the real deployment — beat and the healthcheck —
    # resolve the path through this env override; doing the same here is what
    # lets the test exercise the real code path rather than a patched-out one.
    path = tmp_path / "beat" / "heartbeat"
    monkeypatch.setenv("BARE_BEAT_HEARTBEAT", str(path))
    return path


class TestTouch:
    def test_a_tick_touches_the_file(self, heartbeat_in_tmp: Path) -> None:
        """The scheduler is driven directly here — no broker, no Celery app —
        by exercising the one method that carries the heartbeat."""
        assert not heartbeat_in_tmp.exists()
        HeartbeatScheduler._touch()
        assert heartbeat_in_tmp.is_file()
        assert heartbeat_age_s() is not None
        assert heartbeat_age_s() < 5

    def test_touch_survives_an_unwritable_path_without_raising(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Scheduling beats proof-of-scheduling (ADR-0008 in spirit): a failed
        touch must not stop the sweeps. The stale heartbeat then fails the
        healthcheck, which is the honest signal."""
        monkeypatch.setenv("BARE_BEAT_HEARTBEAT", "/proc/nonexistent-dir-for-test/hb")
        HeartbeatScheduler._touch()  # raises nothing

    def test_path_honours_the_override(self, heartbeat_in_tmp: Path) -> None:
        assert heartbeat_path() == heartbeat_in_tmp


class TestAgeCheck:
    def test_fresh_is_healthy(self, heartbeat_in_tmp: Path) -> None:
        heartbeat_in_tmp.parent.mkdir(parents=True)
        heartbeat_in_tmp.touch()
        assert main() == 0

    def test_stale_is_unhealthy(self, heartbeat_in_tmp: Path) -> None:
        heartbeat_in_tmp.parent.mkdir(parents=True)
        heartbeat_in_tmp.touch()
        old = time.time() - GRACE_S - 60
        os.utime(heartbeat_in_tmp, (old, old))
        assert main() == 1

    def test_missing_is_unhealthy(self, heartbeat_in_tmp: Path) -> None:
        assert heartbeat_age_s() is None
        assert main() == 1

    def test_the_grace_window_bounded_by_the_tick_contract(self) -> None:
        """GRACE_S must exceed a real tick interval — otherwise an idle beat
        fails its check between honest ticks."""
        assert GRACE_S > BEAT_MAX_LOOP_INTERVAL_S


class TestWiring:
    def test_the_app_uses_the_heartbeat_scheduler(self) -> None:
        assert celery_app.conf.beat_scheduler == (
            "core.orchestrator.beat_scheduler.HeartbeatScheduler"
        )

    def test_the_tick_interval_is_pinned(self) -> None:
        """The load-bearing line of ADR-0033. Measured on the real image,
        default beat wakes at maxinterval->5m with only the sweeps scheduled,
        so without this pin the 'heartbeat' is a five-minute heartbeat and the
        120s grace makes every check about the grace vs. sleep race."""
        assert celery_app.conf.beat_max_loop_interval == BEAT_MAX_LOOP_INTERVAL_S

    def test_the_scheduler_subclass_resolves_as_celery_would_resolve_it(self) -> None:
        """`beat_scheduler` is a dotted path Celery resolves with
        `symbol_by_name` at beat startup; a typo or a moved class fails the
        service, not the test suite — so the test performs that resolution."""
        from celery.utils.imports import symbol_by_name

        assert symbol_by_name(celery_app.conf.beat_scheduler) is HeartbeatScheduler
