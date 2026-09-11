"""Guarantees that live in docker-compose.yml rather than in Python.

A deployment is two commands and no file editing (CLAUDE.md §2), which puts
real correctness properties in the compose file: that nothing starts against an
unmigrated database, that a wedged worker is visible, that logs cannot fill the
disk. None of those are expressible as a Python assertion about `core/`, so
they are asserted against the file itself.
"""

from __future__ import annotations

import pytest

from tests.compose import COMPOSE_PATH, compose_service

# Everything that runs indefinitely. One-shot services (the analyzer builds,
# minio-init) exit immediately and are excluded on purpose.
LONG_LIVED = ("postgres", "redis", "minio", "api", "worker", "worker-heavy", "beat", "web")

# Only the API migrates: api/main.py's lifespan calls upgrade_schema(), and
# uvicorn does not serve until the lifespan has finished, so a passing /healthz
# means the schema exists.
NEEDS_THE_SCHEMA = ("worker", "worker-heavy", "beat", "web")


class TestNothingRunsAgainstAnUnmigratedDatabase:
    @pytest.mark.parametrize("name", NEEDS_THE_SCHEMA)
    def test_it_waits_for_a_healthy_api(self, name: str) -> None:
        """Without this edge the service starts against a database that has no
        tables yet, and the first thing it touches is a 500 rather than a wait."""
        service = compose_service(name)
        assert "api:" in service, f"{name} does not depend on the API"
        api_block = service.split("api:", 1)[1]
        assert "condition: service_healthy" in api_block.split("\n\n", 1)[0], (
            f"{name} depends on the API but not on it being healthy; "
            "service_started only means the process was launched"
        )

    def test_the_api_is_the_only_migrator(self) -> None:
        """If a second service ever migrates, the dependency edges above stop
        being the thing that orders schema against use."""
        from pathlib import Path

        sources = [
            path
            for directory in ("core", "api", "cli", "reporting", "mcp")
            for path in Path(directory).rglob("*.py")
        ]
        callers = sorted(
            # as_posix(), not str(): on Windows str(Path) yields "api\main.py"
            # and the comparison below is against a forward-slash literal, so
            # this assertion could only ever pass on Linux (ADR-0006).
            path.as_posix()
            for path in sources
            if any(
                "upgrade_schema()" in line and not line.lstrip().startswith("def ")
                for line in path.read_text(encoding="utf-8").splitlines()
            )
        )
        assert callers == ["api/main.py"], (
            f"upgrade_schema() is called from {callers}; the compose dependency "
            "edges assume the API is the only migrator"
        )


class TestAWedgedWorkerIsVisible:
    @pytest.mark.parametrize("name", ("worker", "worker-heavy"))
    def test_the_worker_has_a_healthcheck(self, name: str) -> None:
        """CLAUDE.md §6 carried this as debt: a wedged worker was visible only
        in logs."""
        service = compose_service(name)
        assert "healthcheck:" in service, f"{name} has no healthcheck"
        assert "core.orchestrator.health" in service

    def test_beat_says_why_it_has_none(self) -> None:
        """Beat answers no `inspect ping`. Inventing a check that cannot fail
        would be worse than the gap, so the gap is written down."""
        service = compose_service("beat")
        # The key, not the word — the comment explaining the absence says
        # "No healthcheck:" and would otherwise match.
        assert "    healthcheck:" not in service
        assert "No healthcheck" in service


class TestLogsCannotFillTheDisk:
    @pytest.mark.parametrize("name", LONG_LIVED)
    def test_it_rotates_its_logs(self, name: str) -> None:
        """Docker's default json-file driver never rotates."""
        assert "<<: *logging" in compose_service(name), f"{name} has unbounded logs"


class TestItRestartsUnlessStopped:
    @pytest.mark.parametrize("name", LONG_LIVED)
    def test_it_comes_back_after_a_crash(self, name: str) -> None:
        assert "restart: unless-stopped" in compose_service(name)


class TestTheStackBootsWithoutAnEnvFile:
    def test_the_minio_default_password_meets_its_floor(self) -> None:
        """MinIO refuses to start when MINIO_ROOT_PASSWORD is under 8
        characters, and the compose default is what a fresh clone boots with.
        The project-name default was exactly 4 after the BARE rename, so every
        clean `docker compose up` crash-looped minio and the API never came up.
        Keep the default (and any future rename of it) at least 8 characters."""
        import re

        text = COMPOSE_PATH.read_text(encoding="utf-8")
        defaults = re.findall(r"\$\{MINIO_ROOT_PASSWORD:-(.*?)\}", text)
        assert defaults, "no ${MINIO_ROOT_PASSWORD:-...} default in compose"
        for value in defaults:
            assert len(value) >= 8, f"compose default {value!r} is under MinIO's 8-char floor"
