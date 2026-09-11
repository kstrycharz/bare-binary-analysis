"""Analyzer image naming.

The tag used to be hard-coded in eight places. What matters now is that the one
configuration point behaves, and — more importantly — that leaving it unset is
indistinguishable from the old hard-coded behaviour, because every existing
workflow depends on that.
"""

from __future__ import annotations

import pytest

from core.sandbox.images import ANALYZERS, DEFAULT_TAG, analyzer_image, analyzer_tag
from tests.compose import compose_service


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start from no configuration, whatever the developer's shell exports."""
    monkeypatch.delenv("BARE_ANALYZER_TAG", raising=False)
    for name in ANALYZERS:
        monkeypatch.delenv(f"BARE_{name.upper()}_IMAGE", raising=False)


class TestBackwardCompatibility:
    """Unset must be identical to the behaviour this replaced."""

    def test_the_default_is_exactly_what_was_hard_coded(self) -> None:
        assert analyzer_image("hello") == "bare/hello:dev"
        assert analyzer_image("static") == "bare/static:dev"
        assert analyzer_image("unpack") == "bare/unpack:dev"

    def test_an_exported_but_empty_tag_falls_back(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The usual shape of a broken deployment script. Honouring it would
        produce `bare/static:` and a daemon error that says nothing about
        the cause."""
        monkeypatch.setenv("BARE_ANALYZER_TAG", "   ")
        assert analyzer_image("static") == "bare/static:dev"

    def test_the_default_constant_matches_the_documented_one(self) -> None:
        assert DEFAULT_TAG == "dev"
        assert analyzer_tag() == "dev"


class TestTheTagIsConfigurable:
    @pytest.mark.parametrize("tag", ["latest", "0.1.0", "a3f9c21", "v2.0.0-rc1"])
    def test_every_analyzer_picks_up_the_tag(
        self, tag: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BARE_ANALYZER_TAG", tag)
        for name in ANALYZERS:
            assert analyzer_image(name) == f"bare/{name}:{tag}"

    def test_surrounding_whitespace_is_ignored(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`export BARE_ANALYZER_TAG="0.1.0 "` is a typo, not a tag."""
        monkeypatch.setenv("BARE_ANALYZER_TAG", "  0.1.0  ")
        assert analyzer_image("static") == "bare/static:0.1.0"

    def test_it_is_read_at_call_time_not_at_import(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The constants this replaced were evaluated once when the module
        loaded, so a worker that set the variable after start-up could not
        change them."""
        monkeypatch.setenv("BARE_ANALYZER_TAG", "first")
        assert analyzer_image("static") == "bare/static:first"
        monkeypatch.setenv("BARE_ANALYZER_TAG", "second")
        assert analyzer_image("static") == "bare/static:second"


class TestPerAnalyzerOverride:
    """`BARE_<NAME>_IMAGE` predates the tag setting and must keep
    working; it is also the only way to pin a digest or move one analyzer to a
    different registry."""

    def test_a_full_reference_wins_over_the_tag(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BARE_ANALYZER_TAG", "0.1.0")
        monkeypatch.setenv(
            "BARE_STATIC_IMAGE", "registry.internal/bare/static@sha256:abc123"
        )
        assert analyzer_image("static") == "registry.internal/bare/static@sha256:abc123"
        # and only that one analyzer is affected
        assert analyzer_image("unpack") == "bare/unpack:0.1.0"

    def test_an_empty_override_does_not_shadow_the_tag(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BARE_ANALYZER_TAG", "0.1.0")
        monkeypatch.setenv("BARE_STATIC_IMAGE", "")
        assert analyzer_image("static") == "bare/static:0.1.0"


class TestTheBuildAndTheRunAgree:
    """A tag the build produces but the orchestrator does not run is a scan
    that fails with 'image not found' at the worst possible moment.

    The build lives in docker-compose.yml since ADR-0028 — the analyzer images
    are Compose services so that one `docker compose up` builds them — so that
    is where the tag has to be checked. The Makefile and its PowerShell twin
    delegate, and are checked for the delegation rather than for a `-t` flag
    they no longer carry.
    """

    def test_compose_builds_every_analyzer_at_the_configured_tag(self) -> None:
        from pathlib import Path

        compose = Path("docker-compose.yml").read_text(encoding="utf-8")
        for name in ANALYZERS:
            assert f"  analyzer-{name}:" in compose, f"no analyzer-{name} service"
            # `:-` and not `-`: an exported-but-empty variable must reach the
            # default, which is where analyzer_tag() puts it too.
            assert (
                f"image: bare/{name}:${{BARE_ANALYZER_TAG:-{DEFAULT_TAG}}}" in compose
            ), f"analyzer-{name} does not follow BARE_ANALYZER_TAG"

    def test_the_worker_waits_for_every_analyzer_image(self) -> None:
        """`docker compose up -d worker` must drag the builds in with it rather
        than starting a worker that has nothing to spawn."""
        from pathlib import Path

        compose = Path("docker-compose.yml").read_text(encoding="utf-8")
        worker = compose.split("  worker:", 1)[1].split("\n  worker-heavy:", 1)[0]
        for name in ANALYZERS:
            assert f"analyzer-{name}:" in worker, f"worker does not depend on analyzer-{name}"

    def test_compose_never_tries_to_pull_an_analyzer(self) -> None:
        """`bare/static` parses as a Docker Hub reference, and Compose's
        default policy pulls an image it cannot find locally. On a fresh machine
        that means Docker Hub, no such repository, and "pull access denied for
        bare/static" — the build that was meant to happen never runs."""
        for name in ANALYZERS:
            service = compose_service(f"analyzer-{name}")
            assert "pull_policy: build" in service, (
                f"analyzer-{name} has no `pull_policy: build`; Compose will try to "
                f"pull bare/{name} from a registry that does not have it"
            )

    def test_the_makefile_delegates_to_those_services(self) -> None:
        from pathlib import Path

        makefile = Path("Makefile").read_text(encoding="utf-8")
        for name in ANALYZERS:
            assert f"image-{name}:" in makefile, f"Makefile has no image-{name} target"
            assert f"$(BUILD_ANALYZER) analyzer-{name}" in makefile

    def test_the_powershell_twin_builds_the_same_set(self) -> None:
        """`./make.ps1 <target>` is documented as mirroring every Makefile
        target, so the two cannot disagree about which images exist."""
        from pathlib import Path

        script = Path("make.ps1").read_text(encoding="utf-8")
        for name in ANALYZERS:
            assert f"'image-{name}'" in script
            assert f"Build-Analyzer 'analyzer-{name}'" in script
