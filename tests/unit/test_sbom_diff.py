"""`bare sbom-diff` and the comparison behind it.

The cases are the ways a component diff is wrong in practice: an upgrade shown
as a removal plus an addition, a scoped npm package whose identity is cut at the
wrong `@`, a library bundled twice at two versions, and a "removed" component
that was only outside a truncated walk.
"""

from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from cli.client import ApiError
from cli.main import app
from core.composition import Component, ComponentInventory, Confidence
from core.composition.model import Ecosystem
from reporting.cyclonedx import build_sbom, dump_sbom
from reporting.sbom_diff import (
    SbomDiffError,
    diff_sboms,
    identity,
    render_json,
    render_text,
)

runner = CliRunner()


def doc(
    *components: dict[str, Any],
    name: str = "installer.exe",
    run: str = "run-a",
    complete: bool = True,
) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "component": {
                "name": name,
                "properties": [
                    {"name": "bare:run", "value": run},
                    {"name": "bare:inventory_complete", "value": "true" if complete else "false"},
                ],
            }
        },
        "components": list(components),
    }


def lib(purl: str, *, version: str = "", name: str = "", licence: str = "") -> dict[str, Any]:
    entry: dict[str, Any] = {"type": "library", "purl": purl, "name": name or purl}
    if version:
        entry["version"] = version
    if licence:
        entry["licenses"] = [{"expression": licence}]
    return entry


ZLIB_11 = lib("pkg:generic/zlib@1.2.11", version="1.2.11", name="zlib")
ZLIB_13 = lib("pkg:generic/zlib@1.2.13", version="1.2.13", name="zlib")
LEFT_PAD = lib("pkg:npm/left-pad@1.3.0", version="1.3.0", name="left-pad")


# --- identity ----------------------------------------------------------------


@pytest.mark.parametrize(
    ("purl", "key", "version"),
    [
        ("pkg:generic/zlib@1.2.11", "pkg:generic/zlib", "1.2.11"),
        ("pkg:npm/%40angular/core@12.3.1", "pkg:npm/%40angular/core", "12.3.1"),
        # Written raw by other generators; must not split at the scope's `@`.
        ("pkg:npm/@angular/core@12.3.1", "pkg:npm/@angular/core", "12.3.1"),
        ("pkg:npm/@angular/core", "pkg:npm/@angular/core", ""),
        ("pkg:golang/github.com/spf13/cobra@v1.8.0", "pkg:golang/github.com/spf13/cobra", "v1.8.0"),
        ("pkg:maven/org.x/y@1.0?type=jar#sub/dir", "pkg:maven/org.x/y", "1.0"),
    ],
)
def test_identity_strips_only_the_version(purl: str, key: str, version: str) -> None:
    assert identity({"purl": purl, "name": "x"}) == (key, version)


def test_a_component_without_a_purl_is_matched_by_name() -> None:
    assert identity({"name": "openssl", "version": "3.0.13"}) == ("name:openssl", "3.0.13")


# --- the comparison ----------------------------------------------------------


def test_identical_documents_have_no_changes() -> None:
    diff = diff_sboms(doc(ZLIB_11, LEFT_PAD), doc(LEFT_PAD, ZLIB_11))
    assert not diff.has_changes
    assert diff.unchanged == 2
    assert "No component changes." in render_text(diff)


def test_an_upgrade_is_one_version_change_not_a_removal_and_an_addition() -> None:
    diff = diff_sboms(doc(ZLIB_11), doc(ZLIB_13))
    assert diff.added == () and diff.removed == ()
    (change,) = diff.version_changed
    assert (change.key, change.before, change.after) == (
        "pkg:generic/zlib",
        ("1.2.11",),
        ("1.2.13",),
    )
    assert "1.2.11 -> 1.2.13" in render_text(diff)


def test_added_and_removed_components() -> None:
    diff = diff_sboms(doc(ZLIB_11), doc(LEFT_PAD))
    assert [c.key for c in diff.added] == ["pkg:npm/left-pad"]
    assert [c.key for c in diff.removed] == ["pkg:generic/zlib"]


def test_a_library_bundled_twice_is_a_change_in_its_version_set() -> None:
    diff = diff_sboms(doc(ZLIB_11), doc(ZLIB_11, ZLIB_13))
    (change,) = diff.version_changed
    assert change.after == ("1.2.11", "1.2.13")


def test_a_licence_change_is_reported_even_when_the_version_is_not() -> None:
    before = lib("pkg:npm/thing@1.0.0", version="1.0.0", licence="MIT")
    after = lib("pkg:npm/thing@1.0.0", version="1.0.0", licence="GPL-3.0-only")
    diff = diff_sboms(doc(before), doc(after))
    (change,) = diff.licence_changed
    assert change.before == ("MIT",) and change.after == ("GPL-3.0-only",)
    assert diff.version_changed == ()


def test_an_incomplete_inventory_is_called_out() -> None:
    diff = diff_sboms(doc(ZLIB_11, run="run-a"), doc(run="run-b", complete=False))
    assert diff.incomplete == ("installer.exe (run run-b)",)
    assert "incomplete inventory" in render_text(diff)


def test_output_does_not_depend_on_component_order() -> None:
    components = [lib(f"pkg:npm/p{i}@{i}.0.0", version=f"{i}.0.0") for i in range(30)]
    shuffled = components[:]
    random.Random(7).shuffle(shuffled)
    upgraded = [lib(f"pkg:npm/p{i}@{i}.1.0", version=f"{i}.1.0") for i in range(0, 30, 3)]

    first = diff_sboms(doc(*components), doc(*components[1::3], *upgraded))
    second = diff_sboms(doc(*shuffled), doc(*reversed([*components[1::3], *upgraded])))
    assert render_text(first) == render_text(second)
    assert render_json(first) == render_json(second)


def test_something_that_is_not_an_sbom_is_refused() -> None:
    with pytest.raises(SbomDiffError, match="not a CycloneDX"):
        diff_sboms({"findings": []}, doc())


def test_it_reads_what_the_real_exporter_writes() -> None:
    """Built through build_sbom rather than hand-written, so a change to the
    exporter's shape breaks this test rather than the command."""

    def sbom(version: str, *, truncated: bool = False) -> dict[str, Any]:
        inventory = ComponentInventory(
            components=(
                Component("@babel/parser", version, Ecosystem.NPM, Confidence.DECLARED, "a/b"),
                Component(
                    "github.com/spf13/cobra", "v1.8.0", Ecosystem.GOLANG, Confidence.EMBEDDED, "bin"
                ),
            ),
            files_examined=10,
            truncated=truncated,
        )
        return json.loads(
            dump_sbom(
                build_sbom(
                    inventory,
                    run_id=f"run-{version}",
                    artifact_name="app.exe",
                    artifact_sha256="a" * 64,
                    artifact_size_bytes=1,
                    tool_version="test",
                )
            )
        )

    diff = diff_sboms(sbom("7.24.0"), sbom("7.25.1", truncated=True))
    (change,) = diff.version_changed
    assert change.key == "pkg:npm/%40babel/parser"
    assert (change.before, change.after) == (("7.24.0",), ("7.25.1",))
    assert diff.unchanged == 1
    assert diff.incomplete == ("app.exe (run run-7.25.1)",)


# --- the command ------------------------------------------------------------


@pytest.fixture
def api(monkeypatch: pytest.MonkeyPatch) -> dict[str, dict[str, Any]]:
    runs: dict[str, dict[str, Any]] = {}

    class FakeClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def get_sbom(self, run_id: str) -> dict[str, Any]:
            if run_id not in runs:
                raise ApiError(f"GET /api/runs/{run_id}/sbom failed: HTTP 404")
            return runs[run_id]

    monkeypatch.setattr("cli.scan_commands.BareClient", FakeClient)
    return runs


def test_the_command_diffs_two_runs(api: dict[str, dict[str, Any]]) -> None:
    api["old"] = doc(ZLIB_11)
    api["new"] = doc(ZLIB_13, LEFT_PAD)
    result = runner.invoke(app, ["sbom-diff", "old", "new"])
    assert result.exit_code == 0, result.output
    assert "+ pkg:npm/left-pad  1.3.0" in result.output
    assert "~ pkg:generic/zlib  1.2.11 -> 1.2.13" in result.output


def test_the_command_diffs_two_files_without_an_api(tmp_path: Path) -> None:
    old = tmp_path / "v2.4.json"
    new = tmp_path / "v2.5.json"
    old.write_text(json.dumps(doc(ZLIB_11)), encoding="utf-8")
    new.write_text(json.dumps(doc(ZLIB_11)), encoding="utf-8")
    result = runner.invoke(app, ["sbom-diff", str(old), str(new), "--json"])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["has_changes"] is False
    assert payload["before"] == "v2.4.json"


def test_exit_code_reports_differences_like_git_diff(api: dict[str, dict[str, Any]]) -> None:
    api["old"] = doc(ZLIB_11)
    api["new"] = doc(ZLIB_13)
    assert runner.invoke(app, ["sbom-diff", "old", "new"]).exit_code == 0
    assert runner.invoke(app, ["sbom-diff", "old", "new", "--exit-code"]).exit_code == 1
    assert runner.invoke(app, ["sbom-diff", "old", "old", "--exit-code"]).exit_code == 0


def test_an_unknown_run_is_a_tool_error(api: dict[str, dict[str, Any]]) -> None:
    api["old"] = doc(ZLIB_11)
    result = runner.invoke(app, ["sbom-diff", "old", "missing"])
    assert result.exit_code == 2
    assert "could not fetch the SBOM for 'missing'" in result.output


def test_a_file_that_is_not_json_is_a_tool_error(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")
    result = runner.invoke(app, ["sbom-diff", str(bad), str(bad)])
    assert result.exit_code == 2
    assert "could not read" in result.output
