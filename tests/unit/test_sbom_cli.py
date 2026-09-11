"""`bare sbom RUN_ID`.

`scan --sbom` writes an SBOM as a side effect of scanning. This command covers
everything after that — attaching a bill of materials to a release built last
week, re-exporting after a detector improves, diffing two runs — none of which
should require re-uploading the artifact.

The property that matters is that every route out of the system emits the same
bytes for the same run, because an SBOM that differs per export cannot be
hashed or diffed, which is most of what one is for.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from cli.client import ApiError
from cli.main import app
from reporting.cyclonedx import dump_sbom

runner = CliRunner()

# A non-ASCII name on purpose: the CLI used to serialise with the default
# ensure_ascii=True while the API did not, so these two paths disagreed byte
# for byte on exactly this input.
DOCUMENT: dict[str, Any] = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": "urn:uuid:0d6f1b21-9f9a-4f0e-9a1e-1f2a3b4c5d6e",
    "version": 1,
    "components": [
        {"type": "library", "name": "café-parser", "version": "1.0.0"},
        {"type": "library", "name": "left-pad", "version": "1.3.0"},
    ],
}


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Stand in for the API, recording which run was asked for."""
    asked: list[str] = []

    class FakeClient:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def get_sbom(self, run_id: str) -> dict[str, Any]:
            asked.append(run_id)
            return DOCUMENT

    monkeypatch.setattr("cli.scan_commands.BareClient", FakeClient)
    return asked


class TestItExportsAnExistingRun:
    def test_it_writes_the_document_to_stdout(self, client: list[str]) -> None:
        """Default to stdout so it pipes into jq without a temp file."""
        result = runner.invoke(app, ["sbom", "run-abc"])
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout)["bomFormat"] == "CycloneDX"

    def test_it_asks_for_the_run_it_was_given(self, client: list[str]) -> None:
        runner.invoke(app, ["sbom", "run-abc"])
        assert client == ["run-abc"]

    def test_it_writes_a_file_when_asked(self, client: list[str], tmp_path: Path) -> None:
        target = tmp_path / "nested" / "sbom.json"
        result = runner.invoke(app, ["sbom", "run-abc", "--out", str(target)])
        assert result.exit_code == 0, result.output
        assert json.loads(target.read_text(encoding="utf-8"))["specVersion"] == "1.5"

    def test_it_creates_the_parent_directory(self, client: list[str], tmp_path: Path) -> None:
        """CI writes into a reports/ directory that does not exist yet."""
        target = tmp_path / "a" / "b" / "sbom.json"
        runner.invoke(app, ["sbom", "run-abc", "-o", str(target)])
        assert target.is_file()

    def test_writing_a_file_reports_what_it_wrote(self, client: list[str], tmp_path: Path) -> None:
        target = tmp_path / "sbom.json"
        result = runner.invoke(app, ["sbom", "run-abc", "-o", str(target)])
        assert "2 component(s)" in result.output


class TestEveryExportIsTheSameBytes:
    def test_stdout_matches_the_canonical_serialisation(self, client: list[str]) -> None:
        result = runner.invoke(app, ["sbom", "run-abc"])
        assert result.stdout == dump_sbom(DOCUMENT)

    def test_a_file_matches_stdout(self, client: list[str], tmp_path: Path) -> None:
        target = tmp_path / "sbom.json"
        runner.invoke(app, ["sbom", "run-abc", "-o", str(target)])
        piped = runner.invoke(app, ["sbom", "run-abc"]).stdout
        assert target.read_text(encoding="utf-8") == piped

    def test_non_ascii_names_are_not_escaped(self, client: list[str]) -> None:
        """`ensure_ascii=True` would render this as \\u00e9 — still valid JSON,
        but a different document to hash and diff than the API's."""
        result = runner.invoke(app, ["sbom", "run-abc"])
        assert "café-parser" in result.stdout


class TestFailures:
    def test_an_unreachable_api_fails_the_command(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Exit non-zero rather than writing an empty SBOM, which a release
        pipeline would happily attach to a build."""

        class Failing:
            def __init__(self, *args: object, **kwargs: object) -> None:
                pass

            def get_sbom(self, run_id: str) -> dict[str, Any]:
                raise ApiError("run not found")

        monkeypatch.setattr("cli.scan_commands.BareClient", Failing)
        result = runner.invoke(app, ["sbom", "missing-run"])
        assert result.exit_code != 0
        assert "could not fetch the SBOM" in result.output

    def test_it_needs_a_run_id(self) -> None:
        assert runner.invoke(app, ["sbom"]).exit_code != 0
