"""The Ghidra analyzer's handling of analyzeHeadless, without Ghidra.

The image carries a 569 MB JVM application, so the unit suite drives the
analyzer with a fake ``runner`` standing in for ``analyzeHeadless``: it reads
the argv the analyzer built and writes what the post-script would have. What is
under test is everything around Ghidra — per-binary status, budgets, the result
contract — which is where "Ghidra choked" silently becomes "no references" if it
is wrong. ``tests/integration/test_ghidra_image.py`` runs the real thing.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ANALYZER_PATH = REPO_ROOT / "sandbox" / "images" / "ghidra" / "analyzer.py"


def _load_analyzer() -> ModuleType:
    # Loaded by path: the analyzer ships inside the image rather than as a
    # package. Its one import, core.analyzers.ghidra_result, resolves from the
    # repo root.
    spec = importlib.util.spec_from_file_location("bare_ghidra_analyzer", ANALYZER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


analyzer = _load_analyzer()

Dirs = tuple[Path, Path, Path]


@pytest.fixture
def dirs(tmp_path: Path) -> Dirs:
    made = (tmp_path / "input", tmp_path / "output", tmp_path / "work")
    for directory in made:
        directory.mkdir()
    return made


def _stage(input_dir: Path, *binaries: tuple[str, list[int]]) -> None:
    for path, _ in binaries:
        binary = input_dir / "binaries" / path
        binary.parent.mkdir(parents=True, exist_ok=True)
        binary.write_bytes(b"MZ not really a binary")
    order = {"binaries": [{"path": path, "offsets": offsets} for path, offsets in binaries]}
    (input_dir / "targets.json").write_text(json.dumps(order), encoding="utf-8")


def _script_files(argv: Sequence[str]) -> tuple[Path, Path]:
    at = list(argv).index("-postScript")
    return Path(argv[at + 2]), Path(argv[at + 3])


def ghidra_resolving_to(function: str | None, *, references: int = 1) -> Any:
    """A stand-in analyzeHeadless whose post-script resolves every offset."""

    def runner(argv: Sequence[str], env: dict[str, str], timeout_s: float) -> Any:
        offsets_file, output = _script_files(argv)
        offsets = [int(line) for line in offsets_file.read_text().split()]
        output.write_text(
            json.dumps(
                {
                    "language": "x86:LE:64:default",
                    "function_count": 12,
                    "targets": [
                        {
                            "file_offset": offset,
                            "address": hex(0x140000000 + offset),
                            "found": True,
                            "references": [
                                {
                                    "from_address": hex(0x140001000 + n),
                                    "reference_type": "DATA",
                                    "function": function,
                                    "function_address": "0x140001000",
                                    "context": None,
                                }
                                for n in range(references)
                            ],
                        }
                        for offset in offsets
                    ],
                }
            ),
            encoding="utf-8",
        )
        return analyzer.HeadlessOutcome(0, "INFO  REPORT: Import succeeded")

    return runner


def _run(dirs: Dirs, runner: Any, *args: str) -> dict[str, Any]:
    input_dir, output_dir, work_dir = dirs
    code = analyzer.main(
        list(args), runner=runner, input_dir=input_dir, output_dir=output_dir, work_dir=work_dir
    )
    assert code == 0
    return json.loads((output_dir / "result.json").read_text(encoding="utf-8"))


class TestAnalysedBinaries:
    def test_offsets_come_back_with_their_function(self, dirs: Dirs) -> None:
        _stage(dirs[0], ("a1/broker.exe", [0x8200, 0x10]))
        result = _run(dirs, ghidra_resolving_to("connect_broker"))

        (binary,) = result["binaries"]
        assert binary["status"] == "analyzed"
        assert binary["language"] == "x86:LE:64:default"
        assert [t["file_offset"] for t in binary["targets"]] == [0x10, 0x8200]
        assert binary["targets"][0]["references"][0]["function"] == "connect_broker"

    def test_the_offsets_handed_to_ghidra_are_unique_and_sorted(self, dirs: Dirs) -> None:
        seen: list[list[int]] = []
        inner = ghidra_resolving_to("f")

        def runner(argv: Sequence[str], env: dict[str, str], timeout_s: float) -> Any:
            seen.append([int(x) for x in _script_files(argv)[0].read_text().split()])
            return inner(argv, env, timeout_s)

        _stage(dirs[0], ("x/app", [30, 10, 30, -1, 20]))
        _run(dirs, runner)
        assert seen == [[10, 20, 30]]

    def test_references_are_capped(self, dirs: Dirs) -> None:
        """Ten thousand references to a string in a jump table are not
        evidence; they are a denial of service against the report."""
        _stage(dirs[0], ("x/app", [1]))
        result = _run(dirs, ghidra_resolving_to("f", references=500))
        references = result["binaries"][0]["targets"][0]["references"]
        assert len(references) == analyzer.MAX_REFERENCES_PER_TARGET

    def test_the_ghidra_version_comes_from_the_image(
        self, dirs: Dirs, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BARE_GHIDRA_VERSION", "12.1.3")
        _stage(dirs[0], ("x/app", [1]))
        assert _run(dirs, ghidra_resolving_to("f"))["tool_versions"] == {"ghidra": "12.1.3"}

    def test_results_are_ordered_by_path_whatever_the_work_order_said(self, dirs: Dirs) -> None:
        _stage(dirs[0], ("z/last", [1]), ("a/first", [1]))
        result = _run(dirs, ghidra_resolving_to("f"))
        assert [b["path"] for b in result["binaries"]] == ["a/first", "z/last"]

    def test_the_scratch_project_does_not_outlive_the_binary(self, dirs: Dirs) -> None:
        _stage(dirs[0], ("x/app", [1]))
        _run(dirs, ghidra_resolving_to("f"))
        assert list(dirs[2].iterdir()) == []


class TestTheInvocation:
    def test_it_runs_the_bare_script_and_deletes_the_project(self, dirs: Dirs) -> None:
        calls: list[tuple[list[str], dict[str, str]]] = []
        inner = ghidra_resolving_to("f")

        def runner(argv: Sequence[str], env: dict[str, str], timeout_s: float) -> Any:
            calls.append((list(argv), env))
            return inner(argv, env, timeout_s)

        _stage(dirs[0], ("x/app", [1]))
        _run(dirs, runner)
        ((argv, env),) = calls
        assert argv[0].endswith("support/analyzeHeadless")
        assert "-deleteProject" in argv
        assert argv[argv.index("-scriptPath") + 1] == "/scripts"
        assert argv[argv.index("-postScript") + 1] == "BareXrefs.java"
        assert "GHIDRA_HEADLESS_MAXMEM" in env

    def test_ghidras_own_analysis_timeout_fires_before_the_process_timeout(
        self, dirs: Dirs
    ) -> None:
        """So the post-script still runs over whatever analysis finished."""
        timeouts: list[tuple[int, float]] = []
        inner = ghidra_resolving_to("f")

        def runner(argv: Sequence[str], env: dict[str, str], timeout_s: float) -> Any:
            timeouts.append((int(argv[argv.index("-analysisTimeoutPerFile") + 1]), timeout_s))
            return inner(argv, env, timeout_s)

        _stage(dirs[0], ("x/app", [1]))
        _run(dirs, runner, "--per-binary-timeout", "400")
        ((analysis, process),) = timeouts
        assert analysis < process <= 400


class TestFailuresStayVisible:
    def test_a_binary_ghidra_wrote_nothing_for_is_failed(self, dirs: Dirs) -> None:
        def runner(argv: Sequence[str], env: dict[str, str], timeout_s: float) -> Any:
            return analyzer.HeadlessOutcome(
                1,
                "main ERROR Could not determine local host name\n"
                "java.net.UnknownHostException: 0c3e: Temporary failure in name resolution\n"
                "ERROR DWARF un-recoverable expressions: (DWARFImportSummary)\n"
                "ERROR Abort due to Headless analyzer error: Directory not found: /work/p\n",
            )

        _stage(dirs[0], ("x/app", [1]))
        (binary,) = _run(dirs, runner)["binaries"]
        assert binary["status"] == "failed"
        # The sandbox's harmless hostname noise is not the reason.
        assert "Directory not found" in binary["reason"]

    def test_a_timeout_is_a_timeout(self, dirs: Dirs) -> None:
        def runner(argv: Sequence[str], env: dict[str, str], timeout_s: float) -> Any:
            return analyzer.HeadlessOutcome(None, "", timed_out=True)

        _stage(dirs[0], ("x/app", [1]))
        (binary,) = _run(dirs, runner)["binaries"]
        assert binary["status"] == "timeout"

    def test_unreadable_script_output_is_a_failure(self, dirs: Dirs) -> None:
        def runner(argv: Sequence[str], env: dict[str, str], timeout_s: float) -> Any:
            _script_files(argv)[1].write_text("{not json", encoding="utf-8")
            return analyzer.HeadlessOutcome(0, "")

        _stage(dirs[0], ("x/app", [1]))
        assert _run(dirs, runner)["binaries"][0]["status"] == "failed"

    def test_a_binary_missing_from_staging_is_failed_not_skipped(self, dirs: Dirs) -> None:
        _stage(dirs[0], ("x/app", [1]))
        (dirs[0] / "binaries" / "x" / "app").unlink()
        (binary,) = _run(dirs, ghidra_resolving_to("f"))["binaries"]
        assert binary["status"] == "failed"

    def test_a_path_that_escapes_staging_is_ignored(self, dirs: Dirs) -> None:
        (dirs[0] / "targets.json").write_text(
            json.dumps({"binaries": [{"path": "../../etc/passwd", "offsets": [1]}]}),
            encoding="utf-8",
        )
        assert _run(dirs, ghidra_resolving_to("f"))["binaries"] == []

    def test_no_work_order_is_an_error_exit(self, dirs: Dirs) -> None:
        input_dir, output_dir, work_dir = dirs
        code = analyzer.main(
            [],
            runner=ghidra_resolving_to("f"),
            input_dir=input_dir,
            output_dir=output_dir,
            work_dir=work_dir,
        )
        assert code == 2


class TestBudgets:
    def test_binaries_over_the_cap_are_skipped_and_the_result_says_truncated(
        self, dirs: Dirs
    ) -> None:
        _stage(dirs[0], ("a", [1]), ("b", [1]), ("c", [1]))
        result = _run(dirs, ghidra_resolving_to("f"), "--max-binaries", "2")
        assert [b["status"] for b in result["binaries"]] == ["analyzed", "analyzed", "skipped"]
        assert result["truncated"] is True

    def test_an_exhausted_time_budget_skips_rather_than_starting_a_doomed_jvm(
        self, dirs: Dirs
    ) -> None:
        calls: list[str] = []

        def runner(argv: Sequence[str], env: dict[str, str], timeout_s: float) -> Any:
            calls.append("ran")
            return analyzer.HeadlessOutcome(0, "")

        _stage(dirs[0], ("a", [1]))
        result = _run(dirs, runner, "--total-timeout", "5")
        assert calls == []
        assert result["binaries"][0]["status"] == "skipped"
        assert result["truncated"] is True


class TestHeap:
    def test_the_heap_is_a_share_of_the_container_limit(self) -> None:
        assert analyzer.heap_size(4 * 1024**3) == f"{int(4 * 1024 * 0.6)}M"

    def test_a_small_limit_still_gets_a_usable_heap(self) -> None:
        assert analyzer.heap_size(512 * 1024**2) == "1024M"

    def test_no_limit_falls_back_to_ghidras_default(self) -> None:
        assert analyzer.heap_size(None) == "2G"

    @pytest.mark.parametrize(
        ("content", "expected"),
        [("4294967296\n", 4294967296), ("max\n", None), (str(1 << 62), None)],
    )
    def test_the_cgroup_limit_is_read(self, tmp_path: Path, content: str, expected: Any) -> None:
        limit = tmp_path / "memory.max"
        limit.write_text(content, encoding="ascii")
        assert analyzer.memory_limit_bytes((tmp_path / "absent", limit)) == expected
