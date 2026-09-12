"""The static analyzer's parallel scan.

The analyzer ships inside a container image, so it is not importable as a
package — it is loaded by path here. That is worth doing rather than skipping:
the worker-count logic decides how a scan is executed, and getting it wrong
either wastes seven eighths of the machine or spawns eight workers to fight
over a two-CPU quota.

The determinism guarantee (§2.5, "parallelism must not affect output") is
asserted here at the unit level; `scripts/bench_analyzer.py` asserts the same
thing end to end through a real sandboxed container.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
ANALYZER_PATH = REPO_ROOT / "sandbox" / "images" / "static" / "analyzer.py"


def _load_analyzer() -> ModuleType:
    # The analyzer inserts /opt/bare on sys.path for its container
    # layout; importing it here works because core.rules is already importable
    # from the repo root.
    spec = importlib.util.spec_from_file_location("bare_static_analyzer", ANALYZER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


analyzer = _load_analyzer()


@pytest.fixture
def staged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A small input tree, with the analyzer pointed at it."""
    input_dir = tmp_path / "input"
    input_dir.mkdir()
    for index in range(12):
        # Exactly 20 characters, which is what an AWS access key ID is. A
        # 21-character value is correctly not a match, so a naive f"...{index}"
        # silently stops matching at index 10.
        key = f"AKIA2QZ7XKPLMNRTUV{index:02d}"
        assert len(key) == 20
        (input_dir / f"file{index:02d}.bin").write_bytes(
            b"MZ\x90\x00" + key.encode() + b"\x00" * 64
        )
    monkeypatch.setattr(analyzer, "INPUT_DIR", input_dir)
    monkeypatch.setattr(analyzer, "RULES_DIR", REPO_ROOT / "detections")
    monkeypatch.setattr(analyzer, "_WORKER_PACK", None)
    return input_dir


class TestWorkerCount:
    def test_small_trees_stay_sequential(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Below the threshold a pool costs more than it saves."""
        monkeypatch.delenv("BARE_SCAN_WORKERS", raising=False)
        assert analyzer.scan_worker_count(1) == 1
        assert analyzer.scan_worker_count(analyzer.MIN_FILES_FOR_POOL - 1) == 1

    def test_large_trees_use_a_pool(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BARE_SCAN_WORKERS", raising=False)
        monkeypatch.setattr(analyzer, "available_cpus", lambda: 8)
        assert analyzer.scan_worker_count(500) == analyzer.MAX_SCAN_WORKERS

    def test_worker_count_never_exceeds_the_cpu_quota(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Eight workers sharing two CPUs is slower than two, not faster."""
        monkeypatch.delenv("BARE_SCAN_WORKERS", raising=False)
        monkeypatch.setattr(analyzer, "available_cpus", lambda: 2)
        assert analyzer.scan_worker_count(500) == 2

    def test_worker_count_never_exceeds_the_file_count(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("BARE_SCAN_WORKERS", raising=False)
        monkeypatch.setattr(analyzer, "available_cpus", lambda: 32)
        # Bounded by MAX_SCAN_WORKERS first, then by the file count below it.
        assert analyzer.scan_worker_count(10) == min(analyzer.MAX_SCAN_WORKERS, 10)
        assert analyzer.scan_worker_count(9) == min(analyzer.MAX_SCAN_WORKERS, 9)

    def test_env_override_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BARE_SCAN_WORKERS", "3")
        assert analyzer.scan_worker_count(500) == 3

    def test_invalid_override_is_ignored_not_fatal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("BARE_SCAN_WORKERS", "lots")
        monkeypatch.setattr(analyzer, "available_cpus", lambda: 4)
        assert analyzer.scan_worker_count(500) == 4

    def test_available_cpus_is_always_positive(self) -> None:
        """Whatever the cgroup files say — or do not say — this must not
        return 0, which would size an empty pool."""
        assert analyzer.available_cpus() >= 1


class TestParallelDeterminism:
    def test_parallel_output_matches_sequential_exactly(self, staged: Path) -> None:
        """§2.5: parallelism must not affect output."""
        artifacts = analyzer.find_artifacts()
        assert len(artifacts) == 12

        sequential = analyzer.scan_all(
            artifacts, max_bytes=1 << 20, include_plaintext=False, workers=1
        )
        parallel = analyzer.scan_all(
            artifacts, max_bytes=1 << 20, include_plaintext=False, workers=4
        )
        assert parallel == sequential

    def test_file_order_is_preserved(self, staged: Path) -> None:
        """`map` yields in submission order, not completion order — which is
        what keeps evidence rows stable across runs."""
        artifacts = analyzer.find_artifacts()
        results = analyzer.scan_all(
            artifacts, max_bytes=1 << 20, include_plaintext=False, workers=4
        )
        assert [r["relative_path"] for r in results] == [
            p.relative_to(staged).as_posix() for p in artifacts
        ]

    def test_matches_are_actually_found(self, staged: Path) -> None:
        """A parallel scan that finds nothing would also be 'deterministic'."""
        results = analyzer.scan_all(
            analyzer.find_artifacts(), max_bytes=1 << 20, include_plaintext=False, workers=4
        )
        assert sum(len(r["matches"]) for r in results) >= 12

    def test_a_broken_pool_falls_back_rather_than_failing_the_scan(
        self, staged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Sandboxes vary; a pool that cannot start must cost speed, not the
        scan. This is ADR-0008's posture one level down."""

        def explode(*args: object, **kwargs: object) -> None:
            raise OSError("no process for you")

        monkeypatch.setattr(analyzer, "ProcessPoolExecutor", explode)
        results = analyzer.scan_all(
            analyzer.find_artifacts(), max_bytes=1 << 20, include_plaintext=False, workers=4
        )
        assert len(results) == 12
        assert sum(len(r["matches"]) for r in results) >= 12

    def test_unreadable_file_does_not_sink_the_batch(
        self, staged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        missing = staged / "vanished.bin"
        missing.write_bytes(b"MZ")
        artifacts = analyzer.find_artifacts()
        missing.unlink()

        results = analyzer.scan_all(
            artifacts, max_bytes=1 << 20, include_plaintext=False, workers=1
        )
        assert len(results) == len(artifacts)
        errored = [r for r in results if "error" in r]
        assert len(errored) == 1
        assert errored[0]["relative_path"] == "vanished.bin"


class TestReconParallelism:
    """Recon parallelises only its extraction phase.

    `sweep` ranks by rarity across the whole corpus, so it needs every string
    in one place and stays in the parent. These tests pin that the split does
    not change what recon reports.
    """

    def test_parallel_recon_matches_sequential(self, staged: Path) -> None:
        artifacts = analyzer.find_artifacts()
        sequential = analyzer.run_recon(artifacts, workers=1).to_dict()
        parallel = analyzer.run_recon(artifacts, workers=4).to_dict()
        assert parallel == sequential

    def test_recon_actually_inventories_something(self, staged: Path) -> None:
        inventory = analyzer.run_recon(analyzer.find_artifacts(), workers=4)
        assert inventory.files_scanned or inventory.categories

    def test_extract_for_recon_survives_a_vanished_file(self, staged: Path) -> None:
        """A survey must not die on one unreadable file."""
        missing = staged / "gone.bin"
        missing.write_bytes(b"MZ" + b"A" * 64)
        path = str(missing)
        missing.unlink()
        assert analyzer.extract_for_recon(path) == []

    def test_broken_pool_falls_back_for_recon_too(
        self, staged: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def explode(*args: object, **kwargs: object) -> None:
            raise OSError("no process for you")

        sequential = analyzer.run_recon(analyzer.find_artifacts(), workers=1).to_dict()
        monkeypatch.setattr(analyzer, "ProcessPoolExecutor", explode)
        fallback = analyzer.run_recon(analyzer.find_artifacts(), workers=4).to_dict()
        assert fallback == sequential
