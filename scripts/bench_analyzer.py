#!/usr/bin/env python3
"""Benchmark the static analyzer through the real sandbox driver.

Answers two questions that only the real container can answer:

1. Does a process pool survive the seccomp allowlist, the pids limit, the
   read-only rootfs and the tmpfs scratch? A pool that works on the host and
   dies in the sandbox is worse than no pool, because the fallback hides it.
2. Is the parallel result *byte-identical* to the sequential one? §2.5 requires
   that parallelism not affect output, so this compares the two result
   documents rather than trusting that `map` preserves order.

    uv run python scripts/bench_analyzer.py var/fieldtest/PowerShell-*.zip
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import time
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

from core.sandbox import BindMount, MountMode, SandboxSpec, driver_from_settings  # noqa: E402
from core.sandbox.images import analyzer_image  # noqa: E402
from core.sandbox.spec import INPUT_DIR, OUTPUT_DIR  # noqa: E402

RULES_MOUNT = "/rules"
STATIC_IMAGE = analyzer_image("static")


def run_once(
    staging: Path,
    rules: Path,
    run_root: Path,
    *,
    workers: int,
    nano_cpus: int,
    extra_args: tuple[str, ...] = (),
) -> tuple[float, dict, str]:
    """One analyzer container. Returns (wall seconds, result doc, stdout)."""
    results = Path(tempfile.mkdtemp(prefix="res-", dir=run_root))
    results.chmod(0o777)

    driver = driver_from_settings()
    try:
        spec = SandboxSpec(
            image=STATIC_IMAGE,
            run_id=f"bench-{workers}w",
            analyzer="static",
            command=(*extra_args, "--workers", str(workers)),
            timeout_s=1800,
            nano_cpus=nano_cpus,
            mounts=(
                BindMount(str(staging), INPUT_DIR, MountMode.READ_ONLY),
                BindMount(str(rules), RULES_MOUNT, MountMode.READ_ONLY),
                BindMount(str(results), OUTPUT_DIR, MountMode.READ_WRITE),
            ),
        )
        started = time.monotonic()
        result = driver.run(spec)
        wall = time.monotonic() - started
    finally:
        driver.close()

    doc_path = results / "result.json"
    doc = json.loads(doc_path.read_text(encoding="utf-8")) if doc_path.is_file() else {}
    stderr = result.stderr.decode("utf-8", "replace").strip()
    stdout = result.stdout.decode("utf-8", "replace").strip()
    if result.status != "completed":
        print(f"    !! status={result.status} error={result.error}")
    if stderr:
        print(f"    !! stderr: {stderr[:300]}")
    shutil.rmtree(results, ignore_errors=True)
    return wall, doc, stdout


def fingerprint(doc: dict) -> str:
    """Hash of everything except the self-reported duration, which of course
    differs between a fast run and a slow one."""
    stable = {k: v for k, v in doc.items() if k != "duration_s"}
    return hashlib.sha256(json.dumps(stable, sort_keys=True).encode("utf-8", "replace")).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Static analyzer benchmark")
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--run-root", type=Path, default=REPO_ROOT / "var" / "bench")
    parser.add_argument(
        "--cpus", type=float, default=8.0, help="container CPU quota for the parallel runs"
    )
    args = parser.parse_args()

    args.run_root.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="stage-", dir=args.run_root))

    if zipfile.is_zipfile(args.artifact):
        with zipfile.ZipFile(args.artifact) as z:
            z.extractall(staging)
    else:
        shutil.copy2(args.artifact, staging / args.artifact.name)

    # Analyzers may only see per-run staging directories, so the rule pack is
    # copied into the run root rather than bind-mounted from the repo. The
    # driver enforces this; mirroring `_stage_rules` keeps the benchmark on the
    # same path production takes.
    rules = Path(tempfile.mkdtemp(prefix="rules-", dir=args.run_root))
    for rule_file in (REPO_ROOT / "detections").glob("*.yaml"):
        shutil.copy2(rule_file, rules / rule_file.name)

    files = [p for p in staging.rglob("*") if p.is_file()]
    total = sum(p.stat().st_size for p in files)
    print(f"staged {len(files)} files, {total / 1e6:.0f} MB from {args.artifact.name}\n")

    baseline_fp = None
    # The production pipeline passes --recon --emit-residue, so the benchmark
    # must too: measuring only the scan pass hides whatever those cost.
    production_args = ("--recon", "--emit-residue", "400")
    for label, workers, cpus, extra in (
        (f"scan only,      auto {args.cpus:g}cpu", 0, args.cpus, ()),
        (f"scan+recon,     auto {args.cpus:g}cpu", 0, args.cpus, ("--recon",)),
        (f"scan+residue,   auto {args.cpus:g}cpu", 0, args.cpus, ("--emit-residue", "400")),
        (f"scan+both,      auto {args.cpus:g}cpu", 0, args.cpus, production_args),
    ):
        wall, doc, stdout = run_once(
            staging,
            rules,
            args.run_root,
            workers=workers,
            nano_cpus=int(cpus * 1_000_000_000),
            extra_args=extra,
        )
        fp = fingerprint(doc)
        if baseline_fp is None:
            baseline_fp = fp
        identical = "identical" if fp == baseline_fp else "differs (recon/residue added)"
        scanned = len(doc.get("files", []))
        matches = sum(len(f.get("matches", ())) for f in doc.get("files", []))
        print(f"  {label:<30} {wall:6.1f}s  {total / 1e6 / max(wall, 0.01):5.1f} MB/s")
        print(f"  {'':<30} {scanned} files, {matches} matches, output {identical}")
        print(f"  {'':<30} {stdout.splitlines()[0] if stdout else ''}\n")

    shutil.rmtree(staging, ignore_errors=True)
    shutil.rmtree(rules, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
