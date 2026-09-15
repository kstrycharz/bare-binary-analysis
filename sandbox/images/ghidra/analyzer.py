#!/usr/bin/env python3
"""Ghidra analyzer (S4): which function uses each flagged string.

Reads ``/input/targets.json`` — the executables the static pass found secrets
in, and the file offsets it found them at — runs Ghidra's headless analyzer over
each executable, and writes ``/output/result.json`` in the shape
``core.analyzers.ghidra_result`` defines.

One ``analyzeHeadless`` process per binary rather than one for the batch. A JVM
start costs a few seconds; a shared process that wedges on the third of eight
binaries costs the other five, and "which one hung" becomes something the
result can no longer say. Per binary, every entry gets its own status and its
own clock.

Exit status is 0 whenever a result was written, including when individual
binaries failed: those failures are data, recorded per binary, and the
orchestrator decides what they mean (ADR-0008). Non-zero means there was no
work order to act on.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

sys.path.insert(0, "/opt/bare")

from core.analyzers.ghidra_result import (
    MAX_REFERENCES_PER_TARGET,
    BinaryResult,
    GhidraResult,
    XrefSite,
    XrefTarget,
)

INPUT_DIR = Path("/input")
OUTPUT_DIR = Path("/output")
WORK_DIR = Path("/work")
TARGETS_FILE = "targets.json"
BINARIES_DIR = "binaries"

# Paths inside the image, so POSIX whatever platform builds the command line.
GHIDRA_HOME = PurePosixPath(os.environ.get("GHIDRA_HOME", "/opt/ghidra"))
SCRIPT_DIR = PurePosixPath("/scripts")
SCRIPT_NAME = "BareXrefs.java"

# The JVM heap as a share of the container's memory limit. The remainder is not
# slack: the decompiler runs as a separate native process, and metaspace, thread
# stacks and the JIT all live outside -Xmx. A heap that fills at 60% is an
# OutOfMemoryError Ghidra reports against one binary; a heap sized to the whole
# limit is the kernel OOM-killing the container, which reports nothing at all
# about which binary did it.
HEAP_SHARE = 0.6
MIN_HEAP_MB = 1024
GHIDRA_DEFAULT_HEAP = "2G"

CGROUP_MEMORY_FILES = (
    Path("/sys/fs/cgroup/memory.max"),
    Path("/sys/fs/cgroup/memory/memory.limit_in_bytes"),
)

# Below this there is no point starting a JVM: importing and auto-analysing
# even a small binary takes longer, and a guaranteed timeout reads worse than
# an honest "skipped".
MIN_BINARY_BUDGET_S = 30.0

# Ghidra's own analysis timeout fires first, so the post-script still runs over
# whatever analysis did finish. The process timeout is the backstop for a JVM
# that has stopped responding altogether.
ANALYSIS_SHARE = 0.75

# Ghidra logs these on ordinary runs in this sandbox, and none of them means the
# binary failed. The first two are the no-network container failing to resolve
# its own hostname for a log field; the rest are loader diagnostics about debug
# info and relocations that it recovers from. Reporting one as the reason a
# binary failed would send an operator after the wrong problem.
BENIGN_LOG_ERRORS = (
    "Could not determine local host name",
    "UnknownHostException",
    "DWARF",
    "DW_OP_",
    "pseudo-relocation",
)


@dataclass(slots=True)
class HeadlessOutcome:
    exit_code: int | None
    output: str
    timed_out: bool = False


Runner = Callable[[Sequence[str], dict[str, str], float], HeadlessOutcome]


def run_headless(argv: Sequence[str], env: dict[str, str], timeout_s: float) -> HeadlessOutcome:
    """Run one ``analyzeHeadless`` to completion or to its deadline."""
    process = subprocess.Popen(
        list(argv),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        start_new_session=True,
    )
    try:
        output, _ = process.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        # analyzeHeadless is a shell script; the JVM and the native decompiler
        # are its descendants. Killing the script alone would leave them holding
        # the container's memory — and every later binary's budget — until the
        # watchdog tears the whole container down.
        os.killpg(process.pid, signal.SIGKILL)
        output, _ = process.communicate()
        return HeadlessOutcome(None, output.decode("utf-8", "replace"), timed_out=True)
    return HeadlessOutcome(process.returncode, output.decode("utf-8", "replace"))


def memory_limit_bytes(candidates: Sequence[Path] = CGROUP_MEMORY_FILES) -> int | None:
    """The container's memory limit, or ``None`` when there is none to read."""
    for path in candidates:
        try:
            raw = path.read_text(encoding="ascii").strip()
        except OSError:
            continue
        if not raw.isdigit():
            return None  # cgroup v2 writes "max" for unlimited
        value = int(raw)
        # cgroup v1 expresses "unlimited" as a number near 2**63.
        return value if value < 1 << 60 else None
    return None


def heap_size(limit_bytes: int | None) -> str:
    """``GHIDRA_HEADLESS_MAXMEM`` for a container with this memory limit."""
    if limit_bytes is None:
        return GHIDRA_DEFAULT_HEAP
    return f"{max(MIN_HEAP_MB, int(limit_bytes * HEAP_SHARE) >> 20)}M"


def headless_argv(
    binary: Path,
    project_dir: Path,
    offsets_file: Path,
    output_file: Path,
    analysis_timeout_s: int,
) -> list[str]:
    return [
        str(GHIDRA_HOME / "support" / "analyzeHeadless"),
        str(project_dir),
        "bare",
        "-import",
        str(binary),
        "-scriptPath",
        str(SCRIPT_DIR),
        "-postScript",
        SCRIPT_NAME,
        str(offsets_file),
        str(output_file),
        "-analysisTimeoutPerFile",
        str(analysis_timeout_s),
        "-deleteProject",
    ]


def failure_reason(outcome: HeadlessOutcome) -> str:
    """The first log line that actually explains a failure."""
    for line in outcome.output.splitlines():
        text = line.strip()
        if ("ERROR" in text or "Exception" in text) and not any(
            noise in text for noise in BENIGN_LOG_ERRORS
        ):
            return text[:300]
    return f"analyzeHeadless exited {outcome.exit_code} without writing a result"


def analyze_binary(
    path: str,
    offsets: Sequence[int],
    *,
    index: int,
    runner: Runner,
    input_dir: Path,
    work_dir: Path,
    env: dict[str, str],
    budget_s: float,
) -> BinaryResult:
    if budget_s < MIN_BINARY_BUDGET_S:
        return BinaryResult(
            path=path,
            status="skipped",
            reason="the analyzer's time budget ran out before this binary",
        )

    binary = input_dir / BINARIES_DIR / path
    if not binary.is_file():
        return BinaryResult(path=path, status="failed", reason="the binary was not staged")

    job = work_dir / f"job-{index}"
    project = job / "project"
    # analyzeHeadless refuses a project directory that does not exist yet.
    project.mkdir(parents=True, exist_ok=True)
    offsets_file = job / "offsets.txt"
    offsets_file.write_text("".join(f"{offset}\n" for offset in offsets), encoding="ascii")
    output_file = job / "xrefs.json"

    started = time.monotonic()
    try:
        argv = headless_argv(
            binary,
            project,
            offsets_file,
            output_file,
            max(1, int(budget_s * ANALYSIS_SHARE)),
        )
        outcome = runner(argv, env, budget_s)
        return _interpret(path, outcome, output_file, time.monotonic() - started)
    finally:
        shutil.rmtree(job, ignore_errors=True)


def _interpret(
    path: str, outcome: HeadlessOutcome, output_file: Path, duration_s: float
) -> BinaryResult:
    if outcome.timed_out:
        return BinaryResult(
            path=path,
            status="timeout",
            reason=f"no result within {duration_s:.0f}s",
            duration_s=duration_s,
        )
    if not output_file.is_file():
        return BinaryResult(
            path=path, status="failed", reason=failure_reason(outcome), duration_s=duration_s
        )
    try:
        data = json.loads(output_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return BinaryResult(
            path=path,
            status="failed",
            reason=f"the post-script wrote unreadable output: {exc}",
            duration_s=duration_s,
        )

    targets: list[XrefTarget] = []
    for raw in data.get("targets") or []:
        if not isinstance(raw, dict):
            continue
        target = XrefTarget.from_json(raw)
        target.references = sorted(target.references, key=_address_order)[
            :MAX_REFERENCES_PER_TARGET
        ]
        targets.append(target)

    reason = None
    if "timed out" in outcome.output.lower():
        reason = "Ghidra's analysis timeout fired; references may be incomplete"
    return BinaryResult(
        path=path,
        status="analyzed",
        reason=reason,
        language=str(data.get("language") or "") or None,
        function_count=int(data.get("function_count") or 0),
        duration_s=duration_s,
        targets=sorted(targets, key=lambda t: t.file_offset),
    )


def _address_order(site: XrefSite) -> tuple[int, str]:
    # Lower-case 0x-prefixed hex sorts numerically once length is compared first.
    return len(site.from_address), site.from_address


def work_order(order: Any) -> list[tuple[str, list[int]]]:
    """``(path, sorted offsets)`` per binary, sorted by path.

    Paths are relative to ``/input/binaries`` and anything that could escape it
    is dropped: the orchestrator writes this file, but the analyzer does not get
    to assume so.
    """
    raw_binaries = order.get("binaries") if isinstance(order, dict) else None
    entries: list[tuple[str, list[int]]] = []
    for raw in raw_binaries if isinstance(raw_binaries, list) else []:
        if not isinstance(raw, dict):
            continue
        path = str(raw.get("path") or "")
        pure = PurePosixPath(path)
        if not path or pure.is_absolute() or ".." in pure.parts:
            continue
        offsets = sorted(
            {
                value
                for value in raw.get("offsets") or []
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0
            }
        )
        entries.append((path, offsets))
    return sorted(entries)


def main(
    argv: list[str] | None = None,
    *,
    runner: Runner = run_headless,
    input_dir: Path = INPUT_DIR,
    output_dir: Path = OUTPUT_DIR,
    work_dir: Path = WORK_DIR,
) -> int:
    parser = argparse.ArgumentParser(description="BARE Ghidra analyzer")
    parser.add_argument("--total-timeout", type=float, default=1500.0)
    parser.add_argument("--per-binary-timeout", type=float, default=600.0)
    parser.add_argument("--max-binaries", type=int, default=16)
    args = parser.parse_args(argv)

    targets_path = input_dir / TARGETS_FILE
    try:
        order = json.loads(targets_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"no readable work order at {targets_path}: {exc}", file=sys.stderr)
        return 2

    env = {**os.environ, "GHIDRA_HEADLESS_MAXMEM": heap_size(memory_limit_bytes())}
    result = GhidraResult(ghidra_version=os.environ.get("BARE_GHIDRA_VERSION", "unknown"))
    deadline = time.monotonic() + args.total_timeout

    for index, (path, offsets) in enumerate(work_order(order)):
        if index >= args.max_binaries:
            binary = BinaryResult(
                path=path,
                status="skipped",
                reason=f"over the {args.max_binaries}-binary cap for one run",
            )
        else:
            binary = analyze_binary(
                path,
                offsets,
                index=index,
                runner=runner,
                input_dir=input_dir,
                work_dir=work_dir,
                env=env,
                budget_s=min(args.per_binary_timeout, deadline - time.monotonic()),
            )
        # A skipped binary is one nobody looked at. Say so at the top level too,
        # for the same reason the unpack analyzer does (ADR-0018).
        if binary.status == "skipped":
            result.truncated = True
        result.binaries.append(binary)

        resolved = sum(1 for target in binary.targets if target.best_function)
        note = f" — {binary.reason}" if binary.reason else ""
        print(
            f"ghidra {binary.path}: {binary.status} in {binary.duration_s:.1f}s, "
            f"{resolved}/{len(offsets)} offsets resolved to a function{note}",
            flush=True,
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "result.json").write_text(
        json.dumps(result.to_json(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
