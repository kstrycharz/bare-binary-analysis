#!/usr/bin/env python3
"""Unpack analyzer: recursive container extraction.

Reads one artifact from ``/input``, extracts it recursively into
``/output/extracted``, and writes a tree manifest to ``/output/result.json``.

Runs with no network, a read-only rootfs, dropped capabilities, and hard
extraction budgets. Untrusted archives are exactly what this container exists
to open, so the boundary matters more here than anywhere else in the pipeline.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, "/opt/bare")

from core.unpack import ExtractionBudget, Extractor, summarise

SCHEMA_VERSION = 1
INPUT_DIR = Path("/input")
OUTPUT_DIR = Path("/output")
EXTRACT_DIR = OUTPUT_DIR / "extracted"
RESULT_PATH = OUTPUT_DIR / "result.json"

_HASH_CHUNK = 1024 * 1024


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(_HASH_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def tool_versions() -> dict[str, str]:
    """Recorded in the run manifest — extraction behaviour is tool-dependent,
    so a reproducibility claim has to name the versions."""
    versions: dict[str, str] = {"python": sys.version.split()[0]}
    for name, argv in (("7z", ["7z", "i"]), ("unsquashfs", ["unsquashfs", "-version"])):
        binary = shutil.which(name)
        if binary is None:
            continue
        try:
            completed = subprocess.run(
                [binary, *argv[1:]], capture_output=True, timeout=15, check=False
            )
            first = completed.stdout.decode("utf-8", "replace").strip().splitlines()
            versions[name] = first[0][:120] if first else "unknown"
        except Exception:
            versions[name] = "unknown"
    return versions


def find_artifact() -> Path | None:
    candidates = sorted(p for p in INPUT_DIR.rglob("*") if p.is_file())
    return candidates[0] if candidates else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BARE unpack analyzer")
    parser.add_argument("--max-depth", type=int, default=8)
    parser.add_argument(
        "--max-files",
        type=int,
        default=0,
        help="0 scales the cap to the input size; anything else is a hard override",
    )
    parser.add_argument(
        "--max-total-bytes",
        type=int,
        default=0,
        help="0 scales the cap to the input size (20x, capped at 10 GiB)",
    )
    args = parser.parse_args(argv)

    started = time.monotonic()
    artifact = find_artifact()
    if artifact is None:
        print("no artifact found in /input", file=sys.stderr)
        return 2

    size = artifact.stat().st_size
    # Only pass an override when one was actually given. Passing the flag's
    # default clobbered the scaled value — `for_input` computed 121 800 files
    # for a 213 MB installer and then had 20 000 written straight back over it,
    # which is how that installer's 377 MB app.asar went unopened.
    budget = ExtractionBudget.for_input(size, max_depth=args.max_depth)
    if args.max_files:
        budget.max_files = args.max_files
    if args.max_total_bytes:
        budget.max_total_bytes = args.max_total_bytes

    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
    extraction = Extractor(budget).extract_tree(artifact, EXTRACT_DIR, root_name=artifact.name)

    # Hash each extracted file here rather than on the host: the bytes are
    # already local, and the orchestrator needs the digest to dedupe artifacts
    # across runs.
    for node in extraction.nodes:
        path = EXTRACT_DIR / node.relative_path
        try:
            node.sha256 = sha256_of(path)
        except OSError:
            node.sha256 = ""

    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "analyzer": "unpack",
        "root": {"name": artifact.name, "size_bytes": size, "sha256": sha256_of(artifact)},
        "tool_versions": tool_versions(),
        "duration_s": round(time.monotonic() - started, 3),
        **extraction.to_dict(),
    }

    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(summarise(extraction), flush=True)
    for error in extraction.errors[:20]:
        print(f"  note: {error}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
