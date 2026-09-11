#!/usr/bin/env python3
"""Static scan analyzer: strings, rule matching, entropy, file identification.

Runs inside a locked-down container with no network. It reads the artifact from
``/input``, the rule pack from ``/rules``, and writes one JSON document to
``/output/result.json``.

It shares ``core.rules`` with the host rather than reimplementing the scanner,
so the engine that produces findings in production is the same one the unit
tests exercise. The alternative — a standalone script that drifts from the
tested code — is how a scanner quietly stops matching.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import sys
import time
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

sys.path.insert(0, "/opt/bare")

from core.composition import inventory as build_inventory
from core.rules import RulePack, load_rule_pack, scan_file, sweep
from core.rules.recon import summarise as summarise_recon
from core.rules.scanner import MIN_STRING_LENGTH, extract_strings

SCHEMA_VERSION = 1
INPUT_DIR = Path("/input")
RULES_DIR = Path("/rules")
OUTPUT_DIR = Path("/output")
RESULT_PATH = OUTPUT_DIR / "result.json"

# Rule matching is CPU-bound regex work over independent files, which is the
# one shape that parallelises cleanly. Measured on a 502-file, 64 MB .NET tree:
# 59.7s sequential, 10.8s across 8 workers, byte-identical output. The cap
# exists because the win flattens and each worker holds its own copy of the
# compiled pack.
MAX_SCAN_WORKERS = 8

# One worker's share has to be worth a process. Below this, the fork and the
# pickling cost more than the scan.
MIN_FILES_FOR_POOL = 8

# Recon holds every extracted string in memory at once so `sweep` can rank by
# rarity across the whole corpus. That is affordable for a 500-file tree
# (~600k strings) and fatal for a 69 000-file one: the same installer, once its
# Electron archive actually unpacked, produced tens of millions and OOM-killed
# a 4 GiB analyzer 256 seconds in. The cap bounds the worst case to a few
# hundred MB alongside eight worker processes; when it bites, the result says
# so rather than quietly reporting a partial inventory as a complete one.
MAX_RECON_STRINGS = 1_500_000

# Magic bytes are enough for S1's purposes here; full LIEF/pefile parsing lands
# with the identify analyzer. This exists so the report can say "PE32+
# executable" rather than "file".
_SIGNATURES: tuple[tuple[bytes, str, str], ...] = (
    (b"MZ", "pe", "application/vnd.microsoft.portable-executable"),
    (b"\x7fELF", "elf", "application/x-elf"),
    (b"\xca\xfe\xba\xbe", "macho", "application/x-mach-binary"),
    (b"\xcf\xfa\xed\xfe", "macho", "application/x-mach-binary"),
    (b"PK\x03\x04", "archive", "application/zip"),
    (b"7z\xbc\xaf\x27\x1c", "archive", "application/x-7z-compressed"),
    (b"\x1f\x8b", "archive", "application/gzip"),
    (b"hsqs", "filesystem", "application/x-squashfs"),
    (b"\xd0\xcf\x11\xe0", "installer", "application/x-msi"),
    (b"-----BEGIN", "certificate", "application/x-pem-file"),
)


def identify(path: Path) -> dict[str, Any]:
    """Cheap file identification from magic bytes and structure."""
    with path.open("rb") as handle:
        header = handle.read(4096)

    kind, media_type = "unknown", None
    for magic, detected_kind, detected_media in _SIGNATURES:
        if header.startswith(magic):
            kind, media_type = detected_kind, detected_media
            break

    result: dict[str, Any] = {"kind": kind, "media_type": media_type}

    if kind == "pe":
        result.update(_identify_pe(path, header))
    elif kind == "elf":
        result.update(_identify_elf(header))
    elif kind == "unknown" and _looks_like_text(header):
        result["kind"] = "text"
        result["media_type"] = "text/plain"

    return result


def _identify_pe(path: Path, header: bytes) -> dict[str, Any]:
    """Architecture and characteristics from the COFF header."""
    info: dict[str, Any] = {}
    try:
        if len(header) < 0x40:
            return info
        pe_offset = int.from_bytes(header[0x3C:0x40], "little")
        with path.open("rb") as handle:
            handle.seek(pe_offset)
            coff = handle.read(24)
        if not coff.startswith(b"PE\x00\x00"):
            return info
        machine = int.from_bytes(coff[4:6], "little")
        info["architecture"] = {
            0x014C: "x86",
            0x8664: "x86_64",
            0x01C0: "arm",
            0xAA64: "arm64",
            0x0200: "ia64",
        }.get(machine, f"unknown(0x{machine:04x})")
        characteristics = int.from_bytes(coff[22:24], "little")
        info["is_dll"] = bool(characteristics & 0x2000)
    except OSError:
        pass
    return info


def _identify_elf(header: bytes) -> dict[str, Any]:
    if len(header) < 20:
        return {}
    is_64 = header[4] == 2
    little = header[5] == 1
    machine = int.from_bytes(header[18:20], "little" if little else "big")
    return {
        "architecture": {
            0x03: "x86",
            0x3E: "x86_64",
            0x28: "arm",
            0xB7: "arm64",
            0x08: "mips",
            0xF3: "riscv",
        }.get(machine, f"unknown(0x{machine:02x})"),
        "elf_class": "64-bit" if is_64 else "32-bit",
    }


def _looks_like_text(header: bytes) -> bool:
    if not header:
        return False
    printable = sum(1 for b in header if 0x20 <= b < 0x7F or b in (0x09, 0x0A, 0x0D))
    return printable / len(header) > 0.95


def find_artifacts() -> list[Path]:
    """Every file staged under /input.

    The orchestrator stages the root artifact plus the whole extracted tree, so
    one container pass scans the entire unpack tree. Spawning a container per
    extracted file would multiply a 400-file installer into 400 container
    starts, which is minutes of pure overhead for milliseconds of work.

    Sorted so evidence lands in the same order on every run (§2.5).
    """
    return sorted(p for p in INPUT_DIR.rglob("*") if p.is_file() and not p.is_symlink())


def available_cpus() -> int:
    """CPUs this container may actually use, not the host's core count.

    ``os.cpu_count()`` reports the host's CPUs from inside a container, so
    sizing a pool from it spawns eight workers to share a two-CPU quota and
    makes things slower. The cgroup quota is the real limit; affinity is the
    fallback, and both are read defensively because a missing or unparseable
    cgroup file must degrade to "one worker", never to a crash.
    """
    for quota_file, period_file in (
        ("/sys/fs/cgroup/cpu.max", None),  # cgroup v2: "<quota> <period>" or "max <period>"
        ("/sys/fs/cgroup/cpu/cpu.cfs_quota_us", "/sys/fs/cgroup/cpu/cpu.cfs_period_us"),
    ):
        try:
            raw = Path(quota_file).read_text(encoding="utf-8").split()
            if period_file is None:
                quota_s, period_s = raw[0], raw[1]
            else:
                quota_s = raw[0]
                period_s = Path(period_file).read_text(encoding="utf-8").strip()
            if quota_s == "max":
                break
            quota, period = int(quota_s), int(period_s)
            if quota > 0 and period > 0:
                return max(1, quota // period)
        except (OSError, ValueError, IndexError):
            continue

    try:
        return max(1, len(os.sched_getaffinity(0)))
    except (AttributeError, OSError):
        return max(1, os.cpu_count() or 1)


def scan_worker_count(artifact_count: int) -> int:
    """How many processes to scan with. ``BARE_SCAN_WORKERS`` overrides."""
    override = os.environ.get("BARE_SCAN_WORKERS", "").strip()
    if override:
        try:
            return max(1, min(int(override), artifact_count))
        except ValueError:
            print(f"ignoring invalid BARE_SCAN_WORKERS={override!r}", file=sys.stderr)
    if artifact_count < MIN_FILES_FOR_POOL:
        return 1
    return max(1, min(MAX_SCAN_WORKERS, available_cpus(), artifact_count))


# Each worker process compiles its own copy of the rule pack once, then reuses
# it for every file it is handed. Measured at ~10ms, so it is not worth the
# complexity of sharing compiled patterns across processes.
_WORKER_PACK: RulePack | None = None


def _worker_pack() -> RulePack:
    global _WORKER_PACK
    if _WORKER_PACK is None:
        _WORKER_PACK = load_rule_pack(RULES_DIR)
    return _WORKER_PACK


def scan_one(job: tuple[str, int, bool]) -> dict[str, Any]:
    """Scan a single artifact. Module-level and picklable so it can be mapped
    across a process pool; called directly on the sequential path."""
    path_str, max_bytes, include_plaintext = job
    artifact = Path(path_str)
    relative = artifact.relative_to(INPUT_DIR).as_posix()
    try:
        size = artifact.stat().st_size
        matches = scan_file(path_str, _worker_pack(), max_bytes=max_bytes)
    except OSError as exc:
        # One unreadable file must not cost the other 399.
        return {"relative_path": relative, "error": str(exc), "matches": []}

    return {
        "relative_path": relative,
        "size_bytes": size,
        "truncated": size > max_bytes,
        **identify(artifact),
        # Sorted by the scanner; preserved here so evidence rows land in the
        # same order on every run regardless of scheduling.
        "matches": [
            {
                "rule_id": m.rule_id,
                "value_hash": m.value_hash,
                "value_masked": m.masked,
                **({"value_plaintext": m.value} if include_plaintext else {}),
                "offset": m.offset,
                "encoding": m.encoding,
                "entropy": m.entropy,
                "context": m.context,
            }
            for m in matches
        ],
    }


def _map_ordered(
    fn: Callable[[Any], Any], jobs: list[Any], workers: int, *, chunksize: int, what: str
) -> list[Any]:
    """Map ``fn`` over ``jobs``, preserving input order.

    ``Executor.map`` yields results in the order the jobs were *submitted*, not
    the order they finish, so output is identical whether one worker or eight
    did the work — which §2.5 requires and the unit tests assert.

    A pool that cannot start is not a scan failure. Sandboxes vary: a seccomp
    profile, a tight pids limit, or a missing /dev/shm can each deny process
    creation, and the right answer is a slower scan, not a lost one (ADR-0008's
    posture, one level down).
    """
    if workers <= 1:
        return [fn(job) for job in jobs]
    try:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            return list(pool.map(fn, jobs, chunksize=chunksize))
    except Exception as exc:  # any pool failure falls back to sequential
        print(
            f"parallel {what} unavailable ({type(exc).__name__}: {exc}); "
            "falling back to sequential",
            file=sys.stderr,
        )
        return [fn(job) for job in jobs]


def scan_all(
    artifacts: list[Path], *, max_bytes: int, include_plaintext: bool, workers: int
) -> list[dict[str, Any]]:
    """Scan every artifact, in input order."""
    jobs: list[Any] = [(str(p), max_bytes, include_plaintext) for p in artifacts]
    return _map_ordered(scan_one, jobs, workers, chunksize=4, what="scan")


# Shapes that are worth a human's (or a model's) attention when nothing matched
# them. Deliberately narrow: the residue is for *discovering rules*, so it wants
# strings that look like configuration, endpoints, or identifiers — not every
# unmatched string in a 34 MB installer.
_RESIDUE_INTERESTING = re.compile(
    r"""(?x)
    (?: [a-z][a-z0-9+.\-]{1,14} :// )          # any URI scheme
  | (?: [A-Za-z]:\\ | //| \\\\ )               # absolute or UNC paths
  | (?: \b[a-z0-9-]{2,40}(?:\.[a-z0-9-]{2,40}){2,} \b )   # 3+ label hostnames
  | (?: \b[A-Za-z0-9_-]{2,30} \s* [=:] \s* \S{8,} )       # key = value
  | (?: \b(?:passwd|password|secret|token|apikey|api_key|credential|licen[cs]e)\b )
    """,
    re.IGNORECASE,
)

# Document and container structure. Measured: without this, a sample from a
# release containing seven PDFs is ~90% PDF object syntax, which crowds out the
# handful of strings actually worth a reader's attention.
_RESIDUE_BORING = re.compile(
    r"""(?xi)
    \.(?:dll|exe|png|jpg|gif|xml|xsd|resources)$
  | ^(?:System|Microsoft|Windows)\.
  | <</ | /Subtype | /Rect\[ | endobj | endstream | /FlateDecode | /Font
  | ^\s*[%&'()*\d:;<>?@\[\]^_`|~-]+\s*$        # punctuation and digit runs
  | \\(?:par|fonttbl|colortbl|viewkind|uc1|pard)\b   # RTF control words
  | ^(?:https?://(?:www\.)?[a-z0-9-]+\.[a-z]{2,6}/?)$   # bare public URLs
    """
)


def collect_residue(artifacts: list[Path], pack: Any, limit: int) -> list[dict[str, Any]]:
    """Sample strings that no rule matched but that look like they might matter.

    This is the honest version of "what did we miss?". A scanner cannot report
    what it has no pattern for, so the only way to find the next rule is to
    look at what fell through — which is exactly the loop that produced the
    `svn+ssh://` rule in this pack.
    """
    seen: set[str] = set()
    residue: list[dict[str, Any]] = []

    for artifact in artifacts:
        if len(residue) >= limit:
            break
        try:
            data = artifact.read_bytes()
        except OSError:
            continue

        matched_spans = {(m.offset, len(m.value)) for m in scan_file(str(artifact), pack)}
        matched_offsets = {offset for offset, _ in matched_spans}

        for extracted in extract_strings(data):
            if len(residue) >= limit:
                break
            value = extracted.value.strip()
            if len(value) < 12 or len(value) > 300:
                continue
            if extracted.offset in matched_offsets:
                continue
            if _RESIDUE_BORING.search(value) or not _RESIDUE_INTERESTING.search(value):
                continue
            key = value[:120]
            if key in seen:
                continue
            seen.add(key)
            residue.append(
                {
                    "value": value[:300],
                    "offset": extracted.offset,
                    "encoding": extracted.encoding,
                    "relative_path": artifact.relative_to(INPUT_DIR).as_posix(),
                }
            )

    return residue


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BARE static analyzer")
    parser.add_argument("--min-string-length", type=int, default=MIN_STRING_LENGTH)
    parser.add_argument(
        "--workers",
        type=int,
        default=0,
        help=(
            "processes to scan with. 0 (default) sizes it from the container's "
            "CPU quota; 1 forces the sequential path. Output is identical "
            "either way."
        ),
    )
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=512 * 1024 * 1024,
        help="truncate artifacts larger than this; recorded in the result",
    )
    parser.add_argument(
        "--components",
        action="store_true",
        help=(
            "identify third-party components from the manifests the artifact "
            "ships — package.json, .nuspec, dist-info, Go build info. This is "
            "what an SBOM is built from."
        ),
    )
    parser.add_argument(
        "--recon",
        action="store_true",
        help=(
            "inventory what kinds of things are in the artifact — every URI "
            "scheme, path, hostname, address, and assignment — regardless of "
            "whether any rule matches them. This is the sweep that finds what "
            "no rule describes; see core/rules/recon.py."
        ),
    )
    parser.add_argument(
        "--emit-residue",
        type=int,
        default=0,
        metavar="N",
        help=(
            "sample up to N strings that no rule matched, for rule discovery. "
            "This is the input to the AI author loop: the interesting things a "
            "scanner misses are by definition the things no pattern describes."
        ),
    )
    parser.add_argument(
        "--include-plaintext",
        action="store_true",
        help=(
            "include discovered secret values in the result. Off by default: "
            "the orchestrator passes it only for runs that opted into "
            "plaintext retention (§14), so the value never lands on disk "
            "otherwise."
        ),
    )
    args = parser.parse_args(argv)

    started = time.monotonic()
    artifacts = find_artifacts()
    if not artifacts:
        print("no artifacts found in /input", file=sys.stderr)
        return 2

    try:
        pack = load_rule_pack(RULES_DIR)
    except Exception as exc:
        print(f"could not load rule pack from {RULES_DIR}: {exc}", file=sys.stderr)
        return 3

    # The parent already loaded the pack above, which validates it before any
    # worker is spawned — a broken pack should fail once, not N times.
    global _WORKER_PACK
    _WORKER_PACK = pack

    workers = args.workers if args.workers > 0 else scan_worker_count(len(artifacts))
    scanned = scan_all(
        artifacts,
        max_bytes=args.max_bytes,
        include_plaintext=args.include_plaintext,
        workers=workers,
    )
    total_matches = sum(len(entry.get("matches", ())) for entry in scanned)

    inventory = run_recon(artifacts, workers=workers) if args.recon else None

    components = None
    if args.components:
        started_components = time.monotonic()
        components = build_inventory(
            [(path, path.relative_to(INPUT_DIR).as_posix()) for path in artifacts]
        )
        print(
            f"identified {len(components.components)} component(s) in "
            f"{time.monotonic() - started_components:.1f}s",
            flush=True,
        )

    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "analyzer": "static",
        "recon": inventory.to_dict() if inventory is not None else None,
        "components": components.to_dict() if components is not None else None,
        "residue": collect_residue(artifacts, pack, args.emit_residue) if args.emit_residue else [],
        "rule_pack": {"version": pack.version, "hash": pack.hash},
        "tool_versions": {
            "python": platform.python_version(),
            "bare_scanner": str(SCHEMA_VERSION),
        },
        "duration_s": round(time.monotonic() - started, 3),
        "plaintext_included": args.include_plaintext,
        "files": scanned,
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    RESULT_PATH.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"scanned {len(artifacts)} file(s) with {workers} worker(s): "
        f"{total_matches} matches",
        flush=True,
    )
    if inventory is not None:
        print(summarise_recon(inventory), flush=True)
    return 0


def extract_for_recon(path_str: str) -> list[tuple[str, str, int, str]]:
    """Every string in one file, as ``sweep`` wants them.

    Module-level and picklable so it can be mapped across a process pool. An
    unreadable file yields nothing rather than raising: recon is a survey, and
    one bad file must not cost the inventory.
    """
    artifact = Path(path_str)
    try:
        data = artifact.read_bytes()
    except OSError:
        return []
    relative = artifact.relative_to(INPUT_DIR).as_posix()
    return [(e.value, relative, e.offset, e.encoding) for e in extract_strings(data)]


def run_recon(artifacts: list[Path], *, workers: int = 1) -> Any:
    """Inventory sweep across every staged file.

    Independent of the rule pack on purpose: recon asks "what is in here?" and
    must stay over-inclusive, while rules ask "is this specific bad thing
    present?" and must stay precise. Coupling them would drag one failure mode
    into the other.

    Only the extraction is parallelised. ``sweep`` ranks by *rarity across the
    whole corpus* — the interesting string appears once, `System.Runtime`
    appears three thousand times — so it needs every string in one place and
    stays in the parent. Measured on a 502-file tree: extraction 9.0s → 2.2s
    across 8 workers, sweep 2.9s either way, and the collected list comes back
    byte-identical because `map` preserves submission order.
    """
    jobs = [str(p) for p in artifacts]
    collected: list[tuple[str, str, int, str]] = []
    truncated = False

    def absorb(chunk: list[tuple[str, str, int, str]]) -> bool:
        """Take what fits. Returns False once the cap is reached."""
        nonlocal truncated
        room = MAX_RECON_STRINGS - len(collected)
        if room <= 0:
            truncated = True
            return False
        if len(chunk) > room:
            collected.extend(chunk[:room])
            truncated = True
            return False
        collected.extend(chunk)
        return True

    # Consumed lazily and abandoned at the cap. `_map_ordered` wraps the pool
    # in `list()`, which materialises every chunk for every file before any cap
    # can apply — that is not a slower path, it is the OOM itself: 68 976 files
    # produced enough strings to kill a 4 GiB analyzer 319 seconds in, with the
    # cap in place and doing nothing.
    if workers <= 1:
        for job in jobs:
            if not absorb(extract_for_recon(job)):
                break
    else:
        try:
            with ProcessPoolExecutor(max_workers=workers) as pool:
                iterator = pool.map(extract_for_recon, jobs, chunksize=8)
                for chunk in iterator:
                    if not absorb(chunk):
                        # Stop feeding the pool; the remaining futures are
                        # cancelled when the context manager exits.
                        break
        except Exception as exc:  # any pool failure falls back to sequential
            print(
                f"parallel recon unavailable ({type(exc).__name__}: {exc}); "
                "falling back to sequential",
                file=sys.stderr,
            )
            collected.clear()
            truncated = False
            for job in jobs:
                if not absorb(extract_for_recon(job)):
                    break

    if truncated:
        print(
            f"recon sampled the first {len(collected):,} strings "
            f"({MAX_RECON_STRINGS:,} cap); the inventory is partial",
            file=sys.stderr,
        )

    inventory = sweep(collected)
    inventory.truncated = truncated
    return inventory


if __name__ == "__main__":
    raise SystemExit(main())
