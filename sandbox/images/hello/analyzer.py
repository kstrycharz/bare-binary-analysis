#!/usr/bin/env python3
"""Reference analyzer: the smallest thing that exercises the whole contract.

Every BARE analyzer image obeys the same contract, and this one exists to
prove the contract works before any real analysis code depends on it:

  * read the artifact from ``/input`` (read-only bind mount)
  * do work in ``/work`` or ``/tmp`` (tmpfs)
  * write exactly one JSON document to ``/output/result.json``
  * exit 0 on success, non-zero on failure, and say why on stderr
  * never touch the network, never expect to be root

It doubles as the isolation probe. ``--probe`` makes it *attempt* the things
the sandbox is supposed to forbid — writing to the read-only rootfs, opening a
socket, reading /input read-write — and report what happened. The sandbox tests
assert on that report, which is the only way to verify the boundary from the
inside rather than trusting the daemon's own description of it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
INPUT_DIR = Path("/input")
OUTPUT_DIR = Path("/output")
RESULT_PATH = OUTPUT_DIR / "result.json"


def _attempt(description: str, fn: Any) -> dict[str, Any]:
    """Run ``fn``; report whether it succeeded, without letting it abort us."""
    try:
        fn()
    except Exception as exc:
        return {"action": description, "succeeded": False, "error": type(exc).__name__}
    return {"action": description, "succeeded": True, "error": None}


def probe() -> dict[str, Any]:
    """Report the isolation posture as observed from inside the container."""

    def write_rootfs() -> None:
        Path("/bare-probe").write_text("should not be possible", encoding="utf-8")

    def write_input() -> None:
        (INPUT_DIR / ".probe").write_text("should not be possible", encoding="utf-8")

    def open_socket() -> None:
        # With network_mode=none there is no route anywhere; a connect must fail.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        try:
            sock.connect(("1.1.1.1", 53))
        finally:
            sock.close()

    def resolve_dns() -> None:
        socket.getaddrinfo("example.com", 80)

    def write_tmpfs() -> None:
        Path("/work/.probe").write_text("expected to work", encoding="utf-8")

    def write_output() -> None:
        (OUTPUT_DIR / ".probe").write_text("expected to work", encoding="utf-8")

    def unshare_namespace() -> None:
        # The syscall the seccomp allowlist is really there for. An
        # unprivileged user can normally unshare a user namespace even under
        # cap_drop=ALL, so success here means the profile did not apply — which
        # is exactly the silent failure that passing a profile *path* through
        # the Docker API produces.
        os.unshare(os.CLONE_NEWUSER)

    def ptrace_self() -> None:
        import ctypes

        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        ctypes.set_errno(0)
        # PTRACE_TRACEME. Denied by the profile; the dynamic analyzer (M5) gets
        # its own profile that permits it.
        if libc.ptrace(0, 0, 0, 0) == -1:
            raise OSError(ctypes.get_errno(), "ptrace denied")

    return {
        "uid": os.getuid(),
        "gid": os.getgid(),
        "is_root": os.getuid() == 0,
        "hostname": socket.gethostname(),
        "attempts": [
            _attempt("write_rootfs", write_rootfs),
            _attempt("write_input", write_input),
            _attempt("tcp_connect", open_socket),
            _attempt("dns_resolve", resolve_dns),
            _attempt("unshare_userns", unshare_namespace),
            _attempt("ptrace_self", ptrace_self),
            _attempt("write_work_tmpfs", write_tmpfs),
            _attempt("write_output", write_output),
        ],
    }


def scan_input() -> dict[str, Any]:
    """Hash and size everything handed to us. Stands in for real analysis."""
    files: list[dict[str, Any]] = []
    if not INPUT_DIR.is_dir():
        return {"present": False, "files": files}

    for path in sorted(INPUT_DIR.rglob("*")):
        if not path.is_file():
            continue
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        files.append(
            {
                "path": str(path.relative_to(INPUT_DIR)).replace("\\", "/"),
                "size_bytes": path.stat().st_size,
                "sha256": digest.hexdigest(),
            }
        )
    return {"present": True, "files": files}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="BARE hello analyzer")
    parser.add_argument(
        "--probe",
        action="store_true",
        help="attempt forbidden operations and report the outcome",
    )
    parser.add_argument(
        "--fail",
        action="store_true",
        help="exit non-zero, for testing degraded-analyzer handling",
    )
    parser.add_argument(
        "--hang",
        action="store_true",
        help="ignore SIGTERM and sleep forever, for testing the watchdog",
    )
    parser.add_argument(
        "--alloc-mb",
        type=int,
        default=0,
        metavar="N",
        help="allocate N MiB of resident memory, for testing the memory limit",
    )
    args = parser.parse_args(argv)

    if args.alloc_mb:
        # Touch every page: a bytearray is lazily backed, and an allocation the
        # kernel never has to fault in would not trigger the OOM killer.
        chunk = bytearray(1024 * 1024)
        held = []
        for _ in range(args.alloc_mb):
            block = bytearray(chunk)
            block[0] = 1
            held.append(block)
        print(f"allocated {args.alloc_mb} MiB", flush=True)

    if args.hang:
        import signal
        import time

        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        print("hanging deliberately; ignoring SIGTERM", flush=True)
        while True:
            time.sleep(3600)

    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "analyzer": "hello",
        "input": scan_input(),
    }
    if args.probe:
        result["probe"] = probe()

    try:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        RESULT_PATH.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except OSError as exc:
        print(f"could not write {RESULT_PATH}: {exc}", file=sys.stderr)
        return 2

    print(f"wrote {RESULT_PATH} ({len(result['input']['files'])} input files)", flush=True)
    if args.fail:
        print("failing deliberately as requested", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
