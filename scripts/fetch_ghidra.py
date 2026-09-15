#!/usr/bin/env python3
"""Fetch and verify the pinned Ghidra release.

Ghidra is not ours. It is a 569 MB Apache-2.0 distribution published by the
NSA, and BARE consumes it the way a package manager consumes a release: by
pinned version, from the vendor's own URL, verified against a digest the vendor
published. Nothing about Ghidra is committed to this repository.

Three jobs, all of which exist because the image build alone cannot do them:

``--check-upstream``
    Ask GitHub what the latest release is and whether our pin still matches.
    A bump is then a deliberate edit to ``ghidra.lock.json`` and the Dockerfile,
    not a moving ``:latest`` that silently changes decompiler output between
    runs of the same artifact.

``--output DIR``
    Download the pinned archive and verify it. This is the air-gap path: fetch
    on a connected machine, carry the archive in, and build with
    ``--build-arg GHIDRA_ARCHIVE_URL=file:///...``. Also what CI warms, so a
    build does not re-download 569 MB per job.

``--verify FILE``
    Check an archive somebody else handed you against the pin. An operator who
    mirrors releases internally needs an answer to "is this the real one" that
    is not "trust the mirror".

Exit codes: 0 verified, 1 digest mismatch or fetch failure, 2 the pin is stale.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = REPO_ROOT / "sandbox" / "images" / "ghidra" / "ghidra.lock.json"
RELEASES_API = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"

# 569 MB through a 64 KiB pipe is a lot of syscalls for no reason.
CHUNK_BYTES = 4 * 1024 * 1024


def load_lock() -> dict[str, Any]:
    """The pinned coordinates. The one place they are written down."""
    data: dict[str, Any] = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    missing = {"version", "url", "sha256", "archive"} - data.keys()
    if missing:
        raise SystemExit(f"{LOCK_PATH} is missing required keys: {sorted(missing)}")
    return data


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def verify(path: Path, expected: str) -> bool:
    """Compare an archive against the pin, and say which it is either way."""
    if not path.is_file():
        print(f"not a file: {path}", file=sys.stderr)
        return False
    actual = sha256_of(path)
    if actual == expected:
        print(f"OK  {path.name}\n    sha256 {actual}")
        return True
    print(
        f"DIGEST MISMATCH for {path}\n"
        f"    expected {expected}\n"
        f"    actual   {actual}\n"
        "Do not use this archive. Either the download was corrupted or it is\n"
        "not the release this repository pins.",
        file=sys.stderr,
    )
    return False


def download(url: str, destination: Path, expected: str) -> bool:
    """Stream to a temporary file, verify, then move into place.

    Verified before the rename on purpose: a half-written or wrong archive must
    never occupy the path a build is about to trust. The temporary file is
    removed either way, so a failed fetch leaves nothing behind to be picked up
    by the next one.
    """
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_suffix(destination.suffix + ".partial")
    print(f"fetching {url}\n      -> {destination}")
    try:
        with urllib.request.urlopen(url, timeout=120) as response:
            total = int(response.headers.get("Content-Length") or 0)
            seen = 0
            with partial.open("wb") as handle:
                while chunk := response.read(CHUNK_BYTES):
                    handle.write(chunk)
                    seen += len(chunk)
                    if total:
                        print(f"\r    {seen / total:6.1%}  {seen >> 20} MiB", end="", flush=True)
            print()
    except (urllib.error.URLError, OSError) as exc:
        partial.unlink(missing_ok=True)
        print(f"fetch failed: {exc}", file=sys.stderr)
        return False

    if not verify(partial, expected):
        partial.unlink(missing_ok=True)
        return False
    shutil.move(str(partial), str(destination))
    return True


def check_upstream(lock: dict[str, Any]) -> int:
    """Report whether the pin is still the latest release.

    Advisory, never automatic. A new Ghidra can change decompiler output, which
    changes findings, which is exactly the kind of drift the run manifest
    exists to make visible — so the bump is a human's commit.
    """
    try:
        with urllib.request.urlopen(RELEASES_API, timeout=30) as response:
            release = json.loads(response.read())
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"could not reach the GitHub releases API: {exc}", file=sys.stderr)
        return 1

    tag = release.get("tag_name", "")
    assets = [a.get("name", "") for a in release.get("assets", [])]
    print(f"pinned:   {lock['version']}  ({lock['release_tag']})")
    print(f"upstream: {tag}")

    if tag == lock.get("release_tag"):
        print("\nThe pin is current.")
        return 0

    # The digest lives in the release body as a markdown line; upstream
    # publishes no checksum asset. Surfaced rather than parsed into an
    # automatic edit, because a digest scraped from prose is exactly the thing
    # a human should read before trusting.
    body = release.get("body") or ""
    digest_line = next((ln.strip() for ln in body.splitlines() if "SHA-256" in ln), "")
    print(
        f"\nA newer release is available.\n"
        f"  assets:  {', '.join(assets) or '(none)'}\n"
        f"  {digest_line or 'no SHA-256 line found in the release notes'}\n\n"
        f"To bump: edit {LOCK_PATH.relative_to(REPO_ROOT)} and the matching ARG\n"
        "defaults in sandbox/images/ghidra/Dockerfile, then run\n"
        "  uv run pytest tests/unit/test_ghidra_pin.py\n"
        "which fails if the two disagree."
    )
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--output", type=Path, metavar="DIR", help="download the pinned archive here"
    )
    group.add_argument("--verify", type=Path, metavar="FILE", help="verify an existing archive")
    group.add_argument(
        "--check-upstream",
        action="store_true",
        help="report whether a newer Ghidra release exists (does not modify anything)",
    )
    args = parser.parse_args(argv)
    lock = load_lock()

    if args.check_upstream:
        return check_upstream(lock)
    if args.verify:
        return 0 if verify(args.verify, lock["sha256"]) else 1

    destination = args.output / lock["archive"]
    if destination.is_file() and verify(destination, lock["sha256"]):
        print("already present and verified; nothing to do")
        return 0
    return 0 if download(lock["url"], destination, lock["sha256"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
