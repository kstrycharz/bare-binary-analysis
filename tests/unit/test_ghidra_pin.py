"""The Ghidra pin is written down twice, and the two copies must agree.

``ghidra.lock.json`` is what a human edits to bump; the Dockerfile's ARG
defaults are what a build actually downloads and verifies. A bump that lands in
one and not the other either builds the old release while every document names
the new one, or fails a digest check with an error that points nowhere near the
cause. See ADR-0034.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
IMAGE_DIR = REPO_ROOT / "sandbox" / "images" / "ghidra"
LOCK = json.loads((IMAGE_DIR / "ghidra.lock.json").read_text(encoding="utf-8"))
DOCKERFILE = (IMAGE_DIR / "Dockerfile").read_text(encoding="utf-8")


def _arg_defaults() -> dict[str, str]:
    return dict(re.findall(r"^ARG (\w+)=(\S+)$", DOCKERFILE, flags=re.MULTILINE))


@pytest.mark.parametrize(
    ("arg", "key"),
    [
        ("GHIDRA_VERSION", "version"),
        ("GHIDRA_ARCHIVE", "archive"),
        ("GHIDRA_SHA256", "sha256"),
        ("GHIDRA_DIR", "unpacked_dir"),
        ("GHIDRA_URL", "url"),
    ],
)
def test_the_dockerfile_default_matches_the_lock(arg: str, key: str) -> None:
    assert _arg_defaults().get(arg) == LOCK[key], f"{arg} disagrees with ghidra.lock.json[{key!r}]"


def test_the_digest_is_a_full_sha256() -> None:
    assert re.fullmatch(r"[0-9a-f]{64}", LOCK["sha256"])


def test_the_url_is_the_upstream_release_of_the_pinned_version() -> None:
    """Not a mirror, not a fork: the vendor's own release asset for this tag."""
    assert LOCK["url"] == (
        f"{LOCK['upstream']}/releases/download/{LOCK['release_tag']}/{LOCK['archive']}"
    )
    assert LOCK["version"] in LOCK["release_tag"]
    assert LOCK["archive"].startswith(f"ghidra_{LOCK['version']}_PUBLIC")


def test_the_build_verifies_the_archive_before_unzipping_it() -> None:
    """A proxy's HTML error page must fail the digest, not become a broken
    Ghidra tree that fails later with a missing class."""
    verify = DOCKERFILE.index("sha256sum --check")
    unzip = DOCKERFILE.index("unzip -q")
    assert verify < unzip


def test_the_notice_names_the_same_release() -> None:
    notice = (IMAGE_DIR / "NOTICE.md").read_text(encoding="utf-8")
    for value in (LOCK["version"], LOCK["sha256"], LOCK["archive"]):
        assert value in notice, f"NOTICE.md does not mention {value}"


def test_upstream_licensing_material_is_not_stripped() -> None:
    """Shipping Ghidra with its own licence text is a condition of using it."""
    removal = next(line for line in DOCKERFILE.splitlines() if line.startswith("RUN rm -rf"))
    for kept in ("licenses", "LICENSE", "NOTICE"):
        assert kept not in removal
