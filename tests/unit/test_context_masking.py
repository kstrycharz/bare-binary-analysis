"""Context snippets must not carry *any* matched secret, not just their own.

Found on a live scan of the synthetic corpus: the context stored for the AWS
secret access key contained the AWS access key ID in the clear, and vice versa.
Each snippet masked only its own finding's value, and secrets cluster — the two
halves of a credential pair sit on adjacent lines. Triage and explain send the
snippet to the configured model labelled "value masked", so with a cloud
provider this was plaintext crossing the §9 boundary.

A UTF-16LE neighbour is the quieter half of the same bug: in an ASCII-decoded
window it reads ``g.h.p._.9.f``, which no string replacement of the value finds
and a person still reads without effort.

Every credential-shaped value here comes from the corpus builder at runtime
rather than being written into this file. They are provably invalid either way,
but a literal would put a secret-shaped string in the diff, and the repository's
own secret scan is right to refuse that.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from core.rules import RulePack, load_rule_pack, mask, scan_bytes

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def pack() -> RulePack:
    return load_rule_pack(ROOT / "detections")


def _corpus() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "build_corpus", ROOT / "tests/corpus/build_corpus.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # Registered before executing: its dataclasses resolve string annotations
    # through sys.modules, and an unregistered module fails at class creation.
    sys.modules.setdefault(spec.name, module)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def installer(tmp_path_factory: pytest.TempPathFactory) -> tuple[bytes, list[Any]]:
    """The corpus installer that exposed the leak, and its answer key."""
    artifact = tmp_path_factory.mktemp("corpus") / "vulnerable-installer.exe"
    planted = _corpus().build_vulnerable_installer(artifact)
    return artifact.read_bytes(), planted


def _planted(installer: tuple[bytes, list[Any]], rule_id: str) -> str:
    values = [item.value for item in installer[1] if item.rule_id == rule_id]
    assert values, f"the corpus no longer plants a {rule_id}"
    return str(values[0])


def _legible_forms(value: str) -> list[str]:
    """How a value can appear in an ASCII-decoded window: as itself, and as a
    wide string whose zero bytes render as dots."""
    wide = "".join(f"{c}." for c in value)[:-1]
    return [value, wide]


def test_no_planted_secret_survives_in_any_context_of_the_corpus_installer(
    pack: RulePack, installer: tuple[bytes, list[Any]]
) -> None:
    """The regression, on the exact artifact that exposed it."""
    data, planted = installer
    matches = scan_bytes(data, pack)
    assert matches, "the corpus installer should produce matches"

    leaks = [
        f"{item.rule_id} ({item.encoding}) in context of {match.rule_id}@{match.offset:#x}"
        for item in planted
        for match in matches
        for form in _legible_forms(item.value)
        # Values shorter than this are not credentials and collide with ordinary text.
        if len(item.value) >= 8 and form in match.context
    ]
    assert leaks == []


def test_a_neighbouring_secret_is_masked_in_the_context(
    pack: RulePack, installer: tuple[bytes, list[Any]]
) -> None:
    key_id = _planted(installer, "aws-access-key-id")
    secret = _planted(installer, "aws-secret-access-key")
    data = "\n".join(
        [f"aws_access_key_id = {key_id}", f"aws_secret_access_key = {secret}", ""]
    ).encode()
    matches = scan_bytes(data, pack)
    assert {m.rule_id for m in matches} >= {"aws-access-key-id", "aws-secret-access-key"}
    for match in matches:
        assert key_id not in match.context
        assert secret not in match.context


def test_a_utf16_neighbour_is_masked_rather_than_left_legible(
    pack: RulePack, installer: tuple[bytes, list[Any]]
) -> None:
    key_id = _planted(installer, "aws-access-key-id")
    token = _planted(installer, "github-token")
    data = f"aws_key={key_id} ".encode() + f"token={token}".encode("utf-16le")
    matches = scan_bytes(data, pack)
    assert any(m.rule_id == "github-token" for m in matches)
    for match in matches:
        for form in _legible_forms(token) + _legible_forms(key_id):
            assert form not in match.context, match.rule_id


def test_a_finding_still_shows_its_own_value_masked(
    pack: RulePack, installer: tuple[bytes, list[Any]]
) -> None:
    """Masking neighbours must not cost the reviewer the one thing the snippet
    is for: seeing the shape of this finding's value in place."""
    key_id = _planted(installer, "aws-access-key-id")
    (match,) = [
        m for m in scan_bytes(f"key={key_id};".encode(), pack) if m.rule_id == "aws-access-key-id"
    ]
    assert mask(key_id) in match.context
    assert "key=" in match.context


def test_overlapping_matches_leave_no_fragment_of_either(
    pack: RulePack, installer: tuple[bytes, list[Any]]
) -> None:
    """The corpus plants a connection string whose host is an internal
    hostname: two matches over the same bytes. Neither the outer nor the inner
    value may show through any snippet."""
    data, _ = installer
    matches = scan_bytes(data, pack)

    def span(m: Any) -> tuple[int, int]:
        width = 2 if m.encoding == "utf-16le" else 1
        return m.offset, m.offset + len(m.value) * width

    pairs = [
        (outer, inner)
        for outer in matches
        for inner in matches
        if outer is not inner
        and span(outer)[0] <= span(inner)[0]
        and span(inner)[1] <= span(outer)[1]
    ]
    assert pairs, "the corpus should contain at least one match nested inside another"
    for outer, inner in pairs:
        for match in matches:
            assert outer.value not in match.context, (outer.rule_id, match.rule_id)
            assert inner.value not in match.context, (inner.rule_id, match.rule_id)


def test_context_is_deterministic(pack: RulePack, installer: tuple[bytes, list[Any]]) -> None:
    data, _ = installer
    first = [(m.rule_id, m.offset, m.context) for m in scan_bytes(data, pack)]
    second = [(m.rule_id, m.offset, m.context) for m in scan_bytes(data, pack)]
    assert first == second
