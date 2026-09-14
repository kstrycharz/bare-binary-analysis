"""Tests for the CI client and the verdict wire format.

Two things are worth pinning here. The multipart body is hand-rolled so that a
2 GB installer never has to fit in a build agent's memory, and a hand-rolled
multipart body that is subtly wrong produces a 422 from the API with no useful
message. The verdict codec is what the CLI's exit code is ultimately derived
from, so a field lost in transit is a build that passes when it should fail.
"""

from __future__ import annotations

import urllib.request
from datetime import date
from pathlib import Path

import pytest

from cli.client import ApiError, BareClient, _MultipartBody
from cli.gate_output import render_json, render_markdown, render_text
from core.policy import (
    GateDecision,
    GateFinding,
    GateVerdict,
    Policy,
    Violation,
    ViolationKind,
    WaivedFinding,
    Waiver,
    evaluate,
    verdict_from_dict,
    verdict_to_dict,
)
from core.vocab import Severity

TODAY = date(2026, 8, 18)


def _blocked_verdict() -> GateVerdict:
    return evaluate(
        [
            GateFinding(
                id="abc123def456",
                rule_id="aws_secret_key",
                category="cloud_credentials",
                title="AWS secret access key",
                severity=Severity.CRITICAL,
                status="open",
                artifact_path="installer.exe",
            ),
            GateFinding(
                id="inherited1",
                rule_id="pdb_path",
                category="build_and_scm",
                title="PDB path",
                severity=Severity.HIGH,
                status="open",
                is_new=False,
            ),
        ],
        Policy(),
        today=TODAY,
    )


# --- multipart streaming ---------------------------------------------------


def _drain(body: _MultipartBody) -> bytes:
    chunks: list[bytes] = []
    while True:
        chunk = body.read(8192)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def test_multipart_content_length_matches_the_bytes_produced(tmp_path: Path) -> None:
    """A Content-Length that disagrees with the body hangs the request or
    truncates the upload, and neither failure names its cause."""
    artifact = tmp_path / "installer.exe"
    artifact.write_bytes(b"MZ" + b"\x00" * 5000)

    body = _MultipartBody({"profile": "standard", "attested_by": "kyle"}, "file", artifact)
    declared = body.content_length
    produced = _drain(body)
    assert len(produced) == declared


def test_multipart_carries_every_field_and_the_file(tmp_path: Path) -> None:
    artifact = tmp_path / "installer.exe"
    artifact.write_bytes(b"MZ\x90\x00PAYLOAD")

    body = _MultipartBody(
        {"profile": "deep", "attested_by": "kyle", "attestation_reference": "SEC-1"},
        "file",
        artifact,
    )
    raw = _drain(body)

    assert b'name="profile"' in raw
    assert b"deep" in raw
    assert b'name="attested_by"' in raw
    assert b'name="file"; filename="installer.exe"' in raw
    assert b"MZ\x90\x00PAYLOAD" in raw
    assert raw.endswith(f"--{body.boundary}--\r\n".encode())


def test_multipart_streams_rather_than_buffering(tmp_path: Path) -> None:
    """The first read returns only the preamble; the file arrives in later
    reads. If this ever buffers, a large installer takes the agent down."""
    artifact = tmp_path / "big.bin"
    artifact.write_bytes(b"A" * 100_000)

    body = _MultipartBody({"profile": "standard"}, "file", artifact)
    first = body.read(8192)
    assert b'name="profile"' in first
    assert b"A" * 100 not in first
    body.close()


def test_multipart_handles_an_empty_file(tmp_path: Path) -> None:
    artifact = tmp_path / "empty.bin"
    artifact.write_bytes(b"")
    body = _MultipartBody({"profile": "standard"}, "file", artifact)
    assert len(_drain(body)) == body.content_length


# --- verdict codec ---------------------------------------------------------


def test_verdict_round_trips() -> None:
    original = _blocked_verdict()
    restored = verdict_from_dict(verdict_to_dict(original))

    assert restored.decision is original.decision
    assert restored.exit_code == original.exit_code
    assert restored.policy_name == original.policy_name
    assert restored.total_findings == original.total_findings
    assert restored.counts_by_severity == original.counts_by_severity
    assert len(restored.violations) == len(original.violations)
    assert restored.violations[0].finding_id == original.violations[0].finding_id
    assert restored.violations[0].severity is original.violations[0].severity
    assert len(restored.inherited) == len(original.inherited)


def test_waivers_round_trip_with_their_dates() -> None:
    verdict = evaluate(
        [
            GateFinding(
                id="f1",
                rule_id="aws_secret_key",
                category="cloud_credentials",
                title="AWS key",
                severity=Severity.CRITICAL,
                status="open",
            )
        ],
        Policy(),
        waivers=[Waiver("f1", "vendor sample", "kyle@example.com", date(2026, 12, 1))],
        today=TODAY,
    )
    restored = verdict_from_dict(verdict_to_dict(verdict))
    assert restored.decision is GateDecision.PASS
    assert restored.waived[0].expires == date(2026, 12, 1)
    assert restored.waived[0].owner == "kyle@example.com"


def test_degraded_verdict_round_trips_its_exit_code() -> None:
    verdict = evaluate([], Policy(), degraded_stages=["unpack (oom)"], today=TODAY)
    restored = verdict_from_dict(verdict_to_dict(verdict))
    assert restored.decision is GateDecision.INCONCLUSIVE
    assert restored.exit_code == 3
    assert restored.degraded_stages == ("unpack (oom)",)


# --- rendering -------------------------------------------------------------


def test_text_output_leads_with_the_decision() -> None:
    rendered = render_text(_blocked_verdict(), artifact="installer.exe")
    head = rendered.splitlines()[1]
    assert "BLOCKED" in head


def test_text_output_names_the_blocking_finding_and_the_next_step() -> None:
    rendered = render_text(_blocked_verdict(), artifact="installer.exe")
    assert "AWS secret access key" in rendered
    assert "installer.exe" in rendered
    assert "rotate it if it is live" in rendered


def test_text_output_summarises_inherited_findings_without_listing_them() -> None:
    rendered = render_text(_blocked_verdict())
    assert "INHERITED (1)" in rendered
    assert "PDB path" not in rendered


def test_inconclusive_output_says_the_scan_was_incomplete() -> None:
    verdict = evaluate([], Policy(), degraded_stages=["ghidra (oom)"], today=TODAY)
    rendered = render_text(verdict)
    assert "INCONCLUSIVE" in rendered
    assert "not fully examined" in rendered
    # The advice must not be "lower the gate".
    assert "raise the analyzer limits" in rendered


def test_pass_output_is_unambiguous() -> None:
    verdict = evaluate([], Policy(), today=TODAY)
    rendered = render_text(verdict)
    assert "PASS" in rendered
    assert "Release may proceed" in rendered


def test_json_output_carries_the_exit_code() -> None:
    import json

    payload = json.loads(render_json(_blocked_verdict(), run_id="run-1", artifact="installer.exe"))
    assert payload["decision"] == "blocked"
    assert payload["exit_code"] == 1
    assert payload["run_id"] == "run-1"
    assert payload["violations"][0]["rule_id"] == "aws_secret_key"


def test_markdown_output_is_a_table_a_reviewer_can_read() -> None:
    rendered = render_markdown(_blocked_verdict(), artifact="installer.exe", run_url="http://x/1")
    assert "| Severity | Finding | Location | Why | Id |" in rendered
    assert "aws" in rendered.lower()
    assert "http://x/1" in rendered


def test_rendering_never_emits_a_raw_secret() -> None:
    """The renderers only ever receive masked values, and must not gain a path
    to anything else."""
    verdict = GateVerdict(
        decision=GateDecision.BLOCKED,
        policy_name="default",
        violations=(
            Violation(
                kind=ViolationKind.SEVERITY_FLOOR,
                detail="critical finding blocks release",
                finding_id="f1",
                rule_id="aws_secret_key",
                severity=Severity.CRITICAL,
                title="AWS secret access key",
                artifact_path="installer.exe",
            ),
        ),
        waived=(
            WaivedFinding("f2", "Vendor key", Severity.HIGH, "kyle", "inert", date(2026, 12, 1)),
        ),
    )
    for rendered in (render_text(verdict), render_markdown(verdict), render_json(verdict)):
        assert "AKIAIOSFODNN7EXAMPLE" not in rendered


# -- transport failures -----------------------------------------------------
#
# A build agent gets a sentence and an exit code. Anything that reaches it as a
# Python traceback is a bug in this client, not information: it buries the one
# actionable line in forty of stack, and the operator cannot tell a broken
# BARE from a broken pipeline. Observed against a real 213 MB scan — a
# read that stalled after the response headers arrived raised a bare
# TimeoutError, which is not a URLError and so matched no handler at all.


def _client_raising(
    monkeypatch: pytest.MonkeyPatch, exc: BaseException
) -> BareClient:
    """Fail at the socket, where these errors actually originate."""

    def _boom(*args: object, **kwargs: object) -> None:
        raise exc

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    return BareClient("http://example.invalid", token="t", timeout_s=30)


def test_a_read_timeout_becomes_an_actionable_error_not_a_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client_raising(monkeypatch, TimeoutError())
    with pytest.raises(ApiError) as caught:
        client.get_run("run-1")
    message = str(caught.value)
    assert "timed out" in message
    # Naming the remedy matters: the default is frequently just too short for a
    # large installer, and "timed out" alone reads as "the server is broken".
    assert "--timeout" in message


def test_an_unexpected_socket_error_is_still_an_api_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Anything from the socket layer, not only the cases we predicted."""
    client = _client_raising(monkeypatch, ConnectionResetError("connection reset by peer"))
    with pytest.raises(ApiError) as caught:
        client.get_run("run-1")
    assert "connection reset" in str(caught.value)


def test_the_pdf_download_is_guarded_the_same_way(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """It has its own urlopen call, so it needs its own handlers — the kind of
    divergence that only shows up on the slow path in production."""
    client = _client_raising(monkeypatch, TimeoutError())
    with pytest.raises(ApiError) as caught:
        client.get_pdf("run-1")
    assert "timed out" in str(caught.value)
