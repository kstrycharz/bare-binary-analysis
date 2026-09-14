"""`bare waive` and the module behind it.

The failure this guards against is specific: a waiver written under pressure
that the gate then refuses or silently ignores, so the build stays red with a
waiver sitting in the file. Every case below is a way that has happened by hand.
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from cli.gate_output import render_markdown, render_text
from cli.main import app
from core.policy import (
    GateDecision,
    GateFinding,
    Policy,
    ViolationKind,
    evaluate,
    load_policy,
    load_waivers,
    parse_policy,
)
from core.policy.waive import (
    NEW_FILE_HEADER,
    WaiveError,
    append_waiver,
    build_waiver,
    parse_expiry,
)
from core.vocab import Severity

RUNNER = CliRunner()
TODAY = date(2026, 9, 14)
FID = "3f2a91c4e8b7d05a9c1e44b2d7f08a61"
OTHER = "0123456789abcdef0123456789abcdef"


def _waiver(finding_id: str = FID, *, days: int = 30, policy: Policy | None = None):  # type: ignore[no-untyped-def]
    return build_waiver(
        finding_id=finding_id,
        reason="Vendor SDK sample key, confirmed inert",
        owner="kyle@example.com",
        expires=TODAY + timedelta(days=days),
        policy=policy or parse_policy({}),
        today=TODAY,
    )


# --- validation ------------------------------------------------------------


def test_a_shortened_id_is_refused_and_the_reason_is_explained() -> None:
    with pytest.raises(WaiveError) as caught:
        _waiver(FID[:12])
    message = str(caught.value)
    assert "shortened" in message
    assert "32" in message


def test_something_that_is_not_an_id_is_refused() -> None:
    with pytest.raises(WaiveError, match="not a finding id"):
        _waiver("aws_secret_key")


def test_ids_are_normalised_to_lower_case() -> None:
    assert _waiver(FID.upper()).finding_id == FID


@pytest.mark.parametrize(("field", "flag"), [("reason", "--reason"), ("owner", "--owner")])
def test_policy_required_fields_are_enforced(field: str, flag: str) -> None:
    kwargs = {"reason": "inert", "owner": "kyle@example.com", field: "  "}
    with pytest.raises(WaiveError, match=flag):
        build_waiver(
            finding_id=FID,
            expires=TODAY + timedelta(days=1),
            policy=parse_policy({}),
            today=TODAY,
            **kwargs,
        )


def test_a_policy_that_does_not_require_an_owner_accepts_none() -> None:
    policy = parse_policy({"waivers": {"require_owner": False}})
    waiver = build_waiver(
        finding_id=FID, reason="inert", owner="", expires=TODAY, policy=policy, today=TODAY
    )
    assert waiver.owner == ""


def test_an_expiry_in_the_past_is_refused() -> None:
    with pytest.raises(WaiveError, match="past"):
        _waiver(days=-1)


def test_an_expiry_past_the_policy_maximum_is_refused_rather_than_written() -> None:
    """The engine would decline to honour it, so writing it is a trap."""
    policy = parse_policy({"waivers": {"max_ttl_days": 14}})
    assert _waiver(days=14, policy=policy).expires == TODAY + timedelta(days=14)
    with pytest.raises(WaiveError, match="at most 14"):
        _waiver(days=15, policy=policy)


def test_expiry_accepts_a_date_or_a_number_of_days() -> None:
    assert parse_expiry("2026-10-01", TODAY) == date(2026, 10, 1)
    assert parse_expiry("30d", TODAY) == TODAY + timedelta(days=30)
    with pytest.raises(WaiveError):
        parse_expiry("next month", TODAY)


# --- appending -------------------------------------------------------------


def _loads(text: str) -> list[str]:
    return [w.finding_id for w in load_from_text(text)]


def load_from_text(text: str):  # type: ignore[no-untyped-def]
    from core.policy import parse_waivers

    return parse_waivers(yaml.safe_load(text), parse_policy({}))


def test_a_new_file_gets_a_header_and_loads() -> None:
    text = append_waiver("", _waiver(), parse_policy({}), source="w.yaml")
    assert text.startswith(NEW_FILE_HEADER)
    assert _loads(text) == [FID]


def test_existing_entries_and_comments_survive() -> None:
    existing = (
        "# Reviewed by the release board.\n"
        "waivers:\n"
        f"  - finding_id: {OTHER}\n"
        "    reason: bundled test cert  # SEC-4471\n"
        "    owner: sam@example.com\n"
        "    expires: 2026-10-01\n"
    )
    text = append_waiver(existing, _waiver(), parse_policy({}), source="w.yaml")
    assert text.startswith(existing)
    assert "# Reviewed by the release board." in text
    assert sorted(_loads(text)) == sorted([OTHER, FID])


def test_the_existing_list_indentation_is_followed() -> None:
    existing = (
        "waivers:\n"
        f"- finding_id: {OTHER}\n"
        "  reason: x\n"
        "  owner: sam@example.com\n"
        "  expires: 2026-10-01\n"
    )
    text = append_waiver(existing, _waiver(), parse_policy({}), source="w.yaml")
    assert sorted(_loads(text)) == sorted([OTHER, FID])


def test_an_empty_flow_list_is_opened_up() -> None:
    text = append_waiver("waivers: []\n", _waiver(), parse_policy({}), source="w.yaml")
    assert _loads(text) == [FID]


def test_a_file_with_no_waivers_key_gets_one() -> None:
    text = append_waiver("# nothing yet\n", _waiver(), parse_policy({}), source="w.yaml")
    assert _loads(text) == [FID]


def test_a_second_waiver_for_the_same_finding_is_refused() -> None:
    once = append_waiver("", _waiver(), parse_policy({}), source="w.yaml")
    with pytest.raises(WaiveError, match="already waives"):
        append_waiver(once, _waiver(days=10), parse_policy({}), source="w.yaml")


def test_a_layout_that_cannot_be_appended_to_is_refused_with_the_entry_to_paste() -> None:
    existing = (
        "waivers:\n"
        f"  - finding_id: {OTHER}\n"
        "    reason: x\n"
        "    owner: sam@example.com\n"
        "    expires: 2026-10-01\n"
        "notes: kept at the bottom\n"
    )
    with pytest.raises(WaiveError) as caught:
        append_waiver(existing, _waiver(), parse_policy({}), source="w.yaml")
    assert "by hand" in str(caught.value)
    assert FID in str(caught.value)


def test_a_file_that_already_fails_to_load_is_not_added_to() -> None:
    broken = f"waivers:\n  - finding_id: {OTHER}\n    reason: x\n    owner: sam@example.com\n"
    with pytest.raises(WaiveError, match="does not load"):
        append_waiver(broken, _waiver(), parse_policy({}), source="w.yaml")


def test_a_reason_cannot_change_the_document_structure() -> None:
    hostile = 'inert: yes # not a comment\n  - finding_id: "ffff"\n"quoted" ünïcode'
    waiver = build_waiver(
        finding_id=FID,
        reason=hostile,
        owner="kyle@example.com",
        expires=TODAY,
        policy=parse_policy({}),
        today=TODAY,
    )
    text = append_waiver("", waiver, parse_policy({}), source="w.yaml")
    loaded = load_from_text(text)
    assert [w.finding_id for w in loaded] == [FID]
    assert loaded[0].reason == hostile


# --- the command -----------------------------------------------------------


def _repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, policy: str = "name: strict\n") -> Path:
    (tmp_path / ".bare").mkdir()
    (tmp_path / ".bare" / "policy.yaml").write_text(policy, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return tmp_path / ".bare" / "waivers.yaml"


def _args(*extra: str) -> list[str]:
    return [
        "waive",
        FID,
        "--reason",
        "Vendor SDK sample key",
        "--owner",
        "kyle@example.com",
        *extra,
    ]


def test_the_command_writes_a_waiver_the_gate_then_honours(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _repo(tmp_path, monkeypatch)
    result = RUNNER.invoke(app, _args("--expires", "30d"))
    assert result.exit_code == 0, result.output
    assert "strict" in result.output

    policy = load_policy(tmp_path / ".bare" / "policy.yaml")
    waivers = load_waivers(target, policy)
    finding = GateFinding(
        id=FID,
        rule_id="aws_secret_key",
        category="cloud_credentials",
        title="AWS key",
        severity=Severity.CRITICAL,
        status="open",
    )
    verdict = evaluate([finding], policy, waivers=waivers)
    assert verdict.decision is GateDecision.PASS
    assert [w.finding_id for w in verdict.waived] == [FID]


def test_the_command_refuses_a_waiver_with_no_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _repo(tmp_path, monkeypatch)
    result = RUNNER.invoke(app, _args())
    assert result.exit_code == 2
    assert "--expires is required" in result.output
    assert not target.exists()


def test_the_command_uses_the_policy_maximum(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _repo(tmp_path, monkeypatch, "waivers:\n  max_ttl_days: 7\n")
    result = RUNNER.invoke(app, _args("--expires", "8d"))
    assert result.exit_code == 2
    assert "at most 7" in result.output
    assert not target.exists()


def test_dry_run_prints_the_entry_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _repo(tmp_path, monkeypatch)
    result = RUNNER.invoke(app, _args("--expires", "30d", "--dry-run"))
    assert result.exit_code == 0, result.output
    assert f"finding_id: {FID}" in result.output
    assert not target.exists()


def test_dry_run_on_an_empty_flow_list_prints_a_loadable_document(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = _repo(tmp_path, monkeypatch)
    target.write_text("waivers: []\n", encoding="utf-8")
    result = RUNNER.invoke(app, _args("--expires", "30d", "--dry-run"))
    assert result.exit_code == 0, result.output
    assert "waivers:\n" in result.output
    assert target.read_text(encoding="utf-8") == "waivers: []\n"


def test_crlf_line_endings_are_preserved(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    target = _repo(tmp_path, monkeypatch)
    target.write_bytes(b"# windows checkout\r\nwaivers:\r\n")
    result = RUNNER.invoke(app, _args("--expires", "30d"))
    assert result.exit_code == 0, result.output
    raw = target.read_bytes()
    assert b"\r\n" in raw
    assert b"\n" not in raw.replace(b"\r\n", b"")


def test_without_a_policy_the_waiver_goes_in_the_default_location(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    result = RUNNER.invoke(app, _args("--expires", "30d"))
    assert result.exit_code == 0, result.output
    assert (tmp_path / ".bare" / "waivers.yaml").is_file()


# --- the output people copy ids from ----------------------------------------


def _verdict_with_violation():  # type: ignore[no-untyped-def]
    finding = GateFinding(
        id=FID,
        rule_id="aws_secret_key",
        category="cloud_credentials",
        title="AWS key",
        severity=Severity.CRITICAL,
        status="open",
    )
    verdict = evaluate([finding], Policy(), today=TODAY)
    assert verdict.violations[0].kind is ViolationKind.SEVERITY_FLOOR
    return verdict


def test_gate_output_prints_the_full_id_that_a_waiver_needs() -> None:
    verdict = _verdict_with_violation()
    assert f"[{FID}]" in render_text(verdict)
    assert f"`{FID}`" in render_markdown(verdict)
    assert "bare waive" in render_text(verdict)
