"""SARIF output tests.

The contract here is with GitHub code scanning and its equivalents, so the
tests pin the fields those platforms actually read: `ruleIndex` pointing at the
right rule, `partialFingerprints` staying stable, `security-severity` present,
and no plaintext anywhere.
"""

from __future__ import annotations

import json

from core.policy import GateDecision, GateVerdict
from core.vocab import Severity
from reporting.sarif import SARIF_VERSION, SarifFinding, build_sarif, dump_sarif


def finding(
    finding_id: str = "abc123",
    severity: Severity = Severity.CRITICAL,
    *,
    rule_id: str = "aws_secret_key",
    offset: int | None = 4096,
    is_new: bool = True,
) -> SarifFinding:
    return SarifFinding(
        id=finding_id,
        rule_id=rule_id,
        title="AWS secret access key",
        severity=severity,
        value_masked="AKIA****************EXAM",
        artifact_path="installer.exe",
        offset=offset,
        category="cloud_credentials",
        cwe="CWE-798",
        remediation_md="Rotate the key and remove it from the build.",
        is_new=is_new,
    )


def test_envelope_is_valid_sarif() -> None:
    log = build_sarif([finding()], tool_version="0.0.1", run_id="run-1")
    assert log["version"] == SARIF_VERSION
    assert log["$schema"].endswith("sarif-2.1.0.json")
    driver = log["runs"][0]["tool"]["driver"]
    assert driver["name"] == "BARE"
    assert driver["version"] == "0.0.1"


def test_rule_index_points_at_the_matching_rule() -> None:
    """A wrong ruleIndex silently mislabels every annotation."""
    findings = [
        finding("a", Severity.CRITICAL, rule_id="aws_secret_key"),
        finding("b", Severity.MEDIUM, rule_id="pdb_path"),
    ]
    log = build_sarif(findings, tool_version="0.0.1")
    rules = log["runs"][0]["tool"]["driver"]["rules"]
    for result in log["runs"][0]["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_severity_maps_to_level_and_security_severity() -> None:
    log = build_sarif(
        [finding("a", Severity.CRITICAL), finding("b", Severity.LOW, rule_id="internal_host")],
        tool_version="0.0.1",
    )
    results = {r["ruleId"]: r for r in log["runs"][0]["results"]}
    assert results["aws_secret_key"]["level"] == "error"
    assert results["internal_host"]["level"] == "note"

    rules = {r["id"]: r for r in log["runs"][0]["tool"]["driver"]["rules"]}
    assert rules["aws_secret_key"]["properties"]["security-severity"] == "9.5"
    assert rules["aws_secret_key"]["properties"]["bare-severity"] == "critical"


def test_fingerprint_is_the_content_derived_finding_id() -> None:
    """Stable ids are what stop a service reopening the same finding forever."""
    log = build_sarif([finding("stable-id")], tool_version="0.0.1")
    result = log["runs"][0]["results"][0]
    assert result["partialFingerprints"]["bareFindingId"] == "stable-id"


def test_byte_offset_is_used_rather_than_a_fabricated_line() -> None:
    log = build_sarif([finding(offset=4096)], tool_version="0.0.1")
    region = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["byteOffset"] == 4096
    assert "startLine" not in region


def test_missing_offset_omits_the_region_entirely() -> None:
    log = build_sarif([finding(offset=None)], tool_version="0.0.1")
    physical = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert "region" not in physical


def test_new_findings_are_marked_in_the_message() -> None:
    log = build_sarif(
        [finding("a", is_new=True), finding("b", rule_id="pdb_path", is_new=False)],
        tool_version="0.0.1",
    )
    messages = {r["ruleId"]: r["message"]["text"] for r in log["runs"][0]["results"]}
    assert "introduced by this build" in messages["aws_secret_key"]
    assert "introduced by this build" not in messages["pdb_path"]


def test_cwe_becomes_a_github_external_tag() -> None:
    log = build_sarif([finding()], tool_version="0.0.1")
    tags = log["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
    assert "external/cwe/cwe-798" in tags


def test_gate_verdict_is_carried_in_run_properties() -> None:
    verdict = GateVerdict(decision=GateDecision.BLOCKED, policy_name="release")
    log = build_sarif([finding()], tool_version="0.0.1", verdict=verdict)
    gate = log["runs"][0]["properties"]["gate"]
    assert gate["decision"] == "blocked"
    assert gate["policy"] == "release"


def test_no_plaintext_secret_reaches_the_sarif() -> None:
    """A SARIF file is uploaded to a third-party service and retained. Only
    masked values may appear in it."""
    plaintext = "AKIAIOSFODNN7EXAMPLE"
    item = SarifFinding(
        id="a",
        rule_id="aws_secret_key",
        title="AWS secret access key",
        severity=Severity.CRITICAL,
        value_masked="AKIA****************",
        artifact_path="installer.exe",
    )
    rendered = dump_sarif(build_sarif([item], tool_version="0.0.1"))
    assert plaintext not in rendered


def test_output_is_deterministic() -> None:
    findings = [
        finding("c", Severity.LOW, rule_id="internal_host"),
        finding("a", Severity.CRITICAL),
        finding("b", Severity.MEDIUM, rule_id="pdb_path"),
    ]
    first = dump_sarif(build_sarif(findings, tool_version="0.0.1"))
    second = dump_sarif(build_sarif(list(reversed(findings)), tool_version="0.0.1"))
    assert first == second


def test_dump_is_parseable_json() -> None:
    rendered = dump_sarif(build_sarif([finding()], tool_version="0.0.1"))
    assert json.loads(rendered)["version"] == SARIF_VERSION
    assert rendered.endswith("\n")


def test_empty_run_is_still_valid_sarif() -> None:
    """A clean scan must produce an uploadable file, not an empty one — an
    upload step that fails on success is a broken pipeline."""
    log = build_sarif([], tool_version="0.0.1", run_id="run-1")
    assert log["runs"][0]["results"] == []
    assert log["runs"][0]["tool"]["driver"]["rules"] == []
    assert json.loads(dump_sarif(log))
