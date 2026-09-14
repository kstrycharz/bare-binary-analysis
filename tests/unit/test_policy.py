"""Release-gate tests.

This is the component that fails somebody's build at 4pm on a Friday, so the
cases below are written around the ways a gate is wrong in practice: it blocks
on findings the team inherited, it lets an incomplete scan through as a pass,
or it lets a model's opinion open the door.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from core.policy import (
    BaselineMode,
    Budgets,
    DegradedPosture,
    GateDecision,
    GateFinding,
    Policy,
    PolicyLoadError,
    ViolationKind,
    Waiver,
    evaluate,
    parse_policy,
    parse_waivers,
)
from core.vocab import Severity

TODAY = date(2026, 8, 18)


def finding(
    finding_id: str = "f1",
    severity: Severity = Severity.CRITICAL,
    *,
    rule_id: str = "aws_secret_key",
    category: str = "cloud_credentials",
    status: str = "open",
    is_new: bool = True,
    llm_dismissed: bool = False,
) -> GateFinding:
    return GateFinding(
        id=finding_id,
        rule_id=rule_id,
        category=category,
        title=f"{rule_id} in shipped binary",
        severity=severity,
        status=status,
        is_new=is_new,
        llm_dismissed=llm_dismissed,
        artifact_path="installer.exe",
    )


# --- the severity floor ---------------------------------------------------


def test_critical_finding_blocks_by_default() -> None:
    verdict = evaluate([finding()], Policy(), today=TODAY)
    assert verdict.decision is GateDecision.BLOCKED
    assert verdict.exit_code == 1
    assert verdict.violations[0].kind is ViolationKind.SEVERITY_FLOOR


def test_medium_finding_does_not_block_by_default() -> None:
    verdict = evaluate([finding(severity=Severity.MEDIUM)], Policy(), today=TODAY)
    assert verdict.decision is GateDecision.PASS
    assert verdict.exit_code == 0
    assert verdict.total_findings == 1


def test_floor_can_be_disabled_entirely() -> None:
    policy = Policy(block_at_or_above=None)
    verdict = evaluate([finding()], policy, today=TODAY)
    assert verdict.decision is GateDecision.PASS


def test_blocked_rule_fires_below_the_floor() -> None:
    policy = Policy(block_rules=frozenset({"pdb_path"}))
    low = finding(severity=Severity.LOW, rule_id="pdb_path")
    verdict = evaluate([low], policy, today=TODAY)
    assert verdict.decision is GateDecision.BLOCKED
    assert verdict.violations[0].kind is ViolationKind.BLOCKED_RULE


def test_blocked_category_fires_below_the_floor() -> None:
    policy = Policy(block_categories=frozenset({"internal_infrastructure"}))
    verdict = evaluate(
        [finding(severity=Severity.LOW, category="internal_infrastructure")],
        policy,
        today=TODAY,
    )
    assert verdict.decision is GateDecision.BLOCKED
    assert verdict.violations[0].kind is ViolationKind.BLOCKED_CATEGORY


# --- the baseline, which is the whole point -------------------------------


def test_inherited_finding_does_not_fail_the_build() -> None:
    """The gate fails on what this build introduced, not what it inherited."""
    verdict = evaluate([finding(is_new=False)], Policy(), today=TODAY)
    assert verdict.decision is GateDecision.PASS
    assert len(verdict.inherited) == 1
    # Still reported: it is real, still shipped, and must stay visible.
    assert verdict.counts_by_severity == {"critical": 1}


def test_inherited_finding_blocks_under_all_mode() -> None:
    policy = Policy(baseline_mode=BaselineMode.ALL)
    verdict = evaluate([finding(is_new=False)], policy, today=TODAY)
    assert verdict.decision is GateDecision.BLOCKED


def test_new_finding_blocks_even_when_others_are_inherited() -> None:
    verdict = evaluate(
        [finding("old", is_new=False), finding("new", is_new=True)],
        Policy(),
        today=TODAY,
    )
    assert verdict.decision is GateDecision.BLOCKED
    assert [v.finding_id for v in verdict.violations] == ["new"]
    assert verdict.new_counts_by_severity == {"critical": 1}


# --- a model may not unblock a release ------------------------------------


def test_llm_dismissal_does_not_unblock_by_default() -> None:
    dismissed = finding(status="false_positive", llm_dismissed=True)
    verdict = evaluate([dismissed], Policy(), today=TODAY)
    assert verdict.decision is GateDecision.BLOCKED


def test_llm_dismissal_honoured_when_explicitly_trusted() -> None:
    dismissed = finding(status="false_positive", llm_dismissed=True)
    policy = Policy(trust_llm_dismissals=True)
    verdict = evaluate([dismissed], policy, today=TODAY)
    assert verdict.decision is GateDecision.PASS


def test_human_disposition_is_trusted() -> None:
    closed = finding(status="accepted_risk", llm_dismissed=False)
    verdict = evaluate([closed], Policy(), today=TODAY)
    assert verdict.decision is GateDecision.PASS


# --- degraded scans -------------------------------------------------------


def test_degraded_scan_with_no_findings_is_inconclusive_not_pass() -> None:
    """A scan that did not finish cannot support a pass."""
    verdict = evaluate([], Policy(), degraded_stages=["unpack"], today=TODAY)
    assert verdict.decision is GateDecision.INCONCLUSIVE
    assert verdict.exit_code == 3
    assert verdict.violations[0].kind is ViolationKind.DEGRADED_SCAN


def test_degraded_scan_with_a_real_finding_is_blocked() -> None:
    verdict = evaluate([finding()], Policy(), degraded_stages=["unpack"], today=TODAY)
    assert verdict.decision is GateDecision.BLOCKED


def test_degraded_posture_warn_is_inconclusive_but_not_a_violation() -> None:
    policy = Policy(on_degraded=DegradedPosture.WARN)
    verdict = evaluate([], policy, degraded_stages=["strings"], today=TODAY)
    assert verdict.decision is GateDecision.INCONCLUSIVE
    assert verdict.violations == ()
    assert verdict.warnings


def test_degraded_posture_pass_ignores_it() -> None:
    policy = Policy(on_degraded=DegradedPosture.PASS)
    verdict = evaluate([], policy, degraded_stages=["strings"], today=TODAY)
    assert verdict.decision is GateDecision.PASS


# --- waivers --------------------------------------------------------------


def test_live_waiver_unblocks_and_is_reported() -> None:
    waiver = Waiver(
        "f1", "vendor test key, not live", "kyle@example.com", TODAY + timedelta(days=30)
    )
    verdict = evaluate([finding()], Policy(), waivers=[waiver], today=TODAY)
    assert verdict.decision is GateDecision.PASS
    assert verdict.waived[0].owner == "kyle@example.com"


def test_expired_waiver_blocks_and_says_so() -> None:
    waiver = Waiver("f1", "was fine", "kyle@example.com", TODAY - timedelta(days=1))
    verdict = evaluate([finding()], Policy(), waivers=[waiver], today=TODAY)
    assert verdict.decision is GateDecision.BLOCKED
    assert verdict.violations[0].kind is ViolationKind.EXPIRED_WAIVER


def test_waiver_expiring_today_is_still_valid() -> None:
    waiver = Waiver("f1", "fine until close of play", "kyle@example.com", TODAY)
    verdict = evaluate([finding()], Policy(), waivers=[waiver], today=TODAY)
    assert verdict.decision is GateDecision.PASS


def test_waiver_beyond_max_ttl_warns_but_holds() -> None:
    waiver = Waiver("f1", "long haul", "kyle@example.com", TODAY + timedelta(days=400))
    verdict = evaluate([finding()], Policy(), waivers=[waiver], today=TODAY)
    assert verdict.decision is GateDecision.PASS
    assert any("maximum" in w for w in verdict.warnings)


def test_waiver_for_an_unrelated_finding_does_not_help() -> None:
    waiver = Waiver("other", "unrelated", "kyle@example.com", TODAY + timedelta(days=30))
    verdict = evaluate([finding()], Policy(), waivers=[waiver], today=TODAY)
    assert verdict.decision is GateDecision.BLOCKED


# --- budgets --------------------------------------------------------------


def test_budget_fires_on_non_blocking_severities() -> None:
    policy = Policy(budgets=Budgets(medium=2))
    findings = [finding(f"m{i}", Severity.MEDIUM) for i in range(3)]
    verdict = evaluate(findings, policy, today=TODAY)
    assert verdict.decision is GateDecision.BLOCKED
    assert verdict.violations[0].kind is ViolationKind.BUDGET_EXCEEDED


def test_budget_at_the_limit_passes() -> None:
    policy = Policy(budgets=Budgets(medium=2))
    findings = [finding(f"m{i}", Severity.MEDIUM) for i in range(2)]
    assert evaluate(findings, policy, today=TODAY).decision is GateDecision.PASS


def test_budget_does_not_double_count_a_blocking_finding() -> None:
    """Budgets are counted over what survived the floor, so a critical shows up
    as a severity violation once and not also as a budget overrun."""
    policy = Policy(budgets=Budgets(critical=0))
    verdict = evaluate([finding()], policy, today=TODAY)
    kinds = [v.kind for v in verdict.violations]
    assert kinds == [ViolationKind.SEVERITY_FLOOR]


# --- determinism ----------------------------------------------------------


def test_verdict_is_order_independent() -> None:
    findings = [
        finding("a", Severity.CRITICAL),
        finding("b", Severity.HIGH),
        finding("c", Severity.MEDIUM),
    ]
    forward = evaluate(findings, Policy(), today=TODAY)
    backward = evaluate(list(reversed(findings)), Policy(), today=TODAY)
    assert [v.finding_id for v in forward.violations] == [v.finding_id for v in backward.violations]


def test_violations_are_ordered_most_severe_first() -> None:
    findings = [finding("b", Severity.HIGH), finding("a", Severity.CRITICAL)]
    verdict = evaluate(findings, Policy(), today=TODAY)
    assert [v.severity for v in verdict.violations] == [Severity.CRITICAL, Severity.HIGH]


# --- loading --------------------------------------------------------------


def test_parse_policy_defaults_are_the_shipping_recommendation() -> None:
    policy = parse_policy({})
    assert policy.block_at_or_above is Severity.HIGH
    assert policy.baseline_mode is BaselineMode.NEW_ONLY
    assert policy.on_degraded is DegradedPosture.FAIL
    assert policy.trust_llm_dismissals is False


def test_parse_policy_reads_a_full_document() -> None:
    policy = parse_policy(
        {
            "name": "release",
            "block": {
                "severity_at_or_above": "critical",
                "categories": ["cloud_credentials"],
                "rules": ["pdb_path"],
            },
            "budgets": {"medium": 10},
            "baseline": {"mode": "all"},
            "on_degraded": "warn",
            "trust_llm_dismissals": True,
        }
    )
    assert policy.name == "release"
    assert policy.block_at_or_above is Severity.CRITICAL
    assert policy.block_categories == frozenset({"cloud_credentials"})
    assert policy.budgets.medium == 10
    assert policy.baseline_mode is BaselineMode.ALL
    assert policy.on_degraded is DegradedPosture.WARN


@pytest.mark.parametrize(
    "document",
    [
        {"block": {"severity_at_or_above": "catastrophic"}},
        {"baseline": {"mode": "sometimes"}},
        {"on_degraded": "shrug"},
        {"budgets": {"medium": "lots"}},
        {"budgets": {"nonsense": 1}},
        {"version": 2},
        {"waivers": {"max_ttl_days": 0}},
    ],
)
def test_malformed_policy_is_fatal(document: dict[str, object]) -> None:
    """A gate that falls back to a permissive default on a typo is worse than
    no gate at all."""
    with pytest.raises(PolicyLoadError):
        parse_policy(document)


def test_waiver_without_expiry_is_rejected() -> None:
    with pytest.raises(PolicyLoadError, match="expires"):
        parse_waivers({"waivers": [{"finding_id": "f1", "reason": "r", "owner": "o"}]}, Policy())


def test_waiver_without_owner_is_rejected_when_policy_requires_one() -> None:
    document = {"waivers": [{"finding_id": "f1", "reason": "r", "expires": "2026-12-01"}]}
    with pytest.raises(PolicyLoadError, match="owner"):
        parse_waivers(document, Policy())


def test_duplicate_waiver_is_rejected() -> None:
    entry = {"finding_id": "f1", "reason": "r", "owner": "o", "expires": "2026-12-01"}
    with pytest.raises(PolicyLoadError, match="duplicate"):
        parse_waivers({"waivers": [entry, dict(entry)]}, Policy())


def test_waiver_accepts_yaml_native_and_quoted_dates() -> None:
    """PyYAML turns an unquoted ISO date into a `date`, a quoted one into a
    string. Both spellings appear in real files."""
    document = {
        "waivers": [
            {"finding_id": "a", "reason": "r", "owner": "o", "expires": date(2026, 12, 1)},
            {"finding_id": "b", "reason": "r", "owner": "o", "expires": "2026-12-02"},
        ]
    }
    waivers = parse_waivers(document, Policy())
    assert [w.expires for w in waivers] == [date(2026, 12, 1), date(2026, 12, 2)]
