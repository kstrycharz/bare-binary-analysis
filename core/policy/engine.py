"""Policy evaluation: findings in, a release decision out.

Pure and deterministic. No database, no network, no model. The same findings
and the same policy produce the same verdict on any machine, which is the only
way a gate is defensible in an audit — "the build failed because clause X
matched finding Y" has to be reproducible six months later.

The ordering rules matter and are explicit:

1. A degraded scan is considered *before* findings. An incomplete scan cannot
   support a PASS, and letting a clean-but-partial result through is the
   failure mode that makes a gate worse than useless.
2. Waivers apply only to findings that would otherwise block, and an expired
   waiver is itself a violation rather than a silent no-op.
3. Budgets are counted after the severity floor, over the findings that
   survived it, so a budget cannot mask a blocking finding.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import date

from core.policy.model import (
    BaselineMode,
    DegradedPosture,
    GateDecision,
    GateFinding,
    GateVerdict,
    Violation,
    ViolationKind,
    WaivedFinding,
    Waiver,
)
from core.policy.policy import UNLIMITED, Policy
from core.vocab import Severity


def evaluate(
    findings: Iterable[GateFinding],
    policy: Policy,
    *,
    waivers: Iterable[Waiver] = (),
    degraded_stages: Iterable[str] = (),
    today: date | None = None,
) -> GateVerdict:
    """Decide whether this artifact may ship."""
    today = today or date.today()
    all_findings = sorted(findings, key=lambda f: (f.severity.rank, f.rule_id, f.id))
    stages = tuple(sorted(set(degraded_stages)))
    waiver_index = {w.finding_id: w for w in waivers}

    counts: dict[str, int] = defaultdict(int)
    new_counts: dict[str, int] = defaultdict(int)
    for finding in all_findings:
        counts[finding.severity.value] += 1
        if finding.is_new:
            new_counts[finding.severity.value] += 1

    violations: list[Violation] = []
    waived: list[WaivedFinding] = []
    inherited: list[GateFinding] = []
    warnings: list[str] = []

    # --- 1. an incomplete scan cannot support a pass ------------------------
    if stages and policy.on_degraded is DegradedPosture.FAIL:
        violations.append(
            Violation(
                kind=ViolationKind.DEGRADED_SCAN,
                detail=(
                    f"scan incomplete: {', '.join(stages)} did not finish, so the artifact "
                    "was not fully examined"
                ),
            )
        )
    elif stages and policy.on_degraded is DegradedPosture.WARN:
        warnings.append(
            f"scan incomplete: {', '.join(stages)} did not finish; findings may be partial"
        )

    # --- 2. per-finding evaluation -----------------------------------------
    considered: list[GateFinding] = []
    for finding in all_findings:
        if not _is_actionable(finding, policy):
            continue

        if policy.baseline_mode is BaselineMode.NEW_ONLY and not finding.is_new:
            # Present in the baseline: real, still in the artifact, reported —
            # but not something this build introduced, so it does not fail it.
            inherited.append(finding)
            continue

        reason = _blocking_reason(finding, policy)
        if reason is None:
            considered.append(finding)
            continue

        waiver = waiver_index.get(finding.id)
        if waiver is None:
            violations.append(_violation(finding, reason))
            continue

        if waiver.is_expired(today):
            violations.append(
                Violation(
                    kind=ViolationKind.EXPIRED_WAIVER,
                    detail=(
                        f"waiver expired {waiver.expires.isoformat()} "
                        f"(owner: {waiver.owner or 'unknown'})"
                    ),
                    finding_id=finding.id,
                    rule_id=finding.rule_id,
                    severity=finding.severity,
                    title=finding.title,
                    artifact_path=finding.artifact_path,
                )
            )
            continue

        if _waiver_exceeds_ttl(waiver, policy, today):
            warnings.append(
                f"waiver for {finding.id[:12]} runs past the {policy.max_waiver_days}-day "
                f"maximum (expires {waiver.expires.isoformat()})"
            )

        waived.append(
            WaivedFinding(
                finding_id=finding.id,
                title=finding.title,
                severity=finding.severity,
                owner=waiver.owner,
                reason=waiver.reason,
                expires=waiver.expires,
            )
        )

    # --- 3. budgets, over what survived the floor ---------------------------
    violations.extend(_budget_violations(considered, policy))

    decision = _decide(violations, stages, policy)

    return GateVerdict(
        decision=decision,
        policy_name=policy.name,
        violations=tuple(violations),
        waived=tuple(waived),
        inherited=tuple(inherited),
        degraded_stages=stages,
        counts_by_severity=dict(counts),
        new_counts_by_severity=dict(new_counts),
        total_findings=len(all_findings),
        warnings=tuple(warnings),
    )


def _is_actionable(finding: GateFinding, policy: Policy) -> bool:
    """Whether the gate should consider this finding at all.

    A finding a *person* closed is closed. A finding the *model* called a false
    positive is only closed if the policy says so, which it does not by
    default: a language model must not be able to unblock a release on its own
    (ADR-0017). The severity floor in triage (ADR-0012) already keeps criticals
    out of the model's reach, and this is the same principle one layer out.
    """
    if finding.is_open:
        return True
    # Closed — but the gate reopens it if the model was what closed it.
    return finding.llm_dismissed and not policy.trust_llm_dismissals


def _blocking_reason(finding: GateFinding, policy: Policy) -> ViolationKind | None:
    if finding.rule_id in policy.block_rules:
        return ViolationKind.BLOCKED_RULE
    if finding.category in policy.block_categories:
        return ViolationKind.BLOCKED_CATEGORY
    if policy.blocks(finding.severity):
        return ViolationKind.SEVERITY_FLOOR
    return None


def _violation(finding: GateFinding, kind: ViolationKind) -> Violation:
    detail = {
        ViolationKind.SEVERITY_FLOOR: f"{finding.severity.value} finding blocks release",
        ViolationKind.BLOCKED_RULE: f"rule {finding.rule_id} is blocked by policy",
        ViolationKind.BLOCKED_CATEGORY: f"category {finding.category} is blocked by policy",
    }[kind]
    return Violation(
        kind=kind,
        detail=detail,
        finding_id=finding.id,
        rule_id=finding.rule_id,
        severity=finding.severity,
        title=finding.title,
        artifact_path=finding.artifact_path,
    )


def _budget_violations(findings: list[GateFinding], policy: Policy) -> list[Violation]:
    counts: dict[Severity, int] = defaultdict(int)
    for finding in findings:
        counts[finding.severity] += 1

    violations: list[Violation] = []
    for severity in sorted(counts, key=lambda s: s.rank):
        limit = policy.budgets.limit_for(severity)
        if limit == UNLIMITED:
            continue
        count = counts[severity]
        if count > limit:
            violations.append(
                Violation(
                    kind=ViolationKind.BUDGET_EXCEEDED,
                    detail=(f"{count} {severity.value} findings exceed the budget of {limit}"),
                    severity=severity,
                )
            )
    return violations


def _waiver_exceeds_ttl(waiver: Waiver, policy: Policy, today: date) -> bool:
    return (waiver.expires - today).days > policy.max_waiver_days


def _decide(violations: list[Violation], stages: tuple[str, ...], policy: Policy) -> GateDecision:
    """A degraded scan with no findings is INCONCLUSIVE, not BLOCKED.

    The distinction is real: "we found a problem" and "we could not finish
    looking" call for different responses from a release manager, and
    collapsing them into one failure teaches people to retry until it passes.
    """
    degraded_only = violations and all(v.kind is ViolationKind.DEGRADED_SCAN for v in violations)
    if degraded_only:
        return GateDecision.INCONCLUSIVE
    if violations:
        return GateDecision.BLOCKED
    if stages and policy.on_degraded is DegradedPosture.WARN:
        return GateDecision.INCONCLUSIVE
    return GateDecision.PASS
