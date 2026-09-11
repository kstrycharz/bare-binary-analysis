"""Rendering a gate verdict for a build log.

A CI failure message is read by someone who did not run the scan, is not a
security engineer, and wants to know three things in the first five lines: did
it fail, what failed it, and what do I do now. Everything here is shaped around
that, which is why the remediation hint is not optional and the inherited
findings are summarised rather than listed.
"""

from __future__ import annotations

import json
from typing import Any

from core.policy import GateDecision, GateVerdict

# Box-drawing stays out of it: build log renderers mangle it, and the output
# has to survive being pasted into a chat message.
_RULE = "-" * 72


def render_text(verdict: GateVerdict, *, artifact: str = "", run_url: str = "") -> str:
    headline = f"  BARE RELEASE GATE — {verdict.decision.value.upper()}"
    lines: list[str] = [_RULE, headline, _RULE]

    if artifact:
        lines.append(f"  artifact : {artifact}")
    lines.append(f"  policy   : {verdict.policy_name}")
    if run_url:
        lines.append(f"  report   : {run_url}")

    counts = verdict.counts_by_severity
    if counts:
        summary = ", ".join(
            f"{count} {severity}"
            for severity, count in sorted(counts.items(), key=lambda kv: _rank(kv[0]))
        )
        new_total = sum(verdict.new_counts_by_severity.values())
        lines.append(f"  findings : {summary}  ({new_total} new in this build)")
    else:
        lines.append("  findings : none")
    lines.append("")

    if verdict.violations:
        lines.append(f"  BLOCKING ({len(verdict.violations)}):")
        for violation in verdict.violations:
            lines.append(f"    {violation.render()}")
            if violation.finding_id:
                lines.append(f"             {violation.detail}  [{violation.finding_id[:12]}]")
            else:
                lines.append(f"             {violation.detail}")
        lines.append("")

    if verdict.waived:
        lines.append(f"  WAIVED ({len(verdict.waived)}):")
        for waived in verdict.waived:
            lines.append(
                f"    {waived.severity.value:8} {waived.title} "
                f"— {waived.owner}, expires {waived.expires.isoformat()}"
            )
        lines.append("")

    if verdict.inherited:
        # Summarised, not listed. These did not fail the build, but a release
        # manager must not be able to forget they are still in the artifact.
        lines.append(
            f"  INHERITED ({len(verdict.inherited)}): present in the baseline, still shipped, "
            "not introduced by this build"
        )
        lines.append("")

    for warning in verdict.warnings:
        lines.append(f"  warning: {warning}")
    if verdict.warnings:
        lines.append("")

    lines.append(f"  {_next_step(verdict)}")
    lines.append(_RULE)
    return "\n".join(lines)


def _rank(severity: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(severity, 9)


def _next_step(verdict: GateVerdict) -> str:
    if verdict.decision is GateDecision.PASS:
        return "Release may proceed."
    if verdict.decision is GateDecision.INCONCLUSIVE:
        return (
            "The scan did not complete, so this artifact was not fully examined. "
            "Re-run the scan; if it degrades again, raise the analyzer limits "
            "rather than lowering the gate."
        )
    return (
        "Remove the value from the artifact and rotate it if it is live. "
        "If it is genuinely benign, add a time-boxed waiver to "
        ".bare/waivers.yaml with an owner and a reason."
    )


def render_json(
    verdict: GateVerdict,
    *,
    run_id: str = "",
    artifact: str = "",
    baseline: str = "",
) -> str:
    """Machine-readable verdict, for a pipeline step that wants to branch."""
    payload: dict[str, Any] = {
        "decision": verdict.decision.value,
        "exit_code": verdict.exit_code,
        "policy": verdict.policy_name,
        "run_id": run_id,
        "artifact": artifact,
        "baseline": baseline,
        "counts_by_severity": verdict.counts_by_severity,
        "new_counts_by_severity": verdict.new_counts_by_severity,
        "total_findings": verdict.total_findings,
        "degraded_stages": list(verdict.degraded_stages),
        "warnings": list(verdict.warnings),
        "violations": [
            {
                "kind": v.kind.value,
                "detail": v.detail,
                "finding_id": v.finding_id,
                "rule_id": v.rule_id,
                "severity": v.severity.value if v.severity else None,
                "title": v.title,
                "artifact_path": v.artifact_path,
            }
            for v in verdict.violations
        ],
        "waived": [
            {
                "finding_id": w.finding_id,
                "title": w.title,
                "severity": w.severity.value,
                "owner": w.owner,
                "reason": w.reason,
                "expires": w.expires.isoformat(),
            }
            for w in verdict.waived
        ],
        "inherited_count": len(verdict.inherited),
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_markdown(verdict: GateVerdict, *, artifact: str = "", run_url: str = "") -> str:
    """A PR comment / job summary. GitHub Actions renders this into the run
    summary page, which is where people actually look after a red build."""
    icon = {
        GateDecision.PASS: "✅",
        GateDecision.BLOCKED: "🚫",
        GateDecision.INCONCLUSIVE: "⚠️",
    }[verdict.decision]

    lines = [f"## {icon} BARE release gate — {verdict.decision.value}", ""]
    if artifact:
        lines.append(f"**Artifact:** `{artifact}`  ")
    lines.append(f"**Policy:** `{verdict.policy_name}`  ")
    if run_url:
        lines.append(f"**Full report:** {run_url}  ")
    lines.append("")

    if verdict.violations:
        lines += [
            "### Blocking findings",
            "",
            "| Severity | Finding | Location | Why |",
            "| --- | --- | --- | --- |",
        ]
        for v in verdict.violations:
            severity = v.severity.value if v.severity else "—"
            lines.append(
                f"| {severity} | {v.title or '—'} | `{v.artifact_path or '—'}` | {v.detail} |"
            )
        lines.append("")

    if verdict.inherited:
        lines.append(
            f"_{len(verdict.inherited)} inherited finding(s) are still present in this "
            "artifact but were not introduced by this build._"
        )
        lines.append("")

    for warning in verdict.warnings:
        lines.append(f"> ⚠️ {warning}")

    lines.append("")
    lines.append(_next_step(verdict))
    return "\n".join(lines) + "\n"
