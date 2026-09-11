"""The `explain` and `summarize` roles.

Both were routable in ``config/llm.yaml`` and described on the settings page
long before anything called them, which is a worse failure than not having
them: the UI promised a capability, an operator configured a model for it, and
nothing ever happened. This module is what those two roles now run.

**Neither role may change a finding.** Triage at least writes a status, under
the severity floor. These two write prose and nothing else — ``explain`` fills
``llm_explanation``, ``summarize`` fills ``Run.llm_summary``. There is no code
path here that touches severity, offsets, ``value_hash``, or status, which is
how §2.5 is kept structural rather than prompt-dependent.

**Masked values only.** Same rule as triage: the model is shown shape,
entropy, rule, and location. A run that retained plaintext does not change
what is sent — retention exists so a human can rotate the credential, not so a
model can read it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

import structlog

from core.llm.provider import Completion, LLMProvider, Message
from core.models import Finding, LlmCall, Run
from core.vocab import Severity

log = structlog.get_logger(__name__)

EXPLAIN_SYSTEM_PROMPT = """\
You are a security engineer writing for the developer who has to fix an \
exposure found in a compiled artifact their team is about to ship. A \
deterministic scanner found it; you are explaining it, not deciding whether \
it is real.

Write three short paragraphs, no headings, no bullet points:
1. What this value is and how it most likely ended up in the binary.
2. What an attacker who extracted it could reach, and why that matters here.
3. What to do about it, in order, starting with rotation.

Ground every claim in the evidence given. If the evidence does not support a \
claim, leave it out rather than speculating. Say plainly when the impact \
depends on something you were not told.

You are shown a MASKED value. Never ask for the real one, and never guess it.

Describe exposure and remediation only. Never write exploit code, credential \
recovery steps, or instructions for using the discovered value.

Reply with prose only. No JSON, no preamble, no sign-off."""

SUMMARIZE_SYSTEM_PROMPT = """\
You are a security engineer briefing a release manager who must decide \
whether to ship a build. A deterministic scanner has finished; you are \
summarising its results, not re-judging them.

Write one paragraph, at most six sentences, covering:
- The overall exposure picture, led by the most severe finding.
- Any pattern worth naming (one leaked build environment, one vendored \
component, credentials of a single kind).
- What a reviewer should look at first.

Use only the counts and findings given. Never invent a finding, never revise \
a severity, and never state a total that contradicts the numbers provided. If \
the scan found nothing of consequence, say so plainly and stop.

Describe exposure and remediation only. No exploit code.

Reply with prose only. No JSON, no headings, no bullet points."""


@dataclass(slots=True)
class SummaryResult:
    text: str
    call: LlmCall | None = None
    error: str | None = None


def build_explain_prompt(finding: Finding, *, path_in_tree: str, location_count: int) -> str:
    lines = [
        f"Rule: {finding.rule_id}",
        f"Category: {finding.category}",
        f"Title: {finding.title}",
        f"Severity: {finding.severity}",
        f"Masked value: {finding.value_masked}",
        f"Entropy: {finding.entropy if finding.entropy is not None else 'unknown'}",
        f"Found in: {path_in_tree}",
        f"Occurrences in artifact: {location_count}",
    ]
    if finding.cwe:
        lines.append(f"CWE: {finding.cwe}")
    if finding.context_snippet:
        lines.append(f"Surrounding context (value masked): {finding.context_snippet[:600]}")
    if finding.remediation_md:
        # The rule pack's own advice. Given so the model builds on it rather
        # than contradicting the remediation the report already shows.
        lines.append(f"Rule pack remediation: {finding.remediation_md[:600]}")
    return "\n".join(lines)


def explain_finding(
    provider: LLMProvider,
    finding: Finding,
    *,
    path_in_tree: str,
    location_count: int = 1,
    run_id: str | None = None,
    max_tokens: int = 4000,
) -> tuple[str | None, LlmCall]:
    """Explain one finding. Never raises — advisory work cannot fail a run.

    ``max_tokens`` is generous because this role is routed to a reasoning model
    by default, and a reasoning model spends its budget thinking before it
    answers. Sizing this like triage's 300 is what produces an empty response
    and the "exhausted its token budget" error.
    """
    messages = [
        Message("system", EXPLAIN_SYSTEM_PROMPT),
        Message(
            "user",
            build_explain_prompt(finding, path_in_tree=path_in_tree, location_count=location_count),
        ),
    ]

    call = LlmCall(
        run_id=run_id,
        finding_id=finding.id,
        provider=provider.name,
        model=provider.model,
        role="explain",
        is_local=provider.is_local,
        redaction_level="strict",
        prompt_hash=LLMProvider.prompt_hash(messages),
        prompt_rendered="\n\n".join(f"[{m.role}]\n{m.content}" for m in messages),
    )

    try:
        # No json_mode: this role returns prose, and forcing structured output
        # makes a model wrap a paragraph in a JSON string for no benefit.
        completion = provider.complete(messages, max_tokens=max_tokens)
    except Exception as exc:
        log.warning("explain.call_failed", finding_id=finding.id, error=str(exc))
        call.error = str(exc)[:1000]
        return None, call

    call.response_text = completion.text[:8000]
    call.prompt_tokens = completion.prompt_tokens
    call.completion_tokens = completion.completion_tokens
    call.duration_s = completion.duration_s

    text = _prose(completion)
    if text is None:
        call.error = _budget_error(completion)
    return text, call


def apply_explanation(finding: Finding, text: str, model: str) -> None:
    """Write the explanation. Touches no deterministic field, by construction."""
    finding.llm_explanation = text
    finding.llm_explained_by = model
    finding.llm_explained_at = datetime.now(UTC)


def build_summary_prompt(
    run: Run, findings: list[Finding], *, artifact_name: str, artifact_count: int
) -> str:
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    tally = (
        ", ".join(f"{counts[s.value]} {s.value}" for s in Severity if counts.get(s.value)) or "none"
    )

    lines = [
        f"Artifact: {artifact_name}",
        f"Files analysed: {artifact_count}",
        f"Total findings: {len(findings)}",
        f"By severity: {tally}",
        "",
        "Findings, most severe first (values masked):",
    ]

    # Capped, because a 45-finding run is normal and a 500-finding run exists.
    # The tally above still reports the true totals, so the model is never
    # given a truncated list without also being told the real count.
    ordered = sorted(findings, key=lambda f: (Severity(f.severity).rank, f.rule_id, f.id))
    for finding in ordered[:40]:
        lines.append(
            f"- [{finding.severity}] {finding.title} ({finding.rule_id}) "
            f"= {finding.value_masked}"
        )
    if len(ordered) > 40:
        lines.append(f"- ... and {len(ordered) - 40} more, already counted above")

    return "\n".join(lines)


def summarize_run(
    provider: LLMProvider,
    run: Run,
    findings: list[Finding],
    *,
    artifact_name: str,
    artifact_count: int,
    max_tokens: int = 4000,
) -> SummaryResult:
    """One call per run. Never raises."""
    messages = [
        Message("system", SUMMARIZE_SYSTEM_PROMPT),
        Message(
            "user",
            build_summary_prompt(
                run, findings, artifact_name=artifact_name, artifact_count=artifact_count
            ),
        ),
    ]

    call = LlmCall(
        run_id=run.id,
        provider=provider.name,
        model=provider.model,
        role="summarize",
        is_local=provider.is_local,
        redaction_level="strict",
        prompt_hash=LLMProvider.prompt_hash(messages),
        prompt_rendered="\n\n".join(f"[{m.role}]\n{m.content}" for m in messages),
    )

    try:
        completion = provider.complete(messages, max_tokens=max_tokens)
    except Exception as exc:
        log.warning("summarize.call_failed", run_id=run.id, error=str(exc))
        call.error = str(exc)[:1000]
        return SummaryResult(text="", call=call, error=str(exc))

    call.response_text = completion.text[:8000]
    call.prompt_tokens = completion.prompt_tokens
    call.completion_tokens = completion.completion_tokens
    call.duration_s = completion.duration_s

    text = _prose(completion)
    if text is None:
        error = _budget_error(completion)
        call.error = error
        return SummaryResult(text="", call=call, error=error)

    run.llm_summary = text
    run.llm_summary_model = provider.model
    run.llm_summary_at = datetime.now(UTC)
    return SummaryResult(text=text, call=call)


def _prose(completion: Completion) -> str | None:
    """The answer, or None when the model produced nothing usable."""
    text = completion.text.strip()
    return text or None


def _budget_error(completion: Completion) -> str:
    """Tell the operator which failure this is.

    An empty answer from a reasoning model that filled its budget thinking is
    a configuration problem with a specific fix, and reporting it as a generic
    empty response sends people looking at the wrong thing.
    """
    if completion.raw.get("thinking"):
        return (
            "the model exhausted its token budget on reasoning without producing "
            "an answer; raise max_tokens for this role or route it to a "
            "non-reasoning model"
        )
    return "the model returned an empty response"
