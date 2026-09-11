"""LLM triage.

What this does: takes deterministic findings and classifies each as
true_positive, false_positive, or needs_review, with reasoning.

What it emphatically does not do: create findings. §2.5 is binding — a model
may suppress or demote, never invent. Enforced structurally rather than by
prompt: this module receives existing ``Finding`` rows and writes only to
``status``, ``llm_verdict``, ``llm_reasoning``, ``llm_model``, and ``llm_at``.
It has no code path that constructs a Finding, and the severity floor below
prevents demoting a critical out of sight.

Why it matters: deterministic rules are deliberately over-inclusive, because
missing a live key is far worse than surfacing a dud. That trade is only
tolerable if something collapses the false positives afterwards. This is that
something.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime

import structlog

from core.llm.provider import Completion, LLMProvider, Message
from core.models import Finding, LlmCall
from core.models.enums import FindingStatus, LlmVerdict
from core.vocab import Severity

log = structlog.get_logger(__name__)

SYSTEM_PROMPT = """\
You are a security analyst triaging candidate secrets found in a compiled \
artifact that a company is about to ship. A deterministic scanner already \
matched these; your job is to judge whether each is a real exposure.

Judge on evidence, not vibes:
- Documentation examples, RFC sample values, and obvious placeholders are \
false positives.
- Test fixtures and sample data may still be real exposures if the value looks \
live.
- High entropy plus a credential-shaped variable name is usually a true \
positive.
- Low entropy, dictionary words, and version strings usually are not.
- If you genuinely cannot tell from the evidence, say needs_review. That is a \
useful answer, not a failure.

You will be shown MASKED values. You are judging the shape, the context, and \
the location - never the secret itself.

Describe exposure and remediation only. Never produce exploit code, credential \
recovery techniques, or instructions for using a discovered secret.

Reply with JSON only, no prose outside it:
{"verdict": "true_positive" | "false_positive" | "needs_review", \
"reasoning": "<one or two sentences citing the specific evidence>"}"""

# Findings at or above this severity are never auto-suppressed on a model's
# say-so. A model calling a shipped private key a false positive is a model
# being wrong in the most expensive possible direction; it gets demoted to
# needs_review so a human still sees it.
SEVERITY_FLOOR = Severity.HIGH


@dataclass(slots=True)
class TriageResult:
    triaged: int = 0
    confirmed: int = 0
    dismissed: int = 0
    needs_review: int = 0
    errors: int = 0
    calls: list[LlmCall] = field(default_factory=list)
    total_duration_s: float = 0.0

    @property
    def summary(self) -> str:
        return (
            f"{self.triaged} triaged: {self.confirmed} confirmed, "
            f"{self.dismissed} dismissed, {self.needs_review} need review, "
            f"{self.errors} errors"
        )


def build_prompt(finding: Finding, *, path_in_tree: str, location_count: int) -> str:
    """Render one candidate.

    Only masked values, shape, entropy, and location. The plaintext is never
    included, for any provider — the local-plaintext opt-in applies to deep
    investigation, not to bulk triage where the volume makes review impractical.
    """
    lines = [
        f"Rule: {finding.rule_id}",
        f"Category: {finding.category}",
        f"Rule severity: {finding.severity}",
        f"Masked value: {finding.value_masked}",
        f"Value length: {len(finding.value_masked)} (masked)",
        f"Entropy: {finding.entropy if finding.entropy is not None else 'unknown'}",
        f"Found in: {path_in_tree}",
        f"Occurrences in artifact: {location_count}",
    ]
    if finding.context_snippet:
        lines.append(f"Surrounding context (value masked): {finding.context_snippet[:400]}")
    return "\n".join(lines)


def triage_finding(
    provider: LLMProvider,
    finding: Finding,
    *,
    path_in_tree: str,
    location_count: int = 1,
    run_id: str | None = None,
    max_tokens: int = 300,
) -> tuple[LlmVerdict, str, LlmCall]:
    """Classify one finding. Never raises — a triage failure must not fail a run."""
    messages = [
        Message("system", SYSTEM_PROMPT),
        Message(
            "user", build_prompt(finding, path_in_tree=path_in_tree, location_count=location_count)
        ),
    ]
    prompt_hash = LLMProvider.prompt_hash(messages)

    call = LlmCall(
        run_id=run_id,
        finding_id=finding.id,
        provider=provider.name,
        model=provider.model,
        role="triage",
        is_local=provider.is_local,
        redaction_level="strict",
        prompt_hash=prompt_hash,
        prompt_rendered="\n\n".join(f"[{m.role}]\n{m.content}" for m in messages),
    )

    try:
        completion = provider.complete(
            messages,
            json_mode=provider.capabilities().structured_output,
            max_tokens=max_tokens,
        )
    except Exception as exc:
        log.warning("triage.call_failed", finding_id=finding.id, error=str(exc))
        call.error = str(exc)[:1000]
        return LlmVerdict.ERROR, f"triage unavailable: {exc}", call

    call.response_text = completion.text[:4000]
    call.prompt_tokens = completion.prompt_tokens
    call.completion_tokens = completion.completion_tokens
    call.duration_s = completion.duration_s

    verdict, reasoning = _parse(completion)
    if verdict is LlmVerdict.ERROR:
        call.error = "unparseable response"
    return verdict, reasoning, call


def _parse(completion: Completion) -> tuple[LlmVerdict, str]:
    payload = completion.as_json()
    if not payload:
        if completion.raw.get("thinking"):
            # Either an empty answer or one truncated inside the JSON — both
            # are the reasoner spending a budget sized for a non-reasoning
            # model. Say which knob to turn rather than blaming the parser.
            return (
                LlmVerdict.ERROR,
                "the model exhausted its token budget on reasoning without "
                "producing a complete answer; use a non-reasoning model for triage",
            )
        return LlmVerdict.ERROR, "model did not return parseable JSON"

    raw_verdict = str(payload.get("verdict", "")).strip().lower()
    reasoning = str(payload.get("reasoning", "")).strip()[:2000]
    try:
        return LlmVerdict(raw_verdict), reasoning or "no reasoning given"
    except ValueError:
        return LlmVerdict.ERROR, f"unrecognised verdict {raw_verdict!r}"


def apply_verdict(finding: Finding, verdict: LlmVerdict, reasoning: str, model: str) -> None:
    """Write the model's judgement onto the finding, within the §2.5 rules.

    The severity floor is the important part. A model is allowed to be wrong;
    it is not allowed to be wrong in a way that hides a shipped private key.
    """
    finding.llm_verdict = str(verdict)
    finding.llm_reasoning = reasoning
    finding.llm_model = model
    finding.llm_at = datetime.now(UTC)

    if verdict is LlmVerdict.ERROR:
        return  # status untouched; the deterministic result stands

    # detected_by becomes 'both' — the rule found it, the model assessed it.
    # It never becomes 'llm', and a database constraint enforces that.
    finding.detected_by = "both"

    severity = Severity(finding.severity)

    if verdict is LlmVerdict.FALSE_POSITIVE:
        if severity.rank <= SEVERITY_FLOOR.rank:
            finding.status = FindingStatus.NEEDS_REVIEW
            log.info(
                "triage.floor_applied",
                finding_id=finding.id,
                severity=finding.severity,
                note="model said false positive; demoted to needs_review, not dismissed",
            )
        else:
            finding.status = FindingStatus.FALSE_POSITIVE
    elif verdict is LlmVerdict.TRUE_POSITIVE:
        finding.status = FindingStatus.CONFIRMED
    else:
        finding.status = FindingStatus.NEEDS_REVIEW


def triage_run(
    provider: LLMProvider,
    findings: list[Finding],
    paths: dict[str, str],
    *,
    run_id: str,
    location_counts: dict[str, int] | None = None,
) -> TriageResult:
    """Triage every finding in a run.

    Findings are processed in a deterministic order and results are cached by
    prompt hash within the pass, so an artifact containing the same candidate
    twice costs one call.
    """
    result = TriageResult()
    counts = location_counts or {}
    cache: dict[str, tuple[LlmVerdict, str]] = {}

    for finding in sorted(findings, key=lambda f: (Severity(f.severity).rank, f.id)):
        path = paths.get(finding.id, "")
        cache_key = hashlib.sha256(
            f"{finding.rule_id}\x1f{finding.value_hash}".encode()
        ).hexdigest()

        if cache_key in cache:
            verdict, reasoning = cache[cache_key]
            call = None
        else:
            verdict, reasoning, call = triage_finding(
                provider,
                finding,
                path_in_tree=path,
                location_count=counts.get(finding.id, 1),
                run_id=run_id,
            )
            cache[cache_key] = (verdict, reasoning)
            result.calls.append(call)
            result.total_duration_s += call.duration_s or 0.0

        apply_verdict(finding, verdict, reasoning, provider.model)
        result.triaged += 1

        if verdict is LlmVerdict.TRUE_POSITIVE:
            result.confirmed += 1
        elif verdict is LlmVerdict.FALSE_POSITIVE:
            result.dismissed += 1
        elif verdict is LlmVerdict.NEEDS_REVIEW:
            result.needs_review += 1
        else:
            result.errors += 1

    log.info("triage.completed", run_id=run_id, summary=result.summary)
    return result
