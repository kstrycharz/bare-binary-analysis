"""Agentic investigation: the model drives, the orchestrator holds the tools.

The `explain` role writes prose from what the scanner already knows.
Investigation is different — it lets the model *go and look*: notice that a
value is base64, decode it, see a connection string inside, search the run for
the host it names, and report what it found with every step on the record.

**It still cannot create a finding.** §2.5 is binding and is enforced
structurally, not by prompt: this module writes to `Investigation` rows and
nothing else. There is no code path from here to a `Finding`, so the worst a
confused model can do is write a wrong paragraph attached to a finding that a
deterministic rule already produced.

**Bounded on purpose.** A step cap, a per-result size cap, and a read-only
tool surface. An investigation that cannot terminate is an investigation that
bills forever, and one that can write is a scanner that fails open.

**The loop is a prompted ReAct rather than native tool calling.** Local models
— the ones an air-gapped deployment can actually run — use native tool calling
unreliably, while they follow a strict JSON protocol well. The same code path
then works for every provider, which also means the transcript looks identical
whichever model produced it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime

import structlog

from core.llm.provider import LLMProvider, Message
from core.llm.tools import ToolBox, ToolCall, tool_manifest
from core.models import Finding, LlmCall

log = structlog.get_logger(__name__)

MAX_STEPS = 12
MAX_TOKENS = 4000

# How many prior exchanges to carry. The system prompt and the opening brief
# are always resent; only the middle of the conversation is dropped.
#
# This exists because the first real run failed on it. A local 14b with
# num_ctx 8192 read the same 16 bytes twelve times: each turn appended a hex
# dump, by turn three the system prompt had scrolled out of the window, and
# the model could no longer see either the protocol or the offsets it had been
# given. It was not being stupid — it could not see the instructions.
MAX_CONTEXT_TURNS = 4

SYSTEM_PROMPT = """\
You are a reverse engineer investigating one finding in a binary a company is \
about to ship. A deterministic scanner found it. Your job is to work out what \
it actually is and what it means, by looking at the artifact rather than by \
guessing.

You have tools. Use them. A typical investigation: look at the bytes around \
the value, notice the value is encoded, decode it, then search the run for \
related strings. Follow what you find.

TOOLS AVAILABLE:
%s

PROTOCOL. Reply with exactly one JSON object per turn, and nothing else:

To use a tool:
{"thought": "<why this step>", "tool": "<name>", "arguments": {...}}

To finish:
{"thought": "<why you are done>", "conclusion": "<what this is, what it means, \
and what to do about it>", "confidence": "high" | "medium" | "low"}

Every argument must be a literal value. Write "offset": 4096, never
"offset": <the offset> — a placeholder is not valid JSON and the turn is wasted.
The offsets you may use are given below; if you need one you were not given,
find it with search_strings or read a window you can name.

RULES:
- Ground every claim in a tool result. If the tools did not show it, do not \
assert it. Saying "the evidence does not settle this" is a good answer.
- Values may be MASKED (shown with bullet characters). That is deliberate. \
Reason about shape, length, entropy, and position; never ask for the real value.
- Do not pass a masked value to `decode` or `entropy`. The bullets are not the \
data, so the answer means nothing. Decode only text you read out of the bytes.
- You cannot change the finding, its severity, or its location, and you cannot \
create a new one. You are writing an assessment.
- Describe exposure and remediation only. Never write exploit code, credential \
recovery steps, or instructions for using what you find.
- Stop as soon as you can answer. %d steps is the hard limit.
"""


@dataclass(slots=True)
class Investigation:
    finding_id: str
    run_id: str
    conclusion: str = ""
    confidence: str = "low"
    steps: list[ToolCall] = field(default_factory=list)
    calls: list[LlmCall] = field(default_factory=list)
    error: str | None = None
    duration_s: float = 0.0

    @property
    def transcript(self) -> list[dict[str, object]]:
        """The audit trail, as stored. Every claim traces to a step here."""
        return [
            {
                "tool": step.tool,
                "arguments": step.arguments,
                "ok": step.ok,
                "output": step.output,
                "detail": step.detail,
            }
            for step in self.steps
        ]


def _window(history: list[Message]) -> list[Message]:
    """The recent tail of the conversation, plus a note when there is more.

    Dropping the middle rather than the end: the model needs the protocol (in
    the system prompt, always resent) and what it just learned. What it did six
    steps ago is already reflected in what it knows now, and the transcript
    keeps the full record for the reader regardless.
    """
    keep = MAX_CONTEXT_TURNS * 2
    if len(history) <= keep:
        return history
    dropped = (len(history) - keep) // 2
    note = Message(
        "user",
        f"[{dropped} earlier step(s) omitted to stay within the context window. "
        "Do not repeat them; build on what you have learned.]",
    )
    return [note, *history[-keep:]]


def _opening_prompt(finding: Finding, path_in_tree: str, location_count: int) -> str:
    lines = [
        "Investigate this finding.",
        "",
        f"Rule: {finding.rule_id}",
        f"Title: {finding.title}",
        f"Category: {finding.category}",
        f"Severity: {finding.severity}",
        f"Masked value: {finding.value_masked}",
        f"Entropy: {finding.entropy if finding.entropy is not None else 'unknown'}",
        f"File: {path_in_tree}",
        f"Occurrences: {location_count}",
    ]
    if finding.locations:
        offsets = [f"0x{loc.offset:x}" for loc in finding.locations[:5] if loc.offset is not None]
        if offsets:
            lines.append(f"Byte offsets: {', '.join(offsets)}")
    if finding.context_snippet:
        lines.append(f"Surrounding context (value masked): {finding.context_snippet[:600]}")
    lines.append("")
    lines.append("Begin. Reply with one JSON object.")
    return "\n".join(lines)


def investigate_finding(
    provider: LLMProvider,
    toolbox: ToolBox,
    finding: Finding,
    *,
    path_in_tree: str,
    location_count: int = 1,
    max_steps: int = MAX_STEPS,
) -> Investigation:
    """Run the loop. Never raises — an investigation is advisory."""
    result = Investigation(finding_id=finding.id, run_id=finding.run_id)

    system = Message("system", SYSTEM_PROMPT % (tool_manifest(), max_steps))
    opening = Message("user", _opening_prompt(finding, path_in_tree, location_count))
    history: list[Message] = []
    # Signature -> what happened. A model that repeats itself is a model that
    # has lost the thread, and re-running the call would only confirm it.
    seen: dict[str, str] = {}

    for step in range(max_steps):
        messages = [system, opening, *_window(history)]
        call = LlmCall(
            run_id=finding.run_id,
            finding_id=finding.id,
            provider=provider.name,
            model=provider.model,
            role="investigate",
            is_local=provider.is_local,
            redaction_level="none" if toolbox._allow_plaintext else "strict",
            prompt_hash=LLMProvider.prompt_hash(messages),
            prompt_rendered=f"[step {step + 1}] {messages[-1].content}"[:8000],
        )

        try:
            # JSON mode where the provider has it. Without it a small model
            # writes a well-formed *looking* object containing a placeholder
            # like "offset": <the offset>, which parses as nothing and burns
            # the turn. Observed, not hypothetical.
            completion = provider.complete(
                messages,
                json_mode=provider.capabilities().structured_output,
                max_tokens=MAX_TOKENS,
            )
        except Exception as exc:
            log.warning("investigate.call_failed", finding_id=finding.id, error=str(exc))
            call.error = str(exc)[:1000]
            result.calls.append(call)
            result.error = f"the model became unreachable after {step} step(s): {exc}"
            return result

        call.response_text = completion.text[:8000]
        call.prompt_tokens = completion.prompt_tokens
        call.completion_tokens = completion.completion_tokens
        call.duration_s = completion.duration_s
        result.calls.append(call)
        result.duration_s += completion.duration_s or 0.0

        payload = completion.as_json()
        if not payload:
            if completion.raw.get("thinking"):
                # Thinking present and nothing parseable — an empty answer or
                # one truncated mid-JSON. Both are the budget, not the parser.
                result.error = (
                    "the model exhausted its token budget on reasoning without "
                    "producing a complete answer; raise max_tokens for the "
                    "investigate role or route it to a non-reasoning model"
                )
                return result
            # Record the malformed turn. Without this a run that never parses
            # ends with an empty transcript and nothing to diagnose from —
            # which is exactly how the placeholder-argument bug above stayed
            # invisible through twelve steps and ninety seconds.
            result.steps.append(
                ToolCall(
                    tool="(unparseable model response)",
                    arguments={},
                    ok=False,
                    output=completion.text[:1000],
                    detail="not a single JSON object",
                )
            )
            history.append(Message("assistant", completion.text[:1000]))
            history.append(
                Message(
                    "user",
                    "That was not a single JSON object. Reply with exactly one, "
                    "either a tool call or a conclusion. Every argument must be a "
                    "literal value — never a placeholder like <offset>.",
                )
            )
            continue

        if "conclusion" in payload:
            result.conclusion = str(payload.get("conclusion", "")).strip()
            confidence = str(payload.get("confidence", "low")).strip().lower()
            result.confidence = confidence if confidence in ("high", "medium", "low") else "low"
            return result

        tool = str(payload.get("tool", "")).strip()
        arguments = payload.get("arguments")
        if not isinstance(arguments, dict):
            arguments = {}

        signature = f"{tool}:{json.dumps(arguments, sort_keys=True)}"
        if signature in seen:
            # Do not spend a real call confirming it. Say so and push it on —
            # this is what turns a twelve-step stall into a recoverable turn.
            feedback = (
                f"You already ran that exact call. It returned: {seen[signature]}\n\n"
                "Do something different, or conclude with what you have."
            )
            history.append(Message("assistant", json.dumps(payload)))
            history.append(Message("user", feedback))
            result.steps.append(
                ToolCall(
                    tool=tool,
                    arguments=arguments,
                    ok=False,
                    output="",
                    detail="repeat of an earlier call; not re-executed",
                )
            )
            continue

        outcome = toolbox.run(tool, arguments)
        seen[signature] = (outcome.output or outcome.detail)[:200]
        result.steps.append(
            ToolCall(
                tool=tool,
                arguments=arguments,
                ok=outcome.ok,
                output=outcome.output,
                detail=outcome.detail,
            )
        )

        history.append(Message("assistant", json.dumps(payload)))
        history.append(Message("user", _render_result(outcome.ok, outcome.output, outcome.detail)))

    # Out of steps without a conclusion. Reported as what it is rather than
    # dressed up as a result — the transcript is still worth keeping.
    result.error = (
        f"the investigation did not reach a conclusion within {max_steps} steps; "
        "the steps it did take are recorded below"
    )
    return result


def _render_result(ok: bool, output: str, detail: str) -> str:
    header = "TOOL RESULT" if ok else "TOOL ERROR"
    body = output if ok else detail
    suffix = f"\n({detail})" if ok and detail else ""
    return f"{header}:\n{body}{suffix}\n\nNext JSON object."


def apply_investigation(finding: Finding, result: Investigation, model: str) -> None:
    """Attach the outcome. Touches no deterministic field, by construction."""
    finding.llm_investigation = result.conclusion
    finding.llm_investigation_steps = result.transcript
    finding.llm_investigated_by = model
    finding.llm_investigated_at = datetime.now(UTC)
    finding.llm_investigation_confidence = result.confidence
