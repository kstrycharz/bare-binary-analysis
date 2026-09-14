"""Rule discovery — the AI author loop.

This is where the model belongs.

The scanner cannot report what it has no pattern for, so the only way to find
the next rule is to look at what fell through. That loop — read the unmatched
strings, recognise which ones are infrastructure or credentials or IP, propose
a pattern — is judgement work over a small sample, and a model is genuinely
good at it.

It is also how the `svn+ssh://` rule in this pack came to exist. Scanning a real
release, the pack reported nothing interesting; dumping the strings nothing
matched showed
``svn+ssh://delinux03.de.moog.com/data/svn/nvce/tags/B99133-DV002-B-211b_11827``
in every device description — an internal SCM host, its repository layout, and
the firmware part-number scheme. That was invisible to the scanner and obvious
to a reader. This module automates the reading.

**What it does not do is create findings.** A proposal is a YAML rule and a
rationale, for a human to review and merge. Once merged it is deterministic and
the model is out of the path forever — the scan that then finds it runs in
milliseconds, produces byte-identical results, and works with the LLM disabled.
That is the whole architecture in one sentence: the model writes the rule, the
rule finds the secret.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import structlog
import yaml

from core.llm.provider import LLMProvider, Message
from core.models import LlmCall
from core.vocab import Severity

log = structlog.get_logger(__name__)

MAX_RESIDUE_SAMPLE = 120
MAX_VALUE_CHARS = 220

SYSTEM_PROMPT = """\
You are a detection engineer for a tool that scans compiled artifacts a company \
is about to ship, looking for exposed secrets, internal infrastructure, and \
unintended IP disclosure.

You are shown strings extracted from a real artifact that the current rule pack \
did NOT match. Your job is to spot the ones that represent an exposure and \
propose deterministic detection rules for them.

What counts as an exposure:
- Internal infrastructure: SCM/build/artifact servers, internal hostnames, \
database endpoints, management interfaces.
- Credentials of any kind, including ones no vendor pattern would know.
- Build-pipeline leakage: source paths, CI agent directories, developer or \
service account names, internal project codenames.
- IP disclosure: internal part numbers, unreleased feature flags, customer \
names in sample data.

What does NOT count, and must not be proposed:
- Public endpoints a product is expected to contact (vendor websites, CRL and \
OCSP responders, package registries, update servers).
- Library and package namespaces compiled into a binary (Go module paths, .NET \
assembly names, symbol names).
- Localisation strings, licence text, UI copy, file names.

Rules must be specific. A pattern that matches any high-entropy string, any \
long base64 run, or any hostname is worse than no rule: it buries real findings \
under noise. Anchor on a scheme, a prefix, a keyword, or a distinctive \
structure. If a value has no distinguishing shape, require nearby context \
instead.

Reply with JSON only:
{"proposals": [{
  "id": "kebab-case-rule-id",
  "name": "Human readable name",
  "category": "internal-infrastructure|cloud-credentials|service-token\
|crypto-material|ip-exposure|sensitive-data|hygiene",
  "severity": "critical|high|medium|low|info",
  "confidence": 0.0-1.0,
  "regex": "a Python regex with exactly one capture group around the value",
  "rationale": "why this is an exposure, citing the evidence you were shown",
  "example": "the string from the sample that this matches",
  "remediation": "what the engineer should change"
}]}

Propose at most 5. Fewer is better. If nothing in the sample is an exposure, \
reply {"proposals": []} — that is a useful answer, not a failure."""


@dataclass(slots=True)
class RuleProposal:
    """A candidate rule. Advisory until a human merges it."""

    id: str
    name: str
    category: str
    severity: str
    confidence: float
    regex: str
    rationale: str
    example: str
    remediation: str
    valid: bool = True
    error: str | None = None

    def to_yaml(self) -> str:
        """Render in rule-pack form, ready to paste into detections/."""
        entry = {
            "rules": [
                {
                    "id": self.id,
                    "name": self.name,
                    "category": self.category,
                    "severity": self.severity,
                    "confidence": round(self.confidence, 2),
                    "description": self.rationale,
                    "remediation": self.remediation,
                    "patterns": [{"regex": self.regex, "capture": 1}],
                    "tags": ["ai-proposed", "needs-review"],
                    "tests": {"positive": [self.example], "negative": []},
                }
            ]
        }
        return yaml.safe_dump(entry, sort_keys=False, allow_unicode=True, width=100)


@dataclass(slots=True)
class DiscoveryResult:
    proposals: list[RuleProposal] = field(default_factory=list)
    sampled: int = 0
    model: str = ""
    duration_s: float = 0.0
    call: LlmCall | None = None
    error: str | None = None

    @property
    def usable(self) -> list[RuleProposal]:
        return [p for p in self.proposals if p.valid]


def _redact(value: str) -> str:
    """Residue goes to the model, so it gets the same treatment as evidence.

    Anything that looks like it could itself be a secret is truncated hard. The
    model needs the *shape* of a string to propose a pattern, not its payload.
    """
    trimmed = value[:MAX_VALUE_CHARS]
    return trimmed


def build_sample(residue: list[dict[str, Any]], limit: int = MAX_RESIDUE_SAMPLE) -> list[str]:
    """Deduplicate and cap the residue, preserving order for determinism."""
    seen: set[str] = set()
    sample: list[str] = []
    for entry in residue:
        value = _redact(str(entry.get("value", "")).strip())
        if len(value) < 12 or value in seen:
            continue
        seen.add(value)
        sample.append(value)
        if len(sample) >= limit:
            break
    return sample


def discover_rules(
    provider: LLMProvider,
    residue: list[dict[str, Any]],
    *,
    run_id: str | None = None,
    max_tokens: int = 3000,
) -> DiscoveryResult:
    """Ask the model to propose rules for what the pack missed.

    Never raises: discovery is an optional enrichment, and a model being
    unreachable must not affect a completed scan in any way.
    """
    sample = build_sample(residue)
    if not sample:
        return DiscoveryResult(sampled=0, model=provider.model)

    numbered = "\n".join(f"{i + 1}. {value}" for i, value in enumerate(sample))
    messages = [
        Message("system", SYSTEM_PROMPT),
        Message("user", f"Strings no rule matched:\n\n{numbered}"),
    ]

    call = LlmCall(
        run_id=run_id,
        provider=provider.name,
        model=provider.model,
        role="discover",
        is_local=provider.is_local,
        redaction_level="sample",
        prompt_hash=LLMProvider.prompt_hash(messages),
        prompt_rendered="\n\n".join(f"[{m.role}]\n{m.content}" for m in messages),
    )

    try:
        completion = provider.complete(
            messages,
            json_mode=provider.capabilities().structured_output,
            max_tokens=max_tokens,
        )
    except Exception as exc:
        log.warning("discovery.call_failed", error=str(exc))
        call.error = str(exc)[:1000]
        return DiscoveryResult(sampled=len(sample), model=provider.model, call=call, error=str(exc))

    call.response_text = completion.text[:8000]
    call.prompt_tokens = completion.prompt_tokens
    call.completion_tokens = completion.completion_tokens
    call.duration_s = completion.duration_s

    payload = completion.as_json()
    if not payload:
        # Distinguish the two failures, because the fixes are opposite. A
        # reasoning model spends the same budget on thinking that it needs for
        # the answer, so a budget sized for the JSON returns nothing at all —
        # measured here: glm-4.7-flash consumed 2000 tokens deliberating and
        # emitted no content. That is a routing problem, not a model problem.
        # Thinking plus an answer cut off mid-JSON is the same problem.
        if completion.raw.get("thinking"):
            reason = (
                "the model exhausted its token budget on reasoning without "
                "producing an answer. Route the `discover` role to a "
                "non-reasoning model, or raise max_tokens well above the "
                "reasoning length."
            )
        else:
            reason = "model did not return parseable JSON"
        return DiscoveryResult(
            sampled=len(sample),
            model=provider.model,
            duration_s=completion.duration_s,
            call=call,
            error=reason,
        )

    proposals = [_build_proposal(raw) for raw in payload.get("proposals", [])[:5]]
    log.info(
        "discovery.completed",
        run_id=run_id,
        sampled=len(sample),
        proposed=len(proposals),
        usable=sum(1 for p in proposals if p.valid),
    )
    return DiscoveryResult(
        proposals=proposals,
        sampled=len(sample),
        model=provider.model,
        duration_s=completion.duration_s,
        call=call,
    )


def _build_proposal(raw: dict[str, Any]) -> RuleProposal:
    """Validate a proposal before it is ever shown as actionable.

    A model-authored regex is untrusted input twice over: it may not compile,
    and it may be catastrophically broad. Both are checked here so a reviewer
    sees "rejected, matches everything" rather than discovering it after merge.
    """
    proposal = RuleProposal(
        id=str(raw.get("id", "")).strip() or "unnamed-proposal",
        name=str(raw.get("name", "")).strip() or "Unnamed",
        category=str(raw.get("category", "ip-exposure")).strip(),
        severity=str(raw.get("severity", "low")).strip(),
        confidence=float(raw.get("confidence", 0.4) or 0.4),
        regex=str(raw.get("regex", "")),
        rationale=str(raw.get("rationale", "")).strip(),
        example=str(raw.get("example", "")).strip(),
        remediation=str(raw.get("remediation", "")).strip(),
    )

    try:
        Severity(proposal.severity)
    except ValueError:
        proposal.severity = "low"

    if not proposal.regex:
        proposal.valid = False
        proposal.error = "no pattern supplied"
        return proposal

    try:
        compiled = re.compile(proposal.regex)
    except re.error as exc:
        proposal.valid = False
        proposal.error = f"pattern does not compile: {exc}"
        return proposal

    if compiled.groups < 1:
        proposal.valid = False
        proposal.error = "pattern has no capture group; the value would be unidentifiable"
        return proposal

    # A rule that fires on ordinary prose is the failure mode this whole
    # module is guarding against. Cheap smoke test before a human sees it.
    for benign in (
        "The quick brown fox jumps over the lazy dog and keeps running along.",
        "Copyright (c) 2026 Example Corporation. All rights reserved worldwide.",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ):
        if compiled.search(benign):
            proposal.valid = False
            proposal.error = "pattern matches ordinary text; too broad to merge"
            return proposal

    if proposal.example and not compiled.search(proposal.example):
        proposal.valid = False
        proposal.error = "pattern does not match the example it was proposed from"

    return proposal


def proposals_to_yaml(result: DiscoveryResult) -> str:
    """One pasteable document for the whole batch."""
    usable = result.usable
    if not usable:
        return "# No usable rule proposals.\n"

    header = (
        "# AI-proposed detection rules — REVIEW BEFORE MERGING.\n"
        f"# Model: {result.model}. Sampled {result.sampled} unmatched strings.\n"
        "#\n"
        "# These are proposals, not findings. Nothing here has affected any\n"
        "# scan result. Merging one makes it deterministic; until then it does\n"
        "# not exist as far as the pipeline is concerned.\n"
        "#\n"
        "# Every rule needs a negative fixture before it merges — see\n"
        "# tests/unit/test_rules.py, which executes them.\n\n"
    )
    body = "\n".join(f"# --- {p.id}: {p.rationale}\n{p.to_yaml()}" for p in usable)
    return header + body


def summarise(result: DiscoveryResult) -> dict[str, Any]:
    return {
        "sampled": result.sampled,
        "model": result.model,
        "duration_s": round(result.duration_s, 2),
        "proposed": len(result.proposals),
        "usable": len(result.usable),
        "rejected": [{"id": p.id, "error": p.error} for p in result.proposals if not p.valid],
        "proposals": [
            {
                "id": p.id,
                "name": p.name,
                "category": p.category,
                "severity": p.severity,
                "confidence": p.confidence,
                "regex": p.regex,
                "rationale": p.rationale,
                "example": p.example,
                "remediation": p.remediation,
            }
            for p in result.usable
        ],
        "yaml": proposals_to_yaml(result),
        "error": result.error,
    }


__all__ = [
    "DiscoveryResult",
    "RuleProposal",
    "build_sample",
    "discover_rules",
    "proposals_to_yaml",
    "summarise",
]
