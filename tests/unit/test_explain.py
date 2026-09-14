"""The `explain` and `summarize` roles.

These two were routable in `config/llm.yaml`, described on the settings page,
and never invoked by anything — so the tests that matter most are the ones
asserting they now stay inside the same boundary triage does: masked values
only, no deterministic field touched, and a model failure that reports rather
than raises.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from core.llm.explain import (
    apply_explanation,
    build_explain_prompt,
    build_summary_prompt,
    explain_finding,
    summarize_run,
)
from core.llm.provider import Capabilities, Completion, LLMProvider, Message
from core.models import Finding, Run
from core.models.enums import FindingStatus, RunStatus
from core.vocab import Severity

SECRET = "AKIA2QZ7XKPLMNRTUVWX"


class FakeProvider(LLMProvider):
    """Records what it was asked, returns what the test wants."""

    def __init__(self, text: str = "An explanation.", raw: dict | None = None) -> None:
        self.name = "fake"
        self.model = "fake-model:1b"
        self._text = text
        self._raw = raw or {}
        self.seen: list[Message] = []
        self.max_tokens_seen: int | None = None

    @property
    def is_local(self) -> bool:
        return True

    def complete(  # type: ignore[override]
        self,
        messages: list[Message],
        *,
        json_mode: bool = False,
        max_tokens: int = 512,
        temperature: float = 0.0,
        timeout_s: int = 60,
    ) -> Completion:
        self.seen = list(messages)
        self.max_tokens_seen = max_tokens
        return Completion(text=self._text, model=self.model, duration_s=0.1, raw=self._raw)

    def capabilities(self) -> Capabilities:
        return Capabilities(structured_output=True)

    def health(self):  # type: ignore[no-untyped-def]
        raise NotImplementedError


class RaisingProvider(FakeProvider):
    def complete(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        raise RuntimeError("connection refused")


@pytest.fixture
def finding() -> Finding:
    return Finding(
        id="f1",
        run_id="r1",
        rule_id="aws-access-key-id",
        category="cloud-credentials",
        title="AWS access key ID",
        severity=Severity.CRITICAL.value,
        confidence=0.99,
        value_masked="AKIA••••••••••••UVWX",
        value_hash="a" * 64,
        entropy=3.9,
        status=FindingStatus.OPEN,
        detected_by="rule",
        context_snippet="aws_key = AKIA••••••••••••UVWX",
    )


@pytest.fixture
def run() -> Run:
    return Run(
        id="r1",
        status=RunStatus.COMPLETED,
        profile="standard",
        attested_by="kyle",
        attestation_reference="SEC-1",
        attested_at=datetime.now(UTC),
    )


class TestTheSecretNeverLeaves:
    """The single most important property of both roles."""

    def test_explain_prompt_carries_no_plaintext(self, finding: Finding) -> None:
        prompt = build_explain_prompt(finding, path_in_tree="app.exe", location_count=2)
        assert SECRET not in prompt
        assert finding.value_masked in prompt

    def test_explain_call_sends_no_plaintext(self, finding: Finding) -> None:
        """Asserted on what reached the provider, not on the builder — a future
        caller could assemble messages some other way."""
        provider = FakeProvider()
        explain_finding(provider, finding, path_in_tree="app.exe")
        assert SECRET not in "\n".join(m.content for m in provider.seen)

    def test_a_retained_plaintext_run_still_sends_masked(self, finding: Finding) -> None:
        """Retention exists so a human can rotate the credential, not so a
        model can read it. `explain` takes a Finding, which has no plaintext
        column at all — this pins that."""
        assert not hasattr(finding, "value_plaintext")

    def test_summary_prompt_carries_no_plaintext(self, run: Run, finding: Finding) -> None:
        prompt = build_summary_prompt(run, [finding], artifact_name="app.exe", artifact_count=10)
        assert SECRET not in prompt


class TestExplainTouchesNothingDeterministic:
    def test_apply_writes_only_the_advisory_fields(self, finding: Finding) -> None:
        before = (
            finding.severity,
            finding.status,
            finding.value_hash,
            finding.confidence,
            finding.detected_by,
            finding.llm_verdict,
            finding.llm_reasoning,
        )

        apply_explanation(finding, "Because it is a live key.", "fake-model:1b")

        after = (
            finding.severity,
            finding.status,
            finding.value_hash,
            finding.confidence,
            finding.detected_by,
            finding.llm_verdict,
            finding.llm_reasoning,
        )
        assert before == after
        assert finding.llm_explanation == "Because it is a live key."
        assert finding.llm_explained_by == "fake-model:1b"
        assert finding.llm_explained_at is not None

    def test_explaining_does_not_overwrite_a_triage_verdict(self, finding: Finding) -> None:
        """`llm_reasoning` is the audit trail for a status change. Reusing one
        column for both roles would mean asking for an explanation destroyed
        the record of why a finding was dismissed."""
        finding.llm_verdict = "false_positive"
        finding.llm_reasoning = "documentation example"

        apply_explanation(finding, "New prose.", "fake-model:1b")

        assert finding.llm_verdict == "false_positive"
        assert finding.llm_reasoning == "documentation example"


class TestFailuresReportRatherThanRaise:
    def test_an_unreachable_model_returns_none_with_the_error_on_the_call(
        self, finding: Finding
    ) -> None:
        text, call = explain_finding(RaisingProvider(), finding, path_in_tree="app.exe")
        assert text is None
        assert call.error is not None and "connection refused" in call.error

    def test_an_empty_answer_is_not_written_as_an_explanation(self, finding: Finding) -> None:
        text, call = explain_finding(FakeProvider(text="   "), finding, path_in_tree="a")
        assert text is None
        assert finding.llm_explanation is None

    def test_a_reasoning_model_that_ran_out_of_budget_says_so(self, finding: Finding) -> None:
        """The failure the operator actually hits. 'empty response' sends them
        looking at the model; naming the budget sends them to the fix."""
        provider = FakeProvider(text="", raw={"thinking": "let me consider..."})
        _, call = explain_finding(provider, finding, path_in_tree="app.exe")
        assert call.error is not None
        assert "token budget" in call.error

    def test_summarize_reports_an_unreachable_model(self, run: Run, finding: Finding) -> None:
        result = summarize_run(
            RaisingProvider(), run, [finding], artifact_name="a.exe", artifact_count=1
        )
        assert result.error is not None
        assert run.llm_summary is None


class TestBudgets:
    def test_explain_asks_for_far_more_than_triage(self, finding: Finding) -> None:
        """Triage caps at 300, which is right for a one-line JSON verdict from
        a fast model. This role runs on a reasoning model by default and needs
        room to think before it answers."""
        provider = FakeProvider()
        explain_finding(provider, finding, path_in_tree="app.exe")
        assert provider.max_tokens_seen is not None
        assert provider.max_tokens_seen >= 2000


class TestSummaryPrompt:
    def test_states_the_true_total_even_when_the_list_is_capped(self, run: Run) -> None:
        """A capped list plus an uncapped count is fine; a capped list that
        looks complete would have the model report a wrong total."""
        many = [
            Finding(
                id=f"f{i}",
                run_id="r1",
                rule_id="r",
                category="c",
                title=f"Finding {i}",
                severity=Severity.LOW.value,
                confidence=0.5,
                value_masked="x",
                value_hash="b" * 64,
                status=FindingStatus.OPEN,
            )
            for i in range(60)
        ]
        prompt = build_summary_prompt(run, many, artifact_name="a.exe", artifact_count=99)
        assert "Total findings: 60" in prompt
        assert "20 more" in prompt

    def test_orders_by_severity_so_the_lead_is_the_worst_finding(
        self, run: Run, finding: Finding
    ) -> None:
        low = Finding(
            id="f2",
            run_id="r1",
            rule_id="repo-url",
            category="disclosure",
            title="Repository URL",
            severity=Severity.LOW.value,
            confidence=0.5,
            value_masked="http••••",
            value_hash="c" * 64,
            status=FindingStatus.OPEN,
        )
        prompt = build_summary_prompt(run, [low, finding], artifact_name="a.exe", artifact_count=1)
        assert prompt.index("AWS access key ID") < prompt.index("Repository URL")

    def test_a_successful_summary_is_written_to_the_run(self, run: Run, finding: Finding) -> None:
        result = summarize_run(
            FakeProvider(text="One critical AWS key."),
            run,
            [finding],
            artifact_name="a.exe",
            artifact_count=1,
        )
        assert result.error is None
        assert run.llm_summary == "One critical AWS key."
        assert run.llm_summary_model == "fake-model:1b"
        assert run.llm_summary_at is not None
