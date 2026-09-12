"""Agentic investigation: the tool surface and the loop.

The model gets to choose what to look at, so what is pinned here is everything
it is *not* allowed to do. In order of how much a failure would cost:

1. It cannot reach outside the run under investigation.
2. It cannot make a secret leave, when redaction is on.
3. It cannot create or alter a finding.
4. It cannot run forever.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.llm.investigate import apply_investigation, investigate_finding
from core.llm.provider import Capabilities, Completion, LLMProvider, Message
from core.llm.tools import ToolBox
from core.models import Artifact, Evidence, Finding, Run
from core.models.base import Base
from core.models.enums import ArtifactKind, FindingStatus, RunStatus
from core.vocab import Severity

SECRET = "AKIA2QZ7XKPLMNRTUVWXYZ01"


class ScriptedProvider(LLMProvider):
    """Replays a fixed list of model turns, so the loop is testable."""

    def __init__(self, turns: list[str]) -> None:
        self.name = "scripted"
        self.model = "scripted:1b"
        self._turns = list(turns)
        self.calls = 0
        self.seen: list[list[Message]] = []

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
        self.calls += 1
        self.seen.append(list(messages))
        text = self._turns.pop(0) if self._turns else "{}"
        return Completion(text=text, model=self.model, duration_s=0.01)

    def capabilities(self) -> Capabilities:
        return Capabilities(structured_output=True)

    def health(self):  # type: ignore[no-untyped-def]
        raise NotImplementedError


@pytest.fixture
def session() -> Iterator[Session]:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as active:
        _seed(active)
        yield active


def _seed(session: Session) -> None:
    for run_id, attested in (("r1", "kyle"), ("r2", "someone-else")):
        session.add(
            Run(
                id=run_id,
                status=RunStatus.COMPLETED,
                profile="standard",
                attested_by=attested,
                attestation_reference="SEC-1",
                attested_at=datetime.now(UTC),
            )
        )
    session.add(
        Artifact(
            id="a1",
            run_id="r1",
            name="app.exe",
            path_in_tree="app.exe",
            depth=0,
            sha256="0" * 64,
            size_bytes=2048,
            kind=ArtifactKind.PE,
        )
    )
    # Belongs to a different run. Nothing in r1 may reach it.
    session.add(
        Artifact(
            id="a2",
            run_id="r2",
            name="other.exe",
            path_in_tree="other.exe",
            depth=0,
            sha256="1" * 64,
            size_bytes=2048,
            kind=ArtifactKind.PE,
        )
    )
    session.add(
        Evidence(
            run_id="r1",
            artifact_id="a1",
            analyzer="static",
            rule_id="aws-access-key-id",
            value_hash="a" * 64,
            value_masked="AKIA••••••••••••WXYZ",
            offset=100,
        )
    )
    session.add(
        Evidence(
            run_id="r2",
            artifact_id="a2",
            analyzer="static",
            rule_id="other-rule",
            value_hash="b" * 64,
            value_masked="OTHER-RUN-SECRET-VALUE",
            offset=200,
        )
    )
    session.flush()


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
        value_masked="AKIA••••••••••••WXYZ",
        value_hash="a" * 64,
        entropy=3.9,
        status=FindingStatus.OPEN,
        detected_by="rule",
    )


class TestToolsStayInsideTheRun:
    """A model that could name another run's file could read another
    customer's scan by guessing an id."""

    def test_a_file_from_another_run_is_not_visible(self, session: Session) -> None:
        box = ToolBox(session, "r1")
        result = box.run("list_files", {})
        assert "app.exe" in result.output
        assert "other.exe" not in result.output

    def test_reading_another_runs_file_is_refused(self, session: Session) -> None:
        box = ToolBox(session, "r1")
        result = box.run("read_bytes", {"artifact_path": "other.exe", "offset": 0})
        assert result.ok is False
        assert "no file" in result.detail

    def test_searching_does_not_cross_runs(self, session: Session) -> None:
        box = ToolBox(session, "r1")
        result = box.run("search_strings", {"pattern": "SECRET"})
        assert "OTHER-RUN-SECRET-VALUE" not in result.output

    def test_an_unknown_tool_is_refused_by_name(self, session: Session) -> None:
        """No dispatch to anything not in the manifest — in particular there is
        no shell, no eval, and no file write."""
        box = ToolBox(session, "r1")
        for attempt in ("shell", "exec", "write_file", "http_get"):
            result = box.run(attempt, {"cmd": "id"})
            assert result.ok is False
            assert "no such tool" in result.detail


class TestRedaction:
    """§9: candidate plaintext never reaches a provider that is not local and
    explicitly opted in."""

    def test_a_decoded_secret_is_masked_by_default(self, session: Session) -> None:
        """The case that matters: base64 is the obvious way a secret would
        otherwise walk straight out through a tool result."""
        box = ToolBox(session, "r1")
        encoded = base64.b64encode(SECRET.encode()).decode()
        result = box.run("decode", {"text": encoded, "codec": "base64"})
        assert result.ok
        assert SECRET not in result.output
        assert "•" in result.output

    def test_plaintext_is_returned_only_under_the_opt_in(self, session: Session) -> None:
        box = ToolBox(session, "r1", allow_plaintext=True)
        encoded = base64.b64encode(SECRET.encode()).decode()
        result = box.run("decode", {"text": encoded, "codec": "base64"})
        assert SECRET in result.output

    def test_byte_windows_are_masked_too(self, session: Session) -> None:
        """Redaction is applied to every tool's output, not just decode."""
        box = ToolBox(session, "r1")
        assert box._emit(f"key={SECRET}") != f"key={SECRET}"


class TestDecoding:
    """The feature that motivated all this: notice it is encoded, decode it."""

    def test_base64_holding_text_decodes(self, session: Session) -> None:
        box = ToolBox(session, "r1", allow_plaintext=True)
        payload = base64.b64encode(b"host=db.internal;user=svc").decode()
        result = box.run("decode", {"text": payload, "codec": "base64"})
        assert result.ok
        assert "db.internal" in result.output

    def test_a_random_key_that_is_not_base64_fails_clearly(self, session: Session) -> None:
        """A useful negative: it tells the model the value is random rather
        than encoded, which is the answer it was looking for."""
        box = ToolBox(session, "r1")
        result = box.run("decode", {"text": "!!!not base64!!!", "codec": "base64"})
        assert result.ok is False
        assert "not valid base64" in result.detail

    def test_binary_output_comes_back_as_hex_not_mojibake(self, session: Session) -> None:
        box = ToolBox(session, "r1", allow_plaintext=True)
        payload = base64.b64encode(bytes(range(0, 32))).decode()
        result = box.run("decode", {"text": payload, "codec": "base64"})
        assert result.ok
        assert "not printable" in result.output

    def test_an_unknown_codec_lists_the_real_ones(self, session: Session) -> None:
        box = ToolBox(session, "r1")
        result = box.run("decode", {"text": "abc", "codec": "rot13"})
        assert result.ok is False
        assert "base64" in result.detail


class TestTheLoopTerminates:
    def test_a_conclusion_ends_it(self, session: Session, finding: Finding) -> None:
        provider = ScriptedProvider(
            [json.dumps({"thought": "done", "conclusion": "A live AWS key.", "confidence": "high"})]
        )
        result = investigate_finding(
            provider, ToolBox(session, "r1"), finding, path_in_tree="app.exe"
        )
        assert result.conclusion == "A live AWS key."
        assert result.confidence == "high"
        assert provider.calls == 1

    def test_it_stops_at_the_step_cap(self, session: Session, finding: Finding) -> None:
        """A model that never concludes must not bill forever."""
        forever = [json.dumps({"tool": "list_files", "arguments": {}})] * 50
        provider = ScriptedProvider(forever)
        result = investigate_finding(
            provider, ToolBox(session, "r1"), finding, path_in_tree="app.exe", max_steps=4
        )
        assert provider.calls == 4
        assert result.error is not None and "did not reach a conclusion" in result.error
        assert len(result.steps) == 4

    def test_tool_results_are_fed_back_to_the_model(
        self, session: Session, finding: Finding
    ) -> None:
        """Without this the loop is not a loop."""
        provider = ScriptedProvider(
            [
                json.dumps({"tool": "list_files", "arguments": {}}),
                json.dumps({"conclusion": "It is in app.exe.", "confidence": "medium"}),
            ]
        )
        investigate_finding(provider, ToolBox(session, "r1"), finding, path_in_tree="app.exe")
        assert "app.exe" in provider.seen[-1][-1].content

    def test_an_unreachable_model_mid_loop_is_reported(
        self, session: Session, finding: Finding
    ) -> None:
        class Dies(ScriptedProvider):
            def complete(self, *a, **k):  # type: ignore[no-untyped-def]
                raise RuntimeError("connection refused")

        result = investigate_finding(
            Dies([]), ToolBox(session, "r1"), finding, path_in_tree="app.exe"
        )
        assert result.error is not None and "unreachable" in result.error

    def test_a_failing_tool_does_not_end_the_investigation(
        self, session: Session, finding: Finding
    ) -> None:
        """The model should be able to read the error and try something else."""
        provider = ScriptedProvider(
            [
                json.dumps({"tool": "read_bytes", "arguments": {"artifact_path": "nope.exe"}}),
                json.dumps({"conclusion": "Could not read it.", "confidence": "low"}),
            ]
        )
        result = investigate_finding(
            provider, ToolBox(session, "r1"), finding, path_in_tree="app.exe"
        )
        assert result.conclusion == "Could not read it."
        assert result.steps[0].ok is False


class TestItCannotAlterTheFinding:
    """§2.5, enforced structurally: this module writes advisory columns only."""

    def test_applying_a_result_touches_nothing_deterministic(self, finding: Finding) -> None:
        before = (
            finding.severity,
            finding.status,
            finding.value_hash,
            finding.confidence,
            finding.rule_id,
            finding.value_masked,
        )
        from core.llm.investigate import Investigation

        result = Investigation(finding_id="f1", run_id="r1", conclusion="x", confidence="high")
        apply_investigation(finding, result, "scripted:1b")

        after = (
            finding.severity,
            finding.status,
            finding.value_hash,
            finding.confidence,
            finding.rule_id,
            finding.value_masked,
        )
        assert before == after
        assert finding.llm_investigation == "x"

    def test_it_does_not_overwrite_triage_or_explain(self, finding: Finding) -> None:
        """Three roles, three records. Running one must not destroy another's."""
        finding.llm_reasoning = "triage said so"
        finding.llm_explanation = "explain said so"
        from core.llm.investigate import Investigation

        apply_investigation(
            finding, Investigation(finding_id="f1", run_id="r1", conclusion="new"), "m"
        )
        assert finding.llm_reasoning == "triage said so"
        assert finding.llm_explanation == "explain said so"


class TestTheTranscriptIsKept:
    def test_every_step_is_recorded_for_audit(self, session: Session, finding: Finding) -> None:
        """A conclusion with no supporting step is one a reviewer should
        distrust, which is only checkable if the steps survive."""
        provider = ScriptedProvider(
            [
                json.dumps({"tool": "list_files", "arguments": {}}),
                json.dumps({"tool": "entropy", "arguments": {"text": "abc"}}),
                json.dumps({"conclusion": "done", "confidence": "low"}),
            ]
        )
        result = investigate_finding(
            provider, ToolBox(session, "r1"), finding, path_in_tree="app.exe"
        )
        transcript = result.transcript
        assert [s["tool"] for s in transcript] == ["list_files", "entropy"]
        assert all("output" in s for s in transcript)


class TestMalformedTurnsAreVisible:
    """A run that never parses used to end with an empty transcript and nothing
    to diagnose from — which is how a model writing `"offset": <the offset>`
    stayed invisible through twelve steps and ninety seconds of wall clock."""

    def test_an_unparseable_turn_is_recorded(self, session: Session, finding: Finding) -> None:
        provider = ScriptedProvider(
            [
                '```json\n{"tool": "read_bytes", "arguments": {"offset": <the offset>}}\n```',
                json.dumps({"conclusion": "recovered", "confidence": "low"}),
            ]
        )
        result = investigate_finding(
            provider, ToolBox(session, "r1"), finding, path_in_tree="app.exe"
        )
        assert result.conclusion == "recovered"
        assert result.steps[0].ok is False
        assert "offset" in result.steps[0].output

    def test_a_run_that_never_parses_still_leaves_a_transcript(
        self, session: Session, finding: Finding
    ) -> None:
        provider = ScriptedProvider(["not json at all"] * 6)
        result = investigate_finding(
            provider, ToolBox(session, "r1"), finding, path_in_tree="app.exe", max_steps=3
        )
        assert result.conclusion == ""
        assert len(result.steps) == 3
        assert all(not s.ok for s in result.steps)

    def test_json_mode_is_requested_when_the_provider_has_it(
        self, session: Session, finding: Finding
    ) -> None:
        """Without it a small model emits a well-formed-looking object holding
        a placeholder, which parses as nothing."""
        seen: dict[str, object] = {}

        class Recording(ScriptedProvider):
            def complete(self, messages, **kwargs):  # type: ignore[no-untyped-def]
                seen.update(kwargs)
                return super().complete(messages, **kwargs)

        investigate_finding(
            Recording([json.dumps({"conclusion": "x", "confidence": "low"})]),
            ToolBox(session, "r1"),
            finding,
            path_in_tree="app.exe",
        )
        assert seen.get("json_mode") is True


class TestItRecoversFromLoops:
    """Both of these are failures observed on a real run, not hypotheticals.

    A local 14b with num_ctx 8192 read the same 16 bytes twelve times: each
    turn appended a hex dump, the system prompt scrolled out of the window, and
    the model could no longer see the protocol or the offsets it had been
    given. It was not being stupid — it could not see the instructions.
    """

    def test_a_repeated_call_is_not_re_executed(self, session: Session, finding: Finding) -> None:
        calls: list[str] = []

        class Counting(ToolBox):
            def run(self, tool, arguments):  # type: ignore[no-untyped-def]
                calls.append(tool)
                return super().run(tool, arguments)

        same = json.dumps({"tool": "list_files", "arguments": {}})
        provider = ScriptedProvider(
            [same, same, same, json.dumps({"conclusion": "done", "confidence": "low"})]
        )
        result = investigate_finding(
            provider, Counting(session, "r1"), finding, path_in_tree="app.exe"
        )
        # Executed once; the repeats were answered without spending a tool call.
        assert calls == ["list_files"]
        assert result.conclusion == "done"

    def test_a_repeat_is_still_recorded_in_the_transcript(
        self, session: Session, finding: Finding
    ) -> None:
        """The reader should be able to see the model stalled."""
        same = json.dumps({"tool": "list_files", "arguments": {}})
        result = investigate_finding(
            ScriptedProvider([same, same, json.dumps({"conclusion": "d", "confidence": "low"})]),
            ToolBox(session, "r1"),
            finding,
            path_in_tree="app.exe",
        )
        assert len(result.steps) == 2
        assert "repeat" in result.steps[1].detail

    def test_the_prompt_stays_bounded_as_the_loop_runs(
        self, session: Session, finding: Finding
    ) -> None:
        """The system prompt must never scroll out of the window — losing it is
        what caused the stall."""
        turns = [
            json.dumps({"tool": "entropy", "arguments": {"text": f"sample-{i}"}}) for i in range(10)
        ]
        turns.append(json.dumps({"conclusion": "done", "confidence": "low"}))
        provider = ScriptedProvider(turns)
        investigate_finding(
            provider, ToolBox(session, "r1"), finding, path_in_tree="app.exe", max_steps=11
        )

        first, last = provider.seen[0], provider.seen[-1]
        assert last[0].role == "system" and last[0].content == first[0].content
        # And it did not grow without bound.
        assert len(last) <= 2 + (4 * 2) + 1

    def test_dropped_history_is_announced_rather_than_silently_lost(
        self, session: Session, finding: Finding
    ) -> None:
        turns = [json.dumps({"tool": "entropy", "arguments": {"text": f"s-{i}"}}) for i in range(9)]
        turns.append(json.dumps({"conclusion": "done", "confidence": "low"}))
        provider = ScriptedProvider(turns)
        investigate_finding(
            provider, ToolBox(session, "r1"), finding, path_in_tree="app.exe", max_steps=10
        )
        assert any("omitted" in m.content for m in provider.seen[-1])
