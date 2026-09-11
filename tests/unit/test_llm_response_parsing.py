"""What `Completion.as_json` accepts, and what triage reports when nothing parses.

The failure this pins is the one an operator actually hits: a reasoning model
thinking out loud before the verdict object, or having the object truncated by
the token budget. Both used to come back as "model did not return parseable
JSON" — a parser accusation, when the real problem is the model choice or its
budget, and the operator goes looking at JSON-escaping code.
"""

from __future__ import annotations

from core.llm.provider import Completion
from core.llm.triage import _parse
from core.models.enums import LlmVerdict


def _completion(text: str, **raw: object) -> Completion:
    return Completion(text=text, model="m", raw=dict(raw))


class TestAsJsonToleratesWrapping:
    def test_plain_object(self) -> None:
        assert _completion('{"verdict": "true_positive"}').as_json() == {"verdict": "true_positive"}

    def test_fenced_block(self) -> None:
        parsed = _completion('```json\n{"verdict": "needs_review"}\n```').as_json()
        assert parsed == {"verdict": "needs_review"}

    def test_prose_before_and_after_the_object(self) -> None:
        parsed = _completion(
            'Sure! {"verdict": "false_positive", "reasoning": "placeholder"} Hope that helps.'
        ).as_json()
        assert parsed is not None
        assert parsed["verdict"] == "false_positive"

    def test_curly_braces_in_the_reasoning_prose(self) -> None:
        """The first-brace-to-last-brace slice used to swallow the prose braces
        and fail. A balanced scan finds the real object wherever it starts."""
        parsed = _completion(
            'The config dict {"key": ...} is a placeholder, so: '
            '{"verdict": "false_positive", "reasoning": "example value"}'
        ).as_json()
        assert parsed is not None
        assert parsed["verdict"] == "false_positive"

    def test_braces_inside_string_values_do_not_desync_the_scan(self) -> None:
        parsed = _completion(
            'prefix {"verdict": "true_positive", "reasoning": "literal { and } in value"}'
        ).as_json()
        assert parsed is not None
        assert parsed["verdict"] == "true_positive"

    def test_nested_object(self) -> None:
        parsed = _completion('lead-in {"a": {"b": 1}, "verdict": "needs_review"}').as_json()
        assert parsed is not None
        assert parsed["verdict"] == "needs_review"

    def test_no_object_at_all(self) -> None:
        assert _completion("I cannot help with that.").as_json() is None

    def test_truncated_object_is_not_mangled_into_one(self) -> None:
        assert _completion('{"verdict": "true_positive", "reason').as_json() is None

    def test_a_list_is_not_an_object(self) -> None:
        assert _completion("[1, 2]").as_json() is None


class TestTriageNamesTheReasonerCase:
    def test_a_thinking_model_cut_off_mid_answer_says_budget_not_parser(self) -> None:
        completion = _completion(
            '{"verdict": "true',  # truncated while writing the verdict
            thinking="The entropy is high, let me consider every angle " * 40,
        )
        verdict, reasoning = _parse(completion)
        assert verdict is LlmVerdict.ERROR
        assert "token budget" in reasoning

    def test_unparseable_output_from_a_non_reasoner_still_blames_the_parser(self) -> None:
        verdict, reasoning = _parse(_completion("I think it is probably fine."))
        assert verdict is LlmVerdict.ERROR
        assert reasoning == "model did not return parseable JSON"

    def test_prose_wrapped_verdict_parses(self) -> None:
        completion = _completion(
            'Based on the evidence, {"verdict": "false_positive", '
            '"reasoning": "RFC example value"} — that is my call.'
        )
        verdict, reasoning = _parse(completion)
        assert verdict is LlmVerdict.FALSE_POSITIVE
        assert "RFC" in reasoning
