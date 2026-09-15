"""`bare scan --show-logs`: printing analyzer output while the scan runs.

The follower is a debugging aid in a terminal, and a terminal is a parser — so
beyond "prints what is new, once", the property held here is that nothing the
analyzer printed reaches it as a control sequence.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cli.client import ApiError
from cli.log_follow import LogFollower, sanitize, split_streams
from core.pipeline.logs import render_stage_log
from core.rules import load_rule_pack

RULES_DIR = Path(__file__).resolve().parents[2] / "detections"


def _doc(stdout: str, stderr: str = "") -> str:
    """The shape `render_stage_log` writes; pinned to it by a test below."""
    return f"--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"


def _run(*stages: tuple[str, str, str]) -> dict[str, Any]:
    return {"stages": [{"id": i, "analyzer": a, "status": s} for i, a, s in stages]}


class FakeSource:
    def __init__(self) -> None:
        self.logs: dict[str, tuple[str, str]] = {}
        self.calls: list[str] = []
        self.error: ApiError | None = None

    def get_stage_log(self, run_id: str, stage_id: str) -> tuple[str, str] | None:
        self.calls.append(stage_id)
        if self.error is not None:
            raise self.error
        return self.logs.get(stage_id)


def _follower(source: FakeSource) -> tuple[LogFollower, list[str], list[str]]:
    out: list[str] = []
    warnings: list[str] = []
    return LogFollower(source, "run-1", echo=out.append, warn=warnings.append), out, warnings


class TestSplitStreams:
    def test_matches_the_renderer(self) -> None:
        document, _ = render_stage_log(b"a\nb\n", b"boom\n", pack=load_rule_pack(RULES_DIR))
        assert document == _doc("a\nb\n", "boom\n")
        assert split_streams(document) == {"stdout": ["a", "b"], "stderr": ["boom"]}

    def test_empty_streams_have_no_lines(self) -> None:
        assert split_streams(_doc("", "")) == {"stdout": [], "stderr": []}

    def test_a_carriage_return_does_not_split_a_line(self) -> None:
        assert split_streams(_doc("50%\r100%\n"))["stdout"] == ["50%\r100%"]


class TestSanitize:
    def test_escape_sequences_are_shown_not_sent(self) -> None:
        assert sanitize("\x1b]0;owned\x07\x1b[2Jclear") == "\\x1b]0;owned\\x07\\x1b[2Jclear"

    def test_a_carriage_return_cannot_overwrite_the_line(self) -> None:
        assert sanitize("ok\rFAILED") == "ok\\x0dFAILED"

    def test_a_bidi_override_is_escaped(self) -> None:
        assert sanitize("safe" + chr(0x202E) + "gnp.exe") == "safe\\u202egnp.exe"

    def test_tabs_and_ordinary_text_pass_through(self) -> None:
        assert sanitize("col\tcafé — ok") == "col\tcafé — ok"


class TestLogFollower:
    def test_prints_only_what_is_new_labelled_by_stage_and_stream(self) -> None:
        source = FakeSource()
        follower, out, _ = _follower(source)
        running = _run(("s1", "static", "running"))

        source.logs["s1"] = (_doc("one\n"), "live")
        follower.poll(running)
        source.logs["s1"] = (_doc("one\ntwo\n", "warn\n"), "live")
        follower.poll(running)

        assert out == [
            "[static] running",
            "[static:stdout] one",
            "[static:stdout] two",
            "[static:stderr] warn",
        ]

    def test_nothing_printed_yet_shows_only_the_status(self) -> None:
        source = FakeSource()
        follower, out, _ = _follower(source)
        follower.poll(_run(("s1", "unpack", "running")))
        follower.poll(_run(("s1", "unpack", "running")))
        assert out == ["[unpack] running"]

    def test_a_finished_stage_is_read_once_more_then_left_alone(self) -> None:
        source = FakeSource()
        follower, out, _ = _follower(source)
        source.logs["s1"] = (_doc("one\n"), "live")
        follower.poll(_run(("s1", "unpack", "running")))
        source.logs["s1"] = (_doc("one\nexit 0"), "final")
        follower.poll(_run(("s1", "unpack", "completed")))
        follower.poll(_run(("s1", "unpack", "completed")))

        assert source.calls == ["s1", "s1"]
        assert out[-2:] == ["[unpack] completed", "[unpack:stdout] exit 0"]

    def test_output_reaches_the_terminal_escaped(self) -> None:
        source = FakeSource()
        follower, out, _ = _follower(source)
        source.logs["s1"] = (_doc("\x1b[2J\rpwned\n"), "live")
        follower.poll(_run(("s1", "static", "running")))
        assert out[-1] == "[static:stdout] \\x1b[2J\\x0dpwned"

    def test_a_ci_token_warns_once_and_the_scan_carries_on(self) -> None:
        source = FakeSource()
        source.error = ApiError("GET ... failed: HTTP 403", status=403)
        follower, _, warnings = _follower(source)
        follower.poll(_run(("s1", "static", "running")))
        follower.poll(_run(("s1", "static", "running")))
        assert len(warnings) == 1 and "admin" in warnings[0]
        assert source.calls == ["s1"]

    def test_an_unreachable_log_warns_and_keeps_trying(self) -> None:
        source = FakeSource()
        source.error = ApiError("cannot reach http://bare:8000: refused")
        follower, _, warnings = _follower(source)
        follower.poll(_run(("s1", "static", "running")))
        source.error = None
        source.logs["s1"] = (_doc("back\n"), "live")
        follower.poll(_run(("s1", "static", "running")))
        assert len(warnings) == 1
        assert source.calls == ["s1", "s1"]

    def test_a_document_that_comes_back_shorter_says_so(self) -> None:
        source = FakeSource()
        follower, out, _ = _follower(source)
        source.logs["s1"] = (_doc("a\nb\nc\n"), "live")
        follower.poll(_run(("s1", "static", "running")))
        source.logs["s1"] = (_doc("a\nb\n"), "final")
        follower.poll(_run(("s1", "static", "completed")))
        assert "log rewritten" in out[-1]
