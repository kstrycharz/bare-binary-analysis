"""`bare scan --show-logs`: analyzer output, printed while the scan runs.

For the operator debugging a scan from a terminal — a stage that degrades, an
unpack that looks hung — without opening the dashboard. It reads the endpoint
the dashboard's "Show logs" reads, once per status poll: while a stage runs
that is a snapshot the worker republishes every few seconds, and once the stage
ends it is the retained log (ADR-0033).

Two things this file is careful about:

**The text is untrusted.** It is output derived from a customer's binary, and
a terminal is a parser: an escape sequence can clear the screen, overwrite an
earlier line of a job log, or retitle the window. Every control character is
printed as a visible escape, never passed through.

**It cannot become a CI default by accident.** The logs endpoint is ADMIN-scoped
(ADR-0032) — masked text, but the findings corpus's neighbour — so a CI token
gets one warning and the scan carries on without logs. Showing them in a
pipeline means deliberately handing it an admin token.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Any, Protocol

from cli.client import ApiError

_UNFINISHED = frozenset({"pending", "running"})

# The two headlines `core.pipeline.logs.render_stage_log` writes, as they sit
# in the document: stdout first, then stderr after the joining newline.
_STDOUT_HEADLINE = "--- stdout ---\n"
_STDERR_HEADLINE = "\n--- stderr ---\n"

# C0 and C1 controls except tab, plus the Unicode separators and bidi controls
# that make a printed line read as something it is not. Built from code points
# so this file holds no invisible characters of its own.
_UNSAFE_RANGES = (
    (0x00, 0x08),
    (0x0A, 0x1F),
    (0x7F, 0x9F),
    (0x2028, 0x2029),
    (0x202A, 0x202E),
    (0x2066, 0x2069),
)
_UNSAFE = re.compile("[" + "".join(f"{chr(a)}-{chr(b)}" for a, b in _UNSAFE_RANGES) + "]")


class LogSource(Protocol):
    def get_stage_log(self, run_id: str, stage_id: str) -> tuple[str, str] | None: ...


def sanitize(line: str) -> str:
    """One line of untrusted output, safe to hand to a terminal."""

    def escape(match: re.Match[str]) -> str:
        code = ord(match.group())
        return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"

    return _UNSAFE.sub(escape, line)


def split_streams(document: str) -> dict[str, list[str]]:
    """The lines of each stream in a rendered stage log.

    Split at the first stderr headline. Output can spoof that by printing the
    line itself; the cost is some lines labelled with the wrong stream in a
    debugging aid, and every line is still printed.

    Split on ``\\n`` only, not `str.splitlines`, which would also break at a
    carriage return or form feed and so hide exactly the characters
    `sanitize` exists to show.
    """
    body = document.removeprefix(_STDOUT_HEADLINE)
    stdout, _, stderr = body.partition(_STDERR_HEADLINE)
    return {"stdout": _lines(stdout), "stderr": _lines(stderr)}


def _lines(text: str) -> list[str]:
    return text.removesuffix("\n").split("\n") if text else []


class LogFollower:
    """Prints each stage's status changes and new output lines, one poll at a time."""

    def __init__(
        self,
        source: LogSource,
        run_id: str,
        *,
        echo: Callable[[str], None],
        warn: Callable[[str], None],
    ) -> None:
        self._source = source
        self._run_id = run_id
        self._echo = echo
        self._warn = warn
        self._printed: dict[tuple[str, str], int] = {}
        self._status: dict[str, str] = {}
        self._settled: set[str] = set()
        self._disabled = False

    def poll(self, run: Mapping[str, Any]) -> None:
        """Print what is new since the last poll of ``run`` (a run detail response).

        Never raises: the scan being waited on matters more than its logs, and
        a log that cannot be read must not turn into a failed build step.
        """
        if self._disabled:
            return
        for stage in run.get("stages") or []:
            stage_id = str(stage.get("id") or "")
            if not stage_id or stage_id in self._settled:
                continue
            analyzer = str(stage.get("analyzer") or "?")
            status = str(stage.get("status") or "")
            if self._status.get(stage_id) != status:
                self._status[stage_id] = status
                self._echo(f"[{analyzer}] {status}")

            try:
                fetched = self._source.get_stage_log(self._run_id, stage_id)
            except ApiError as exc:
                if exc.status in (401, 403):
                    self._warn("analyzer logs need an admin-scoped token; continuing without them")
                    self._disabled = True
                    return
                self._warn(f"could not read the {analyzer} log: {exc}")
                continue

            if fetched is not None:
                self._print_new(stage_id, analyzer, fetched[0])
            if status not in _UNFINISHED:
                # The row that says the stage ended is committed with its
                # retained log, so this read was the last word on it.
                self._settled.add(stage_id)

    def _print_new(self, stage_id: str, analyzer: str, document: str) -> None:
        for stream, lines in split_streams(document).items():
            key = (stage_id, stream)
            printed = self._printed.get(key, 0)
            if len(lines) < printed:
                # The document is rewritten each time, not appended to. If it
                # ever comes back shorter, say so rather than guess which of
                # its lines are new.
                self._echo(f"[{analyzer}:{stream}] [bare: log rewritten; earlier lines may differ]")
                printed = len(lines)
            for line in lines[printed:]:
                self._echo(f"[{analyzer}:{stream}] {sanitize(line)}")
            self._printed[key] = len(lines)
