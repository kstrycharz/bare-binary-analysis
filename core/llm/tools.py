"""The tools an investigating model may use.

**The model gets tools, not a shell.** That is the whole design, and it is
deliberate. Handing a model a shell inside an analyzer container would mean
either giving that container network access to reach the model — which breaks
the isolation boundary the entire product rests on (THREAT_MODEL.md) — or
having the orchestrator proxy arbitrary commands, which is the same thing with
extra steps and no bound on what runs. Both trade the guarantee for
convenience.

A fixed, read-only tool surface gives up nothing that matters. "It sees a
string, notices it is base64, decodes it, and looks at what came out" is a
sequence of tool calls, not a shell session. What it cannot do is write,
execute, reach the network, or touch anything outside the run under
investigation — and none of those were the point.

Every tool here is:

* **read-only.** Nothing mutates a finding, an artifact, or the database.
* **run-scoped.** `artifact_path` is resolved against this run's artifacts, so
  a model cannot read another customer's scan by guessing an id.
* **bounded.** Byte windows, decode inputs, and result counts are all capped,
  because an unbounded tool result is an unbounded prompt.
* **recorded.** The caller keeps every call and result, so any claim the model
  makes at the end can be traced to the bytes that support it.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import json
import re
import zlib
from dataclasses import dataclass
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.models import Artifact, Evidence
from core.rules.model import shannon_entropy
from core.rules.scanner import mask

log = structlog.get_logger(__name__)

# A tool result becomes prompt text on the next turn, so these caps are context
# management first and safety second — and they are sized for the models that
# actually run this. A local 14b with num_ctx 8192 was the first thing pointed
# at the investigate role, and a 2 KB hex window renders to ~6000 characters:
# three of those and the system prompt has scrolled out of the window, at which
# point the model can no longer see the protocol and repeats its last call
# forever. Observed, not hypothetical.
MAX_BYTES_WINDOW = 512
MAX_DECODE_INPUT = 16_384
MAX_RESULT_CHARS = 1200
MAX_SEARCH_HITS = 40
MAX_ARTIFACTS_LISTED = 60


@dataclass(slots=True)
class ToolResult:
    ok: bool
    output: str
    detail: str = ""

    def truncated(self) -> ToolResult:
        if len(self.output) <= MAX_RESULT_CHARS:
            return self
        kept = self.output[:MAX_RESULT_CHARS]
        return ToolResult(
            ok=self.ok,
            output=f"{kept}\n... [truncated at {MAX_RESULT_CHARS} characters]",
            detail=self.detail,
        )


@dataclass(slots=True)
class ToolCall:
    """One step of an investigation, kept for the audit trail."""

    tool: str
    arguments: dict[str, Any]
    ok: bool
    output: str
    detail: str = ""


# The schema handed to the model. Kept as data so the prompt and the dispatch
# table cannot drift apart — `ToolBox.run` refuses anything not named here.
TOOL_SPECS: tuple[dict[str, Any], ...] = (
    {
        "name": "read_bytes",
        "description": (
            "Read a window of raw bytes from a file in this run, as hex and ASCII. "
            "Use it to see what surrounds a finding."
        ),
        "arguments": {
            "artifact_path": "path of the file within the artifact tree",
            "offset": "byte offset to start at",
            "length": f"how many bytes (default 256, max {MAX_BYTES_WINDOW})",
        },
    },
    {
        "name": "decode",
        "description": (
            "Decode a string. Codecs: base64, base64url, hex, url, gzip, zlib, "
            "utf-16. Returns the decoded text when it is printable, otherwise a "
            "hex preview. Use it when a value looks encoded rather than random."
        ),
        "arguments": {"text": "the string to decode", "codec": "one of the codecs above"},
    },
    {
        "name": "search_strings",
        "description": (
            "Search the strings this scan already extracted, across every file in "
            "the run, by regular expression. Use it to find related values — the "
            "other half of a credential pair, the same host mentioned elsewhere."
        ),
        "arguments": {
            "pattern": "a regular expression",
            "artifact_path": "optional: restrict to one file",
        },
    },
    {
        "name": "list_files",
        "description": "List the files in this run, with size and type.",
        "arguments": {},
    },
    {
        "name": "entropy",
        "description": (
            "Shannon entropy of a string, in bits per character. High entropy "
            "(>4.0) suggests a real key; low suggests a word, path, or template."
        ),
        "arguments": {"text": "the string to measure"},
    },
)


class ToolBox:
    """Executes tool calls for one run, under one redaction policy.

    ``allow_plaintext`` is the §9 opt-in. When false — the default, and always
    the case for a hosted provider — every value a tool returns is masked the
    same way a finding's context is. The model can still see structure, length,
    entropy, and position, which is what investigation actually needs; it
    cannot exfiltrate the secret.
    """

    def __init__(
        self,
        session: Session,
        run_id: str,
        *,
        allow_plaintext: bool = False,
    ) -> None:
        self._session = session
        self._run_id = run_id
        self._allow_plaintext = allow_plaintext
        self._artifacts: dict[str, Artifact] | None = None

    # --- dispatch ---------------------------------------------------------

    def run(self, tool: str, arguments: dict[str, Any]) -> ToolResult:
        handler = {
            "read_bytes": self._read_bytes,
            "decode": self._decode,
            "search_strings": self._search_strings,
            "list_files": self._list_files,
            "entropy": self._entropy,
        }.get(tool)

        if handler is None:
            known = ", ".join(spec["name"] for spec in TOOL_SPECS)
            return ToolResult(False, "", f"no such tool {tool!r}; available: {known}")

        try:
            return handler(arguments).truncated()
        except Exception as exc:
            # A tool that raises must not end the investigation: the model can
            # read the error and try something else, which is the point of a
            # loop.
            log.warning("investigate.tool_failed", tool=tool, error=str(exc))
            return ToolResult(False, "", f"{type(exc).__name__}: {exc}"[:300])

    # --- redaction --------------------------------------------------------

    def _emit(self, text: str) -> str:
        """Everything a tool returns passes through here."""
        if self._allow_plaintext:
            return text
        return _mask_secretish(text)

    # --- tools ------------------------------------------------------------

    def _artifact_index(self) -> dict[str, Artifact]:
        if self._artifacts is None:
            rows = self._session.scalars(
                select(Artifact).where(Artifact.run_id == self._run_id)
            ).all()
            self._artifacts = {row.path_in_tree: row for row in rows}
        return self._artifacts

    def _read_bytes(self, args: dict[str, Any]) -> ToolResult:
        path = str(args.get("artifact_path", ""))
        artifact = self._artifact_index().get(path)
        if artifact is None:
            return ToolResult(False, "", f"no file {path!r} in this run; call list_files first")
        if not artifact.storage_key:
            return ToolResult(False, "", f"{path!r} has no stored bytes (it was not retained)")

        offset = max(0, int(args.get("offset", 0)))
        length = min(int(args.get("length", 256) or 256), MAX_BYTES_WINDOW)

        from core.storage import get_object_store

        data = get_object_store().read_range(artifact.storage_key, offset, length)
        if not data:
            return ToolResult(False, "", f"no bytes at offset {offset} in {path!r}")

        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i : i + 16]
            hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(47)
            ascii_part = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
            lines.append(f"{offset + i:08x}  {hexpart}  |{ascii_part}|")

        return ToolResult(True, self._emit("\n".join(lines)))

    def _decode(self, args: dict[str, Any]) -> ToolResult:
        text = str(args.get("text", ""))[:MAX_DECODE_INPUT]
        codec = str(args.get("codec", "")).strip().lower()
        if not text:
            return ToolResult(False, "", "nothing to decode")

        try:
            raw = _DECODERS[codec](text)
        except KeyError:
            return ToolResult(False, "", f"unknown codec {codec!r}; try {list(_DECODERS)}")
        except Exception as exc:
            # "This is not valid base64" is a finding in itself — it tells the
            # model the string is random rather than encoded.
            return ToolResult(False, "", f"not valid {codec}: {type(exc).__name__}")

        printable = _as_printable(raw)
        if printable is not None:
            return ToolResult(
                True,
                self._emit(printable),
                detail=f"{len(raw)} bytes, printable",
            )
        preview = raw[:256].hex()
        return ToolResult(
            True,
            f"not printable; first {min(len(raw), 256)} bytes as hex:\n{preview}",
            detail=f"{len(raw)} bytes, binary",
        )

    def _search_strings(self, args: dict[str, Any]) -> ToolResult:
        pattern = str(args.get("pattern", ""))
        if not pattern:
            return ToolResult(False, "", "a pattern is required")
        try:
            regex = re.compile(pattern)
        except re.error as exc:
            return ToolResult(False, "", f"bad regular expression: {exc}")

        query = select(Evidence).where(Evidence.run_id == self._run_id)
        path = args.get("artifact_path")
        if path:
            artifact = self._artifact_index().get(str(path))
            if artifact is None:
                return ToolResult(False, "", f"no file {path!r} in this run")
            query = query.where(Evidence.artifact_id == artifact.id)

        by_id = {a.id: p for p, a in self._artifact_index().items()}
        hits: list[str] = []
        for row in self._session.scalars(query):
            # Search the masked form: the model is looking for structure and
            # co-location, and searching plaintext would leak it through the
            # pattern's own match.
            haystack = row.value_masked or ""
            if regex.search(haystack):
                where = by_id.get(row.artifact_id, "?")
                offset = f"0x{row.offset:x}" if row.offset is not None else "?"
                hits.append(f"{row.rule_id}  {haystack}  {where} @{offset}")
            if len(hits) >= MAX_SEARCH_HITS:
                break

        if not hits:
            return ToolResult(True, "no matches", detail="0 hits")
        return ToolResult(True, "\n".join(hits), detail=f"{len(hits)} hit(s)")

    def _list_files(self, _args: dict[str, Any]) -> ToolResult:
        rows = sorted(self._artifact_index().items())
        lines = [
            f"{path}  {artifact.size_bytes or 0} bytes  {artifact.kind or 'unknown'}"
            for path, artifact in rows[:MAX_ARTIFACTS_LISTED]
        ]
        if len(rows) > MAX_ARTIFACTS_LISTED:
            lines.append(f"... and {len(rows) - MAX_ARTIFACTS_LISTED} more files")
        return ToolResult(True, "\n".join(lines) or "no files", detail=f"{len(rows)} file(s)")

    def _entropy(self, args: dict[str, Any]) -> ToolResult:
        text = str(args.get("text", ""))
        if not text:
            return ToolResult(False, "", "nothing to measure")
        return ToolResult(
            True, f"{shannon_entropy(text):.2f} bits/char over {len(text)} characters"
        )


# --- decoders -------------------------------------------------------------


def _b64(text: str) -> bytes:
    # validate=True so that a random high-entropy string fails loudly rather
    # than decoding to garbage and sending the model down a false trail.
    padded = text + "=" * (-len(text) % 4)
    return base64.b64decode(padded, validate=True)


def _b64url(text: str) -> bytes:
    padded = text + "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(padded)


def _hex(text: str) -> bytes:
    return binascii.unhexlify(text.strip().replace(" ", ""))


def _url(text: str) -> bytes:
    from urllib.parse import unquote_to_bytes

    return unquote_to_bytes(text)


def _utf16(text: str) -> bytes:
    return text.encode("utf-16-le", "replace")


_DECODERS: dict[str, Any] = {
    "base64": _b64,
    "base64url": _b64url,
    "hex": _hex,
    "url": _url,
    "gzip": lambda t: gzip.decompress(t.encode("latin-1")),
    "zlib": lambda t: zlib.decompress(t.encode("latin-1")),
    "utf-16": _utf16,
}


def _as_printable(raw: bytes) -> str | None:
    """Decoded text, if it reads as text at all.

    The ratio test is what distinguishes "this base64 held a JSON config" from
    "this random key happened to be valid base64" — the second decodes to
    bytes that are mostly unprintable.
    """
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            text = raw.decode("latin-1")
        except Exception:
            return None
    if not text:
        return None
    printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    return text if printable / len(text) > 0.85 else None


# --- redaction ------------------------------------------------------------

# Long unbroken runs of credential-shaped characters. Deliberately blunt: this
# is the last line before a tool result reaches a hosted model, and over-masking
# costs the model a little context while under-masking costs a customer their
# secret.
_SECRETISH = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")


def _mask_secretish(text: str) -> str:
    return _SECRETISH.sub(lambda m: mask(m.group(0)), text)


def tool_manifest() -> str:
    """The tool list as the model sees it."""
    return json.dumps(list(TOOL_SPECS), indent=2)
