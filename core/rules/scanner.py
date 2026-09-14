"""String extraction and rule matching over binary data.

This is where most findings come from, and two details decide whether the tool
is actually useful:

**UTF-16LE.** Windows binaries keep a large share of their strings as wide
characters, and a scanner that only walks ASCII misses roughly half the secrets
in a typical `.exe`. Both encodings are extracted, and the encoding is carried
through to the finding so a reviewer can see which one it came from.

**Offsets.** A finding that says "this key is in the binary" is an argument. A
finding that says "at 0x4a2c, in .rdata, as a wide string" is a fix. Offsets are
preserved from extraction all the way to the report.
"""

from __future__ import annotations

import bisect
import hashlib
from collections.abc import Iterator
from dataclasses import dataclass, replace

from core.rules.model import Rule, RulePack, shannon_entropy
from core.rules.shape import ShapePolicy, classify, has_nearby

MIN_STRING_LENGTH = 6
MAX_STRING_LENGTH = 8192
CONTEXT_BYTES = 60

# Printable ASCII plus tab. Deliberately excludes newline: a "string" spanning
# lines is usually two strings that happen to be adjacent in the binary.
_PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09}


@dataclass(frozen=True, slots=True)
class ExtractedString:
    value: str
    offset: int
    encoding: str

    @property
    def end_offset(self) -> int:
        width = 2 if self.encoding == "utf-16le" else 1
        return self.offset + len(self.value) * width


@dataclass(frozen=True, slots=True)
class Match:
    """One rule hit. Becomes an Evidence row; never a Finding directly —
    correlation decides that."""

    rule_id: str
    value: str
    offset: int
    encoding: str
    entropy: float
    context: str

    @property
    def value_hash(self) -> str:
        """Hash of the plaintext, so the same secret dedupes across every copy
        of it in the unpack tree without ever storing the value itself."""
        return hashlib.sha256(self.value.encode("utf-8", "surrogatepass")).hexdigest()

    @property
    def masked(self) -> str:
        return mask(self.value)


def mask(value: str, *, keep_prefix: int = 4, keep_suffix: int = 4) -> str:
    """``sk-live-••••••••••••4f2a``.

    Enough to recognise the secret you are looking for, not enough to use it.
    Short values are fully masked — revealing 8 of 10 characters is not masking.
    """
    if len(value) <= keep_prefix + keep_suffix + 4:
        return "•" * min(len(value), 12)
    hidden = len(value) - keep_prefix - keep_suffix
    return f"{value[:keep_prefix]}{'•' * min(hidden, 12)}{value[-keep_suffix:]}"


def extract_ascii(data: bytes, min_length: int = MIN_STRING_LENGTH) -> Iterator[ExtractedString]:
    start = -1
    for index, byte in enumerate(data):
        if byte in _PRINTABLE:
            if start < 0:
                start = index
            elif index - start >= MAX_STRING_LENGTH:
                yield ExtractedString(data[start:index].decode("ascii", "replace"), start, "ascii")
                start = index
            continue
        if start >= 0 and index - start >= min_length:
            yield ExtractedString(data[start:index].decode("ascii", "replace"), start, "ascii")
        start = -1
    if start >= 0 and len(data) - start >= min_length:
        yield ExtractedString(data[start:].decode("ascii", "replace"), start, "ascii")


def extract_utf16le(data: bytes, min_length: int = MIN_STRING_LENGTH) -> Iterator[ExtractedString]:
    """Wide strings: printable byte followed by a zero byte, repeated.

    Scans from both even and odd alignments, because a wide string embedded in a
    resource section is not guaranteed to start on an even offset and a
    single-alignment scan quietly misses those.
    """
    for alignment in (0, 1):
        chars: list[str] = []
        start = -1
        index = alignment
        while index + 1 < len(data):
            low, high = data[index], data[index + 1]
            if high == 0x00 and low in _PRINTABLE:
                if start < 0:
                    start = index
                chars.append(chr(low))
                if len(chars) >= MAX_STRING_LENGTH:
                    yield ExtractedString("".join(chars), start, "utf-16le")
                    chars, start = [], -1
            else:
                if len(chars) >= min_length:
                    yield ExtractedString("".join(chars), start, "utf-16le")
                chars, start = [], -1
            index += 2
        if len(chars) >= min_length:
            yield ExtractedString("".join(chars), start, "utf-16le")


def extract_strings(data: bytes, min_length: int = MIN_STRING_LENGTH) -> list[ExtractedString]:
    """Both encodings, deduplicated, in deterministic order.

    Sorted by (offset, encoding, value) so that evidence rows land in the same
    order on every run regardless of extraction order — parallelism must never
    leak into results (§2.5).
    """
    seen: set[tuple[str, int, str]] = set()
    results: list[ExtractedString] = []
    for extracted in (*extract_ascii(data, min_length), *extract_utf16le(data, min_length)):
        key = (extracted.value, extracted.offset, extracted.encoding)
        if key in seen:
            continue
        seen.add(key)
        results.append(extracted)
    results.sort(key=lambda s: (s.offset, s.encoding, s.value))
    return results


@dataclass(frozen=True, slots=True)
class _Span:
    """The bytes one match occupies, and what to show in their place."""

    start: int
    end: int
    value: str


class _SpanIndex:
    """Every match in one buffer, for masking the context around any of them."""

    def __init__(self, matches: list[Match]) -> None:
        spans = {
            _Span(
                m.offset, m.offset + len(m.value) * (2 if m.encoding == "utf-16le" else 1), m.value
            )
            for m in matches
        }
        self._spans = sorted(spans, key=lambda s: (s.start, -s.end, s.value))
        self._starts = [span.start for span in self._spans]
        self._longest = max((span.end - span.start for span in self._spans), default=0)

    def overlapping(self, start: int, end: int) -> list[_Span]:
        # A span can begin before the window and still reach into it, so the
        # search starts one longest-span earlier than the window does.
        first = bisect.bisect_left(self._starts, start - self._longest)
        last = bisect.bisect_left(self._starts, end)
        return [span for span in self._spans[first:last] if span.end > start]


def _printable(raw: bytes) -> str:
    text = raw.decode("ascii", "replace")
    return "".join(c if c.isprintable() or c == " " else "." for c in text)


def _context_for(data: bytes, offset: int, value: str, spans: _SpanIndex) -> str:
    """Bytes around the hit, with *every* matched secret in them masked out.

    This is what gets sent to a remote model, so no value may survive in it —
    the trust boundary depends on this function being correct.

    Masking only the finding's own value was the bug: secrets cluster, so the
    window around an AWS access key ID routinely holds the secret access key on
    the next line, and each finding's context carried its neighbour in the
    clear. Masking by byte span rather than by string replacement is the other
    half: a UTF-16LE secret decodes to ``g.h.p._.9.f`` in an ASCII window, which
    no ``str.replace`` of the value would ever find, and which is still legible.
    """
    start = max(0, offset - CONTEXT_BYTES)
    end = min(len(data), offset + len(value) * 2 + CONTEXT_BYTES)

    overlapping = spans.overlapping(start, end)
    pieces: list[str] = []
    cursor = start
    for span in overlapping:
        if span.end <= cursor:
            continue
        if span.start > cursor:
            pieces.append(_printable(data[cursor : span.start]))
            pieces.append(mask(span.value))
        else:
            # Begins before the cursor: inside the window's leading edge, or
            # overlapping a span already masked. Hide the remainder outright.
            pieces.append("•" * min(span.end - cursor, 12))
        cursor = min(span.end, end)
        if cursor >= end:
            break
    if cursor < end:
        pieces.append(_printable(data[cursor:end]))
    window = "".join(pieces)

    # Belt and braces: the same value repeated in the window at a place no
    # rule matched (a proximity rule rejects the second copy, say).
    for span in overlapping:
        window = window.replace(span.value, mask(span.value))
    return window.replace(value, mask(value))


def scan_bytes(
    data: bytes,
    pack: RulePack,
    *,
    min_length: int = MIN_STRING_LENGTH,
) -> list[Match]:
    """Run every enabled rule over both encodings of ``data``.

    Returns matches in a deterministic order: rules are iterated sorted by id
    and strings by offset, so identical input yields an identical list.
    """
    strings = extract_strings(data, min_length)
    matches: list[Match] = []

    for rule in pack.enabled_rules():
        for extracted in strings:
            if extracted.encoding not in rule.encodings:
                continue
            matches.extend(_apply_rule(rule, extracted, pack))

    # Context is built only once every match is known, so each window can mask
    # its neighbours as well as its own value.
    spans = _SpanIndex(matches)
    matches = [replace(m, context=_context_for(data, m.offset, m.value, spans)) for m in matches]
    matches.sort(key=lambda m: (m.rule_id, m.offset, m.encoding, m.value))
    return matches


def _apply_rule(
    rule: Rule,
    extracted: ExtractedString,
    pack: RulePack,
) -> Iterator[Match]:
    width = 2 if extracted.encoding == "utf-16le" else 1
    for pattern in rule.patterns:
        for match in pattern.regex.finditer(extracted.value):
            value = pattern.extract(match)
            if not value or not rule.accepts(value):
                continue

            if pack.is_known_false_positive(value):
                # Public test keys, RFC samples, AKIAIOSFODNN7EXAMPLE. Dropped
                # here rather than surfaced-and-suppressed: nobody wants a
                # report whose top finding is the AWS documentation example.
                continue

            # Proximity. A shape-based rule without required context is a
            # high-entropy string detector wearing a credential's name.
            if rule.requires_nearby and not has_nearby(
                extracted.value, match.start(), rule.requires_nearby, rule.nearby_window
            ):
                continue

            # Structure. This is what stops a 40-character window carved out of
            # a certificate or a PDF stream being reported as a critical
            # credential — measured at 96.8% of all matches on a real artifact
            # before this existed.
            if rule.shape_policy != "off":
                verdict = classify(
                    value,
                    haystack=extracted.value,
                    start=match.start(),
                    end=match.end(),
                    policy=(
                        ShapePolicy.STRICT if rule.shape_policy == "strict" else ShapePolicy.CONTEXT
                    ),
                    require_mixed_case=rule.require_mixed_case,
                )
                if verdict.rejected:
                    continue

            absolute = extracted.offset + match.start() * width
            yield Match(
                rule_id=rule.id,
                value=value,
                offset=absolute,
                encoding=extracted.encoding,
                entropy=round(shannon_entropy(value), 3),
                context="",  # filled in by scan_bytes once every match is known
            )


def scan_file(path: str, pack: RulePack, *, max_bytes: int = 512 * 1024 * 1024) -> list[Match]:
    """Scan a file whole.

    Whole-file rather than streaming because matches must not be split across
    chunk boundaries — a key that straddles a 1 MB boundary is exactly the key
    you cannot afford to miss. ``max_bytes`` bounds memory; larger files are
    truncated and the caller records that in the stage record.
    """
    with open(path, "rb") as handle:
        data = handle.read(max_bytes)
    return scan_bytes(data, pack)
