"""The S4 result contract: what the Ghidra analyzer writes, and what reads it.

Shared between the container and the orchestrator on purpose, the same way
``core.rules`` is shared with the static image. The alternative is a dict
literal in the analyzer and a second, subtly different set of ``.get()`` calls
on the host — which is how a renamed key becomes "Ghidra found nothing"
instead of a crash.

Dependency-free: no SQLAlchemy, no Pydantic. The Ghidra image installs Python
only to run the entrypoint, and it should stay that way.

The shape answers one question. The static pass says *a secret-shaped string
exists at offset 0x3a91c*. This says *what reads it* — the function, the
instruction, and a window of decompiled code around the use. "This string
exists" is noise; "this string is the second argument to MQTTClient_connect"
is a finding somebody acts on.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA_VERSION = 1

# A decompiled function can be thousands of lines. The window is what a
# reviewer reads and what the LLM layer is later handed, and neither benefits
# from the whole function — the use site and its neighbourhood is the evidence.
MAX_CONTEXT_CHARS = 2000

# Ghidra will happily report ten thousand references to a string in a jump
# table. Past a handful they stop being evidence and start being a denial of
# service against the report renderer.
MAX_REFERENCES_PER_TARGET = 32


@dataclass(slots=True)
class XrefSite:
    """One place a flagged string is referenced from."""

    from_address: str
    """Ghidra address of the referencing instruction, e.g. ``0x140002a1c``.
    A string, not an int: these are 64-bit and JSON has no integer width."""

    reference_type: str
    """Ghidra's own classification — ``DATA``, ``READ``, ``PARAM``. Passed
    through rather than normalised, so the report can say what Ghidra said."""

    function: str | None = None
    """Containing function's name. ``None`` when the reference is not inside
    one, which happens in data sections and is worth distinguishing from
    "Ghidra could not name it" — an unnamed function still gets its
    ``FUN_140002a10`` label, so ``None`` here really does mean "no function"."""

    function_address: str | None = None
    context: str | None = None
    """Decompiled source window around the use site, or ``None`` when the
    decompiler failed or was not asked. Truncated to MAX_CONTEXT_CHARS."""

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> XrefSite:
        return cls(
            from_address=str(data.get("from_address") or ""),
            reference_type=str(data.get("reference_type") or "UNKNOWN"),
            function=_optional_str(data.get("function")),
            function_address=_optional_str(data.get("function_address")),
            context=_optional_str(data.get("context")),
        )


@dataclass(slots=True)
class XrefTarget:
    """One flagged string, and everywhere it is used.

    ``file_offset`` is the join key back to the finding that asked about it.
    It is the *file* offset the static pass recorded, not a memory address:
    the correlator knows nothing about load addresses, and translating between
    the two is precisely Ghidra's job.
    """

    file_offset: int
    address: str | None = None
    """Where the string landed in Ghidra's memory map, once it resolved the
    offset. ``None`` means it could not be mapped — a packed section, or an
    offset inside a resource blob that is never loaded."""

    found: bool = False
    """Whether the offset resolved to something Ghidra recognised. False with
    an empty ``references`` list is a real answer ("that byte range is not code
    or referenced data"), and must not read as "not analysed"."""

    references: list[XrefSite] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "file_offset": self.file_offset,
            "address": self.address,
            "found": self.found,
            "references": [r.to_json() for r in self.references],
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> XrefTarget:
        raw = data.get("references")
        references = [XrefSite.from_json(r) for r in raw] if isinstance(raw, list) else []
        return cls(
            file_offset=int(data.get("file_offset") or 0),
            address=_optional_str(data.get("address")),
            found=bool(data.get("found")),
            references=references,
        )

    @property
    def best_function(self) -> str | None:
        """The single function name worth putting on a finding location.

        There is one column and there may be many references, so this picks the
        first named function in Ghidra's address order. Deterministic because
        the analyzer sorts references by address before writing them —
        parallelism must not change which name a report shows (§8).
        """
        for ref in self.references:
            if ref.function:
                return ref.function
        return None


@dataclass(slots=True)
class BinaryResult:
    """What happened to one binary in the tree."""

    path: str
    """Staged path, e.g. ``extracted/app/broker.exe``. The same key the static
    analyzer used, which is what lets the orchestrator map it to an artifact."""

    status: str = "analyzed"
    """``analyzed`` | ``skipped`` | ``failed`` | ``timeout``.

    Never absent and never silently ``analyzed``: a binary Ghidra choked on
    must not be indistinguishable from one with no cross-references. The
    orchestrator degrades the stage on anything that is not ``analyzed`` or
    ``skipped``."""

    reason: str | None = None
    language: str | None = None
    """Ghidra's language id, e.g. ``x86:LE:64:windows``. Recorded because a
    misidentified processor is the usual explanation for an empty result."""

    function_count: int = 0
    duration_s: float = 0.0
    targets: list[XrefTarget] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "status": self.status,
            "reason": self.reason,
            "language": self.language,
            "function_count": self.function_count,
            "duration_s": round(self.duration_s, 3),
            "targets": [t.to_json() for t in self.targets],
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> BinaryResult:
        raw = data.get("targets")
        targets = [XrefTarget.from_json(t) for t in raw] if isinstance(raw, list) else []
        return cls(
            path=str(data.get("path") or ""),
            status=str(data.get("status") or "failed"),
            reason=_optional_str(data.get("reason")),
            language=_optional_str(data.get("language")),
            function_count=int(data.get("function_count") or 0),
            duration_s=float(data.get("duration_s") or 0.0),
            targets=targets,
        )

    @property
    def degraded(self) -> bool:
        return self.status not in ("analyzed", "skipped")


@dataclass(slots=True)
class GhidraResult:
    """The whole ``/output/result.json``."""

    schema_version: int = SCHEMA_VERSION
    analyzer: str = "ghidra"
    ghidra_version: str = "unknown"
    binaries: list[BinaryResult] = field(default_factory=list)
    truncated: bool = False
    """A budget stopped the pass before every binary was looked at. Surfaced
    for the same reason the unpack analyzer surfaces it: a partial pass that
    reports nothing is indistinguishable from a clean one (ADR-0018)."""

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "analyzer": self.analyzer,
            "ghidra_version": self.ghidra_version,
            "truncated": self.truncated,
            "tool_versions": {"ghidra": self.ghidra_version},
            # Sorted so two runs over the same tree produce byte-identical
            # output regardless of the order the directory walk returned.
            "binaries": [b.to_json() for b in sorted(self.binaries, key=lambda b: b.path)],
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> GhidraResult:
        raw = data.get("binaries")
        binaries = [BinaryResult.from_json(b) for b in raw] if isinstance(raw, list) else []
        version = (data.get("tool_versions") or {}).get("ghidra") or data.get("ghidra_version")
        return cls(
            schema_version=int(data.get("schema_version") or 0),
            analyzer=str(data.get("analyzer") or "ghidra"),
            ghidra_version=str(version or "unknown"),
            binaries=binaries,
            truncated=bool(data.get("truncated")),
        )

    def xref_functions(self) -> dict[tuple[str, int], str]:
        """``(staged path, file offset) -> function name``.

        Exactly what the orchestrator needs to fill
        ``FindingLocation.xref_function`` and nothing else. Offsets with no
        named function are absent rather than mapped to ``None``, so a caller
        iterating this writes only what Ghidra actually established.
        """
        resolved: dict[tuple[str, int], str] = {}
        for binary in self.binaries:
            for target in binary.targets:
                name = target.best_function
                if name:
                    resolved[(binary.path, target.file_offset)] = name
        return resolved

    @property
    def degraded_binaries(self) -> list[BinaryResult]:
        return [b for b in self.binaries if b.degraded]


def _optional_str(value: Any) -> str | None:
    """Empty string and JSON null both mean absent.

    Ghidra's script writes the former for a missing function name; a
    hand-written fixture writes the latter. Neither should become the literal
    text ``"None"`` in a report.
    """
    if value is None:
        return None
    text = str(value)
    return text or None
