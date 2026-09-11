"""PDF release records.

Written against the PDF format directly rather than pulled from a library, and
that is a deliberate trade worth stating. ReportLab and WeasyPrint are both
better typesetters than this. Neither is worth adding here: the output is a
fixed, tabular document with no flowing text or images, this product ships into
air-gapped networks where every dependency is another thing to vendor and
audit, and `core/` is kept to boring, pinned, justified packages (§8). The
whole generator is stdlib.

The document is **deterministic**: the same run produces byte-identical PDF.
That is not a nicety — a release record whose bytes change between renderings
cannot be hashed, cannot be signed, and cannot be an audit artifact. So there
is no creation timestamp drawn from the clock, no random object ids, and the
run's own data is the only input.

Only masked values appear. A PDF is emailed, archived and printed, and it is
the last place a credential should be legible (§14).
"""

from __future__ import annotations

import zlib
from dataclasses import dataclass, field
from datetime import datetime

from core.policy import GateVerdict
from core.vocab import Severity

# The 14 fonts every conforming PDF reader has built in, so nothing is
# embedded and the file stays small and portable.
FONT_REGULAR = "Helvetica"
FONT_BOLD = "Helvetica-Bold"
FONT_MONO = "Courier"

PAGE_WIDTH = 595.28  # A4 at 72 dpi
PAGE_HEIGHT = 841.89
MARGIN = 48.0
CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN

# Severity colours, converted from the console's oklch palette to sRGB. Kept in
# step with `web/app/globals.css` by hand — there are five of them and a build
# step to share one palette across a stylesheet and a PDF writer would cost
# more than it saves.
SEVERITY_RGB: dict[str, tuple[float, float, float]] = {
    "critical": (0.839, 0.243, 0.192),
    "high": (0.882, 0.522, 0.180),
    "medium": (0.831, 0.663, 0.157),
    "low": (0.361, 0.569, 0.831),
    "info": (0.478, 0.494, 0.541),
}
INK = (0.11, 0.12, 0.14)
INK_MUTED = (0.40, 0.42, 0.46)
RULE = (0.82, 0.83, 0.85)
OK_RGB = (0.157, 0.612, 0.404)


def _escape(text: str) -> str:
    """PDF strings are parenthesised; three characters need escaping."""
    return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _latin1(text: str) -> str:
    """The base-14 fonts are Latin-1. Anything outside it — a bullet in a rule
    description, a dash in a path — becomes a plain ASCII stand-in rather than
    a mojibake box."""
    # Every key here trips the ambiguous-character lint, which is exactly the
    # point: these are the typographic characters being normalised away, so
    # they have to appear literally. Scoped off in pyproject rather than with
    # ten inline suppressions.
    swaps = {
        "—": "-",
        "–": "-",
        "‘": "'",
        "’": "'",
        "“": '"',
        "”": '"',
        "…": "...",
        "→": "->",
        "·": "-",
        "•": "-",
        " ": " ",
    }
    for bad, good in swaps.items():
        text = text.replace(bad, good)
    return text.encode("latin-1", "replace").decode("latin-1")


def _width(text: str, size: float, bold: bool = False) -> float:
    """Helvetica advance widths, approximated.

    Exact metrics would mean shipping the AFM tables. This is close enough to
    keep columns from colliding, and every column is width-clipped anyway.
    """
    narrow = sum(1 for c in text if c in "iljtfIr .,:;'|!()[]")
    wide = sum(1 for c in text if c in "mwMW@")
    other = len(text) - narrow - wide
    factor = 0.56 if bold else 0.52
    return (narrow * 0.28 + wide * 0.85 + other * factor) * size


def _clip(text: str, size: float, limit: float, bold: bool = False) -> str:
    if _width(text, size, bold) <= limit:
        return text
    out = text
    while out and _width(out + "...", size, bold) > limit:
        out = out[:-1]
    return (out + "...") if out else ""


@dataclass
class _Page:
    """One page's content stream, built as text operators."""

    ops: list[str] = field(default_factory=list)
    y: float = PAGE_HEIGHT - MARGIN


class PdfWriter:
    """Minimal PDF 1.4 writer: pages, text, rules, filled rectangles."""

    def __init__(self) -> None:
        self.pages: list[_Page] = []
        self._new_page()

    # -- page management --------------------------------------------------

    def _new_page(self) -> _Page:
        page = _Page()
        self.pages.append(page)
        return page

    @property
    def page(self) -> _Page:
        return self.pages[-1]

    def space(self, amount: float) -> None:
        self.page.y -= amount

    def need(self, amount: float) -> None:
        """Break to a new page when the next block would not fit."""
        if self.page.y - amount < MARGIN + 28:
            self._new_page()

    # -- drawing ----------------------------------------------------------

    def text(
        self,
        value: str,
        *,
        size: float = 9.5,
        bold: bool = False,
        mono: bool = False,
        colour: tuple[float, float, float] = INK,
        x: float = MARGIN,
        leading: float = 0.0,
    ) -> None:
        font = FONT_MONO if mono else (FONT_BOLD if bold else FONT_REGULAR)
        r, g, b = colour
        self.page.ops.append(
            f"BT /{font} {size:.2f} Tf {r:.3f} {g:.3f} {b:.3f} rg "
            f"1 0 0 1 {x:.2f} {self.page.y:.2f} Tm ({_escape(_latin1(value))}) Tj ET"
        )
        if leading:
            self.page.y -= leading

    def rule(self, *, colour: tuple[float, float, float] = RULE, width: float = 0.6) -> None:
        r, g, b = colour
        self.page.ops.append(
            f"{r:.3f} {g:.3f} {b:.3f} RG {width:.2f} w "
            f"{MARGIN:.2f} {self.page.y:.2f} m {PAGE_WIDTH - MARGIN:.2f} {self.page.y:.2f} l S"
        )

    def box(
        self, x: float, width: float, height: float, colour: tuple[float, float, float]
    ) -> None:
        r, g, b = colour
        self.page.ops.append(
            f"{r:.3f} {g:.3f} {b:.3f} rg "
            f"{x:.2f} {self.page.y - height + 2:.2f} {width:.2f} {height:.2f} re f"
        )

    def wrap(
        self,
        value: str,
        *,
        size: float = 9.5,
        colour: tuple[float, float, float] = INK_MUTED,
        width: float = CONTENT_WIDTH,
        leading: float = 12.0,
        x: float = MARGIN,
    ) -> None:
        words = _latin1(value).split()
        line = ""
        for word in words:
            candidate = f"{line} {word}".strip()
            if _width(candidate, size) > width and line:
                self.text(line, size=size, colour=colour, x=x, leading=leading)
                line = word
            else:
                line = candidate
        if line:
            self.text(line, size=size, colour=colour, x=x, leading=leading)

    # -- serialisation ----------------------------------------------------

    def build(self, title: str) -> bytes:
        objects: list[bytes] = []

        def add(body: bytes) -> int:
            objects.append(body)
            return len(objects)

        font_ids = {
            name: add(
                f"<< /Type /Font /Subtype /Type1 /BaseFont /{name} "
                f"/Encoding /WinAnsiEncoding >>".encode("latin-1")
            )
            for name in (FONT_REGULAR, FONT_BOLD, FONT_MONO)
        }

        content_ids: list[int] = []
        for page in self.pages:
            stream = "\n".join(page.ops).encode("latin-1", "replace")
            packed = zlib.compress(stream, 9)
            content_ids.append(
                add(
                    b"<< /Length "
                    + str(len(packed)).encode()
                    + b" /Filter /FlateDecode >>\nstream\n"
                    + packed
                    + b"\nendstream"
                )
            )

        pages_id = len(objects) + len(self.pages) + 1
        page_ids: list[int] = []
        resources = "/Font << " + " ".join(
            f"/{name} {oid} 0 R" for name, oid in font_ids.items()
        ) + " >>"
        for content_id in content_ids:
            page_ids.append(
                add(
                    f"<< /Type /Page /Parent {pages_id} 0 R "
                    f"/MediaBox [0 0 {PAGE_WIDTH:.2f} {PAGE_HEIGHT:.2f}] "
                    f"/Resources << {resources} >> /Contents {content_id} 0 R >>".encode("latin-1")
                )
            )

        kids = " ".join(f"{pid} 0 R" for pid in page_ids)
        add(f"<< /Type /Pages /Count {len(page_ids)} /Kids [{kids}] >>".encode("latin-1"))
        info_id = add(
            f"<< /Title ({_escape(_latin1(title))}) /Producer (BARE) >>".encode("latin-1")
        )
        catalog_id = add(f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("latin-1"))

        out = bytearray(b"%PDF-1.4\n")
        offsets = [0]
        for index, body in enumerate(objects, start=1):
            offsets.append(len(out))
            out += f"{index} 0 obj\n".encode() + body + b"\nendobj\n"

        xref_at = len(out)
        out += f"xref\n0 {len(objects) + 1}\n".encode()
        out += b"0000000000 65535 f \n"
        for offset in offsets[1:]:
            out += f"{offset:010d} 00000 n \n".encode()
        out += (
            f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_id} 0 R "
            f"/Info {info_id} 0 R >>\nstartxref\n{xref_at}\n%%EOF\n"
        ).encode()
        return bytes(out)


@dataclass(frozen=True, slots=True)
class ReportFinding:
    severity: Severity
    rule_id: str
    title: str
    value_masked: str
    path_in_tree: str
    offset: int | None = None
    is_new: bool = True


@dataclass(frozen=True, slots=True)
class ReportData:
    """Everything the document needs, already projected.

    A frozen input rather than a live session: a report generator that queries
    the database mid-render is one that can produce two different documents for
    the same run.
    """

    run_id: str
    artifact_name: str
    artifact_sha256: str
    artifact_size_bytes: int
    attested_by: str
    attestation_reference: str
    scanned_at: datetime | None
    findings: list[ReportFinding]
    counts_by_severity: dict[str, int]
    files_analysed: int
    verdict: GateVerdict | None = None
    rule_pack_version: str = ""
    rule_pack_hash: str = ""
    manifest_fingerprint: str = ""
    tool_versions: dict[str, str] = field(default_factory=dict)
    degraded_stages: tuple[str, ...] = ()


def render_report(data: ReportData) -> bytes:
    """Build the release record. Deterministic for a given ``ReportData``."""
    pdf = PdfWriter()

    _cover(pdf, data)
    _summary(pdf, data)
    _findings(pdf, data)
    _methodology(pdf, data)

    return pdf.build(f"BARE release record - {data.artifact_name}")


def _cover(pdf: PdfWriter, data: ReportData) -> None:
    pdf.text("BARE", size=8, bold=True, colour=INK_MUTED, leading=6)
    pdf.text("Release record", size=25, bold=True, leading=30)

    pdf.text(_clip(data.artifact_name, 13, CONTENT_WIDTH), size=13, leading=16)
    pdf.text(
        f"sha256 {data.artifact_sha256[:48]}", size=8.5, mono=True, colour=INK_MUTED, leading=13
    )

    scanned = data.scanned_at.strftime("%Y-%m-%d %H:%M UTC") if data.scanned_at else "unknown"
    pdf.text(
        f"{data.artifact_size_bytes:,} bytes  |  {data.files_analysed:,} files analysed  "
        f"|  scanned {scanned}",
        size=8.5,
        colour=INK_MUTED,
        leading=22,
    )

    # The verdict, given the room it deserves.
    if data.verdict is not None:
        decision = data.verdict.decision.value.upper()
        colour = {
            "PASS": OK_RGB,
            "BLOCKED": SEVERITY_RGB["critical"],
            "INCONCLUSIVE": SEVERITY_RGB["high"],
        }.get(decision, INK)
        pdf.rule()
        pdf.space(26)
        pdf.text(decision, size=30, bold=True, colour=colour, leading=18)
        pdf.text(
            f"Policy '{data.verdict.policy_name}'  |  exit code {data.verdict.exit_code}",
            size=9,
            colour=INK_MUTED,
            leading=16,
        )
        pdf.wrap(_verdict_sentence(data.verdict), size=9.5, leading=12)
        pdf.space(6)
        pdf.rule()
        pdf.space(20)

    pdf.text("Authorisation", size=8, bold=True, colour=INK_MUTED, leading=13)
    pdf.text(f"Attested by {data.attested_by}", size=9.5, leading=12)
    pdf.text(data.attestation_reference or "-", size=9, colour=INK_MUTED, leading=16)
    pdf.wrap(
        "No artifact is analysed without an attestation of authorisation. It is "
        "recorded in the audit log and reproduced here.",
        size=8.5,
        leading=11,
    )


def _verdict_sentence(verdict: GateVerdict) -> str:
    if verdict.decision.value == "pass":
        return (
            "Nothing this build introduced meets the policy floor. Inherited findings "
            "remain in the artifact and are listed below."
        )
    if verdict.decision.value == "inconclusive":
        return (
            "The scan did not complete, so this artifact was not fully examined. A partial "
            "scan cannot support a pass."
        )
    return (
        f"{len(verdict.violations)} finding(s) meet or exceed the policy floor. "
        "A release gated on this policy stops here."
    )


def _summary(pdf: PdfWriter, data: ReportData) -> None:
    pdf.need(150)
    pdf.space(24)
    pdf.text("Findings by severity", size=12, bold=True, leading=18)

    total = sum(data.counts_by_severity.values()) or 1
    for severity in ("critical", "high", "medium", "low", "info"):
        count = data.counts_by_severity.get(severity, 0)
        if not count:
            continue
        colour = SEVERITY_RGB[severity]
        pdf.text(severity.upper(), size=8, bold=True, colour=colour)
        # A proportional bar reads as a distribution without a legend.
        bar = max(3.0, (count / total) * (CONTENT_WIDTH - 200))
        pdf.box(MARGIN + 70, bar, 7, colour)
        pdf.text(str(count), size=9.5, bold=True, x=MARGIN + 76 + bar, leading=15)

    if data.degraded_stages:
        pdf.space(8)
        pdf.text("Scan completeness", size=9, bold=True, colour=SEVERITY_RGB["high"], leading=12)
        pdf.wrap(
            "This artifact was not fully examined: "
            + "; ".join(data.degraded_stages)
            + ". Findings below are partial.",
            size=8.5,
            leading=11,
        )


def _findings(pdf: PdfWriter, data: ReportData) -> None:
    pdf.need(120)
    pdf.space(26)
    pdf.text("Findings", size=12, bold=True, leading=8)
    pdf.rule()
    pdf.space(14)

    if not data.findings:
        pdf.text("No findings.", size=9.5, colour=INK_MUTED, leading=14)
        return

    for finding in data.findings:
        pdf.need(46)
        colour = SEVERITY_RGB.get(finding.severity.value, INK_MUTED)

        pdf.box(MARGIN, 3, 11, colour)
        pdf.text(finding.severity.value.upper(), size=7.5, bold=True, colour=colour, x=MARGIN + 9)
        pdf.text(
            _clip(finding.title, 10, CONTENT_WIDTH - 150, bold=True),
            size=10,
            bold=True,
            x=MARGIN + 62,
        )
        if finding.is_new:
            pdf.text(
                "NEW",
                size=7.5,
                bold=True,
                colour=SEVERITY_RGB["high"],
                x=PAGE_WIDTH - MARGIN - 26,
            )
        pdf.space(13)

        pdf.text(finding.value_masked, size=8.5, mono=True, colour=INK, x=MARGIN + 62, leading=11)

        where = finding.path_in_tree
        if finding.offset is not None:
            where += f" @ 0x{finding.offset:x}"
        pdf.text(
            _clip(where, 8, CONTENT_WIDTH - 70, ),
            size=8,
            mono=True,
            colour=INK_MUTED,
            x=MARGIN + 62,
            leading=10,
        )
        pdf.text(finding.rule_id, size=7.5, colour=INK_MUTED, x=MARGIN + 62, leading=15)

    pdf.space(4)
    pdf.wrap(
        "Values are masked. This document is archived and circulated; the plaintext of a "
        "candidate secret is never written into it.",
        size=8,
        leading=10,
    )


def _methodology(pdf: PdfWriter, data: ReportData) -> None:
    pdf.need(160)
    pdf.space(24)
    pdf.text("Methodology", size=12, bold=True, leading=8)
    pdf.rule()
    pdf.space(14)

    pdf.wrap(
        "Every finding above was produced by a deterministic rule. No result in this "
        "document was created, altered or removed by a language model.",
        size=9,
        leading=12,
    )
    pdf.space(8)

    rows = [
        ("Run", data.run_id),
        ("Manifest fingerprint", data.manifest_fingerprint or "-"),
        ("Rule pack", f"{data.rule_pack_version} ({data.rule_pack_hash[:16]})"),
    ] + [(name, version) for name, version in sorted(data.tool_versions.items())]

    for label, value in rows:
        pdf.need(16)
        pdf.text(label, size=8, colour=INK_MUTED)
        pdf.text(_clip(str(value), 8.5, CONTENT_WIDTH - 150), size=8.5, mono=True, x=MARGIN + 145,
                 leading=12)

    pdf.space(10)
    pdf.wrap(
        "Two runs sharing a manifest fingerprint produce identical findings. The fingerprint "
        "covers the artifact hash, the rule pack, the analyzer image digests and the tool "
        "versions above.",
        size=8,
        leading=10,
    )
