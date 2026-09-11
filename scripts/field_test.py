#!/usr/bin/env python3
"""Run the real pipeline over real, third-party binaries.

`precision_check.py` answers "what does the rule pack fire on for one
artifact". This answers the question that comes after it: *does the product
work* — unpack, scan, correlate, and gate — against software nobody wrote for
us, at sizes and shapes a synthetic corpus never produces.

It runs the production components in-process:

    Extractor  →  scan_file  →  correlate  →  evaluate (the release gate)

Everything except the Docker sandbox, MinIO, and the database. Those are
boundaries, not detection logic; what this exercises is the part that decides
whether an artifact ships.

    uv run python scripts/field_test.py var/fieldtest
    uv run python scripts/field_test.py var/fieldtest --rule aws_secret_key

The verdicts here are about *BARE*, not about the projects scanned. A
finding in somebody's released binary is a candidate false positive until a
human says otherwise, and the point of this harness is to make that triage
cheap.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

# `path_in_tree` uses → as its separator, and a Windows console defaults to
# cp1252, which cannot encode it. Without this the harness dies with a
# UnicodeEncodeError partway through printing results it already computed.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

from core.models import Evidence  # noqa: E402
from core.pipeline.correlator import correlate  # noqa: E402
from core.policy import GateFinding, Policy, evaluate  # noqa: E402
from core.rules import Match, RulePack, load_rule_pack, scan_file  # noqa: E402
from core.unpack import ExtractionBudget, Extractor  # noqa: E402
from core.unpack.extractor import (  # noqa: E402
    SEVENZIP_BINARY,
    should_scan,
)
from core.vocab import Severity  # noqa: E402

BOLD, DIM, RED, YELLOW, GREEN, RESET = (
    "\033[1m",
    "\033[2m",
    "\033[31m",
    "\033[33m",
    "\033[32m",
    "\033[0m",
)


@dataclass
class ArtifactReport:
    name: str
    size_bytes: int
    files_extracted: int = 0
    files_scanned: int = 0
    bytes_scanned: int = 0
    unpack_errors: list[str] = field(default_factory=list)
    truncated: bool = False
    matches: int = 0
    findings: int = 0
    by_severity: Counter[str] = field(default_factory=Counter)
    by_rule: Counter[str] = field(default_factory=Counter)
    decision: str = "?"
    violations: int = 0
    unpack_s: float = 0.0
    scan_s: float = 0.0

    @property
    def total_s(self) -> float:
        return self.unpack_s + self.scan_s


def _severity_colour(name: str) -> str:
    return {"critical": RED, "high": RED, "medium": YELLOW}.get(name, DIM)


def process(
    artifact: Path, pack: RulePack, workdir: Path, *, policy: Policy, keep: bool
) -> tuple[ArtifactReport, list[GateFinding], list[tuple[str, Match]]]:
    report = ArtifactReport(name=artifact.name, size_bytes=artifact.stat().st_size)
    extract_root = workdir / artifact.stem
    extract_root.mkdir(parents=True, exist_ok=True)

    # --- unpack ---------------------------------------------------------
    t0 = time.monotonic()
    budget = ExtractionBudget.for_input(report.size_bytes)
    extractor = Extractor(budget)
    result = extractor.extract_tree(artifact, extract_root, root_name=artifact.name)
    report.unpack_s = time.monotonic() - t0
    report.files_extracted = len(result.nodes)
    report.unpack_errors = list(result.errors)
    report.truncated = result.truncated

    # --- scan every file in the tree -------------------------------------
    # The root artifact is scanned too: an installer's own bytes carry strings
    # that none of its extracted members do.
    targets: list[tuple[str, Path]] = [(artifact.name, artifact)]
    for node in result.nodes:
        on_disk = extract_root / node.relative_path
        if on_disk.is_file() and should_scan(on_disk):
            targets.append((node.path_in_tree, on_disk))

    t0 = time.monotonic()
    evidence: list[Evidence] = []
    raw: list[tuple[str, Match]] = []
    artifact_paths: dict[str, str] = {}

    for index, (path_in_tree, on_disk) in enumerate(targets):
        try:
            matches = scan_file(str(on_disk), pack)
        except (OSError, ValueError) as exc:
            report.unpack_errors.append(f"{path_in_tree}: scan failed: {exc}")
            continue
        report.files_scanned += 1
        report.bytes_scanned += on_disk.stat().st_size

        artifact_id = f"art-{index}"
        artifact_paths[artifact_id] = path_in_tree
        for match in matches:
            raw.append((path_in_tree, match))
            evidence.append(
                Evidence(
                    run_id="field",
                    artifact_id=artifact_id,
                    analyzer="static",
                    rule_id=match.rule_id,
                    value_hash=match.value_hash,
                    value_masked=match.masked,
                    offset=match.offset,
                    encoding=match.encoding,
                    entropy=match.entropy,
                    context_snippet=match.context,
                )
            )
    report.scan_s = time.monotonic() - t0
    report.matches = len(evidence)

    # --- correlate, then gate --------------------------------------------
    correlation = correlate("field", evidence, pack, artifact_paths)
    report.findings = len(correlation.findings)

    first_path: dict[str, str] = {}
    for location in correlation.locations:
        first_path.setdefault(location.finding_id, location.path_in_tree)

    gate_findings: list[GateFinding] = []
    for finding in correlation.findings:
        severity = Severity(finding.severity)
        report.by_severity[severity.value] += 1
        report.by_rule[finding.rule_id] += 1
        gate_findings.append(
            GateFinding(
                id=finding.id,
                rule_id=finding.rule_id,
                category=finding.category,
                title=finding.title,
                severity=severity,
                status=str(finding.status),
                artifact_path=first_path.get(finding.id, artifact.name),
            )
        )

    verdict = evaluate(gate_findings, policy)
    report.decision = verdict.decision.value
    report.violations = len(verdict.violations)

    if not keep:
        shutil.rmtree(extract_root, ignore_errors=True)
    return report, gate_findings, raw


def main() -> int:
    parser = argparse.ArgumentParser(description="Field test against real binaries")
    parser.add_argument("corpus", type=Path, help="directory of artifacts")
    parser.add_argument("--rules", type=Path, default=REPO_ROOT / "detections")
    parser.add_argument("--rule", help="print every hit for this rule id")
    parser.add_argument("--top-rules", type=int, default=12)
    parser.add_argument("--keep", action="store_true", help="keep extracted trees")
    parser.add_argument("--json", type=Path, help="write the report as JSON")
    args = parser.parse_args()

    artifacts = sorted(
        p
        for p in args.corpus.iterdir()
        if p.is_file() and p.suffix.lower() not in (".json", ".sha256", ".txt")
    )
    if not artifacts:
        print(f"no artifacts in {args.corpus}", file=sys.stderr)
        return 2

    pack = load_rule_pack(args.rules)
    policy = Policy()  # the shipped defaults: block at high and above
    print(f"{BOLD}BARE field test{RESET}")
    print(f"  rule pack : {len(pack.rules)} rules ({pack.hash[:12]})")
    print(f"  policy    : block at/above {policy.block_at_or_above}, baseline all-new")
    print(f"  corpus    : {len(artifacts)} artifacts from {args.corpus}")
    if SEVENZIP_BINARY is None:
        # The unpack analyzer image installs p7zip-full, so the real pipeline
        # handles these formats. Say so plainly, rather than letting a
        # host-side limitation read as a product defect in the results below.
        print(
            f"  {YELLOW}note      : 7z not found on this host — MSI, CAB, NSIS and ISO "
            f"will not unpack.{RESET}"
        )
        print(
            "              The sandboxed unpack analyzer installs p7zip-full and "
            "does handle them."
        )
    print()

    workdir = Path(tempfile.mkdtemp(prefix="bare-field-"))
    reports: list[ArtifactReport] = []
    rule_hits: dict[str, list[tuple[str, str, Match]]] = defaultdict(list)

    try:
        for artifact in artifacts:
            report, _, raw = process(artifact, pack, workdir, policy=policy, keep=args.keep)
            reports.append(report)
            for path_in_tree, match in raw:
                rule_hits[match.rule_id].append((artifact.name, path_in_tree, match))
            _print_artifact(report)
    finally:
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)
        else:
            print(f"\n{DIM}extracted trees kept in {workdir}{RESET}")

    _print_summary(reports, rule_hits, args.top_rules)

    if args.rule:
        _print_rule_detail(args.rule, rule_hits)

    if args.json:
        args.json.write_text(
            json.dumps(
                [
                    {
                        "artifact": r.name,
                        "size_bytes": r.size_bytes,
                        "files_extracted": r.files_extracted,
                        "files_scanned": r.files_scanned,
                        "bytes_scanned": r.bytes_scanned,
                        "matches": r.matches,
                        "findings": r.findings,
                        "by_severity": dict(r.by_severity),
                        "by_rule": dict(r.by_rule),
                        "decision": r.decision,
                        "violations": r.violations,
                        "unpack_s": round(r.unpack_s, 2),
                        "scan_s": round(r.scan_s, 2),
                        "truncated": r.truncated,
                        "errors": r.unpack_errors[:20],
                    }
                    for r in reports
                ],
                indent=2,
            ),
            encoding="utf-8",
        )
        print(f"\nwrote {args.json}")

    return 0


def _print_artifact(r: ArtifactReport) -> None:
    colour = {"pass": GREEN, "blocked": RED, "inconclusive": YELLOW}.get(r.decision, DIM)
    print(f"{BOLD}{r.name}{RESET}  {DIM}({r.size_bytes / 1e6:.1f} MB){RESET}")
    print(
        f"  unpacked {r.files_extracted:>5} files, scanned {r.files_scanned:>5} "
        f"({r.bytes_scanned / 1e6:.0f} MB)  "
        f"{DIM}unpack {r.unpack_s:.1f}s / scan {r.scan_s:.1f}s{RESET}"
    )
    if r.by_severity:
        parts = [
            f"{_severity_colour(s)}{n} {s}{RESET}"
            for s, n in sorted(r.by_severity.items(), key=lambda kv: Severity(kv[0]).rank)
        ]
        print(f"  {r.findings} findings from {r.matches} matches: " + ", ".join(parts))
    else:
        print(f"  {r.findings} findings from {r.matches} matches")
    print(f"  gate: {colour}{r.decision.upper()}{RESET} ({r.violations} violations)")
    if r.truncated:
        print(f"  {YELLOW}extraction truncated by budget{RESET}")
    for err in r.unpack_errors[:3]:
        print(f"  {DIM}! {err[:110]}{RESET}")
    if len(r.unpack_errors) > 3:
        print(f"  {DIM}! … {len(r.unpack_errors) - 3} more{RESET}")
    print()


def _print_summary(
    reports: list[ArtifactReport],
    rule_hits: dict[str, list[tuple[str, str, Match]]],
    top: int,
) -> None:
    print(f"{BOLD}{'=' * 72}{RESET}")
    print(f"{BOLD}Summary{RESET}\n")

    total_findings = sum(r.findings for r in reports)
    total_scanned = sum(r.files_scanned for r in reports)
    total_bytes = sum(r.bytes_scanned for r in reports)
    total_time = sum(r.total_s for r in reports)
    blocked = [r for r in reports if r.decision == "blocked"]

    print(f"  artifacts      : {len(reports)}")
    print(f"  files scanned  : {total_scanned:,} ({total_bytes / 1e6:.0f} MB)")
    throughput = total_bytes / 1e6 / max(total_time, 0.01)
    print(f"  wall time      : {total_time:.1f}s ({throughput:.1f} MB/s)")
    print(f"  findings       : {total_findings}")
    print(f"  gate blocked   : {len(blocked)}/{len(reports)}")
    if blocked:
        print(f"                   {', '.join(r.name for r in blocked)}")

    aggregate: Counter[str] = Counter()
    for r in reports:
        aggregate.update(r.by_rule)
    if aggregate:
        print(f"\n  {BOLD}rules by hit count{RESET}  {DIM}(every hit is a candidate FP){RESET}")
        for rule_id, count in aggregate.most_common(top):
            spread = len({a for a, _, _ in rule_hits.get(rule_id, [])})
            print(f"    {count:>5}  {rule_id:<38} {DIM}in {spread} artifact(s){RESET}")
    print()


def _print_rule_detail(rule_id: str, rule_hits: dict[str, list[tuple[str, str, Match]]]) -> None:
    hits = rule_hits.get(rule_id, [])
    print(f"{BOLD}Every hit for {rule_id} ({len(hits)}){RESET}\n")
    for artifact, path_in_tree, match in hits[:60]:
        print(f"  {artifact}")
        print(f"    {DIM}{path_in_tree} @ {match.offset} ({match.encoding}){RESET}")
        print(f"    value  : {match.masked}")
        if match.context:
            print(f"    context: {match.context[:150]!r}")
        print()
    if len(hits) > 60:
        print(f"  {DIM}… {len(hits) - 60} more{RESET}")


if __name__ == "__main__":
    raise SystemExit(main())
