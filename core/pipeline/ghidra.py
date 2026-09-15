"""S4: Ghidra cross-references for findings the static pass already made.

Enrichment, not detection (ADR-0034). The static pass says a secret-shaped
string sits at offset 0x8200 of ``broker.exe``; this stage asks Ghidra which
function reads it and writes the answer onto the finding's location. It cannot
create a finding, alter one, or change what the release gate decides — so it
runs after the scan has finished, on the slow ``ghidra`` lane, and a Ghidra
failure is recorded on its own stage without degrading a run whose findings are
complete.

Only executables that carry a finding are analysed, and only at the offsets
those findings point to. Ghidra over a whole installer tree is hours; over the
three binaries that have something in them it is seconds.

The bytes come from object storage, because the scan's staging directory is
deleted when the scan ends (it is a plaintext copy of the customer's artifact).
What survives is the root artifact and every evidence-bearing extracted file
under ``RETAIN_EXTRACTED_MAX_BYTES``; a larger one is noted on the stage as not
retained rather than silently left out.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.analyzers.ghidra_result import GhidraResult
from core.config import get_settings
from core.models import Artifact, FindingLocation, Run, RunManifest, RunStage
from core.models.enums import ArtifactKind, RunStatus, StageStatus
from core.pipeline.logs import redact_log_text
from core.pipeline.scan import (
    _analyzer_nano_cpus,
    _grant_analyzer_access,
    _live_log,
    _read_result,
    _record_stage,
)
from core.rules import load_rule_pack
from core.rules.model import RulePack
from core.sandbox import BindMount, MountMode, SandboxSpec, driver_from_settings
from core.sandbox.images import analyzer_image
from core.sandbox.spec import INPUT_DIR, OUTPUT_DIR
from core.storage import get_object_store

log = structlog.get_logger(__name__)

ANALYZER = "ghidra"

# The container's wall clock. The analyzer's own budget sits inside it, so a
# slow last binary is recorded by the analyzer as skipped rather than killed,
# unrecorded, by the watchdog along with every result before it.
GHIDRA_TIMEOUT_S = 1800
ANALYZER_BUDGET_S = 1500
PER_BINARY_TIMEOUT_S = 600

# Each binary is a JVM start plus auto-analysis. The binaries carrying the most
# findings go first, so when the cap bites it drops the least evidence.
MAX_BINARIES = 16
MAX_OFFSETS_PER_BINARY = 256

# What Ghidra is worth running on. Installers and archives were opened by the
# unpack stage, and their contents are artifacts of their own; .NET assemblies
# are PE files whose code is IL that Ghidra's native analysis does not follow.
EXECUTABLE_KINDS = (ArtifactKind.PE, ArtifactKind.ELF, ArtifactKind.MACHO)

# A failed run has no findings worth enriching. A degraded one does: its
# findings are real, the report just cannot promise they are all of them.
ENRICHABLE_RUN_STATUSES = (RunStatus.COMPLETED, RunStatus.DEGRADED)

# A stage in one of these states means the work is under way or done. A second
# delivery of the same task — Celery is at-least-once — must not start another
# 2 GB JVM over the same binaries.
_ALREADY_HANDLED = (StageStatus.RUNNING, StageStatus.COMPLETED, StageStatus.TRUNCATED)


@dataclass(slots=True)
class BinaryTarget:
    artifact_id: str
    path_in_tree: str
    storage_key: str
    offsets: list[int]

    @property
    def staged_path(self) -> str:
        """Where the analyzer finds the bytes, under ``/input/binaries``.

        The artifact id rather than the file's own name: names come out of the
        customer's archive and can be anything, ``..`` included.
        """
        return self.artifact_id


@dataclass(slots=True)
class EnrichmentOutcome:
    run_id: str
    status: str
    binaries: int = 0
    resolved: int = 0
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "status": str(self.status),
            "binaries": self.binaries,
            "resolved": self.resolved,
            "detail": self.detail,
        }


def select_targets(
    session: Session,
    run_id: str,
    *,
    max_binaries: int = MAX_BINARIES,
    max_offsets: int = MAX_OFFSETS_PER_BINARY,
) -> tuple[list[BinaryTarget], list[str]]:
    """The executables worth analysing, and a note for each one left out."""
    rows = session.execute(
        select(Artifact.id, Artifact.path_in_tree, Artifact.storage_key, FindingLocation.offset)
        .join(FindingLocation, FindingLocation.artifact_id == Artifact.id)
        .where(
            FindingLocation.run_id == run_id,
            FindingLocation.offset.is_not(None),
            Artifact.run_id == run_id,
            Artifact.kind.in_([str(kind) for kind in EXECUTABLE_KINDS]),
        )
    ).all()

    offsets: dict[str, set[int]] = {}
    described: dict[str, tuple[str, str | None]] = {}
    for artifact_id, path_in_tree, storage_key, offset in rows:
        offsets.setdefault(artifact_id, set()).add(int(offset))
        described[artifact_id] = (path_in_tree, storage_key)

    notes: list[str] = []
    candidates: list[BinaryTarget] = []
    for artifact_id, found in offsets.items():
        path_in_tree, storage_key = described[artifact_id]
        if not storage_key:
            notes.append(f"{path_in_tree}: bytes not retained, so not analysed")
            continue
        if len(found) > max_offsets:
            notes.append(f"{path_in_tree}: only the first {max_offsets} offsets were analysed")
        candidates.append(
            BinaryTarget(
                artifact_id=artifact_id,
                path_in_tree=path_in_tree,
                storage_key=storage_key,
                offsets=sorted(found)[:max_offsets],
            )
        )

    # Most findings first, then path: deterministic, and the cap drops the
    # binaries with the least in them.
    candidates.sort(key=lambda target: (-len(target.offsets), target.path_in_tree))
    for dropped in candidates[max_binaries:]:
        notes.append(f"{dropped.path_in_tree}: over the {max_binaries}-binary cap")
    return candidates[:max_binaries], sorted(notes)


def enrich_run(run_id: str, session: Session) -> EnrichmentOutcome:
    """Run S4 over one finished run and record what it established."""
    run = session.get(Run, run_id)
    if run is None:
        raise LookupError(f"run {run_id} not found")
    if RunStatus(run.status) not in ENRICHABLE_RUN_STATUSES:
        return EnrichmentOutcome(run_id, "not_applicable", detail=f"run is {run.status}")
    if _already_handled(session, run_id):
        return EnrichmentOutcome(run_id, "already_handled", detail="a ghidra stage exists")

    root = session.scalars(
        select(Artifact).where(Artifact.run_id == run_id, Artifact.parent_id.is_(None))
    ).first()
    stage = RunStage(
        run_id=run_id,
        artifact_id=root.id if root else None,
        analyzer=ANALYZER,
        started_at=datetime.now(UTC),
    )
    session.add(stage)

    settings = get_settings()
    pack = load_rule_pack(Path(settings.repo_root) / "detections")

    targets, notes = select_targets(session, run_id)
    if not targets:
        # Recorded rather than left absent, so "Ghidra did not run" and "Ghidra
        # is not deployed" are distinguishable on the run page.
        stage.status = StageStatus.SKIPPED
        stage.finished_at = datetime.now(UTC)
        stage.duration_s = 0.0
        stage.error = _joined(["no executable has a finding at a file offset", *notes], pack)
        return EnrichmentOutcome(run_id, StageStatus.SKIPPED, detail=stage.error)

    stage.status = StageStatus.RUNNING
    # Committed before the container starts: the run page can show the stage
    # working, and a worker that dies mid-stage leaves a row the recovery sweep
    # can find and close (fail_stale_enrichment_stages).
    session.commit()

    work = Path(settings.run_root) / run_id / ANALYZER
    try:
        payload = _run_analyzer(run, stage, targets, work, pack)
    except Exception as exc:
        log.exception("ghidra.failed", run_id=run_id)
        stage.status = StageStatus.FAILED
        stage.finished_at = datetime.now(UTC)
        stage.error = redact_log_text(str(exc), pack=pack)[:2000]
        return EnrichmentOutcome(
            run_id, StageStatus.FAILED, binaries=len(targets), detail=stage.error
        )
    finally:
        # The binaries are the customer's, staged in plaintext. Same rule as
        # the scan's own staging: they do not outlive the stage.
        shutil.rmtree(work, ignore_errors=True)

    if payload is None:
        if StageStatus(stage.status) is StageStatus.COMPLETED:
            stage.status = StageStatus.FAILED
            stage.error = "the analyzer exited without writing a result"
        return EnrichmentOutcome(run_id, stage.status, binaries=len(targets), detail=stage.error)

    result = GhidraResult.from_json(payload)
    resolved = apply_xrefs(
        session, run_id, result, {t.staged_path: t.artifact_id for t in targets}, pack=pack
    )
    stage.evidence_count = resolved
    _summarise_stage(stage, result, {t.staged_path: t.path_in_tree for t in targets}, notes, pack)
    _record_in_manifest(session, run_id, result, stage.image_digest)

    log.info(
        "ghidra.completed",
        run_id=run_id,
        status=str(stage.status),
        binaries=len(targets),
        resolved=resolved,
        ghidra_version=result.ghidra_version,
    )
    return EnrichmentOutcome(
        run_id, stage.status, binaries=len(targets), resolved=resolved, detail=stage.error
    )


def apply_xrefs(
    session: Session,
    run_id: str,
    result: GhidraResult,
    artifact_by_path: dict[str, str],
    *,
    pack: RulePack,
) -> int:
    """Write each resolved function name onto its finding locations.

    Returns how many locations gained one. Only ``xref_function`` is written:
    offsets, severity and every other field the rule produced stay exactly as
    the deterministic pass left them (§9).
    """
    wanted: dict[tuple[str, int], str] = {}
    for (path, offset), name in result.xref_functions().items():
        artifact_id = artifact_by_path.get(path)
        if artifact_id is None:
            continue
        # A function name is text from the customer's binary. It is not a
        # secret by nature, but it passes the same detectors the stage logs do
        # before it is stored beside a finding.
        wanted[(artifact_id, offset)] = redact_log_text(name, pack=pack)[:255]
    if not wanted:
        return 0

    resolved = 0
    locations = session.scalars(
        select(FindingLocation).where(
            FindingLocation.run_id == run_id,
            FindingLocation.artifact_id.in_(sorted({artifact for artifact, _ in wanted})),
            FindingLocation.offset.is_not(None),
        )
    ).all()
    for location in locations:
        function = wanted.get((location.artifact_id, int(location.offset or 0)))
        if function:
            location.xref_function = function
            resolved += 1
    return resolved


def _run_analyzer(
    run: Run,
    stage: RunStage,
    targets: list[BinaryTarget],
    work: Path,
    pack: RulePack,
) -> dict[str, Any] | None:
    inputs = work / "in"
    results = work / "out"
    binaries = inputs / "binaries"
    binaries.mkdir(parents=True, exist_ok=True)
    results.mkdir(parents=True, exist_ok=True)

    store = get_object_store()
    for target in targets:
        store.download_to(target.storage_key, binaries / target.staged_path)
    order = {"binaries": [{"path": t.staged_path, "offsets": t.offsets} for t in targets]}
    (inputs / "targets.json").write_text(json.dumps(order, sort_keys=True), encoding="utf-8")
    _grant_analyzer_access(results)

    driver = driver_from_settings()
    try:
        result = driver.run(
            SandboxSpec(
                image=analyzer_image(ANALYZER),
                run_id=run.id,
                analyzer=ANALYZER,
                command=(
                    "--total-timeout",
                    str(ANALYZER_BUDGET_S),
                    "--per-binary-timeout",
                    str(PER_BINARY_TIMEOUT_S),
                    "--max-binaries",
                    str(MAX_BINARIES),
                ),
                timeout_s=GHIDRA_TIMEOUT_S,
                nano_cpus=_analyzer_nano_cpus(),
                mem_limit_bytes=_ghidra_memory_bytes(),
                mounts=(
                    BindMount(str(inputs), INPUT_DIR, MountMode.READ_ONLY),
                    BindMount(str(results), OUTPUT_DIR, MountMode.READ_WRITE),
                ),
            ),
            on_output=_live_log(stage, pack),
        )
    finally:
        driver.close()

    _record_stage(stage, result, pack=pack)
    return _read_result(results)


def _summarise_stage(
    stage: RunStage,
    result: GhidraResult,
    labels: dict[str, str],
    notes: list[str],
    pack: RulePack,
) -> None:
    """Turn per-binary outcomes into the stage's status and message.

    Only when the container itself finished: a timeout or OOM of the whole
    container was already recorded by ``_record_stage`` and says more than any
    partial result could.
    """
    if StageStatus(stage.status) is not StageStatus.COMPLETED:
        return

    analyzed = [b for b in result.binaries if b.status == "analyzed"]
    problems = [
        f"{labels.get(b.path, b.path)}: {b.status}" + (f" ({b.reason})" if b.reason else "")
        for b in result.binaries
        if b.status != "analyzed"
    ]
    if result.degraded_binaries and not analyzed:
        stage.status = StageStatus.FAILED
    elif result.truncated:
        stage.status = StageStatus.TRUNCATED
    stage.error = _joined([*problems, *notes], pack) if problems or notes else None


def _record_in_manifest(
    session: Session, run_id: str, result: GhidraResult, image_digest: str | None
) -> None:
    """Ghidra's version belongs in the manifest with every other tool's.

    Its analysis changes between releases, so a run whose locations name
    functions cannot be reproduced without knowing which Ghidra named them.
    """
    manifest = session.scalars(select(RunManifest).where(RunManifest.run_id == run_id)).first()
    if manifest is None:
        return
    # Reassigned rather than mutated in place: a plain JSON column does not
    # notice an in-place change, and the update would silently not be written.
    manifest.tool_versions = {**(manifest.tool_versions or {}), "ghidra": result.ghidra_version}
    manifest.image_digests = {**(manifest.image_digests or {}), ANALYZER: image_digest or "unknown"}


def _already_handled(session: Session, run_id: str) -> bool:
    existing = session.scalars(
        select(RunStage.status).where(RunStage.run_id == run_id, RunStage.analyzer == ANALYZER)
    ).all()
    return any(StageStatus(status) in _ALREADY_HANDLED for status in existing)


def _joined(parts: list[str], pack: RulePack) -> str:
    return redact_log_text("; ".join(parts), pack=pack)[:2000]


def _ghidra_memory_bytes() -> int:
    return int(max(1.0, get_settings().ghidra_memory_gb) * 1024**3)
