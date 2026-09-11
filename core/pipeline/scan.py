"""The scan pipeline: stage, unpack, scan, correlate, persist.

Two analyzer passes rather than one container per file. The unpack container
walks the artifact recursively and writes the whole tree to disk; the static
container then scans that entire tree in a single pass. A container per
extracted file would turn a 400-file installer into 400 container starts —
minutes of pure overhead for milliseconds of work.

Provenance survives the whole way: every finding location carries the path that
produced it, so the report says
``release.zip → payload.tar.gz → config/prod.json`` rather than naming a
temporary directory.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

import structlog
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from core.config import BARE_VERSION, get_settings
from core.models import Artifact, Evidence, Run, RunManifest, RunStage, Suppression
from core.models.base import new_uuid
from core.models.enums import RunStatus, StageStatus
from core.pipeline.correlator import correlate
from core.pipeline.stages import degraded_stages, describe_degraded
from core.rules import load_rule_pack
from core.sandbox import (
    BindMount,
    MountMode,
    SandboxResult,
    SandboxSpec,
    SandboxStatus,
    driver_from_settings,
)
from core.sandbox.images import analyzer_image
from core.sandbox.spec import INPUT_DIR, OUTPUT_DIR
from core.storage import get_object_store

log = structlog.get_logger(__name__)

RULES_MOUNT = PurePosixPath("/rules")

UNPACK_TIMEOUT_S = 900
STATIC_TIMEOUT_S = 1800
# Extracted files above this are stored in MinIO; smaller ones are analysed and
# discarded. Retaining every file from every installer would dominate storage
# for little benefit — findings carry their own context snippets.
RETAIN_EXTRACTED_MAX_BYTES = 32 * 1024 * 1024

# Strings no rule matched, sampled for the AI rule-author loop. Collected on
# every scan because it costs one extra pass and is the only honest answer to
# "what did we miss?" — see core/llm/discovery.py.
RESIDUE_SAMPLE_SIZE = 400


@dataclass(slots=True)
class ScanOutcome:
    run_id: str
    status: RunStatus
    finding_count: int = 0
    evidence_count: int = 0
    suppressed_count: int = 0
    artifact_count: int = 1
    error: str | None = None


class RunAlreadyClaimedError(RuntimeError):
    """Another worker is already scanning this run."""


def _claim(run_id: str, session: Session) -> bool:
    """Move the run from `queued` to `running`, atomically.

    Returns False if somebody else got there first.

    A conditional UPDATE rather than read-then-write, because Celery delivers
    at least once and two workers can hold the same message. Observed in the
    field: the orphan sweep requeued a run at age 399s while its original task
    was still inside the static analyzer, and a second `scan_run` was
    dispatched for the same 213 MB artifact — two sets of analyzer containers
    racing to write the same rows. The commit below closes the window that
    made the run *look* abandoned; this closes the race itself, which
    at-least-once delivery can open for other reasons too.
    """
    claimed = session.execute(
        update(Run)
        .where(Run.id == run_id, Run.status == RunStatus.QUEUED)
        .values(status=RunStatus.RUNNING, started_at=datetime.now(UTC))
    ).rowcount
    # Committed rather than flushed: the whole scan runs inside one
    # transaction, so until this lands every other connection still reads the
    # run as `queued` — eight minutes of a dashboard showing "queued" while two
    # analyzer containers work, and eight minutes in which the orphan sweep is
    # entitled to conclude the task was lost.
    session.commit()
    return bool(claimed)


def run_scan(run_id: str, session: Session) -> ScanOutcome:
    """Execute a full scan. Owns the run's state transitions."""
    run = session.get(Run, run_id)
    if run is None:
        raise LookupError(f"run {run_id} not found")

    if not _claim(run_id, session):
        # Not an error: a duplicate delivery is expected occasionally, and the
        # worker that holds the claim is doing the work. Returning the run's
        # actual state keeps this honest in the task result.
        session.refresh(run)
        log.warning("scan.already_claimed", run_id=run_id, status=str(run.status))
        raise RunAlreadyClaimedError(f"run {run_id} is already {run.status}")

    session.refresh(run)

    settings = get_settings()
    run_dir = Path(settings.run_root) / run_id
    try:
        outcome = _execute(run, session, run_dir)
    except Exception as exc:
        log.exception("scan.failed", run_id=run_id)
        run.status = RunStatus.FAILED
        run.error = str(exc)[:2000]
        run.finished_at = datetime.now(UTC)
        return ScanOutcome(run_id=run_id, status=RunStatus.FAILED, error=str(exc))
    finally:
        # Staging holds a plaintext copy of the customer's artifact and
        # everything inside it. It does not outlive the run.
        shutil.rmtree(run_dir, ignore_errors=True)

    # A run whose analyzers did not all finish is not a completed run. Saying
    # otherwise is how a failed static stage became a clean bill of health on a
    # 213 MB installer: findings=0, status=completed, nothing to look at.
    degraded = degraded_stages(session, run.id)
    if degraded:
        described = describe_degraded(degraded)
        run.status = RunStatus.DEGRADED
        run.error = "; ".join(described)[:2000]
        log.warning("scan.degraded", run_id=run.id, stages=described)
    else:
        run.status = RunStatus.COMPLETED

    run.finished_at = datetime.now(UTC)
    return replace(outcome, status=run.status)


def _execute(run: Run, session: Session, run_dir: Path) -> ScanOutcome:
    settings = get_settings()
    pack = load_rule_pack(Path(settings.repo_root) / "detections")

    root = session.scalars(
        select(Artifact).where(Artifact.run_id == run.id, Artifact.parent_id.is_(None))
    ).first()
    if root is None:
        raise LookupError(f"run {run.id} has no root artifact")

    # Layout: the original artifact alone in unpack_in/ (the unpack analyzer
    # expects exactly one), and scan_in/ holding the original plus everything
    # extracted, so the static pass sees the whole tree at once.
    unpack_in = run_dir / "unpack_in"
    unpack_out = run_dir / "unpack_out"
    scan_in = run_dir / "scan_in"
    scan_out = run_dir / "scan_out"
    rules_dir = run_dir / "rules"
    for directory in (unpack_in, unpack_out, scan_in, scan_out, rules_dir):
        directory.mkdir(parents=True, exist_ok=True)

    _stage_rules(Path(settings.repo_root) / "detections", rules_dir)

    artifact_path = unpack_in / root.name
    get_object_store().download_to(str(root.storage_key), artifact_path)

    # --- S2: unpack ------------------------------------------------------
    unpack_result, unpack_payload = _run_unpack(run, session, root, unpack_in, unpack_out)
    _checkpoint(session, run.id, "index")
    artifacts_by_path = _materialise_tree(run, session, root, unpack_payload, unpack_out)
    # The artifact count is the scan's scale, and this is the moment it becomes
    # known. It is also the phase with no analyzer of its own.
    _checkpoint(session, run.id, "indexed")

    # --- stage everything for the scanner --------------------------------
    root_staged = scan_in / "root" / root.name
    root_staged.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(artifact_path, root_staged)
    staged_paths: dict[str, str] = {"root/" + root.name: root.id}

    extracted_dir = unpack_out / "extracted"
    if extracted_dir.is_dir():
        target = scan_in / "extracted"
        shutil.copytree(extracted_dir, target, dirs_exist_ok=True)
        for node in unpack_payload.get("nodes", []):
            relative = node["relative_path"]
            artifact_id = artifacts_by_path.get(node["path_in_tree"])
            if artifact_id:
                staged_paths[f"extracted/{relative}"] = artifact_id

    _grant_analyzer_access(scan_out)

    # --- S3: static scan over the whole tree ------------------------------
    static_result, static_payload = _run_static(run, session, root, scan_in, rules_dir, scan_out)
    # Publishes the finished static stage, which is what moves the run into its
    # last phase: correlating evidence into findings and writing the manifest.
    _checkpoint(session, run.id, "report")

    evidence = _to_evidence(run, static_payload, staged_paths, root)
    session.add_all(evidence)
    session.flush()

    # Only now is it known which files matter enough to keep.
    _retain_evidence_bytes(session, run, evidence, staged_paths, scan_in)

    _apply_identification(session, run, static_payload, staged_paths)

    # --- S6: correlate ----------------------------------------------------
    artifact_paths = {
        artifact.id: artifact.path_in_tree
        for artifact in session.scalars(select(Artifact).where(Artifact.run_id == run.id))
    }
    suppressions = list(session.scalars(select(Suppression)))
    correlation = correlate(
        run.id, evidence, pack, artifact_paths=artifact_paths, suppressions=suppressions
    )
    session.add_all(correlation.findings)
    session.flush()
    session.add_all(correlation.locations)

    session.add(
        RunManifest(
            run_id=run.id,
            bare_version=BARE_VERSION,
            artifact_sha256=root.sha256,
            rule_pack_version=pack.version,
            rule_pack_hash=pack.hash,
            image_digests={
                "unpack": unpack_result.image_digest or "unknown",
                "static": static_result.image_digest or "unknown",
            },
            tool_versions={
                **(unpack_payload.get("tool_versions") or {}),
                **(static_payload.get("tool_versions") or {}),
            },
            residue=static_payload.get("residue") or [],
            recon=static_payload.get("recon") or {},
            components=static_payload.get("components") or {},
        )
    )
    _link_previous_run(run, root, session)

    artifact_count = 1 + len(artifacts_by_path)
    log.info(
        "scan.completed",
        run_id=run.id,
        artifacts=artifact_count,
        evidence=len(evidence),
        findings=len(correlation.findings),
        suppressed=correlation.suppressed,
        by_severity=correlation.counts_by_severity,
    )
    return ScanOutcome(
        run_id=run.id,
        status=RunStatus.COMPLETED,
        finding_count=len(correlation.findings),
        evidence_count=len(evidence),
        suppressed_count=correlation.suppressed,
        artifact_count=artifact_count,
    )


# --- stages ---------------------------------------------------------------
def _checkpoint(session: Session, run_id: str, phase: str) -> None:
    """Make progress so far visible to everything outside this transaction.

    The scan runs as one long transaction, so without this the stage rows and
    the artifact tree are invisible until it ends — the progress panel could
    only ever show `queued` and then, minutes later, the finished report. Every
    phase in between existed only in an uncommitted transaction.

    Committing at a phase boundary also means a scan killed mid-flight leaves
    behind what it actually completed rather than nothing, which is what lets
    the recovery sweep and the DEGRADED status say something true about it.
    """
    session.commit()
    log.info("scan.phase", run_id=run_id, phase=phase)


def _run_unpack(
    run: Run, session: Session, root: Artifact, staging: Path, results: Path
) -> tuple[SandboxResult, dict[str, Any]]:
    _grant_analyzer_access(results)
    stage = RunStage(run_id=run.id, artifact_id=root.id, analyzer="unpack")
    stage.started_at = datetime.now(UTC)
    # RUNNING, not the PENDING default: this row is committed before the
    # container starts, so anything reading it while the analyzer works would
    # otherwise be told the stage had not begun.
    stage.status = StageStatus.RUNNING
    session.add(stage)
    # Before the container starts, not after: unpacking a large installer takes
    # long enough that a panel showing nothing looks like a stalled run.
    _checkpoint(session, run.id, "unpack")

    driver = driver_from_settings()
    try:
        result = driver.run(
            SandboxSpec(
                image=analyzer_image("unpack"),
                run_id=run.id,
                analyzer="unpack",
                timeout_s=UNPACK_TIMEOUT_S,
                nano_cpus=_analyzer_nano_cpus(),
                mem_limit_bytes=_analyzer_memory_bytes(),
                mounts=(
                    BindMount(str(staging), INPUT_DIR, MountMode.READ_ONLY),
                    BindMount(str(results), OUTPUT_DIR, MountMode.READ_WRITE),
                ),
            )
        )
    finally:
        driver.close()

    _record_stage(stage, result)
    payload = _read_result(results) or {}
    nodes = payload.get("nodes", [])
    stage.evidence_count = len(nodes)
    if payload.get("truncated"):
        # Surfaced rather than swallowed: a truncated tree that reports "no
        # findings" is indistinguishable from a clean artifact.
        #
        # This said COMPLETED, which recorded the reason in `error` and then
        # hid it from the one consumer that matters. `is_degraded` is what the
        # release gate reads to decide whether a scan can support a PASS, so a
        # completed-but-partial stage let a 213 MB installer pass with its
        # 376 MB app.asar never opened. TRUNCATED makes the gate return
        # INCONCLUSIVE instead (ADR-0018).
        stage.status = StageStatus.TRUNCATED
        stage.error = "; ".join((payload.get("budget") or {}).get("reasons", []))[:2000]
    return result, payload


def _run_static(
    run: Run, session: Session, root: Artifact, staging: Path, rules_dir: Path, results: Path
) -> tuple[SandboxResult, dict[str, Any]]:
    stage = RunStage(run_id=run.id, artifact_id=root.id, analyzer="static")
    stage.started_at = datetime.now(UTC)
    # RUNNING, not the PENDING default: this row is committed before the
    # container starts, so anything reading it while the analyzer works would
    # otherwise be told the stage had not begun.
    stage.status = StageStatus.RUNNING
    session.add(stage)
    # The longest phase by far — six minutes on a 213 MB installer.
    _checkpoint(session, run.id, "static")

    command: list[str] = [
        "--recon",
        "--components",
        "--emit-residue",
        str(RESIDUE_SAMPLE_SIZE),
    ]
    if run.retain_plaintext:
        command.append("--include-plaintext")

    driver = driver_from_settings()
    try:
        result = driver.run(
            SandboxSpec(
                image=analyzer_image("static"),
                run_id=run.id,
                analyzer="static",
                command=tuple(command),
                timeout_s=STATIC_TIMEOUT_S,
                # The static analyzer parallelises across this quota; see
                # Settings.analyzer_cpus for the measurements.
                nano_cpus=_analyzer_nano_cpus(),
                mem_limit_bytes=_analyzer_memory_bytes(),
                mounts=(
                    BindMount(str(staging), INPUT_DIR, MountMode.READ_ONLY),
                    BindMount(str(rules_dir), RULES_MOUNT, MountMode.READ_ONLY),
                    BindMount(str(results), OUTPUT_DIR, MountMode.READ_WRITE),
                ),
            )
        )
    finally:
        driver.close()

    _record_stage(stage, result)
    payload = _read_result(results) or {}
    stage.evidence_count = sum(len(f.get("matches", [])) for f in payload.get("files", []))
    return result, payload


# --- tree -----------------------------------------------------------------
def _materialise_tree(
    run: Run,
    session: Session,
    root: Artifact,
    payload: dict[str, Any],
    unpack_out: Path,
) -> dict[str, str]:
    """Turn the unpack manifest into Artifact rows. Returns path_in_tree -> id.

    Metadata only — no bytes are uploaded here. Storing every extracted file
    was the wall: a 213 MB installer that unpacks to 69 000 files meant 69 000
    object-store round trips at roughly 22/sec, so the static analyzer did not
    start for the better part of an hour. The overwhelming majority of those
    files never appear in a finding and their bytes are never fetched.

    `_retain_evidence_bytes` uploads afterwards, for the handful that did
    produce evidence. Every node still gets a row, a hash and a size, so the
    artifact tree and the manifest are unchanged — what is dropped is the
    ability to re-download a file nothing was found in, which nothing in the
    product does.
    """
    by_path: dict[str, str] = {}

    # Sorted by depth so a parent always exists before its children.
    nodes = sorted(payload.get("nodes", []), key=lambda n: (n["depth"], n["path_in_tree"]))

    pending: list[Artifact] = []
    for node in nodes:
        parent_path = node.get("parent_path_in_tree")
        parent_id = root.id if parent_path == root.path_in_tree else by_path.get(parent_path or "")
        if parent_id is None:
            parent_id = root.id

        # Assigned here rather than left to the column default, so children can
        # reference a parent id without a flush per node — the other half of
        # the 69 000-round-trip problem.
        artifact = Artifact(
            id=new_uuid(),
            run_id=run.id,
            parent_id=parent_id,
            name=Path(node["relative_path"]).name,
            path_in_tree=node["path_in_tree"],
            depth=node["depth"],
            sha256=node.get("sha256") or "",
            size_bytes=node["size_bytes"],
            storage_key=None,
            extracted_by=node.get("extracted_by"),
        )
        pending.append(artifact)
        by_path[node["path_in_tree"]] = artifact.id

    session.add_all(pending)
    session.flush()
    log.info("scan.tree_materialised", run_id=run.id, artifacts=len(pending))
    return by_path


def _retain_evidence_bytes(
    session: Session,
    run: Run,
    evidence: list[Evidence],
    staged_paths: dict[str, str],
    scan_in: Path,
) -> int:
    """Upload bytes for the artifacts that actually produced evidence.

    This is what makes "show me the bytes behind this finding" work, and it
    costs one round trip per interesting file rather than one per file.
    """
    wanted = {row.artifact_id for row in evidence if row.artifact_id}
    if not wanted:
        return 0

    # staged_paths maps the analyzer's relative path to an artifact id; invert
    # it to find the bytes on disk for the ids we care about.
    on_disk_by_id = {artifact_id: rel for rel, artifact_id in staged_paths.items()}

    store = get_object_store()
    stored = 0
    for artifact in session.scalars(
        select(Artifact).where(Artifact.run_id == run.id, Artifact.id.in_(wanted))
    ).all():
        if artifact.storage_key or artifact.size_bytes > RETAIN_EXTRACTED_MAX_BYTES:
            continue
        relative = on_disk_by_id.get(artifact.id)
        if not relative:
            continue
        path = scan_in / relative
        if not path.is_file():
            continue
        try:
            artifact.storage_key = store.put_file(path, name=artifact.name).key
            stored += 1
        except Exception as exc:
            # A finding without retrievable bytes is still a finding.
            log.warning("scan.store_evidence_failed", path=artifact.path_in_tree, error=str(exc))

    log.info("scan.evidence_bytes_retained", run_id=run.id, stored=stored, candidates=len(wanted))
    return stored


def _to_evidence(
    run: Run,
    payload: dict[str, Any],
    staged_paths: dict[str, str],
    root: Artifact,
) -> list[Evidence]:
    rows: list[Evidence] = []
    for entry in payload.get("files", []):
        artifact_id = staged_paths.get(entry.get("relative_path", ""))
        if artifact_id is None:
            # A file the scanner saw but the tree does not know about. Attribute
            # it to the root rather than dropping the finding on the floor.
            artifact_id = root.id
        for match in entry.get("matches", []):
            rows.append(
                Evidence(
                    run_id=run.id,
                    artifact_id=artifact_id,
                    analyzer="static",
                    rule_id=match["rule_id"],
                    value_hash=match["value_hash"],
                    value_masked=match["value_masked"],
                    value_plaintext=(
                        match.get("value_plaintext") if run.retain_plaintext else None
                    ),
                    offset=match.get("offset"),
                    encoding=match.get("encoding"),
                    entropy=match.get("entropy"),
                    context_snippet=match.get("context"),
                )
            )
    return rows


def _apply_identification(
    session: Session, run: Run, payload: dict[str, Any], staged_paths: dict[str, str]
) -> None:
    by_id = {
        artifact.id: artifact
        for artifact in session.scalars(select(Artifact).where(Artifact.run_id == run.id))
    }
    for entry in payload.get("files", []):
        artifact = by_id.get(staged_paths.get(entry.get("relative_path", ""), ""))
        if artifact is None:
            continue
        artifact.kind = entry.get("kind", artifact.kind)
        artifact.media_type = entry.get("media_type")
        artifact.architecture = entry.get("architecture")
        artifact.identified = {
            k: v
            for k, v in entry.items()
            if k
            not in ("kind", "media_type", "architecture", "matches", "relative_path", "size_bytes")
        }


# --- helpers --------------------------------------------------------------
def _stage_rules(source: Path, destination: Path) -> None:
    """The rule pack travels with the run rather than being baked into the
    image, so a rule change takes effect without a rebuild and the manifest
    still records exactly which pack ran."""
    for rule_file in sorted(source.glob("*.yaml")):
        shutil.copy2(rule_file, destination / rule_file.name)
    version_file = source / "VERSION"
    if version_file.is_file():
        shutil.copy2(version_file, destination / "VERSION")


def _record_stage(stage: RunStage, result: SandboxResult) -> None:
    stage.finished_at = datetime.now(UTC)
    stage.duration_s = round(result.duration_s, 3)
    stage.exit_code = result.exit_code
    stage.image_digest = result.image_digest
    stage.error = result.error or (
        result.stderr.decode("utf-8", "replace")[:2000] if result.exit_code else None
    )
    stage.status = {
        SandboxStatus.COMPLETED: (
            StageStatus.COMPLETED if result.exit_code == 0 else StageStatus.FAILED
        ),
        SandboxStatus.TIMEOUT: StageStatus.TIMEOUT,
        SandboxStatus.OOM: StageStatus.OOM,
        SandboxStatus.START_FAILED: StageStatus.FAILED,
        SandboxStatus.ERROR: StageStatus.FAILED,
    }[result.status]


def _read_result(results: Path) -> dict[str, Any] | None:
    path = results / "result.json"
    if not path.is_file():
        return None
    try:
        payload: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        log.warning("scan.unparseable_result", error=str(exc))
        return None
    return payload


def _link_previous_run(run: Run, root: Artifact, session: Session) -> None:
    """Point this run at the last completed run of a same-named artifact.

    "What is new since the last release" is the question CI actually asks, and
    answering it needs a predecessor recorded at scan time rather than guessed
    at report time.
    """
    previous = session.scalars(
        select(Run)
        .join(Artifact, Artifact.run_id == Run.id)
        .where(
            Run.id != run.id,
            Run.status == RunStatus.COMPLETED,
            Artifact.parent_id.is_(None),
            Artifact.name == root.name,
        )
        .order_by(Run.created_at.desc())
        .limit(1)
    ).first()
    if previous is not None:
        run.previous_run_id = previous.id


def _analyzer_memory_bytes() -> int:
    """Memory ceiling for an analyzer container, from settings."""
    return int(max(1.0, get_settings().analyzer_memory_gb) * 1024**3)


def _analyzer_nano_cpus() -> int:
    """CPU quota for an analyzer container, from settings, in nano-CPUs.

    Floored at one whole core: a fractional quota makes the analyzer's own
    cgroup read round down to a single worker anyway, and a sub-core quota
    turns a CPU-bound scan into a timeout.
    """
    cpus = max(1.0, get_settings().analyzer_cpus)
    return int(cpus * 1_000_000_000)


def _grant_analyzer_access(path: Path) -> None:
    """The analyzer runs as uid 10001 and must be able to write its results.

    No-op on Windows, where Docker Desktop bind mounts do not carry POSIX
    ownership and the container already sees a permissive mount.
    """
    if os.name == "nt":
        return
    from core.sandbox.spec import ANALYZER_GID, ANALYZER_UID

    chown = getattr(os, "chown", None)
    if chown is None:  # pragma: no cover - Windows returns early above
        return
    try:
        chown(path, ANALYZER_UID, ANALYZER_GID)
    except (PermissionError, OSError):
        path.chmod(0o777)
