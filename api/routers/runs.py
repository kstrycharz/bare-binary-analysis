"""Run management: upload, list, detail, progress, triage."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Sequence
from typing import Annotated, Any

import structlog
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import PlainTextResponse, StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.deps import get_caller, require_scope
from api.schemas.models import (
    ArtifactOut,
    ExplainResponse,
    InvestigateResponse,
    ManifestOut,
    RunCreated,
    RunDetail,
    RunSummary,
    StageOut,
    SummaryResponse,
    TriageResponse,
)
from core.auth import Scope
from core.db import get_session, session_scope
from core.models import Artifact, Finding, FindingLocation, Run, RunStage
from core.models.enums import RunStatus, StageStatus
from core.pipeline.ingest import AttestationRequired, ingest_artifact
from core.storage import get_object_store

log = structlog.get_logger(__name__)

router = APIRouter(
    prefix="/api/runs",
    tags=["runs"],
    dependencies=[Depends(get_caller)],
)


@router.post("", response_model=RunCreated, status_code=status.HTTP_201_CREATED)
async def create_run(
    file: Annotated[UploadFile, File(description="The artifact to analyse.")],
    profile: Annotated[str, Form()] = "standard",
    attested_by: Annotated[str, Form(description="Who is attesting authorization.")] = "",
    attestation_reference: Annotated[
        str, Form(description="Contract, ticket, or engagement reference.")
    ] = "",
    llm_enabled: Annotated[bool, Form()] = False,
    retain_plaintext: Annotated[bool, Form()] = False,
) -> RunCreated:
    """Upload an artifact and queue a scan.

    The attestation is not optional and not a checkbox: it is recorded in the
    audit log and stamped into every report. An upload without one is rejected
    (§14).
    """
    if not file.filename:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "a filename is required")

    try:
        with session_scope() as session:
            result = ingest_artifact(
                session,
                file.file,
                filename=file.filename,
                attested_by=attested_by,
                attestation_reference=attestation_reference,
                profile=profile,
                llm_enabled=llm_enabled,
                retain_plaintext=retain_plaintext,
            )
            payload = RunCreated(
                run_id=result.run.id,
                artifact_name=result.artifact.name,
                artifact_sha256=result.artifact.sha256,
                size_bytes=result.artifact.size_bytes,
                status=result.run.status,
            )
    except AttestationRequired as exc:
        # 422 rather than 400: the request was well-formed, the authorization
        # claim was not adequate.
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None

    from core.orchestrator.tasks import scan_run

    scan_run.delay(payload.run_id)
    return payload


@router.get("", response_model=list[RunSummary])
def list_runs(
    session: Annotated[Session, Depends(get_session)],
    limit: Annotated[int, Query(le=200)] = 50,
    offset: int = 0,
) -> list[RunSummary]:
    runs = session.scalars(
        select(Run).order_by(Run.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return [_summarise(session, run) for run in runs]


@router.get("/{run_id}", response_model=RunDetail)
def get_run(run_id: str, session: Annotated[Session, Depends(get_session)]) -> RunDetail:
    run = session.get(Run, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"run {run_id} not found")

    summary = _summarise(session, run)
    stages = session.scalars(
        select(RunStage).where(RunStage.run_id == run_id).order_by(RunStage.created_at)
    ).all()

    manifest = None
    if run.manifest is not None:
        manifest = ManifestOut.model_validate(run.manifest)
        manifest.fingerprint = run.manifest.fingerprint

    tree, tree_truncated = _build_tree(session, run)
    return RunDetail(
        **summary.model_dump(),
        stages=[StageOut.model_validate(s) for s in stages],
        manifest=manifest,
        artifact_tree=tree,
        artifact_tree_truncated=tree_truncated,
        previous_run_id=run.previous_run_id,
        llm_summary=run.llm_summary,
        llm_summary_model=run.llm_summary_model,
        llm_summary_at=run.llm_summary_at,
    )


# The phases a scan actually passes through, in order. These are derived from
# observable state — which stage rows exist and what status they carry — not
# from a timer. A progress bar that advances on a clock rather than on work is
# a lie that costs the operator the one thing they came to the page for.
#
# `index` and `report` have no stage row of their own: they are the pipeline
# doing its own work between analyzers (materialising 68 976 artifact rows,
# then correlating evidence into findings and writing the manifest). They are
# named because they are slow enough to look like a hang otherwise.
SCAN_PHASES: tuple[tuple[str, str], ...] = (
    ("queued", "Waiting for a worker"),
    ("unpack", "Recursively extracting nested containers"),
    ("index", "Recording the artifact tree"),
    ("static", "Extracting strings and matching rules"),
    ("report", "Correlating evidence into findings"),
    ("done", "Complete"),
)


def _phase(run: Run, stages: Sequence[RunStage]) -> str:
    """Which phase this run is in right now.

    Reads the stage rows rather than tracking state separately, so the phase
    cannot drift from what the pipeline actually did.
    """
    if RunStatus(run.status).is_terminal:
        return "done"

    by_analyzer = {stage.analyzer: StageStatus(stage.status) for stage in stages}
    unpack = by_analyzer.get("unpack")
    static = by_analyzer.get("static")

    # A stage row is committed before its container starts, so the row existing
    # says the phase has begun — not that it is over. PENDING belongs here with
    # RUNNING because it is the column default, and reading it as "finished"
    # reported the last phase for the whole of the longest one.
    unfinished = (StageStatus.PENDING, StageStatus.RUNNING)

    if static is not None:
        # Once static is done but the run is not, evidence is being correlated
        # into findings and the manifest written.
        return "static" if static in unfinished else "report"
    if unpack is not None:
        # Unpack done, static not started: the pipeline is writing one artifact
        # row per extracted file.
        return "unpack" if unpack in unfinished else "index"
    return "queued"


def _expected_duration_s(session: Session, run: Run) -> float | None:
    """How long this same artifact took the last time it was scanned.

    Deliberately not a model or an average across artifacts: scan time is
    dominated by how many files an artifact unpacks to, so the only estimate
    worth showing is one drawn from the same bytes. Absent for a first scan,
    and the UI says so rather than inventing a number.
    """
    root = session.scalars(
        select(Artifact).where(Artifact.run_id == run.id, Artifact.parent_id.is_(None))
    ).first()
    if root is None:
        return None

    previous = session.execute(
        select(Run.started_at, Run.finished_at)
        .join(Artifact, Artifact.run_id == Run.id)
        .where(
            Artifact.parent_id.is_(None),
            Artifact.sha256 == root.sha256,
            Run.id != run.id,
            Run.status == RunStatus.COMPLETED,
            Run.started_at.is_not(None),
            Run.finished_at.is_not(None),
        )
        .order_by(Run.finished_at.desc())
        .limit(1)
    ).first()
    if previous is None:
        return None
    started, finished = previous
    return (finished - started).total_seconds()


@router.get("/{run_id}/events")
async def stream_events(run_id: str) -> StreamingResponse:
    """Server-sent progress.

    SSE rather than WebSocket (§4): it survives corporate proxies that mangle
    upgrade handshakes, and reconnection semantics come free.
    """

    async def generate() -> AsyncIterator[str]:
        last: str | None = None
        expected_s: float | None = None
        expected_resolved = False

        for _ in range(600):  # ~20 minutes at 2s, then the client reconnects
            with session_scope() as session:
                run = session.get(Run, run_id)
                if run is None:
                    yield _sse({"error": "run not found"})
                    return
                stages = session.scalars(select(RunStage).where(RunStage.run_id == run_id)).all()

                # Resolved once: the previous run's duration cannot change
                # while this one is in flight, and it is the most expensive
                # query here.
                if not expected_resolved:
                    expected_s = _expected_duration_s(session, run)
                    expected_resolved = True

                started = run.started_at
                payload = {
                    "status": run.status,
                    "phase": _phase(run, stages),
                    "stages": [
                        {"analyzer": s.analyzer, "status": s.status, "duration_s": s.duration_s}
                        for s in stages
                    ],
                    "finding_count": session.scalar(
                        select(func.count()).select_from(Finding).where(Finding.run_id == run_id)
                    )
                    or 0,
                    # Climbs while the tree is being recorded, which is the one
                    # phase with no analyzer of its own and the one that most
                    # looks like a hang on a large installer.
                    "artifact_count": session.scalar(
                        select(func.count()).select_from(Artifact).where(Artifact.run_id == run_id)
                    )
                    or 0,
                    "started_at": started.isoformat() if started else None,
                    "expected_s": expected_s,
                }
                terminal = RunStatus(run.status).is_terminal

            serialised = json.dumps(payload, sort_keys=True)
            if serialised != last:
                # Only emit on change: a client left open on a finished run
                # should cost nothing.
                yield _sse(payload)
                last = serialised
            if terminal:
                return
            await asyncio.sleep(2)

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


def _sse(payload: dict[str, Any]) -> str:
    return f"data: {json.dumps(payload, sort_keys=True)}\n\n"


# Triage drives the model over the findings corpus, so it is an ADMIN act.
@router.post(
    "/{run_id}/triage",
    response_model=TriageResponse,
    dependencies=[Depends(require_scope(Scope.ADMIN))],
)
def triage(run_id: str) -> TriageResponse:
    """Run LLM triage over this run's findings.

    Explicitly triggered. Triage never runs implicitly, because a scan must
    complete and be useful whether or not a model is reachable (§2.5).
    """
    from core.orchestrator.tasks import triage_run_task

    try:
        result = triage_run_task.apply(args=[run_id]).get()
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from None

    if result.get("error"):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, result["error"])
    return TriageResponse(**result)


# Explain and summarize read the findings corpus and drive a model over it —
# ADMIN, for the same reason triage is.
@router.post(
    "/{run_id}/findings/{finding_id}/explain",
    response_model=ExplainResponse,
    dependencies=[Depends(require_scope(Scope.ADMIN))],
)
def explain(run_id: str, finding_id: str) -> ExplainResponse:
    """Explain one finding in depth.

    On demand and per-finding: this role runs on a reasoning model by default,
    so doing it for every finding in a run would cost more than the scan and
    produce prose nobody asked to read.
    """
    from core.orchestrator.tasks import explain_finding_task

    try:
        result = explain_finding_task.apply(args=[run_id, finding_id]).get()
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from None

    if result.get("error"):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, result["error"])
    return ExplainResponse(**result)


@router.post(
    "/{run_id}/findings/{finding_id}/investigate",
    response_model=InvestigateResponse,
    dependencies=[Depends(require_scope(Scope.ADMIN))],
)
def investigate(run_id: str, finding_id: str) -> InvestigateResponse:
    """Let the model investigate one finding with read-only tools.

    Deeper and slower than `explain`: a loop of model calls, each carrying the
    transcript so far. The model chooses what to look at; it never gets a
    shell, and nothing it does here can create a finding or change one.
    """
    from core.orchestrator.tasks import investigate_finding_task

    try:
        result = investigate_finding_task.apply(args=[run_id, finding_id]).get()
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from None

    if result.get("error"):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, result["error"])
    return InvestigateResponse(**result)


@router.post(
    "/{run_id}/summarize",
    response_model=SummaryResponse,
    dependencies=[Depends(require_scope(Scope.ADMIN))],
)
def summarize(run_id: str) -> SummaryResponse:
    """Write the run's reviewer-facing summary. One model call."""
    from core.orchestrator.tasks import summarize_run_task

    try:
        result = summarize_run_task.apply(args=[run_id]).get()
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from None

    if result.get("error"):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, result["error"])
    return SummaryResponse(**result)


def _summarise(session: Session, run: Run) -> RunSummary:
    root = session.scalars(
        select(Artifact).where(Artifact.run_id == run.id, Artifact.parent_id.is_(None))
    ).first()

    rows = session.execute(
        select(Finding.severity, func.count())
        .where(Finding.run_id == run.id)
        .group_by(Finding.severity)
    ).all()
    counts = dict(rows)

    new_since = None
    if run.previous_run_id:
        previous_ids = set(
            session.scalars(select(Finding.id).where(Finding.run_id == run.previous_run_id)).all()
        )
        current_ids = set(session.scalars(select(Finding.id).where(Finding.run_id == run.id)).all())
        # Finding IDs are content-derived, so "what is new" is a set difference
        # rather than a fuzzy match (§2.5).
        new_since = len(current_ids - previous_ids)

    artifact_count = (
        session.scalar(select(func.count()).select_from(Artifact).where(Artifact.run_id == run.id))
        or 1
    )

    return RunSummary(
        id=run.id,
        status=run.status,
        profile=run.profile,
        created_at=run.created_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
        error=run.error,
        attested_by=run.attested_by,
        attestation_reference=run.attestation_reference,
        llm_enabled=run.llm_enabled,
        artifact_name=root.name if root else None,
        artifact_sha256=root.sha256 if root else None,
        artifact_size_bytes=root.size_bytes if root else None,
        finding_count=sum(counts.values()),
        severity_counts=counts,
        artifact_count=artifact_count,
        new_since_previous=new_since,
    )


# A recursive installer unpacks to tens of thousands of artifacts — the NVIDIA
# AI Workbench setup yields 68 975. Building a Pydantic node for each and
# serialising the result took 58 seconds per request, and `bare scan`
# polls this endpoint every 20 seconds for the length of the scan. No browser
# renders a tree that size either, so the cap costs nothing an operator wanted.
MAX_TREE_NODES = 500


def _build_tree(session: Session, run: Run) -> tuple[ArtifactOut | None, bool]:
    """The artifact tree, bounded. Returns the root and whether it was capped.

    Ordered by depth so the cap keeps the top of the tree — the part that shows
    what the artifact *is* — rather than an arbitrary slice of the deepest
    leaves. A child whose parent fell outside the cap is dropped with it, so
    what remains is always a connected tree rather than orphaned fragments.
    """
    artifacts = session.scalars(
        select(Artifact)
        .where(Artifact.run_id == run.id)
        .order_by(Artifact.depth, Artifact.path_in_tree)
        .limit(MAX_TREE_NODES + 1)
    ).all()
    if not artifacts:
        return None, False

    truncated = len(artifacts) > MAX_TREE_NODES
    artifacts = artifacts[:MAX_TREE_NODES]

    # Findings per artifact, so a tree node carries a badge and the operator can
    # see at a glance which nested file is the problem — which is the whole
    # reason for showing the tree rather than a flat list.
    finding_counts: dict[str, int] = dict(
        session.execute(
            select(FindingLocation.artifact_id, func.count())
            .where(FindingLocation.run_id == run.id)
            .group_by(FindingLocation.artifact_id)
        ).all()
    )

    # Already ordered by (depth, path) in SQL, so parents precede their
    # children and insertion order is the display order.
    by_parent: dict[str | None, list[Artifact]] = {}
    for artifact in artifacts:
        by_parent.setdefault(artifact.parent_id, []).append(artifact)

    def build(artifact: Artifact) -> ArtifactOut:
        # Constructed field by field rather than with `model_validate`.
        # `ArtifactOut.children` and `Artifact.children` share a name, so
        # validating from the ORM object made Pydantic read the relationship —
        # lazy-loading the node's entire subtree from the database, recursively,
        # for every node, and then discarding all of it on the next line. 500
        # nodes took 58 seconds; the same 500 take under a tenth of one.
        return ArtifactOut(
            id=artifact.id,
            name=artifact.name,
            path_in_tree=artifact.path_in_tree,
            depth=artifact.depth,
            sha256=artifact.sha256,
            size_bytes=artifact.size_bytes,
            kind=artifact.kind,
            media_type=artifact.media_type,
            architecture=artifact.architecture,
            identified=artifact.identified or {},
            finding_count=finding_counts.get(artifact.id, 0),
            children=[build(child) for child in by_parent.get(artifact.id, [])],
        )

    roots = by_parent.get(None, [])
    return (build(roots[0]) if roots else None), truncated


# The log of one analyzer stage. ADMIN, not CI: retained log text is masked
# with the run's own detectors, but it is still derived from a customer's
# binary and belongs behind the same gate as the findings corpus (ADR-0032).
@router.get(
    "/{run_id}/stages/{stage_id}/logs",
    dependencies=[Depends(require_scope(Scope.ADMIN))],
    response_class=PlainTextResponse,
)
def get_stage_logs(
    run_id: str,
    stage_id: str,
    session: Annotated[Session, Depends(get_session)],
) -> PlainTextResponse:
    """The retained stdout/stderr of one stage, as plain text.

    ``text/plain`` is the whole XSS story: a browser and the dashboard alike
    get inert characters, never markup. The dashboard renders it into a
    ``<pre>`` with no HTML parsing on the path from bucket to pixels.
    """
    stage = session.get(RunStage, stage_id)
    if stage is None or stage.run_id != run_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "stage not found")
    if not stage.log_key:
        # A stage from before log retention, or one whose bucket write failed.
        # 404 with a reason rather than an empty 200: an empty log and no log
        # are different facts, and only one of them is a lie about the first.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no log retained for this stage")

    from core.pipeline.logs import read_stage_log

    try:
        text = read_stage_log(get_object_store(), stage.log_key)
    except Exception as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"log unreadable: {exc}") from None
    return PlainTextResponse(
        text,
        headers={
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )


@router.post("/{run_id}/discover", dependencies=[Depends(require_scope(Scope.ADMIN))])
def discover(run_id: str) -> dict[str, Any]:
    """Propose detection rules for what this run's rule pack missed.

    The AI author loop. It reads the strings no rule matched and proposes
    patterns; the response is YAML for a human to review and merge. Nothing
    here alters the run's findings, and a proposal that is never merged has no
    effect on anything.
    """
    from core.orchestrator.tasks import discover_rules_task

    try:
        result: dict[str, Any] = discover_rules_task.apply(args=[run_id]).get()
    except Exception as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)) from None

    if result.get("error") and not result.get("proposals"):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, result["error"])
    return result
