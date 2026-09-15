"""Analysis tasks.

Kept separate from ``tasks.py`` (which holds the operational tasks) so the
import graph stays legible as the stage count grows.
"""

from __future__ import annotations

from typing import Any

import structlog
from sqlalchemy import func, select

from core.db import session_scope
from core.orchestrator.celery_app import QUEUE_GHIDRA, QUEUE_LLM, QUEUE_STATIC, celery_app

log = structlog.get_logger(__name__)


@celery_app.task(name="bare.scan_run", queue=QUEUE_STATIC, bind=True, max_retries=0)
def scan_run(self: Any, run_id: str) -> dict[str, Any]:
    """Run the full scan pipeline for one run.

    ``max_retries=0`` on purpose: analyzer containers are not free, and a
    retried scan of a hung artifact just hangs again. The run state machine
    records the failure and a human decides whether to re-run.
    """
    from core.pipeline.scan import RunAlreadyClaimedError, run_scan

    try:
        with session_scope() as session:
            outcome = run_scan(run_id, session)
    except RunAlreadyClaimedError as exc:
        # A duplicate delivery, not a failure. Celery is at-least-once, and the
        # orphan sweep can re-dispatch a run whose original task is alive. The
        # worker holding the claim is doing the work; this one returns quietly
        # rather than failing the task and making a healthy run look broken.
        log.info("scan.duplicate_delivery", run_id=run_id, detail=str(exc))
        return {"run_id": run_id, "status": "already_running", "skipped": True}

    if _should_enrich(outcome):
        # After the scan's transaction has committed, so the Ghidra worker never
        # reads a run that is not yet terminal. A broker failure here costs the
        # enrichment and never the scan (ADR-0034).
        try:
            ghidra_run_task.delay(run_id)
        except Exception as exc:
            log.warning("ghidra.dispatch_failed", run_id=run_id, error=str(exc))

    return {
        "run_id": outcome.run_id,
        "status": str(outcome.status),
        "findings": outcome.finding_count,
        "evidence": outcome.evidence_count,
        "suppressed": outcome.suppressed_count,
        "error": outcome.error,
    }


def _should_enrich(outcome: Any) -> bool:
    """Whether a finished scan has anything for Ghidra to cross-reference."""
    from core.config import get_settings
    from core.models.enums import RunStatus

    return bool(
        get_settings().ghidra_enabled
        and outcome.finding_count
        and outcome.status in (RunStatus.COMPLETED, RunStatus.DEGRADED)
    )


@celery_app.task(name="bare.ghidra_run", queue=QUEUE_GHIDRA, max_retries=0)
def ghidra_run_task(run_id: str) -> dict[str, Any]:
    """Name the functions that reference a finished run's flagged strings (S4).

    Its own task on the `ghidra` queue, which only `worker-heavy` consumes, so a
    Ghidra job that runs for twenty minutes holds the slow lane and not the
    scanners (§4). ``max_retries=0`` for the scan's reason: a binary that wedged
    Ghidra once wedges it again.
    """
    from core.pipeline.ghidra import enrich_run

    with session_scope() as session:
        outcome = enrich_run(run_id, session)
    return outcome.to_dict()


@celery_app.task(name="bare.triage_run", queue=QUEUE_LLM, max_retries=0)
def triage_run_task(run_id: str) -> dict[str, Any]:
    """Run LLM triage over a completed run's findings.

    Never implicit, and never fatal. If the model is unreachable this returns
    an error and the deterministic report stands entirely unchanged — that is
    the §2.5 guarantee, and it is why triage is a separate task rather than a
    stage of the scan.
    """
    from core.llm import LLMConfigError, load_config, provider_for_role, triage_run
    from core.models import Finding, FindingLocation

    try:
        config = load_config()
        if not config.enabled:
            return {"run_id": run_id, "error": "the LLM layer is disabled in config/llm.yaml"}
        provider = provider_for_role("triage", config)
    except (LLMConfigError, NotImplementedError) as exc:
        return {"run_id": run_id, "error": str(exc)}

    health = provider.health()
    if not health.healthy:
        return {"run_id": run_id, "error": f"triage provider unavailable: {health.detail}"}

    # Page the model in first. On bandwidth-bound hardware a cold 9 GB model
    # takes 20+ seconds to load and then answers in two — without this, that
    # load time lands on the first finding and looks like the model is slow.
    warm = getattr(provider, "warm", None)
    if callable(warm):
        warm()

    with session_scope() as session:
        findings = list(session.scalars(select(Finding).where(Finding.run_id == run_id)))
        if not findings:
            return {
                "run_id": run_id,
                "triaged": 0,
                "confirmed": 0,
                "dismissed": 0,
                "needs_review": 0,
                "errors": 0,
                "duration_s": 0.0,
                "model": provider.model,
            }

        locations = session.scalars(
            select(FindingLocation).where(FindingLocation.run_id == run_id)
        ).all()
        paths: dict[str, str] = {}
        counts: dict[str, int] = {}
        for location in locations:
            paths.setdefault(location.finding_id, location.path_in_tree)
            counts[location.finding_id] = counts.get(location.finding_id, 0) + 1

        result = triage_run(provider, findings, paths, run_id=run_id, location_counts=counts)
        session.add_all(result.calls)

    return {
        "run_id": run_id,
        "triaged": result.triaged,
        "confirmed": result.confirmed,
        "dismissed": result.dismissed,
        "needs_review": result.needs_review,
        "errors": result.errors,
        "duration_s": round(result.total_duration_s, 2),
        "model": provider.model,
    }


@celery_app.task(name="bare.discover_rules", queue=QUEUE_LLM, max_retries=0)
def discover_rules_task(run_id: str) -> dict[str, Any]:
    """Ask the model to propose rules for what the pack missed on this run.

    This is the AI author loop, and it is the one place a model genuinely
    belongs in a deterministic scanner: it reads the strings nothing matched
    and proposes patterns for a human to review. Proposals are never findings —
    merging one makes it deterministic, and from then on the model is out of
    the path entirely.
    """
    from core.llm import LLMConfigError, discover_rules, load_config, provider_for_role
    from core.llm.discovery import summarise
    from core.models import RunManifest

    try:
        config = load_config()
        if not config.enabled:
            return {"run_id": run_id, "error": "the LLM layer is disabled in config/llm.yaml"}
        # Rule authoring is low-volume, high-judgement work — the opposite of
        # triage — so it routes to the reasoning model when one is configured.
        role = "discover" if "discover" in config.roles else "explain"
        provider = provider_for_role(role, config)
    except (LLMConfigError, NotImplementedError) as exc:
        return {"run_id": run_id, "error": str(exc)}

    health = provider.health()
    if not health.healthy:
        return {"run_id": run_id, "error": f"provider unavailable: {health.detail}"}

    warm = getattr(provider, "warm", None)
    if callable(warm):
        warm()

    with session_scope() as session:
        manifest = session.scalars(select(RunManifest).where(RunManifest.run_id == run_id)).first()
        residue = list(manifest.residue or []) if manifest else []

        if not residue:
            return {
                "run_id": run_id,
                "sampled": 0,
                "proposed": 0,
                "usable": 0,
                "error": "no unmatched strings were sampled for this run",
            }

        result = discover_rules(provider, residue, run_id=run_id)
        if result.call is not None:
            session.add(result.call)

    return {"run_id": run_id, **summarise(result)}


def _llm_provider(role: str, run_id: str) -> tuple[Any, dict[str, Any] | None]:
    """Resolve a provider for one role, or the error to return to the caller.

    Every advisory task begins this way: disabled config, an unroutable role,
    and an unreachable model are all *reportable* states, not exceptions. The
    deterministic report stands unchanged in all three (§2.5).
    """
    from core.llm import LLMConfigError, load_config, provider_for_role

    try:
        config = load_config()
        if not config.enabled:
            return None, {"run_id": run_id, "error": "the LLM layer is disabled in config/llm.yaml"}
        if role not in config.roles:
            return None, {
                "run_id": run_id,
                "error": (
                    f"no provider is routed to the {role!r} role; add it under "
                    f"`roles:` in config/llm.yaml"
                ),
            }
        provider = provider_for_role(role, config)
    except (LLMConfigError, NotImplementedError) as exc:
        return None, {"run_id": run_id, "error": str(exc)}

    health = provider.health()
    if not health.healthy:
        return None, {"run_id": run_id, "error": f"{role} provider unavailable: {health.detail}"}

    # Same reason as triage: a cold model's load time would otherwise land on
    # the first call and look like the model being slow.
    warm = getattr(provider, "warm", None)
    if callable(warm):
        warm()
    return provider, None


@celery_app.task(name="bare.explain_finding", queue=QUEUE_LLM, max_retries=0)
def explain_finding_task(run_id: str, finding_id: str) -> dict[str, Any]:
    """Explain one finding in depth, on request.

    Per-finding rather than per-run on purpose. This role is routed to a
    reasoning model by default, which costs tens of seconds per call — running
    it over every finding in a 45-finding run would take longer than the scan
    that produced them, for prose nobody asked to read. The reviewer picks the
    findings that matter.
    """
    from core.llm import apply_explanation, explain_finding
    from core.models import Finding, FindingLocation

    provider, error = _llm_provider("explain", run_id)
    if error is not None:
        return error

    with session_scope() as session:
        finding = session.get(Finding, (finding_id, run_id))
        if finding is None:
            return {"run_id": run_id, "error": f"finding {finding_id} not found in run {run_id}"}

        locations = list(
            session.scalars(
                select(FindingLocation).where(
                    FindingLocation.finding_id == finding_id,
                    FindingLocation.run_id == run_id,
                )
            )
        )
        path = locations[0].path_in_tree if locations else ""

        text, call = explain_finding(
            provider,
            finding,
            path_in_tree=path,
            location_count=len(locations) or 1,
            run_id=run_id,
        )
        session.add(call)

        if text is None:
            return {"run_id": run_id, "error": call.error or "the model returned no explanation"}

        apply_explanation(finding, text, provider.model)
        return {
            "run_id": run_id,
            "finding_id": finding_id,
            "explanation": text,
            "model": provider.model,
            "duration_s": round(call.duration_s or 0.0, 2),
        }


@celery_app.task(name="bare.summarize_run", queue=QUEUE_LLM, max_retries=0)
def summarize_run_task(run_id: str) -> dict[str, Any]:
    """One reviewer-facing paragraph over the whole run."""
    from core.llm import summarize_run
    from core.models import Artifact, Finding, Run

    provider, error = _llm_provider("summarize", run_id)
    if error is not None:
        return error

    with session_scope() as session:
        run = session.get(Run, run_id)
        if run is None:
            return {"run_id": run_id, "error": f"run {run_id} not found"}

        findings = list(session.scalars(select(Finding).where(Finding.run_id == run_id)))
        root = session.scalars(
            select(Artifact).where(Artifact.run_id == run_id, Artifact.parent_id.is_(None))
        ).first()
        artifact_count = session.scalar(
            select(func.count()).select_from(Artifact).where(Artifact.run_id == run_id)
        )

        result = summarize_run(
            provider,
            run,
            findings,
            artifact_name=root.name if root else "(unknown)",
            artifact_count=artifact_count or 0,
        )
        if result.call is not None:
            session.add(result.call)

        if result.error is not None:
            return {"run_id": run_id, "error": result.error}

        return {
            "run_id": run_id,
            "summary": result.text,
            "model": provider.model,
            "duration_s": round(result.call.duration_s or 0.0, 2) if result.call else 0.0,
        }


@celery_app.task(name="bare.investigate_finding", queue=QUEUE_LLM, max_retries=0)
def investigate_finding_task(run_id: str, finding_id: str) -> dict[str, Any]:
    """Let the model investigate one finding with tools.

    Deeper than `explain`, and correspondingly slower and more expensive: this
    is a loop of model calls, each carrying the transcript so far. Per-finding
    and on request for that reason.

    The tools are read-only and scoped to this run (`core/llm/tools.py`). The
    model never gets a shell, and this task cannot write a Finding — it writes
    the conclusion and the transcript onto the finding a rule already produced.
    """
    from core.llm import load_config
    from core.llm.investigate import apply_investigation, investigate_finding
    from core.llm.tools import ToolBox
    from core.models import Finding, FindingLocation, Run

    provider, error = _llm_provider("investigate", run_id)
    if error is not None:
        return error

    config = load_config()

    with session_scope() as session:
        finding = session.get(Finding, (finding_id, run_id))
        if finding is None:
            return {"run_id": run_id, "error": f"finding {finding_id} not found in run {run_id}"}

        run = session.get(Run, run_id)

        # §9: plaintext may reach a *local* provider only, and only when the
        # run opted into retaining it and redaction is not strict. Any one of
        # those being false means the tools mask what they return.
        allow_plaintext = bool(
            provider.is_local
            and run is not None
            and run.retain_plaintext
            and config.redaction != "strict"
        )

        locations = list(
            session.scalars(
                select(FindingLocation).where(
                    FindingLocation.finding_id == finding_id,
                    FindingLocation.run_id == run_id,
                )
            )
        )
        path = locations[0].path_in_tree if locations else ""

        toolbox = ToolBox(session, run_id, allow_plaintext=allow_plaintext)
        result = investigate_finding(
            provider,
            toolbox,
            finding,
            path_in_tree=path,
            location_count=len(locations) or 1,
        )
        session.add_all(result.calls)

        # A run that ended without a conclusion still leaves its transcript:
        # the steps are the useful part even when the summary is missing.
        apply_investigation(finding, result, provider.model)

        if result.error is not None and not result.conclusion:
            return {
                "run_id": run_id,
                "finding_id": finding_id,
                "error": result.error,
                "steps": len(result.steps),
            }

        return {
            "run_id": run_id,
            "finding_id": finding_id,
            "conclusion": result.conclusion,
            "confidence": result.confidence,
            "steps": len(result.steps),
            "model": provider.model,
            "duration_s": round(result.duration_s, 2),
            "redaction": "none" if allow_plaintext else "strict",
        }
