"""Bridge between a stored run and the release gate.

:mod:`core.policy` is deliberately free of the database (ADR-0011's reasoning,
one layer out), so the projection from ORM rows to :class:`GateFinding` lives
here, where the pipeline already owns a session.

The baseline resolution is the interesting part. "Is this finding new?" is a
set difference over content-derived finding ids (ADR-0010) against a
predecessor run, and the predecessor is chosen in this order:

1. an explicitly supplied run id — what a pipeline promoting a specific release
   candidate should pass;
2. an explicitly supplied set of ids — what an air-gapped or repo-committed
   baseline file provides;
3. ``run.previous_run_id``, linked at scan time to the last completed run of a
   same-named artifact.

If none resolves, every finding is new. That is the safe direction: a first
scan with no history blocks on everything it finds rather than silently
treating an unknown baseline as "all of this was already there".
"""

from __future__ import annotations

from dataclasses import dataclass

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from core.models import Finding, FindingLocation, Run
from core.models.enums import RunStatus
from core.pipeline.stages import degraded_stages as stage_degradation
from core.pipeline.stages import describe_degraded
from core.policy import GateFinding, GateVerdict, Policy, Waiver, evaluate
from core.vocab import Severity

log = structlog.get_logger(__name__)


class RunNotReady(ValueError):  # noqa: N818 - names the state, not an error kind
    """The run has not reached a terminal state, so there is nothing to gate.

    Raised rather than returning a verdict: an unfinished scan has no honest
    answer, and inventing one is how a gate ends up passing a build that was
    never actually examined.
    """


@dataclass(frozen=True, slots=True)
class BaselineRef:
    """Where the "what is new" comparison came from. Reported so a release
    manager can see whether the gate had a baseline at all."""

    run_id: str | None = None
    finding_ids: frozenset[str] = frozenset()
    source: str = "none"

    @property
    def resolved(self) -> bool:
        return self.source != "none"


def resolve_baseline(
    session: Session,
    run: Run,
    *,
    baseline_run_id: str | None = None,
    baseline_finding_ids: frozenset[str] | None = None,
) -> BaselineRef:
    """Pick the predecessor this run is measured against."""
    if baseline_finding_ids is not None:
        return BaselineRef(finding_ids=baseline_finding_ids, source="supplied_ids")

    candidate = baseline_run_id or run.previous_run_id
    if candidate is None:
        return BaselineRef()

    previous = session.get(Run, candidate)
    if previous is None:
        log.warning("gate.baseline_missing", run_id=run.id, baseline_run_id=candidate)
        return BaselineRef()
    if previous.status != RunStatus.COMPLETED:
        # A failed or cancelled predecessor saw an unknown fraction of the
        # artifact. Treating its findings as the baseline would mark genuinely
        # new secrets as inherited.
        log.warning(
            "gate.baseline_not_completed",
            run_id=run.id,
            baseline_run_id=candidate,
            status=previous.status,
        )
        return BaselineRef()

    ids = frozenset(session.scalars(select(Finding.id).where(Finding.run_id == previous.id)).all())
    source = "explicit_run" if baseline_run_id else "previous_run"
    return BaselineRef(run_id=previous.id, finding_ids=ids, source=source)


def collect_gate_findings(
    session: Session, run_id: str, baseline: BaselineRef
) -> list[GateFinding]:
    """Project this run's findings into the gate's narrow view."""
    findings = list(session.scalars(select(Finding).where(Finding.run_id == run_id)).all())
    if not findings:
        return []

    paths = _artifact_paths(session, run_id, [f.id for f in findings])

    projected: list[GateFinding] = []
    for finding in findings:
        projected.append(
            GateFinding(
                id=finding.id,
                rule_id=finding.rule_id,
                category=finding.category,
                title=finding.title,
                severity=Severity(finding.severity),
                status=str(finding.status),
                is_new=finding.id not in baseline.finding_ids,
                llm_dismissed=finding.llm_verdict == "false_positive",
                artifact_path=paths.get(finding.id, ""),
                value_masked=finding.value_masked,
            )
        )
    return projected


def _artifact_paths(session: Session, run_id: str, finding_ids: list[str]) -> dict[str, str]:
    """First location per finding, for the CI failure message.

    A finding can appear in forty unpacked copies; the gate output names one so
    the message stays readable, and the full location list stays in the report.
    """
    if not finding_ids:
        return {}
    # No join to `artifacts`: the location already denormalises the path, which
    # is what makes a finding's location readable after the unpack tree has
    # been pruned.
    rows = session.execute(
        select(FindingLocation.finding_id, FindingLocation.path_in_tree)
        .where(
            FindingLocation.run_id == run_id,
            FindingLocation.finding_id.in_(finding_ids),
        )
        .order_by(FindingLocation.finding_id, FindingLocation.path_in_tree, FindingLocation.offset)
    ).all()

    paths: dict[str, str] = {}
    for finding_id, path in rows:
        paths.setdefault(str(finding_id), str(path))
    return paths


def degraded_stages(session: Session, run_id: str) -> list[str]:
    """Analyzers that timed out, OOMed, or failed, described for a human.

    Their absence from the findings list is not evidence of a clean artifact,
    which is exactly what the gate's INCONCLUSIVE verdict exists to say. The
    set itself comes from `core.pipeline.stages` so that the gate and the run's
    own status can never disagree about what degraded means.
    """
    return describe_degraded(stage_degradation(session, run_id))


def gate_run(
    session: Session,
    run_id: str,
    policy: Policy,
    *,
    waivers: list[Waiver] | None = None,
    baseline_run_id: str | None = None,
    baseline_finding_ids: frozenset[str] | None = None,
) -> tuple[GateVerdict, BaselineRef]:
    """Evaluate a stored run against a policy."""
    run = session.get(Run, run_id)
    if run is None:
        raise RunNotReady(f"run {run_id} does not exist")
    if not RunStatus(run.status).is_terminal:
        raise RunNotReady(f"run {run_id} is {run.status}; the gate needs a finished scan")

    if run.status == RunStatus.FAILED:
        # A failed scan is not a clean artifact. The engine reports this as
        # INCONCLUSIVE through the degraded path rather than PASS.
        baseline = BaselineRef()
        verdict = evaluate(
            [],
            policy,
            degraded_stages=[f"run failed: {run.error or 'unknown error'}"],
            waivers=waivers or [],
        )
        return verdict, baseline

    baseline = resolve_baseline(
        session,
        run,
        baseline_run_id=baseline_run_id,
        baseline_finding_ids=baseline_finding_ids,
    )
    findings = collect_gate_findings(session, run_id, baseline)
    stages = degraded_stages(session, run_id)

    verdict = evaluate(
        findings,
        policy,
        waivers=waivers or [],
        degraded_stages=stages,
    )
    log.info(
        "gate.evaluated",
        run_id=run_id,
        decision=verdict.decision,
        policy=policy.name,
        violations=len(verdict.violations),
        baseline=baseline.source,
    )
    return verdict, baseline
