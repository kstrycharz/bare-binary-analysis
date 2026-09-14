"""Findings: list, filter, inspect, triage by hand."""

from __future__ import annotations

from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from api.deps import require_scope
from api.schemas.models import (
    FindingOut,
    FindingPatch,
    InvestigationStep,
    LlmAssessment,
    LocationOut,
)
from core.auth import Scope
from core.db import get_session, session_scope
from core.models import AuditLog, Evidence, Finding, FindingLocation, Run
from core.models.enums import AuditAction, FindingStatus
from core.retention import (
    RetentionKeyError,
    decrypt_value,
    plaintext_available,
    retention_key,
)
from core.storage import get_object_store
from core.vocab import Severity

log = structlog.get_logger(__name__)

# The findings corpus is a company's exposed secrets in one document, and
# artifact bytes are the artifact itself. A CI token may submit and receive a
# verdict; it may not read either (ADR-0019).
router = APIRouter(
    prefix="/api",
    tags=["findings"],
    dependencies=[Depends(require_scope(Scope.ADMIN))],
)


@router.get("/runs/{run_id}/findings", response_model=list[FindingOut])
def list_findings(
    run_id: str,
    session: Annotated[Session, Depends(get_session)],
    severity: Annotated[list[str] | None, Query()] = None,
    finding_status: Annotated[list[str] | None, Query(alias="status")] = None,
    category: Annotated[list[str] | None, Query()] = None,
    detected_by: Annotated[str | None, Query()] = None,
    new_only: bool = False,
    limit: Annotated[int, Query(le=2000)] = 500,
) -> list[FindingOut]:
    query = select(Finding).where(Finding.run_id == run_id)
    if severity:
        query = query.where(Finding.severity.in_(severity))
    if finding_status:
        query = query.where(Finding.status.in_(finding_status))
    if category:
        query = query.where(Finding.category.in_(category))
    if detected_by:
        query = query.where(Finding.detected_by == detected_by)

    findings = list(session.scalars(query.limit(limit)))

    previous_ids = _previous_finding_ids(session, run_id)
    results = [_to_out(session, f, previous_ids) for f in findings]
    if new_only:
        results = [f for f in results if f.is_new]

    # Sorted here rather than in SQL: severity order is semantic
    # (critical first), not alphabetical, and must be identical everywhere.
    results.sort(key=lambda f: (Severity(f.severity).rank, f.rule_id, f.id))
    return results


# Finding routes are run-scoped because finding ids are content-derived and
# therefore shared across runs on purpose: the same secret in two releases
# carries the same id. `/api/findings/{id}` would be genuinely ambiguous.
@router.get("/runs/{run_id}/findings/{finding_id}", response_model=FindingOut)
def get_finding(
    run_id: str, finding_id: str, session: Annotated[Session, Depends(get_session)]
) -> FindingOut:
    finding = session.get(Finding, (finding_id, run_id))
    if finding is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, f"finding {finding_id} not found in run {run_id}"
        )
    return _to_out(session, finding, _previous_finding_ids(session, finding.run_id))


@router.patch("/runs/{run_id}/findings/{finding_id}", response_model=FindingOut)
def update_finding(run_id: str, finding_id: str, patch: FindingPatch) -> FindingOut:
    """Human triage. Every change is audited."""
    if patch.status is not None:
        try:
            new_status = FindingStatus(patch.status)
        except ValueError:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                f"unknown status {patch.status!r}; expected one of "
                f"{[s.value for s in FindingStatus]}",
            ) from None
    else:
        new_status = None

    with session_scope() as session:
        finding = session.get(Finding, (finding_id, run_id))
        if finding is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, f"finding {finding_id} not found in run {run_id}"
            )

        if new_status is not None:
            session.add(
                AuditLog.record(
                    AuditAction.FINDING_STATUS_CHANGED,
                    run_id=finding.run_id,
                    finding_id=finding.id,
                    old_status=finding.status,
                    new_status=str(new_status),
                    note=patch.note,
                )
            )
            finding.status = new_status

        session.flush()
        return _to_out(session, finding, _previous_finding_ids(session, finding.run_id))


@router.get("/artifacts/{artifact_id}/bytes")
def read_bytes(
    artifact_id: str,
    session: Annotated[Session, Depends(get_session)],
    offset: Annotated[int, Query(ge=0)] = 0,
    length: Annotated[int, Query(ge=1, le=4096)] = 256,
) -> dict[str, object]:
    """A byte window for the hex viewer.

    A ranged GET against object storage, not a download: the finding detail
    page must not pull a 40 MB installer to render 256 bytes.
    """
    from core.models import Artifact

    artifact = session.get(Artifact, artifact_id)
    if artifact is None or not artifact.storage_key:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "artifact not found")

    data = get_object_store().read_range(artifact.storage_key, offset, length)
    return {
        "offset": offset,
        "length": len(data),
        "hex": data.hex(),
        "ascii": "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in data),
    }


def _previous_finding_ids(session: Session, run_id: str) -> set[str]:
    from core.models import Run

    run = session.get(Run, run_id)
    if run is None or not run.previous_run_id:
        return set()
    return set(
        session.scalars(select(Finding.id).where(Finding.run_id == run.previous_run_id)).all()
    )


# A clustered finding can cover hundreds of distinct values. This bounds what
# one response carries; the locations list still reports the true total.
MAX_PLAINTEXT_VALUES = 500


def _plaintexts(
    session: Session, finding: Finding, locations: list[FindingLocation]
) -> list[str]:
    """The real values behind this finding, when the run retained them.

    Matched through the finding's *locations*, not its ``value_hash``. A
    clustered finding — "40 values, e.g. …" — carries a synthetic hash derived
    from its members' hashes, which by construction equals no evidence row's
    hash, so a hash join silently returned nothing for exactly the findings
    with the most values to show. Locations are the real link: the correlator
    keeps every member's ``(artifact_id, offset)`` when it builds a cluster.
    """
    if not locations or not plaintext_available(session.get(Run, finding.run_id)):
        return []
    try:
        key = retention_key()
    except RetentionKeyError as exc:
        # Fail closed and loudly: the findings page still renders, masked, and
        # the operator gets a log line naming the broken key.
        log.error("retention.key_unusable", error=str(exc))
        return []

    keys = {(location.artifact_id, location.offset) for location in locations}
    rows = session.scalars(
        select(Evidence).where(
            Evidence.run_id == finding.run_id,
            Evidence.artifact_id.in_({artifact_id for artifact_id, _ in keys}),
            Evidence.value_plaintext.is_not(None),
        )
    ).all()

    # The artifact filter is as far as this goes in SQL — a composite IN over
    # (artifact_id, offset) is not portable to SQLite, which the unit suite
    # runs on. The exact pairing happens here.
    seen: set[str] = set()
    values: list[str] = []
    for row in rows:
        if (row.artifact_id, row.offset) not in keys or row.value_plaintext is None:
            continue
        value = decrypt_value(
            row.value_plaintext, run_id=row.run_id, value_hash=row.value_hash, key=key
        )
        if value is None or value in seen:
            continue
        seen.add(value)
        values.append(value)
        if len(values) >= MAX_PLAINTEXT_VALUES:
            break

    return sorted(values)


def _to_out(session: Session, finding: Finding, previous_ids: set[str]) -> FindingOut:
    locations = list(
        session.scalars(
            select(FindingLocation).where(
                FindingLocation.finding_id == finding.id,
                FindingLocation.run_id == finding.run_id,
            )
        )
    )
    locations.sort(key=lambda location: (location.path_in_tree, location.offset or 0))

    assessment = None
    if finding.llm_verdict:
        assessment = LlmAssessment(
            verdict=finding.llm_verdict,
            reasoning=finding.llm_reasoning,
            model=finding.llm_model,
            assessed_at=finding.llm_at,
        )

    value_plaintexts = _plaintexts(session, finding, locations)

    return FindingOut(
        id=finding.id,
        run_id=finding.run_id,
        rule_id=finding.rule_id,
        category=finding.category,
        title=finding.title,
        severity=finding.severity,
        confidence=finding.confidence,
        value_masked=finding.value_masked,
        entropy=finding.entropy,
        context_snippet=finding.context_snippet,
        cwe=finding.cwe,
        tags=list(finding.tags or []),
        remediation_md=finding.remediation_md,
        status=finding.status,
        detected_by=finding.detected_by,
        is_new=bool(previous_ids) and finding.id not in previous_ids,
        locations=[LocationOut.model_validate(location) for location in locations],
        location_count=len(locations),
        llm=assessment,
        value_plaintexts=value_plaintexts,
        llm_explanation=finding.llm_explanation,
        llm_explained_by=finding.llm_explained_by,
        llm_explained_at=finding.llm_explained_at,
        llm_investigation=finding.llm_investigation,
        llm_investigation_steps=[
            InvestigationStep(**step) for step in (finding.llm_investigation_steps or [])
        ],
        llm_investigation_confidence=finding.llm_investigation_confidence,
        llm_investigated_by=finding.llm_investigated_by,
        llm_investigated_at=finding.llm_investigated_at,
    )
