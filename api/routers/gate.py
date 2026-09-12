"""The release-gate endpoints.

The gate is evaluated *server-side* and the policy travels to it, rather than
the findings travelling out to be judged on a build agent. Two reasons, and the
second is the one that matters:

1. The server holds the baseline, so "is this finding new" is a set difference
   it can do directly.
2. A findings list is a company's exposed secrets in one document. Shipping it
   to every build agent, into CI logs and artifact stores, would re-leak the
   thing the product exists to catch. The runner gets a verdict and the masked
   values behind the violations — not the corpus.
"""

from __future__ import annotations

import contextlib
from typing import Annotated, Any

import structlog
import yaml
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from api.deps import get_caller
from core.composition import Component, ComponentInventory, Confidence, Ecosystem
from core.config import BARE_VERSION
from core.db import get_session
from core.models import Artifact, Finding, FindingLocation, Run, RunManifest, RunStage
from core.models.enums import StageStatus
from core.pipeline.gate import RunNotReady, gate_run, resolve_baseline
from core.policy import (
    Policy,
    PolicyLoadError,
    parse_policy,
    parse_waivers,
    verdict_to_dict,
)
from core.vocab import Severity
from reporting.cyclonedx import build_sbom
from reporting.pdf import ReportData, ReportFinding, render_report
from reporting.sarif import SarifFinding, build_sarif

log = structlog.get_logger(__name__)

# A CI token is enough here: submitting an artifact and receiving a verdict
# is exactly what a build agent is for. SARIF carries masked values only.
router = APIRouter(
    prefix="/api/runs",
    tags=["gate"],
    dependencies=[Depends(get_caller)],
)


class GateRequest(BaseModel):
    """The policy is sent as YAML text rather than a parsed object.

    It means the file committed in the release repository is the exact bytes
    evaluated, with one parser and one set of error messages, instead of a JSON
    projection that can drift from the document a reviewer approved.
    """

    policy_yaml: str = ""
    waivers_yaml: str = ""
    baseline_run_id: str | None = None


class GateResponse(BaseModel):
    decision: str
    exit_code: int
    policy_name: str
    run_id: str
    artifact: str = ""
    """The root artifact's name. A verdict that does not say what it is about
    is hard to act on when it arrives days later from `bare gate`."""

    baseline: str
    baseline_run_id: str | None = None
    total_findings: int = 0
    counts_by_severity: dict[str, int] = Field(default_factory=dict)
    new_counts_by_severity: dict[str, int] = Field(default_factory=dict)
    degraded_stages: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    violations: list[dict[str, Any]] = Field(default_factory=list)
    waived: list[dict[str, Any]] = Field(default_factory=list)
    inherited: list[dict[str, Any]] = Field(default_factory=list)


def _parse_policy_yaml(text: str) -> Policy:
    if not text.strip():
        # No policy supplied: the built-in defaults apply. They are the
        # shipping recommendation, not a permissive fallback — block at high
        # and above, new findings only, fail closed on a degraded scan.
        return Policy()
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, f"policy is not valid YAML: {exc}"
        ) from None
    if not isinstance(data, dict):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "policy must be a mapping")
    try:
        return parse_policy(data, source="<request>")
    except PolicyLoadError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from None


@router.post("/{run_id}/gate", response_model=GateResponse)
def evaluate_gate(
    run_id: str,
    request: GateRequest,
    session: Annotated[Session, Depends(get_session)],
) -> GateResponse:
    """Evaluate a finished run against a release policy."""
    policy = _parse_policy_yaml(request.policy_yaml)

    waivers = []
    if request.waivers_yaml.strip():
        try:
            raw = yaml.safe_load(request.waivers_yaml) or {}
            if not isinstance(raw, dict):
                raise PolicyLoadError("waiver document must be a mapping")
            waivers = parse_waivers(raw, policy, source="<request>")
        except yaml.YAMLError as exc:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, f"waivers are not valid YAML: {exc}"
            ) from None
        except PolicyLoadError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from None

    try:
        verdict, baseline = gate_run(
            session,
            run_id,
            policy,
            waivers=waivers,
            baseline_run_id=request.baseline_run_id,
        )
    except RunNotReady as exc:
        # 409, not 404 or 400: the resource exists, the request is well formed,
        # the run simply is not in a state that can be gated yet.
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None

    root = session.scalars(
        select(Artifact).where(Artifact.run_id == run_id, Artifact.parent_id.is_(None)).limit(1)
    ).first()

    payload = verdict_to_dict(verdict)
    return GateResponse(
        run_id=run_id,
        artifact=root.name if root is not None else "",
        baseline=baseline.source,
        baseline_run_id=baseline.run_id,
        **payload,
    )


@router.get("/{run_id}/sarif")
def get_sarif(
    run_id: str,
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """SARIF 2.1.0 for this run, for upload to a code-scanning service."""
    run = session.get(Run, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"run {run_id} not found")

    baseline = resolve_baseline(session, run)
    findings = list(session.scalars(select(Finding).where(Finding.run_id == run_id)).all())

    locations = session.execute(
        select(FindingLocation.finding_id, FindingLocation.path_in_tree, FindingLocation.offset)
        .where(FindingLocation.run_id == run_id)
        .order_by(FindingLocation.finding_id, FindingLocation.path_in_tree, FindingLocation.offset)
    ).all()

    first_location: dict[str, tuple[str, int | None]] = {}
    for finding_id, path, offset in locations:
        first_location.setdefault(str(finding_id), (str(path), offset))

    root_name = ""
    root = session.scalars(
        select(Artifact).where(Artifact.run_id == run_id, Artifact.parent_id.is_(None)).limit(1)
    ).first()
    if root is not None:
        root_name = root.name

    projected: list[SarifFinding] = []
    for finding in findings:
        path, offset = first_location.get(finding.id, (root_name or "unknown", None))
        projected.append(
            SarifFinding(
                id=finding.id,
                rule_id=finding.rule_id,
                title=finding.title,
                severity=Severity(finding.severity),
                value_masked=finding.value_masked,
                artifact_path=path,
                offset=offset,
                category=finding.category,
                cwe=finding.cwe,
                remediation_md=finding.remediation_md,
                is_new=finding.id not in baseline.finding_ids,
                status=str(finding.status),
            )
        )

    return build_sarif(
        projected,
        tool_version=BARE_VERSION,
        artifact_name=root_name,
        run_id=run_id,
    )


@router.get("/{run_id}/report.pdf")
def get_pdf_report(
    run_id: str,
    session: Annotated[Session, Depends(get_session)],
) -> Response:
    """The release record, as a PDF.

    Rendered from the stored run rather than from a live scan, so the document
    for a given run never changes — which is what makes it archivable. Values
    are masked; a PDF is emailed and printed, and is the last place a
    credential should be legible.
    """
    run = session.get(Run, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"run {run_id} not found")

    root = session.scalars(
        select(Artifact).where(Artifact.run_id == run_id, Artifact.parent_id.is_(None)).limit(1)
    ).first()

    baseline = resolve_baseline(session, run)
    findings = list(
        session.scalars(
            select(Finding).where(Finding.run_id == run_id).order_by(Finding.severity)
        ).all()
    )

    locations = session.execute(
        select(FindingLocation.finding_id, FindingLocation.path_in_tree, FindingLocation.offset)
        .where(FindingLocation.run_id == run_id)
        .order_by(FindingLocation.finding_id, FindingLocation.path_in_tree)
    ).all()
    first_location: dict[str, tuple[str, int | None]] = {}
    for finding_id, path, offset in locations:
        first_location.setdefault(str(finding_id), (str(path), offset))

    counts: dict[str, int] = {}
    projected: list[ReportFinding] = []
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
        path, offset = first_location.get(finding.id, (root.name if root else "unknown", None))
        projected.append(
            ReportFinding(
                severity=Severity(finding.severity),
                rule_id=finding.rule_id,
                title=finding.title,
                value_masked=finding.value_masked,
                path_in_tree=path,
                offset=offset,
                is_new=finding.id not in baseline.finding_ids,
            )
        )
    # Most severe first, which is the order a reader needs and not the order
    # the database returns.
    projected.sort(key=lambda f: (f.severity.rank, f.rule_id))

    manifest = session.scalars(
        select(RunManifest).where(RunManifest.run_id == run_id).limit(1)
    ).first()
    stages = session.scalars(select(RunStage).where(RunStage.run_id == run_id)).all()
    degraded = tuple(
        sorted(f"{s.analyzer} ({s.status})" for s in stages if StageStatus(s.status).is_degraded)
    )

    artifact_count = session.scalar(
        select(func.count()).select_from(Artifact).where(Artifact.run_id == run_id)
    )

    # A run still in flight has no verdict yet, and the record is still worth
    # producing without one.
    verdict = None
    with contextlib.suppress(RunNotReady):
        verdict, _ = gate_run(session, run_id, Policy())

    document = render_report(
        ReportData(
            run_id=run_id,
            artifact_name=root.name if root else run_id,
            artifact_sha256=root.sha256 if root else "",
            artifact_size_bytes=root.size_bytes if root else 0,
            attested_by=run.attested_by,
            attestation_reference=run.attestation_reference,
            scanned_at=run.finished_at or run.created_at,
            findings=projected,
            counts_by_severity=counts,
            files_analysed=int(artifact_count or 1),
            verdict=verdict,
            rule_pack_version=manifest.rule_pack_version if manifest else "",
            rule_pack_hash=manifest.rule_pack_hash if manifest else "",
            manifest_fingerprint=manifest.fingerprint if manifest else "",
            tool_versions=dict(manifest.tool_versions or {}) if manifest else {},
            degraded_stages=degraded,
        )
    )

    filename = f"bare-{(root.name if root else run_id)}.pdf".replace(" ", "-")
    return Response(
        content=document,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/{run_id}/sbom")
def get_sbom(
    run_id: str,
    session: Annotated[Session, Depends(get_session)],
) -> dict[str, Any]:
    """CycloneDX 1.5 bill of materials for this run.

    Rebuilt from the stored inventory rather than re-scanning, so the document
    for a given run never changes and can be attached to a release.
    """
    run = session.get(Run, run_id)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"run {run_id} not found")

    manifest = session.scalars(
        select(RunManifest).where(RunManifest.run_id == run_id).limit(1)
    ).first()
    stored = (manifest.components if manifest else {}) or {}

    components: list[Component] = []
    for entry in stored.get("components", []):
        try:
            components.append(
                Component(
                    name=str(entry["name"]),
                    version=str(entry.get("version", "")),
                    ecosystem=Ecosystem(entry.get("ecosystem", "generic")),
                    confidence=Confidence(entry.get("confidence", "declared")),
                    path_in_tree=str(entry.get("path_in_tree", "")),
                    licence=str(entry.get("licence", "")),
                    evidence=str(entry.get("evidence", "")),
                )
            )
        except (KeyError, ValueError):
            # A row written by an older detector than this one. Skipping it
            # beats refusing to produce an SBOM at all.
            continue

    inventory = ComponentInventory(
        components=tuple(components),
        files_examined=int(stored.get("files_examined", 0)),
        truncated=bool(stored.get("truncated", False)),
    )

    root = session.scalars(
        select(Artifact).where(Artifact.run_id == run_id, Artifact.parent_id.is_(None)).limit(1)
    ).first()

    return build_sbom(
        inventory,
        run_id=run_id,
        artifact_name=root.name if root else run_id,
        artifact_sha256=root.sha256 if root else "",
        artifact_size_bytes=root.size_bytes if root else 0,
        tool_version=BARE_VERSION,
    )
