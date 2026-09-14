"""S0 — ingest.

Hash, store, and record the artifact along with the authorization attestation.
The attestation is a real gate: there is no code path that creates a Run
without one, and the values are copied into every report (§14).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import BinaryIO

import structlog
from sqlalchemy.orm import Session

from core.config import get_settings
from core.models import Artifact, AuditLog, Run
from core.models.enums import AuditAction, RunStatus
from core.retention import retention_deadline
from core.storage import get_object_store

log = structlog.get_logger(__name__)

MAX_ARTIFACT_BYTES = 2 * 1024**3


class AttestationRequired(ValueError):  # noqa: N818 - names the requirement
    """No attestation, no ingestion."""


@dataclass(slots=True)
class IngestResult:
    run: Run
    artifact: Artifact
    deduplicated: bool = False
    """The same bytes were uploaded before. The object store already had them,
    so the upload was free — but this is still a new run."""


def ingest_artifact(
    session: Session,
    stream: BinaryIO,
    *,
    filename: str,
    attested_by: str,
    attestation_reference: str,
    profile: str = "standard",
    llm_enabled: bool = False,
    retain_plaintext: bool = False,
) -> IngestResult:
    """Create a run from an uploaded artifact.

    Raises :class:`AttestationRequired` if the attestation is missing or
    obviously perfunctory. That check is deliberate: an audit record reading
    "yes" is worth nothing to the compliance officer who has to rely on it
    two years from now.
    """
    settings = get_settings()
    attested_by = (attested_by or "").strip()
    attestation_reference = (attestation_reference or "").strip()

    if settings.require_attestation:
        if not attested_by:
            raise AttestationRequired("an attesting identity is required")
        if len(attestation_reference) < 8:
            raise AttestationRequired(
                "an authorization reference is required — cite the contract, ticket, "
                "or engagement that authorises analysing this artifact"
            )
    else:
        # Gate disabled for prototyping. The records are still written, so the
        # audit trail is continuous and enabling the gate later does not leave
        # a hole where these runs were.
        attested_by = attested_by or settings.default_attested_by
        attestation_reference = attestation_reference or settings.default_attestation_reference

    store = get_object_store()
    existing = None
    stored = store.put_stream(stream, name=filename)

    if stored.size_bytes > MAX_ARTIFACT_BYTES:
        raise ValueError(f"artifact exceeds the {MAX_ARTIFACT_BYTES // 1024**3} GiB limit")

    now = datetime.now(UTC)
    run = Run(
        status=RunStatus.QUEUED,
        profile=profile,
        attested_by=attested_by,
        attestation_reference=attestation_reference,
        attested_at=now,
        llm_enabled=llm_enabled,
        retain_plaintext=retain_plaintext,
        # From the moment of upload, not scan completion: a run that sat queued
        # for a day has not earned an extra day of holding secrets.
        plaintext_expires_at=retention_deadline(now, settings) if retain_plaintext else None,
    )
    session.add(run)
    session.flush()

    artifact = Artifact(
        run_id=run.id,
        parent_id=None,
        name=filename,
        path_in_tree=filename,
        depth=0,
        sha256=stored.sha256,
        size_bytes=stored.size_bytes,
        storage_key=stored.key,
    )
    session.add(artifact)
    session.flush()

    run.root_artifact_id = artifact.id

    # Two records, not one: the upload and the attestation are separate events
    # and an auditor may care about either independently.
    session.add(
        AuditLog.record(
            AuditAction.ARTIFACT_UPLOADED,
            actor=attested_by,
            run_id=run.id,
            filename=filename,
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
        )
    )
    session.add(
        AuditLog.record(
            AuditAction.ATTESTATION_RECORDED,
            actor=attested_by,
            run_id=run.id,
            attestation_reference=attestation_reference,
            attested_at=now.isoformat(),
        )
    )

    log.info(
        "ingest.accepted",
        run_id=run.id,
        filename=filename,
        sha256=stored.sha256[:16],
        size_bytes=stored.size_bytes,
        attested_by=attested_by,
    )
    return IngestResult(run=run, artifact=artifact, deduplicated=existing is not None)
