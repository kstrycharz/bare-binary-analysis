"""Shared vocabulary.

These are plain ``StrEnum`` and stored as strings rather than as PostgreSQL
enum types: adding a severity or a status should be a code change and a
migration of *data*, not an ``ALTER TYPE`` that locks the table.
"""

from __future__ import annotations

from enum import StrEnum

# Re-exported: Severity lives in core.vocab so the detection engine can be
# imported inside analyzer containers without pulling in a database layer.
from core.vocab import Severity as Severity


class RunStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"

    DEGRADED = "degraded"
    """The scan finished, but an analyzer did not.

    Distinct from both `completed` and `failed` because it is neither: findings
    were produced and are real, and the absence of others proves nothing. The
    gate already refuses to pass a run in this state (ADR-0018); this exists so
    that the API and the dashboard say so too. Observed in the field: a static
    analyzer that failed to import a module exited non-zero in under a second,
    and the run reported `completed` with zero findings — a clean bill of
    health for a 213 MB installer nobody had looked inside."""

    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in (
            RunStatus.COMPLETED,
            RunStatus.DEGRADED,
            RunStatus.FAILED,
            RunStatus.CANCELLED,
        )

    @property
    def produced_results(self) -> bool:
        """The run got far enough to have written findings worth reading."""
        return self in (RunStatus.COMPLETED, RunStatus.DEGRADED)


class StageStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    OOM = "oom"
    FAILED = "failed"
    TRUNCATED = "truncated"
    """An extraction budget was hit, so part of the artifact was never opened.

    Its own status rather than a flavour of `completed`, because the gate reads
    `is_degraded` to decide whether a scan can support a PASS — and a partial
    tree cannot. Found in the field: a 213 MB installer truncated at 20 000
    files still returned `completed`, and the gate passed a build whose
    application code had never been unpacked."""

    SKIPPED = "skipped"

    @property
    def is_degraded(self) -> bool:
        """Degraded stages still let the run finish, but the report must say so
        rather than implying the artifact was clean."""
        return self in (
            StageStatus.TIMEOUT,
            StageStatus.OOM,
            StageStatus.FAILED,
            StageStatus.TRUNCATED,
        )


class FindingStatus(StrEnum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"
    NEEDS_REVIEW = "needs_review"

    @property
    def is_actionable(self) -> bool:
        return self in (FindingStatus.OPEN, FindingStatus.CONFIRMED, FindingStatus.NEEDS_REVIEW)


class DetectedBy(StrEnum):
    """Provenance. The UI renders these in visually distinct treatments and the
    'deterministic view only' toggle hides anything that is not ``RULE``.

    ``LLM`` alone is deliberately not a permitted value on a persisted finding:
    a model may never assert a finding into existence (§2.5). It exists in the
    enum so that the constraint can be expressed and tested.
    """

    RULE = "rule"
    BOTH = "both"
    LLM = "llm"


class ArtifactKind(StrEnum):
    """What S1 identified. Drives which unpackers and analyzers get scheduled."""

    UNKNOWN = "unknown"
    PE = "pe"
    ELF = "elf"
    MACHO = "macho"
    DOTNET = "dotnet"
    JAVA = "java"
    ARCHIVE = "archive"
    INSTALLER = "installer"
    FIRMWARE = "firmware"
    FILESYSTEM = "filesystem"
    SCRIPT = "script"
    CONFIG = "config"
    CERTIFICATE = "certificate"
    DATA = "data"
    TEXT = "text"


class LlmVerdict(StrEnum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"
    ERROR = "error"
    """The model was unreachable or returned unparseable output. Recorded
    rather than hidden — a run where triage silently did nothing must not look
    like a run where triage confirmed everything."""


class AuditAction(StrEnum):
    RUN_CREATED = "run_created"
    ARTIFACT_UPLOADED = "artifact_uploaded"
    ATTESTATION_RECORDED = "attestation_recorded"
    PLAINTEXT_REVEALED = "plaintext_revealed"
    PLAINTEXT_PURGED = "plaintext_purged"
    """A run's retained secret values deleted because its retention ended.
    Carries the count, so the deletion is provable rather than assumed."""
    FINDING_STATUS_CHANGED = "finding_status_changed"
    SUPPRESSION_CREATED = "suppression_created"
    LLM_CALL = "llm_call"
    EXPORT = "export"
    CONFIG_CHANGED = "config_changed"
    RUN_REQUEUED = "run_requeued"
    """A queued run whose Celery task was lost, re-dispatched by the recovery
    sweep. Counted from this log rather than a column, so the trail an operator
    reads is the same one the sweep reasons about."""

    RUN_ORPHANED = "run_orphaned"
    """A run failed because its task was lost and could not be recovered."""

    TOKEN_CREATED = "token_created"
    TOKEN_REVOKED = "token_revoked"
    AUTH_FAILED = "auth_failed"
    """A rejected credential. Recorded because a burst of these is the first
    visible sign of someone probing the gate, and a control nobody can audit is
    not a control."""
