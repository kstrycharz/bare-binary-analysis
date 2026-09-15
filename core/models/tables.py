"""The schema.

Kept in one module because these tables are densely cross-referential and
splitting them across files buys nothing but import cycles.

Two things here carry the determinism guarantee of §2.5 and should be changed
only deliberately:

* ``Finding.id`` is **content-derived**, not a sequence or a UUID. Two runs of
  the same artifact with the same rule pack produce the same finding IDs, which
  is what makes "what is new since the last release" answerable by set
  difference rather than by fuzzy matching.
* ``RunManifest`` records everything that could change a result — artifact
  hash, rule-pack hash, image digests, tool versions. Two runs with matching
  manifests must produce matching findings, and the report prints it.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from core.models.base import Base, TimestampMixin, new_uuid
from core.models.enums import (
    ArtifactKind,
    AuditAction,
    DetectedBy,
    FindingStatus,
    RunStatus,
    Severity,
    StageStatus,
)


class Run(Base, TimestampMixin):
    """One scan of one submitted artifact."""

    __tablename__ = "runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    status: Mapped[str] = mapped_column(String(16), default=RunStatus.QUEUED, index=True)
    profile: Mapped[str] = mapped_column(String(32), default="standard")
    """quick | standard | deep — decides which stages are scheduled."""

    root_artifact_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True
    )

    # --- the authorization gate (§14) -------------------------------------
    # Not nullable, no default. Ingestion is impossible without it, and the
    # values are copied into every report.
    attested_by: Mapped[str] = mapped_column(String(255), nullable=False)
    attestation_reference: Mapped[str] = mapped_column(Text, nullable=False)
    """Free text: a contract, ticket, or engagement reference. 'yes' is not a
    useful audit record; the UI says so."""
    attested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # --- policy captured at run time, not read from config at report time ---
    llm_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    retain_plaintext: Mapped[bool] = mapped_column(Boolean, default=False)
    dynamic_enabled: Mapped[bool] = mapped_column(Boolean, default=False)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)

    # --- advisory: the `summarize` role's run-level briefing ----------------
    llm_summary: Mapped[str | None] = mapped_column(Text)
    """One reviewer-facing paragraph over the whole run. Advisory like every
    other llm_* field: null unless someone asked for it, and the report is
    complete without it."""
    llm_summary_model: Mapped[str | None] = mapped_column(String(128))
    llm_summary_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    previous_run_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("runs.id", ondelete="SET NULL")
    )
    """Prior run over the same root artifact path, for run diffing."""

    artifacts: Mapped[list[Artifact]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
        foreign_keys="Artifact.run_id",
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    stages: Mapped[list[RunStage]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    manifest: Mapped[RunManifest | None] = relationship(
        back_populates="run", cascade="all, delete-orphan", uselist=False
    )


class RunManifest(Base, TimestampMixin):
    """Everything that could change a result. See module docstring."""

    __tablename__ = "run_manifests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("runs.id", ondelete="CASCADE"), unique=True, index=True
    )

    bare_version: Mapped[str] = mapped_column(String(32))
    artifact_sha256: Mapped[str] = mapped_column(String(64))
    rule_pack_version: Mapped[str] = mapped_column(String(32))
    rule_pack_hash: Mapped[str] = mapped_column(String(64))
    image_digests: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    """analyzer name -> resolved sha256. Digests, not tags: tags drift."""
    tool_versions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    recon: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    """The reconnaissance inventory: what kinds of things are in the artifact,
    swept independently of the rule pack. Not findings — see core/rules/recon.py
    for why the two are deliberately separate."""

    components: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    """The bill of materials: what this artifact is made of.

    On the manifest rather than its own table because it is a *property of the
    run* in exactly the way the rule-pack hash is — re-scanning with a newer
    detector should produce a new inventory beside a new set of findings, not
    mutate a shared one."""

    residue: Mapped[list[Any]] = mapped_column(JSON, default=list)
    """Strings no rule matched, sampled during the scan. Input to the AI
    rule-author loop (core/llm/discovery.py). Deliberately stored with the
    manifest rather than as evidence: it is not a finding and never becomes
    one — a human merges a proposed rule, and the *rule* produces findings."""

    run: Mapped[Run] = relationship(back_populates="manifest")

    @property
    def fingerprint(self) -> str:
        """One hash over the whole manifest. Two runs sharing this must produce
        identical findings; the determinism test asserts exactly that."""
        parts = [
            self.bare_version,
            self.artifact_sha256,
            self.rule_pack_version,
            self.rule_pack_hash,
            *(f"{k}={v}" for k, v in sorted(self.image_digests.items())),
            *(f"{k}={v}" for k, v in sorted(self.tool_versions.items())),
        ]
        return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()


class RunStage(Base, TimestampMixin):
    """One analyzer execution. Surfaced in the UI as live progress, and in the
    report as the methodology appendix auditors ask for."""

    __tablename__ = "run_stages"
    __table_args__ = (UniqueConstraint("run_id", "artifact_id", "analyzer"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("runs.id", ondelete="CASCADE"), index=True
    )
    artifact_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("artifacts.id", ondelete="CASCADE")
    )
    analyzer: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default=StageStatus.PENDING)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_s: Mapped[float | None] = mapped_column(Float)
    exit_code: Mapped[int | None] = mapped_column(Integer)
    image_digest: Mapped[str | None] = mapped_column(String(128))
    error: Mapped[str | None] = mapped_column(Text)
    evidence_count: Mapped[int] = mapped_column(Integer, default=0)

    # --- retained analyzer output (bounty: analyzer-logs) -------------------
    # Key + size + flag only. The bytes live in object storage under a
    # `logs/` prefix — a chatty analyzer must never be able to grow this row
    # (ADR-0032).
    log_key: Mapped[str | None] = mapped_column(Text)
    log_bytes: Mapped[int | None] = mapped_column(Integer)
    log_truncated: Mapped[bool] = mapped_column(Boolean, default=False)

    run: Mapped[Run] = relationship(back_populates="stages")


class Artifact(Base, TimestampMixin):
    """A file under analysis. Self-referencing, because the unpack tree is a
    real tree: the report must be able to say
    ``setup.exe -> app.7z -> resources/app.asar -> config/prod.json``.
    """

    __tablename__ = "artifacts"
    __table_args__ = (
        Index("ix_artifacts_run_parent", "run_id", "parent_id"),
        Index("ix_artifacts_sha256", "sha256"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("runs.id", ondelete="CASCADE"), index=True
    )
    parent_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("artifacts.id", ondelete="CASCADE")
    )

    name: Mapped[str] = mapped_column(String(512))
    path_in_tree: Mapped[str] = mapped_column(Text)
    """Full path from the root artifact, using ``->`` between container
    boundaries. Denormalised on purpose: every finding location renders it, and
    walking parents per finding is the obvious way to make the findings page
    slow."""
    depth: Mapped[int] = mapped_column(Integer, default=0)

    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(BigInteger)
    storage_key: Mapped[str | None] = mapped_column(Text)
    """Object-store key. Null for artifacts we chose not to retain."""

    kind: Mapped[str] = mapped_column(String(24), default=ArtifactKind.UNKNOWN)
    media_type: Mapped[str | None] = mapped_column(String(255))
    architecture: Mapped[str | None] = mapped_column(String(32))
    identified: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    """S1 output: compiler, packer, build metadata, PDB path, signing chain."""

    extracted_by: Mapped[str | None] = mapped_column(String(64))

    run: Mapped[Run] = relationship(back_populates="artifacts", foreign_keys=[run_id])
    children: Mapped[list[Artifact]] = relationship(
        back_populates="parent", cascade="all, delete-orphan"
    )
    parent: Mapped[Artifact | None] = relationship(back_populates="children", remote_side=[id])


class Evidence(Base, TimestampMixin):
    """Raw analyzer output, before correlation.

    Analyzers write independent evidence rows and never findings, so that
    parallel execution cannot affect the result: the correlator sorts before
    merging (§2.5).
    """

    __tablename__ = "evidence"
    __table_args__ = (Index("ix_evidence_run_rule", "run_id", "rule_id"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("runs.id", ondelete="CASCADE"), index=True
    )
    artifact_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("artifacts.id", ondelete="CASCADE"), index=True
    )
    analyzer: Mapped[str] = mapped_column(String(64))
    rule_id: Mapped[str] = mapped_column(String(128), index=True)

    value_hash: Mapped[str] = mapped_column(String(64), index=True)
    value_masked: Mapped[str] = mapped_column(Text)
    value_plaintext: Mapped[str | None] = mapped_column(Text)
    """Populated only when the run opted into plaintext retention. Subject to
    TTL and the auto-purge job."""

    offset: Mapped[int | None] = mapped_column(BigInteger)
    section: Mapped[str | None] = mapped_column(String(128))
    encoding: Mapped[str | None] = mapped_column(String(16))
    """ascii | utf-16le — worth surfacing, because a secret found only in wide
    strings is one most scanners miss."""
    entropy: Mapped[float | None] = mapped_column(Float)
    context_snippet: Mapped[str | None] = mapped_column(Text)
    context_plaintext: Mapped[str | None] = mapped_column(Text)
    """``context_snippet`` unmasked. Same retention rule as ``value_plaintext``,
    and never what the LLM layer reads — prompts use ``context_snippet``."""
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class Finding(Base, TimestampMixin):
    """A correlated, deduplicated result. One per distinct secret, with every
    place it appears hanging off ``locations``."""

    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_run_severity", "run_id", "severity"),
        Index("ix_findings_value_hash", "value_hash"),
        CheckConstraint(
            "detected_by <> 'llm'",
            name="no_llm_only_findings",
        ),
    )

    # Composite primary key, and it has to be. `id` is derived from content
    # *excluding* the run, which is what makes "what is new since the last
    # release" a set difference rather than a fuzzy match. The consequence is
    # that re-scanning the same artifact legitimately produces the same id
    # again — the same finding, in a different run — so the run must be part
    # of the key. Making `id` alone the primary key means the second scan of
    # any artifact dies on a unique violation.
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    """Content-derived; see :meth:`compute_id`. Never a sequence number.
    Stable across runs, so the same secret carries the same id in every
    release that ships it."""

    run_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("runs.id", ondelete="CASCADE"), primary_key=True, index=True
    )
    rule_id: Mapped[str] = mapped_column(String(128), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(512))

    # --- deterministic fields: these come from the rule, never from a model --
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    value_masked: Mapped[str] = mapped_column(Text)
    value_hash: Mapped[str] = mapped_column(String(64))
    entropy: Mapped[float | None] = mapped_column(Float)
    context_snippet: Mapped[str | None] = mapped_column(Text)
    cwe: Mapped[str | None] = mapped_column(String(16))
    tags: Mapped[list[Any]] = mapped_column(JSON, default=list)
    remediation_md: Mapped[str | None] = mapped_column(Text)

    detected_by: Mapped[str] = mapped_column(String(8), default=DetectedBy.RULE)
    status: Mapped[str] = mapped_column(String(20), default=FindingStatus.OPEN, index=True)

    # --- advisory fields: clearly separated, hidden by the determinism toggle -
    llm_verdict: Mapped[str | None] = mapped_column(String(20))
    llm_reasoning: Mapped[str | None] = mapped_column(Text)
    llm_model: Mapped[str | None] = mapped_column(String(128))
    llm_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    llm_explanation: Mapped[str | None] = mapped_column(Text)
    """Long-form 'why does this matter, what do I do about it' prose from the
    `explain` role. Separate from `llm_reasoning`, which is triage's one-line
    justification for a verdict: they answer different questions, come from
    different models under the default routing, and conflating them would mean
    running explain silently overwrote the audit trail of the triage decision."""
    llm_explained_by: Mapped[str | None] = mapped_column(String(128))
    llm_explained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    llm_investigation: Mapped[str | None] = mapped_column(Text)
    """The `investigate` role's conclusion after using tools on the artifact.
    Distinct from `llm_explanation` for the same reason that one is distinct
    from `llm_reasoning`: explanation is written from what the scanner already
    knew, investigation from what the model went and looked at."""
    llm_investigation_steps: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON)
    """Every tool call and result, in order. This is what makes the conclusion
    checkable: a claim with no supporting step in here is a claim to distrust."""
    llm_investigation_confidence: Mapped[str | None] = mapped_column(String(10))
    llm_investigated_by: Mapped[str | None] = mapped_column(String(128))
    llm_investigated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    first_seen_run_id: Mapped[str | None] = mapped_column(String(36))
    suppressed_by: Mapped[str | None] = mapped_column(String(64))

    run: Mapped[Run] = relationship(back_populates="findings")
    locations: Mapped[list[FindingLocation]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )

    @staticmethod
    def compute_id(rule_id: str, value_hash: str, artifact_path: str, offset: int | None) -> str:
        """``hash(rule_id + value_hash + artifact_path + offset)``.

        Stable across re-runs and comparable across releases, which is what
        makes run diffing a set operation. Note it deliberately does *not*
        include the run id.
        """
        payload = "\x1f".join([rule_id, value_hash, artifact_path, str(offset if offset else 0)])
        return hashlib.sha256(payload.encode()).hexdigest()[:32]

    @property
    def severity_rank(self) -> int:
        return Severity(self.severity).rank

    @property
    def is_ai_influenced(self) -> bool:
        return self.detected_by != DetectedBy.RULE or self.llm_verdict is not None


class FindingLocation(Base):
    """Where a finding appears. The same key baked into 40 unpacked copies is
    one finding with 40 locations, not 40 findings."""

    __tablename__ = "finding_locations"
    __table_args__ = (
        # Composite FK, following the composite key on findings.
        ForeignKeyConstraint(
            ["finding_id", "run_id"],
            ["findings.id", "findings.run_id"],
            ondelete="CASCADE",
        ),
        UniqueConstraint("finding_id", "run_id", "artifact_id", "offset"),
        Index("ix_finding_locations_finding", "run_id", "finding_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    finding_id: Mapped[str] = mapped_column(String(64))
    run_id: Mapped[str] = mapped_column(String(36))
    artifact_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("artifacts.id", ondelete="CASCADE")
    )
    path_in_tree: Mapped[str] = mapped_column(Text)
    offset: Mapped[int | None] = mapped_column(BigInteger)
    section: Mapped[str | None] = mapped_column(String(128))
    encoding: Mapped[str | None] = mapped_column(String(16))
    xref_function: Mapped[str | None] = mapped_column(String(255))
    """Filled by S4. 'this string exists' is noise; 'this string is passed to
    MQTTClient_connect' is a finding."""

    finding: Mapped[Finding] = relationship(back_populates="locations")


class ApiToken(Base, TimestampMixin):
    """A credential for the API.

    The plaintext is shown once at creation and never stored — only
    ``token_hash``, which is what the lookup is keyed on. A dump of this table
    therefore yields nothing usable, which is the point: the rows describe
    *which* credentials exist, not what they are.

    Revocation is a flag rather than a delete. "Who could reach this API in
    March, and who revoked them" is an audit question, and a deleted row cannot
    answer it.
    """

    __tablename__ = "api_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(128))
    """Human label — 'github-actions release pipeline', 'kyle laptop'. What
    makes rotation possible: you cannot retire a credential nobody can name."""

    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    token_prefix: Mapped[str] = mapped_column(String(32))
    """The redacted form, for display. Lets an operator match a row to a log
    line without the plaintext existing anywhere."""

    scope: Mapped[str] = mapped_column(String(16), default="ci")
    created_by: Mapped[str] = mapped_column(String(255), default="system")

    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    """Optional, unlike a waiver's expiry. A CI token that rotates on a
    schedule is better, but a build pipeline that dies at 3am because a token
    silently lapsed is how teams end up setting no expiry at all — so this is
    encouraged in the docs and not enforced by the schema."""

    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    """Best-effort and deliberately coarse: updated on use, but a token used
    twice in the same second records one timestamp. It exists to answer "is
    anything still using this?" before revoking, not to be a request log."""

    use_count: Mapped[int] = mapped_column(Integer, default=0)

    def is_active(self, now: datetime) -> bool:
        if self.revoked_at is not None:
            return False
        return not (self.expires_at is not None and self.expires_at <= now)


class AuditLog(Base, TimestampMixin):
    """Append-only. There is deliberately no update or delete path."""

    __tablename__ = "audit_log"
    __table_args__ = (Index("ix_audit_run_action", "run_id", "action"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    run_id: Mapped[str | None] = mapped_column(String(36), index=True)
    action: Mapped[str] = mapped_column(String(40), index=True)
    actor: Mapped[str] = mapped_column(String(255), default="system")
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    @classmethod
    def record(
        cls,
        action: AuditAction,
        *,
        actor: str = "system",
        run_id: str | None = None,
        **detail: Any,
    ) -> AuditLog:
        return cls(action=action, actor=actor, run_id=run_id, detail=detail)


class Suppression(Base, TimestampMixin):
    """Keyed on value hash + rule + path pattern, and portable across runs via
    a checked-in ``.bare-ignore.yaml``.

    If a user cannot suppress a known-benign finding once and have it stay
    suppressed, they stop using the tool by week three.
    """

    __tablename__ = "suppressions"
    __table_args__ = (UniqueConstraint("value_hash", "rule_id", "path_pattern"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    value_hash: Mapped[str] = mapped_column(String(64), index=True)
    rule_id: Mapped[str] = mapped_column(String(128))
    path_pattern: Mapped[str] = mapped_column(Text, default="*")
    reason: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(String(255), default="system")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class LlmCall(Base, TimestampMixin):
    """Every outbound model call.

    "What exactly did you send to OpenAI?" is a question a security team will
    ask during procurement, and the tool must answer it precisely rather than
    approximately.
    """

    __tablename__ = "llm_calls"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    run_id: Mapped[str | None] = mapped_column(String(36), index=True)
    finding_id: Mapped[str | None] = mapped_column(String(64), index=True)

    provider: Mapped[str] = mapped_column(String(64))
    model: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(32))
    is_local: Mapped[bool] = mapped_column(Boolean, default=True)
    redaction_level: Mapped[str] = mapped_column(String(16), default="strict")

    prompt_hash: Mapped[str] = mapped_column(String(64))
    prompt_rendered: Mapped[str | None] = mapped_column(Text)
    """The exact text sent. Retained so the audit panel can show it verbatim."""
    response_text: Mapped[str | None] = mapped_column(Text)

    prompt_tokens: Mapped[int | None] = mapped_column(Integer)
    completion_tokens: Mapped[int | None] = mapped_column(Integer)
    duration_s: Mapped[float | None] = mapped_column(Float)
    cached: Mapped[bool] = mapped_column(Boolean, default=False)
    error: Mapped[str | None] = mapped_column(Text)
