"""API response shapes.

Deliberately separate from the SQLAlchemy models. The wire format is a
contract with the dashboard and with CI consumers; the database schema is an
implementation detail, and coupling them means every column rename becomes a
breaking API change.

Note how AI-derived fields are grouped into a single nullable ``llm`` object
rather than spread across the finding. The dashboard's "deterministic view
only" toggle is then one field to drop, not six to remember (§2.5).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AttestationIn(BaseModel):
    """The authorization gate. Required on every upload."""

    attested_by: str = Field(min_length=1, max_length=255)
    attestation_reference: str = Field(
        min_length=8,
        max_length=2000,
        description=(
            "The contract, ticket, or engagement authorising analysis of this "
            "artifact. 'yes' is not a useful audit record."
        ),
    )


class RunSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    status: str
    profile: str
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None

    attested_by: str
    attestation_reference: str

    llm_enabled: bool = False
    artifact_name: str | None = None
    artifact_sha256: str | None = None
    artifact_size_bytes: int | None = None

    finding_count: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)
    artifact_count: int = 1
    """Files analysed, including everything unpacked out of the artifact."""
    new_since_previous: int | None = Field(
        default=None,
        description="Findings not present in the previous run of this artifact.",
    )


class StageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    """The stage row id — the handle the logs endpoint is addressed by."""
    analyzer: str
    status: str
    duration_s: float | None = None
    exit_code: int | None = None
    evidence_count: int = 0
    error: str | None = None
    image_digest: str | None = None
    log_bytes: int | None = None
    """Size of the retained analyzer output. The bytes live in object storage;
    this row only points at them, so a chatty analyzer cannot grow it."""
    log_truncated: bool = False


class ManifestOut(BaseModel):
    """Printed in the report and shown in the UI. Two runs with matching
    manifests must produce matching findings."""

    model_config = ConfigDict(from_attributes=True)

    bare_version: str
    artifact_sha256: str
    rule_pack_version: str
    rule_pack_hash: str
    image_digests: dict[str, Any] = Field(default_factory=dict)
    tool_versions: dict[str, Any] = Field(default_factory=dict)
    fingerprint: str = ""


class ArtifactOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    path_in_tree: str
    depth: int
    sha256: str
    size_bytes: int
    kind: str
    media_type: str | None = None
    architecture: str | None = None
    identified: dict[str, Any] = Field(default_factory=dict)
    finding_count: int = 0
    children: list[ArtifactOut] = Field(default_factory=list)


class RunDetail(RunSummary):
    stages: list[StageOut] = Field(default_factory=list)
    manifest: ManifestOut | None = None
    artifact_tree: ArtifactOut | None = None
    artifact_tree_truncated: bool = False
    """The tree is capped. A recursive installer unpacks to tens of thousands
    of files, which no browser renders and no operator reads; the count in the
    summary remains exact."""
    previous_run_id: str | None = None

    # Advisory, from the `summarize` role. Null until someone asks for it.
    llm_summary: str | None = None
    llm_summary_model: str | None = None
    llm_summary_at: datetime | None = None


class LocationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    artifact_id: str
    path_in_tree: str
    offset: int | None = None
    section: str | None = None
    encoding: str | None = None
    xref_function: str | None = None


class LlmAssessment(BaseModel):
    """Every AI-derived field, in one place, clearly attributed.

    A user must always be able to answer "would this finding exist without the
    AI?" — and for anything above medium, the answer is yes.
    """

    verdict: str
    reasoning: str | None = None
    model: str | None = None
    assessed_at: datetime | None = None


class InvestigationStep(BaseModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    ok: bool
    output: str
    detail: str = ""


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    rule_id: str
    category: str
    title: str

    # Deterministic. These come from the rule and a model cannot change them.
    severity: str
    confidence: float
    value_masked: str
    entropy: float | None = None
    context_snippet: str | None = None
    cwe: str | None = None
    tags: list[str] = Field(default_factory=list)
    remediation_md: str | None = None

    status: str
    detected_by: str
    is_new: bool = False

    locations: list[LocationOut] = Field(default_factory=list)
    location_count: int = 0

    # Empty unless the run opted into plaintext retention (`retain_plaintext`).
    # A list, not a single value, because a clustered finding legitimately
    # covers many — "40 values, e.g. …" is one finding over 40 distinct paths,
    # and showing only the first would be the least useful one to pick.
    #
    # Every route in this router already requires ADMIN scope (ADR-0019), so
    # this is not a new exposure surface: it is the retrieval path for values
    # that were already in the database with no other way to read them back.
    value_plaintexts: list[str] = Field(default_factory=list)

    # Advisory. Null when triage has not run, and hidden entirely by the
    # dashboard's deterministic-view toggle.
    llm: LlmAssessment | None = None

    # Advisory, from the `explain` role. Separate from `llm` above because it
    # answers a different question and, by default, comes from a different
    # model — which is why the model that wrote it is carried alongside it
    # rather than assumed to be the triage one.
    llm_explanation: str | None = None
    llm_explained_by: str | None = None
    llm_explained_at: datetime | None = None

    # Advisory, from the `investigate` role. The steps are the point: a
    # conclusion with no supporting tool call in them is one to distrust.
    llm_investigation: str | None = None
    llm_investigation_steps: list[InvestigationStep] = Field(default_factory=list)
    llm_investigation_confidence: str | None = None
    llm_investigated_by: str | None = None
    llm_investigated_at: datetime | None = None


class FindingPatch(BaseModel):
    status: str | None = None
    note: str | None = None


class ProviderHealthOut(BaseModel):
    name: str
    healthy: bool
    model: str = ""
    detail: str = ""
    latency_s: float | None = None
    is_local: bool = True
    available_models: list[str] = Field(default_factory=list)


class LlmSettingsOut(BaseModel):
    enabled: bool
    egress: str
    redaction: str
    roles: dict[str, str] = Field(default_factory=dict)
    providers: list[ProviderHealthOut] = Field(default_factory=list)
    config_path: str | None = None


class TriageResponse(BaseModel):
    run_id: str
    triaged: int
    confirmed: int
    dismissed: int
    needs_review: int
    errors: int
    duration_s: float
    model: str


class ExplainResponse(BaseModel):
    run_id: str
    finding_id: str
    explanation: str
    model: str
    duration_s: float


class SummaryResponse(BaseModel):
    run_id: str
    summary: str
    model: str
    duration_s: float


class InvestigateResponse(BaseModel):
    run_id: str
    finding_id: str
    conclusion: str
    confidence: str
    steps: int
    model: str
    duration_s: float
    redaction: str


class RunCreated(BaseModel):
    run_id: str
    artifact_name: str
    artifact_sha256: str
    size_bytes: int
    status: str
