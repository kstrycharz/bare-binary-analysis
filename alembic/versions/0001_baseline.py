"""Baseline schema.

The schema as it stood before Alembic was introduced. Databases created by the
old ``create_all()`` bootstrap are stamped at this revision rather than having
it replayed against them.

Revision ID: 0001_baseline
Revises: nothing
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001_baseline"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "api_tokens",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("token_prefix", sa.String(length=32), nullable=False),
        sa.Column("scope", sa.String(length=16), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("use_count", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_api_tokens")),
    )
    op.create_index(op.f("ix_api_tokens_created_at"), "api_tokens", ["created_at"], unique=False)
    op.create_index(op.f("ix_api_tokens_token_hash"), "api_tokens", ["token_hash"], unique=True)
    op.create_table(
        "runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("profile", sa.String(length=32), nullable=False),
        sa.Column("root_artifact_id", sa.String(length=36), nullable=True),
        sa.Column("attested_by", sa.String(length=255), nullable=False),
        sa.Column("attestation_reference", sa.Text(), nullable=False),
        sa.Column("attested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("llm_enabled", sa.Boolean(), nullable=False),
        sa.Column("retain_plaintext", sa.Boolean(), nullable=False),
        sa.Column("dynamic_enabled", sa.Boolean(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("previous_run_id", sa.String(length=36), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["previous_run_id"],
            ["runs.id"],
            name=op.f("fk_runs_previous_run_id_runs"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_runs")),
    )
    op.create_index(op.f("ix_runs_created_at"), "runs", ["created_at"], unique=False)
    op.create_index(op.f("ix_runs_status"), "runs", ["status"], unique=False)
    op.create_table(
        "artifacts",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("parent_id", sa.String(length=36), nullable=True),
        sa.Column("name", sa.String(length=512), nullable=False),
        sa.Column("path_in_tree", sa.Text(), nullable=False),
        sa.Column("depth", sa.Integer(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("storage_key", sa.Text(), nullable=True),
        sa.Column("kind", sa.String(length=24), nullable=False),
        sa.Column("media_type", sa.String(length=255), nullable=True),
        sa.Column("architecture", sa.String(length=32), nullable=True),
        sa.Column("identified", sa.JSON(), nullable=False),
        sa.Column("extracted_by", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["parent_id"],
            ["artifacts.id"],
            name=op.f("fk_artifacts_parent_id_artifacts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"], ["runs.id"], name=op.f("fk_artifacts_run_id_runs"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_artifacts")),
    )
    op.create_index(op.f("ix_artifacts_created_at"), "artifacts", ["created_at"], unique=False)
    op.create_index(op.f("ix_artifacts_run_id"), "artifacts", ["run_id"], unique=False)
    op.create_index("ix_artifacts_run_parent", "artifacts", ["run_id", "parent_id"], unique=False)
    op.create_index("ix_artifacts_sha256", "artifacts", ["sha256"], unique=False)
    # `runs.root_artifact_id` points at `artifacts`, and `artifacts.run_id`
    # points back at `runs` — a genuine cycle, not just the wrong order. `runs`
    # is created first with the column but not the constraint; this closes it
    # once `artifacts` exists. Batch mode: Postgres runs this as a plain ALTER,
    # but SQLite has no ALTER-ADD-CONSTRAINT at all, only the recreate-and-copy
    # that batch mode performs — without it this passes review and Postgres,
    # and fails only in the unit suite, which is the one place it is cheap to
    # catch.
    with op.batch_alter_table("runs") as batch_op:
        batch_op.create_foreign_key(
            op.f("fk_runs_root_artifact_id_artifacts"),
            "artifacts",
            ["root_artifact_id"],
            ["id"],
            ondelete="SET NULL",
        )
    op.create_table(
        "audit_log",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=True),
        sa.Column("action", sa.String(length=40), nullable=False),
        sa.Column("actor", sa.String(length=255), nullable=False),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_log")),
    )
    op.create_index(op.f("ix_audit_log_action"), "audit_log", ["action"], unique=False)
    op.create_index(op.f("ix_audit_log_created_at"), "audit_log", ["created_at"], unique=False)
    op.create_index(op.f("ix_audit_log_run_id"), "audit_log", ["run_id"], unique=False)
    op.create_index("ix_audit_run_action", "audit_log", ["run_id", "action"], unique=False)
    op.create_table(
        "llm_calls",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=True),
        sa.Column("finding_id", sa.String(length=64), nullable=True),
        sa.Column("provider", sa.String(length=64), nullable=False),
        sa.Column("model", sa.String(length=128), nullable=False),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("is_local", sa.Boolean(), nullable=False),
        sa.Column("redaction_level", sa.String(length=16), nullable=False),
        sa.Column("prompt_hash", sa.String(length=64), nullable=False),
        sa.Column("prompt_rendered", sa.Text(), nullable=True),
        sa.Column("response_text", sa.Text(), nullable=True),
        sa.Column("prompt_tokens", sa.Integer(), nullable=True),
        sa.Column("completion_tokens", sa.Integer(), nullable=True),
        sa.Column("duration_s", sa.Float(), nullable=True),
        sa.Column("cached", sa.Boolean(), nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_llm_calls")),
    )
    op.create_index(op.f("ix_llm_calls_created_at"), "llm_calls", ["created_at"], unique=False)
    op.create_index(op.f("ix_llm_calls_finding_id"), "llm_calls", ["finding_id"], unique=False)
    op.create_index(op.f("ix_llm_calls_run_id"), "llm_calls", ["run_id"], unique=False)
    op.create_table(
        "suppressions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("value_hash", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column("path_pattern", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_suppressions")),
        sa.UniqueConstraint(
            "value_hash", "rule_id", "path_pattern", name=op.f("uq_suppressions_value_hash")
        ),
    )
    op.create_index(
        op.f("ix_suppressions_created_at"), "suppressions", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_suppressions_value_hash"), "suppressions", ["value_hash"], unique=False
    )
    op.create_table(
        "evidence",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("artifact_id", sa.String(length=36), nullable=False),
        sa.Column("analyzer", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column("value_hash", sa.String(length=64), nullable=False),
        sa.Column("value_masked", sa.Text(), nullable=False),
        sa.Column("value_plaintext", sa.Text(), nullable=True),
        sa.Column("offset", sa.BigInteger(), nullable=True),
        sa.Column("section", sa.String(length=128), nullable=True),
        sa.Column("encoding", sa.String(length=16), nullable=True),
        sa.Column("entropy", sa.Float(), nullable=True),
        sa.Column("context_snippet", sa.Text(), nullable=True),
        sa.Column("extra", sa.JSON(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["artifact_id"],
            ["artifacts.id"],
            name=op.f("fk_evidence_artifact_id_artifacts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"], ["runs.id"], name=op.f("fk_evidence_run_id_runs"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_evidence")),
    )
    op.create_index(op.f("ix_evidence_artifact_id"), "evidence", ["artifact_id"], unique=False)
    op.create_index(op.f("ix_evidence_created_at"), "evidence", ["created_at"], unique=False)
    op.create_index(op.f("ix_evidence_rule_id"), "evidence", ["rule_id"], unique=False)
    op.create_index(op.f("ix_evidence_run_id"), "evidence", ["run_id"], unique=False)
    op.create_index("ix_evidence_run_rule", "evidence", ["run_id", "rule_id"], unique=False)
    op.create_index(op.f("ix_evidence_value_hash"), "evidence", ["value_hash"], unique=False)
    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("rule_id", sa.String(length=128), nullable=False),
        sa.Column("category", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("value_masked", sa.Text(), nullable=False),
        sa.Column("value_hash", sa.String(length=64), nullable=False),
        sa.Column("entropy", sa.Float(), nullable=True),
        sa.Column("context_snippet", sa.Text(), nullable=True),
        sa.Column("cwe", sa.String(length=16), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("remediation_md", sa.Text(), nullable=True),
        sa.Column("detected_by", sa.String(length=8), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("llm_verdict", sa.String(length=20), nullable=True),
        sa.Column("llm_reasoning", sa.Text(), nullable=True),
        sa.Column("llm_model", sa.String(length=128), nullable=True),
        sa.Column("llm_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_seen_run_id", sa.String(length=36), nullable=True),
        sa.Column("suppressed_by", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("detected_by <> 'llm'", name=op.f("ck_findings_no_llm_only_findings")),
        sa.ForeignKeyConstraint(
            ["run_id"], ["runs.id"], name=op.f("fk_findings_run_id_runs"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", "run_id", name=op.f("pk_findings")),
    )
    op.create_index(op.f("ix_findings_category"), "findings", ["category"], unique=False)
    op.create_index(op.f("ix_findings_created_at"), "findings", ["created_at"], unique=False)
    op.create_index(op.f("ix_findings_rule_id"), "findings", ["rule_id"], unique=False)
    op.create_index(op.f("ix_findings_run_id"), "findings", ["run_id"], unique=False)
    op.create_index("ix_findings_run_severity", "findings", ["run_id", "severity"], unique=False)
    op.create_index(op.f("ix_findings_severity"), "findings", ["severity"], unique=False)
    op.create_index(op.f("ix_findings_status"), "findings", ["status"], unique=False)
    op.create_index("ix_findings_value_hash", "findings", ["value_hash"], unique=False)
    op.create_table(
        "run_manifests",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("bare_version", sa.String(length=32), nullable=False),
        sa.Column("artifact_sha256", sa.String(length=64), nullable=False),
        sa.Column("rule_pack_version", sa.String(length=32), nullable=False),
        sa.Column("rule_pack_hash", sa.String(length=64), nullable=False),
        sa.Column("image_digests", sa.JSON(), nullable=False),
        sa.Column("tool_versions", sa.JSON(), nullable=False),
        sa.Column("recon", sa.JSON(), nullable=False),
        sa.Column("residue", sa.JSON(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["run_id"], ["runs.id"], name=op.f("fk_run_manifests_run_id_runs"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_run_manifests")),
    )
    op.create_index(
        op.f("ix_run_manifests_created_at"), "run_manifests", ["created_at"], unique=False
    )
    op.create_index(op.f("ix_run_manifests_run_id"), "run_manifests", ["run_id"], unique=True)
    op.create_table(
        "run_stages",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("artifact_id", sa.String(length=36), nullable=True),
        sa.Column("analyzer", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_s", sa.Float(), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("image_digest", sa.String(length=128), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("evidence_count", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["artifact_id"],
            ["artifacts.id"],
            name=op.f("fk_run_stages_artifact_id_artifacts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["run_id"], ["runs.id"], name=op.f("fk_run_stages_run_id_runs"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_run_stages")),
        sa.UniqueConstraint("run_id", "artifact_id", "analyzer", name=op.f("uq_run_stages_run_id")),
    )
    op.create_index(op.f("ix_run_stages_created_at"), "run_stages", ["created_at"], unique=False)
    op.create_index(op.f("ix_run_stages_run_id"), "run_stages", ["run_id"], unique=False)
    op.create_table(
        "finding_locations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=36), nullable=False),
        sa.Column("artifact_id", sa.String(length=36), nullable=False),
        sa.Column("path_in_tree", sa.Text(), nullable=False),
        sa.Column("offset", sa.BigInteger(), nullable=True),
        sa.Column("section", sa.String(length=128), nullable=True),
        sa.Column("encoding", sa.String(length=16), nullable=True),
        sa.Column("xref_function", sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(
            ["artifact_id"],
            ["artifacts.id"],
            name=op.f("fk_finding_locations_artifact_id_artifacts"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["finding_id", "run_id"],
            ["findings.id", "findings.run_id"],
            name=op.f("fk_finding_locations_finding_id_findings"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_finding_locations")),
        sa.UniqueConstraint(
            "finding_id",
            "run_id",
            "artifact_id",
            "offset",
            name=op.f("uq_finding_locations_finding_id"),
        ),
    )
    op.create_index(
        "ix_finding_locations_finding", "finding_locations", ["run_id", "finding_id"], unique=False
    )


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index("ix_finding_locations_finding", table_name="finding_locations")
    op.drop_table("finding_locations")
    op.drop_index(op.f("ix_run_stages_run_id"), table_name="run_stages")
    op.drop_index(op.f("ix_run_stages_created_at"), table_name="run_stages")
    op.drop_table("run_stages")
    op.drop_index(op.f("ix_run_manifests_run_id"), table_name="run_manifests")
    op.drop_index(op.f("ix_run_manifests_created_at"), table_name="run_manifests")
    op.drop_table("run_manifests")
    op.drop_index("ix_findings_value_hash", table_name="findings")
    op.drop_index(op.f("ix_findings_status"), table_name="findings")
    op.drop_index(op.f("ix_findings_severity"), table_name="findings")
    op.drop_index("ix_findings_run_severity", table_name="findings")
    op.drop_index(op.f("ix_findings_run_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_rule_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_created_at"), table_name="findings")
    op.drop_index(op.f("ix_findings_category"), table_name="findings")
    op.drop_table("findings")
    op.drop_index(op.f("ix_evidence_value_hash"), table_name="evidence")
    op.drop_index("ix_evidence_run_rule", table_name="evidence")
    op.drop_index(op.f("ix_evidence_run_id"), table_name="evidence")
    op.drop_index(op.f("ix_evidence_rule_id"), table_name="evidence")
    op.drop_index(op.f("ix_evidence_created_at"), table_name="evidence")
    op.drop_index(op.f("ix_evidence_artifact_id"), table_name="evidence")
    op.drop_table("evidence")
    op.drop_index(op.f("ix_suppressions_value_hash"), table_name="suppressions")
    op.drop_index(op.f("ix_suppressions_created_at"), table_name="suppressions")
    op.drop_table("suppressions")
    # The FK added by ALTER TABLE in upgrade() must go before either table it
    # joins does, or dropping `artifacts` while `runs` still references it
    # (or `runs` while `artifacts` still does) fails exactly as the cycle it
    # was closing.
    with op.batch_alter_table("runs") as batch_op:
        batch_op.drop_constraint("fk_runs_root_artifact_id_artifacts", type_="foreignkey")
    op.drop_index("ix_artifacts_sha256", table_name="artifacts")
    op.drop_index("ix_artifacts_run_parent", table_name="artifacts")
    op.drop_index(op.f("ix_artifacts_run_id"), table_name="artifacts")
    op.drop_index(op.f("ix_artifacts_created_at"), table_name="artifacts")
    op.drop_table("artifacts")
    op.drop_index(op.f("ix_runs_status"), table_name="runs")
    op.drop_index(op.f("ix_runs_created_at"), table_name="runs")
    op.drop_table("runs")
    op.drop_index(op.f("ix_llm_calls_run_id"), table_name="llm_calls")
    op.drop_index(op.f("ix_llm_calls_finding_id"), table_name="llm_calls")
    op.drop_index(op.f("ix_llm_calls_created_at"), table_name="llm_calls")
    op.drop_table("llm_calls")
    op.drop_index("ix_audit_run_action", table_name="audit_log")
    op.drop_index(op.f("ix_audit_log_run_id"), table_name="audit_log")
    op.drop_index(op.f("ix_audit_log_created_at"), table_name="audit_log")
    op.drop_index(op.f("ix_audit_log_action"), table_name="audit_log")
    op.drop_table("audit_log")
    op.drop_index(op.f("ix_api_tokens_token_hash"), table_name="api_tokens")
    op.drop_index(op.f("ix_api_tokens_created_at"), table_name="api_tokens")
    op.drop_table("api_tokens")
