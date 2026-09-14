"""Give retained plaintext a deadline.

`plaintext_expires_at` is when a run that retained secret values must stop
serving them; `plaintext_purged_at` is when the purge task actually deleted
them. Both nullable: a run that never retained anything has neither.

Existing retaining runs are expired immediately. Their values were written
unencrypted, which the reveal path no longer serves (core/retention.py), and
the promise these columns exist to keep is that such values do not sit in the
database indefinitely. The first purge pass after upgrade deletes them and
audits the count. A deployment that needs one of those values has to re-scan
with retention on — which now encrypts it.

`CURRENT_TIMESTAMP` and a bare boolean predicate rather than bound parameters,
so the statement renders identically for Postgres, SQLite, and `--sql` offline
mode.

Revision ID: 0005_plaintext_retention
Revises: 0004_llm_investigation
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_plaintext_retention"
down_revision: str | None = "0004_llm_investigation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "runs", sa.Column("plaintext_expires_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "runs", sa.Column("plaintext_purged_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.execute(
        "UPDATE runs SET plaintext_expires_at = CURRENT_TIMESTAMP "
        "WHERE retain_plaintext AND plaintext_expires_at IS NULL"
    )


def downgrade() -> None:
    op.drop_column("runs", "plaintext_purged_at")
    op.drop_column("runs", "plaintext_expires_at")
