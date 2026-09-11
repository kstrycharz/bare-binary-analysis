"""Keep the logs the scanning containers produce.

The driver already collects analyzer stdout/stderr; until now they were handed
back on the `SandboxResult` and dropped. These three columns are *pointers*,
deliberately fixed-width: the log bytes live in object storage, so a chatty
analyzer cannot grow a `run_stages` row without bound (ADR-0032). Nullable,
because stage rows predating this migration — and stages whose bucket write
failed — simply have no log to show.

Revision ID: 0005_analyzer_logs
Revises: 0004_llm_investigation
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005_analyzer_logs"
down_revision: str | None = "0004_llm_investigation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("run_stages", sa.Column("log_key", sa.Text(), nullable=True))
    op.add_column("run_stages", sa.Column("log_bytes", sa.Integer(), nullable=True))
    op.add_column(
        "run_stages",
        sa.Column("log_truncated", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("run_stages", "log_truncated")
    op.drop_column("run_stages", "log_bytes")
    op.drop_column("run_stages", "log_key")
