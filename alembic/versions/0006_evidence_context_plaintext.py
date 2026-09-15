"""Keep the unmasked context window when a run retains plaintext.

`context_snippet` masks the finding's own value, which is right for the model
and wrong for an operator who opted into plaintext retention and wants to read
the surrounding bytes as they are. Nullable, and populated only under
`retain_plaintext` — the same rule as `value_plaintext`.

Revision ID: 0006_evidence_context_plaintext
Revises: 0005_analyzer_logs
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_evidence_context_plaintext"
down_revision: str | None = "0005_analyzer_logs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("evidence", sa.Column("context_plaintext", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("evidence", "context_plaintext")
