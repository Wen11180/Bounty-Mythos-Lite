"""add llm run audit fields

Revision ID: 0004_llm_run_audit_fields
Revises: 0003_evidence_aware_learning_signals
Create Date: 2026-07-03
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0004_llm_run_audit_fields"
down_revision: str | None = "0003_evidence_aware_learning_signals"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("llm_runs") as batch_op:
        batch_op.add_column(
            sa.Column("purpose", sa.String(length=100), nullable=False, server_default="general")
        )
        batch_op.add_column(
            sa.Column("safety_notes", sa.JSON(), nullable=False, server_default="[]")
        )
        batch_op.add_column(sa.Column("created_at", sa.DateTime(timezone=True), nullable=True))
    with op.batch_alter_table("llm_runs") as batch_op:
        batch_op.alter_column("purpose", server_default=None)
        batch_op.alter_column("safety_notes", server_default=None)


def downgrade() -> None:
    with op.batch_alter_table("llm_runs") as batch_op:
        batch_op.drop_column("created_at")
        batch_op.drop_column("safety_notes")
        batch_op.drop_column("purpose")
