"""add evidence context to learning signals

Revision ID: 0003_evidence_aware_learning_signals
Revises: 0002_mythos_brain
Create Date: 2026-07-03
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0003_evidence_aware_learning_signals"
down_revision: str | None = "0002_mythos_brain"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("learning_signals") as batch_op:
        batch_op.add_column(sa.Column("bounty_amount", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("severity_delta", sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column("evidence_quality", sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column("triager_feedback", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("learning_signals") as batch_op:
        batch_op.drop_column("triager_feedback")
        batch_op.drop_column("evidence_quality")
        batch_op.drop_column("severity_delta")
        batch_op.drop_column("bounty_amount")
