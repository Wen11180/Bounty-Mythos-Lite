"""add mythos brain learning signals

Revision ID: 0002_mythos_brain
Revises: 0001_initial
Create Date: 2026-07-03
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0002_mythos_brain"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("pipeline_runs") as batch_op:
        batch_op.add_column(sa.Column("program_id", sa.String(length=100), nullable=True))
        batch_op.create_foreign_key(
            "fk_pipeline_runs_program_id_programs",
            "programs",
            ["program_id"],
            ["id"],
        )
    op.create_table(
        "learning_signals",
        sa.Column("id", sa.String(length=100), primary_key=True),
        sa.Column("program_id", sa.String(length=100), sa.ForeignKey("programs.id"), nullable=False),
        sa.Column("playbook_id", sa.String(length=100), nullable=False),
        sa.Column("outcome", sa.String(length=50), nullable=False),
        sa.Column("surface_key", sa.String(length=255), nullable=True),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("learning_signals")
    with op.batch_alter_table("pipeline_runs") as batch_op:
        batch_op.drop_constraint("fk_pipeline_runs_program_id_programs", type_="foreignkey")
        batch_op.drop_column("program_id")
