"""Add operating reasons to finding candidates."""

from alembic import op
import sqlalchemy as sa


revision = "0005_finding_operating_reasons"
down_revision = "0004_llm_run_audit_fields"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("operating_reasons", sa.JSON(), nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_column("findings", "operating_reasons")
