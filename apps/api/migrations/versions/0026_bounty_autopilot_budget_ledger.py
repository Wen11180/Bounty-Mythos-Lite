"""Persist Autopilot authorization-generation budget reservations."""

from alembic import op
import sqlalchemy as sa


revision = "0026_bounty_autopilot_budget_ledger"
down_revision = "0025_bounty_autopilot_lease_deadlines"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "execution_leases",
        sa.Column("duration_reserved_seconds", sa.Integer(), nullable=True),
    )
    op.add_column(
        "execution_leases",
        sa.Column("cost_units_reserved", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("execution_leases", "cost_units_reserved")
    op.drop_column("execution_leases", "duration_reserved_seconds")
