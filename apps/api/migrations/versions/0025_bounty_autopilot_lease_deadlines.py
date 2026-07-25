"""Bind Autopilot leases to one authorization generation and deadline."""

from alembic import op
import sqlalchemy as sa


revision = "0025_bounty_autopilot_lease_deadlines"
down_revision = "0024_bounty_autopilot_reservation_bounds"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "execution_leases",
        sa.Column("authorization_id", sa.String(length=100), nullable=True),
    )
    op.add_column(
        "execution_leases",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_execution_leases_campaign_authorization_status",
        "execution_leases",
        ["campaign_id", "authorization_id", "status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_execution_leases_campaign_authorization_status",
        table_name="execution_leases",
    )
    op.drop_column("execution_leases", "expires_at")
    op.drop_column("execution_leases", "authorization_id")
