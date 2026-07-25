"""Persist the comparison reservation for an R2 differential observation."""

from alembic import op
import sqlalchemy as sa


revision = "0028_bounty_autopilot_r2_observation_pair"
down_revision = "0027_bounty_autopilot_observation_binding"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "autopilot_observations",
        sa.Column("comparison_reservation_id", sa.String(length=128), nullable=True),
    )
    op.create_index(
        "ix_autopilot_observations_campaign_comparison_reservation",
        "autopilot_observations",
        ["campaign_id", "comparison_reservation_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_autopilot_observations_campaign_comparison_reservation",
        table_name="autopilot_observations",
    )
    op.drop_column("autopilot_observations", "comparison_reservation_id")
