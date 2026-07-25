"""Bind Autopilot observations to one durable execution reservation."""

from alembic import op
import sqlalchemy as sa


revision = "0027_bounty_autopilot_observation_binding"
down_revision = "0026_bounty_autopilot_budget_ledger"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Additive DDL keeps SQLite upgrades in-place.  Rebuilding this table via
    # batch_alter_table triggers a column-order cycle in current SQLAlchemy.
    op.add_column(
        "autopilot_observations",
        sa.Column("lease_id", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "autopilot_observations",
        sa.Column("reservation_id", sa.String(length=128), nullable=True),
    )
    op.create_index(
        "uq_autopilot_observations_campaign_reservation",
        "autopilot_observations",
        ["campaign_id", "reservation_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        "uq_autopilot_observations_campaign_reservation",
        table_name="autopilot_observations",
    )
    op.drop_column("autopilot_observations", "reservation_id")
    op.drop_column("autopilot_observations", "lease_id")
