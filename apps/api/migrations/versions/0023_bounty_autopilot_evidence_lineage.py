"""Add Autopilot evidence lineage tables."""

from alembic import op
import sqlalchemy as sa


revision = "0023_bounty_autopilot_evidence_lineage"
down_revision = "0022_bounty_autopilot_execution_authority"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "autopilot_observations",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("campaign_id", sa.String(length=100), nullable=False),
        sa.Column("observation_id", sa.String(length=128), nullable=False),
        sa.Column("branch_id", sa.String(length=128), nullable=False),
        sa.Column("plan_digest", sa.String(length=100), nullable=False),
        sa.Column("grade", sa.String(length=32), nullable=False),
        sa.Column("outcome_class", sa.String(length=64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "campaign_id",
            "observation_id",
            name="uq_autopilot_observations_campaign_obs",
        ),
    )


def downgrade() -> None:
    op.drop_table("autopilot_observations")
