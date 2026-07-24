"""Add execution leases for autonomous research tasks."""

from alembic import op
import sqlalchemy as sa


revision = "0015_campaign_task_execution_lease"
down_revision = "0014_autonomous_research_wakeup"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "campaign_tasks",
        sa.Column("execution_claim_id", sa.String(length=100), nullable=True),
    )
    op.add_column(
        "campaign_tasks",
        sa.Column("execution_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "campaign_tasks",
        sa.Column(
            "execution_lease_expires_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("campaign_tasks", "execution_lease_expires_at")
    op.drop_column("campaign_tasks", "execution_heartbeat_at")
    op.drop_column("campaign_tasks", "execution_claim_id")
