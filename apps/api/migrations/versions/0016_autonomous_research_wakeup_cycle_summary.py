"""Persist safe autonomous wakeup cycle summaries."""

from alembic import op
import sqlalchemy as sa


revision = "0016_autonomous_research_wakeup_cycle_summary"
down_revision = "0015_campaign_task_execution_lease"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "autonomous_research_wakeup_states",
        sa.Column("last_cycle_completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "autonomous_research_wakeup_states",
        sa.Column("last_cycle_status", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "autonomous_research_wakeup_states",
        sa.Column("last_cycle_stop_reason", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "autonomous_research_wakeup_states",
        sa.Column(
            "last_cycle_processed_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    op.add_column(
        "autonomous_research_wakeup_states",
        sa.Column(
            "last_cycle_outcome_counts",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'"),
        ),
    )


def downgrade() -> None:
    op.drop_column("autonomous_research_wakeup_states", "last_cycle_outcome_counts")
    op.drop_column("autonomous_research_wakeup_states", "last_cycle_processed_count")
    op.drop_column("autonomous_research_wakeup_states", "last_cycle_stop_reason")
    op.drop_column("autonomous_research_wakeup_states", "last_cycle_status")
    op.drop_column("autonomous_research_wakeup_states", "last_cycle_completed_at")
