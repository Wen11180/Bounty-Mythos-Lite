"""Persist the shared autonomous wakeup cadence."""

from alembic import op
import sqlalchemy as sa


revision = "0017_autonomous_research_wakeup_cadence"
down_revision = "0016_autonomous_research_wakeup_cycle_summary"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "autonomous_research_wakeup_states",
        sa.Column("next_due_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("autonomous_research_wakeup_states", "next_due_at")
