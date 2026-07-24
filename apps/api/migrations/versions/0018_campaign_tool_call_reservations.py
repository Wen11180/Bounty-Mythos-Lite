"""Persist durable local-tool call reservations."""

from alembic import op
import sqlalchemy as sa


revision = "0018_campaign_tool_call_reservations"
down_revision = "0017_autonomous_research_wakeup_cadence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "campaign_budgets",
        sa.Column(
            "tool_calls_reserved",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )


def downgrade() -> None:
    op.drop_column("campaign_budgets", "tool_calls_reserved")
