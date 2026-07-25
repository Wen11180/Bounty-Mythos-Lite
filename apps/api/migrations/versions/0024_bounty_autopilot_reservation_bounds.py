"""Make Autopilot reservation accounting atomic and unambiguous."""

from alembic import op
import sqlalchemy as sa


revision = "0024_bounty_autopilot_reservation_bounds"
down_revision = "0023_bounty_autopilot_evidence_lineage"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "execution_leases",
        sa.Column(
            "requests_reserved",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.create_index(
        "uq_execution_request_ledger_reservation",
        "execution_request_ledger",
        ["campaign_id", "reservation_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(
        "uq_execution_request_ledger_reservation",
        table_name="execution_request_ledger",
    )
    op.drop_column("execution_leases", "requests_reserved")
