"""Add durable Autopilot plans, leases, and request ledger tables."""

from alembic import op
import sqlalchemy as sa


revision = "0022_bounty_autopilot_execution_authority"
down_revision = "0021_bounty_autopilot_assets_branches"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "validation_plans",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("campaign_id", sa.String(length=100), nullable=False),
        sa.Column("plan_id", sa.String(length=128), nullable=False),
        sa.Column("plan_digest", sa.String(length=100), nullable=False),
        sa.Column("branch_id", sa.String(length=128), nullable=False),
        sa.Column("asset_id", sa.String(length=100), nullable=False),
        sa.Column("risk_tier", sa.String(length=8), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("campaign_id", "plan_id", name="uq_validation_plans_campaign_plan"),
    )
    op.create_table(
        "execution_leases",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("campaign_id", sa.String(length=100), nullable=False),
        sa.Column("lease_id", sa.String(length=128), nullable=False),
        sa.Column("plan_id", sa.String(length=128), nullable=False),
        sa.Column("plan_digest", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("r3_approval_id", sa.String(length=128), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("campaign_id", "lease_id", name="uq_execution_leases_campaign_lease"),
    )
    op.create_table(
        "execution_request_ledger",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("campaign_id", sa.String(length=100), nullable=False),
        sa.Column("reservation_id", sa.String(length=128), nullable=False),
        sa.Column("lease_id", sa.String(length=128), nullable=False),
        sa.Column("plan_digest", sa.String(length=100), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "campaign_id",
            "lease_id",
            "idempotency_key",
            name="uq_execution_request_ledger_idempotency",
        ),
    )
    op.add_column(
        "approval_records",
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "approval_records",
        sa.Column("consumed_by_lease_id", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "approval_records",
        sa.Column("single_use_nonce_digest", sa.String(length=100), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("approval_records", "single_use_nonce_digest")
    op.drop_column("approval_records", "consumed_by_lease_id")
    op.drop_column("approval_records", "consumed_at")
    op.drop_table("execution_request_ledger")
    op.drop_table("execution_leases")
    op.drop_table("validation_plans")
