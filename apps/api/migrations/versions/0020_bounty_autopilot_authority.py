"""Add durable Bounty Autopilot campaign authorization records."""

from alembic import op
import sqlalchemy as sa


revision = "0020_bounty_autopilot_authority"
down_revision = "0019_campaign_local_tool_execution_slot"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "campaigns",
        sa.Column(
            "campaign_mode",
            sa.String(length=50),
            nullable=False,
            server_default="legacy",
        ),
    )
    op.create_table(
        "campaign_authorizations",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("campaign_id", sa.String(length=100), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.String(length=100), nullable=False),
        sa.Column("authorization_digest", sa.String(length=100), nullable=False),
        sa.Column("scope_snapshot_id", sa.String(length=128), nullable=False),
        sa.Column("scope_snapshot_digest", sa.String(length=100), nullable=False),
        sa.Column("policy_digest", sa.String(length=100), nullable=False),
        sa.Column("operator_id", sa.String(length=128), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("is_current", sa.Boolean(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "campaign_id",
            "generation",
            name="uq_campaign_authorizations_campaign_generation",
        ),
    )
    op.create_index(
        "ix_campaign_authorizations_campaign_current",
        "campaign_authorizations",
        ["campaign_id", "is_current"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_campaign_authorizations_campaign_current",
        table_name="campaign_authorizations",
    )
    op.drop_table("campaign_authorizations")
    op.drop_column("campaigns", "campaign_mode")
