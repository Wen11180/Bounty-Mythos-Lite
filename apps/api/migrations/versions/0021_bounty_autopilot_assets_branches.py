"""Add durable Autopilot assets and research branches."""

from alembic import op
import sqlalchemy as sa


revision = "0021_bounty_autopilot_assets_branches"
down_revision = "0020_bounty_autopilot_authority"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "campaign_assets",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("campaign_id", sa.String(length=100), nullable=False),
        sa.Column("asset_id", sa.String(length=100), nullable=False),
        sa.Column("identity_digest", sa.String(length=100), nullable=False),
        sa.Column("scheme", sa.String(length=16), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("path_authority", sa.String(length=1024), nullable=False),
        sa.Column("provenance", sa.String(length=32), nullable=False),
        sa.Column("admission_decision", sa.String(length=64), nullable=False),
        sa.Column("scope_snapshot_digest", sa.String(length=100), nullable=False),
        sa.Column("network_identity", sa.JSON(), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.String(length=128), nullable=False),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "campaign_id",
            "asset_id",
            name="uq_campaign_assets_campaign_asset",
        ),
    )
    op.create_index(
        "ix_campaign_assets_campaign_decision",
        "campaign_assets",
        ["campaign_id", "admission_decision"],
        unique=False,
    )
    op.create_table(
        "campaign_asset_admission_events",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("campaign_id", sa.String(length=100), nullable=False),
        sa.Column("asset_id", sa.String(length=100), nullable=False),
        sa.Column("identity_digest", sa.String(length=100), nullable=False),
        sa.Column("decision", sa.String(length=64), nullable=False),
        sa.Column("scope_snapshot_digest", sa.String(length=100), nullable=False),
        sa.Column("network_identity", sa.JSON(), nullable=False),
        sa.Column("source", sa.String(length=64), nullable=False),
        sa.Column("reason", sa.String(length=128), nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_campaign_asset_admission_events_campaign_asset",
        "campaign_asset_admission_events",
        ["campaign_id", "asset_id"],
        unique=False,
    )
    op.create_table(
        "research_branches",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("campaign_id", sa.String(length=100), nullable=False),
        sa.Column("branch_id", sa.String(length=128), nullable=False),
        sa.Column("asset_id", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("priority", sa.Integer(), nullable=False),
        sa.Column("risk_tier", sa.String(length=8), nullable=False),
        sa.Column("hypothesis_id", sa.String(length=128), nullable=True),
        sa.Column("parent_signal_id", sa.String(length=128), nullable=True),
        sa.Column("recipe_id", sa.String(length=64), nullable=True),
        sa.Column("recipe_version", sa.String(length=32), nullable=True),
        sa.Column("account_aliases", sa.JSON(), nullable=False),
        sa.Column("budget_counters", sa.JSON(), nullable=False),
        sa.Column("stop_reason", sa.String(length=255), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "campaign_id",
            "branch_id",
            name="uq_research_branches_campaign_branch",
        ),
    )
    op.create_index(
        "ix_research_branches_campaign_status",
        "research_branches",
        ["campaign_id", "status"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_research_branches_campaign_status",
        table_name="research_branches",
    )
    op.drop_table("research_branches")
    op.drop_index(
        "ix_campaign_asset_admission_events_campaign_asset",
        table_name="campaign_asset_admission_events",
    )
    op.drop_table("campaign_asset_admission_events")
    op.drop_index(
        "ix_campaign_assets_campaign_decision",
        table_name="campaign_assets",
    )
    op.drop_table("campaign_assets")
