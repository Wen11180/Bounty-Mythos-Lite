"""Add codebase and scanner fact records."""

from alembic import op
import sqlalchemy as sa


revision = "0007_codebase_fact_layer"
down_revision = "0006_p0_autonomous_audit_records"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "codebase_maps",
        sa.Column("id", sa.String(length=100), primary_key=True),
        sa.Column("campaign_id", sa.String(length=100), sa.ForeignKey("campaigns.id"), nullable=False),
        sa.Column("source_ref", sa.String(length=255), nullable=False),
        sa.Column("repository", sa.String(length=255), nullable=False),
        sa.Column("commit_ref", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("route_count", sa.Integer(), nullable=False),
        sa.Column("handler_count", sa.Integer(), nullable=False),
        sa.Column("model_count", sa.Integer(), nullable=False),
        sa.Column("authz_check_count", sa.Integer(), nullable=False),
        sa.Column("sensitive_sink_count", sa.Integer(), nullable=False),
        sa.Column("provenance_refs", sa.JSON(), nullable=False),
        sa.Column("safety_gate_state", sa.String(length=100), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "codebase_facts",
        sa.Column("id", sa.String(length=100), primary_key=True),
        sa.Column("codebase_map_id", sa.String(length=100), sa.ForeignKey("codebase_maps.id"), nullable=False),
        sa.Column("campaign_id", sa.String(length=100), sa.ForeignKey("campaigns.id"), nullable=False),
        sa.Column("fact_type", sa.String(length=100), nullable=False),
        sa.Column("source_path", sa.String(length=500), nullable=False),
        sa.Column("symbol_name", sa.String(length=255), nullable=True),
        sa.Column("route_method", sa.String(length=20), nullable=True),
        sa.Column("route_path", sa.String(length=500), nullable=True),
        sa.Column("authz_hint", sa.String(length=255), nullable=True),
        sa.Column("sensitivity_label", sa.String(length=50), nullable=False),
        sa.Column("provenance_refs", sa.JSON(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "scanner_runs",
        sa.Column("id", sa.String(length=100), primary_key=True),
        sa.Column("campaign_id", sa.String(length=100), sa.ForeignKey("campaigns.id"), nullable=False),
        sa.Column("codebase_map_id", sa.String(length=100), sa.ForeignKey("codebase_maps.id"), nullable=True),
        sa.Column("tool_name", sa.String(length=100), nullable=False),
        sa.Column("command_hash", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False),
        sa.Column("candidate_count", sa.Integer(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("safety_gate_state", sa.String(length=100), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("scanner_runs")
    op.drop_table("codebase_facts")
    op.drop_table("codebase_maps")
