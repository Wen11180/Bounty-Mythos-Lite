"""Add validation run audit records."""

from alembic import op
import sqlalchemy as sa


revision = "0008_validation_runs"
down_revision = "0007_codebase_fact_layer"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "validation_runs",
        sa.Column("id", sa.String(length=100), primary_key=True),
        sa.Column("campaign_id", sa.String(length=100), sa.ForeignKey("campaigns.id"), nullable=False),
        sa.Column("task_id", sa.String(length=100), sa.ForeignKey("campaign_tasks.id"), nullable=True),
        sa.Column("approval_id", sa.String(length=100), sa.ForeignKey("approval_records.id"), nullable=True),
        sa.Column("validation_mode", sa.String(length=100), nullable=False),
        sa.Column("target_ref", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("safety_gate_state", sa.String(length=100), nullable=False),
        sa.Column("plan_digest", sa.String(length=255), nullable=True),
        sa.Column("approval_required", sa.Boolean(), nullable=False),
        sa.Column("allowed_to_execute", sa.Boolean(), nullable=False),
        sa.Column("evidence_ref_count", sa.Integer(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("validation_runs")
