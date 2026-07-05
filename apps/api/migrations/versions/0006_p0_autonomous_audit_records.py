"""Add P0 autonomous audit records."""

from alembic import op
import sqlalchemy as sa


revision = "0006_p0_autonomous_audit_records"
down_revision = "0005_finding_operating_reasons"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "campaigns",
        sa.Column("id", sa.String(length=100), primary_key=True),
        sa.Column("program_id", sa.String(length=100), sa.ForeignKey("programs.id"), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("autonomy_level", sa.String(length=100), nullable=False),
        sa.Column("scope_status", sa.String(length=50), nullable=False),
        sa.Column("policy_text_hash", sa.String(length=100), nullable=False),
        sa.Column("default_asset", sa.String(length=255), nullable=False),
        sa.Column("target_classes", sa.JSON(), nullable=False),
        sa.Column("allowed_tools", sa.JSON(), nullable=False),
        sa.Column("created_by", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "campaign_budgets",
        sa.Column("id", sa.String(length=100), primary_key=True),
        sa.Column("campaign_id", sa.String(length=100), sa.ForeignKey("campaigns.id"), nullable=False),
        sa.Column("time_budget_minutes", sa.Integer(), nullable=True),
        sa.Column("token_budget", sa.Integer(), nullable=True),
        sa.Column("tool_call_budget", sa.Integer(), nullable=True),
        sa.Column("validation_budget", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "campaign_tasks",
        sa.Column("id", sa.String(length=100), primary_key=True),
        sa.Column("campaign_id", sa.String(length=100), sa.ForeignKey("campaigns.id"), nullable=False),
        sa.Column("task_type", sa.String(length=100), nullable=False),
        sa.Column("agent_type", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("input_refs", sa.JSON(), nullable=False),
        sa.Column("output_refs", sa.JSON(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "agent_runs",
        sa.Column("id", sa.String(length=100), primary_key=True),
        sa.Column("campaign_id", sa.String(length=100), sa.ForeignKey("campaigns.id"), nullable=True),
        sa.Column("task_id", sa.String(length=100), sa.ForeignKey("campaign_tasks.id"), nullable=True),
        sa.Column("agent_type", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("input_refs", sa.JSON(), nullable=False),
        sa.Column("output_refs", sa.JSON(), nullable=False),
        sa.Column("tool_calls", sa.JSON(), nullable=False),
        sa.Column("safety_gate_state", sa.String(length=100), nullable=False),
        sa.Column("stop_reason", sa.Text(), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "approval_records",
        sa.Column("id", sa.String(length=100), primary_key=True),
        sa.Column("campaign_id", sa.String(length=100), sa.ForeignKey("campaigns.id"), nullable=True),
        sa.Column("task_id", sa.String(length=100), sa.ForeignKey("campaign_tasks.id"), nullable=True),
        sa.Column("run_id", sa.String(length=100), nullable=True),
        sa.Column("program_id", sa.String(length=100), sa.ForeignKey("programs.id"), nullable=True),
        sa.Column("approval_type", sa.String(length=100), nullable=False),
        sa.Column("actor", sa.String(length=255), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("scope_reference", sa.String(length=255), nullable=True),
        sa.Column("requested_action", sa.String(length=255), nullable=True),
        sa.Column("asset", sa.String(length=255), nullable=True),
        sa.Column("validation_mode", sa.String(length=100), nullable=True),
        sa.Column("plan_digest", sa.String(length=255), nullable=True),
        sa.Column("autonomy_level", sa.String(length=100), nullable=True),
        sa.Column("safety_gate_state", sa.String(length=100), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column("decided_by", sa.String(length=255), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "pipeline_stages",
        sa.Column("id", sa.String(length=100), primary_key=True),
        sa.Column("pipeline_run_id", sa.String(length=100), sa.ForeignKey("pipeline_runs.id"), nullable=True),
        sa.Column("campaign_id", sa.String(length=100), sa.ForeignKey("campaigns.id"), nullable=True),
        sa.Column("task_id", sa.String(length=100), sa.ForeignKey("campaign_tasks.id"), nullable=True),
        sa.Column("stage_key", sa.String(length=100), nullable=False),
        sa.Column("stage_order", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(length=50), nullable=False),
        sa.Column("input_refs", sa.JSON(), nullable=False),
        sa.Column("output_refs", sa.JSON(), nullable=False),
        sa.Column("safety_gate_state", sa.String(length=100), nullable=False),
        sa.Column("stop_reason", sa.Text(), nullable=True),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("pipeline_stages")
    op.drop_table("approval_records")
    op.drop_table("agent_runs")
    op.drop_table("campaign_tasks")
    op.drop_table("campaign_budgets")
    op.drop_table("campaigns")
