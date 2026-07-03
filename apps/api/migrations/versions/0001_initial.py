"""create core tables

Revision ID: 0001_initial
Revises:
Create Date: 2026-07-03
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0001_initial"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "programs",
        sa.Column("id", sa.String(length=100), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("platform", sa.String(length=255), nullable=False),
        sa.Column("bounty_range", sa.String(length=255), nullable=False),
        sa.Column("scope_status", sa.String(length=50), nullable=False),
        sa.Column("automation", sa.String(length=100), nullable=False),
        sa.Column("testing_accounts", sa.String(length=100), nullable=False),
        sa.Column("api_docs", sa.String(length=100), nullable=False),
        sa.Column("public_code", sa.String(length=100), nullable=False),
        sa.Column("duplicate_risk", sa.String(length=100), nullable=False),
        sa.Column("priority", sa.String(length=50), nullable=False),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=100), primary_key=True),
        sa.Column("program_id", sa.String(length=100), sa.ForeignKey("programs.id"), nullable=True),
        sa.Column("program", sa.String(length=255), nullable=False),
        sa.Column("asset", sa.String(length=255), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("vuln_type", sa.String(length=100), nullable=False),
        sa.Column("severity_estimate", sa.String(length=50), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("scope_status", sa.String(length=50), nullable=False),
        sa.Column("policy_status", sa.String(length=50), nullable=False),
        sa.Column("broken_invariant", sa.Text(), nullable=False),
        sa.Column("validation_status", sa.String(length=100), nullable=False),
        sa.Column("refutation_status", sa.String(length=100), nullable=False),
        sa.Column("duplicate_likelihood", sa.String(length=100), nullable=False),
        sa.Column("submission_recommendation", sa.String(length=100), nullable=False),
        sa.Column("evidence_refs", sa.JSON(), nullable=False),
    )
    op.create_table(
        "reports",
        sa.Column("id", sa.String(length=100), primary_key=True),
        sa.Column("finding_id", sa.String(length=100), sa.ForeignKey("findings.id"), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("draft", sa.Text(), nullable=False),
    )
    op.create_table(
        "llm_runs",
        sa.Column("id", sa.String(length=100), primary_key=True),
        sa.Column("provider", sa.String(length=50), nullable=False),
        sa.Column("model", sa.String(length=100), nullable=False),
        sa.Column("prompt_hash", sa.String(length=100), nullable=False),
        sa.Column("mode", sa.String(length=50), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
    )
    op.create_table(
        "pipeline_runs",
        sa.Column("id", sa.String(length=100), primary_key=True),
        sa.Column("asset", sa.String(length=255), nullable=False),
        sa.Column("policy_text_hash", sa.String(length=100), nullable=False),
        sa.Column("scope_status", sa.String(length=50), nullable=False),
        sa.Column("hypothesis_count", sa.Integer(), nullable=False),
        sa.Column("blocked_count", sa.Integer(), nullable=False),
        sa.Column("report_title", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("pipeline_runs")
    op.drop_table("llm_runs")
    op.drop_table("reports")
    op.drop_table("findings")
    op.drop_table("programs")
