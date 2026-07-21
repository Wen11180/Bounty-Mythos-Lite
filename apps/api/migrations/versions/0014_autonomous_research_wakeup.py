"""Add durable autonomous research wakeup state."""

from alembic import op
import sqlalchemy as sa


revision = "0014_autonomous_research_wakeup"
down_revision = "0013_program_rule_intake"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "autonomous_research_wakeup_states",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("after_campaign_id", sa.String(length=100), nullable=True),
        sa.Column("lease_token_digest", sa.String(length=64), nullable=True),
        sa.Column("lease_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "execution_allowed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "validation_allowed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "report_submission_allowed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "execution_allowed = false",
            name="ck_autonomous_research_wakeup_execution_allowed_false",
        ),
        sa.CheckConstraint(
            "validation_allowed = false",
            name="ck_autonomous_research_wakeup_validation_allowed_false",
        ),
        sa.CheckConstraint(
            "report_submission_allowed = false",
            name="ck_autonomous_research_wakeup_report_submission_allowed_false",
        ),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("autonomous_research_wakeup_states")
