"""Add durable public program-rule intake records."""

from alembic import op
import sqlalchemy as sa


revision = "0013_program_rule_intake"
down_revision = "0012_field_pilot_feedback"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "program_rule_sources",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("program_id", sa.String(length=100), nullable=True),
        sa.Column("program_alias", sa.String(length=100), nullable=False),
        sa.Column("registered_url", sa.String(length=2048), nullable=False),
        sa.Column("canonical_url", sa.String(length=2048), nullable=False),
        sa.Column(
            "refresh_interval_seconds",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("86400"),
        ),
        sa.Column(
            "fetch_status",
            sa.String(length=50),
            nullable=False,
            server_default="scheduled",
        ),
        sa.Column("last_check_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_success_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_check_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "failure_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("failure_code", sa.String(length=50), nullable=True),
        sa.Column("last_manual_refresh_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claim_id", sa.String(length=100), nullable=True),
        sa.Column("claim_token_digest", sa.String(length=64), nullable=True),
        sa.Column("claim_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claim_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_snapshot_id", sa.String(length=100), nullable=True),
        sa.Column("pending_snapshot_id", sa.String(length=100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "refresh_interval_seconds = 86400",
            name="ck_program_rule_sources_refresh_interval_fixed",
        ),
        sa.CheckConstraint(
            "failure_count >= 0",
            name="ck_program_rule_sources_failure_count_nonnegative",
        ),
        sa.ForeignKeyConstraint(["program_id"], ["programs.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "canonical_url",
            name="uq_program_rule_sources_canonical_url",
        ),
        sa.UniqueConstraint(
            "program_id",
            name="uq_program_rule_sources_program_id",
        ),
    )
    op.create_index(
        "ix_program_rule_sources_due",
        "program_rule_sources",
        ["fetch_status", "next_check_at"],
        unique=False,
    )

    op.create_table(
        "program_rule_snapshots",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("source_id", sa.String(length=100), nullable=False),
        sa.Column("raw_aggregate_sha256", sa.String(length=64), nullable=False),
        sa.Column("normalized_sha256", sa.String(length=64), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("fetch_mode", sa.String(length=50), nullable=False),
        sa.Column("content_types", sa.JSON(), nullable=False),
        sa.Column("detected_language", sa.String(length=50), nullable=False),
        sa.Column("extraction", sa.JSON(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("linked_documents", sa.JSON(), nullable=False),
        sa.Column("openapi_candidates", sa.JSON(), nullable=False),
        sa.Column("ai_status", sa.String(length=50), nullable=False),
        sa.Column("review_status", sa.String(length=50), nullable=False),
        sa.Column("reviewer_alias", sa.String(length=100), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_digest", sa.String(length=64), nullable=False),
        sa.Column(
            "execution_allowed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "lease_grant_allowed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "scope_change_allowed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "review_bypass_allowed",
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
        sa.CheckConstraint(
            "execution_allowed = false",
            name="ck_program_rule_snapshots_execution_allowed_false",
        ),
        sa.CheckConstraint(
            "lease_grant_allowed = false",
            name="ck_program_rule_snapshots_lease_grant_allowed_false",
        ),
        sa.CheckConstraint(
            "scope_change_allowed = false",
            name="ck_program_rule_snapshots_scope_change_allowed_false",
        ),
        sa.CheckConstraint(
            "review_bypass_allowed = false",
            name="ck_program_rule_snapshots_review_bypass_allowed_false",
        ),
        sa.CheckConstraint(
            "report_submission_allowed = false",
            name="ck_program_rule_snapshots_report_submission_allowed_false",
        ),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["program_rule_sources.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "source_id",
            "normalized_sha256",
            name="uq_program_rule_snapshots_source_normalized_sha256",
        ),
    )

    op.create_table(
        "program_scope_rules",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("program_id", sa.String(length=100), nullable=False),
        sa.Column("source_id", sa.String(length=100), nullable=False),
        sa.Column("approved_snapshot_id", sa.String(length=100), nullable=False),
        sa.Column("canonical_asset", sa.String(length=2048), nullable=False),
        sa.Column("asset_kind", sa.String(length=50), nullable=False),
        sa.Column("source_evidence_refs", sa.JSON(), nullable=False),
        sa.Column("scope_status", sa.String(length=50), nullable=False),
        sa.Column("automation", sa.String(length=100), nullable=False),
        sa.Column("allowed_validation", sa.JSON(), nullable=False),
        sa.Column("prohibited", sa.JSON(), nullable=False),
        sa.Column("rate_limit", sa.JSON(), nullable=True),
        sa.Column("approval_digest", sa.String(length=64), nullable=False),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["program_id"], ["programs.id"]),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["program_rule_sources.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["approved_snapshot_id"],
            ["program_rule_snapshots.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "approved_snapshot_id",
            "canonical_asset",
            name="uq_program_scope_rules_snapshot_asset",
        ),
    )


def downgrade() -> None:
    op.drop_table("program_scope_rules")
    op.drop_table("program_rule_snapshots")
    op.drop_index("ix_program_rule_sources_due", table_name="program_rule_sources")
    op.drop_table("program_rule_sources")
