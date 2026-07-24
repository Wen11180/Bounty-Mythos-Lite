"""Add durable sanitized audit lineage for the Autopilot release gate."""

from alembic import op
import sqlalchemy as sa


revision = "0024_bounty_autopilot_audit_lineage"
down_revision = "0023_bounty_autopilot_evidence_lineage"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "autopilot_risk_decisions",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("campaign_id", sa.String(length=100), nullable=False),
        sa.Column("risk_decision_id", sa.String(length=128), nullable=False),
        sa.Column("authorization_id", sa.String(length=128), nullable=False),
        sa.Column("authorization_digest", sa.String(length=100), nullable=False),
        sa.Column("scope_snapshot_digest", sa.String(length=100), nullable=False),
        sa.Column("asset_id", sa.String(length=100), nullable=False),
        sa.Column("branch_id", sa.String(length=128), nullable=False),
        sa.Column("recipe_id", sa.String(length=128), nullable=False),
        sa.Column("recipe_version", sa.String(length=32), nullable=False),
        sa.Column("recipe_definition_digest", sa.String(length=100), nullable=False),
        sa.Column("risk_tier", sa.String(length=8), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("reason_code", sa.String(length=128), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "campaign_id",
            "risk_decision_id",
            name="uq_autopilot_risk_decisions_campaign_decision",
        ),
    )
    op.create_index(
        "ix_autopilot_risk_decisions_campaign_branch",
        "autopilot_risk_decisions",
        ["campaign_id", "branch_id"],
    )

    op.create_table(
        "autopilot_tool_runs",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("campaign_id", sa.String(length=100), nullable=False),
        sa.Column("tool_run_id", sa.String(length=128), nullable=False),
        sa.Column("authorization_id", sa.String(length=128), nullable=False),
        sa.Column("authorization_digest", sa.String(length=100), nullable=False),
        sa.Column("scope_snapshot_digest", sa.String(length=100), nullable=False),
        sa.Column("asset_id", sa.String(length=100), nullable=False),
        sa.Column("asset_identity_digest", sa.String(length=100), nullable=False),
        sa.Column("branch_id", sa.String(length=128), nullable=False),
        sa.Column("plan_id", sa.String(length=128), nullable=False),
        sa.Column("plan_digest", sa.String(length=100), nullable=False),
        sa.Column("risk_decision_id", sa.String(length=128), nullable=False),
        sa.Column("risk_tier", sa.String(length=8), nullable=False),
        sa.Column("recipe_id", sa.String(length=128), nullable=False),
        sa.Column("recipe_version", sa.String(length=32), nullable=False),
        sa.Column("recipe_definition_digest", sa.String(length=100), nullable=False),
        sa.Column("lease_id", sa.String(length=128), nullable=False),
        sa.Column("reservation_id", sa.String(length=128), nullable=False),
        sa.Column("session_generation", sa.Integer(), nullable=False),
        sa.Column("isolation_profile", sa.String(length=16), nullable=False),
        sa.Column("gateway_decision", sa.String(length=32), nullable=False),
        sa.Column("request_sent", sa.Boolean(), nullable=False),
        sa.Column("run_status", sa.String(length=32), nullable=False),
        sa.Column("outcome_class", sa.String(length=64), nullable=False),
        sa.Column("outcome_code", sa.String(length=128), nullable=False),
        sa.Column("third_party_data_discarded", sa.Boolean(), nullable=False),
        sa.Column(
            "raw_content_retained",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "raw_secret_retained",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "request_content_retained",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "response_content_retained",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "raw_content_retained = false",
            name="ck_autopilot_tool_runs_raw_content_retained_false",
        ),
        sa.CheckConstraint(
            "raw_secret_retained = false",
            name="ck_autopilot_tool_runs_raw_secret_retained_false",
        ),
        sa.CheckConstraint(
            "request_content_retained = false",
            name="ck_autopilot_tool_runs_request_content_retained_false",
        ),
        sa.CheckConstraint(
            "response_content_retained = false",
            name="ck_autopilot_tool_runs_response_content_retained_false",
        ),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "campaign_id",
            "tool_run_id",
            name="uq_autopilot_tool_runs_campaign_run",
        ),
    )
    op.create_index(
        "ix_autopilot_tool_runs_campaign_plan",
        "autopilot_tool_runs",
        ["campaign_id", "plan_id"],
    )

    op.create_table(
        "autopilot_evidence_claims",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("campaign_id", sa.String(length=100), nullable=False),
        sa.Column("claim_id", sa.String(length=128), nullable=False),
        sa.Column("hypothesis_id", sa.String(length=128), nullable=False),
        sa.Column("observation_ids", sa.JSON(), nullable=False),
        sa.Column("evidence_grade", sa.String(length=32), nullable=False),
        sa.Column("lineage_digest", sa.String(length=100), nullable=False),
        sa.Column("summary_code", sa.String(length=128), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "campaign_id",
            "claim_id",
            name="uq_autopilot_evidence_claims_campaign_claim",
        ),
    )
    op.create_index(
        "ix_autopilot_evidence_claims_campaign_hypothesis",
        "autopilot_evidence_claims",
        ["campaign_id", "hypothesis_id"],
    )

    op.create_table(
        "autopilot_refutation_decisions",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("campaign_id", sa.String(length=100), nullable=False),
        sa.Column("decision_id", sa.String(length=128), nullable=False),
        sa.Column("case_id", sa.String(length=128), nullable=False),
        sa.Column("hypothesis_id", sa.String(length=128), nullable=False),
        sa.Column("branch_id", sa.String(length=128), nullable=False),
        sa.Column("observation_ids", sa.JSON(), nullable=False),
        sa.Column("lineage_digest", sa.String(length=100), nullable=False),
        sa.Column("verdict", sa.String(length=64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "campaign_id",
            "decision_id",
            name="uq_autopilot_refutation_decisions_campaign_decision",
        ),
    )
    op.create_index(
        "ix_autopilot_refutation_decisions_campaign_hypothesis",
        "autopilot_refutation_decisions",
        ["campaign_id", "hypothesis_id"],
    )

    op.create_table(
        "autopilot_candidate_revisions",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("campaign_id", sa.String(length=100), nullable=False),
        sa.Column("revision_id", sa.String(length=128), nullable=False),
        sa.Column("candidate_id", sa.String(length=128), nullable=False),
        sa.Column("hypothesis_id", sa.String(length=128), nullable=False),
        sa.Column("branch_id", sa.String(length=128), nullable=False),
        sa.Column("evidence_claim_ids", sa.JSON(), nullable=False),
        sa.Column("refutation_decision_id", sa.String(length=128), nullable=False),
        sa.Column("judge_verdict", sa.String(length=64), nullable=False),
        sa.Column("lineage_digest", sa.String(length=100), nullable=False),
        sa.Column(
            "confirmed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "candidate_promotion_allowed",
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
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "confirmed = false",
            name="ck_autopilot_candidate_revisions_confirmed_false",
        ),
        sa.CheckConstraint(
            "candidate_promotion_allowed = false",
            name="ck_autopilot_candidate_revisions_promotion_false",
        ),
        sa.CheckConstraint(
            "report_submission_allowed = false",
            name="ck_autopilot_candidate_revisions_submission_false",
        ),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "campaign_id",
            "revision_id",
            name="uq_autopilot_candidate_revisions_campaign_revision",
        ),
    )

    op.create_table(
        "autopilot_report_revisions",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("campaign_id", sa.String(length=100), nullable=False),
        sa.Column("revision_id", sa.String(length=128), nullable=False),
        sa.Column("report_id", sa.String(length=128), nullable=False),
        sa.Column("candidate_id", sa.String(length=128), nullable=False),
        sa.Column("evidence_claim_ids", sa.JSON(), nullable=False),
        sa.Column("lineage_digest", sa.String(length=100), nullable=False),
        sa.Column("evidence_grade", sa.String(length=32), nullable=False),
        sa.Column(
            "submission_blocked",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
        sa.Column(
            "automatic_submission_allowed",
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
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "submission_blocked = true",
            name="ck_autopilot_report_revisions_submission_blocked_true",
        ),
        sa.CheckConstraint(
            "automatic_submission_allowed = false",
            name="ck_autopilot_report_revisions_automatic_submission_false",
        ),
        sa.CheckConstraint(
            "report_submission_allowed = false",
            name="ck_autopilot_report_revisions_submission_false",
        ),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "campaign_id",
            "revision_id",
            name="uq_autopilot_report_revisions_campaign_revision",
        ),
    )

    op.create_table(
        "autopilot_human_evidence_reviews",
        sa.Column("id", sa.String(length=100), nullable=False),
        sa.Column("campaign_id", sa.String(length=100), nullable=False),
        sa.Column("review_id", sa.String(length=128), nullable=False),
        sa.Column("hypothesis_id", sa.String(length=128), nullable=False),
        sa.Column("observation_ids", sa.JSON(), nullable=False),
        sa.Column("grade", sa.String(length=32), nullable=False),
        sa.Column("decision_code", sa.String(length=128), nullable=False),
        sa.Column("reviewer_alias", sa.String(length=128), nullable=False),
        sa.Column(
            "automated_source",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column(
            "candidate_promotion_allowed",
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
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "automated_source = false",
            name="ck_autopilot_human_evidence_reviews_automated_source_false",
        ),
        sa.CheckConstraint(
            "candidate_promotion_allowed = false",
            name="ck_autopilot_human_evidence_reviews_promotion_false",
        ),
        sa.CheckConstraint(
            "report_submission_allowed = false",
            name="ck_autopilot_human_evidence_reviews_submission_false",
        ),
        sa.ForeignKeyConstraint(["campaign_id"], ["campaigns.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "campaign_id",
            "review_id",
            name="uq_autopilot_human_evidence_reviews_campaign_review",
        ),
    )


def downgrade() -> None:
    op.drop_table("autopilot_human_evidence_reviews")
    op.drop_table("autopilot_report_revisions")
    op.drop_table("autopilot_candidate_revisions")
    op.drop_index(
        "ix_autopilot_refutation_decisions_campaign_hypothesis",
        table_name="autopilot_refutation_decisions",
    )
    op.drop_table("autopilot_refutation_decisions")
    op.drop_index(
        "ix_autopilot_evidence_claims_campaign_hypothesis",
        table_name="autopilot_evidence_claims",
    )
    op.drop_table("autopilot_evidence_claims")
    op.drop_index(
        "ix_autopilot_tool_runs_campaign_plan",
        table_name="autopilot_tool_runs",
    )
    op.drop_table("autopilot_tool_runs")
    op.drop_index(
        "ix_autopilot_risk_decisions_campaign_branch",
        table_name="autopilot_risk_decisions",
    )
    op.drop_table("autopilot_risk_decisions")
