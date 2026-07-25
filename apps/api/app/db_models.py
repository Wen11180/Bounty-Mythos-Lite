from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    false,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class ProgramRecord(Base):
    __tablename__ = "programs"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    platform: Mapped[str] = mapped_column(String(255), nullable=False)
    bounty_range: Mapped[str] = mapped_column(String(255), nullable=False)
    scope_status: Mapped[str] = mapped_column(String(50), nullable=False)
    automation: Mapped[str] = mapped_column(String(100), nullable=False)
    testing_accounts: Mapped[str] = mapped_column(String(100), nullable=False)
    api_docs: Mapped[str] = mapped_column(String(100), nullable=False)
    public_code: Mapped[str] = mapped_column(String(100), nullable=False)
    duplicate_risk: Mapped[str] = mapped_column(String(100), nullable=False)
    priority: Mapped[str] = mapped_column(String(50), nullable=False)


class ProgramRuleSourceRecord(Base):
    __tablename__ = "program_rule_sources"
    __table_args__ = (
        CheckConstraint(
            "refresh_interval_seconds = 86400",
            name="ck_program_rule_sources_refresh_interval_fixed",
        ),
        CheckConstraint(
            "failure_count >= 0",
            name="ck_program_rule_sources_failure_count_nonnegative",
        ),
        UniqueConstraint(
            "canonical_url",
            name="uq_program_rule_sources_canonical_url",
        ),
        UniqueConstraint(
            "program_id",
            name="uq_program_rule_sources_program_id",
        ),
        Index(
            "ix_program_rule_sources_due",
            "fetch_status",
            "next_check_at",
        ),
    )

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    program_id: Mapped[str | None] = mapped_column(
        ForeignKey("programs.id"),
        nullable=True,
    )
    program_alias: Mapped[str] = mapped_column(String(100), nullable=False)
    registered_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    canonical_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    refresh_interval_seconds: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=86_400,
        server_default="86400",
    )
    fetch_status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="scheduled",
        server_default="scheduled",
    )
    last_check_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_success_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    next_check_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    failure_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    failure_code: Mapped[str | None] = mapped_column(String(50), nullable=True)
    last_manual_refresh_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    claim_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    claim_token_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    claim_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    claim_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    approved_snapshot_id: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    pending_snapshot_id: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    program: Mapped[ProgramRecord | None] = relationship()


class ProgramRuleSnapshotRecord(Base):
    __tablename__ = "program_rule_snapshots"
    __table_args__ = (
        CheckConstraint(
            "execution_allowed = false",
            name="ck_program_rule_snapshots_execution_allowed_false",
        ),
        CheckConstraint(
            "lease_grant_allowed = false",
            name="ck_program_rule_snapshots_lease_grant_allowed_false",
        ),
        CheckConstraint(
            "scope_change_allowed = false",
            name="ck_program_rule_snapshots_scope_change_allowed_false",
        ),
        CheckConstraint(
            "review_bypass_allowed = false",
            name="ck_program_rule_snapshots_review_bypass_allowed_false",
        ),
        CheckConstraint(
            "report_submission_allowed = false",
            name="ck_program_rule_snapshots_report_submission_allowed_false",
        ),
        UniqueConstraint(
            "source_id",
            "normalized_sha256",
            name="uq_program_rule_snapshots_source_normalized_sha256",
        ),
    )

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    source_id: Mapped[str] = mapped_column(
        ForeignKey("program_rule_sources.id", ondelete="CASCADE"),
        nullable=False,
    )
    raw_aggregate_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    normalized_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )
    fetch_mode: Mapped[str] = mapped_column(String(50), nullable=False)
    content_types: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    detected_language: Mapped[str] = mapped_column(String(50), nullable=False)
    extraction: Mapped[dict] = mapped_column(JSON, nullable=False)
    evidence: Mapped[list[dict]] = mapped_column(JSON, nullable=False)
    linked_documents: Mapped[list[dict]] = mapped_column(JSON, nullable=False)
    openapi_candidates: Mapped[list[dict]] = mapped_column(JSON, nullable=False)
    ai_status: Mapped[str] = mapped_column(String(50), nullable=False)
    review_status: Mapped[str] = mapped_column(String(50), nullable=False)
    reviewer_alias: Mapped[str | None] = mapped_column(String(100), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    review_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    execution_allowed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=false(),
    )
    lease_grant_allowed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=false(),
    )
    scope_change_allowed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=false(),
    )
    review_bypass_allowed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=false(),
    )
    report_submission_allowed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=false(),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    source: Mapped[ProgramRuleSourceRecord] = relationship()


class ProgramScopeRuleRecord(Base):
    __tablename__ = "program_scope_rules"
    __table_args__ = (
        UniqueConstraint(
            "approved_snapshot_id",
            "canonical_asset",
            name="uq_program_scope_rules_snapshot_asset",
        ),
    )

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    program_id: Mapped[str] = mapped_column(
        ForeignKey("programs.id"),
        nullable=False,
    )
    source_id: Mapped[str] = mapped_column(
        ForeignKey("program_rule_sources.id", ondelete="CASCADE"),
        nullable=False,
    )
    approved_snapshot_id: Mapped[str] = mapped_column(
        ForeignKey("program_rule_snapshots.id", ondelete="CASCADE"),
        nullable=False,
    )
    canonical_asset: Mapped[str] = mapped_column(String(2048), nullable=False)
    asset_kind: Mapped[str] = mapped_column(String(50), nullable=False)
    source_evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    scope_status: Mapped[str] = mapped_column(String(50), nullable=False)
    automation: Mapped[str] = mapped_column(String(100), nullable=False)
    allowed_validation: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    prohibited: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    rate_limit: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    approval_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    effective_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    program: Mapped[ProgramRecord] = relationship()
    source: Mapped[ProgramRuleSourceRecord] = relationship()
    approved_snapshot: Mapped[ProgramRuleSnapshotRecord] = relationship()


class ArtifactRecord(Base):
    __tablename__ = "artifacts"
    __table_args__ = (
        UniqueConstraint(
            "program_id",
            "source_hash",
            name="uq_artifacts_program_source_hash",
        ),
    )

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    program_id: Mapped[str | None] = mapped_column(ForeignKey("programs.id"), nullable=True)
    asset: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(String(50), nullable=False)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)
    source_hash: Mapped[str] = mapped_column(String(100), nullable=False)
    ingestion_status: Mapped[str] = mapped_column(String(50), nullable=False)
    provenance: Mapped[dict] = mapped_column(JSON, nullable=False)
    payload_summary: Mapped[dict] = mapped_column(JSON, nullable=False)
    derived_facts: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    program_record: Mapped[ProgramRecord | None] = relationship()


class FindingRecord(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    program_id: Mapped[str | None] = mapped_column(ForeignKey("programs.id"), nullable=True)
    program: Mapped[str] = mapped_column(String(255), nullable=False)
    asset: Mapped[str] = mapped_column(String(255), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    vuln_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity_estimate: Mapped[str] = mapped_column(String(50), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    scope_status: Mapped[str] = mapped_column(String(50), nullable=False)
    policy_status: Mapped[str] = mapped_column(String(50), nullable=False)
    broken_invariant: Mapped[str] = mapped_column(Text, nullable=False)
    validation_status: Mapped[str] = mapped_column(String(100), nullable=False)
    refutation_status: Mapped[str] = mapped_column(String(100), nullable=False)
    duplicate_likelihood: Mapped[str] = mapped_column(String(100), nullable=False)
    submission_recommendation: Mapped[str] = mapped_column(String(100), nullable=False)
    evidence_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    operating_reasons: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    program_record: Mapped[ProgramRecord | None] = relationship()


class ReportRecord(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id"), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    draft: Mapped[str] = mapped_column(Text, nullable=False)

    finding: Mapped[FindingRecord] = relationship()


class LLMRunRecord(Base):
    __tablename__ = "llm_runs"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    purpose: Mapped[str] = mapped_column(String(100), nullable=False, default="general")
    prompt_hash: Mapped[str] = mapped_column(String(100), nullable=False)
    mode: Mapped[str] = mapped_column(String(50), nullable=False)
    latency_ms: Mapped[int | None] = mapped_column(nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    safety_notes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )


class PipelineRunRecord(Base):
    __tablename__ = "pipeline_runs"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    program_id: Mapped[str | None] = mapped_column(ForeignKey("programs.id"), nullable=True)
    asset: Mapped[str] = mapped_column(String(255), nullable=False)
    policy_text_hash: Mapped[str] = mapped_column(String(100), nullable=False)
    scope_status: Mapped[str] = mapped_column(String(50), nullable=False)
    hypothesis_count: Mapped[int] = mapped_column(Integer, nullable=False)
    blocked_count: Mapped[int] = mapped_column(Integer, nullable=False)
    report_title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)

    program_record: Mapped[ProgramRecord | None] = relationship()


class CampaignRecord(Base):
    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    program_id: Mapped[str | None] = mapped_column(ForeignKey("programs.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    campaign_mode: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="legacy",
        server_default="legacy",
    )
    autonomy_level: Mapped[str] = mapped_column(String(100), nullable=False)
    scope_status: Mapped[str] = mapped_column(String(50), nullable=False)
    policy_text_hash: Mapped[str] = mapped_column(String(100), nullable=False)
    default_asset: Mapped[str] = mapped_column(String(255), nullable=False)
    target_classes: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    allowed_tools: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="draft")
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    program_record: Mapped[ProgramRecord | None] = relationship()


class CampaignLocalToolExecutionSlotRecord(Base):
    __tablename__ = "campaign_local_tool_execution_slots"
    __table_args__ = (
        UniqueConstraint(
            "campaign_id",
            "source_snapshot_digest",
            name="uq_campaign_local_tool_execution_slots_campaign_snapshot",
        ),
    )

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False)
    source_snapshot_digest: Mapped[str] = mapped_column(String(100), nullable=False)
    active_task_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    active_execution_claim_id: Mapped[str | None] = mapped_column(
        String(100),
        nullable=True,
    )
    legacy_active_task_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    campaign: Mapped[CampaignRecord] = relationship()


class AutonomousResearchWakeupStateRecord(Base):
    __tablename__ = "autonomous_research_wakeup_states"
    __table_args__ = (
        CheckConstraint(
            "execution_allowed = false",
            name="ck_autonomous_research_wakeup_execution_allowed_false",
        ),
        CheckConstraint(
            "validation_allowed = false",
            name="ck_autonomous_research_wakeup_validation_allowed_false",
        ),
        CheckConstraint(
            "report_submission_allowed = false",
            name="ck_autonomous_research_wakeup_report_submission_allowed_false",
        ),
    )

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    after_campaign_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    lease_token_digest: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    next_due_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_cycle_completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    last_cycle_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    last_cycle_stop_reason: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )
    last_cycle_processed_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    last_cycle_outcome_counts: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
        server_default="{}",
    )
    execution_allowed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=false(),
    )
    validation_allowed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=false(),
    )
    report_submission_allowed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=false(),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )


class CampaignBudgetRecord(Base):
    __tablename__ = "campaign_budgets"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False)
    time_budget_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    token_budget: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tool_call_budget: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tool_calls_reserved: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default="0",
    )
    validation_budget: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    campaign: Mapped[CampaignRecord] = relationship()


class CampaignTaskRecord(Base):
    __tablename__ = "campaign_tasks"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False)
    task_type: Mapped[str] = mapped_column(String(100), nullable=False)
    agent_type: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="queued")
    input_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    output_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    execution_claim_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    execution_heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    execution_lease_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    campaign: Mapped[CampaignRecord] = relationship()


class AgentRunRecord(Base):
    __tablename__ = "agent_runs"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    campaign_id: Mapped[str | None] = mapped_column(ForeignKey("campaigns.id"), nullable=True)
    task_id: Mapped[str | None] = mapped_column(ForeignKey("campaign_tasks.id"), nullable=True)
    agent_type: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    input_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    output_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    tool_calls: Mapped[list[dict]] = mapped_column(JSON, nullable=False, default=list)
    safety_gate_state: Mapped[str] = mapped_column(String(100), nullable=False)
    stop_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    campaign: Mapped[CampaignRecord | None] = relationship()
    task: Mapped[CampaignTaskRecord | None] = relationship()


class ApprovalRecord(Base):
    __tablename__ = "approval_records"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    campaign_id: Mapped[str | None] = mapped_column(ForeignKey("campaigns.id"), nullable=True)
    task_id: Mapped[str | None] = mapped_column(ForeignKey("campaign_tasks.id"), nullable=True)
    run_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    program_id: Mapped[str | None] = mapped_column(ForeignKey("programs.id"), nullable=True)
    approval_type: Mapped[str] = mapped_column(String(100), nullable=False)
    actor: Mapped[str] = mapped_column(String(255), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    scope_reference: Mapped[str | None] = mapped_column(String(255), nullable=True)
    requested_action: Mapped[str | None] = mapped_column(String(255), nullable=True)
    asset: Mapped[str | None] = mapped_column(String(255), nullable=True)
    validation_mode: Mapped[str | None] = mapped_column(String(100), nullable=True)
    plan_digest: Mapped[str | None] = mapped_column(String(255), nullable=True)
    autonomy_level: Mapped[str | None] = mapped_column(String(100), nullable=True)
    safety_gate_state: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed_by_lease_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    single_use_nonce_digest: Mapped[str | None] = mapped_column(String(100), nullable=True)

    campaign: Mapped[CampaignRecord | None] = relationship()
    task: Mapped[CampaignTaskRecord | None] = relationship()
    program_record: Mapped[ProgramRecord | None] = relationship()


class PipelineStageRecord(Base):
    __tablename__ = "pipeline_stages"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    pipeline_run_id: Mapped[str | None] = mapped_column(ForeignKey("pipeline_runs.id"), nullable=True)
    campaign_id: Mapped[str | None] = mapped_column(ForeignKey("campaigns.id"), nullable=True)
    task_id: Mapped[str | None] = mapped_column(ForeignKey("campaign_tasks.id"), nullable=True)
    stage_key: Mapped[str] = mapped_column(String(100), nullable=False)
    stage_order: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    input_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    output_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    safety_gate_state: Mapped[str] = mapped_column(String(100), nullable=False)
    stop_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    pipeline_run: Mapped[PipelineRunRecord | None] = relationship()
    campaign: Mapped[CampaignRecord | None] = relationship()
    task: Mapped[CampaignTaskRecord | None] = relationship()


class CodebaseMapRecord(Base):
    __tablename__ = "codebase_maps"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False)
    source_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    repository: Mapped[str] = mapped_column(String(255), nullable=False)
    commit_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    route_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    handler_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    model_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    authz_check_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sensitive_sink_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    provenance_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    safety_gate_state: Mapped[str] = mapped_column(String(100), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    campaign: Mapped[CampaignRecord] = relationship()


class CodebaseFactRecord(Base):
    __tablename__ = "codebase_facts"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    codebase_map_id: Mapped[str] = mapped_column(ForeignKey("codebase_maps.id"), nullable=False)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False)
    fact_type: Mapped[str] = mapped_column(String(100), nullable=False)
    source_path: Mapped[str] = mapped_column(String(500), nullable=False)
    symbol_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    route_method: Mapped[str | None] = mapped_column(String(20), nullable=True)
    route_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    authz_hint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    sensitivity_label: Mapped[str] = mapped_column(String(50), nullable=False)
    provenance_refs: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    codebase_map: Mapped[CodebaseMapRecord] = relationship()
    campaign: Mapped[CampaignRecord] = relationship()


class ScannerRunRecord(Base):
    __tablename__ = "scanner_runs"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False)
    codebase_map_id: Mapped[str | None] = mapped_column(ForeignKey("codebase_maps.id"), nullable=True)
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    command_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    candidate_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    safety_gate_state: Mapped[str] = mapped_column(String(100), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    campaign: Mapped[CampaignRecord] = relationship()
    codebase_map: Mapped[CodebaseMapRecord | None] = relationship()


class ValidationRunRecord(Base):
    __tablename__ = "validation_runs"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False)
    task_id: Mapped[str | None] = mapped_column(ForeignKey("campaign_tasks.id"), nullable=True)
    approval_id: Mapped[str | None] = mapped_column(ForeignKey("approval_records.id"), nullable=True)
    validation_mode: Mapped[str] = mapped_column(String(100), nullable=False)
    target_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    safety_gate_state: Mapped[str] = mapped_column(String(100), nullable=False)
    plan_digest: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approval_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    allowed_to_execute: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    evidence_ref_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    campaign: Mapped[CampaignRecord] = relationship()
    task: Mapped[CampaignTaskRecord | None] = relationship()
    approval: Mapped[ApprovalRecord | None] = relationship()


class LearningSignalRecord(Base):
    __tablename__ = "learning_signals"
    __table_args__ = (
        Index("uq_learning_signals_identity_hash", "identity_hash", unique=True),
    )

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    identity_hash: Mapped[str | None] = mapped_column(String(100), nullable=True)
    program_id: Mapped[str] = mapped_column(ForeignKey("programs.id"), nullable=False)
    playbook_id: Mapped[str] = mapped_column(String(100), nullable=False)
    outcome: Mapped[str] = mapped_column(String(50), nullable=False)
    surface_key: Mapped[str | None] = mapped_column(String(255), nullable=True)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    bounty_amount: Mapped[int | None] = mapped_column(Integer, nullable=True)
    severity_delta: Mapped[str | None] = mapped_column(String(50), nullable=True)
    evidence_quality: Mapped[str | None] = mapped_column(String(50), nullable=True)
    triager_feedback: Mapped[str | None] = mapped_column(Text, nullable=True)
    target_relationships: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    field_pilot_feedback: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    program_record: Mapped[ProgramRecord] = relationship()

class CampaignAuthorizationRecord(Base):
    """Immutable Autopilot Campaign authorization generation."""

    __tablename__ = "campaign_authorizations"
    __table_args__ = (
        UniqueConstraint(
            "campaign_id",
            "generation",
            name="uq_campaign_authorizations_campaign_generation",
        ),
        Index(
            "ix_campaign_authorizations_campaign_current",
            "campaign_id",
            "is_current",
        ),
    )

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False)
    generation: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    schema_version: Mapped[str] = mapped_column(String(100), nullable=False)
    authorization_digest: Mapped[str] = mapped_column(String(100), nullable=False)
    scope_snapshot_id: Mapped[str] = mapped_column(String(128), nullable=False)
    scope_snapshot_digest: Mapped[str] = mapped_column(String(100), nullable=False)
    policy_digest: Mapped[str] = mapped_column(String(100), nullable=False)
    operator_id: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revocation_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)

    campaign: Mapped[CampaignRecord] = relationship()


class CampaignAssetRecord(Base):
    """Immutable Autopilot asset identity with latest admission decision."""

    __tablename__ = "campaign_assets"
    __table_args__ = (
        UniqueConstraint(
            "campaign_id",
            "asset_id",
            name="uq_campaign_assets_campaign_asset",
        ),
        Index("ix_campaign_assets_campaign_decision", "campaign_id", "admission_decision"),
    )

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(100), nullable=False)
    identity_digest: Mapped[str] = mapped_column(String(100), nullable=False)
    scheme: Mapped[str] = mapped_column(String(16), nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    path_authority: Mapped[str] = mapped_column(String(1024), nullable=False)
    provenance: Mapped[str] = mapped_column(String(32), nullable=False)
    admission_decision: Mapped[str] = mapped_column(String(64), nullable=False)
    scope_snapshot_digest: Mapped[str] = mapped_column(String(100), nullable=False)
    network_identity: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(String(128), nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    campaign: Mapped[CampaignRecord] = relationship()


class CampaignAssetAdmissionEventRecord(Base):
    """Append-only admission decisions for campaign assets."""

    __tablename__ = "campaign_asset_admission_events"
    __table_args__ = (
        Index(
            "ix_campaign_asset_admission_events_campaign_asset",
            "campaign_id",
            "asset_id",
        ),
    )

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(100), nullable=False)
    identity_digest: Mapped[str] = mapped_column(String(100), nullable=False)
    decision: Mapped[str] = mapped_column(String(64), nullable=False)
    scope_snapshot_digest: Mapped[str] = mapped_column(String(100), nullable=False)
    network_identity: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(String(128), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)

    campaign: Mapped[CampaignRecord] = relationship()


class ResearchBranchRecord(Base):
    """Independent research branch with optimistic concurrency version."""

    __tablename__ = "research_branches"
    __table_args__ = (
        UniqueConstraint(
            "campaign_id",
            "branch_id",
            name="uq_research_branches_campaign_branch",
        ),
        Index("ix_research_branches_campaign_status", "campaign_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False)
    branch_id: Mapped[str] = mapped_column(String(128), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_tier: Mapped[str] = mapped_column(String(8), nullable=False, default="R0")
    hypothesis_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    parent_signal_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    recipe_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    recipe_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    account_aliases: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    budget_counters: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    stop_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    campaign: Mapped[CampaignRecord] = relationship()


class ValidationPlanRecord(Base):
    """Immutable Autopilot validation plan."""

    __tablename__ = "validation_plans"
    __table_args__ = (
        UniqueConstraint(
            "campaign_id",
            "plan_id",
            name="uq_validation_plans_campaign_plan",
        ),
    )

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False)
    plan_id: Mapped[str] = mapped_column(String(128), nullable=False)
    plan_digest: Mapped[str] = mapped_column(String(100), nullable=False)
    branch_id: Mapped[str] = mapped_column(String(128), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(100), nullable=False)
    risk_tier: Mapped[str] = mapped_column(String(8), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    campaign: Mapped[CampaignRecord] = relationship()


class ExecutionLeaseRecord(Base):
    """Durable Autopilot execution lease bound to an immutable plan."""

    __tablename__ = "execution_leases"
    __table_args__ = (
        UniqueConstraint(
            "campaign_id",
            "lease_id",
            name="uq_execution_leases_campaign_lease",
        ),
        Index("ix_execution_leases_campaign_status", "campaign_id", "status"),
        Index(
            "ix_execution_leases_campaign_authorization_status",
            "campaign_id",
            "authorization_id",
            "status",
        ),
    )

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False)
    lease_id: Mapped[str] = mapped_column(String(128), nullable=False)
    plan_id: Mapped[str] = mapped_column(String(128), nullable=False)
    plan_digest: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    authorization_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    r3_approval_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    requests_reserved: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    duration_reserved_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cost_units_reserved: Mapped[int | None] = mapped_column(Integer, nullable=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    campaign: Mapped[CampaignRecord] = relationship()


class ExecutionRequestLedgerRecord(Base):
    """Idempotent request reservation ledger for Autopilot leases."""

    __tablename__ = "execution_request_ledger"
    __table_args__ = (
        UniqueConstraint(
            "campaign_id",
            "lease_id",
            "idempotency_key",
            name="uq_execution_request_ledger_idempotency",
        ),
        Index(
            "uq_execution_request_ledger_reservation",
            "campaign_id",
            "reservation_id",
            unique=True,
        ),
        Index(
            "ix_execution_request_ledger_campaign_lease",
            "campaign_id",
            "lease_id",
        ),
    )

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False)
    reservation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    lease_id: Mapped[str] = mapped_column(String(128), nullable=False)
    plan_digest: Mapped[str] = mapped_column(String(100), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    campaign: Mapped[CampaignRecord] = relationship()


class AutopilotObservationRecord(Base):
    """Sanitized Autopilot observations with plan lineage."""

    __tablename__ = "autopilot_observations"
    __table_args__ = (
        UniqueConstraint(
            "campaign_id",
            "observation_id",
            name="uq_autopilot_observations_campaign_obs",
        ),
        Index(
            "uq_autopilot_observations_campaign_reservation",
            "campaign_id",
            "reservation_id",
            unique=True,
        ),
        Index(
            "ix_autopilot_observations_campaign_branch",
            "campaign_id",
            "branch_id",
        ),
        Index(
            "ix_autopilot_observations_campaign_comparison_reservation",
            "campaign_id",
            "comparison_reservation_id",
        ),
    )

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False)
    observation_id: Mapped[str] = mapped_column(String(128), nullable=False)
    branch_id: Mapped[str] = mapped_column(String(128), nullable=False)
    plan_digest: Mapped[str] = mapped_column(String(100), nullable=False)
    # Nullable only for pre-lineage rows migrated from the initial lab schema.
    lease_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reservation_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    comparison_reservation_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    grade: Mapped[str] = mapped_column(String(32), nullable=False)
    outcome_class: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    campaign: Mapped[CampaignRecord] = relationship()
