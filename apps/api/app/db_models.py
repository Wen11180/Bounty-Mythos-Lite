from datetime import UTC, datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
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


class ArtifactRecord(Base):
    __tablename__ = "artifacts"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    program_id: Mapped[str | None] = mapped_column(ForeignKey("programs.id"), nullable=True)
    asset: Mapped[str] = mapped_column(String(255), nullable=False)
    kind: Mapped[str] = mapped_column(String(50), nullable=False)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)
    source_hash: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
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


class CampaignBudgetRecord(Base):
    __tablename__ = "campaign_budgets"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(ForeignKey("campaigns.id"), nullable=False)
    time_budget_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    token_budget: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tool_call_budget: Mapped[int | None] = mapped_column(Integer, nullable=True)
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
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

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

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
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
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    program_record: Mapped[ProgramRecord] = relationship()
