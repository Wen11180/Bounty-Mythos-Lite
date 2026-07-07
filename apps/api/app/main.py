from datetime import UTC, datetime
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session

from app.db import get_session
from app.db_models import (
    AgentRunRecord,
    ApprovalRecord,
    ArtifactRecord,
    CampaignBudgetRecord,
    CampaignRecord,
    CampaignTaskRecord,
    CodebaseFactRecord,
    CodebaseMapRecord,
    LearningSignalRecord,
    LLMRunRecord,
    PipelineStageRecord,
    PipelineRunRecord,
    ScannerRunRecord,
    ValidationRunRecord,
)
from app.campaign_orchestrator import tick_campaign
from app.hunter_intelligence import (
    HunterIntelligence,
)
from app.llm.base import LLMRequest, LLMResponse
from app.llm.registry import UnknownProviderError, build_default_registry
from app.models import Finding, Program, ReportDraft
from app.mythos_brain import (
    LearningEvidenceQuality,
    LearningOutcome,
    LearningSignal,
    LearningSeverityDelta,
    LessonRecommendation,
    LessonScopeType,
    KnowledgeArtifactImportResult,
    MythosLesson,
    ProgramIntelligenceProfile,
    ReasoningMemoryPlaybook,
    ReasoningMemorySummary,
    build_learning_signal_from_outcome,
    build_learning_signals_from_knowledge_artifact,
    build_mythos_lessons,
    build_program_intelligence,
)
from app.mythos_finding import promote_pipeline_run_to_finding_candidate
from app.mythos_pipeline import (
    MythosPipelineDryRunRequest,
    MythosPipelineDryRunResponse,
    PipelineArtifactSummary,
    PipelineStage,
    PipelineValidationGate,
    artifact_payload_summary,
    artifact_source_hash,
    bounded_stage,
    build_mythos_pipeline_dry_run,
    count_blocked,
)
from app.mythos_report import (
    ClaimLedgerEntry,
    ClaimReviewDecisionValue,
    ClaimReviewDecisionResponse,
    ReportPreviewResponse,
    best_finding_candidate_claim,
    build_report_preview_response,
    review_evidence_refs_are_report_safe,
    safe_preview_lines,
    safe_preview_text,
    safe_string_list,
)
from app.repository import (
    APPROVAL_TERMINAL_STATUSES,
    DatabaseRepository,
    _safe_asset_value,
    approval_record_is_active,
)
from app.scope_guard import (
    ScopeGuardDecision,
    ScopeGuardRule,
    ValidationRequest,
    evaluate_validation_request,
)
from app.source_audit import (
    SourceAuditBlocked,
    run_source_audit,
    save_source_audit_pipeline_run,
)
from app.worker.tasks import dispatch_agent_task
from pydantic import BaseModel, Field


app = FastAPI(title="Bounty Mythos-Lite API")


class ScopeGuardEvaluationRequest(BaseModel):
    rule: ScopeGuardRule
    request: ValidationRequest
    campaign_id: str | None = None
    task_id: str | None = None
    run_id: str | None = None


class MythosPipelineRunSummary(BaseModel):
    id: str
    program_id: str | None = None
    asset: str
    policy_text_hash: str
    scope_status: str
    hypothesis_count: int
    blocked_count: int
    evidence_count: int
    report_title: str | None
    created_at: str
    timeline: list[PipelineStage] = Field(default_factory=list)
    artifact: PipelineArtifactSummary | None = None
    validation_gate: PipelineValidationGate | None = None
    hunter_intelligence: HunterIntelligence | None = None
    evidence_support_summary: dict | None = None
    closed_loop_summary: dict | None = None
    safety_gate_summary: dict = Field(default_factory=dict)
    audit_gate_summary: dict = Field(default_factory=dict)
    timeline_stage_summary: list[dict] = Field(default_factory=list)


class MythosPipelineRunDetail(MythosPipelineRunSummary):
    payload: dict


class SourceAuditScanRequest(BaseModel):
    repo_path: str = Field(min_length=1)
    scope_path: str = Field(min_length=1)
    policy_text: str | None = None
    program_id: str | None = None
    patch_diff_metadata: dict | None = None


class SourceAuditScanResponse(BaseModel):
    run_id: str
    artifact_id: str
    report_title: str
    scope_status: str
    hypothesis_count: int
    submission_blocked: bool
    safety_notes: list[str] = Field(default_factory=list)
    safety_gate_summary: dict = Field(default_factory=dict)
    audit_gate_summary: dict = Field(default_factory=dict)
    timeline_stage_summary: list[dict] = Field(default_factory=list)


class ArtifactResponse(BaseModel):
    id: str
    program_id: str | None
    asset: str
    kind: str
    source_type: str
    source_hash: str
    ingestion_status: str
    provenance: dict
    payload_summary: dict
    derived_facts: dict
    sensitivity_label: str
    redaction_status: str
    report_chain_allowed: bool
    safety_blockers: list[str] = Field(default_factory=list)
    usage_records: list[dict] = Field(default_factory=list)
    created_at: str


class CampaignBudgetRequest(BaseModel):
    time_budget_minutes: int | None = Field(default=None, ge=0)
    token_budget: int | None = Field(default=None, ge=0)
    tool_call_budget: int | None = Field(default=None, ge=0)
    validation_budget: int | None = Field(default=None, ge=0)


class CampaignCreateRequest(BaseModel):
    program_id: str | None = None
    name: str = Field(min_length=1, max_length=255)
    autonomy_level: str = Field(min_length=1, max_length=100)
    scope_status: str = Field(min_length=1, max_length=50)
    policy_text: str = Field(min_length=1)
    default_asset: str = Field(min_length=1, max_length=255)
    target_classes: list[str] = Field(default_factory=list, max_length=50)
    allowed_tools: list[str] = Field(default_factory=list, max_length=50)
    created_by: str = Field(default="operator", min_length=1, max_length=255)
    budget: CampaignBudgetRequest | None = None


class CampaignBudgetResponse(BaseModel):
    id: str
    campaign_id: str
    time_budget_minutes: int | None = None
    token_budget: int | None = None
    tool_call_budget: int | None = None
    tool_call_used: int = 0
    tool_call_remaining: int | None = None
    validation_budget: int | None = None
    validation_budget_used: int = 0
    validation_budget_remaining: int | None = None
    status: str
    created_at: str


class CampaignResponse(BaseModel):
    id: str
    program_id: str | None = None
    name: str
    status: str
    autonomy_level: str
    scope_status: str
    policy_text_hash: str
    default_asset: str
    target_classes: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    created_by: str
    created_at: str
    budget: CampaignBudgetResponse | None = None


class CampaignControlCampaignResponse(BaseModel):
    id: str
    program_id: str | None = None
    name: str
    status: str
    autonomy_level: str
    scope_status: str
    default_asset: str
    target_classes: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    created_by: str
    created_at: str


class CampaignTaskResponse(BaseModel):
    id: str
    campaign_id: str
    task_type: str
    agent_type: str
    title: str
    status: str
    input_refs: list[str] = Field(default_factory=list)
    output_refs: list[str] = Field(default_factory=list)
    created_at: str


class AgentRunResponse(BaseModel):
    id: str
    campaign_id: str | None
    task_id: str | None
    agent_type: str
    status: str
    input_refs: list[str] = Field(default_factory=list)
    output_refs: list[str] = Field(default_factory=list)
    safety_gate_state: str
    stop_reason: str | None
    created_at: str
    finished_at: str | None


class PipelineStageResponse(BaseModel):
    id: str
    pipeline_run_id: str | None = None
    campaign_id: str | None = None
    task_id: str | None = None
    stage_key: str
    stage_order: int
    status: str
    input_refs: list[str] = Field(default_factory=list)
    output_refs: list[str] = Field(default_factory=list)
    safety_gate_state: str
    stop_reason: str | None = None
    payload: dict = Field(default_factory=dict)
    created_at: str


class CodebaseMapResponse(BaseModel):
    id: str
    campaign_id: str
    source_ref: str
    repository: str
    commit_ref: str | None = None
    status: str
    route_count: int
    handler_count: int
    model_count: int
    authz_check_count: int
    sensitive_sink_count: int
    provenance_refs: list[str] = Field(default_factory=list)
    safety_gate_state: str
    created_at: str


class CodebaseFactResponse(BaseModel):
    id: str
    codebase_map_id: str
    campaign_id: str
    fact_type: str
    source_path: str
    symbol_name: str | None = None
    route_method: str | None = None
    route_path: str | None = None
    authz_hint: str | None = None
    sensitivity_label: str
    provenance_refs: list[str] = Field(default_factory=list)
    created_at: str


class ScannerRunResponse(BaseModel):
    id: str
    campaign_id: str
    codebase_map_id: str | None = None
    tool_name: str
    command_hash: str
    status: str
    finding_count: int
    candidate_count: int
    summary: str
    safety_gate_state: str
    created_at: str


class ValidationRunResponse(BaseModel):
    id: str
    campaign_id: str
    task_id: str | None = None
    approval_id: str | None = None
    validation_mode: str
    target_ref: str
    status: str
    safety_gate_state: str
    plan_digest: str | None = None
    approval_required: bool
    allowed_to_execute: bool
    preflight_passed: bool
    execution_started: bool = False
    evidence_ref_count: int
    summary: str
    created_at: str
    finished_at: str | None = None


class ValidationRunPreflightResponse(BaseModel):
    decision: ScopeGuardDecision
    validation_run: ValidationRunResponse
    execution_started: bool = False


ValidationRunManualOutcome = Literal["observed", "refuted", "needs_more_evidence"]


class ValidationRunManualResultRequest(BaseModel):
    outcome: ValidationRunManualOutcome
    reviewer: str = Field(min_length=1, max_length=100)
    summary: str = Field(min_length=1, max_length=1000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)


class CampaignCodebaseMapResponse(BaseModel):
    maps: list[CodebaseMapResponse] = Field(default_factory=list)
    facts: list[CodebaseFactResponse] = Field(default_factory=list)
    scanner_runs: list[ScannerRunResponse] = Field(default_factory=list)


class ClaimReviewDecisionRequest(BaseModel):
    claim_id: str
    decision: ClaimReviewDecisionValue
    reviewer: str = Field(min_length=1, max_length=100)
    rationale: str = Field(default="", max_length=1000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)

ManualObservationType = Literal[
    "manual_observation",
    "role_matrix_observation",
    "request_response_diff",
    "redaction_note",
]
REPORT_SAFE_REVIEW_EVIDENCE_REFS = {
    "local_code_reference",
    "log_ref",
    "request_response_diff",
    "sanitized_cross_account_diff",
    "sanitized_parent_child_matrix",
    "role_matrix_snapshot",
    "sanitized_request_response",
    "sanitized_role_matrix",
    "screenshot_ref",
}
SECURITY_IMPACT_OBSERVATION_TYPES = {
    "request_response_diff",
    "role_matrix_observation",
}


class ManualObservationRequest(BaseModel):
    claim_id: str
    observation_type: ManualObservationType = "manual_observation"
    observer: str = Field(min_length=1, max_length=100)
    observation: str = Field(min_length=1, max_length=1000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    safety_notes: list[str] = Field(default_factory=list, max_length=20)


class ManualObservationResponse(BaseModel):
    observation_id: str
    claim_id: str
    observation_type: ManualObservationType
    observer: str
    observation: str
    evidence_refs: list[str] = Field(default_factory=list)
    safety_notes: list[str] = Field(default_factory=list)
    redaction_status: str = "redacted"
    execution_allowed: bool = False
    report_chain_blocked: bool = True
    created_at: str


class ApprovalRecordRequest(BaseModel):
    run_id: str | None = None
    program_id: str | None = None
    asset: str | None = None
    validation_mode: str | None = None
    plan_digest: str | None = None
    expires_at: datetime | None = None
    requester: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=1000)


ApprovalDecisionValue = Literal["approved", "denied", "revoked", "expired", "used"]


class ApprovalDecisionRequest(BaseModel):
    decision: ApprovalDecisionValue
    actor: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=1000)


class ApprovalRecordResponse(BaseModel):
    id: str
    campaign_id: str | None
    task_id: str | None
    run_id: str | None
    program_id: str | None
    approval_type: str
    actor: str
    reason: str
    scope_reference: str | None
    requested_action: str | None
    asset: str | None
    validation_mode: str | None
    plan_digest: str | None
    autonomy_level: str | None
    safety_gate_state: str
    status: str
    decision_reason: str | None
    decided_by: str | None
    decided_at: str | None
    expires_at: str | None
    created_at: str


class ResearchQueueSuggestionResponse(BaseModel):
    queue_key: str
    title: str
    source: str
    candidate_status: str | None = None
    human_approval_required: bool = True
    refutation_question_count: int = 0
    validation_step_count: int = 0
    blocked_action_count: int = 0
    playbook_id: str | None = None
    surface_key: str | None = None
    priority_score: int = Field(ge=0, le=100)
    safety_gate: str
    next_allowed_action: str
    execution_allowed: bool = False


class ResearchQueueTaskRequest(BaseModel):
    queue_key: str = Field(min_length=1, max_length=255)
    requester: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=1000)


class AutonomousCandidateContextResponse(BaseModel):
    pipeline_run_id: str
    candidate_id: str
    candidate_status: str
    triage_signals: list[str] = Field(default_factory=list)
    evidence_focus: list[str] = Field(default_factory=list)
    source_fact_types: list[str] = Field(default_factory=list)
    hypothesis: str
    refutation_status: str
    refutation_questions: list[str] = Field(default_factory=list)
    validation_plan_status: str
    validation_steps: list[str] = Field(default_factory=list)
    human_approval_required: bool = True
    blocked_actions: list[str] = Field(default_factory=list)
    safety_notes: list[str] = Field(default_factory=list)
    execution_allowed: bool = False
    dispatch_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False


class ResearchTaskReviewResponse(BaseModel):
    task_id: str
    campaign_id: str
    queue_key: str
    title: str
    status: str
    source: str
    playbook_id: str | None = None
    surface_key: str | None = None
    priority_score: int = Field(ge=0, le=100)
    safety_gate: str
    next_allowed_action: str
    non_destructive_plan: list[str] = Field(default_factory=list)
    required_human_gates: list[str] = Field(default_factory=list)
    execution_allowed: bool = False
    dispatch_allowed: bool = False
    report_submission_allowed: bool = False
    latest_review_plan: dict | None = None
    latest_refutation_decision: dict | None = None
    suggested_refutation_decision: "SuggestedRefutationDecisionResponse | None" = None
    latest_validation_feedback: dict | None = None
    autonomous_candidate_context: AutonomousCandidateContextResponse | None = None


class ResearchReviewPlanRequest(BaseModel):
    reviewer: str = Field(min_length=1, max_length=100)
    rationale: str = Field(default="", max_length=1000)
    hypothesis: str = Field(min_length=1, max_length=1000)
    refutation_questions: list[str] = Field(default_factory=list, max_length=10)
    evidence_plan: list[str] = Field(default_factory=list, max_length=10)


class ResearchReviewPlanResponse(BaseModel):
    plan_id: str
    task_id: str
    campaign_id: str
    status: str
    hypothesis: str
    refutation_questions: list[str] = Field(default_factory=list)
    evidence_plan: list[str] = Field(default_factory=list)
    required_human_gates: list[str] = Field(default_factory=list)
    safety_gate: str
    next_allowed_action: str
    execution_allowed: bool = False
    dispatch_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False


ResearchRefutationDecisionValue = Literal[
    "refuted",
    "needs_evidence",
    "needs_validation_review",
    "parked_duplicate",
    "policy_blocked",
]
ValidationFeedbackReviewDecisionValue = Literal["allow_finding_promotion"]


class ResearchCandidateContextSummaryRequest(BaseModel):
    triage_signal_count: int = Field(default=0, ge=0, le=100)
    evidence_focus_count: int = Field(default=0, ge=0, le=100)
    source_fact_type_count: int = Field(default=0, ge=0, le=100)
    priority_reason_count: int = Field(default=0, ge=0, le=10)
    has_authorization_gap_candidate: bool = False


class ResearchRefutationDecisionRequest(BaseModel):
    plan_id: str = Field(min_length=1, max_length=255)
    reviewer: str = Field(min_length=1, max_length=100)
    decision: ResearchRefutationDecisionValue
    rationale: str = Field(min_length=1, max_length=1000)
    candidate_context_summary: ResearchCandidateContextSummaryRequest | None = None
    refutation_answers: list[str] = Field(default_factory=list, max_length=10)
    validation_mode: str | None = Field(default=None, max_length=100)
    target_ref: str | None = Field(default=None, max_length=1000)


class ResearchRefutationDecisionResponse(BaseModel):
    decision_id: str
    task_id: str
    campaign_id: str
    plan_id: str
    decision: ResearchRefutationDecisionValue
    rationale: str
    refutation_answers: list[str] = Field(default_factory=list)
    next_allowed_action: str
    validation_run_id: str | None = None
    approval_id: str | None = None
    execution_allowed: bool = False
    dispatch_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False


class SuggestedRefutationDecisionResponse(BaseModel):
    decision: ResearchRefutationDecisionValue
    plan_id: str
    rationale: str
    refutation_answer_count: int = Field(ge=0)
    refutation_question_count: int = Field(ge=0)
    next_allowed_action: str
    validation_mode: str | None = None
    target_ref: str | None = None
    human_review_required: bool = True
    execution_allowed: bool = False
    dispatch_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False


class ValidationFeedbackReviewRequest(BaseModel):
    reviewer: str = Field(min_length=1, max_length=100)
    decision: ValidationFeedbackReviewDecisionValue
    rationale: str = Field(min_length=1, max_length=1000)


class CampaignPromotionReviewSummary(BaseModel):
    blocked_attempt_count: int = 0
    finding_promotion_allowed: bool = False
    latest_reason: str | None = None
    next_allowed_action: str = "Review claim evidence and human gates before candidate promotion."
    provenance_ref_count: int = 0
    report_submission_allowed: bool = False
    validation_feedback_review_count: int = 0


class CampaignControlCenterResponse(BaseModel):
    campaign: CampaignControlCampaignResponse
    budget: CampaignBudgetResponse | None = None
    tasks: list[CampaignTaskResponse] = Field(default_factory=list)
    agent_runs: list[AgentRunResponse] = Field(default_factory=list)
    approvals: list[ApprovalRecordResponse] = Field(default_factory=list)
    validation_runs: list[ValidationRunResponse] = Field(default_factory=list)
    pipeline_stages: list[PipelineStageResponse] = Field(default_factory=list)
    safe_next_action: str
    blocked_reasons: list[str] = Field(default_factory=list)
    execution_allowed: bool = False
    promotion_review: CampaignPromotionReviewSummary = Field(
        default_factory=CampaignPromotionReviewSummary,
    )
    research_queue_suggestions: list[ResearchQueueSuggestionResponse] = Field(default_factory=list)
    research_review_plans: list[ResearchReviewPlanResponse] = Field(default_factory=list)


class LearningSignalRequest(BaseModel):
    program_id: str
    playbook_id: str
    outcome: LearningOutcome
    surface_key: str | None = None
    notes: str = Field(default="", max_length=1000)
    bounty_amount: int | None = Field(default=None, ge=0)
    severity_delta: LearningSeverityDelta | None = None
    evidence_quality: LearningEvidenceQuality | None = None
    triager_feedback: str | None = Field(default=None, max_length=1000)
    target_relationships: list[str] = Field(default_factory=list, max_length=20)


class LearningOutcomeRequest(BaseModel):
    outcome: LearningOutcome
    program_id: str | None = None
    run_id: str | None = None
    playbook_id: str | None = None
    surface_key: str | None = None
    notes: str = Field(default="", max_length=1000)
    bounty_amount: int | None = Field(default=None, ge=0)
    severity_delta: LearningSeverityDelta | None = None
    evidence_quality: LearningEvidenceQuality | None = None
    triager_feedback: str | None = Field(default=None, max_length=1000)
    target_relationships: list[str] | None = Field(default=None, max_length=20)


class KnowledgeArtifactImportRequest(BaseModel):
    program_id: str
    artifact: dict[str, Any]
    approval_id: str | None = Field(default=None, max_length=100)
    human_review_approved: bool = False
    reviewer: str | None = Field(default=None, max_length=100)


class CampaignCycleReviewCompletionRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=1000)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "bounty-mythos-api"}


@app.post("/mythos/campaigns", response_model=CampaignResponse)
def create_mythos_campaign(
    request: CampaignCreateRequest,
    session: Session = Depends(get_session),
) -> CampaignResponse:
    repository = DatabaseRepository(session)
    if request.program_id is None or repository.get_program(request.program_id) is None:
        raise HTTPException(status_code=404, detail="Program not found")
    campaign = repository.create_campaign(
        program_id=request.program_id,
        name=request.name,
        autonomy_level=request.autonomy_level,
        scope_status=request.scope_status,
        policy_text=request.policy_text,
        default_asset=request.default_asset,
        target_classes=request.target_classes,
        allowed_tools=request.allowed_tools,
        created_by=request.created_by,
        payload={"source": "campaign_api"},
    )
    if request.budget is not None:
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=request.budget.time_budget_minutes,
            token_budget=request.budget.token_budget,
            tool_call_budget=request.budget.tool_call_budget,
            validation_budget=request.budget.validation_budget,
        )
    return _campaign_response(campaign, repository)


@app.get("/mythos/campaigns", response_model=list[CampaignResponse])
def list_mythos_campaigns(
    session: Session = Depends(get_session),
) -> list[CampaignResponse]:
    repository = DatabaseRepository(session)
    return [
        _campaign_response(campaign, repository)
        for campaign in repository.list_campaigns()
    ]


@app.get("/mythos/campaigns/{campaign_id}", response_model=CampaignResponse)
def get_mythos_campaign(
    campaign_id: str,
    session: Session = Depends(get_session),
) -> CampaignResponse:
    repository = DatabaseRepository(session)
    campaign = repository.get_campaign(campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return _campaign_response(campaign, repository)


@app.post("/mythos/campaigns/{campaign_id}/start", response_model=CampaignResponse)
def start_mythos_campaign(
    campaign_id: str,
    session: Session = Depends(get_session),
) -> CampaignResponse:
    repository = DatabaseRepository(session)
    campaign = repository.update_campaign_status(campaign_id, "running")
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    tick_result = tick_campaign(
        campaign_id,
        repository=repository,
        dispatcher=dispatch_agent_task,
    )
    if tick_result["status"] == "blocked":
        campaign = repository.update_campaign_status(campaign_id, "blocked")
    return _campaign_response(campaign, repository)


@app.post("/mythos/campaigns/{campaign_id}/pause", response_model=CampaignResponse)
def pause_mythos_campaign(
    campaign_id: str,
    session: Session = Depends(get_session),
) -> CampaignResponse:
    return _update_campaign_status(campaign_id, "paused", session)


@app.post("/mythos/campaigns/{campaign_id}/resume", response_model=CampaignResponse)
def resume_mythos_campaign(
    campaign_id: str,
    session: Session = Depends(get_session),
) -> CampaignResponse:
    repository = DatabaseRepository(session)
    campaign = repository.get_campaign(campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.scope_status != "in_scope":
        raise HTTPException(status_code=409, detail="scope_not_in_scope")
    budget = repository.get_campaign_budget(campaign_id)
    if _campaign_budget_exhausted(budget):
        raise HTTPException(status_code=409, detail="budget_exhausted")
    return _update_campaign_status(campaign_id, "running", session)


@app.get("/mythos/campaigns/{campaign_id}/tasks", response_model=list[CampaignTaskResponse])
def list_mythos_campaign_tasks(
    campaign_id: str,
    session: Session = Depends(get_session),
) -> list[CampaignTaskResponse]:
    repository = DatabaseRepository(session)
    if repository.get_campaign(campaign_id) is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return [
        _campaign_task_response(record)
        for record in repository.list_campaign_tasks(campaign_id)
    ]


@app.post(
    "/mythos/campaigns/{campaign_id}/research-queue/tasks",
    response_model=CampaignTaskResponse,
)
def materialize_mythos_research_queue_task(
    campaign_id: str,
    request: ResearchQueueTaskRequest,
    session: Session = Depends(get_session),
) -> CampaignTaskResponse:
    repository = DatabaseRepository(session)
    campaign = repository.get_campaign(campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.scope_status != "in_scope":
        raise HTTPException(status_code=409, detail="scope_not_in_scope")
    if _campaign_budget_exhausted(repository.get_campaign_budget(campaign.id)):
        raise HTTPException(status_code=409, detail="budget_exhausted")

    suggestion = _campaign_research_queue_suggestion_by_key(
        campaign=campaign,
        repository=repository,
        queue_key=request.queue_key,
    )
    if suggestion is None:
        raise HTTPException(
            status_code=409,
            detail="research_queue_suggestion_not_available",
        )

    existing = _existing_research_queue_task(
        repository=repository,
        campaign_id=campaign.id,
        queue_key=suggestion.queue_key,
    )
    if existing is not None:
        return _campaign_task_response(existing)

    input_refs = _research_queue_task_input_refs(campaign.id, suggestion)
    task_payload = {
        "source": suggestion.source,
        "queue_key": suggestion.queue_key,
        "playbook_id": suggestion.playbook_id,
        "surface_key": suggestion.surface_key,
        "priority_score": suggestion.priority_score,
        "safety_gate": "advisory_memory_only",
        "next_allowed_action": suggestion.next_allowed_action,
        "requester": request.requester,
        "reason": request.reason,
        "execution_allowed": False,
        "dispatch_allowed": False,
    }
    if suggestion.source == "mythos_pipeline_autonomous_hunt_queue":
        task_payload.update(
            _autonomous_hunt_queue_task_metadata(
                repository=repository,
                queue_key=suggestion.queue_key,
            )
        )
    task = repository.create_campaign_task(
        campaign_id=campaign.id,
        task_type="research_queue_review",
        agent_type="human_research_reviewer",
        title=suggestion.title,
        input_refs=input_refs,
        payload=task_payload,
    )
    task = repository.update_campaign_task_status(task.id, "queued_review") or task
    _record_research_queue_materialized_stage(
        repository=repository,
        campaign_id=campaign.id,
        task=task,
        suggestion=suggestion,
        input_refs=input_refs,
    )
    _record_autonomous_research_review_plan_draft(
        repository=repository,
        campaign_id=campaign.id,
        task=task,
        task_payload=task_payload,
    )
    return _campaign_task_response(task)


@app.get(
    "/mythos/campaigns/{campaign_id}/research-queue/tasks/{task_id}/review",
    response_model=ResearchTaskReviewResponse,
)
def get_mythos_research_task_review(
    campaign_id: str,
    task_id: str,
    session: Session = Depends(get_session),
) -> ResearchTaskReviewResponse:
    repository = DatabaseRepository(session)
    campaign = repository.get_campaign(campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.scope_status != "in_scope":
        raise HTTPException(status_code=409, detail="scope_not_in_scope")
    task = repository.session.get(CampaignTaskRecord, task_id)
    if task is None or task.campaign_id != campaign.id:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.task_type != "research_queue_review":
        raise HTTPException(status_code=409, detail="not_research_queue_task")
    return _research_task_review_response(task, repository=repository)


@app.post(
    "/mythos/campaigns/{campaign_id}/research-queue/tasks/{task_id}/review-plans",
    response_model=ResearchReviewPlanResponse,
)
def create_mythos_research_review_plan(
    campaign_id: str,
    task_id: str,
    request: ResearchReviewPlanRequest,
    session: Session = Depends(get_session),
) -> ResearchReviewPlanResponse:
    repository = DatabaseRepository(session)
    campaign = repository.get_campaign(campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.scope_status != "in_scope":
        raise HTTPException(status_code=409, detail="scope_not_in_scope")
    if _campaign_budget_exhausted(repository.get_campaign_budget(campaign.id)):
        raise HTTPException(status_code=409, detail="budget_exhausted")

    task = repository.session.get(CampaignTaskRecord, task_id)
    if task is None or task.campaign_id != campaign.id:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.task_type != "research_queue_review":
        raise HTTPException(status_code=409, detail="not_research_queue_task")

    existing_plan = _existing_research_review_plan_for_request(
        repository,
        task=task,
        request=request,
    )
    if existing_plan is not None:
        return ResearchReviewPlanResponse(**existing_plan)

    response = _research_review_plan_response(
        task=task,
        request=request,
    )
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    queue_key = safe_preview_text(task_payload.get("queue_key", "research_queue"))
    input_refs = _research_review_plan_input_refs(
        campaign_id=campaign.id,
        task_id=task.id,
        queue_key=queue_key,
        task_payload=task_payload,
    )
    stage_payload = {
        "plan_id": response.plan_id,
        "hypothesis": response.hypothesis,
        "refutation_questions": response.refutation_questions,
        "evidence_plan": response.evidence_plan,
        "reviewer": safe_preview_text(request.reviewer),
        "rationale": safe_preview_text(request.rationale),
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "raw_payload_processed": False,
    }
    stage_payload.update(_autonomous_research_review_plan_payload(repository, task_payload))
    repository.save_pipeline_stage(
        pipeline_run_id=None,
        campaign_id=campaign.id,
        task_id=task.id,
        stage_key="research_task_review_plan",
        stage_order=len(repository.list_campaign_pipeline_stages(campaign.id)),
        status=response.status,
        input_refs=input_refs,
        output_refs=[f"research_plan:{response.plan_id}"],
        safety_gate_state=response.safety_gate,
        stop_reason=None,
        payload=stage_payload,
    )
    return response


@app.post(
    "/mythos/campaigns/{campaign_id}/research-queue/tasks/{task_id}/review-decisions",
    response_model=ResearchRefutationDecisionResponse,
    response_model_exclude_none=True,
)
def create_mythos_research_refutation_decision(
    campaign_id: str,
    task_id: str,
    request: ResearchRefutationDecisionRequest,
    session: Session = Depends(get_session),
) -> ResearchRefutationDecisionResponse:
    repository = DatabaseRepository(session)
    campaign = repository.get_campaign(campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.scope_status != "in_scope":
        raise HTTPException(status_code=409, detail="scope_not_in_scope")
    task = repository.session.get(CampaignTaskRecord, task_id)
    if task is None or task.campaign_id != campaign.id:
        raise HTTPException(status_code=404, detail="Task not found")
    if task.task_type != "research_queue_review":
        raise HTTPException(status_code=409, detail="not_research_queue_task")

    latest_plan = _latest_research_review_plan(repository, task)
    if latest_plan is None or latest_plan["plan_id"] != safe_preview_text(request.plan_id):
        raise HTTPException(status_code=409, detail="research_review_plan_not_current")

    _raise_if_refutation_decision_request_missing_required_gate_fields(request)
    latest_decision = _latest_research_refutation_decision(repository, task)
    if (
        latest_decision is not None
        and latest_decision.get("plan_id") == safe_preview_text(request.plan_id)
        and latest_decision.get("decision") == request.decision
    ):
        if request.decision == "needs_validation_review":
            latest_run_id = latest_decision.get("validation_run_id")
            latest_run = (
                repository.get_validation_run(latest_run_id)
                if isinstance(latest_run_id, str)
                else None
            )
            requested_mode = safe_preview_text(request.validation_mode or "")
            requested_target = safe_preview_text(request.target_ref or f"campaign:{campaign.id}")
            if (
                latest_run is None
                or latest_run.validation_mode != requested_mode
                or latest_run.target_ref != requested_target
            ):
                raise HTTPException(status_code=409, detail="validation_review_gate_mismatch")
        return ResearchRefutationDecisionResponse(**latest_decision)
    if (
        latest_decision is not None
        and latest_decision.get("plan_id") == safe_preview_text(request.plan_id)
        and latest_decision.get("decision") == "needs_validation_review"
    ):
        raise HTTPException(status_code=409, detail="research_decision_not_current")

    response = _research_refutation_decision_response(
        task=task,
        request=request,
    )
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    autonomous_payload = _autonomous_research_review_plan_payload(repository, task_payload)
    validation_run_id = None
    approval_id = None
    if response.decision == "needs_validation_review":
        validation_mode = safe_preview_text(request.validation_mode or "")
        if not validation_mode:
            raise HTTPException(status_code=422, detail="validation_mode_required")
        if validation_mode not in safe_string_list(campaign.allowed_tools):
            raise HTTPException(status_code=409, detail="validation_mode_not_allowed")
        budget = repository.get_campaign_budget(campaign.id)
        if (
            budget is not None
            and budget.validation_budget is not None
            and _campaign_validation_budget_used(
                repository.list_campaign_validation_runs(campaign.id),
            ) >= budget.validation_budget
        ):
            raise HTTPException(status_code=409, detail="budget_exhausted")
        target_ref = safe_preview_text(request.target_ref or f"campaign:{campaign.id}")
        if target_ref.startswith("campaign:") and target_ref != f"campaign:{campaign.id}":
            raise HTTPException(status_code=409, detail="target_ref_campaign_mismatch")
        approval_asset = campaign.default_asset if target_ref == f"campaign:{campaign.id}" else target_ref
        plan_digest = f"research_plan:{response.plan_id}"
        approval_payload = {
            "source": "research_task_refutation_decision",
            "decision_id": response.decision_id,
            "plan_id": response.plan_id,
            "raw_payload_processed": False,
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        }
        approval_payload.update(autonomous_payload)
        approval = repository.create_approval_record(
            campaign_id=campaign.id,
            task_id=task.id,
            program_id=campaign.program_id,
            approval_type="validation_batch",
            actor=request.reviewer,
            reason="Human approval required before validation preflight.",
            requested_action="validation_preflight_review",
            asset=approval_asset,
            validation_mode=validation_mode,
            plan_digest=plan_digest,
            autonomy_level=campaign.autonomy_level,
            safety_gate_state="awaiting_approval",
            payload=approval_payload,
        )
        approval_id = approval.id
        response.approval_id = approval_id
        validation_payload = {
            "source": "research_task_refutation_decision",
            "decision_id": response.decision_id,
            "plan_id": response.plan_id,
            "approval_record_id": approval_id,
            "raw_payload_processed": False,
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        }
        validation_payload.update(autonomous_payload)
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=approval_id,
            validation_mode=validation_mode,
            target_ref=target_ref,
            status="awaiting_approval",
            safety_gate_state="awaiting_approval",
            plan_digest=plan_digest,
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="Human approval required before validation. Refutation review requested validation planning.",
            payload=validation_payload,
        )
        validation_run_id = validation_run.id
        response.validation_run_id = validation_run_id
    stage_payload = {
        "decision_id": response.decision_id,
        "plan_id": response.plan_id,
        "decision": response.decision,
        "reviewer": safe_preview_text(request.reviewer),
        "rationale": response.rationale,
        "refutation_answers": response.refutation_answers,
        "approval_id": approval_id,
        "validation_run_id": validation_run_id,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "raw_payload_processed": False,
    }
    stage_payload.update(autonomous_payload)
    repository.save_pipeline_stage(
        pipeline_run_id=None,
        campaign_id=campaign.id,
        task_id=task.id,
        stage_key="research_task_refutation_decision",
        stage_order=len(repository.list_campaign_pipeline_stages(campaign.id)),
        status=response.decision,
        input_refs=_research_refutation_decision_input_refs(
            campaign_id=campaign.id,
            task_id=task.id,
            plan_id=response.plan_id,
            task_payload=task_payload,
        ),
        output_refs=[
            f"refutation_decision:{response.decision_id}",
            *(
                [f"approval:{approval_id}"]
                if approval_id is not None
                else []
            ),
            *(
                [f"validation_run:{validation_run_id}"]
                if validation_run_id is not None
                else []
            ),
        ],
        safety_gate_state="advisory_refutation_only",
        stop_reason=None,
        payload=stage_payload,
    )
    return response


@app.get("/mythos/campaigns/{campaign_id}/agent-runs", response_model=list[AgentRunResponse])
def list_mythos_campaign_agent_runs(
    campaign_id: str,
    session: Session = Depends(get_session),
) -> list[AgentRunResponse]:
    repository = DatabaseRepository(session)
    if repository.get_campaign(campaign_id) is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return [
        _agent_run_response(record)
        for record in repository.list_campaign_agent_runs(campaign_id)
    ]


@app.get("/mythos/campaigns/{campaign_id}/approvals", response_model=list[ApprovalRecordResponse])
def list_mythos_campaign_approvals(
    campaign_id: str,
    session: Session = Depends(get_session),
) -> list[ApprovalRecordResponse]:
    repository = DatabaseRepository(session)
    if repository.get_campaign(campaign_id) is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return [
        _approval_record_response(record)
        for record in repository.list_campaign_approval_records(campaign_id)
    ]


@app.get(
    "/mythos/campaigns/{campaign_id}/pipeline-stages",
    response_model=list[PipelineStageResponse],
)
def list_mythos_campaign_pipeline_stages(
    campaign_id: str,
    session: Session = Depends(get_session),
) -> list[PipelineStageResponse]:
    repository = DatabaseRepository(session)
    if repository.get_campaign(campaign_id) is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return [
        _pipeline_stage_response(record)
        for record in repository.list_campaign_pipeline_stages(campaign_id)
    ]


@app.post(
    "/mythos/campaigns/{campaign_id}/pipeline-stages/{stage_id}/validation-feedback-review",
    response_model=PipelineStageResponse,
)
def review_mythos_validation_feedback_for_finding_promotion(
    campaign_id: str,
    stage_id: str,
    request: ValidationFeedbackReviewRequest,
    session: Session = Depends(get_session),
) -> PipelineStageResponse:
    repository = DatabaseRepository(session)
    campaign = repository.get_campaign(campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.scope_status != "in_scope":
        raise HTTPException(status_code=409, detail="scope_not_in_scope")

    stage = repository.get_pipeline_stage(stage_id)
    if (
        stage is None
        or stage.campaign_id != campaign_id
        or stage.stage_key != "research_task_validation_feedback"
    ):
        raise HTTPException(status_code=404, detail="Validation feedback stage not found")
    payload = stage.payload if isinstance(stage.payload, dict) else {}
    if safe_preview_text(payload.get("outcome", "")) != "observed":
        raise HTTPException(status_code=409, detail="Validation feedback is not observed")
    _validation_feedback_stage_validation_run_or_409(repository, stage)
    if not _validation_feedback_stage_matches_validation_run(repository, stage):
        raise HTTPException(status_code=409, detail="validation_feedback_run_mismatch")
    existing_review = _research_feedback_allow_review_stage(repository, stage)
    if existing_review is not None:
        return _pipeline_stage_response(existing_review)

    validation_run_id = safe_preview_text(payload.get("validation_run_id", ""))
    input_refs = [
        f"campaign:{campaign_id}",
        *([f"campaign_task:{stage.task_id}"] if stage.task_id else []),
        f"pipeline_stage:{stage.id}",
        *([f"validation_run:{validation_run_id}"] if validation_run_id else []),
    ]
    reviewed = repository.save_pipeline_stage(
        pipeline_run_id=stage.pipeline_run_id,
        campaign_id=campaign_id,
        task_id=stage.task_id,
        stage_key="research_task_validation_feedback_review",
        stage_order=len(repository.list_campaign_pipeline_stages(campaign_id)),
        status="completed",
        input_refs=input_refs,
        output_refs=[f"pipeline_stage:{stage.id}"],
        safety_gate_state="manual_review_required",
        stop_reason=None,
        payload={
            "source": "human_validation_feedback_review",
            "reviewed_stage_id": stage.id,
            "decision": request.decision,
            "reviewer": safe_preview_text(request.reviewer),
            "rationale": safe_preview_text(request.rationale),
            "finding_confirmation_allowed": True,
            "report_submission_allowed": False,
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "raw_payload_processed": False,
        },
    )
    usage_record = _artifact_usage_record_for_validation_feedback_review(
        repository=repository,
        feedback_stage=stage,
        review_stage=reviewed,
    )
    if usage_record is not None:
        artifact_id, usage = usage_record
        repository.append_artifact_usage_records(
            artifact_id=artifact_id,
            usage_records=[usage],
        )
    return _pipeline_stage_response(reviewed)


@app.post(
    "/mythos/campaigns/{campaign_id}/cycle-reviews/{stage_id}/complete",
    response_model=PipelineStageResponse,
)
def complete_mythos_campaign_cycle_review(
    campaign_id: str,
    stage_id: str,
    request: CampaignCycleReviewCompletionRequest,
    session: Session = Depends(get_session),
) -> PipelineStageResponse:
    repository = DatabaseRepository(session)
    campaign = repository.get_campaign(campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.scope_status != "in_scope":
        raise HTTPException(status_code=409, detail="scope_not_in_scope")

    stage = repository.get_pipeline_stage(stage_id)
    if (
        stage is None
        or stage.campaign_id != campaign_id
        or stage.stage_key != "campaign_cycle_review"
    ):
        raise HTTPException(status_code=404, detail="Cycle review stage not found")
    if stage.status != "awaiting_review":
        raise HTTPException(status_code=409, detail="Cycle review is not awaiting review")
    if _cycle_review_unresolved_gate_refs(repository, stage):
        raise HTTPException(status_code=409, detail="Cycle review has unresolved gates")
    completed_reviews = {
        _cycle_review_signature(record)
        for record in repository.list_campaign_pipeline_stages(campaign_id)
        if record.stage_key == "campaign_cycle_review"
        and record.status == "completed"
        and record.safety_gate_state == "allowed"
    }
    if _cycle_review_signature(stage) in completed_reviews:
        raise HTTPException(status_code=409, detail="Cycle review is already completed")

    completed = repository.save_pipeline_stage(
        pipeline_run_id=stage.pipeline_run_id,
        campaign_id=campaign_id,
        task_id=stage.task_id,
        stage_key="campaign_cycle_review",
        stage_order=stage.stage_order,
        status="completed",
        input_refs=stage.input_refs,
        output_refs=stage.output_refs,
        safety_gate_state="allowed",
        stop_reason=None,
        payload={
            "review_gate": "human_review_completed",
            "actor": request.actor,
            "reason_recorded": bool(request.reason),
            "raw_payload_processed": False,
            "execution_allowed": False,
            "submission_allowed": False,
        },
    )
    return _pipeline_stage_response(completed)


@app.get("/mythos/campaigns/{campaign_id}/validation-runs", response_model=list[ValidationRunResponse])
def list_mythos_campaign_validation_runs(
    campaign_id: str,
    session: Session = Depends(get_session),
) -> list[ValidationRunResponse]:
    repository = DatabaseRepository(session)
    if repository.get_campaign(campaign_id) is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return [
        _validation_run_response(record, repository=repository)
        for record in repository.list_campaign_validation_runs(campaign_id)
    ]


@app.post(
    "/mythos/validation-runs/{validation_run_id}/preflight",
    response_model=ValidationRunPreflightResponse,
)
def preflight_mythos_validation_run(
    validation_run_id: str,
    session: Session = Depends(get_session),
) -> ValidationRunPreflightResponse:
    repository = DatabaseRepository(session)
    validation_run = repository.get_validation_run(validation_run_id)
    if validation_run is None:
        raise HTTPException(status_code=404, detail="Validation run not found")
    if _validation_run_has_manual_result(validation_run):
        raise HTTPException(
            status_code=409,
            detail="Validation run already has manual result",
        )

    campaign = repository.get_campaign(validation_run.campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")

    campaign_budget = repository.get_campaign_budget(campaign.id)
    if _campaign_budget_exhausted(campaign_budget) or _campaign_validation_budget_exhausted(
        repository,
        budget=campaign_budget,
        validation_run=validation_run,
    ):
        decision = ScopeGuardDecision(
            allowed=False,
            reason="budget_exhausted",
        )
    elif validation_run.status not in {
        "ready",
        "preflight_passed",
    } and not _validation_run_awaits_approval_review(validation_run):
        decision = ScopeGuardDecision(
            allowed=False,
            reason="validation_run_not_ready",
        )
    else:
        asset = _validation_run_scope_asset(validation_run, campaign)
        rule = ScopeGuardRule(
            asset=asset,
            scope_status=campaign.scope_status,
            automation="human_controlled_validation",
            allowed_validation=safe_string_list(campaign.allowed_tools),
            forbidden=["DoS"],
            human_approval_required=validation_run.approval_required,
        )
        decision = evaluate_validation_request(
            rule,
            ValidationRequest(
                asset=asset,
                validation_type=validation_run.validation_mode,
                human_approved=True,
                plan_digest=validation_run.plan_digest,
            ),
        )
        if decision.allowed and validation_run.approval_required:
            approval = (
                repository.session.get(ApprovalRecord, validation_run.approval_id)
                if validation_run.approval_id
                else None
            )
            if approval is not None and _validation_run_approval_matches(
                approval=approval,
                validation_run=validation_run,
                campaign=campaign,
                asset=asset,
            ):
                decision = (
                    ScopeGuardDecision(
                        allowed=False,
                        reason="approval_budget_exhausted",
                    )
                    if _approval_validation_budget_exhausted(
                        repository,
                        approval=approval,
                        validation_run=validation_run,
                    )
                    else ScopeGuardDecision(
                        allowed=True,
                        reason="approved_validation_record",
                    )
                )
            else:
                decision = ScopeGuardDecision(
                    allowed=False,
                    reason="approval_record_required",
                )

    updated_run = repository.record_validation_run_preflight(
        validation_run.id,
        allowed=decision.allowed,
        reason=decision.reason,
    )
    if updated_run is None:
        raise HTTPException(status_code=404, detail="Validation run not found")
    return ValidationRunPreflightResponse(
        decision=decision,
        validation_run=_validation_run_response(updated_run, repository=repository),
        execution_started=False,
    )


@app.post(
    "/mythos/validation-runs/{validation_run_id}/manual-results",
    response_model=ValidationRunResponse,
)
def record_mythos_validation_run_manual_result(
    validation_run_id: str,
    request: ValidationRunManualResultRequest,
    session: Session = Depends(get_session),
) -> ValidationRunResponse:
    repository = DatabaseRepository(session)
    validation_run = repository.get_validation_run(validation_run_id)
    if validation_run is None:
        raise HTTPException(status_code=404, detail="Validation run not found")
    if _validation_run_has_manual_result(validation_run):
        campaign = _validation_run_campaign_or_404_in_scope(repository, validation_run)
        _raise_if_validation_run_approval_not_active(
            repository=repository,
            validation_run=validation_run,
            campaign=campaign,
        )
    if _validation_run_manual_result_matches(validation_run, request):
        return _validation_run_response(validation_run, repository=repository)
    if validation_run.status != "preflight_passed":
        raise HTTPException(
            status_code=409,
            detail="Validation run preflight has not passed",
        )
    if not validation_run.allowed_to_execute:
        raise HTTPException(
            status_code=409,
            detail="Validation run preflight is not active",
        )
    campaign = _validation_run_campaign_or_404_in_scope(repository, validation_run)
    _raise_if_validation_run_approval_not_active(
        repository=repository,
        validation_run=validation_run,
        campaign=campaign,
    )

    updated_run = repository.record_validation_run_manual_result(
        validation_run.id,
        outcome=request.outcome,
        reviewer=safe_preview_text(request.reviewer),
        summary=safe_preview_text(request.summary),
        evidence_refs=safe_preview_lines(request.evidence_refs),
    )
    if updated_run is None:
        raise HTTPException(status_code=404, detail="Validation run not found")
    repository.save_pipeline_stage(
        pipeline_run_id=None,
        campaign_id=updated_run.campaign_id,
        task_id=updated_run.task_id,
        stage_key="validation_manual_result",
        stage_order=len(repository.list_campaign_pipeline_stages(updated_run.campaign_id)),
        status=updated_run.status,
        input_refs=[f"validation_run:{updated_run.id}"],
        output_refs=[f"validation_run:{updated_run.id}"],
        safety_gate_state=updated_run.safety_gate_state,
        stop_reason=None,
        payload={
            "outcome": request.outcome,
            "reviewer": safe_preview_text(request.reviewer),
            "evidence_ref_count": updated_run.evidence_ref_count,
            "execution_started": False,
            "validation_result_review": _validation_result_review_payload(updated_run),
        },
    )
    _record_research_validation_feedback_stage(repository, updated_run, request)
    usage_record = _artifact_usage_record_for_validation_feedback(
        repository=repository,
        validation_run=updated_run,
    )
    if usage_record is not None:
        artifact_id, usage = usage_record
        repository.append_artifact_usage_records(
            artifact_id=artifact_id,
            usage_records=[usage],
        )
    return _validation_run_response(updated_run, repository=repository)


@app.get(
    "/mythos/campaigns/{campaign_id}/codebase-map",
    response_model=CampaignCodebaseMapResponse,
)
def get_mythos_campaign_codebase_map(
    campaign_id: str,
    session: Session = Depends(get_session),
) -> CampaignCodebaseMapResponse:
    repository = DatabaseRepository(session)
    if repository.get_campaign(campaign_id) is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return CampaignCodebaseMapResponse(
        maps=[
            _codebase_map_response(record)
            for record in repository.list_campaign_codebase_maps(campaign_id)
        ],
        facts=[
            _codebase_fact_response(record)
            for record in repository.list_campaign_codebase_facts(campaign_id)
        ],
        scanner_runs=[
            _scanner_run_response(record)
            for record in repository.list_campaign_scanner_runs(campaign_id)
        ],
    )


@app.get(
    "/mythos/campaigns/{campaign_id}/control-center",
    response_model=CampaignControlCenterResponse,
)
def get_mythos_campaign_control_center(
    campaign_id: str,
    session: Session = Depends(get_session),
) -> CampaignControlCenterResponse:
    repository = DatabaseRepository(session)
    campaign = repository.get_campaign(campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")

    budget = repository.get_campaign_budget(campaign_id)
    tasks = repository.list_campaign_tasks(campaign_id)
    agent_runs = repository.list_campaign_agent_runs(campaign_id)
    approvals = repository.list_campaign_approval_records(campaign_id)
    validation_runs = repository.list_campaign_validation_runs(campaign_id)
    stages = repository.list_campaign_pipeline_stages(campaign_id)
    blocked_reasons = _campaign_control_center_blocked_reasons(
        campaign=campaign,
        budget=budget,
        agent_runs=agent_runs,
        validation_runs=validation_runs,
        stages=stages,
    )

    return CampaignControlCenterResponse(
        campaign=_campaign_control_campaign_response(campaign),
        budget=_campaign_budget_response(budget, repository=repository),
        tasks=[_campaign_task_response(record) for record in tasks],
        agent_runs=[_agent_run_response(record) for record in agent_runs],
        approvals=[_approval_record_response(record) for record in approvals],
        validation_runs=[
            _validation_run_response(record, repository=repository)
            for record in validation_runs
        ],
        pipeline_stages=[_pipeline_stage_response(record) for record in stages],
        safe_next_action=_campaign_control_center_safe_next_action(
            campaign=campaign,
            budget=budget,
            tasks=tasks,
            agent_runs=agent_runs,
            approvals=approvals,
            validation_runs=validation_runs,
            pipeline_stages=stages,
            repository=repository,
            blocked_reasons=blocked_reasons,
        ),
        blocked_reasons=blocked_reasons,
        execution_allowed=False,
        promotion_review=_campaign_promotion_review_summary(stages),
        research_queue_suggestions=_campaign_research_queue_suggestions(
            campaign,
            repository,
        ),
        research_review_plans=_campaign_research_review_plans(
            campaign,
            repository,
        ),
    )


@app.get("/programs", response_model=list[Program])
def list_programs(session: Session = Depends(get_session)) -> list[Program]:
    return DatabaseRepository(session).list_programs()


@app.get("/programs/{program_id}", response_model=Program)
def get_program(program_id: str, session: Session = Depends(get_session)) -> Program:
    program = DatabaseRepository(session).get_program(program_id)
    if program is not None:
        return program
    raise HTTPException(status_code=404, detail="Program not found")


@app.get("/findings", response_model=list[Finding])
def list_findings(session: Session = Depends(get_session)) -> list[Finding]:
    return DatabaseRepository(session).list_findings()


@app.get("/findings/{finding_id}", response_model=Finding)
def get_finding(finding_id: str, session: Session = Depends(get_session)) -> Finding:
    finding = DatabaseRepository(session).get_finding(finding_id)
    if finding is not None:
        return finding
    raise HTTPException(status_code=404, detail="Finding not found")


@app.get("/reports", response_model=list[ReportDraft])
def list_reports(session: Session = Depends(get_session)) -> list[ReportDraft]:
    return DatabaseRepository(session).list_reports()


@app.get("/reports/{report_id}", response_model=ReportDraft)
def get_report(report_id: str, session: Session = Depends(get_session)) -> ReportDraft:
    report = DatabaseRepository(session).get_report(report_id)
    if report is not None:
        return report
    raise HTTPException(status_code=404, detail="Report not found")


@app.post("/mythos/approval-records", response_model=ApprovalRecordResponse)
def create_approval_record(
    request: ApprovalRecordRequest,
    session: Session = Depends(get_session),
) -> ApprovalRecordResponse:
    repository = DatabaseRepository(session)
    if request.program_id is not None:
        _program_or_404_in_scope(repository, request.program_id)
    if request.run_id is not None:
        if repository.get_pipeline_run(request.run_id) is None:
            raise HTTPException(status_code=404, detail="Pipeline run not found")
        _raise_if_campaign_scoped_run_not_in_scope(repository, request.run_id)
    record = repository.create_approval_record(
        run_id=request.run_id,
        program_id=request.program_id,
        asset=request.asset,
        validation_mode=request.validation_mode,
        plan_digest=request.plan_digest,
        expires_at=request.expires_at,
        requester=request.requester,
        reason=request.reason,
        status="requested",
    )
    return _approval_record_response(record)


@app.get("/mythos/approval-records", response_model=list[ApprovalRecordResponse])
def list_approval_records(
    run_id: str | None = None,
    session: Session = Depends(get_session),
) -> list[ApprovalRecordResponse]:
    return [
        _approval_record_response(record)
        for record in DatabaseRepository(session).list_approval_records(run_id=run_id)
    ]


@app.post("/mythos/approval-records/{approval_id}/decisions", response_model=ApprovalRecordResponse)
def decide_approval_record(
    approval_id: str,
    request: ApprovalDecisionRequest,
    session: Session = Depends(get_session),
) -> ApprovalRecordResponse:
    return _decide_approval_record_response(approval_id, request, session)


@app.post("/mythos/approvals/{approval_id}/decisions", response_model=ApprovalRecordResponse)
def decide_mythos_approval(
    approval_id: str,
    request: ApprovalDecisionRequest,
    session: Session = Depends(get_session),
) -> ApprovalRecordResponse:
    return _decide_approval_record_response(approval_id, request, session)


def _decide_approval_record_response(
    approval_id: str,
    request: ApprovalDecisionRequest,
    session: Session,
) -> ApprovalRecordResponse:
    repository = DatabaseRepository(session)
    current_record = repository.session.get(ApprovalRecord, approval_id)
    if current_record is None:
        raise HTTPException(status_code=404, detail="Approval record not found")
    if current_record.status in APPROVAL_TERMINAL_STATUSES:
        raise HTTPException(status_code=409, detail="Approval record already terminal")
    if current_record.status == request.decision and current_record.decided_at is not None:
        raise HTTPException(status_code=409, detail="Approval record already decided")
    if request.decision == "approved" and not approval_record_is_active(current_record):
        raise HTTPException(status_code=409, detail="Approval record expired")
    if request.decision == "approved" and current_record.program_id is not None:
        _program_or_404_in_scope(repository, current_record.program_id)
    if request.decision == "approved" and current_record.campaign_id is not None:
        campaign = repository.get_campaign(current_record.campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="Campaign not found")
        if campaign.scope_status != "in_scope":
            raise HTTPException(status_code=409, detail="scope_not_in_scope")

    record = repository.decide_approval_record(
        approval_id=approval_id,
        decision=request.decision,
        actor=request.actor,
        reason=request.reason,
    )
    return _approval_record_response(record)


@app.get("/mythos/artifacts", response_model=list[ArtifactResponse])
def list_mythos_artifacts(
    program_id: str | None = None,
    asset: str | None = None,
    source_type: str | None = None,
    ingestion_status: str | None = None,
    provenance_ref: str | None = None,
    fact_type: str | None = None,
    usage_type: str | None = None,
    usage_run_id: str | None = None,
    sensitivity_label: str | None = None,
    redaction_status: str | None = None,
    report_chain_allowed: bool | None = None,
    session: Session = Depends(get_session),
) -> list[ArtifactResponse]:
    return [
        _artifact_response(record)
        for record in DatabaseRepository(session).list_artifacts(
            program_id=program_id,
            asset=asset,
            source_type=source_type,
            ingestion_status=ingestion_status,
            provenance_ref=provenance_ref,
            fact_type=fact_type,
            usage_type=usage_type,
            usage_run_id=usage_run_id,
            sensitivity_label=sensitivity_label,
            redaction_status=redaction_status,
            report_chain_allowed=report_chain_allowed,
        )
    ]


@app.get("/mythos/artifacts/{artifact_id}", response_model=ArtifactResponse)
def get_mythos_artifact(
    artifact_id: str,
    session: Session = Depends(get_session),
) -> ArtifactResponse:
    record = DatabaseRepository(session).get_artifact(artifact_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Artifact not found")
    return _artifact_response(record)


@app.get(
    "/mythos/brain/programs/{program_id}",
    response_model=ProgramIntelligenceProfile,
)
def get_mythos_brain_program(
    program_id: str,
    session: Session = Depends(get_session),
) -> ProgramIntelligenceProfile:
    repository = DatabaseRepository(session)
    program = repository.get_program(program_id)
    if program is None:
        raise HTTPException(status_code=404, detail="Program not found")
    return _program_intelligence_profile(repository, program_id)


@app.post("/mythos/brain/learning-signals", response_model=LearningSignal)
def create_mythos_brain_learning_signal(
    request: LearningSignalRequest,
    session: Session = Depends(get_session),
) -> LearningSignal:
    repository = DatabaseRepository(session)
    _program_or_404_in_scope(repository, request.program_id)
    signal = LearningSignal(
        program_id=request.program_id,
        playbook_id=request.playbook_id,
        outcome=request.outcome,
        surface_key=request.surface_key,
        notes=request.notes,
        bounty_amount=request.bounty_amount,
        severity_delta=request.severity_delta,
        evidence_quality=request.evidence_quality,
        triager_feedback=request.triager_feedback,
        target_relationships=request.target_relationships,
    )
    record = _existing_learning_signal_for_outcome(repository, signal=signal, run_record=None)
    if record is None:
        record = repository.save_learning_signal(
            program_id=signal.program_id,
            playbook_id=signal.playbook_id,
            outcome=signal.outcome,
            surface_key=signal.surface_key,
            notes=signal.notes,
            bounty_amount=signal.bounty_amount,
            severity_delta=signal.severity_delta,
            evidence_quality=signal.evidence_quality,
            triager_feedback=signal.triager_feedback,
            target_relationships=signal.target_relationships,
        )
    return _learning_signal_response(record)


@app.post(
    "/mythos/brain/knowledge-artifacts",
    response_model=KnowledgeArtifactImportResult,
)
def import_mythos_brain_knowledge_artifact(
    request: KnowledgeArtifactImportRequest,
    session: Session = Depends(get_session),
) -> KnowledgeArtifactImportResult:
    repository = DatabaseRepository(session)
    _program_or_404_in_scope(repository, request.program_id)
    human_review_approved = request.human_review_approved
    if request.approval_id is not None:
        approval = repository.session.get(ApprovalRecord, request.approval_id)
        if not _approval_allows_knowledge_artifact_import(
            repository,
            approval,
            program_id=request.program_id,
            artifact=request.artifact,
        ):
            return _knowledge_artifact_import_result_with_gate_notes(
                KnowledgeArtifactImportResult(
                    status="blocked_invalid_approval",
                    skipped_count=_knowledge_artifact_entry_count(request.artifact),
                )
            )
        human_review_approved = True
    elif request.human_review_approved:
        return _knowledge_artifact_import_result_with_gate_notes(
            KnowledgeArtifactImportResult(
                status="blocked_invalid_approval",
                skipped_count=_knowledge_artifact_entry_count(request.artifact),
            )
        )

    import_result = build_learning_signals_from_knowledge_artifact(
        program_id=request.program_id,
        artifact=request.artifact,
        human_review_approved=human_review_approved,
        reviewer=request.reviewer,
    )
    if import_result.status != "imported":
        return _knowledge_artifact_import_result_with_gate_notes(import_result)

    saved_signals: list[LearningSignal] = []
    for signal in import_result.learning_signals:
        signal = _knowledge_artifact_signal_with_provenance(
            signal,
            approval_id=request.approval_id,
            artifact_digest=_knowledge_artifact_plan_digest(request.artifact),
        )
        record = _existing_learning_signal_for_outcome(
            repository,
            signal=signal,
            run_record=None,
        )
        if record is None:
            record = repository.save_learning_signal(
                program_id=signal.program_id,
                playbook_id=signal.playbook_id,
                outcome=signal.outcome,
                surface_key=signal.surface_key,
                notes=signal.notes,
                bounty_amount=signal.bounty_amount,
                severity_delta=signal.severity_delta,
                evidence_quality=signal.evidence_quality,
                triager_feedback=signal.triager_feedback,
                target_relationships=signal.target_relationships,
            )
        saved_signals.append(_learning_signal_response(record))

    return _knowledge_artifact_import_result_with_gate_notes(
        KnowledgeArtifactImportResult(
            status="imported",
            imported_count=len(saved_signals),
            skipped_count=import_result.skipped_count,
            learning_signals=saved_signals,
        )
    )


def _approval_allows_knowledge_artifact_import(
    repository: DatabaseRepository,
    approval: ApprovalRecord | None,
    *,
    program_id: str,
    artifact: dict[str, Any],
) -> bool:
    if approval is None:
        return False
    if approval.status != "approved":
        return False
    if not approval_record_is_active(approval):
        return False
    if approval.validation_mode != "v4_advisory_knowledge_import":
        return False
    if approval.plan_digest != _knowledge_artifact_plan_digest(artifact):
        return False
    if approval.program_id is not None:
        return approval.program_id == program_id
    if approval.run_id is None:
        return False
    run = repository.get_pipeline_run(approval.run_id)
    return run is not None and run.program_id == program_id


def _knowledge_artifact_entry_count(artifact: dict[str, Any]) -> int:
    entries = artifact.get("entries")
    return len(entries) if isinstance(entries, list) else 0


def _knowledge_artifact_plan_digest(artifact: dict[str, Any]) -> str:
    encoded = json.dumps(artifact, sort_keys=True, separators=(",", ":"))
    return f"knowledge_artifact:{sha256(encoded.encode('utf-8')).hexdigest()}"


def _knowledge_artifact_signal_with_provenance(
    signal: LearningSignal,
    *,
    approval_id: str | None,
    artifact_digest: str,
) -> LearningSignal:
    provenance_refs = [
        ref
        for ref in (
            "v4_advisory_knowledge",
            f"approval:{approval_id}" if approval_id else None,
            artifact_digest,
        )
        if ref
    ]
    target_relationships = list(signal.target_relationships)
    for ref in provenance_refs:
        if ref not in target_relationships:
            target_relationships.append(ref)
    return signal.model_copy(update={"target_relationships": target_relationships})


def _knowledge_artifact_import_result_with_gate_notes(
    result: KnowledgeArtifactImportResult,
) -> KnowledgeArtifactImportResult:
    safety_notes = list(result.safety_notes)
    for note in (
        "durable_approval_required",
        "approval_artifact_digest_bound",
    ):
        if note not in safety_notes:
            safety_notes.append(note)
    return result.model_copy(update={"safety_notes": safety_notes})


@app.get("/mythos/brain/lessons", response_model=list[MythosLesson])
def list_mythos_brain_lessons(
    program_id: str | None = None,
    scope_type: LessonScopeType | None = None,
    playbook_id: str | None = None,
    surface_pattern: str | None = None,
    recommendation: LessonRecommendation | None = None,
    session: Session = Depends(get_session),
) -> list[MythosLesson]:
    repository = DatabaseRepository(session)
    records = (
        repository.list_learning_signals(program_id)
        if program_id is not None
        else repository.list_all_learning_signals()
    )
    lessons = build_mythos_lessons([_learning_signal_response(record) for record in records])
    return [
        lesson
        for lesson in lessons
        if (scope_type is None or lesson.scope_type == scope_type)
        and (playbook_id is None or lesson.playbook_id == playbook_id)
        and (surface_pattern is None or lesson.surface_pattern == surface_pattern)
        and (recommendation is None or lesson.recommendation == recommendation)
    ]


@app.post("/mythos/brain/outcomes", response_model=ProgramIntelligenceProfile)
def create_mythos_brain_outcome(
    request: LearningOutcomeRequest,
    session: Session = Depends(get_session),
) -> ProgramIntelligenceProfile:
    repository = DatabaseRepository(session)
    run_record = None
    if request.run_id is not None:
        run_record = repository.get_pipeline_run(request.run_id)
        if run_record is None:
            raise HTTPException(status_code=404, detail="Pipeline run not found")
        _raise_if_campaign_scoped_run_not_in_scope(repository, run_record.id)

    program_id = request.program_id or (run_record.program_id if run_record else None)
    if program_id is None:
        raise HTTPException(status_code=422, detail="program_id or run_id is required")
    if run_record is not None and run_record.program_id not in {None, program_id}:
        raise HTTPException(status_code=409, detail="Outcome program does not match run")
    _program_or_404_in_scope(repository, program_id)

    evidence_quality = request.evidence_quality
    if evidence_quality is None and run_record is not None:
        evidence_quality = _evidence_quality_from_reviewed_claims(run_record)

    signal = build_learning_signal_from_outcome(
        program_id=program_id,
        outcome=request.outcome,
        notes=request.notes,
        pipeline_run=_pipeline_run_brain_payload(run_record) if run_record else None,
        playbook_id=request.playbook_id,
        surface_key=request.surface_key,
        bounty_amount=request.bounty_amount,
        severity_delta=request.severity_delta,
        evidence_quality=evidence_quality,
        triager_feedback=request.triager_feedback,
        target_relationships=request.target_relationships,
    )
    signal_record = _existing_learning_signal_for_outcome(
        repository,
        signal=signal,
        run_record=run_record,
    )
    if signal_record is None:
        signal_record = repository.save_learning_signal(
            program_id=signal.program_id,
            playbook_id=signal.playbook_id,
            outcome=signal.outcome,
            surface_key=signal.surface_key,
            notes=signal.notes,
            bounty_amount=signal.bounty_amount,
            severity_delta=signal.severity_delta,
            evidence_quality=signal.evidence_quality,
            triager_feedback=signal.triager_feedback,
            target_relationships=signal.target_relationships,
            reuse_identical=run_record is None,
        )
    if run_record is not None:
        usage_record = _artifact_usage_record_for_learning_signal(
            record=run_record,
            signal=_learning_signal_response(signal_record),
        )
        if usage_record is not None:
            artifact_id, usage = usage_record
            repository.append_artifact_usage_records(
                artifact_id=artifact_id,
                usage_records=[usage],
            )
        _save_campaign_learning_outcome_stage(
            repository=repository,
            run_record=run_record,
            signal=_learning_signal_response(signal_record),
        )
    return _program_intelligence_profile(repository, program_id)


@app.post("/internal/llm/generate", response_model=LLMResponse)
async def generate_with_llm(
    request: LLMRequest,
    session: Session = Depends(get_session),
) -> LLMResponse:
    registry = build_default_registry()
    try:
        response = await registry.generate(request)
    except UnknownProviderError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    DatabaseRepository(session).save_llm_run(
        provider=response.provider,
        model=response.model,
        purpose=request.purpose,
        prompt_hash=response.prompt_hash,
        mode=response.mode,
        latency_ms=response.latency_ms,
        error=response.error,
        safety_notes=_llm_audit_safety_notes(response),
    )
    if response.error:
        raise HTTPException(status_code=503, detail=response.model_dump(mode="json"))
    return response


@app.post("/scope-guard/evaluate", response_model=ScopeGuardDecision)
def evaluate_scope_guard(
    request: ScopeGuardEvaluationRequest,
    session: Session = Depends(get_session),
) -> ScopeGuardDecision:
    repository = DatabaseRepository(session)
    if request.campaign_id is not None:
        campaign = repository.get_campaign(request.campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="Campaign not found")
        if campaign.scope_status != "in_scope":
            return ScopeGuardDecision(
                allowed=False,
                reason="scope_not_in_scope",
            )
    if request.run_id is not None:
        try:
            _raise_if_campaign_scoped_run_not_in_scope(repository, request.run_id)
        except HTTPException as exc:
            if exc.status_code == 409 and exc.detail == "scope_not_in_scope":
                return ScopeGuardDecision(
                    allowed=False,
                    reason="scope_not_in_scope",
                )
            raise

    if request.rule.human_approval_required:
        preflight_request = request.request.model_copy(update={"human_approved": True})
        preflight_decision = evaluate_validation_request(request.rule, preflight_request)
        if not preflight_decision.allowed:
            return preflight_decision

        approval = repository.find_approved_validation_record(
            asset=request.request.asset,
            validation_mode=request.request.validation_type,
            plan_digest=request.request.plan_digest,
            campaign_id=request.campaign_id,
            task_id=request.task_id,
            run_id=request.run_id,
        )
        if approval is None:
            return ScopeGuardDecision(
                allowed=False,
                reason="approval_record_required",
            )
        if approval.program_id is not None:
            program = repository.get_program(approval.program_id)
            if program is None:
                raise HTTPException(status_code=404, detail="Program not found")
            if program.scope_status != "in_scope":
                return ScopeGuardDecision(
                    allowed=False,
                    reason="scope_not_in_scope",
                )
        return ScopeGuardDecision(
            allowed=True,
            reason="approved_validation_record",
        )

    return evaluate_validation_request(request.rule, request.request)


@app.post("/mythos/source-audit/scans", response_model=SourceAuditScanResponse)
def run_mythos_source_audit_scan(
    request: SourceAuditScanRequest,
    session: Session = Depends(get_session),
) -> SourceAuditScanResponse:
    repository = DatabaseRepository(session)
    if request.program_id is not None:
        _program_or_404_in_scope(repository, request.program_id)
    try:
        result = run_source_audit(
            request.repo_path,
            request.scope_path,
            patch_diff_metadata=request.patch_diff_metadata,
        )
    except SourceAuditBlocked as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    record = save_source_audit_pipeline_run(
        repository=repository,
        result=result,
        policy_text=(
            request.policy_text
            if request.policy_text is not None
            else _read_source_audit_policy_text(request.scope_path)
        ),
        program_id=request.program_id,
    )
    preview = build_report_preview_response(record)
    artifact = record.payload.get("artifact") if isinstance(record.payload, dict) else {}
    artifact_id = artifact.get("artifact_id") if isinstance(artifact, dict) else ""
    safety_notes = record.payload.get("safety_notes") if isinstance(record.payload, dict) else []
    safety_gate_summary = (
        record.payload.get("safety_gate_summary")
        if isinstance(record.payload, dict)
        else {}
    )
    timeline_stage_summary = (
        record.payload.get("timeline_stage_summary")
        if isinstance(record.payload, dict)
        else []
    )
    audit_gate_summary = (
        record.payload.get("audit_gate_summary")
        if isinstance(record.payload, dict)
        else {}
    )
    return SourceAuditScanResponse(
        run_id=record.id,
        artifact_id=safe_preview_text(artifact_id),
        report_title=safe_preview_text(record.report_title or preview.title),
        scope_status=safe_preview_text(record.scope_status),
        hypothesis_count=record.hypothesis_count,
        submission_blocked=preview.submission_blocked,
        safety_notes=safe_string_list(safety_notes),
        safety_gate_summary=(
            safety_gate_summary if isinstance(safety_gate_summary, dict) else {}
        ),
        audit_gate_summary=(
            audit_gate_summary if isinstance(audit_gate_summary, dict) else {}
        ),
        timeline_stage_summary=(
            timeline_stage_summary if isinstance(timeline_stage_summary, list) else []
        ),
    )


@app.post("/mythos/pipeline/dry-run", response_model=MythosPipelineDryRunResponse)
def run_mythos_pipeline_dry_run(
    request: MythosPipelineDryRunRequest,
    session: Session = Depends(get_session),
) -> MythosPipelineDryRunResponse:
    repository = DatabaseRepository(session)
    if request.program_id is not None:
        _program_or_404_in_scope(repository, request.program_id)
    try:
        response, payload, openapi_like = build_mythos_pipeline_dry_run(request)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if request.program_id is not None:
        learning_signals = repository.list_learning_signals(request.program_id)
        (
            applied_reasons,
            skipped_reasons,
            lesson_traces,
        ) = _apply_program_learning_to_hunter_intelligence(
            response.hunter_intelligence,
            learning_signals,
        )
        if response.hunter_intelligence is not None:
            _sync_hypothesis_assessment_hunter_scores(response)
            payload["hunter_intelligence"] = response.hunter_intelligence.model_dump(mode="json")
            payload["hypothesis_assessments"] = [
                item.model_dump(mode="json")
                for item in response.hypothesis_assessments
            ]
        if applied_reasons or skipped_reasons:
            learning_stage = _program_learning_stage(
                len(learning_signals),
                applied_reasons or skipped_reasons,
                "completed" if applied_reasons else "skipped",
                lesson_traces,
            )
            response.timeline.append(learning_stage)
            payload["timeline"] = [stage.model_dump(mode="json") for stage in response.timeline]
    artifact_record = repository.save_artifact(
        program_id=request.program_id,
        asset=request.asset,
        kind=response.artifact_kind,
        source_type="dry_run_inline",
        source_hash=artifact_source_hash(request, response.artifact_kind),
        ingestion_status="normalized",
        provenance={
            "source": "dry-run inline artifact",
            "asset": request.asset,
            "kind": response.artifact_kind,
        },
        payload_summary=artifact_payload_summary(openapi_like, response.target_model),
        derived_facts={
            "paths": sorted(openapi_like.get("paths", {}).keys()),
            "objects": [
                item.model_dump(mode="json")
                for item in response.target_model.objects
            ],
            "sensitive_actions": [
                item.model_dump(mode="json")
                for item in response.target_model.sensitive_actions
            ],
            "relationships": [
                item.model_dump(mode="json")
                for item in response.target_model.relationships
            ],
        },
    )
    response.artifact = _pipeline_artifact_summary(
        artifact_record,
        evidence_count=_count_evidence_items(payload),
    )
    payload["artifact"] = response.artifact.model_dump(mode="json")
    record = repository.save_pipeline_run(
        program_id=request.program_id,
        asset=request.asset,
        policy_text=request.policy_text,
        scope_status=response.scope_rule.scope_status,
        hypothesis_count=len(response.hypotheses),
        blocked_count=count_blocked(response.hypothesis_assessments),
        report_title=response.report_draft.title if response.report_draft else None,
        payload=payload,
    )
    repository.append_artifact_usage_records(
        artifact_id=artifact_record.id,
        usage_records=_artifact_usage_records_for_run(record, artifact_record.id),
    )
    response.run_id = record.id
    return response


@app.get("/mythos/pipeline/runs", response_model=list[MythosPipelineRunSummary])
def list_mythos_pipeline_runs(
    session: Session = Depends(get_session),
) -> list[MythosPipelineRunSummary]:
    repository = DatabaseRepository(session)
    return [
        _pipeline_run_summary(record, repository)
        for record in repository.list_pipeline_runs()
    ]


@app.get("/mythos/pipeline/runs/{run_id}", response_model=MythosPipelineRunDetail)
def get_mythos_pipeline_run(
    run_id: str,
    session: Session = Depends(get_session),
) -> MythosPipelineRunDetail:
    repository = DatabaseRepository(session)
    record = repository.get_pipeline_run(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    return _pipeline_run_detail(record, repository)


@app.get(
    "/mythos/pipeline/runs/{run_id}/report-preview",
    response_model=ReportPreviewResponse,
)
def get_mythos_pipeline_report_preview(
    run_id: str,
    session: Session = Depends(get_session),
) -> ReportPreviewResponse:
    record = DatabaseRepository(session).get_pipeline_run(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    return _build_report_preview_response_or_404(record)


@app.post(
    "/mythos/pipeline/runs/{run_id}/claim-review-decisions",
    response_model=ClaimReviewDecisionResponse,
)
def create_claim_review_decision(
    run_id: str,
    request: ClaimReviewDecisionRequest,
    session: Session = Depends(get_session),
) -> ClaimReviewDecisionResponse:
    repository = DatabaseRepository(session)
    record = repository.get_pipeline_run(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    _raise_if_campaign_scoped_run_not_in_scope(repository, record.id)

    preview = _build_report_preview_response_or_404(record)
    claims_by_id = {claim.claim_id: claim for claim in preview.claim_ledger}
    claim = claims_by_id.get(request.claim_id)
    if claim is None:
        raise HTTPException(status_code=404, detail="Claim not found")
    if request.decision == "confirmed_observed_fact" and claim.claim_type != "observed_fact":
        raise HTTPException(status_code=422, detail="Only observed fact claims can be confirmed")
    evidence_refs = safe_preview_lines(request.evidence_refs)
    if request.decision == "confirmed_observed_fact" and not _claim_review_evidence_refs_supported(
        claim,
        evidence_refs,
    ):
        raise HTTPException(status_code=422, detail="Unsupported evidence refs")

    existing_decision = _existing_claim_review_decision(
        record,
        claim_id=request.claim_id,
        decision=request.decision,
        reviewer=request.reviewer,
        evidence_refs=evidence_refs,
    )
    if existing_decision is not None:
        return existing_decision

    decision = ClaimReviewDecisionResponse(
        claim_id=safe_preview_text(request.claim_id),
        decision=request.decision,
        reviewer=safe_preview_text(request.reviewer),
        rationale=safe_preview_text(request.rationale),
        evidence_refs=evidence_refs,
        reviewed_at=datetime.now(UTC).isoformat(),
    )
    updated_record = repository.append_claim_review_decision(
        run_id=run_id,
        decision=decision.model_dump(mode="json"),
        claim_type=claim.claim_type,
        evidence_refs_supported=True,
    )
    if updated_record is None:
        raise HTTPException(status_code=422, detail="Unsupported evidence refs")
    usage_record = _artifact_usage_record_for_claim_review_decision(
        record=updated_record,
        claim=claim,
        decision=decision,
    )
    if usage_record is not None:
        artifact_id, usage = usage_record
        repository.append_artifact_usage_records(
            artifact_id=artifact_id,
            usage_records=[usage],
        )
    return decision


@app.post("/mythos/pipeline/runs/{run_id}/finding-candidates", response_model=Finding)
def create_finding_candidate_from_pipeline_run(
    run_id: str,
    session: Session = Depends(get_session),
) -> Finding:
    repository = DatabaseRepository(session)
    record = repository.get_pipeline_run(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    _raise_if_campaign_scoped_run_not_in_scope(repository, record.id)

    preview = _build_report_preview_response_or_404(record)
    research_feedback_gate = _research_feedback_promotion_gate_for_run(
        repository,
        run_id=record.id,
    )
    if research_feedback_gate is not None:
        _record_research_feedback_promotion_block(
            repository,
            run_id=record.id,
            gate=research_feedback_gate,
        )
        raise HTTPException(status_code=409, detail=research_feedback_gate)
    try:
        finding = promote_pipeline_run_to_finding_candidate(
            repository=repository,
            record=record,
            preview=preview,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if _existing_finding_promotion_stage(repository, record.id, finding.id) is not None:
        return finding
    claim = best_finding_candidate_claim(preview)
    if claim is not None:
        candidate_refs = _candidate_refs_for_finding_promotion(
            record,
            repository,
        )
        manual_observation_refs = _manual_observation_refs_for_finding_promotion(
            record,
            repository,
            claim,
        )
        validation_feedback_refs = _validation_feedback_refs_for_finding_promotion(
            record,
            repository,
        )
        llm_audit = _record_finding_promotion_llm_audit(
            repository=repository,
            record=record,
            claim=claim,
            finding=finding,
        )
        usage_record = _artifact_usage_record_for_finding_candidate(
            record=record,
            claim=claim,
            finding=finding,
            candidate_refs=candidate_refs,
            manual_observation_refs=manual_observation_refs,
            validation_feedback_refs=validation_feedback_refs,
        )
        if usage_record is not None:
            artifact_id, usage = usage_record
            repository.append_artifact_usage_records(
                artifact_id=artifact_id,
                usage_records=[usage],
            )
        _record_finding_promotion_stage(
            repository=repository,
            record=record,
            claim=claim,
            finding=finding,
            candidate_refs=candidate_refs,
            manual_observation_refs=manual_observation_refs,
            validation_feedback_refs=validation_feedback_refs,
            llm_audit=llm_audit,
        )
    return finding


@app.post(
    "/mythos/pipeline/runs/{run_id}/manual-observations",
    response_model=ManualObservationResponse,
)
def create_manual_observation(
    run_id: str,
    request: ManualObservationRequest,
    session: Session = Depends(get_session),
) -> ManualObservationResponse:
    repository = DatabaseRepository(session)
    record = repository.get_pipeline_run(run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    _raise_if_campaign_scoped_run_not_in_scope(repository, record.id)

    preview = _build_report_preview_response_or_404(record)
    claims_by_id = {claim.claim_id: claim for claim in preview.claim_ledger}
    claim = claims_by_id.get(request.claim_id)
    if claim is None:
        raise HTTPException(status_code=404, detail="Claim not found")
    if (
        request.observation_type in SECURITY_IMPACT_OBSERVATION_TYPES
        and claim.claim_type != "observed_fact"
    ):
        raise HTTPException(
            status_code=422,
            detail="Security impact observations require observed fact claims",
        )
    existing_observation = _existing_manual_observation(
        record,
        claim_id=request.claim_id,
        observation_type=request.observation_type,
        observer=request.observer,
        observation=request.observation,
        evidence_refs=request.evidence_refs,
        safety_notes=request.safety_notes,
    )
    if existing_observation is not None:
        return existing_observation

    observation = ManualObservationResponse(
        observation_id=f"manual_observation_{uuid4().hex}",
        claim_id=safe_preview_text(request.claim_id),
        observation_type=request.observation_type,
        observer=safe_preview_text(request.observer),
        observation=safe_preview_text(request.observation),
        evidence_refs=safe_preview_lines(request.evidence_refs),
        safety_notes=safe_preview_lines(request.safety_notes),
        created_at=datetime.now(UTC).isoformat(),
    )
    updated_record = repository.append_manual_observation(
        run_id=run_id,
        observation=observation.model_dump(mode="json"),
        claim_exists=True,
        claim_type=claim.claim_type,
    )
    if updated_record is None:
        raise HTTPException(status_code=422, detail="Unsupported evidence refs")
    usage_record = _artifact_usage_record_for_manual_observation(
        record=updated_record,
        claim=claim,
        observation=observation,
    )
    if usage_record is not None:
        artifact_id, usage = usage_record
        repository.append_artifact_usage_records(
            artifact_id=artifact_id,
            usage_records=[usage],
        )
    return observation


def _pipeline_artifact_summary(
    record: ArtifactRecord,
    *,
    evidence_count: int,
) -> PipelineArtifactSummary:
    source = str(record.provenance.get("source", "dry-run inline artifact"))
    safety = _artifact_safety(record)
    return PipelineArtifactSummary(
        artifact_id=record.id,
        kind=record.kind,
        source_type=record.source_type,
        source=source,
        provenance=f"{source}; source hash recorded for provenance.",
        summary=(
            f"{record.payload_summary.get('path_count', 0)} path(s), "
            f"{record.payload_summary.get('endpoint_count', 0)} endpoint(s)."
        ),
        evidence_count=evidence_count,
        digest=record.source_hash,
        sensitivity_label=safety["sensitivity_label"],
        redaction_status=safety["redaction_status"],
        report_chain_allowed=safety["report_chain_allowed"],
        safety_blockers=safety["safety_blockers"],
    )


def _approval_record_response(record: ApprovalRecord) -> ApprovalRecordResponse:
    return ApprovalRecordResponse(
        id=record.id,
        campaign_id=record.campaign_id,
        task_id=record.task_id,
        run_id=record.run_id,
        program_id=record.program_id,
        approval_type=record.approval_type,
        actor=record.actor,
        reason=record.reason,
        scope_reference=record.scope_reference,
        requested_action=record.requested_action,
        asset=record.asset,
        validation_mode=record.validation_mode,
        plan_digest=record.plan_digest,
        autonomy_level=record.autonomy_level,
        safety_gate_state=record.safety_gate_state,
        status=record.status,
        decision_reason=record.decision_reason,
        decided_by=record.decided_by,
        decided_at=record.decided_at.isoformat() if record.decided_at else None,
        expires_at=record.expires_at.isoformat() if record.expires_at else None,
        created_at=record.created_at.isoformat(),
    )


def _artifact_response(record: ArtifactRecord) -> ArtifactResponse:
    safety = _artifact_safety(record)
    return ArtifactResponse(
        id=record.id,
        program_id=record.program_id,
        asset=record.asset,
        kind=record.kind,
        source_type=record.source_type,
        source_hash=record.source_hash,
        ingestion_status=record.ingestion_status,
        provenance=record.provenance,
        payload_summary=record.payload_summary,
        derived_facts=record.derived_facts,
        sensitivity_label=safety["sensitivity_label"],
        redaction_status=safety["redaction_status"],
        report_chain_allowed=safety["report_chain_allowed"],
        safety_blockers=safety["safety_blockers"],
        usage_records=_artifact_usage_records(record),
        created_at=record.created_at.isoformat(),
    )


def _campaign_response(
    record: CampaignRecord,
    repository: DatabaseRepository,
) -> CampaignResponse:
    return CampaignResponse(
        id=record.id,
        program_id=record.program_id,
        name=record.name,
        status=record.status,
        autonomy_level=record.autonomy_level,
        scope_status=record.scope_status,
        policy_text_hash=record.policy_text_hash,
        default_asset=record.default_asset,
        target_classes=record.target_classes,
        allowed_tools=record.allowed_tools,
        created_by=record.created_by,
        created_at=record.created_at.isoformat(),
        budget=_campaign_budget_response(
            repository.get_campaign_budget(record.id),
            repository=repository,
        ),
    )


def _campaign_control_campaign_response(
    record: CampaignRecord,
) -> CampaignControlCampaignResponse:
    return CampaignControlCampaignResponse(
        id=record.id,
        program_id=record.program_id,
        name=safe_preview_text(record.name),
        status=safe_preview_text(record.status),
        autonomy_level=safe_preview_text(record.autonomy_level),
        scope_status=safe_preview_text(record.scope_status),
        default_asset=safe_preview_text(record.default_asset),
        target_classes=safe_string_list(record.target_classes),
        allowed_tools=safe_string_list(record.allowed_tools),
        created_by=safe_preview_text(record.created_by),
        created_at=record.created_at.isoformat(),
    )


def _campaign_budget_response(
    record: CampaignBudgetRecord | None,
    *,
    repository: DatabaseRepository | None = None,
) -> CampaignBudgetResponse | None:
    if record is None:
        return None
    tool_call_used = (
        _campaign_tool_call_used(record.campaign_id, repository)
        if repository is not None
        else 0
    )
    tool_call_remaining = (
        None
        if record.tool_call_budget is None
        else max(record.tool_call_budget - tool_call_used, 0)
    )
    validation_budget_used = (
        _campaign_validation_budget_used(
            repository.list_campaign_validation_runs(record.campaign_id)
        )
        if repository is not None
        else 0
    )
    validation_budget_remaining = (
        None
        if record.validation_budget is None
        else max(record.validation_budget - validation_budget_used, 0)
    )
    return CampaignBudgetResponse(
        id=record.id,
        campaign_id=record.campaign_id,
        time_budget_minutes=record.time_budget_minutes,
        token_budget=record.token_budget,
        tool_call_budget=record.tool_call_budget,
        tool_call_used=tool_call_used,
        tool_call_remaining=tool_call_remaining,
        validation_budget=record.validation_budget,
        validation_budget_used=validation_budget_used,
        validation_budget_remaining=validation_budget_remaining,
        status=record.status,
        created_at=record.created_at.isoformat(),
    )


def _campaign_tool_call_used(
    campaign_id: str,
    repository: DatabaseRepository,
) -> int:
    return _campaign_tool_call_used_from_runs(
        repository.list_campaign_agent_runs(campaign_id)
    )


def _campaign_tool_call_used_from_runs(
    agent_runs: list[AgentRunRecord],
) -> int:
    return sum(
        1
        for run in agent_runs
        if run.safety_gate_state == "allowed"
    )


def _campaign_task_response(record: CampaignTaskRecord) -> CampaignTaskResponse:
    return CampaignTaskResponse(
        id=record.id,
        campaign_id=record.campaign_id,
        task_type=safe_preview_text(record.task_type),
        agent_type=safe_preview_text(record.agent_type),
        title=safe_preview_text(record.title),
        status=safe_preview_text(record.status),
        input_refs=safe_string_list(record.input_refs),
        output_refs=safe_string_list(record.output_refs),
        created_at=record.created_at.isoformat(),
    )


def _research_task_review_response(
    record: CampaignTaskRecord,
    *,
    repository: DatabaseRepository | None = None,
) -> ResearchTaskReviewResponse:
    payload = record.payload if isinstance(record.payload, dict) else {}
    latest_review_plan = (
        _latest_research_review_plan(repository, record)
        if repository is not None
        else None
    )
    latest_refutation_decision = (
        _latest_research_refutation_decision(repository, record)
        if repository is not None
        else None
    )
    autonomous_candidate_context = (
        _autonomous_candidate_context_response(repository, payload)
        if repository is not None
        else None
    )
    return ResearchTaskReviewResponse(
        task_id=record.id,
        campaign_id=record.campaign_id,
        queue_key=safe_preview_text(payload.get("queue_key", "research_queue")),
        title=safe_preview_text(record.title),
        status=safe_preview_text(record.status),
        source=safe_preview_text(payload.get("source", "mythos_brain_reasoning_memory")),
        playbook_id=(
            safe_preview_text(payload["playbook_id"])
            if isinstance(payload.get("playbook_id"), str)
            else None
        ),
        surface_key=(
            safe_preview_text(payload["surface_key"])
            if isinstance(payload.get("surface_key"), str)
            else None
        ),
        priority_score=_safe_priority_score(payload.get("priority_score")),
        safety_gate="advisory_memory_only",
        next_allowed_action=safe_preview_text(
            payload.get(
                "next_allowed_action",
                "Review hypothesis board and plan non-destructive evidence work.",
            )
        ),
        non_destructive_plan=[
            "Review existing hypothesis board entries for this playbook and surface.",
            "Collect only redacted artifact summaries and provenance counts.",
            "Draft refutation questions before any validation request.",
            "Prepare a human-approved validation plan without executing it.",
        ],
        required_human_gates=[
            "scope_guard_review",
            "redaction_review",
            "approval_required_before_validation",
        ],
        execution_allowed=False,
        dispatch_allowed=False,
        report_submission_allowed=False,
        latest_review_plan=latest_review_plan,
        latest_refutation_decision=latest_refutation_decision,
        suggested_refutation_decision=_suggested_refutation_decision(
            campaign_id=record.campaign_id,
            repository=repository,
            task_payload=payload,
            latest_review_plan=latest_review_plan,
            latest_refutation_decision=latest_refutation_decision,
            autonomous_candidate_context=autonomous_candidate_context,
        ),
        latest_validation_feedback=(
            _latest_research_validation_feedback(repository, record)
            if repository is not None
            else None
        ),
        autonomous_candidate_context=autonomous_candidate_context,
    )


def _research_review_plan_input_refs(
    *,
    campaign_id: str,
    task_id: str,
    queue_key: str,
    task_payload: dict,
) -> list[str]:
    input_refs = [
        f"campaign:{safe_preview_text(campaign_id)}",
        f"campaign_task:{safe_preview_text(task_id)}",
        f"research_queue:{safe_preview_text(queue_key)}",
    ]
    if task_payload.get("source") != "mythos_pipeline_autonomous_hunt_queue":
        return input_refs

    pipeline_run_id = task_payload.get("pipeline_run_id")
    candidate_id = task_payload.get("candidate_id")
    playbook_id = task_payload.get("playbook_id")
    if isinstance(pipeline_run_id, str):
        input_refs.append(f"pipeline_run:{safe_preview_text(pipeline_run_id)}")
    if isinstance(candidate_id, str):
        input_refs.append(f"candidate:{safe_preview_text(candidate_id)}")
    if isinstance(playbook_id, str):
        input_refs.append(f"playbook:{safe_preview_text(playbook_id)}")
    return input_refs


def _suggested_refutation_decision(
    *,
    campaign_id: str,
    repository: DatabaseRepository | None,
    task_payload: dict,
    latest_review_plan: dict | None,
    latest_refutation_decision: dict | None,
    autonomous_candidate_context: AutonomousCandidateContextResponse | None,
) -> SuggestedRefutationDecisionResponse | None:
    if latest_review_plan is None or latest_refutation_decision is not None:
        return None
    if autonomous_candidate_context is None:
        return None

    question_count = len(autonomous_candidate_context.refutation_questions)
    decision: ResearchRefutationDecisionValue = "needs_evidence"
    rationale = "Autonomous candidate needs more redacted evidence before validation review."
    if (
        autonomous_candidate_context.human_approval_required
        and autonomous_candidate_context.validation_steps
    ):
        decision = "needs_validation_review"
        rationale = (
            "Autonomous candidate still has unanswered refutation questions "
            "and a human-gated validation plan."
        )

    validation_mode = _allowed_autonomous_validation_mode(
        campaign_id=campaign_id,
        repository=repository,
        task_payload=task_payload,
    )

    return SuggestedRefutationDecisionResponse(
        decision=decision,
        plan_id=safe_preview_text(latest_review_plan.get("plan_id", "research_plan")),
        rationale=rationale,
        refutation_answer_count=0,
        refutation_question_count=question_count,
        next_allowed_action=_research_refutation_next_allowed_action(decision),
        validation_mode=validation_mode if decision == "needs_validation_review" else None,
        target_ref=f"campaign:{safe_preview_text(campaign_id)}"
        if decision == "needs_validation_review" and validation_mode
        else None,
        human_review_required=True,
        execution_allowed=False,
        dispatch_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
    )


def _allowed_autonomous_validation_mode(
    *,
    campaign_id: str,
    repository: DatabaseRepository | None,
    task_payload: dict,
) -> str | None:
    if repository is None:
        return None
    campaign = repository.get_campaign(campaign_id)
    if campaign is None:
        return None
    assessment = _autonomous_hunt_assessment_for_task_payload(repository, task_payload)
    if assessment is None:
        return None
    hypothesis = assessment.get("hypothesis")
    if not isinstance(hypothesis, dict):
        return None
    validation_mode = safe_preview_text(hypothesis.get("validation_mode", ""))
    if validation_mode in safe_string_list(campaign.allowed_tools):
        return validation_mode
    return None


def _autonomous_hunt_assessment_for_task_payload(
    repository: DatabaseRepository,
    task_payload: dict,
) -> dict | None:
    if task_payload.get("source") != "mythos_pipeline_autonomous_hunt_queue":
        return None
    run_id = task_payload.get("pipeline_run_id")
    candidate_id = task_payload.get("candidate_id")
    if not isinstance(run_id, str) or not isinstance(candidate_id, str):
        return None
    record = repository.get_pipeline_run(run_id)
    if record is None:
        return None
    return _autonomous_hunt_candidate_assessment(record, candidate_id)


def _research_refutation_decision_input_refs(
    *,
    campaign_id: str,
    task_id: str,
    plan_id: str,
    task_payload: dict,
) -> list[str]:
    input_refs = [
        f"campaign:{safe_preview_text(campaign_id)}",
        f"campaign_task:{safe_preview_text(task_id)}",
        f"research_plan:{safe_preview_text(plan_id)}",
    ]
    if task_payload.get("source") != "mythos_pipeline_autonomous_hunt_queue":
        return input_refs

    pipeline_run_id = task_payload.get("pipeline_run_id")
    candidate_id = task_payload.get("candidate_id")
    playbook_id = task_payload.get("playbook_id")
    if isinstance(pipeline_run_id, str):
        input_refs.append(f"pipeline_run:{safe_preview_text(pipeline_run_id)}")
    if isinstance(candidate_id, str):
        input_refs.append(f"candidate:{safe_preview_text(candidate_id)}")
    if isinstance(playbook_id, str):
        input_refs.append(f"playbook:{safe_preview_text(playbook_id)}")
    return input_refs


def _autonomous_research_review_plan_payload(
    repository: DatabaseRepository,
    task_payload: dict,
) -> dict:
    if task_payload.get("source") != "mythos_pipeline_autonomous_hunt_queue":
        return {}

    candidate_summary = _autonomous_candidate_context_summary_for_payload(
        repository,
        task_payload,
    )
    payload: dict = {
        "human_approval_required": _autonomous_human_approval_required(task_payload),
        "blocked_actions": safe_preview_lines(task_payload.get("blocked_actions", [])),
        "safety_notes": safe_preview_lines(task_payload.get("safety_notes", [])),
        "triage_signal_count": len(candidate_summary["triage_signals"]),
        "evidence_focus_count": len(candidate_summary["evidence_focus"]),
        "source_fact_type_count": len(candidate_summary["source_fact_types"]),
        "priority_reason_count": candidate_summary["priority_reason_count"],
        "has_authorization_gap_candidate": candidate_summary[
            "has_authorization_gap_candidate"
        ],
    }
    pipeline_run_id = task_payload.get("pipeline_run_id")
    candidate_id = task_payload.get("candidate_id")
    if isinstance(pipeline_run_id, str):
        payload["pipeline_run_id"] = safe_preview_text(pipeline_run_id)
    if isinstance(candidate_id, str):
        payload["candidate_id"] = safe_preview_text(candidate_id)
    return payload


def _autonomous_candidate_context_response(
    repository: DatabaseRepository,
    payload: dict,
) -> AutonomousCandidateContextResponse | None:
    if payload.get("source") != "mythos_pipeline_autonomous_hunt_queue":
        return None
    run_id = payload.get("pipeline_run_id")
    candidate_id = payload.get("candidate_id")
    if not isinstance(run_id, str) or not isinstance(candidate_id, str):
        return None

    record = repository.get_pipeline_run(run_id)
    if record is None:
        return None
    assessment = _autonomous_hunt_candidate_assessment(record, candidate_id)
    if assessment is None:
        return None

    hypothesis = assessment.get("hypothesis")
    refutation = assessment.get("refutation")
    validation_plan = assessment.get("validation_plan")
    hunter_assessment = assessment.get("hunter_assessment")
    return AutonomousCandidateContextResponse(
        pipeline_run_id=safe_preview_text(run_id),
        candidate_id=safe_preview_text(candidate_id),
        candidate_status=safe_preview_text(assessment.get("candidate_status", "unknown")),
        triage_signals=safe_preview_lines(
            hunter_assessment.get("reasons", [])
            if isinstance(hunter_assessment, dict)
            else []
        ),
        evidence_focus=safe_preview_lines(
            hunter_assessment.get("evidence_focus", [])
            if isinstance(hunter_assessment, dict)
            else []
        ),
        source_fact_types=_autonomous_source_fact_types(hypothesis),
        hypothesis=safe_preview_text(
            hypothesis.get("hypothesis", "Hypothesis summary unavailable.")
            if isinstance(hypothesis, dict)
            else "Hypothesis summary unavailable."
        ),
        refutation_status=safe_preview_text(
            refutation.get("status", "unknown")
            if isinstance(refutation, dict)
            else "unknown"
        ),
        refutation_questions=safe_preview_lines(
            refutation.get("questions", []) if isinstance(refutation, dict) else []
        ),
        validation_plan_status=safe_preview_text(
            validation_plan.get("status", "unknown")
            if isinstance(validation_plan, dict)
            else "unknown"
        ),
        validation_steps=safe_preview_lines(
            validation_plan.get("steps", [])
            if isinstance(validation_plan, dict)
            else []
        ),
        human_approval_required=_autonomous_human_approval_required(payload),
        blocked_actions=safe_preview_lines(payload.get("blocked_actions", [])),
        safety_notes=safe_preview_lines(payload.get("safety_notes", [])),
        execution_allowed=False,
        dispatch_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
    )


def _autonomous_candidate_context_summary_for_payload(
    repository: DatabaseRepository,
    task_payload: dict,
) -> dict:
    triage_signals: list[str] = []
    evidence_focus: list[str] = []
    source_fact_types: list[str] = []

    run_id = task_payload.get("pipeline_run_id")
    candidate_id = task_payload.get("candidate_id")
    if isinstance(run_id, str) and isinstance(candidate_id, str):
        record = repository.get_pipeline_run(run_id)
        if record is not None:
            assessment = _autonomous_hunt_candidate_assessment(record, candidate_id)
            if assessment is not None:
                hunter_assessment = assessment.get("hunter_assessment")
                if isinstance(hunter_assessment, dict):
                    triage_signals = safe_preview_lines(
                        hunter_assessment.get("reasons", [])
                    )
                    evidence_focus = safe_preview_lines(
                        hunter_assessment.get("evidence_focus", [])
                    )
                source_fact_types = _autonomous_source_fact_types(
                    assessment.get("hypothesis")
                )

    has_authorization_gap_candidate = (
        "authorization_gap_candidate" in triage_signals
        or "authorization_gap_candidate" in source_fact_types
    )
    return {
        "triage_signals": triage_signals,
        "evidence_focus": evidence_focus,
        "source_fact_types": source_fact_types,
        "priority_reason_count": _autonomous_priority_reason_count(
            triage_signals,
            evidence_focus,
            source_fact_types,
        ),
        "has_authorization_gap_candidate": has_authorization_gap_candidate,
    }


def _autonomous_priority_reason_count(
    triage_signals: list[str],
    evidence_focus: list[str],
    source_fact_types: list[str],
) -> int:
    combined = {value.strip().lower() for value in [
        *triage_signals,
        *evidence_focus,
        *source_fact_types,
    ]}
    reason_count = 0
    if "authorization_gap_candidate" in combined:
        reason_count += 1
    if combined & {"same_handler_authz_evidence", "same_handler_authorization_evidence"}:
        reason_count += 1
    if combined & {"sensitive_sink", "sensitive_sink_present"}:
        reason_count += 1
    return reason_count


def _autonomous_source_fact_types(hypothesis: object) -> list[str]:
    if not isinstance(hypothesis, dict):
        return []
    facts = hypothesis.get("source_facts")
    if not isinstance(facts, list):
        return []
    fact_types: list[str] = []
    for fact in facts:
        if not isinstance(fact, dict):
            continue
        fact_type = safe_preview_text(fact.get("fact_type", ""))
        if fact_type and fact_type not in fact_types:
            fact_types.append(fact_type)
    return fact_types


def _autonomous_human_approval_required(payload: dict) -> bool:
    if payload.get("source") == "mythos_pipeline_autonomous_hunt_queue":
        return True
    return payload.get("human_approval_required") is not False


def _autonomous_hunt_candidate_assessment(
    record: PipelineRunRecord,
    candidate_id: str,
) -> dict | None:
    assessments = record.payload.get("hypothesis_assessments")
    if not isinstance(assessments, list):
        return None
    safe_candidate_id = safe_preview_text(candidate_id)
    for assessment in assessments:
        if not isinstance(assessment, dict):
            continue
        if safe_preview_text(assessment.get("candidate_id", "")) == safe_candidate_id:
            return assessment
    return None


def _latest_research_review_plan(
    repository: DatabaseRepository,
    task: CampaignTaskRecord,
) -> dict | None:
    stages = [
        stage
        for stage in repository.list_campaign_pipeline_stages(task.campaign_id)
        if stage.task_id == task.id
        and stage.stage_key == "research_task_review_plan"
        and isinstance(stage.payload, dict)
    ]
    if not stages:
        return None
    stage = max(stages, key=lambda record: (record.stage_order, record.created_at, record.id))
    payload = stage.payload
    return ResearchReviewPlanResponse(
        plan_id=safe_preview_text(payload.get("plan_id", "research_plan")),
        task_id=task.id,
        campaign_id=task.campaign_id,
        status=safe_preview_text(stage.status),
        hypothesis=safe_preview_text(payload.get("hypothesis", "Hypothesis redacted")),
        refutation_questions=safe_preview_lines(payload.get("refutation_questions", [])),
        evidence_plan=safe_preview_lines(payload.get("evidence_plan", [])),
        required_human_gates=[
            "scope_guard_review",
            "redaction_review",
            "approval_required_before_validation",
        ],
        safety_gate=safe_preview_text(stage.safety_gate_state),
        next_allowed_action="Review hypothesis board and request approval before validation.",
        execution_allowed=False,
        dispatch_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
    ).model_dump(mode="json")


def _latest_research_refutation_decision(
    repository: DatabaseRepository,
    task: CampaignTaskRecord,
) -> dict | None:
    stages = [
        stage
        for stage in repository.list_campaign_pipeline_stages(task.campaign_id)
        if stage.task_id == task.id
        and stage.stage_key == "research_task_refutation_decision"
        and isinstance(stage.payload, dict)
    ]
    if not stages:
        return None
    stage = max(stages, key=lambda record: (record.stage_order, record.created_at, record.id))
    payload = stage.payload
    decision = safe_preview_text(payload.get("decision", "needs_evidence"))
    if decision not in {
        "refuted",
        "needs_evidence",
        "needs_validation_review",
        "parked_duplicate",
        "policy_blocked",
    }:
        decision = "needs_evidence"
    return ResearchRefutationDecisionResponse(
        decision_id=safe_preview_text(payload.get("decision_id", "refutation_decision")),
        task_id=task.id,
        campaign_id=task.campaign_id,
        plan_id=safe_preview_text(payload.get("plan_id", "research_plan")),
        decision=decision,
        rationale=safe_preview_text(payload.get("rationale", "Refutation review recorded.")),
        refutation_answers=safe_preview_lines(payload.get("refutation_answers", [])),
        next_allowed_action=_research_refutation_next_allowed_action(decision),
        validation_run_id=(
            safe_preview_text(payload.get("validation_run_id"))
            if payload.get("validation_run_id")
            else None
        ),
        approval_id=(
            safe_preview_text(payload.get("approval_id"))
            if payload.get("approval_id")
            else None
        ),
        execution_allowed=False,
        dispatch_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
    ).model_dump(mode="json", exclude_none=True)


def _latest_research_validation_feedback(
    repository: DatabaseRepository,
    task: CampaignTaskRecord,
) -> dict | None:
    stages = [
        stage
        for stage in repository.list_campaign_pipeline_stages(task.campaign_id)
        if stage.task_id == task.id
        and stage.stage_key == "research_task_validation_feedback"
        and isinstance(stage.payload, dict)
    ]
    if not stages:
        return None
    stage = max(stages, key=lambda record: (record.stage_order, record.created_at, record.id))
    payload = stage.payload
    evidence_ref_count = _safe_non_negative_int(payload.get("evidence_ref_count"))
    finding_confirmation_allowed = _research_feedback_stage_has_allow_review(
        repository,
        stage,
    )
    next_allowed_action = (
        "Promote to finding candidate only after explicit human action."
        if finding_confirmation_allowed
        else "Review validation evidence before finding promotion."
    )
    promotion_gate_reason = (
        "validation_feedback_review_allowed_finding_promotion"
        if finding_confirmation_allowed
        else "research_validation_feedback_is_advisory"
    )
    return {
        "campaign_id": task.campaign_id,
        "task_id": task.id,
        "plan_id": safe_preview_text(payload.get("plan_id", "research_plan")),
        "decision_id": safe_preview_text(payload.get("decision_id", "refutation_decision")),
        "approval_id": safe_preview_text(payload.get("approval_id", "approval")),
        "validation_run_id": safe_preview_text(
            payload.get("validation_run_id", "validation_run")
        ),
        "feedback_stage_id": safe_preview_text(stage.id),
        "status": safe_preview_text(stage.status),
        "outcome": safe_preview_text(payload.get("outcome", "needs_more_evidence")),
        "evidence_ref_count": evidence_ref_count,
        "safety_gate": safe_preview_text(stage.safety_gate_state),
        "next_allowed_action": next_allowed_action,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "finding_confirmation_allowed": finding_confirmation_allowed,
        "report_submission_allowed": False,
        "promotion_gate": {
            "status": (
                "manual_review_completed"
                if finding_confirmation_allowed
                else "manual_review_required"
            ),
            "reason": promotion_gate_reason,
            "provenance_refs": safe_preview_lines(stage.input_refs),
            "evidence_ref_count": evidence_ref_count,
            "finding_promotion_allowed": finding_confirmation_allowed,
            "report_submission_allowed": False,
            "next_allowed_action": next_allowed_action,
        },
}


def _safe_non_negative_int(value: Any) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return max(0, value)
    return 0


def _campaign_research_review_plans(
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> list[ResearchReviewPlanResponse]:
    plans: list[ResearchReviewPlanResponse] = []
    seen_task_ids: set[str] = set()
    for stage in repository.list_campaign_pipeline_stages(campaign.id):
        if (
            stage.stage_key != "research_task_review_plan"
            or stage.task_id is None
            or not isinstance(stage.payload, dict)
        ):
            continue
        if stage.task_id in seen_task_ids:
            continue
        task = repository.session.get(CampaignTaskRecord, stage.task_id)
        if task is None or task.campaign_id != campaign.id:
            continue
        plan = _latest_research_review_plan(repository, task)
        if plan is not None:
            plans.append(ResearchReviewPlanResponse(**plan))
            seen_task_ids.add(stage.task_id)
    return plans


def _research_review_plan_response(
    *,
    task: CampaignTaskRecord,
    request: ResearchReviewPlanRequest,
) -> ResearchReviewPlanResponse:
    return ResearchReviewPlanResponse(
        plan_id=f"research_plan_{uuid4().hex}",
        task_id=task.id,
        campaign_id=task.campaign_id,
        status="drafted",
        hypothesis=safe_preview_text(request.hypothesis),
        refutation_questions=safe_preview_lines(request.refutation_questions),
        evidence_plan=safe_preview_lines(request.evidence_plan),
        required_human_gates=[
            "scope_guard_review",
            "redaction_review",
            "approval_required_before_validation",
        ],
        safety_gate="advisory_plan_only",
        next_allowed_action="Review hypothesis board and request approval before validation.",
        execution_allowed=False,
        dispatch_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
    )


def _existing_research_review_plan_for_request(
    repository: DatabaseRepository,
    *,
    task: CampaignTaskRecord,
    request: ResearchReviewPlanRequest,
) -> dict | None:
    latest_plan = _latest_research_review_plan(repository, task)
    if latest_plan is None:
        return None

    latest_stage = next(
        (
            stage
            for stage in repository.list_campaign_pipeline_stages(task.campaign_id)
            if stage.task_id == task.id
            and stage.stage_key == "research_task_review_plan"
            and isinstance(stage.payload, dict)
            and safe_preview_text(stage.payload.get("plan_id", "")) == latest_plan["plan_id"]
        ),
        None,
    )
    if latest_stage is None:
        return None
    payload = latest_stage.payload
    if (
        latest_plan.get("hypothesis") == safe_preview_text(request.hypothesis)
        and latest_plan.get("refutation_questions")
        == safe_preview_lines(request.refutation_questions)
        and latest_plan.get("evidence_plan") == safe_preview_lines(request.evidence_plan)
        and safe_preview_text(payload.get("reviewer", "")) == safe_preview_text(request.reviewer)
        and safe_preview_text(payload.get("rationale", "")) == safe_preview_text(request.rationale)
    ):
        return latest_plan
    return None


def _research_refutation_next_allowed_action(decision: str) -> str:
    action_by_decision = {
        "refuted": "Park this hypothesis and continue reviewing other candidates.",
        "needs_evidence": "Collect redacted evidence or refine the hypothesis before validation.",
        "needs_validation_review": "Prepare a human-approved validation plan without executing it.",
        "parked_duplicate": "Park this hypothesis as a duplicate-risk candidate.",
        "policy_blocked": "Stop this hypothesis unless program scope or policy changes.",
    }
    return action_by_decision.get(
        decision,
        "Collect redacted evidence or refine the hypothesis before validation.",
    )


def _research_refutation_decision_response(
    *,
    task: CampaignTaskRecord,
    request: ResearchRefutationDecisionRequest,
) -> ResearchRefutationDecisionResponse:
    decision = request.decision
    return ResearchRefutationDecisionResponse(
        decision_id=f"refutation_decision_{uuid4().hex}",
        task_id=task.id,
        campaign_id=task.campaign_id,
        plan_id=safe_preview_text(request.plan_id),
        decision=decision,
        rationale=safe_preview_text(request.rationale),
        refutation_answers=safe_preview_lines(request.refutation_answers),
        next_allowed_action=_research_refutation_next_allowed_action(decision),
        execution_allowed=False,
        dispatch_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
    )


def _raise_if_refutation_decision_request_missing_required_gate_fields(
    request: ResearchRefutationDecisionRequest,
) -> None:
    if request.decision != "needs_validation_review":
        return
    if not any(answer.strip() for answer in request.refutation_answers):
        raise HTTPException(status_code=422, detail="refutation_answers_required")
    if not safe_preview_text(request.validation_mode or ""):
        raise HTTPException(status_code=422, detail="validation_mode_required")


def _record_research_validation_feedback_stage(
    repository: DatabaseRepository,
    validation_run: ValidationRunRecord,
    request: ValidationRunManualResultRequest,
) -> None:
    payload = validation_run.payload if isinstance(validation_run.payload, dict) else {}
    if payload.get("source") != "research_task_refutation_decision":
        return
    if validation_run.task_id is None:
        return

    plan_id = safe_preview_text(payload.get("plan_id", ""))
    decision_id = safe_preview_text(payload.get("decision_id", ""))
    approval_id = safe_preview_text(
        validation_run.approval_id or payload.get("approval_record_id", "")
    )
    if not plan_id or not decision_id or not approval_id:
        return

    repository.save_pipeline_stage(
        pipeline_run_id=None,
        campaign_id=validation_run.campaign_id,
        task_id=validation_run.task_id,
        stage_key="research_task_validation_feedback",
        stage_order=len(repository.list_campaign_pipeline_stages(validation_run.campaign_id)),
        status=safe_preview_text(validation_run.status),
        input_refs=[
            f"campaign:{validation_run.campaign_id}",
            f"campaign_task:{validation_run.task_id}",
            f"research_plan:{plan_id}",
            f"refutation_decision:{decision_id}",
            f"approval:{approval_id}",
            f"validation_run:{validation_run.id}",
        ],
        output_refs=[f"validation_run:{validation_run.id}"],
        safety_gate_state="advisory_validation_feedback_only",
        stop_reason=None,
        payload={
            "source": "research_task_refutation_decision",
            "plan_id": plan_id,
            "decision_id": decision_id,
            "approval_id": approval_id,
            "validation_run_id": validation_run.id,
            "outcome": safe_preview_text(request.outcome),
            "evidence_ref_count": validation_run.evidence_ref_count,
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "finding_confirmation_allowed": False,
            "report_submission_allowed": False,
            "raw_payload_processed": False,
        },
    )


def _safe_priority_score(value: Any) -> int:
    score = int(value) if isinstance(value, int | float) else 0
    return max(0, min(100, score))


def _agent_run_response(record: AgentRunRecord) -> AgentRunResponse:
    return AgentRunResponse(
        id=record.id,
        campaign_id=record.campaign_id,
        task_id=record.task_id,
        agent_type=safe_preview_text(record.agent_type),
        status=safe_preview_text(record.status),
        input_refs=safe_string_list(record.input_refs),
        output_refs=safe_string_list(record.output_refs),
        safety_gate_state=safe_preview_text(record.safety_gate_state),
        stop_reason=safe_preview_text(record.stop_reason) if record.stop_reason else None,
        created_at=record.created_at.isoformat(),
        finished_at=record.finished_at.isoformat() if record.finished_at else None,
    )


def _pipeline_stage_response(record: PipelineStageRecord) -> PipelineStageResponse:
    return PipelineStageResponse(
        id=record.id,
        pipeline_run_id=record.pipeline_run_id,
        campaign_id=record.campaign_id,
        task_id=record.task_id,
        stage_key=safe_preview_text(record.stage_key),
        stage_order=record.stage_order,
        status=safe_preview_text(record.status),
        input_refs=safe_string_list(record.input_refs),
        output_refs=safe_string_list(record.output_refs),
        safety_gate_state=safe_preview_text(record.safety_gate_state),
        stop_reason=safe_preview_text(record.stop_reason) if record.stop_reason else None,
        payload=_pipeline_stage_safe_payload(record),
        created_at=record.created_at.isoformat(),
    )


def _pipeline_stage_safe_payload(record: PipelineStageRecord) -> dict:
    payload = record.payload if isinstance(record.payload, dict) else {}
    if record.stage_key == "finding_promotion":
        safe_payload = {
            "claim_provenance_ref_count": len(safe_string_list(payload.get("claim_provenance_refs", []))),
            "candidate_ref_count": len(safe_string_list(payload.get("candidate_refs", []))),
            "finding_promotion_allowed": False,
            "report_submission_allowed": False,
            "review_evidence_ref_count": len(safe_string_list(payload.get("review_evidence_refs", []))),
        }
        validation_feedback_refs = safe_string_list(payload.get("validation_feedback_refs", []))
        if validation_feedback_refs:
            safe_payload["validation_feedback_ref_count"] = len(validation_feedback_refs)
        return safe_payload
    if record.stage_key == "research_queue_materialized":
        return {
            "blocked_action_count": _safe_non_negative_int(payload.get("blocked_action_count")),
            "candidate_id": safe_preview_text(payload.get("candidate_id", "candidate")),
            "candidate_status": safe_preview_text(payload.get("candidate_status", "queued_review")),
            "dispatch_allowed": False,
            "execution_allowed": False,
            "human_approval_required": _autonomous_human_approval_required(payload),
            "playbook_id": safe_preview_text(payload.get("playbook_id", "unknown_playbook")),
            "priority_score": _safe_priority_score(payload.get("priority_score")),
            "queue_key": safe_preview_text(payload.get("queue_key", "research_queue")),
            "raw_payload_processed": False,
            "refutation_question_count": _safe_non_negative_int(payload.get("refutation_question_count")),
            "report_submission_allowed": False,
            "source": safe_preview_text(payload.get("source", "research_queue")),
            "validation_allowed": False,
            "validation_step_count": _safe_non_negative_int(payload.get("validation_step_count")),
        }
    if record.stage_key == "research_task_review_plan":
        return {
            "blocked_action_count": len(safe_string_list(payload.get("blocked_actions", []))),
            "candidate_id": safe_preview_text(payload.get("candidate_id", "candidate")),
            "dispatch_allowed": False,
            "evidence_focus_count": _safe_non_negative_int(payload.get("evidence_focus_count")),
            "evidence_step_count": len(safe_string_list(payload.get("evidence_plan", []))),
            "execution_allowed": False,
            "has_authorization_gap_candidate": payload.get("has_authorization_gap_candidate") is True,
            "human_approval_required": _autonomous_human_approval_required(payload),
            "pipeline_run_id": safe_preview_text(payload.get("pipeline_run_id", "pipeline_run")),
            "priority_reason_count": _safe_non_negative_int(payload.get("priority_reason_count")),
            "raw_payload_processed": False,
            "refutation_question_count": len(safe_string_list(payload.get("refutation_questions", []))),
            "report_submission_allowed": False,
            "source_fact_type_count": _safe_non_negative_int(payload.get("source_fact_type_count")),
            "triage_signal_count": _safe_non_negative_int(payload.get("triage_signal_count")),
            "validation_allowed": False,
        }
    if record.stage_key == "research_task_refutation_decision":
        approval_id = payload.get("approval_id")
        validation_run_id = payload.get("validation_run_id")
        return {
            **(
                {"approval_id": safe_preview_text(approval_id)}
                if isinstance(approval_id, str) and approval_id
                else {}
            ),
            "approval_created": isinstance(approval_id, str) and bool(approval_id),
            "blocked_action_count": len(safe_string_list(payload.get("blocked_actions", []))),
            "candidate_id": safe_preview_text(payload.get("candidate_id", "candidate")),
            "decision": safe_preview_text(payload.get("decision", "needs_evidence")),
            "dispatch_allowed": False,
            "evidence_focus_count": _safe_non_negative_int(payload.get("evidence_focus_count")),
            "execution_allowed": False,
            "has_authorization_gap_candidate": payload.get("has_authorization_gap_candidate") is True,
            "human_approval_required": _autonomous_human_approval_required(payload),
            "pipeline_run_id": safe_preview_text(payload.get("pipeline_run_id", "pipeline_run")),
            "priority_reason_count": _safe_non_negative_int(payload.get("priority_reason_count")),
            "raw_payload_processed": False,
            "refutation_answer_count": len(safe_string_list(payload.get("refutation_answers", []))),
            "report_submission_allowed": False,
            "source_fact_type_count": _safe_non_negative_int(payload.get("source_fact_type_count")),
            "triage_signal_count": _safe_non_negative_int(payload.get("triage_signal_count")),
            "validation_allowed": False,
            "validation_run_created": isinstance(validation_run_id, str) and bool(validation_run_id),
            **(
                {"validation_run_id": safe_preview_text(validation_run_id)}
                if isinstance(validation_run_id, str) and validation_run_id
                else {}
            ),
        }
    if record.stage_key == "research_task_validation_feedback_review":
        return {
            "decision": safe_preview_text(payload.get("decision", "allow_finding_promotion")),
            "execution_allowed": False,
            "finding_confirmation_allowed": payload.get("finding_confirmation_allowed") is True,
            "report_submission_allowed": False,
            "validation_allowed": False,
        }
    if record.stage_key == "validation_manual_result":
        return {
            "outcome": safe_preview_text(payload.get("outcome", "unknown")),
            "reviewer": safe_preview_text(payload.get("reviewer", "reviewer")),
            "evidence_ref_count": _safe_non_negative_int(payload.get("evidence_ref_count")),
            "execution_started": False,
            "validation_result_review": _safe_validation_result_review_payload(
                payload.get("validation_result_review"),
            ),
        }
    return {}


def _validation_result_review_payload(record: ValidationRunRecord) -> dict:
    payload = record.payload if isinstance(record.payload, dict) else {}
    return _safe_validation_result_review_payload(payload.get("validation_result_review"))


def _safe_validation_result_review_payload(value: object) -> dict:
    review = value if isinstance(value, dict) else {}
    return {
        "source_type": safe_preview_text(review.get("source_type", "manual_safe_observation")),
        "redaction_status": safe_preview_text(review.get("redaction_status", "unknown")),
        "evidence_quality": safe_preview_text(review.get("evidence_quality", "weak")),
        "quality_score": _safe_quality_score(review.get("quality_score")),
        "promotion_review_ready": review.get("promotion_review_ready") is True,
        "quality_reasons": safe_preview_lines(review.get("quality_reasons", [])),
        "safe_evidence_ref_count": _safe_non_negative_int(review.get("safe_evidence_ref_count")),
        "unsafe_evidence_ref_count": _safe_non_negative_int(review.get("unsafe_evidence_ref_count")),
    }


def _safe_quality_score(value: object) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return max(0, min(100, value))
    return 0


def _codebase_map_response(record: CodebaseMapRecord) -> CodebaseMapResponse:
    return CodebaseMapResponse(
        id=record.id,
        campaign_id=record.campaign_id,
        source_ref=safe_preview_text(record.source_ref),
        repository=safe_preview_text(record.repository),
        commit_ref=safe_preview_text(record.commit_ref) if record.commit_ref else None,
        status=safe_preview_text(record.status),
        route_count=record.route_count,
        handler_count=record.handler_count,
        model_count=record.model_count,
        authz_check_count=record.authz_check_count,
        sensitive_sink_count=record.sensitive_sink_count,
        provenance_refs=safe_string_list(record.provenance_refs),
        safety_gate_state=safe_preview_text(record.safety_gate_state),
        created_at=record.created_at.isoformat(),
    )


def _codebase_fact_response(record: CodebaseFactRecord) -> CodebaseFactResponse:
    return CodebaseFactResponse(
        id=record.id,
        codebase_map_id=record.codebase_map_id,
        campaign_id=record.campaign_id,
        fact_type=safe_preview_text(record.fact_type),
        source_path=safe_preview_text(record.source_path),
        symbol_name=safe_preview_text(record.symbol_name) if record.symbol_name else None,
        route_method=safe_preview_text(record.route_method) if record.route_method else None,
        route_path=safe_preview_text(record.route_path) if record.route_path else None,
        authz_hint=safe_preview_text(record.authz_hint) if record.authz_hint else None,
        sensitivity_label=safe_preview_text(record.sensitivity_label),
        provenance_refs=safe_string_list(record.provenance_refs),
        created_at=record.created_at.isoformat(),
    )


def _scanner_run_response(record: ScannerRunRecord) -> ScannerRunResponse:
    return ScannerRunResponse(
        id=record.id,
        campaign_id=record.campaign_id,
        codebase_map_id=record.codebase_map_id,
        tool_name=safe_preview_text(record.tool_name),
        command_hash=safe_preview_text(record.command_hash),
        status=safe_preview_text(record.status),
        finding_count=record.finding_count,
        candidate_count=record.candidate_count,
        summary=safe_preview_text(record.summary),
        safety_gate_state=safe_preview_text(record.safety_gate_state),
        created_at=record.created_at.isoformat(),
    )


def _validation_run_response(
    record: ValidationRunRecord,
    *,
    repository: DatabaseRepository | None = None,
) -> ValidationRunResponse:
    allowed_to_execute = _validation_run_currently_allowed_to_execute(
        record,
        repository=repository,
    )
    return ValidationRunResponse(
        id=record.id,
        campaign_id=record.campaign_id,
        task_id=record.task_id,
        approval_id=record.approval_id,
        validation_mode=safe_preview_text(record.validation_mode),
        target_ref=safe_preview_text(record.target_ref),
        status=safe_preview_text(record.status),
        safety_gate_state=safe_preview_text(record.safety_gate_state),
        plan_digest=safe_preview_text(record.plan_digest) if record.plan_digest else None,
        approval_required=bool(record.approval_required),
        allowed_to_execute=allowed_to_execute,
        preflight_passed=(
            record.status == "preflight_passed"
            or record.safety_gate_state == "scope_guard_preflight_passed"
        ),
        execution_started=False,
        evidence_ref_count=record.evidence_ref_count,
        summary=safe_preview_text(record.summary),
        created_at=record.created_at.isoformat(),
        finished_at=record.finished_at.isoformat() if record.finished_at else None,
    )


def _validation_run_currently_allowed_to_execute(
    record: ValidationRunRecord,
    *,
    repository: DatabaseRepository | None,
) -> bool:
    if record.status != "preflight_passed":
        return False
    if not record.allowed_to_execute:
        return False
    if repository is None:
        return False
    campaign = repository.get_campaign(record.campaign_id)
    if campaign is None or campaign.scope_status != "in_scope":
        return False
    if not record.approval_required:
        return True
    if record.approval_id is None:
        return False

    approval = repository.session.get(ApprovalRecord, record.approval_id)
    if approval is None:
        return False

    return _validation_run_approval_matches(
        approval=approval,
        validation_run=record,
        campaign=campaign,
        asset=_validation_run_scope_asset(record, campaign),
    )


def _validation_run_scope_asset(
    record: ValidationRunRecord,
    campaign: CampaignRecord,
) -> str:
    if record.target_ref == f"campaign:{campaign.id}":
        return campaign.default_asset
    return record.target_ref


def _validation_run_approval_matches(
    *,
    approval: ApprovalRecord,
    validation_run: ValidationRunRecord,
    campaign: CampaignRecord,
    asset: str,
) -> bool:
    return (
        approval.status == "approved"
        and approval_record_is_active(approval)
        and approval.campaign_id == campaign.id
        and approval.task_id == validation_run.task_id
        and approval.asset is not None
        and _safe_asset_value(approval.asset) == _safe_asset_value(asset)
        and approval.validation_mode == validation_run.validation_mode
        and approval.plan_digest == validation_run.plan_digest
        and _approval_scope_reference_matches(approval, validation_run)
        and _approval_allowed_accounts_match(approval, validation_run)
    )


def _approval_scope_reference_matches(
    approval: ApprovalRecord,
    validation_run: ValidationRunRecord,
) -> bool:
    if approval.scope_reference is None:
        return True
    payload = validation_run.payload if isinstance(validation_run.payload, dict) else {}
    return payload.get("scope_reference") == approval.scope_reference


def _approval_allowed_accounts_match(
    approval: ApprovalRecord,
    validation_run: ValidationRunRecord,
) -> bool:
    approval_accounts = _payload_string_set(approval.payload, "allowed_accounts")
    if not approval_accounts:
        return True
    validation_accounts = _payload_string_set(validation_run.payload, "allowed_accounts")
    return bool(validation_accounts) and validation_accounts <= approval_accounts


def _approval_validation_budget_exhausted(
    repository: DatabaseRepository,
    *,
    approval: ApprovalRecord,
    validation_run: ValidationRunRecord,
) -> bool:
    validation_budget = _payload_int(approval.payload, "validation_budget")
    if validation_budget is None:
        return False
    used_count = sum(
        1
        for record in repository.list_campaign_validation_runs(validation_run.campaign_id)
        if record.approval_id == approval.id
        and record.id != validation_run.id
        and record.status
        in {
            "ready",
            "preflight_passed",
            "evidence_recorded",
            "refuted",
            "needs_evidence",
        }
    )
    return used_count >= validation_budget


def _payload_string_set(payload: dict, key: str) -> set[str]:
    values = payload.get(key) if isinstance(payload, dict) else None
    if not isinstance(values, list):
        return set()
    return {value for value in values if isinstance(value, str) and value}


def _payload_int(payload: dict, key: str) -> int | None:
    value = payload.get(key) if isinstance(payload, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _campaign_budget_exhausted(budget: CampaignBudgetRecord | None) -> bool:
    if budget is None:
        return False
    return any(
        value is not None and value <= 0
        for value in (
            budget.time_budget_minutes,
            budget.token_budget,
            budget.tool_call_budget,
            budget.validation_budget,
        )
    )


def _campaign_validation_budget_exhausted(
    repository: DatabaseRepository,
    *,
    budget: CampaignBudgetRecord | None,
    validation_run: ValidationRunRecord,
) -> bool:
    if budget is None or budget.validation_budget is None:
        return False
    used_or_reserved = _campaign_validation_budget_used(
        repository.list_campaign_validation_runs(validation_run.campaign_id),
        excluded_validation_run_id=validation_run.id,
    )
    return used_or_reserved >= budget.validation_budget


def _campaign_validation_budget_used(
    validation_runs: list[ValidationRunRecord],
    *,
    excluded_validation_run_id: str | None = None,
) -> int:
    return sum(
        1
        for run in validation_runs
        if run.id != excluded_validation_run_id
        and _validation_run_consumes_campaign_budget(run)
    )


def _validation_run_consumes_campaign_budget(run: ValidationRunRecord) -> bool:
    return (
        run.allowed_to_execute
        or run.status in {"preflight_passed", "evidence_recorded", "refuted", "needs_evidence"}
        or run.evidence_ref_count > 0
        or str(run.safety_gate_state).startswith("manual_")
    )


def _campaign_control_center_blocked_reasons(
    *,
    campaign: CampaignRecord,
    budget: CampaignBudgetRecord | None,
    agent_runs: list[AgentRunRecord],
    validation_runs: list[ValidationRunRecord],
    stages: list[PipelineStageRecord],
) -> list[str]:
    reasons: list[str] = []
    if campaign.scope_status != "in_scope":
        reasons.append("scope_not_in_scope")
    if campaign.status in {"blocked", "canceled", "failed"}:
        reasons.append(f"campaign_{campaign.status}")
    if _campaign_budget_exhausted(budget):
        reasons.append("budget_exhausted")
    if (
        budget is not None
        and budget.tool_call_budget is not None
        and _campaign_tool_call_used_from_runs(agent_runs) >= budget.tool_call_budget
    ):
        reasons.append("budget_exhausted")
    if (
        budget is not None
        and budget.validation_budget is not None
        and _campaign_validation_budget_used(validation_runs) >= budget.validation_budget
    ):
        reasons.append("budget_exhausted")
    for stage in stages:
        if stage.status in {"blocked", "paused"} and stage.stop_reason:
            reasons.append(safe_preview_text(stage.stop_reason))
    return list(dict.fromkeys(reasons))


def _campaign_control_center_safe_next_action(
    *,
    campaign: CampaignRecord,
    budget: CampaignBudgetRecord | None,
    tasks: list[CampaignTaskRecord],
    agent_runs: list[AgentRunRecord],
    approvals: list[ApprovalRecord],
    validation_runs: list[ValidationRunRecord],
    pipeline_stages: list[PipelineStageRecord],
    repository: DatabaseRepository,
    blocked_reasons: list[str],
) -> str:
    if any(
        record.status in {"pending", "requested"} and approval_record_is_active(record)
        for record in approvals
    ):
        return "review_approval_queue"
    if any(
        _validation_run_awaits_approval_review(record, repository=repository)
        for record in validation_runs
    ):
        return "review_validation_queue"
    if "scope_not_in_scope" in blocked_reasons:
        return "resolve_blockers"
    if any(
        _validation_run_awaits_manual_observation(record, repository=repository)
        for record in validation_runs
    ):
        return "record_validation_observation"
    if _campaign_has_reviewed_validation_feedback_for_promotion(pipeline_stages):
        return "promote_finding_candidate"
    if any(_validation_run_has_manual_result(record) for record in validation_runs):
        return "review_evidence_or_report_drafts"
    if _campaign_has_report_preview_learning_signal(pipeline_stages, repository):
        return "review_learning_outcome"
    if _campaign_has_report_preview_finding_candidate(
        pipeline_stages,
        repository,
    ):
        return "record_learning_outcome"
    if _campaign_has_blocked_finding_promotion(pipeline_stages):
        return "review_blocked_promotion"
    if _campaign_has_hypothesis_reasoning_review(
        pipeline_stages,
        repository,
    ):
        return "review_hypothesis_board"
    if _campaign_has_target_model_review(pipeline_stages, repository):
        return "review_attack_surface_map"
    if _campaign_has_awaiting_cycle_review(pipeline_stages):
        return "complete_cycle_review"
    if blocked_reasons:
        return "resolve_blockers"
    if campaign.status != "running":
        return "start_campaign"
    if budget is None:
        return "set_campaign_budget"
    if any(record.status in {"dispatched", "running"} for record in agent_runs):
        return "monitor_agent_runs"
    if any(record.status in {"queued", "queued_review", "ready"} for record in tasks):
        return "review_ready_tasks"
    return "plan_next_tick"


def _campaign_research_queue_suggestions(
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> list[ResearchQueueSuggestionResponse]:
    if campaign.scope_status != "in_scope" or campaign.program_id is None:
        return []

    try:
        profile = _program_intelligence_profile(repository, campaign.program_id)
    except HTTPException:
        return []

    surfaces_by_playbook: dict[str, str] = {}
    for surface in profile.high_value_surfaces:
        for playbook_id in surface.playbooks:
            surfaces_by_playbook.setdefault(playbook_id, surface.surface_key)

    suggestions: list[ResearchQueueSuggestionResponse] = []
    for playbook in profile.reasoning_memory.top_playbooks[:3]:
        playbook_id = safe_preview_text(playbook.playbook_id)
        suggestions.append(
            ResearchQueueSuggestionResponse(
                queue_key=f"reasoning_memory:{playbook_id}",
                title=f"Review {playbook_id} reasoning memory",
                source="mythos_brain_reasoning_memory",
                playbook_id=playbook_id,
                surface_key=surfaces_by_playbook.get(playbook.playbook_id),
                priority_score=playbook.highest_reasoning_review_score,
                safety_gate="advisory_memory_only",
                next_allowed_action=(
                    "Review hypothesis board and plan non-destructive evidence work."
                ),
                execution_allowed=False,
            )
        )
    suggestions.extend(
        _campaign_autonomous_hunt_queue_suggestions(
            campaign=campaign,
            repository=repository,
        )
    )
    return suggestions


def _campaign_autonomous_hunt_queue_suggestions(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> list[ResearchQueueSuggestionResponse]:
    if campaign.program_id is None:
        return []
    for record in repository.list_pipeline_runs_for_program(campaign.program_id):
        if record.scope_status != "in_scope":
            continue
        queue = record.payload.get("autonomous_hunt_queue")
        if not isinstance(queue, list) or not queue:
            continue
        suggestions: list[ResearchQueueSuggestionResponse] = []
        for item in queue[:3]:
            if not isinstance(item, dict):
                continue
            queue_id = safe_preview_text(item.get("queue_id", "hunt_queue"))
            candidate_id = safe_preview_text(item.get("candidate_id", "candidate"))
            suggestions.append(
                ResearchQueueSuggestionResponse(
                    queue_key=f"autonomous_hunt:{record.id}:{queue_id}",
                    title=f"Review autonomous hunt candidate {candidate_id}",
                    source="mythos_pipeline_autonomous_hunt_queue",
                    candidate_status=safe_preview_text(
                        item.get("candidate_status", "awaiting_human_approval")
                    ),
                    human_approval_required=True,
                    refutation_question_count=_autonomous_hunt_assessment_count(
                        record.payload,
                        candidate_id,
                        "refutation",
                        "questions",
                    ),
                    validation_step_count=_autonomous_hunt_assessment_count(
                        record.payload,
                        candidate_id,
                        "validation_plan",
                        "steps",
                    ),
                    blocked_action_count=len(
                        _required_autonomous_blocked_actions(
                            item.get("blocked_actions", [])
                        )
                    ),
                    playbook_id=safe_preview_text(
                        item.get("playbook_id", "unknown_playbook")
                    ),
                    surface_key=None,
                    priority_score=_safe_priority_score(item.get("priority_score")),
                    safety_gate=safe_preview_text(
                        item.get("status", "awaiting_human_approval")
                    ),
                    next_allowed_action="Review validation plan before any execution.",
                    execution_allowed=False,
                )
            )
        return suggestions
    return []


def _autonomous_hunt_assessment_count(
    payload: dict,
    candidate_id: str,
    section_key: str,
    list_key: str,
) -> int:
    assessments = payload.get("hypothesis_assessments")
    if not isinstance(assessments, list):
        return 0
    safe_candidate_id = safe_preview_text(candidate_id)
    for assessment in assessments:
        if not isinstance(assessment, dict):
            continue
        if safe_preview_text(assessment.get("candidate_id", "")) != safe_candidate_id:
            continue
        section = assessment.get(section_key)
        if not isinstance(section, dict):
            return 0
        return len(safe_preview_lines(section.get(list_key, [])))
    return 0


def _campaign_research_queue_suggestion_by_key(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    queue_key: str,
) -> ResearchQueueSuggestionResponse | None:
    safe_queue_key = safe_preview_text(queue_key)
    return next(
        (
            suggestion
            for suggestion in _campaign_research_queue_suggestions(campaign, repository)
            if suggestion.queue_key == safe_queue_key
        ),
        None,
    )


def _research_queue_task_input_refs(
    campaign_id: str,
    suggestion: ResearchQueueSuggestionResponse,
) -> list[str]:
    refs = [
        f"campaign:{safe_preview_text(campaign_id)}",
        f"research_queue:{safe_preview_text(suggestion.queue_key)}",
    ]
    autonomous_context = _autonomous_hunt_queue_context(suggestion.queue_key)
    if suggestion.source == "mythos_pipeline_autonomous_hunt_queue" and autonomous_context:
        run_id, queue_id = autonomous_context
        refs.append(f"pipeline_run:{run_id}")
        refs.append(f"candidate:{_autonomous_candidate_id_from_queue_id(queue_id)}")
    if suggestion.playbook_id:
        refs.append(f"playbook:{safe_preview_text(suggestion.playbook_id)}")
    if suggestion.surface_key:
        refs.append(f"surface:{safe_preview_text(suggestion.surface_key)}")
    return refs


def _record_research_queue_materialized_stage(
    *,
    repository: DatabaseRepository,
    campaign_id: str,
    task: CampaignTaskRecord,
    suggestion: ResearchQueueSuggestionResponse,
    input_refs: list[str],
) -> None:
    pipeline_run_id = None
    if suggestion.source == "mythos_pipeline_autonomous_hunt_queue":
        context = _autonomous_hunt_queue_context(suggestion.queue_key)
        pipeline_run_id = context[0] if context is not None else None
    payload = {
        "source": safe_preview_text(suggestion.source),
        "queue_key": safe_preview_text(suggestion.queue_key),
        "playbook_id": safe_preview_text(suggestion.playbook_id)
        if suggestion.playbook_id
        else None,
        "priority_score": suggestion.priority_score,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "raw_payload_processed": False,
    }
    if suggestion.source == "mythos_pipeline_autonomous_hunt_queue":
        payload.update(
            {
                "candidate_id": safe_preview_text(task.payload.get("candidate_id", ""))
                if isinstance(task.payload, dict)
                else "",
                "candidate_status": safe_preview_text(
                    suggestion.candidate_status or "unknown"
                ),
                "human_approval_required": suggestion.human_approval_required,
                "blocked_action_count": suggestion.blocked_action_count,
                "refutation_question_count": suggestion.refutation_question_count,
                "validation_step_count": suggestion.validation_step_count,
            }
        )
    repository.save_pipeline_stage(
        pipeline_run_id=pipeline_run_id,
        campaign_id=campaign_id,
        task_id=task.id,
        stage_key="research_queue_materialized",
        stage_order=len(repository.list_campaign_pipeline_stages(campaign_id)),
        status=safe_preview_text(task.status),
        input_refs=input_refs,
        output_refs=[f"campaign_task:{safe_preview_text(task.id)}"],
        safety_gate_state=(
            "manual_review_required"
            if suggestion.source == "mythos_pipeline_autonomous_hunt_queue"
            else "advisory_memory_only"
        ),
        stop_reason=None,
        payload=payload,
    )


def _record_autonomous_research_review_plan_draft(
    *,
    repository: DatabaseRepository,
    campaign_id: str,
    task: CampaignTaskRecord,
    task_payload: dict,
) -> None:
    if task_payload.get("source") != "mythos_pipeline_autonomous_hunt_queue":
        return
    if _latest_research_review_plan(repository, task) is not None:
        return

    context = _autonomous_candidate_context_response(repository, task_payload)
    if context is None:
        return

    queue_key = safe_preview_text(task_payload.get("queue_key", "research_queue"))
    plan_id = f"auto_research_plan_{safe_preview_text(task.id)}"
    stage_payload = {
        "plan_id": plan_id,
        "hypothesis": context.hypothesis,
        "refutation_questions": context.refutation_questions,
        "evidence_plan": context.validation_steps,
        "reviewer": "mythos_autonomous_planner",
        "rationale": "Auto-drafted from redacted autonomous candidate context.",
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "raw_payload_processed": False,
    }
    stage_payload.update(_autonomous_research_review_plan_payload(repository, task_payload))

    repository.save_pipeline_stage(
        pipeline_run_id=safe_preview_text(task_payload.get("pipeline_run_id", "")) or None,
        campaign_id=campaign_id,
        task_id=task.id,
        stage_key="research_task_review_plan",
        stage_order=len(repository.list_campaign_pipeline_stages(campaign_id)),
        status="auto_drafted",
        input_refs=_research_review_plan_input_refs(
            campaign_id=campaign_id,
            task_id=task.id,
            queue_key=queue_key,
            task_payload=task_payload,
        ),
        output_refs=[f"research_plan:{plan_id}"],
        safety_gate_state="advisory_plan_only",
        stop_reason=None,
        payload=stage_payload,
    )


def _existing_research_queue_task(
    *,
    repository: DatabaseRepository,
    campaign_id: str,
    queue_key: str,
) -> CampaignTaskRecord | None:
    queue_ref = f"research_queue:{safe_preview_text(queue_key)}"
    for task in repository.list_campaign_tasks(campaign_id):
        if task.task_type == "research_queue_review" and queue_ref in task.input_refs:
            return task
    return None


def _autonomous_hunt_queue_context(queue_key: str) -> tuple[str, str] | None:
    parts = safe_preview_text(queue_key).split(":", 2)
    if len(parts) != 3 or parts[0] != "autonomous_hunt":
        return None
    return safe_preview_text(parts[1]), safe_preview_text(parts[2])


def _autonomous_candidate_id_from_queue_id(queue_id: str) -> str:
    safe_queue_id = safe_preview_text(queue_id)
    return safe_queue_id.removeprefix("hunt_queue_")


def _autonomous_hunt_queue_task_metadata(
    *,
    repository: DatabaseRepository,
    queue_key: str,
) -> dict:
    context = _autonomous_hunt_queue_context(queue_key)
    if context is None:
        return {
            "human_approval_required": True,
            "blocked_actions": [
                "execute_live_validation",
                "touch_real_user_data",
                "submit_report",
                "bypass_scope_guard",
            ],
            "safety_notes": [
                "scope_guard_required",
                "non_destructive_validation_only",
                "human_review_required",
            ],
        }

    run_id, queue_id = context
    metadata = {
        "pipeline_run_id": run_id,
        "candidate_id": _autonomous_candidate_id_from_queue_id(queue_id),
        "human_approval_required": True,
        "blocked_actions": [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
            "bypass_scope_guard",
        ],
        "safety_notes": [
            "scope_guard_required",
            "non_destructive_validation_only",
            "human_review_required",
        ],
    }
    record = repository.get_pipeline_run(run_id)
    if record is None:
        return metadata
    queue = record.payload.get("autonomous_hunt_queue")
    if not isinstance(queue, list):
        return metadata
    for item in queue:
        if not isinstance(item, dict):
            continue
        if safe_preview_text(item.get("queue_id", "")) != queue_id:
            continue
        metadata["candidate_id"] = safe_preview_text(
            item.get("candidate_id", metadata["candidate_id"])
        )
        metadata["human_approval_required"] = True
        metadata["blocked_actions"] = _required_autonomous_blocked_actions(
            item.get("blocked_actions", [])
        )
        metadata["safety_notes"] = _required_autonomous_safety_notes(
            item.get("safety_notes", [])
        )
        assessment = _autonomous_hunt_candidate_assessment(record, metadata["candidate_id"])
        hypothesis = assessment.get("hypothesis") if isinstance(assessment, dict) else None
        if isinstance(hypothesis, dict):
            metadata["validation_mode"] = safe_preview_text(
                hypothesis.get("validation_mode", "")
            )
        return metadata
    return metadata


def _required_autonomous_blocked_actions(values: object) -> list[str]:
    actions = safe_preview_lines(values)
    for required in (
        "execute_live_validation",
        "touch_real_user_data",
        "submit_report",
        "bypass_scope_guard",
    ):
        if required not in actions:
            actions.append(required)
    return actions


def _required_autonomous_safety_notes(values: object) -> list[str]:
    notes = safe_preview_lines(values)
    for required in (
        "scope_guard_required",
        "non_destructive_validation_only",
        "human_review_required",
    ):
        if required not in notes:
            notes.append(required)
    return notes


def _campaign_has_report_preview_finding_candidate(
    pipeline_stages: list[PipelineStageRecord],
    repository: DatabaseRepository,
) -> bool:
    pipeline_run_ids = [
        stage.pipeline_run_id
        for stage in pipeline_stages
        if stage.stage_key == "campaign_report_preview" and stage.pipeline_run_id
    ]
    for run_id in pipeline_run_ids:
        record = repository.get_pipeline_run(run_id)
        if record is None:
            continue
        usage_records = _closed_loop_artifact_usage_records(record, repository)
        if _closed_loop_usage_count(usage_records, "finding_candidate", record.id):
            return True
    return False


def _campaign_has_hypothesis_reasoning_review(
    pipeline_stages: list[PipelineStageRecord],
    repository: DatabaseRepository,
) -> bool:
    pipeline_run_ids = [
        stage.pipeline_run_id
        for stage in pipeline_stages
        if stage.stage_key == "campaign_report_preview" and stage.pipeline_run_id
    ]
    for run_id in pipeline_run_ids:
        record = repository.get_pipeline_run(run_id)
        if record is None:
            continue
        assessments = record.payload.get("hypothesis_assessments", [])
        if not isinstance(assessments, list):
            continue
        for assessment in assessments:
            if not isinstance(assessment, dict):
                continue
            exploit_chain = assessment.get("exploit_chain")
            refutation = assessment.get("refutation")
            has_chain = isinstance(exploit_chain, dict) and bool(
                exploit_chain.get("primitives")
            )
            has_refutation_questions = isinstance(refutation, dict) and bool(
                refutation.get("questions")
            )
            if has_chain or has_refutation_questions:
                return True
    return False


def _campaign_has_target_model_review(
    pipeline_stages: list[PipelineStageRecord],
    repository: DatabaseRepository,
) -> bool:
    pipeline_run_ids = list(
        dict.fromkeys(
            stage.pipeline_run_id
            for stage in pipeline_stages
            if stage.pipeline_run_id
        )
    )
    for run_id in pipeline_run_ids:
        record = repository.get_pipeline_run(run_id)
        if record is None:
            continue
        target_model = record.payload.get("target_model")
        if not isinstance(target_model, dict):
            continue
        if any(
            isinstance(target_model.get(key), list) and bool(target_model.get(key))
            for key in ("endpoints", "objects", "roles", "sensitive_actions", "relationships")
        ):
            return True
    return False


def _campaign_has_awaiting_cycle_review(
    pipeline_stages: list[PipelineStageRecord],
) -> bool:
    completed_reviews = {
        _cycle_review_signature(stage)
        for stage in pipeline_stages
        if stage.stage_key == "campaign_cycle_review"
        and stage.status == "completed"
        and stage.safety_gate_state == "allowed"
    }
    return any(
        stage.stage_key == "campaign_cycle_review"
        and stage.status == "awaiting_review"
        and _cycle_review_signature(stage) not in completed_reviews
        for stage in pipeline_stages
    )


def _campaign_has_blocked_finding_promotion(
    pipeline_stages: list[PipelineStageRecord],
) -> bool:
    return any(
        stage.stage_key == "finding_promotion_blocked"
        and stage.status == "blocked"
        and stage.stop_reason == "blocked_by_research_feedback_gate"
        for stage in pipeline_stages
    )


def _campaign_has_reviewed_validation_feedback_for_promotion(
    pipeline_stages: list[PipelineStageRecord],
) -> bool:
    return _campaign_promotion_review_summary(pipeline_stages).finding_promotion_allowed


def _campaign_promotion_review_summary(
    pipeline_stages: list[PipelineStageRecord],
) -> CampaignPromotionReviewSummary:
    allow_review_stages = []
    reviewed_feedback_stage_ids = set()
    feedback_stage_ids = {
        stage.id
        for stage in pipeline_stages
        if stage.stage_key == "research_task_validation_feedback"
    }
    for stage in pipeline_stages:
        payload = stage.payload if isinstance(stage.payload, dict) else {}
        reviewed_stage_id = payload.get("reviewed_stage_id")
        if (
            stage.stage_key == "research_task_validation_feedback_review"
            and isinstance(reviewed_stage_id, str)
            and reviewed_stage_id in feedback_stage_ids
            and payload.get("decision") == "allow_finding_promotion"
            and payload.get("finding_confirmation_allowed") is True
        ):
            allow_review_stages.append(stage)
            reviewed_feedback_stage_ids.add(reviewed_stage_id)

    blocked_stages = [
        stage
        for stage in pipeline_stages
        if stage.stage_key == "finding_promotion_blocked"
        and stage.status == "blocked"
        and stage.stop_reason == "blocked_by_research_feedback_gate"
    ]
    if not blocked_stages:
        if allow_review_stages:
            reviewed_feedback_stages = [
                stage
                for stage in pipeline_stages
                if stage.stage_key == "research_task_validation_feedback"
                and stage.id in reviewed_feedback_stage_ids
            ]
            provenance_refs = {
                safe_preview_text(ref)
                for stage in reviewed_feedback_stages
                for ref in (stage.input_refs or [])
                if safe_preview_text(ref) != "[REDACTED]"
            }
            return CampaignPromotionReviewSummary(
                finding_promotion_allowed=True,
                latest_reason="validation_feedback_review_allowed_finding_promotion",
                next_allowed_action="Promote to finding candidate only after explicit human action.",
                provenance_ref_count=len(provenance_refs),
                validation_feedback_review_count=len(allow_review_stages),
            )

        research_feedback_stages = [
            stage
            for stage in pipeline_stages
            if stage.stage_key == "research_task_validation_feedback"
            and _research_feedback_stage_blocks_promotion(stage)
        ]
        if not research_feedback_stages:
            return CampaignPromotionReviewSummary()

        provenance_refs = {
            safe_preview_text(ref)
            for stage in research_feedback_stages
            for ref in (stage.input_refs or [])
            if safe_preview_text(ref) != "[REDACTED]"
        }
        return CampaignPromotionReviewSummary(
            latest_reason="research_validation_feedback_is_advisory",
            next_allowed_action="Review validation feedback before candidate promotion.",
            provenance_ref_count=len(provenance_refs),
        )

    latest_stage = blocked_stages[-1]
    provenance_ref_count = _payload_int(
        latest_stage.payload,
        "provenance_ref_count",
    )

    return CampaignPromotionReviewSummary(
        blocked_attempt_count=len(blocked_stages),
        latest_reason=(
            safe_preview_text(latest_stage.stop_reason)
            if latest_stage.stop_reason
            else "blocked_by_research_feedback_gate"
        ),
        next_allowed_action="Review blocked promotion evidence before retrying candidate promotion.",
        provenance_ref_count=provenance_ref_count or 0,
        validation_feedback_review_count=len(allow_review_stages),
    )


def _cycle_review_signature(stage: PipelineStageRecord) -> tuple:
    return (
        stage.stage_order,
        stage.task_id,
        tuple(stage.input_refs or []),
        tuple(stage.output_refs or []),
    )


def _cycle_review_unresolved_gate_refs(
    repository: DatabaseRepository,
    stage: PipelineStageRecord,
) -> list[str]:
    unresolved_refs: list[str] = []
    for ref in stage.output_refs or []:
        if ref.startswith("approval:"):
            approval = repository.session.get(ApprovalRecord, ref.removeprefix("approval:"))
            if (
                approval is not None
                and approval.campaign_id == stage.campaign_id
                and approval.status in {"pending", "requested"}
                and approval_record_is_active(approval)
            ):
                unresolved_refs.append(ref)
        elif ref.startswith("validation_run:"):
            validation_run = repository.get_validation_run(
                ref.removeprefix("validation_run:")
            )
            if (
                validation_run is not None
                and validation_run.campaign_id == stage.campaign_id
                and _validation_run_awaits_approval_review(
                    validation_run,
                    repository=repository,
                )
            ):
                unresolved_refs.append(ref)
    return unresolved_refs


def _validation_run_awaits_approval_review(
    record: ValidationRunRecord,
    *,
    repository: DatabaseRepository | None = None,
) -> bool:
    currently_allowed = (
        _validation_run_currently_allowed_to_execute(record, repository=repository)
        if repository is not None
        else record.allowed_to_execute
    )
    return (
        record.approval_required
        and not currently_allowed
        and (
            record.status in {"awaiting_approval", "ready", "preflight_passed"}
            or record.safety_gate_state
            in {
                "awaiting_approval",
                "approved_validation_record",
                "scope_guard_preflight_passed",
            }
        )
    )


def _campaign_has_report_preview_learning_signal(
    pipeline_stages: list[PipelineStageRecord],
    repository: DatabaseRepository,
) -> bool:
    pipeline_run_ids = [
        stage.pipeline_run_id
        for stage in pipeline_stages
        if stage.stage_key == "campaign_report_preview" and stage.pipeline_run_id
    ]
    for run_id in pipeline_run_ids:
        record = repository.get_pipeline_run(run_id)
        if record is None:
            continue
        usage_records = _closed_loop_artifact_usage_records(record, repository)
        if _campaign_has_learning_outcome_audit_stage(
            pipeline_stages,
            run_id=record.id,
            usage_records=usage_records,
        ):
            return True
    return False


def _campaign_has_learning_outcome_audit_stage(
    pipeline_stages: list[PipelineStageRecord],
    *,
    run_id: str,
    usage_records: list[dict],
) -> bool:
    signal_refs = {
        f"learning_signal:{safe_preview_text(usage.get('learning_signal_id', ''))}"
        for usage in usage_records
        if usage.get("usage_type") == "learning_signal"
        and usage.get("run_id") == run_id
        and safe_preview_text(usage.get("learning_signal_id", "")) != "[REDACTED]"
    }
    if not signal_refs:
        return False

    return any(
        stage.pipeline_run_id == run_id
        and stage.stage_key == "learning_outcome_recorded"
        and stage.status == "recorded"
        and stage.safety_gate_state == "advisory_memory_only"
        and any(ref in safe_string_list(stage.output_refs) for ref in signal_refs)
        for stage in pipeline_stages
    )


def _validation_run_has_manual_result(record: ValidationRunRecord) -> bool:
    return isinstance(record.payload, dict) and isinstance(
        record.payload.get("manual_result"),
        dict,
    )


def _validation_run_awaits_manual_observation(
    record: ValidationRunRecord,
    *,
    repository: DatabaseRepository,
) -> bool:
    return (
        not _validation_run_has_manual_result(record)
        and _validation_run_currently_allowed_to_execute(
            record,
            repository=repository,
        )
    )


def _validation_run_campaign_or_404_in_scope(
    repository: DatabaseRepository,
    validation_run: ValidationRunRecord,
) -> CampaignRecord:
    campaign = repository.get_campaign(validation_run.campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.scope_status != "in_scope":
        raise HTTPException(status_code=409, detail="scope_not_in_scope")
    return campaign


def _raise_if_validation_run_approval_not_active(
    *,
    repository: DatabaseRepository,
    validation_run: ValidationRunRecord,
    campaign: CampaignRecord,
) -> None:
    if not validation_run.approval_required:
        return
    approval = (
        repository.session.get(ApprovalRecord, validation_run.approval_id)
        if validation_run.approval_id
        else None
    )
    if approval is None or not _validation_run_approval_matches(
        approval=approval,
        validation_run=validation_run,
        campaign=campaign,
        asset=_validation_run_scope_asset(validation_run, campaign),
    ):
        raise HTTPException(
            status_code=409,
            detail="Validation run approval is not active",
        )


def _validation_run_manual_result_matches(
    record: ValidationRunRecord,
    request: ValidationRunManualResultRequest,
) -> bool:
    if not isinstance(record.payload, dict):
        return False
    manual_result = record.payload.get("manual_result")
    if not isinstance(manual_result, dict):
        return False
    return (
        safe_preview_text(manual_result.get("outcome", "")) == request.outcome
        and safe_preview_text(manual_result.get("reviewer", ""))
        == safe_preview_text(request.reviewer)
        and safe_preview_text(manual_result.get("summary", ""))
        == safe_preview_text(request.summary)
        and safe_preview_lines(manual_result.get("evidence_refs", []))
        == safe_preview_lines(request.evidence_refs)
    )


def _update_campaign_status(
    campaign_id: str,
    status: str,
    session: Session,
) -> CampaignResponse:
    repository = DatabaseRepository(session)
    campaign = repository.update_campaign_status(campaign_id, status)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    return _campaign_response(campaign, repository)


def _artifact_safety(record: ArtifactRecord) -> dict:
    safety = record.provenance.get("safety")
    if not isinstance(safety, dict):
        return {
            "sensitivity_label": "unknown",
            "redaction_status": "unknown",
            "report_chain_allowed": False,
            "safety_blockers": ["missing_safety_metadata"],
        }

    blockers = safety.get("safety_blockers", [])
    return {
        "sensitivity_label": safe_preview_text(safety.get("sensitivity_label", "unknown")),
        "redaction_status": safe_preview_text(safety.get("redaction_status", "unknown")),
        "report_chain_allowed": safety.get("report_chain_allowed") is True,
        "safety_blockers": _artifact_safety_blockers(blockers),
    }


def _artifact_safety_blockers(value: object) -> list[str]:
    if not isinstance(value, list):
        return []

    known_blockers = {
        "contains_secret_like_value",
        "contains_real_user_data_risk",
        "missing_safety_metadata",
    }
    blockers: list[str] = []
    for item in value:
        blocker = str(item)
        blockers.append(blocker if blocker in known_blockers else safe_preview_text(blocker))
    return blockers


def _artifact_usage_records(record: ArtifactRecord) -> list[dict]:
    usage_records = record.provenance.get("usage_records", [])
    if not isinstance(usage_records, list):
        return []
    return [usage_record for usage_record in usage_records if isinstance(usage_record, dict)]


def _artifact_usage_records_for_run(
    record: PipelineRunRecord,
    artifact_id: str,
) -> list[dict]:
    usage_records = [
        {
            "usage_type": "pipeline_run",
            "ref": f"run:{record.id}",
            "run_id": record.id,
            "stage": "pipeline_persistence",
        }
    ]

    evidence_bundle = record.payload.get("evidence_bundle")
    evidence_items = evidence_bundle.get("items", []) if isinstance(evidence_bundle, dict) else []
    for index, item in enumerate(evidence_items, start=1):
        if not isinstance(item, dict):
            continue
        evidence_type = safe_preview_text(item.get("type", "evidence_item"))
        usage_records.append(
            {
                "usage_type": "evidence_bundle",
                "ref": f"evidence:{record.id}:{index}",
                "run_id": record.id,
                "stage": "evidence_model",
                "evidence_type": evidence_type,
            }
        )

    hypothesis_assessments = record.payload.get("hypothesis_assessments", [])
    if isinstance(hypothesis_assessments, list):
        for index, assessment in enumerate(hypothesis_assessments, start=1):
            if not isinstance(assessment, dict):
                continue
            hypothesis = assessment.get("hypothesis")
            hunter_assessment = assessment.get("hunter_assessment")
            refutation = assessment.get("refutation")
            exploit_chain = assessment.get("exploit_chain")
            chain_primitive_count = _safe_count(
                exploit_chain.get("primitives") if isinstance(exploit_chain, dict) else []
            )
            chain_precondition_count = _safe_count(
                exploit_chain.get("preconditions") if isinstance(exploit_chain, dict) else []
            )
            refutation_question_count = _safe_count(
                refutation.get("questions") if isinstance(refutation, dict) else []
            )
            hunter_priority_score = (
                hunter_assessment.get("hunter_priority_score")
                if isinstance(hunter_assessment, dict)
                else None
            )
            candidate_id = safe_preview_text(
                assessment.get("candidate_id", f"hypothesis_{index}")
            )
            usage_records.append(
                {
                    "usage_type": "hypothesis_candidate",
                    "ref": f"candidate:{record.id}:{candidate_id}",
                    "run_id": record.id,
                    "stage": "hypothesis_lifecycle",
                    "candidate_id": candidate_id,
                    "candidate_index": index - 1,
                    "candidate_status": safe_preview_text(
                        assessment.get("candidate_status", "unknown")
                    ),
                    "validation_mode": safe_preview_text(
                        hypothesis.get("validation_mode", "unknown")
                        if isinstance(hypothesis, dict)
                        else "unknown"
                    ),
                    "refutation_status": safe_preview_text(
                        refutation.get("status", "unknown")
                        if isinstance(refutation, dict)
                        else "unknown"
                    ),
                    "playbook_id": safe_preview_text(
                        hunter_assessment.get("playbook_id", "unknown")
                        if isinstance(hunter_assessment, dict)
                        else "unknown"
                    ),
                    "hunter_priority_score": hunter_priority_score,
                    "chain_primitive_count": chain_primitive_count,
                    "chain_precondition_count": chain_precondition_count,
                    "refutation_question_count": refutation_question_count,
                    "reasoning_review_score": _reasoning_review_score(
                        hunter_priority_score,
                        chain_primitive_count,
                        chain_precondition_count,
                        refutation_question_count,
                    ),
                }
            )

    try:
        preview = build_report_preview_response(record)
    except ValueError:
        return usage_records
    for claim in preview.claim_ledger:
        if artifact_id not in claim.provenance_refs:
            continue
        usage_records.append(
            {
                "usage_type": "report_claim",
                "ref": f"claim:{claim.claim_id}",
                "run_id": record.id,
                "stage": "report_preview",
                "claim_id": claim.claim_id,
                "claim_type": claim.claim_type,
            }
        )
    return usage_records


def _safe_count(value: Any) -> int:
    return len(value) if isinstance(value, list) else 0


def _reasoning_review_score(
    hunter_priority_score: Any,
    chain_primitive_count: int,
    chain_precondition_count: int,
    refutation_question_count: int,
) -> int:
    hunter_score = (
        int(hunter_priority_score)
        if isinstance(hunter_priority_score, int | float)
        else 0
    )
    score = (
        hunter_score
        + chain_primitive_count * 2
        + chain_precondition_count
        + refutation_question_count * 2
    )
    return max(0, min(100, score))


def _artifact_usage_record_for_manual_observation(
    *,
    record: PipelineRunRecord,
    claim: ClaimLedgerEntry,
    observation: ManualObservationResponse,
) -> tuple[str, dict] | None:
    artifact = record.payload.get("artifact")
    if not isinstance(artifact, dict):
        return None

    artifact_id = artifact.get("artifact_id")
    if not artifact_id or str(artifact_id) not in claim.provenance_refs:
        return None

    return str(artifact_id), {
        "usage_type": "manual_observation",
        "ref": f"manual_observation:{observation.observation_id}",
        "run_id": record.id,
        "stage": "validation_workspace",
        "claim_id": observation.claim_id,
        "observation_id": observation.observation_id,
        "observation_type": observation.observation_type,
        "evidence_refs": observation.evidence_refs,
        "safety_notes": observation.safety_notes,
    }


def _artifact_usage_record_for_claim_review_decision(
    *,
    record: PipelineRunRecord,
    claim: ClaimLedgerEntry,
    decision: ClaimReviewDecisionResponse,
) -> tuple[str, dict] | None:
    artifact = record.payload.get("artifact")
    if not isinstance(artifact, dict):
        return None

    artifact_id = artifact.get("artifact_id")
    if not artifact_id or str(artifact_id) not in claim.provenance_refs:
        return None

    return str(artifact_id), {
        "usage_type": "claim_review_decision",
        "ref": f"claim_review:{decision.claim_id}",
        "run_id": record.id,
        "stage": "report_review",
        "claim_id": decision.claim_id,
        "decision": decision.decision,
        "reviewer": decision.reviewer,
        "reviewed_at": decision.reviewed_at,
        "evidence_refs": decision.evidence_refs,
    }


def _existing_manual_observation(
    record: PipelineRunRecord,
    *,
    claim_id: str,
    observation_type: ManualObservationType,
    observer: str,
    observation: str,
    evidence_refs: list[str],
    safety_notes: list[str],
) -> ManualObservationResponse | None:
    observations = record.payload.get("manual_observations", [])
    if not isinstance(observations, list):
        return None

    safe_claim_id = safe_preview_text(claim_id)
    safe_observer = safe_preview_text(observer)
    safe_observation = safe_preview_text(observation)
    safe_evidence_refs = safe_preview_lines(evidence_refs)
    safe_safety_notes = safe_preview_lines(safety_notes)
    for item in observations:
        if not isinstance(item, dict):
            continue
        if (
            safe_preview_text(item.get("claim_id", "")) == safe_claim_id
            and item.get("observation_type") == observation_type
            and safe_preview_text(item.get("observer", "")) == safe_observer
            and safe_preview_text(item.get("observation", "")) == safe_observation
            and safe_preview_lines(item.get("evidence_refs", [])) == safe_evidence_refs
            and safe_preview_lines(item.get("safety_notes", [])) == safe_safety_notes
        ):
            try:
                return ManualObservationResponse(
                    observation_id=safe_preview_text(item.get("observation_id", "")),
                    claim_id=safe_claim_id,
                    observation_type=observation_type,
                    observer=safe_observer,
                    observation=safe_observation,
                    evidence_refs=safe_evidence_refs,
                    safety_notes=safe_safety_notes,
                    redaction_status=safe_preview_text(
                        item.get("redaction_status", "redacted")
                    ),
                    execution_allowed=False,
                    report_chain_blocked=True,
                    created_at=safe_preview_text(item.get("created_at", "")),
                )
            except ValueError:
                return None
    return None


def _existing_claim_review_decision(
    record: PipelineRunRecord,
    *,
    claim_id: str,
    decision: ClaimReviewDecisionValue,
    reviewer: str,
    evidence_refs: list[str],
) -> ClaimReviewDecisionResponse | None:
    decisions = record.payload.get("claim_review_decisions", [])
    if not isinstance(decisions, list):
        return None

    safe_claim_id = safe_preview_text(claim_id)
    safe_reviewer = safe_preview_text(reviewer)
    safe_evidence_refs = safe_preview_lines(evidence_refs)
    for item in decisions:
        if not isinstance(item, dict):
            continue
        if (
            safe_preview_text(item.get("claim_id", "")) == safe_claim_id
            and item.get("decision") == decision
            and safe_preview_text(item.get("reviewer", "")) == safe_reviewer
            and safe_preview_lines(item.get("evidence_refs", [])) == safe_evidence_refs
        ):
            try:
                return ClaimReviewDecisionResponse(
                    claim_id=safe_claim_id,
                    decision=decision,
                    reviewer=safe_reviewer,
                    rationale=safe_preview_text(item.get("rationale", "")),
                    evidence_refs=safe_evidence_refs,
                    reviewed_at=safe_preview_text(item.get("reviewed_at", "")),
                )
            except ValueError:
                return None
    return None


def _artifact_usage_record_for_validation_feedback(
    *,
    repository: DatabaseRepository,
    validation_run: ValidationRunRecord,
) -> tuple[str, dict] | None:
    payload = validation_run.payload if isinstance(validation_run.payload, dict) else {}
    run_id = payload.get("pipeline_run_id")
    if not isinstance(run_id, str):
        return None

    record = repository.get_pipeline_run(safe_preview_text(run_id))
    if record is None:
        return None
    artifact = record.payload.get("artifact")
    if not isinstance(artifact, dict):
        return None
    artifact_id = artifact.get("artifact_id")
    if not artifact_id:
        return None

    manual_result = payload.get("manual_result")
    manual_result_payload = manual_result if isinstance(manual_result, dict) else {}
    approval_id = validation_run.approval_id or payload.get("approval_record_id", "")
    return str(artifact_id), {
        "usage_type": "validation_feedback",
        "ref": f"validation_run:{validation_run.id}",
        "run_id": safe_preview_text(run_id),
        "stage": "research_validation_feedback",
        "candidate_id": safe_preview_text(payload.get("candidate_id", "candidate")),
        "task_id": safe_preview_text(validation_run.task_id or ""),
        "plan_id": safe_preview_text(payload.get("plan_id", "")),
        "decision_id": safe_preview_text(payload.get("decision_id", "")),
        "approval_id": safe_preview_text(approval_id),
        "validation_run_id": validation_run.id,
        "outcome": safe_preview_text(manual_result_payload.get("outcome", "unknown")),
        "evidence_refs": safe_preview_lines(manual_result_payload.get("evidence_refs", [])),
        "evidence_ref_count": validation_run.evidence_ref_count,
        "finding_confirmation_allowed": False,
        "report_submission_allowed": False,
    }


def _artifact_usage_record_for_validation_feedback_review(
    *,
    repository: DatabaseRepository,
    feedback_stage: PipelineStageRecord,
    review_stage: PipelineStageRecord,
) -> tuple[str, dict] | None:
    feedback_payload = feedback_stage.payload if isinstance(feedback_stage.payload, dict) else {}
    validation_run_id = feedback_payload.get("validation_run_id")
    if not isinstance(validation_run_id, str):
        return None

    validation_run = repository.get_validation_run(safe_preview_text(validation_run_id))
    if validation_run is None:
        return None
    validation_payload = (
        validation_run.payload if isinstance(validation_run.payload, dict) else {}
    )
    run_id = validation_payload.get("pipeline_run_id")
    if not isinstance(run_id, str):
        return None
    safe_run_id = safe_preview_text(run_id)
    if not _validation_feedback_stage_matches_validation_run(repository, feedback_stage):
        return None

    record = repository.get_pipeline_run(safe_run_id)
    if record is None:
        return None
    artifact = record.payload.get("artifact")
    if not isinstance(artifact, dict):
        return None
    artifact_id = artifact.get("artifact_id")
    if not artifact_id:
        return None

    return str(artifact_id), {
        "usage_type": "validation_feedback_review",
        "ref": f"pipeline_stage:{review_stage.id}",
        "run_id": safe_preview_text(run_id),
        "stage": "research_validation_feedback_review",
        "candidate_id": safe_preview_text(validation_payload.get("candidate_id", "candidate")),
        "task_id": safe_preview_text(feedback_stage.task_id or ""),
        "plan_id": safe_preview_text(feedback_payload.get("plan_id", "")),
        "decision_id": safe_preview_text(feedback_payload.get("decision_id", "")),
        "approval_id": safe_preview_text(feedback_payload.get("approval_id", "")),
        "validation_run_id": validation_run.id,
        "reviewed_stage_ref": f"pipeline_stage:{feedback_stage.id}",
        "finding_confirmation_allowed": True,
        "report_submission_allowed": False,
    }


def _validation_feedback_stage_matches_validation_run(
    repository: DatabaseRepository,
    feedback_stage: PipelineStageRecord,
) -> bool:
    payload = feedback_stage.payload if isinstance(feedback_stage.payload, dict) else {}
    validation_run_id = payload.get("validation_run_id")
    if not isinstance(validation_run_id, str):
        return True

    validation_run = repository.get_validation_run(safe_preview_text(validation_run_id))
    if validation_run is None:
        return True

    validation_payload = (
        validation_run.payload if isinstance(validation_run.payload, dict) else {}
    )
    run_id = validation_payload.get("pipeline_run_id")
    if not isinstance(run_id, str):
        return True

    explicit_feedback_run_refs: list[str] = []
    if feedback_stage.pipeline_run_id is not None:
        explicit_feedback_run_refs.append(feedback_stage.pipeline_run_id)
    explicit_feedback_run_refs.extend(
        ref.removeprefix("pipeline_run:")
        for ref in safe_string_list(feedback_stage.input_refs)
        if ref.startswith("pipeline_run:")
    )
    return not explicit_feedback_run_refs or safe_preview_text(run_id) in explicit_feedback_run_refs


def _validation_feedback_stage_validation_run_or_409(
    repository: DatabaseRepository,
    feedback_stage: PipelineStageRecord,
) -> ValidationRunRecord:
    payload = feedback_stage.payload if isinstance(feedback_stage.payload, dict) else {}
    validation_run_id = payload.get("validation_run_id")
    if not isinstance(validation_run_id, str) or not validation_run_id:
        raise HTTPException(status_code=409, detail="validation_run_not_found")

    validation_run = repository.get_validation_run(safe_preview_text(validation_run_id))
    if validation_run is None:
        raise HTTPException(status_code=409, detail="validation_run_not_found")
    return validation_run


def _artifact_usage_record_for_finding_candidate(
    *,
    record: PipelineRunRecord,
    claim: ClaimLedgerEntry,
    finding: Finding,
    candidate_refs: list[str] | None = None,
    manual_observation_refs: list[str] | None = None,
    validation_feedback_refs: list[str] | None = None,
) -> tuple[str, dict] | None:
    artifact = record.payload.get("artifact")
    if not isinstance(artifact, dict):
        return None

    artifact_id = artifact.get("artifact_id")
    if not artifact_id or str(artifact_id) not in claim.provenance_refs:
        return None

    safe_candidate_refs = safe_preview_lines(candidate_refs or [])
    safe_manual_observation_refs = safe_preview_lines(manual_observation_refs or [])
    safe_validation_feedback_refs = safe_preview_lines(validation_feedback_refs or [])
    usage = {
        "usage_type": "finding_candidate",
        "ref": f"finding_candidate:{finding.id}",
        "run_id": record.id,
        "stage": "finding_promotion",
        "claim_id": claim.claim_id,
        "finding_id": finding.id,
        "submission_recommendation": finding.submission_recommendation,
        "evidence_refs": finding.evidence_refs,
        "candidate_refs": safe_candidate_refs,
        "candidate_ref_count": len(safe_candidate_refs),
    }
    if safe_manual_observation_refs:
        usage["manual_observation_refs"] = safe_manual_observation_refs
        usage["manual_observation_ref_count"] = len(safe_manual_observation_refs)
    if safe_validation_feedback_refs:
        usage["validation_feedback_refs"] = safe_validation_feedback_refs
        usage["validation_feedback_ref_count"] = len(safe_validation_feedback_refs)
    return str(artifact_id), usage


def _candidate_refs_for_finding_promotion(
    record: PipelineRunRecord,
    repository: DatabaseRepository,
) -> list[str]:
    refs: list[str] = []
    for usage in _closed_loop_artifact_usage_records(record, repository):
        if usage.get("usage_type") != "hypothesis_candidate":
            continue
        if usage.get("run_id") != record.id:
            continue
        ref = usage.get("ref")
        if not isinstance(ref, str):
            continue
        safe_ref = safe_preview_text(ref)
        if safe_ref not in refs:
            refs.append(safe_ref)
    return refs


def _manual_observation_refs_for_finding_promotion(
    record: PipelineRunRecord,
    repository: DatabaseRepository,
    claim: ClaimLedgerEntry,
) -> list[str]:
    refs: list[str] = []
    for usage in _closed_loop_artifact_usage_records(record, repository):
        if usage.get("usage_type") != "manual_observation":
            continue
        if usage.get("run_id") != record.id or usage.get("claim_id") != claim.claim_id:
            continue
        ref = usage.get("ref")
        if not isinstance(ref, str):
            continue
        safe_ref = safe_preview_text(ref)
        if safe_ref != "[REDACTED]" and safe_ref not in refs:
            refs.append(safe_ref)
    return refs


def _validation_feedback_refs_for_finding_promotion(
    record: PipelineRunRecord,
    repository: DatabaseRepository,
) -> list[str]:
    campaign_ids = {
        stage.campaign_id
        for stage in repository.list_pipeline_stages_for_run(record.id)
        if stage.campaign_id
        and stage.stage_key == "campaign_report_preview"
    }
    refs: list[str] = []
    for campaign_id in campaign_ids:
        for stage in repository.list_campaign_pipeline_stages(campaign_id):
            if stage.stage_key != "research_task_validation_feedback":
                continue
            if not _research_feedback_stage_belongs_to_run(stage, record.id):
                continue
            review_refs = _research_feedback_allow_review_refs(repository, stage)
            if not review_refs:
                continue
            for ref in [f"pipeline_stage:{stage.id}", *review_refs]:
                safe_ref = safe_preview_text(ref)
                if safe_ref != "[REDACTED]" and safe_ref not in refs:
                    refs.append(safe_ref)
    return refs


def _record_finding_promotion_llm_audit(
    *,
    repository: DatabaseRepository,
    record: PipelineRunRecord,
    claim: ClaimLedgerEntry,
    finding: Finding,
) -> LLMRunRecord:
    prompt_fingerprint_material = "|".join(
        [
            "finding_promotion_recommendation",
            safe_preview_text(record.id),
            safe_preview_text(claim.claim_id),
            safe_preview_text(finding.id),
            safe_preview_text(finding.submission_recommendation),
            str(len(safe_string_list(finding.evidence_refs))),
        ]
    )
    return repository.save_llm_run(
        provider="internal_hunter_loop",
        model="hunter_operating_loop_v1",
        purpose="finding_promotion_recommendation",
        prompt_hash=sha256(prompt_fingerprint_material.encode("utf-8")).hexdigest(),
        mode="audit_only",
        latency_ms=0,
        error=None,
        safety_notes=[
            "prompt_hash_only",
            "no_prompt_text_stored",
            "advisory_only",
            "human_gate:still_required",
            "no_live_requests",
            "no_auto_submission",
        ],
    )


def _record_finding_promotion_stage(
    *,
    repository: DatabaseRepository,
    record: PipelineRunRecord,
    claim: ClaimLedgerEntry,
    finding: Finding,
    candidate_refs: list[str] | None = None,
    manual_observation_refs: list[str] | None = None,
    validation_feedback_refs: list[str] | None = None,
    llm_audit: LLMRunRecord | None = None,
) -> None:
    report_preview_stages = [
        stage
        for stage in repository.list_pipeline_stages_for_run(record.id)
        if stage.stage_key == "campaign_report_preview" and stage.campaign_id
    ]
    campaign_stage = report_preview_stages[-1] if report_preview_stages else None
    campaign_id = campaign_stage.campaign_id if campaign_stage is not None else None
    task_id = campaign_stage.task_id if campaign_stage is not None else None
    stage_order = (
        len(repository.list_campaign_pipeline_stages(campaign_id))
        if campaign_id is not None
        else len(repository.list_pipeline_stages_for_run(record.id))
    )
    safe_candidate_refs = safe_preview_lines(candidate_refs or [])
    safe_manual_observation_refs = safe_preview_lines(manual_observation_refs or [])
    safe_validation_feedback_refs = safe_preview_lines(validation_feedback_refs or [])
    payload = {
        "claim_id": claim.claim_id,
        "finding_candidate_id": finding.id,
        "evidence_ref_count": len(safe_string_list(finding.evidence_refs)),
        "candidate_ref_count": len(safe_candidate_refs),
        "candidate_refs": safe_candidate_refs,
        "manual_observation_ref_count": len(safe_manual_observation_refs),
        "manual_observation_refs": safe_manual_observation_refs,
        "claim_provenance_refs": safe_preview_lines(claim.provenance_refs),
        "review_evidence_refs": safe_string_list(claim.review_evidence_refs),
        "hunter_operating_action": finding.submission_recommendation,
        "hunter_operating_safety_notes": [
            "advisory_only",
            "human_gate:still_required",
            "no_live_requests",
            "no_auto_submission",
        ],
        "finding_promotion_allowed": False,
        "report_submission_allowed": False,
        "next_allowed_action": "Review finding candidate and report draft manually.",
        "raw_payload_processed": False,
    }
    if llm_audit is not None:
        payload["llm_audit"] = {
            "llm_run_id": llm_audit.id,
            "provider": llm_audit.provider,
            "model": llm_audit.model,
            "purpose": llm_audit.purpose,
            "prompt_hash": llm_audit.prompt_hash,
            "mode": llm_audit.mode,
            "latency_ms": llm_audit.latency_ms,
            "error": llm_audit.error,
            "prompt_text_stored": False,
        }
    if safe_validation_feedback_refs:
        payload["validation_feedback_ref_count"] = len(safe_validation_feedback_refs)
        payload["validation_feedback_refs"] = safe_validation_feedback_refs
    repository.save_pipeline_stage(
        pipeline_run_id=record.id,
        campaign_id=campaign_id,
        task_id=task_id,
        stage_key="finding_promotion",
        stage_order=stage_order,
        status="candidate_created",
        input_refs=[
            f"pipeline_run:{record.id}",
            f"claim:{claim.claim_id}",
            *safe_candidate_refs,
            *safe_manual_observation_refs,
            *safe_validation_feedback_refs,
        ],
        output_refs=[f"finding_candidate:{finding.id}"],
        safety_gate_state="manual_review_required",
        stop_reason=None,
        payload=payload,
    )


def _existing_finding_promotion_stage(
    repository: DatabaseRepository,
    run_id: str,
    finding_id: str,
) -> PipelineStageRecord | None:
    finding_ref = f"finding_candidate:{safe_preview_text(finding_id)}"
    for stage in repository.list_pipeline_stages_for_run(run_id):
        if stage.stage_key == "finding_promotion" and finding_ref in safe_string_list(
            stage.output_refs
        ):
            return stage
    return None


def _artifact_usage_record_for_learning_signal(
    *,
    record: PipelineRunRecord,
    signal: LearningSignal,
) -> tuple[str, dict] | None:
    artifact = record.payload.get("artifact")
    if not isinstance(artifact, dict):
        return None

    artifact_id = artifact.get("artifact_id")
    if not artifact_id or signal.id is None:
        return None

    usage = {
        "usage_type": "learning_signal",
        "ref": f"learning_signal:{signal.id}",
        "run_id": record.id,
        "stage": "mythos_brain",
        "learning_signal_id": signal.id,
        "outcome": signal.outcome,
        "playbook_id": signal.playbook_id,
        "surface_key": signal.surface_key,
    }
    if signal.bounty_amount is not None:
        usage["bounty_amount"] = signal.bounty_amount
    if signal.severity_delta is not None:
        usage["severity_delta"] = signal.severity_delta
    if signal.evidence_quality is not None:
        usage["evidence_quality"] = signal.evidence_quality
    if signal.target_relationships:
        usage["target_relationships"] = signal.target_relationships
    reasoning_context = _learning_signal_reasoning_context(record, str(artifact_id), signal)
    if reasoning_context is not None:
        usage["reasoning_context"] = reasoning_context
    return str(artifact_id), usage


def _learning_signal_reasoning_context(
    record: PipelineRunRecord,
    artifact_id: str,
    signal: LearningSignal,
) -> dict | None:
    scores = [
        usage.get("reasoning_review_score")
        for usage in _artifact_usage_records_for_run(record, artifact_id)
        if usage.get("usage_type") == "hypothesis_candidate"
        and usage.get("playbook_id") == signal.playbook_id
        and isinstance(usage.get("reasoning_review_score"), int)
    ]

    if not scores:
        return None
    return {
        "source": "hypothesis_lifecycle",
        "reasoning_review_score": max(scores),
        "candidate_context_count": len(scores),
        "safety_gate": "advisory_memory_only",
    }


def _save_campaign_learning_outcome_stage(
    *,
    repository: DatabaseRepository,
    run_record: PipelineRunRecord,
    signal: LearningSignal,
) -> None:
    if signal.id is None:
        return

    report_preview_stages = [
        stage
        for stage in repository.list_pipeline_stages_for_run(run_record.id)
        if stage.stage_key == "campaign_report_preview" and stage.campaign_id
    ]
    for stage in report_preview_stages:
        if _existing_campaign_learning_outcome_stage(
            repository=repository,
            campaign_id=stage.campaign_id,
            run_id=run_record.id,
            signal_id=signal.id,
        ):
            continue
        repository.save_pipeline_stage(
            pipeline_run_id=run_record.id,
            campaign_id=stage.campaign_id,
            task_id=stage.task_id,
            stage_key="learning_outcome_recorded",
            stage_order=len(repository.list_campaign_pipeline_stages(stage.campaign_id)),
            status="recorded",
            input_refs=[f"pipeline_run:{run_record.id}"],
            output_refs=[f"learning_signal:{signal.id}"],
            safety_gate_state="advisory_memory_only",
            stop_reason=None,
            payload={
                "outcome": signal.outcome,
                "evidence_quality": signal.evidence_quality,
                "raw_payload_processed": False,
                "submission_allowed": False,
                "execution_allowed": False,
            },
        )


def _existing_campaign_learning_outcome_stage(
    *,
    repository: DatabaseRepository,
    campaign_id: str,
    run_id: str,
    signal_id: str,
) -> bool:
    signal_ref = f"learning_signal:{safe_preview_text(signal_id)}"
    return any(
        stage.pipeline_run_id == run_id
        and stage.stage_key == "learning_outcome_recorded"
        and signal_ref in safe_string_list(stage.output_refs)
        for stage in repository.list_campaign_pipeline_stages(campaign_id)
    )


def _learning_signal_response(record: LearningSignalRecord) -> LearningSignal:
    return LearningSignal(
        id=record.id,
        program_id=record.program_id,
        playbook_id=record.playbook_id,
        outcome=record.outcome,
        surface_key=record.surface_key,
        notes=record.notes,
        bounty_amount=record.bounty_amount,
        severity_delta=record.severity_delta,
        evidence_quality=record.evidence_quality,
        triager_feedback=record.triager_feedback,
        target_relationships=record.target_relationships,
        created_at=record.created_at.isoformat(),
    )


def _existing_learning_signal_for_outcome(
    repository: DatabaseRepository,
    *,
    signal: LearningSignal,
    run_record: PipelineRunRecord | None,
) -> LearningSignalRecord | None:
    candidate_signal_ids: set[str] | None = None
    if run_record is not None:
        candidate_signal_ids = {
            safe_preview_text(usage.get("learning_signal_id", ""))
            for usage in _closed_loop_artifact_usage_records(run_record, repository)
            if usage.get("usage_type") == "learning_signal"
            and usage.get("run_id") == run_record.id
            and safe_preview_text(usage.get("learning_signal_id", "")) != "[REDACTED]"
        }
        if not candidate_signal_ids:
            return None
    elif _learning_signal_requires_raw_identity(signal):
        return None

    safe_surface_key = safe_preview_text(signal.surface_key)
    safe_notes = safe_preview_text(signal.notes)
    safe_severity_delta = safe_preview_text(signal.severity_delta)
    safe_evidence_quality = safe_preview_text(signal.evidence_quality)
    safe_triager_feedback = safe_preview_text(signal.triager_feedback)
    safe_target_relationships = safe_preview_lines(signal.target_relationships)
    for record in repository.list_learning_signals(signal.program_id):
        if candidate_signal_ids is not None and record.id not in candidate_signal_ids:
            continue
        if (
            record.playbook_id == signal.playbook_id
            and record.outcome == signal.outcome
            and safe_preview_text(record.surface_key) == safe_surface_key
            and safe_preview_text(record.notes) == safe_notes
            and record.bounty_amount == signal.bounty_amount
            and safe_preview_text(record.severity_delta) == safe_severity_delta
            and safe_preview_text(record.evidence_quality) == safe_evidence_quality
            and safe_preview_text(record.triager_feedback) == safe_triager_feedback
            and safe_preview_lines(record.target_relationships) == safe_target_relationships
        ):
            return record
    return None


def _learning_signal_requires_raw_identity(signal: LearningSignal) -> bool:
    return (
        _learning_text_requires_raw_identity(signal.notes)
        or _learning_text_requires_raw_identity(signal.triager_feedback)
        or safe_preview_lines(signal.target_relationships) != signal.target_relationships
    )


def _learning_text_requires_raw_identity(value: str | None) -> bool:
    return value is not None and safe_preview_text(value) != value


def _claim_review_evidence_refs_supported(
    claim: ClaimLedgerEntry,
    evidence_refs: list[str],
) -> bool:
    if not evidence_refs:
        return (
            "has_security_impact_observation" in claim.quality_reasons
            and "manual_observation_missing_safe_evidence" not in claim.quality_reasons
        )
    if not review_evidence_refs_are_report_safe(evidence_refs):
        return False
    supported_refs = set(REPORT_SAFE_REVIEW_EVIDENCE_REFS)
    if "has_security_impact_observation" in claim.quality_reasons:
        supported_refs.update(claim.evidence_refs)
    return set(evidence_refs) <= supported_refs


def _evidence_quality_from_reviewed_claims(
    record: PipelineRunRecord,
) -> LearningEvidenceQuality | None:
    try:
        preview = build_report_preview_response(record)
    except ValueError:
        return None

    weak_evidence_seen = False
    for claim in preview.claim_ledger:
        if claim.claim_type != "observed_fact":
            continue
        if claim.review_status == "needs_evidence":
            weak_evidence_seen = True
            continue
        if claim.review_status != "confirmed_observed_fact":
            continue
        has_security_impact_observation = (
            "has_security_impact_observation" in claim.quality_reasons
            and "missing_security_impact_observation" not in claim.readiness_blockers
        )
        if not has_security_impact_observation:
            weak_evidence_seen = True
            continue
        if review_evidence_refs_are_report_safe(claim.review_evidence_refs):
            return "strong"

    for claim in preview.claim_ledger:
        if (
            claim.claim_type == "observed_fact"
            and claim.review_status == "confirmed_observed_fact"
            and claim.quality_score >= 80
            and (claim.provenance_edges or claim.provenance_refs)
            and "has_security_impact_observation" in claim.quality_reasons
            and "missing_security_impact_observation" not in claim.readiness_blockers
        ):
            return "adequate"
    if weak_evidence_seen:
        return "weak"
    return None


def _apply_program_learning_to_hunter_intelligence(
    intelligence: HunterIntelligence | None,
    learning_signals: list[LearningSignalRecord],
) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    if intelligence is None:
        return [], [], []

    lesson_inputs = [_learning_signal_response(signal) for signal in learning_signals]
    lessons = build_mythos_lessons(lesson_inputs)
    lessons_by_playbook: dict[str, list[MythosLesson]] = {}
    for lesson in lessons:
        lessons_by_playbook.setdefault(lesson.playbook_id, []).append(lesson)
    weak_accepted_playbooks = {
        signal.playbook_id
        for signal in learning_signals
        if signal.outcome == "accepted" and signal.evidence_quality == "weak"
    }
    lesson_candidate_playbooks = {signal.playbook_id for signal in learning_signals}

    applied_reasons: list[str] = []
    skipped_reasons: list[str] = []
    lesson_traces: list[dict[str, Any]] = []
    for assessment in intelligence.assessments:
        matching_lessons = lessons_by_playbook.get(assessment.playbook_id, [])
        hard_gate_blocked = (
            assessment.recommendation == "blocked"
            or assessment.rejection_risk_score >= 90
        )
        if hard_gate_blocked:
            if matching_lessons:
                skipped_reasons.append("learning:safety_gate_blocked")
                for lesson in matching_lessons:
                    lesson_traces.append(_lesson_trace(lesson, action="skipped"))
            continue
        if not matching_lessons:
            if assessment.playbook_id in weak_accepted_playbooks:
                skipped_reasons.append("learning:weak_accepted_evidence_not_boosted")
            elif assessment.playbook_id in lesson_candidate_playbooks:
                skipped_reasons.append("learning:lesson_not_ready")
            continue
        for lesson in matching_lessons:
            delta = max(-10, min(10, lesson.score_delta))
            if lesson.recommendation == "boost":
                assessment.hunter_priority_score = min(
                    100,
                    assessment.hunter_priority_score + delta,
                )
                if "learning:accepted_history" not in assessment.reasons:
                    assessment.reasons.append("learning:accepted_history")
                applied_reasons.append("learning:accepted_history")
                lesson_traces.append(_lesson_trace(lesson, action="applied"))
            elif lesson.recommendation == "duplicate_watch":
                assessment.duplicate_risk_score = min(
                    100,
                    assessment.duplicate_risk_score + abs(delta),
                )
                assessment.hunter_priority_score = max(
                    0,
                    assessment.hunter_priority_score - round(abs(delta) * 0.25),
                )
                if "learning:duplicate_history" not in assessment.reasons:
                    assessment.reasons.append("learning:duplicate_history")
                applied_reasons.append("learning:duplicate_history")
                lesson_traces.append(_lesson_trace(lesson, action="applied"))
            elif lesson.recommendation == "penalize":
                assessment.hunter_priority_score = max(
                    0,
                    assessment.hunter_priority_score + delta,
                )
                if "learning:rejection_history" not in assessment.reasons:
                    assessment.reasons.append("learning:rejection_history")
                applied_reasons.append("learning:rejection_history")
                lesson_traces.append(_lesson_trace(lesson, action="applied"))
            elif lesson.recommendation == "evidence_needed":
                skipped_reasons.append("learning:weak_accepted_evidence_not_boosted")
                lesson_traces.append(_lesson_trace(lesson, action="skipped"))
            for reason in lesson.reasons:
                if reason not in assessment.reasons:
                    assessment.reasons.append(reason)
        if "advisory_memory_only" not in assessment.safety_notes:
            assessment.safety_notes.append("advisory_memory_only")
    return sorted(set(applied_reasons)), sorted(set(skipped_reasons)), lesson_traces


def _lesson_trace(lesson: MythosLesson, *, action: str) -> dict[str, Any]:
    return {
        "lesson_id": (
            f"{lesson.scope_type}:{lesson.scope_key}:{lesson.playbook_id}:"
            f"{lesson.surface_pattern}:{lesson.recommendation}"
        ),
        "playbook_id": lesson.playbook_id,
        "surface_pattern": lesson.surface_pattern,
        "recommendation": lesson.recommendation,
        "action": action,
        "source_signal_count": len(lesson.source_signal_ids),
        "source_signal_ids": lesson.source_signal_ids,
        "reasons": lesson.reasons,
    }


def _program_learning_stage(
    signal_count: int,
    reasons: list[str],
    status: str,
    lesson_traces: list[dict[str, Any]] | None = None,
) -> PipelineStage:
    action = "adjusted hunter intelligence priorities" if status == "completed" else "left hunter intelligence unchanged"
    return bounded_stage(
        name="program_learning",
        status=status,
        input_summary=f"{signal_count} program learning signal(s) reviewed.",
        output_summary=(
            f"Program memory {action}: "
            f"{', '.join(reasons)}."
        ),
        safety_notes=[
            "advisory_memory_only",
            "human_review_required",
            "no_execution_permission",
        ],
        role="Learning Agent",
        allowed_actions=["review_program_memory", "adjust_hunter_priority"],
        requires_human_review=True,
        details={"lesson_traces": lesson_traces or []},
    )


def _sync_hypothesis_assessment_hunter_scores(
    response: MythosPipelineDryRunResponse,
) -> None:
    if response.hunter_intelligence is None:
        return
    for index, assessment in enumerate(response.hunter_intelligence.assessments):
        if index >= len(response.hypothesis_assessments):
            break
        response.hypothesis_assessments[index].hunter_assessment = assessment


def _pipeline_run_brain_payload(record: PipelineRunRecord) -> dict:
    return {
        "id": record.id,
        "program_id": record.program_id,
        "asset": record.asset,
        "payload": record.payload,
    }


def _program_intelligence_profile(
    repository: DatabaseRepository,
    program_id: str,
) -> ProgramIntelligenceProfile:
    program = repository.get_program(program_id)
    if program is None:
        raise HTTPException(status_code=404, detail="Program not found")
    pipeline_runs = [
        _pipeline_run_brain_payload(record)
        for record in repository.list_pipeline_runs_for_program(program_id)
    ]
    learning_signals = [
        _learning_signal_response(record)
        for record in repository.list_learning_signals(program_id)
    ]
    lesson_signals = [
        _learning_signal_response(record)
        for record in repository.list_all_learning_signals()
    ]
    profile = build_program_intelligence(
        program=program,
        pipeline_runs=pipeline_runs,
        learning_signals=learning_signals,
        lesson_signals=lesson_signals,
    )
    profile.reasoning_memory = _program_reasoning_memory(repository, program_id)
    return profile


def _program_reasoning_memory(
    repository: DatabaseRepository,
    program_id: str,
) -> ReasoningMemorySummary:
    playbooks: dict[str, dict[str, int]] = {}
    for record in repository.list_pipeline_runs_for_program(program_id):
        for usage in _closed_loop_artifact_usage_records(record, repository):
            if usage.get("usage_type") != "learning_signal":
                continue
            context = usage.get("reasoning_context")
            if not isinstance(context, dict):
                continue
            score = context.get("reasoning_review_score")
            if not isinstance(score, int):
                continue
            playbook_id = safe_preview_text(usage.get("playbook_id", "unknown_playbook"))
            entry = playbooks.setdefault(
                playbook_id,
                {
                    "highest_reasoning_review_score": 0,
                    "learning_signal_context_count": 0,
                    "candidate_context_count": 0,
                },
            )
            entry["highest_reasoning_review_score"] = max(
                entry["highest_reasoning_review_score"],
                max(0, min(100, score)),
            )
            entry["learning_signal_context_count"] += 1
            candidate_context_count = context.get("candidate_context_count")
            if isinstance(candidate_context_count, int):
                entry["candidate_context_count"] += max(0, candidate_context_count)

    all_playbooks = [
        ReasoningMemoryPlaybook(
            playbook_id=playbook_id,
            highest_reasoning_review_score=data["highest_reasoning_review_score"],
            learning_signal_context_count=data["learning_signal_context_count"],
            candidate_context_count=data["candidate_context_count"],
        )
        for playbook_id, data in sorted(
            playbooks.items(),
            key=lambda item: (-item[1]["highest_reasoning_review_score"], item[0]),
        )
    ]
    if not all_playbooks:
        return ReasoningMemorySummary()

    return ReasoningMemorySummary(
        highest_reasoning_review_score=max(
            item.highest_reasoning_review_score for item in all_playbooks
        ),
        learning_signal_context_count=sum(
            item.learning_signal_context_count for item in all_playbooks
        ),
        candidate_context_count=sum(item.candidate_context_count for item in all_playbooks),
        top_playbooks=all_playbooks[:5],
    )


def _llm_audit_safety_notes(response: LLMResponse) -> list[str]:
    notes = [
        "prompt_hash_only",
        "no_prompt_storage",
        "provider_response_not_fact",
    ]
    if response.mode == "dry_run":
        notes.append("dry_run_no_provider_call")
    if response.error:
        notes.append("provider_error_recorded")
    return notes


def _build_report_preview_response_or_404(
    record: PipelineRunRecord,
) -> ReportPreviewResponse:
    try:
        return build_report_preview_response(record)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


def _raise_if_campaign_scoped_run_not_in_scope(
    repository: DatabaseRepository,
    run_id: str,
) -> None:
    run = repository.get_pipeline_run(run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    if run.scope_status != "in_scope":
        raise HTTPException(status_code=409, detail="scope_not_in_scope")
    if _campaign_scoped_run_has_out_of_scope_campaign(repository, run_id):
        raise HTTPException(status_code=409, detail="scope_not_in_scope")


def _campaign_scoped_run_has_out_of_scope_campaign(
    repository: DatabaseRepository,
    run_id: str,
) -> bool:
    campaign_ids = {
        stage.campaign_id
        for stage in repository.list_pipeline_stages_for_run(run_id)
        if stage.campaign_id
        and stage.stage_key == "campaign_report_preview"
    }
    for campaign_id in campaign_ids:
        campaign = repository.get_campaign(campaign_id)
        if campaign is not None and campaign.scope_status != "in_scope":
            return True
    return False


def _program_or_404_in_scope(
    repository: DatabaseRepository,
    program_id: str,
):
    program = repository.get_program(program_id)
    if program is None:
        raise HTTPException(status_code=404, detail="Program not found")
    if program.scope_status != "in_scope":
        raise HTTPException(status_code=409, detail="scope_not_in_scope")
    return program


def _research_feedback_promotion_gate_for_run(
    repository: DatabaseRepository,
    *,
    run_id: str,
) -> dict | None:
    campaign_ids = {
        stage.campaign_id
        for stage in repository.list_pipeline_stages_for_run(run_id)
        if stage.campaign_id
        and stage.stage_key == "campaign_report_preview"
    }
    blocked_stages: list[PipelineStageRecord] = []
    for campaign_id in campaign_ids:
        blocked_stages.extend(
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign_id)
            if stage.stage_key == "research_task_validation_feedback"
            and _research_feedback_stage_belongs_to_run(stage, run_id)
            and _research_feedback_stage_blocks_promotion(stage)
            and not _research_feedback_stage_has_allow_review(repository, stage)
        )
    if not blocked_stages:
        return None

    provenance_refs = {
        safe_preview_text(ref)
        for stage in blocked_stages
        for ref in (stage.input_refs or [])
        if safe_preview_text(ref) != "[REDACTED]"
    }
    return {
        "reason": "blocked_by_research_feedback_gate",
        "blocked_stage_count": len(blocked_stages),
        "provenance_ref_count": len(provenance_refs),
        "finding_promotion_allowed": False,
        "report_submission_allowed": False,
    }


def _record_research_feedback_promotion_block(
    repository: DatabaseRepository,
    *,
    run_id: str,
    gate: dict,
) -> None:
    campaign_ids = {
        stage.campaign_id
        for stage in repository.list_pipeline_stages_for_run(run_id)
        if stage.campaign_id
        and stage.stage_key == "campaign_report_preview"
    }
    for campaign_id in campaign_ids:
        if _existing_research_feedback_promotion_block(
            repository,
            campaign_id=campaign_id,
            run_id=run_id,
        ) is not None:
            continue
        repository.save_pipeline_stage(
            pipeline_run_id=run_id,
            campaign_id=campaign_id,
            task_id=None,
            stage_key="finding_promotion_blocked",
            stage_order=len(repository.list_campaign_pipeline_stages(campaign_id)),
            status="blocked",
            input_refs=[f"pipeline_run:{run_id}"],
            output_refs=[],
            safety_gate_state="manual_review_required",
            stop_reason="blocked_by_research_feedback_gate",
            payload={
                "reason": "blocked_by_research_feedback_gate",
                "blocked_stage_count": gate.get("blocked_stage_count", 0),
                "provenance_ref_count": gate.get("provenance_ref_count", 0),
                "finding_promotion_allowed": False,
                "report_submission_allowed": False,
                "raw_payload_processed": False,
            },
        )


def _existing_research_feedback_promotion_block(
    repository: DatabaseRepository,
    *,
    campaign_id: str,
    run_id: str,
) -> PipelineStageRecord | None:
    for stage in repository.list_campaign_pipeline_stages(campaign_id):
        if (
            stage.pipeline_run_id == run_id
            and stage.stage_key == "finding_promotion_blocked"
            and stage.stop_reason == "blocked_by_research_feedback_gate"
        ):
            return stage
    return None


def _research_feedback_stage_blocks_promotion(stage: PipelineStageRecord) -> bool:
    payload = stage.payload if isinstance(stage.payload, dict) else {}
    return (
        stage.safety_gate_state == "advisory_validation_feedback_only"
        and payload.get("finding_confirmation_allowed") is not True
    )


def _research_feedback_stage_belongs_to_run(
    stage: PipelineStageRecord,
    run_id: str,
) -> bool:
    run_ref = f"pipeline_run:{safe_preview_text(run_id)}"
    return stage.pipeline_run_id == run_id or run_ref in safe_string_list(stage.input_refs)


def _research_feedback_stage_has_allow_review(
    repository: DatabaseRepository,
    stage: PipelineStageRecord,
) -> bool:
    return _research_feedback_allow_review_stage(repository, stage) is not None


def _research_feedback_allow_review_refs(
    repository: DatabaseRepository,
    stage: PipelineStageRecord,
) -> list[str]:
    review = _research_feedback_allow_review_stage(repository, stage)
    if review is None:
        return []
    ref = safe_preview_text(f"pipeline_stage:{review.id}")
    return [] if ref == "[REDACTED]" else [ref]


def _research_feedback_allow_review_stage(
    repository: DatabaseRepository,
    stage: PipelineStageRecord,
) -> PipelineStageRecord | None:
    if stage.campaign_id is None:
        return None
    stage_ref = f"pipeline_stage:{stage.id}"
    matching_reviews: list[PipelineStageRecord] = []
    for review in repository.list_campaign_pipeline_stages(stage.campaign_id):
        payload = review.payload if isinstance(review.payload, dict) else {}
        if (
            review.stage_key == "research_task_validation_feedback_review"
            and review.stage_order >= stage.stage_order
            and stage_ref in safe_string_list(review.input_refs)
            and payload.get("reviewed_stage_id") == stage.id
            and payload.get("decision") == "allow_finding_promotion"
            and payload.get("finding_confirmation_allowed") is True
        ):
            matching_reviews.append(review)
    if not matching_reviews:
        return None
    return min(matching_reviews, key=lambda record: (record.stage_order, record.created_at, record.id))


SECURITY_IMPACT_REQUIRED_OBSERVATION_TYPES = [
    "request_response_diff",
    "role_matrix_observation",
]


def _pipeline_run_detail_payload(
    record: PipelineRunRecord,
    repository: DatabaseRepository,
) -> dict:
    payload = dict(record.payload)
    workspace = payload.get("validation_workspace")
    if isinstance(workspace, dict):
        enriched_workspace = dict(workspace)
        enriched_workspace["claim_validation_tasks"] = _claim_validation_tasks(record)
        payload["validation_workspace"] = enriched_workspace
    payload["evidence_support_summary"] = _evidence_support_summary(record)
    payload["closed_loop_summary"] = _closed_loop_summary(record, repository)
    return payload


def _claim_validation_tasks(record: PipelineRunRecord) -> list[dict]:
    try:
        preview = build_report_preview_response(record)
    except ValueError:
        return []

    eligible_claim = best_finding_candidate_claim(preview)
    eligible_claim_id = eligible_claim.claim_id if eligible_claim is not None else None
    return [
        _claim_validation_task(
            claim,
            eligible_claim_id,
            _claim_relationship_contexts(record.payload, claim),
        )
        for claim in preview.claim_ledger
    ]


def _evidence_support_summary(record: PipelineRunRecord) -> dict:
    try:
        preview = build_report_preview_response(record)
    except ValueError:
        claims = []
    else:
        claims = preview.claim_ledger

    statuses = [_claim_evidence_support_status(claim) for claim in claims]
    status_counts = {status: statuses.count(status) for status in sorted(set(statuses))}

    return {
        "total_count": len(claims),
        "status_counts": status_counts,
        "missing_required_count": status_counts.get("missing_required_evidence", 0),
        "partially_supported_count": status_counts.get("partially_supported", 0),
        "satisfied_human_gated_count": status_counts.get("human_gated_supported", 0),
        "unsafe_or_redacted_requirement_count": status_counts.get(
            "unsafe_or_redacted_evidence",
            0,
        ),
        "top_support_status": _top_evidence_support_status(status_counts),
        "safety_notes": [
            "claim_ledger_derived",
            "advisory_only",
            "human_review_required",
            "no_submission_unblock",
        ],
    }


def _claim_evidence_support_status(claim: ClaimLedgerEntry) -> str:
    evidence_refs = list(claim.evidence_refs) + list(claim.review_evidence_refs)
    if any(ref == "[REDACTED]" for ref in evidence_refs):
        return "unsafe_or_redacted_evidence"
    if (
        claim.review_status == "confirmed_observed_fact"
        and claim.evidence_refs
        and claim.review_evidence_refs
    ):
        return "human_gated_supported"
    if "missing_evidence_refs" in claim.readiness_blockers or not claim.evidence_refs:
        return "missing_required_evidence"
    return "partially_supported"


def _top_evidence_support_status(status_counts: dict[str, int]) -> str | None:
    for status in [
        "unsafe_or_redacted_evidence",
        "human_gated_supported",
        "missing_required_evidence",
        "partially_supported",
    ]:
        if status_counts.get(status, 0) > 0:
            return status
    return None


def _closed_loop_summary(
    record: PipelineRunRecord,
    repository: DatabaseRepository,
) -> dict:
    payload = record.payload
    manual_observations = _safe_record_list(payload.get("manual_observations"))
    claim_review_decisions = _safe_record_list(payload.get("claim_review_decisions"))
    usage_records = _closed_loop_artifact_usage_records(record, repository)
    finding_candidate_count = _closed_loop_usage_count(
        usage_records,
        "finding_candidate",
        record.id,
    )
    validation_feedback_count = _closed_loop_usage_count(
        usage_records,
        "validation_feedback",
        record.id,
    )
    validation_feedback_review_count = _closed_loop_usage_count(
        usage_records,
        "validation_feedback_review",
        record.id,
    )
    learning_signal_count = _closed_loop_usage_count(
        usage_records,
        "learning_signal",
        record.id,
    )
    run_learning_signals = _closed_loop_learning_signals(
        usage_records,
        record,
        repository,
    )
    memory_lessons = build_mythos_lessons(run_learning_signals)
    lesson_count = len(memory_lessons)
    brain_memory_status = _closed_loop_brain_memory_status(
        learning_signal_count=learning_signal_count,
        lesson_count=lesson_count,
    )
    reasoning_context = _closed_loop_reasoning_context(usage_records)
    blocked_reasons = _closed_loop_blocked_reasons(record)

    summary = {
        "status": _closed_loop_status(
            manual_observation_count=len(manual_observations),
            reviewed_claim_count=len(claim_review_decisions),
            finding_candidate_count=finding_candidate_count,
            learning_signal_count=learning_signal_count,
            brain_memory_status=brain_memory_status,
            blocked_reasons=blocked_reasons,
        ),
        "manual_observation_count": len(manual_observations),
        "reviewed_claim_count": len(claim_review_decisions),
        "finding_candidate_count": finding_candidate_count,
        "validation_feedback_count": validation_feedback_count,
        "validation_feedback_review_count": validation_feedback_review_count,
        "learning_signal_count": learning_signal_count,
        "lesson_count": lesson_count,
        "brain_memory_status": brain_memory_status,
        "memory_lessons": [_closed_loop_memory_lesson(lesson) for lesson in memory_lessons],
        "blocked_reasons": blocked_reasons,
        "safety_notes": _closed_loop_safety_notes(record),
        "steps": _closed_loop_steps_for_record(
            record=record,
            manual_observation_count=len(manual_observations),
            reviewed_claim_count=len(claim_review_decisions),
            finding_candidate_count=finding_candidate_count,
            validation_feedback_count=validation_feedback_count,
            validation_feedback_review_count=validation_feedback_review_count,
            learning_signal_count=learning_signal_count,
            lesson_count=lesson_count,
            brain_memory_status=brain_memory_status,
            blocked_reasons=blocked_reasons,
        ),
    }
    if reasoning_context is not None:
        summary["reasoning_context"] = reasoning_context
    return summary


def _closed_loop_safety_notes(record: PipelineRunRecord) -> list[str]:
    if record.payload.get("artifact_kind") == "source_audit":
        return [
            "source_audit_hypotheses_only",
            "local_files_only",
            "no_live_requests",
            "human_review_required",
            "submission_blocked",
        ]
    return [
        "no_live_requests",
        "test_accounts_only",
        "human_review_required",
        "candidate_not_validated",
    ]


def _closed_loop_reasoning_context(usage_records: list[dict]) -> dict | None:
    scores = [
        context.get("reasoning_review_score")
        for usage in usage_records
        if usage.get("usage_type") == "learning_signal"
        for context in [usage.get("reasoning_context")]
        if isinstance(context, dict)
        and isinstance(context.get("reasoning_review_score"), int)
    ]
    if not scores:
        return None
    return {
        "source": "hypothesis_lifecycle",
        "highest_reasoning_review_score": max(0, min(100, max(scores))),
        "learning_signal_context_count": len(scores),
        "safety_gate": "advisory_memory_only",
    }


def _closed_loop_status(
    *,
    manual_observation_count: int,
    reviewed_claim_count: int,
    finding_candidate_count: int,
    learning_signal_count: int,
    brain_memory_status: str,
    blocked_reasons: list[str],
) -> str:
    if blocked_reasons:
        return "blocked"
    if brain_memory_status == "lesson_ready":
        return "brain_memory_ready"
    if learning_signal_count:
        return "candidate_learning_recorded"
    if finding_candidate_count:
        return "finding_candidate_created"
    if reviewed_claim_count:
        return "claim_reviewed"
    if manual_observation_count:
        return "manual_observation_recorded"
    return "not_started"


def _closed_loop_steps_for_record(
    *,
    record: PipelineRunRecord,
    manual_observation_count: int,
    reviewed_claim_count: int,
    finding_candidate_count: int,
    validation_feedback_count: int,
    validation_feedback_review_count: int,
    learning_signal_count: int,
    lesson_count: int,
    brain_memory_status: str,
    blocked_reasons: list[str],
) -> list[dict]:
    steps = _closed_loop_steps(
        manual_observation_count=manual_observation_count,
        reviewed_claim_count=reviewed_claim_count,
        finding_candidate_count=finding_candidate_count,
        validation_feedback_count=validation_feedback_count,
        validation_feedback_review_count=validation_feedback_review_count,
        learning_signal_count=learning_signal_count,
        lesson_count=lesson_count,
        brain_memory_status=brain_memory_status,
        blocked_reasons=blocked_reasons,
    )
    if record.payload.get("artifact_kind") != "source_audit":
        return steps

    source_steps = [
        {
            "key": "source_audit_review",
            "label": "Source Audit Review",
            "status": "waiting" if manual_observation_count == 0 else "complete",
            "reason": (
                "Sanitized local evidence has been attached for review."
                if manual_observation_count
                else "Source audit hypotheses need sanitized local evidence."
            ),
            "safety_gate": "local_files_only",
            "next_allowed_action": (
                "Review the attached sanitized evidence in the report preview."
                if manual_observation_count
                else "Open the validation workspace and attach sanitized local evidence."
            ),
        },
        {
            "key": "report_preview",
            "label": "Report Preview",
            "status": "waiting" if reviewed_claim_count == 0 else "complete",
            "reason": (
                "A human claim review decision is recorded for the report preview."
                if reviewed_claim_count
                else "Report preview is submission-blocked until human claim review."
            ),
            "safety_gate": "submission_blocked",
            "next_allowed_action": (
                "Review promotion readiness while keeping submission manual."
                if reviewed_claim_count
                else "Review the submission-blocked report preview before claim review."
            ),
        },
    ]
    return source_steps + [
        _source_audit_closed_loop_step(step)
        if step.get("key") == "finding_candidate"
        else step
        for step in steps
    ]


def _source_audit_closed_loop_step(step: dict) -> dict:
    source_step = dict(step)
    if source_step.get("status") == "waiting":
        source_step["next_allowed_action"] = (
            "Wait for sanitized evidence and human claim review before promotion."
        )
    return source_step


def _closed_loop_steps(
    *,
    manual_observation_count: int,
    reviewed_claim_count: int,
    finding_candidate_count: int,
    validation_feedback_count: int,
    validation_feedback_review_count: int,
    learning_signal_count: int,
    lesson_count: int,
    brain_memory_status: str,
    blocked_reasons: list[str],
) -> list[dict]:
    claim_blocked = "no_promotion_eligible_claim" in blocked_reasons
    promotion_blocked = bool(blocked_reasons)

    return [
        {
            "key": "manual_observation",
            "label": "Manual Observation",
            "status": "complete" if manual_observation_count else "waiting",
            "reason": (
                f"{manual_observation_count} sanitized manual observation recorded."
                if manual_observation_count
                else "No sanitized manual observation recorded yet."
            ),
            "safety_gate": "test_accounts_only",
            "next_allowed_action": (
                "Review the observed claim against redacted evidence."
                if manual_observation_count
                else "Record a sanitized manual observation."
            ),
        },
        {
            "key": "claim_review",
            "label": "Claim Review",
            "status": (
                "blocked"
                if claim_blocked
                else "complete"
                if reviewed_claim_count
                else "waiting"
            ),
            "reason": (
                "Reviewed claim is not promotion eligible."
                if claim_blocked
                else f"{reviewed_claim_count} claim review decision recorded."
                if reviewed_claim_count
                else "No human claim review decision recorded yet."
            ),
            "safety_gate": (
                "no_promotion_eligible_claim" if claim_blocked else "human_review_required"
            ),
            "next_allowed_action": (
                "Resolve blockers before promotion."
                if claim_blocked
                else "Promote eligible observed claims to finding candidates."
                if reviewed_claim_count
                else "Review the observed claim with redacted evidence."
            ),
        },
        {
            "key": "finding_candidate",
            "label": "Finding Candidate",
            "status": (
                "blocked"
                if promotion_blocked and finding_candidate_count == 0
                else "complete"
                if finding_candidate_count
                else "waiting"
            ),
            "reason": (
                "Promotion is blocked by the current safety gate."
                if promotion_blocked and finding_candidate_count == 0
                else f"{finding_candidate_count} finding candidate created."
                if finding_candidate_count
                else "No finding candidate created yet."
            ),
            "safety_gate": "candidate_not_validated",
            "next_allowed_action": (
                "Resolve blockers before promotion."
                if promotion_blocked and finding_candidate_count == 0
                else "Record an advisory learning outcome without changing validation state."
                if finding_candidate_count
                else "Create a candidate from an eligible reviewed observed claim."
            ),
        },
        {
            "key": "validation_feedback_review",
            "label": "Validation Feedback Review",
            "status": (
                "complete"
                if validation_feedback_review_count
                else "waiting"
                if validation_feedback_count
                else "not_applicable"
            ),
            "reason": (
                f"{validation_feedback_review_count} validation feedback review recorded."
                if validation_feedback_review_count
                else "Validation feedback is recorded and awaiting human review."
                if validation_feedback_count
                else "No validation feedback linked to this run."
            ),
            "safety_gate": "manual_review_required",
            "next_allowed_action": (
                "Promote to finding candidate only through explicit human action."
                if validation_feedback_review_count
                else "Review validation feedback before finding promotion."
                if validation_feedback_count
                else "Record validation feedback only after approved non-destructive validation."
            ),
        },
        {
            "key": "learning_signal",
            "label": "Learning Signal",
            "status": "complete" if learning_signal_count else "waiting",
            "reason": (
                f"{learning_signal_count} learning signal linked to this run."
                if learning_signal_count
                else "No advisory learning signal linked yet."
            ),
            "safety_gate": "advisory_memory_only",
            "next_allowed_action": (
                "Refresh the Mythos Brain profile for future prioritization."
                if learning_signal_count
                else "Record an accepted, duplicate, informative, N/A, or rejected outcome."
            ),
        },
        {
            "key": "brain_memory",
            "label": "Brain Memory",
            "status": "complete" if brain_memory_status == "lesson_ready" else "waiting",
            "reason": _closed_loop_brain_memory_reason(
                learning_signal_count=learning_signal_count,
                lesson_count=lesson_count,
            ),
            "safety_gate": "no_execution_permission",
            "next_allowed_action": _closed_loop_brain_memory_next_action(
                brain_memory_status,
            ),
        },
    ]


def _closed_loop_brain_memory_status(
    *,
    learning_signal_count: int,
    lesson_count: int,
) -> str:
    if lesson_count:
        return "lesson_ready"
    if learning_signal_count:
        return "learning_recorded"
    return "waiting_for_learning"


def _closed_loop_brain_memory_reason(
    *,
    learning_signal_count: int,
    lesson_count: int,
) -> str:
    if lesson_count:
        return (
            f"{lesson_count} reusable advisory lesson available for future prioritization."
        )
    if learning_signal_count:
        return "Learning signal is recorded; reusable lesson needs more evidence."
    return "Program brain is waiting for a learning signal."


def _closed_loop_brain_memory_next_action(status: str) -> str:
    if status == "lesson_ready":
        return "Use lesson memory as advisory context only."
    if status == "learning_recorded":
        return "Record another corroborating outcome before advisory lesson use."
    return "Keep the candidate gated until outcome memory exists."


def _closed_loop_memory_lesson(lesson: MythosLesson) -> dict:
    return {
        "lesson_id": _closed_loop_readable_lesson_id(lesson),
        "scope_type": lesson.scope_type,
        "scope_key": lesson.scope_key,
        "playbook_id": lesson.playbook_id,
        "surface_pattern": lesson.surface_pattern,
        "recommendation": lesson.recommendation,
        "confidence": lesson.confidence,
        "source_signal_count": len(lesson.source_signal_ids),
        "source_signal_ids": lesson.source_signal_ids,
        "reasons": lesson.reasons,
        "safety_notes": sorted(lesson.safety_notes),
    }


def _closed_loop_readable_lesson_id(lesson: MythosLesson) -> str:
    return ":".join(
        [
            lesson.scope_type,
            lesson.scope_key,
            lesson.playbook_id,
            lesson.surface_pattern,
            lesson.recommendation,
        ]
    )


def _closed_loop_artifact_usage_records(
    record: PipelineRunRecord,
    repository: DatabaseRepository,
) -> list[dict]:
    artifact = record.payload.get("artifact")
    artifact_id = artifact.get("artifact_id") if isinstance(artifact, dict) else None
    if not artifact_id:
        return []

    artifact_record = repository.get_artifact(str(artifact_id))
    if artifact_record is None:
        return []
    return _artifact_usage_records(artifact_record)


def _closed_loop_learning_signals(
    usage_records: list[dict],
    record: PipelineRunRecord,
    repository: DatabaseRepository,
) -> list[LearningSignal]:
    if record.program_id is None:
        return []

    run_signal_ids = {
        str(usage.get("learning_signal_id"))
        for usage in usage_records
        if usage.get("usage_type") == "learning_signal"
        and usage.get("run_id") == record.id
        and usage.get("learning_signal_id")
    }
    if not run_signal_ids:
        return []

    return [
        _learning_signal_response(signal)
        for signal in repository.list_learning_signals(record.program_id)
        if signal.id in run_signal_ids
    ]


def _closed_loop_usage_count(
    usage_records: list[dict],
    usage_type: str,
    run_id: str,
) -> int:
    return sum(
        1
        for usage in usage_records
        if usage.get("usage_type") == usage_type and usage.get("run_id") == run_id
    )


def _closed_loop_blocked_reasons(record: PipelineRunRecord) -> list[str]:
    payload = record.payload
    try:
        preview = build_report_preview_response(record)
    except ValueError:
        return ["report_preview_unavailable"]

    claim_review_decisions = _safe_record_list(payload.get("claim_review_decisions"))
    if claim_review_decisions and best_finding_candidate_claim(preview) is None:
        return ["no_promotion_eligible_claim"]

    return []


def _safe_record_list(value: object) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _claim_validation_task(
    claim: ClaimLedgerEntry,
    eligible_claim_id: str | None,
    relationship_contexts: list[str] | None = None,
) -> dict:
    relationship_contexts = relationship_contexts or []
    readiness_blockers = claim.readiness_blockers.copy()
    if (
        "manual_observation_missing_safe_evidence" in claim.quality_reasons
        and "manual_observation_missing_safe_evidence" not in readiness_blockers
    ):
        readiness_blockers.append("manual_observation_missing_safe_evidence")
    required_observation_types = (
        SECURITY_IMPACT_REQUIRED_OBSERVATION_TYPES.copy()
        if (
            "missing_security_impact_observation" in readiness_blockers
            or "manual_observation_missing_safe_evidence" in readiness_blockers
        )
        else []
    )
    return {
        "claim_id": claim.claim_id,
        "claim_type": claim.claim_type,
        "claim_text": claim.text,
        "status": _claim_validation_task_status(
            claim,
            eligible_claim_id,
            relationship_contexts,
        ),
        "promotion_eligible": claim.claim_id == eligible_claim_id,
        "required_observation_types": required_observation_types,
        "relationship_contexts": relationship_contexts,
        "evidence_focus": (
            ["parent_child_authorization_matrix"]
            if relationship_contexts
            else []
        ),
        "evidence_refs": claim.evidence_refs,
        "review_evidence_refs": claim.review_evidence_refs,
        "readiness_blockers": readiness_blockers,
        "quality_reasons": claim.quality_reasons,
        "quality_score": claim.quality_score,
        "readiness_level": claim.readiness_level,
        "review_status": claim.review_status,
        "human_review_required": claim.human_review_required,
        "execution_allowed": False,
        "safety_notes": [
            "advisory_only",
            "human_review_required",
            "test_accounts_only",
            "no_live_requests",
            "no_real_user_data",
        ],
    }


def _claim_validation_task_status(
    claim: ClaimLedgerEntry,
    eligible_claim_id: str | None,
    relationship_contexts: list[str] | None = None,
) -> str:
    blockers = set(claim.readiness_blockers)
    if "manual_observation_missing_safe_evidence" in claim.quality_reasons:
        blockers.add("manual_observation_missing_safe_evidence")
    if claim.claim_id == eligible_claim_id:
        return "promotion_eligible"
    if "manual_observation_missing_safe_evidence" in blockers:
        return "needs_report_safe_evidence"
    if "artifact_report_chain_blocked" in blockers:
        return "blocked_report_chain"
    if claim.claim_type != "observed_fact":
        return "not_reportable"
    if "missing_security_impact_observation" in blockers:
        if relationship_contexts:
            return "needs_boundary_matrix_observation"
        return "needs_security_impact_observation"
    if blockers & {"missing_evidence_refs", "missing_provenance_refs"}:
        return "needs_evidence"
    if claim.review_status == "confirmed_observed_fact":
        return "human_reviewed_gated"
    return "needs_human_review"


def _claim_relationship_contexts(
    payload: dict,
    claim: ClaimLedgerEntry,
) -> list[str]:
    target_model = payload.get("target_model")
    if not isinstance(target_model, dict):
        return []

    claim_refs = {str(ref) for ref in claim.provenance_refs if ref}
    claim_edge_refs = {
        edge.ref
        for edge in claim.provenance_edges
        if edge.fact_type == "object_relationship" and edge.ref
    }
    if not claim_refs and not claim_edge_refs:
        return []

    relationships = [
        relationship
        for relationship in target_model.get("relationships", [])
        if _relationship_matches_claim(relationship, claim_refs, claim_edge_refs)
    ]
    return _relationship_context_chains(relationships)


def _relationship_matches_claim(
    relationship: object,
    claim_refs: set[str],
    claim_edge_refs: set[str],
) -> bool:
    if not isinstance(relationship, dict):
        return False
    refs = {
        str(ref)
        for ref in relationship.get("provenance_refs", [])
        if ref
    }
    for edge in relationship.get("provenance_edges", []):
        if isinstance(edge, dict) and edge.get("ref"):
            refs.add(str(edge["ref"]))
    return bool(refs & (claim_refs | claim_edge_refs))


def _relationship_context_chains(relationships: list[dict]) -> list[str]:
    children_by_parent: dict[str, list[str]] = {}
    parents: set[str] = set()
    children: set[str] = set()

    for relationship in relationships:
        if relationship.get("relationship", "contains") != "contains":
            continue
        parent = safe_preview_text(relationship.get("parent_object", ""))
        child = safe_preview_text(relationship.get("child_object", ""))
        if not parent or not child or "[REDACTED]" in {parent, child}:
            continue
        children_by_parent.setdefault(parent, [])
        if child not in children_by_parent[parent]:
            children_by_parent[parent].append(child)
        parents.add(parent)
        children.add(child)

    roots = sorted(parents - children) or sorted(parents)
    contexts: list[str] = []
    for root in roots:
        for path in _relationship_context_paths(root, children_by_parent, []):
            if len(path) < 2:
                continue
            context = ">".join(path)
            if context not in contexts:
                contexts.append(context)
    return contexts


def _relationship_context_paths(
    node: str,
    children_by_parent: dict[str, list[str]],
    path: list[str],
) -> list[list[str]]:
    if node in path:
        return [path]

    next_path = [*path, node]
    children = children_by_parent.get(node, [])
    if not children:
        return [next_path]

    paths: list[list[str]] = []
    for child in sorted(children):
        paths.extend(_relationship_context_paths(child, children_by_parent, next_path))
    return paths


def _pipeline_run_summary(
    record: PipelineRunRecord,
    repository: DatabaseRepository | None = None,
) -> MythosPipelineRunSummary:
    payload = record.payload
    return MythosPipelineRunSummary(
        id=record.id,
        program_id=record.program_id,
        asset=record.asset,
        policy_text_hash=record.policy_text_hash,
        scope_status=record.scope_status,
        hypothesis_count=record.hypothesis_count,
        blocked_count=record.blocked_count,
        evidence_count=_count_evidence_items(payload),
        report_title=record.report_title,
        created_at=record.created_at.isoformat(),
        timeline=payload.get("timeline", []),
        artifact=payload.get("artifact"),
        validation_gate=payload.get("validation_gate"),
        hunter_intelligence=payload.get("hunter_intelligence"),
        evidence_support_summary=_evidence_support_summary(record),
        safety_gate_summary=(
            payload.get("safety_gate_summary")
            if isinstance(payload.get("safety_gate_summary"), dict)
            else {}
        ),
        audit_gate_summary=(
            payload.get("audit_gate_summary")
            if isinstance(payload.get("audit_gate_summary"), dict)
            else {}
        ),
        timeline_stage_summary=(
            payload.get("timeline_stage_summary")
            if isinstance(payload.get("timeline_stage_summary"), list)
            else []
        ),
        closed_loop_summary=(
            _closed_loop_summary(record, repository)
            if repository is not None
            else None
        ),
    )


def _pipeline_run_detail(
    record: PipelineRunRecord,
    repository: DatabaseRepository,
) -> MythosPipelineRunDetail:
    summary = _pipeline_run_summary(record, repository)
    payload = _pipeline_run_detail_payload(record, repository)
    return MythosPipelineRunDetail(
        id=summary.id,
        program_id=summary.program_id,
        asset=summary.asset,
        policy_text_hash=summary.policy_text_hash,
        scope_status=summary.scope_status,
        hypothesis_count=summary.hypothesis_count,
        blocked_count=summary.blocked_count,
        evidence_count=summary.evidence_count,
        report_title=summary.report_title,
        created_at=summary.created_at,
        timeline=summary.timeline,
        artifact=summary.artifact,
        validation_gate=summary.validation_gate,
        hunter_intelligence=summary.hunter_intelligence,
        evidence_support_summary=summary.evidence_support_summary,
        closed_loop_summary=summary.closed_loop_summary,
        payload=payload,
    )


def _count_evidence_items(payload: dict) -> int:
    evidence_bundle = payload.get("evidence_bundle")
    if not isinstance(evidence_bundle, dict):
        return 0
    items = evidence_bundle.get("items")
    return len(items) if isinstance(items, list) else 0


def _safe_string_list(value: object) -> list[str]:
    return safe_string_list(value)


def _read_source_audit_policy_text(scope_path: str) -> str:
    try:
        return Path(scope_path).read_text(encoding="utf-8-sig")
    except OSError:
        return "source audit scope policy unavailable"
