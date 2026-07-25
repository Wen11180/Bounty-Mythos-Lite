"""Pydantic request/response models for all API routes.

Extracted from main.py so that router modules and response builders can import
them without creating circular dependencies. No business logic lives here.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.bounty_autopilot.observations import AutopilotObservationInput
from app.llm.base import ProviderName
from app.mythos_brain import (
    LearningEvidenceQuality,
    LearningOutcome,
    LearningSeverityDelta,
)
from app.mythos_pipeline import PipelineArtifactSummary, PipelineStage, PipelineValidationGate
from app.hunter_intelligence import HunterIntelligence
from app.scope_guard import ScopeGuardDecision, ScopeGuardRule, ValidationRequest

# ---------------------------------------------------------------------------
# Scope guard
# ---------------------------------------------------------------------------

class ScopeGuardEvaluationRequest(BaseModel):
    rule: ScopeGuardRule | None = None
    request: ValidationRequest
    campaign_id: str | None = None
    task_id: str | None = None
    run_id: str | None = None


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Source audit
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Artifact
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Campaign budget
# ---------------------------------------------------------------------------

class CampaignBudgetRequest(BaseModel):
    time_budget_minutes: int | None = Field(default=None, ge=0)
    token_budget: int | None = Field(default=None, ge=0)
    tool_call_budget: int | None = Field(default=None, ge=0)
    validation_budget: int | None = Field(default=None, ge=0)


class CampaignBudgetResponse(BaseModel):
    id: str
    campaign_id: str
    time_budget_minutes: int | None = None
    time_budget_used_minutes: float = 0
    time_budget_remaining_minutes: float | None = None
    token_budget: int | None = None
    token_budget_used: int = 0
    token_budget_remaining: int | None = None
    tool_call_budget: int | None = None
    tool_call_used: int = 0
    tool_call_remaining: int | None = None
    validation_budget: int | None = None
    validation_budget_used: int = 0
    validation_budget_remaining: int | None = None
    status: str
    created_at: str


# ---------------------------------------------------------------------------
# Campaign
# ---------------------------------------------------------------------------

class AuthorizedCodeFileRequest(BaseModel):
    path: str = Field(min_length=1, max_length=500)
    content: str = Field(min_length=1, max_length=20000)


class AuthorizedApiArtifactRequest(BaseModel):
    kind: str = Field(min_length=1, max_length=50)
    source_name: str | None = Field(default=None, max_length=255)
    payload: dict[str, Any]


class CampaignCreateRequest(BaseModel):
    program_id: str | None = None
    name: str = Field(min_length=1, max_length=255)
    autonomy_level: str = Field(min_length=1, max_length=100)
    scope_status: str = Field(min_length=1, max_length=50)
    policy_text: str = Field(min_length=1)
    default_asset: str = Field(min_length=1, max_length=255)
    target_classes: list[str] = Field(default_factory=list, max_length=50)
    allowed_tools: list[str] = Field(default_factory=list, max_length=50)
    authorized_code_files: list[AuthorizedCodeFileRequest] = Field(
        default_factory=list, max_length=20,
    )
    authorized_api_artifacts: list[AuthorizedApiArtifactRequest] = Field(
        default_factory=list, max_length=10,
    )
    created_by: str = Field(default="operator", min_length=1, max_length=255)
    budget: CampaignBudgetRequest | None = None
    campaign_mode: Literal["legacy", "bounty_autopilot"] = "legacy"
    autopilot_authorization: dict[str, Any] | None = None


class CampaignResponse(BaseModel):
    id: str
    program_id: str | None = None
    name: str
    status: str
    campaign_mode: str = "legacy"
    autonomy_level: str
    scope_status: str
    policy_text_hash: str
    default_asset: str
    target_classes: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)
    created_by: str
    created_at: str
    budget: CampaignBudgetResponse | None = None
    current_authorization_digest: str | None = None


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
    campaign_id: str
    task_id: str | None = None
    agent_type: str
    status: str
    input_refs: list[str] = Field(default_factory=list)
    output_refs: list[str] = Field(default_factory=list)
    safety_gate_state: str
    stop_reason: str | None = None
    created_at: str
    finished_at: str | None = None


class PipelineStageResponse(BaseModel):
    id: str
    pipeline_run_id: str
    campaign_id: str | None = None
    task_id: str | None = None
    stage_key: str
    stage_order: int
    status: str
    input_refs: list[str] = Field(default_factory=list)
    output_refs: list[str] = Field(default_factory=list)
    safety_gate_state: str
    stop_reason: str | None = None
    duration_seconds: int | None = None
    error_summary: str | None = None
    payload: dict = Field(default_factory=dict)
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


# ---------------------------------------------------------------------------
# Approval records
# ---------------------------------------------------------------------------

ApprovalDecisionValue = Literal["approved", "denied", "revoked", "expired", "used"]


class ApprovalRecordRequest(BaseModel):
    run_id: str | None = None
    program_id: str | None = None
    asset: str | None = None
    validation_mode: str | None = None
    plan_digest: str | None = None
    expires_at: datetime | None = None
    requester: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=1000)


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


# ---------------------------------------------------------------------------
# Autopilot
# ---------------------------------------------------------------------------

class AutopilotValidationPlanRequest(BaseModel):
    plan: dict[str, Any]


class AutopilotLeaseIssueRequest(BaseModel):
    plan_id: str = Field(min_length=1, max_length=128)
    lease_id: str | None = Field(default=None, max_length=128)
    authorization_digest: str = Field(min_length=1, max_length=100)
    scope_snapshot_digest: str = Field(min_length=1, max_length=100)
    authorization_recipe_allowed: bool = False
    policy_mode: str = Field(default="authorized_local_lab", min_length=1, max_length=64)
    approval_id: str | None = Field(default=None, max_length=128)


class AutopilotRequestReserveRequest(BaseModel):
    lease_id: str = Field(min_length=1, max_length=128)
    reservation: dict[str, Any]


class AutopilotRequestCompleteRequest(BaseModel):
    reservation_id: str = Field(min_length=1, max_length=128)
    outcome: str = Field(min_length=1, max_length=64)


class AutopilotGatewayAuthorizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lease_id: str = Field(min_length=1, max_length=128)
    reservation_id: str | None = Field(default=None, min_length=1, max_length=128)
    method: str = Field(min_length=1, max_length=16)
    scheme: str = Field(min_length=1, max_length=16)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    path: str = Field(min_length=1, max_length=1024)
    body_digest: str | None = None
    mutation_class: str = Field(default="none", max_length=64)


class AutopilotEmergencyStopRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: str = Field(default="operator", min_length=1, max_length=255)
    reason: str = Field(default="emergency_stop", min_length=1, max_length=512)
    confirmation_nonce: str | None = Field(default=None, min_length=16, max_length=256)


class AutopilotEmergencyStopPrepareRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    actor: str = Field(default="operator", min_length=1, max_length=255)
    reason: str = Field(default="emergency_stop", min_length=1, max_length=512)


class AutopilotApprovalDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approved", "denied"]
    actor: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=1, max_length=512)


class AutopilotSteeringRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    branch_id: str = Field(min_length=1, max_length=128)
    priority: int | None = Field(default=None, ge=0, le=100)
    hypothesis_guidance: str | None = Field(default=None, max_length=512)
    actor: str = Field(default="operator", min_length=1, max_length=255)
    reason: str = Field(default="operator_steering", min_length=1, max_length=256)


class AutopilotObservationCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    observation: AutopilotObservationInput


class AutopilotSteerRequest(BaseModel):
    directive: str = Field(min_length=1, max_length=64)
    branch_id: str | None = Field(default=None, max_length=128)
    reason: str = Field(default="operator_steer", min_length=1, max_length=256)
    emergency_stopped: bool = False
    policy_drift: bool = False
    branches: list[dict[str, Any]] = Field(default_factory=list)
    admitted_asset_ids: list[str] = Field(default_factory=list)
    campaign_max_requests: int = Field(default=20, ge=1, le=10000)
    campaign_max_time_seconds: int = Field(default=600, ge=1, le=86400)
    campaign_max_cost_units: int = Field(default=20, ge=1, le=10000)


class AutonomousWakeupCampaignResponse(BaseModel):
    id: str
    autonomy_level: str
    scope_status: str
    status: str


class AutonomousWakeupRunResponse(BaseModel):
    status: Literal["accepted", "completed", "failed", "lease_held", "lease_lost", "not_due"]
    stop_reason: Literal[
        "wakeup_accepted", "wakeup_candidate_invalid", "wakeup_candidate_query_failed",
        "wakeup_campaign_tick_failed", "wakeup_lease_held", "wakeup_lease_lost", "wakeup_not_due",
    ] | None = None
    processed_count: int = Field(ge=0, le=20)
    outcome_counts: dict[str, int] = Field(default_factory=dict)
    execution_allowed: Literal[False] = False
    dispatch_allowed: Literal[False] = False
    validation_allowed: Literal[False] = False
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False


# ---------------------------------------------------------------------------
# Campaign control center
# ---------------------------------------------------------------------------

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
    top_candidate_rank: int | None = Field(default=None, ge=1, le=5)
    priority_score: int = Field(ge=0, le=100)
    raw_priority_score: int | None = Field(default=None, ge=0, le=100)
    quality_gate_reasons: list[str] = Field(default_factory=list)
    evidence_needed: list[str] = Field(default_factory=list)
    required_evidence: list[str] = Field(default_factory=list)
    satisfied_evidence: list[str] = Field(default_factory=list)
    evidence_trace_summary: dict[str, Any] = Field(default_factory=dict)
    report_readiness: dict[str, Any] = Field(default_factory=dict)
    safety_gate: str
    next_allowed_action: str
    execution_allowed: bool = False


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


class CampaignPromotionReviewSummary(BaseModel):
    blocked_attempt_count: int = 0
    finding_promotion_allowed: bool = False
    latest_reason: str | None = None
    next_allowed_action: str = "Review claim evidence and human gates before candidate promotion."
    provenance_ref_count: int = 0
    report_submission_allowed: bool = False
    required_evidence_blocked_count: int = 0
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


# ---------------------------------------------------------------------------
# Brain / learning
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Campaign lifecycle
# ---------------------------------------------------------------------------

class CampaignCycleReviewCompletionRequest(BaseModel):
    actor: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=1000)


class AutonomousValidationHandoffReviewRequest(BaseModel):
    decision: Literal["accepted_for_manual_follow_up", "dismissed"]
    reviewer: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=1000)
    validation_mode: str | None = Field(default=None, min_length=1, max_length=100)


class AutonomousReportRevisionRequest(BaseModel):
    reviewer: str = Field(min_length=1, max_length=100)
    rationale: str = Field(min_length=1, max_length=1000)


# ---------------------------------------------------------------------------
# Research / refutation
# ---------------------------------------------------------------------------

ResearchRefutationDecisionValue = Literal[
    "refuted", "needs_evidence", "needs_validation_review",
    "parked_duplicate", "policy_blocked",
]
ValidationFeedbackReviewDecisionValue = Literal["allow_finding_promotion"]


class ResearchQueueTaskRequest(BaseModel):
    queue_key: str = Field(min_length=1, max_length=255)
    requester: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=1000)


class ResearchReviewPlanRequest(BaseModel):
    reviewer: str = Field(min_length=1, max_length=100)
    rationale: str = Field(default="", max_length=1000)
    hypothesis: str = Field(min_length=1, max_length=1000)
    refutation_questions: list[str] = Field(default_factory=list, max_length=10)
    evidence_plan: list[str] = Field(default_factory=list, max_length=10)


class ResearchRefutationDecisionRequest(BaseModel):
    plan_id: str = Field(min_length=1, max_length=255)
    reviewer: str = Field(min_length=1, max_length=100)
    decision: ResearchRefutationDecisionValue
    rationale: str = Field(min_length=1, max_length=1000)
    refutation_answers: list[str] = Field(default_factory=list, max_length=10)
    validation_mode: str | None = Field(default=None, max_length=100)
    target_ref: str | None = Field(default=None, max_length=1000)


class ValidationFeedbackReviewRequest(BaseModel):
    reviewer: str = Field(min_length=1, max_length=100)
    decision: ValidationFeedbackReviewDecisionValue
    rationale: str = Field(min_length=1, max_length=1000)


class ValidationRunManualOutcome(str):
    pass


ValidationRunManualOutcomeType = Literal["observed", "refuted", "needs_more_evidence"]


class ValidationRunManualResultRequest(BaseModel):
    outcome: ValidationRunManualOutcomeType
    reviewer: str = Field(min_length=1, max_length=100)
    summary: str = Field(min_length=1, max_length=1000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)


ManualObservationType = Literal[
    "manual_observation", "role_matrix_observation",
    "request_response_diff", "redaction_note",
]
REPORT_SAFE_REVIEW_EVIDENCE_REFS = {
    "local_code_reference", "log_ref", "request_response_diff",
    "sanitized_cross_account_diff", "sanitized_parent_child_matrix",
    "role_matrix_snapshot", "sanitized_request_response",
    "sanitized_role_matrix", "screenshot_ref",
}


class ManualObservationRequest(BaseModel):
    claim_id: str
    observation_type: ManualObservationType = "manual_observation"
    observer: str = Field(min_length=1, max_length=100)
    observation: str = Field(min_length=1, max_length=1000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
    safety_notes: list[str] = Field(default_factory=list, max_length=20)


class ClaimReviewDecisionRequest(BaseModel):
    claim_id: str
    decision: Any  # ClaimReviewDecisionValue from mythos_report
    reviewer: str = Field(min_length=1, max_length=100)
    rationale: str = Field(default="", max_length=1000)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)
