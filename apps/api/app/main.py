from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
from pathlib import Path
from threading import RLock
from typing import Any, Literal
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.artifact_ingestion import normalize_artifact
from app.black_box_hunter import BlackBoxExecutionLease, BlackBoxStop, LeaseApproval
from app.black_box_hunter.audit import (
    BlackBoxAuditError,
    BlackBoxAuditProjection,
    BlackBoxBoundedResultRequest,
    load_black_box_audit_projection,
    record_black_box_bounded_result,
)
from app.black_box_hunter.field_pilot import (
    FieldPilotFeedbackError,
    FieldPilotFeedbackRequest,
    FieldPilotFeedbackResponse,
    FieldPilotStatus,
    evaluate_field_pilot_status,
    field_pilot_entries,
    record_field_pilot_feedback,
)
from app.black_box_hunter.remote_profile import (
    RemoteAuthorizationDecision,
    RemoteHumanLease,
    RemoteLeaseRuntime,
    RemoteRequestAuthorization,
    RemoteWorkflowLease,
    issue_remote_human_lease,
)
from app.config import get_settings
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
from app.campaign_orchestrator import (
    campaign_elapsed_minutes,
    campaign_token_used_from_runs,
    tick_campaign,
)
from app.candidate_hunter_loop import (
    build_candidate_hunter_observations,
    load_candidate_hunter_projection,
    run_candidate_hunter_loop,
)
from app.cross_source_candidate_generator import (
    CandidateModelConfig,
    CandidateReasoner,
    RegistryCandidateReasoner,
    build_fact_pack,
    candidate_hunter_inputs,
    generation_stage_payload,
    generate_cross_source_candidates,
)
from app.hunter_intelligence import (
    HunterIntelligence,
)
from app.intelligence_benchmark import (
    build_studio_expectations_template,
    evaluate_studio_candidates,
)
from app.llm.base import LLMRequest, LLMResponse, ProviderName
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
from app.policy_ingestion import parse_policy_text
from app.program_rule_intake.advisory import build_configured_program_rule_advisory
from app.program_rule_intake.contracts import (
    NormalizedRuleDocument,
    ProgramRuleClaimCompleteRequest,
    ProgramRuleClaimFailRequest,
    ProgramRuleClaimNextResult,
    ProgramRuleClaimNormalizeRequest,
    ProgramRuleRegistrationRequest,
    ProgramRuleSnapshotDiff,
    ProgramRuleSnapshotProjection,
    ProgramRuleSourceProjection,
    ProgramScopeRuleProjection,
    SnapshotReviewRequest,
)
from app.program_rule_intake.service import (
    ProgramRuleBrowserRenderRequired,
    ProgramRuleClaimRejected,
    ProgramRuleConflict,
    ProgramRuleCooldown,
    ProgramRuleIntakeError,
    ProgramRuleIntakeService,
    ProgramRuleNotFound,
    ProgramRuleValidationError,
)
from app.mythos_report import (
    ClaimLedgerEntry,
    ClaimReviewDecisionValue,
    ClaimReviewDecisionResponse,
    ReportPreviewResponse,
    best_finding_candidate_claim,
    build_black_box_report_review_packet,
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
from app.studio_workspace import (
    StudioArtifactImport,
    StudioWorkspaceAccessError,
    create_workspace,
    import_workspace_artifact,
    load_workspace_manifest,
    record_workspace_benchmark_result,
    record_workspace_benchmark_template,
    record_workspace_campaign_hunter_report_export,
    record_workspace_campaign_hunter_run,
    record_workspace_mission_dossier,
    record_workspace_report_export,
    record_workspace_run,
    resolve_configured_workspace_artifact,
    resolve_workspace_file,
)
from app.worker.tasks import dispatch_agent_task
from app.residual_patch_decision_api import (
    ResidualPatchDecisionApiError,
    ResidualPatchDecisionApply,
    ResidualPatchDecisionCreate,
    ResidualPatchDecisionView,
    create_residual_patch_decision,
    decide_residual_patch_decision,
    get_residual_patch_decision,
    list_residual_patch_decisions,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator


def _studio_web_origin() -> str | None:
    raw_origin = get_settings().studio_web_origin.strip()
    parsed = urlparse(raw_origin)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost"}
        or parsed.path not in {"", "/"}
    ):
        return None
    return raw_origin.rstrip("/")


app = FastAPI(title="Bounty Mythos-Lite API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin] if (origin := _studio_web_origin()) is not None else [],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type"],
)


@app.exception_handler(StudioWorkspaceAccessError)
async def studio_workspace_access_error_handler(_, exc: StudioWorkspaceAccessError):
    return JSONResponse(status_code=403, content={"detail": str(exc)})


@app.exception_handler(RequestValidationError)
async def request_validation_error_handler(request: Request, exc: RequestValidationError):
    if request.url.path.startswith((
        "/program-rule-sources",
        "/mythos/studio/program-rule-fetch/",
    )):
        return JSONResponse(
            status_code=422,
            content={"detail": "Program rule request is invalid"},
        )
    return await request_validation_exception_handler(request, exc)


class ScopeGuardEvaluationRequest(BaseModel):
    rule: ScopeGuardRule | None = None
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


class StudioWorkspaceCreateRequest(BaseModel):
    root_path: str = Field(min_length=1)
    name: str = Field(min_length=1, max_length=255)


class StudioArtifactImportRequest(BaseModel):
    workspace_path: str = Field(min_length=1)
    kind: str = Field(min_length=1, max_length=50)
    source_path: str = Field(min_length=1)


class StudioCandidateModelRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = False
    provider: ProviderName | None = None
    model: str | None = Field(default=None, max_length=255)

    @model_validator(mode="after")
    def validate_enabled_configuration(self):
        if self.enabled:
            if self.provider is None or self.model is None or not self.model.strip():
                raise ValueError("enabled candidate model requires provider and model")
        elif self.provider is not None or self.model is not None:
            raise ValueError("disabled candidate model cannot include provider or model")
        return self


_STUDIO_BLACK_BOX_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}
_STUDIO_BLACK_BOX_SENSITIVE_MARKERS = {
    "authorization",
    "cookie",
    "credential",
    "password",
    "secret",
    "token",
}
_STUDIO_BLACK_BOX_METHODS_BY_ACTION = {
    "read_only_replay": {"GET", "HEAD"},
    "reversible_update": {"PATCH", "PUT"},
    "test_object_create": {"POST"},
}


def _studio_black_box_safe_alias(value: str) -> str:
    normalized = value.strip()
    if (
        value != normalized
        or not 1 <= len(value) <= 64
        or not value[0].isalpha()
        or any(not (character.isalnum() or character in {"_", "-"}) for character in value)
        or any(marker in value.lower() for marker in _STUDIO_BLACK_BOX_SENSITIVE_MARKERS)
    ):
        raise ValueError("safe_lab_alias_required")
    return value


def _studio_black_box_loopback_origin(value: str) -> str:
    parsed = urlparse(value)
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("loopback_origin_required") from exc
    if (
        parsed.scheme != "http"
        or parsed.hostname not in _STUDIO_BLACK_BOX_LOOPBACK_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.params
        or parsed.query
        or parsed.fragment
        or value != f"{parsed.scheme}://{parsed.netloc}"
    ):
        raise ValueError("loopback_origin_required")
    return value


def _studio_black_box_route_template(value: str) -> str:
    segments = value.split("/")[1:] if value.startswith("/") else []
    if (
        not segments
        or value != f"/{'/'.join(segments)}"
        or value.count("{object}") != 1
        or any(marker in value for marker in {"?", "#", "\\", "%"})
        or any(
            segment != "{object}"
            and (
                not segment
                or not segment[0].isalpha()
                or len(segment) > 64
                or any(
                    not (character.isalnum() or character in {"_", "-"})
                    for character in segment
                )
                or any(
                    marker in segment.lower()
                    for marker in _STUDIO_BLACK_BOX_SENSITIVE_MARKERS
                )
            )
            for segment in segments
        )
    ):
        raise ValueError("normalized_route_template_required")
    return value


class StudioBlackBoxLabSessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_alias: str = Field(min_length=1, max_length=64)
    account_alias: str = Field(min_length=1, max_length=64)
    role_alias: str = Field(min_length=1, max_length=64)
    ready: bool = False

    @model_validator(mode="after")
    def validate_safe_aliases(self):
        self.session_alias = _studio_black_box_safe_alias(self.session_alias)
        self.account_alias = _studio_black_box_safe_alias(self.account_alias)
        self.role_alias = _studio_black_box_safe_alias(self.role_alias)
        return self


class StudioBlackBoxLabWorkflowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workflow_alias: str = Field(min_length=1, max_length=64)
    session_alias: str = Field(min_length=1, max_length=64)
    origin: str = Field(min_length=1, max_length=255)
    route_template: str = Field(min_length=1, max_length=1024)
    method: str = Field(min_length=1, max_length=16)
    action: str = Field(min_length=1, max_length=64)
    object_aliases: list[str]

    @model_validator(mode="after")
    def validate_safe_workflow(self):
        self.workflow_alias = _studio_black_box_safe_alias(self.workflow_alias)
        self.session_alias = _studio_black_box_safe_alias(self.session_alias)
        self.origin = _studio_black_box_loopback_origin(self.origin)
        self.route_template = _studio_black_box_route_template(self.route_template)
        self.method = self.method.upper()
        if self.method not in _STUDIO_BLACK_BOX_METHODS_BY_ACTION.get(self.action, set()):
            raise ValueError("safe_lab_workflow_action_required")
        if (
            not 1 <= len(self.object_aliases) <= 20
            or len(set(self.object_aliases)) != len(self.object_aliases)
        ):
            raise ValueError("safe_lab_object_aliases_required")
        self.object_aliases = [
            _studio_black_box_safe_alias(alias) for alias in self.object_aliases
        ]
        return self


class StudioBlackBoxLabLeasePreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    active_origin: str = Field(min_length=1, max_length=255)
    sessions: list[StudioBlackBoxLabSessionRequest]
    workflows: list[StudioBlackBoxLabWorkflowRequest]

    @model_validator(mode="after")
    def validate_bounded_local_lab(self):
        self.active_origin = _studio_black_box_loopback_origin(self.active_origin)
        if len(self.sessions) != 2:
            raise ValueError("exactly_two_lab_sessions_required")
        if not 1 <= len(self.workflows) <= 3:
            raise ValueError("one_to_three_lab_workflows_required")
        session_aliases = [session.session_alias for session in self.sessions]
        if set(session_aliases) != {"session_a", "session_b"}:
            raise ValueError("independent_lab_session_aliases_required")
        if len({session.account_alias for session in self.sessions}) != 2:
            raise ValueError("independent_lab_accounts_required")
        workflow_aliases = [workflow.workflow_alias for workflow in self.workflows]
        if len(set(workflow_aliases)) != len(workflow_aliases):
            raise ValueError("unique_lab_workflow_aliases_required")
        if any(
            workflow.origin != self.active_origin
            or workflow.session_alias not in session_aliases
            for workflow in self.workflows
        ):
            raise ValueError("lab_workflow_lease_mismatch")
        return self


class StudioBlackBoxLabLeasePreviewResponse(BaseModel):
    profile: Literal["local_lab"] = "local_lab"
    active_origin: str
    session_aliases: list[str]
    workflow_aliases: list[str]
    sessions_ready: bool
    trace_review_required: bool = True
    human_approval_required: bool = True
    execution_allowed: bool = False
    persist_session_state: bool = False
    blocked_actions: list[str]


class StudioBlackBoxLabTraceReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workflow_alias: str = Field(min_length=1, max_length=64)
    session_alias: str = Field(min_length=1, max_length=64)
    route_template: str = Field(min_length=1, max_length=1024)
    response_schema_fingerprint: str = Field(min_length=71, max_length=71)
    redacted: bool

    @model_validator(mode="after")
    def validate_safe_trace(self):
        self.workflow_alias = _studio_black_box_safe_alias(self.workflow_alias)
        self.session_alias = _studio_black_box_safe_alias(self.session_alias)
        self.route_template = _studio_black_box_route_template(self.route_template)
        digest = self.response_schema_fingerprint.removeprefix("sha256:")
        if (
            not self.response_schema_fingerprint.startswith("sha256:")
            or len(digest) != 64
            or digest != digest.lower()
            or any(character not in "0123456789abcdef" for character in digest.lower())
        ):
            raise ValueError("safe_trace_fingerprint_required")
        if not self.redacted:
            raise ValueError("redacted_trace_required")
        return self


class StudioBlackBoxLabRunApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    validation_run_id: str = Field(min_length=1, max_length=100)
    lease_preview: StudioBlackBoxLabLeasePreviewRequest
    trace_review: list[StudioBlackBoxLabTraceReviewRequest]
    operator_confirmed: bool = False

    @model_validator(mode="after")
    def validate_trace_review_bound(self):
        if not 1 <= len(self.trace_review) <= 3:
            raise ValueError("one_to_three_reviewed_traces_required")
        return self


class StudioBlackBoxLabRunApprovalResponse(BaseModel):
    approval_status: Literal["approved"] = "approved"
    validation_run_id: str
    approval_id: str
    lease_digest: str
    local_runner_dispatch_allowed: bool = True
    execution_allowed: bool = False
    report_submission_allowed: bool = False
    reason: Literal["bounded_local_lab_run_approved"] = "bounded_local_lab_run_approved"


def build_studio_black_box_lab_lease_preview(
    request: StudioBlackBoxLabLeasePreviewRequest,
) -> StudioBlackBoxLabLeasePreviewResponse:
    return StudioBlackBoxLabLeasePreviewResponse(
        active_origin=request.active_origin,
        session_aliases=[session.session_alias for session in request.sessions],
        workflow_aliases=[workflow.workflow_alias for workflow in request.workflows],
        sessions_ready=all(session.ready for session in request.sessions),
        blocked_actions=[
            "remote_origin",
            "credential_input",
            "session_persistence",
            "automatic_report_submission",
        ],
    )


class StudioBlackBoxRemoteLeaseIssueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    validation_run_id: str = Field(min_length=1, max_length=100)
    active_origin: str = Field(min_length=1, max_length=255)
    passive_origins: list[str] = Field(default_factory=list, max_length=10)
    account_aliases: list[str] = Field(min_length=2, max_length=2)
    role_aliases: list[str] = Field(min_length=1, max_length=10)
    allowed_actions: list[str] = Field(min_length=1, max_length=3)
    request_budget_per_workflow: int = Field(default=50, ge=1, le=50)
    duration_seconds: int = Field(default=1800, ge=1, le=1800)
    min_interval_seconds: int = Field(default=3, ge=3)
    workflows: list[RemoteWorkflowLease] = Field(min_length=1, max_length=3)
    operator_confirmed: bool = False

    @model_validator(mode="after")
    def require_bounded_remote_authority(self):
        self.active_origin = _studio_black_box_remote_exact_origin(self.active_origin)
        self.passive_origins = [
            _studio_black_box_remote_exact_origin(origin)
            for origin in self.passive_origins
        ]
        if (
            len(set(self.passive_origins)) != len(self.passive_origins)
            or self.active_origin in self.passive_origins
        ):
            raise ValueError("unique_remote_origins_required")
        for aliases in (self.account_aliases, self.role_aliases):
            if len(set(aliases)) != len(aliases):
                raise ValueError("unique_remote_aliases_required")
            for alias in aliases:
                _studio_black_box_safe_alias(alias)
        if len(set(self.allowed_actions)) != len(self.allowed_actions):
            raise ValueError("unique_remote_actions_required")
        workflow_actions = {workflow.action for workflow in self.workflows}
        if set(self.allowed_actions) != workflow_actions:
            raise ValueError("recorded_remote_actions_required")
        if any(
            workflow.origin != self.active_origin
            or workflow.source_account_alias not in self.account_aliases
            or workflow.object_owner_alias not in self.account_aliases
            or workflow.source_role_alias not in self.role_aliases
            for workflow in self.workflows
        ):
            raise ValueError("remote_workflow_lease_mismatch")
        return self


class StudioBlackBoxRemoteLeaseIssueResponse(RemoteHumanLease):
    remote_runner_dispatch_allowed: Literal[True] = True
    relogin_required: Literal[False] = False


class StudioBlackBoxRemoteStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile: Literal["remote_human_lease"] = "remote_human_lease"
    enabled: bool
    state: Literal[
        "disabled",
        "awaiting_lease",
        "active",
        "stopped",
        "expired",
        "relogin_required",
    ]
    expires_at: str | None = None
    relogin_required: bool
    stop_reason: str | None = None
    report_submission_allowed: Literal[False] = False
    human_confirmation_allowed: Literal[False] = False


class StudioBlackBoxRemoteCompletionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_grant_id: str = Field(
        min_length=1,
        max_length=100,
        pattern=r"^remote_grant_[0-9a-f]{32}$",
    )
    outcome: Literal[
        "success",
        "rate_limited",
        "captcha_or_waf_detected",
        "off_origin_redirect",
        "third_party_data_detected",
        "test_owned_object_required",
        "ambiguous_authority",
        "rollback_failed",
        "server_error",
        "unstable_response",
        "session_expired",
        "request_failed",
    ]


class StudioBlackBoxRemoteStopRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def require_known_terminal_stop(self):
        BlackBoxStop(reason=self.reason)
        return self


@dataclass
class _StudioBlackBoxRemoteRuntimeEntry:
    runtime: RemoteLeaseRuntime
    validation_run_id: str
    approval_id: str


@dataclass(frozen=True)
class _StudioBlackBoxRemoteStoppedState:
    reason: str
    expires_at: str


_STUDIO_BLACK_BOX_REMOTE_RUNTIMES: dict[
    str,
    _StudioBlackBoxRemoteRuntimeEntry,
] = {}
_STUDIO_BLACK_BOX_REMOTE_STOPS: dict[
    str,
    _StudioBlackBoxRemoteStoppedState,
] = {}
_STUDIO_BLACK_BOX_REMOTE_ISSUE_LOCK = RLock()


def _studio_black_box_remote_now() -> datetime:
    return datetime.now(UTC)


def _studio_black_box_remote_reset_for_tests() -> None:
    with _STUDIO_BLACK_BOX_REMOTE_ISSUE_LOCK:
        _STUDIO_BLACK_BOX_REMOTE_RUNTIMES.clear()
        _STUDIO_BLACK_BOX_REMOTE_STOPS.clear()


def _studio_black_box_remote_exact_origin(value: str) -> str:
    parsed = urlparse(value)
    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("exact_https_remote_origin_required") from exc
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.params
        or parsed.query
        or parsed.fragment
        or "*" in parsed.netloc
        or value != f"{parsed.scheme}://{parsed.netloc}"
    ):
        raise ValueError("exact_https_remote_origin_required")
    return value


def _studio_black_box_remote_digest(payload: dict) -> str:
    serialized = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return f"sha256:{sha256(serialized.encode('utf-8')).hexdigest()}"


def _studio_black_box_remote_policy_digest(campaign: CampaignRecord) -> str:
    digest = campaign.policy_text_hash.removeprefix("sha256:").lower()
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError("current_policy_digest_required")
    return f"sha256:{digest}"


def _studio_black_box_remote_scope_digest(campaign: CampaignRecord) -> str:
    rule = _campaign_scope_guard_rule(campaign)
    if rule is None:
        raise ValueError("current_scope_digest_required")
    return _studio_black_box_remote_digest(
        {
            "asset": campaign.default_asset,
            "allowed_tools": sorted(campaign.allowed_tools),
            "scope_guard_rule": rule.model_dump(mode="json"),
            "target_classes": sorted(campaign.target_classes),
        }
    )


def _studio_black_box_remote_plan_digest(
    request: StudioBlackBoxRemoteLeaseIssueRequest,
) -> str:
    return _studio_black_box_remote_digest(
        request.model_dump(
            mode="json",
            exclude={"validation_run_id", "operator_confirmed"},
        )
    )


def _studio_black_box_remote_as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _studio_black_box_remote_payload_matches(
    payload: object,
    *,
    request: StudioBlackBoxRemoteLeaseIssueRequest,
    policy_digest: str,
    scope_digest: str,
    plan_digest: str,
) -> bool:
    if not isinstance(payload, dict):
        return False
    allowed_accounts = payload.get("allowed_accounts")
    allowed_actions = payload.get("allowed_actions")
    return (
        payload.get("remote_human_lease") is True
        and payload.get("policy_digest") == policy_digest
        and payload.get("scope_digest") == scope_digest
        and payload.get("recorded_workflow_plan_digest") == plan_digest
        and isinstance(allowed_accounts, list)
        and all(isinstance(value, str) for value in allowed_accounts)
        and set(request.account_aliases) <= set(allowed_accounts)
        and isinstance(allowed_actions, list)
        and all(isinstance(value, str) for value in allowed_actions)
        and set(request.allowed_actions) <= set(allowed_actions)
    )


def _studio_black_box_remote_dedicated_approval(
    approval: ApprovalRecord | None,
    *,
    validation_run: ValidationRunRecord,
    request: StudioBlackBoxRemoteLeaseIssueRequest,
    policy_digest: str,
    scope_digest: str,
    plan_digest: str,
    now: datetime,
) -> bool:
    if approval is None:
        return False
    decided_at = _studio_black_box_remote_as_utc(approval.decided_at)
    expires_at = _studio_black_box_remote_as_utc(approval.expires_at)
    return (
        approval.id == validation_run.approval_id
        and approval.status == "approved"
        and approval.approval_type == "black_box_remote_lease"
        and approval.requested_action == "remote_black_box_differential"
        and approval.validation_mode == "black_box_differential"
        and approval.plan_digest == plan_digest
        and decided_at is not None
        and decided_at <= now
        and now - decided_at <= timedelta(minutes=30)
        and expires_at is not None
        and expires_at > now
        and _studio_black_box_remote_payload_matches(
            approval.payload,
            request=request,
            policy_digest=policy_digest,
            scope_digest=scope_digest,
            plan_digest=plan_digest,
        )
    )


def _studio_black_box_remote_origin_matches_asset(origin: str, asset: str) -> bool:
    parsed = urlparse(origin)
    return asset in {origin, parsed.netloc}


class StudioWorkspaceRunRequest(BaseModel):
    workspace_path: str = Field(min_length=1)
    candidate_model: StudioCandidateModelRequest | None = None


class StudioCampaignLaunchRequest(BaseModel):
    workspace_path: str = Field(min_length=1)
    program_id: str | None = None
    name: str | None = Field(default=None, max_length=255)
    default_asset: str | None = Field(default=None, max_length=255)


class StudioMissionExportRequest(BaseModel):
    workspace_path: str = Field(min_length=1)
    run_id: str | None = None


class StudioReportExportRequest(BaseModel):
    workspace_path: str = Field(min_length=1)
    run_id: str = Field(min_length=1)


class StudioCampaignHunterReportExportRequest(BaseModel):
    workspace_path: str = Field(min_length=1)
    campaign_id: str = Field(min_length=1)


class StudioBenchmarkRunRequest(BaseModel):
    workspace_path: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    expectations_path: str = Field(min_length=1)


class StudioBenchmarkTemplateRequest(BaseModel):
    workspace_path: str = Field(min_length=1)
    run_id: str = Field(min_length=1)


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
        default_factory=list,
        max_length=20,
    )
    authorized_api_artifacts: list[AuthorizedApiArtifactRequest] = Field(
        default_factory=list,
        max_length=10,
    )
    created_by: str = Field(default="operator", min_length=1, max_length=255)
    budget: CampaignBudgetRequest | None = None


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
    evidence_needed: list[str] = Field(default_factory=list)
    required_evidence: list[str] = Field(default_factory=list)
    satisfied_evidence: list[str] = Field(default_factory=list)
    evidence_trace_summary: dict[str, Any] = Field(default_factory=dict)
    report_readiness: dict[str, Any] = Field(default_factory=dict)
    raw_priority_score: int | None = Field(default=None, ge=0, le=100)
    quality_gate_reasons: list[str] = Field(default_factory=list)
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
    scope_guard_rule = parse_policy_text(request.policy_text, request.default_asset)
    payload = _campaign_create_payload(request)
    payload["scope_guard_rule"] = scope_guard_rule.model_dump(mode="json")
    campaign = repository.create_campaign(
        program_id=request.program_id,
        name=request.name,
        autonomy_level=request.autonomy_level,
        scope_status=scope_guard_rule.scope_status,
        policy_text=request.policy_text,
        default_asset=request.default_asset,
        target_classes=request.target_classes,
        allowed_tools=request.allowed_tools,
        created_by=request.created_by,
        payload=payload,
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


def _campaign_create_payload(request: CampaignCreateRequest) -> dict:
    payload: dict[str, object] = {"source": "campaign_api"}
    if request.authorized_code_files:
        payload["authorized_code_files"] = [
            {
                "path": code_file.path,
                "content": code_file.content,
            }
            for code_file in request.authorized_code_files
        ]
    if request.authorized_api_artifacts:
        payload["authorized_api_artifacts"] = [
            {
                "kind": artifact.kind,
                "source_name": artifact.source_name,
                "payload": artifact.payload,
            }
            for artifact in request.authorized_api_artifacts
        ]
    return payload


def _campaign_scope_guard_rule(campaign: CampaignRecord) -> ScopeGuardRule | None:
    payload = campaign.payload if isinstance(campaign.payload, dict) else {}
    stored_rule = payload.get("scope_guard_rule")
    if not isinstance(stored_rule, dict):
        return None
    try:
        return ScopeGuardRule.model_validate(stored_rule)
    except ValueError:
        return None


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
    campaign = repository.get_campaign(campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    if campaign.scope_status != "in_scope":
        raise HTTPException(status_code=409, detail="scope_not_in_scope")
    scope_guard_rule = _campaign_scope_guard_rule(campaign)
    if scope_guard_rule is None:
        raise HTTPException(status_code=409, detail="scope_guard_rule_missing")
    if scope_guard_rule.scope_status != "in_scope":
        raise HTTPException(status_code=409, detail="scope_not_in_scope")
    campaign = repository.update_campaign_status(campaign_id, "running") or campaign
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
    scope_guard_rule = _campaign_scope_guard_rule(campaign)
    if scope_guard_rule is None:
        raise HTTPException(status_code=409, detail="scope_guard_rule_missing")
    if scope_guard_rule.scope_status != "in_scope":
        raise HTTPException(status_code=409, detail="scope_not_in_scope")
    budget = repository.get_campaign_budget(campaign_id)
    if _campaign_budget_exhausted(
        budget,
        campaign=campaign,
        agent_runs=repository.list_campaign_agent_runs(campaign.id),
    ):
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
    if _campaign_budget_exhausted(
        repository.get_campaign_budget(campaign.id),
        campaign=campaign,
        agent_runs=repository.list_campaign_agent_runs(campaign.id),
    ):
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
        "top_candidate_rank": suggestion.top_candidate_rank,
        "priority_score": suggestion.priority_score,
        "evidence_needed": suggestion.evidence_needed,
        "evidence_trace_summary": suggestion.evidence_trace_summary,
        "report_readiness": suggestion.report_readiness,
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
    if _campaign_budget_exhausted(
        repository.get_campaign_budget(campaign.id),
        campaign=campaign,
        agent_runs=repository.list_campaign_agent_runs(campaign.id),
    ):
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
    if _campaign_budget_exhausted(
        campaign_budget,
        campaign=campaign,
        agent_runs=repository.list_campaign_agent_runs(campaign.id),
    ) or _campaign_validation_budget_exhausted(
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
        rule = _campaign_scope_guard_rule(campaign)
        if rule is None:
            decision = ScopeGuardDecision(
                allowed=False,
                reason="scope_guard_rule_missing",
            )
        else:
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


@app.post(
    "/mythos/black-box/validation-runs/{validation_run_id}/bounded-results",
    response_model=BlackBoxAuditProjection,
)
def record_black_box_bounded_result_api(
    validation_run_id: str,
    result: BlackBoxBoundedResultRequest,
    session: Session = Depends(get_session),
) -> BlackBoxAuditProjection:
    repository = DatabaseRepository(session)
    validation_run = repository.get_validation_run(validation_run_id)
    if validation_run is None:
        raise HTTPException(status_code=404, detail="Validation run not found")
    campaign = _validation_run_campaign_or_404_in_scope(repository, validation_run)
    _raise_if_validation_run_approval_not_active(
        repository=repository,
        validation_run=validation_run,
        campaign=campaign,
    )
    try:
        return record_black_box_bounded_result(
            repository=repository,
            validation_run_id=validation_run_id,
            plan_index=result.plan_index,
            evidence=result.evidence,
        )
    except BlackBoxAuditError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/mythos/black-box/validation-runs/{validation_run_id}/review-packet")
def get_black_box_review_packet(
    validation_run_id: str,
    session: Session = Depends(get_session),
) -> dict:
    repository = DatabaseRepository(session)
    validation_run = repository.get_validation_run(validation_run_id)
    if validation_run is None:
        raise HTTPException(status_code=404, detail="Validation run not found")
    campaign = _validation_run_campaign_or_404_in_scope(repository, validation_run)
    _raise_if_validation_run_approval_not_active(
        repository=repository,
        validation_run=validation_run,
        campaign=campaign,
    )
    try:
        projection = load_black_box_audit_projection(
            repository=repository,
            validation_run_id=validation_run_id,
        )
    except BlackBoxAuditError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if projection.status != "review_ready" or projection.candidate is None:
        raise HTTPException(status_code=409, detail="review_ready_candidate_required")
    try:
        return build_black_box_report_review_packet(projection.candidate)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post(
    "/mythos/black-box/field-pilot/feedback",
    response_model=FieldPilotFeedbackResponse,
)
def create_black_box_field_pilot_feedback(
    request: FieldPilotFeedbackRequest,
    session: Session = Depends(get_session),
) -> FieldPilotFeedbackResponse:
    repository = DatabaseRepository(session)
    _program_or_404_in_scope(repository, request.program_id)
    try:
        return record_field_pilot_feedback(
            repository=repository,
            request=request,
        )
    except FieldPilotFeedbackError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get(
    "/mythos/black-box/field-pilot/status",
    response_model=FieldPilotStatus,
)
def get_black_box_field_pilot_status(
    session: Session = Depends(get_session),
) -> FieldPilotStatus:
    repository = DatabaseRepository(session)
    return evaluate_field_pilot_status(
        field_pilot_entries(repository.list_all_learning_signals())
    )


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

    return _campaign_control_center_response(campaign, repository)


def _campaign_control_center_response(
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> CampaignControlCenterResponse:
    budget = repository.get_campaign_budget(campaign.id)
    tasks = repository.list_campaign_tasks(campaign.id)
    agent_runs = repository.list_campaign_agent_runs(campaign.id)
    approvals = repository.list_campaign_approval_records(campaign.id)
    validation_runs = repository.list_campaign_validation_runs(campaign.id)
    stages = repository.list_campaign_pipeline_stages(campaign.id)
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


def _program_rule_intake_service(session: Session) -> ProgramRuleIntakeService:
    settings = get_settings()
    return ProgramRuleIntakeService(
        DatabaseRepository(session),
        advisory_extractor=build_configured_program_rule_advisory(settings),
    )


def _raise_program_rule_http_error(error: ProgramRuleIntakeError) -> None:
    if isinstance(error, ProgramRuleCooldown):
        raise HTTPException(
            status_code=429,
            detail="Program rule manual refresh is cooling down",
            headers={"Retry-After": str(error.retry_after_seconds)},
        )
    if isinstance(error, ProgramRuleNotFound):
        raise HTTPException(status_code=404, detail="Program rule resource not found")
    if isinstance(error, ProgramRuleBrowserRenderRequired):
        raise HTTPException(status_code=422, detail="browser_render_required")
    if isinstance(error, ProgramRuleValidationError):
        raise HTTPException(status_code=422, detail="Program rule request is invalid")
    if isinstance(error, ProgramRuleClaimRejected):
        raise HTTPException(status_code=409, detail="Program rule claim is invalid")
    if isinstance(error, ProgramRuleConflict):
        raise HTTPException(status_code=409, detail="Program rule state conflict")
    raise HTTPException(status_code=400, detail="Program rule request failed")


@app.post(
    "/program-rule-sources",
    response_model=ProgramRuleSourceProjection,
    status_code=201,
)
def register_program_rule_source(
    request: ProgramRuleRegistrationRequest,
    session: Session = Depends(get_session),
) -> ProgramRuleSourceProjection:
    try:
        return _program_rule_intake_service(session).register_source(
            program_alias=request.program_alias,
            public_rule_url=request.public_rule_url,
        )
    except ProgramRuleIntakeError as error:
        _raise_program_rule_http_error(error)


@app.get(
    "/program-rule-sources",
    response_model=list[ProgramRuleSourceProjection],
)
def list_program_rule_sources(
    session: Session = Depends(get_session),
) -> list[ProgramRuleSourceProjection]:
    return _program_rule_intake_service(session).list_sources()


@app.get(
    "/program-rule-sources/{source_id}",
    response_model=ProgramRuleSourceProjection,
)
def get_program_rule_source(
    source_id: str,
    session: Session = Depends(get_session),
) -> ProgramRuleSourceProjection:
    try:
        return _program_rule_intake_service(session).get_source(source_id)
    except ProgramRuleIntakeError as error:
        _raise_program_rule_http_error(error)


@app.post(
    "/program-rule-sources/{source_id}/refresh",
    response_model=ProgramRuleSourceProjection,
    status_code=202,
)
def refresh_program_rule_source(
    source_id: str,
    session: Session = Depends(get_session),
) -> ProgramRuleSourceProjection:
    try:
        return _program_rule_intake_service(session).request_refresh(source_id)
    except ProgramRuleIntakeError as error:
        _raise_program_rule_http_error(error)


@app.get(
    "/program-rule-sources/{source_id}/snapshots",
    response_model=list[ProgramRuleSnapshotProjection],
)
def list_program_rule_source_snapshots(
    source_id: str,
    session: Session = Depends(get_session),
) -> list[ProgramRuleSnapshotProjection]:
    try:
        return _program_rule_intake_service(session).list_snapshots(source_id)
    except ProgramRuleIntakeError as error:
        _raise_program_rule_http_error(error)


@app.get(
    "/program-rule-sources/{source_id}/snapshots/{snapshot_id}/diff",
    response_model=ProgramRuleSnapshotDiff,
)
def get_program_rule_snapshot_diff(
    source_id: str,
    snapshot_id: str,
    session: Session = Depends(get_session),
) -> ProgramRuleSnapshotDiff:
    try:
        return _program_rule_intake_service(session).get_snapshot_diff(
            source_id,
            snapshot_id,
        )
    except ProgramRuleIntakeError as error:
        _raise_program_rule_http_error(error)


def _review_program_rule_snapshot(
    *,
    source_id: str,
    snapshot_id: str,
    decision: str,
    request: SnapshotReviewRequest,
    session: Session,
) -> ProgramRuleSnapshotProjection:
    try:
        return _program_rule_intake_service(session).review_snapshot(
            source_id=source_id,
            snapshot_id=snapshot_id,
            decision=decision,
            reviewer_alias=request.reviewer_alias,
            expected_review_digest=request.expected_review_digest,
            operator_confirmed=request.operator_confirmed,
        )
    except ProgramRuleIntakeError as error:
        _raise_program_rule_http_error(error)


@app.post(
    "/program-rule-sources/{source_id}/snapshots/{snapshot_id}/approve",
    response_model=ProgramRuleSnapshotProjection,
)
def approve_program_rule_snapshot(
    source_id: str,
    snapshot_id: str,
    request: SnapshotReviewRequest,
    session: Session = Depends(get_session),
) -> ProgramRuleSnapshotProjection:
    return _review_program_rule_snapshot(
        source_id=source_id,
        snapshot_id=snapshot_id,
        decision="approved",
        request=request,
        session=session,
    )


@app.post(
    "/program-rule-sources/{source_id}/snapshots/{snapshot_id}/reject",
    response_model=ProgramRuleSnapshotProjection,
)
def reject_program_rule_snapshot(
    source_id: str,
    snapshot_id: str,
    request: SnapshotReviewRequest,
    session: Session = Depends(get_session),
) -> ProgramRuleSnapshotProjection:
    return _review_program_rule_snapshot(
        source_id=source_id,
        snapshot_id=snapshot_id,
        decision="rejected",
        request=request,
        session=session,
    )


@app.get(
    "/programs/{program_id}/scope-rules",
    response_model=list[ProgramScopeRuleProjection],
)
def list_program_scope_rules(
    program_id: str,
    session: Session = Depends(get_session),
) -> list[ProgramScopeRuleProjection]:
    try:
        return _program_rule_intake_service(session).list_scope_rules(program_id)
    except ProgramRuleIntakeError as error:
        _raise_program_rule_http_error(error)


@app.post(
    "/mythos/studio/program-rule-fetch/claims/next",
    response_model=ProgramRuleClaimNextResult,
)
def claim_next_program_rule_source(
    session: Session = Depends(get_session),
) -> ProgramRuleClaimNextResult:
    return _program_rule_intake_service(session).claim_next()


@app.post(
    "/mythos/studio/program-rule-fetch/claims/{claim_id}/normalize",
    response_model=NormalizedRuleDocument,
)
def normalize_program_rule_claim_document(
    claim_id: str,
    request: ProgramRuleClaimNormalizeRequest,
    session: Session = Depends(get_session),
) -> NormalizedRuleDocument:
    try:
        return _program_rule_intake_service(session).normalize_claim_document(
            claim_id=claim_id,
            source_id=request.source_id,
            claim_token=request.claim_token,
            envelope=request.document,
        )
    except ProgramRuleIntakeError as error:
        _raise_program_rule_http_error(error)


@app.post(
    "/mythos/studio/program-rule-fetch/claims/{claim_id}/complete",
    response_model=ProgramRuleSnapshotProjection,
)
async def complete_program_rule_claim(
    claim_id: str,
    request: ProgramRuleClaimCompleteRequest,
    session: Session = Depends(get_session),
) -> ProgramRuleSnapshotProjection:
    try:
        documents = [
            NormalizedRuleDocument.model_validate_json(
                json.dumps(document, separators=(",", ":"))
            )
            for document in request.documents
        ]
        return await _program_rule_intake_service(session).complete_claim(
            claim_id=claim_id,
            source_id=request.source_id,
            claim_token=request.claim_token,
            documents=documents,
        )
    except ValidationError:
        raise HTTPException(status_code=422, detail="Program rule request is invalid")
    except ProgramRuleIntakeError as error:
        _raise_program_rule_http_error(error)


@app.post(
    "/mythos/studio/program-rule-fetch/claims/{claim_id}/fail",
    response_model=ProgramRuleSourceProjection,
)
def fail_program_rule_claim(
    claim_id: str,
    request: ProgramRuleClaimFailRequest,
    session: Session = Depends(get_session),
) -> ProgramRuleSourceProjection:
    try:
        return _program_rule_intake_service(session).fail_claim(
            claim_id=claim_id,
            source_id=request.source_id,
            claim_token=request.claim_token,
            failure_code=request.failure_code.value,
        )
    except ProgramRuleIntakeError as error:
        _raise_program_rule_http_error(error)


@app.get("/programs", response_model=list[Program])
def list_programs(session: Session = Depends(get_session)) -> list[Program]:
    return DatabaseRepository(session).list_programs()


@app.post("/programs", response_model=Program, status_code=201)
def create_program(program: Program, session: Session = Depends(get_session)) -> Program:
    repository = DatabaseRepository(session)
    if repository.get_program(program.id) is not None:
        raise HTTPException(status_code=409, detail="Program already exists")
    return repository.create_program(program)


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




@app.post(
    "/mythos/factory/residual-patch-decisions",
    response_model=ResidualPatchDecisionView,
)
def create_factory_residual_patch_decision(
    request: ResidualPatchDecisionCreate,
    session: Session = Depends(get_session),
) -> ResidualPatchDecisionView:
    """Create residual_review / patch_review decision (context only; never unlocks submit/PR)."""
    repository = DatabaseRepository(session)
    if request.program_id is not None:
        _program_or_404_in_scope(repository, request.program_id)
    if request.run_id is not None:
        if repository.get_pipeline_run(request.run_id) is None:
            raise HTTPException(status_code=404, detail="Pipeline run not found")
        _raise_if_campaign_scoped_run_not_in_scope(repository, request.run_id)
    try:
        return create_residual_patch_decision(request, repository=repository)
    except ResidualPatchDecisionApiError as exc:
        detail = str(exc)
        if detail.startswith("unsupported_approval_kind"):
            raise HTTPException(status_code=400, detail=detail) from exc
        raise HTTPException(status_code=400, detail=detail) from exc


@app.get(
    "/mythos/factory/residual-patch-decisions",
    response_model=list[ResidualPatchDecisionView],
)
def list_factory_residual_patch_decisions(
    package_id: str | None = None,
    candidate_id: str | None = None,
    approval_kind: str | None = None,
    run_id: str | None = None,
    package_root: str | None = None,
    limit: int = 100,
    session: Session = Depends(get_session),
) -> list[ResidualPatchDecisionView]:
    repository = DatabaseRepository(session)
    try:
        return list_residual_patch_decisions(
            repository=repository,
            package_id=package_id,
            candidate_id=candidate_id,
            approval_kind=approval_kind,
            run_id=run_id,
            package_root=package_root,
            limit=limit,
        )
    except ResidualPatchDecisionApiError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get(
    "/mythos/factory/residual-patch-decisions/{approval_id}",
    response_model=ResidualPatchDecisionView,
)
def get_factory_residual_patch_decision(
    approval_id: str,
    session: Session = Depends(get_session),
) -> ResidualPatchDecisionView:
    repository = DatabaseRepository(session)
    try:
        return get_residual_patch_decision(approval_id, repository=repository)
    except ResidualPatchDecisionApiError as exc:
        detail = str(exc)
        if detail == "approval_not_found":
            raise HTTPException(status_code=404, detail=detail) from exc
        if detail == "not_residual_or_patch_approval":
            raise HTTPException(status_code=404, detail=detail) from exc
        raise HTTPException(status_code=400, detail=detail) from exc


@app.post(
    "/mythos/factory/residual-patch-decisions/{approval_id}/decisions",
    response_model=ResidualPatchDecisionView,
)
def decide_factory_residual_patch_decision(
    approval_id: str,
    request: ResidualPatchDecisionApply,
    session: Session = Depends(get_session),
) -> ResidualPatchDecisionView:
    """Apply residual/patch human decision; never unlocks execution/submit/auto-PR."""
    repository = DatabaseRepository(session)
    try:
        return decide_residual_patch_decision(
            approval_id=approval_id,
            body=request,
            repository=repository,
        )
    except ResidualPatchDecisionApiError as exc:
        detail = str(exc)
        if detail == "approval_not_found":
            raise HTTPException(status_code=404, detail=detail) from exc
        if detail == "not_residual_or_patch_approval":
            raise HTTPException(status_code=404, detail=detail) from exc
        if detail.startswith("unsupported_decision"):
            raise HTTPException(status_code=400, detail=detail) from exc
        raise HTTPException(status_code=400, detail=detail) from exc


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
    rule = request.rule
    if request.campaign_id is not None:
        campaign = repository.get_campaign(request.campaign_id)
        if campaign is None:
            raise HTTPException(status_code=404, detail="Campaign not found")
        if campaign.scope_status != "in_scope":
            return ScopeGuardDecision(
                allowed=False,
                reason="scope_not_in_scope",
            )
        rule = _campaign_scope_guard_rule(campaign)
        if rule is None:
            return ScopeGuardDecision(
                allowed=False,
                reason="scope_guard_rule_missing",
            )
        if rule.scope_status != "in_scope":
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

    if rule is None:
        return ScopeGuardDecision(
            allowed=False,
            reason="scope_guard_rule_required",
        )

    if rule.human_approval_required:
        preflight_request = request.request.model_copy(update={"human_approved": True})
        preflight_decision = evaluate_validation_request(rule, preflight_request)
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

    return evaluate_validation_request(rule, request.request)


@app.post(
    "/mythos/studio/black-box-lab/leases/preview",
    response_model=StudioBlackBoxLabLeasePreviewResponse,
)
def preview_mythos_studio_black_box_lab_lease(
    request: StudioBlackBoxLabLeasePreviewRequest,
) -> StudioBlackBoxLabLeasePreviewResponse:
    return build_studio_black_box_lab_lease_preview(request)


@app.post(
    "/mythos/studio/black-box-lab/runs/approve",
    response_model=StudioBlackBoxLabRunApprovalResponse,
)
def approve_mythos_studio_black_box_lab_run(
    request: StudioBlackBoxLabRunApprovalRequest,
    session: Session = Depends(get_session),
) -> StudioBlackBoxLabRunApprovalResponse:
    if not request.operator_confirmed:
        raise HTTPException(status_code=409, detail="operator_confirmation_required")
    if not all(session.ready for session in request.lease_preview.sessions):
        raise HTTPException(status_code=409, detail="two_ready_lab_sessions_required")
    expected_traces = {
        (
            workflow.workflow_alias,
            workflow.session_alias,
            workflow.route_template,
        )
        for workflow in request.lease_preview.workflows
    }
    reviewed_traces = {
        (trace.workflow_alias, trace.session_alias, trace.route_template)
        for trace in request.trace_review
    }
    if (
        len(request.trace_review) != len(reviewed_traces)
        or reviewed_traces != expected_traces
    ):
        raise HTTPException(status_code=409, detail="reviewed_trace_set_required")

    repository = DatabaseRepository(session)
    validation_run = repository.get_validation_run(request.validation_run_id)
    if validation_run is None:
        raise HTTPException(status_code=404, detail="Validation run not found")
    campaign = _validation_run_campaign_or_404_in_scope(repository, validation_run)
    if (
        validation_run.validation_mode != "black_box_differential"
        or validation_run.status != "preflight_passed"
        or not validation_run.allowed_to_execute
    ):
        raise HTTPException(status_code=409, detail="local_lab_preflight_required")
    _raise_if_validation_run_approval_not_active(
        repository=repository,
        validation_run=validation_run,
        campaign=campaign,
    )
    approval = (
        repository.session.get(ApprovalRecord, validation_run.approval_id)
        if validation_run.approval_id
        else None
    )
    if approval is None:
        raise HTTPException(status_code=409, detail="active_lab_approval_required")

    approved_asset = _validation_run_scope_asset(validation_run, campaign)
    active_origin = request.lease_preview.active_origin
    origin_netloc = urlparse(active_origin).netloc
    if approved_asset not in {active_origin, origin_netloc}:
        raise HTTPException(status_code=409, detail="lab_origin_approval_mismatch")

    lease_payload = request.lease_preview.model_dump(mode="json")
    serialized_lease = json.dumps(
        lease_payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    lease_digest = f"sha256:{sha256(serialized_lease.encode('utf-8')).hexdigest()}"
    return StudioBlackBoxLabRunApprovalResponse(
        validation_run_id=validation_run.id,
        approval_id=approval.id,
        lease_digest=lease_digest,
    )


@app.get(
    "/mythos/studio/black-box-remote/status",
    response_model=StudioBlackBoxRemoteStatusResponse,
)
def get_mythos_studio_black_box_remote_status() -> StudioBlackBoxRemoteStatusResponse:
    enabled = bool(get_settings().black_box_remote_profile_enabled)
    if not enabled:
        return StudioBlackBoxRemoteStatusResponse(
            enabled=False,
            state="disabled",
            relogin_required=True,
            stop_reason="remote_profile_disabled",
        )
    now = _studio_black_box_remote_now()
    statuses = [
        entry.runtime.safe_status(now=now)
        for entry in reversed(list(_STUDIO_BLACK_BOX_REMOTE_RUNTIMES.values()))
    ]
    current = next(
        (status for status in statuses if status["state"] == "active"),
        None,
    )
    if current is None:
        current = next(
            (status for status in statuses if status["state"] == "expired"),
            None,
        )
    if current is not None:
        return StudioBlackBoxRemoteStatusResponse(
            enabled=True,
            state=current["state"],
            expires_at=current["expires_at"],
            relogin_required=current["relogin_required"],
            stop_reason=current["stop_reason"],
        )
    if _STUDIO_BLACK_BOX_REMOTE_STOPS:
        stopped = next(reversed(_STUDIO_BLACK_BOX_REMOTE_STOPS.values()))
        return StudioBlackBoxRemoteStatusResponse(
            enabled=True,
            state="stopped",
            expires_at=stopped.expires_at,
            relogin_required=True,
            stop_reason=stopped.reason,
        )
    return StudioBlackBoxRemoteStatusResponse(
        enabled=True,
        state="awaiting_lease",
        relogin_required=False,
    )


@app.post(
    "/mythos/studio/black-box-remote/leases",
    response_model=StudioBlackBoxRemoteLeaseIssueResponse,
)
def issue_mythos_studio_black_box_remote_lease(
    request: StudioBlackBoxRemoteLeaseIssueRequest,
    session: Session = Depends(get_session),
) -> StudioBlackBoxRemoteLeaseIssueResponse:
    if not get_settings().black_box_remote_profile_enabled:
        raise HTTPException(
            status_code=409,
            detail="remote_human_lease_profile_disabled",
        )
    if not request.operator_confirmed:
        raise HTTPException(status_code=409, detail="operator_confirmation_required")

    with _STUDIO_BLACK_BOX_REMOTE_ISSUE_LOCK:
        return _issue_mythos_studio_black_box_remote_lease(request, session)


def _issue_mythos_studio_black_box_remote_lease(
    request: StudioBlackBoxRemoteLeaseIssueRequest,
    session: Session,
) -> StudioBlackBoxRemoteLeaseIssueResponse:

    repository = DatabaseRepository(session)
    validation_run = repository.get_validation_run(request.validation_run_id)
    if validation_run is None:
        raise HTTPException(status_code=404, detail="Validation run not found")
    campaign = _validation_run_campaign_or_404_in_scope(repository, validation_run)
    rule = _campaign_scope_guard_rule(campaign)
    if rule is None:
        raise HTTPException(status_code=409, detail="scope_guard_rule_missing")
    if (
        validation_run.validation_mode != "black_box_differential"
        or validation_run.status != "preflight_passed"
        or not validation_run.allowed_to_execute
        or not _validation_run_currently_allowed_to_execute(
            validation_run,
            repository=repository,
        )
    ):
        raise HTTPException(status_code=409, detail="remote_preflight_required")
    scope_decision = evaluate_validation_request(
        rule,
        ValidationRequest(
            asset=campaign.default_asset,
            validation_type="black_box_differential",
            human_approved=True,
            plan_digest=validation_run.plan_digest,
        ),
    )
    if not scope_decision.allowed:
        raise HTTPException(status_code=409, detail=scope_decision.reason)

    now = _studio_black_box_remote_now()
    try:
        policy_digest = _studio_black_box_remote_policy_digest(campaign)
        scope_digest = _studio_black_box_remote_scope_digest(campaign)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    plan_digest = _studio_black_box_remote_plan_digest(request)
    if validation_run.plan_digest != plan_digest:
        raise HTTPException(status_code=409, detail="recorded_remote_plan_required")
    if not _studio_black_box_remote_payload_matches(
        validation_run.payload,
        request=request,
        policy_digest=policy_digest,
        scope_digest=scope_digest,
        plan_digest=plan_digest,
    ):
        raise HTTPException(status_code=409, detail="current_remote_preflight_required")
    if not _studio_black_box_remote_origin_matches_asset(
        request.active_origin,
        _validation_run_scope_asset(validation_run, campaign),
    ):
        raise HTTPException(status_code=409, detail="remote_origin_approval_mismatch")

    approval = (
        repository.session.get(ApprovalRecord, validation_run.approval_id)
        if validation_run.approval_id
        else None
    )
    if not _studio_black_box_remote_dedicated_approval(
        approval,
        validation_run=validation_run,
        request=request,
        policy_digest=policy_digest,
        scope_digest=scope_digest,
        plan_digest=plan_digest,
        now=now,
    ):
        raise HTTPException(
            status_code=409,
            detail="fresh_dedicated_remote_approval_required",
        )
    if (
        isinstance(validation_run.payload, dict)
        and "remote_human_lease_summary" in validation_run.payload
    ):
        raise HTTPException(
            status_code=409,
            detail="single_run_remote_lease_already_issued",
        )

    approval_expires_at = _studio_black_box_remote_as_utc(approval.expires_at)
    approved_at = _studio_black_box_remote_as_utc(approval.decided_at)
    if approval_expires_at is None or approved_at is None:
        raise HTTPException(
            status_code=409,
            detail="fresh_dedicated_remote_approval_required",
        )
    expires_at = min(
        now + timedelta(seconds=request.duration_seconds),
        approval_expires_at,
    )
    execution_lease = BlackBoxExecutionLease(
        lease_id=f"remote_lease_{uuid4().hex}",
        asset=_validation_run_scope_asset(validation_run, campaign),
        policy_digest=policy_digest,
        scope_digest=scope_digest,
        plan_digest=plan_digest,
        active_origins=[request.active_origin],
        passive_origins=request.passive_origins,
        account_aliases=request.account_aliases,
        role_aliases=request.role_aliases,
        allowed_actions=request.allowed_actions,
        rollback_required=True,
        workflow_budget=len(request.workflows),
        request_budget_per_workflow=request.request_budget_per_workflow,
        duration_seconds=request.duration_seconds,
        min_interval_seconds=request.min_interval_seconds,
        issued_at=now,
        expires_at=expires_at,
    )
    lease_approval = LeaseApproval(
        approval_id=approval.id,
        preflight_id=validation_run.id,
        lease_id=execution_lease.lease_id,
        asset=execution_lease.asset,
        policy_digest=policy_digest,
        scope_digest=scope_digest,
        plan_digest=plan_digest,
        validation_mode="black_box_differential",
        approval_status="approved",
        preflight_status="preflight_passed",
        expires_at=approval_expires_at,
    )
    try:
        remote_lease = issue_remote_human_lease(
            lease=execution_lease,
            approval=lease_approval,
            approved_at=approved_at,
            workflows=request.workflows,
            now=now,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    lease_payload = remote_lease.lease.model_dump(mode="json")
    validation_payload = dict(validation_run.payload)
    validation_payload["remote_human_lease_summary"] = {
        "profile": "remote_human_lease",
        "lease_digest": remote_lease.lease_digest,
        "approval_id": approval.id,
        "issued_at": lease_payload["issued_at"],
        "expires_at": lease_payload["expires_at"],
    }
    validation_run.payload = validation_payload
    repository.session.add(validation_run)
    repository.session.commit()
    _STUDIO_BLACK_BOX_REMOTE_RUNTIMES[remote_lease.lease_digest] = (
        _StudioBlackBoxRemoteRuntimeEntry(
            runtime=RemoteLeaseRuntime(remote_lease),
            validation_run_id=validation_run.id,
            approval_id=approval.id,
        )
    )
    return StudioBlackBoxRemoteLeaseIssueResponse(
        **remote_lease.model_dump(mode="json")
    )


def _studio_black_box_remote_current_authority(
    *,
    entry: _StudioBlackBoxRemoteRuntimeEntry,
    repository: DatabaseRepository,
) -> tuple[ValidationRunRecord, CampaignRecord, ScopeGuardRule, LeaseApproval] | None:
    validation_run = repository.get_validation_run(entry.validation_run_id)
    if validation_run is None or validation_run.approval_id != entry.approval_id:
        return None
    if not _validation_run_currently_allowed_to_execute(
        validation_run,
        repository=repository,
    ):
        return None
    campaign = repository.get_campaign(validation_run.campaign_id)
    if campaign is None or campaign.scope_status != "in_scope":
        return None
    rule = _campaign_scope_guard_rule(campaign)
    if rule is None:
        return None
    approval = repository.session.get(ApprovalRecord, entry.approval_id)
    summary = (
        validation_run.payload.get("remote_human_lease_summary")
        if isinstance(validation_run.payload, dict)
        else None
    )
    remote_lease = entry.runtime.remote_lease
    if (
        approval is None
        or approval.status != "approved"
        or approval.approval_type != "black_box_remote_lease"
        or approval.requested_action != "remote_black_box_differential"
        or not isinstance(summary, dict)
        or summary.get("lease_digest") != remote_lease.lease_digest
    ):
        return None
    approval_expires_at = _studio_black_box_remote_as_utc(approval.expires_at)
    approval_payload = approval.payload if isinstance(approval.payload, dict) else {}
    if approval_expires_at is None:
        return None
    try:
        lease_approval = LeaseApproval(
            approval_id=approval.id,
            preflight_id=validation_run.id,
            lease_id=remote_lease.lease.lease_id,
            asset=remote_lease.lease.asset,
            policy_digest=approval_payload.get("policy_digest"),
            scope_digest=approval_payload.get("scope_digest"),
            plan_digest=approval.plan_digest,
            validation_mode="black_box_differential",
            approval_status="approved",
            preflight_status="preflight_passed",
            expires_at=approval_expires_at,
        )
    except ValueError:
        return None
    return validation_run, campaign, rule, lease_approval


def _studio_black_box_remote_stopped_decision(reason: str) -> RemoteAuthorizationDecision:
    return RemoteAuthorizationDecision(
        allowed=False,
        reason=reason,
        stop=BlackBoxStop(reason=reason),
    )


def _studio_black_box_remote_finalize_stop(
    *,
    lease_digest: str,
    entry: _StudioBlackBoxRemoteRuntimeEntry,
    decision: RemoteAuthorizationDecision,
    repository: DatabaseRepository,
) -> RemoteAuthorizationDecision:
    if decision.stop is None:
        return decision
    now = _studio_black_box_remote_now()
    validation_run = repository.get_validation_run(entry.validation_run_id)
    if validation_run is not None:
        validation_payload = (
            dict(validation_run.payload)
            if isinstance(validation_run.payload, dict)
            else {}
        )
        validation_payload["remote_human_lease_stop_summary"] = {
            "lease_digest": lease_digest,
            "reason": decision.reason,
            "stopped_at": now.isoformat(),
        }
        validation_run.payload = validation_payload
        validation_run.allowed_to_execute = False
        validation_run.status = "blocked"
        validation_run.safety_gate_state = "black_box_remote_stopped"
        validation_run.finished_at = now
        repository.session.add(validation_run)
        repository.session.commit()
    _STUDIO_BLACK_BOX_REMOTE_STOPS[lease_digest] = (
        _StudioBlackBoxRemoteStoppedState(
            reason=decision.reason,
            expires_at=entry.runtime.remote_lease.lease.expires_at.isoformat().replace(
                "+00:00", "Z"
            ),
        )
    )
    _STUDIO_BLACK_BOX_REMOTE_RUNTIMES.pop(lease_digest, None)
    return decision


@app.post(
    "/mythos/studio/black-box-remote/leases/{lease_digest}/authorize",
    response_model=RemoteAuthorizationDecision,
)
def authorize_mythos_studio_black_box_remote_request(
    lease_digest: str,
    request: RemoteRequestAuthorization,
    session: Session = Depends(get_session),
) -> RemoteAuthorizationDecision:
    stopped = _STUDIO_BLACK_BOX_REMOTE_STOPS.get(lease_digest)
    if stopped is not None:
        return _studio_black_box_remote_stopped_decision(stopped.reason)
    entry = _STUDIO_BLACK_BOX_REMOTE_RUNTIMES.get(lease_digest)
    if entry is None:
        return _studio_black_box_remote_stopped_decision("relogin_required")
    repository = DatabaseRepository(session)
    if not get_settings().black_box_remote_profile_enabled:
        return _studio_black_box_remote_finalize_stop(
            lease_digest=lease_digest,
            entry=entry,
            decision=entry.runtime.stop("remote_profile_disabled"),
            repository=repository,
        )
    authority = _studio_black_box_remote_current_authority(
        entry=entry,
        repository=repository,
    )
    if authority is None:
        return _studio_black_box_remote_finalize_stop(
            lease_digest=lease_digest,
            entry=entry,
            decision=entry.runtime.stop("approval_preflight_changed"),
            repository=repository,
        )
    validation_run, campaign, rule, approval = authority
    try:
        current_policy_digest = _studio_black_box_remote_policy_digest(campaign)
        current_scope_digest = _studio_black_box_remote_scope_digest(campaign)
    except ValueError:
        return _studio_black_box_remote_finalize_stop(
            lease_digest=lease_digest,
            entry=entry,
            decision=entry.runtime.stop("policy_or_scope_changed"),
            repository=repository,
        )
    decision = entry.runtime.authorize(
        rule=rule,
        approval=approval,
        request=request,
        current_policy_digest=current_policy_digest,
        current_scope_digest=current_scope_digest,
        current_plan_digest=validation_run.plan_digest or "",
        lease_digest=lease_digest,
        now=_studio_black_box_remote_now(),
    )
    return _studio_black_box_remote_finalize_stop(
        lease_digest=lease_digest,
        entry=entry,
        decision=decision,
        repository=repository,
    )


@app.post(
    "/mythos/studio/black-box-remote/leases/{lease_digest}/complete",
    response_model=RemoteAuthorizationDecision,
)
def complete_mythos_studio_black_box_remote_request(
    lease_digest: str,
    request: StudioBlackBoxRemoteCompletionRequest,
    session: Session = Depends(get_session),
) -> RemoteAuthorizationDecision:
    stopped = _STUDIO_BLACK_BOX_REMOTE_STOPS.get(lease_digest)
    if stopped is not None:
        return _studio_black_box_remote_stopped_decision(stopped.reason)
    entry = _STUDIO_BLACK_BOX_REMOTE_RUNTIMES.get(lease_digest)
    if entry is None:
        return _studio_black_box_remote_stopped_decision("relogin_required")
    repository = DatabaseRepository(session)
    decision = entry.runtime.complete(
        request.request_grant_id,
        outcome=request.outcome,
        now=_studio_black_box_remote_now(),
    )
    return _studio_black_box_remote_finalize_stop(
        lease_digest=lease_digest,
        entry=entry,
        decision=decision,
        repository=repository,
    )


@app.post(
    "/mythos/studio/black-box-remote/leases/{lease_digest}/stop",
    response_model=RemoteAuthorizationDecision,
)
def stop_mythos_studio_black_box_remote_lease(
    lease_digest: str,
    request: StudioBlackBoxRemoteStopRequest,
    session: Session = Depends(get_session),
) -> RemoteAuthorizationDecision:
    stopped = _STUDIO_BLACK_BOX_REMOTE_STOPS.get(lease_digest)
    if stopped is not None:
        return _studio_black_box_remote_stopped_decision(stopped.reason)
    entry = _STUDIO_BLACK_BOX_REMOTE_RUNTIMES.get(lease_digest)
    if entry is None:
        return _studio_black_box_remote_stopped_decision("relogin_required")
    return _studio_black_box_remote_finalize_stop(
        lease_digest=lease_digest,
        entry=entry,
        decision=entry.runtime.stop(request.reason),
        repository=DatabaseRepository(session),
    )


@app.get(
    "/mythos/studio/black-box-remote/leases/{lease_digest}/status",
    response_model=StudioBlackBoxRemoteStatusResponse,
)
def get_mythos_studio_black_box_remote_lease_status(
    lease_digest: str,
) -> StudioBlackBoxRemoteStatusResponse:
    enabled = bool(get_settings().black_box_remote_profile_enabled)
    stopped = _STUDIO_BLACK_BOX_REMOTE_STOPS.get(lease_digest)
    if stopped is not None:
        return StudioBlackBoxRemoteStatusResponse(
            enabled=enabled,
            state="stopped",
            expires_at=stopped.expires_at,
            relogin_required=True,
            stop_reason=stopped.reason,
        )
    entry = _STUDIO_BLACK_BOX_REMOTE_RUNTIMES.get(lease_digest)
    if entry is None:
        return StudioBlackBoxRemoteStatusResponse(
            enabled=enabled,
            state="relogin_required",
            relogin_required=True,
            stop_reason="relogin_required",
        )
    status = entry.runtime.safe_status(now=_studio_black_box_remote_now())
    return StudioBlackBoxRemoteStatusResponse(
        enabled=enabled,
        state=status["state"],
        expires_at=status["expires_at"],
        relogin_required=status["relogin_required"],
        stop_reason=status["stop_reason"],
    )


@app.post("/mythos/studio/workspaces")
def create_mythos_studio_workspace(request: StudioWorkspaceCreateRequest) -> dict:
    workspace = create_workspace(
        get_settings().studio_workspace_root,
        name=request.name,
    )
    return {"path": str(workspace.path), "manifest": workspace.manifest}


@app.get("/mythos/studio/workspaces/manifest")
def get_mythos_studio_workspace_manifest(workspace_path: str) -> dict:
    try:
        return load_workspace_manifest(workspace_path)
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail="workspace_manifest_not_found",
        ) from exc


@app.post("/mythos/studio/workspaces/imports")
def import_mythos_studio_workspace_artifact(
    request: StudioArtifactImportRequest,
) -> dict:
    try:
        return import_workspace_artifact(
            request.workspace_path,
            StudioArtifactImport(kind=request.kind, source_path=request.source_path),
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="artifact_source_not_found") from exc


@app.post("/mythos/studio/workspaces/runs")
async def run_mythos_studio_workspace_research(
    request: StudioWorkspaceRunRequest,
    session: Session = Depends(get_session),
) -> dict:
    return await _run_mythos_studio_workspace_research_service(request, session)


async def _run_mythos_studio_workspace_research_service(
    request: StudioWorkspaceRunRequest,
    session: Session,
    *,
    reasoner_override: CandidateReasoner | None = None,
    audit_mode: Literal["live", "replay"] = "live",
) -> dict:
    model_enabled = (
        request.candidate_model is not None
        and request.candidate_model.enabled
    )
    if reasoner_override is not None and (
        audit_mode != "replay" or not model_enabled
    ):
        raise ValueError("replay_reasoner_requires_enabled_model_request")
    if audit_mode == "replay" and reasoner_override is None:
        raise ValueError("replay_audit_requires_reasoner")
    manifest = load_workspace_manifest(request.workspace_path)
    if _studio_missing_ab_artifacts(manifest):
        raise HTTPException(
            status_code=422,
            detail="studio_ab_artifacts_required",
        )
    scope_path = _studio_artifact_path(manifest, "scope")
    policy_path = _studio_artifact_path(manifest, "policy")
    repo_path = _studio_artifact_path(manifest, "code")

    repository = DatabaseRepository(session)
    try:
        result = run_source_audit(repo_path, scope_path)
    except SourceAuditBlocked as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    policy_text = _read_source_audit_policy_text(policy_path or scope_path)
    record = save_source_audit_pipeline_run(
        repository=repository,
        result=result,
        policy_text=policy_text,
    )
    candidates = _studio_candidates_for_run(record, manifest, repository=repository)
    surface_facts = _studio_imported_surface_facts(manifest)
    for kind in ("api", "har"):
        if not any(
            fact.get("artifact_kind") == kind for fact in surface_facts
        ):
            if context_fact := _studio_empty_surface_context_fact(manifest, kind):
                surface_facts.append(context_fact)
    code_files = _studio_authorized_code_files(repo_path)
    context_facts = _studio_authorization_context_facts(manifest)
    baseline_observations = build_candidate_hunter_observations(
        pipeline_run_id=record.id,
        candidates=candidates,
        code_files=code_files,
        surface_facts=surface_facts,
        context_facts=context_facts,
    )
    fact_pack = build_fact_pack(
        pipeline_run_id=record.id,
        scope_status=record.scope_status,
        source_files=_studio_fact_pack_code_files(code_files),
        facts=(
            baseline_observations["facts"]
            if isinstance(baseline_observations.get("facts"), list)
            else []
        ),
        baseline_candidates=candidates,
    )
    model_config = None
    reasoner = reasoner_override
    if request.candidate_model is not None and request.candidate_model.enabled:
        assert request.candidate_model.provider is not None
        assert request.candidate_model.model is not None
        model_config = CandidateModelConfig(
            provider=request.candidate_model.provider,
            model=request.candidate_model.model.strip(),
        )
        if reasoner is None:
            reasoner = RegistryCandidateReasoner(build_default_registry())
    generation = await generate_cross_source_candidates(
        fact_pack=fact_pack,
        baseline_candidates=fact_pack.baseline_candidates,
        model_config=model_config,
        reasoner=reasoner,
    )
    generation_payload = generation_stage_payload(
        fact_pack=fact_pack,
        result=generation,
        model_config=model_config,
    )
    if model_config is not None:
        audit_safety_notes = [
            "prompt_hash_only",
            "no_prompt_storage",
            "provider_response_not_fact",
            "model_proposals_unverified",
            "human_approval_still_required",
        ]
        if generation.model_failure_reason:
            audit_safety_notes.append("model_failure_recorded")
        if audit_mode == "replay":
            audit_safety_notes.append("synthetic_replay_no_provider_call")
        repository.save_llm_run(
            provider=model_config.provider.value,
            model=model_config.model,
            purpose="cross_source_candidate_generation",
            prompt_hash=generation.prompt_hash,
            mode=audit_mode,
            latency_ms=generation.model_latency_ms,
            error=generation.model_failure_reason,
            safety_notes=audit_safety_notes,
        )
    repository.save_pipeline_stage(
        pipeline_run_id=record.id,
        campaign_id=None,
        task_id=None,
        stage_key="cross_source_candidate_generation",
        stage_order=0,
        status="completed",
        input_refs=[],
        output_refs=[],
        safety_gate_state="safe",
        stop_reason=generation.model_status,
        payload=generation_payload,
    )
    hunter_candidates = candidate_hunter_inputs(
        candidates=generation.working_candidates,
        fact_pack=fact_pack,
    )
    observations = build_candidate_hunter_observations(
        pipeline_run_id=record.id,
        candidates=hunter_candidates,
        code_files=code_files,
        surface_facts=surface_facts,
        context_facts=context_facts,
    )
    loop_result = run_candidate_hunter_loop(
        repository=repository,
        record=record,
        policy_text=policy_text,
        candidates=hunter_candidates,
        observations=observations,
        evidence_context=_studio_candidate_hunter_evidence_context(
            repo_path=repo_path,
            fact_pack=fact_pack,
        ),
    )
    if loop_result.get("status") == "awaiting_evidence":
        evidence_task_id = loop_result.get("evidence_task_id")
        if (
            get_settings().worker_dispatch_mode == "inline"
            and isinstance(evidence_task_id, str)
            and evidence_task_id
        ):
            from app.worker.tasks import run_agent_task

            run_agent_task(evidence_task_id, repository=repository)
    preview = build_report_preview_response(record)
    updated_manifest = record_workspace_run(
        request.workspace_path,
        run_id=record.id,
        status="submission_blocked" if preview.submission_blocked else "ready_for_review",
        report_path=None,
        candidate_count=len(hunter_candidates),
    )
    candidate_generation = {
        key: generation_payload[key]
        for key in (
            "model_requested",
            "model_status",
            "model_failure_reason",
            "prompt_hash",
            "model_latency_ms",
            "baseline_count",
            "proposed_count",
            "accepted_count",
            "rejected_count",
            "working_candidate_count",
            "execution_allowed",
            "dispatch_allowed",
            "validation_allowed",
            "candidate_promotion_allowed",
            "report_submission_allowed",
        )
    }
    for key in ("provider", "model"):
        if key in generation_payload:
            candidate_generation[key] = generation_payload[key]
    return {
        "run_id": record.id,
        "candidate_count": len(hunter_candidates),
        "candidate_generation": candidate_generation,
        "submission_blocked": preview.submission_blocked,
        "report_title": safe_preview_text(record.report_title or preview.title),
        "safety_notes": safe_string_list(
            record.payload.get("safety_notes", [])
            if isinstance(record.payload, dict)
            else []
        ),
        "manifest": updated_manifest,
    }


@app.post("/mythos/studio/workspaces/campaigns/launch")
def launch_mythos_studio_workspace_campaign(
    request: StudioCampaignLaunchRequest,
    session: Session = Depends(get_session),
) -> dict:
    manifest = load_workspace_manifest(request.workspace_path)
    missing = _studio_missing_ab_artifacts(manifest)
    if missing:
        raise HTTPException(
            status_code=422,
            detail={
                "reason": "studio_ab_artifacts_required",
                "missing": missing,
            },
        )

    repository = DatabaseRepository(session)
    program_id = request.program_id or "program_example"
    if repository.get_program(program_id) is None:
        raise HTTPException(status_code=404, detail="Program not found")

    default_asset = request.default_asset or _studio_campaign_default_asset(
        manifest,
        request.workspace_path,
    )
    scope_guard_rule = parse_policy_text(
        _studio_scope_policy_text_from_manifest(manifest),
        default_asset,
    )
    if scope_guard_rule.scope_status != "in_scope":
        raise HTTPException(status_code=409, detail="scope_not_in_scope")

    payload = _studio_campaign_payload_from_manifest(manifest)
    payload["scope_guard_rule"] = scope_guard_rule.model_dump(mode="json")
    campaign = repository.create_campaign(
        program_id=program_id,
        name=request.name or f"Mythos Studio hunter: {manifest.get('name', 'workspace')}",
        autonomy_level="level_0_read_only",
        scope_status=scope_guard_rule.scope_status,
        policy_text=_studio_policy_text_from_manifest(manifest),
        default_asset=default_asset,
        target_classes=["idor", "authorization"],
        allowed_tools=["static_analyzer", "api_artifact_mapper"],
        created_by="mythos_studio",
        payload=payload,
    )
    repository.upsert_campaign_budget(
        campaign_id=campaign.id,
        time_budget_minutes=30,
        token_budget=5000,
        tool_call_budget=10,
        validation_budget=1,
    )
    campaign = repository.update_campaign_status(campaign.id, "running") or campaign
    tick_result = tick_campaign(
        campaign.id,
        repository=repository,
        dispatcher=dispatch_agent_task,
    )
    if tick_result["status"] == "blocked":
        campaign = repository.update_campaign_status(campaign.id, "blocked") or campaign

    control_center = _campaign_control_center_response(campaign, repository)
    dispatched_task_ids = tick_result.get("dispatched_task_ids", [])
    updated_manifest = record_workspace_campaign_hunter_run(
        request.workspace_path,
        campaign_id=campaign.id,
        campaign_name=campaign.name,
        campaign_status=campaign.status,
        dispatched_task_ids=dispatched_task_ids,
        suggestion_count=len(control_center.research_queue_suggestions),
    )
    return {
        "campaign": _campaign_response(campaign, repository).model_dump(mode="json"),
        "control_center": control_center.model_dump(mode="json"),
        "dispatched_task_ids": dispatched_task_ids,
        "manifest": updated_manifest,
        "safety_gate": "review_only_no_execution",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


@app.get("/mythos/studio/workspaces/mission")
def get_mythos_studio_workspace_mission(
    workspace_path: str,
    run_id: str | None = None,
    session: Session = Depends(get_session),
) -> dict:
    return _studio_workspace_mission(workspace_path, run_id, session)


@app.get("/mythos/studio/workspaces/mission/handoff")
def get_mythos_studio_workspace_mission_handoff(
    workspace_path: str,
    run_id: str | None = None,
    session: Session = Depends(get_session),
) -> dict:
    mission = _studio_workspace_mission(workspace_path, run_id, session)
    handoff_pack = mission.get("agent_handoff_pack")
    if not isinstance(handoff_pack, dict):
        handoff_pack = {}
    candidate_hunter_plan = mission.get("candidate_hunter_plan")
    if not isinstance(candidate_hunter_plan, dict):
        candidate_hunter_plan = {}
    candidate_hunter_review_loop = mission.get("candidate_hunter_review_loop")
    if not isinstance(candidate_hunter_review_loop, dict):
        candidate_hunter_review_loop = {}
    candidate_hunter_execution_loop = mission.get("candidate_hunter_execution_loop")
    if not isinstance(candidate_hunter_execution_loop, dict):
        candidate_hunter_execution_loop = {}
    return {
        "run_id": mission.get("run_id"),
        "scope_guard_status": mission.get("scope_guard_status"),
        "candidate_count": mission.get("candidate_count", 0),
        "quality_summary": mission.get("quality_summary", {}),
        "artifacts": mission.get("artifacts", {}),
        "agent_handoff_pack": handoff_pack,
        "candidate_hunter_plan": candidate_hunter_plan,
        "candidate_hunter_review_loop": candidate_hunter_review_loop,
        "candidate_hunter_execution_loop": candidate_hunter_execution_loop,
        "safety_gate": "review_only_no_execution",
        "completion_gate": "human_review_required",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _studio_workspace_mission(
    workspace_path: str,
    run_id: str | None,
    session: Session,
) -> dict:
    manifest = load_workspace_manifest(workspace_path)
    selected_run_id = run_id or _latest_studio_run_id(manifest)
    if selected_run_id is None:
        return _studio_mission_summary(manifest, None, [])
    repository = DatabaseRepository(session)
    record = repository.get_pipeline_run(selected_run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    candidates = _studio_candidates_for_run(record, manifest, repository=repository)
    return _studio_mission_summary(manifest, selected_run_id, candidates)


@app.post("/mythos/studio/workspaces/mission/export")
def export_mythos_studio_workspace_mission(
    request: StudioMissionExportRequest,
    session: Session = Depends(get_session),
) -> dict:
    manifest = load_workspace_manifest(request.workspace_path)
    selected_run_id = request.run_id or _latest_studio_run_id(manifest)
    candidates: list[dict] = []
    if selected_run_id is not None:
        repository = DatabaseRepository(session)
        record = repository.get_pipeline_run(selected_run_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Pipeline run not found")
        candidates = _studio_candidates_for_run(record, manifest, repository=repository)
    mission = _studio_mission_summary(manifest, selected_run_id, candidates)
    updated_manifest = record_workspace_mission_dossier(
        request.workspace_path,
        run_id=selected_run_id,
        mission=mission,
    )
    return {
        "run_id": selected_run_id,
        "mission_dossier_path": _studio_mission_dossier_field(
            updated_manifest,
            selected_run_id,
            "dossier_path",
        ),
        "mission_dossier_markdown_path": _studio_mission_dossier_field(
            updated_manifest,
            selected_run_id,
            "dossier_markdown_path",
        ),
        "agent_queue_path": _studio_mission_dossier_field(
            updated_manifest,
            selected_run_id,
            "agent_queue_path",
        ),
        "agent_queue_markdown_path": _studio_mission_dossier_field(
            updated_manifest,
            selected_run_id,
            "agent_queue_markdown_path",
        ),
        "report_submission_allowed": False,
        "validation_execution_allowed": False,
        "mission": mission,
        "manifest": updated_manifest,
    }


@app.get("/mythos/studio/workspaces/candidates")
def list_mythos_studio_workspace_candidates(
    workspace_path: str,
    run_id: str | None = None,
    session: Session = Depends(get_session),
) -> dict:
    manifest = load_workspace_manifest(workspace_path)
    selected_run_id = run_id or _latest_studio_run_id(manifest)
    if selected_run_id is None:
        return {"run_id": None, "candidates": []}
    repository = DatabaseRepository(session)
    record = repository.get_pipeline_run(selected_run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    candidates = _studio_candidates_for_run(record, manifest, repository=repository)
    return {"run_id": selected_run_id, "candidates": candidates}


@app.post("/mythos/studio/workspaces/benchmarks/run")
def run_mythos_studio_workspace_benchmark(
    request: StudioBenchmarkRunRequest,
    session: Session = Depends(get_session),
) -> dict:
    manifest = load_workspace_manifest(request.workspace_path)
    if request.run_id not in {
        run.get("run_id") for run in manifest.get("runs", []) if isinstance(run, dict)
    }:
        raise HTTPException(status_code=404, detail="workspace_run_not_found")
    try:
        expectations_path = resolve_workspace_file(
            request.workspace_path,
            request.expectations_path,
            directory="benchmarks",
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="benchmark_expectations_not_found")
    try:
        expectations = json.loads(expectations_path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail="invalid_benchmark_expectations") from exc
    repository = DatabaseRepository(session)
    record = repository.get_pipeline_run(request.run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    result = evaluate_studio_candidates(
        {"candidates": _studio_candidates_for_run(record, manifest, repository=repository)},
        expectations,
    )
    updated_manifest = record_workspace_benchmark_result(
        request.workspace_path,
        run_id=request.run_id,
        result=result,
    )
    return {
        "run_id": request.run_id,
        "benchmark": result,
        "benchmark_path": _studio_benchmark_field(
            updated_manifest,
            request.run_id,
            "benchmark_path",
        ),
        "manifest": updated_manifest,
    }


@app.post("/mythos/studio/workspaces/benchmarks/template")
def create_mythos_studio_workspace_benchmark_template(
    request: StudioBenchmarkTemplateRequest,
    session: Session = Depends(get_session),
) -> dict:
    manifest = load_workspace_manifest(request.workspace_path)
    if request.run_id not in {
        run.get("run_id") for run in manifest.get("runs", []) if isinstance(run, dict)
    }:
        raise HTTPException(status_code=404, detail="workspace_run_not_found")
    repository = DatabaseRepository(session)
    record = repository.get_pipeline_run(request.run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    template = build_studio_expectations_template(
        {"candidates": _studio_candidates_for_run(record, manifest, repository=repository)}
    )
    updated_manifest = record_workspace_benchmark_template(
        request.workspace_path,
        run_id=request.run_id,
        template=template,
    )
    return {
        "run_id": request.run_id,
        "template": template,
        "template_path": _studio_benchmark_template_field(
            updated_manifest,
            request.run_id,
            "template_path",
        ),
        "manifest": updated_manifest,
    }


@app.post("/mythos/studio/workspaces/reports/export")
def export_mythos_studio_workspace_report(
    request: StudioReportExportRequest,
    session: Session = Depends(get_session),
) -> dict:
    manifest = load_workspace_manifest(request.workspace_path)
    if request.run_id not in {
        run.get("run_id") for run in manifest.get("runs", []) if isinstance(run, dict)
    }:
        raise HTTPException(status_code=404, detail="workspace_run_not_found")
    repository = DatabaseRepository(session)
    record = repository.get_pipeline_run(request.run_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Pipeline run not found")
    preview = _build_report_preview_response_or_404(record)
    report = preview.model_dump(mode="json")
    report.update(
        _studio_report_candidate_guidance(record, manifest, repository=repository)
    )
    report["studio_context"] = _studio_report_context(manifest)
    updated_manifest = record_workspace_report_export(
        request.workspace_path,
        run_id=request.run_id,
        report=report,
    )
    return {
        "run_id": request.run_id,
        "title": preview.title,
        "submission_blocked": preview.submission_blocked,
        "report_submission_allowed": False,
        "report_markdown_path": _studio_run_field(
            updated_manifest,
            request.run_id,
            "report_markdown_path",
        ),
        "report": report,
        "manifest": updated_manifest,
    }


@app.post("/mythos/studio/workspaces/campaigns/reports/export")
def export_mythos_studio_campaign_hunter_report(
    request: StudioCampaignHunterReportExportRequest,
    session: Session = Depends(get_session),
) -> dict:
    manifest = load_workspace_manifest(request.workspace_path)
    if request.campaign_id not in {
        run.get("campaign_id")
        for run in manifest.get("campaign_hunter_runs", [])
        if isinstance(run, dict)
    }:
        raise HTTPException(status_code=404, detail="workspace_campaign_hunter_not_found")

    repository = DatabaseRepository(session)
    campaign = repository.get_campaign(request.campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    control_center = _campaign_control_center_response(campaign, repository)
    suggestions = control_center.research_queue_suggestions[:5]
    report = _studio_campaign_hunter_report(
        campaign=campaign,
        manifest=manifest,
        suggestions=suggestions,
    )
    updated_manifest = record_workspace_campaign_hunter_report_export(
        request.workspace_path,
        campaign_id=request.campaign_id,
        report=report,
    )
    return {
        "campaign_id": request.campaign_id,
        "run_id": request.campaign_id,
        "title": report["title"],
        "submission_blocked": True,
        "report_submission_allowed": False,
        "report_markdown_path": _studio_campaign_hunter_run_field(
            updated_manifest,
            request.campaign_id,
            "report_markdown_path",
        ),
        "report": report,
        "manifest": updated_manifest,
    }


def _studio_artifact_path(manifest: dict, kind: str) -> str | None:
    artifacts = manifest.get("artifacts", [])
    if not isinstance(artifacts, list):
        return None
    for artifact in reversed(artifacts):
        if not isinstance(artifact, dict) or artifact.get("kind") != kind:
            continue
        source_path = artifact.get("source_path")
        if isinstance(source_path, str) and source_path:
            return source_path
    return None


def _studio_missing_ab_artifacts(manifest: dict) -> list[str]:
    artifacts = manifest.get("artifacts", [])
    if not isinstance(artifacts, list):
        return ["scope", "policy", "code", "api", "har"]
    present = {
        artifact.get("kind")
        for artifact in artifacts
        if isinstance(artifact, dict) and isinstance(artifact.get("kind"), str)
    }
    return [
        kind
        for kind in ("scope", "policy", "code", "api", "har")
        if kind not in present
    ]


def _studio_campaign_payload_from_manifest(manifest: dict) -> dict[str, object]:
    payload: dict[str, object] = {"source": "studio_workspace_campaign_bridge"}
    code_path = _studio_artifact_path(manifest, "code")
    api_path = _studio_artifact_path(manifest, "api")
    har_path = _studio_artifact_path(manifest, "har")

    code_files = _studio_authorized_code_files(code_path)
    if code_files:
        payload["authorized_code_files"] = code_files

    api_artifacts = []
    if api_path:
        api_artifacts.append(_studio_authorized_json_artifact("openapi", api_path))
    if har_path:
        api_artifacts.append(_studio_authorized_json_artifact("har", har_path))
    if api_artifacts:
        payload["authorized_api_artifacts"] = api_artifacts
    return payload


def _studio_policy_text_from_manifest(manifest: dict) -> str:
    policy_path = _studio_artifact_path(manifest, "policy") or _studio_artifact_path(
        manifest,
        "scope",
    )
    if not policy_path:
        return "Authorized Studio workspace policy unavailable."
    return _studio_read_text_file(policy_path)


def _studio_scope_policy_text_from_manifest(manifest: dict) -> str:
    texts = []
    for kind in ("policy", "scope"):
        path = _studio_artifact_path(manifest, kind)
        if path:
            texts.append(_studio_read_text_file(path))
    return "\n".join(texts)


def _studio_campaign_default_asset(manifest: dict, workspace_path: str) -> str:
    scope_path = _studio_artifact_path(manifest, "scope")
    if scope_path:
        text = _studio_read_text_file(scope_path)
        for line in text.splitlines():
            stripped = line.strip().strip("-").strip()
            if stripped and "." in stripped and " " not in stripped:
                return stripped[:255]
    return Path(workspace_path).name or "studio-authorized-workspace"


def _studio_authorized_code_files(path_value: str | None) -> list[dict[str, str]]:
    if not path_value:
        return []
    path = Path(path_value)
    if path.is_file():
        return [{"path": str(path), "content": _studio_read_text_file(str(path))}]
    if not path.is_dir():
        return []

    resolved_root = path.resolve(strict=True)
    files: list[dict[str, str]] = []
    for candidate in sorted(path.rglob("*")):
        if len(files) >= 20:
            break
        try:
            resolved_candidate = candidate.resolve(strict=True)
        except OSError:
            continue
        if not resolved_candidate.is_relative_to(resolved_root):
            raise HTTPException(status_code=403, detail="studio_artifact_not_authorized")
        if not resolved_candidate.is_file() or candidate.suffix.lower() not in {
            ".py",
            ".js",
            ".jsx",
            ".ts",
            ".tsx",
            ".go",
            ".java",
            ".kt",
            ".rb",
            ".php",
        }:
            continue
        try:
            content = resolved_candidate.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError):
            continue
        if content.strip():
            files.append({"path": str(candidate), "content": content[:20000]})
    return files


def _studio_fact_pack_code_files(code_files: list[dict[str, str]]) -> list[dict[str, str]]:
    files: list[dict[str, str]] = []
    seen_paths: set[str] = set()
    for item in code_files:
        path = item.get("path")
        content = item.get("content")
        if not isinstance(path, str) or not isinstance(content, str):
            continue
        source_path = Path(path).name
        if not source_path or source_path in seen_paths:
            continue
        seen_paths.add(source_path)
        files.append({"path": source_path, "content": content})
    return files


def _studio_candidate_hunter_evidence_context(
    *,
    repo_path: str | None,
    fact_pack: object,
) -> dict[str, object] | None:
    if not repo_path:
        return None
    try:
        root = Path(repo_path).resolve(strict=True)
    except OSError:
        return None
    if not root.is_dir():
        return None
    source_snapshot_digest = getattr(fact_pack, "source_snapshot_digest", None)
    source_manifest = getattr(fact_pack, "source_manifest", None)
    if not isinstance(source_snapshot_digest, str) or not isinstance(source_manifest, list):
        return None
    manifest = []
    for item in source_manifest:
        model_dump = getattr(item, "model_dump", None)
        if not callable(model_dump):
            return None
        value = model_dump(mode="json")
        if not isinstance(value, dict):
            return None
        manifest.append(value)
    return {
        "source_snapshot_digest": source_snapshot_digest,
        "source_manifest": manifest,
        "saved_scope_guard": {
            "scope_status": "in_scope",
            "authorized_local_root": str(root),
        },
    }


def _studio_authorized_json_artifact(kind: str, path_value: str) -> dict[str, object]:
    path = Path(path_value)
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"invalid_{kind}_artifact_json",
        ) from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail=f"invalid_{kind}_artifact_json")
    return {
        "kind": kind,
        "source_name": str(path),
        "payload": payload,
    }


def _studio_read_text_file(path_value: str) -> str:
    try:
        return Path(path_value).read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError):
        return "Authorized Studio artifact text unavailable."


def _studio_mission_summary(
    manifest: dict,
    run_id: str | None,
    candidates: list[dict],
) -> dict[str, object]:
    present = _studio_present_ab_artifacts(manifest)
    missing = [kind for kind in _studio_required_ab_artifacts() if kind not in present]
    top_candidates = candidates[:5]
    candidate_summaries = [
        _studio_mission_candidate_summary(candidate)
        for candidate in top_candidates
    ]
    quality_summary = _studio_mission_quality_summary(
        candidate_summaries,
        missing,
        len(candidates),
    )
    candidate_hunter_backlog = _studio_candidate_hunter_backlog(
        candidate_summaries,
        missing,
    )
    candidate_review_packets = _studio_candidate_review_packets(candidate_summaries)
    submission_blocked_report_summary = _studio_submission_blocked_report_summary(
        candidate_review_packets
    )
    candidate_hunter_iteration = _studio_candidate_hunter_iteration(
        candidate_hunter_backlog,
        quality_summary,
    )
    candidate_hunter_plan = _studio_candidate_hunter_plan(
        candidate_hunter_backlog,
        candidate_hunter_iteration,
    )
    candidate_hunter_review_loop = _studio_candidate_hunter_review_loop(
        candidate_hunter_plan
    )
    candidate_hunter_execution_loop = _studio_candidate_hunter_execution_loop(
        candidate_hunter_review_loop,
        candidate_summaries,
    )
    agent_queue = _studio_mission_agent_queue(
        present,
        missing,
        run_id,
        candidate_summaries,
    )
    agent_task_timeline = _studio_mission_agent_task_timeline(agent_queue)
    studio_timeline_summary = _studio_mission_timeline_summary(agent_task_timeline)
    agent_handoff_pack = _studio_agent_handoff_pack(
        candidate_hunter_backlog,
        candidate_hunter_iteration,
        agent_queue,
        studio_timeline_summary,
    )
    readiness_audit = _studio_readiness_audit(
        present,
        _studio_present_advisory_artifacts(manifest),
        candidate_summaries,
        candidate_review_packets,
        submission_blocked_report_summary,
        candidate_hunter_backlog,
        candidate_hunter_iteration,
        agent_handoff_pack,
    )
    return {
        "mode": "local_ai_vulnerability_research_workbench",
        "run_id": run_id,
        "scope_guard_status": safe_preview_text(
            manifest.get("safety", {}).get("scope_guard_status", "")
            if isinstance(manifest.get("safety"), dict)
            else ""
        ),
        "artifacts": {
            "required": list(_studio_required_ab_artifacts()),
            "present": present,
            "missing": missing,
        },
        "attack_surface_model": _studio_attack_surface_model(manifest),
        "advisory_artifacts": {
            "supported": list(_studio_supported_advisory_artifacts()),
            "present": _studio_present_advisory_artifacts(manifest),
        },
        "agent_queue": agent_queue,
        "agent_task_timeline": agent_task_timeline,
        "studio_timeline_summary": studio_timeline_summary,
        "agent_handoff_pack": agent_handoff_pack,
        "candidate_count": len(top_candidates),
        "top_candidates": candidate_summaries,
        "candidate_review_packets": candidate_review_packets,
        "submission_blocked_report_summary": submission_blocked_report_summary,
        "readiness_audit": readiness_audit,
        "quality_summary": quality_summary,
        "candidate_hunter_backlog": candidate_hunter_backlog,
        "candidate_hunter_iteration": candidate_hunter_iteration,
        "candidate_hunter_plan": candidate_hunter_plan,
        "candidate_hunter_review_loop": candidate_hunter_review_loop,
        "candidate_hunter_execution_loop": candidate_hunter_execution_loop,
        "research_loop": _studio_mission_research_loop(
            present,
            missing,
            run_id,
            candidate_summaries,
        ),
        "quality_gates": {
            "top_candidates_limited": len(candidates) <= 5,
            "submission_blocked": True,
            "report_submission_allowed": False,
            "validation_execution_allowed": False,
            "human_review_required": True,
            "top_candidate_quality_gate": (
                quality_summary["top_candidate_quality_gate"] == "passed"
            ),
        },
        "blocked_actions": [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
        ],
        "next_actions": [
            "review_top_candidates",
            "create_benchmark_template",
            "export_submission_blocked_report",
        ],
    }


def _studio_required_ab_artifacts() -> tuple[str, ...]:
    return ("scope", "policy", "code", "api", "har")


def _studio_supported_advisory_artifacts() -> tuple[str, ...]:
    return ("sarif", "sbom", "fuzzing", "strategy", "knowledge")


def _studio_present_ab_artifacts(manifest: dict) -> list[str]:
    artifacts = manifest.get("artifacts", [])
    if not isinstance(artifacts, list):
        return []
    present = {
        artifact.get("kind")
        for artifact in artifacts
        if isinstance(artifact, dict)
        and artifact.get("kind") in _studio_required_ab_artifacts()
    }
    return [kind for kind in _studio_required_ab_artifacts() if kind in present]


def _studio_present_advisory_artifacts(manifest: dict) -> list[str]:
    artifacts = manifest.get("artifacts", [])
    if not isinstance(artifacts, list):
        return []
    present = {
        artifact.get("kind")
        for artifact in artifacts
        if isinstance(artifact, dict)
        and artifact.get("kind") in _studio_supported_advisory_artifacts()
    }
    return [kind for kind in _studio_supported_advisory_artifacts() if kind in present]


def _studio_mission_agent_queue(
    present_artifacts: list[str],
    missing_artifacts: list[str],
    run_id: str | None,
    candidates: list[dict[str, object]],
) -> list[dict[str, object]]:
    has_candidates = len(candidates) > 0
    has_endpoint = any(candidate.get("affected_endpoint") for candidate in candidates)
    has_code_path = any(candidate.get("affected_code_path") for candidate in candidates)
    has_review_plan = any(
        candidate.get("evidence_review_status")
        or candidate.get("validation_status")
        or candidate.get("safe_validation_step_count")
        for candidate in candidates
    )
    candidate_ids = [
        str(candidate["hypothesis_id"])
        for candidate in candidates
        if isinstance(candidate.get("hypothesis_id"), str)
        and str(candidate.get("hypothesis_id")).strip()
    ]
    candidate_quality_gaps = _studio_candidate_quality_gap_labels(candidates)

    return [
        _studio_mission_agent_task(
            "scope_guard_intake",
            "Scope Guard",
            "complete" if "scope" in present_artifacts else "blocked",
            "authorized_artifacts_only",
            ["scope"],
            [],
            "Review scope and policy coverage.",
            ["scope_guard_status", "policy_alignment"],
            [],
        ),
        _studio_mission_agent_task(
            "artifact_intake",
            "Artifact Intake",
            "complete" if not missing_artifacts else "blocked",
            "redacted_local_artifacts_only",
            list(_studio_required_ab_artifacts()),
            [],
            "Review imported A+B artifact coverage."
            if not missing_artifacts
            else "Import missing authorized A+B artifacts.",
            ["required_ab_artifact_coverage"]
            if not missing_artifacts
            else [f"missing_{artifact}" for artifact in missing_artifacts],
            [],
        ),
        _studio_mission_agent_task(
            "surface_modeling",
            "Attack Surface Mapper",
            "complete" if has_endpoint else "not_started",
            "normalized_api_har_only",
            ["api", "har"],
            candidate_ids,
            "Review modeled endpoints and traffic facts.",
            ["endpoint_coverage", "api_har_route_matching"],
            candidate_quality_gaps,
        ),
        _studio_mission_agent_task(
            "semantic_candidate_hunt",
            "Semantic Auditor",
            "complete" if has_candidates and has_code_path else "not_started",
            "local_static_analysis_only",
            ["code", "api", "har"],
            candidate_ids,
            "Review top candidate invariants.",
            ["security_invariants", "affected_code_paths", "candidate_quality"],
            candidate_quality_gaps,
        ),
        _studio_mission_agent_task(
            "refutation_dedup_review",
            "Refutation Reviewer",
            "needs_review" if has_candidates else "not_started",
            "human_review_required",
            ["policy", "code", "api", "har"],
            candidate_ids,
            "Review refutation questions and duplicate-risk signals.",
            ["false_positive_checks", "deduplication_review", "candidate_quality"],
            candidate_quality_gaps,
        ),
        _studio_mission_agent_task(
            "evidence_validation_plan_review",
            "Evidence Planner",
            "needs_review" if has_review_plan else "not_started",
            "non_destructive_plan_only",
            ["scope", "policy", "code", "api", "har"],
            candidate_ids,
            "Review evidence needs and safe validation plans.",
            ["evidence_needs", "evidence_gaps", "safe_validation_plan"],
            candidate_quality_gaps,
        ),
        _studio_mission_agent_task(
            "report_draft_review",
            "Report Draft Builder",
            "blocked" if run_id else "not_started",
            "submission_blocked",
            ["policy", "code", "api", "har"],
            candidate_ids,
            "Export a submission-blocked draft for human review."
            if run_id
            else "Report drafting starts after a local research run.",
            ["submission_blocked_report", "redaction_review", "human_review_gate"],
            candidate_quality_gaps,
        ),
    ]


def _studio_mission_agent_task(
    task_id: str,
    agent: str,
    status: str,
    safety_gate: str,
    input_refs: list[str],
    target_candidates: list[str],
    next_action: str,
    review_focus: list[str],
    candidate_quality_gaps: list[str],
) -> dict[str, object]:
    return {
        "task_id": task_id,
        "agent": safe_preview_text(agent),
        "status": status,
        "safety_gate": safety_gate,
        "input_refs": input_refs,
        "target_candidates": target_candidates,
        "review_focus": _studio_agent_label_list(review_focus),
        "candidate_quality_gaps": _studio_agent_label_list(candidate_quality_gaps),
        "next_action": safe_preview_text(next_action),
    }


def _studio_mission_agent_task_timeline(
    agent_queue: list[dict[str, object]],
) -> list[dict[str, object]]:
    timeline: list[dict[str, object]] = []
    for task in agent_queue[:10]:
        task_id = safe_preview_text(task.get("task_id", ""))
        if not task_id:
            continue
        timeline.append(
            {
                "stage_id": f"agent_queue:{task_id}",
                "task_id": task_id,
                "attempt": 1,
                "agent": safe_preview_text(task.get("agent", "")),
                "status": safe_preview_text(task.get("status", "")),
                "safety_gate": safe_preview_text(task.get("safety_gate", "")),
                "gate_decision": _studio_agent_task_gate_decision(task),
                "input_summary": _studio_agent_task_input_summary(task),
                "output_summary": _studio_agent_task_output_summary(task),
                "next_human_action": safe_preview_text(task.get("next_action", "")),
                "report_submission_allowed": False,
                "validation_execution_allowed": False,
            }
        )
    return timeline


def _studio_agent_task_gate_decision(task: dict[str, object]) -> str:
    status = safe_preview_text(task.get("status", ""))
    if status == "complete":
        return "review_recorded"
    if status == "needs_review":
        return "human_review_required"
    if status == "blocked":
        return "blocked"
    return "pending"


def _studio_agent_task_input_summary(task: dict[str, object]) -> str:
    refs = _studio_agent_string_list(task.get("input_refs", []))
    if not refs:
        return "No input refs recorded."
    return "Input refs: " + ", ".join(refs)


def _studio_agent_task_output_summary(task: dict[str, object]) -> str:
    candidates = _studio_agent_string_list(task.get("target_candidates", []))
    focus = _studio_agent_string_list(task.get("review_focus", []))
    gaps = _studio_agent_string_list(task.get("candidate_quality_gaps", []))
    parts: list[str] = []
    if candidates:
        parts.append("candidates: " + ", ".join(candidates))
    if focus:
        parts.append("focus: " + ", ".join(focus))
    if gaps:
        parts.append("quality gaps: " + ", ".join(gaps))
    return "; ".join(parts) if parts else "No output summary recorded."


def _studio_agent_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [
        text
        for item in value
        if (text := safe_preview_text(item)) and text != "[REDACTED]"
    ][:10]


def _studio_mission_timeline_summary(
    timeline: list[dict[str, object]],
) -> dict[str, object]:
    gate_counts: dict[str, int] = {}
    blocked_stage_ids: list[str] = []
    needs_review_stage_ids: list[str] = []
    pending_stage_ids: list[str] = []
    next_human_actions: list[str] = []

    for stage in timeline[:10]:
        stage_id = safe_preview_text(stage.get("stage_id", ""))
        gate_decision = safe_preview_text(stage.get("gate_decision", "pending"))
        if not stage_id:
            continue
        gate_counts[gate_decision] = gate_counts.get(gate_decision, 0) + 1
        if gate_decision == "blocked":
            blocked_stage_ids.append(stage_id)
        elif gate_decision == "human_review_required":
            needs_review_stage_ids.append(stage_id)
        elif gate_decision == "pending":
            pending_stage_ids.append(stage_id)

        next_action = safe_preview_text(stage.get("next_human_action", ""))
        if next_action and next_action not in next_human_actions:
            next_human_actions.append(next_action)

    return {
        "total_stages": len(timeline),
        "gate_decision_counts": gate_counts,
        "blocked_stage_ids": blocked_stage_ids,
        "needs_review_stage_ids": needs_review_stage_ids,
        "pending_stage_ids": pending_stage_ids,
        "next_human_actions": next_human_actions[:5],
        "safety_gate": "review_only_no_execution",
        "report_submission_allowed": False,
        "validation_execution_allowed": False,
    }


def _studio_candidate_review_packets(
    candidates: list[dict[str, object]],
) -> list[dict[str, object]]:
    return [_studio_candidate_review_packet(candidate) for candidate in candidates[:5]]


def _studio_submission_blocked_report_summary(
    packets: list[dict[str, object]],
) -> dict[str, object]:
    ready_candidate_ids: list[str] = []
    needs_review_candidate_ids: list[str] = []
    missing_review_items: dict[str, list[str]] = {}
    report_review_queue: list[dict[str, object]] = []
    next_human_actions: list[str] = []

    for packet in packets[:5]:
        candidate_id = safe_preview_text(packet.get("candidate_id", ""))
        if not candidate_id:
            continue
        missing = _studio_agent_string_list(packet.get("missing_items", []))
        status = safe_preview_text(packet.get("status", "needs_review"))
        if packet.get("status") == "review_ready" and not missing:
            ready_candidate_ids.append(candidate_id)
        else:
            needs_review_candidate_ids.append(candidate_id)
            missing_review_items[candidate_id] = missing
        next_action = safe_preview_text(packet.get("next_human_action", ""))
        if next_action and next_action not in next_human_actions:
            next_human_actions.append(next_action)
        report_review_queue.append(
            {
                "candidate_id": candidate_id,
                "priority": _studio_report_review_priority(status, missing),
                "quality_score": _studio_nonnegative_int(packet.get("quality_score")),
                "next_human_action": next_action,
                "safety_gate": "submission_blocked_human_review",
                "report_submission_allowed": False,
                "validation_execution_allowed": False,
            }
        )

    return {
        "status": (
            "ready_for_redaction_review"
            if ready_candidate_ids and not needs_review_candidate_ids
            else "needs_human_review"
        ),
        "candidate_count": len(packets),
        "ready_candidate_ids": ready_candidate_ids,
        "needs_review_candidate_ids": needs_review_candidate_ids,
        "missing_review_items": missing_review_items,
        "report_review_queue": sorted(
            report_review_queue,
            key=lambda item: (
                _studio_report_review_priority_rank(item.get("priority")),
                -_studio_nonnegative_int(item.get("quality_score")),
            ),
        )[:5],
        "next_human_actions": next_human_actions[:5],
        "safety_gate": "submission_blocked_human_review",
        "redaction_review_required": True,
        "report_submission_allowed": False,
        "validation_execution_allowed": False,
    }


def _studio_candidate_review_packet(candidate: dict[str, object]) -> dict[str, object]:
    candidate_id = safe_preview_text(candidate.get("hypothesis_id", "candidate"))
    checklist = [
        _studio_candidate_review_item(
            "endpoint_trace",
            bool(candidate.get("affected_endpoint")),
            "Affected endpoint is traced.",
        ),
        _studio_candidate_review_item(
            "code_path_trace",
            bool(candidate.get("affected_code_path")),
            "Affected code path is traced.",
        ),
        _studio_candidate_review_item(
            "evidence_needs",
            _studio_nonnegative_int(candidate.get("evidence_need_count")) > 0,
            "Evidence needs are listed.",
        ),
        _studio_candidate_review_item(
            "refutation_checks",
            _studio_nonnegative_int(candidate.get("false_positive_check_count")) > 0,
            "False-positive checks are listed.",
        ),
        _studio_candidate_review_item(
            "deduplication_review",
            bool(candidate.get("deduplication_review_status")),
            "Deduplication review status is recorded.",
        ),
        _studio_candidate_review_item(
            "safe_validation_plan",
            _studio_nonnegative_int(candidate.get("safe_validation_step_count")) > 0,
            "Non-destructive validation plan is drafted.",
        ),
        _studio_candidate_review_item(
            "submission_blocked_report",
            candidate.get("report_status") == "submission_blocked",
            "Report draft remains submission-blocked.",
        ),
        _studio_candidate_review_item(
            "independent_cross_check",
            _studio_hallucination_guard_cross_checked(candidate),
            "Independent static or fuzzing challenge is present.",
        ),
    ]
    completed_items = [
        safe_preview_text(item.get("key", ""))
        for item in checklist
        if item.get("status") == "complete"
    ]
    missing_items = [
        safe_preview_text(item.get("key", ""))
        for item in checklist
        if item.get("status") != "complete"
    ]
    status = "review_ready" if not missing_items else "needs_review"
    return {
        "candidate_id": candidate_id,
        "status": status,
        "completed_items": completed_items,
        "missing_items": missing_items,
        "checklist": checklist,
        "next_human_action": _studio_candidate_review_next_action(
            missing_items,
            candidate,
        ),
        "safety_gate": "human_review_required",
        "evidence_need_count": _studio_nonnegative_int(
            candidate.get("evidence_need_count")
        ),
        "false_positive_check_count": _studio_nonnegative_int(
            candidate.get("false_positive_check_count")
        ),
        "safe_validation_step_count": _studio_nonnegative_int(
            candidate.get("safe_validation_step_count")
        ),
        "quality_score": _studio_nonnegative_int(candidate.get("quality_score")),
        "report_review_priority": _studio_report_review_priority(
            status,
            missing_items,
        ),
        "report_status": safe_preview_text(
            candidate.get("report_status", "submission_blocked")
        ),
        "hallucination_guard_status": _studio_candidate_hallucination_guard_status(
            candidate
        ),
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _studio_report_review_priority(status: str, missing_items: list[str]) -> str:
    if status == "review_ready" and not missing_items:
        return "redaction_review_ready"
    return "resolve_review_gaps"


def _studio_report_review_priority_rank(value: object) -> int:
    priority = safe_preview_text(value)
    if priority == "redaction_review_ready":
        return 0
    if priority == "resolve_review_gaps":
        return 1
    return 2


def _studio_readiness_audit(
    present_artifacts: list[str],
    advisory_artifacts: list[str],
    candidates: list[dict[str, object]],
    candidate_review_packets: list[dict[str, object]],
    submission_blocked_report_summary: dict[str, object],
    candidate_hunter_backlog: list[dict[str, object]],
    candidate_hunter_iteration: dict[str, object],
    agent_handoff_pack: dict[str, object],
) -> dict[str, object]:
    checks = [
        _studio_readiness_check(
            "authorized_ab_intake",
            all(kind in present_artifacts for kind in _studio_required_ab_artifacts()),
            present_artifacts,
            "Authorized policy, scope, API, HAR, and local code are present.",
        ),
        _studio_readiness_check(
            "hallucination_governed_candidates",
            bool(candidates)
            and all(_studio_candidate_is_hallucination_governed(candidate) for candidate in candidates),
            _studio_candidate_readiness_refs(candidates),
            "LLM claims remain unverified until local evidence and cross-checks agree.",
        ),
        _studio_readiness_check(
            "advisory_knowledge_context",
            bool(advisory_artifacts),
            _studio_advisory_readiness_refs(advisory_artifacts),
            "Private knowledge/RAG context is advisory few-shot context only.",
        ),
        _studio_readiness_check(
            "cross_validation_refutation",
            bool(candidates)
            and all(_studio_candidate_has_cross_validation(candidate) for candidate in candidates),
            _studio_cross_validation_refs(candidates, advisory_artifacts),
            "Independent static or fuzzing challenge and refutation questions are present.",
        ),
        _studio_readiness_check(
            "candidate_hunter_backlog",
            not candidate_hunter_backlog
            and candidate_hunter_iteration.get("status") == "ready_for_human_review",
            _studio_candidate_readiness_refs(candidates),
            "Candidate hunter backlog is clear for human review.",
        ),
        _studio_readiness_check(
            "safe_validation_planning",
            bool(candidates)
            and all(
                _studio_nonnegative_int(candidate.get("safe_validation_step_count")) > 0
                for candidate in candidates
            ),
            _studio_candidate_readiness_refs(candidates),
            "Non-destructive validation plans exist, but execution remains blocked.",
        ),
        _studio_readiness_check(
            "submission_blocked_report",
            submission_blocked_report_summary.get("status") == "ready_for_redaction_review"
            and submission_blocked_report_summary.get("report_submission_allowed") is False,
            _studio_agent_string_list(
                submission_blocked_report_summary.get("ready_candidate_ids", [])
            ),
            "Report draft is ready only for redaction and human review.",
            safety_gate="submission_blocked_human_review",
        ),
        _studio_readiness_check(
            "review_only_handoff",
            agent_handoff_pack.get("safety_gate") == "review_only_no_execution"
            and agent_handoff_pack.get("execution_allowed") is False
            and agent_handoff_pack.get("validation_allowed") is False
            and agent_handoff_pack.get("report_submission_allowed") is False,
            _studio_agent_string_list(agent_handoff_pack.get("agent_queue_refs", [])),
            "Agent handoff is review-only and cannot execute validation or submission.",
        ),
    ]
    passed_count = sum(1 for check in checks if check["status"] == "passed")
    return {
        "status": (
            "demo_ready_for_human_review"
            if passed_count == len(checks)
            else "needs_review"
        ),
        "required_check_count": len(checks),
        "passed_check_count": passed_count,
        "checks": checks,
        "safety_gate": "review_only_no_execution",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _studio_readiness_check(
    key: str,
    passed: bool,
    evidence_refs: list[str],
    summary: str,
    *,
    safety_gate: str = "review_only_no_execution",
) -> dict[str, object]:
    return {
        "key": key,
        "status": "passed" if passed else "needs_review",
        "summary": safe_preview_text(summary),
        "evidence_refs": _studio_agent_label_list(evidence_refs),
        "safety_gate": safety_gate,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _studio_candidate_is_hallucination_governed(candidate: dict[str, object]) -> bool:
    guard = candidate.get("hallucination_guard")
    return (
        isinstance(guard, dict)
        and guard.get("status") == "cross_checked"
        and guard.get("model_output_status") == "unverified_claim_not_fact"
        and candidate.get("quality_status") == "review_ready"
    )


def _studio_candidate_has_cross_validation(candidate: dict[str, object]) -> bool:
    guard = candidate.get("hallucination_guard")
    independent_sources = (
        _studio_agent_string_list(guard.get("independent_cross_check_sources", []))
        if isinstance(guard, dict)
        else []
    )
    return (
        bool(independent_sources)
        and _studio_nonnegative_int(candidate.get("false_positive_check_count")) > 0
    )


def _studio_candidate_readiness_refs(
    candidates: list[dict[str, object]],
) -> list[str]:
    refs: list[str] = []
    for candidate in candidates:
        candidate_id = safe_preview_text(candidate.get("hypothesis_id", ""))
        if candidate_id:
            refs.append(candidate_id)
    return refs


def _studio_cross_validation_refs(
    candidates: list[dict[str, object]],
    advisory_artifacts: list[str],
) -> list[str]:
    refs: set[str] = {
        artifact
        for artifact in advisory_artifacts
        if artifact in {"sarif", "fuzzing"}
    }
    for candidate in candidates:
        guard = candidate.get("hallucination_guard")
        if not isinstance(guard, dict):
            continue
        refs.update(_studio_agent_string_list(guard.get("independent_cross_check_sources", [])))
    return sorted(refs)


def _studio_advisory_readiness_refs(advisory_artifacts: list[str]) -> list[str]:
    refs = set(advisory_artifacts)
    refs.add("knowledge")
    return sorted(refs)


def _studio_candidate_review_item(
    key: str,
    complete: bool,
    label: str,
) -> dict[str, str]:
    return {
        "key": key,
        "status": "complete" if complete else "needs_review",
        "label": safe_preview_text(label),
    }


def _studio_hallucination_guard_cross_checked(candidate: dict[str, object]) -> bool:
    guard = candidate.get("hallucination_guard")
    return isinstance(guard, dict) and guard.get("status") == "cross_checked"


def _studio_candidate_hallucination_guard_status(
    candidate: dict[str, object],
) -> str:
    guard = candidate.get("hallucination_guard")
    if not isinstance(guard, dict):
        return "needs_review"
    return safe_preview_text(guard.get("status", "needs_review"))


def _studio_candidate_review_next_action(
    missing_items: list[str],
    candidate: dict[str, object],
) -> str:
    by_gap = {
        "endpoint_trace": "Map the affected endpoint from authorized API or HAR artifacts.",
        "code_path_trace": "Trace the affected code path in authorized local code.",
        "evidence_needs": "List concrete evidence needed for human review.",
        "refutation_checks": "Add false-positive checks before validation planning.",
        "deduplication_review": "Record duplicate-risk and prior-finding review.",
        "safe_validation_plan": "Draft a non-destructive validation plan for approval.",
        "submission_blocked_report": "Export only a submission-blocked report draft.",
        "independent_cross_check": "Add SARIF or fuzzing challenge evidence before high confidence.",
    }
    for item in missing_items:
        if item in by_gap:
            return by_gap[item]
    next_report_action = safe_preview_text(candidate.get("next_report_action", ""))
    return next_report_action or "Human evidence and redaction review required."


def _studio_agent_label_list(values: list[str]) -> list[str]:
    labels: list[str] = []
    for value in values:
        text = safe_preview_text(value)
        if text and text != "[REDACTED]":
            labels.append(text)
    return labels[:10]


def _studio_candidate_quality_gap_labels(candidates: list[dict[str, object]]) -> list[str]:
    required_reasons = {
        "endpoint_and_code_path_traced": "missing_endpoint_or_code_path_trace",
        "provenance_review_present": "missing_provenance_review",
        "evidence_needs_present": "missing_evidence_needs",
        "refutation_checks_present": "missing_refutation_checks",
        "deduplication_review_present": "missing_deduplication_review",
        "safe_validation_plan_present": "missing_safe_validation_plan",
        "submission_blocked_report_ready": "missing_submission_blocked_report_state",
        "hallucination_guard_cross_checked": "missing_cross_validation_consensus",
    }
    labels: list[str] = []
    for candidate in candidates:
        hypothesis_id = candidate.get("hypothesis_id")
        if not isinstance(hypothesis_id, str) or not hypothesis_id.strip():
            continue
        reasons = candidate.get("quality_reasons", [])
        present_reasons = {reason for reason in reasons if isinstance(reason, str)}
        candidate_labels = [
            label
            for reason, label in required_reasons.items()
            if reason not in present_reasons
        ]
        if _studio_nonnegative_int(candidate.get("evidence_gap_count")) > 0:
            candidate_labels.append("evidence_gaps_need_review")
        if (
            candidate.get("quality_status") == "review_ready"
            and not candidate_labels
        ):
            continue
        labels.extend(f"{hypothesis_id}:{label}" for label in candidate_labels)
    return labels[:10]


def _studio_candidate_hunter_backlog(
    candidates: list[dict[str, object]],
    missing_artifacts: list[str],
) -> list[dict[str, object]]:
    if missing_artifacts:
        return [
            _studio_candidate_hunter_work_item(
                work_item_id="intake:missing_ab_artifacts",
                candidate_id=None,
                gap="missing_ab_artifacts",
                review_focus=["required_ab_artifact_coverage", "scope_guard_status"],
                required_evidence=[f"authorized_{artifact}" for artifact in missing_artifacts],
                next_action=(
                    "Import missing authorized A+B artifacts before candidate hunting: "
                    + ", ".join(missing_artifacts)
                ),
            )
        ]

    items: list[dict[str, object]] = []
    for candidate in candidates[:5]:
        candidate_id = safe_preview_text(candidate.get("hypothesis_id", "candidate"))
        if not candidate_id:
            continue
        items.extend(_studio_candidate_hunter_candidate_items(candidate_id, candidate))
    return items[:10]


def _studio_candidate_hunter_candidate_items(
    candidate_id: str,
    candidate: dict[str, object],
) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    if not candidate.get("affected_endpoint"):
        items.append(
            _studio_candidate_hunter_work_item(
                work_item_id=f"{candidate_id}:map_endpoint",
                candidate_id=candidate_id,
                gap="missing_endpoint",
                review_focus=["endpoint_coverage", "api_har_route_matching"],
                required_evidence=["api_route", "har_request_summary"],
                next_action=f"Map the affected endpoint for {candidate_id} from API/HAR evidence.",
            )
        )
    if not candidate.get("affected_code_path"):
        items.append(
            _studio_candidate_hunter_work_item(
                work_item_id=f"{candidate_id}:map_code_path",
                candidate_id=candidate_id,
                gap="missing_code_path",
                review_focus=["affected_code_paths", "security_invariants"],
                required_evidence=["local_code_reference", "handler_symbol"],
                next_action=f"Map the affected code path for {candidate_id} from local code.",
            )
        )
    if not candidate.get("provenance_review_status"):
        items.append(
            _studio_candidate_hunter_work_item(
                work_item_id=f"{candidate_id}:review_provenance",
                candidate_id=candidate_id,
                gap="missing_provenance_review",
                review_focus=["provenance_review", "artifact_traceability"],
                required_evidence=["scope", "policy", "code", "api", "har"],
                next_action=f"Review provenance artifacts supporting {candidate_id}.",
            )
        )
    if (
        not candidate.get("evidence_review_status")
        or _studio_nonnegative_int(candidate.get("evidence_need_count")) == 0
    ):
        items.append(
            _studio_candidate_hunter_work_item(
                work_item_id=f"{candidate_id}:define_evidence_needs",
                candidate_id=candidate_id,
                gap="missing_evidence_needs",
                review_focus=["evidence_needs", "human_evidence_review"],
                required_evidence=["sanitized_evidence_plan"],
                next_action=f"Define report-safe evidence needs for {candidate_id}.",
            )
        )
    if (
        not candidate.get("refutation_review_status")
        or _studio_nonnegative_int(candidate.get("false_positive_check_count")) == 0
    ):
        items.append(
            _studio_candidate_hunter_work_item(
                work_item_id=f"{candidate_id}:add_refutation",
                candidate_id=candidate_id,
                gap="missing_refutation_checks",
                review_focus=["false_positive_checks", "independent_refutation_review"],
                required_evidence=["refutation_questions"],
                next_action=f"Add refutation questions for {candidate_id}.",
            )
        )
    if not candidate.get("deduplication_review_status"):
        items.append(
            _studio_candidate_hunter_work_item(
                work_item_id=f"{candidate_id}:review_dedup",
                candidate_id=candidate_id,
                gap="missing_deduplication_review",
                review_focus=["deduplication_review", "duplicate_risk"],
                required_evidence=["candidate_similarity_review"],
                next_action=f"Review duplicate risk for {candidate_id}.",
            )
        )
    if (
        not candidate.get("validation_status")
        or _studio_nonnegative_int(candidate.get("safe_validation_step_count")) == 0
    ):
        items.append(
            _studio_candidate_hunter_work_item(
                work_item_id=f"{candidate_id}:draft_validation_plan",
                candidate_id=candidate_id,
                gap="missing_safe_validation_plan",
                review_focus=["safe_validation_plan", "non_destructive_plan_only"],
                required_evidence=["non_destructive_validation_plan"],
                next_action=f"Draft a non-destructive validation plan for {candidate_id}.",
            )
        )
    if candidate.get("report_status") != "submission_blocked":
        items.append(
            _studio_candidate_hunter_work_item(
                work_item_id=f"{candidate_id}:prepare_report_draft",
                candidate_id=candidate_id,
                gap="missing_submission_blocked_report",
                review_focus=["submission_blocked_report", "redaction_review"],
                required_evidence=["submission_blocked_report_draft"],
                next_action=f"Prepare a submission-blocked report draft for {candidate_id}.",
            )
        )
    guard = candidate.get("hallucination_guard", {})
    if not isinstance(guard, dict) or guard.get("status") != "cross_checked":
        items.append(
            _studio_candidate_hunter_work_item(
                work_item_id=f"{candidate_id}:cross_check_claims",
                candidate_id=candidate_id,
                gap="missing_cross_validation_consensus",
                review_focus=["local_artifact_trace", "independent_refutation_review"],
                required_evidence=["local_evidence_source", "cross_validation_source"],
                next_action=f"Cross-check model claims for {candidate_id} against local evidence.",
            )
        )
    if _studio_nonnegative_int(candidate.get("evidence_gap_count")) > 0:
        items.append(
            _studio_candidate_hunter_work_item(
                work_item_id=f"{candidate_id}:resolve_evidence_gaps",
                candidate_id=candidate_id,
                gap="evidence_gaps_need_review",
                review_focus=["evidence_gaps", "report_safe_evidence"],
                required_evidence=["gap_resolution_notes"],
                next_action=f"Resolve evidence gaps for {candidate_id}.",
            )
        )
    return items


def _studio_candidate_hunter_work_item(
    *,
    work_item_id: str,
    candidate_id: str | None,
    gap: str,
    review_focus: list[str],
    required_evidence: list[str],
    next_action: str,
) -> dict[str, object]:
    return {
        "work_item_id": safe_preview_text(work_item_id),
        "candidate_id": safe_preview_text(candidate_id or ""),
        "gap": safe_preview_text(gap),
        "status": "needs_review",
        "review_focus": _studio_agent_label_list(review_focus),
        "required_evidence": _studio_agent_label_list(required_evidence),
        "next_action": safe_preview_text(next_action),
        "safety_gate": "review_only_no_execution",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _studio_candidate_hunter_iteration(
    backlog: list[dict[str, object]],
    quality_summary: dict[str, object],
) -> dict[str, object]:
    priority_order = [
        work_item_id
        for item in backlog[:10]
        if (work_item_id := safe_preview_text(item.get("work_item_id", "")))
    ]
    first_gap = safe_preview_text(backlog[0].get("gap", "")) if backlog else ""
    quality_gate = safe_preview_text(
        quality_summary.get("top_candidate_quality_gate", "")
    )
    if first_gap == "missing_ab_artifacts":
        status = "blocked"
    elif priority_order:
        status = "needs_review"
    elif quality_gate == "passed":
        status = "ready_for_human_review"
    else:
        status = "needs_review"

    review_focus: list[str] = []
    for item in backlog[:3]:
        review_focus.extend(_studio_agent_string_list(item.get("review_focus", [])))

    return {
        "iteration_id": "candidate_hunter:next_review",
        "status": status,
        "work_item_count": len(backlog),
        "priority_order": priority_order,
        "next_review_agent": _studio_candidate_hunter_next_agent(first_gap),
        "review_focus": _studio_agent_label_list(review_focus),
        "success_criteria": _studio_candidate_hunter_success_criteria(
            backlog,
            quality_gate,
        ),
        "safety_gate": "review_only_no_execution",
        "completion_gate": "human_review_required",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _studio_candidate_hunter_next_agent(gap: str) -> str:
    by_gap = {
        "missing_ab_artifacts": "Artifact Intake",
        "missing_endpoint": "Attack Surface Mapper",
        "missing_code_path": "Semantic Auditor",
        "missing_provenance_review": "Scope Guard",
        "missing_evidence_needs": "Evidence Planner",
        "missing_refutation_checks": "Refutation Reviewer",
        "missing_deduplication_review": "Refutation Reviewer",
        "missing_safe_validation_plan": "Evidence Planner",
        "missing_submission_blocked_report": "Report Draft Builder",
        "missing_cross_validation_consensus": "Refutation Reviewer",
        "evidence_gaps_need_review": "Evidence Planner",
    }
    return by_gap.get(gap, "Human Reviewer")


def _studio_candidate_hunter_success_criteria(
    backlog: list[dict[str, object]],
    quality_gate: str,
) -> list[str]:
    if not backlog and quality_gate == "passed":
        return [
            "Top candidates remain review-ready after human evidence review.",
            "Submission-blocked report draft is ready for redaction review.",
        ]

    criteria: list[str] = []
    for item in backlog[:3]:
        work_item_id = safe_preview_text(item.get("work_item_id", ""))
        required = _studio_agent_string_list(item.get("required_evidence", []))
        if not work_item_id:
            continue
        if required:
            criteria.append(
                f"{work_item_id} has traceable evidence: {', '.join(required)}."
            )
        else:
            criteria.append(f"{work_item_id} has review notes and a human decision.")
    criteria.append("No validation, fuzzing, or report submission is executed.")
    return _studio_agent_label_list(criteria)


def _studio_candidate_hunter_plan(
    backlog: list[dict[str, object]],
    iteration: dict[str, object],
) -> dict[str, object]:
    plan_steps = [
        _studio_candidate_hunter_plan_step(item)
        for item in backlog[:10]
        if safe_preview_text(item.get("work_item_id", ""))
    ]
    return {
        "plan_id": "candidate_hunter:autonomous_review_plan",
        "status": safe_preview_text(iteration.get("status", "needs_review")),
        "work_item_count": len(backlog),
        "step_count": len(plan_steps),
        "next_review_agent": safe_preview_text(
            iteration.get("next_review_agent", "Human Reviewer")
        ),
        "plan_steps": plan_steps,
        "hallucination_governance": _studio_candidate_hunter_hallucination_governance(),
        "safety_gate": "review_only_no_execution",
        "completion_gate": "human_review_required",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _studio_candidate_hunter_plan_step(item: dict[str, object]) -> dict[str, object]:
    work_item_id = safe_preview_text(item.get("work_item_id", ""))
    return {
        "step_id": f"candidate_hunter:plan:{work_item_id}",
        "work_item_id": work_item_id,
        "candidate_id": safe_preview_text(item.get("candidate_id", "")),
        "assigned_agent": _studio_candidate_hunter_next_agent(
            safe_preview_text(item.get("gap", ""))
        ),
        "gap": safe_preview_text(item.get("gap", "")),
        "input_refs": ["scope", "policy", "code", "api", "har"],
        "review_focus": _studio_agent_string_list(item.get("review_focus", [])),
        "required_evidence": _studio_agent_string_list(
            item.get("required_evidence", [])
        ),
        "next_action": safe_preview_text(item.get("next_action", "")),
        "review_checklist": _studio_candidate_hunter_plan_step_review_checklist(
            item
        ),
        "success_criteria": _studio_candidate_hunter_plan_step_success(item),
        "hallucination_governance_refs": _studio_candidate_hunter_plan_step_governance_refs(
            item
        ),
        "safety_gate": "review_only_no_execution",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _studio_candidate_hunter_plan_step_success(
    item: dict[str, object],
) -> list[str]:
    work_item_id = safe_preview_text(item.get("work_item_id", "candidate_work_item"))
    required = _studio_agent_string_list(item.get("required_evidence", []))
    criteria = [
        f"{work_item_id} is reviewed against authorized local artifacts.",
    ]
    if required:
        criteria.append("Evidence refs required: " + ", ".join(required) + ".")
    criteria.append("No validation, fuzzing, or report submission is executed.")
    return _studio_agent_label_list(criteria)


def _studio_candidate_hunter_plan_step_review_checklist(
    item: dict[str, object],
) -> list[dict[str, object]]:
    gap = safe_preview_text(item.get("gap", ""))
    required = _studio_agent_string_list(item.get("required_evidence", []))
    evidence_label = (
        "Record traceable evidence refs: " + ", ".join(required) + "."
        if required
        else "Record review notes and a human decision."
    )

    def checklist_item(key: str, label: str, status: str) -> dict[str, object]:
        return {
            "key": key,
            "label": safe_preview_text(label),
            "status": status,
            "required": True,
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        }

    return [
        checklist_item(
            "authorized_artifact_trace",
            "Trace the step to scope, policy, code, API, and HAR artifacts.",
            "needs_review",
        ),
        checklist_item(
            "evidence_requirements",
            evidence_label,
            "needs_review",
        ),
        checklist_item(
            "refutation_review",
            "Record false-positive questions or confirm existing refutation coverage.",
            "needs_review"
            if gap
            in {"missing_refutation_checks", "missing_cross_validation_consensus"}
            else "confirm_current_state",
        ),
        checklist_item(
            "deduplication_review",
            "Compare endpoint, code path, invariant, and impact against prior candidates.",
            "needs_review"
            if gap == "missing_deduplication_review"
            else "confirm_current_state",
        ),
        checklist_item(
            "safe_validation_plan",
            "Draft or review a non-destructive validation plan without execution.",
            "needs_review"
            if gap == "missing_safe_validation_plan"
            else "confirm_current_state",
        ),
        checklist_item(
            "submission_blocked_report_draft",
            "Confirm report draft readiness while keeping submission blocked.",
            "needs_review"
            if gap == "missing_submission_blocked_report"
            else "confirm_current_state",
        ),
    ]


def _studio_candidate_hunter_plan_step_governance_refs(
    item: dict[str, object],
) -> list[str]:
    gap = safe_preview_text(item.get("gap", ""))
    refs = [
        "LLM output remains an unverified claim until local evidence is traced.",
        "Knowledge/RAG context is few-shot guidance only and cannot satisfy cross-validation.",
    ]
    if gap == "missing_cross_validation_consensus":
        refs.append(
            "High confidence requires local evidence plus SARIF, fuzzing, static analysis rule, or independent refutation consensus."
        )
    return _studio_agent_label_list(refs)


def _studio_candidate_hunter_hallucination_governance() -> dict[str, object]:
    return {
        "claim_promotion_rule": "no_verified_evidence_no_high_confidence",
        "model_output_policy": "llm_claims_start_unverified",
        "knowledge_policy": "rag_few_shot_context_only_not_cross_validation",
        "required_consensus": [
            "authorized_local_artifact_evidence",
            "independent_refutation_or_static_rule",
            "human_review_decision",
        ],
        "independent_challenge_sources": [
            "sarif_static_analysis",
            "fuzzing_artifact",
            "second_model_refutation",
            "manual_code_review",
        ],
        "candidate_promotion_allowed": False,
    }


def _studio_candidate_hunter_review_loop(
    plan: dict[str, object],
) -> dict[str, object]:
    steps = [
        _studio_candidate_hunter_review_loop_step(step)
        for step in _studio_plan_step_list(plan.get("plan_steps", []))[:10]
        if safe_preview_text(step.get("step_id", ""))
    ]
    governance = plan.get("hallucination_governance", {})
    if not isinstance(governance, dict):
        governance = {}
    return {
        "loop_id": "candidate_hunter:next_review_loop",
        "status": safe_preview_text(plan.get("status", "needs_review")),
        "source_plan_id": safe_preview_text(
            plan.get("plan_id", "candidate_hunter:autonomous_review_plan")
        ),
        "active_step_count": len(steps),
        "next_review_agent": safe_preview_text(
            plan.get("next_review_agent", "Human Reviewer")
        ),
        "review_agents": _studio_unique_review_loop_values(
            step.get("assigned_agent", "") for step in steps
        ),
        "required_evidence": _studio_unique_review_loop_values(
            evidence
            for step in steps
            for evidence in _studio_agent_string_list(step.get("required_evidence", []))
        ),
        "active_steps": steps,
        "governance_summary": {
            "claim_promotion_rule": safe_preview_text(
                governance.get(
                    "claim_promotion_rule",
                    "no_verified_evidence_no_high_confidence",
                )
            ),
            "required_consensus": _studio_agent_string_list(
                governance.get("required_consensus", [])
            ),
            "candidate_promotion_allowed": False,
        },
        "blocked_actions": [
            "execute_live_validation",
            "run_fuzzer",
            "submit_report",
        ],
        "safety_gate": "review_only_no_execution",
        "completion_gate": "human_review_required",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _studio_candidate_hunter_review_loop_step(
    step: dict[str, object],
) -> dict[str, object]:
    return {
        "step_id": safe_preview_text(step.get("step_id", "")),
        "work_item_id": safe_preview_text(step.get("work_item_id", "")),
        "candidate_id": safe_preview_text(step.get("candidate_id", "")),
        "assigned_agent": safe_preview_text(
            step.get("assigned_agent", "Human Reviewer")
        ),
        "gap": safe_preview_text(step.get("gap", "")),
        "required_evidence": _studio_agent_string_list(
            step.get("required_evidence", [])
        ),
        "governance_refs": _studio_agent_string_list(
            step.get("hallucination_governance_refs", [])
        ),
        "review_checklist": _studio_candidate_hunter_review_loop_checklist(
            step.get("review_checklist", [])
        ),
        "next_action": safe_preview_text(step.get("next_action", "")),
        "success_criteria": _studio_agent_string_list(
            step.get("success_criteria", [])
        ),
        "safety_gate": "review_only_no_execution",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _studio_candidate_hunter_review_loop_checklist(
    value: object,
) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    checklist: list[dict[str, object]] = []
    for item in value[:10]:
        if not isinstance(item, dict):
            continue
        key = safe_preview_text(item.get("key", ""))
        if not key:
            continue
        checklist.append(
            {
                "key": key,
                "label": safe_preview_text(item.get("label", "Review item.")),
                "status": safe_preview_text(item.get("status", "needs_review")),
                "required": item.get("required") is not False,
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            }
        )
    return checklist


def _studio_candidate_hunter_execution_loop(
    review_loop: dict[str, object],
    candidates: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    safe_candidates = _studio_candidate_hunter_budgeted_candidates(candidates or [])
    active_steps = _studio_plan_step_list(review_loop.get("active_steps", []))
    active_work_items = [
        _studio_candidate_hunter_execution_work_item(step)
        for step in active_steps[:10]
        if safe_preview_text(step.get("work_item_id", ""))
    ]
    next_candidate_actions = _studio_candidate_hunter_next_candidate_actions(
        safe_candidates
    )
    current_phase = (
        safe_preview_text(active_work_items[0].get("phase_id", ""))
        if active_work_items
        else safe_preview_text(
            next_candidate_actions[0].get("phase_id", "")
            if next_candidate_actions
            else "report_draft_readiness"
        )
    )
    status = safe_preview_text(review_loop.get("status", "needs_review"))
    phases = _studio_candidate_hunter_execution_phases(current_phase, active_work_items)
    evidence_matrix = _studio_candidate_hunter_evidence_matrix(safe_candidates)
    learning_feedback_target = _studio_candidate_hunter_learning_feedback_target(
        next_candidate_actions
    )
    return {
        "loop_id": "candidate_hunter:bounded_execution_loop",
        "status": status,
        "iteration": 1,
        "source_review_loop_id": safe_preview_text(
            review_loop.get("loop_id", "candidate_hunter:next_review_loop")
        ),
        "source_plan_id": safe_preview_text(
            review_loop.get("source_plan_id", "candidate_hunter:autonomous_review_plan")
        ),
        "candidate_budget": 5,
        "top_candidate_limit": 5,
        "current_phase": current_phase,
        "phase_count": len(phases),
        "phases": phases,
        "active_work_items": active_work_items,
        "candidate_evidence_summary": _studio_candidate_hunter_evidence_summary(
            safe_candidates
        ),
        "candidate_evidence_matrix": evidence_matrix,
        "ranked_top_candidates": _studio_candidate_hunter_ranked_top_candidates(
            evidence_matrix,
            next_candidate_actions,
        ),
        "next_candidate_actions": next_candidate_actions,
        "refutation_queue": _studio_candidate_hunter_refutation_queue(
            evidence_matrix
        ),
        "deduplication_queue": _studio_candidate_hunter_deduplication_queue(
            safe_candidates
        ),
        "safe_validation_queue": _studio_candidate_hunter_safe_validation_queue(
            safe_candidates
        ),
        "report_draft_queue": _studio_candidate_hunter_report_draft_queue(
            safe_candidates
        ),
        "learning_feedback_target": learning_feedback_target,
        "learning_review_actions": _studio_candidate_hunter_learning_review_actions(
            learning_feedback_target,
            evidence_matrix,
        ),
        "promotion_policy": {
            "candidate_promotion_allowed": False,
            "requires_local_artifact_trace": True,
            "requires_independent_refutation": True,
            "requires_human_review": True,
        },
        "blocked_actions": [
            "execute_live_validation",
            "run_fuzzer",
            "submit_report",
            "touch_real_user_data",
            "store_raw_secret",
        ],
        "safety_gate": "bounded_autonomous_review_only",
        "completion_gate": "human_review_required",
        "execution_allowed": False,
        "validation_allowed": False,
        "validation_execution_allowed": False,
        "report_submission_allowed": False,
        "candidate_promotion_allowed": False,
    }


def _studio_candidate_hunter_budgeted_candidates(
    candidates: list[dict[str, object]],
) -> list[dict[str, object]]:
    rows: list[tuple[int, dict[str, object], dict[str, object]]] = []
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, dict):
            continue
        if not safe_preview_text(candidate.get("hypothesis_id", "")):
            continue
        rows.append((index, candidate, _studio_candidate_hunter_evidence_row(candidate)))
    selected = sorted(
        rows,
        key=lambda item: (
            0 if _studio_candidate_hunter_row_is_evidence_ready(item[2]) else 1,
            -_studio_candidate_hunter_priority_score(item[2]),
            safe_preview_text(item[2].get("candidate_id", "")),
        ),
    )[:5]
    return [candidate for _, candidate, _ in sorted(selected, key=lambda item: item[0])]


def _studio_candidate_hunter_learning_review_actions(
    learning_feedback_target: dict[str, object],
    evidence_matrix: list[dict[str, object]],
) -> list[dict[str, object]]:
    allowed_outcomes = [
        outcome
        for outcome in _studio_agent_string_list(
            learning_feedback_target.get("allowed_outcomes", [])
        )
        if outcome in {"confirmed", "refuted", "needs_more_evidence", "duplicate"}
    ] or ["confirmed", "refuted", "needs_more_evidence", "duplicate"]
    source_loop_id = safe_preview_text(
        learning_feedback_target.get(
            "source_loop_id", "candidate_hunter:bounded_execution_loop"
        )
    )
    target_id = safe_preview_text(
        learning_feedback_target.get(
            "target_id", "candidate_hunter:learning_feedback:next_actions"
        )
    )
    evidence_by_candidate_id = {
        safe_preview_text(item.get("candidate_id", "")): item
        for item in evidence_matrix
        if safe_preview_text(item.get("candidate_id", ""))
    }
    actions: list[dict[str, object]] = []
    for candidate_id in _studio_agent_string_list(
        learning_feedback_target.get("candidate_ids", [])
    )[:5]:
        evidence = evidence_by_candidate_id.get(candidate_id, {})
        suggested_outcome = (
            "duplicate"
            if _studio_nonnegative_int(evidence.get("duplicate_risk_score")) >= 50
            else "confirmed"
            if _studio_candidate_hunter_row_is_evidence_ready(evidence)
            else "needs_more_evidence"
        )
        action = {
            "action_id": f"{target_id}:{candidate_id}",
            "candidate_id": candidate_id,
            "source_loop_id": source_loop_id,
            "suggested_outcome": suggested_outcome,
            "evidence_ready": _studio_candidate_hunter_row_is_evidence_ready(
                evidence
            ),
            "trace_status": safe_preview_text(
                evidence.get("evidence_trace_status", "needs_evidence")
            )
            or "needs_evidence",
            "missing_evidence": _studio_agent_string_list(
                evidence.get("missing_evidence", [])
            ),
            "missing_required_artifact_kinds": _studio_agent_string_list(
                evidence.get("missing_required_artifact_kinds", [])
            ),
            "allowed_outcomes": allowed_outcomes,
            "next_action": (
                f"Review {candidate_id} and record a human outcome before updating future ranking."
            ),
            "safety_gate": "human_review_required",
            "learning_write_allowed": False,
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        }
        template = _studio_candidate_hunter_learning_signal_template(
            evidence,
            candidate_id=candidate_id,
            source_loop_id=source_loop_id,
        )
        if template:
            action["learning_signal_template"] = template
        actions.append(action)
    return actions


def _studio_candidate_hunter_ranked_top_candidates(
    evidence_matrix: list[dict[str, object]],
    next_candidate_actions: list[dict[str, object]],
) -> list[dict[str, object]]:
    evidence_by_candidate_id = {
        safe_preview_text(item.get("candidate_id", "")): item
        for item in evidence_matrix
        if safe_preview_text(item.get("candidate_id", ""))
    }
    ranked: list[dict[str, object]] = []
    for rank, action in enumerate(next_candidate_actions[:5], start=1):
        candidate_id = safe_preview_text(action.get("candidate_id", ""))
        if not candidate_id:
            continue
        evidence = evidence_by_candidate_id.get(candidate_id, {})
        ranked.append(
            {
                "rank": rank,
                "candidate_id": candidate_id,
                "phase_id": safe_preview_text(action.get("phase_id", "refutation")),
                "priority_score": _studio_nonnegative_int(
                    action.get("priority_score")
                ),
                "reason": safe_preview_text(action.get("reason", "needs_review")),
                "required_evidence": _studio_agent_string_list(
                    action.get("required_evidence", [])
                ),
                "next_action": safe_preview_text(action.get("next_action", "")),
                "affected_endpoint": safe_preview_text(
                    evidence.get("affected_endpoint", "")
                ),
                "affected_code_path": safe_preview_text(
                    evidence.get("affected_code_path", "")
                ),
                "quality_status": safe_preview_text(
                    evidence.get("quality_status", "needs_review")
                ),
                "evidence_ready": _studio_candidate_hunter_row_is_evidence_ready(
                    evidence
                ),
                "trace_status": safe_preview_text(
                    evidence.get("evidence_trace_status", "needs_evidence")
                )
                or "needs_evidence",
                "missing_evidence": _studio_agent_string_list(
                    evidence.get("missing_evidence", [])
                ),
                "missing_required_artifact_kinds": _studio_agent_string_list(
                    evidence.get("missing_required_artifact_kinds", [])
                ),
                "ranking_signal_breakdown": _studio_agent_string_list(
                    evidence.get("ranking_signal_breakdown", [])
                ),
                "safety_gate": safe_preview_text(
                    action.get("safety_gate", "review_only_no_execution")
                ),
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            }
        )
    return ranked


def _studio_candidate_hunter_learning_signal_template(
    evidence: dict[str, object],
    *,
    candidate_id: str,
    source_loop_id: str,
) -> dict[str, object]:
    playbook_id = safe_preview_text(evidence.get("playbook_id", ""))
    surface_key = safe_preview_text(evidence.get("surface_key", ""))
    if not playbook_id or not surface_key:
        return {}
    return {
        "playbook_id": playbook_id,
        "surface_key": surface_key,
        "target_relationships": [
            f"candidate:{candidate_id}",
            source_loop_id,
        ],
        "human_review_required": True,
        "learning_write_allowed": False,
    }


def _studio_candidate_hunter_refutation_queue(
    evidence_matrix: list[dict[str, object]],
) -> list[dict[str, object]]:
    items = [
        _studio_candidate_hunter_refutation_item(row)
        for row in evidence_matrix
        if _studio_candidate_hunter_needs_refutation(row)
    ]
    return sorted(
        items,
        key=lambda item: (
            -_studio_nonnegative_int(item.get("priority_score")),
            safe_preview_text(item.get("candidate_id", "")),
        ),
    )[:5]


def _studio_candidate_hunter_needs_refutation(row: dict[str, object]) -> bool:
    missing_evidence = _studio_agent_string_list(row.get("missing_evidence", []))
    missing_required = _studio_agent_string_list(
        row.get("missing_required_artifact_kinds", [])
    )
    trace_status = safe_preview_text(row.get("evidence_trace_status", ""))
    return (
        bool(missing_required)
        or "independent_cross_check" in missing_evidence
        or "semantic_evidence" in missing_evidence
        or (bool(trace_status) and trace_status != "traceable")
    )


def _studio_candidate_hunter_refutation_item(
    row: dict[str, object],
) -> dict[str, object]:
    candidate_id = safe_preview_text(row.get("candidate_id", "candidate"))
    missing_evidence = _studio_agent_string_list(row.get("missing_evidence", []))
    missing_required = _studio_agent_string_list(
        row.get("missing_required_artifact_kinds", [])
    )
    questions: list[str] = []
    required_evidence: list[str] = []
    if missing_required:
        questions.extend(
            [
                "Which required A+B artifacts are still missing from the candidate evidence trace?",
                "Can the candidate be downgraded until scope, policy, code, API, and HAR provenance are all present?",
            ]
        )
        required_evidence.extend(missing_required)
    if "independent_cross_check" in missing_evidence:
        questions.extend(
            [
                "Can an independent static rule, SARIF finding, fuzzing plan, or local fixture challenge this candidate without live execution?",
                "Does a local two-account or role-fixture review refute the suspected impact?",
            ]
        )
        required_evidence.append("independent_refutation_or_static_rule")
    if "semantic_evidence" in missing_evidence:
        questions.extend(
            [
                "Does the candidate have a concrete root cause, broken invariant, and reviewed sink before report drafting?",
                "Can the semantic claim be refuted by inspecting the authorized local code path?",
            ]
        )
        required_evidence.extend(
            _studio_agent_string_list(row.get("semantic_evidence_required", []))
            or ["root_cause", "security_invariant", "sink_symbols"]
        )
    return {
        "queue_id": f"candidate_hunter:refutation:{candidate_id}",
        "candidate_id": candidate_id,
        "priority_score": _studio_candidate_hunter_refutation_priority_score(row),
        "trace_status": safe_preview_text(
            row.get("evidence_trace_status", "needs_evidence")
        ),
        "missing_evidence": missing_evidence,
        "missing_required_artifact_kinds": missing_required,
        "questions": _studio_unique_review_loop_values(questions),
        "required_evidence": _studio_unique_review_loop_values(required_evidence),
        "next_action": (
            f"Refute {candidate_id} using independent local evidence before report readiness."
        ),
        "safety_gate": "review_only_no_execution",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _studio_candidate_hunter_refutation_priority_score(
    row: dict[str, object],
) -> int:
    missing_evidence = _studio_agent_string_list(row.get("missing_evidence", []))
    missing_required = _studio_agent_string_list(
        row.get("missing_required_artifact_kinds", [])
    )
    score = _studio_nonnegative_int(row.get("quality_score"))
    score -= 10 * len(missing_evidence)
    score -= 10 * len(missing_required)
    return max(0, score)


def _studio_candidate_hunter_deduplication_queue(
    candidates: list[dict[str, object]],
) -> list[dict[str, object]]:
    items = [
        _studio_candidate_hunter_deduplication_item(candidate)
        for candidate in candidates[:5]
        if _studio_duplicate_risk_score(candidate) >= 50
    ]
    return sorted(
        items,
        key=lambda item: (
            -_studio_nonnegative_int(item.get("priority_score")),
            safe_preview_text(item.get("candidate_id", "")),
        ),
    )[:5]


def _studio_candidate_hunter_deduplication_item(
    candidate: dict[str, object],
) -> dict[str, object]:
    candidate_id = safe_preview_text(candidate.get("hypothesis_id", "candidate"))
    endpoint = safe_preview_text(candidate.get("affected_endpoint", ""))
    code_path = safe_preview_text(candidate.get("affected_code_path", ""))
    duplicate_risk_score = _studio_duplicate_risk_score(candidate)
    similarity_keys: list[str] = []
    if endpoint:
        similarity_keys.append(f"endpoint:{endpoint}")
    if code_path:
        similarity_keys.append(f"code_path:{code_path}")
    return {
        "queue_id": f"candidate_hunter:deduplication:{candidate_id}",
        "candidate_id": candidate_id,
        "priority_score": duplicate_risk_score,
        "duplicate_risk_score": duplicate_risk_score,
        "affected_endpoint": endpoint,
        "affected_code_path": code_path,
        "similarity_keys": similarity_keys,
        "questions": [
            "Does this candidate overlap an existing report, prior candidate, scanner finding, or known program pattern?",
            "Is the affected endpoint, code path, invariant, and impact distinct enough to keep this candidate in the Top 1-5?",
        ],
        "required_evidence": [
            "prior_submission_search",
            "endpoint_code_path_similarity_review",
        ],
        "next_action": (
            f"Deduplicate {candidate_id} against prior candidates before promotion or report readiness."
        ),
        "safety_gate": "review_only_no_execution",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _studio_candidate_hunter_safe_validation_queue(
    candidates: list[dict[str, object]],
) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    for candidate in candidates[:5]:
        row = _studio_candidate_hunter_evidence_row(candidate)
        if _studio_candidate_hunter_needs_refutation(row):
            continue
        if _studio_duplicate_risk_score(candidate) >= 50:
            continue
        if safe_preview_text(candidate.get("quality_status", "")) != "review_ready":
            continue
        if not _studio_agent_string_list(candidate.get("safe_validation_plan", [])):
            continue
        items.append(_studio_candidate_hunter_safe_validation_item(candidate, row))
    return sorted(
        items,
        key=lambda item: (
            -_studio_nonnegative_int(item.get("priority_score")),
            safe_preview_text(item.get("candidate_id", "")),
        ),
    )[:5]


def _studio_candidate_hunter_safe_validation_item(
    candidate: dict[str, object],
    row: dict[str, object],
) -> dict[str, object]:
    candidate_id = safe_preview_text(candidate.get("hypothesis_id", "candidate"))
    return {
        "queue_id": f"candidate_hunter:safe_validation:{candidate_id}",
        "candidate_id": candidate_id,
        "priority_score": _studio_candidate_hunter_priority_score(row),
        "affected_endpoint": safe_preview_text(candidate.get("affected_endpoint", "")),
        "affected_code_path": safe_preview_text(candidate.get("affected_code_path", "")),
        "validation_mode": "human_approved_non_destructive_plan",
        "plan_steps": _studio_agent_string_list(
            candidate.get("safe_validation_plan", [])
        ),
        "required_approvals": [
            "scope_guard_route_approval",
            "human_validation_approval",
            "redaction_review",
        ],
        "next_action": (
            f"Review and approve the non-destructive validation plan for {candidate_id}; execution remains blocked."
        ),
        "safety_gate": "human_approval_required",
        "execution_allowed": False,
        "validation_allowed": False,
        "validation_execution_allowed": False,
        "report_submission_allowed": False,
    }


def _studio_candidate_hunter_report_draft_queue(
    candidates: list[dict[str, object]],
) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    for candidate in candidates[:5]:
        row = _studio_candidate_hunter_evidence_row(candidate)
        if _studio_candidate_hunter_needs_refutation(row):
            continue
        if _studio_duplicate_risk_score(candidate) >= 50:
            continue
        if safe_preview_text(candidate.get("quality_status", "")) != "review_ready":
            continue
        if not _studio_agent_string_list(candidate.get("safe_validation_plan", [])):
            continue
        report_status = safe_preview_text(
            candidate.get("report_status", "submission_blocked")
        )
        if report_status != "submission_blocked":
            continue
        items.append(_studio_candidate_hunter_report_draft_item(candidate, row))
    return sorted(
        items,
        key=lambda item: (
            -_studio_nonnegative_int(item.get("priority_score")),
            safe_preview_text(item.get("candidate_id", "")),
        ),
    )[:5]


def _studio_candidate_hunter_report_draft_item(
    candidate: dict[str, object],
    row: dict[str, object],
) -> dict[str, object]:
    candidate_id = safe_preview_text(candidate.get("hypothesis_id", "candidate"))
    evidence_focus = _studio_hunter_evidence_focus(candidate)
    return {
        "queue_id": f"candidate_hunter:report_draft:{candidate_id}",
        "candidate_id": candidate_id,
        "priority_score": _studio_candidate_hunter_priority_score(row),
        "report_status": "submission_blocked",
        "affected_endpoint": safe_preview_text(candidate.get("affected_endpoint", "")),
        "affected_code_path": safe_preview_text(candidate.get("affected_code_path", "")),
        "required_sections": [
            "impact_summary",
            "affected_endpoint_and_code_path",
            "evidence_trace",
            "safe_validation_plan",
            "redaction_review",
        ],
        "evidence_focus": evidence_focus,
        "redaction_checks": [
            "Remove raw secrets, cookies, tokens, credentials, and authorization headers.",
            "Use only normalized endpoint, code path, and evidence summaries.",
        ],
        "next_action": (
            f"Draft a submission-blocked report for {candidate_id} and keep submission disabled pending human review."
        ),
        "safety_gate": "submission_blocked_human_review",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _studio_candidate_hunter_learning_feedback_target(
    next_candidate_actions: list[dict[str, object]],
) -> dict[str, object]:
    candidate_ids = [
        candidate_id
        for action in next_candidate_actions[:5]
        if (candidate_id := safe_preview_text(action.get("candidate_id", "")))
    ]
    return {
        "target_id": "candidate_hunter:learning_feedback:next_actions",
        "status": "awaiting_human_outcome",
        "source_loop_id": "candidate_hunter:bounded_execution_loop",
        "candidate_ids": candidate_ids,
        "action_count": len(candidate_ids),
        "allowed_outcomes": [
            "confirmed",
            "refuted",
            "needs_more_evidence",
            "duplicate",
        ],
        "next_action": (
            "Record human-reviewed outcomes for candidate hunter next actions before updating future ranking."
        ),
        "safety_gate": "human_review_required",
        "learning_write_allowed": False,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _studio_candidate_hunter_next_candidate_actions(
    candidates: list[dict[str, object]],
) -> list[dict[str, object]]:
    matrix = _studio_candidate_hunter_evidence_matrix(candidates)
    actions = [_studio_candidate_hunter_next_candidate_action(row) for row in matrix]
    return sorted(
        actions,
        key=lambda item: (
            0 if item.get("reason") == "candidate_evidence_ready" else 1,
            -_studio_nonnegative_int(item.get("priority_score")),
            safe_preview_text(item.get("candidate_id", "")),
        ),
    )[:5]


def _studio_candidate_hunter_next_candidate_action(
    row: dict[str, object],
) -> dict[str, object]:
    candidate_id = safe_preview_text(row.get("candidate_id", "candidate"))
    missing = _studio_agent_string_list(row.get("missing_evidence", []))
    missing_required = _studio_agent_string_list(
        row.get("missing_required_artifact_kinds", [])
    )
    if "affected_endpoint" in missing:
        phase_id = "surface_modeling"
        reason = "missing_affected_endpoint"
        required_evidence = ["affected_endpoint", "api_har_route_trace"]
        next_action = (
            f"Trace affected endpoint evidence for {candidate_id} from authorized API/HAR artifacts."
        )
        safety_gate = "authorized_artifacts_only"
    elif "affected_code_path" in missing:
        phase_id = "semantic_audit"
        reason = "missing_affected_code_path"
        required_evidence = ["affected_code_path", "local_code_reference"]
        next_action = (
            f"Trace affected code path evidence for {candidate_id} from authorized local code."
        )
        safety_gate = "local_static_analysis_only"
    elif "semantic_evidence" in missing:
        phase_id = "semantic_audit"
        reason = "missing_semantic_evidence"
        required_evidence = _studio_agent_string_list(
            row.get("semantic_evidence_required", [])
        ) or ["root_cause", "security_invariant", "sink_symbols"]
        next_action = (
            f"Complete semantic root cause, invariant, and sink-symbol review for {candidate_id} from authorized local code."
        )
        safety_gate = "local_static_analysis_only"
    elif "local_evidence_source" in missing:
        phase_id = "hypothesis_generation"
        reason = "missing_local_evidence_source"
        required_evidence = ["local_artifact_trace"]
        next_action = (
            f"Attach local artifact evidence before treating {candidate_id} as a candidate."
        )
        safety_gate = "model_claims_unverified"
    elif missing_required:
        phase_id = "surface_modeling"
        reason = "missing_ab_artifacts"
        required_evidence = missing_required
        next_action = (
            f"Attach required A+B artifacts for {candidate_id} before report readiness."
        )
        safety_gate = "authorized_artifacts_only"
    elif "independent_cross_check" in missing:
        phase_id = "refutation"
        reason = "missing_independent_cross_check"
        required_evidence = ["independent_refutation_or_static_rule"]
        next_action = (
            f"Add independent refutation or static-rule cross-check evidence for {candidate_id}."
        )
        safety_gate = "review_only_no_execution"
    elif "learned_independent_cross_check" in missing:
        phase_id = "refutation"
        reason = "learned_missing_independent_cross_check"
        required_evidence = ["independent_refutation_or_static_rule"]
        next_action = (
            f"Brain learning says {candidate_id} needs independent cross-check evidence before ranking or report readiness."
        )
        safety_gate = "review_only_no_execution"
    elif _studio_nonnegative_int(row.get("duplicate_risk_score")) >= 50:
        phase_id = "deduplication"
        reason = "duplicate_risk_needs_review"
        required_evidence = [
            "prior_submission_search",
            "endpoint_code_path_similarity_review",
        ]
        next_action = (
            f"Deduplicate {candidate_id} against prior candidates before report readiness."
        )
        safety_gate = "review_only_no_execution"
    else:
        phase_id = "report_draft_readiness"
        reason = "candidate_evidence_ready"
        required_evidence = ["submission_blocked_report_draft"]
        next_action = (
            f"Prepare submission-blocked report readiness review for {candidate_id}."
        )
        safety_gate = "submission_blocked_human_review"
    return {
        "candidate_id": candidate_id,
        "phase_id": phase_id,
        "priority_score": _studio_candidate_hunter_priority_score(row),
        "reason": reason,
        "required_evidence": required_evidence,
        "next_action": safe_preview_text(next_action),
        "safety_gate": safety_gate,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _studio_candidate_hunter_priority_score(row: dict[str, object]) -> int:
    breakdown = _studio_candidate_hunter_ranking_signal_breakdown(row)
    final_prefix = "final_priority_score:"
    for item in reversed(breakdown):
        if item.startswith(final_prefix):
            return _studio_nonnegative_int(int(item.removeprefix(final_prefix)))
    return 0


def _studio_candidate_hunter_ranking_signal_breakdown(
    row: dict[str, object],
) -> list[str]:
    missing = _studio_agent_string_list(row.get("missing_evidence", []))
    missing_required = _studio_agent_string_list(
        row.get("missing_required_artifact_kinds", [])
    )
    quality_score = _studio_nonnegative_int(row.get("quality_score"))
    hunter_priority_score = _studio_nonnegative_int(row.get("hunter_priority_score"))
    score = max(quality_score, hunter_priority_score)
    breakdown = [f"quality_score:{quality_score}"]
    if hunter_priority_score:
        breakdown.append(f"hunter_priority_floor:{hunter_priority_score}")
    for missing_item in missing:
        score -= 10
        breakdown.append(f"{missing_item}_penalty:-10")
    for missing_item in missing_required:
        score -= 15
        breakdown.append(f"missing_required_{missing_item}_penalty:-15")
    if safe_preview_text(row.get("evidence_trace_status", "")) == "traceable":
        score += 20
        breakdown.append("traceable_evidence_bonus:+20")
    cross_check_bonus = min(
        10, 5 * _studio_nonnegative_int(row.get("independent_cross_check_count"))
    )
    if cross_check_bonus:
        score += cross_check_bonus
        breakdown.append(f"independent_cross_check_bonus:+{cross_check_bonus}")
    breakdown.append(f"final_priority_score:{max(0, score)}")
    return breakdown


def _studio_candidate_hunter_evidence_summary(
    candidates: list[dict[str, object]],
) -> dict[str, object]:
    matrix = _studio_candidate_hunter_evidence_matrix(candidates)
    scores = [
        _studio_nonnegative_int(item.get("quality_score"))
        for item in matrix
        if isinstance(item.get("quality_score"), int)
    ]
    ready_items = [
        item
        for item in matrix
        if _studio_candidate_hunter_row_is_evidence_ready(item)
    ]
    review_needed_items = [item for item in matrix if item not in ready_items]
    return {
        "candidate_count": len(matrix),
        "review_ready_count": len(ready_items),
        "review_needed_count": len(review_needed_items),
        "endpoint_traced_count": sum(
            1 for item in matrix if bool(item.get("affected_endpoint"))
        ),
        "code_path_traced_count": sum(
            1 for item in matrix if bool(item.get("affected_code_path"))
        ),
        "local_artifact_kinds": _studio_candidate_hunter_ordered_evidence_kinds(
            candidates,
            "local",
        ),
        "advisory_artifact_kinds": _studio_candidate_hunter_ordered_evidence_kinds(
            candidates,
            "advisory",
        ),
        "average_quality_score": round(sum(scores) / len(scores)) if scores else 0,
        "evidence_ready_candidate_ids": [
            safe_preview_text(item.get("candidate_id", ""))
            for item in ready_items
        ],
        "review_needed_candidate_ids": [
            safe_preview_text(item.get("candidate_id", ""))
            for item in review_needed_items
        ],
    }


def _studio_candidate_hunter_row_is_evidence_ready(row: dict[str, object]) -> bool:
    return (
        row.get("quality_status") == "review_ready"
        and not _studio_agent_string_list(row.get("missing_evidence", []))
        and not _studio_agent_string_list(
            row.get("missing_required_artifact_kinds", [])
        )
        and _studio_nonnegative_int(row.get("duplicate_risk_score")) < 50
    )


def _studio_candidate_hunter_evidence_matrix(
    candidates: list[dict[str, object]],
) -> list[dict[str, object]]:
    return [
        _studio_candidate_hunter_evidence_row(candidate)
        for candidate in candidates[:5]
        if safe_preview_text(candidate.get("hypothesis_id", ""))
    ]


def _studio_candidate_hunter_evidence_row(
    candidate: dict[str, object],
) -> dict[str, object]:
    guard = candidate.get("hallucination_guard", {})
    if not isinstance(guard, dict):
        guard = {}
    endpoint = safe_preview_text(candidate.get("affected_endpoint", ""))
    code_path = safe_preview_text(candidate.get("affected_code_path", ""))
    local_sources = _studio_agent_string_list(guard.get("local_evidence_sources", []))
    independent_sources = _studio_agent_string_list(
        guard.get("independent_cross_check_sources", [])
    )
    trace_summary = candidate.get("evidence_trace_summary", {})
    if not isinstance(trace_summary, dict):
        trace_summary = {}
    missing_evidence: list[str] = []
    if not endpoint:
        missing_evidence.append("affected_endpoint")
    if not code_path:
        missing_evidence.append("affected_code_path")
    if not local_sources:
        missing_evidence.append("local_evidence_source")
    if not independent_sources:
        missing_evidence.append("independent_cross_check")
    semantic_required = _studio_candidate_hunter_semantic_required_evidence(
        candidate.get("evidence_gaps", [])
    )
    if semantic_required:
        missing_evidence.append("semantic_evidence")
    row: dict[str, object] = {
        "candidate_id": safe_preview_text(candidate.get("hypothesis_id", "")),
        "affected_endpoint": endpoint,
        "affected_code_path": code_path,
        "quality_score": _studio_nonnegative_int(candidate.get("quality_score")),
        "quality_status": safe_preview_text(
            candidate.get("quality_status", "needs_review")
        ),
        "local_evidence_sources": local_sources,
        "advisory_sources": _studio_agent_string_list(
            guard.get("advisory_sources", [])
        ),
        "independent_cross_check_sources": independent_sources,
        "missing_evidence": missing_evidence,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }
    duplicate_risk_score = _studio_duplicate_risk_score(candidate)
    if duplicate_risk_score > 0:
        row["duplicate_risk_score"] = duplicate_risk_score
    if semantic_required:
        row["semantic_evidence_required"] = semantic_required
    if trace_summary:
        trace_missing_required = _studio_agent_string_list(
            trace_summary.get("missing_required_artifact_kinds", [])
        )
        row.update(
            {
                "evidence_trace_status": safe_preview_text(
                    trace_summary.get("status", "needs_evidence")
                ),
                "missing_required_artifact_kinds": trace_missing_required,
                "endpoint_traced": trace_summary.get("endpoint_traced") is True,
                "code_path_traced": trace_summary.get("code_path_traced") is True,
                "independent_cross_check_count": _studio_nonnegative_int(
                    trace_summary.get("independent_cross_check_count")
                ),
            }
        )
    hunter_assessment = candidate.get("hunter_assessment")
    if isinstance(hunter_assessment, dict):
        for key in (
            "hunter_priority_score",
            "impact_score",
            "rejection_risk_score",
            "policy_risk_score",
        ):
            score = _studio_hunter_assessment_score(hunter_assessment.get(key))
            if score:
                row[key] = score
        playbook_id = safe_preview_text(hunter_assessment.get("playbook_id", ""))
        surface_key = _studio_candidate_hunter_surface_key(endpoint)
        if playbook_id and surface_key:
            row["playbook_id"] = playbook_id
            row["surface_key"] = surface_key
        learning_gaps = _studio_candidate_hunter_learning_evidence_gaps(
            hunter_assessment
        )
        if learning_gaps["missing_evidence"]:
            row["missing_evidence"] = [
                *missing_evidence,
                *[
                    item
                    for item in learning_gaps["missing_evidence"]
                    if item not in missing_evidence
                ],
            ]
        if learning_gaps["missing_required_artifact_kinds"]:
            current_missing_required = _studio_agent_string_list(
                row.get("missing_required_artifact_kinds", [])
            )
            row["missing_required_artifact_kinds"] = [
                *current_missing_required,
                *[
                    item
                    for item in learning_gaps["missing_required_artifact_kinds"]
                    if item not in current_missing_required
                ],
            ]
        if learning_gaps["reasons"]:
            row["learning_evidence_needed_reasons"] = learning_gaps["reasons"]
        if _studio_nonnegative_int(row.get("hunter_priority_score")):
            row["ranking_signal_breakdown"] = (
                _studio_candidate_hunter_ranking_signal_breakdown(row)
            )
    return row


def _studio_candidate_hunter_learning_evidence_gaps(
    hunter_assessment: dict[str, object],
) -> dict[str, list[str]]:
    reasons = [
        reason
        for reason in _studio_agent_string_list(hunter_assessment.get("reasons", []))
        if reason.startswith("lesson:evidence_needed:")
    ]
    missing_evidence: list[str] = []
    missing_required: list[str] = []
    for reason in reasons:
        if reason == "lesson:evidence_needed:missing_evidence:independent_cross_check":
            missing_evidence.append("learned_independent_cross_check")
        elif reason.startswith("lesson:evidence_needed:missing_required_artifact:"):
            artifact = safe_preview_text(
                reason.removeprefix(
                    "lesson:evidence_needed:missing_required_artifact:"
                )
            )
            if artifact and artifact != "[REDACTED]":
                missing_required.append(artifact)
    return {
        "missing_evidence": sorted(set(missing_evidence)),
        "missing_required_artifact_kinds": sorted(set(missing_required)),
        "reasons": reasons,
    }


def _studio_hunter_assessment_score(value: object) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        return max(0, min(100, value))
    return 0


def _studio_candidate_hunter_surface_key(endpoint: str) -> str:
    parts = endpoint.split(maxsplit=1)
    path = parts[1] if len(parts) == 2 else endpoint
    segments = [segment for segment in path.strip("/").split("/") if segment]
    for index, segment in enumerate(segments):
        if segment.startswith("{") and segment.endswith("}"):
            object_key = segment.strip("{}")
            action = next(
                (
                    candidate
                    for candidate in segments[index + 1 :]
                    if not (candidate.startswith("{") and candidate.endswith("}"))
                ),
                "",
            )
            return f"{object_key}:{action or 'review'}"
    return ""


def _studio_candidate_hunter_semantic_required_evidence(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    required: list[str] = []
    reason_to_required = {
        "missing_root_cause": "root_cause",
        "missing_security_invariant": "security_invariant",
        "missing_sink_symbols": "sink_symbols",
    }
    for item in value:
        if isinstance(item, dict):
            if safe_preview_text(item.get("artifact_kind", "")) != "semantic":
                continue
            reason = safe_preview_text(item.get("reason", ""))
        else:
            label = safe_preview_text(item)
            if not label.startswith("semantic: "):
                continue
            reason = label.split(":", 1)[1].strip()
        required_item = reason_to_required.get(reason)
        if required_item and required_item not in required:
            required.append(required_item)
    return required


def _studio_candidate_hunter_ordered_evidence_kinds(
    candidates: list[dict[str, object]],
    kind: str,
) -> list[str]:
    values: list[str] = []
    for candidate in candidates[:5]:
        guard = candidate.get("hallucination_guard", {})
        if not isinstance(guard, dict):
            guard = {}
        if kind == "local":
            values.extend(_studio_agent_string_list(candidate.get("provenance_artifacts", [])))
            values.extend(_studio_agent_string_list(guard.get("local_evidence_sources", [])))
        else:
            values.extend(_studio_agent_string_list(guard.get("advisory_sources", [])))
            values.extend(
                _studio_agent_string_list(guard.get("independent_cross_check_sources", []))
            )
    return _studio_unique_review_loop_values(values)


def _studio_candidate_hunter_execution_work_item(
    step: dict[str, object],
) -> dict[str, object]:
    gap = safe_preview_text(step.get("gap", ""))
    return {
        "work_item_id": safe_preview_text(step.get("work_item_id", "")),
        "candidate_id": safe_preview_text(step.get("candidate_id", "")),
        "gap": gap,
        "assigned_agent": safe_preview_text(
            step.get("assigned_agent", "Human Reviewer")
        ),
        "phase_id": _studio_candidate_hunter_phase_for_gap(gap),
        "required_evidence": _studio_agent_string_list(
            step.get("required_evidence", [])
        ),
        "next_action": safe_preview_text(step.get("next_action", "")),
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _studio_candidate_hunter_phase_for_gap(gap: str) -> str:
    by_gap = {
        "missing_ab_artifacts": "surface_modeling",
        "missing_endpoint": "surface_modeling",
        "missing_code_path": "semantic_audit",
        "missing_provenance_review": "hypothesis_generation",
        "missing_evidence_needs": "refutation",
        "missing_refutation_checks": "refutation",
        "missing_cross_validation_consensus": "refutation",
        "evidence_gaps_need_review": "refutation",
        "missing_deduplication_review": "deduplication",
        "missing_safe_validation_plan": "safe_validation_work",
        "missing_submission_blocked_report": "report_draft_readiness",
    }
    return by_gap.get(gap, "refutation")


def _studio_candidate_hunter_execution_phases(
    current_phase: str,
    active_work_items: list[dict[str, object]],
) -> list[dict[str, object]]:
    active_phases = {
        safe_preview_text(item.get("phase_id", "")) for item in active_work_items
    }
    has_active_work = len(active_work_items) > 0
    definitions = [
        (
            "surface_modeling",
            "Attack surface modeling",
            ["scope", "policy", "api", "har"],
            ["affected_endpoints", "surface_facts"],
            "authorized_artifacts_only",
        ),
        (
            "semantic_audit",
            "Semantic code/API audit",
            ["code", "api", "har"],
            ["affected_code_paths", "security_invariants"],
            "local_static_analysis_only",
        ),
        (
            "hypothesis_generation",
            "High-value hypothesis generation",
            ["surface_facts", "security_invariants"],
            ["candidate_hypotheses"],
            "model_claims_unverified",
        ),
        (
            "refutation",
            "Refutation review",
            ["candidate_hypotheses"],
            ["false_positive_questions"],
            "review_only_no_execution",
        ),
        (
            "deduplication",
            "Candidate deduplication",
            ["candidate_hypotheses"],
            ["candidate_similarity_review"],
            "review_only_no_execution",
        ),
        (
            "ranking",
            "Top candidate ranking",
            ["candidate_hypotheses", "refutation_notes"],
            ["top_1_to_5_candidates"],
            "review_only_no_execution",
        ),
        (
            "safe_validation_work",
            "Safe validation work planning",
            ["top_1_to_5_candidates"],
            ["non_destructive_validation_plan"],
            "human_approval_required",
        ),
        (
            "report_draft_readiness",
            "Submission-blocked report draft readiness",
            ["evidence_review", "safe_validation_plan"],
            ["submission_blocked_report_draft"],
            "submission_blocked_human_review",
        ),
    ]
    phases: list[dict[str, object]] = []
    seen_current = False
    for phase_id, label, input_refs, output_refs, safety_gate in definitions:
        status = "complete"
        if phase_id == current_phase:
            status = "needs_review"
            seen_current = True
        elif seen_current:
            status = "pending"
        elif phase_id == "refutation" and has_active_work:
            status = "needs_review"
        elif phase_id in active_phases:
            status = "needs_review"
        elif phase_id == "report_draft_readiness" and has_active_work:
            status = "pending"
        phases.append(
            {
                "phase_id": phase_id,
                "label": label,
                "status": status,
                "input_refs": input_refs,
                "output_refs": output_refs,
                "safety_gate": safety_gate,
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            }
        )
    return phases


def _studio_plan_step_list(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _studio_unique_review_loop_values(values: object) -> list[str]:
    seen: set[str] = set()
    items: list[str] = []
    for value in values:
        text = safe_preview_text(value)
        if text and text not in seen:
            seen.add(text)
            items.append(text)
    return items[:10]


def _studio_agent_handoff_pack(
    backlog: list[dict[str, object]],
    iteration: dict[str, object],
    agent_queue: list[dict[str, object]],
    timeline_summary: dict[str, object],
) -> dict[str, object]:
    handoff_items = [
        _studio_agent_handoff_item(item)
        for item in backlog[:5]
        if safe_preview_text(item.get("work_item_id", ""))
    ]
    return {
        "pack_id": "studio:agent_handoff:next_review",
        "status": safe_preview_text(iteration.get("status", "needs_review")),
        "handoff_item_count": len(handoff_items),
        "next_review_agent": safe_preview_text(
            iteration.get("next_review_agent", "Human Reviewer")
        ),
        "priority_order": _studio_agent_string_list(
            iteration.get("priority_order", [])
        ),
        "review_focus": _studio_agent_string_list(iteration.get("review_focus", [])),
        "success_criteria": _studio_agent_string_list(
            iteration.get("success_criteria", [])
        ),
        "handoff_items": handoff_items,
        "agent_queue_refs": [
            safe_preview_text(task.get("task_id", ""))
            for task in agent_queue[:10]
            if safe_preview_text(task.get("task_id", ""))
        ],
        "timeline_gate_counts": timeline_summary.get("gate_decision_counts", {})
        if isinstance(timeline_summary.get("gate_decision_counts"), dict)
        else {},
        "safety_gate": "review_only_no_execution",
        "completion_gate": "human_review_required",
        "blocked_actions": [
            "execute_live_validation",
            "run_fuzzer",
            "submit_report",
        ],
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _studio_agent_handoff_item(item: dict[str, object]) -> dict[str, object]:
    work_item_id = safe_preview_text(item.get("work_item_id", ""))
    return {
        "handoff_id": f"handoff:{work_item_id}",
        "work_item_id": work_item_id,
        "candidate_id": safe_preview_text(item.get("candidate_id", "")),
        "status": safe_preview_text(item.get("status", "needs_review")),
        "assigned_agent": _studio_candidate_hunter_next_agent(
            safe_preview_text(item.get("gap", ""))
        ),
        "gap": safe_preview_text(item.get("gap", "")),
        "input_refs": ["scope", "policy", "code", "api", "har"],
        "review_focus": _studio_agent_string_list(item.get("review_focus", [])),
        "required_evidence": _studio_agent_string_list(
            item.get("required_evidence", [])
        ),
        "success_criteria": _studio_agent_handoff_item_success(item),
        "next_action": safe_preview_text(item.get("next_action", "")),
        "safety_gate": "review_only_no_execution",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _studio_agent_handoff_item_success(item: dict[str, object]) -> list[str]:
    work_item_id = safe_preview_text(item.get("work_item_id", "candidate_work_item"))
    required = _studio_agent_string_list(item.get("required_evidence", []))
    criteria = [
        f"{work_item_id} is reviewed against authorized local artifacts.",
        "Reviewer records a human decision before promotion.",
    ]
    if required:
        criteria.append("Evidence refs required: " + ", ".join(required) + ".")
    criteria.append("No validation, fuzzing, or report submission is executed.")
    return _studio_agent_label_list(criteria)


def _studio_nonnegative_int(value: object) -> int:
    return value if isinstance(value, int) and value >= 0 else 0


def _studio_mission_research_loop(
    present_artifacts: list[str],
    missing_artifacts: list[str],
    run_id: str | None,
    candidates: list[dict[str, object]],
) -> list[dict[str, str]]:
    has_candidates = len(candidates) > 0
    has_endpoint = any(candidate.get("affected_endpoint") for candidate in candidates)
    has_code_path = any(candidate.get("affected_code_path") for candidate in candidates)
    has_refutation = any(
        candidate.get("refutation_review_status") for candidate in candidates
    )
    has_deduplication = any(
        candidate.get("deduplication_review_status") for candidate in candidates
    )
    has_validation_plan = any(
        candidate.get("validation_status")
        and isinstance(candidate.get("safe_validation_step_count"), int)
        and candidate.get("safe_validation_step_count") > 0
        for candidate in candidates
    )
    has_evidence_review = any(
        candidate.get("evidence_review_status") for candidate in candidates
    )

    return [
        _studio_mission_stage(
            "scope_guard",
            "complete" if "scope" in present_artifacts else "blocked",
            "Scope Guard is ready for imported authorized materials."
            if "scope" in present_artifacts
            else "Scope artifact is required before research can start.",
        ),
        _studio_mission_stage(
            "target_intake",
            "complete" if not missing_artifacts else "blocked",
            "Required A+B artifacts are present."
            if not missing_artifacts
            else "Required A+B artifacts are still missing.",
        ),
        _studio_mission_stage(
            "attack_surface_modeling",
            "complete" if has_endpoint else "not_started",
            "API and traffic context produced affected endpoint summaries."
            if has_endpoint
            else "Endpoint modeling starts after a local research run.",
        ),
        _studio_mission_stage(
            "semantic_audit",
            "complete" if has_code_path else "not_started",
            "Semantic audit produced affected code-path summaries."
            if has_code_path
            else "Code-path audit starts after a local research run.",
        ),
        _studio_mission_stage(
            "hypothesis_generation",
            "complete" if has_candidates else "not_started",
            "Top candidate hypotheses are ready for review."
            if has_candidates
            else "Candidate generation starts after authorized intake.",
        ),
        _studio_mission_stage(
            "refutation_review",
            "needs_review" if has_refutation else "not_started",
            "Candidate refutation questions need human review."
            if has_refutation
            else "Refutation review starts after candidates exist.",
        ),
        _studio_mission_stage(
            "deduplication_review",
            "needs_review" if has_deduplication else "not_started",
            "Duplicate-risk review needs human review."
            if has_deduplication
            else "Deduplication review starts after candidates exist.",
        ),
        _studio_mission_stage(
            "safe_validation_planning",
            "needs_review" if has_validation_plan else "not_started",
            "Safe validation plans are drafted but execution remains blocked."
            if has_validation_plan
            else "Safe validation planning starts after candidates exist.",
        ),
        _studio_mission_stage(
            "evidence_review",
            "needs_review" if has_evidence_review else "not_started",
            "Evidence needs and gaps require human review."
            if has_evidence_review
            else "Evidence review starts after candidates exist.",
        ),
        _studio_mission_stage(
            "submission_blocked_report",
            "blocked" if run_id else "not_started",
            "Submission-blocked report draft remains review-only."
            if run_id
            else "Report drafting starts after a local research run.",
        ),
    ]


def _studio_mission_stage(key: str, status: str, summary: str) -> dict[str, str]:
    return {
        "key": key,
        "status": status,
        "summary": safe_preview_text(summary),
    }


def _studio_mission_candidate_summary(candidate: dict) -> dict[str, object]:
    report_readiness = candidate.get("report_readiness", {})
    evidence_review = candidate.get("evidence_review", {})
    deduplication_review = candidate.get("deduplication_review", {})
    refutation_review = candidate.get("refutation_review", {})
    policy_review = candidate.get("policy_review", {})
    validation_review = candidate.get("validation_review", {})
    provenance_review = candidate.get("provenance_review", {})
    summary: dict[str, object] = {
        "hypothesis_id": _studio_report_guidance_text(candidate.get("hypothesis_id", "")),
        "vuln_type": _studio_report_guidance_text(candidate.get("vuln_type", "")),
        "risk": _studio_report_guidance_text(candidate.get("risk", "")),
        "priority_score": candidate.get("priority_score", 0),
        "affected_endpoint": _studio_report_endpoint(candidate),
        "affected_code_path": _studio_report_code_path(candidate),
        "report_status": _studio_report_guidance_text(
            report_readiness.get("status", "") if isinstance(report_readiness, dict) else ""
        ),
        "next_report_action": _studio_report_guidance_text(
            report_readiness.get("next_allowed_action", "")
            if isinstance(report_readiness, dict)
            else ""
        ),
        "evidence_review_status": _studio_report_guidance_text(
            evidence_review.get("status", "") if isinstance(evidence_review, dict) else ""
        ),
        "deduplication_review_status": _studio_report_guidance_text(
            deduplication_review.get("status", "")
            if isinstance(deduplication_review, dict)
            else ""
        ),
        "refutation_status": _studio_report_guidance_text(candidate.get("refutation_status", "")),
        "refutation_review_status": _studio_report_guidance_text(
            refutation_review.get("status", "") if isinstance(refutation_review, dict) else ""
        ),
        "policy_review_status": _studio_report_guidance_text(
            policy_review.get("status", "") if isinstance(policy_review, dict) else ""
        ),
        "validation_status": _studio_report_guidance_text(
            validation_review.get("status", "") if isinstance(validation_review, dict) else ""
        ),
        "provenance_review_status": _studio_report_guidance_text(
            provenance_review.get("status", "") if isinstance(provenance_review, dict) else ""
        ),
        "execution_allowed": False,
        "provenance_artifacts": _studio_report_guidance_list(
            provenance_review.get("artifact_kinds", [])
            if isinstance(provenance_review, dict)
            else []
        ),
        "evidence_need_count": len(
            _studio_report_guidance_list(candidate.get("evidence_needed", []))
        ),
        "false_positive_check_count": len(
            _studio_report_guidance_list(candidate.get("false_positive_checks", []))
        ),
        "evidence_gap_count": len(
            _studio_report_evidence_gap_labels(candidate.get("evidence_gaps", []))
        ),
        "safe_validation_step_count": len(
            _studio_report_guidance_list(candidate.get("safe_validation_plan", []))
        ),
        "evidence_needed": _studio_review_packet_items(candidate.get("evidence_needed", [])),
        "false_positive_checks": _studio_review_packet_items(
            candidate.get("false_positive_checks", [])
        ),
        "safe_validation_plan": _studio_review_packet_items(
            candidate.get("safe_validation_plan", [])
        ),
        "safety_blockers": _studio_review_packet_safety_blockers(
            candidate.get("safety_blockers", [])
        ),
        "evidence_gaps": _studio_report_evidence_gap_labels(
            candidate.get("evidence_gaps", [])
        )[:3],
        "evidence_trace_summary": _studio_safe_evidence_trace_summary(candidate),
    }
    summary["hallucination_guard"] = _studio_hallucination_guard(candidate, summary)
    summary.update(_studio_mission_candidate_quality(summary))
    return summary


def _studio_safe_evidence_trace_summary(candidate: dict) -> dict[str, object]:
    summary = candidate.get("evidence_trace_summary", {})
    if not isinstance(summary, dict):
        summary = {}
    source_facts = candidate.get("source_facts", [])
    if not summary and isinstance(source_facts, list):
        summary = _studio_evidence_trace_summary(
            [fact for fact in source_facts if isinstance(fact, dict)]
        )
    return {
        "status": _studio_report_guidance_text(summary.get("status", "needs_evidence")),
        "required_artifact_kinds": _studio_report_guidance_list(
            summary.get("required_artifact_kinds", [])
        ),
        "present_required_artifact_kinds": _studio_report_guidance_list(
            summary.get("present_required_artifact_kinds", [])
        ),
        "advisory_artifact_kinds": _studio_report_guidance_list(
            summary.get("advisory_artifact_kinds", [])
        ),
        "missing_required_artifact_kinds": _studio_report_guidance_list(
            summary.get("missing_required_artifact_kinds", [])
        ),
        "source_fact_count": max(
            0,
            summary.get("source_fact_count", 0)
            if isinstance(summary.get("source_fact_count"), int)
            else 0,
        ),
        "endpoint_traced": summary.get("endpoint_traced") is True,
        "code_path_traced": summary.get("code_path_traced") is True,
        "independent_cross_check_count": max(
            0,
            summary.get("independent_cross_check_count", 0)
            if isinstance(summary.get("independent_cross_check_count"), int)
            else 0,
        ),
        "next_action": _studio_report_guidance_text(
            summary.get(
                "next_action",
                "Review trace summary and refutation questions before any validation.",
            )
        ),
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _studio_mission_candidate_quality(candidate: dict[str, object]) -> dict[str, object]:
    score = 0
    reasons: list[str] = []
    hallucination_guard = candidate.get("hallucination_guard", {})
    hallucination_guard_passed = (
        isinstance(hallucination_guard, dict)
        and hallucination_guard.get("status") == "cross_checked"
    )
    if candidate.get("affected_endpoint") and candidate.get("affected_code_path"):
        score += 20
        reasons.append("endpoint_and_code_path_traced")
    if candidate.get("provenance_review_status"):
        score += 15
        reasons.append("provenance_review_present")
    if candidate.get("evidence_review_status") and int(candidate.get("evidence_need_count", 0)) > 0:
        score += 15
        reasons.append("evidence_needs_present")
    if (
        candidate.get("refutation_review_status")
        and int(candidate.get("false_positive_check_count", 0)) > 0
    ):
        score += 15
        reasons.append("refutation_checks_present")
    if candidate.get("deduplication_review_status"):
        score += 10
        reasons.append("deduplication_review_present")
    if (
        candidate.get("validation_status")
        and int(candidate.get("safe_validation_step_count", 0)) > 0
    ):
        score += 15
        reasons.append("safe_validation_plan_present")
    if candidate.get("report_status") == "submission_blocked":
        score += 10
        reasons.append("submission_blocked_report_ready")
    if int(candidate.get("evidence_gap_count", 0)) > 0:
        score = max(0, score - 15)
        reasons.append("evidence_gaps_need_review")
    if hallucination_guard_passed:
        reasons.append("hallucination_guard_cross_checked")
    else:
        score = max(0, score - 30)
        reasons.append("hallucination_guard_needs_cross_validation")

    return {
        "quality_score": min(score, 100),
        "quality_status": (
            "review_ready" if score >= 85 and hallucination_guard_passed else "needs_review"
        ),
        "quality_reasons": reasons,
    }


def _studio_hallucination_guard(
    candidate: dict,
    summary: dict[str, object],
) -> dict[str, object]:
    source_facts = candidate.get("source_facts", [])
    if not isinstance(source_facts, list):
        source_facts = []
    artifact_kinds = sorted(
        {
            _studio_report_guidance_text(fact.get("artifact_kind", ""))
            for fact in source_facts
            if isinstance(fact, dict)
        }
        - {""}
    )
    local_evidence_sources = [
        kind for kind in artifact_kinds if kind in {"scope", "policy", "code", "api", "har"}
    ]
    advisory_sources = [
        kind for kind in artifact_kinds if kind in {"sarif", "sbom", "fuzzing", "strategy", "knowledge"}
    ]
    independent_cross_check_sources = _studio_independent_cross_check_sources(
        source_facts
    )
    has_endpoint_and_code = bool(summary.get("affected_endpoint")) and bool(
        summary.get("affected_code_path")
    )
    has_refutation = _studio_nonnegative_int(
        summary.get("false_positive_check_count")
    ) > 0
    has_evidence_needs = _studio_nonnegative_int(summary.get("evidence_need_count")) > 0
    blockers: list[str] = []
    if not local_evidence_sources:
        blockers.append("no_local_evidence_source")
    if not has_endpoint_and_code:
        blockers.append("missing_endpoint_or_code_path_trace")
    if not has_refutation:
        blockers.append("missing_refutation_questions")
    if not has_evidence_needs:
        blockers.append("missing_evidence_needs")
    if not independent_cross_check_sources:
        blockers.append("missing_independent_cross_check")

    status = "cross_checked" if not blockers else "needs_review"
    if not local_evidence_sources:
        status = "blocked"
    return {
        "status": status,
        "model_output_status": "unverified_claim_not_fact",
        "high_confidence_allowed": status == "cross_checked",
        "local_evidence_sources": local_evidence_sources,
        "advisory_sources": advisory_sources,
        "independent_cross_check_sources": independent_cross_check_sources,
        "cross_validation_sources": sorted(
            set(local_evidence_sources + independent_cross_check_sources)
        ),
        "required_consensus": [
            "local_artifact_trace",
            "independent_static_or_fuzzing_challenge",
            "independent_refutation_review",
            "human_evidence_review",
        ],
        "blockers": blockers,
    }


def _studio_independent_cross_check_sources(
    source_facts: list[object],
) -> list[str]:
    sources: set[str] = set()
    for fact in source_facts:
        if not isinstance(fact, dict):
            continue
        artifact_kind = _studio_report_guidance_text(fact.get("artifact_kind", ""))
        fact_type = _studio_report_guidance_text(fact.get("fact_type", ""))
        if artifact_kind == "sarif" and fact_type == "scanner_signal":
            sources.add("sarif")
        if artifact_kind == "fuzzing" and fact_type == "fuzzing_signal":
            sources.add("fuzzing")
    return sorted(sources)


def _studio_mission_quality_summary(
    candidates: list[dict[str, object]],
    missing_artifacts: list[str],
    total_candidate_count: int,
) -> dict[str, object]:
    threshold = 85
    candidate_count = len(candidates)
    scores = [
        int(candidate.get("quality_score", 0))
        for candidate in candidates
        if isinstance(candidate.get("quality_score"), int)
    ]
    review_ready_count = sum(
        1
        for candidate in candidates
        if candidate.get("quality_status") == "review_ready"
        and _studio_nonnegative_int(candidate.get("quality_score")) >= threshold
    )
    evidence_gap_count = sum(
        int(candidate.get("evidence_gap_count", 0))
        for candidate in candidates
        if isinstance(candidate.get("evidence_gap_count"), int)
    )
    blockers = _studio_mission_quality_blockers(
        candidate_count=candidate_count,
        review_ready_count=review_ready_count,
        evidence_gap_count=evidence_gap_count,
        missing_artifacts=missing_artifacts,
        total_candidate_count=total_candidate_count,
    )
    quality_gate = _studio_mission_quality_gate(
        blockers,
        candidate_count,
        review_ready_count,
    )
    return {
        "status": _studio_mission_quality_status(quality_gate),
        "top_candidate_quality_gate": quality_gate,
        "candidate_count": candidate_count,
        "required_candidate_min": 1,
        "required_candidate_max": 5,
        "review_ready_threshold": threshold,
        "review_ready_count": review_ready_count,
        "average_quality_score": round(sum(scores) / len(scores)) if scores else 0,
        "blockers": blockers,
        "improvement_actions": _studio_mission_quality_improvement_actions(
            candidates,
            missing_artifacts,
        ),
    }


def _studio_mission_quality_blockers(
    *,
    candidate_count: int,
    review_ready_count: int,
    evidence_gap_count: int,
    missing_artifacts: list[str],
    total_candidate_count: int,
) -> list[str]:
    blockers: list[str] = []
    if missing_artifacts:
        blockers.append(
            "Missing required A+B artifacts: " + ", ".join(missing_artifacts)
        )
    if candidate_count == 0:
        blockers.append("No Top 1-5 candidate is ready for review.")
    if total_candidate_count > 5:
        blockers.append("Candidate list needs Top 1-5 ranking review.")
    if candidate_count and review_ready_count < candidate_count:
        blockers.append("Some Top candidates still need quality review.")
    if evidence_gap_count:
        blockers.append("Evidence gaps remain in Top candidates.")
    return [safe_preview_text(blocker) for blocker in blockers if safe_preview_text(blocker)]


def _studio_mission_quality_gate(
    blockers: list[str],
    candidate_count: int,
    review_ready_count: int,
) -> str:
    if candidate_count == 0:
        return "blocked"
    if blockers:
        return "needs_review"
    if review_ready_count == candidate_count:
        return "passed"
    return "needs_review"


def _studio_mission_quality_status(quality_gate: str) -> str:
    if quality_gate == "passed":
        return "review_ready"
    if quality_gate == "blocked":
        return "blocked"
    return "needs_review"


def _studio_mission_quality_improvement_actions(
    candidates: list[dict[str, object]],
    missing_artifacts: list[str],
) -> list[str]:
    actions: list[str] = []
    if missing_artifacts:
        actions.append(
            "Import missing authorized A+B artifacts: " + ", ".join(missing_artifacts)
        )
    if not candidates:
        actions.append("Run authorized local research to produce Top 1-5 candidates.")
        return [safe_preview_text(action) for action in actions if safe_preview_text(action)]

    for candidate in candidates[:5]:
        hypothesis_id = safe_preview_text(candidate.get("hypothesis_id", "candidate"))
        if not candidate.get("affected_endpoint"):
            actions.append(f"Map affected endpoint for {hypothesis_id}.")
        if not candidate.get("affected_code_path"):
            actions.append(f"Map affected code path for {hypothesis_id}.")
        if not candidate.get("provenance_review_status"):
            actions.append(f"Review provenance artifacts for {hypothesis_id}.")
        if (
            not candidate.get("evidence_review_status")
            or _studio_nonnegative_int(candidate.get("evidence_need_count")) == 0
        ):
            actions.append(f"Define evidence needs for {hypothesis_id}.")
        if (
            not candidate.get("refutation_review_status")
            or _studio_nonnegative_int(candidate.get("false_positive_check_count")) == 0
        ):
            actions.append(f"Add refutation questions for {hypothesis_id}.")
        if not candidate.get("deduplication_review_status"):
            actions.append(f"Review duplicate risk for {hypothesis_id}.")
        if (
            not candidate.get("validation_status")
            or _studio_nonnegative_int(candidate.get("safe_validation_step_count")) == 0
        ):
            actions.append(f"Draft a non-destructive validation plan for {hypothesis_id}.")
        if candidate.get("report_status") != "submission_blocked":
            actions.append(f"Prepare a submission-blocked report draft for {hypothesis_id}.")
        hallucination_guard = candidate.get("hallucination_guard", {})
        if (
            not isinstance(hallucination_guard, dict)
            or hallucination_guard.get("status") != "cross_checked"
        ):
            actions.append(f"Cross-check model claims against local evidence for {hypothesis_id}.")
        if _studio_nonnegative_int(candidate.get("evidence_gap_count")) > 0:
            actions.append(f"Resolve evidence gaps for {hypothesis_id}.")

    return [safe_preview_text(action) for action in actions[:8] if safe_preview_text(action)]


def _studio_review_packet_items(value: object) -> list[str]:
    return [
        item
        for item in _studio_report_guidance_list(value)
        if item not in {"execute_live_validation", "touch_real_user_data", "submit_report"}
    ][:3]


def _studio_review_packet_safety_blockers(value: object) -> list[str]:
    labels = {
        "execute_live_validation": "Validation execution remains blocked pending human approval.",
        "touch_real_user_data": "Protected user data remains out of scope.",
        "submit_report": "Report submission remains blocked pending human review.",
    }
    items = []
    for item in _studio_report_guidance_list(value):
        items.append(labels.get(item, item))
    return items[:3]


def _studio_report_context(manifest: dict) -> dict[str, object]:
    surface_facts = [
        fact
        for fact in _studio_imported_surface_facts(manifest)
        if fact.get("artifact_kind") in {"api", "har"} and fact.get("route_path")
    ][:10]
    return {
        "required_artifacts": ["scope", "policy", "code", "api", "har"],
        "surface_facts": surface_facts,
        "safety_notes": [
            "Imported API and HAR context is advisory and normalized.",
            "Raw artifact paths, headers, cookies, query tokens, and bodies are not included.",
        ],
    }


def _studio_campaign_hunter_report(
    *,
    campaign: CampaignRecord,
    manifest: dict,
    suggestions: list[ResearchQueueSuggestionResponse],
) -> dict[str, object]:
    top_suggestion = suggestions[0] if suggestions else None
    candidate_summary: list[str] = []
    ranking_reasons: list[str] = []
    evidence_needed: list[str] = []
    false_positive_checks: list[str] = []
    safe_validation_plan: list[str] = []
    evidence_gaps: list[str] = []
    satisfied_evidence: list[str] = []
    candidate_readiness: list[dict[str, object]] = []
    readiness_packet: list[str] = []
    for suggestion in suggestions:
        candidate_summary.append(
            f"{suggestion.title}; playbook {suggestion.playbook_id or 'review'}; priority {suggestion.priority_score}/100."
        )
        if suggestion.surface_key:
            candidate_summary.append(f"Affected surface: {suggestion.surface_key}")
        ranking_reasons.append(
            f"{suggestion.queue_key}: priority {suggestion.priority_score}/100 from {suggestion.source}"
        )
        evidence_needed.extend(suggestion.required_evidence)
        evidence_needed.extend(suggestion.evidence_needed)
        evidence_gaps.extend(suggestion.quality_gate_reasons)
        satisfied_evidence.extend(suggestion.satisfied_evidence)
        false_positive_checks.append(
            f"Review {suggestion.refutation_question_count} refutation questions before promoting {suggestion.queue_key}."
        )
        safe_validation_plan.append(
            f"Review {suggestion.validation_step_count} non-destructive validation steps; execution remains blocked."
        )
        readiness = _studio_campaign_hunter_candidate_readiness(suggestion)
        candidate_readiness.append(readiness)
        readiness_packet.append(
            "Candidate readiness: "
            f"{readiness['queue_key']} status {readiness['status']}; "
            f"trace {readiness['trace_status']}; "
            f"required evidence {readiness['required_evidence_count']}; "
            f"safe validation steps {readiness['safe_validation_step_count']}."
        )
    safe_evidence_needed = _studio_unique_review_loop_values(evidence_needed)
    safe_evidence_gaps = _studio_unique_review_loop_values(evidence_gaps)
    safe_satisfied_evidence = _studio_unique_review_loop_values(satisfied_evidence)
    return {
        "title": f"Submission-blocked campaign hunter draft: {safe_preview_text(campaign.name)}",
        "summary": "Campaign hunter candidates are advisory until evidence, refutation, redaction, and human review gates pass.",
        "campaign_id": campaign.id,
        "submission_blocked": True,
        "report_submission_allowed": False,
        "studio_context": _studio_report_context(manifest),
        "candidate_summary": candidate_summary[:10],
        "candidate_readiness": candidate_readiness[:5],
        "ranking_reasons": ranking_reasons[:10],
        "evidence_needed": safe_evidence_needed[:10],
        "satisfied_evidence": safe_satisfied_evidence[:10],
        "false_positive_checks": safe_preview_lines(false_positive_checks)[:10],
        "evidence_gaps": safe_evidence_gaps[:10],
        "evidence_review_packet": [
            "Required artifacts: scope, policy, code, api, har.",
            "Evidence needs: "
            + (
                ", ".join(safe_evidence_needed[:5])
                if safe_evidence_needed
                else "campaign hunter candidate review"
            )
            + ".",
            "Evidence gaps: "
            + (
                ", ".join(safe_evidence_gaps[:5])
                if safe_evidence_gaps
                else "none"
            )
            + ".",
            "Satisfied local evidence: "
            + (
                ", ".join(safe_satisfied_evidence[:5])
                if safe_satisfied_evidence
                else "none"
            )
            + ".",
            *safe_preview_lines(readiness_packet)[:5],
            "Redaction review required before sharing evidence; raw secrets, tokens, cookies, authorization headers, and user data stay excluded.",
            "Evidence review remains read-only: execution blocked, validation blocked, report submission blocked.",
        ],
        "safe_validation_plan": safe_preview_lines(safe_validation_plan)[:10],
        "report_readiness": {
            "status": "submission_blocked",
            "report_submission_allowed": False,
            "next_allowed_action": "Resolve campaign hunter evidence gates before report submission review.",
        },
        "evidence_review": {
            "status": "needs_human_review",
            "required_items": (
                top_suggestion.required_evidence
                if top_suggestion is not None
                else ["campaign_hunter_candidate_review"]
            ),
        },
        "safety_notes": [
            "Campaign hunter report export is local and submission-blocked.",
            "Validation execution and report submission remain disabled.",
        ],
    }


def _studio_campaign_hunter_candidate_readiness(
    suggestion: ResearchQueueSuggestionResponse,
) -> dict[str, object]:
    readiness = _safe_report_readiness_summary(suggestion.report_readiness)
    if not readiness:
        readiness = {
            "status": "blocked_by_evidence_trace",
            "submission_blocked": True,
            "report_submission_allowed": False,
            "required_evidence_count": len(suggestion.required_evidence),
            "safe_validation_step_count": suggestion.validation_step_count,
            "trace_status": "needs_evidence",
            "next_allowed_action": "Review evidence gates before report drafting.",
        }
    return {
        "queue_key": safe_preview_text(suggestion.queue_key),
        "top_candidate_rank": suggestion.top_candidate_rank,
        "status": readiness["status"],
        "submission_blocked": True,
        "report_submission_allowed": False,
        "required_evidence_count": readiness["required_evidence_count"],
        "safe_validation_step_count": readiness["safe_validation_step_count"],
        "trace_status": readiness["trace_status"],
        "next_allowed_action": readiness["next_allowed_action"],
    }


def _studio_report_candidate_guidance(
    record: PipelineRunRecord,
    manifest: dict,
    repository=None,
) -> dict[str, object]:
    candidates = _studio_candidates_for_run(record, manifest, repository=repository)
    top_candidate_reviews = [
        _studio_mission_candidate_summary(candidate)
        for candidate in candidates[:5]
    ]
    for candidate in candidates:
        suggested_fix = _studio_report_guidance_text(candidate.get("suggested_fix", ""))
        regression_test = _studio_report_guidance_text(candidate.get("regression_test", ""))
        evidence_needed = _studio_report_guidance_list(candidate.get("evidence_needed", []))
        false_positive_checks = _studio_report_guidance_list(
            candidate.get("false_positive_checks", [])
        )
        evidence_gaps = _studio_report_evidence_gap_labels(candidate.get("evidence_gaps", []))
        advisory_signals = _studio_report_advisory_signal_labels(
            candidate.get("source_facts", [])
        )
        safe_validation_plan = _studio_report_guidance_list(
            candidate.get("safe_validation_plan", [])
        )
        safety_blockers = _studio_report_guidance_list(candidate.get("safety_blockers", []))
        candidate_summary = _studio_report_candidate_summary(candidate)
        ranking_reasons = _studio_report_guidance_list(candidate.get("ranking_reasons", []))
        hunter_assessment = candidate.get("hunter_assessment")
        evidence_focus = _studio_report_guidance_list(
            hunter_assessment.get("evidence_focus", [])
            if isinstance(hunter_assessment, dict)
            else []
        )
        evidence_review = _studio_report_evidence_review(candidate.get("evidence_review", {}))
        deduplication_review = _studio_report_deduplication_review(
            candidate.get("deduplication_review", {})
        )
        refutation_review = _studio_report_refutation_review(
            candidate.get("refutation_review", {})
        )
        policy_review = _studio_report_policy_review(candidate.get("policy_review", {}))
        provenance_review = _studio_report_provenance_review(
            candidate.get("provenance_review", {})
        )
        validation_review = _studio_report_validation_review(
            candidate.get("validation_review", {})
        )
        report_readiness = _studio_report_readiness(candidate.get("report_readiness", {}))
        guidance: dict[str, object] = {}
        if top_candidate_reviews:
            guidance["top_candidate_reviews"] = top_candidate_reviews
        if candidate_summary:
            guidance["candidate_summary"] = candidate_summary
        if ranking_reasons:
            guidance["ranking_reasons"] = ranking_reasons
        if evidence_focus:
            guidance["evidence_focus"] = evidence_focus
        if report_readiness:
            guidance["report_readiness"] = report_readiness
        if evidence_review:
            guidance["evidence_review"] = evidence_review
        if deduplication_review:
            guidance["deduplication_review"] = deduplication_review
        if refutation_review:
            guidance["refutation_review"] = refutation_review
        if policy_review:
            guidance["policy_review"] = policy_review
        if provenance_review:
            guidance["provenance_review"] = provenance_review
        if validation_review:
            guidance["validation_review"] = validation_review
        if evidence_needed:
            guidance["evidence_needed"] = evidence_needed
        if false_positive_checks:
            guidance["false_positive_checks"] = false_positive_checks
        if evidence_gaps:
            guidance["evidence_gaps"] = evidence_gaps
        if advisory_signals:
            guidance["advisory_signals"] = advisory_signals
        if safe_validation_plan:
            guidance["safe_validation_plan"] = safe_validation_plan
        if safety_blockers:
            guidance["safety_blockers"] = safety_blockers
        if suggested_fix:
            guidance["suggested_fix"] = suggested_fix
        if regression_test:
            guidance["regression_test"] = regression_test
        if guidance:
            return guidance
    return {"top_candidate_reviews": top_candidate_reviews} if top_candidate_reviews else {}


def _studio_report_guidance_text(value: object) -> str:
    text = safe_preview_text(value)
    return "" if text == "[REDACTED]" else text.strip()


def _studio_report_readiness(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    readiness: dict[str, object] = {}
    status = _studio_report_guidance_text(value.get("status", ""))
    if status:
        readiness["status"] = status
    if value.get("report_submission_allowed") is False:
        readiness["report_submission_allowed"] = False
    next_allowed_action = _studio_report_guidance_text(value.get("next_allowed_action", ""))
    if next_allowed_action:
        readiness["next_allowed_action"] = next_allowed_action
    return readiness


def _studio_report_evidence_review(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    review: dict[str, object] = {}
    status = _studio_report_guidance_text(value.get("status", ""))
    if status:
        review["status"] = status
    required_items = _studio_report_guidance_list(value.get("required_items", []))
    if required_items:
        review["required_items"] = required_items
    return review


def _studio_report_deduplication_review(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    review: dict[str, object] = {}
    status = _studio_report_guidance_text(value.get("status", ""))
    if status:
        review["status"] = status
    duplicate_risk_score = value.get("duplicate_risk_score")
    if isinstance(duplicate_risk_score, int):
        review["duplicate_risk_score"] = max(0, min(100, duplicate_risk_score))
    review_items = _studio_report_guidance_list(value.get("review_items", []))
    if review_items:
        review["review_items"] = review_items
    return review


def _studio_report_refutation_review(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    review: dict[str, object] = {}
    status = _studio_report_guidance_text(value.get("status", ""))
    if status:
        review["status"] = status
    questions = _studio_report_guidance_list(value.get("questions", []))
    if questions:
        review["questions"] = questions
    return review


def _studio_report_policy_review(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    review: dict[str, object] = {}
    status = _studio_report_guidance_text(value.get("status", ""))
    if status:
        review["status"] = status
    policy_risk = _studio_report_guidance_text(value.get("policy_risk", ""))
    if policy_risk:
        review["policy_risk"] = policy_risk
    policy_risk_score = value.get("policy_risk_score")
    if isinstance(policy_risk_score, int):
        review["policy_risk_score"] = max(0, min(100, policy_risk_score))
    review_items = _studio_report_guidance_list(value.get("review_items", []))
    if review_items:
        review["review_items"] = review_items
    return review


def _studio_report_provenance_review(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    review: dict[str, object] = {}
    status = _studio_report_guidance_text(value.get("status", ""))
    if status:
        review["status"] = status
    artifact_kinds = _studio_report_guidance_list(value.get("artifact_kinds", []))
    if artifact_kinds:
        review["artifact_kinds"] = artifact_kinds
    review_items = _studio_report_guidance_list(value.get("review_items", []))
    if review_items:
        review["review_items"] = review_items
    return review


def _studio_report_validation_review(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    review: dict[str, object] = {}
    status = _studio_report_guidance_text(value.get("status", ""))
    if status:
        review["status"] = status
    if value.get("execution_allowed") is False:
        review["execution_allowed"] = False
    review_items = _studio_report_guidance_list(value.get("review_items", []))
    if review_items:
        review["review_items"] = review_items
    return review


def _studio_report_candidate_summary(candidate: dict) -> list[str]:
    summary: list[str] = []
    _append_studio_summary(summary, "Vulnerability type", candidate.get("vuln_type", ""))
    _append_studio_summary(summary, "Risk", candidate.get("risk", ""))
    _append_studio_summary(summary, "Affected endpoint", _studio_report_endpoint(candidate))
    _append_studio_summary(summary, "Affected code path", _studio_report_code_path(candidate))
    _append_studio_summary(summary, "Broken invariant", candidate.get("broken_invariant", ""))
    _append_studio_summary(summary, "Refutation status", candidate.get("refutation_status", ""))
    priority_score = candidate.get("priority_score")
    if isinstance(priority_score, int):
        _append_studio_summary(summary, "Priority score", str(priority_score))
    duplicate_risk_score = candidate.get("duplicate_risk_score")
    if isinstance(duplicate_risk_score, int):
        _append_studio_summary(summary, "Duplicate risk score", str(duplicate_risk_score))
    _append_studio_summary(summary, "Policy risk", candidate.get("policy_risk", ""))
    policy_risk_score = candidate.get("policy_risk_score")
    if isinstance(policy_risk_score, int):
        _append_studio_summary(summary, "Policy risk score", str(policy_risk_score))
    return summary


def _append_studio_summary(summary: list[str], label: str, value: object) -> None:
    text = _studio_report_guidance_text(value)
    if text:
        summary.append(f"{label}: {text}")


def _studio_report_endpoint(candidate: dict) -> str:
    source_facts = candidate.get("source_facts", [])
    if isinstance(source_facts, list):
        for fact in source_facts:
            if not isinstance(fact, dict):
                continue
            route_path = _studio_report_guidance_text(fact.get("route_path", ""))
            if route_path:
                method = _studio_report_guidance_text(fact.get("route_method", ""))
                return f"{method} {route_path}".strip()
    return _studio_report_guidance_text(candidate.get("location", ""))


def _studio_report_code_path(candidate: dict) -> str:
    source_facts = candidate.get("source_facts", [])
    if not isinstance(source_facts, list):
        return ""
    for fact in source_facts:
        if not isinstance(fact, dict):
            continue
        if _studio_report_guidance_text(fact.get("artifact_kind", "")) != "code":
            continue
        source_path = _studio_report_guidance_text(fact.get("source_path", ""))
        if not source_path:
            continue
        source_name = source_path.replace("\\", "/").split("/")[-1]
        symbol_name = _studio_report_guidance_text(fact.get("symbol_name", ""))
        return f"{source_name}:{symbol_name}" if symbol_name else source_name
    return ""


def _studio_report_guidance_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [
        text
        for item in value
        if (text := _studio_report_guidance_text(item))
    ]


def _studio_report_evidence_gap_labels(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    labels: list[str] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        artifact_kind = _studio_report_guidance_text(item.get("artifact_kind", ""))
        reason = _studio_report_guidance_text(item.get("reason", ""))
        if artifact_kind and reason:
            labels.append(f"{artifact_kind}: {reason}")
    return labels


def _studio_report_advisory_signal_labels(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    labels: list[str] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        if _studio_report_guidance_text(item.get("advisory_only", "")).lower() != "true":
            continue
        fact_type = _studio_report_guidance_text(item.get("fact_type", ""))
        if fact_type == "scanner_signal":
            label = _studio_report_scanner_signal_label(item)
        elif fact_type == "dependency_signal":
            label = _studio_report_dependency_signal_label(item)
        elif fact_type == "fuzzing_signal":
            label = _studio_report_fuzzing_signal_label(item)
        elif fact_type == "strategy_signal":
            label = _studio_report_strategy_signal_label(item)
        elif fact_type == "knowledge_signal":
            label = _studio_report_knowledge_signal_label(item)
        else:
            label = ""
        if label and label not in labels:
            labels.append(label)
    return labels[:5]


def _studio_report_scanner_signal_label(value: dict) -> str:
    artifact_kind = _studio_report_guidance_text(value.get("artifact_kind", "")).upper()
    method = _studio_report_guidance_text(value.get("route_method", ""))
    route_path = _studio_report_guidance_text(value.get("route_path", ""))
    if not artifact_kind or not route_path:
        return ""
    route = f"{method} {route_path}".strip()
    return f"{artifact_kind} scanner advisory: {route}"


def _studio_report_dependency_signal_label(value: dict) -> str:
    artifact_kind = _studio_report_guidance_text(value.get("artifact_kind", "")).upper()
    package_name = _studio_report_guidance_text(value.get("package_name", ""))
    package_version = _studio_report_guidance_text(value.get("package_version", ""))
    vulnerability_id = _studio_report_guidance_text(value.get("vulnerability_id", ""))
    severity = _studio_report_guidance_text(value.get("severity", ""))
    if not artifact_kind or not package_name:
        return ""
    package = f"{package_name} {package_version}".strip()
    suffix = ", ".join(item for item in (vulnerability_id, severity) if item)
    suffix_text = f" ({suffix})" if suffix else ""
    return f"{artifact_kind} dependency advisory: {package}{suffix_text}"


def _studio_report_fuzzing_signal_label(value: dict) -> str:
    target_symbol = _studio_report_guidance_text(value.get("target_symbol", ""))
    candidate_type = _studio_report_guidance_text(value.get("candidate_type", ""))
    harness_status = _studio_report_guidance_text(value.get("harness_status", ""))
    fuzzer_status = _studio_report_guidance_text(value.get("fuzzer_status", ""))
    if not target_symbol:
        return ""
    details = ", ".join(
        item for item in (candidate_type, harness_status, fuzzer_status) if item
    )
    details_text = f" ({details})" if details else ""
    return f"Fuzzing plan advisory: {target_symbol}{details_text}"


def _studio_report_strategy_signal_label(value: dict) -> str:
    focus = _studio_report_guidance_text(value.get("focus", ""))
    risk_family = _studio_report_guidance_text(value.get("risk_family", ""))
    note = _studio_report_guidance_text(value.get("note", ""))
    subject = focus or note
    if not subject:
        return ""
    suffix = f" ({risk_family})" if risk_family else ""
    return f"Strategy advisory: {subject}{suffix}"


def _studio_report_knowledge_signal_label(value: dict) -> str:
    pattern_id = _studio_report_guidance_text(value.get("pattern_id", ""))
    vuln_type = _studio_report_guidance_text(value.get("vuln_type", ""))
    source = _studio_report_guidance_text(value.get("source", "local_knowledge"))
    cve_id = _studio_report_guidance_text(value.get("cve_id", ""))
    framework = _studio_report_guidance_text(value.get("framework", ""))
    similarity = _studio_report_guidance_text(value.get("similarity_score", ""))
    if not pattern_id and not vuln_type:
        return ""
    subject = pattern_id or vuln_type
    suffix = f" ({vuln_type})" if pattern_id and vuln_type else ""
    details = ", ".join(
        item
        for item in (framework, cve_id, f"similarity {similarity}" if similarity else "")
        if item
    )
    details_text = f"; {details}" if details else ""
    return f"Knowledge advisory: {subject}{suffix} from {source}{details_text}"


def _latest_studio_run_id(manifest: dict) -> str | None:
    runs = manifest.get("runs", [])
    if not isinstance(runs, list):
        return None
    for run in reversed(runs):
        if not isinstance(run, dict):
            continue
        run_id = run.get("run_id")
        if isinstance(run_id, str) and run_id:
            return run_id
    return None


def _studio_run_field(manifest: dict, run_id: str, field_name: str) -> str | None:
    runs = manifest.get("runs", [])
    if not isinstance(runs, list):
        return None
    for run in reversed(runs):
        if not isinstance(run, dict) or run.get("run_id") != run_id:
            continue
        value = run.get(field_name)
        return value if isinstance(value, str) else None
    return None


def _studio_campaign_hunter_run_field(
    manifest: dict,
    campaign_id: str,
    field_name: str,
) -> str | None:
    runs = manifest.get("campaign_hunter_runs", [])
    if not isinstance(runs, list):
        return None
    for run in reversed(runs):
        if not isinstance(run, dict) or run.get("campaign_id") != campaign_id:
            continue
        value = run.get(field_name)
        return value if isinstance(value, str) else None
    return None


def _studio_benchmark_field(manifest: dict, run_id: str, field_name: str) -> str | None:
    benchmarks = manifest.get("benchmarks", [])
    if not isinstance(benchmarks, list):
        return None
    for benchmark in reversed(benchmarks):
        if not isinstance(benchmark, dict) or benchmark.get("run_id") != run_id:
            continue
        value = benchmark.get(field_name)
        return value if isinstance(value, str) else None
    return None


def _studio_benchmark_template_field(
    manifest: dict,
    run_id: str,
    field_name: str,
) -> str | None:
    templates = manifest.get("benchmark_templates", [])
    if not isinstance(templates, list):
        return None
    for template in reversed(templates):
        if not isinstance(template, dict) or template.get("run_id") != run_id:
            continue
        value = template.get(field_name)
        return value if isinstance(value, str) else None
    return None


def _studio_mission_dossier_field(
    manifest: dict,
    run_id: str | None,
    field_name: str,
) -> str | None:
    dossiers = manifest.get("mission_dossiers", [])
    if not isinstance(dossiers, list):
        return None
    for dossier in reversed(dossiers):
        if not isinstance(dossier, dict) or dossier.get("run_id") != run_id:
            continue
        value = dossier.get(field_name)
        return value if isinstance(value, str) else None
    return None


def _studio_candidates_for_run(
    record: PipelineRunRecord,
    manifest: dict,
    repository=None,
) -> list[dict]:
    payload = record.payload if isinstance(record.payload, dict) else {}
    imported_surface_facts = _studio_imported_surface_facts(manifest)
    authorization_context_facts = _studio_authorization_context_facts(manifest)
    if repository is not None:
        projection = load_candidate_hunter_projection(
            repository=repository,
            pipeline_run_id=record.id,
        )
        if projection.get("status") == "ready":
            finals = projection.get("final_candidates")
            if isinstance(finals, list) and finals:
                hunter_candidates = _studio_candidates_from_hunter_projection(
                    projection,
                    imported_surface_facts,
                    authorization_context_facts,
                )
                if hunter_candidates:
                    return hunter_candidates
    hypotheses = payload.get("hypotheses", [])
    if not isinstance(hypotheses, list):
        return []
    assessment_candidate_ids = _studio_assessment_candidate_ids_by_index(
        payload.get("hypothesis_assessments", [])
    )
    candidates = []
    for index, item in enumerate(hypotheses):
        if not isinstance(item, dict):
            continue
        hypothesis = item
        if not safe_preview_text(hypothesis.get("hypothesis_id", "")):
            candidate_id = assessment_candidate_ids.get(index)
            if candidate_id:
                hypothesis = {**hypothesis, "hypothesis_id": candidate_id}
        candidates.append(
            _studio_candidate_from_hypothesis(
                hypothesis,
                imported_surface_facts,
                authorization_context_facts,
            )
        )
    return sorted(
        candidates,
        key=lambda candidate: (
            -_safe_priority_score(candidate.get("priority_score")),
            safe_preview_text(candidate.get("hypothesis_id", "")),
        ),
    )[:5]


def _studio_candidates_from_hunter_projection(
    projection: dict,
    imported_surface_facts: list[dict[str, str]] | None = None,
    authorization_context_facts: list[dict[str, str]] | None = None,
) -> list[dict] | None:
    finals = projection.get("final_candidates")
    if not isinstance(finals, list):
        return None
    candidates = []
    for item in finals:
        if not isinstance(item, dict):
            continue
        candidates.append(
            _studio_candidate_from_hunter_final(
                item,
                imported_surface_facts,
                authorization_context_facts,
            )
        )
    return candidates[:5]


def _studio_candidate_from_hunter_final(
    candidate: dict,
    imported_surface_facts: list[dict[str, str]] | None = None,
    authorization_context_facts: list[dict[str, str]] | None = None,
) -> dict:
    route = candidate.get("route") if isinstance(candidate.get("route"), dict) else {}
    method = safe_preview_text(route.get("method", "")).upper()
    path = safe_preview_text(route.get("path", ""))
    location = f"{method} {path}".strip()
    card = (
        candidate.get("falsification_card")
        if isinstance(candidate.get("falsification_card"), dict)
        else {}
    )
    summary = (
        candidate.get("falsification_summary")
        if isinstance(candidate.get("falsification_summary"), dict)
        else {}
    )
    broken_invariant = safe_preview_text(
        candidate.get(
            "broken_invariant",
            card.get("broken_invariant", summary.get("broken_invariant", "")),
        )
    )
    why_still_alive = safe_preview_lines(
        candidate.get(
            "why_still_alive",
            summary.get("why_still_alive", []),
        )
    )
    if not why_still_alive and isinstance(card.get("decision"), dict):
        why_still_alive = safe_preview_lines(card["decision"].get("why_still_alive", []))
    refutation_questions = safe_preview_lines(candidate.get("refutation_questions", []))
    source_fact_refs = safe_preview_lines(candidate.get("source_fact_refs", []))
    source_facts: list[dict[str, object]] = []
    if method and path:
        source_facts.append(
            {
                "fact_type": "candidate_route",
                "artifact_kind": "code",
                "route_method": method,
                "route_path": path,
            }
        )
    code_path = safe_preview_text(candidate.get("affected_code_path", ""))
    if code_path:
        source_facts.append(
            {
                "fact_type": "authorization_gap_candidate",
                "artifact_kind": "code",
                "source_path": code_path,
                "root_cause": safe_preview_text(candidate.get("root_cause_id", "")),
                "security_invariant": broken_invariant,
            }
        )
    ranking_reasons = []
    if candidate.get("rank") is not None:
        ranking_reasons.append(f"hunter_rank:{candidate.get('rank')}")
    if isinstance(summary, dict) and summary.get("survived_kill_score") is not None:
        ranking_reasons.append(
            f"survived_kill_score:{summary.get('survived_kill_score')}"
        )
    ranking_reasons.append("falsification_first_retained")
    priority = _safe_priority_score(candidate.get("priority_score"))
    if priority <= 0:
        priority = max(10, 100 - (_safe_priority_score(candidate.get("rank")) - 1) * 10)
    hypothesis = {
        "hypothesis_id": safe_preview_text(candidate.get("candidate_id", "")),
        "vuln_type": safe_preview_text(candidate.get("vuln_type", "candidate")),
        "risk": "medium",
        "location": location,
        "hypothesis": (
            f"Hunter retained candidate on {location or 'unknown route'} "
            f"(root={safe_preview_text(candidate.get('root_cause_id', 'unknown'))}). "
            "Unverified; local review only."
        ),
        "broken_invariant": broken_invariant,
        "why_still_alive": why_still_alive,
        "falsification_summary": summary,
        "false_positive_checks": refutation_questions,
        "evidence_needed": source_fact_refs[:12],
        "safe_validation_plan": safe_preview_lines(
            candidate.get("safe_validation_plan", [])
        ),
        "validation_mode": "manual_review",
        "priority_score": priority,
        "ranking_reasons": ranking_reasons,
        "source_facts": source_facts,
        "hunter_assessment": {
            "evidence_focus": [
                "falsification_card_review",
                "why_still_alive_review",
                *why_still_alive[:3],
            ]
        },
    }
    studio_candidate = _studio_candidate_from_hypothesis(
        hypothesis,
        imported_surface_facts,
        authorization_context_facts,
    )
    studio_candidate["broken_invariant"] = broken_invariant or studio_candidate.get(
        "broken_invariant", ""
    )
    studio_candidate["why_still_alive"] = why_still_alive
    studio_candidate["falsification_summary"] = {
        "decision_status": safe_preview_text(summary.get("decision_status", "retained")),
        "why_still_alive": why_still_alive,
        "why_dead": safe_preview_lines(summary.get("why_dead", [])),
        "broken_invariant": broken_invariant,
        "open_dimensions": safe_preview_lines(summary.get("open_dimensions", [])),
        "survived_kill_score": _safe_priority_score(summary.get("survived_kill_score")),
    }
    studio_candidate["false_positive_checks"] = (
        refutation_questions
        or studio_candidate.get("false_positive_checks", [])
    )
    return studio_candidate


def _studio_assessment_candidate_ids_by_index(value: object) -> dict[int, str]:
    if not isinstance(value, list):
        return {}
    ids_by_index: dict[int, str] = {}
    for fallback_index, assessment in enumerate(value):
        if not isinstance(assessment, dict):
            continue
        candidate_id = safe_preview_text(assessment.get("candidate_id", ""))
        if not candidate_id:
            continue
        hypothesis_index = assessment.get("hypothesis_index", fallback_index)
        if isinstance(hypothesis_index, int) and hypothesis_index >= 0:
            ids_by_index[hypothesis_index] = candidate_id
    return ids_by_index


def _studio_candidate_route_fact(hypothesis: dict) -> dict[str, str] | None:
    location = hypothesis.get("location")
    if not isinstance(location, str) or not location:
        return None
    parts = location.split(maxsplit=1)
    if len(parts) != 2 or not parts[1].startswith("/"):
        return None
    return {
        "fact_type": "candidate_route",
        "artifact_kind": "code",
        "route_method": safe_preview_text(parts[0].upper()),
        "route_path": safe_preview_text(parts[1]),
    }


def _studio_candidate_from_hypothesis(
    hypothesis: dict,
    imported_surface_facts: list[dict[str, str]] | None = None,
    authorization_context_facts: list[dict[str, str]] | None = None,
) -> dict:
    source_facts = hypothesis.get("source_facts", [])
    if not isinstance(source_facts, list):
        source_facts = []
    safe_source_facts = [
        safe_fact
        for fact in source_facts
        if isinstance(fact, dict)
        if (safe_fact := _studio_safe_source_fact(fact))
    ]
    candidate_route_fact = _studio_candidate_route_fact(hypothesis)
    if candidate_route_fact is not None:
        safe_source_facts = [candidate_route_fact, *safe_source_facts]
    candidate_source_facts = (
        safe_source_facts
        + (authorization_context_facts or [])
        + _studio_matching_surface_facts(
            hypothesis,
            imported_surface_facts or [],
        )
    )
    duplicate_risk_score = _studio_duplicate_risk_score(hypothesis)
    policy_risk = _studio_policy_risk(hypothesis)
    policy_risk_score = _studio_policy_risk_score(hypothesis)
    route_evidence_kinds = _studio_surface_model_route_evidence_kinds(
        candidate_source_facts
    )
    semantic_priority_boost = _studio_semantic_evidence_priority_boost(
        candidate_source_facts
    )
    priority_score = min(
        100,
        _safe_priority_score(hypothesis.get("priority_score"))
        + _studio_surface_model_priority_boost(route_evidence_kinds)
        + semantic_priority_boost,
    )
    ranking_reasons = safe_preview_lines(hypothesis.get("ranking_reasons", []))
    surface_ranking_reason = _studio_surface_model_ranking_reason(route_evidence_kinds)
    if surface_ranking_reason and surface_ranking_reason not in ranking_reasons:
        ranking_reasons.append(surface_ranking_reason)
    semantic_ranking_reason = _studio_semantic_evidence_ranking_reason(
        semantic_priority_boost
    )
    if semantic_ranking_reason and semantic_ranking_reason not in ranking_reasons:
        ranking_reasons.append(semantic_ranking_reason)
    evidence_gaps = _studio_candidate_evidence_gaps(candidate_source_facts)
    evidence_review = _studio_evidence_review(candidate_source_facts)
    report_next_action = (
        "Resolve semantic evidence gaps before exporting a report preview."
        if any(gap.get("artifact_kind") == "semantic" for gap in evidence_gaps)
        else "Review evidence, refutation checks, and safety blockers before exporting a report preview."
    )
    return {
        "hypothesis_id": safe_preview_text(hypothesis.get("hypothesis_id", "")),
        "vuln_type": safe_preview_text(hypothesis.get("vuln_type", "candidate")),
        "risk": safe_preview_text(
            hypothesis.get("risk", hypothesis.get("risk_level", "medium"))
        ),
        "location": safe_preview_text(hypothesis.get("location", "")),
        "reason": safe_preview_text(hypothesis.get("hypothesis", "")),
        "broken_invariant": _studio_broken_invariant(hypothesis),
        "why_still_alive": safe_preview_lines(hypothesis.get("why_still_alive", [])),
        "falsification_summary": (
            hypothesis.get("falsification_summary")
            if isinstance(hypothesis.get("falsification_summary"), dict)
            else {}
        ),
        "repair_guidance": _studio_repair_guidance(hypothesis),
        "evidence_needed": safe_preview_lines(hypothesis.get("evidence_needed", [])),
        "false_positive_checks": safe_preview_lines(
            hypothesis.get("false_positive_checks", [])
        ),
        "ranking_reasons": ranking_reasons,
        "suggested_fix": _studio_suggested_fix(hypothesis),
        "regression_test": _studio_regression_test(hypothesis),
        "validation_mode": safe_preview_text(hypothesis.get("validation_mode", "manual_review")),
        "safe_validation_plan": _studio_safe_validation_plan(hypothesis),
        "validation_review": _studio_validation_review(),
        "safety_blockers": [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
        ],
        "report_readiness": {
            "status": "submission_blocked",
            "report_submission_allowed": False,
            "next_allowed_action": report_next_action,
        },
        "safe_verification": hypothesis.get("validation_mode") != "blocked",
        "priority_score": priority_score,
        "refutation_status": safe_preview_text(hypothesis.get("refutation_status", "")),
        "refutation_review": _studio_refutation_review(),
        "duplicate_risk_score": duplicate_risk_score,
        "deduplication_review": _studio_deduplication_review(duplicate_risk_score),
        "policy_risk": policy_risk,
        "policy_risk_score": policy_risk_score,
        "policy_review": _studio_policy_review(policy_risk, policy_risk_score),
        "evidence_gaps": evidence_gaps,
        "evidence_review": evidence_review,
        "provenance_review": _studio_provenance_review(candidate_source_facts),
        "hunter_assessment": _studio_safe_hunter_assessment(hypothesis),
        "evidence_trace_summary": _studio_evidence_trace_summary(
            candidate_source_facts
        ),
        "source_facts": candidate_source_facts,
        "submission_blocked": True,
}


def _studio_safe_hunter_assessment(hypothesis: dict) -> dict[str, object]:
    evidence_focus = _studio_hunter_evidence_focus(hypothesis)
    return {"evidence_focus": evidence_focus} if evidence_focus else {}


def _studio_hunter_evidence_focus(hypothesis: dict) -> list[str]:
    hunter_assessment = hypothesis.get("hunter_assessment")
    if not isinstance(hunter_assessment, dict):
        return []
    evidence_focus = safe_preview_lines(hunter_assessment.get("evidence_focus", []))
    return [item for item in evidence_focus if item and item != "[REDACTED]"]


def _studio_safe_source_fact(fact: dict[str, object]) -> dict[str, object]:
    safe_fact: dict[str, object] = {}
    for key, value in fact.items():
        if _studio_sensitive_source_fact_key(key):
            continue
        safe_key = safe_preview_text(key)
        if not safe_key or safe_key == "[REDACTED]":
            continue
        safe_fact[safe_key] = _studio_safe_source_fact_value(value)
    return safe_fact


def _studio_safe_source_fact_value(value: object) -> object:
    if isinstance(value, str):
        return safe_preview_text(value)
    if isinstance(value, list):
        return [_studio_safe_source_fact_value(item) for item in value]
    if isinstance(value, tuple):
        return [_studio_safe_source_fact_value(item) for item in value]
    if isinstance(value, dict):
        return {
            safe_key: _studio_safe_source_fact_value(nested_value)
            for key, nested_value in value.items()
            if not _studio_sensitive_source_fact_key(key)
            if (safe_key := safe_preview_text(key))
            and safe_key != "[REDACTED]"
        }
    if isinstance(value, bool | int | float) or value is None:
        return value
    return safe_preview_text(value)


def _studio_sensitive_source_fact_key(value: object) -> bool:
    normalized = str(value).lower().replace("-", "_")
    return any(
        marker in normalized
        for marker in (
            "authorization",
            "cookie",
            "header",
            "body",
            "raw",
            "token",
            "secret",
            "password",
            "credential",
        )
    )


def _studio_surface_model_route_evidence_kinds(source_facts: list[dict]) -> list[str]:
    return sorted(
        {
            safe_preview_text(fact.get("artifact_kind", ""))
            for fact in source_facts
            if isinstance(fact, dict)
            and safe_preview_text(fact.get("artifact_kind", ""))
            in {"api", "har", "sarif"}
            and safe_preview_text(fact.get("route_method", ""))
            and safe_preview_text(fact.get("route_path", ""))
        },
        key=_studio_surface_model_artifact_sort_key,
    )


def _studio_surface_model_priority_boost(route_evidence_kinds: list[str]) -> int:
    boost_by_kind = {"api": 15, "har": 15, "sarif": 10}
    return sum(boost_by_kind.get(kind, 0) for kind in route_evidence_kinds)


def _studio_surface_model_ranking_reason(route_evidence_kinds: list[str]) -> str:
    if not route_evidence_kinds:
        return ""
    return (
        "surface_model_priority: matched "
        f"{', '.join(route_evidence_kinds)} route evidence"
    )


def _studio_surface_model_artifact_sort_key(kind: str) -> int:
    return {"api": 0, "har": 1, "sarif": 2}.get(kind, 99)


def _studio_semantic_evidence_priority_boost(source_facts: list[dict]) -> int:
    return 15 if _studio_has_complete_semantic_evidence(source_facts) else 0


def _studio_semantic_evidence_ranking_reason(priority_boost: int) -> str:
    if priority_boost <= 0:
        return ""
    return "semantic_evidence_priority: root cause, invariant, and sink symbols present"


def _studio_has_complete_semantic_evidence(source_facts: list[dict]) -> bool:
    return any(
        isinstance(fact, dict)
        and safe_preview_text(fact.get("fact_type")) == "authorization_gap_candidate"
        and _studio_semantic_text_present(fact.get("root_cause"))
        and _studio_semantic_text_present(fact.get("security_invariant"))
        and isinstance(fact.get("sink_symbols"), list)
        and any(
            _studio_semantic_text_present(symbol)
            for symbol in fact.get("sink_symbols", [])
        )
        for fact in source_facts
    )


def _studio_broken_invariant(hypothesis: dict) -> str:
    explicit = safe_preview_text(hypothesis.get("broken_invariant", ""))
    if explicit:
        return explicit
    vuln_type = safe_preview_text(hypothesis.get("vuln_type", "candidate"))
    if "authorization" in vuln_type.lower():
        return "Object access must be authorized before sensitive data or actions are returned."
    return "Candidate security invariant requires human review before validation."


def _studio_repair_guidance(hypothesis: dict) -> str:
    explicit = safe_preview_text(
        hypothesis.get("repair_guidance", hypothesis.get("suggested_fix", ""))
    )
    if explicit:
        return explicit
    vuln_type = safe_preview_text(hypothesis.get("vuln_type", "candidate"))
    if "authorization" in vuln_type.lower():
        return "Review the route, service, and data-access ownership checks before allowing this object action."
    return "Review the affected security boundary and add the smallest confirmed fix after human evidence review."


def _studio_candidate_evidence_gaps(source_facts: list[dict]) -> list[dict[str, str]]:
    artifact_kinds = {
        safe_preview_text(fact.get("artifact_kind"))
        for fact in source_facts
        if isinstance(fact, dict)
    }
    gaps = [
        {
            "artifact_kind": artifact_kind,
            "reason": "missing_required_artifact",
        }
        for artifact_kind in ("scope", "policy", "code", "api", "har")
        if artifact_kind not in artifact_kinds
    ]
    has_code_path = any(
        isinstance(fact, dict)
        and safe_preview_text(fact.get("artifact_kind")) == "code"
        and safe_preview_text(fact.get("source_path"))
        for fact in source_facts
    )
    if "code" in artifact_kinds and not has_code_path:
        gaps.append(
            {
                "artifact_kind": "code",
                "reason": "missing_code_path",
            }
        )
    gaps.extend(_studio_candidate_semantic_evidence_gaps(source_facts))
    return gaps


def _studio_candidate_semantic_evidence_gaps(
    source_facts: list[dict],
) -> list[dict[str, str]]:
    semantic_facts = [
        fact
        for fact in source_facts
        if isinstance(fact, dict)
        and safe_preview_text(fact.get("fact_type")) == "authorization_gap_candidate"
    ]
    if not semantic_facts:
        return []
    gaps: list[dict[str, str]] = []
    if not any(_studio_semantic_text_present(fact.get("root_cause")) for fact in semantic_facts):
        gaps.append({"artifact_kind": "semantic", "reason": "missing_root_cause"})
    if not any(
        _studio_semantic_text_present(fact.get("security_invariant")) for fact in semantic_facts
    ):
        gaps.append(
            {"artifact_kind": "semantic", "reason": "missing_security_invariant"}
        )
    has_sink_symbols = any(
        isinstance(fact.get("sink_symbols"), list)
        and any(
            _studio_semantic_text_present(symbol)
            for symbol in fact.get("sink_symbols", [])
        )
        for fact in semantic_facts
    )
    if not has_sink_symbols:
        gaps.append({"artifact_kind": "semantic", "reason": "missing_sink_symbols"})
    return gaps


def _studio_semantic_text_present(value: object) -> bool:
    return isinstance(value, str) and bool(safe_preview_text(value).strip())


def _studio_evidence_review(source_facts: list[dict]) -> dict[str, object]:
    items = [
        "Confirm the affected endpoint and code path using authorized local artifacts.",
        "Resolve evidence gaps and false-positive checks before validation.",
        "Complete redaction review before report export or sharing.",
    ]
    evidence_gaps = _studio_candidate_evidence_gaps(source_facts)
    if evidence_gaps:
        items.insert(1, "Collect the missing required artifacts before treating this as report-ready.")
    if any(gap.get("artifact_kind") == "semantic" for gap in evidence_gaps):
        items.insert(
            1,
            "Review semantic root cause, security invariant, and sink symbols before report drafting.",
        )
    return {
        "status": "needs_human_review",
        "required_items": items,
    }


def _studio_provenance_review(source_facts: list[dict]) -> dict[str, object]:
    kinds = {
        safe_preview_text(fact.get("artifact_kind"))
        for fact in source_facts
        if isinstance(fact, dict)
    }
    provenance_kinds = kinds - {"knowledge"}
    ordered = [
        kind
        for kind in ("scope", "policy", "code", "api", "har")
        if kind in provenance_kinds
    ]
    ordered.extend(sorted(provenance_kinds.difference(ordered)))
    return {
        "status": "needs_human_review",
        "artifact_kinds": ordered,
        "review_items": [
            "Confirm every candidate claim is traceable to imported authorized artifacts.",
            "Review only normalized artifact summaries; raw paths, headers, tokens, and bodies remain excluded.",
        ],
    }


def _studio_evidence_trace_summary(source_facts: list[dict]) -> dict[str, object]:
    required_artifact_kinds = ["scope", "policy", "code", "api", "har"]
    artifact_kinds = {
        safe_preview_text(fact.get("artifact_kind"))
        for fact in source_facts
        if isinstance(fact, dict)
    }
    present_required = [
        artifact_kind
        for artifact_kind in required_artifact_kinds
        if artifact_kind in artifact_kinds
    ]
    missing_required = [
        artifact_kind
        for artifact_kind in required_artifact_kinds
        if artifact_kind not in artifact_kinds
    ]
    advisory = [
        artifact_kind
        for artifact_kind in sorted(artifact_kinds - set(required_artifact_kinds))
        if artifact_kind
    ]
    endpoint_traced = any(
        isinstance(fact, dict) and safe_preview_text(fact.get("route_path"))
        for fact in source_facts
    )
    code_path_traced = any(
        isinstance(fact, dict)
        and safe_preview_text(fact.get("artifact_kind")) == "code"
        and safe_preview_text(fact.get("source_path"))
        for fact in source_facts
    )
    independent_cross_check_count = sum(
        1 for artifact_kind in advisory if artifact_kind in {"sarif", "fuzzing_plan"}
    )
    return {
        "status": (
            "traceable"
            if not missing_required and endpoint_traced and code_path_traced
            else "needs_evidence"
        ),
        "required_artifact_kinds": required_artifact_kinds,
        "present_required_artifact_kinds": present_required,
        "advisory_artifact_kinds": advisory,
        "missing_required_artifact_kinds": missing_required,
        "source_fact_count": len(source_facts),
        "endpoint_traced": endpoint_traced,
        "code_path_traced": code_path_traced,
        "independent_cross_check_count": independent_cross_check_count,
        "next_action": (
            "Review trace summary and refutation questions before any validation."
        ),
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _studio_deduplication_review(duplicate_risk_score: int) -> dict[str, object]:
    return {
        "status": "needs_human_review",
        "duplicate_risk_score": max(0, min(100, duplicate_risk_score)),
        "review_items": [
            "Compare endpoint, code path, invariant, and impact against prior submissions.",
            "Treat similar scanner, dependency, fuzzing, or strategy signals as advisory until novelty is reviewed.",
        ],
    }


def _studio_refutation_review() -> dict[str, object]:
    return {
        "status": "needs_human_review",
        "questions": [
            "Does an upstream middleware or policy layer already enforce the claimed boundary?",
            "Can the affected endpoint and code path be reached under the authorized scope?",
            "Does a local two-account or role-fixture check refute the suspected impact?",
        ],
    }


def _studio_policy_review(policy_risk: str, policy_risk_score: int) -> dict[str, object]:
    return {
        "status": "needs_human_review",
        "policy_risk": policy_risk,
        "policy_risk_score": max(0, min(100, policy_risk_score)),
        "review_items": [
            "Confirm the candidate remains inside the imported policy and scope artifacts.",
            "Check that the validation plan avoids prohibited actions before any execution.",
            "Keep report submission blocked until policy, evidence, and redaction review are complete.",
        ],
    }


def _studio_validation_review() -> dict[str, object]:
    return {
        "status": "needs_human_approval",
        "execution_allowed": False,
        "review_items": [
            "Confirm Scope Guard allows the exact asset, route, and validation mode.",
            "Confirm validation remains non-destructive and uses only authorized test data.",
            "Record human approval before executing any validation step.",
        ],
    }


def _studio_suggested_fix(hypothesis: dict) -> str:
    explicit = safe_preview_text(hypothesis.get("suggested_fix", ""))
    if explicit:
        return explicit
    return (
        "Enforce the affected authorization or input boundary in the backend service layer "
        "before returning sensitive data or performing state changes."
    )


def _studio_regression_test(hypothesis: dict) -> str:
    explicit = safe_preview_text(hypothesis.get("regression_test", ""))
    if explicit:
        return explicit
    vuln_type = safe_preview_text(hypothesis.get("vuln_type", ""))
    if "authorization" in vuln_type.lower():
        return (
            "Add a non-destructive local regression test proving the protected boundary "
            "rejects unauthorized cross-object access."
        )
    return (
        "Add a non-destructive local regression test proving the reviewed security "
        "invariant remains enforced."
    )


def _studio_duplicate_risk_score(hypothesis: dict) -> int:
    value = hypothesis.get("duplicate_risk_score")
    if isinstance(value, int):
        return value
    hunter_assessment = hypothesis.get("hunter_assessment")
    if isinstance(hunter_assessment, dict):
        value = hunter_assessment.get("duplicate_risk_score")
        if isinstance(value, int):
            return value
    return 0


def _studio_policy_risk(hypothesis: dict) -> str:
    value = safe_preview_text(hypothesis.get("policy_risk", ""))
    if value:
        return value
    hunter_assessment = hypothesis.get("hunter_assessment")
    if isinstance(hunter_assessment, dict):
        value = safe_preview_text(hunter_assessment.get("policy_risk", ""))
        if value:
            return value
    return "unknown"


def _studio_policy_risk_score(hypothesis: dict) -> int:
    value = hypothesis.get("policy_risk_score")
    if isinstance(value, int):
        return max(0, min(100, value))
    hunter_assessment = hypothesis.get("hunter_assessment")
    if isinstance(hunter_assessment, dict):
        value = hunter_assessment.get("policy_risk_score")
        if isinstance(value, int):
            return max(0, min(100, value))
    return {
        "low": 10,
        "medium": 35,
        "high": 70,
        "blocked": 100,
    }.get(_studio_policy_risk(hypothesis).lower(), 0)


def _studio_safe_validation_plan(hypothesis: dict) -> list[str]:
    validation_mode = safe_preview_text(hypothesis.get("validation_mode", "manual_review"))
    if validation_mode == "two_account_authorization_check":
        return [
            "Prepare two authorized test accounts in a local or explicitly approved test environment.",
            "Confirm the target object belongs to account A before any access comparison.",
            "Have a human reviewer approve any non-destructive role or ownership check before execution.",
        ]
    if validation_mode == "blocked":
        return [
            "Do not execute validation for this candidate.",
            "Review scope, policy, and redaction requirements before changing the candidate state.",
        ]
    return [
        "Review the linked code path and imported artifact context locally.",
        "Attach sanitized observations before promoting any claim.",
        "Keep report submission blocked until human evidence review is complete.",
    ]


def _studio_authorization_context_facts(manifest: dict) -> list[dict[str, str]]:
    artifacts = manifest.get("artifacts", [])
    if not isinstance(artifacts, list):
        return []
    present = {
        artifact.get("kind")
        for artifact in artifacts
        if isinstance(artifact, dict)
        and isinstance(artifact.get("kind"), str)
        and artifact.get("source_path")
    }
    return [
        {
            "fact_type": f"{kind}_context",
            "artifact_kind": kind,
        }
        for kind in ("scope", "policy")
        if kind in present
    ]


def _studio_imported_surface_facts(manifest: dict) -> list[dict[str, str]]:
    facts: list[dict[str, str]] = []
    artifacts = manifest.get("artifacts", [])
    if not isinstance(artifacts, list):
        return facts
    for artifact in artifacts:
        if (
            not isinstance(artifact, dict)
            or artifact.get("kind")
            not in {"api", "har", "sarif", "sbom", "fuzzing", "strategy", "knowledge"}
        ):
            continue
        source_path = artifact.get("source_path")
        if not isinstance(source_path, str) or not source_path:
            continue
        facts.extend(_studio_surface_facts_from_file(artifact["kind"], source_path))
    return facts


def _studio_empty_surface_context_fact(
    manifest: dict,
    kind: str,
) -> dict[str, str] | None:
    if kind not in {"api", "har"}:
        return None
    source_path = next(
        (
            artifact.get("source_path")
            for artifact in manifest.get("artifacts", [])
            if isinstance(artifact, dict)
            and artifact.get("kind") == kind
            and isinstance(artifact.get("source_path"), str)
        ),
        None,
    )
    if not source_path:
        return None
    try:
        payload = json.loads(Path(source_path).read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return None
    if kind == "api":
        valid = isinstance(payload, dict) and isinstance(payload.get("paths"), dict)
    else:
        log = payload.get("log") if isinstance(payload, dict) else None
        valid = isinstance(log, dict) and isinstance(log.get("entries"), list)
    if not valid:
        return None
    return {"fact_type": f"{kind}_context", "artifact_kind": kind}


def _studio_attack_surface_model(manifest: dict) -> dict[str, object]:
    facts = _studio_imported_surface_facts(manifest)
    route_facts = [
        fact
        for fact in facts
        if fact.get("route_method") and fact.get("route_path")
    ]
    route_groups: dict[tuple[str, str], set[str]] = {}
    for fact in route_facts:
        method = safe_preview_text(fact.get("route_method", "")).upper()
        path = safe_preview_text(fact.get("route_path", ""))
        kind = safe_preview_text(fact.get("artifact_kind", ""))
        if not method or not path or not kind or "[REDACTED]" in {method, path, kind}:
            continue
        route_groups.setdefault((method, path), set()).add(kind)

    def route_sort_key(item: tuple[tuple[str, str], set[str]]) -> tuple[int, str, str]:
        (method, path), artifact_kinds = item
        kind_priority = min(
            (_studio_attack_surface_artifact_priority(kind) for kind in artifact_kinds),
            default=99,
        )
        return (kind_priority, path, method)

    top_routes = [
        {
            "method": method,
            "path": path,
            "artifact_kinds": sorted(artifact_kinds),
        }
        for (method, path), artifact_kinds in sorted(
            route_groups.items(),
            key=route_sort_key,
        )[:5]
    ]
    next_action = (
        "Review normalized API/HAR/code surface coverage before candidate promotion."
        if facts
        else "Import API/HAR/local code artifacts before surface modeling."
    )
    return {
        "status": "modeled" if facts else "not_modeled",
        "source_artifact_kinds": sorted(
            {
                safe_preview_text(fact.get("artifact_kind", ""))
                for fact in facts
                if safe_preview_text(fact.get("artifact_kind", ""))
            }
        ),
        "route_count": len(route_groups),
        "api_route_count": len(_studio_attack_surface_route_keys(route_facts, "api")),
        "har_route_count": len(_studio_attack_surface_route_keys(route_facts, "har")),
        "advisory_signal_count": sum(
            1 for fact in facts if fact.get("artifact_kind") not in {"api", "har"}
        ),
        "methods": sorted({method for method, _path in route_groups}),
        "top_routes": top_routes,
        "next_action": next_action,
        "safety_gate": "authorized_artifacts_only",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _studio_attack_surface_route_keys(
    facts: list[dict[str, str]],
    artifact_kind: str,
) -> set[tuple[str, str]]:
    return {
        (
            safe_preview_text(fact.get("route_method", "")).upper(),
            safe_preview_text(fact.get("route_path", "")),
        )
        for fact in facts
        if fact.get("artifact_kind") == artifact_kind
        and safe_preview_text(fact.get("route_method", ""))
        and safe_preview_text(fact.get("route_path", ""))
    }


def _studio_attack_surface_artifact_priority(kind: str) -> int:
    priority = {
        "api": 0,
        "har": 1,
        "sarif": 2,
        "sbom": 3,
        "fuzzing": 4,
        "strategy": 5,
        "knowledge": 6,
    }
    return priority.get(kind, 99)


def _studio_surface_facts_from_file(kind: str, source_path: str) -> list[dict[str, str]]:
    if kind == "strategy":
        try:
            text = Path(source_path).read_text(encoding="utf-8-sig")
        except OSError:
            return []
        return _studio_strategy_surface_facts(text)
    try:
        payload = json.loads(Path(source_path).read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return []
    if kind == "api":
        return _studio_openapi_surface_facts(payload)
    if kind == "har":
        return _studio_har_surface_facts(payload)
    if kind == "sarif":
        return _studio_sarif_surface_facts(payload)
    if kind == "sbom":
        return _studio_sbom_surface_facts(payload)
    if kind == "fuzzing":
        return _studio_fuzzing_surface_facts(payload)
    if kind == "knowledge":
        return _studio_knowledge_surface_facts(payload)
    return []


def _studio_strategy_surface_facts(text: str) -> list[dict[str, str]]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower().replace("-", "_")
        if key not in {"focus", "risk_family", "note"} or key in values:
            continue
        safe_value = safe_preview_text(value.strip())
        if safe_value and safe_value != "[REDACTED]":
            values[key] = safe_value
    if not values:
        return []
    fact = {
        "fact_type": "strategy_signal",
        "artifact_kind": "strategy",
        "advisory_only": "true",
        **values,
    }
    return [fact]


def _studio_openapi_surface_facts(payload: object) -> list[dict[str, str]]:
    if not isinstance(payload, dict):
        return []
    paths = payload.get("paths")
    if not isinstance(paths, dict):
        return []
    facts: list[dict[str, str]] = []
    document_security = payload.get("security")
    for route_path, operations in paths.items():
        if not isinstance(route_path, str) or not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            if not isinstance(method, str) or not isinstance(operation, dict):
                continue
            fact = {
                "fact_type": "api_surface",
                "artifact_kind": "api",
                "route_method": safe_preview_text(method.upper()),
                "route_path": safe_preview_text(route_path),
            }
            operation_id = operation.get("operationId")
            if isinstance(operation_id, str) and operation_id:
                fact["operation_id"] = safe_preview_text(operation_id)
            security = (
                operation.get("security")
                if "security" in operation
                else operations.get("security")
                if "security" in operations
                else document_security
            )
            if isinstance(security, list):
                fact["access_mode"] = "protected" if security else "public"
            facts.append(fact)
    return facts


def _studio_har_surface_facts(payload: object) -> list[dict[str, str]]:
    if not isinstance(payload, dict):
        return []
    log = payload.get("log")
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        return []
    facts: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for entry in entries:
        request = entry.get("request") if isinstance(entry, dict) else None
        if not isinstance(request, dict):
            continue
        method = request.get("method")
        url = request.get("url")
        if not isinstance(method, str) or not isinstance(url, str):
            continue
        route_path = urlparse(url).path
        key = (method.upper(), route_path)
        if not route_path or key in seen:
            continue
        seen.add(key)
        facts.append(
            {
                "fact_type": "api_surface",
                "artifact_kind": "har",
                "route_method": safe_preview_text(method.upper()),
                "route_path": safe_preview_text(route_path),
                "advisory_only": "true",
            }
        )
    return facts


def _studio_sarif_surface_facts(payload: object) -> list[dict[str, str]]:
    if not isinstance(payload, dict):
        return []
    try:
        normalized = normalize_artifact("sarif", payload).openapi_like
    except ValueError:
        return []
    facts: list[dict[str, str]] = []
    for route_path, operations in normalized.get("paths", {}).items():
        if not isinstance(route_path, str) or not isinstance(operations, dict):
            continue
        for method, operation in operations.items():
            if not isinstance(method, str):
                continue
            fact = {
                "fact_type": "scanner_signal",
                "artifact_kind": "sarif",
                "route_method": safe_preview_text(method.upper()),
                "route_path": safe_preview_text(route_path),
                "advisory_only": "true",
            }
            operation_id = operation.get("operationId") if isinstance(operation, dict) else None
            if isinstance(operation_id, str) and operation_id:
                fact["operation_id"] = safe_preview_text(operation_id)
            facts.append(fact)
    return facts


def _studio_sbom_surface_facts(payload: object) -> list[dict[str, str]]:
    if not isinstance(payload, dict):
        return []
    components = payload.get("components")
    if not isinstance(components, list):
        return []
    vulnerability_by_ref = _studio_sbom_vulnerability_by_ref(payload)
    facts: list[dict[str, str]] = []
    for component in components:
        if not isinstance(component, dict) or component.get("type") not in {None, "library"}:
            continue
        name = component.get("name")
        if not isinstance(name, str) or not name:
            continue
        purl = component.get("purl")
        purl_ref = purl if isinstance(purl, str) else ""
        vulnerability = vulnerability_by_ref.get(purl_ref, {})
        fact = {
            "fact_type": "dependency_signal",
            "artifact_kind": "sbom",
            "package_name": safe_preview_text(name),
            "package_version": safe_preview_text(str(component.get("version", ""))),
            "ecosystem": safe_preview_text(_studio_purl_ecosystem(purl_ref)),
            "advisory_only": "true",
        }
        vulnerability_id = vulnerability.get("id")
        if isinstance(vulnerability_id, str) and vulnerability_id:
            fact["vulnerability_id"] = safe_preview_text(vulnerability_id)
        severity = vulnerability.get("severity")
        if isinstance(severity, str) and severity:
            fact["severity"] = safe_preview_text(severity.lower())
        facts.append(fact)
    return facts[:5]


def _studio_sbom_vulnerability_by_ref(payload: dict) -> dict[str, dict[str, str]]:
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return {}
    by_ref: dict[str, dict[str, str]] = {}
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue
        affects = vulnerability.get("affects")
        if not isinstance(affects, list):
            continue
        for affected in affects:
            if not isinstance(affected, dict):
                continue
            ref = affected.get("ref")
            if not isinstance(ref, str) or not ref:
                continue
            by_ref.setdefault(
                ref,
                {
                    "id": safe_preview_text(vulnerability.get("id", "")),
                    "severity": _studio_sbom_vulnerability_severity(vulnerability),
                },
            )
    return by_ref


def _studio_sbom_vulnerability_severity(vulnerability: dict) -> str:
    ratings = vulnerability.get("ratings")
    if not isinstance(ratings, list):
        return ""
    for rating in ratings:
        if not isinstance(rating, dict):
            continue
        severity = rating.get("severity")
        if isinstance(severity, str) and severity:
            return safe_preview_text(severity)
    return ""


def _studio_fuzzing_surface_facts(payload: object) -> list[dict[str, str]]:
    if not isinstance(payload, dict):
        return []
    plan = (
        payload.get("crs_fuzzing")
        if isinstance(payload.get("crs_fuzzing"), dict)
        else payload
    )
    fuzzer_plan = plan.get("fuzzer_plan")
    if not isinstance(fuzzer_plan, dict):
        return []
    if plan.get("execution_mode") != "plan_only":
        return []
    if fuzzer_plan.get("execution_allowed") is True:
        return []
    parser_candidates = plan.get("parser_candidates")
    if not isinstance(parser_candidates, list):
        return []
    harness_status_by_symbol = _studio_fuzzing_harness_status_by_symbol(plan)
    facts: list[dict[str, str]] = []
    for candidate in parser_candidates:
        if not isinstance(candidate, dict):
            continue
        symbol_name = candidate.get("symbol_name")
        if not isinstance(symbol_name, str) or not symbol_name:
            continue
        fact = {
            "fact_type": "fuzzing_signal",
            "artifact_kind": "fuzzing",
            "target_symbol": safe_preview_text(symbol_name),
            "candidate_type": safe_preview_text(candidate.get("candidate_type", "")),
            "harness_status": safe_preview_text(
                harness_status_by_symbol.get(symbol_name, "")
            ),
            "fuzzer_engine": safe_preview_text(fuzzer_plan.get("engine", "")),
            "fuzzer_status": safe_preview_text(fuzzer_plan.get("status", "")),
            "execution_allowed": "false",
            "advisory_only": "true",
        }
        facts.append({key: value for key, value in fact.items() if value})
    return facts[:3]


def _studio_fuzzing_harness_status_by_symbol(plan: dict) -> dict[str, str]:
    harness_plans = plan.get("harness_plans")
    if not isinstance(harness_plans, list):
        return {}
    status_by_symbol: dict[str, str] = {}
    for harness_plan in harness_plans:
        if not isinstance(harness_plan, dict):
            continue
        target_symbol = harness_plan.get("target_symbol")
        status = harness_plan.get("status")
        if isinstance(target_symbol, str) and isinstance(status, str):
            status_by_symbol[target_symbol] = status
    return status_by_symbol


def _studio_knowledge_surface_facts(payload: object) -> list[dict[str, str]]:
    if not isinstance(payload, dict):
        return []
    entries = payload.get("entries")
    if not isinstance(entries, list):
        entries = payload.get("patterns")
    if not isinstance(entries, list):
        return []
    facts: list[dict[str, str]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        pattern_id = safe_preview_text(entry.get("pattern_id", entry.get("id", "")))
        vuln_type = safe_preview_text(entry.get("vuln_type", entry.get("category", "")))
        source = safe_preview_text(entry.get("source", "local_knowledge"))
        cve_id = safe_preview_text(entry.get("cve_id", entry.get("cve", "")))
        framework = safe_preview_text(entry.get("framework", entry.get("ecosystem", "")))
        case_title = safe_preview_text(entry.get("case_title", entry.get("title", "")))
        similarity_score = _studio_knowledge_similarity_score(entry.get("similarity_score"))
        retrieval_rank = _studio_knowledge_retrieval_rank(entry.get("retrieval_rank"))
        if (
            pattern_id == "[REDACTED]"
            or vuln_type == "[REDACTED]"
            or cve_id == "[REDACTED]"
            or framework == "[REDACTED]"
            or case_title == "[REDACTED]"
        ):
            continue
        if not pattern_id and not vuln_type:
            continue
        fact = {
            "fact_type": "knowledge_signal",
            "artifact_kind": "knowledge",
            "advisory_only": "true",
            "model_input_role": "few_shot_context_only",
            "exploit_code_allowed": "false",
            "source": source or "local_knowledge",
        }
        if pattern_id:
            fact["pattern_id"] = pattern_id
        if vuln_type:
            fact["vuln_type"] = vuln_type
        if cve_id:
            fact["cve_id"] = cve_id
        if framework:
            fact["framework"] = framework
        if case_title:
            fact["case_title"] = case_title
        if similarity_score:
            fact["similarity_score"] = similarity_score
        if retrieval_rank:
            fact["retrieval_rank"] = retrieval_rank
        facts.append(fact)
    return facts[:5]


def _studio_knowledge_similarity_score(value: object) -> str:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        bounded = max(0.0, min(1.0, float(value)))
        return f"{bounded:.2f}"
    if isinstance(value, str):
        try:
            bounded = max(0.0, min(1.0, float(value.strip())))
        except ValueError:
            return ""
        return f"{bounded:.2f}"
    return ""


def _studio_knowledge_retrieval_rank(value: object) -> str:
    if isinstance(value, int) and value > 0:
        return str(value)
    if isinstance(value, str) and value.strip().isdigit():
        rank = int(value.strip())
        if rank > 0:
            return str(rank)
    return ""


def _studio_purl_ecosystem(purl: str) -> str:
    if not purl.startswith("pkg:"):
        return ""
    return purl.removeprefix("pkg:").split("/", 1)[0].split("@", 1)[0]


def _studio_matching_surface_facts(
    hypothesis: dict,
    imported_surface_facts: list[dict[str, str]],
) -> list[dict[str, str]]:
    global_facts = [
        fact
        for fact in imported_surface_facts
        if not fact.get("route_path")
    ][:5]
    route_hints = _studio_candidate_route_hints(hypothesis)
    if not route_hints:
        return imported_surface_facts[:5]
    route_facts = [
        fact
        for fact in imported_surface_facts
        if _studio_surface_fact_matches_route_hints(fact, route_hints)
    ][:5]
    return (route_facts + global_facts)[:5]


def _studio_surface_fact_matches_route_hints(
    fact: dict[str, str],
    route_hints: set[str],
) -> bool:
    route_path = fact.get("route_path")
    if not isinstance(route_path, str) or not route_path:
        return False
    return any(_studio_route_paths_match(route_hint, route_path) for route_hint in route_hints)


def _studio_route_paths_match(route_hint: str, route_path: str) -> bool:
    hint_segments = _studio_route_segments(route_hint)
    path_segments = _studio_route_segments(route_path)
    if len(hint_segments) != len(path_segments):
        return False
    return all(
        _studio_route_segment_matches(hint_segment, path_segment)
        or _studio_route_segment_matches(path_segment, hint_segment)
        for hint_segment, path_segment in zip(hint_segments, path_segments, strict=True)
    )


def _studio_route_segments(route_path: str) -> list[str]:
    return [segment for segment in route_path.strip("/").split("/") if segment]


def _studio_route_segment_matches(pattern: str, value: str) -> bool:
    if pattern == value:
        return True
    return (
        (pattern.startswith("{") and pattern.endswith("}"))
        or (pattern.startswith("<") and pattern.endswith(">"))
        or pattern.startswith(":")
    )


def _studio_candidate_route_hints(hypothesis: dict) -> set[str]:
    hints: set[str] = set()
    location = hypothesis.get("location")
    if isinstance(location, str):
        if location.startswith("/"):
            hints.add(location)
        parts = location.split(maxsplit=1)
        if len(parts) == 2 and parts[1].startswith("/"):
            hints.add(parts[1])
    source_facts = hypothesis.get("source_facts", [])
    if not isinstance(source_facts, list):
        return hints
    for fact in source_facts:
        if not isinstance(fact, dict):
            continue
        route_path = fact.get("route_path")
        if isinstance(route_path, str) and route_path:
            hints.add(route_path)
    return hints


@app.post("/mythos/source-audit/scans", response_model=SourceAuditScanResponse)
def run_mythos_source_audit_scan(
    request: SourceAuditScanRequest,
    session: Session = Depends(get_session),
) -> SourceAuditScanResponse:
    repository = DatabaseRepository(session)
    if request.program_id is not None:
        _program_or_404_in_scope(repository, request.program_id)
    try:
        repo_path = resolve_configured_workspace_artifact(request.repo_path, kind="code")
        scope_path = resolve_configured_workspace_artifact(
            request.scope_path,
            kind="scope",
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="source_audit_artifact_not_found") from exc
    try:
        result = run_source_audit(
            str(repo_path),
            str(scope_path),
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
            else _read_source_audit_policy_text(str(scope_path))
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
    campaign = repository.get_campaign(record.campaign_id) if repository is not None else None
    agent_runs = (
        repository.list_campaign_agent_runs(record.campaign_id)
        if repository is not None
        else []
    )
    time_budget_used = (
        round(campaign_elapsed_minutes(campaign), 2) if campaign is not None else 0
    )
    time_budget_remaining = (
        None
        if record.time_budget_minutes is None
        else max(record.time_budget_minutes - time_budget_used, 0)
    )
    token_budget_used = campaign_token_used_from_runs(agent_runs)
    token_budget_remaining = (
        None
        if record.token_budget is None
        else max(record.token_budget - token_budget_used, 0)
    )
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
        time_budget_used_minutes=time_budget_used,
        time_budget_remaining_minutes=time_budget_remaining,
        token_budget=record.token_budget,
        token_budget_used=token_budget_used,
        token_budget_remaining=token_budget_remaining,
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
        "quality_gate_reasons": safe_preview_lines(
            task_payload.get("quality_gate_reasons", [])
        ),
        "required_evidence": safe_preview_lines(
            task_payload.get("required_evidence", [])
        ),
        "evidence_needed": safe_preview_lines(
            task_payload.get("evidence_needed", [])
        ),
        "satisfied_evidence": safe_preview_lines(
            task_payload.get("satisfied_evidence", [])
        ),
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
    raw_priority_score = _optional_safe_priority_score(
        task_payload.get("raw_priority_score")
    )
    if raw_priority_score is not None:
        payload["raw_priority_score"] = raw_priority_score
    top_candidate_rank = _optional_top_candidate_rank(
        task_payload.get("top_candidate_rank")
    )
    if top_candidate_rank is not None:
        payload["top_candidate_rank"] = top_candidate_rank
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
        evidence_needed=safe_preview_lines(payload.get("evidence_needed", [])),
        required_evidence=safe_preview_lines(payload.get("required_evidence", [])),
        satisfied_evidence=safe_preview_lines(payload.get("satisfied_evidence", [])),
        evidence_trace_summary=_safe_evidence_trace_summary(
            payload.get("evidence_trace_summary")
        ),
        report_readiness=_safe_report_readiness_summary(
            payload.get("report_readiness")
        ),
        raw_priority_score=_optional_safe_priority_score(
            payload.get("raw_priority_score")
        ),
        quality_gate_reasons=safe_preview_lines(
            payload.get("quality_gate_reasons", [])
        ),
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


def _safe_evidence_trace_summary(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or not value:
        return {}
    trace_status = safe_preview_text(value.get("trace_status", "needs_evidence"))
    if trace_status not in {"traceable", "needs_evidence"}:
        trace_status = "needs_evidence"
    return {
        "trace_status": trace_status,
        "source_fact_count": _safe_non_negative_int(value.get("source_fact_count")),
        "traceable_source_fact_count": _safe_non_negative_int(
            value.get("traceable_source_fact_count")
        ),
        "route_fact_count": _safe_non_negative_int(value.get("route_fact_count")),
        "artifact_kinds": safe_preview_lines(value.get("artifact_kinds", [])),
        "source_fact_types": safe_preview_lines(value.get("source_fact_types", [])),
        "report_submission_allowed": False,
    }


def _safe_report_readiness_summary(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or not value:
        return {}
    status = safe_preview_text(value.get("status", "blocked_by_evidence_trace"))
    allowed_statuses = {
        "blocked_by_required_evidence",
        "blocked_by_evidence_trace",
        "needs_safe_validation_plan",
        "submission_blocked_draft_ready",
    }
    if status not in allowed_statuses:
        status = "blocked_by_evidence_trace"
    trace_status = safe_preview_text(value.get("trace_status", "needs_evidence"))
    if trace_status not in {"traceable", "needs_evidence"}:
        trace_status = "needs_evidence"
    return {
        "status": status,
        "submission_blocked": True,
        "report_submission_allowed": False,
        "required_evidence_count": _safe_non_negative_int(
            value.get("required_evidence_count")
        ),
        "safe_validation_step_count": _safe_non_negative_int(
            value.get("safe_validation_step_count")
        ),
        "trace_status": trace_status,
        "next_allowed_action": safe_preview_text(
            value.get(
                "next_allowed_action",
                "Review evidence gates before report drafting.",
            )
        ),
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


def _optional_safe_priority_score(value: Any) -> int | None:
    if not isinstance(value, int | float):
        return None
    return _safe_priority_score(value)


def _optional_top_candidate_rank(value: Any) -> int | None:
    if not isinstance(value, int | float):
        return None
    rank = int(value)
    if rank < 1 or rank > 5:
        return None
    return rank


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
        safe_payload = {
            "blocked_action_count": _safe_non_negative_int(payload.get("blocked_action_count")),
            "candidate_id": safe_preview_text(payload.get("candidate_id", "candidate")),
            "candidate_status": safe_preview_text(payload.get("candidate_status", "queued_review")),
            "dispatch_allowed": False,
            "execution_allowed": False,
            "human_approval_required": _autonomous_human_approval_required(payload),
            "evidence_needed": safe_preview_lines(payload.get("evidence_needed", [])),
            "evidence_trace_summary": _safe_evidence_trace_summary(
                payload.get("evidence_trace_summary")
            ),
            "playbook_id": safe_preview_text(payload.get("playbook_id", "unknown_playbook")),
            "priority_score": _safe_priority_score(payload.get("priority_score")),
            "queue_key": safe_preview_text(payload.get("queue_key", "research_queue")),
            "raw_payload_processed": False,
            "refutation_question_count": _safe_non_negative_int(payload.get("refutation_question_count")),
            "report_readiness": _safe_report_readiness_summary(
                payload.get("report_readiness")
            ),
            "report_submission_allowed": False,
            "required_evidence": safe_preview_lines(payload.get("required_evidence", [])),
            "satisfied_evidence": safe_preview_lines(payload.get("satisfied_evidence", [])),
            "source": safe_preview_text(payload.get("source", "research_queue")),
            "top_candidate_rank": _optional_top_candidate_rank(
                payload.get("top_candidate_rank")
            ),
            "validation_allowed": False,
            "validation_step_count": _safe_non_negative_int(payload.get("validation_step_count")),
        }
        raw_priority_score = _optional_safe_priority_score(payload.get("raw_priority_score"))
        if raw_priority_score is not None:
            safe_payload["raw_priority_score"] = raw_priority_score
        quality_gate_reasons = safe_preview_lines(payload.get("quality_gate_reasons", []))
        if quality_gate_reasons:
            safe_payload["quality_gate_reasons"] = quality_gate_reasons
        return safe_payload
    if record.stage_key == "research_task_review_plan":
        safe_payload = {
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
            "required_evidence": safe_preview_lines(payload.get("required_evidence", [])),
            "satisfied_evidence": safe_preview_lines(payload.get("satisfied_evidence", [])),
            "source_fact_type_count": _safe_non_negative_int(payload.get("source_fact_type_count")),
            "triage_signal_count": _safe_non_negative_int(payload.get("triage_signal_count")),
            "validation_allowed": False,
        }
        raw_priority_score = _optional_safe_priority_score(payload.get("raw_priority_score"))
        if raw_priority_score is not None:
            safe_payload["raw_priority_score"] = raw_priority_score
        quality_gate_reasons = safe_preview_lines(payload.get("quality_gate_reasons", []))
        if quality_gate_reasons:
            safe_payload["quality_gate_reasons"] = quality_gate_reasons
        return safe_payload
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


def _campaign_budget_exhausted(
    budget: CampaignBudgetRecord | None,
    *,
    campaign: CampaignRecord | None = None,
    agent_runs: list[AgentRunRecord] | None = None,
) -> bool:
    if budget is None:
        return False
    if any(
        value is not None and value <= 0
        for value in (
            budget.time_budget_minutes,
            budget.token_budget,
            budget.tool_call_budget,
            budget.validation_budget,
        )
    ):
        return True
    if (
        campaign is not None
        and budget.time_budget_minutes is not None
        and campaign_elapsed_minutes(campaign) >= budget.time_budget_minutes
    ):
        return True
    return (
        agent_runs is not None
        and budget.token_budget is not None
        and campaign_token_used_from_runs(agent_runs) >= budget.token_budget
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
    if _campaign_budget_exhausted(
        budget,
        campaign=campaign,
        agent_runs=agent_runs,
    ):
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
    if _campaign_unresolved_required_evidence_count(pipeline_stages) > 0:
        return "review_evidence_or_report_drafts"
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
                    top_candidate_rank=_optional_top_candidate_rank(
                        item.get("top_candidate_rank")
                    ),
                    priority_score=_safe_priority_score(item.get("priority_score")),
                    raw_priority_score=_optional_safe_priority_score(
                        item.get("raw_priority_score")
                    ),
                    quality_gate_reasons=safe_preview_lines(
                        item.get("quality_gate_reasons", [])
                    ),
                    evidence_needed=safe_preview_lines(
                        item.get("evidence_needed", [])
                    ),
                    evidence_trace_summary=_safe_evidence_trace_summary(
                        item.get("evidence_trace_summary")
                    ),
                    report_readiness=_safe_report_readiness_summary(
                        item.get("report_readiness")
                    ),
                    required_evidence=safe_preview_lines(
                        item.get("required_evidence", [])
                    ),
                    satisfied_evidence=safe_preview_lines(
                        item.get("satisfied_evidence", [])
                    ),
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
        "top_candidate_rank": suggestion.top_candidate_rank,
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
                "raw_priority_score": suggestion.raw_priority_score,
                "quality_gate_reasons": suggestion.quality_gate_reasons,
                "evidence_needed": suggestion.evidence_needed,
                "evidence_trace_summary": suggestion.evidence_trace_summary,
                "report_readiness": suggestion.report_readiness,
                "required_evidence": suggestion.required_evidence,
                "satisfied_evidence": suggestion.satisfied_evidence,
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
            "required_evidence": [],
            "satisfied_evidence": [],
            "evidence_needed": [],
            "quality_gate_reasons": [],
            "evidence_trace_summary": {},
            "report_readiness": {},
            "top_candidate_rank": None,
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
        "required_evidence": [],
        "satisfied_evidence": [],
        "evidence_needed": [],
        "quality_gate_reasons": [],
        "evidence_trace_summary": {},
        "report_readiness": {},
        "top_candidate_rank": None,
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
        metadata["required_evidence"] = safe_preview_lines(
            item.get("required_evidence", [])
        )
        metadata["satisfied_evidence"] = safe_preview_lines(
            item.get("satisfied_evidence", [])
        )
        metadata["evidence_needed"] = safe_preview_lines(
            item.get("evidence_needed", [])
        )
        metadata["quality_gate_reasons"] = safe_preview_lines(
            item.get("quality_gate_reasons", [])
        )
        metadata["evidence_trace_summary"] = _safe_evidence_trace_summary(
            item.get("evidence_trace_summary")
        )
        metadata["report_readiness"] = _safe_report_readiness_summary(
            item.get("report_readiness")
        )
        raw_priority_score = _optional_safe_priority_score(
            item.get("raw_priority_score")
        )
        if raw_priority_score is not None:
            metadata["raw_priority_score"] = raw_priority_score
        metadata["top_candidate_rank"] = _optional_top_candidate_rank(
            item.get("top_candidate_rank")
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


def _campaign_unresolved_required_evidence_count(
    pipeline_stages: list[PipelineStageRecord],
) -> int:
    resolved_task_ids = {
        stage.task_id
        for stage in pipeline_stages
        if stage.task_id
        and stage.stage_key == "research_task_refutation_decision"
        and stage.status != "needs_evidence"
    }
    return sum(
        1
        for stage in pipeline_stages
        if stage.task_id
        and stage.stage_key == "research_task_review_plan"
        and stage.task_id not in resolved_task_ids
        and safe_preview_lines(
            (stage.payload if isinstance(stage.payload, dict) else {}).get(
                "required_evidence",
                [],
            )
        )
    )


def _campaign_promotion_review_summary(
    pipeline_stages: list[PipelineStageRecord],
) -> CampaignPromotionReviewSummary:
    allow_review_stages = []
    reviewed_feedback_stage_ids = set()
    required_evidence_blocked_count = _campaign_unresolved_required_evidence_count(
        pipeline_stages,
    )
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
        if required_evidence_blocked_count > 0:
            return CampaignPromotionReviewSummary(
                latest_reason="required_evidence_unresolved",
                next_allowed_action="Resolve required evidence gaps before candidate promotion.",
                required_evidence_blocked_count=required_evidence_blocked_count,
                validation_feedback_review_count=len(allow_review_stages),
            )
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
                required_evidence_blocked_count=required_evidence_blocked_count,
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
            required_evidence_blocked_count=required_evidence_blocked_count,
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
        required_evidence_blocked_count=required_evidence_blocked_count,
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
