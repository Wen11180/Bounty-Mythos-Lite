from datetime import datetime
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.scope_guard import (
    ScopeGuardDecision,
    ScopeGuardRule,
    ValidationRequest,
    evaluate_validation_request,
)


ALLOWED_ACTIONS = {
    "read_only_replay",
    "test_object_create",
    "reversible_update",
}
ALLOWED_METHODS_BY_ACTION = {
    "read_only_replay": {"GET", "HEAD"},
    "test_object_create": {"POST"},
    "reversible_update": {"POST", "PUT", "PATCH"},
}
BLACK_BOX_VALIDATION_TYPE = "black_box_differential"
SECRET_MARKERS = (
    "authorization:",
    "bearer ",
    "cookie:",
    "password=",
    "secret=",
    "token=",
)


def _has_secret_marker(value: str) -> bool:
    return any(marker in value.lower() for marker in SECRET_MARKERS)


def _require_safe_authority_text(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("safe_authority_text_required")
    if _has_secret_marker(value):
        raise ValueError("secret_like_authority_text")
    return value


def _require_exact_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
        or "*" in parsed.netloc
        or value != f"{parsed.scheme}://{parsed.netloc}"
    ):
        raise ValueError("exact_origin_required")
    return value


class RuntimeSessionRegistry:
    __slots__ = ("_session_handles", "_object_ids")

    def __init__(self) -> None:
        self._session_handles: dict[str, object] = {}
        self._object_ids: dict[str, str] = {}

    def __reduce__(self):
        raise TypeError("runtime_session_registry_not_serializable")

    def register_session(self, alias: str, handle: object) -> None:
        self._session_handles[alias] = handle

    def register_object(self, alias: str, object_id: str) -> None:
        self._object_ids[alias] = object_id

    def session_handle(self, alias: str) -> object:
        return self._session_handles[alias]

    def object_id(self, alias: str) -> str:
        return self._object_ids[alias]

    def safe_projection(self) -> dict:
        return {
            "session_aliases": sorted(self._session_handles),
            "object_aliases": sorted(self._object_ids),
        }


class BlackBoxExecutionLease(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lease_id: str = Field(min_length=1, max_length=255)
    asset: str = Field(min_length=1, max_length=255)
    policy_digest: str = Field(min_length=1, max_length=255)
    scope_digest: str = Field(min_length=1, max_length=255)
    plan_digest: str = Field(min_length=1, max_length=255)
    active_origins: list[str] = Field(min_length=1)
    passive_origins: list[str] = Field(default_factory=list)
    account_aliases: list[str] = Field(min_length=2)
    role_aliases: list[str] = Field(min_length=1)
    allowed_actions: list[str] = Field(min_length=1)
    rollback_required: bool
    workflow_budget: int = Field(default=3, ge=1, le=3)
    request_budget_per_workflow: int = Field(default=50, ge=1, le=50)
    duration_seconds: int = Field(default=1800, ge=1, le=1800)
    min_interval_seconds: int = Field(default=3, ge=3)
    issued_at: datetime
    expires_at: datetime

    @field_validator(
        "lease_id",
        "asset",
        "policy_digest",
        "scope_digest",
        "plan_digest",
        mode="before",
    )
    @classmethod
    def reject_secret_text(cls, value: object) -> str:
        return _require_safe_authority_text(value)

    @field_validator("active_origins", "passive_origins")
    @classmethod
    def require_exact_origins(cls, values: list[str]) -> list[str]:
        return [_require_exact_origin(value) for value in values]

    @field_validator("account_aliases", "role_aliases")
    @classmethod
    def require_safe_aliases(cls, values: list[str]) -> list[str]:
        if len(set(values)) != len(values) or any(
            not value.strip()
            or _has_secret_marker(value)
            for value in values
        ):
            raise ValueError("safe_unique_aliases_required")
        return values

    @field_validator("allowed_actions")
    @classmethod
    def require_allowed_actions(cls, values: list[str]) -> list[str]:
        if len(set(values)) != len(values) or any(value not in ALLOWED_ACTIONS for value in values):
            raise ValueError("unsupported_black_box_action")
        return values

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_timezone_aware_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timezone_aware_expiry_required")
        return value

    @model_validator(mode="after")
    def reject_active_passive_origin_overlap(self):
        if self.expires_at <= self.issued_at:
            raise ValueError("expiry_after_issuance_required")
        if set(self.active_origins) & set(self.passive_origins):
            raise ValueError("active_passive_origin_overlap")
        return self

    def safe_projection(self) -> dict:
        return self.model_dump(mode="json")


class LeaseApproval(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str = Field(min_length=1, max_length=255)
    preflight_id: str = Field(min_length=1, max_length=255)
    lease_id: str = Field(min_length=1, max_length=255)
    asset: str = Field(min_length=1, max_length=255)
    policy_digest: str = Field(min_length=1, max_length=255)
    scope_digest: str = Field(min_length=1, max_length=255)
    plan_digest: str = Field(min_length=1, max_length=255)
    validation_mode: Literal["black_box_differential"]
    approval_status: Literal["approved"]
    preflight_status: Literal["preflight_passed"]
    expires_at: datetime

    @field_validator(
        "approval_id",
        "preflight_id",
        "lease_id",
        "asset",
        "policy_digest",
        "scope_digest",
        "plan_digest",
        mode="before",
    )
    @classmethod
    def reject_secret_text(cls, value: object) -> str:
        return _require_safe_authority_text(value)

    @field_validator("expires_at")
    @classmethod
    def require_timezone_aware_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timezone_aware_expiry_required")
        return value


class SessionAlias(BaseModel):
    model_config = ConfigDict(extra="forbid")

    account_alias: str = Field(min_length=1, max_length=255)
    role_alias: str = Field(min_length=1, max_length=255)
    active: bool

    @field_validator("account_alias", "role_alias")
    @classmethod
    def reject_secret_text(cls, value: str) -> str:
        if _has_secret_marker(value):
            raise ValueError("secret_like_alias")
        return value


class WorkflowStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workflow_index: int = Field(ge=1)
    origin: str = Field(min_length=1, max_length=255)
    route_template: str = Field(min_length=1, max_length=1024)
    method: str = Field(min_length=1, max_length=16)
    action: str = Field(min_length=1, max_length=255)
    state: str = Field(min_length=1, max_length=255)

    @field_validator("origin")
    @classmethod
    def require_exact_origin(cls, value: str) -> str:
        return _require_exact_origin(value)

    @field_validator("route_template")
    @classmethod
    def reject_query_values(cls, value: str) -> str:
        if "?" in value:
            raise ValueError("normalized_route_template_required")
        return value

    @field_validator("state")
    @classmethod
    def reject_secret_state(cls, value: str) -> str:
        if _has_secret_marker(value):
            raise ValueError("secret_like_state")
        return value


class TestObjectAlias(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alias: str = Field(min_length=1, max_length=255)
    owner_alias: str = Field(min_length=1, max_length=255)
    test_owned: bool
    reversible: bool
    state: str = Field(min_length=1, max_length=255)

    @field_validator("alias", "owner_alias", "state")
    @classmethod
    def reject_secret_text(cls, value: str) -> str:
        if _has_secret_marker(value):
            raise ValueError("secret_like_alias")
        return value


class DifferentialTrial(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workflow: WorkflowStep
    session: SessionAlias
    test_object: TestObjectAlias
    generated_requests_in_workflow: int = Field(ge=0)
    active_generated_requests: int = Field(ge=0)
    elapsed_seconds: int = Field(ge=0)
    seconds_since_last_generated_request: int = Field(ge=0)
    requires_rollback: bool
    rollback_ready: bool


class TrialObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status_class: Literal["2xx", "3xx", "4xx", "5xx", "network_error"]
    response_schema_fingerprint: str = Field(min_length=1, max_length=255)
    timing_bucket: str = Field(min_length=1, max_length=64)
    canary_match: bool | None = None
    state_effect: bool | None = None
    redacted: Literal[True]

    @field_validator("response_schema_fingerprint")
    @classmethod
    def reject_secret_text(cls, value: str) -> str:
        if _has_secret_marker(value):
            raise ValueError("secret_like_fingerprint")
        return value


class BlackBoxStop(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=255)
    terminal: Literal[True] = True


class BlackBoxTrialDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    reason: str = Field(min_length=1, max_length=255)
    stop: BlackBoxStop | None = None


def validate_black_box_trial(
    rule: ScopeGuardRule,
    lease: BlackBoxExecutionLease,
    approval: LeaseApproval | None,
    trial: DifferentialTrial,
    *,
    now: datetime,
) -> BlackBoxTrialDecision:
    scope_decision = evaluate_validation_request(
        rule,
        ValidationRequest(
            asset=lease.asset,
            validation_type=BLACK_BOX_VALIDATION_TYPE,
            human_approved=approval is not None,
            plan_digest=lease.plan_digest,
        ),
    )
    if not scope_decision.allowed:
        return _blocked_trial(scope_decision)

    if approval is None:
        return _blocked_trial_reason("approval_record_required")
    if now.tzinfo is None or now.utcoffset() is None:
        return _blocked_trial_reason("timezone_aware_time_required")
    if not _approval_matches_lease(approval, lease):
        return _blocked_trial_reason("approval_preflight_mismatch")
    if lease.issued_at > now:
        return _blocked_trial_reason("lease_not_active")
    if lease.expires_at <= now or approval.expires_at <= now:
        return _blocked_trial_reason("lease_or_approval_expired")
    if (now - lease.issued_at).total_seconds() >= lease.duration_seconds:
        return _blocked_trial_reason("duration_budget_exhausted")
    if trial.workflow.origin not in lease.active_origins:
        return _blocked_trial_reason("active_origin_required")
    if trial.workflow.route_template == "/":
        return _blocked_trial_reason("root_route_not_trialable")
    if trial.workflow.action not in lease.allowed_actions:
        return _blocked_trial_reason("action_not_leased")
    if trial.workflow.action not in ALLOWED_ACTIONS:
        return _blocked_trial_reason("unsupported_black_box_action")
    if trial.workflow.method.upper() not in ALLOWED_METHODS_BY_ACTION[
        trial.workflow.action
    ]:
        return _blocked_trial_reason("method_action_mismatch")
    if not trial.session.active:
        return _blocked_trial_reason("session_inactive")
    if trial.session.account_alias not in lease.account_aliases:
        return _blocked_trial_reason("account_not_leased")
    if trial.session.role_alias not in lease.role_aliases:
        return _blocked_trial_reason("role_not_leased")
    if not trial.test_object.test_owned:
        return _blocked_trial_reason("test_owned_object_required")
    if trial.test_object.owner_alias not in lease.account_aliases:
        return _blocked_trial_reason("object_owner_not_leased")
    if trial.workflow.workflow_index > lease.workflow_budget:
        return _blocked_trial_reason("workflow_budget_exhausted")
    if trial.generated_requests_in_workflow >= lease.request_budget_per_workflow:
        return _blocked_trial_reason("request_budget_exhausted")
    if trial.active_generated_requests >= 1:
        return _blocked_trial_reason("concurrency_limit")
    if trial.elapsed_seconds >= lease.duration_seconds:
        return _blocked_trial_reason("duration_budget_exhausted")
    if trial.seconds_since_last_generated_request < lease.min_interval_seconds:
        return _blocked_trial_reason("rate_limit")
    requires_rollback = trial.requires_rollback or trial.workflow.action in {
        "test_object_create",
        "reversible_update",
    }
    if requires_rollback and (
        not lease.rollback_required
        or not trial.test_object.reversible
        or not trial.rollback_ready
    ):
        return _blocked_trial_reason("rollback_required")

    return BlackBoxTrialDecision(allowed=True, reason="trial_allowed")


def _approval_matches_lease(
    approval: LeaseApproval,
    lease: BlackBoxExecutionLease,
) -> bool:
    return (
        approval.lease_id == lease.lease_id
        and approval.asset == lease.asset
        and approval.policy_digest == lease.policy_digest
        and approval.scope_digest == lease.scope_digest
        and approval.plan_digest == lease.plan_digest
        and approval.validation_mode == BLACK_BOX_VALIDATION_TYPE
        and approval.approval_status == "approved"
        and approval.preflight_status == "preflight_passed"
    )


def _blocked_trial(decision: ScopeGuardDecision) -> BlackBoxTrialDecision:
    return _blocked_trial_reason(decision.reason)


def _blocked_trial_reason(reason: str) -> BlackBoxTrialDecision:
    return BlackBoxTrialDecision(
        allowed=False,
        reason=reason,
        stop=BlackBoxStop(reason=reason),
    )
