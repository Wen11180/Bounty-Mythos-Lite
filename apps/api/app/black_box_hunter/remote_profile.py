from datetime import datetime, timedelta
from hashlib import sha256
import json
import re
from threading import RLock
from typing import Literal
from urllib.parse import urlsplit
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.black_box_hunter import (
    ALLOWED_ACTIONS,
    ALLOWED_METHODS_BY_ACTION,
    BlackBoxExecutionLease,
    BlackBoxStop,
    DifferentialTrial,
    LeaseApproval,
    ObservedTestObject,
    ObservedWorkflow,
    ObservedWorkflowModel,
    RuntimeSessionRegistry,
    SessionAlias,
    TestObjectAlias,
    WorkflowStep,
    validate_black_box_trial,
)
from app.scope_guard import ScopeGuardRule


REMOTE_PROFILE = "remote_human_lease"
REMOTE_APPROVAL_MAX_AGE = timedelta(minutes=30)
REMOTE_TRIAL_CLASSES = {
    "cross_account_object_swap",
    "lower_role_replay",
    "unauthenticated_read_only_replay",
    "owned_parent_child_swap",
    "reversible_out_of_order_state_transition",
}
REMOTE_TERMINAL_OUTCOMES = {
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
}
_SAFE_ALIAS = re.compile(
    r"^[a-z][a-z0-9_-]{0,63}$",
    re.IGNORECASE | re.ASCII,
)


class RemoteWorkflowLease(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    workflow_index: int = Field(ge=1, le=3)
    workflow_alias: str = Field(min_length=1, max_length=64)
    source_account_alias: str = Field(min_length=1, max_length=64)
    source_role_alias: str = Field(min_length=1, max_length=64)
    origin: str = Field(min_length=1, max_length=255)
    route_template: str = Field(min_length=1, max_length=1024)
    method: str = Field(min_length=1, max_length=16)
    action: str = Field(min_length=1, max_length=64)
    object_alias: str = Field(min_length=1, max_length=64)
    object_owner_alias: str = Field(min_length=1, max_length=64)
    object_state: str = Field(min_length=1, max_length=64)
    object_reversible: bool
    rollback_ready: bool
    allowed_trial_classes: tuple[str, ...] = Field(min_length=1)

    @field_validator(
        "workflow_alias",
        "source_account_alias",
        "source_role_alias",
        "object_alias",
        "object_owner_alias",
        "object_state",
    )
    @classmethod
    def require_safe_alias(cls, value: str) -> str:
        if _SAFE_ALIAS.fullmatch(value) is None:
            raise ValueError("safe_remote_alias_required")
        return value

    @field_validator("origin")
    @classmethod
    def require_exact_https_origin(cls, value: str) -> str:
        _require_exact_https_remote_origin(value)
        return value

    @field_validator("allowed_trial_classes")
    @classmethod
    def require_supported_trials(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(values)) != len(values) or any(
            value not in REMOTE_TRIAL_CLASSES for value in values
        ):
            raise ValueError("supported_remote_trial_class_required")
        return values

    @model_validator(mode="after")
    def require_recorded_safe_operation(self):
        method = self.method.upper()
        if not self.route_template.isascii():
            raise ValueError("ascii_remote_route_required")
        if (
            self.action not in ALLOWED_ACTIONS
            or method not in ALLOWED_METHODS_BY_ACTION[self.action]
        ):
            raise ValueError("safe_workflow_action_required")
        step = WorkflowStep(
            workflow_index=self.workflow_index,
            origin=self.origin,
            route_template=self.route_template,
            method=method,
            action=self.action,
            state=self.object_state,
        )
        if step.route_template == "/":
            raise ValueError("recorded_non_root_workflow_required")
        if "{object}" not in step.route_template:
            raise ValueError("recorded_object_route_required")
        if step.route_template.count("{object}") != 1:
            raise ValueError("single_remote_object_route_required")
        if self.action in {"test_object_create", "reversible_update"} and (
            not self.object_reversible or not self.rollback_ready
        ):
            raise ValueError("remote_rollback_readiness_required")
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "route_template", step.route_template)
        return self

    def workflow_step(self) -> WorkflowStep:
        return WorkflowStep(
            workflow_index=self.workflow_index,
            origin=self.origin,
            route_template=self.route_template,
            method=self.method,
            action=self.action,
            state=self.object_state,
        )


class RemoteHumanLease(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    profile: Literal["remote_human_lease"] = REMOTE_PROFILE
    lease: BlackBoxExecutionLease
    approval_id: str = Field(min_length=1, max_length=255)
    preflight_id: str = Field(min_length=1, max_length=255)
    approved_at: datetime
    workflows: tuple[RemoteWorkflowLease, ...] = Field(min_length=1, max_length=3)
    lease_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    report_submission_allowed: Literal[False] = False
    human_confirmation_allowed: Literal[False] = False

    @field_validator("approval_id", "preflight_id")
    @classmethod
    def require_safe_authority_alias(cls, value: str) -> str:
        if _SAFE_ALIAS.fullmatch(value) is None:
            raise ValueError("safe_remote_alias_required")
        return value

    @model_validator(mode="after")
    def require_bound_remote_authority(self):
        if len(self.lease.active_origins) != 1:
            raise ValueError("single_remote_active_origin_required")
        _require_exact_https_remote_origin(self.lease.active_origins[0])
        for origin in self.lease.passive_origins:
            _require_exact_https_remote_origin(origin)
        if (
            _SAFE_ALIAS.fullmatch(self.lease.lease_id) is None
            or not self.lease.asset.isascii()
            or any(
                _SAFE_ALIAS.fullmatch(alias) is None
                for alias in (*self.lease.account_aliases, *self.lease.role_aliases)
            )
        ):
            raise ValueError("safe_remote_alias_required")
        aliases = [workflow.workflow_alias for workflow in self.workflows]
        indexes = [workflow.workflow_index for workflow in self.workflows]
        if len(set(aliases)) != len(aliases) or len(set(indexes)) != len(indexes):
            raise ValueError("unique_remote_workflows_required")
        for workflow in self.workflows:
            if workflow.origin != self.lease.active_origins[0]:
                raise ValueError("active_origin_not_lease_approved")
            if workflow.source_account_alias not in self.lease.account_aliases:
                raise ValueError("leased_source_account_required")
            if workflow.source_role_alias not in self.lease.role_aliases:
                raise ValueError("leased_source_role_required")
            if workflow.object_owner_alias not in self.lease.account_aliases:
                raise ValueError("leased_test_object_owner_required")
            if workflow.object_owner_alias != workflow.source_account_alias:
                raise ValueError("source_owned_remote_object_required")
            if workflow.action not in self.lease.allowed_actions:
                raise ValueError("action_not_leased")
            if workflow.workflow_index > self.lease.workflow_budget:
                raise ValueError("workflow_budget_exhausted")
        if remote_lease_digest(self) != self.lease_digest:
            raise ValueError("lease_digest_mismatch")
        return self

    def safe_status(self, *, now: datetime, stop: BlackBoxStop | None = None) -> dict:
        expired = now >= self.lease.expires_at
        relogin_required = expired or stop is not None
        return {
            "profile": self.profile,
            "state": "stopped" if stop is not None else "expired" if expired else "active",
            "expires_at": self.lease.expires_at.isoformat().replace("+00:00", "Z"),
            "relogin_required": relogin_required,
            "stop_reason": stop.reason if stop is not None else None,
            "report_submission_allowed": False,
            "human_confirmation_allowed": False,
        }


class RemoteRequestAuthorization(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    workflow_alias: str = Field(min_length=1, max_length=64)
    trial_class: str = Field(min_length=1, max_length=64)
    target_account_alias: str = Field(min_length=1, max_length=64)
    target_role_alias: str = Field(min_length=1, max_length=64)
    object_alias: str = Field(min_length=1, max_length=64)
    session_generation: str = Field(min_length=1, max_length=64)

    @field_validator(
        "workflow_alias",
        "target_account_alias",
        "target_role_alias",
        "object_alias",
        "session_generation",
    )
    @classmethod
    def require_safe_alias(cls, value: str) -> str:
        if _SAFE_ALIAS.fullmatch(value) is None:
            raise ValueError("safe_remote_alias_required")
        return value

    @field_validator("trial_class")
    @classmethod
    def require_supported_trial(cls, value: str) -> str:
        if value not in REMOTE_TRIAL_CLASSES:
            raise ValueError("supported_remote_trial_class_required")
        return value


class RemoteAuthorizationDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: bool
    reason: str
    request_grant_id: str | None = None
    stop: BlackBoxStop | None = None
    report_submission_allowed: Literal[False] = False
    human_confirmation_allowed: Literal[False] = False


def issue_remote_human_lease(
    *,
    lease: BlackBoxExecutionLease,
    approval: LeaseApproval,
    approved_at: datetime,
    workflows: list[RemoteWorkflowLease],
    now: datetime,
) -> RemoteHumanLease:
    if any(value.tzinfo is None or value.utcoffset() is None for value in (approved_at, now)):
        raise ValueError("timezone_aware_time_required")
    if approved_at > now or now - approved_at > REMOTE_APPROVAL_MAX_AGE:
        raise ValueError("fresh_remote_approval_required")
    if lease.issued_at != now:
        raise ValueError("single_run_lease_issuance_required")
    if not _approval_matches(approval, lease) or approval.expires_at <= now:
        raise ValueError("approved_unexpired_remote_authority_required")
    payload = {
        "profile": REMOTE_PROFILE,
        "lease": lease.model_dump(mode="json"),
        "approval_id": approval.approval_id,
        "preflight_id": approval.preflight_id,
        "approved_at": approved_at.isoformat().replace("+00:00", "Z"),
        "workflows": [workflow.model_dump(mode="json") for workflow in workflows],
        "report_submission_allowed": False,
        "human_confirmation_allowed": False,
    }
    payload["lease_digest"] = _digest(payload)
    return RemoteHumanLease(**payload)


def remote_lease_digest(remote_lease: RemoteHumanLease) -> str:
    serialized = remote_lease.model_dump(mode="json")
    payload = {
        key: serialized[key]
        for key in (
            "profile",
            "lease",
            "approval_id",
            "preflight_id",
            "approved_at",
            "workflows",
            "report_submission_allowed",
            "human_confirmation_allowed",
        )
    }
    return _digest(payload)


class RemoteLeaseRuntime:
    __slots__ = (
        "remote_lease",
        "_active_grant_id",
        "_last_request_at",
        "_lock",
        "_request_counts",
        "_session_generation",
        "_stop",
    )

    def __init__(self, remote_lease: RemoteHumanLease) -> None:
        self.remote_lease = remote_lease
        self._active_grant_id: str | None = None
        self._last_request_at: datetime | None = None
        self._lock = RLock()
        self._request_counts = {workflow.workflow_alias: 0 for workflow in remote_lease.workflows}
        self._session_generation: str | None = None
        self._stop: BlackBoxStop | None = None

    def __reduce__(self):
        raise TypeError("remote_lease_runtime_not_serializable")

    def authorize(
        self,
        *,
        rule: ScopeGuardRule,
        approval: LeaseApproval,
        request: RemoteRequestAuthorization,
        current_policy_digest: str,
        current_scope_digest: str,
        current_plan_digest: str,
        lease_digest: str,
        now: datetime,
    ) -> RemoteAuthorizationDecision:
        with self._lock:
            return self._authorize_unlocked(
                rule=rule,
                approval=approval,
                request=request,
                current_policy_digest=current_policy_digest,
                current_scope_digest=current_scope_digest,
                current_plan_digest=current_plan_digest,
                lease_digest=lease_digest,
                now=now,
            )

    def _authorize_unlocked(
        self,
        *,
        rule: ScopeGuardRule,
        approval: LeaseApproval,
        request: RemoteRequestAuthorization,
        current_policy_digest: str,
        current_scope_digest: str,
        current_plan_digest: str,
        lease_digest: str,
        now: datetime,
    ) -> RemoteAuthorizationDecision:
        if self._stop is not None:
            return self._stopped_decision()
        lease = self.remote_lease.lease
        if remote_lease_digest(self.remote_lease) != self.remote_lease.lease_digest:
            return self._stop_once("lease_digest_mismatch")
        if lease_digest != self.remote_lease.lease_digest:
            return self._stop_once("lease_digest_mismatch")
        if (
            current_policy_digest != lease.policy_digest
            or current_scope_digest != lease.scope_digest
            or current_plan_digest != lease.plan_digest
        ):
            return self._stop_once("policy_or_scope_changed")
        if not _approval_matches(approval, lease):
            return self._stop_once("approval_preflight_changed")
        if self._session_generation is None:
            self._session_generation = request.session_generation
        elif request.session_generation != self._session_generation:
            return self._stop_once("session_changed")

        workflow = next(
            (
                candidate
                for candidate in self.remote_lease.workflows
                if candidate.workflow_alias == request.workflow_alias
            ),
            None,
        )
        if workflow is None or request.trial_class not in workflow.allowed_trial_classes:
            return self._stop_once("demonstrated_workflow_step_required")
        if request.object_alias != workflow.object_alias:
            return self._stop_once("test_owned_object_required")
        if self._active_grant_id is not None:
            return self._stop_once("concurrency_limit")

        observed_workflows, runtime_registry = _runtime_provenance(
            workflow,
            request,
        )
        last_interval = (
            lease.min_interval_seconds
            if self._last_request_at is None
            else max(0, int((now - self._last_request_at).total_seconds()))
        )
        trial = DifferentialTrial(
            trial_class=request.trial_class,
            workflow=workflow.workflow_step(),
            session=SessionAlias(
                account_alias=request.target_account_alias,
                role_alias=request.target_role_alias,
                active=request.trial_class != "unauthenticated_read_only_replay",
            ),
            test_object=TestObjectAlias(
                alias=workflow.object_alias,
                owner_alias=workflow.object_owner_alias,
                test_owned=True,
                reversible=workflow.object_reversible,
                state=workflow.object_state,
            ),
            generated_requests_in_workflow=self._request_counts[workflow.workflow_alias],
            active_generated_requests=0,
            elapsed_seconds=max(0, int((now - lease.issued_at).total_seconds())),
            seconds_since_last_generated_request=last_interval,
            requires_rollback=workflow.action in {"test_object_create", "reversible_update"},
            rollback_ready=workflow.rollback_ready,
        )
        decision = validate_black_box_trial(
            rule,
            lease,
            approval,
            trial,
            now=now,
            observed_workflows=observed_workflows,
            runtime_registry=runtime_registry,
        )
        if not decision.allowed:
            return self._stop_once(decision.reason)

        grant_id = f"remote_grant_{uuid4().hex}"
        self._active_grant_id = grant_id
        self._request_counts[workflow.workflow_alias] += 1
        return RemoteAuthorizationDecision(
            allowed=True,
            reason="remote_request_authorized",
            request_grant_id=grant_id,
        )

    def complete(
        self,
        request_grant_id: str,
        *,
        outcome: str,
        now: datetime,
    ) -> RemoteAuthorizationDecision:
        with self._lock:
            return self._complete_unlocked(
                request_grant_id,
                outcome=outcome,
                now=now,
            )

    def _complete_unlocked(
        self,
        request_grant_id: str,
        *,
        outcome: str,
        now: datetime,
    ) -> RemoteAuthorizationDecision:
        if self._stop is not None:
            return self._stopped_decision()
        if request_grant_id != self._active_grant_id:
            return self._stop_once("ambiguous_authority")
        self._active_grant_id = None
        self._last_request_at = now
        if outcome == "success":
            return RemoteAuthorizationDecision(
                allowed=True,
                reason="remote_request_completed",
            )
        if outcome not in REMOTE_TERMINAL_OUTCOMES:
            return self._stop_once("ambiguous_authority")
        return self._stop_once(outcome)

    def safe_status(self, *, now: datetime) -> dict:
        with self._lock:
            return self.remote_lease.safe_status(now=now, stop=self._stop)

    def stop(self, reason: str) -> RemoteAuthorizationDecision:
        with self._lock:
            return self._stop_once(reason)

    def _stop_once(self, reason: str) -> RemoteAuthorizationDecision:
        if self._stop is None:
            self._stop = BlackBoxStop(reason=reason)
            self._active_grant_id = None
        return self._stopped_decision()

    def _stopped_decision(self) -> RemoteAuthorizationDecision:
        return RemoteAuthorizationDecision(
            allowed=False,
            reason=self._stop.reason,
            stop=self._stop,
        )


def _runtime_provenance(
    workflow: RemoteWorkflowLease,
    request: RemoteRequestAuthorization,
) -> tuple[ObservedWorkflowModel, RuntimeSessionRegistry]:
    observed = ObservedWorkflowModel(
        workflows=[
            ObservedWorkflow(
                workflow_alias=workflow.workflow_alias,
                session=SessionAlias(
                    account_alias=workflow.source_account_alias,
                    role_alias=workflow.source_role_alias,
                    active=True,
                ),
                steps=[workflow.workflow_step()],
                objects=[
                    ObservedTestObject(
                        alias=workflow.object_alias,
                        owner_alias=workflow.object_owner_alias,
                        state=workflow.object_state,
                        reversible=workflow.object_reversible,
                        provenance="demonstrated_normal_flow",
                    )
                ],
                baseline_stable=True,
                rollback_ready=workflow.rollback_ready,
            )
        ]
    )
    registry = RuntimeSessionRegistry()
    registry.register_session(request.target_account_alias, object())
    registry.register_object(workflow.object_alias, "runtime_owned_object")
    return observed, registry


def _approval_matches(approval: LeaseApproval, lease: BlackBoxExecutionLease) -> bool:
    return (
        approval.lease_id == lease.lease_id
        and approval.asset == lease.asset
        and approval.policy_digest == lease.policy_digest
        and approval.scope_digest == lease.scope_digest
        and approval.plan_digest == lease.plan_digest
        and approval.validation_mode == "black_box_differential"
        and approval.approval_status == "approved"
        and approval.preflight_status == "preflight_passed"
    )


def _require_exact_https_remote_origin(value: str) -> None:
    parsed = urlsplit(value)
    if (
        not value.isascii()
        or parsed.scheme != "https"
        or not parsed.netloc
        or parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
        or "*" in parsed.netloc
        or value != f"{parsed.scheme}://{parsed.netloc}"
    ):
        raise ValueError("exact_https_remote_origin_required")


def _digest(payload: dict) -> str:
    serialized = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return f"sha256:{sha256(serialized.encode('utf-8')).hexdigest()}"
