from datetime import datetime
import re
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
ALLOWED_TIMING_BUCKETS = {
    "synthetic",
    "under_100ms",
    "under_500ms",
    "under_1s",
    "under_3s",
    "over_3s",
}
ALLOWED_STOP_REASONS = {
    "out_of_scope",
    "automation_not_allowed",
    "forbidden_validation",
    "research_only_action",
    "human_approval_required",
    "validation_not_allowed",
    "approval_record_required",
    "timezone_aware_time_required",
    "approval_preflight_mismatch",
    "lease_not_active",
    "lease_or_approval_expired",
    "duration_budget_exhausted",
    "active_origin_required",
    "active_origin_not_scope_approved",
    "root_route_not_trialable",
    "action_not_leased",
    "unsupported_black_box_action",
    "method_action_mismatch",
    "session_inactive",
    "runtime_session_required",
    "account_not_leased",
    "role_not_leased",
    "test_owned_object_required",
    "demonstrated_object_provenance_required",
    "demonstrated_workflow_step_required",
    "object_provenance_mismatch",
    "object_owner_not_leased",
    "workflow_budget_exhausted",
    "request_budget_exhausted",
    "concurrency_limit",
    "rate_limit",
    "rollback_required",
    "loopback_origin_required",
    "local_lab_route_required",
    "third_party_data_detected",
    "off_origin_redirect",
    "expired_session",
    "session_expired",
    "rate_limited",
    "server_error",
    "rollback_failed",
    "unstable_response",
    "unknown_test_object",
    "request_failed",
    "captcha_or_waf_detected",
    "page_closed",
    "browser_crash",
    "lease_expired",
    "operator_stop",
    "app_exit",
    "policy_or_scope_changed",
    "lease_digest_mismatch",
    "session_changed",
    "approval_preflight_changed",
    "ambiguous_authority",
    "remote_profile_disabled",
    "relogin_required",
}
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


_UUID_SEGMENT = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_HEX_ID_SEGMENT = re.compile(r"^[0-9a-f]{24,}$", re.IGNORECASE)
_NUMERIC_ID_SEGMENT = re.compile(r"^[0-9]+$")
_ULID_SEGMENT = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$", re.IGNORECASE)
_SLUG_SEGMENT = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)+$", re.IGNORECASE)
_BRACED_PLACEHOLDER = re.compile(r"^\{([^{}]+)\}$")
_ANGLE_PLACEHOLDER = re.compile(r"^<([^<>]+)>$")


def _normalized_parameter_name(value: str) -> str:
    return value.strip().lower().replace("-", "_")


def _placeholder_name(segment: str) -> str | None:
    placeholder = _BRACED_PLACEHOLDER.fullmatch(segment)
    if placeholder is not None:
        return placeholder.group(1)
    if segment.startswith(":") and len(segment) > 1:
        return segment[1:]
    angle_placeholder = _ANGLE_PLACEHOLDER.fullmatch(segment)
    if angle_placeholder is not None:
        return angle_placeholder.group(1).split(":")[-1]
    return None


def _is_identifier_placeholder(value: str) -> bool:
    normalized_name = _normalized_parameter_name(value)
    return (
        normalized_name == "object"
        or normalized_name.endswith("_id")
        or normalized_name in {"id", "pk", "uuid"}
    )


def _normalize_route_template(
    value: str,
    path_parameters: list["WorkflowPathParameter"],
    *,
    reject_undeclared_slug_segments: bool = False,
) -> str:
    parsed = urlsplit(value)
    if (
        not value.startswith("/")
        or value.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or "\\" in value
        or "%" in value
    ):
        raise ValueError("normalized_route_template_required")

    non_empty_segments = [segment for segment in value.split("/") if segment]
    parameters_by_segment: dict[int, WorkflowPathParameter] = {}
    for parameter in path_parameters:
        if parameter.segment > len(non_empty_segments):
            raise ValueError("path_parameter_segment_required")
        if parameter.segment in parameters_by_segment:
            raise ValueError("path_parameter_segment_unique")
        parameters_by_segment[parameter.segment] = parameter

    normalized_segments: list[str] = []
    non_empty_index = 0
    for segment in value.split("/"):
        if not segment:
            normalized_segments.append(segment)
            continue
        non_empty_index += 1
        if segment in {".", ".."} or any(
            ord(character) < 0x20 or ord(character) == 0x7F
            for character in segment
        ):
            raise ValueError("unsafe_route_segment")

        placeholder_name = _placeholder_name(segment)
        declared_parameter = parameters_by_segment.get(non_empty_index)

        if (
            _NUMERIC_ID_SEGMENT.fullmatch(segment)
            or _UUID_SEGMENT.fullmatch(segment)
            or _ULID_SEGMENT.fullmatch(segment)
            or _HEX_ID_SEGMENT.fullmatch(segment)
        ):
            raise ValueError("concrete_object_id_route_forbidden")

        if declared_parameter is not None:
            if placeholder_name is None:
                raise ValueError("path_parameter_segment_required")
            if (
                _normalized_parameter_name(placeholder_name) != "object"
                and _normalized_parameter_name(placeholder_name)
                != _normalized_parameter_name(declared_parameter.name)
            ):
                raise ValueError("path_parameter_name_mismatch")

        if placeholder_name is not None:
            if _is_identifier_placeholder(placeholder_name) or declared_parameter is not None:
                normalized_segments.append("{object}")
                continue
            raise ValueError("path_parameter_metadata_required")
        if declared_parameter is not None:
            raise ValueError("path_parameter_segment_required")
        if (
            reject_undeclared_slug_segments
            and _SLUG_SEGMENT.fullmatch(segment)
        ):
            raise ValueError("path_parameter_metadata_required")
        normalized_segments.append(segment)

    return "/".join(normalized_segments)


def _origin_matches_scope_asset(origin: str, asset: str) -> bool:
    if "://" in asset:
        try:
            return _require_exact_origin(asset) == origin
        except ValueError:
            return False
    try:
        parsed = urlsplit(origin)
    except ValueError:
        return False
    return (
        parsed.scheme in {"http", "https"}
        and parsed.netloc == asset
        and not parsed.path
        and not parsed.query
        and not parsed.fragment
    )


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


class WorkflowPathParameter(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    name: str = Field(min_length=1, max_length=255)
    segment: int = Field(ge=1)
    value_type: Literal["string", "integer", "uuid", "ulid", "slug"] = Field(
        default="string",
        alias="type",
    )

    @field_validator("name")
    @classmethod
    def require_safe_name(cls, value: str) -> str:
        if (
            value.strip() != value
            or "/" in value
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
            or _has_secret_marker(value)
        ):
            raise ValueError("safe_path_parameter_name_required")
        return value


class WorkflowStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workflow_index: int = Field(ge=1)
    origin: str = Field(min_length=1, max_length=255)
    route_template: str = Field(min_length=1, max_length=1024)
    path_parameters: list[WorkflowPathParameter] = Field(default_factory=list)
    method: str = Field(min_length=1, max_length=16)
    action: str = Field(min_length=1, max_length=255)
    state: str = Field(min_length=1, max_length=255)

    @field_validator("origin")
    @classmethod
    def require_exact_origin(cls, value: str) -> str:
        return _require_exact_origin(value)

    @model_validator(mode="after")
    def normalize_route_template(self):
        self.route_template = _normalize_route_template(
            self.route_template,
            self.path_parameters,
        )
        return self

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


class ObservedTestObject(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alias: str = Field(min_length=1, max_length=255)
    owner_alias: str = Field(min_length=1, max_length=255)
    parent_alias: str | None = Field(default=None, min_length=1, max_length=255)
    state: str = Field(min_length=1, max_length=255)
    reversible: bool
    provenance: Literal["demonstrated_normal_flow"]

    @field_validator("alias", "owner_alias", "parent_alias", "state")
    @classmethod
    def reject_secret_text(cls, value: str | None) -> str | None:
        if value is not None and _has_secret_marker(value):
            raise ValueError("secret_like_alias")
        return value

    @model_validator(mode="after")
    def reject_self_parent(self):
        if self.parent_alias == self.alias:
            raise ValueError("object_parent_must_differ")
        return self


class ObservedWorkflow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workflow_alias: str = Field(min_length=1, max_length=255)
    session: SessionAlias
    steps: list[WorkflowStep] = Field(min_length=1)
    objects: list[ObservedTestObject] = Field(min_length=1)
    role_rank: int | None = Field(default=None, ge=0, le=100)
    baseline_stable: bool
    rollback_ready: bool

    @field_validator("workflow_alias")
    @classmethod
    def reject_secret_text(cls, value: str) -> str:
        if _has_secret_marker(value):
            raise ValueError("secret_like_alias")
        return value

    @model_validator(mode="after")
    def require_session_owned_objects(self):
        if any(obj.owner_alias != self.session.account_alias for obj in self.objects):
            raise ValueError("workflow_object_owner_mismatch")
        return self


class ObservedWorkflowModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workflows: list[ObservedWorkflow] = Field(min_length=1)

    def safe_projection(self) -> dict:
        return {
            "workflows": [
                {
                    "workflow_alias": workflow.workflow_alias,
                    "account_alias": workflow.session.account_alias,
                    "role_alias": workflow.session.role_alias,
                    "baseline_stable": workflow.baseline_stable,
                    "rollback_ready": workflow.rollback_ready,
                    **(
                        {"role_rank": workflow.role_rank}
                        if workflow.role_rank is not None
                        else {}
                    ),
                    "steps": [
                        step.model_dump(exclude_defaults=True)
                        for step in workflow.steps
                    ],
                    "objects": [
                        {
                            "alias": obj.alias,
                            "owner_alias": obj.owner_alias,
                            **(
                                {"parent_alias": obj.parent_alias}
                                if obj.parent_alias is not None
                                else {}
                            ),
                            "state": obj.state,
                            "reversible": obj.reversible,
                            "provenance": obj.provenance,
                        }
                        for obj in workflow.objects
                    ],
                }
                for workflow in self.workflows
            ]
        }


class PlannedDifferentialTrial(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trial_class: Literal[
        "cross_account_object_swap",
        "lower_role_replay",
        "unauthenticated_read_only_replay",
        "owned_parent_child_swap",
        "reversible_out_of_order_state_transition",
    ]
    phase: Literal[
        "baseline",
        "trial",
        "owner_control",
        "session_control",
        "repeat",
        "rollback",
    ]
    changed_variable: Literal["object", "role", "session", "parent", "state"]
    workflow: WorkflowStep
    session: SessionAlias
    test_object: TestObjectAlias
    parent_object_alias: str | None = Field(default=None, min_length=1, max_length=255)
    requires_rollback: bool
    rollback_ready: bool

    @field_validator("parent_object_alias")
    @classmethod
    def reject_secret_parent_alias(cls, value: str | None) -> str | None:
        if value is not None and _has_secret_marker(value):
            raise ValueError("secret_like_alias")
        return value


class DifferentialPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trial_class: Literal[
        "cross_account_object_swap",
        "lower_role_replay",
        "unauthenticated_read_only_replay",
        "owned_parent_child_swap",
        "reversible_out_of_order_state_transition",
    ]
    baseline: PlannedDifferentialTrial
    trial: PlannedDifferentialTrial
    owner_control: PlannedDifferentialTrial
    session_control: PlannedDifferentialTrial
    repeat: PlannedDifferentialTrial
    rollback: PlannedDifferentialTrial | None = None

    @model_validator(mode="after")
    def require_consistent_trial_stages(self):
        stages = (
            self.baseline,
            self.trial,
            self.owner_control,
            self.session_control,
            self.repeat,
        )
        if any(stage.trial_class != self.trial_class for stage in stages):
            raise ValueError("plan_trial_class_mismatch")
        if self.rollback is not None and self.rollback.trial_class != self.trial_class:
            raise ValueError("plan_rollback_class_mismatch")
        return self


def plan_differential_trials(
    model: ObservedWorkflowModel,
    *,
    require_all_classes: bool = True,
) -> list[DifferentialPlan]:
    _require_plannable_workflows(model)
    source_workflow = max(model.workflows, key=lambda workflow: workflow.role_rank)
    alternate_workflow = min(model.workflows, key=lambda workflow: workflow.role_rank)
    source_object = source_workflow.objects[0]
    alternate_object = alternate_workflow.objects[0]
    source_read = _workflow_step(source_workflow, "read_only_replay")
    try:
        alternate_read = _workflow_step(alternate_workflow, "read_only_replay")
    except ValueError:
        alternate_read = None
    try:
        update_step = _workflow_step(source_workflow, "reversible_update")
    except ValueError:
        update_step = None
    child_object = next(
        (obj for obj in source_workflow.objects if obj.parent_alias is not None),
        None,
    )
    alternate_parent = (
        next(
            (
                obj
                for obj in source_workflow.objects
                if obj.parent_alias is None and obj.alias != child_object.parent_alias
            ),
            None,
        )
        if child_object is not None
        else None
    )

    plans: list[DifferentialPlan] = []
    plans.append(
        _build_read_only_plan(
            trial_class="cross_account_object_swap",
            changed_variable="object",
            source_workflow=source_workflow,
            alternate_workflow=alternate_workflow,
            source_object=source_object,
            alternate_object=alternate_object,
            source_read=source_read,
            trial_session=alternate_workflow.session,
        )
    )
    plans.append(
        _build_read_only_plan(
            trial_class="lower_role_replay",
            changed_variable="role",
            source_workflow=source_workflow,
            alternate_workflow=alternate_workflow,
            source_object=source_object,
            alternate_object=alternate_object,
            source_read=source_read,
            trial_session=alternate_workflow.session,
        )
    )
    plans.append(
        _build_read_only_plan(
            trial_class="unauthenticated_read_only_replay",
            changed_variable="session",
            source_workflow=source_workflow,
            alternate_workflow=alternate_workflow,
            source_object=source_object,
            alternate_object=alternate_object,
            source_read=source_read,
            trial_session=SessionAlias(
                account_alias="unauthenticated",
                role_alias="unauthenticated",
                active=False,
            ),
        )
    )

    if child_object is not None and alternate_parent is not None:
        plans.append(
            _build_read_only_plan(
                trial_class="owned_parent_child_swap",
                changed_variable="parent",
                source_workflow=source_workflow,
                alternate_workflow=alternate_workflow,
                source_object=child_object,
                alternate_object=alternate_object,
                source_read=source_read,
                trial_session=source_workflow.session,
                parent_object_alias=alternate_parent.alias,
            )
        )
    elif require_all_classes:
        raise ValueError("owned_parent_child_relationship_required")

    if update_step is not None and alternate_read is not None:
        plans.append(
            _build_state_transition_plan(
                source_workflow=source_workflow,
                alternate_workflow=alternate_workflow,
                source_object=source_object,
                alternate_object=alternate_object,
                source_read=source_read,
                alternate_read=alternate_read,
                update_step=update_step,
            )
        )
    elif require_all_classes:
        if update_step is None:
            raise ValueError("demonstrated_reversible_update_required")
        raise ValueError("demonstrated_read_only_replay_required")

    return plans


def _require_plannable_workflows(model: ObservedWorkflowModel) -> None:
    if len(model.workflows) < 2:
        raise ValueError("two_demonstrated_workflows_required")
    if any(not workflow.baseline_stable for workflow in model.workflows):
        raise ValueError("stable_baseline_required")
    if any(workflow.role_rank is None for workflow in model.workflows):
        raise ValueError("role_rank_required")
    if len({workflow.session.account_alias for workflow in model.workflows}) < 2:
        raise ValueError("two_account_aliases_required")
    if len({workflow.role_rank for workflow in model.workflows}) < 2:
        raise ValueError("lower_role_relationship_required")
    if any(not workflow.rollback_ready for workflow in model.workflows):
        raise ValueError("rollback_ready_required")
    if any(
        not obj.reversible
        for workflow in model.workflows
        for obj in workflow.objects
    ):
        raise ValueError("reversible_objects_required")


def _workflow_step(workflow: ObservedWorkflow, action: str) -> WorkflowStep:
    step = next((step for step in workflow.steps if step.action == action), None)
    if step is None:
        raise ValueError(f"demonstrated_{action}_required")
    return step


def _planned_trial(
    *,
    trial_class: Literal[
        "cross_account_object_swap",
        "lower_role_replay",
        "unauthenticated_read_only_replay",
        "owned_parent_child_swap",
        "reversible_out_of_order_state_transition",
    ],
    phase: Literal[
        "baseline",
        "trial",
        "owner_control",
        "session_control",
        "repeat",
        "rollback",
    ],
    changed_variable: Literal["object", "role", "session", "parent", "state"],
    workflow: WorkflowStep,
    session: SessionAlias,
    observed_object: ObservedTestObject,
    requires_rollback: bool,
    parent_object_alias: str | None = None,
) -> PlannedDifferentialTrial:
    return PlannedDifferentialTrial(
        trial_class=trial_class,
        phase=phase,
        changed_variable=changed_variable,
        workflow=workflow,
        session=session,
        test_object=TestObjectAlias(
            alias=observed_object.alias,
            owner_alias=observed_object.owner_alias,
            test_owned=True,
            reversible=observed_object.reversible,
            state=observed_object.state,
        ),
        parent_object_alias=parent_object_alias,
        requires_rollback=requires_rollback,
        rollback_ready=requires_rollback,
    )


def _build_read_only_plan(
    *,
    trial_class: Literal[
        "cross_account_object_swap",
        "lower_role_replay",
        "unauthenticated_read_only_replay",
        "owned_parent_child_swap",
    ],
    changed_variable: Literal["object", "role", "session", "parent"],
    source_workflow: ObservedWorkflow,
    alternate_workflow: ObservedWorkflow,
    source_object: ObservedTestObject,
    alternate_object: ObservedTestObject,
    source_read: WorkflowStep,
    trial_session: SessionAlias,
    parent_object_alias: str | None = None,
) -> DifferentialPlan:
    return DifferentialPlan(
        trial_class=trial_class,
        baseline=_planned_trial(
            trial_class=trial_class,
            phase="baseline",
            changed_variable=changed_variable,
            workflow=source_read,
            session=source_workflow.session,
            observed_object=source_object,
            requires_rollback=False,
        ),
        trial=_planned_trial(
            trial_class=trial_class,
            phase="trial",
            changed_variable=changed_variable,
            workflow=source_read,
            session=trial_session,
            observed_object=source_object,
            requires_rollback=False,
            parent_object_alias=parent_object_alias,
        ),
        owner_control=_planned_trial(
            trial_class=trial_class,
            phase="owner_control",
            changed_variable=changed_variable,
            workflow=source_read,
            session=source_workflow.session,
            observed_object=source_object,
            requires_rollback=False,
        ),
        session_control=_planned_trial(
            trial_class=trial_class,
            phase="session_control",
            changed_variable=changed_variable,
            workflow=_workflow_step(alternate_workflow, "read_only_replay"),
            session=alternate_workflow.session,
            observed_object=alternate_object,
            requires_rollback=False,
        ),
        repeat=_planned_trial(
            trial_class=trial_class,
            phase="repeat",
            changed_variable=changed_variable,
            workflow=source_read,
            session=trial_session,
            observed_object=source_object,
            requires_rollback=False,
            parent_object_alias=parent_object_alias,
        ),
    )


def _build_state_transition_plan(
    *,
    source_workflow: ObservedWorkflow,
    alternate_workflow: ObservedWorkflow,
    source_object: ObservedTestObject,
    alternate_object: ObservedTestObject,
    source_read: WorkflowStep,
    alternate_read: WorkflowStep,
    update_step: WorkflowStep,
) -> DifferentialPlan:
    trial_class = "reversible_out_of_order_state_transition"
    return DifferentialPlan(
        trial_class=trial_class,
        baseline=_planned_trial(
            trial_class=trial_class,
            phase="baseline",
            changed_variable="state",
            workflow=source_read,
            session=source_workflow.session,
            observed_object=source_object,
            requires_rollback=True,
        ),
        trial=_planned_trial(
            trial_class=trial_class,
            phase="trial",
            changed_variable="state",
            workflow=update_step,
            session=source_workflow.session,
            observed_object=source_object,
            requires_rollback=True,
        ),
        owner_control=_planned_trial(
            trial_class=trial_class,
            phase="owner_control",
            changed_variable="state",
            workflow=source_read,
            session=source_workflow.session,
            observed_object=source_object,
            requires_rollback=True,
        ),
        session_control=_planned_trial(
            trial_class=trial_class,
            phase="session_control",
            changed_variable="state",
            workflow=alternate_read,
            session=alternate_workflow.session,
            observed_object=alternate_object,
            requires_rollback=True,
        ),
        repeat=_planned_trial(
            trial_class=trial_class,
            phase="repeat",
            changed_variable="state",
            workflow=update_step,
            session=source_workflow.session,
            observed_object=source_object,
            requires_rollback=True,
        ),
        rollback=_planned_trial(
            trial_class=trial_class,
            phase="rollback",
            changed_variable="state",
            workflow=update_step,
            session=source_workflow.session,
            observed_object=source_object,
            requires_rollback=True,
        ),
    )


class DifferentialTrial(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trial_class: Literal[
        "cross_account_object_swap",
        "lower_role_replay",
        "unauthenticated_read_only_replay",
        "owned_parent_child_swap",
        "reversible_out_of_order_state_transition",
    ] | None = None
    workflow: WorkflowStep
    session: SessionAlias
    test_object: TestObjectAlias
    generated_requests_in_workflow: int = Field(ge=0)
    active_generated_requests: int = Field(ge=0)
    elapsed_seconds: int = Field(ge=0)
    seconds_since_last_generated_request: int = Field(ge=0)
    requires_rollback: bool
    rollback_ready: bool


class BlackBoxStop(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=255)
    terminal: Literal[True] = True

    @field_validator("reason")
    @classmethod
    def require_allowlisted_reason(cls, value: str) -> str:
        if value not in ALLOWED_STOP_REASONS:
            raise ValueError("unsupported_black_box_stop_reason")
        return value


class TrialObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status_class: Literal["2xx", "3xx", "4xx", "5xx", "network_error"]
    response_schema_fingerprint: str = Field(min_length=1, max_length=255)
    timing_bucket: str = Field(min_length=1, max_length=64)
    canary_match: bool | None = None
    structural_identity_match: bool | None = None
    state_effect: bool | None = None
    intended_sharing: bool = False
    redacted: Literal[True]
    stop: BlackBoxStop | None = None

    @field_validator("response_schema_fingerprint")
    @classmethod
    def reject_secret_text(cls, value: str) -> str:
        if _has_secret_marker(value):
            raise ValueError("secret_like_fingerprint")
        if re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
            raise ValueError("sha256_fingerprint_required")
        return value

    @field_validator("timing_bucket")
    @classmethod
    def require_allowlisted_timing_bucket(cls, value: str) -> str:
        if value not in ALLOWED_TIMING_BUCKETS:
            raise ValueError("unsupported_timing_bucket")
        return value


class DifferentialEvidenceBundle(BaseModel):
    model_config = ConfigDict(extra="forbid")

    baseline_a: TrialObservation | None = None
    baseline_b: TrialObservation | None = None
    trial: TrialObservation
    owner_control: TrialObservation | None = None
    session_control: TrialObservation | None = None
    repeat: TrialObservation | None = None
    rollback: TrialObservation | None = None
    independent_repeat: bool
    rollback_required: bool


class DifferentialEvidenceDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal[
        "hypothesis",
        "observed",
        "reproduced",
        "review_ready",
        "refuted",
        "inconclusive",
    ]
    reason: str = Field(min_length=1, max_length=255)


def evaluate_differential_evidence(
    bundle: DifferentialEvidenceBundle,
) -> DifferentialEvidenceDecision:
    observations = [
        observation
        for observation in (
            bundle.baseline_a,
            bundle.baseline_b,
            bundle.trial,
            bundle.owner_control,
            bundle.session_control,
            bundle.repeat,
            bundle.rollback,
        )
        if observation is not None
    ]
    if any(observation.stop is not None for observation in observations):
        return DifferentialEvidenceDecision(
            status="inconclusive",
            reason="terminal_transport_stop",
        )
    if bundle.trial.intended_sharing:
        return DifferentialEvidenceDecision(
            status="refuted",
            reason="intended_sharing_observed",
        )
    if not _strong_signal(bundle.trial):
        return DifferentialEvidenceDecision(
            status="inconclusive",
            reason="status_only_signal_insufficient",
        )
    if not _stable_baselines(bundle.baseline_a, bundle.baseline_b):
        return DifferentialEvidenceDecision(
            status="inconclusive",
            reason="stable_dual_baseline_required",
        )
    if not _safe_control(bundle.owner_control) or not _safe_control(bundle.session_control):
        return DifferentialEvidenceDecision(
            status="hypothesis",
            reason="owner_and_session_controls_required",
        )
    if bundle.repeat is None:
        return DifferentialEvidenceDecision(
            status="observed",
            reason="independent_repeat_required",
        )
    if not bundle.independent_repeat or not _matches_trial(bundle.trial, bundle.repeat):
        return DifferentialEvidenceDecision(
            status="observed",
            reason="matching_independent_repeat_required",
        )
    if bundle.rollback_required:
        if bundle.rollback is None:
            return DifferentialEvidenceDecision(
                status="reproduced",
                reason="rollback_observation_required",
            )
        if not _successful_rollback(bundle.rollback):
            return DifferentialEvidenceDecision(
                status="inconclusive",
                reason="rollback_not_confirmed",
            )
    return DifferentialEvidenceDecision(
        status="review_ready",
        reason="bounded_differential_evidence_complete",
    )


def _strong_signal(observation: TrialObservation) -> bool:
    return any(
        (
            observation.canary_match is True,
            observation.structural_identity_match is True,
            observation.state_effect is True,
        )
    )


def _safe_control(observation: TrialObservation | None) -> bool:
    return (
        observation is not None
        and observation.status_class == "2xx"
        and not observation.intended_sharing
        and _strong_signal(observation)
    )


def _stable_baselines(
    baseline_a: TrialObservation | None,
    baseline_b: TrialObservation | None,
) -> bool:
    return (
        _safe_control(baseline_a)
        and _safe_control(baseline_b)
        and baseline_a.response_schema_fingerprint
        == baseline_b.response_schema_fingerprint
    )


def _matches_trial(
    trial: TrialObservation,
    repeat: TrialObservation,
) -> bool:
    return (
        repeat.status_class == "2xx"
        and _strong_signal(repeat)
        and repeat.response_schema_fingerprint == trial.response_schema_fingerprint
    )


def _successful_rollback(observation: TrialObservation) -> bool:
    return (
        observation.status_class == "2xx"
        and observation.stop is None
        and observation.state_effect is True
    )


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
    observed_workflows: ObservedWorkflowModel | None = None,
    runtime_registry: RuntimeSessionRegistry | None = None,
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
    if any(
        not _origin_matches_scope_asset(origin, rule.asset)
        for origin in lease.active_origins
    ):
        return _blocked_trial_reason("active_origin_not_scope_approved")
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
    unauthenticated_read_only_replay = (
        trial.trial_class == "unauthenticated_read_only_replay"
        and trial.session.account_alias == "unauthenticated"
        and trial.session.role_alias == "unauthenticated"
        and not trial.session.active
        and trial.workflow.action == "read_only_replay"
    )
    if not trial.session.active and not unauthenticated_read_only_replay:
        return _blocked_trial_reason("session_inactive")
    if (
        trial.session.account_alias not in lease.account_aliases
        and not unauthenticated_read_only_replay
    ):
        return _blocked_trial_reason("account_not_leased")
    if (
        trial.session.role_alias not in lease.role_aliases
        and not unauthenticated_read_only_replay
    ):
        return _blocked_trial_reason("role_not_leased")
    if not trial.test_object.test_owned:
        return _blocked_trial_reason("test_owned_object_required")
    if observed_workflows is None or runtime_registry is None:
        return _blocked_trial_reason("demonstrated_object_provenance_required")
    observed_object_matches = [
        (workflow, observed_object)
        for workflow in observed_workflows.workflows
        for observed_object in workflow.objects
        if observed_object.alias == trial.test_object.alias
    ]
    try:
        runtime_registry.object_id(trial.test_object.alias)
    except KeyError:
        return _blocked_trial_reason("demonstrated_object_provenance_required")
    if len(observed_object_matches) != 1:
        return _blocked_trial_reason("demonstrated_object_provenance_required")
    observed_workflow, observed_object = observed_object_matches[0]
    if (
        trial.test_object.owner_alias != observed_object.owner_alias
        or trial.test_object.state != observed_object.state
        or trial.test_object.reversible != observed_object.reversible
    ):
        return _blocked_trial_reason("object_provenance_mismatch")
    if trial.workflow not in observed_workflow.steps:
        return _blocked_trial_reason("demonstrated_workflow_step_required")
    try:
        session_handle = runtime_registry.session_handle(
            trial.session.account_alias
        )
    except KeyError:
        return _blocked_trial_reason("runtime_session_required")
    if session_handle is None:
        return _blocked_trial_reason("runtime_session_required")
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
