"""Typed, immutable authority contracts for the bounty Autopilot."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_validator,
    model_validator,
)


_SAFE_ID = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$", re.ASCII)
_SAFE_ALIAS = re.compile(r"^[a-z][a-z0-9_-]{0,31}$", re.ASCII)
_SAFE_OPERATOR = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$", re.ASCII)
_OPAQUE_HANDLE = re.compile(r"^hdl_[0-9a-f]{48}$", re.ASCII)
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)

# Public aliases used by the durable execution-plane contracts.  Keeping these
# bound to the same strict/frozen primitives avoids a second, weaker contract
# hierarchy as later phases are layered onto the Phase 1 authority model.
DIGEST_PATTERN = _SHA256
SCHEMA_VERSION = "bounty-autopilot-authorization/v1"

RiskTier = Literal["R0", "R1", "R2", "R3", "R4"]
AutomaticRiskTier = Literal["R0", "R1", "R2"]
PolicyMode = Literal["passive_only", "authorized_local_lab"]
NetworkProfile = Literal["none", "authorized_local_lab"]
MethodClass = Literal["passive", "read_only", "reversible_owned_account"]
ActionCategory = Literal[
    "passive_analysis",
    "browser_mapping",
    "owned_account_read",
    "two_owned_account_differential",
    "novel_active",
    "reversible_owned_account_write",
    "dos_resource_exhaustion",
    "credential_attack",
    "social_engineering",
    "destructive_irreversible_transaction",
    "persistence_malware",
    "scope_or_gate_bypass",
    "intentional_third_party_data_collection",
    "raw_secret_retention",
    "automatic_report_submission",
]
ProhibitedActionCategory = Literal[
    "dos_resource_exhaustion",
    "credential_attack",
    "social_engineering",
    "destructive_irreversible_transaction",
    "persistence_malware",
    "scope_or_gate_bypass",
    "intentional_third_party_data_collection",
    "raw_secret_retention",
    "automatic_report_submission",
]


class FrozenContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


StrictContract = FrozenContract

# A few execution-plane call sites use enum-style constants while the public
# wire contract intentionally remains a Literal.  Attributes preserve that
# ergonomic form without weakening strict string validation or serialization.
for _risk_tier in ("R0", "R1", "R2", "R3", "R4"):
    setattr(RiskTier, _risk_tier, _risk_tier)
setattr(PolicyMode, "PASSIVE_ONLY", "passive_only")
setattr(PolicyMode, "AUTHORIZED_LOCAL_LAB", "authorized_local_lab")


class AutopilotBudgets(FrozenContract):
    max_requests: int = Field(ge=1, le=50)
    max_concurrency: int = Field(ge=1, le=2)
    max_response_bytes: int = Field(ge=1, le=1_048_576)
    max_duration_seconds: int = Field(ge=1, le=300)
    max_account_operations: int = Field(ge=1, le=8)
    max_cost_microusd: int = Field(ge=1, le=5_000_000)


class ActiveHoursWindow(FrozenContract):
    days_utc: tuple[int, ...] = Field(min_length=1, max_length=7)
    start_minute_utc: int = Field(ge=0, le=1439)
    end_minute_utc: int = Field(ge=1, le=1440)

    @field_validator("days_utc")
    @classmethod
    def normalize_days(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if any(day < 0 or day > 6 for day in value):
            raise ValueError("utc_weekday_out_of_range")
        if len(set(value)) != len(value):
            raise ValueError("duplicate_utc_weekday")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def require_forward_window(self) -> ActiveHoursWindow:
        if self.start_minute_utc >= self.end_minute_utc:
            raise ValueError("active_hours_window_must_not_cross_midnight")
        return self


class RecipeRef(FrozenContract):
    recipe_id: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=5, max_length=32)
    definition_digest: str = Field(min_length=71, max_length=71)

    @field_validator("recipe_id")
    @classmethod
    def require_safe_recipe_id(cls, value: str) -> str:
        return _require_match(value, _SAFE_ID, "safe_recipe_id_required")

    @field_validator("version")
    @classmethod
    def require_semver(cls, value: str) -> str:
        return _require_match(value, _SEMVER, "semantic_recipe_version_required")

    @field_validator("definition_digest")
    @classmethod
    def require_digest(cls, value: str) -> str:
        return _require_match(value, _SHA256, "sha256_digest_required")


class MutationInventory(FrozenContract):
    network_access: bool
    browser_automation: bool
    reads_owned_account_data: bool
    two_owned_account_differential: bool
    state_change: bool
    reversible: bool
    external_side_effect: bool
    prohibited_categories: tuple[ProhibitedActionCategory, ...] = ()

    @field_validator("prohibited_categories")
    @classmethod
    def normalize_prohibited_categories(
        cls, value: tuple[ProhibitedActionCategory, ...]
    ) -> tuple[ProhibitedActionCategory, ...]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate_prohibited_category")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def require_consistent_inventory(self) -> MutationInventory:
        if self.browser_automation and not self.network_access:
            raise ValueError("browser_automation_requires_network")
        if self.two_owned_account_differential and (
            not self.network_access or not self.reads_owned_account_data
        ):
            raise ValueError("two_account_differential_inventory_invalid")
        if self.reversible and not self.state_change:
            raise ValueError("reversible_requires_state_change")
        if self.external_side_effect and not self.state_change:
            raise ValueError("external_side_effect_requires_state_change")
        if (
            self.state_change
            and not self.reversible
            and "destructive_irreversible_transaction"
            not in self.prohibited_categories
        ):
            raise ValueError("irreversible_state_change_must_be_r4")
        return self


class VersionedRecipe(FrozenContract):
    schema_version: Literal["bounty-autopilot-recipe/v1"] = (
        "bounty-autopilot-recipe/v1"
    )
    recipe_id: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=5, max_length=32)
    title: str = Field(min_length=1, max_length=160)
    validation_type: str = Field(min_length=1, max_length=128)
    risk_floor: AutomaticRiskTier
    policy_modes: tuple[PolicyMode, ...] = Field(min_length=1, max_length=2)
    network_profile: NetworkProfile
    method_classes: tuple[MethodClass, ...] = Field(min_length=1, max_length=3)
    required_account_aliases: int = Field(ge=0, le=2)
    max_budgets: AutopilotBudgets
    mutation_inventory: MutationInventory

    @field_validator("recipe_id", "validation_type")
    @classmethod
    def require_safe_identifier(cls, value: str) -> str:
        return _require_match(value, _SAFE_ID, "safe_recipe_identifier_required")

    @field_validator("version")
    @classmethod
    def require_recipe_semver(cls, value: str) -> str:
        return _require_match(value, _SEMVER, "semantic_recipe_version_required")

    @field_validator("policy_modes", "method_classes")
    @classmethod
    def normalize_literal_sets(cls, value: tuple[Any, ...]) -> tuple[Any, ...]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate_recipe_constraint")
        return tuple(sorted(value))

    @model_validator(mode="after")
    def require_bounded_recipe_shape(self) -> VersionedRecipe:
        inventory = self.mutation_inventory
        if self.risk_floor == "R0":
            if inventory.network_access or self.network_profile != "none":
                raise ValueError("r0_recipe_must_be_offline")
            if self.method_classes != ("passive",):
                raise ValueError("r0_recipe_must_be_passive")
            if self.required_account_aliases != 0:
                raise ValueError("r0_recipe_cannot_require_accounts")
        else:
            if (
                not inventory.network_access
                or self.network_profile != "authorized_local_lab"
                or self.policy_modes != ("authorized_local_lab",)
            ):
                raise ValueError("active_recipe_must_be_lab_only")
        if self.risk_floor == "R2" and (
            not inventory.two_owned_account_differential
            or self.required_account_aliases != 2
        ):
            raise ValueError("r2_recipe_requires_two_owned_accounts")
        return self

    @computed_field
    @property
    def definition_digest(self) -> str:
        return canonical_sha256(self)

    @property
    def ref(self) -> RecipeRef:
        return RecipeRef(
            recipe_id=self.recipe_id,
            version=self.version,
            definition_digest=self.definition_digest,
        )


class CampaignAuthorization(FrozenContract):
    schema_version: Literal["bounty-autopilot-authorization/v1"] = (
        "bounty-autopilot-authorization/v1"
    )
    campaign_id: str = Field(min_length=1, max_length=128)
    scope_snapshot_id: str = Field(min_length=1, max_length=128)
    scope_review_state: Literal["approved"]
    scope_snapshot_digest: str = Field(min_length=71, max_length=71)
    policy_digest: str = Field(min_length=71, max_length=71)
    asset_ids: tuple[str, ...] = Field(min_length=1, max_length=50)
    account_aliases: tuple[str, ...] = Field(min_length=2, max_length=8)
    recipe_refs: tuple[RecipeRef, ...] = Field(min_length=1, max_length=20)
    max_automatic_risk: AutomaticRiskTier
    policy_mode: PolicyMode
    network_profile: NetworkProfile
    allowed_method_classes: tuple[MethodClass, ...] = Field(
        min_length=1, max_length=3
    )
    active_hours_utc: tuple[ActiveHoursWindow, ...] = Field(
        min_length=1, max_length=49
    )
    budgets: AutopilotBudgets
    issued_at: datetime
    expires_at: datetime
    operator_identity: str = Field(min_length=1, max_length=128)

    @field_validator("campaign_id", "scope_snapshot_id")
    @classmethod
    def require_safe_contract_id(cls, value: str) -> str:
        return _require_match(value, _SAFE_ID, "safe_contract_id_required")

    @field_validator("scope_snapshot_digest", "policy_digest")
    @classmethod
    def require_authority_digest(cls, value: str) -> str:
        return _require_match(value, _SHA256, "sha256_digest_required")

    @field_validator("asset_ids")
    @classmethod
    def normalize_asset_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for asset_id in value:
            _require_match(asset_id, _SAFE_ID, "exact_asset_id_required")
        return _normalize_unique(value, "duplicate_asset_id")

    @field_validator("account_aliases")
    @classmethod
    def normalize_account_aliases(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for alias in value:
            _require_match(alias, _SAFE_ALIAS, "safe_account_alias_required")
        return _normalize_unique(value, "duplicate_account_alias")

    @field_validator("recipe_refs")
    @classmethod
    def normalize_recipe_refs(
        cls, value: tuple[RecipeRef, ...]
    ) -> tuple[RecipeRef, ...]:
        keys = [
            (ref.recipe_id, ref.version, ref.definition_digest) for ref in value
        ]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate_recipe_ref")
        return tuple(
            sorted(
                value,
                key=lambda ref: (
                    ref.recipe_id,
                    ref.version,
                    ref.definition_digest,
                ),
            )
        )

    @field_validator("allowed_method_classes")
    @classmethod
    def normalize_method_classes(
        cls, value: tuple[MethodClass, ...]
    ) -> tuple[MethodClass, ...]:
        return _normalize_unique(value, "duplicate_method_class")

    @field_validator("active_hours_utc")
    @classmethod
    def normalize_active_hours(
        cls, value: tuple[ActiveHoursWindow, ...]
    ) -> tuple[ActiveHoursWindow, ...]:
        return tuple(
            sorted(
                value,
                key=lambda window: (
                    window.days_utc,
                    window.start_minute_utc,
                    window.end_minute_utc,
                ),
            )
        )

    @field_validator("issued_at", "expires_at")
    @classmethod
    def normalize_datetime(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timezone_aware_datetime_required")
        return value.astimezone(timezone.utc)

    @field_validator("operator_identity")
    @classmethod
    def require_safe_operator_identity(cls, value: str) -> str:
        return _require_match(
            value, _SAFE_OPERATOR, "safe_operator_identity_required"
        )

    @model_validator(mode="after")
    def require_valid_authority(self) -> CampaignAuthorization:
        if self.issued_at >= self.expires_at:
            raise ValueError("authorization_expiry_must_follow_issue")
        _require_non_overlapping_windows(self.active_hours_utc)

        from app.bounty_autopilot.recipes import default_recipe_registry

        registry = default_recipe_registry()
        for ref in self.recipe_refs:
            recipe = registry.get(ref.recipe_id, ref.version)
            if recipe is None or recipe.definition_digest != ref.definition_digest:
                raise ValueError("registered_recipe_ref_required")
        return self

    @computed_field
    @property
    def authorization_digest(self) -> str:
        return campaign_authorization_digest(self)


class AccountAliasProjection(FrozenContract):
    account_alias: str = Field(min_length=1, max_length=32)
    role_label: Literal["owned"] = "owned"
    vault_generation: int = Field(ge=1)

    @field_validator("account_alias")
    @classmethod
    def require_safe_alias(cls, value: str) -> str:
        return _require_match(value, _SAFE_ALIAS, "safe_account_alias_required")


class SessionHandleProjection(FrozenContract):
    handle_id: str = Field(min_length=52, max_length=52)
    campaign_id: str = Field(min_length=1, max_length=128)
    account_alias: str = Field(min_length=1, max_length=32)
    role_label: Literal["owned"] = "owned"
    login_state: Literal["unknown", "logged_out", "logged_in", "expired", "locked"]
    generation: int = Field(ge=1)
    pod_id: str = Field(min_length=1, max_length=128)
    issued_at: datetime
    expires_at: datetime
    revoked: bool = False
    raw_secret_present: Literal[False] = False

    @field_validator("handle_id")
    @classmethod
    def require_opaque_handle(cls, value: str) -> str:
        return _require_match(value, _OPAQUE_HANDLE, "opaque_session_handle_required")

    @field_validator("campaign_id", "pod_id")
    @classmethod
    def require_safe_binding_id(cls, value: str) -> str:
        return _require_match(value, _SAFE_ID, "safe_session_binding_required")

    @field_validator("account_alias")
    @classmethod
    def require_session_alias(cls, value: str) -> str:
        return _require_match(value, _SAFE_ALIAS, "safe_account_alias_required")

    @field_validator("issued_at", "expires_at")
    @classmethod
    def normalize_session_datetime(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timezone_aware_datetime_required")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def require_bounded_lifetime(self) -> SessionHandleProjection:
        lifetime = (self.expires_at - self.issued_at).total_seconds()
        if lifetime <= 0 or lifetime > 3600:
            raise ValueError("session_lifetime_out_of_bounds")
        if self.revoked and self.login_state not in {"expired", "logged_out", "locked"}:
            raise ValueError("revoked_session_must_not_be_logged_in")
        return self


class RecipeSelection(FrozenContract):
    schema_version: Literal["bounty-autopilot-selection/v1"] = (
        "bounty-autopilot-selection/v1"
    )
    recipe_id: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=5, max_length=32)
    target_asset_id: str = Field(min_length=1, max_length=128)
    method_class: MethodClass
    account_aliases: tuple[str, ...] = Field(max_length=2)
    requested_budgets: AutopilotBudgets
    client_risk_hint: RiskTier | None = None
    model_risk_hint: RiskTier | None = None
    tool_risk_hint: RiskTier | None = None
    action_categories: tuple[ActionCategory, ...] = Field(max_length=12)

    @field_validator("recipe_id", "target_asset_id")
    @classmethod
    def require_safe_selection_id(cls, value: str) -> str:
        return _require_match(value, _SAFE_ID, "safe_selection_id_required")

    @field_validator("version")
    @classmethod
    def require_selection_semver(cls, value: str) -> str:
        return _require_match(value, _SEMVER, "semantic_recipe_version_required")

    @field_validator("account_aliases")
    @classmethod
    def normalize_selected_aliases(
        cls, value: tuple[str, ...]
    ) -> tuple[str, ...]:
        for alias in value:
            _require_match(alias, _SAFE_ALIAS, "safe_account_alias_required")
        return _normalize_unique(value, "duplicate_account_alias")

    @field_validator("action_categories")
    @classmethod
    def normalize_action_categories(
        cls, value: tuple[ActionCategory, ...]
    ) -> tuple[ActionCategory, ...]:
        return _normalize_unique(value, "duplicate_action_category")


class AuthorizedRiskDecision(FrozenContract):
    status: Literal["authorized"] = "authorized"
    risk_tier: Literal["R0", "R1", "R2"]
    reason: str
    eligible_for_plan: Literal[True] = True
    execution_authorized: Literal[False] = False
    exact_approval_required: Literal[False] = False
    recipe_ref: RecipeRef | None = None


class DeniedRiskDecision(FrozenContract):
    status: Literal["denied"] = "denied"
    risk_tier: RiskTier
    reason: str
    eligible_for_plan: Literal[False] = False
    execution_authorized: Literal[False] = False
    exact_approval_required: Literal[False] = False
    recipe_ref: RecipeRef | None = None


class PolicyBlockedRiskDecision(FrozenContract):
    status: Literal["policy_mode_blocks_active_execution"] = (
        "policy_mode_blocks_active_execution"
    )
    risk_tier: Literal["R1", "R2"]
    reason: Literal["policy_mode_blocks_active_execution"] = (
        "policy_mode_blocks_active_execution"
    )
    eligible_for_plan: Literal[False] = False
    execution_authorized: Literal[False] = False
    exact_approval_required: Literal[False] = False
    recipe_ref: RecipeRef | None = None


class AwaitingExactApprovalRiskDecision(FrozenContract):
    status: Literal["awaiting_exact_approval"] = "awaiting_exact_approval"
    risk_tier: Literal["R3"] = "R3"
    reason: Literal["awaiting_exact_approval"] = "awaiting_exact_approval"
    eligible_for_plan: Literal[False] = False
    execution_authorized: Literal[False] = False
    exact_approval_required: Literal[True] = True
    recipe_ref: RecipeRef | None = None


class ProhibitedRiskDecision(FrozenContract):
    status: Literal["prohibited"] = "prohibited"
    risk_tier: Literal["R4"] = "R4"
    reason: str
    eligible_for_plan: Literal[False] = False
    execution_authorized: Literal[False] = False
    exact_approval_required: Literal[False] = False
    exact_approval_allowed: Literal[False] = False
    recipe_ref: RecipeRef | None = None


RiskDecision = Annotated[
    AuthorizedRiskDecision
    | DeniedRiskDecision
    | PolicyBlockedRiskDecision
    | AwaitingExactApprovalRiskDecision
    | ProhibitedRiskDecision,
    Field(discriminator="status"),
]


def canonical_json_bytes(value: BaseModel | dict[str, Any]) -> bytes:
    normalized = _canonical_value(value)
    return json.dumps(
        normalized,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_sha256(value: BaseModel | dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def campaign_authorization_digest(
    authorization: CampaignAuthorization,
) -> str:
    return canonical_sha256(authorization)


def campaign_authorization_payload(
    authorization: CampaignAuthorization,
) -> dict[str, Any]:
    payload = json.loads(canonical_json_bytes(authorization))
    if not isinstance(payload, dict):
        raise TypeError("campaign_authorization_payload_must_be_an_object")
    return payload


def campaign_authorization_from_payload(
    payload: dict[str, Any],
) -> CampaignAuthorization:
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    return CampaignAuthorization.model_validate_json(encoded)


def _canonical_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        computed_fields = set(type(value).model_computed_fields)
        value = value.model_dump(
            mode="python",
            exclude_none=False,
            exclude=computed_fields,
        )
    if isinstance(value, dict):
        return {key: _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_canonical_value(item) for item in value]
    if isinstance(value, datetime):
        normalized = value.astimezone(timezone.utc)
        return normalized.isoformat(timespec="microseconds").replace(
            "+00:00", "Z"
        )
    return value


def _require_match(value: str, pattern: re.Pattern[str], reason: str) -> str:
    if pattern.fullmatch(value) is None:
        raise ValueError(reason)
    return value


def _normalize_unique(value: tuple[Any, ...], reason: str) -> tuple[Any, ...]:
    if len(set(value)) != len(value):
        raise ValueError(reason)
    return tuple(sorted(value))


def _require_non_overlapping_windows(
    windows: tuple[ActiveHoursWindow, ...],
) -> None:
    by_day: dict[int, list[tuple[int, int]]] = {}
    for window in windows:
        for day in window.days_utc:
            by_day.setdefault(day, []).append(
                (window.start_minute_utc, window.end_minute_utc)
            )
    for ranges in by_day.values():
        ordered = sorted(ranges)
        if any(
            current_start < previous_end
            for (_, previous_end), (current_start, _) in zip(
                ordered, ordered[1:]
            )
        ):
            raise ValueError("overlapping_active_hours")


__all__ = [
    "ActionCategory",
    "AccountAliasProjection",
    "ActiveHoursWindow",
    "AutopilotBudgets",
    "AuthorizedRiskDecision",
    "AwaitingExactApprovalRiskDecision",
    "CampaignAuthorization",
    "DIGEST_PATTERN",
    "DeniedRiskDecision",
    "MethodClass",
    "MutationInventory",
    "NetworkProfile",
    "PolicyBlockedRiskDecision",
    "PolicyMode",
    "ProhibitedActionCategory",
    "ProhibitedRiskDecision",
    "RecipeRef",
    "RecipeSelection",
    "RiskDecision",
    "RiskTier",
    "SCHEMA_VERSION",
    "StrictContract",
    "SessionHandleProjection",
    "VersionedRecipe",
    "campaign_authorization_from_payload",
    "campaign_authorization_digest",
    "campaign_authorization_payload",
    "canonical_json_bytes",
    "canonical_sha256",
]
