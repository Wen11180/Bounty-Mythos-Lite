"""Pure typed contracts for Bounty Autopilot authority and risk decisions."""

from __future__ import annotations

import json
import re
from datetime import datetime
from enum import Enum
from hashlib import sha256
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)


SCHEMA_VERSION = "bounty_autopilot_authorization_v1"
DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
RECIPE_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,63}$", re.ASCII)
ACCOUNT_ALIAS_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,63}$", re.ASCII)
SAFE_ID_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_:-]{0,127}$", re.ASCII)

SafeAlias = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,63}$", min_length=1, max_length=64),
]
Sha256Digest = Annotated[
    str,
    StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$"),
]


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RiskTier(str, Enum):
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"
    R4 = "R4"


class PolicyMode(str, Enum):
    """Server policy mode that bounds active automation."""

    AUTHORIZED_LOCAL_LAB = "authorized_local_lab"
    # Public-target active automation is intentionally absent under current policy.
    RESEARCH_PASSIVE_ONLY = "research_passive_only"


class RiskDecisionStatus(str, Enum):
    ALLOWED = "allowed"
    AWAITING_EXACT_APPROVAL = "awaiting_exact_approval"
    PROHIBITED = "prohibited"
    POLICY_MODE_BLOCKS_ACTIVE_EXECUTION = "policy_mode_blocks_active_execution"
    REJECTED = "rejected"


class RecipeRef(StrictContract):
    recipe_id: str = Field(min_length=1, max_length=64)
    version: str = Field(min_length=1, max_length=32)

    @field_validator("recipe_id")
    @classmethod
    def require_safe_recipe_id(cls, value: str) -> str:
        if RECIPE_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("safe_recipe_id_required")
        return value

    @field_validator("version")
    @classmethod
    def require_safe_version(cls, value: str) -> str:
        if re.fullmatch(r"^[0-9]+(\.[0-9]+){0,2}$", value) is None:
            raise ValueError("safe_recipe_version_required")
        return value


class MutationInventory(StrictContract):
    """Declared mutation surface for a versioned recipe."""

    methods: tuple[str, ...] = Field(min_length=1, max_length=16)
    mutates_state: bool
    reversible: bool
    requires_owned_accounts: bool
    third_party_data_allowed: Literal[False] = False
    raw_secret_retention_allowed: Literal[False] = False
    automatic_report_submission_allowed: Literal[False] = False

    @field_validator("methods")
    @classmethod
    def require_known_methods(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        allowed = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
        normalized: list[str] = []
        for value in values:
            method = value.upper()
            if method not in allowed:
                raise ValueError("unknown_http_method")
            normalized.append(method)
        return tuple(normalized)


class AuthorizationBudget(StrictContract):
    """Hard ceilings; unbounded budgets are rejected by validation."""

    max_requests: int = Field(ge=1, le=10_000)
    max_concurrent_requests: int = Field(ge=1, le=32)
    max_response_bytes: int = Field(ge=1, le=5_000_000)
    max_duration_seconds: int = Field(ge=1, le=86_400)
    max_accounts: int = Field(ge=0, le=16)
    max_cost_units: int = Field(ge=1, le=1_000_000)


class VersionedRecipe(StrictContract):
    """Code-owned recipe definition. Runtime selection is by ID/version only."""

    recipe_id: str = Field(min_length=1, max_length=64)
    version: str = Field(min_length=1, max_length=32)
    risk_tier: RiskTier
    policy_modes: tuple[PolicyMode, ...] = Field(min_length=1, max_length=4)
    network_profile: Literal["none", "lab_loopback", "scope_enforced"]
    mutation_inventory: MutationInventory
    required_account_aliases: tuple[SafeAlias, ...] = Field(default_factory=tuple, max_length=8)
    allowed_method_classes: tuple[str, ...] = Field(min_length=1, max_length=16)
    description: str = Field(min_length=1, max_length=256)

    @field_validator("recipe_id")
    @classmethod
    def require_safe_recipe_id(cls, value: str) -> str:
        if RECIPE_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("safe_recipe_id_required")
        return value

    @field_validator("version")
    @classmethod
    def require_safe_version(cls, value: str) -> str:
        if re.fullmatch(r"^[0-9]+(\.[0-9]+){0,2}$", value) is None:
            raise ValueError("safe_recipe_version_required")
        return value

    @model_validator(mode="after")
    def enforce_tier_network_rules(self) -> VersionedRecipe:
        if self.risk_tier is RiskTier.R0 and self.network_profile != "none":
            raise ValueError("r0_requires_no_network_profile")
        if self.risk_tier in {RiskTier.R1, RiskTier.R2} and self.network_profile == "none":
            raise ValueError("active_recipe_requires_network_profile")
        if self.risk_tier is RiskTier.R4:
            raise ValueError("r4_recipe_unrepresentable")
        if (
            self.risk_tier in {RiskTier.R1, RiskTier.R2}
            and PolicyMode.AUTHORIZED_LOCAL_LAB not in self.policy_modes
        ):
            raise ValueError("active_recipe_requires_local_lab_policy_mode")
        return self

    def as_ref(self) -> RecipeRef:
        return RecipeRef(recipe_id=self.recipe_id, version=self.version)


class CampaignAuthorizationCreate(StrictContract):
    """Operator-issued authorization inputs before server digest binding."""

    campaign_id: str = Field(min_length=1, max_length=128)
    scope_snapshot_id: str = Field(min_length=1, max_length=128)
    scope_snapshot_digest: Sha256Digest
    policy_digest: Sha256Digest
    asset_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    account_aliases: tuple[SafeAlias, ...] = Field(default_factory=tuple, max_length=16)
    recipe_refs: tuple[RecipeRef, ...] = Field(min_length=1, max_length=32)
    risk_ceiling: RiskTier
    active_hours_utc: tuple[int, ...] = Field(min_length=1, max_length=24)
    budget: AuthorizationBudget
    expires_at: datetime
    operator_id: str = Field(min_length=1, max_length=128)
    policy_mode: PolicyMode = PolicyMode.AUTHORIZED_LOCAL_LAB

    @field_validator("campaign_id", "scope_snapshot_id", "operator_id")
    @classmethod
    def require_safe_ids(cls, value: str) -> str:
        if SAFE_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("safe_identifier_required")
        return value

    @field_validator("asset_ids")
    @classmethod
    def require_unique_assets(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if not values:
            raise ValueError("asset_ids_required")
        if len(set(values)) != len(values):
            raise ValueError("duplicate_asset_ids")
        for asset_id in values:
            if SAFE_ID_PATTERN.fullmatch(asset_id) is None:
                raise ValueError("safe_asset_id_required")
        return values

    @field_validator("account_aliases")
    @classmethod
    def require_unique_aliases(cls, values: tuple[SafeAlias, ...]) -> tuple[SafeAlias, ...]:
        if len(set(values)) != len(values):
            raise ValueError("duplicate_account_aliases")
        return values

    @field_validator("recipe_refs")
    @classmethod
    def require_unique_recipe_refs(cls, values: tuple[RecipeRef, ...]) -> tuple[RecipeRef, ...]:
        keys = {(item.recipe_id, item.version) for item in values}
        if len(keys) != len(values):
            raise ValueError("duplicate_recipe_refs")
        return values

    @field_validator("active_hours_utc")
    @classmethod
    def require_valid_hours(cls, values: tuple[int, ...]) -> tuple[int, ...]:
        if not values:
            raise ValueError("active_hours_required")
        if any(hour < 0 or hour > 23 for hour in values):
            raise ValueError("active_hour_out_of_range")
        if len(set(values)) != len(values):
            raise ValueError("duplicate_active_hours")
        return tuple(sorted(values))

    @model_validator(mode="after")
    def enforce_ceiling_and_mode(self) -> CampaignAuthorizationCreate:
        if self.risk_ceiling is RiskTier.R4:
            raise ValueError("risk_ceiling_cannot_be_r4")
        if len(self.account_aliases) > self.budget.max_accounts:
            raise ValueError("account_budget_exceeded")
        if self.policy_mode is not PolicyMode.AUTHORIZED_LOCAL_LAB:
            if self.risk_ceiling in {RiskTier.R1, RiskTier.R2, RiskTier.R3}:
                raise ValueError("policy_mode_blocks_active_risk_ceiling")
        return self


class CampaignAuthorization(StrictContract):
    """Immutable, digest-bound server-side authorization contract."""

    schema_version: Literal["bounty_autopilot_authorization_v1"] = SCHEMA_VERSION
    campaign_id: str = Field(min_length=1, max_length=128)
    scope_snapshot_id: str = Field(min_length=1, max_length=128)
    scope_snapshot_digest: Sha256Digest
    policy_digest: Sha256Digest
    asset_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    account_aliases: tuple[SafeAlias, ...] = Field(default_factory=tuple, max_length=16)
    recipe_refs: tuple[RecipeRef, ...] = Field(min_length=1, max_length=32)
    risk_ceiling: RiskTier
    active_hours_utc: tuple[int, ...] = Field(min_length=1, max_length=24)
    budget: AuthorizationBudget
    expires_at: datetime
    operator_id: str = Field(min_length=1, max_length=128)
    policy_mode: PolicyMode
    authorization_digest: Sha256Digest

    @model_validator(mode="after")
    def enforce_account_budget(self) -> CampaignAuthorization:
        if len(self.account_aliases) > self.budget.max_accounts:
            raise ValueError("account_budget_exceeded")
        return self

    @classmethod
    def from_create(cls, create: CampaignAuthorizationCreate) -> CampaignAuthorization:
        payload = canonicalize_authorization_payload(create)
        digest = compute_authorization_digest(payload)
        return cls(
            campaign_id=create.campaign_id,
            scope_snapshot_id=create.scope_snapshot_id,
            scope_snapshot_digest=create.scope_snapshot_digest,
            policy_digest=create.policy_digest,
            asset_ids=tuple(sorted(create.asset_ids)),
            account_aliases=tuple(sorted(create.account_aliases)),
            recipe_refs=tuple(
                sorted(create.recipe_refs, key=lambda item: (item.recipe_id, item.version))
            ),
            risk_ceiling=create.risk_ceiling,
            active_hours_utc=tuple(sorted(create.active_hours_utc)),
            budget=create.budget,
            expires_at=create.expires_at,
            operator_id=create.operator_id,
            policy_mode=create.policy_mode,
            authorization_digest=digest,
        )

    def permits_recipe(self, recipe_ref: RecipeRef) -> bool:
        return any(
            item.recipe_id == recipe_ref.recipe_id and item.version == recipe_ref.version
            for item in self.recipe_refs
        )


class RiskDecision(StrictContract):
    """Monotonic risk classification result. R4 cannot become allowed."""

    status: RiskDecisionStatus
    risk_tier: RiskTier
    reason: str = Field(min_length=1, max_length=128)
    recipe_ref: RecipeRef | None = None
    policy_mode: PolicyMode | None = None
    requires_exact_approval: bool = False
    allowed_to_execute: bool = False
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False

    @model_validator(mode="after")
    def enforce_status_invariants(self) -> RiskDecision:
        if self.risk_tier is RiskTier.R4 and self.status is not RiskDecisionStatus.PROHIBITED:
            raise ValueError("r4_must_be_prohibited")
        if self.risk_tier is RiskTier.R4 and self.allowed_to_execute:
            raise ValueError("r4_cannot_execute")
        if self.status is RiskDecisionStatus.PROHIBITED and self.allowed_to_execute:
            raise ValueError("prohibited_cannot_execute")
        if (
            self.status is RiskDecisionStatus.AWAITING_EXACT_APPROVAL
            and self.allowed_to_execute
        ):
            raise ValueError("awaiting_approval_cannot_execute")
        if (
            self.status is RiskDecisionStatus.POLICY_MODE_BLOCKS_ACTIVE_EXECUTION
            and self.allowed_to_execute
        ):
            raise ValueError("policy_blocked_cannot_execute")
        if self.status is RiskDecisionStatus.ALLOWED and not self.allowed_to_execute:
            raise ValueError("allowed_requires_execute_true")
        if self.status is RiskDecisionStatus.ALLOWED and self.risk_tier is RiskTier.R3:
            raise ValueError("r3_cannot_be_allowed_from_campaign_authorization")
        return self


def _json_ready(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _json_ready(value.model_dump(mode="json"))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _json_ready(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    return value


def canonicalize_authorization_payload(
    create: CampaignAuthorizationCreate | CampaignAuthorization | dict[str, Any],
) -> dict[str, Any]:
    """Return a stable dict used for authorization digests."""

    if isinstance(create, CampaignAuthorization):
        data = create.model_dump(mode="json", exclude={"authorization_digest"})
    elif isinstance(create, CampaignAuthorizationCreate):
        data = create.model_dump(mode="json")
    else:
        data = dict(create)

    payload = {
        "schema_version": SCHEMA_VERSION,
        "campaign_id": data["campaign_id"],
        "scope_snapshot_id": data["scope_snapshot_id"],
        "scope_snapshot_digest": data["scope_snapshot_digest"],
        "policy_digest": data["policy_digest"],
        "asset_ids": sorted(data["asset_ids"]),
        "account_aliases": sorted(data["account_aliases"]),
        "recipe_refs": sorted(
            data["recipe_refs"],
            key=lambda item: (item["recipe_id"], item["version"]),
        ),
        "risk_ceiling": data["risk_ceiling"],
        "active_hours_utc": sorted(data["active_hours_utc"]),
        "budget": data["budget"],
        "expires_at": data["expires_at"],
        "operator_id": data["operator_id"],
        "policy_mode": data["policy_mode"],
    }
    return _json_ready(payload)


def compute_authorization_digest(payload: dict[str, Any]) -> str:
    serialized = json.dumps(
        _json_ready(payload),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return f"sha256:{sha256(serialized.encode('utf-8')).hexdigest()}"


__all__ = [
    "ACCOUNT_ALIAS_PATTERN",
    "AuthorizationBudget",
    "CampaignAuthorization",
    "CampaignAuthorizationCreate",
    "DIGEST_PATTERN",
    "MutationInventory",
    "PolicyMode",
    "RECIPE_ID_PATTERN",
    "RecipeRef",
    "RiskDecision",
    "RiskDecisionStatus",
    "RiskTier",
    "SCHEMA_VERSION",
    "SafeAlias",
    "Sha256Digest",
    "StrictContract",
    "VersionedRecipe",
    "canonicalize_authorization_payload",
    "compute_authorization_digest",
]
