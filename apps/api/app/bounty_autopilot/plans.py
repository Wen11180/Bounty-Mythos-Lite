"""Immutable validation plans for Bounty Autopilot."""

from __future__ import annotations

import json
from enum import Enum
from hashlib import sha256
from typing import Any, Literal
from urllib.parse import unquote

from pydantic import Field, field_validator, model_validator

from app.bounty_autopilot.contracts import (
    DIGEST_PATTERN,
    MutationInventory,
    RecipeRef,
    RiskTier,
    StrictContract,
)


class PlanStatus(str, Enum):
    DRAFT = "draft"
    READY = "ready"
    AWAITING_R3 = "awaiting_r3"
    ISSUED = "issued"
    EXPIRED = "expired"
    REVOKED = "revoked"
    COMPLETED = "completed"


class ValidationPlan(StrictContract):
    """Canonical immutable plan. Any bound field change changes plan_digest."""

    plan_id: str = Field(min_length=1, max_length=128)
    campaign_id: str = Field(min_length=1, max_length=128)
    authorization_digest: str
    scope_snapshot_digest: str
    asset_id: str = Field(min_length=1, max_length=128)
    destination_scheme: Literal["http", "https"]
    destination_host: str = Field(min_length=1, max_length=253)
    destination_port: int = Field(ge=1, le=65535)
    destination_path: str = Field(min_length=1, max_length=1024)
    branch_id: str = Field(min_length=1, max_length=128)
    hypothesis_id: str | None = None
    account_aliases: tuple[str, ...] = Field(default_factory=tuple, max_length=8)
    canary_token_id: str | None = None
    risk_tier: RiskTier
    recipe_ref: RecipeRef
    methods: tuple[str, ...] = Field(min_length=1, max_length=8)
    mutation_inventory: MutationInventory
    max_requests: int = Field(ge=1, le=1000)
    max_response_bytes: int = Field(ge=1, le=5_000_000)
    max_duration_seconds: int = Field(ge=1, le=86_400)
    cost_units: int = Field(ge=1, le=1_000_000)
    rollback_plan: str = Field(min_length=1, max_length=256)
    stop_conditions: tuple[str, ...] = Field(min_length=1, max_length=16)
    tool_profile: str = Field(min_length=1, max_length=64)
    container_profile: str = Field(min_length=1, max_length=64)
    r3_approval_id: str | None = None
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False
    plan_digest: str

    @field_validator("authorization_digest", "scope_snapshot_digest", "plan_digest")
    @classmethod
    def require_digest(cls, value: str) -> str:
        if DIGEST_PATTERN.fullmatch(value) is None:
            raise ValueError("digest_required")
        return value

    @field_validator("methods")
    @classmethod
    def normalize_methods(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        allowed = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
        out = []
        for value in values:
            method = value.upper()
            if method not in allowed:
                raise ValueError("unknown_http_method")
            out.append(method)
        return tuple(out)

    @field_validator("destination_path")
    @classmethod
    def reject_path_escape_segments(cls, value: str) -> str:
        if not value.startswith("/") or any(
            char in value for char in ("\\", "?", "#", "\x00", "%")
        ):
            raise ValueError("invalid_destination_path")
        decoded = unquote(value)
        if decoded != value or any(segment in {".", ".."} for segment in decoded.split("/")):
            raise ValueError("destination_path_traversal")
        return value

    @model_validator(mode="after")
    def enforce_invariants(self) -> ValidationPlan:
        if self.risk_tier is RiskTier.R4:
            raise ValueError("r4_plan_impossible")
        if self.cost_units != self.max_requests:
            raise ValueError("plan_cost_units_server_calculated")
        expected = compute_plan_digest_from_fields(self)
        if self.plan_digest != expected:
            raise ValueError("plan_digest_mismatch")
        return self


def _normalize_plan_dict(data: dict[str, Any]) -> dict[str, Any]:
    out = dict(data)
    out.pop("plan_digest", None)
    if hasattr(out.get("risk_tier"), "value"):
        out["risk_tier"] = out["risk_tier"].value
    recipe = out.get("recipe_ref")
    if hasattr(recipe, "model_dump"):
        out["recipe_ref"] = recipe.model_dump(mode="json")
    mutation = out.get("mutation_inventory")
    if hasattr(mutation, "model_dump"):
        out["mutation_inventory"] = mutation.model_dump(mode="json")
    methods = out.get("methods")
    if isinstance(methods, (list, tuple)):
        out["methods"] = list(m.upper() for m in methods)
    aliases = out.get("account_aliases")
    if isinstance(aliases, (list, tuple)):
        out["account_aliases"] = list(aliases)
    stops = out.get("stop_conditions")
    if isinstance(stops, (list, tuple)):
        out["stop_conditions"] = list(stops)
    out.setdefault("hypothesis_id", None)
    out.setdefault("canary_token_id", None)
    out.setdefault("r3_approval_id", None)
    out.setdefault("cost_units", out.get("max_requests"))
    out.setdefault("candidate_promotion_allowed", False)
    out.setdefault("report_submission_allowed", False)
    if "account_aliases" not in out or out["account_aliases"] is None:
        out["account_aliases"] = []
    if "methods" not in out or out["methods"] is None:
        out["methods"] = []
    if "stop_conditions" not in out or out["stop_conditions"] is None:
        out["stop_conditions"] = []
    return {key: out[key] for key in sorted(out.keys())}


def compute_plan_digest_from_fields(plan: ValidationPlan | dict[str, Any]) -> str:
    if isinstance(plan, ValidationPlan):
        data = plan.model_dump(mode="json")
    elif hasattr(plan, "model_dump"):
        data = plan.model_dump(mode="json")
    else:
        data = dict(plan)
    payload = _normalize_plan_dict(data)
    serialized = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return f"sha256:{sha256(serialized.encode('utf-8')).hexdigest()}"


def build_validation_plan(**fields: Any) -> ValidationPlan:
    """Construct a plan with server-bound digest."""

    if fields.get("risk_tier") is RiskTier.R4 or fields.get("risk_tier") == "R4":
        raise ValueError("r4_plan_impossible")
    working = dict(fields)
    working.pop("plan_digest", None)
    requested_cost_units = working.pop("cost_units", None)
    if requested_cost_units is not None and requested_cost_units != working.get("max_requests"):
        raise ValueError("plan_cost_units_server_calculated")
    working["cost_units"] = working.get("max_requests")
    digest = compute_plan_digest_from_fields(working)
    working["plan_digest"] = digest
    return ValidationPlan(**working)


def compute_plan_digest(plan: ValidationPlan) -> str:
    return compute_plan_digest_from_fields(plan)


__all__ = [
    "PlanStatus",
    "ValidationPlan",
    "build_validation_plan",
    "compute_plan_digest",
    "compute_plan_digest_from_fields",
]
