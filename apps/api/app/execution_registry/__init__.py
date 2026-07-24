"""Capability registry for campaign-scoped research and validation tools.

The registry is a control-plane boundary. It does not execute tools, send
network traffic, or promote findings. Callers must obtain an eligibility
decision here before handing work to a local runner or a lease-bound runtime.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.scope_guard import (
    ScopeGuardDecision,
    ScopeGuardRule,
    ValidationRequest,
    evaluate_validation_request,
)


_SAFE_TOOL_ID = re.compile(r"^[a-z][a-z0-9_]{0,63}$", re.ASCII)

ExecutionTier = Literal["local", "remote"]


class ToolCapability(BaseModel):
    """Immutable description of one executable capability."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: str = Field(min_length=1, max_length=64)
    validation_mode: str = Field(min_length=1, max_length=100)
    execution_tier: ExecutionTier
    network_access: bool
    human_approval_required: bool
    execution_lease_required: bool
    dispatch_allowed: bool
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False

    @field_validator("tool_id", "validation_mode")
    @classmethod
    def require_safe_identifier(cls, value: str) -> str:
        if _SAFE_TOOL_ID.fullmatch(value) is None:
            raise ValueError("safe_tool_identifier_required")
        return value

    @model_validator(mode="after")
    def require_safe_tier_contract(self) -> ToolCapability:
        if self.execution_tier == "local" and self.network_access:
            raise ValueError("local_tool_network_access_not_allowed")
        if self.execution_tier == "remote" and not self.network_access:
            raise ValueError("remote_tool_network_access_required")
        if self.execution_tier == "remote" and not self.human_approval_required:
            raise ValueError("remote_tool_human_approval_required")
        if self.execution_tier == "remote" and not self.execution_lease_required:
            raise ValueError("remote_tool_execution_lease_required")
        if self.execution_tier == "remote" and self.dispatch_allowed:
            raise ValueError("remote_tool_direct_dispatch_not_allowed")
        return self


class ExecutionRegistry:
    """Lookup-only registry with duplicate capability rejection."""

    def __init__(self, capabilities: Iterable[ToolCapability]) -> None:
        by_id: dict[str, ToolCapability] = {}
        for capability in capabilities:
            if capability.tool_id in by_id:
                raise ValueError(f"duplicate_tool_capability:{capability.tool_id}")
            by_id[capability.tool_id] = capability
        self._by_id = by_id

    def get(self, tool_id: str) -> ToolCapability | None:
        return self._by_id.get(tool_id)

    def list_capabilities(self) -> list[ToolCapability]:
        return [self._by_id[tool_id] for tool_id in sorted(self._by_id)]


class ExecutionAuthorizationRequest(BaseModel):
    """All campaign and Scope Guard context needed before tool dispatch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool_id: str = Field(min_length=1, max_length=64)
    asset: str = Field(min_length=1, max_length=255)
    campaign_allowed_tools: list[str] = Field(default_factory=list, max_length=50)
    scope_rule: ScopeGuardRule
    human_approved: bool = False
    execution_lease_active: bool = False
    # Autopilot path: server-resolved authority IDs (optional for legacy callers).
    campaign_id: str | None = Field(default=None, max_length=128)
    plan_id: str | None = Field(default=None, max_length=128)
    plan_digest: str | None = Field(default=None, max_length=100)
    lease_id: str | None = Field(default=None, max_length=128)
    authorization_digest: str | None = Field(default=None, max_length=100)

    @field_validator("tool_id")
    @classmethod
    def require_safe_tool_id(cls, value: str) -> str:
        if _SAFE_TOOL_ID.fullmatch(value) is None:
            raise ValueError("safe_tool_identifier_required")
        return value


class ExecutionAuthorizationDecision(BaseModel):
    """Eligibility result. A positive decision never permits promotion or submission."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    eligible: bool
    reason: str
    capability: ToolCapability | None = None
    scope_decision: ScopeGuardDecision | None = None
    execution_tier: ExecutionTier | None = None
    network_access: bool = False
    requires_human_approval: bool = False
    requires_execution_lease: bool = False
    dispatch_allowed: bool = False
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False


_DEFAULT_CAPABILITIES = (
    ToolCapability(
        tool_id="semgrep_local",
        validation_mode="static_analyzer",
        execution_tier="local",
        network_access=False,
        human_approval_required=True,
        execution_lease_required=False,
        dispatch_allowed=True,
    ),
    ToolCapability(
        tool_id="codeql_local",
        validation_mode="static_analyzer",
        execution_tier="local",
        network_access=False,
        human_approval_required=True,
        execution_lease_required=False,
        dispatch_allowed=True,
    ),
    ToolCapability(
        tool_id="dependency_sbom_local",
        validation_mode="static_analyzer",
        execution_tier="local",
        network_access=False,
        human_approval_required=True,
        execution_lease_required=False,
        dispatch_allowed=True,
    ),
    ToolCapability(
        tool_id="two_account_authorization_check",
        validation_mode="two_account_authorization_check",
        execution_tier="remote",
        network_access=True,
        human_approval_required=True,
        execution_lease_required=True,
        dispatch_allowed=False,
    ),
    ToolCapability(
        tool_id="black_box_differential",
        validation_mode="black_box_differential",
        execution_tier="remote",
        network_access=True,
        human_approval_required=True,
        execution_lease_required=True,
        dispatch_allowed=False,
    ),
)

_DEFAULT_EXECUTION_REGISTRY = ExecutionRegistry(_DEFAULT_CAPABILITIES)


def default_execution_registry() -> ExecutionRegistry:
    return _DEFAULT_EXECUTION_REGISTRY


def authorize_tool_execution(
    request: ExecutionAuthorizationRequest,
    *,
    registry: ExecutionRegistry | None = None,
) -> ExecutionAuthorizationDecision:
    """Return a fail-closed campaign/tool eligibility decision."""
    capability = (registry or default_execution_registry()).get(request.tool_id)
    if capability is None:
        return ExecutionAuthorizationDecision(eligible=False, reason="unknown_tool")

    if not _campaign_allows(capability, request.campaign_allowed_tools):
        return _blocked_decision(capability, "tool_not_campaign_allowed")

    scope_decision = evaluate_validation_request(
        request.scope_rule,
        ValidationRequest(
            asset=request.asset,
            validation_type=capability.validation_mode,
            human_approved=request.human_approved,
        ),
    )
    if not scope_decision.allowed:
        return _blocked_decision(capability, scope_decision.reason, scope_decision)

    if capability.human_approval_required and not request.human_approved:
        return _blocked_decision(capability, "human_approval_required", scope_decision)
    if capability.execution_lease_required and not request.execution_lease_active:
        return _blocked_decision(capability, "execution_lease_required", scope_decision)

    # Autopilot authority path: when plan_digest is present, require lease and auth digests.
    if request.plan_digest is not None:
        if not request.lease_id or not request.execution_lease_active:
            return _blocked_decision(capability, "autopilot_lease_required", scope_decision)
        if not request.authorization_digest:
            return _blocked_decision(
                capability, "autopilot_authorization_digest_required", scope_decision
            )
        if not request.plan_id or not request.campaign_id:
            return _blocked_decision(
                capability, "autopilot_plan_identity_required", scope_decision
            )

    return ExecutionAuthorizationDecision(
        eligible=True,
        reason="eligible",
        capability=capability,
        scope_decision=scope_decision,
        execution_tier=capability.execution_tier,
        network_access=capability.network_access,
        requires_human_approval=capability.human_approval_required,
        requires_execution_lease=capability.execution_lease_required,
        dispatch_allowed=capability.dispatch_allowed,
    )


def _campaign_allows(capability: ToolCapability, allowed_tools: list[str]) -> bool:
    allowed = set(allowed_tools)
    return capability.tool_id in allowed or capability.validation_mode in allowed


def _blocked_decision(
    capability: ToolCapability,
    reason: str,
    scope_decision: ScopeGuardDecision | None = None,
) -> ExecutionAuthorizationDecision:
    return ExecutionAuthorizationDecision(
        eligible=False,
        reason=reason,
        capability=capability,
        scope_decision=scope_decision,
        execution_tier=capability.execution_tier,
        network_access=capability.network_access,
        requires_human_approval=capability.human_approval_required,
        requires_execution_lease=capability.execution_lease_required,
    )


__all__ = [
    "ExecutionAuthorizationDecision",
    "ExecutionAuthorizationRequest",
    "ExecutionRegistry",
    "ToolCapability",
    "authorize_tool_execution",
    "default_execution_registry",
]
