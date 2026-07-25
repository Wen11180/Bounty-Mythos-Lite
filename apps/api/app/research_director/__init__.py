"""Evidence-driven next-action selection for autonomous research campaigns.

The director chooses the next bounded research action. It never executes a
tool, sends remote traffic, promotes a finding, or submits a report.
"""

from __future__ import annotations

import json
import re
from hashlib import sha256
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.execution_registry import (
    ExecutionAuthorizationDecision,
    ExecutionAuthorizationRequest,
    ExecutionRegistry,
    ToolCapability,
    authorize_tool_execution,
    default_execution_registry,
)
from app.scope_guard import ScopeGuardRule


_SAFE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_:-]{0,127}$", re.ASCII)
_SNAPSHOT_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)

ActionKind = Literal["local_tool", "remote_tool", "research_task", "none"]
PlanStatus = Literal["ready", "awaiting_human_review", "blocked"]
SignalState = Literal[
    "open",
    "needs_evidence",
    "retained",
    "refuted",
    "deduplicated",
]


class ResearchSignal(BaseModel):
    """A redacted, evidence-linked reason for the director to continue research."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    signal_id: str = Field(min_length=1, max_length=128)
    state: SignalState
    priority: int = Field(ge=0, le=100)
    tool_hints: list[str] = Field(default_factory=list, max_length=10)
    evidence_refs: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("signal_id")
    @classmethod
    def require_safe_signal_id(cls, value: str) -> str:
        if _SAFE_ID.fullmatch(value) is None:
            raise ValueError("safe_research_signal_id_required")
        return value

    @field_validator("tool_hints")
    @classmethod
    def require_safe_tool_hints(cls, values: list[str]) -> list[str]:
        if any(_SAFE_ID.fullmatch(value) is None for value in values):
            raise ValueError("safe_research_tool_hint_required")
        return values


class ResearchDirectorContext(BaseModel):
    """Snapshot-bound, non-sensitive state used to choose one next action."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    campaign_id: str = Field(min_length=1, max_length=128)
    asset: str = Field(min_length=1, max_length=255)
    autonomy_level: str = Field(min_length=1, max_length=100)
    source_snapshot_digest: str = Field(min_length=1, max_length=80)
    scope_rule: ScopeGuardRule
    campaign_allowed_tools: list[str] = Field(default_factory=list, max_length=50)
    has_authorized_local_root: bool = False
    local_execution_authorized: bool = False
    remaining_tool_calls: int | None = Field(default=None, ge=0)
    completed_action_ids: list[str] = Field(default_factory=list, max_length=100)
    signals: list[ResearchSignal] = Field(default_factory=list, max_length=100)
    human_review_required: bool = False
    execution_lease_active: bool = False

    @field_validator("campaign_id")
    @classmethod
    def require_safe_campaign_id(cls, value: str) -> str:
        if _SAFE_ID.fullmatch(value) is None:
            raise ValueError("safe_campaign_id_required")
        return value

    @field_validator("source_snapshot_digest")
    @classmethod
    def require_snapshot_digest(cls, value: str) -> str:
        if _SNAPSHOT_DIGEST.fullmatch(value) is None:
            raise ValueError("source_snapshot_digest_required")
        return value

    @field_validator("completed_action_ids")
    @classmethod
    def require_safe_completed_action_ids(cls, values: list[str]) -> list[str]:
        if any(_SAFE_ID.fullmatch(value) is None for value in values):
            raise ValueError("safe_completed_action_id_required")
        return values


class ResearchDirectorPlan(BaseModel):
    """One auditable action selected from current evidence and capability gates."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: str
    plan_digest: str
    status: PlanStatus
    action_kind: ActionKind
    action_id: str | None = None
    signal_id: str | None = None
    priority: int = Field(ge=0, le=100)
    source_snapshot_digest: str
    reasons: list[str] = Field(default_factory=list)
    required_gates: list[str] = Field(default_factory=list)
    stop_reason: str | None = None
    execution_tier: Literal["local", "remote"] | None = None
    dispatch_allowed: bool = False
    execution_eligibility: ExecutionAuthorizationDecision | None = None
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False


def build_research_director_plan(
    context: ResearchDirectorContext,
    *,
    registry: ExecutionRegistry | None = None,
) -> ResearchDirectorPlan:
    """Choose one high-value, policy-bounded next action for a campaign snapshot."""
    if context.scope_rule.asset != context.asset or context.scope_rule.scope_status != "in_scope":
        return _plan(context, status="blocked", reasons=["scope_not_in_scope"], stop_reason="scope_not_in_scope")
    if context.human_review_required:
        return _plan(
            context,
            status="awaiting_human_review",
            reasons=["human_review_required"],
            required_gates=["human_review"],
            stop_reason="human_review_required",
        )

    resolved_registry = registry or default_execution_registry()
    skipped_reasons: list[str] = []
    for signal in _active_signals(context.signals):
        tool_plan = _tool_plan_for_signal(
            context=context,
            signal=signal,
            registry=resolved_registry,
            skipped_reasons=skipped_reasons,
        )
        if tool_plan is not None:
            return tool_plan

    retained = _highest_retained_signal(context.signals)
    if retained is not None:
        return _plan(
            context,
            status="ready",
            action_kind="research_task",
            action_id="report_review",
            signal=retained,
            reasons=["retained_candidate_requires_report_review"],
            required_gates=["evidence_review", "human_review"],
        )

    active = _active_signals(context.signals)
    if active:
        return _plan(
            context,
            status="ready",
            action_kind="research_task",
            action_id="candidate_refutation",
            signal=active[0],
            reasons=[*skipped_reasons, "evidence_gap_requires_refutation"],
            required_gates=["scope_guard"],
        )

    return _plan(
        context,
        status="ready",
        action_kind="research_task",
        action_id="attack_surface_mapping",
        reasons=["no_open_candidate_signal"],
        required_gates=["scope_guard"],
    )


def _tool_plan_for_signal(
    *,
    context: ResearchDirectorContext,
    signal: ResearchSignal,
    registry: ExecutionRegistry,
    skipped_reasons: list[str],
) -> ResearchDirectorPlan | None:
    completed = set(context.completed_action_ids)
    for tool_id in signal.tool_hints:
        if tool_id in completed:
            skipped_reasons.append(f"completed_action:{tool_id}")
            continue
        if context.remaining_tool_calls is not None and context.remaining_tool_calls <= 0:
            skipped_reasons.append(f"tool_budget_exhausted:{tool_id}")
            continue
        capability = registry.get(tool_id)
        if capability is None:
            skipped_reasons.append(f"unregistered_tool_hint:{tool_id}")
            continue
        if capability.execution_tier == "local":
            local_plan = _local_tool_plan(context, signal, capability, registry)
            if local_plan is not None:
                return local_plan
            skipped_reasons.append(f"local_tool_unavailable:{tool_id}")
            continue
        return _remote_tool_plan(context, signal, capability, registry)
    return None


def _local_tool_plan(
    context: ResearchDirectorContext,
    signal: ResearchSignal,
    capability: ToolCapability,
    registry: ExecutionRegistry,
) -> ResearchDirectorPlan | None:
    if not context.has_authorized_local_root:
        return None
    if (
        context.autonomy_level != "level_1_local_validation"
        or not context.local_execution_authorized
    ):
        return _plan(
            context,
            status="ready",
            action_kind="research_task",
            action_id="candidate_refutation",
            signal=signal,
            reasons=["local_execution_autonomy_required"],
            required_gates=["level_1_local_validation"],
        )

    eligibility = authorize_tool_execution(
        ExecutionAuthorizationRequest(
            tool_id=capability.tool_id,
            asset=context.asset,
            campaign_allowed_tools=context.campaign_allowed_tools,
            scope_rule=context.scope_rule,
            human_approved=True,
        ),
        registry=registry,
    )
    if not eligibility.eligible:
        return None
    return _plan(
        context,
        status="ready",
        action_kind="local_tool",
        action_id=capability.tool_id,
        signal=signal,
        reasons=[
            "high_priority_evidence_gap",
            f"tool_selected:{capability.tool_id}",
            "human_approval_required",
        ],
        required_gates=[
            "scope_guard",
            "campaign_tool_allowlist",
            "human_approval",
        ],
        execution_tier="local",
        dispatch_allowed=eligibility.dispatch_allowed,
        execution_eligibility=eligibility,
    )


def _remote_tool_plan(
    context: ResearchDirectorContext,
    signal: ResearchSignal,
    capability: ToolCapability,
    registry: ExecutionRegistry,
) -> ResearchDirectorPlan:
    eligibility = authorize_tool_execution(
        ExecutionAuthorizationRequest(
            tool_id=capability.tool_id,
            asset=context.asset,
            campaign_allowed_tools=context.campaign_allowed_tools,
            scope_rule=context.scope_rule,
            human_approved=False,
            execution_lease_active=context.execution_lease_active,
        ),
        registry=registry,
    )
    reasons = ["remote_validation_requires_human_review"]
    if not context.execution_lease_active:
        reasons.append("execution_lease_required")
    if not eligibility.eligible:
        reasons.append(f"eligibility:{eligibility.reason}")
    return _plan(
        context,
        status="awaiting_human_review",
        action_kind="remote_tool",
        action_id=capability.tool_id,
        signal=signal,
        reasons=reasons,
        required_gates=["human_approval", "execution_lease", "remote_lease_runtime"],
        stop_reason="human_review_required",
        execution_tier="remote",
        execution_eligibility=eligibility,
    )


def _active_signals(signals: list[ResearchSignal]) -> list[ResearchSignal]:
    return sorted(
        (
            signal
            for signal in signals
            if signal.state in {"open", "needs_evidence"}
        ),
        key=lambda signal: (-signal.priority, signal.signal_id),
    )


def _highest_retained_signal(signals: list[ResearchSignal]) -> ResearchSignal | None:
    retained = [signal for signal in signals if signal.state == "retained"]
    return min(retained, key=lambda signal: (-signal.priority, signal.signal_id), default=None)


def _plan(
    context: ResearchDirectorContext,
    *,
    status: PlanStatus,
    action_kind: ActionKind = "none",
    action_id: str | None = None,
    signal: ResearchSignal | None = None,
    priority: int | None = None,
    reasons: list[str],
    required_gates: list[str] | None = None,
    stop_reason: str | None = None,
    execution_tier: Literal["local", "remote"] | None = None,
    dispatch_allowed: bool = False,
    execution_eligibility: ExecutionAuthorizationDecision | None = None,
) -> ResearchDirectorPlan:
    resolved_priority = signal.priority if signal is not None else priority or 0
    payload = {
        "campaign_id": context.campaign_id,
        "source_snapshot_digest": context.source_snapshot_digest,
        "status": status,
        "action_kind": action_kind,
        "action_id": action_id,
        "signal_id": signal.signal_id if signal is not None else None,
        "priority": resolved_priority,
        "reasons": reasons,
        "required_gates": required_gates or [],
        "stop_reason": stop_reason,
        "execution_tier": execution_tier,
        "dispatch_allowed": dispatch_allowed,
        "execution_eligibility": (
            execution_eligibility.model_dump(mode="json")
            if execution_eligibility is not None
            else None
        ),
    }
    canonical = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    digest = f"sha256:{sha256(canonical.encode('utf-8')).hexdigest()}"
    return ResearchDirectorPlan(
        plan_id=f"research_plan_{digest.removeprefix('sha256:')[:24]}",
        plan_digest=digest,
        status=status,
        action_kind=action_kind,
        action_id=action_id,
        signal_id=signal.signal_id if signal is not None else None,
        priority=resolved_priority,
        source_snapshot_digest=context.source_snapshot_digest,
        reasons=reasons,
        required_gates=required_gates or [],
        stop_reason=stop_reason,
        execution_tier=execution_tier,
        dispatch_allowed=dispatch_allowed,
        execution_eligibility=execution_eligibility,
    )


__all__ = [
    "ResearchDirectorContext",
    "ResearchDirectorPlan",
    "ResearchSignal",
    "build_research_director_plan",
]

def select_research_director_branch(
    branches: list,
    *,
    limits,
    policy_drift: bool = False,
    admitted_asset_ids: set[str] | frozenset[str] | None = None,
    asset_requests: dict[str, int] | None = None,
    account_requests: dict[str, int] | None = None,
    hypothesis_requests: dict[str, int] | None = None,
    campaign_requests_used: int = 0,
    campaign_time_used: int = 0,
    campaign_cost_used: int = 0,
):
    """Select one eligible Autopilot branch without stopping parked/R3 peers."""

    from app.bounty_autopilot.branches import select_next_branch

    return select_next_branch(
        branches,
        limits=limits,
        policy_drift=policy_drift,
        admitted_asset_ids=admitted_asset_ids,
        asset_requests=asset_requests,
        account_requests=account_requests,
        hypothesis_requests=hypothesis_requests,
        campaign_requests_used=campaign_requests_used,
        campaign_time_used=campaign_time_used,
        campaign_cost_used=campaign_cost_used,
    )
