"""Independent durable research branch selection for Bounty Autopilot."""

from __future__ import annotations

from enum import Enum

from pydantic import Field, field_validator

from app.bounty_autopilot.contracts import RecipeRef, RiskTier, StrictContract


class BranchStatus(str, Enum):
    QUEUED = "queued"
    ACTIVE = "active"
    PARKED = "parked"
    AWAITING_R3 = "awaiting_r3"
    AWAITING_HUMAN = "awaiting_human"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    CLOSED = "closed"


class BranchBudgetCounters(StrictContract):
    requests_used: int = Field(ge=0, default=0)
    time_seconds_used: int = Field(ge=0, default=0)
    cost_units_used: int = Field(ge=0, default=0)


class BranchLimits(StrictContract):
    campaign_max_requests: int = Field(ge=1)
    campaign_max_time_seconds: int = Field(ge=1)
    campaign_max_cost_units: int = Field(ge=1)
    per_asset_max_requests: int = Field(ge=1)
    per_account_max_requests: int = Field(ge=1)
    per_hypothesis_max_requests: int = Field(ge=1)


class ResearchBranch(StrictContract):
    branch_id: str = Field(min_length=1, max_length=128)
    campaign_id: str = Field(min_length=1, max_length=128)
    asset_id: str = Field(min_length=1, max_length=128)
    status: BranchStatus
    priority: int = Field(ge=0, le=100)
    recipe_ref: RecipeRef | None = None
    risk_tier: RiskTier = RiskTier.R0
    hypothesis_id: str | None = None
    account_aliases: tuple[str, ...] = Field(default_factory=tuple, max_length=8)
    budget: BranchBudgetCounters = Field(default_factory=BranchBudgetCounters)
    stop_reason: str | None = None
    version: int = Field(ge=1, default=1)

    @field_validator("account_aliases", mode="before")
    @classmethod
    def as_tuple(cls, value):
        if value is None:
            return ()
        if isinstance(value, list):
            return tuple(value)
        return value


class BranchSelection(StrictContract):
    selected_branch_id: str | None
    reason: str
    frozen_for_policy_drift: bool = False
    visible_waiting_branch_ids: tuple[str, ...] = Field(default_factory=tuple)
    suppressed_duplicate_branch_ids: tuple[str, ...] = Field(default_factory=tuple)


_ELIGIBLE = {BranchStatus.QUEUED, BranchStatus.ACTIVE}
_WAITING = {
    BranchStatus.PARKED,
    BranchStatus.AWAITING_R3,
    BranchStatus.AWAITING_HUMAN,
}


def branch_within_limits(
    branch: ResearchBranch,
    *,
    limits: BranchLimits,
    asset_requests: dict[str, int] | None = None,
    account_requests: dict[str, int] | None = None,
    hypothesis_requests: dict[str, int] | None = None,
    campaign_requests_used: int = 0,
    campaign_time_used: int = 0,
    campaign_cost_used: int = 0,
) -> bool:
    asset_requests = asset_requests or {}
    account_requests = account_requests or {}
    hypothesis_requests = hypothesis_requests or {}
    if campaign_requests_used >= limits.campaign_max_requests:
        return False
    if campaign_time_used >= limits.campaign_max_time_seconds:
        return False
    if campaign_cost_used >= limits.campaign_max_cost_units:
        return False
    if asset_requests.get(branch.asset_id, 0) >= limits.per_asset_max_requests:
        return False
    if branch.hypothesis_id and hypothesis_requests.get(branch.hypothesis_id, 0) >= limits.per_hypothesis_max_requests:
        return False
    for alias in branch.account_aliases:
        if account_requests.get(alias, 0) >= limits.per_account_max_requests:
            return False
    if branch.budget.requests_used >= limits.per_asset_max_requests:
        return False
    return True


def branch_matches_authorization(
    branch: ResearchBranch,
    *,
    authorized_asset_ids: set[str] | frozenset[str],
    authorized_recipe_refs: tuple[RecipeRef, ...],
    risk_ceiling: RiskTier,
    authorized_account_aliases: set[str] | frozenset[str],
) -> bool:
    """Keep scheduler work inside the current authorization generation."""

    risk_order = {tier: index for index, tier in enumerate(RiskTier)}
    if branch.asset_id not in authorized_asset_ids:
        return False
    if risk_order[branch.risk_tier] > risk_order[risk_ceiling]:
        return False
    if not set(branch.account_aliases).issubset(authorized_account_aliases):
        return False
    if branch.recipe_ref is None:
        return True
    return any(
        branch.recipe_ref.recipe_id == recipe.recipe_id
        and branch.recipe_ref.version == recipe.version
        for recipe in authorized_recipe_refs
    )


def select_next_branch(
    branches: list[ResearchBranch] | tuple[ResearchBranch, ...],
    *,
    limits: BranchLimits,
    policy_drift: bool = False,
    asset_requests: dict[str, int] | None = None,
    account_requests: dict[str, int] | None = None,
    hypothesis_requests: dict[str, int] | None = None,
    campaign_requests_used: int = 0,
    campaign_time_used: int = 0,
    campaign_cost_used: int = 0,
    admitted_asset_ids: set[str] | frozenset[str] | None = None,
) -> BranchSelection:
    """Select one eligible branch without replaying completed hypotheses."""

    waiting_ids = tuple(
        sorted(branch.branch_id for branch in branches if branch.status in _WAITING)
    )
    completed_hypotheses = {
        branch.hypothesis_id
        for branch in branches
        if branch.hypothesis_id
        and branch.status in {BranchStatus.COMPLETED, BranchStatus.CLOSED}
    }
    if policy_drift:
        return BranchSelection(
            selected_branch_id=None,
            reason="policy_drift_freeze",
            frozen_for_policy_drift=True,
            visible_waiting_branch_ids=waiting_ids,
        )

    # An empty admission set means nothing is eligible. It never means
    # "unrestricted"; callers must explicitly admit every active asset.
    admitted = set(admitted_asset_ids or ())

    def is_within_schedule_bounds(branch: ResearchBranch) -> bool:
        return (
            branch.asset_id in admitted
            and branch.risk_tier not in {RiskTier.R3, RiskTier.R4}
            and branch_within_limits(
                branch,
                limits=limits,
                asset_requests=asset_requests,
                account_requests=account_requests,
                hypothesis_requests=hypothesis_requests,
                campaign_requests_used=campaign_requests_used,
                campaign_time_used=campaign_time_used,
                campaign_cost_used=campaign_cost_used,
            )
        )

    # A stale, out-of-scope, or exhausted ACTIVE branch cannot block the
    # independently schedulable queued branch for the same hypothesis.
    active_hypotheses = {
        branch.hypothesis_id
        for branch in branches
        if branch.hypothesis_id
        and branch.status is BranchStatus.ACTIVE
        and is_within_schedule_bounds(branch)
    }
    candidates: list[ResearchBranch] = []
    suppressed_duplicate_ids: list[str] = []
    for branch in branches:
        if branch.status not in _ELIGIBLE:
            continue
        if branch.hypothesis_id in completed_hypotheses:
            suppressed_duplicate_ids.append(branch.branch_id)
            continue
        if (
            branch.status is BranchStatus.QUEUED
            and branch.hypothesis_id in active_hypotheses
        ):
            suppressed_duplicate_ids.append(branch.branch_id)
            continue
        if not is_within_schedule_bounds(branch):
            continue
        candidates.append(branch)

    if not candidates:
        return BranchSelection(
            selected_branch_id=None,
            reason="no_eligible_branch",
            visible_waiting_branch_ids=waiting_ids,
            suppressed_duplicate_branch_ids=tuple(sorted(suppressed_duplicate_ids)),
        )

    # Stable: highest priority, then branch_id ascending.
    candidates.sort(key=lambda item: (-item.priority, item.branch_id))
    selected = candidates[0]
    return BranchSelection(
        selected_branch_id=selected.branch_id,
        reason="selected",
        visible_waiting_branch_ids=waiting_ids,
        suppressed_duplicate_branch_ids=tuple(sorted(suppressed_duplicate_ids)),
    )


def transition_branch(
    branch: ResearchBranch,
    *,
    new_status: BranchStatus,
    expected_version: int,
    stop_reason: str | None = None,
) -> ResearchBranch:
    if branch.version != expected_version:
        raise ValueError("branch_version_conflict")
    # Prevent duplicate successful completion transitions.
    if branch.status is BranchStatus.COMPLETED and new_status is BranchStatus.COMPLETED:
        raise ValueError("duplicate_completed_transition")
    if branch.status is BranchStatus.CLOSED:
        raise ValueError("branch_closed")
    return branch.model_copy(
        update={
            "status": new_status,
            "stop_reason": stop_reason,
            "version": branch.version + 1,
        }
    )


__all__ = [
    "BranchBudgetCounters",
    "BranchLimits",
    "BranchSelection",
    "BranchStatus",
    "ResearchBranch",
    "branch_matches_authorization",
    "branch_within_limits",
    "select_next_branch",
    "transition_branch",
]
