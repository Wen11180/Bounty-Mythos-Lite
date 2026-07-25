"""Continuous scheduling and steering signals for Autopilot."""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from app.bounty_autopilot.branches import (
    BranchLimits,
    BranchSelection,
    ResearchBranch,
    select_next_branch,
)
from app.bounty_autopilot.contracts import StrictContract


class SteerDirective(str, Enum):
    CONTINUE = "continue"
    PAUSE_CAMPAIGN = "pause_campaign"
    EMERGENCY_STOP = "emergency_stop"
    FOCUS_BRANCH = "focus_branch"
    DEPRIORITIZE_BRANCH = "deprioritize_branch"


class OperatorSteerMessage(StrictContract):
    directive: SteerDirective
    branch_id: str | None = None
    reason: str = Field(min_length=1, max_length=256)


class SchedulerTickResult(StrictContract):
    selected_branch_id: str | None
    reason: str
    frozen: bool = False
    emergency_stopped: bool = False
    visible_waiting_branch_ids: tuple[str, ...] = Field(default_factory=tuple)
    suppressed_duplicate_branch_ids: tuple[str, ...] = Field(default_factory=tuple)


def apply_steer_to_selection(
    *,
    branches: list[ResearchBranch] | tuple[ResearchBranch, ...],
    limits: BranchLimits,
    steer: OperatorSteerMessage | None,
    admitted_asset_ids: set[str] | frozenset[str] | None = None,
    policy_drift: bool = False,
    emergency_stopped: bool = False,
    campaign_requests_used: int = 0,
    campaign_time_used: int = 0,
    campaign_cost_used: int = 0,
) -> SchedulerTickResult:
    if emergency_stopped or (steer and steer.directive is SteerDirective.EMERGENCY_STOP):
        return SchedulerTickResult(
            selected_branch_id=None,
            reason="emergency_stopped",
            emergency_stopped=True,
        )
    if steer and steer.directive is SteerDirective.PAUSE_CAMPAIGN:
        return SchedulerTickResult(
            selected_branch_id=None,
            reason="paused_by_operator",
            frozen=True,
        )
    selection: BranchSelection = select_next_branch(
        branches,
        limits=limits,
        policy_drift=policy_drift,
        admitted_asset_ids=admitted_asset_ids,
        campaign_requests_used=campaign_requests_used,
        campaign_time_used=campaign_time_used,
        campaign_cost_used=campaign_cost_used,
    )
    if selection.frozen_for_policy_drift:
        return SchedulerTickResult(
            selected_branch_id=None,
            reason=selection.reason,
            frozen=True,
            visible_waiting_branch_ids=selection.visible_waiting_branch_ids,
            suppressed_duplicate_branch_ids=selection.suppressed_duplicate_branch_ids,
        )
    if steer and steer.directive is SteerDirective.FOCUS_BRANCH and steer.branch_id:
        target = next((b for b in branches if b.branch_id == steer.branch_id), None)
        if target is not None:
            target_selection = select_next_branch(
                [target],
                limits=limits,
                policy_drift=policy_drift,
                admitted_asset_ids=admitted_asset_ids,
                campaign_requests_used=campaign_requests_used,
                campaign_time_used=campaign_time_used,
                campaign_cost_used=campaign_cost_used,
            )
        else:
            target_selection = None
        if (
            target_selection is not None
            and target_selection.selected_branch_id is not None
            and steer.branch_id not in selection.suppressed_duplicate_branch_ids
        ):
            return SchedulerTickResult(
                selected_branch_id=steer.branch_id,
                reason="operator_focus",
                visible_waiting_branch_ids=selection.visible_waiting_branch_ids,
                suppressed_duplicate_branch_ids=selection.suppressed_duplicate_branch_ids,
            )
    return SchedulerTickResult(
        selected_branch_id=selection.selected_branch_id,
        reason=selection.reason,
        visible_waiting_branch_ids=selection.visible_waiting_branch_ids,
        suppressed_duplicate_branch_ids=selection.suppressed_duplicate_branch_ids,
    )


__all__ = [
    "OperatorSteerMessage",
    "SchedulerTickResult",
    "SteerDirective",
    "apply_steer_to_selection",
]
