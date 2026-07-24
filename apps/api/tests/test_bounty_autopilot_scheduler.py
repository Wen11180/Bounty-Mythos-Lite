"""Phase 9 scheduler/steer tests."""

from app.bounty_autopilot.branches import BranchLimits, BranchStatus, ResearchBranch
from app.bounty_autopilot.contracts import RiskTier
from app.bounty_autopilot.scheduler import (
    OperatorSteerMessage,
    SteerDirective,
    apply_steer_to_selection,
)


def test_scheduler_continues_around_waiting_and_honors_emergency_stop():
    branches = [
        ResearchBranch(
            branch_id="parked",
            campaign_id="c1",
            asset_id="a1",
            status=BranchStatus.PARKED,
            priority=99,
            risk_tier=RiskTier.R1,
        ),
        ResearchBranch(
            branch_id="ready",
            campaign_id="c1",
            asset_id="a2",
            status=BranchStatus.QUEUED,
            priority=10,
            risk_tier=RiskTier.R0,
        ),
    ]
    limits = BranchLimits(
        campaign_max_requests=10,
        campaign_max_time_seconds=100,
        campaign_max_cost_units=10,
        per_asset_max_requests=5,
        per_account_max_requests=5,
        per_hypothesis_max_requests=5,
    )
    tick = apply_steer_to_selection(
        branches=branches,
        limits=limits,
        steer=None,
        admitted_asset_ids={"a1", "a2"},
    )
    assert tick.selected_branch_id == "ready"
    stop = apply_steer_to_selection(
        branches=branches,
        limits=limits,
        steer=OperatorSteerMessage(
            directive=SteerDirective.EMERGENCY_STOP,
            reason="operator_stop",
        ),
        admitted_asset_ids={"a1", "a2"},
    )
    assert stop.emergency_stopped is True
    assert stop.selected_branch_id is None
