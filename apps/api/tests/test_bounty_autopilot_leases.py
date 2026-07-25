"""Phase 4 lease issuance and R3 consumption tests."""

from __future__ import annotations

from app.bounty_autopilot.contracts import MutationInventory, PolicyMode, RecipeRef, RiskTier
from app.bounty_autopilot.leases import (
    ApprovalStore,
    R3ApprovalToken,
    emergency_stop_leases,
    issue_execution_lease,
)
from app.bounty_autopilot.plans import build_validation_plan


def _digest(n: str = "a") -> str:
    return "sha256:" + (n * 64)


def _plan(*, risk_tier: RiskTier = RiskTier.R1):
    return build_validation_plan(
        plan_id="plan_1",
        campaign_id="campaign_1",
        authorization_digest=_digest("a"),
        scope_snapshot_digest=_digest("b"),
        asset_id="asset_loopback",
        destination_scheme="http",
        destination_host="127.0.0.1",
        destination_port=8080,
        destination_path="/api",
        branch_id="branch_1",
        risk_tier=risk_tier,
        recipe_ref=RecipeRef(recipe_id="lab_browser_mapping", version="1.0"),
        methods=("GET",),
        mutation_inventory=MutationInventory(
            methods=("GET",),
            mutates_state=False,
            reversible=True,
            requires_owned_accounts=False,
        ),
        max_requests=3,
        max_response_bytes=1000,
        max_duration_seconds=30,
        rollback_plan="noop",
        stop_conditions=("stop",),
        tool_profile="lab",
        container_profile="lab",
    )


def test_issue_lease_for_lab_r1():
    plan = _plan()
    result = issue_execution_lease(
        plan=plan,
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        authorization_recipe_allowed=True,
        authorization_digest=plan.authorization_digest,
        scope_snapshot_digest=plan.scope_snapshot_digest,
        lease_id="lease_1",
        now_iso="2026-07-24T00:00:00+00:00",
    )
    assert result.allowed is True
    assert result.lease is not None
    assert result.lease.report_submission_allowed is False


def test_r4_cannot_create_lease_or_approval():
    try:
        plan = _plan(risk_tier=RiskTier.R4)
    except ValueError:
        plan = None
    assert plan is None


def test_r3_approval_single_use_and_plan_bound():
    plan = _plan(risk_tier=RiskTier.R3)
    store = ApprovalStore()
    token = R3ApprovalToken(
        approval_id="appr_1",
        plan_digest=plan.plan_digest,
        scope_snapshot_digest=plan.scope_snapshot_digest,
        authorization_digest=plan.authorization_digest,
        account_aliases=plan.account_aliases,
        nonce_digest=_digest("c"),
        expires_at="2026-07-24T01:00:00+00:00",
    )
    store.put(token)
    first = issue_execution_lease(
        plan=plan,
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        authorization_recipe_allowed=True,
        authorization_digest=plan.authorization_digest,
        scope_snapshot_digest=plan.scope_snapshot_digest,
        lease_id="lease_r3_1",
        now_iso="2026-07-24T00:30:00+00:00",
        approval_store=store,
        approval_token=token,
    )
    assert first.allowed is True
    assert first.consumed_approval_id == "appr_1"
    second = issue_execution_lease(
        plan=plan,
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        authorization_recipe_allowed=True,
        authorization_digest=plan.authorization_digest,
        scope_snapshot_digest=plan.scope_snapshot_digest,
        lease_id="lease_r3_2",
        now_iso="2026-07-24T00:31:00+00:00",
        approval_store=store,
        approval_token=token,
    )
    assert second.allowed is False
    assert second.reason == "approval_already_consumed"


def test_r3_invalid_after_plan_change():
    plan = _plan(risk_tier=RiskTier.R3)
    other = build_validation_plan(
        plan_id="plan_2",
        campaign_id=plan.campaign_id,
        authorization_digest=plan.authorization_digest,
        scope_snapshot_digest=plan.scope_snapshot_digest,
        asset_id=plan.asset_id,
        destination_scheme=plan.destination_scheme,
        destination_host=plan.destination_host,
        destination_port=plan.destination_port,
        destination_path="/other",
        branch_id=plan.branch_id,
        risk_tier=RiskTier.R3,
        recipe_ref=plan.recipe_ref,
        methods=plan.methods,
        mutation_inventory=plan.mutation_inventory,
        max_requests=plan.max_requests,
        max_response_bytes=plan.max_response_bytes,
        max_duration_seconds=plan.max_duration_seconds,
        rollback_plan=plan.rollback_plan,
        stop_conditions=plan.stop_conditions,
        tool_profile=plan.tool_profile,
        container_profile=plan.container_profile,
    )
    store = ApprovalStore()
    token = R3ApprovalToken(
        approval_id="appr_2",
        plan_digest=plan.plan_digest,
        scope_snapshot_digest=plan.scope_snapshot_digest,
        authorization_digest=plan.authorization_digest,
        nonce_digest=_digest("d"),
        expires_at="2026-07-24T01:00:00+00:00",
    )
    store.put(token)
    result = issue_execution_lease(
        plan=other,
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        authorization_recipe_allowed=True,
        authorization_digest=other.authorization_digest,
        scope_snapshot_digest=other.scope_snapshot_digest,
        lease_id="lease_x",
        now_iso="2026-07-24T00:30:00+00:00",
        approval_store=store,
        approval_token=token,
    )
    assert result.allowed is False
    assert result.reason == "approval_plan_mismatch"


def test_emergency_stop_revokes_active_leases():
    plan = _plan()
    issued = issue_execution_lease(
        plan=plan,
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        authorization_recipe_allowed=True,
        authorization_digest=plan.authorization_digest,
        scope_snapshot_digest=plan.scope_snapshot_digest,
        lease_id="lease_stop",
        now_iso="2026-07-24T00:00:00+00:00",
    )
    assert issued.lease is not None
    stopped = emergency_stop_leases([issued.lease])
    assert stopped[0].status.value == "revoked"
    assert stopped[0].emergency_stopped is True
    blocked = issue_execution_lease(
        plan=plan,
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        authorization_recipe_allowed=True,
        authorization_digest=plan.authorization_digest,
        scope_snapshot_digest=plan.scope_snapshot_digest,
        lease_id="lease_after_stop",
        now_iso="2026-07-24T00:01:00+00:00",
        emergency_stopped=True,
    )
    assert blocked.allowed is False
