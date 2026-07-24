"""Phase 5 gateway authorize tests."""

from __future__ import annotations

from app.bounty_autopilot.contracts import MutationInventory, PolicyMode, RecipeRef, RiskTier
from app.bounty_autopilot.gateway import (
    GatewayAuthorizeRequest,
    GatewayDecisionStatus,
    GatewayOutcomeClass,
    authorize_gateway_request,
    classify_response_outcome,
    outcome_to_branch_action,
)
from app.bounty_autopilot.leases import ExecutionLease, LeaseStatus
from app.bounty_autopilot.plans import build_validation_plan
from app.bounty_autopilot.recipes import default_recipe_registry


def _digest(n="a"):
    return "sha256:" + (n * 64)


def _plan():
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
        risk_tier=RiskTier.R1,
        recipe_ref=default_recipe_registry().require(
            "lab_browser_mapping", "1.0.0"
        ).ref,
        methods=("GET", "HEAD"),
        mutation_inventory=default_recipe_registry().require(
            "lab_browser_mapping", "1.0.0"
        ).mutation_inventory,
        max_requests=5,
        max_response_bytes=1000,
        max_duration_seconds=30,
        rollback_plan="close",
        stop_conditions=("waf",),
        tool_profile="lab",
        container_profile="lab",
    )


def _lease(plan):
    return ExecutionLease(
        lease_id="lease_1",
        plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
        campaign_id=plan.campaign_id,
        authorization_digest=plan.authorization_digest,
        scope_snapshot_digest=plan.scope_snapshot_digest,
        asset_id=plan.asset_id,
        branch_id=plan.branch_id,
        recipe_ref=plan.recipe_ref,
        risk_tier=plan.risk_tier,
        status=LeaseStatus.ACTIVE,
        max_requests=5,
    )


def test_gateway_allows_lab_loopback_get():
    plan = _plan()
    decision = authorize_gateway_request(
        plan=plan,
        lease=_lease(plan),
        request=GatewayAuthorizeRequest(
            url="http://127.0.0.1:8080/api/items",
            method="GET",
            resolved_ips=("127.0.0.1",),
        ),
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        admitted_asset_id="asset_loopback",
        current_scope_snapshot_digest=plan.scope_snapshot_digest,
        asset_identity_digest_current=True,
    )
    assert decision.status is GatewayDecisionStatus.ALLOWED


def test_gateway_blocks_cross_scope_redirect_and_public_ip():
    plan = _plan()
    lease = _lease(plan)
    redirect = authorize_gateway_request(
        plan=plan,
        lease=lease,
        request=GatewayAuthorizeRequest(
            url="http://evil.example:8080/api",
            method="GET",
            is_redirect=True,
            resolved_ips=("203.0.113.5",),
        ),
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        admitted_asset_id="asset_loopback",
        current_scope_snapshot_digest=plan.scope_snapshot_digest,
        asset_identity_digest_current=True,
    )
    assert redirect.status is GatewayDecisionStatus.BLOCKED
    assert redirect.outcome_class in {
        GatewayOutcomeClass.OFF_SCOPE_REDIRECT,
        GatewayOutcomeClass.SCOPE_ESCAPE,
        GatewayOutcomeClass.DNS_REBIND,
    }


def test_gateway_enforces_segment_bounded_canonical_path_authority():
    plan = _plan()
    lease = _lease(plan)
    for path in ("/api2", "/api/%2e%2e/admin"):
        decision = authorize_gateway_request(
            plan=plan,
            lease=lease,
            request=GatewayAuthorizeRequest(
                url=f"http://127.0.0.1:8080{path}",
                method="GET",
                resolved_ips=("127.0.0.1",),
            ),
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
            admitted_asset_id="asset_loopback",
            current_scope_snapshot_digest=plan.scope_snapshot_digest,
            asset_identity_digest_current=True,
        )
        assert decision.status is GatewayDecisionStatus.BLOCKED
        assert decision.reason == "path_not_authorized"
        assert decision.outcome_class is GatewayOutcomeClass.SCOPE_ESCAPE


def test_waf_parks_branch_only():
    outcome = classify_response_outcome(
        status_code=403,
        response_bytes=100,
        max_response_bytes=1000,
        body_markers={"waf", "captcha"},
    )
    assert outcome is GatewayOutcomeClass.WAF_CAPTCHA
    assert outcome_to_branch_action(outcome) is GatewayDecisionStatus.PARK_BRANCH


def test_third_party_and_size_ceiling():
    assert (
        classify_response_outcome(
            status_code=200,
            response_bytes=10,
            max_response_bytes=1000,
            body_markers={"third_party"},
        )
        is GatewayOutcomeClass.THIRD_PARTY_DATA
    )
    assert (
        classify_response_outcome(
            status_code=200,
            response_bytes=5000,
            max_response_bytes=1000,
        )
        is GatewayOutcomeClass.SIZE_CEILING
    )
