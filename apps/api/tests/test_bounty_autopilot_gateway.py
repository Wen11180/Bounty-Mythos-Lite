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


def _digest(n="a"):
    return "sha256:" + (n * 64)


def _plan(destination_host="127.0.0.1"):
    return build_validation_plan(
        plan_id="plan_1",
        campaign_id="campaign_1",
        authorization_digest=_digest("a"),
        scope_snapshot_digest=_digest("b"),
        asset_id="asset_loopback",
        destination_scheme="http",
        destination_host=destination_host,
        destination_port=8080,
        destination_path="/api",
        branch_id="branch_1",
        risk_tier=RiskTier.R1,
        recipe_ref=RecipeRef(recipe_id="lab_browser_mapping", version="1.0"),
        methods=("GET", "HEAD"),
        mutation_inventory=MutationInventory(
            methods=("GET", "HEAD"),
            mutates_state=False,
            reversible=True,
            requires_owned_accounts=False,
        ),
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


def _r2_plan():
    return build_validation_plan(
        plan_id="plan_r2",
        campaign_id="campaign_1",
        authorization_digest=_digest("a"),
        scope_snapshot_digest=_digest("b"),
        asset_id="asset_loopback",
        destination_scheme="http",
        destination_host="127.0.0.1",
        destination_port=8080,
        destination_path="/api",
        branch_id="branch_r2",
        account_aliases=("account_a", "account_b"),
        risk_tier=RiskTier.R2,
        recipe_ref=RecipeRef(
            recipe_id="lab_two_owned_account_readonly_authz",
            version="1.0",
        ),
        methods=("GET", "HEAD", "OPTIONS"),
        mutation_inventory=MutationInventory(
            methods=("GET", "HEAD", "OPTIONS"),
            mutates_state=False,
            reversible=True,
            requires_owned_accounts=True,
        ),
        max_requests=2,
        max_response_bytes=1000,
        max_duration_seconds=30,
        rollback_plan="close",
        stop_conditions=("waf",),
        tool_profile="lab",
        container_profile="lab",
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


def test_gateway_blocks_private_network_destination_in_loopback_lab():
    plan = _plan(destination_host="192.168.1.10")
    decision = authorize_gateway_request(
        plan=plan,
        lease=_lease(plan),
        request=GatewayAuthorizeRequest(
            url="http://192.168.1.10:8080/api/items",
            method="GET",
            resolved_ips=("192.168.1.10",),
        ),
        policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
        admitted_asset_id="asset_loopback",
        current_scope_snapshot_digest=plan.scope_snapshot_digest,
        asset_identity_digest_current=True,
    )

    assert decision.status is GatewayDecisionStatus.BLOCKED
    assert decision.reason == "non_loopback_destination"
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


def test_gateway_rejects_unbound_query_fragment_and_encoded_paths():
    plan = _plan()
    for suffix in ("?op=delete", "#hidden", "%2Fother", "/../other"):
        decision = authorize_gateway_request(
            plan=plan,
            lease=_lease(plan),
            request=GatewayAuthorizeRequest(
                url=f"http://127.0.0.1:8080/api{suffix}",
                method="GET",
                resolved_ips=("127.0.0.1",),
            ),
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
            admitted_asset_id="asset_loopback",
            current_scope_snapshot_digest=plan.scope_snapshot_digest,
            asset_identity_digest_current=True,
        )
        assert decision.status is GatewayDecisionStatus.BLOCKED
        assert decision.outcome_class is GatewayOutcomeClass.SCOPE_ESCAPE


def test_r2_gateway_requires_one_of_the_fixed_owned_account_aliases():
    plan = _r2_plan()
    common = {
        "url": "http://127.0.0.1:8080/api/docs/1",
        "method": "GET",
        "resolved_ips": ("127.0.0.1",),
    }
    kwargs = {
        "plan": plan,
        "lease": _lease(plan),
        "policy_mode": PolicyMode.AUTHORIZED_LOCAL_LAB,
        "admitted_asset_id": "asset_loopback",
        "current_scope_snapshot_digest": plan.scope_snapshot_digest,
        "asset_identity_digest_current": True,
    }

    missing = authorize_gateway_request(
        request=GatewayAuthorizeRequest(**common, account_alias=None),
        **kwargs,
    )
    assert missing.status is GatewayDecisionStatus.BLOCKED
    assert missing.reason == "r2_account_alias_required"

    wrong_alias = authorize_gateway_request(
        request=GatewayAuthorizeRequest(**common, account_alias="account_other"),
        **kwargs,
    )
    assert wrong_alias.status is GatewayDecisionStatus.BLOCKED
    assert wrong_alias.reason == "r2_account_alias_not_allowed"

    allowed = authorize_gateway_request(
        request=GatewayAuthorizeRequest(**common, account_alias="account_a"),
        **kwargs,
    )
    assert allowed.status is GatewayDecisionStatus.ALLOWED
