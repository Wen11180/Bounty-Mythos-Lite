"""Loopback lab HTTP fixture server integration."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from urllib.request import urlopen

from app.bounty_autopilot.contracts import MutationInventory, PolicyMode, RecipeRef, RiskTier
from app.bounty_autopilot.gateway import (
    GatewayAuthorizeRequest,
    GatewayDecisionStatus,
    authorize_gateway_request,
)
from app.bounty_autopilot.leases import issue_execution_lease
from app.bounty_autopilot.plans import build_validation_plan
from app.bounty_autopilot.recipes import default_recipe_registry
from app.bounty_autopilot.request_ledger import (
    RequestLedger,
    RequestReservation,
    RequestReservationStatus,
)


def _digest(n: str = "a") -> str:
    return "sha256:" + (n * 64)


def _load_lab_server():
    server_path = (
        Path(__file__).resolve().parent / "fixtures" / "bounty_autopilot_lab" / "server.py"
    )
    spec = importlib.util.spec_from_file_location("bounty_autopilot_lab_server", server_path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_lab_server_is_loopback_and_serves_matrix_behaviors():
    mod = _load_lab_server()
    manifest = mod.load_lab_manifest()
    assert manifest["loopback_only"] is True
    server = mod.start_lab_target(port=0)
    try:
        assert server.host in {"127.0.0.1", "localhost"}
        with urlopen(f"{server.base_url}/public/health", timeout=2) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        assert payload["ok"] is True
        with urlopen(f"{server.base_url}/api/docs/1", timeout=2) as resp:
            doc = json.loads(resp.read().decode("utf-8"))
        assert doc["owner"] == "account_a"
    finally:
        server.stop()


def test_gateway_allows_only_plan_bound_loopback_against_live_lab_server():
    mod = _load_lab_server()
    server = mod.start_lab_target(port=0)
    try:
        plan = build_validation_plan(
            plan_id="plan_live",
            campaign_id="lab",
            authorization_digest=_digest("a"),
            scope_snapshot_digest=_digest("b"),
            asset_id="asset_lab",
            destination_scheme="http",
            destination_host="127.0.0.1",
            destination_port=server.port,
            destination_path="/api/docs/1",
            branch_id="branch_lab",
            account_aliases=("account_a", "account_b"),
            risk_tier=RiskTier.R1,
            recipe_ref=default_recipe_registry().require(
                "lab_two_account_authorization_differential", "1.0.0"
            ).ref,
            methods=("GET",),
            mutation_inventory=default_recipe_registry().require(
                "lab_two_account_authorization_differential", "1.0.0"
            ).mutation_inventory,
            max_requests=2,
            max_response_bytes=10000,
            max_duration_seconds=30,
            rollback_plan="close_context",
            stop_conditions=("waf", "third_party"),
            tool_profile="lab_browser",
            container_profile="lab_pod",
        )
        lease_result = issue_execution_lease(
            plan=plan,
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
            authorization_recipe_allowed=True,
            authorization_digest=plan.authorization_digest,
            scope_snapshot_digest=plan.scope_snapshot_digest,
            lease_id="lease_live",
            now_iso="2026-07-24T00:00:00+00:00",
        )
        assert lease_result.allowed and lease_result.lease is not None
        lease = lease_result.lease
        ledger = RequestLedger()
        reservation = ledger.reserve(
            lease=lease,
            reservation=RequestReservation(
                reservation_id="res_live",
                lease_id=lease.lease_id,
                plan_id=plan.plan_id,
                plan_digest=plan.plan_digest,
                destination_host="127.0.0.1",
                destination_port=server.port,
                destination_path="/api/docs/1",
                method="GET",
                mutation_class="none",
                idempotency_key="idem_live",
                remaining_request_budget=1,
            ),
        )
        decision = authorize_gateway_request(
            plan=plan,
            lease=lease,
            request=GatewayAuthorizeRequest(
                url=f"http://127.0.0.1:{server.port}/api/docs/1",
                method="GET",
                resolved_ips=("127.0.0.1",),
            ),
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
            admitted_asset_id="asset_lab",
            current_scope_snapshot_digest=plan.scope_snapshot_digest,
            asset_identity_digest_current=True,
        )
        assert decision.status is GatewayDecisionStatus.ALLOWED
        with urlopen(f"{server.base_url}/api/docs/1", timeout=2) as resp:
            assert resp.status == 200
        ledger.complete(reservation.reservation_id, outcome=RequestReservationStatus.COMPLETED)

        blocked = authorize_gateway_request(
            plan=plan,
            lease=lease,
            request=GatewayAuthorizeRequest(
                url="http://evil.example/api/docs/1",
                method="GET",
                resolved_ips=("93.184.216.34",),
            ),
            policy_mode=PolicyMode.AUTHORIZED_LOCAL_LAB,
            admitted_asset_id="asset_lab",
            current_scope_snapshot_digest=plan.scope_snapshot_digest,
            asset_identity_digest_current=True,
        )
        assert blocked.status is GatewayDecisionStatus.BLOCKED
    finally:
        server.stop()
