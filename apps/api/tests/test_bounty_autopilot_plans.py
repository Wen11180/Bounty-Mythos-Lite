"""Phase 4 immutable plan tests."""

from __future__ import annotations

import pytest

from app.bounty_autopilot.contracts import MutationInventory, RecipeRef, RiskTier
from app.bounty_autopilot.plans import build_validation_plan, compute_plan_digest
from app.bounty_autopilot.recipes import default_recipe_registry


def _digest(n: str = "a") -> str:
    return "sha256:" + (n * 64)


def _mutation() -> MutationInventory:
    return default_recipe_registry().require(
        "lab_browser_mapping", "1.0.0"
    ).mutation_inventory


def _plan(**updates):
    payload = {
        "plan_id": "plan_1",
        "campaign_id": "campaign_1",
        "authorization_digest": _digest("a"),
        "scope_snapshot_digest": _digest("b"),
        "asset_id": "asset_loopback",
        "destination_scheme": "http",
        "destination_host": "127.0.0.1",
        "destination_port": 8080,
        "destination_path": "/api",
        "branch_id": "branch_1",
        "account_aliases": ("account_a",),
        "risk_tier": RiskTier.R1,
        "recipe_ref": default_recipe_registry()
        .require("lab_browser_mapping", "1.0.0")
        .ref,
        "methods": ("GET",),
        "mutation_inventory": _mutation(),
        "max_requests": 5,
        "max_response_bytes": 10000,
        "max_duration_seconds": 60,
        "rollback_plan": "close_browser_context",
        "stop_conditions": ("waf_detected", "scope_escape"),
        "tool_profile": "lab_browser",
        "container_profile": "lab_pod_readonly",
    }
    payload.update(updates)
    return build_validation_plan(**payload)


def test_plan_binds_required_fields_and_digest():
    plan = _plan()
    assert plan.plan_digest.startswith("sha256:")
    assert plan.candidate_promotion_allowed is False
    assert plan.report_submission_allowed is False
    assert compute_plan_digest(plan) == plan.plan_digest


def test_changing_bound_field_changes_digest():
    plan_a = _plan(destination_path="/api")
    plan_b = _plan(destination_path="/api/v2")
    assert plan_a.plan_digest != plan_b.plan_digest


def test_r4_plan_impossible():
    with pytest.raises(ValueError, match="r4_plan_impossible"):
        _plan(risk_tier=RiskTier.R4)
