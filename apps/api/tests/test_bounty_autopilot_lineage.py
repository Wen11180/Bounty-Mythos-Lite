"""Strict contracts for durable Autopilot release lineage."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.bounty_autopilot.gateway import GatewayOutcomeClass
from app.bounty_autopilot.lineage import (
    AutopilotRiskDecisionRecord,
    AutopilotToolRunRecord,
)
from app.bounty_autopilot.recipes import default_recipe_registry


def _digest(character: str) -> str:
    return "sha256:" + (character * 64)


def _tool_run_fields() -> dict:
    recipe = default_recipe_registry().require("lab_browser_mapping", "1.0.0")
    return {
        "tool_run_id": "toolrun_1",
        "campaign_id": "campaign_1",
        "authorization_id": "campauth_1",
        "authorization_digest": _digest("a"),
        "scope_snapshot_digest": _digest("b"),
        "asset_id": "asset_1",
        "asset_identity_digest": _digest("c"),
        "branch_id": "branch_1",
        "plan_id": "plan_1",
        "plan_digest": _digest("d"),
        "risk_decision_id": "risk_1",
        "risk_tier": "R1",
        "recipe_ref": recipe.ref,
        "lease_id": "lease_1",
        "reservation_id": "request_1",
        "session_generation": 1,
        "isolation_profile": "docker",
        "gateway_decision": "allowed",
        "request_sent": True,
        "run_status": "completed",
        "outcome_class": GatewayOutcomeClass.OK,
        "outcome_code": "owned_response_projected",
        "occurred_at": datetime.now(UTC),
    }


def test_tool_run_contract_has_complete_lineage_and_no_raw_payload_slot():
    record = AutopilotToolRunRecord(**_tool_run_fields())
    assert record.raw_content_retained is False
    assert record.raw_secret_retained is False
    assert record.request_content_retained is False
    assert record.response_content_retained is False

    with pytest.raises(ValidationError):
        AutopilotToolRunRecord(
            **_tool_run_fields(),
            response_body="not persistable",
        )


def test_tool_run_cannot_represent_r4_or_send_after_a_gateway_block():
    with pytest.raises(ValidationError, match="r4_tool_run_impossible"):
        AutopilotToolRunRecord(**{**_tool_run_fields(), "risk_tier": "R4"})

    with pytest.raises(ValidationError, match="gateway_block_must_stop_before_send"):
        AutopilotToolRunRecord(
            **{
                **_tool_run_fields(),
                "gateway_decision": "blocked",
                "run_status": "blocked",
            }
        )


def test_risk_contract_keeps_r4_prohibited_and_r3_approval_bound():
    recipe = default_recipe_registry().require("lab_browser_mapping", "1.0.0")
    common = {
        "risk_decision_id": "risk_1",
        "campaign_id": "campaign_1",
        "authorization_id": "campauth_1",
        "authorization_digest": _digest("a"),
        "scope_snapshot_digest": _digest("b"),
        "asset_id": "asset_1",
        "branch_id": "branch_1",
        "recipe_ref": recipe.ref,
        "reason_code": "server_classification",
        "decided_at": datetime.now(UTC),
    }
    prohibited = AutopilotRiskDecisionRecord(
        **common,
        risk_tier="R4",
        status="prohibited",
    )
    assert prohibited.execution_authorized is False

    with pytest.raises(ValidationError, match="r4_decision_must_be_prohibited"):
        AutopilotRiskDecisionRecord(
            **common,
            risk_tier="R4",
            status="authorized",
        )
    with pytest.raises(ValidationError, match="r3_decision_requires_exact_approval"):
        AutopilotRiskDecisionRecord(
            **common,
            risk_tier="R3",
            status="authorized",
        )
