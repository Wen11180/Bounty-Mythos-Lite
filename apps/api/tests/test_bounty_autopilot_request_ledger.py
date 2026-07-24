"""Phase 4 request ledger tests."""

from __future__ import annotations

from app.bounty_autopilot.contracts import RecipeRef, RiskTier
from app.bounty_autopilot.leases import ExecutionLease, LeaseStatus
from app.bounty_autopilot.request_ledger import (
    RequestLedger,
    RequestReservation,
    RequestReservationStatus,
)
from app.bounty_autopilot.recipes import default_recipe_registry


def _digest(n: str = "a") -> str:
    return "sha256:" + (n * 64)


def _lease() -> ExecutionLease:
    return ExecutionLease(
        lease_id="lease_1",
        plan_id="plan_1",
        plan_digest=_digest("e"),
        campaign_id="campaign_1",
        authorization_digest=_digest("a"),
        scope_snapshot_digest=_digest("b"),
        asset_id="asset_1",
        branch_id="branch_1",
        recipe_ref=default_recipe_registry().require(
            "lab_browser_mapping", "1.0.0"
        ).ref,
        risk_tier=RiskTier.R1,
        status=LeaseStatus.ACTIVE,
        max_requests=2,
        requests_reserved=0,
    )


def _reservation(**updates) -> RequestReservation:
    payload = {
        "reservation_id": "res_1",
        "lease_id": "lease_1",
        "plan_id": "plan_1",
        "plan_digest": _digest("e"),
        "destination_host": "127.0.0.1",
        "destination_port": 8080,
        "destination_path": "/x",
        "method": "GET",
        "mutation_class": "none",
        "idempotency_key": "idem_1",
        "remaining_request_budget": 1,
    }
    payload.update(updates)
    return RequestReservation(**payload)


def test_reservation_binds_lease_plan_destination_and_idempotency():
    ledger = RequestLedger()
    reserved = ledger.reserve(lease=_lease(), reservation=_reservation())
    assert reserved.status is RequestReservationStatus.RESERVED
    again = ledger.reserve(lease=_lease(), reservation=_reservation(reservation_id="res_dup"))
    assert again.reservation_id == "res_1"


def test_completion_idempotent_and_uncertain_mutation_awaits_human():
    ledger = RequestLedger()
    ledger.reserve(lease=_lease(), reservation=_reservation())
    first = ledger.complete("res_1", outcome=RequestReservationStatus.COMPLETED)
    second = ledger.complete("res_1", outcome=RequestReservationStatus.COMPLETED)
    assert first.status is second.status is RequestReservationStatus.COMPLETED

    ledger.reserve(
        lease=_lease(),
        reservation=_reservation(
            reservation_id="res_mut",
            idempotency_key="idem_mut",
            method="POST",
            mutation_class="write",
        ),
    )
    uncertain = ledger.complete(
        "res_mut", outcome=RequestReservationStatus.AWAITING_HUMAN
    )
    assert uncertain.status is RequestReservationStatus.AWAITING_HUMAN
    assert ledger.may_retry("res_mut", method="POST") is False


def test_idempotent_read_may_retry_after_no_send_failure():
    ledger = RequestLedger()
    ledger.reserve(lease=_lease(), reservation=_reservation())
    ledger.complete("res_1", outcome=RequestReservationStatus.NO_SEND_FAILURE)
    assert ledger.may_retry("res_1", method="GET") is True


def test_no_raw_secret_fields_on_reservation():
    reserved = _reservation()
    dumped = reserved.model_dump()
    for key in ("cookie", "authorization", "password", "token", "body", "headers"):
        assert key not in dumped
