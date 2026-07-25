"""Phase 8 observation tests."""

from app.bounty_autopilot.gateway import GatewayOutcomeClass
from app.bounty_autopilot.observations import (
    AutopilotObservationInput,
    ObservationGrade,
    build_observation,
)


def test_third_party_observation_discards_content():
    obs = build_observation(
        observation_id="obs_1",
        campaign_id="c1",
        branch_id="b1",
        plan_digest="sha256:" + ("a" * 64),
        outcome_class=GatewayOutcomeClass.THIRD_PARTY_DATA,
        summary="should_discard",
        grade=ObservationGrade.L2_CORROBORATED,
        evidence_refs=("x",),
    )
    assert obs.third_party_data_discarded is True
    assert obs.evidence_refs == ()
    assert obs.raw_content_retained is False


def test_r2_differential_observation_binds_two_reservations_with_only_metadata():
    observation = AutopilotObservationInput(
        observation_id="obs_r2",
        branch_id="branch_r2",
        plan_digest="sha256:" + ("a" * 64),
        lease_id="lease_r2",
        reservation_id="res_account_a",
        comparison_reservation_id="res_account_b",
        receipt_digest="sha256:" + ("b" * 64),
        comparison_receipt_digest="sha256:" + ("c" * 64),
        outcome_class=GatewayOutcomeClass.OK,
        summary="owned_account_differential_metadata_only",
        status_class="2xx",
        content_type_class="json",
        byte_length=42,
        comparison_status_class="4xx",
        comparison_content_type_class="json",
        comparison_byte_length=17,
        difference_labels=(
            "status_class_different",
            "content_type_class_same",
            "byte_length_different",
        ),
    )

    dumped = observation.model_dump(mode="json")
    assert dumped["comparison_reservation_id"] == "res_account_b"
    assert dumped["difference_labels"] == [
        "status_class_different",
        "content_type_class_same",
        "byte_length_different",
    ]
    assert "body" not in dumped
    assert "headers" not in dumped
