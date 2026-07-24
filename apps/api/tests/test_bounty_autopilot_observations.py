"""Phase 8 observation tests."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from app.bounty_autopilot.contracts import RiskTier
from app.bounty_autopilot.gateway import GatewayOutcomeClass
from app.bounty_autopilot.observations import (
    EndpointIdentity,
    HumanEvidenceGrade,
    HumanEvidenceReview,
    HumanReviewDecision,
    ObservationGrade,
    ObservationSummaryCode,
    build_observation,
)
from app.bounty_autopilot.recipes import default_recipe_registry


def _lineage() -> dict:
    recipe = default_recipe_registry().require(
        "lab_two_account_authorization_differential", "1.0.0"
    )
    return {
        "campaign_id": "c1",
        "authorization_id": "auth_1",
        "authorization_digest": "sha256:" + ("a" * 64),
        "scope_snapshot_digest": "sha256:" + ("b" * 64),
        "asset_id": "asset_1",
        "asset_identity_digest": "sha256:" + ("c" * 64),
        "branch_id": "b1",
        "plan_id": "plan_1",
        "plan_digest": "sha256:" + ("d" * 64),
        "risk_decision_id": "risk_1",
        "risk_tier": RiskTier.R2,
        "recipe_ref": recipe.ref,
        "lease_id": "lease_1",
        "reservation_id": "request_1",
        "session_generation": 1,
        "tool_run_id": "toolrun_1",
        "endpoint": EndpointIdentity(method="GET", route_template="/objects/{owned_object}"),
        "occurred_at": datetime.now(UTC),
    }


def test_third_party_observation_discards_content():
    obs = build_observation(
        observation_id="obs_1",
        **_lineage(),
        outcome_class=GatewayOutcomeClass.THIRD_PARTY_DATA,
        summary_code=ObservationSummaryCode.OWNED_ACCOUNT_DIFFERENTIAL,
        grade=ObservationGrade.L2_CORROBORATED,
        evidence_refs=("evidence_1",),
    )
    assert obs.third_party_data_discarded is True
    assert obs.evidence_refs == ()
    assert obs.grade is ObservationGrade.L0_NOISE
    assert obs.discard_completed is True
    assert obs.raw_content_retained is False


def test_l4_l5_require_an_explicit_bounded_human_review_record():
    review = HumanEvidenceReview(
        review_id="human_review_1",
        campaign_id="c1",
        hypothesis_id="hypothesis_1",
        observation_ids=("obs_1",),
        grade=HumanEvidenceGrade.L4_HUMAN_VERIFIED,
        decision=HumanReviewDecision.VERIFIED,
        reviewer_alias="operator_alpha",
        reviewed_at=datetime.now(UTC),
    )
    assert review.automated_source is False
    assert review.report_submission_allowed is False

    with pytest.raises(ValidationError):
        HumanEvidenceReview(
            **review.model_dump(),
            raw_response_body="not allowed",
        )


def test_l3_requires_a_sanitized_owned_differential_and_evidence_refs():
    with pytest.raises(ValidationError, match="l3_owned_differential_required"):
        build_observation(
            observation_id="obs_blocked_l3",
            **_lineage(),
            outcome_class=GatewayOutcomeClass.RATE_LIMIT,
            summary_code=ObservationSummaryCode.RATE_LIMITED,
            grade=ObservationGrade.L3_ACTIONABLE,
            evidence_refs=("evidence_1",),
        )

    with pytest.raises(ValidationError, match="l3_evidence_refs_required"):
        build_observation(
            observation_id="obs_missing_evidence",
            **_lineage(),
            outcome_class=GatewayOutcomeClass.OK,
            summary_code=ObservationSummaryCode.OWNED_ACCOUNT_DIFFERENTIAL,
            grade=ObservationGrade.L3_ACTIONABLE,
        )
