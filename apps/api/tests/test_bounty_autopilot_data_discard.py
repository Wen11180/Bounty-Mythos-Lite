"""Third-party discard and secret redaction canaries."""

from app.bounty_autopilot.gateway import GatewayOutcomeClass
from app.bounty_autopilot.observations import ObservationGrade, build_observation
from app.bounty_autopilot.response_guard import project_response, redact_text


def test_third_party_content_is_discarded_before_persistence_projection():
    obs = build_observation(
        observation_id="obs_tp",
        campaign_id="lab",
        branch_id="branch_tp",
        plan_digest="sha256:" + ("a" * 64),
        outcome_class=GatewayOutcomeClass.THIRD_PARTY_DATA,
        summary="should_be_replaced",
        grade=ObservationGrade.L3_ACTIONABLE,
        evidence_refs=("ref1",),
    )
    assert obs.third_party_data_discarded is True
    assert obs.raw_content_retained is False
    assert obs.evidence_refs == ()
    assert obs.summary == "third_party_data_discarded"
    assert obs.report_submission_allowed is False

    projected = project_response(
        observation_id="obs_tp",
        outcome_class=GatewayOutcomeClass.THIRD_PARTY_DATA,
        status_code=200,
        content_type="application/javascript",
        body_preview="track('user@example.com', 'cookie=abc')",
        byte_length=999,
    )
    assert projected.third_party_data_discarded is True
    assert projected.redacted_excerpt == ""
    assert projected.byte_length == 0
    assert projected.raw_secret_retained is False


def test_secret_canaries_are_redacted():
    text = "Authorization: Bearer super-secret\nCookie: session=abc\npassword=hunter2"
    redacted = redact_text(text)
    assert "super-secret" not in redacted
    assert "session=abc" not in redacted
    assert "hunter2" not in redacted
    assert "[REDACTED]" in redacted
