"""Phase 5 response guard tests."""

from app.bounty_autopilot.gateway import GatewayOutcomeClass
from app.bounty_autopilot.response_guard import project_response, redact_text


def test_redacts_secrets_and_never_marks_raw_secret_retained():
    text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.aaa.bbb password=supersecret"
    redacted = redact_text(text)
    assert "supersecret" not in redacted
    assert "Bearer" not in redacted or "[REDACTED]" in redacted
    obs = project_response(
        observation_id="obs_1",
        outcome_class=GatewayOutcomeClass.OK,
        status_code=200,
        content_type="application/json",
        body_preview=text,
        byte_length=len(text),
    )
    assert obs.raw_secret_retained is False
    assert obs.report_submission_allowed is False


def test_third_party_discard_clears_excerpt():
    obs = project_response(
        observation_id="obs_2",
        outcome_class=GatewayOutcomeClass.THIRD_PARTY_DATA,
        status_code=200,
        content_type="text/html",
        body_preview="foreign user email a@b.c",
        byte_length=100,
    )
    assert obs.third_party_data_discarded is True
    assert obs.redacted_excerpt == ""
    assert obs.byte_length == 0
