"""Third-party discard and secret redaction canaries."""

from datetime import UTC, datetime

from app.bounty_autopilot.gateway import GatewayOutcomeClass
from app.bounty_autopilot.observations import EndpointIdentity, ObservationGrade, ObservationSummaryCode, build_observation
from app.bounty_autopilot.recipes import default_recipe_registry
from app.bounty_autopilot.response_guard import inspect_response_bytes, project_response, redact_text


def test_third_party_content_is_discarded_before_persistence_projection():
    recipe = default_recipe_registry().require("lab_browser_mapping", "1.0.0")
    obs = build_observation(
        observation_id="obs_tp",
        campaign_id="lab",
        authorization_id="auth_1",
        authorization_digest="sha256:" + ("a" * 64),
        scope_snapshot_digest="sha256:" + ("b" * 64),
        asset_id="asset_1",
        asset_identity_digest="sha256:" + ("c" * 64),
        branch_id="branch_tp",
        plan_id="plan_1",
        plan_digest="sha256:" + ("d" * 64),
        risk_decision_id="risk_1",
        risk_tier="R1",
        recipe_ref=recipe.ref,
        lease_id="lease_1",
        reservation_id="request_1",
        session_generation=1,
        tool_run_id="toolrun_1",
        endpoint=EndpointIdentity(method="GET", route_template="/third-party"),
        occurred_at=datetime.now(UTC),
        outcome_class=GatewayOutcomeClass.THIRD_PARTY_DATA,
        summary_code=ObservationSummaryCode.REQUEST_BLOCKED,
        grade=ObservationGrade.L3_ACTIONABLE,
        evidence_refs=("evidence_1",),
    )
    assert obs.third_party_data_discarded is True
    assert obs.raw_content_retained is False
    assert obs.evidence_refs == ()
    assert obs.summary_code is ObservationSummaryCode.THIRD_PARTY_DATA_DISCARDED
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

    inspected = inspect_response_bytes(
        observation_id="obs_stream",
        status_code=200,
        content_type="application/json",
        chunks=(b'{"third_party": true, "value":"must-discard"}',),
        max_response_bytes=1024,
    )
    assert inspected.third_party_data_discarded is True
    assert inspected.redacted_excerpt == ""
    assert inspected.byte_length == 0


def test_secret_canaries_are_redacted():
    text = "Authorization: Bearer super-secret\nCookie: session=abc\npassword=hunter2"
    redacted = redact_text(text)
    assert "super-secret" not in redacted
    assert "session=abc" not in redacted
    assert "hunter2" not in redacted
    assert "[REDACTED]" in redacted


def test_session_and_pii_canaries_stop_before_any_projection_is_retained():
    inspected = inspect_response_bytes(
        observation_id="obs_sensitive",
        status_code=200,
        content_type="application/json",
        chunks=(
            b'{"sessionid":"supersecret","email":"real.user@example.test"}',
        ),
        max_response_bytes=1024,
    )
    assert inspected.outcome_class is GatewayOutcomeClass.THIRD_PARTY_DATA
    assert inspected.third_party_data_discarded is True
    assert inspected.byte_length == 0
    assert inspected.redacted_excerpt == ""

    multiline_marker = inspect_response_bytes(
        observation_id="obs_multiline_marker",
        status_code=200,
        content_type="application/json",
        chunks=(b'{"third_party":\n true,"value":"discard"}',),
        max_response_bytes=1024,
    )
    assert multiline_marker.outcome_class is GatewayOutcomeClass.THIRD_PARTY_DATA
