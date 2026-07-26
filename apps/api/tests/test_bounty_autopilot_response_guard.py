"""Phase 5 response guard tests."""

import pytest

from app.bounty_autopilot import response_guard
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


@pytest.mark.parametrize(
    ("text", "secret"),
    (
        ('{"token":"json-token-secret"}', "json-token-secret"),
        ('{"nested":{"password":"nested-password-secret"}}', "nested-password-secret"),
        (r'{"\u0063lient_secret":"escaped-client-secret"}', "escaped-client-secret"),
        ("token[primary]=form-token-secret", "form-token-secret"),
        ("api_key.value=query-api-key-secret", "query-api-key-secret"),
        ("refresh_token: refresh-token-secret", "refresh-token-secret"),
        ("Bearer bearer-token-secret", "bearer-token-secret"),
    ),
)
def test_redacts_structured_and_encoded_secret_values(text, secret):
    redacted = redact_text(text)

    assert redacted == "[REDACTED]"
    assert secret not in redacted


def test_preserves_safe_short_excerpt():
    assert redact_text('{"status":"ok","count":2}') == '{"status":"ok","count":2}'


def test_deep_json_fails_closed_without_recursion_error():
    text = '{"a":' * 1_100 + '""' + '}' * 1_100

    assert len(text) < 8_192
    assert redact_text(text) == "[REDACTED]"


def test_json_parser_recursion_error_fails_closed(monkeypatch):
    def raise_recursion_error(_value):
        raise RecursionError("depth")

    monkeypatch.setattr(response_guard.json, "loads", raise_recursion_error)

    assert redact_text('{"status":"ok"}') == "[REDACTED]"


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
