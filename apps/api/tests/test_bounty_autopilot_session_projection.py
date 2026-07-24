"""Phase 6 session projection tests."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from app.bounty_autopilot.session_projection import (
    LoginStateClass,
    project_session_handle,
    revoke_handle,
)


def test_projection_has_no_secret_fields():
    proj = project_session_handle(
        handle_id="hdl_" + ("a" * 48),
        campaign_id="campaign_1",
        account_alias="account_a",
        login_state=LoginStateClass.LOGGED_IN,
        generation=1,
        pod_id="pod_1",
        issued_at=datetime.now(UTC),
        expires_at=datetime.now(UTC) + timedelta(minutes=15),
    )
    dumped = proj.model_dump()
    for key in ("password", "cookie", "token", "authorization", "secret"):
        assert key not in dumped
    assert proj.raw_secret_present is False
    revoked = revoke_handle(proj)
    assert revoked.revoked is True


def test_projection_requires_opaque_handle_and_bounded_expiry():
    now = datetime.now(UTC)
    with pytest.raises(ValidationError):
        project_session_handle(
            handle_id="raw-cookie",
            campaign_id="campaign_1",
            account_alias="account_a",
            login_state="logged_in",
            generation=1,
            pod_id="pod_1",
            issued_at=now,
            expires_at=now + timedelta(hours=2),
        )
