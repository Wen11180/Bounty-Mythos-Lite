"""Phase 6 session projection tests."""

from app.bounty_autopilot.session_projection import (
    LoginStateClass,
    project_session_handle,
    revoke_handle,
)


def test_projection_has_no_secret_fields():
    proj = project_session_handle(
        handle_id="hdl_abc12345",
        campaign_id="campaign_1",
        account_alias="account_a",
        role_label="user",
        login_state=LoginStateClass.LOGGED_IN,
        generation=1,
        pod_id="pod_1",
    )
    dumped = proj.model_dump()
    for key in ("password", "cookie", "token", "authorization", "secret"):
        assert key not in dumped
    assert proj.raw_secret_present is False
    revoked = revoke_handle(proj)
    assert revoked.revoked is True
