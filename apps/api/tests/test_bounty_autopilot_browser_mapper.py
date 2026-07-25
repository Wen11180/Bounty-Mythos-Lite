"""Phase 7 browser mapper tests."""

from app.bounty_autopilot.browser_mapper import WorkflowActionClass, build_authz_workflow


def test_two_owned_account_workflow_mapping():
    wf = build_authz_workflow(
        workflow_id="wf_1",
        actor_alias="account_a",
        actor_role="user",
        owner_alias="account_b",
        object_type="document",
        method="get",
        path_template="/api/docs/{id}",
        recipe_id="lab_two_owned_account_readonly_authz",
        recipe_version="1.0",
        action_class=WorkflowActionClass.READ,
    )
    assert wf.requires_two_accounts is True
    assert wf.action.method == "GET"
    assert wf.obj.owner_alias == "account_b"
