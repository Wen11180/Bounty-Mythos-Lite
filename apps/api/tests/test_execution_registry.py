from app.execution_registry import (
    ExecutionAuthorizationRequest,
    ExecutionRegistry,
    ToolCapability,
    authorize_tool_execution,
    default_execution_registry,
)
from app.scope_guard import ScopeGuardRule


def _rule(*, allowed_validation: list[str], human_approval_required: bool = False):
    return ScopeGuardRule(
        asset="api.example.test",
        scope_status="in_scope",
        automation="limited",
        allowed_validation=allowed_validation,
        forbidden=[],
        human_approval_required=human_approval_required,
    )


def test_known_local_tool_is_eligible_only_when_campaign_and_scope_allow_it():
    decision = authorize_tool_execution(
        ExecutionAuthorizationRequest(
            tool_id="semgrep_local",
            asset="api.example.test",
            campaign_allowed_tools=["static_analyzer"],
            scope_rule=_rule(allowed_validation=["static_analyzer"]),
            human_approved=True,
        )
    )

    assert decision.eligible is True
    assert decision.reason == "eligible"
    assert decision.capability.tool_id == "semgrep_local"
    assert decision.execution_tier == "local"
    assert decision.network_access is False
    assert decision.requires_execution_lease is False
    assert decision.candidate_promotion_allowed is False
    assert decision.report_submission_allowed is False


def test_dependency_sbom_local_is_offline_static_analysis_only():
    decision = authorize_tool_execution(
        ExecutionAuthorizationRequest(
            tool_id="dependency_sbom_local",
            asset="api.example.test",
            campaign_allowed_tools=["dependency_sbom_local"],
            scope_rule=_rule(allowed_validation=["static_analyzer"]),
            human_approved=True,
        )
    )

    assert decision.eligible is True
    assert decision.execution_tier == "local"
    assert decision.network_access is False
    assert decision.candidate_promotion_allowed is False
    assert decision.report_submission_allowed is False


def test_campaign_allowlist_blocks_known_tool_before_execution():
    decision = authorize_tool_execution(
        ExecutionAuthorizationRequest(
            tool_id="semgrep_local",
            asset="api.example.test",
            campaign_allowed_tools=[],
            scope_rule=_rule(allowed_validation=["static_analyzer"]),
            human_approved=True,
        )
    )

    assert decision.eligible is False
    assert decision.reason == "tool_not_campaign_allowed"


def test_unknown_tool_is_fail_closed():
    decision = authorize_tool_execution(
        ExecutionAuthorizationRequest(
            tool_id="unregistered_tool",
            asset="api.example.test",
            campaign_allowed_tools=["unregistered_tool"],
            scope_rule=_rule(allowed_validation=["unregistered_tool"]),
            human_approved=True,
        )
    )

    assert decision.eligible is False
    assert decision.reason == "unknown_tool"
    assert decision.capability is None


def test_remote_tool_requires_human_approval_and_execution_lease():
    request = ExecutionAuthorizationRequest(
        tool_id="two_account_authorization_check",
        asset="api.example.test",
        campaign_allowed_tools=["two_account_authorization_check"],
        scope_rule=_rule(
            allowed_validation=["two_account_authorization_check"],
            human_approval_required=True,
        ),
        human_approved=True,
        execution_lease_active=False,
    )

    blocked = authorize_tool_execution(request)
    allowed = authorize_tool_execution(request.model_copy(update={"execution_lease_active": True}))

    assert blocked.eligible is False
    assert blocked.reason == "execution_lease_required"
    assert allowed.eligible is True
    assert allowed.execution_tier == "remote"
    assert allowed.network_access is True
    assert allowed.requires_execution_lease is True
    assert allowed.dispatch_allowed is False


def test_scope_guard_denial_is_preserved():
    decision = authorize_tool_execution(
        ExecutionAuthorizationRequest(
            tool_id="semgrep_local",
            asset="other.example.test",
            campaign_allowed_tools=["static_analyzer"],
            scope_rule=_rule(allowed_validation=["static_analyzer"]),
            human_approved=True,
        )
    )

    assert decision.eligible is False
    assert decision.reason == "out_of_scope"


def test_registry_rejects_duplicate_capability_ids():
    capability = ToolCapability(
        tool_id="local_fixture_review",
        validation_mode="static_local_check",
        execution_tier="local",
        network_access=False,
        human_approval_required=False,
        execution_lease_required=False,
        dispatch_allowed=True,
    )

    try:
        ExecutionRegistry([capability, capability])
    except ValueError as error:
        assert str(error) == "duplicate_tool_capability:local_fixture_review"
    else:
        raise AssertionError("duplicate tool capability should be rejected")


def test_default_registry_lists_only_non_promoting_capabilities():
    capabilities = default_execution_registry().list_capabilities()

    assert {capability.tool_id for capability in capabilities} >= {
        "semgrep_local",
        "codeql_local",
        "two_account_authorization_check",
    }
    assert all(capability.candidate_promotion_allowed is False for capability in capabilities)
    assert all(capability.report_submission_allowed is False for capability in capabilities)


def test_default_registry_does_not_advertise_unimplemented_local_adapters():
    local_capabilities = {
        capability.tool_id
        for capability in default_execution_registry().list_capabilities()
        if capability.execution_tier == "local" and capability.dispatch_allowed
    }

    assert local_capabilities == {
        "codeql_local",
        "dependency_sbom_local",
        "semgrep_local",
    }
