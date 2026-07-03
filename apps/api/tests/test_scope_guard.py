from app.scope_guard import (
    ScopeGuardRule,
    ValidationRequest,
    evaluate_validation_request,
)


def test_blocks_out_of_scope_asset():
    rule = ScopeGuardRule(
        asset="api.example.com",
        scope_status="out_of_scope",
        automation="limited",
        allowed_validation=["local_code_review"],
        forbidden=[],
        human_approval_required=False,
    )
    request = ValidationRequest(asset="api.example.com", validation_type="local_code_review")

    decision = evaluate_validation_request(rule, request)

    assert decision.allowed is False
    assert decision.reason == "out_of_scope"


def test_blocks_forbidden_validation_type():
    rule = ScopeGuardRule(
        asset="api.example.com",
        scope_status="in_scope",
        automation="limited",
        allowed_validation=["local_code_review"],
        forbidden=["DoS"],
        human_approval_required=False,
    )
    request = ValidationRequest(asset="api.example.com", validation_type="DoS")

    decision = evaluate_validation_request(rule, request)

    assert decision.allowed is False
    assert decision.reason == "forbidden_validation"


def test_blocks_request_without_required_human_approval():
    rule = ScopeGuardRule(
        asset="api.example.com",
        scope_status="in_scope",
        automation="limited",
        allowed_validation=["non_destructive_business_logic_test"],
        forbidden=[],
        human_approval_required=True,
    )
    request = ValidationRequest(
        asset="api.example.com",
        validation_type="non_destructive_business_logic_test",
        human_approved=False,
    )

    decision = evaluate_validation_request(rule, request)

    assert decision.allowed is False
    assert decision.reason == "human_approval_required"


def test_allows_approved_allowed_validation():
    rule = ScopeGuardRule(
        asset="api.example.com",
        scope_status="in_scope",
        automation="limited",
        allowed_validation=["two_account_authorization_check"],
        forbidden=["DoS"],
        human_approval_required=True,
    )
    request = ValidationRequest(
        asset="api.example.com",
        validation_type="two_account_authorization_check",
        human_approved=True,
    )

    decision = evaluate_validation_request(rule, request)

    assert decision.allowed is True
    assert decision.reason == "allowed_validation"
