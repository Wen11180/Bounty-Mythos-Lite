from app.policy_ingestion import parse_policy_text


def test_parse_policy_text_builds_in_scope_rule_for_matching_asset():
    policy = """
    In scope assets include api.example.com.
    Automation is limited.
    DoS, credential stuffing, social engineering, destructive testing,
    and real user data access are forbidden.
    """

    rule = parse_policy_text(policy, "api.example.com")

    assert rule.asset == "api.example.com"
    assert rule.scope_status == "in_scope"
    assert rule.automation == "limited"
    assert rule.human_approval_required is True
    assert rule.allowed_validation == [
        "two_account_authorization_check",
        "local_code_review",
        "non_destructive_business_logic_test",
    ]
    assert rule.forbidden == [
        "DoS",
        "credential_stuffing",
        "social_engineering",
        "destructive_testing",
        "real_user_data_access",
    ]


def test_parse_policy_text_marks_excluded_asset_out_of_scope():
    policy = "In scope: api.example.com. Out of scope: staging.example.com."

    rule = parse_policy_text(policy, "staging.example.com")

    assert rule.scope_status == "out_of_scope"


def test_parse_policy_text_marks_unknown_asset_for_review():
    rule = parse_policy_text("In scope: api.example.com.", "unknown.example.com")

    assert rule.scope_status == "needs_review"
