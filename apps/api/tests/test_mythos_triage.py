from app.mythos_triage import (
    build_report_draft,
    build_validation_plan,
    refute_hypothesis,
)


def test_refutation_blocks_scope_guard_blocked_hypothesis():
    refutation = refute_hypothesis(
        {"hypothesis": "x", "policy_risk": "low"},
        {"allowed": False, "reason": "out_of_scope"},
    )

    assert refutation.status == "blocked"
    assert "out_of_scope" in refutation.reasons
    assert refutation.questions
    assert all("Authorization" not in question for question in refutation.questions)
    assert all("secret" not in question.lower() for question in refutation.questions)


def test_validation_plan_uses_only_safe_non_destructive_methods():
    hypothesis = {
        "hypothesis": "普通成员可能修改团队邀请设置",
        "validation_mode": "role_based_authorization_check",
        "risk_level": "high",
    }
    refutation = refute_hypothesis(hypothesis, {"allowed": True, "reason": "allowed_validation"})

    plan = build_validation_plan(hypothesis, refutation)

    assert plan.status == "validation_plan_ready"
    assert plan.human_approval_required is True
    assert plan.methods == ["role_matrix_check", "request_response_diff"]
    assert all("DoS" not in step for step in plan.steps)


def test_refutation_questions_do_not_echo_sensitive_terms_when_passed():
    refutation = refute_hypothesis(
        {"hypothesis": "x", "policy_risk": "low"},
        {"allowed": True, "reason": "allowed_validation"},
    )

    assert refutation.status == "passed"
    assert refutation.questions
    assert all("authorization" not in question.lower() for question in refutation.questions)
    assert all("secret" not in question.lower() for question in refutation.questions)


def test_report_draft_requires_human_review_and_contains_core_fields():
    hypothesis = {
        "hypothesis": "修改文件标识符可能读取其他用户私有文件",
        "vuln_type": "broken_access_control",
        "broken_invariant": "用户不能访问其他用户私有文件",
        "risk_level": "high",
        "validation_mode": "two_account_authorization_check",
    }
    refutation = refute_hypothesis(hypothesis, {"allowed": True, "reason": "allowed_validation"})
    plan = build_validation_plan(hypothesis, refutation)

    draft = build_report_draft(hypothesis, plan, refutation)

    assert draft.title == "修改文件标识符可能读取其他用户私有文件"
    assert draft.severity == "high"
    assert draft.scope_status == "allowed_validation"
    assert draft.human_review_required is True
    assert draft.expected_result
    assert draft.actual_result
