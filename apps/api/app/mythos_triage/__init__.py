from pydantic import BaseModel, Field


SAFE_VALIDATION_METHODS = {
    "two_account_authorization_check": ["two_account_authorization_check", "request_response_diff"],
    "role_based_authorization_check": ["role_matrix_check", "request_response_diff"],
    "non_destructive_request_review": ["local_code_review", "request_response_diff"],
    "non_destructive_business_logic_test": ["non_destructive_business_logic_test", "request_response_diff"],
}


class RefutationResult(BaseModel):
    status: str
    reasons: list[str] = Field(default_factory=list)
    human_review_required: bool = True


class ValidationPlan(BaseModel):
    status: str
    methods: list[str]
    steps: list[str]
    human_approval_required: bool = True


class ReportDraftCandidate(BaseModel):
    title: str
    severity: str
    scope_status: str
    safety_notes: list[str]
    steps: list[str]
    expected_result: str
    actual_result: str
    human_review_required: bool = True


def refute_hypothesis(hypothesis: dict, scope_decision: dict) -> RefutationResult:
    reasons: list[str] = []

    if not scope_decision.get("allowed", False):
        reasons.append(str(scope_decision.get("reason", "scope_guard_blocked")))
    if hypothesis.get("self_impact_only"):
        reasons.append("self_impact_only")
    if hypothesis.get("best_practice_only"):
        reasons.append("best_practice_only")
    if hypothesis.get("requires_real_user_data"):
        reasons.append("requires_real_user_data")
    if hypothesis.get("policy_risk") == "high":
        reasons.append("high_policy_risk")

    return RefutationResult(
        status="blocked" if reasons else "passed",
        reasons=reasons,
        human_review_required=True,
    )


def build_validation_plan(hypothesis: dict, refutation: RefutationResult) -> ValidationPlan:
    if refutation.status == "blocked":
        return ValidationPlan(
            status="blocked",
            methods=[],
            steps=["Do not validate until refutation findings are resolved."],
            human_approval_required=True,
        )

    validation_mode = str(hypothesis.get("validation_mode", "non_destructive_business_logic_test"))
    methods = SAFE_VALIDATION_METHODS.get(
        validation_mode,
        ["non_destructive_business_logic_test", "request_response_diff"],
    )
    return ValidationPlan(
        status="validation_plan_ready",
        methods=methods,
        steps=[
            "Use only configured test accounts.",
            "Prepare baseline authorized request and candidate unauthorized request.",
            "Capture request/response difference without touching real user data.",
            "Stop before any destructive state change or high-frequency traffic.",
        ],
        human_approval_required=True,
    )


def build_report_draft(
    hypothesis: dict,
    validation_plan: ValidationPlan,
    refutation: RefutationResult,
) -> ReportDraftCandidate:
    return ReportDraftCandidate(
        title=str(hypothesis.get("hypothesis", "Untitled hypothesis")),
        severity=str(hypothesis.get("risk_level", "medium")),
        scope_status="; ".join(refutation.reasons) if refutation.reasons else "allowed_validation",
        safety_notes=[
            "human_review_required",
            "test_accounts_only",
            "non_destructive_validation_only",
        ],
        steps=validation_plan.steps,
        expected_result=str(hypothesis.get("broken_invariant", "The protected invariant should hold.")),
        actual_result="To be filled after safe validation evidence is reviewed.",
        human_review_required=True,
    )
