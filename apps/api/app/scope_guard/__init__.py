from pydantic import BaseModel


class ScopeGuardRule(BaseModel):
    asset: str
    scope_status: str
    automation: str
    allowed_validation: list[str]
    forbidden: list[str]
    human_approval_required: bool


class ValidationRequest(BaseModel):
    asset: str
    validation_type: str
    human_approved: bool = False
    plan_digest: str | None = None


class ScopeGuardDecision(BaseModel):
    allowed: bool
    reason: str


def evaluate_validation_request(
    rule: ScopeGuardRule, request: ValidationRequest
) -> ScopeGuardDecision:
    if rule.asset != request.asset or rule.scope_status != "in_scope":
        return ScopeGuardDecision(allowed=False, reason="out_of_scope")

    if request.validation_type in rule.forbidden:
        return ScopeGuardDecision(allowed=False, reason="forbidden_validation")

    if rule.human_approval_required and not request.human_approved:
        return ScopeGuardDecision(allowed=False, reason="human_approval_required")

    if request.validation_type in rule.allowed_validation:
        return ScopeGuardDecision(allowed=True, reason="allowed_validation")

    return ScopeGuardDecision(allowed=False, reason="validation_not_allowed")
