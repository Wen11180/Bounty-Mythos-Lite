from app.scope_guard import ScopeGuardRule


DEFAULT_ALLOWED_VALIDATION = [
    "two_account_authorization_check",
    "local_code_review",
    "non_destructive_business_logic_test",
]

FORBIDDEN_PATTERNS = [
    ("DoS", ["dos", "denial of service"]),
    ("credential_stuffing", ["credential stuffing", "credential-stuffing"]),
    ("social_engineering", ["social engineering", "social-engineering"]),
    ("destructive_testing", ["destructive testing", "destructive"]),
    ("real_user_data_access", ["real user data", "real-user data", "customer data"]),
]


def parse_policy_text(policy_text: str, asset: str) -> ScopeGuardRule:
    normalized = policy_text.lower()
    return ScopeGuardRule(
        asset=asset,
        scope_status=_scope_status(normalized, asset),
        automation=_automation(normalized),
        allowed_validation=DEFAULT_ALLOWED_VALIDATION,
        forbidden=_forbidden(normalized),
        human_approval_required=True,
    )


def _scope_status(policy_text: str, asset: str) -> str:
    asset_lower = asset.lower()
    out_of_scope_markers = ("out of scope", "excluded", "not in scope")
    if asset_lower in policy_text and any(marker in policy_text for marker in out_of_scope_markers):
        out_of_scope_index = min(
            policy_text.find(marker)
            for marker in out_of_scope_markers
            if marker in policy_text
        )
        if policy_text.find(asset_lower, out_of_scope_index) != -1:
            return "out_of_scope"

    if asset_lower in policy_text and ("in scope" in policy_text or "allowed" in policy_text):
        return "in_scope"

    return "needs_review"


def _automation(policy_text: str) -> str:
    if "no automation" in policy_text or "automated testing is prohibited" in policy_text:
        return "none"
    if "limited" in policy_text or "rate limit" in policy_text:
        return "limited"
    return "needs_review"


def _forbidden(policy_text: str) -> list[str]:
    forbidden: list[str] = []
    for value, patterns in FORBIDDEN_PATTERNS:
        if any(pattern in policy_text for pattern in patterns):
            forbidden.append(value)
    return forbidden
