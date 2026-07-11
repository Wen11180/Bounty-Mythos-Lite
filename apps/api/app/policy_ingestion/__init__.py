import re

from app.scope_guard import ScopeGuardRule


EXPLICIT_VALIDATION_PATTERNS = [
    ("two_account_authorization_check", "two account authorization check"),
    (
        "non_destructive_business_logic_test",
        "non destructive business logic test",
    ),
]
PERMISSION_MARKERS = (
    "allowed",
    "allows",
    "permit",
    "permitted",
    "permits",
    "authorized",
    "authorizes",
    "may ",
)
DENIAL_MARKERS = (
    "not allowed",
    "not permitted",
    "not authorized",
    "may not",
    "prohibited",
    "forbidden",
)

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
        allowed_validation=_allowed_validation(normalized),
        forbidden=_forbidden(normalized),
        human_approval_required=True,
    )


def _scope_status(policy_text: str, asset: str) -> str:
    asset_lower = asset.lower()
    escaped_asset = re.escape(asset_lower)
    out_of_scope = r"(?:out[ _-]of[ _-]scope|excluded|not[ _-]in[ _-]scope|not allowed)"
    in_scope = r"(?:in[ _-]scope|allowed)"
    if re.search(
        (
            rf"{escaped_asset}[^.\n]{{0,80}}{out_of_scope}"
            rf"|{out_of_scope}[^.\n]{{0,80}}{escaped_asset}"
            rf"|{out_of_scope}\s*:\s*(?:-\s*)?{escaped_asset}"
        ),
        policy_text,
    ):
        return "out_of_scope"

    if re.search(
        (
            rf"{escaped_asset}[^.\n]{{0,80}}{in_scope}"
            rf"|{in_scope}[^.\n]{{0,80}}{escaped_asset}"
            rf"|{in_scope}\s*:\s*(?:-\s*)?{escaped_asset}"
        ),
        policy_text,
    ):
        return "in_scope"

    return "needs_review"


def _automation(policy_text: str) -> str:
    if "no automation" in policy_text or "automated testing is prohibited" in policy_text:
        return "none"
    if "limited" in policy_text or "rate limit" in policy_text:
        return "limited"
    return "needs_review"


def _allowed_validation(policy_text: str) -> list[str]:
    allowed: list[str] = []
    for clause in policy_text.replace("-", " ").replace("_", " ").split("."):
        if any(marker in clause for marker in DENIAL_MARKERS):
            continue
        if not any(marker in clause for marker in PERMISSION_MARKERS):
            continue
        for validation_type, pattern in EXPLICIT_VALIDATION_PATTERNS:
            if pattern in clause:
                allowed.append(validation_type)
    return allowed


def _forbidden(policy_text: str) -> list[str]:
    forbidden: list[str] = []
    for value, patterns in FORBIDDEN_PATTERNS:
        if any(pattern in policy_text for pattern in patterns):
            forbidden.append(value)
    return forbidden
