from __future__ import annotations

from dataclasses import asdict, dataclass, field

from app.codebase_map import map_authorized_code_files


HTTP_METHODS = {"get", "post", "put", "patch", "delete"}
SECRET_KEYS = {"password", "secret", "token", "api_key", "authorization", "cookie"}
SENSITIVE_PATH_MARKERS = (
    "admin",
    "delete",
    "export",
    "role",
    "transfer",
    "checkout",
    "refund",
    "order",
    "invoice",
    "file",
)
LOGIC_PATH_MARKERS = ("transfer", "checkout", "refund", "role")
SAFETY_INVARIANTS = [
    "authorized_assets_only",
    "scope_checked_required",
    "no_public_target_scanning",
    "no_destructive_validation",
    "no_credential_collection",
    "no_real_user_data_handling",
    "no_automatic_report_submission",
    "human_approval_required_before_validation",
]


@dataclass(frozen=True)
class AuthorizedAsset:
    asset: str
    source: str
    automation: str = "limited_plan_only"


@dataclass(frozen=True)
class APIOperation:
    method: str
    path: str
    operation_id: str | None
    source: str
    sensitivity: str


@dataclass(frozen=True)
class RoleModel:
    account_label: str
    role: str
    secret_status: str = "redacted_not_stored"


@dataclass(frozen=True)
class RoleDiffPlan:
    endpoint: str
    method: str
    roles: list[str]
    status: str
    validation_type: str
    execution_allowed: bool
    approval_required: bool


@dataclass(frozen=True)
class BusinessLogicCandidate:
    candidate_id: str
    vuln_type: str
    endpoint: str
    reason: str
    safe_validation: bool
    status: str = "unverified_hypothesis"


@dataclass(frozen=True)
class EvidencePackageSchema:
    status: str
    redaction_required: bool
    required_fields: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class HumanGate:
    status: str
    execution_allowed: bool
    approval_required: bool
    required_for: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ValidationPreflightCheck:
    check: str
    status: str
    reason: str
    execution_allowed: bool
    approval_required: bool


@dataclass(frozen=True)
class ReportDraft:
    status: str
    auto_submit_allowed: bool
    sections: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AuthorizedBugBountyPlan:
    stage: str
    inspirations: list[str]
    execution_mode: str
    allowed_assets: list[AuthorizedAsset]
    api_operations: list[APIOperation]
    role_models: list[RoleModel]
    role_diff_plans: list[RoleDiffPlan]
    business_logic_candidates: list[BusinessLogicCandidate]
    evidence_package: EvidencePackageSchema
    human_gate: HumanGate
    validation_preflight: list[ValidationPreflightCheck]
    report_draft: ReportDraft
    safety_invariants: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def build_authorized_bug_bounty_plan(
    scope_policy: dict,
    authorized_code_files: list[dict[str, str]],
) -> AuthorizedBugBountyPlan:
    bug_bounty = _bug_bounty_policy(scope_policy)
    operations = _dedupe_operations(
        [
            *_openapi_operations(bug_bounty.get("api_specs")),
            *_route_operations(authorized_code_files),
        ]
    )
    allowed_assets = _allowed_assets(bug_bounty)
    roles = _role_models(bug_bounty.get("test_accounts"))
    role_names = sorted({role.role for role in roles})

    return AuthorizedBugBountyPlan(
        stage="v2_authorized_bug_bounty",
        inspirations=["XBOW"],
        execution_mode="plan_only",
        allowed_assets=allowed_assets,
        api_operations=operations,
        role_models=roles,
        role_diff_plans=_role_diff_plans(operations, role_names),
        business_logic_candidates=_business_logic_candidates(operations),
        evidence_package=EvidencePackageSchema(
            status="schema_only",
            redaction_required=True,
            required_fields=[
                "scope_confirmation",
                "asset",
                "endpoint",
                "role_labels",
                "redacted_request_metadata",
                "redacted_response_diff",
                "human_review_decision",
            ],
        ),
        human_gate=HumanGate(
            status="required",
            execution_allowed=False,
            approval_required=True,
            required_for=[
                "external_network_test",
                "authenticated_role_test",
                "evidence_promotion",
                "report_submission",
            ],
        ),
        validation_preflight=_validation_preflight(allowed_assets, roles),
        report_draft=ReportDraft(
            status="draft_schema_only",
            auto_submit_allowed=False,
            sections=[
                "summary",
                "scope_confirmation",
                "impact",
                "safe_reproduction_plan",
                "redacted_evidence",
                "suggested_fix",
            ],
        ),
        safety_invariants=SAFETY_INVARIANTS,
    )


def _validation_preflight(
    allowed_assets: list[AuthorizedAsset],
    roles: list[RoleModel],
) -> list[ValidationPreflightCheck]:
    return [
        ValidationPreflightCheck(
            check="authorized_asset_allowlist",
            status="passed" if allowed_assets else "blocked",
            reason=(
                "authorized_assets_imported"
                if allowed_assets
                else "missing_authorized_asset_allowlist"
            ),
            execution_allowed=False,
            approval_required=True,
        ),
        ValidationPreflightCheck(
            check="test_account_roles",
            status="passed" if len({role.role for role in roles}) >= 2 else "blocked",
            reason=(
                "two_or_more_roles_modeled"
                if len({role.role for role in roles}) >= 2
                else "two_authorized_test_roles_required"
            ),
            execution_allowed=False,
            approval_required=True,
        ),
        ValidationPreflightCheck(
            check="durable_human_approval",
            status="blocked",
            reason="durable_approval_record_required_before_validation",
            execution_allowed=False,
            approval_required=True,
        ),
        ValidationPreflightCheck(
            check="redacted_evidence_package",
            status="blocked",
            reason="sanitized_evidence_required_before_promotion",
            execution_allowed=False,
            approval_required=True,
        ),
    ]


def _bug_bounty_policy(scope_policy: dict) -> dict:
    bug_bounty = scope_policy.get("bug_bounty")
    return bug_bounty if isinstance(bug_bounty, dict) else scope_policy


def _allowed_assets(policy: dict) -> list[AuthorizedAsset]:
    assets: list[AuthorizedAsset] = []
    for key in ("allowed_assets", "allowed_domains"):
        values = policy.get(key)
        if not isinstance(values, list):
            continue
        for value in values:
            if isinstance(value, str) and value.strip():
                assets.append(
                    AuthorizedAsset(asset=_safe_label(value), source=f"scope_policy.{key}")
                )
    return _dedupe_assets(assets)


def _openapi_operations(value: object) -> list[APIOperation]:
    specs = value if isinstance(value, list) else []
    operations: list[APIOperation] = []
    for spec in specs:
        if not isinstance(spec, dict):
            continue
        source = _safe_label(str(spec.get("source", "openapi")))
        openapi = spec.get("openapi") if isinstance(spec.get("openapi"), dict) else spec
        paths = openapi.get("paths") if isinstance(openapi.get("paths"), dict) else {}
        for path, methods in paths.items():
            if not isinstance(path, str) or not isinstance(methods, dict):
                continue
            for method, details in methods.items():
                if not isinstance(method, str) or method.lower() not in HTTP_METHODS:
                    continue
                operation_id = None
                if isinstance(details, dict) and isinstance(details.get("operationId"), str):
                    operation_id = _safe_label(details["operationId"])
                operations.append(
                    APIOperation(
                        method=method.upper(),
                        path=_safe_path(path),
                        operation_id=operation_id,
                        source=source,
                        sensitivity=_path_sensitivity(path),
                    )
                )
    return operations


def _route_operations(authorized_code_files: list[dict[str, str]]) -> list[APIOperation]:
    codebase_map = map_authorized_code_files({"authorized_code_files": authorized_code_files})
    operations: list[APIOperation] = []
    for fact in codebase_map.facts:
        if fact.fact_type != "route_handler" or not fact.route_path:
            continue
        operations.append(
            APIOperation(
                method=fact.route_method or "GET",
                path=_safe_path(fact.route_path),
                operation_id=_safe_label(fact.symbol_name) if fact.symbol_name else None,
                source=f"local_route:{_safe_path(fact.source_path)}",
                sensitivity=_path_sensitivity(fact.route_path),
            )
        )
    return operations


def _role_models(value: object) -> list[RoleModel]:
    accounts = value if isinstance(value, list) else []
    roles: list[RoleModel] = []
    for index, account in enumerate(accounts, start=1):
        if not isinstance(account, dict):
            continue
        label = account.get("label")
        role = account.get("role")
        if not isinstance(role, str) or not role.strip():
            continue
        account_label = label if isinstance(label, str) and label.strip() else f"account_{index}"
        roles.append(
            RoleModel(
                account_label=_safe_label(account_label),
                role=_safe_label(role),
            )
        )
    return _dedupe_roles(roles)


def _role_diff_plans(
    operations: list[APIOperation],
    role_names: list[str],
) -> list[RoleDiffPlan]:
    if len(role_names) < 2:
        return []
    return [
        RoleDiffPlan(
            endpoint=operation.path,
            method=operation.method,
            roles=role_names,
            status="planned_requires_human_approval",
            validation_type="two_account_authorization_check",
            execution_allowed=False,
            approval_required=True,
        )
        for operation in operations
        if operation.sensitivity in {"medium", "high"} or "{" in operation.path
    ]


def _business_logic_candidates(
    operations: list[APIOperation],
) -> list[BusinessLogicCandidate]:
    candidates: list[BusinessLogicCandidate] = []
    for operation in operations:
        lowered = f"{operation.method} {operation.path}".lower()
        if "{" in operation.path and any(marker in lowered for marker in ("id", "order", "user")):
            candidates.append(
                _candidate(
                    len(candidates) + 1,
                    "bola_idor",
                    operation,
                    "Parameterized object endpoint should be compared across authorized test roles before any report use.",
                )
            )
        if operation.sensitivity == "high":
            candidates.append(
                _candidate(
                    len(candidates) + 1,
                    "authorization",
                    operation,
                    "Sensitive operation needs explicit role and ownership boundary review.",
                )
            )
        if any(marker in lowered for marker in LOGIC_PATH_MARKERS):
            candidates.append(
                _candidate(
                    len(candidates) + 1,
                    "business_logic",
                    operation,
                    "Business action should be modeled as a low-risk state transition plan before validation.",
                )
            )
    return candidates


def _candidate(
    index: int,
    vuln_type: str,
    operation: APIOperation,
    reason: str,
) -> BusinessLogicCandidate:
    return BusinessLogicCandidate(
        candidate_id=f"V2-{index:03d}",
        vuln_type=vuln_type,
        endpoint=f"{operation.method} {operation.path}",
        reason=reason,
        safe_validation=True,
    )


def _path_sensitivity(path: str) -> str:
    lowered = path.lower()
    if any(marker in lowered for marker in ("admin", "delete", "role", "transfer", "refund")):
        return "high"
    if any(marker in lowered for marker in SENSITIVE_PATH_MARKERS) or "{" in path:
        return "medium"
    return "low"


def _dedupe_assets(assets: list[AuthorizedAsset]) -> list[AuthorizedAsset]:
    seen: set[str] = set()
    deduped: list[AuthorizedAsset] = []
    for asset in assets:
        if asset.asset in seen:
            continue
        seen.add(asset.asset)
        deduped.append(asset)
    return deduped


def _dedupe_operations(operations: list[APIOperation]) -> list[APIOperation]:
    seen: set[tuple[str, str]] = set()
    deduped: list[APIOperation] = []
    for operation in operations:
        key = (operation.method, operation.path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(operation)
    return deduped


def _dedupe_roles(roles: list[RoleModel]) -> list[RoleModel]:
    seen: set[tuple[str, str]] = set()
    deduped: list[RoleModel] = []
    for role in roles:
        key = (role.account_label, role.role)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(role)
    return deduped


def _safe_label(value: str) -> str:
    if _looks_secret(value):
        return "[REDACTED]"
    return value.strip()[:120]


def _safe_path(value: str) -> str:
    return value.strip()[:240]


def _looks_secret(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in SECRET_KEYS)
