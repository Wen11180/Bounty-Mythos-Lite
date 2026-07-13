from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

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
    "webhook",
    "ssrf",
    "fetch",
    "proxy",
)
LOGIC_PATH_MARKERS = ("transfer", "checkout", "refund", "role", "webhook")
SAFETY_INVARIANTS = [
    "authorized_assets_only",
    "scope_checked_required",
    "no_public_target_scanning",
    "no_destructive_validation",
    "no_credential_collection",
    "no_real_user_data_handling",
    "no_automatic_report_submission",
    "human_approval_required_before_validation",
    "offline_package_artifacts_only",
    "no_network_access_by_planner",
]

STATUS_READY = "authorized_web_api_plan_ready"
STATUS_EMPTY = "authorized_web_api_no_operations"
STATUS_SKIPPED = "authorized_web_api_package_missing"
STATUS_EMPTY_INPUT = "authorized_web_api_no_scope_or_api"

STAGE_EXPLICIT = "v2_authorized_bug_bounty"
STAGE_PACKAGE = "v2_authorized_bug_bounty_package_ingest"

_MAX_CODE_FILES = 200
_MAX_FILE_BYTES = 256_000
_MAX_CONTENT = 64_000
_CODE_SUFFIXES = {
    ".py",
    ".pyi",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".go",
    ".java",
    ".rs",
}
_SKIP_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "dist",
    "build",
    "coverage",
    ".idea",
    ".vscode",
    "target",
    "vendor",
    ".mythos",
}


class AuthorizedWebApiError(ValueError):
    pass


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
    status: str = STATUS_READY
    package_id: str = ""
    package_root: str = ""
    operation_count: int = 0
    role_diff_count: int = 0
    business_logic_count: int = 0
    notes: list[str] = field(default_factory=list)
    network_access: bool = False
    live_validation: bool = False
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    human_approval_required_before_run: bool = True
    next_allowed_action: str = (
        "Review role-diff and business-logic plans; never validate without durable human approval."
    )

    def to_dict(self) -> dict[str, Any]:
        return _force_safety_dict(asdict(self))



def build_authorized_bug_bounty_plan(
    scope_policy: dict | None = None,
    authorized_code_files: list[dict[str, str]] | None = None,
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
) -> AuthorizedBugBountyPlan:
    """Build plan-only authorized Web/API surface.

    Compatibility:
    - explicit dict path keeps stage `v2_authorized_bug_bounty`
    - package_root path uses package ingest and stage `..._package_ingest`
    """
    notes: list[str] = ["plan_only", "no_live_validation", "offline_package_artifacts_only"]
    root: Path | None = None
    files = list(authorized_code_files or [])
    policy: dict[str, Any] = dict(scope_policy or {})
    pkg_id = str(package_id or "").strip()

    if package_root is not None and str(package_root).strip():
        root = Path(package_root).resolve()
        if not root.is_dir():
            return _empty_plan(
                status=STATUS_SKIPPED,
                package_id=pkg_id,
                package_root=str(root),
                notes=notes + ["package_root_missing"],
                next_action="Provide authorized package_root under local workspace.",
            )
        loaded = load_package_scope_policy(root)
        if loaded:
            policy = _merge_policy(policy, loaded)
            notes.append("scope_policy_from_package_root")
        if not files:
            files = collect_authorized_code_files(root)
            if files:
                notes.append("code_files_from_package_root")
        if not pkg_id:
            pkg_id = _package_id_from_root(root)
        stage = STAGE_PACKAGE
    else:
        stage = STAGE_EXPLICIT

    bug_bounty = _bug_bounty_policy(policy)
    package_ops = _package_route_operations(policy, bug_bounty)
    openapi_ops = _openapi_operations(bug_bounty.get("api_specs"))
    if not openapi_ops:
        openapi_ops = _openapi_operations(_openapi_specs_from_policy(policy, bug_bounty))
    route_ops = _route_operations(files)
    operations = _dedupe_operations([*package_ops, *openapi_ops, *route_ops])

    allowed_assets = _allowed_assets(bug_bounty, policy)
    roles = _role_models(bug_bounty.get("test_accounts") or policy.get("test_accounts"))
    if not roles and _is_local_only(policy, bug_bounty):
        roles = [
            RoleModel(account_label="lab_role_a", role="user"),
            RoleModel(account_label="lab_role_b", role="admin"),
        ]
        notes.append("synthetic_lab_roles_labels_only")
    role_names = sorted({role.role for role in roles})

    role_diffs = _role_diff_plans(operations, role_names)
    logic = _business_logic_candidates(operations)

    if not operations and not allowed_assets and not roles:
        status = STATUS_EMPTY_INPUT if root is not None else STATUS_EMPTY
    elif not operations:
        status = STATUS_EMPTY
    else:
        status = STATUS_READY

    plan = AuthorizedBugBountyPlan(
        stage=stage,
        inspirations=["XBOW"],
        execution_mode="plan_only",
        allowed_assets=allowed_assets,
        api_operations=operations,
        role_models=roles,
        role_diff_plans=role_diffs,
        business_logic_candidates=logic,
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
        safety_invariants=list(SAFETY_INVARIANTS),
        status=status,
        package_id=pkg_id,
        package_root=str(root) if root is not None else "",
        operation_count=len(operations),
        role_diff_count=len(role_diffs),
        business_logic_count=len(logic),
        notes=notes,
    )
    return _force_safety_plan(plan)


def load_package_scope_policy(package_root: str | Path) -> dict[str, Any]:
    """Load scope/api/roles/package metadata into a bug_bounty-compatible policy dict."""
    root = Path(package_root).resolve()
    if not root.is_dir():
        return {}

    scope = _read_json(root / "inputs" / "scope.json")
    api = _read_json(root / "inputs" / "api.json")
    roles_doc = _read_json(root / "inputs" / "roles.json")
    package_meta = _read_json(root / "package.json")

    policy: dict[str, Any] = {}
    if package_meta:
        policy["package_id"] = package_meta.get("package_id") or root.name
        if package_meta.get("authorized_for_local_research") is True:
            policy["authorized_for_local_research"] = True
        if package_meta.get("contains_secrets") is True:
            policy["contains_secrets_flag"] = True

    if scope:
        for key in (
            "allowed_assets",
            "allowed_domains",
            "allowed_repos",
            "allowed_routes",
            "local_only",
            "forbidden",
            "fixture_id",
            "authorization_note",
        ):
            if key in scope:
                policy[key] = scope[key]
        bug: dict[str, Any] = {}
        for key in ("allowed_assets", "allowed_domains", "test_accounts"):
            if key in scope:
                bug[key] = scope[key]
        if "allowed_repos" in scope:
            bug["allowed_repos"] = scope["allowed_repos"]
        if "allowed_routes" in scope:
            bug["allowed_routes"] = scope["allowed_routes"]
        if "local_only" in scope:
            bug["local_only"] = scope["local_only"]
        if bug:
            policy["bug_bounty"] = bug

    if api:
        if isinstance(api.get("paths"), dict):
            openapi = api
        elif isinstance(api.get("openapi"), dict):
            openapi = api["openapi"]
        else:
            openapi = api
        specs = [
            {
                "source": "package_inputs_api_json",
                "openapi": openapi if isinstance(openapi, dict) else api,
            }
        ]
        policy.setdefault("bug_bounty", {})
        if isinstance(policy["bug_bounty"], dict):
            policy["bug_bounty"]["api_specs"] = specs
        policy["api_specs"] = specs

    if roles_doc:
        accounts = roles_doc.get("test_accounts") if isinstance(roles_doc, dict) else None
        if not isinstance(accounts, list) and isinstance(roles_doc, list):
            accounts = roles_doc
        if isinstance(accounts, list):
            cleaned = _sanitize_account_list(accounts)
            policy.setdefault("bug_bounty", {})
            if isinstance(policy["bug_bounty"], dict):
                policy["bug_bounty"]["test_accounts"] = cleaned
            policy["test_accounts"] = cleaned

    return policy


def collect_authorized_code_files(package_root: str | Path) -> list[dict[str, str]]:
    root = Path(package_root).resolve()
    if not root.is_dir():
        return []
    files: list[dict[str, str]] = []
    preferred = [
        root / "inputs",
        root / "_extract",
        root / "src",
        root / "app",
        root / "backend",
        root / "_upstream",
    ]
    scan_roots = [p for p in preferred if p.is_dir()]
    if not scan_roots:
        scan_roots = [root]

    for scan_root in scan_roots:
        for path in _iter_code_files(scan_root, package_root=root):
            if len(files) >= _MAX_CODE_FILES:
                break
            text = _safe_read_text(path)
            if text is None:
                continue
            try:
                rel = str(path.resolve().relative_to(root)).replace('\\', '/')
            except ValueError:
                continue
            files.append({"path": rel, "content": text})
        if len(files) >= _MAX_CODE_FILES:
            break
    return files


def load_package_authorized_bug_bounty_plan(
    package_root: str | Path | None,
    *,
    package_id: str = "",
    authorized_code_files: list[dict[str, str]] | None = None,
    scope_policy: dict | None = None,
) -> dict[str, Any]:
    return build_authorized_bug_bounty_plan(
        scope_policy,
        authorized_code_files,
        package_root=package_root,
        package_id=package_id,
    ).to_dict()


def attach_authorized_web_api_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    authorized_code_files: list[dict[str, str]] | None = None,
    scope_policy: dict | None = None,
    authorized_bug_bounty: dict[str, Any] | AuthorizedBugBountyPlan | None = None,
) -> dict[str, Any]:
    """Attach plan-only authorized Web/API profile; never unlocks execute/submit."""
    if not isinstance(bridge_result, dict):
        raise AuthorizedWebApiError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")

    if isinstance(authorized_bug_bounty, AuthorizedBugBountyPlan):
        payload = authorized_bug_bounty.to_dict()
    elif isinstance(authorized_bug_bounty, dict):
        payload = _force_safety_dict(dict(authorized_bug_bounty))
    else:
        payload = build_authorized_bug_bounty_plan(
            scope_policy,
            authorized_code_files,
            package_root=resolved_root,
            package_id=package_id,
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["authorized_bug_bounty"] = payload
    out["authorized_web_api"] = payload
    out["authorized_web_api_present"] = True
    out["authorized_bug_bounty_present"] = True
    out["authorized_web_api_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["authorized_web_api_operation_count"] = int(payload.get("operation_count") or 0)
    out["authorized_web_api_role_diff_count"] = int(payload.get("role_diff_count") or 0)
    out["authorized_web_api_business_logic_count"] = int(
        payload.get("business_logic_count") or 0
    )
    out["authorized_web_api_execution_allowed"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out

def _empty_plan(
    *,
    status: str,
    package_id: str,
    package_root: str,
    notes: list[str],
    next_action: str,
) -> AuthorizedBugBountyPlan:
    plan = AuthorizedBugBountyPlan(
        stage=STAGE_PACKAGE,
        inspirations=["XBOW"],
        execution_mode="plan_only",
        allowed_assets=[],
        api_operations=[],
        role_models=[],
        role_diff_plans=[],
        business_logic_candidates=[],
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
        validation_preflight=_validation_preflight([], []),
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
        safety_invariants=list(SAFETY_INVARIANTS),
        status=status,
        package_id=package_id,
        package_root=package_root,
        notes=list(notes),
        next_allowed_action=next_action,
    )
    return _force_safety_plan(plan)

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


def _merge_policy(base: dict[str, Any], loaded: dict[str, Any]) -> dict[str, Any]:
    if not base:
        return dict(loaded)
    out = dict(loaded)
    for key, value in base.items():
        if key == "bug_bounty" and isinstance(value, dict) and isinstance(out.get("bug_bounty"), dict):
            merged = dict(out["bug_bounty"])
            merged.update(value)
            out["bug_bounty"] = merged
        else:
            out[key] = value
    return out


def _is_local_only(policy: dict, bug_bounty: dict) -> bool:
    for src in (policy, bug_bounty):
        if src.get("local_only") is True:
            return True
    return False

def _allowed_assets(policy: dict, full_policy: dict | None = None) -> list[AuthorizedAsset]:
    assets: list[AuthorizedAsset] = []
    sources = [policy]
    if isinstance(full_policy, dict):
        sources.append(full_policy)

    for src in sources:
        for key in ("allowed_assets", "allowed_domains"):
            values = src.get(key)
            if not isinstance(values, list):
                continue
            for value in values:
                if isinstance(value, str) and value.strip():
                    assets.append(
                        AuthorizedAsset(
                            asset=_normalize_asset_label(value),
                            source=f"scope_policy.{key}",
                        )
                    )
        repos = src.get("allowed_repos")
        if isinstance(repos, list):
            for value in repos:
                if isinstance(value, str) and value.strip():
                    assets.append(
                        AuthorizedAsset(
                            asset=_normalize_asset_label(value),
                            source="scope_policy.allowed_repos",
                        )
                    )
        if src.get("local_only") is True:
            assets.append(
                AuthorizedAsset(
                    asset="local_authorized_package",
                    source="scope_policy.local_only",
                )
            )
    return _dedupe_assets(assets)


def _normalize_asset_label(value: str) -> str:
    text = value.strip()
    if text in {"${STAGED_CODE_ROOT}", "$STAGED_CODE_ROOT"}:
        return "local_staged_code_root"
    return _safe_label(text)


def _package_route_operations(policy: dict, bug_bounty: dict) -> list[APIOperation]:
    operations: list[APIOperation] = []
    for src_name, src in (("policy", policy), ("bug_bounty", bug_bounty)):
        routes = src.get("allowed_routes")
        if not isinstance(routes, list):
            continue
        for route in routes:
            if not isinstance(route, str) or not route.strip():
                continue
            path = _safe_path(route)
            operations.append(
                APIOperation(
                    method="GET",
                    path=path,
                    operation_id=None,
                    source=f"package_allowed_routes:{src_name}",
                    sensitivity=_path_sensitivity(path),
                )
            )
    return operations


def _openapi_specs_from_policy(policy: dict, bug_bounty: dict) -> list[dict]:
    specs: list[dict] = []
    for src in (policy, bug_bounty):
        value = src.get("api_specs")
        if isinstance(value, list):
            specs.extend([item for item in value if isinstance(item, dict)])
        openapi = src.get("openapi")
        if isinstance(openapi, dict):
            specs.append({"source": "policy_openapi", "openapi": openapi})
        paths = src.get("paths")
        if isinstance(paths, dict):
            specs.append({"source": "policy_paths", "openapi": {"paths": paths}})
    return specs

def _openapi_operations(value: object) -> list[APIOperation]:
    specs = value if isinstance(value, list) else []
    operations: list[APIOperation] = []
    for spec in specs:
        if not isinstance(spec, dict):
            continue
        source = _safe_label(str(spec.get("source", "openapi")))
        openapi = spec.get("openapi") if isinstance(spec.get("openapi"), dict) else spec
        if not isinstance(openapi, dict):
            continue
        paths = openapi.get("paths") if isinstance(openapi.get("paths"), dict) else {}
        for path, methods in paths.items():
            if not isinstance(path, str) or not isinstance(methods, dict):
                continue
            for method, body in methods.items():
                if not isinstance(method, str) or method.lower() not in HTTP_METHODS:
                    continue
                operation_id = None
                if isinstance(body, dict):
                    raw_id = body.get("operationId")
                    if isinstance(raw_id, str) and raw_id.strip():
                        operation_id = _safe_label(raw_id)
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
    operations: list[APIOperation] = []
    mapped = map_authorized_code_files(
        {"authorized_code_files": list(authorized_code_files or [])}
    )
    for fact in mapped.facts:
        if not fact.route_path:
            continue
        method = fact.route_method or "GET"
        if isinstance(method, str):
            method = method.upper()
        else:
            method = "GET"
        operations.append(
            APIOperation(
                method=method if method.lower() in HTTP_METHODS else "GET",
                path=_safe_path(fact.route_path),
                operation_id=_safe_label(fact.symbol_name) if fact.symbol_name else None,
                source=f"local_route:{_safe_path(fact.source_path)}",
                sensitivity=_path_sensitivity(fact.route_path),
            )
        )
    return operations

def _sanitize_account_list(accounts: list) -> list[dict[str, str]]:
    cleaned: list[dict[str, str]] = []
    for index, account in enumerate(accounts, start=1):
        if not isinstance(account, dict):
            continue
        role = account.get("role")
        if not isinstance(role, str) or not role.strip():
            continue
        label = account.get("label")
        account_label = (
            label if isinstance(label, str) and label.strip() else f"account_{index}"
        )
        cleaned.append(
            {
                "label": _safe_label(account_label),
                "role": _safe_label(role),
            }
        )
    return cleaned


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
        account_label = (
            label if isinstance(label, str) and label.strip() else f"account_{index}"
        )
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
        if "{" in operation.path and any(
            marker in lowered for marker in ("id", "order", "user")
        ):
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
    if any(
        marker in lowered
        for marker in ("admin", "delete", "role", "transfer", "refund", "webhook")
    ):
        return "high"
    if any(marker in lowered for marker in SENSITIVE_PATH_MARKERS) or "{" in path:
        return "medium"
    return "low"

def _package_id_from_root(root: Path) -> str:
    meta = _read_json(root / "package.json")
    if isinstance(meta.get("package_id"), str) and meta["package_id"].strip():
        return meta["package_id"].strip()[:120]
    return root.name[:120]


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _safe_read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if len(text) > _MAX_CONTENT:
        text = text[:_MAX_CONTENT]
    return text


def _iter_code_files(scan_root: Path, *, package_root: Path) -> list[Path]:
    found: list[Path] = []
    try:
        entries = sorted(scan_root.rglob("*"))
    except OSError:
        return found
    for entry in entries:
        if not entry.is_file():
            continue
        if entry.suffix.lower() not in _CODE_SUFFIXES:
            continue
        try:
            rel_parts = entry.resolve().relative_to(package_root.resolve()).parts
        except ValueError:
            continue
        if any(part in _SKIP_DIR_NAMES for part in rel_parts):
            continue
        found.append(entry)
        if len(found) >= _MAX_CODE_FILES:
            break
    return found


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

def _force_safety_plan(plan: AuthorizedBugBountyPlan) -> AuthorizedBugBountyPlan:
    return AuthorizedBugBountyPlan(
        stage=plan.stage,
        inspirations=list(plan.inspirations),
        execution_mode="plan_only",
        allowed_assets=list(plan.allowed_assets),
        api_operations=list(plan.api_operations),
        role_models=list(plan.role_models),
        role_diff_plans=[
            RoleDiffPlan(
                endpoint=item.endpoint,
                method=item.method,
                roles=list(item.roles),
                status=item.status,
                validation_type=item.validation_type,
                execution_allowed=False,
                approval_required=True,
            )
            for item in plan.role_diff_plans
        ],
        business_logic_candidates=list(plan.business_logic_candidates),
        evidence_package=EvidencePackageSchema(
            status=plan.evidence_package.status,
            redaction_required=True,
            required_fields=list(plan.evidence_package.required_fields),
        ),
        human_gate=HumanGate(
            status="required",
            execution_allowed=False,
            approval_required=True,
            required_for=list(plan.human_gate.required_for),
        ),
        validation_preflight=[
            ValidationPreflightCheck(
                check=item.check,
                status=item.status,
                reason=item.reason,
                execution_allowed=False,
                approval_required=True,
            )
            for item in plan.validation_preflight
        ],
        report_draft=ReportDraft(
            status=plan.report_draft.status,
            auto_submit_allowed=False,
            sections=list(plan.report_draft.sections),
        ),
        safety_invariants=list(SAFETY_INVARIANTS),
        status=plan.status,
        package_id=plan.package_id,
        package_root=plan.package_root,
        operation_count=len(plan.api_operations),
        role_diff_count=len(plan.role_diff_plans),
        business_logic_count=len(plan.business_logic_candidates),
        notes=list(plan.notes),
        network_access=False,
        live_validation=False,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        human_approval_required_before_run=True,
        next_allowed_action=plan.next_allowed_action,
    )


def _force_safety_dict(payload: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    out["execution_mode"] = "plan_only"
    out["network_access"] = False
    out["live_validation"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    out["finding_promotion_allowed"] = False
    out["human_approval_required_before_run"] = True
    out["safety_invariants"] = list(SAFETY_INVARIANTS)
    human = out.get("human_gate")
    if isinstance(human, dict):
        human = dict(human)
        human["execution_allowed"] = False
        human["approval_required"] = True
        human["status"] = "required"
        out["human_gate"] = human
    report = out.get("report_draft")
    if isinstance(report, dict):
        report = dict(report)
        report["auto_submit_allowed"] = False
        out["report_draft"] = report
    evidence = out.get("evidence_package")
    if isinstance(evidence, dict):
        evidence = dict(evidence)
        evidence["redaction_required"] = True
        out["evidence_package"] = evidence
    diffs = out.get("role_diff_plans")
    if isinstance(diffs, list):
        cleaned = []
        for item in diffs:
            if not isinstance(item, dict):
                continue
            row = dict(item)
            row["execution_allowed"] = False
            row["approval_required"] = True
            cleaned.append(row)
        out["role_diff_plans"] = cleaned
    preflight = out.get("validation_preflight")
    if isinstance(preflight, list):
        cleaned_pf = []
        for item in preflight:
            if not isinstance(item, dict):
                continue
            row = dict(item)
            row["execution_allowed"] = False
            row["approval_required"] = True
            cleaned_pf.append(row)
        out["validation_preflight"] = cleaned_pf
    return out


__all__ = [
    "APIOperation",
    "AuthorizedAsset",
    "AuthorizedBugBountyPlan",
    "AuthorizedWebApiError",
    "BusinessLogicCandidate",
    "EvidencePackageSchema",
    "HumanGate",
    "ReportDraft",
    "RoleDiffPlan",
    "RoleModel",
    "SAFETY_INVARIANTS",
    "STATUS_EMPTY",
    "STATUS_EMPTY_INPUT",
    "STATUS_READY",
    "STATUS_SKIPPED",
    "ValidationPreflightCheck",
    "attach_authorized_web_api_to_bridge_result",
    "build_authorized_bug_bounty_plan",
    "collect_authorized_code_files",
    "load_package_authorized_bug_bounty_plan",
    "load_package_scope_policy",
]
