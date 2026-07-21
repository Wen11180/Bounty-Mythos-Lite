import ast
from dataclasses import dataclass, replace
from io import StringIO
import re
import tokenize

from app.codebase_map.static_multilang import MULTILANG_SOURCE_SUFFIXES

ROUTE_DECORATOR_PATTERN = re.compile(
    r"@\w+\.(get|post|put|patch|delete)\(\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
ROUTE_DECORATOR_START_PATTERN = re.compile(
    r"@\w+\.(get|post|put|patch|delete)\(",
    re.IGNORECASE,
)
FLASK_ROUTE_DECORATOR_PATTERN = re.compile(
    r"@\w+\.route\(\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
FLASK_ROUTE_METHOD_PATTERN = re.compile(
    r"methods\s*=\s*\[[^\]]*[\"']([A-Za-z]+)[\"']",
    re.IGNORECASE,
)
FLASK_ADD_URL_RULE_PATTERN = re.compile(r"\.add_url_rule\(")
FLASK_METHOD_VIEW_PATTERN = re.compile(
    r"view_func\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\.as_view\(",
)
FLASK_FUNCTION_VIEW_PATTERN = re.compile(
    r"view_func\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\b(?!\s*\.as_view)",
)
METHOD_VIEW_DECORATORS_PATTERN = re.compile(r"\bdecorators\s*=\s*[\[(]([^\])]+)[\])]")
ROUTE_DECORATOR_ROUTER_PATTERN = re.compile(r"@([A-Za-z_][A-Za-z0-9_]*)\.")
AUTHZ_DECORATOR_PATTERN = re.compile(r"^\s*@([A-Za-z_][A-Za-z0-9_]*)\b")
ROUTER_ASSIGNMENT_PATTERN = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?:(?P<module>[A-Za-z_][A-Za-z0-9_]*)\.)?"
    r"(?P<constructor>[A-Za-z_][A-Za-z0-9_]*)\("
)
STRING_LITERAL_PATTERN = re.compile(r"[\"']([^\"']+)[\"']")
FUNCTION_PATTERN = re.compile(r"\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
MODEL_PATTERN = re.compile(r"\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)")
CLASS_PATTERN = re.compile(r"\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\b")
DEPENDENCY_CALL_PATTERN = re.compile(
    r"\b(?:Depends|Security)\(\s*(?:dependency\s*=\s*)?([A-Za-z_][A-Za-z0-9_]*)"
)
DEPENDENCY_ALIAS_PATTERN = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?:Depends|Security)\(\s*(?:dependency\s*=\s*)?([A-Za-z_][A-Za-z0-9_]*)"
)
IMPORT_AUTHZ_ALIAS_PATTERN = re.compile(r"^\s*from\s+[A-Za-z_][A-Za-z0-9_.]*\s+import\s+(.+)$")
IMPORT_ALIAS_ITEM_PATTERN = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s+as\s+([A-Za-z_][A-Za-z0-9_]*)\s*$"
)
YAML_MODULE_IMPORT_PATTERN = re.compile(
    r"^\s*import\s+yaml(?:\s+as\s+(?P<alias>[A-Za-z_][A-Za-z0-9_]*))?\s*(?:#.*)?$"
)
YAML_FROM_IMPORT_PATTERN = re.compile(
    r"^\s*from\s+yaml\s+import\s+(?P<items>[^#]+?)\s*(?:#.*)?$"
)
LOCAL_CALL_ALIAS_PATTERN = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"[A-Za-z_][A-Za-z0-9_.]*\.([A-Za-z_][A-Za-z0-9_]*)\s*$"
)
SELF_CALL_ALIAS_PATTERN = re.compile(
    r"^\s*self\.([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"[A-Za-z_][A-Za-z0-9_.]*\.([A-Za-z_][A-Za-z0-9_]*)\s*$"
)
SELF_NAME_ALIAS_PATTERN = re.compile(
    r"^\s*self\.([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"self\.([A-Za-z_][A-Za-z0-9_]*)\s*$"
)
LOCAL_NAME_ALIAS_PATTERN = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*$"
)
PRINCIPAL_ID_ALIAS_PATTERN = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_.]*)\s*$"
)
SELF_CALL_PATTERN = re.compile(r"\bself\.([A-Za-z_][A-Za-z0-9_]*)\s*\(")
AUTHZ_BOUNDARY_COMPARISON_PATTERN = re.compile(
    r"\b(?P<left>[A-Za-z_][A-Za-z0-9_.]*)\s*==\s*"
    r"(?P<right>[A-Za-z_][A-Za-z0-9_.]*)\b",
    re.IGNORECASE,
)
AUTHZ_BOUNDARY_KWARG_PATTERN = re.compile(
    r"\b(?P<field>(?:owner|user|tenant|account|org|organization|workspace|team|project|group|agent|created_by|owner_id|user_id|created_by_id|tenant_id|account_id|org_id|organization_id|workspace_id|team_id|project_id|group_id|agent_id|owner__id|user__id|created_by__id|tenant__id|account__id|org__id|organization__id|workspace__id|team__id|project__id|group__id|agent__id)(?:__in)?)\s*=\s*"
    r"(?:[\[({]\s*)?"
    r"(?P<value>[A-Za-z_][A-Za-z0-9_.]*)\s*,?\s*[\])}]?",
    re.IGNORECASE,
)
AUTHZ_BOUNDARY_KWARG_START_PATTERN = re.compile(
    r"\b(?P<field>(?:owner|user|tenant|account|org|organization|workspace|team|project|group|agent|created_by|owner_id|user_id|created_by_id|tenant_id|account_id|org_id|organization_id|workspace_id|team_id|project_id|group_id|agent_id|owner__id|user__id|created_by__id|tenant__id|account__id|org__id|organization__id|workspace__id|team__id|project__id|group__id|agent__id)__in)\s*=\s*[\[({]?\s*$",
    re.IGNORECASE,
)
AUTHZ_BOUNDARY_MEMBERSHIP_PATTERN = re.compile(
    r"\b(?P<field>[A-Za-z_][A-Za-z0-9_.]*)\.in_\(\s*"
    r"(?:[\[({]\s*)?"
    r"(?P<values>[A-Za-z_][A-Za-z0-9_.]*)\s*,?\s*[\])}]?\s*\)",
    re.IGNORECASE,
)
AUTHZ_BOUNDARY_MEMBERSHIP_START_PATTERN = re.compile(
    r"\b(?P<field>[A-Za-z_][A-Za-z0-9_.]*)\.in_\(\s*[\[({]?\s*$",
    re.IGNORECASE,
)
IDENTIFIER_LINE_PATTERN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_.]*)\s*,?\s*$")
MEMBERSHIP_WRAPPER_LINE_PATTERN = re.compile(r"^\s*[\[({]\s*$")
AUTHZ_BOUNDARY_FIELDS = {
    "created_by_id",
    "creator_id",
    "author_id",
    "owner_id",
    "user_id",
    "tenant_id",
    "account_id",
    "org_id",
    "organization_id",
    "workspace_id",
    "team_id",
    "project_id",
    "group_id",
    "agent_id",
}
PRINCIPAL_ID_IDENTIFIERS = {
    "user_id",
    "current_user.id",
    "current_user.pk",
    "request.user.id",
    "request.user.pk",
    "user.id",
    "user.pk",
}
AUTHZ_NAME_MARKERS = (
    "authorize",
    "authz",
    "permission",
    "require_role",
    "require_user",
    "require_owner",
    "ensure_owner",
    "check_ownership",
    "verify_ownership",
    "assert_owner",
    "owner_check",
    "ownership",
    "owner_or_admin",
    "owner_guard",
    "can_access",
    "verify_access",
    "assert_access",
    "login_required",
)
SENSITIVE_SINK_NAMES = {
    "apply_user_update",
    "db_select",
    "delete",
    "delete_file",
    "dispatch_agent_tool",
    "execute_query",
    "export",
    "export_file",
    "execute_agent_tool",
    "fetch",
    "get_blob",
    "persist_user",
    "read_file",
    "run_sql",
    "send_file",
    "send_payload",
    "_send_payload",
    "exec",
    "system",
    "transfer",
    "update",
    "update_role",
    "update_user",
}
# Explicit deserialization entry points only. Generic parse/load helpers are not sinks.
UNSAFE_DESERIALIZATION_SINK_NAMES = {
    "pickle_load",
    "pickle_loads",
    "dill_load",
    "dill_loads",
    "yaml_load",
    "unsafe_deserialize",
    "deserialize_untrusted",
}
SENSITIVE_SINK_NAMES.update(UNSAFE_DESERIALIZATION_SINK_NAMES)
# Explicit upload-storage entry points only. Generic file writes are not upload sinks.
FILE_UPLOAD_SINK_NAMES = {
    "save_upload",
    "save_uploaded_file",
    "store_upload",
    "store_uploaded_file",
}
SENSITIVE_SINK_NAMES.update(FILE_UPLOAD_SINK_NAMES)
# Explicit financial action entry points only. Generic transfers remain authorization sinks.
MONEY_FLOW_SINK_NAMES = {
    "apply_credit",
    "capture_payment",
    "charge_card",
    "create_refund",
    "issue_refund",
    "transfer_funds",
}
SENSITIVE_SINK_NAMES.update(MONEY_FLOW_SINK_NAMES)
# Existing sensitive sinks that require per-tool authorization rather than object access alone.
AGENT_TOOL_SINK_NAMES = {
    "dispatch_agent_tool",
    "execute_agent_tool",
}
# Outbound HTTP sinks used for SSRF-family gap root_cause selection.
OUTBOUND_HTTP_SINK_NAMES = {
    "fetch",
    "send_payload",
    "_send_payload",
}
# File-path sinks used for path-traversal-family gap root_cause selection.
FILE_PATH_SINK_NAMES = {
    "get_blob",
    "read_file",
}
# User-field update sinks used for mass-assignment-family gap root_cause selection.
# Keep distinct from generic "update" so authz ownership packages stay ownership-rooted.
MASS_ASSIGN_SINK_NAMES = {
    "apply_user_update",
    "persist_user",
    "update_user",
}
# Query/SQL sinks used for injection-family gap root_cause selection.
INJECTION_SINK_NAMES = {
    "db_select",
    "execute_query",
    "run_sql",
}
# Command execution sinks used for command-injection-family gap root_cause selection.
# Keep this list explicit; generic helpers such as ``run`` are not command sinks.
COMMAND_EXECUTION_SINK_NAMES = {
    "exec",
    "system",
}
# Protective checks that gate user-controlled outbound URLs (SSRF).
SSRF_GUARD_MARKERS = (
    "ssrf",
    "private_ip",
    "blocked_hostname",
    "validate_url",
    "is_private_ip",
    "is_blocked_hostname",
)
# Protective checks that gate user-controlled file paths (path traversal).
PATH_GUARD_MARKERS = (
    "path_base",
    "filepath_base",
    "sanitize_filename",
    "make_filename",
    "safe_path",
    "safe_join",
    "path_traversal",
    "clean_filename",
)
# Protective checks that gate privilege / sensitive field updates (mass assignment).
MASS_ASSIGN_GUARD_MARKERS = (
    "assert_user_change",
    "permission_attrs",
    "mass_assign",
    "field_allowlist",
    "forbid_privilege",
    "exclude_admin",
    "privilege_field",
)
# Protective checks that sanitize / parameterize user-controlled query input (injection).
INJECTION_GUARD_MARKERS = (
    "make_search_string",
    "sanitize_sql",
    "parameterize",
    "bind_query",
    "escape_like",
    "sql_sanitize",
    "full_text_query",
    "regex_full_text",
)
# Protective checks that constrain command selection or arguments before execution.
COMMAND_EXECUTION_GUARD_MARKERS = (
    "command_allowlist",
    "command_whitelist",
    "allowed_command",
    "validate_command",
    "command_validation",
    "safe_command",
)
# Protective checks that constrain serialized payloads before deserialization.
DESERIALIZATION_GUARD_MARKERS = (
    "validate_serialized",
    "validate_deserialization",
    "deserialization_allowlist",
    "safe_deserialize",
    "safe_loader",
)
# Protective checks that constrain uploaded files before storage.
FILE_UPLOAD_GUARD_MARKERS = (
    "validate_upload",
    "validate_uploaded_file",
    "upload_allowlist",
    "upload_type_allowlist",
    "upload_security_check",
)
# Protective checks that derive financial amounts from trusted server-side state.
MONEY_FLOW_GUARD_MARKERS = (
    "derive_server_amount",
    "calculate_server_total",
    "recalculate_order_total",
    "verify_server_price",
)
# Protective checks that bind an agent, user, and task context to a permitted tool.
AGENT_TOOL_GUARD_MARKERS = (
    "assert_tool_allowed",
    "require_tool_permission",
    "tool_allowlist",
    "tool_policy_check",
    "validate_tool_call",
)
STATIC_GAP_GUARD_HINTS = {
    "missing_agent_tool_authorization_check": {
        "agent_tool_authorization_check",
    },
    "missing_server_authoritative_amount_check": {
        "server_authoritative_amount_check",
    },
}
HTTP_METHOD_NAMES = {"get", "post", "put", "patch", "delete"}
CALL_NAME_PATTERN = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
NON_CALL_KEYWORDS = {
    "and",
    "as",
    "assert",
    "await",
    "class",
    "def",
    "for",
    "if",
    "in",
    "not",
    "or",
    "return",
    "while",
    "with",
}
TYPESCRIPT_SOURCE_SUFFIXES = (".ts", ".tsx", ".mts", ".cts")
SUPPORTED_CODE_SOURCE_SUFFIXES = (
    ".py",
    *TYPESCRIPT_SOURCE_SUFFIXES,
    *MULTILANG_SOURCE_SUFFIXES,
)
TYPESCRIPT_ROUTE_CALL_PATTERN = re.compile(
    r"\b(?P<receiver>[A-Za-z_$][A-Za-z0-9_$]*)\."
    r"(?P<method>get|post|put|patch|delete)\s*\(",
    re.IGNORECASE,
)
TYPESCRIPT_USE_CALL_PATTERN = re.compile(
    r"\b(?P<receiver>[A-Za-z_$][A-Za-z0-9_$]*)\.use\s*\(",
    re.IGNORECASE,
)
TYPESCRIPT_FUNCTION_PATTERN = re.compile(
    r"\b(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+"
    r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\([^)]*\)"
    r"\s*(?::\s*[^\{=]+)?\{",
    re.MULTILINE,
)
TYPESCRIPT_ARROW_FUNCTION_PATTERN = re.compile(
    r"\b(?:export\s+)?(?:const|let)\s+"
    r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)"
    r"(?:\s*:\s*[^=;]+)?\s*=\s*(?:async\s+)?"
    r"(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)"
    r"\s*(?::\s*[^=\{]+)?=>\s*\{",
    re.MULTILINE,
)
TYPESCRIPT_CALL_PATTERN = re.compile(
    r"\b(?P<callee>[A-Za-z_$][A-Za-z0-9_$]*"
    r"(?:\s*\.\s*[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\("
)
TYPESCRIPT_COMPARISON_PATTERN = re.compile(
    r"(?P<left>[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+)"
    r"\s*(?:===|!==|==|!=)\s*"
    r"(?P<right>[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+)"
)
# Prisma/query object filters: ownerId: req.user.id
TYPESCRIPT_BOUNDARY_OBJECT_PROP_PATTERN = re.compile(
    r"\b(?P<field>[A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*"
    r"(?P<value>[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+)"
)
TYPESCRIPT_MEMBERSHIP_INCLUDES_PATTERN = re.compile(
    r"(?P<field>[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+)"
    r"\.includes\s*\(\s*"
    r"(?P<principal>[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+)\s*\)"
)
TYPESCRIPT_PUBLIC_FILTER_PATTERN = re.compile(
    r"\b(?:visibility|access|audience)\s*:\s*[\"']public[\"']",
    re.IGNORECASE,
)
TYPESCRIPT_NON_SERVICE_CALLS = {
    "catch",
    "express",
    "for",
    "if",
    "json",
    "next",
    "promise",
    "router",
    "send",
    "send_status",
    "status",
    "switch",
    "while",
}


@dataclass(frozen=True)
class CodebaseFactCandidate:
    fact_type: str
    source_path: str
    symbol_name: str | None
    route_method: str | None
    route_path: str | None
    authz_hint: str | None
    sensitivity_label: str
    payload: dict


@dataclass(frozen=True)
class CodebaseMapResult:
    facts: list[CodebaseFactCandidate]
    file_count: int

    @property
    def route_count(self) -> int:
        return _count_facts(self.facts, "route_handler")

    @property
    def handler_count(self) -> int:
        return self.route_count

    @property
    def model_count(self) -> int:
        return _count_facts(self.facts, "data_model")

    @property
    def authz_check_count(self) -> int:
        return _count_facts(self.facts, "authz_check")

    @property
    def sensitive_sink_count(self) -> int:
        return _count_facts(self.facts, "sensitive_sink")


@dataclass(frozen=True)
class _FastAPIRouterSource:
    source_path: str
    module_name: str
    tree: ast.Module
    app_names: set[str]
    router_prefixes: dict[str, str | None]
    handlers_by_router: dict[str, set[str]]


@dataclass(frozen=True)
class _FlaskBlueprintSource:
    source_path: str
    module_name: str
    tree: ast.Module
    app_names: set[str]
    blueprint_prefixes: dict[str, str | None]
    handlers_by_blueprint: dict[str, set[str]]


@dataclass(frozen=True)
class _DjangoURLSource:
    source_path: str
    module_name: str
    tree: ast.Module


@dataclass(frozen=True)
class _DjangoURLPattern:
    route_path: str | None
    line: int
    view_identity: tuple[str, str] | None
    include_source_path: str | None


def map_authorized_code_files(payload: dict) -> CodebaseMapResult:
    files = payload.get("authorized_code_files")
    if not isinstance(files, list):
        return CodebaseMapResult(facts=[], file_count=0)

    route_prefixes = _merge_static_route_prefixes(
        _fastapi_route_prefixes(files),
        _flask_route_prefixes(files),
    )
    facts: list[CodebaseFactCandidate] = []
    mapped_file_count = 0
    for item in files:
        if not isinstance(item, dict):
            continue
        source_path = item.get("path")
        content = item.get("content")
        if not isinstance(source_path, str) or not isinstance(content, str):
            continue
        mapped_file_count += 1
        if source_path.lower().endswith(TYPESCRIPT_SOURCE_SUFFIXES):
            facts.extend(
                _map_typescript_express_file(
                    source_path=source_path,
                    content=content,
                )
            )
        elif source_path.lower().endswith((".java", ".go", ".rb", ".cs", ".php", ".kt", ".rs", ".scala")):
            from app.codebase_map.static_multilang import map_static_multilang_file

            facts.extend(
                map_static_multilang_file(
                    source_path=source_path,
                    content=content,
                )
            )
        else:
            facts.extend(_map_file(source_path=source_path, content=content))

    facts.extend(_django_route_facts(files))
    facts = _apply_static_route_prefixes(facts, route_prefixes)
    facts = _dedupe_handler_authz_facts(
        _dedupe_facts(_resolve_dependency_wrapper_authz(facts))
    )
    return CodebaseMapResult(
        facts=_dedupe_facts([*facts, *_authorization_gap_candidates(facts)]),
        file_count=mapped_file_count,
    )


def _fastapi_route_prefixes(files: list[object]) -> dict[tuple[str, str], list[str]]:
    sources: list[_FastAPIRouterSource] = []
    for item in files:
        if not isinstance(item, dict):
            continue
        source_path = item.get("path")
        content = item.get("content")
        if (
            not isinstance(source_path, str)
            or not source_path.lower().endswith(".py")
            or not isinstance(content, str)
        ):
            continue
        module_name = _python_module_name(source_path)
        if module_name is None:
            continue
        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue
        router_prefixes = _fastapi_router_prefixes_from_tree(tree)
        sources.append(
            _FastAPIRouterSource(
                source_path=source_path,
                module_name=module_name,
                tree=tree,
                app_names=_fastapi_app_names_from_tree(tree),
                router_prefixes=router_prefixes,
                handlers_by_router=_fastapi_router_handlers(tree, router_prefixes),
            )
        )
    if not sources:
        return {}

    source_by_module = _python_source_by_module(sources)
    nodes = {
        (source.source_path, router_name): prefix
        for source in sources
        for router_name, prefix in source.router_prefixes.items()
        if prefix is not None
    }
    if not nodes:
        return {}

    edges: dict[tuple[str, str], list[tuple[tuple[str, str], str]]] = {}
    roots: list[tuple[tuple[str, str], str]] = []
    for source in sources:
        router_aliases = {
            router_name: (source.source_path, router_name)
            for router_name in source.router_prefixes
            if (source.source_path, router_name) in nodes
        }
        for statement in ast.walk(source.tree):
            if not isinstance(statement, ast.ImportFrom):
                continue
            module_name = _python_import_module_name(
                source.module_name,
                source.source_path,
                statement,
            )
            imported_source_path = (
                source_by_module.get(module_name) if module_name is not None else None
            )
            if imported_source_path is None:
                continue
            for imported in statement.names:
                node = (imported_source_path, imported.name)
                if node in nodes:
                    router_aliases[imported.asname or imported.name] = node

        for call in ast.walk(source.tree):
            if (
                not isinstance(call, ast.Call)
                or not isinstance(call.func, ast.Attribute)
                or call.func.attr != "include_router"
                or not isinstance(call.func.value, ast.Name)
                or not call.args
                or not isinstance(call.args[0], ast.Name)
            ):
                continue
            child = router_aliases.get(call.args[0].id)
            prefix = _static_fastapi_prefix(call)
            if child is None or prefix is None:
                continue
            parent = router_aliases.get(call.func.value.id)
            if parent is None and call.func.value.id in source.app_names:
                roots.append((child, prefix))
            elif parent is not None:
                edges.setdefault(parent, []).append((child, prefix))

    resolved = _resolve_static_router_prefixes(nodes, edges, roots)

    route_prefixes: dict[tuple[str, str], set[str]] = {}
    for source in sources:
        for router_name, handlers in source.handlers_by_router.items():
            node = (source.source_path, router_name)
            local_prefix = nodes.get(node)
            if local_prefix is None:
                continue
            prefixes = resolved.get(node) or {local_prefix}
            for handler_name in handlers:
                route_prefixes.setdefault((source.source_path, handler_name), set()).update(
                    prefixes
                )
    return {
        identity: sorted(prefixes)
        for identity, prefixes in route_prefixes.items()
    }


def _python_module_name(source_path: str) -> str | None:
    normalized = source_path.replace("\\", "/").strip("/")
    if not normalized.endswith(".py"):
        return None
    parts = normalized[:-3].split("/")
    if parts and parts[-1] == "__init__":
        parts.pop()
    if not parts or any(not part.isidentifier() for part in parts):
        return None
    return ".".join(parts)


def _python_source_by_module(
    sources: list[_FastAPIRouterSource | _FlaskBlueprintSource | _DjangoURLSource],
) -> dict[str, str]:
    candidates: dict[str, set[str]] = {}
    for source in sources:
        parts = source.module_name.split(".")
        for index in range(len(parts)):
            candidates.setdefault(".".join(parts[index:]), set()).add(source.source_path)
    return {
        module_name: next(iter(paths))
        for module_name, paths in candidates.items()
        if len(paths) == 1
    }


def _fastapi_router_prefixes_from_tree(tree: ast.Module) -> dict[str, str | None]:
    constructor_names = {"APIRouter"}
    module_names: set[str] = set()
    for statement in ast.walk(tree):
        if isinstance(statement, ast.ImportFrom) and statement.module == "fastapi":
            constructor_names.update(
                imported.asname or imported.name
                for imported in statement.names
                if imported.name == "APIRouter"
            )
        elif isinstance(statement, ast.Import):
            module_names.update(
                imported.asname or imported.name
                for imported in statement.names
                if imported.name == "fastapi"
            )

    prefixes: dict[str, str | None] = {}
    for statement in ast.walk(tree):
        value = (
            statement.value
            if isinstance(statement, (ast.Assign, ast.AnnAssign))
            else None
        )
        if not isinstance(value, ast.Call) or not _is_fastapi_router_call(
            value,
            constructor_names,
            module_names,
        ):
            continue
        targets = (
            statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        )
        prefix = _static_fastapi_prefix(value)
        for target in targets:
            if isinstance(target, ast.Name):
                prefixes[target.id] = prefix
    return prefixes


def _fastapi_app_names_from_tree(tree: ast.Module) -> set[str]:
    constructor_names: set[str] = set()
    module_names: set[str] = set()
    for statement in ast.walk(tree):
        if isinstance(statement, ast.ImportFrom) and statement.module == "fastapi":
            constructor_names.update(
                imported.asname or imported.name
                for imported in statement.names
                if imported.name == "FastAPI"
            )
        elif isinstance(statement, ast.Import):
            module_names.update(
                imported.asname or imported.name
                for imported in statement.names
                if imported.name == "fastapi"
            )

    app_names: set[str] = set()
    for statement in ast.walk(tree):
        value = (
            statement.value
            if isinstance(statement, (ast.Assign, ast.AnnAssign))
            else None
        )
        if not isinstance(value, ast.Call) or not _is_fastapi_app_call(
            value,
            constructor_names,
            module_names,
        ):
            continue
        targets = (
            statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        )
        app_names.update(target.id for target in targets if isinstance(target, ast.Name))
    return app_names


def _is_fastapi_app_call(
    call: ast.Call,
    constructor_names: set[str],
    module_names: set[str],
) -> bool:
    if isinstance(call.func, ast.Name):
        return call.func.id in constructor_names
    return (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "FastAPI"
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id in module_names
    )


def _is_fastapi_router_call(
    call: ast.Call,
    constructor_names: set[str],
    module_names: set[str],
) -> bool:
    if isinstance(call.func, ast.Name):
        return call.func.id in constructor_names
    return (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "APIRouter"
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id in module_names
    )


def _static_fastapi_prefix(call: ast.Call) -> str | None:
    for keyword in call.keywords:
        if keyword.arg == "prefix":
            return (
                keyword.value.value
                if isinstance(keyword.value, ast.Constant)
                and isinstance(keyword.value.value, str)
                else None
            )
    return ""


def _fastapi_router_handlers(
    tree: ast.Module,
    router_prefixes: dict[str, str | None],
) -> dict[str, set[str]]:
    handlers: dict[str, set[str]] = {}
    for statement in ast.walk(tree):
        if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in statement.decorator_list:
            if (
                not isinstance(decorator, ast.Call)
                or not isinstance(decorator.func, ast.Attribute)
                or decorator.func.attr.lower()
                not in {"get", "post", "put", "patch", "delete"}
                or not isinstance(decorator.func.value, ast.Name)
            ):
                continue
            router_name = decorator.func.value.id
            if router_name in router_prefixes:
                handlers.setdefault(router_name, set()).add(statement.name)
    return handlers


def _python_import_module_name(
    source_module_name: str,
    source_path: str,
    statement: ast.ImportFrom,
) -> str | None:
    if not statement.module:
        return None
    if statement.level == 0:
        return statement.module
    parent_parts = source_module_name.split(".")
    if not _python_source_is_package(source_path):
        parent_parts.pop()
    levels_up = statement.level - 1
    if levels_up >= len(parent_parts):
        return None
    return ".".join(
        [
            *parent_parts[: len(parent_parts) - levels_up],
            *statement.module.split("."),
        ]
    )


def _python_source_is_package(source_path: str) -> bool:
    normalized = source_path.replace("\\", "/").strip("/")
    return normalized == "__init__.py" or normalized.endswith("/__init__.py")


def _flask_route_prefixes(files: list[object]) -> dict[tuple[str, str], list[str]]:
    sources: list[_FlaskBlueprintSource] = []
    for item in files:
        if not isinstance(item, dict):
            continue
        source_path = item.get("path")
        content = item.get("content")
        if (
            not isinstance(source_path, str)
            or not source_path.lower().endswith(".py")
            or not isinstance(content, str)
        ):
            continue
        module_name = _python_module_name(source_path)
        if module_name is None:
            continue
        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue
        blueprint_prefixes = _flask_blueprint_prefixes_from_tree(tree)
        sources.append(
            _FlaskBlueprintSource(
                source_path=source_path,
                module_name=module_name,
                tree=tree,
                app_names=_flask_app_names_from_tree(tree),
                blueprint_prefixes=blueprint_prefixes,
                handlers_by_blueprint=_flask_blueprint_handlers(
                    tree,
                    blueprint_prefixes,
                ),
            )
        )
    if not sources:
        return {}

    source_by_module = _python_source_by_module(sources)
    nodes = {
        (source.source_path, blueprint_name): prefix
        for source in sources
        for blueprint_name, prefix in source.blueprint_prefixes.items()
        if prefix is not None
    }
    if not nodes:
        return {}

    edges: dict[tuple[str, str], list[tuple[tuple[str, str], str]]] = {}
    roots: list[tuple[tuple[str, str], str]] = []
    for source in sources:
        blueprint_aliases = {
            blueprint_name: (source.source_path, blueprint_name)
            for blueprint_name in source.blueprint_prefixes
            if (source.source_path, blueprint_name) in nodes
        }
        for statement in ast.walk(source.tree):
            if not isinstance(statement, ast.ImportFrom):
                continue
            module_name = _python_import_module_name(
                source.module_name,
                source.source_path,
                statement,
            )
            imported_source_path = (
                source_by_module.get(module_name) if module_name is not None else None
            )
            if imported_source_path is None:
                continue
            for imported in statement.names:
                node = (imported_source_path, imported.name)
                if node in nodes:
                    blueprint_aliases[imported.asname or imported.name] = node

        for call in ast.walk(source.tree):
            if (
                not isinstance(call, ast.Call)
                or not isinstance(call.func, ast.Attribute)
                or call.func.attr != "register_blueprint"
                or not isinstance(call.func.value, ast.Name)
                or not call.args
                or not isinstance(call.args[0], ast.Name)
            ):
                continue
            child = blueprint_aliases.get(call.args[0].id)
            prefix = _static_flask_prefix(call)
            if child is None or prefix is None:
                continue
            parent = blueprint_aliases.get(call.func.value.id)
            if parent is None and call.func.value.id in source.app_names:
                roots.append((child, prefix))
            elif parent is not None:
                edges.setdefault(parent, []).append((child, prefix))

    resolved = _resolve_static_router_prefixes(nodes, edges, roots)
    route_prefixes: dict[tuple[str, str], set[str]] = {}
    for source in sources:
        for blueprint_name, handlers in source.handlers_by_blueprint.items():
            node = (source.source_path, blueprint_name)
            local_prefix = nodes.get(node)
            if local_prefix is None:
                continue
            prefixes = resolved.get(node) or {local_prefix}
            for handler_name in handlers:
                route_prefixes.setdefault((source.source_path, handler_name), set()).update(
                    prefixes
                )
    return {
        identity: sorted(prefixes)
        for identity, prefixes in route_prefixes.items()
    }


def _flask_blueprint_prefixes_from_tree(tree: ast.Module) -> dict[str, str | None]:
    constructor_names, module_names = _flask_constructor_aliases(tree, "Blueprint")
    prefixes: dict[str, str | None] = {}
    for statement in ast.walk(tree):
        value = (
            statement.value
            if isinstance(statement, (ast.Assign, ast.AnnAssign))
            else None
        )
        if not isinstance(value, ast.Call) or not _is_flask_constructor_call(
            value,
            "Blueprint",
            constructor_names,
            module_names,
        ):
            continue
        targets = (
            statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        )
        prefix = _static_flask_prefix(value)
        for target in targets:
            if isinstance(target, ast.Name):
                prefixes[target.id] = prefix
    return prefixes


def _flask_app_names_from_tree(tree: ast.Module) -> set[str]:
    constructor_names, module_names = _flask_constructor_aliases(tree, "Flask")
    app_names: set[str] = set()
    for statement in ast.walk(tree):
        value = (
            statement.value
            if isinstance(statement, (ast.Assign, ast.AnnAssign))
            else None
        )
        if not isinstance(value, ast.Call) or not _is_flask_constructor_call(
            value,
            "Flask",
            constructor_names,
            module_names,
        ):
            continue
        targets = (
            statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        )
        app_names.update(target.id for target in targets if isinstance(target, ast.Name))
    return app_names


def _flask_constructor_aliases(
    tree: ast.Module,
    constructor_name: str,
) -> tuple[set[str], set[str]]:
    constructor_names: set[str] = set()
    module_names: set[str] = set()
    for statement in ast.walk(tree):
        if isinstance(statement, ast.ImportFrom) and statement.module == "flask":
            constructor_names.update(
                imported.asname or imported.name
                for imported in statement.names
                if imported.name == constructor_name
            )
        elif isinstance(statement, ast.Import):
            module_names.update(
                imported.asname or imported.name
                for imported in statement.names
                if imported.name == "flask"
            )
    return constructor_names, module_names


def _is_flask_constructor_call(
    call: ast.Call,
    constructor_name: str,
    constructor_names: set[str],
    module_names: set[str],
) -> bool:
    if isinstance(call.func, ast.Name):
        return call.func.id in constructor_names
    return (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == constructor_name
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id in module_names
    )


def _static_flask_prefix(call: ast.Call) -> str | None:
    for keyword in call.keywords:
        if keyword.arg == "url_prefix":
            if isinstance(keyword.value, ast.Constant):
                if isinstance(keyword.value.value, str):
                    return keyword.value.value
                if keyword.value.value is None:
                    return ""
            return None
    return ""


def _flask_blueprint_handlers(
    tree: ast.Module,
    blueprint_prefixes: dict[str, str | None],
) -> dict[str, set[str]]:
    handlers: dict[str, set[str]] = {}
    for statement in ast.walk(tree):
        if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in statement.decorator_list:
            if (
                not isinstance(decorator, ast.Call)
                or not isinstance(decorator.func, ast.Attribute)
                or decorator.func.attr.lower()
                not in {"route", "get", "post", "put", "patch", "delete"}
                or not isinstance(decorator.func.value, ast.Name)
            ):
                continue
            blueprint_name = decorator.func.value.id
            if blueprint_name in blueprint_prefixes:
                handlers.setdefault(blueprint_name, set()).add(statement.name)
    return handlers


def _apply_static_route_prefixes(
    facts: list[CodebaseFactCandidate],
    route_prefixes: dict[tuple[str, str], list[str]],
) -> list[CodebaseFactCandidate]:
    rewritten: list[CodebaseFactCandidate] = []
    for fact in facts:
        prefixes = (
            route_prefixes.get((fact.source_path, fact.symbol_name))
            if fact.fact_type == "route_handler" and isinstance(fact.symbol_name, str)
            else None
        )
        if not prefixes or not isinstance(fact.route_path, str):
            rewritten.append(fact)
            continue
        for prefix in prefixes:
            route_path = _join_static_route_path(prefix, fact.route_path)
            rewritten.append(
                fact if route_path == fact.route_path else replace(fact, route_path=route_path)
            )
    return rewritten


def _join_static_route_path(prefix: str, route_path: str) -> str:
    normalized_prefix = "/" + prefix.strip("/") if prefix.strip("/") else ""
    normalized_route = "/" + route_path.lstrip("/") if route_path else ""
    if not normalized_prefix:
        return normalized_route or "/"
    if not normalized_route or normalized_route == "/":
        return normalized_prefix + ("/" if normalized_route == "/" else "")
    return normalized_prefix + normalized_route


def _resolve_static_router_prefixes(
    nodes: dict[tuple[str, str], str],
    edges: dict[tuple[str, str], list[tuple[tuple[str, str], str]]],
    roots: list[tuple[tuple[str, str], str]],
) -> dict[tuple[str, str], set[str]]:
    resolved: dict[tuple[str, str], set[str]] = {}

    def visit(
        node: tuple[str, str],
        parent_prefix: str,
        lineage: set[tuple[str, str]],
    ) -> None:
        if node in lineage:
            return
        local_prefix = nodes.get(node)
        if local_prefix is None:
            return
        prefix = _join_static_route_path(parent_prefix, local_prefix)
        known_prefixes = resolved.setdefault(node, set())
        if prefix in known_prefixes:
            return
        known_prefixes.add(prefix)
        for child, child_prefix in edges.get(node, []):
            visit(child, _join_static_route_path(prefix, child_prefix), lineage | {node})

    for node, prefix in roots:
        visit(node, prefix, set())
    return resolved


def _merge_static_route_prefixes(
    *prefix_maps: dict[tuple[str, str], list[str]],
) -> dict[tuple[str, str], list[str]]:
    merged: dict[tuple[str, str], set[str]] = {}
    for prefix_map in prefix_maps:
        for identity, prefixes in prefix_map.items():
            merged.setdefault(identity, set()).update(prefixes)
    return {identity: sorted(prefixes) for identity, prefixes in merged.items()}


def _django_route_facts(files: list[object]) -> list[CodebaseFactCandidate]:
    sources: list[_DjangoURLSource] = []
    for item in files:
        if not isinstance(item, dict):
            continue
        source_path = item.get("path")
        content = item.get("content")
        if (
            not isinstance(source_path, str)
            or not source_path.lower().endswith(".py")
            or not isinstance(content, str)
        ):
            continue
        module_name = _python_module_name(source_path)
        if module_name is None:
            continue
        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue
        sources.append(
            _DjangoURLSource(
                source_path=source_path,
                module_name=module_name,
                tree=tree,
            )
        )
    if not sources:
        return []

    source_by_module = _python_source_by_module(sources)
    function_lines = _python_function_lines(sources)
    patterns_by_source: dict[str, list[_DjangoURLPattern]] = {}
    for source in sources:
        patterns = _django_url_patterns(
            source,
            source_by_module=source_by_module,
            function_lines=function_lines,
        )
        if patterns is not None:
            patterns_by_source[source.source_path] = patterns
    if not patterns_by_source:
        return []

    roots = _django_root_urlconf_sources(sources, source_by_module)
    facts: list[CodebaseFactCandidate] = []

    def visit(
        source_path: str,
        prefix: str,
        lineage: set[str],
    ) -> None:
        if source_path in lineage:
            return
        for pattern in patterns_by_source.get(source_path, []):
            if pattern.route_path is None:
                continue
            route_path = _join_static_route_path(prefix, pattern.route_path)
            if pattern.include_source_path is not None:
                visit(
                    pattern.include_source_path,
                    route_path,
                    lineage | {source_path},
                )
                continue
            if pattern.view_identity is None:
                continue
            view_source_path, handler_name = pattern.view_identity
            function_line = function_lines.get(pattern.view_identity)
            payload = {
                "handler": handler_name,
                "line": function_line if function_line is not None else pattern.line,
                "mapping_mode": "static_code_snippet_analysis",
                "route_mapping": "static_django_urlconf",
                "route_source_path": source_path,
                "route_line": pattern.line,
            }
            facts.append(
                CodebaseFactCandidate(
                    fact_type="route_handler",
                    source_path=view_source_path,
                    symbol_name=handler_name,
                    route_method="ANY",
                    route_path=route_path,
                    authz_hint=None,
                    sensitivity_label="low",
                    payload=payload,
                )
            )

    for root in roots:
        visit(root, "", set())
    return facts


def _django_root_urlconf_sources(
    sources: list[_DjangoURLSource],
    source_by_module: dict[str, str],
) -> list[str]:
    roots: set[str] = set()
    has_unresolved_root = False
    for source in sources:
        root_source_path: str | None = None
        saw_root_assignment = False
        for statement in source.tree.body:
            value = (
                statement.value
                if isinstance(statement, (ast.Assign, ast.AnnAssign))
                else None
            )
            targets = (
                statement.targets
                if isinstance(statement, ast.Assign)
                else [statement.target]
                if isinstance(statement, ast.AnnAssign)
                else []
            )
            if any(
                isinstance(target, ast.Name) and target.id == "ROOT_URLCONF"
                for target in targets
            ):
                saw_root_assignment = True
                module_name = _static_string(value) if value is not None else None
                root_source_path = (
                    source_by_module.get(module_name)
                    if module_name is not None
                    else None
                )
                continue
            if (
                isinstance(statement, ast.AugAssign)
                and isinstance(statement.target, ast.Name)
                and statement.target.id == "ROOT_URLCONF"
            ):
                saw_root_assignment = True
                root_source_path = None
                continue
            if isinstance(statement, ast.Delete) and any(
                isinstance(target, ast.Name) and target.id == "ROOT_URLCONF"
                for target in statement.targets
            ):
                saw_root_assignment = True
                root_source_path = None
        if saw_root_assignment:
            if root_source_path is None:
                has_unresolved_root = True
            else:
                roots.add(root_source_path)
    return sorted(roots) if len(roots) == 1 and not has_unresolved_root else []


def _python_function_lines(
    sources: list[_DjangoURLSource],
) -> dict[tuple[str, str], int]:
    lines: dict[tuple[str, str], int] = {}
    for source in sources:
        for statement in source.tree.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                lines[(source.source_path, statement.name)] = statement.lineno
    return lines


def _django_url_patterns(
    source: _DjangoURLSource,
    *,
    source_by_module: dict[str, str],
    function_lines: dict[tuple[str, str], int],
) -> list[_DjangoURLPattern] | None:
    path_names, include_names, django_module_names = _django_url_import_names(source.tree)
    if not path_names and not django_module_names:
        return None
    urlpatterns_values: list[ast.expr] = []
    for statement in source.tree.body:
        if isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "urlpatterns"
            for target in statement.targets
        ):
            urlpatterns_values = [statement.value]
        elif (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.target.id == "urlpatterns"
        ):
            urlpatterns_values = [statement.value] if statement.value is not None else []
        elif (
            isinstance(statement, ast.AugAssign)
            and isinstance(statement.target, ast.Name)
            and statement.target.id == "urlpatterns"
        ):
            if isinstance(statement.op, ast.Add):
                urlpatterns_values.append(statement.value)
            else:
                urlpatterns_values = []
    if not urlpatterns_values:
        return None

    view_aliases, module_aliases = _django_view_import_aliases(
        source,
        source_by_module=source_by_module,
        function_lines=function_lines,
    )
    patterns: list[_DjangoURLPattern] = []
    for value in urlpatterns_values:
        if not isinstance(value, (ast.List, ast.Tuple)):
            continue
        for element in value.elts:
            pattern = _django_url_pattern(
                element,
                path_names=path_names,
                include_names=include_names,
                django_module_names=django_module_names,
                source_by_module=source_by_module,
                function_lines=function_lines,
                view_aliases=view_aliases,
                module_aliases=module_aliases,
            )
            if pattern is not None:
                patterns.append(pattern)
    return patterns


def _django_url_import_names(
    tree: ast.Module,
) -> tuple[set[str], set[str], set[str]]:
    path_names: set[str] = set()
    include_names: set[str] = set()
    django_module_names: set[str] = set()
    for statement in tree.body:
        if isinstance(statement, ast.ImportFrom) and statement.module == "django.urls":
            for imported in statement.names:
                if imported.name == "path":
                    path_names.add(imported.asname or imported.name)
                elif imported.name == "include":
                    include_names.add(imported.asname or imported.name)
        elif isinstance(statement, ast.Import):
            for imported in statement.names:
                if imported.name == "django.urls":
                    django_module_names.add(imported.asname or imported.name)
    return path_names, include_names, django_module_names


def _django_view_import_aliases(
    source: _DjangoURLSource,
    *,
    source_by_module: dict[str, str],
    function_lines: dict[tuple[str, str], int],
) -> tuple[dict[str, tuple[str, str]], dict[str, str]]:
    view_aliases: dict[str, tuple[str, str]] = {
        name: (source.source_path, name)
        for source_path, name in function_lines
        if source_path == source.source_path
    }
    module_aliases: dict[str, str] = {}
    for statement in source.tree.body:
        if isinstance(statement, ast.Import):
            for imported in statement.names:
                imported_source_path = source_by_module.get(imported.name)
                if imported_source_path is not None and imported.asname:
                    module_aliases[imported.asname] = imported_source_path
            continue
        if not isinstance(statement, ast.ImportFrom):
            continue
        module_name = _django_import_module_name(source.module_name, statement)
        if module_name is None:
            continue
        imported_source_path = source_by_module.get(module_name)
        for imported in statement.names:
            local_name = imported.asname or imported.name
            nested_source_path = source_by_module.get(
                f"{module_name}.{imported.name}"
            )
            if nested_source_path is not None:
                module_aliases[local_name] = nested_source_path
            if (
                imported_source_path is not None
                and (imported_source_path, imported.name) in function_lines
            ):
                view_aliases[local_name] = (imported_source_path, imported.name)
    return view_aliases, module_aliases


def _django_import_module_name(
    source_module_name: str,
    statement: ast.ImportFrom,
) -> str | None:
    if statement.level == 0:
        return statement.module
    parent_parts = source_module_name.split(".")[:-1]
    levels_up = statement.level - 1
    if levels_up > len(parent_parts):
        return None
    base_parts = parent_parts[: len(parent_parts) - levels_up]
    if statement.module:
        base_parts.extend(statement.module.split("."))
    return ".".join(base_parts) or None


def _django_url_pattern(
    value: ast.expr,
    *,
    path_names: set[str],
    include_names: set[str],
    django_module_names: set[str],
    source_by_module: dict[str, str],
    function_lines: dict[tuple[str, str], int],
    view_aliases: dict[str, tuple[str, str]],
    module_aliases: dict[str, str],
) -> _DjangoURLPattern | None:
    if not isinstance(value, ast.Call) or not _is_django_url_call(
        value,
        "path",
        path_names,
        django_module_names,
    ):
        return None
    if len(value.args) < 2:
        return None
    route_path = _static_string(value.args[0])
    target = value.args[1]
    if isinstance(target, ast.Call) and _is_django_url_call(
        target,
        "include",
        include_names,
        django_module_names,
    ):
        include_module_name = _django_include_module_name(target)
        return _DjangoURLPattern(
            route_path=route_path,
            line=value.lineno,
            view_identity=None,
            include_source_path=(
                source_by_module.get(include_module_name)
                if include_module_name is not None
                else None
            ),
        )
    return _DjangoURLPattern(
        route_path=route_path,
        line=value.lineno,
        view_identity=_django_view_identity(
            target,
            function_lines=function_lines,
            view_aliases=view_aliases,
            module_aliases=module_aliases,
        ),
        include_source_path=None,
    )


def _is_django_url_call(
    call: ast.Call,
    name: str,
    names: set[str],
    django_module_names: set[str],
) -> bool:
    if isinstance(call.func, ast.Name):
        return call.func.id in names
    return (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == name
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id in django_module_names
    )


def _static_string(value: ast.expr) -> str | None:
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return value.value
    return None


def _django_include_module_name(call: ast.Call) -> str | None:
    if not call.args:
        return None
    module_name = _static_string(call.args[0])
    if module_name is not None:
        return module_name
    if isinstance(call.args[0], ast.Tuple) and call.args[0].elts:
        return _static_string(call.args[0].elts[0])
    return None


def _django_view_identity(
    target: ast.expr,
    *,
    function_lines: dict[tuple[str, str], int],
    view_aliases: dict[str, tuple[str, str]],
    module_aliases: dict[str, str],
) -> tuple[str, str] | None:
    if isinstance(target, ast.Name):
        identity = view_aliases.get(target.id)
        if identity in function_lines:
            return identity
        return None
    if (
        not isinstance(target, ast.Attribute)
        or not isinstance(target.value, ast.Name)
    ):
        return None
    source_path = module_aliases.get(target.value.id)
    identity = (source_path, target.attr) if source_path is not None else None
    if identity in function_lines:
        return identity
    return None


def _map_file(*, source_path: str, content: str) -> list[CodebaseFactCandidate]:
    facts: list[CodebaseFactCandidate] = []
    pending_route: (
        tuple[str, str, int, list[tuple[str, int]], list[tuple[str, int]]] | None
    ) = None
    pending_decorator_authz_refs: list[tuple[str, int]] = []
    pending_route_decorator: (
        tuple[str, int, list[str], list[tuple[str, int]], list[tuple[str, int]]] | None
    ) = None
    pending_router_assignment: tuple[str, int, list[str], str] | None = None
    pending_add_url_rule: tuple[int, list[str]] | None = None
    pending_signature_authz: tuple[str, int] | None = None
    pending_membership_filter: tuple[str, str, int] | None = None
    pending_kwarg_membership_filter: tuple[str, str, int] | None = None
    function_stack: list[tuple[str, int]] = []
    class_stack: list[tuple[str, int]] = []
    dependency_aliases: dict[str, str] = {}
    dependency_wrapper_aliases: dict[str, str] = {}
    router_authz_refs: dict[str, list[tuple[str, int]]] = {}
    router_dependency_refs: dict[str, list[tuple[str, int]]] = {}
    router_constructor_aliases: set[str] = set()
    import_aliases: dict[str, str] = {}
    yaml_module_aliases = {"yaml"}
    yaml_load_aliases: set[str] = set()
    yaml_safe_loader_aliases: set[str] = set()
    local_call_aliases: dict[str, dict[str, str]] = {}
    class_call_aliases: dict[str, dict[str, str]] = {}
    principal_id_aliases: dict[str, dict[str, str]] = {}
    function_authz_refs: dict[str, list[tuple[str, int]]] = {}
    method_view_classes: set[str] = set()
    method_view_methods: dict[str, set[str]] = {}
    method_view_authz_refs: dict[str, list[tuple[str, int]]] = {}
    method_view_method_authz_refs: dict[tuple[str, str], list[tuple[str, int]]] = {}

    for line_number, line in enumerate(content.splitlines(), start=1):
        if pending_add_url_rule is not None:
            add_url_rule_line, add_url_rule_lines = pending_add_url_rule
            add_url_rule_lines = [*add_url_rule_lines, line]
            if _flask_add_url_rule_closed(add_url_rule_lines):
                facts.extend(
                    _flask_method_view_route_facts(
                        source_path,
                        add_url_rule_lines,
                        add_url_rule_line,
                        method_view_methods,
                        method_view_authz_refs,
                        method_view_method_authz_refs,
                    )
                )
                facts.extend(
                    _flask_function_add_url_rule_route_facts(
                        source_path,
                        add_url_rule_lines,
                        add_url_rule_line,
                        function_authz_refs,
                    )
                )
                pending_add_url_rule = None
            else:
                pending_add_url_rule = (add_url_rule_line, add_url_rule_lines)
            continue

        if pending_router_assignment is not None:
            (
                router_name,
                router_line,
                router_lines,
                router_constructor,
            ) = pending_router_assignment
            router_lines = [*router_lines, line]
            if _router_assignment_closed(router_lines, router_constructor):
                router_authz_refs[router_name] = _dedupe_refs(
                    _dependency_authz_refs_from_lines(
                        router_lines,
                        router_line,
                        dependency_aliases,
                    )
                )
                router_dependency_refs[router_name] = _dedupe_refs(
                    _dependency_wrapper_refs_from_lines(
                        router_lines,
                        router_line,
                        dependency_aliases,
                        dependency_wrapper_aliases,
                    )
                )
                pending_router_assignment = None
            else:
                pending_router_assignment = (
                    router_name,
                    router_line,
                    router_lines,
                    router_constructor,
                )
            continue

        if pending_route_decorator is not None:
            (
                method,
                decorator_line,
                decorator_lines,
                authz_calls,
                dependency_calls,
            ) = pending_route_decorator
            decorator_lines = [*decorator_lines, line]
            authz_calls = [
                *authz_calls,
                *_dependency_authz_refs(
                    line,
                    line_number,
                    dependency_aliases,
                ),
            ]
            dependency_calls = [
                *dependency_calls,
                *_dependency_wrapper_refs(
                    line,
                    line_number,
                    dependency_aliases,
                    dependency_wrapper_aliases,
                ),
            ]
            if _route_decorator_closed(line):
                authz_calls = _dedupe_refs(
                    [
                        *authz_calls,
                        *_dependency_authz_refs_from_lines(
                            decorator_lines,
                            decorator_line,
                            dependency_aliases,
                        ),
                    ]
                )
                dependency_calls = _dedupe_refs(
                    [
                        *dependency_calls,
                        *_dependency_wrapper_refs_from_lines(
                            decorator_lines,
                            decorator_line,
                            dependency_aliases,
                            dependency_wrapper_aliases,
                        ),
                    ]
                )
                route_path = _route_path_from_decorator_lines(decorator_lines)
                if route_path is not None:
                    pending_route = (
                        method,
                        route_path,
                        decorator_line,
                        authz_calls,
                        dependency_calls,
                    )
                pending_route_decorator = None
            else:
                pending_route_decorator = (
                    method,
                    decorator_line,
                    decorator_lines,
                    authz_calls,
                    dependency_calls,
                )
            continue

        authz_decorator_ref = _authz_decorator_ref(line, line_number, import_aliases)
        if authz_decorator_ref is not None:
            if pending_route is not None:
                (
                    method,
                    route_path,
                    decorator_line,
                    authz_calls,
                    dependency_calls,
                ) = pending_route
                pending_route = (
                    method,
                    route_path,
                    decorator_line,
                    _dedupe_refs([*authz_calls, authz_decorator_ref]),
                    dependency_calls,
                )
            else:
                pending_decorator_authz_refs = _dedupe_refs(
                    [*pending_decorator_authz_refs, authz_decorator_ref]
                )
            continue

        router_assignment_match = ROUTER_ASSIGNMENT_PATTERN.match(line)
        if (
            router_assignment_match is not None
            and not function_stack
            and _is_router_constructor(
                router_assignment_match.group("module"),
                router_assignment_match.group("constructor"),
                router_constructor_aliases,
            )
        ):
            router_name = router_assignment_match.group(1)
            router_constructor = router_assignment_match.group("constructor")
            if _router_assignment_closed([line], router_constructor):
                router_authz_refs[router_name] = _dependency_authz_refs(
                    line,
                    line_number,
                    dependency_aliases,
                )
                router_dependency_refs[router_name] = _dependency_wrapper_refs(
                    line,
                    line_number,
                    dependency_aliases,
                    dependency_wrapper_aliases,
                )
            else:
                pending_router_assignment = (
                    router_name,
                    line_number,
                    [line],
                    router_constructor,
                )
                continue

        route_match = ROUTE_DECORATOR_PATTERN.search(line)
        if route_match is not None:
            router_name = _route_decorator_router_name(line)
            pending_route = (
                route_match.group(1).upper(),
                route_match.group(2),
                line_number,
                _dedupe_refs(
                    [
                        *pending_decorator_authz_refs,
                        *router_authz_refs.get(router_name, []),
                        *_dependency_authz_refs(line, line_number, dependency_aliases),
                    ]
                ),
                _dedupe_refs(
                    [
                        *router_dependency_refs.get(router_name, []),
                        *_dependency_wrapper_refs(
                            line,
                            line_number,
                            dependency_aliases,
                            dependency_wrapper_aliases,
                        ),
                    ]
                ),
            )
            pending_decorator_authz_refs = []
            continue
        flask_route_match = FLASK_ROUTE_DECORATOR_PATTERN.search(line)
        if flask_route_match is not None:
            pending_route = (
                _flask_route_method(line),
                flask_route_match.group(1),
                line_number,
                pending_decorator_authz_refs,
                [],
            )
            pending_decorator_authz_refs = []
            continue
        route_start_match = ROUTE_DECORATOR_START_PATTERN.search(line)
        if route_start_match is not None:
            router_name = _route_decorator_router_name(line)
            pending_route_decorator = (
                route_start_match.group(1).upper(),
                line_number,
                [line],
                _dedupe_refs(
                    [
                        *pending_decorator_authz_refs,
                        *router_authz_refs.get(router_name, []),
                        *_dependency_authz_refs(line, line_number, dependency_aliases),
                    ]
                ),
                _dedupe_refs(
                    [
                        *router_dependency_refs.get(router_name, []),
                        *_dependency_wrapper_refs(
                            line,
                            line_number,
                            dependency_aliases,
                            dependency_wrapper_aliases,
                        ),
                    ]
                ),
            )
            pending_decorator_authz_refs = []
            continue

        if line.strip():
            if (
                not line.strip().startswith("@")
                and FUNCTION_PATTERN.match(line) is None
            ):
                pending_decorator_authz_refs = []
            indent = _indent_width(line)
            class_stack = [
                (class_name, class_indent)
                for class_name, class_indent in class_stack
                if class_indent < indent
            ]
            function_stack = [
                (function_name, function_indent)
                for function_name, function_indent in function_stack
                if function_indent < indent
            ]

        if not function_stack:
            (
                imported_yaml_modules,
                imported_yaml_loads,
                imported_yaml_safe_loaders,
            ) = _yaml_import_aliases(line)
            yaml_module_aliases.update(imported_yaml_modules)
            yaml_load_aliases.update(imported_yaml_loads)
            yaml_safe_loader_aliases.update(imported_yaml_safe_loaders)

        imported_aliases = _imported_aliases(line)
        dependency_imported_aliases = _dependency_imported_aliases(line)
        if (imported_aliases or dependency_imported_aliases) and not function_stack:
            for alias_name, call_name in imported_aliases:
                if alias_name in yaml_load_aliases:
                    continue
                import_aliases[alias_name] = call_name
                if call_name == "APIRouter":
                    router_constructor_aliases.add(alias_name)
                if _is_authz_call(call_name):
                    dependency_aliases[alias_name] = call_name
            for alias_name, call_name in dependency_imported_aliases:
                dependency_wrapper_aliases[alias_name] = call_name
            continue

        alias = _dependency_alias(line)
        if alias is not None and not function_stack:
            alias_name, call_name = alias
            if _is_authz_call(call_name):
                dependency_aliases[alias_name] = call_name
            else:
                dependency_wrapper_aliases[alias_name] = call_name
                facts.append(
                    CodebaseFactCandidate(
                        fact_type="dependency_call",
                        source_path=source_path,
                        symbol_name=call_name,
                        route_method=None,
                        route_path=None,
                        authz_hint=None,
                        sensitivity_label="low",
                        payload={
                            "caller": alias_name,
                            "line": line_number,
                            "mapping_mode": "static_code_snippet_analysis",
                        },
                    )
                )
            continue

        if FLASK_ADD_URL_RULE_PATTERN.search(line) is not None and not function_stack:
            if _flask_add_url_rule_closed([line]):
                facts.extend(
                    _flask_method_view_route_facts(
                        source_path,
                        [line],
                        line_number,
                        method_view_methods,
                        method_view_authz_refs,
                        method_view_method_authz_refs,
                    )
                )
                facts.extend(
                    _flask_function_add_url_rule_route_facts(
                        source_path,
                        [line],
                        line_number,
                        function_authz_refs,
                    )
                )
            else:
                pending_add_url_rule = (line_number, [line])
            continue

        function_match = FUNCTION_PATTERN.match(line)
        if function_match is not None:
            class_name = _current_class(class_stack)
            function_name = function_match.group(1).lower()
            is_method_view_method = (
                class_name in method_view_classes
                and function_name in HTTP_METHOD_NAMES
            )
            if is_method_view_method:
                method_view_methods.setdefault(class_name, set()).add(function_name)
                method_view_method_authz_refs[(class_name, function_name)] = _dedupe_refs(
                    [
                        *method_view_method_authz_refs.get(
                            (class_name, function_name),
                            [],
                        ),
                        *pending_decorator_authz_refs,
                    ]
                )
                pending_decorator_authz_refs = []
            elif pending_route is None:
                if pending_decorator_authz_refs:
                    function_authz_refs[function_match.group(1)] = _dedupe_refs(
                        [
                            *function_authz_refs.get(function_match.group(1), []),
                            *pending_decorator_authz_refs,
                        ]
                    )
                pending_decorator_authz_refs = []
            function_stack.append((function_match.group(1), _indent_width(line)))
        if function_match is not None and pending_route is None:
            function_name = function_match.group(1)
            for call_name, authz_line in _dependency_authz_refs(
                line,
                line_number,
                dependency_aliases,
            ):
                facts.append(
                    CodebaseFactCandidate(
                        fact_type="authz_check",
                        source_path=source_path,
                        symbol_name=call_name,
                        route_method=None,
                        route_path=None,
                        authz_hint=_authz_hint(call_name),
                        sensitivity_label="low",
                        payload={
                            "handler": function_name,
                            "line": authz_line,
                            "mapping_mode": "static_code_snippet_analysis",
                        },
                    )
                )
            for call_name, dependency_line in _dependency_wrapper_refs(
                line,
                line_number,
                dependency_aliases,
                dependency_wrapper_aliases,
            ):
                facts.append(
                    CodebaseFactCandidate(
                        fact_type="dependency_call",
                        source_path=source_path,
                        symbol_name=call_name,
                        route_method=None,
                        route_path=None,
                        authz_hint=None,
                        sensitivity_label="low",
                        payload={
                            "caller": function_name,
                            "line": dependency_line,
                            "mapping_mode": "static_code_snippet_analysis",
                        },
                    )
                )
        if function_match is not None and pending_route is not None:
            (
                method,
                route_path,
                decorator_line,
                decorator_authz_calls,
                decorator_dependency_calls,
            ) = pending_route
            handler_name = function_match.group(1)
            facts.append(
                CodebaseFactCandidate(
                    fact_type="route_handler",
                    source_path=source_path,
                    symbol_name=handler_name,
                    route_method=method,
                    route_path=route_path,
                    authz_hint=None,
                    sensitivity_label="low",
                    payload={
                        "handler": handler_name,
                        "line": decorator_line,
                        "mapping_mode": "static_code_snippet_analysis",
                    },
                )
            )
            for call_name, authz_line in [
                *decorator_authz_calls,
                *_dependency_authz_refs(
                    line,
                    line_number,
                    dependency_aliases,
                ),
            ]:
                facts.append(
                    CodebaseFactCandidate(
                        fact_type="authz_check",
                        source_path=source_path,
                        symbol_name=call_name,
                        route_method=None,
                        route_path=None,
                        authz_hint=_authz_hint(call_name),
                        sensitivity_label="low",
                        payload={
                            "handler": handler_name,
                            "line": authz_line,
                            "mapping_mode": "static_code_snippet_analysis",
                        },
                    )
                )
            for call_name, dependency_line in [
                *decorator_dependency_calls,
                *_dependency_wrapper_refs(
                    line,
                    line_number,
                    dependency_aliases,
                    dependency_wrapper_aliases,
                ),
            ]:
                facts.append(
                    CodebaseFactCandidate(
                        fact_type="dependency_call",
                        source_path=source_path,
                        symbol_name=call_name,
                        route_method=None,
                        route_path=None,
                        authz_hint=None,
                        sensitivity_label="low",
                        payload={
                            "caller": handler_name,
                            "line": dependency_line,
                            "mapping_mode": "static_code_snippet_analysis",
                        },
                    )
                )
            if not _function_signature_closed(line):
                pending_signature_authz = (handler_name, _indent_width(line))
            pending_route = None

        if function_match is None and pending_signature_authz is not None:
            handler_name, function_indent = pending_signature_authz
            for call_name, authz_line in _dependency_authz_refs(
                line,
                line_number,
                dependency_aliases,
            ):
                facts.append(
                    CodebaseFactCandidate(
                        fact_type="authz_check",
                        source_path=source_path,
                        symbol_name=call_name,
                        route_method=None,
                        route_path=None,
                        authz_hint=_authz_hint(call_name),
                        sensitivity_label="low",
                        payload={
                            "handler": handler_name,
                            "line": authz_line,
                            "mapping_mode": "static_code_snippet_analysis",
                        },
                    )
                )
            for call_name, dependency_line in _dependency_wrapper_refs(
                line,
                line_number,
                dependency_aliases,
                dependency_wrapper_aliases,
            ):
                facts.append(
                    CodebaseFactCandidate(
                        fact_type="dependency_call",
                        source_path=source_path,
                        symbol_name=call_name,
                        route_method=None,
                        route_path=None,
                        authz_hint=None,
                        sensitivity_label="low",
                        payload={
                            "caller": handler_name,
                            "line": dependency_line,
                            "mapping_mode": "static_code_snippet_analysis",
                        },
                    )
                )
            if _function_signature_closed(line):
                pending_signature_authz = None

        class_match = CLASS_PATTERN.match(line)
        if class_match is not None:
            class_stack.append((class_match.group(1), _indent_width(line)))

        model_match = MODEL_PATTERN.match(line)
        if model_match is not None and _is_method_view_base(model_match.group(2)):
            method_view_classes.add(model_match.group(1))
        if model_match is not None and _is_model_base(model_match.group(2)):
            facts.append(
                CodebaseFactCandidate(
                    fact_type="data_model",
                    source_path=source_path,
                    symbol_name=model_match.group(1),
                    route_method=None,
                    route_path=None,
                    authz_hint=None,
                    sensitivity_label="low",
                    payload={
                        "line": line_number,
                        "mapping_mode": "static_code_snippet_analysis",
                    },
                )
            )

        if (
            function_match is not None
            or class_match is not None
            or model_match is not None
            or pending_signature_authz is not None
            or line.strip().startswith("@")
        ):
            continue

        current_class = _current_class(class_stack)
        current_function = _qualified_method_view_function(
            _current_function(function_stack),
            current_class,
            method_view_classes,
        )
        if current_class in method_view_classes:
            method_view_authz_refs[current_class] = _dedupe_refs(
                [
                    *method_view_authz_refs.get(current_class, []),
                    *_method_view_decorator_authz_refs(
                        line,
                        line_number,
                        import_aliases,
                    ),
                ]
            )
        local_alias = _local_call_alias(line)
        if current_function is not None and local_alias is not None:
            alias_name, call_name = local_alias
            local_call_aliases.setdefault(current_function, {})[alias_name] = call_name
        field_alias = _self_call_alias(line)
        if current_class is not None and field_alias is not None:
            alias_name, call_name = field_alias
            class_call_aliases.setdefault(current_class, {})[alias_name] = call_name
        chained_field_alias = _self_name_alias(line)
        if current_class is not None and chained_field_alias is not None:
            alias_name, existing_alias = chained_field_alias
            class_aliases = class_call_aliases.setdefault(current_class, {})
            if existing_alias in class_aliases:
                class_aliases[alias_name] = class_aliases[existing_alias]
        chained_alias = _local_name_alias(line)
        if current_function is not None and chained_alias is not None:
            alias_name, existing_alias = chained_alias
            local_aliases = local_call_aliases.setdefault(current_function, {})
            if existing_alias in local_aliases:
                local_aliases[alias_name] = local_aliases[existing_alias]

        principal_id_alias = _principal_id_alias(line)
        if current_function is not None and principal_id_alias is not None:
            alias_name, boundary_field = principal_id_alias
            principal_id_aliases.setdefault(current_function, {})[alias_name] = boundary_field

        if current_function is not None and pending_membership_filter is not None:
            handler, field_name, membership_line = pending_membership_filter
            values = _identifier_line_value(line)
            if handler == current_function and values is None and _membership_wrapper_line(line):
                continue
            if handler == current_function and values is not None:
                boundary_field = _authz_boundary_membership_field(
                    field_name,
                    values,
                    principal_id_aliases.get(current_function, {}),
                )
                if boundary_field is not None:
                    facts.append(
                        CodebaseFactCandidate(
                            fact_type="authz_check",
                            source_path=source_path,
                            symbol_name=f"{boundary_field}_filter",
                            route_method=None,
                            route_path=None,
                            authz_hint=_authz_boundary_hint(boundary_field),
                            sensitivity_label="low",
                            payload={
                                "handler": current_function,
                                "line": membership_line,
                                "mapping_mode": "static_code_snippet_analysis",
                            },
                        )
                    )
            pending_membership_filter = None

        if (
            current_function is not None
            and pending_kwarg_membership_filter is not None
        ):
            handler, field_name, membership_line = pending_kwarg_membership_filter
            value = _identifier_line_value(line)
            if handler == current_function and value is None and _membership_wrapper_line(line):
                continue
            if handler == current_function and value is not None:
                boundary_field = _authz_boundary_kwarg_field(
                    field_name,
                    value,
                    principal_id_aliases.get(current_function, {}),
                )
                if boundary_field is not None:
                    facts.append(
                        CodebaseFactCandidate(
                            fact_type="authz_check",
                            source_path=source_path,
                            symbol_name=f"{boundary_field}_filter",
                            route_method=None,
                            route_path=None,
                            authz_hint=_authz_boundary_hint(boundary_field),
                            sensitivity_label="low",
                            payload={
                                "handler": current_function,
                                "line": membership_line,
                                "mapping_mode": "static_code_snippet_analysis",
                            },
                        )
                    )
            pending_kwarg_membership_filter = None

        boundary_filter = _authz_boundary_filter(
            line,
            principal_id_aliases.get(current_function or "", {}),
        )
        if current_function is not None and boundary_filter is not None:
            symbol_name, authz_hint = boundary_filter
            facts.append(
                CodebaseFactCandidate(
                    fact_type="authz_check",
                    source_path=source_path,
                    symbol_name=symbol_name,
                    route_method=None,
                    route_path=None,
                    authz_hint=authz_hint,
                    sensitivity_label="low",
                    payload={
                        "handler": current_function,
                        "line": line_number,
                        "mapping_mode": "static_code_snippet_analysis",
                    },
                )
            )
        elif current_function is not None:
            membership_field = _authz_boundary_membership_start(line)
            if membership_field is not None:
                pending_membership_filter = (
                    current_function,
                    membership_field,
                    line_number,
                )
            else:
                kwarg_membership_field = _authz_boundary_kwarg_membership_start(line)
                if kwarg_membership_field is not None:
                    pending_kwarg_membership_filter = (
                        current_function,
                        kwarg_membership_field,
                        line_number,
                    )
        for raw_call_name in _called_names(
            line,
            yaml_module_aliases=yaml_module_aliases,
            yaml_load_aliases=yaml_load_aliases,
            yaml_safe_loader_aliases=yaml_safe_loader_aliases,
        ):
            call_name = _resolved_call_name(
                raw_call_name,
                current_function,
                current_class,
                _self_called_names(line),
                import_aliases,
                local_call_aliases,
                class_call_aliases,
            )
            if _is_authz_call(call_name):
                facts.append(
                    CodebaseFactCandidate(
                        fact_type="authz_check",
                        source_path=source_path,
                        symbol_name=call_name,
                        route_method=None,
                        route_path=None,
                        authz_hint=_authz_hint(call_name),
                        sensitivity_label="low",
                        payload={
                            "handler": current_function,
                            "line": line_number,
                            "mapping_mode": "static_code_snippet_analysis",
                        },
                    )
                )
            if _is_sensitive_sink(call_name):
                facts.append(
                    CodebaseFactCandidate(
                        fact_type="sensitive_sink",
                        source_path=source_path,
                        symbol_name=call_name,
                        route_method=None,
                        route_path=None,
                        authz_hint=None,
                        sensitivity_label="low",
                        payload={
                            "handler": current_function,
                            "line": line_number,
                            "mapping_mode": "static_code_snippet_analysis",
                        },
                    )
                )
            if _is_service_call(call_name) and current_function is not None:
                facts.append(
                    CodebaseFactCandidate(
                        fact_type="service_call",
                        source_path=source_path,
                        symbol_name=call_name,
                        route_method=None,
                        route_path=None,
                        authz_hint=None,
                        sensitivity_label="low",
                        payload={
                            "caller": current_function,
                            "line": line_number,
                            "mapping_mode": "static_code_snippet_analysis",
                        },
                    )
                )

    return facts


def _map_typescript_express_file(
    *,
    source_path: str,
    content: str,
) -> list[CodebaseFactCandidate]:
    source = _strip_typescript_comments(content)
    express_objects = _typescript_express_objects(source)
    facts: list[CodebaseFactCandidate] = []
    # Modules without Express routers still contribute helper authz/service facts
    # so cross-file ownership helpers remain reachable from route handlers.
    if not express_objects:
        function_spans = _typescript_function_spans(source)
        for function_name, declaration_start, body_start, body_end in function_spans:
            nested_ranges = [
                (nested_start, nested_end + 1)
                for _, nested_start, _, nested_end in function_spans
                if declaration_start < nested_start and nested_end <= body_end
            ]
            facts.extend(
                _typescript_function_facts(
                    source_path=source_path,
                    source=source,
                    function_name=function_name,
                    body_start=body_start,
                    body_end=body_end,
                    nested_ranges=nested_ranges,
                )
            )
        facts.extend(
            _map_typescript_nestjs_decorators(
                source_path=source_path,
                source=source,
            )
        )
        return facts

    searchable_source = _mask_typescript_strings(source)
    router_authz_refs = _typescript_router_authz_refs(source, express_objects)
    for match in TYPESCRIPT_ROUTE_CALL_PATTERN.finditer(searchable_source):
        receiver = match.group("receiver")
        if receiver not in express_objects:
            continue
        call = _typescript_call_arguments(source, match.end() - 1)
        if call is None:
            continue
        arguments, _ = call
        if len(arguments) < 2:
            continue
        route_path = _typescript_static_string(arguments[0])
        handler_ref = _typescript_callable_name(arguments[-1])
        if route_path is None or handler_ref is None:
            continue
        handler_name = handler_ref.rsplit(".", 1)[-1]
        route_line = _source_line_number(source, match.start())
        facts.append(
            CodebaseFactCandidate(
                fact_type="route_handler",
                source_path=source_path,
                symbol_name=handler_name,
                route_method=match.group("method").upper(),
                route_path=route_path,
                authz_hint=None,
                sensitivity_label="low",
                payload={
                    "handler": handler_name,
                    "line": route_line,
                    "mapping_mode": "static_code_snippet_analysis",
                },
            )
        )

        authz_refs = [
            (name, line)
            for position, name, line, mount_path in router_authz_refs.get(receiver, [])
            if position < match.start()
            and _typescript_route_matches_use_mount(route_path, mount_path)
        ]
        for argument in arguments[1:-1]:
            middleware_name = _typescript_callable_name(argument)
            if middleware_name is not None and _is_typescript_authz_call(
                middleware_name
            ):
                authz_refs.append((middleware_name.rsplit(".", 1)[-1], route_line))
        for authz_name, authz_line in _dedupe_refs(authz_refs):
            facts.append(
                CodebaseFactCandidate(
                    fact_type="authz_check",
                    source_path=source_path,
                    symbol_name=authz_name,
                    route_method=None,
                    route_path=None,
                    authz_hint=_typescript_authz_hint(authz_name),
                    sensitivity_label="low",
                    payload={
                        "handler": handler_name,
                        "line": authz_line,
                        "mapping_mode": "static_code_snippet_analysis",
                    },
                )
            )

    function_spans = _typescript_function_spans(source)
    for function_name, declaration_start, body_start, body_end in function_spans:
        nested_ranges = [
            (nested_start, nested_end + 1)
            for _, nested_start, _, nested_end in function_spans
            if declaration_start < nested_start and nested_end <= body_end
        ]
        facts.extend(
            _typescript_function_facts(
                source_path=source_path,
                source=source,
                function_name=function_name,
                body_start=body_start,
                body_end=body_end,
                nested_ranges=nested_ranges,
            )
        )
    return facts


def _typescript_express_objects(source: str) -> set[str]:
    masked_source = _mask_typescript_strings(source)
    express_aliases = set(
        match.group(1)
        for match in _typescript_code_matches(
            r"(?m)^\s*import\s+([A-Za-z_$][A-Za-z0-9_$]*)\s+from\s*[\"']express[\"']",
            source,
            masked_source,
        )
    )
    express_aliases.update(
        match.group(1)
        for match in _typescript_code_matches(
            r"(?m)^\s*import\s+\*\s+as\s+([A-Za-z_$][A-Za-z0-9_$]*)"
            r"\s+from\s*[\"']express[\"']",
            source,
            masked_source,
        )
    )
    express_aliases.update(
        match.group(1)
        for match in _typescript_code_matches(
            r"(?m)^\s*(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*"
            r"require\(\s*[\"']express[\"']\s*\)",
            source,
            masked_source,
        )
    )

    router_aliases: set[str] = set()
    for match in _typescript_code_matches(
        r"(?m)^\s*import\s*\{([^}]*)\}\s*from\s*[\"']express[\"']",
        source,
        masked_source,
    ):
        imported_names = match.group(1)
        for imported_name in imported_names.split(","):
            match = re.fullmatch(
                r"\s*Router(?:\s+as\s+([A-Za-z_$][A-Za-z0-9_$]*))?\s*",
                imported_name,
            )
            if match is not None:
                router_aliases.add(match.group(1) or "Router")

    objects: set[str] = set()
    assignment_pattern = re.compile(
        r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)"
        r"(?:\s*:\s*[^=;\n]+)?\s*=\s*"
        r"(?P<factory>[A-Za-z_$][A-Za-z0-9_$]*"
        r"(?:\.[A-Za-z_$][A-Za-z0-9_$]*)?)\s*\("
    )
    for match in assignment_pattern.finditer(_mask_typescript_strings(source)):
        factory = match.group("factory")
        if factory in express_aliases or factory in router_aliases:
            objects.add(match.group("name"))
            continue
        if "." not in factory:
            continue
        namespace, constructor = factory.split(".", 1)
        if namespace in express_aliases and constructor == "Router":
            objects.add(match.group("name"))
    return objects


def _typescript_code_matches(
    pattern: str,
    source: str,
    masked_source: str,
) -> list[re.Match[str]]:
    return [
        match
        for match in re.finditer(pattern, source)
        if masked_source[match.start(1)] == source[match.start(1)]
    ]



TYPESCRIPT_NEST_CONTROLLER_PATTERN = re.compile(
    r"@Controller\s*\(\s*(?:(?P<q>[\'\"])(?P<path>[^\'\"]*)(?P=q))?\s*\)",
    re.MULTILINE,
)
TYPESCRIPT_NEST_METHOD_PATTERN = re.compile(
    r"@(?P<method>Get|Post|Put|Patch|Delete)\s*"
    r"(?:\(\s*(?:(?P<q>[\'\"])(?P<path>[^\'\"]*)(?P=q))?\s*\))?\s*",
    re.MULTILINE,
)
TYPESCRIPT_NEST_USE_GUARDS_PATTERN = re.compile(
    r"@UseGuards\s*\((?P<guards>[^)]*)\)",
    re.MULTILINE,
)
TYPESCRIPT_NEST_METHOD_NAME_PATTERN = re.compile(
    r"(?:public|private|protected|async|readonly|static|\s)*"
    r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
)


def _map_typescript_nestjs_decorators(
    *,
    source_path: str,
    source: str,
) -> list[CodebaseFactCandidate]:
    """Map NestJS @Controller/@Get/@UseGuards style ownership guards (static)."""
    if "@Controller" not in source and "@UseGuards" not in source:
        return []
    # Match on raw source so decorator string paths survive string masking.
    facts: list[CodebaseFactCandidate] = []
    controller_paths: list[tuple[int, str]] = []
    for match in TYPESCRIPT_NEST_CONTROLLER_PATTERN.finditer(source):
        controller_paths.append((match.start(), match.group("path") or ""))

    guard_events: list[tuple[int, int, list[str]]] = []
    for match in TYPESCRIPT_NEST_USE_GUARDS_PATTERN.finditer(source):
        raw = match.group("guards") or ""
        names = [
            part.strip().split(".")[-1]
            for part in raw.split(",")
            if part.strip() and part.strip()[0].isalpha()
        ]
        guard_events.append((match.start(), match.end(), names))

    for method_match in TYPESCRIPT_NEST_METHOD_PATTERN.finditer(source):
        method = method_match.group("method").upper()
        method_path = method_match.group("path") or ""
        after = source[method_match.end() : method_match.end() + 500]
        cursor = 0
        while cursor < len(after):
            rest = after[cursor:]
            stripped = rest.lstrip()
            cursor += len(rest) - len(stripped)
            if not stripped.startswith("@"):
                break
            # Skip nested decorators (e.g. @UseGuards(...), @Param wrappers are on args).
            if "(" in stripped[:120]:
                depth = 0
                pos = 0
                for pos, ch in enumerate(stripped):
                    if ch == "(":
                        depth += 1
                    elif ch == ")":
                        depth -= 1
                        if depth == 0:
                            pos += 1
                            break
                cursor += pos
            else:
                nl = stripped.find("\n")
                cursor += (nl + 1) if nl >= 0 else len(stripped)
        name_match = TYPESCRIPT_NEST_METHOD_NAME_PATTERN.match(after[cursor:])
        if name_match is None:
            continue
        handler_name = name_match.group("name")
        method_start = method_match.start()
        name_abs = method_match.end() + cursor + name_match.start()
        controller_path = ""
        for pos, path in controller_paths:
            if pos < method_start:
                controller_path = path
            else:
                break
        route_path = _nest_join_path(controller_path, method_path)
        route_line = _source_line_number(source, method_start)
        facts.append(
            CodebaseFactCandidate(
                fact_type="route_handler",
                source_path=source_path,
                symbol_name=handler_name,
                route_method=method,
                route_path=route_path,
                authz_hint=None,
                sensitivity_label="low",
                payload={
                    "handler": handler_name,
                    "line": route_line,
                    "mapping_mode": "static_code_snippet_analysis",
                },
            )
        )
        # Attach UseGuards that appear shortly before the method name
        # (class-level or method-level, including after @Get).
        for guard_start, guard_end, guard_names in guard_events:
            if guard_end > name_abs:
                continue
            if method_start - guard_start > 2500 and not (
                method_start <= guard_start <= name_abs
            ):
                continue
            # Prefer guards between previous 40 lines and the method name.
            if name_abs - guard_start > 1200 and guard_start < method_start:
                continue
            for guard_name in guard_names:
                normalized = _normalized_typescript_name(guard_name)
                is_authz = _is_typescript_authz_call(guard_name)
                is_ownerish = "owner" in normalized or "ownership" in normalized
                if not is_authz and not is_ownerish:
                    continue
                facts.append(
                    CodebaseFactCandidate(
                        fact_type="authz_check",
                        source_path=source_path,
                        symbol_name=guard_name,
                        route_method=None,
                        route_path=None,
                        authz_hint=(
                            _typescript_authz_hint(guard_name)
                            if is_authz
                            else "ownership_boundary_check"
                        ),
                        sensitivity_label="low",
                        payload={
                            "handler": handler_name,
                            "line": _source_line_number(source, guard_start),
                            "mapping_mode": "static_code_snippet_analysis",
                        },
                    )
                )
    return facts


def _nest_join_path(controller_path: str, method_path: str) -> str:
    left = (controller_path or "").strip("/")
    right = (method_path or "").strip("/")
    if left and right:
        return f"/{left}/{right}"
    if left:
        return f"/{left}"
    if right:
        return f"/{right}"
    return "/"


def _typescript_router_authz_refs(
    source: str,
    express_objects: set[str],
) -> dict[str, list[tuple[int, str, int, str | None]]]:
    """Collect router.use authz middleware.

    Returns (position, name, line, mount_path). mount_path is None for global
    middleware and a static path string for path-scoped router.use("/x", mw).
    """
    refs: dict[str, list[tuple[int, str, int, str | None]]] = {}
    for match in TYPESCRIPT_USE_CALL_PATTERN.finditer(_mask_typescript_strings(source)):
        receiver = match.group("receiver")
        if receiver not in express_objects:
            continue
        call = _typescript_call_arguments(source, match.end() - 1)
        if call is None:
            continue
        arguments, _ = call
        # router.use(middleware) or router.use("/path", middleware, ...)
        start_index = 0
        mount_path: str | None = None
        if arguments and _typescript_static_string(arguments[0]) is not None:
            mount_path = _typescript_static_string(arguments[0])
            start_index = 1
        for argument in arguments[start_index:]:
            authz_name = _typescript_callable_name(argument)
            if authz_name is None or not _is_typescript_authz_call(authz_name):
                continue
            refs.setdefault(receiver, []).append(
                (
                    match.start(),
                    authz_name.rsplit(".", 1)[-1],
                    _source_line_number(source, match.start()),
                    mount_path,
                )
            )
    return refs


def _typescript_route_matches_use_mount(route_path: str, mount_path: str | None) -> bool:
    """True when a route is covered by a path-scoped router.use mount."""
    if mount_path is None:
        return True
    route = "/" + (route_path or "").strip("/")
    mount = "/" + (mount_path or "").strip("/")
    if route == mount:
        return True
    # Prefix match on static segments only (Express mount semantics).
    if mount != "/" and (route.startswith(mount + "/") or route.startswith(mount)):
        # Avoid matching /adminish for mount /admin when next char is not / end
        if route == mount or route.startswith(mount + "/"):
            return True
    return False


def _typescript_function_spans(source: str) -> list[tuple[str, int, int, int]]:
    masked_source = _mask_typescript_strings(source)
    spans: list[tuple[str, int, int, int]] = []
    seen_open_braces: set[int] = set()
    for pattern in (TYPESCRIPT_FUNCTION_PATTERN, TYPESCRIPT_ARROW_FUNCTION_PATTERN):
        for match in pattern.finditer(masked_source):
            open_brace = match.end() - 1
            if open_brace in seen_open_braces:
                continue
            close_brace = _matching_typescript_delimiter(
                source,
                open_brace,
                "{",
                "}",
            )
            if close_brace is None:
                continue
            seen_open_braces.add(open_brace)
            spans.append((match.group("name"), match.start(), open_brace + 1, close_brace))
    return sorted(spans, key=lambda item: item[2])


def _typescript_function_facts(
    *,
    source_path: str,
    source: str,
    function_name: str,
    body_start: int,
    body_end: int,
    nested_ranges: list[tuple[int, int]],
) -> list[CodebaseFactCandidate]:
    facts: list[CodebaseFactCandidate] = []
    body = _mask_typescript_ranges(
        source[body_start:body_end],
        [
            (nested_start - body_start, nested_end - body_start)
            for nested_start, nested_end in nested_ranges
        ],
    )
    masked_body = _mask_typescript_strings(body)
    for match in TYPESCRIPT_CALL_PATTERN.finditer(masked_body):
        callee = re.sub(r"\s+", "", match.group("callee"))
        call_name = callee.rsplit(".", 1)[-1]
        line_number = _source_line_number(source, body_start + match.start())
        if _is_typescript_authz_call(call_name):
            facts.append(
                _typescript_function_fact(
                    fact_type="authz_check",
                    source_path=source_path,
                    symbol_name=call_name,
                    function_name=function_name,
                    line_number=line_number,
                    authz_hint=_typescript_authz_hint(call_name),
                )
            )
            continue
        if _is_typescript_sensitive_sink(call_name):
            facts.append(
                _typescript_function_fact(
                    fact_type="sensitive_sink",
                    source_path=source_path,
                    symbol_name=call_name,
                    function_name=function_name,
                    line_number=line_number,
                )
            )
            continue
        if _is_typescript_service_call(callee):
            facts.append(
                _typescript_function_fact(
                    fact_type="service_call",
                    source_path=source_path,
                    symbol_name=call_name,
                    function_name=function_name,
                    line_number=line_number,
                )
            )

    for line_offset, line in enumerate(body.splitlines()):
        line_number = _source_line_number(source, body_start) + line_offset
        boundary_field = _typescript_authz_boundary_field(line)
        if boundary_field is not None:
            facts.append(
                _typescript_function_fact(
                    fact_type="authz_check",
                    source_path=source_path,
                    symbol_name=f"{boundary_field}_filter",
                    function_name=function_name,
                    line_number=line_number,
                    authz_hint=_authz_boundary_hint(boundary_field),
                )
            )
            continue
        if _typescript_role_comparison(line):
            facts.append(
                _typescript_function_fact(
                    fact_type="authz_check",
                    source_path=source_path,
                    symbol_name="role_check",
                    function_name=function_name,
                    line_number=line_number,
                    authz_hint="role_check",
                )
            )
            continue
        if TYPESCRIPT_PUBLIC_FILTER_PATTERN.search(line):
            facts.append(
                _typescript_function_fact(
                    fact_type="authz_check",
                    source_path=source_path,
                    symbol_name="public_filter",
                    function_name=function_name,
                    line_number=line_number,
                    authz_hint="public_filter",
                )
            )
    return facts


def _typescript_function_fact(
    *,
    fact_type: str,
    source_path: str,
    symbol_name: str,
    function_name: str,
    line_number: int,
    authz_hint: str | None = None,
) -> CodebaseFactCandidate:
    payload_key = "caller" if fact_type == "service_call" else "handler"
    return CodebaseFactCandidate(
        fact_type=fact_type,
        source_path=source_path,
        symbol_name=symbol_name,
        route_method=None,
        route_path=None,
        authz_hint=authz_hint,
        sensitivity_label="low",
        payload={
            payload_key: function_name,
            "line": line_number,
            "mapping_mode": "static_code_snippet_analysis",
        },
    )


def _typescript_call_arguments(
    source: str,
    open_parenthesis: int,
) -> tuple[list[str], int] | None:
    close_parenthesis = _matching_typescript_delimiter(
        source,
        open_parenthesis,
        "(",
        ")",
    )
    if close_parenthesis is None:
        return None
    return (
        _split_typescript_arguments(source[open_parenthesis + 1 : close_parenthesis]),
        close_parenthesis,
    )


def _matching_typescript_delimiter(
    source: str,
    start: int,
    opening: str,
    closing: str,
) -> int | None:
    if start >= len(source) or source[start] != opening:
        return None
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(start, len(source)):
        character = source[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {"'", '"', "`"}:
            quote = character
            continue
        if character == opening:
            depth += 1
        elif character == closing:
            depth -= 1
            if depth == 0:
                return index
    return None


def _split_typescript_arguments(arguments: str) -> list[str]:
    values: list[str] = []
    start = 0
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    closing_delimiters = {"(": ")", "[": "]", "{": "}"}
    for index, character in enumerate(arguments):
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {"'", '"', "`"}:
            quote = character
        elif character in closing_delimiters:
            stack.append(closing_delimiters[character])
        elif stack and character == stack[-1]:
            stack.pop()
        elif character == "," and not stack:
            values.append(arguments[start:index].strip())
            start = index + 1
    final_value = arguments[start:].strip()
    if final_value:
        values.append(final_value)
    return values


def _typescript_static_string(value: str) -> str | None:
    value = value.strip()
    if len(value) < 2 or value[0] not in {"'", '"', "`"} or value[-1] != value[0]:
        return None
    if value[0] == "`" and "${" in value:
        return None
    return value[1:-1]


def _typescript_callable_name(value: str) -> str | None:
    value = value.strip()
    reference = re.fullmatch(
        r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*",
        value,
    )
    if reference is not None:
        return value
    # Named function expression: router.get(path, async function readRecord(...) { ... })
    named_function = re.match(
        r"(?:async\s+)?function\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
        value,
    )
    if named_function is not None:
        return named_function.group("name")
    call = re.match(
        r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*"
        r"(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)\s*\(",
        value,
    )
    if call is None:
        return None
    return call.group("name")


def _is_typescript_service_call(callee: str) -> bool:
    call_name = callee.rsplit(".", 1)[-1]
    normalized = _normalized_typescript_name(call_name)
    root = _normalized_typescript_name(callee.split(".", 1)[0])
    if normalized in TYPESCRIPT_NON_SERVICE_CALLS:
        return False
    if root in {"console", "json", "math", "object", "promise", "res", "response"}:
        return False
    return not _is_typescript_authz_call(
        call_name
    ) and not _is_typescript_sensitive_sink(call_name)


def _is_typescript_authz_call(call_name: str) -> bool:
    normalized = _normalized_typescript_name(call_name)
    if any(marker in normalized for marker in AUTHZ_NAME_MARKERS):
        return True
    if _is_ssrf_guard_name(normalized):
        return True
    if _is_path_guard_name(normalized):
        return True
    if _is_mass_assign_guard_name(normalized):
        return True
    if _is_command_execution_guard_name(normalized):
        return True
    if _is_deserialization_guard_name(normalized):
        return True
    if _is_file_upload_guard_name(normalized):
        return True
    if _is_money_flow_guard_name(normalized):
        return True
    if _is_agent_tool_guard_name(normalized):
        return True
    return _is_injection_guard_name(normalized)


def _typescript_authz_hint(call_name: str) -> str:
    normalized = _normalized_typescript_name(call_name)
    if _is_ssrf_guard_name(normalized):
        return "ssrf_validation_check"
    if _is_path_guard_name(normalized):
        return "path_validation_check"
    if _is_mass_assign_guard_name(normalized):
        return "mass_assignment_check"
    if _is_command_execution_guard_name(normalized):
        return "command_injection_validation_check"
    if _is_deserialization_guard_name(normalized):
        return "deserialization_validation_check"
    if _is_file_upload_guard_name(normalized):
        return "file_upload_validation_check"
    if _is_money_flow_guard_name(normalized):
        return "server_authoritative_amount_check"
    if _is_agent_tool_guard_name(normalized):
        return "agent_tool_authorization_check"
    if _is_injection_guard_name(normalized):
        return "injection_validation_check"
    if "owner_or_admin" in normalized:
        return "owner_or_admin_check"
    if any(
        marker in normalized
        for marker in (
            "require_owner",
            "ensure_owner",
            "check_ownership",
            "verify_ownership",
            "assert_owner",
            "owner_check",
            "ownership",
            "owner_id",
            "owner_guard",
            "can_access",
            "verify_access",
            "assert_access",
        )
    ) or (
        "owner" in normalized
        and any(
            marker in normalized
            for marker in ("require", "ensure", "check", "verify", "assert", "guard")
        )
    ):
        return "ownership_boundary_check"
    if "permission" in normalized:
        return "permission_check"
    if "role" in normalized:
        return "role_check"
    return "authorization_boundary_candidate"


def _is_typescript_sensitive_sink(call_name: str) -> bool:
    return _normalized_typescript_name(call_name) in SENSITIVE_SINK_NAMES


def _is_ssrf_guard_name(normalized_name: str) -> bool:
    return any(marker in normalized_name for marker in SSRF_GUARD_MARKERS)


def _is_path_guard_name(normalized_name: str) -> bool:
    return any(marker in normalized_name for marker in PATH_GUARD_MARKERS)


def _is_mass_assign_guard_name(normalized_name: str) -> bool:
    return any(marker in normalized_name for marker in MASS_ASSIGN_GUARD_MARKERS)


def _is_injection_guard_name(normalized_name: str) -> bool:
    return any(marker in normalized_name for marker in INJECTION_GUARD_MARKERS)


def _is_command_execution_guard_name(normalized_name: str) -> bool:
    return any(marker in normalized_name for marker in COMMAND_EXECUTION_GUARD_MARKERS)


def _is_deserialization_guard_name(normalized_name: str) -> bool:
    if normalized_name in UNSAFE_DESERIALIZATION_SINK_NAMES:
        return False
    return any(marker in normalized_name for marker in DESERIALIZATION_GUARD_MARKERS)


def _is_file_upload_guard_name(normalized_name: str) -> bool:
    return any(marker in normalized_name for marker in FILE_UPLOAD_GUARD_MARKERS)


def _is_money_flow_guard_name(normalized_name: str) -> bool:
    return any(marker in normalized_name for marker in MONEY_FLOW_GUARD_MARKERS)


def _is_agent_tool_guard_name(normalized_name: str) -> bool:
    return any(marker in normalized_name for marker in AGENT_TOOL_GUARD_MARKERS)


def _normalized_typescript_name(name: str) -> str:
    leaf_name = name.rsplit(".", 1)[-1]
    snake_name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", leaf_name)
    return re.sub(r"[^A-Za-z0-9]+", "_", snake_name).strip("_").lower()


def _typescript_authz_boundary_field(line: str) -> str | None:
    masked_line = _mask_typescript_strings(line)
    for match in TYPESCRIPT_COMPARISON_PATTERN.finditer(masked_line):
        left = match.group("left")
        right = match.group("right")
        left_field = _typescript_boundary_field(left)
        right_field = _typescript_boundary_field(right)
        if left_field is not None and _is_typescript_principal_identifier(right):
            return left_field
        if right_field is not None and _is_typescript_principal_identifier(left):
            return right_field
        if (
            left_field is not None
            and left_field == right_field
            and (
                _is_typescript_principal_context(left)
                or _is_typescript_principal_context(right)
            )
        ):
            return left_field
    for match in TYPESCRIPT_BOUNDARY_OBJECT_PROP_PATTERN.finditer(masked_line):
        field = _typescript_boundary_field(match.group("field"))
        value = match.group("value")
        if field is None:
            continue
        if _is_typescript_principal_identifier(value) or _is_typescript_principal_context(
            value
        ):
            return field
    membership_field = _typescript_membership_boundary_field(masked_line)
    if membership_field is not None:
        return membership_field
    return None


_TYPESCRIPT_MEMBERSHIP_FIELDS = {
    "member_ids",
    "members",
    "allowed_user_ids",
    "collaborators",
    "participant_ids",
    "user_ids",
    "shared_with",
    "editors",
    "viewers",
}


def _typescript_membership_boundary_field(line: str) -> str | None:
    """Detect principal membership checks like record.memberIds.includes(req.user.id)."""
    for match in TYPESCRIPT_MEMBERSHIP_INCLUDES_PATTERN.finditer(line):
        field = match.group("field")
        principal = match.group("principal")
        field_name = _normalized_typescript_name(field.rsplit(".", 1)[-1])
        if field_name not in _TYPESCRIPT_MEMBERSHIP_FIELDS:
            continue
        if _is_typescript_principal_identifier(principal):
            return "user_id"
    return None


def _typescript_boundary_field(identifier: str) -> str | None:
    field_name = _normalized_typescript_name(identifier.rsplit(".", 1)[-1])
    if field_name in AUTHZ_BOUNDARY_FIELDS:
        return field_name
    return None


def _is_typescript_principal_identifier(identifier: str) -> bool:
    normalized_parts = [
        _normalized_typescript_name(part) for part in identifier.split(".") if part
    ]
    normalized = ".".join(normalized_parts)
    return normalized in {
        "current_user.id",
        "req.auth.user_id",
        "req.user.id",
        "request.auth.user_id",
        "request.user.id",
        "user.id",
    }


def _is_typescript_principal_context(identifier: str) -> bool:
    normalized = ".".join(
        _normalized_typescript_name(part) for part in identifier.split(".") if part
    )
    return normalized.startswith(("current_user.", "req.", "request.", "user."))


def _typescript_role_comparison(line: str) -> bool:
    principal_role = (
        r"(?:req\.user|request\.user|currentUser|current_user|user)\.role"
    )
    string_value = r"(?:[\"'][^\"']+[\"'])"
    patterns = (
        rf"(?P<role>{principal_role})\s*(?:===|!==|==|!=)\s*{string_value}",
        rf"{string_value}\s*(?:===|!==|==|!=)\s*(?P<role>{principal_role})",
    )
    masked_line = _mask_typescript_strings(line)
    for pattern in patterns:
        for match in re.finditer(pattern, line):
            role_start, role_end = match.span("role")
            if masked_line[role_start:role_end] == line[role_start:role_end]:
                return True
    return False


def _strip_typescript_comments(source: str) -> str:
    output: list[str] = []
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    index = 0
    while index < len(source):
        character = source[index]
        next_character = source[index + 1] if index + 1 < len(source) else ""
        if line_comment:
            if character == "\n":
                line_comment = False
                output.append(character)
            else:
                output.append(" ")
            index += 1
            continue
        if block_comment:
            if character == "*" and next_character == "/":
                output.extend((" ", " "))
                block_comment = False
                index += 2
            else:
                output.append("\n" if character == "\n" else " ")
                index += 1
            continue
        if quote is not None:
            output.append(character)
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            index += 1
            continue
        if character in {"'", '"', "`"}:
            quote = character
            output.append(character)
            index += 1
            continue
        if character == "/" and next_character == "/":
            output.extend((" ", " "))
            line_comment = True
            index += 2
            continue
        if character == "/" and next_character == "*":
            output.extend((" ", " "))
            block_comment = True
            index += 2
            continue
        output.append(character)
        index += 1
    return "".join(output)


def _mask_typescript_strings(source: str) -> str:
    output: list[str] = []
    quote: str | None = None
    escaped = False
    for character in source:
        if quote is not None:
            output.append("\n" if character == "\n" else " ")
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {"'", '"', "`"}:
            quote = character
            output.append(" ")
        else:
            output.append(character)
    return "".join(output)


def _mask_typescript_ranges(source: str, ranges: list[tuple[int, int]]) -> str:
    masked = list(source)
    for start, end in ranges:
        for index in range(max(start, 0), min(end, len(masked))):
            if masked[index] != "\n":
                masked[index] = " "
    return "".join(masked)


def _source_line_number(source: str, position: int) -> int:
    return source.count("\n", 0, position) + 1


def _current_function(function_stack: list[tuple[str, int]]) -> str | None:
    if not function_stack:
        return None
    return function_stack[-1][0]


def _current_class(class_stack: list[tuple[str, int]]) -> str | None:
    if not class_stack:
        return None
    return class_stack[-1][0]


def _qualified_method_view_function(
    function_name: str | None,
    class_name: str | None,
    method_view_classes: set[str],
) -> str | None:
    if (
        function_name is not None
        and class_name in method_view_classes
        and function_name.lower() in HTTP_METHOD_NAMES
    ):
        return f"{class_name}.{function_name.lower()}"
    return function_name


def _fact_handler_identity(
    fact: CodebaseFactCandidate,
    payload_key: str,
) -> tuple[str, str] | None:
    if not isinstance(fact.payload, dict):
        return None
    source_path = fact.source_path
    symbol_name = fact.payload.get(payload_key)
    if not isinstance(source_path, str) or not isinstance(symbol_name, str):
        return None
    if not source_path or not symbol_name:
        return None
    return source_path, symbol_name


def _handler_identities_by_symbol(
    facts: list[CodebaseFactCandidate],
) -> dict[str, set[tuple[str, str]]]:
    identities_by_symbol: dict[str, set[tuple[str, str]]] = {}
    for fact in facts:
        for payload_key in ("handler", "caller"):
            identity = _fact_handler_identity(fact, payload_key)
            if identity is not None:
                identities_by_symbol.setdefault(identity[1], set()).add(identity)
    return identities_by_symbol


def _resolve_handler_identity(
    source_path: str,
    symbol_name: str,
    identities_by_symbol: dict[str, set[tuple[str, str]]],
) -> tuple[str, str] | None:
    candidates = identities_by_symbol.get(symbol_name, set())
    same_source = (source_path, symbol_name)
    if same_source in candidates:
        return same_source
    if len(candidates) == 1:
        return next(iter(candidates))
    return None


def _authorization_gap_candidates(
    facts: list[CodebaseFactCandidate],
) -> list[CodebaseFactCandidate]:
    candidates: list[CodebaseFactCandidate] = []
    routes = [fact for fact in facts if fact.fact_type == "route_handler"]
    for route in routes:
        handler = route.payload.get("handler") if isinstance(route.payload, dict) else None
        if not isinstance(handler, str):
            continue
        route_identity = (route.source_path, handler)
        service_calls = _reachable_service_handlers(
            facts,
            route.source_path,
            handler,
        )
        reachable_handlers = {route_identity, *service_calls}
        sink_facts = [
            fact
            for fact in facts
            if fact.fact_type == "sensitive_sink"
            and isinstance(fact.symbol_name, str)
            and _fact_handler_identity(fact, "handler") in reachable_handlers
        ]
        sink_symbols = sorted({fact.symbol_name for fact in sink_facts})
        sink_count = len(sink_symbols)
        if sink_count == 0:
            continue
        root_cause, security_invariant, authz_hint = _gap_root_for_sinks(sink_symbols)
        if (
            root_cause == "missing_agent_tool_authorization_check"
            and not _is_agent_tool_route_context(route)
        ):
            root_cause, security_invariant, authz_hint = _object_ownership_gap_root()
        if guard_hints := STATIC_GAP_GUARD_HINTS.get(root_cause):
            if _has_prior_static_guard(
                facts,
                reachable_handlers=reachable_handlers,
                sink_facts=sink_facts,
                guard_hints=guard_hints,
            ):
                continue
        else:
            has_authz = any(
                fact.fact_type == "authz_check"
                and _fact_handler_identity(fact, "handler") == route_identity
                for fact in facts
            )
            if has_authz:
                continue
            has_service_authz = any(
                fact.fact_type == "authz_check"
                and _fact_handler_identity(fact, "handler") in service_calls
                for fact in facts
            )
            if has_service_authz and not route.source_path.lower().endswith(
                TYPESCRIPT_SOURCE_SUFFIXES
            ):
                continue
        candidates.append(
            CodebaseFactCandidate(
                fact_type="authorization_gap_candidate",
                source_path=route.source_path,
                symbol_name=handler,
                route_method=route.route_method,
                route_path=route.route_path,
                authz_hint=authz_hint,
                sensitivity_label="high",
                payload={
                    "handler": handler,
                    "mapping_mode": "static_code_snippet_analysis",
                    "review_state": "needs_human_review",
                    "root_cause": root_cause,
                    "security_invariant": security_invariant,
                    "sink_count": sink_count,
                    "sink_symbols": sink_symbols,
                },
            )
        )
    return candidates


def _is_agent_tool_route_context(route: CodebaseFactCandidate) -> bool:
    route_path = route.route_path.lower() if isinstance(route.route_path, str) else ""
    return "agent" in route_path and "tool" in route_path


def _has_prior_static_guard(
    facts: list[CodebaseFactCandidate],
    *,
    reachable_handlers: set[tuple[str, str]],
    sink_facts: list[CodebaseFactCandidate],
    guard_hints: set[str],
) -> bool:
    earliest_sink_line: dict[tuple[str, str], int] = {}
    for fact in sink_facts:
        handler_identity = _fact_handler_identity(fact, "handler")
        if handler_identity is None or not isinstance(fact.payload, dict):
            continue
        line = fact.payload.get("line")
        if not isinstance(line, int):
            continue
        current = earliest_sink_line.get(handler_identity)
        if current is None or line < current:
            earliest_sink_line[handler_identity] = line

    for fact in facts:
        if fact.fact_type != "authz_check" or fact.authz_hint not in guard_hints:
            continue
        handler_identity = _fact_handler_identity(fact, "handler")
        if handler_identity not in reachable_handlers:
            continue
        sink_line = earliest_sink_line.get(handler_identity)
        if sink_line is None:
            return True
        if not isinstance(fact.payload, dict):
            return True
        line = fact.payload.get("line")
        if not isinstance(line, int) or line < sink_line:
            return True
    return False


def _object_ownership_gap_root() -> tuple[str, str, str]:
    return (
        "missing_object_ownership_check",
        "Object-level actions must verify requester ownership or role before sensitive sinks run.",
        "missing_handler_authz_check",
    )


def _gap_root_for_sinks(sink_symbols: list[str]) -> tuple[str, str, str]:
    """Pick root_cause/invariant from an explicit sensitive-sink family."""
    normalized = {symbol.lower() for symbol in sink_symbols}
    canonicalized = {_normalized_typescript_name(symbol) for symbol in sink_symbols}
    if normalized and normalized.issubset(OUTBOUND_HTTP_SINK_NAMES):
        return (
            "missing_ssrf_validation",
            (
                "Outbound requests to user-controlled URLs must validate the target "
                "against private networks, metadata endpoints, and unsafe schemes."
            ),
            "missing_handler_ssrf_check",
        )
    if normalized and normalized.issubset(FILE_PATH_SINK_NAMES):
        return (
            "missing_path_validation",
            (
                "User-controlled file paths must be sanitized (basename / safe-join) "
                "before reaching filesystem read sinks."
            ),
            "missing_handler_path_check",
        )
    if normalized and normalized.issubset(MASS_ASSIGN_SINK_NAMES):
        return (
            "missing_mass_assignment_guard",
            (
                "User-controlled update payloads must not set privilege or tenancy fields "
                "without an explicit field allowlist or permission-attr guard."
            ),
            "missing_handler_mass_assignment_check",
        )
    if normalized and normalized.issubset(COMMAND_EXECUTION_SINK_NAMES):
        return (
            "missing_command_injection_validation",
            (
                "Command selection and arguments must be constrained by an explicit "
                "allowlist or structured validation before command-execution sinks."
            ),
            "missing_handler_command_injection_check",
        )
    if canonicalized and canonicalized.issubset(UNSAFE_DESERIALIZATION_SINK_NAMES):
        return (
            "missing_unsafe_deserialization_guard",
            (
                "Serialized input must pass an explicit type and loader policy before "
                "reaching unsafe deserialization sinks."
            ),
            "missing_handler_deserialization_check",
        )
    if canonicalized and canonicalized.issubset(FILE_UPLOAD_SINK_NAMES):
        return (
            "missing_file_upload_validation",
            (
                "Uploaded files must pass explicit type, filename, and storage policy "
                "checks before upload-storage sinks."
            ),
            "missing_handler_file_upload_check",
        )
    if canonicalized and canonicalized.issubset(MONEY_FLOW_SINK_NAMES):
        return (
            "missing_server_authoritative_amount_check",
            (
                "Financial amounts, credits, and refunds must be derived from trusted "
                "server-side order or account state before financial action sinks."
            ),
            "missing_handler_server_amount_check",
        )
    if canonicalized and canonicalized.issubset(AGENT_TOOL_SINK_NAMES):
        return (
            "missing_agent_tool_authorization_check",
            (
                "Agent tool dispatch must verify the current user, agent policy, and "
                "task context permit the selected tool before invocation."
            ),
            "missing_handler_agent_tool_authorization_check",
        )
    if normalized and normalized.issubset(INJECTION_SINK_NAMES):
        return (
            "missing_injection_validation",
            (
                "User-controlled query or search input must be sanitized and bound as parameters "
                "before reaching SQL or query execution sinks."
            ),
            "missing_handler_injection_check",
        )
    return _object_ownership_gap_root()


def _reachable_service_handlers(
    facts: list[CodebaseFactCandidate],
    source_path: str,
    handler: str,
) -> set[tuple[str, str]]:
    calls_by_handler: dict[tuple[str, str], list[CodebaseFactCandidate]] = {}
    earliest_sink_line: dict[tuple[str, str], int] = {}
    identities_by_symbol = _handler_identities_by_symbol(facts)
    for fact in facts:
        if fact.fact_type == "sensitive_sink" and isinstance(fact.payload, dict):
            sink_handler = _fact_handler_identity(fact, "handler")
            line = fact.payload.get("line")
            if sink_handler is not None and isinstance(line, int):
                previous = earliest_sink_line.get(sink_handler)
                if previous is None or line < previous:
                    earliest_sink_line[sink_handler] = line
        if fact.fact_type != "service_call" or not isinstance(fact.payload, dict):
            continue
        caller = _fact_handler_identity(fact, "caller")
        if caller is None or not isinstance(fact.symbol_name, str):
            continue
        calls_by_handler.setdefault(caller, []).append(fact)

    reachable: set[tuple[str, str]] = set()
    root = (source_path, handler)
    seen = {root}
    pending = [root]
    while pending:
        caller = pending.pop()
        for call in calls_by_handler.get(caller, []):
            if not _service_call_precedes_handler_sink(call, earliest_sink_line):
                continue
            callee = call.symbol_name
            if not isinstance(callee, str):
                continue
            callee_identity = _resolve_handler_identity(
                caller[0],
                callee,
                identities_by_symbol,
            )
            if callee_identity is None or callee_identity in seen:
                continue
            seen.add(callee_identity)
            reachable.add(callee_identity)
            pending.append(callee_identity)
    return reachable


def _service_call_precedes_handler_sink(
    fact: CodebaseFactCandidate,
    earliest_sink_line: dict[tuple[str, str], int],
) -> bool:
    caller = _fact_handler_identity(fact, "caller")
    line = fact.payload.get("line") if isinstance(fact.payload, dict) else None
    sink_line = earliest_sink_line.get(caller) if caller is not None else None
    return not isinstance(line, int) or sink_line is None or line < sink_line


def _indent_width(line: str) -> int:
    expanded = line.expandtabs()
    return len(expanded) - len(expanded.lstrip(" "))


def _called_names(
    line: str,
    *,
    yaml_module_aliases: set[str],
    yaml_load_aliases: set[str],
    yaml_safe_loader_aliases: set[str],
) -> list[str]:
    calls: list[str] = []
    try:
        tokens = [
            token
            for token in tokenize.generate_tokens(StringIO(line).readline)
            if token.type not in {
                tokenize.COMMENT,
                tokenize.ENCODING,
                tokenize.ENDMARKER,
                tokenize.INDENT,
                tokenize.DEDENT,
                tokenize.NL,
                tokenize.NEWLINE,
                tokenize.STRING,
            }
        ]
    except tokenize.TokenError:
        return _called_names_from_incomplete_line(line)

    for index, token in enumerate(tokens[:-1]):
        next_token = tokens[index + 1]
        if token.type == tokenize.NAME and next_token.string == "(":
            if token.string in yaml_load_aliases:
                calls.append(
                    "yaml_safe_loader"
                    if _yaml_load_uses_safe_loader(
                        tokens,
                        index,
                        yaml_module_aliases=yaml_module_aliases,
                        yaml_safe_loader_aliases=yaml_safe_loader_aliases,
                    )
                    else "yaml_load"
                )
                continue
            if (
                index >= 2
                and tokens[index - 1].string == "."
                and tokens[index - 2].type == tokenize.NAME
            ):
                qualifier = tokens[index - 2].string
                is_yaml_load = (
                    token.string == "load" and qualifier in yaml_module_aliases
                )
                qualified_name = f"{qualifier}_{token.string}".lower()
                if (
                    qualified_name in UNSAFE_DESERIALIZATION_SINK_NAMES
                    or is_yaml_load
                ):
                    calls.append(
                        "yaml_safe_loader"
                        if (
                            is_yaml_load
                            and _yaml_load_uses_safe_loader(
                                tokens,
                                index,
                                yaml_module_aliases=yaml_module_aliases,
                                yaml_safe_loader_aliases=yaml_safe_loader_aliases,
                            )
                        )
                        else "yaml_load"
                        if is_yaml_load
                        else qualified_name
                    )
                    continue
            calls.append(token.string)
    return calls


def _yaml_load_uses_safe_loader(
    tokens: list[tokenize.TokenInfo],
    call_index: int,
    *,
    yaml_module_aliases: set[str],
    yaml_safe_loader_aliases: set[str],
) -> bool:
    depth = 0
    for index in range(call_index + 1, len(tokens)):
        token = tokens[index]
        if token.string == "(":
            depth += 1
            continue
        if token.string == ")":
            depth -= 1
            if depth == 0:
                return False
            continue
        if (
            depth != 1
            or token.type != tokenize.NAME
            or token.string != "Loader"
        ):
            continue
        if index + 2 >= len(tokens) or tokens[index + 1].string != "=":
            continue
        loader = tokens[index + 2]
        if loader.type != tokenize.NAME:
            continue
        if loader.string in yaml_safe_loader_aliases:
            return True
        if (
            index + 4 < len(tokens)
            and loader.string in yaml_module_aliases
            and tokens[index + 3].string == "."
            and tokens[index + 4].type == tokenize.NAME
            and tokens[index + 4].string in {"SafeLoader", "CSafeLoader"}
        ):
            return True
    return False


def _called_names_from_incomplete_line(line: str) -> list[str]:
    scrubbed = re.sub(r"([\"']).*?\1", "\"\"", line)
    return [
        match.group(1)
        for match in CALL_NAME_PATTERN.finditer(scrubbed)
        if match.group(1) not in NON_CALL_KEYWORDS
    ]


def _local_call_alias(line: str) -> tuple[str, str] | None:
    match = LOCAL_CALL_ALIAS_PATTERN.match(line)
    if match is None:
        return None
    return match.group(1), match.group(2)


def _self_call_alias(line: str) -> tuple[str, str] | None:
    match = SELF_CALL_ALIAS_PATTERN.match(line)
    if match is None:
        return None
    return match.group(1), match.group(2)


def _self_name_alias(line: str) -> tuple[str, str] | None:
    match = SELF_NAME_ALIAS_PATTERN.match(line)
    if match is None:
        return None
    return match.group(1), match.group(2)


def _local_name_alias(line: str) -> tuple[str, str] | None:
    match = LOCAL_NAME_ALIAS_PATTERN.match(line)
    if match is None:
        return None
    return match.group(1), match.group(2)


def _principal_id_alias(line: str) -> tuple[str, str] | None:
    match = PRINCIPAL_ID_ALIAS_PATTERN.match(line)
    if match is None:
        return None
    alias_name = match.group(1)
    boundary_field = _principal_boundary_identifier_field(match.group(2))
    if boundary_field is None:
        return None
    return alias_name, boundary_field


def _resolved_call_name(
    call_name: str,
    current_function: str | None,
    current_class: str | None,
    self_called_names: set[str],
    import_aliases: dict[str, str],
    local_call_aliases: dict[str, dict[str, str]],
    class_call_aliases: dict[str, dict[str, str]],
) -> str:
    if current_function is not None:
        local_aliases = local_call_aliases.get(current_function, {})
        if call_name in local_aliases:
            return local_aliases[call_name]
    if current_class is not None and call_name in self_called_names:
        class_aliases = class_call_aliases.get(current_class, {})
        if call_name in class_aliases:
            return class_aliases[call_name]
    return import_aliases.get(call_name, call_name)


def _self_called_names(line: str) -> set[str]:
    return set(SELF_CALL_PATTERN.findall(line))


def _dependency_authz_calls(line: str) -> list[str]:
    return [
        call_name
        for call_name in DEPENDENCY_CALL_PATTERN.findall(line)
        if _is_authz_call(call_name)
    ]


def _dependency_authz_refs(
    line: str,
    line_number: int,
    dependency_aliases: dict[str, str],
) -> list[tuple[str, int]]:
    refs = [(call_name, line_number) for call_name in _dependency_authz_calls(line)]
    refs.extend(
        (call_name, line_number)
        for alias_name, call_name in dependency_aliases.items()
        if _line_references_name(line, alias_name)
    )
    return refs


def _dependency_authz_refs_from_lines(
    lines: list[str],
    start_line: int,
    dependency_aliases: dict[str, str],
) -> list[tuple[str, int]]:
    block = "\n".join(lines)
    refs = [
        (match.group(1), start_line + block.count("\n", 0, match.start(1)))
        for match in DEPENDENCY_CALL_PATTERN.finditer(block)
        if _is_authz_call(match.group(1))
    ]
    refs.extend(
        (call_name, start_line + line_index)
        for line_index, line in enumerate(lines)
        for alias_name, call_name in dependency_aliases.items()
        if _line_references_name(line, alias_name)
    )
    return refs


def _dependency_wrapper_refs(
    line: str,
    line_number: int,
    dependency_aliases: dict[str, str],
    dependency_wrapper_aliases: dict[str, str],
) -> list[tuple[str, int]]:
    authz_names = {call_name for call_name, _ in _dependency_authz_refs(
        line,
        line_number,
        dependency_aliases,
    )}
    refs = [
        (call_name, line_number)
        for call_name in _dependency_calls(line)
        if call_name not in authz_names
    ]
    refs.extend(
        (call_name, line_number)
        for alias_name, call_name in dependency_wrapper_aliases.items()
        if _line_references_dependency_alias(line, alias_name)
    )
    return _dedupe_refs(refs)


def _dependency_wrapper_refs_from_lines(
    lines: list[str],
    start_line: int,
    dependency_aliases: dict[str, str],
    dependency_wrapper_aliases: dict[str, str],
) -> list[tuple[str, int]]:
    block = "\n".join(lines)
    authz_names = {
        call_name
        for call_name, _ in _dependency_authz_refs_from_lines(
            lines,
            start_line,
            dependency_aliases,
        )
    }
    refs = [
        (match.group(1), start_line + block.count("\n", 0, match.start(1)))
        for match in DEPENDENCY_CALL_PATTERN.finditer(block)
        if match.group(1) not in authz_names
    ]
    refs.extend(
        (call_name, start_line + line_index)
        for line_index, line in enumerate(lines)
        for alias_name, call_name in dependency_wrapper_aliases.items()
        if _line_references_name(line, alias_name)
    )
    return _dedupe_refs(refs)


def _dependency_calls(line: str) -> list[str]:
    return DEPENDENCY_CALL_PATTERN.findall(line)


def _dependency_alias(line: str) -> tuple[str, str] | None:
    match = DEPENDENCY_ALIAS_PATTERN.match(line)
    if match is None:
        return None
    alias_name = match.group(1)
    call_name = match.group(2)
    return alias_name, call_name


def _dependency_imported_aliases(line: str) -> list[tuple[str, str]]:
    match = IMPORT_AUTHZ_ALIAS_PATTERN.match(line)
    if match is None or "dependencies" not in line:
        return []
    aliases: list[tuple[str, str]] = []
    for item in match.group(1).split(","):
        item_match = IMPORT_ALIAS_ITEM_PATTERN.match(item)
        if item_match is None:
            call_name = item.strip()
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", call_name):
                aliases.append((call_name, call_name))
            continue
        call_name = item_match.group(1)
        alias_name = item_match.group(2)
        if not _is_authz_call(call_name):
            aliases.append((alias_name, call_name))
    return aliases


def _imported_aliases(line: str) -> list[tuple[str, str]]:
    match = IMPORT_AUTHZ_ALIAS_PATTERN.match(line)
    if match is None:
        return []
    aliases: list[tuple[str, str]] = []
    for item in match.group(1).split(","):
        item_match = IMPORT_ALIAS_ITEM_PATTERN.match(item)
        if item_match is None:
            continue
        call_name = item_match.group(1)
        alias_name = item_match.group(2)
        aliases.append((alias_name, call_name))
    return aliases


def _yaml_import_aliases(line: str) -> tuple[set[str], set[str], set[str]]:
    module_aliases: set[str] = set()
    load_aliases: set[str] = set()
    safe_loader_aliases: set[str] = set()
    module_match = YAML_MODULE_IMPORT_PATTERN.match(line)
    if module_match is not None:
        module_aliases.add(module_match.group("alias") or "yaml")

    from_match = YAML_FROM_IMPORT_PATTERN.match(line)
    if from_match is None:
        return module_aliases, load_aliases, safe_loader_aliases
    for item in from_match.group("items").split(","):
        item = item.strip()
        item_match = IMPORT_ALIAS_ITEM_PATTERN.match(item)
        imported_name = item_match.group(1) if item_match is not None else item
        local_name = item_match.group(2) if item_match is not None else item
        if imported_name == "load":
            load_aliases.add(local_name)
        elif imported_name in {"SafeLoader", "CSafeLoader"}:
            safe_loader_aliases.add(local_name)
    return module_aliases, load_aliases, safe_loader_aliases


def _line_references_name(line: str, name: str) -> bool:
    return re.search(rf"\b{re.escape(name)}\b", line) is not None


def _line_references_dependency_alias(line: str, name: str) -> bool:
    escaped = re.escape(name)
    return (
        re.search(rf"=\s*{escaped}\b", line) is not None
        or re.search(rf"dependencies\s*=\s*\[[^\]]*\b{escaped}\b", line) is not None
    )


def _dedupe_refs(refs: list[tuple[str, int]]) -> list[tuple[str, int]]:
    seen: set[tuple[str, int]] = set()
    deduped: list[tuple[str, int]] = []
    for ref in refs:
        if ref in seen:
            continue
        seen.add(ref)
        deduped.append(ref)
    return deduped


def _resolve_dependency_wrapper_authz(
    facts: list[CodebaseFactCandidate],
) -> list[CodebaseFactCandidate]:
    resolved = list(facts)
    wrapper_authz: dict[tuple[str, str], CodebaseFactCandidate] = {}
    handler_identities = _handler_identities_by_symbol(facts)
    seen_authz: set[tuple[str, str, str | None]] = set()
    dependency_calls = [
        fact
        for fact in facts
        if fact.fact_type == "dependency_call" and isinstance(fact.payload, dict)
    ]
    for fact in facts:
        if fact.fact_type != "authz_check" or not isinstance(fact.payload, dict):
            continue
        handler_identity = _fact_handler_identity(fact, "handler")
        if handler_identity is None:
            continue
        seen_authz.add((*handler_identity, fact.symbol_name))
        existing = wrapper_authz.get(handler_identity)
        if existing is None or _authz_hint_priority(
            fact.authz_hint
        ) > _authz_hint_priority(existing.authz_hint):
            wrapper_authz[handler_identity] = fact

    changed = True
    while changed:
        changed = False
        for fact in dependency_calls:
            caller_identity = _fact_handler_identity(fact, "caller")
            wrapper = fact.symbol_name
            if caller_identity is None or not isinstance(wrapper, str):
                continue
            wrapper_identity = _resolve_handler_identity(
                caller_identity[0],
                wrapper,
                handler_identities,
            )
            if wrapper_identity is None:
                continue
            authz = wrapper_authz.get(wrapper_identity)
            if authz is None:
                continue
            seen_key = (*caller_identity, authz.symbol_name)
            if seen_key in seen_authz:
                continue
            derived = CodebaseFactCandidate(
                fact_type="authz_check",
                source_path=caller_identity[0],
                symbol_name=authz.symbol_name,
                route_method=None,
                route_path=None,
                authz_hint=authz.authz_hint,
                sensitivity_label="low",
                payload={
                    "handler": caller_identity[1],
                    "line": fact.payload.get("line"),
                    "mapping_mode": "static_code_snippet_analysis",
                },
            )
            resolved.append(derived)
            seen_authz.add(seen_key)
            existing = wrapper_authz.get(caller_identity)
            if existing is None or _authz_hint_priority(
                derived.authz_hint
            ) > _authz_hint_priority(existing.authz_hint):
                wrapper_authz[caller_identity] = derived
            handler_identities.setdefault(caller_identity[1], set()).add(
                caller_identity
            )
            changed = True
    return resolved


def _function_signature_closed(line: str) -> bool:
    return line.rstrip().endswith(":")


def _route_decorator_closed(line: str) -> bool:
    return line.strip().startswith(")")


def _is_router_constructor(
    module_name: str | None,
    constructor_name: str,
    router_constructor_aliases: set[str],
) -> bool:
    if module_name is not None:
        return module_name == "fastapi" and constructor_name == "APIRouter"
    if constructor_name == "APIRouter":
        return True
    return constructor_name in router_constructor_aliases


def _router_assignment_closed(lines: list[str], constructor_name: str) -> bool:
    block = "\n".join(lines)
    start = block.find(constructor_name)
    if start == -1:
        return False

    depth = 0
    saw_open = False
    try:
        tokens = tokenize.generate_tokens(StringIO(block[start:]).readline)
        for token in tokens:
            if token.type != tokenize.OP:
                continue
            if token.string == "(":
                depth += 1
                saw_open = True
            elif token.string == ")" and saw_open:
                depth -= 1
                if depth == 0:
                    return True
    except tokenize.TokenError:
        return False
    return False


def _route_decorator_router_name(line: str) -> str | None:
    match = ROUTE_DECORATOR_ROUTER_PATTERN.search(line)
    if match is None:
        return None
    return match.group(1)


def _route_path_from_decorator_lines(lines: list[str]) -> str | None:
    for line in lines:
        match = STRING_LITERAL_PATTERN.search(line)
        if match is not None:
            return match.group(1)
    return None


def _flask_route_method(line: str) -> str:
    match = FLASK_ROUTE_METHOD_PATTERN.search(line)
    if match is None:
        return "GET"
    return match.group(1).upper()


def _flask_add_url_rule_closed(lines: list[str]) -> bool:
    block = "\n".join(lines)
    start = block.find("add_url_rule")
    if start == -1:
        return False

    depth = 0
    saw_open = False
    try:
        tokens = tokenize.generate_tokens(StringIO(block[start:]).readline)
        for token in tokens:
            if token.type != tokenize.OP:
                continue
            if token.string == "(":
                depth += 1
                saw_open = True
            elif token.string == ")" and saw_open:
                depth -= 1
                if depth == 0:
                    return True
    except tokenize.TokenError:
        return False
    return False


def _flask_function_add_url_rule_route_facts(
    source_path: str,
    lines: list[str],
    start_line: int,
    function_authz_refs: dict[str, list[tuple[str, int]]],
) -> list[CodebaseFactCandidate]:
    block = "\n".join(lines)
    route_path = _route_path_from_decorator_lines(lines)
    view_match = FLASK_FUNCTION_VIEW_PATTERN.search(block)
    if route_path is None or view_match is None:
        return []

    handler_name = view_match.group(1)
    facts = [
        CodebaseFactCandidate(
            fact_type="route_handler",
            source_path=source_path,
            symbol_name=handler_name,
            route_method=_flask_route_method(block),
            route_path=route_path,
            authz_hint=None,
            sensitivity_label="low",
            payload={
                "handler": handler_name,
                "line": start_line,
                "mapping_mode": "static_code_snippet_analysis",
            },
        )
    ]
    for call_name, authz_line in function_authz_refs.get(handler_name, []):
        facts.append(
            CodebaseFactCandidate(
                fact_type="authz_check",
                source_path=source_path,
                symbol_name=call_name,
                route_method=None,
                route_path=None,
                authz_hint=_authz_hint(call_name),
                sensitivity_label="low",
                payload={
                    "handler": handler_name,
                    "line": authz_line,
                    "mapping_mode": "static_code_snippet_analysis",
                },
            )
        )
    return facts


def _flask_method_view_route_facts(
    source_path: str,
    lines: list[str],
    start_line: int,
    method_view_methods: dict[str, set[str]],
    method_view_authz_refs: dict[str, list[tuple[str, int]]],
    method_view_method_authz_refs: dict[tuple[str, str], list[tuple[str, int]]],
) -> list[CodebaseFactCandidate]:
    block = "\n".join(lines)
    route_path = _route_path_from_decorator_lines(lines)
    view_match = FLASK_METHOD_VIEW_PATTERN.search(block)
    if route_path is None or view_match is None:
        return []

    class_name = view_match.group(1)
    facts: list[CodebaseFactCandidate] = []
    for method_name in sorted(method_view_methods.get(class_name, set())):
        handler_name = f"{class_name}.{method_name}"
        facts.append(
            CodebaseFactCandidate(
                fact_type="route_handler",
                source_path=source_path,
                symbol_name=handler_name,
                route_method=method_name.upper(),
                route_path=route_path,
                authz_hint=None,
                sensitivity_label="low",
                payload={
                    "handler": handler_name,
                    "line": start_line,
                    "mapping_mode": "static_code_snippet_analysis",
                },
            )
        )
        for call_name, authz_line in _dedupe_refs(
            [
                *method_view_authz_refs.get(class_name, []),
                *method_view_method_authz_refs.get((class_name, method_name), []),
            ]
        ):
            facts.append(
                CodebaseFactCandidate(
                    fact_type="authz_check",
                    source_path=source_path,
                    symbol_name=call_name,
                    route_method=None,
                    route_path=None,
                    authz_hint=_authz_hint(call_name),
                    sensitivity_label="low",
                    payload={
                        "handler": handler_name,
                        "line": authz_line,
                        "mapping_mode": "static_code_snippet_analysis",
                    },
                )
            )
    return facts


def _method_view_decorator_authz_refs(
    line: str,
    line_number: int,
    import_aliases: dict[str, str],
) -> list[tuple[str, int]]:
    match = METHOD_VIEW_DECORATORS_PATTERN.search(line)
    if match is None:
        return []
    refs: list[tuple[str, int]] = []
    for call_name in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", match.group(1)):
        resolved_name = import_aliases.get(call_name, call_name)
        if _is_authz_call(resolved_name):
            refs.append((resolved_name, line_number))
    return _dedupe_refs(refs)


def _authz_decorator_ref(
    line: str,
    line_number: int,
    import_aliases: dict[str, str],
) -> tuple[str, int] | None:
    match = AUTHZ_DECORATOR_PATTERN.match(line)
    if match is None:
        return None
    call_name = import_aliases.get(match.group(1), match.group(1))
    if not _is_authz_call(call_name):
        return None
    return call_name, line_number


def _is_method_view_base(base_list: str) -> bool:
    return any(base.strip().endswith("MethodView") for base in base_list.split(","))


def _is_model_base(base_list: str) -> bool:
    return any(
        base.strip().endswith(marker)
        for base in base_list.split(",")
        for marker in ("BaseModel", "Model")
    )


def _is_authz_call(call_name: str) -> bool:
    normalized = call_name.lower()
    if any(marker in normalized for marker in AUTHZ_NAME_MARKERS):
        return True
    if _is_ssrf_guard_name(normalized):
        return True
    if _is_path_guard_name(normalized):
        return True
    if _is_mass_assign_guard_name(normalized):
        return True
    if _is_command_execution_guard_name(normalized):
        return True
    if _is_deserialization_guard_name(normalized):
        return True
    if _is_file_upload_guard_name(normalized):
        return True
    if _is_money_flow_guard_name(normalized):
        return True
    if _is_agent_tool_guard_name(normalized):
        return True
    return _is_injection_guard_name(normalized)


def _authz_hint(call_name: str) -> str:
    normalized = call_name.lower()
    if _is_ssrf_guard_name(normalized):
        return "ssrf_validation_check"
    if _is_path_guard_name(normalized):
        return "path_validation_check"
    if _is_mass_assign_guard_name(normalized):
        return "mass_assignment_check"
    if _is_command_execution_guard_name(normalized):
        return "command_injection_validation_check"
    if _is_deserialization_guard_name(normalized):
        return "deserialization_validation_check"
    if _is_file_upload_guard_name(normalized):
        return "file_upload_validation_check"
    if _is_money_flow_guard_name(normalized):
        return "server_authoritative_amount_check"
    if _is_agent_tool_guard_name(normalized):
        return "agent_tool_authorization_check"
    if _is_injection_guard_name(normalized):
        return "injection_validation_check"
    if "owner_or_admin" in normalized:
        return "owner_or_admin_check"
    if any(
        marker in normalized
        for marker in (
            "require_owner",
            "ensure_owner",
            "check_ownership",
            "verify_ownership",
            "assert_owner",
            "owner_check",
            "ownership",
            "owner_id",
            "owner_guard",
            "can_access",
            "verify_access",
            "assert_access",
        )
    ) or (
        "owner" in normalized
        and any(
            marker in normalized
            for marker in ("require", "ensure", "check", "verify", "assert", "guard")
        )
    ):
        return "ownership_boundary_check"
    if "permission" in normalized:
        return "permission_check"
    if "role" in normalized:
        return "role_check"
    return "authorization_boundary_candidate"


def _is_sensitive_sink(call_name: str) -> bool:
    return call_name.lower() in SENSITIVE_SINK_NAMES


def _is_service_call(call_name: str) -> bool:
    return not _is_authz_call(call_name) and not _is_sensitive_sink(call_name)


def _authz_boundary_filter(
    line: str,
    principal_aliases: dict[str, str] | None = None,
) -> tuple[str, str] | None:
    if line.lstrip().startswith("#"):
        return None
    principal_aliases = principal_aliases or {}
    for match in AUTHZ_BOUNDARY_COMPARISON_PATTERN.finditer(line):
        field_name = _authz_boundary_field(
            match.group("left"),
            match.group("right"),
            principal_aliases,
        )
        if field_name is None:
            continue
        return (f"{field_name}_filter", _authz_boundary_hint(field_name))
    for match in AUTHZ_BOUNDARY_KWARG_PATTERN.finditer(line):
        field_name = _authz_boundary_kwarg_field(
            match.group("field"),
            match.group("value"),
            principal_aliases,
        )
        if field_name is None:
            continue
        return (f"{field_name}_filter", _authz_boundary_hint(field_name))
    for match in AUTHZ_BOUNDARY_MEMBERSHIP_PATTERN.finditer(line):
        field_name = _authz_boundary_membership_field(
            match.group("field"),
            match.group("values"),
            principal_aliases,
        )
        if field_name is None:
            continue
        return (f"{field_name}_filter", _authz_boundary_hint(field_name))
    return None


def _authz_boundary_membership_start(line: str) -> str | None:
    match = AUTHZ_BOUNDARY_MEMBERSHIP_START_PATTERN.search(line)
    if match is None:
        return None
    return match.group("field")


def _authz_boundary_kwarg_membership_start(line: str) -> str | None:
    match = AUTHZ_BOUNDARY_KWARG_START_PATTERN.search(line)
    if match is None:
        return None
    return match.group("field")


def _identifier_line_value(line: str) -> str | None:
    match = IDENTIFIER_LINE_PATTERN.match(line)
    if match is None:
        return None
    return match.group(1)


def _membership_wrapper_line(line: str) -> bool:
    return MEMBERSHIP_WRAPPER_LINE_PATTERN.match(line) is not None


def _authz_boundary_field(
    left: str,
    right: str,
    principal_aliases: dict[str, str] | None = None,
) -> str | None:
    principal_aliases = principal_aliases or {}
    left_field = _identifier_leaf(left)
    right_field = _identifier_leaf(right)
    left_alias_field = _principal_alias_boundary_field(left, principal_aliases)
    right_alias_field = _principal_alias_boundary_field(right, principal_aliases)
    if (
        left_alias_field is not None
        and right_field in AUTHZ_BOUNDARY_FIELDS
        and _canonical_boundary_field(left_alias_field) == _canonical_boundary_field(right_field)
    ):
        return right_field
    if (
        right_alias_field is not None
        and left_field in AUTHZ_BOUNDARY_FIELDS
        and _canonical_boundary_field(right_alias_field) == _canonical_boundary_field(left_field)
    ):
        return left_field
    left_relation = _relation_boundary_field(left_field)
    right_relation = _relation_boundary_field(right_field)
    if (
        left_relation is not None
        and right_relation is not None
        and _same_relation_boundary(left_relation, right_relation)
    ):
        return f"{left_relation}_id"
    if left_relation in {"owner", "user"} and _is_principal_object_identifier(right):
        return f"{left_relation}_id"
    if right_relation in {"owner", "user"} and _is_principal_object_identifier(left):
        return f"{right_relation}_id"
    if left_field == "created_by" and _is_principal_object_identifier(right):
        return "created_by_id"
    if right_field == "created_by" and _is_principal_object_identifier(left):
        return "created_by_id"
    if _is_principal_id_boundary_field(left_field) and _is_principal_id_identifier(right):
        return left_field
    if _is_principal_id_boundary_field(right_field) and _is_principal_id_identifier(left):
        return right_field
    if left_field not in AUTHZ_BOUNDARY_FIELDS and right_field not in AUTHZ_BOUNDARY_FIELDS:
        return None
    right_relation_id_field = _principal_relation_id_boundary_field(right)
    if (
        left_field in AUTHZ_BOUNDARY_FIELDS
        and right_relation_id_field is not None
        and _canonical_boundary_field(left_field)
        == _canonical_boundary_field(right_relation_id_field)
    ):
        return left_field
    left_relation_id_field = _principal_relation_id_boundary_field(left)
    if (
        right_field in AUTHZ_BOUNDARY_FIELDS
        and left_relation_id_field is not None
        and _canonical_boundary_field(right_field)
        == _canonical_boundary_field(left_relation_id_field)
    ):
        return right_field
    if (
        left_field in AUTHZ_BOUNDARY_FIELDS
        and right_field in AUTHZ_BOUNDARY_FIELDS
        and _canonical_boundary_field(left_field) == _canonical_boundary_field(right_field)
    ):
        return left_field
    if left_field == right_field and left_field in AUTHZ_BOUNDARY_FIELDS:
        return left_field
    return None


def _authz_boundary_kwarg_field(
    field_name: str,
    value: str,
    principal_aliases: dict[str, str] | None = None,
) -> str | None:
    principal_aliases = principal_aliases or {}
    normalized_field = _normalized_boundary_field(field_name)
    value_field = _identifier_leaf(value)
    alias_field = _principal_alias_boundary_field(value, principal_aliases)
    if (
        alias_field is not None
        and normalized_field in AUTHZ_BOUNDARY_FIELDS
        and _canonical_boundary_field(alias_field) == _canonical_boundary_field(normalized_field)
    ):
        return normalized_field
    if _is_principal_id_boundary_field(normalized_field) and _is_principal_id_identifier(value):
        return normalized_field
    relation_id_field = _principal_relation_id_boundary_field(value)
    if (
        normalized_field in AUTHZ_BOUNDARY_FIELDS
        and relation_id_field is not None
        and _canonical_boundary_field(normalized_field)
        == _canonical_boundary_field(relation_id_field)
    ):
        return normalized_field
    relation_field = _relation_boundary_field(field_name)
    if normalized_field == "created_by" and _is_principal_object_identifier(value):
        return "created_by_id"
    if relation_field in {"owner", "user"} and _is_principal_object_identifier(value):
        return f"{relation_field}_id"
    if relation_field is not None and _same_relation_boundary(relation_field, value_field):
        return f"{relation_field}_id"
    relation_membership_field = _relation_membership_boundary_field(field_name)
    if (
        relation_membership_field is not None
        and _relation_collection_matches(relation_membership_field, value_field)
    ):
        return f"{relation_membership_field}_id"
    if normalized_field == value_field and normalized_field in AUTHZ_BOUNDARY_FIELDS:
        return normalized_field
    if (
        normalized_field in AUTHZ_BOUNDARY_FIELDS
        and _boundary_collection_matches(normalized_field, value_field)
    ):
        return normalized_field
    return None


def _authz_boundary_membership_field(
    field_name: str,
    values: str,
    principal_aliases: dict[str, str] | None = None,
) -> str | None:
    principal_aliases = principal_aliases or {}
    normalized_field = _identifier_leaf(field_name)
    values_field = _identifier_leaf(values)
    if normalized_field not in AUTHZ_BOUNDARY_FIELDS:
        relation_field = _relation_boundary_field(normalized_field)
        if relation_field is None or not _relation_collection_matches(
            relation_field,
            values_field,
        ):
            return None
        return f"{relation_field}_id"
    if _is_principal_id_boundary_field(normalized_field) and _is_principal_id_identifier(
        values,
    ):
        return normalized_field
    alias_field = _principal_alias_boundary_field(values, principal_aliases)
    if (
        alias_field is not None
        and _canonical_boundary_field(normalized_field)
        == _canonical_boundary_field(alias_field)
    ):
        return normalized_field
    relation_id_field = _principal_relation_id_boundary_field(values)
    if (
        relation_id_field is not None
        and _canonical_boundary_field(normalized_field)
        == _canonical_boundary_field(relation_id_field)
    ):
        return normalized_field
    if _boundary_collection_matches(normalized_field, values_field):
        return normalized_field
    return None


def _identifier_leaf(identifier: str) -> str:
    return identifier.rsplit(".", 1)[-1].lower()


def _normalized_boundary_field(field_name: str) -> str:
    normalized = field_name.lower()
    if normalized.endswith("__in"):
        normalized = normalized.removesuffix("__in")
    if normalized.endswith("__id"):
        return f"{normalized.removesuffix('__id')}_id"
    return normalized


def _relation_boundary_field(field_name: str) -> str | None:
    normalized = field_name.lower()
    if normalized.endswith("__in"):
        return None
    if normalized in {
        "owner",
        "user",
        "tenant",
        "account",
        "org",
        "organization",
        "workspace",
        "team",
        "project",
        "group",
        "agent",
    }:
        return normalized
    return None


def _relation_membership_boundary_field(field_name: str) -> str | None:
    normalized = field_name.lower()
    if not normalized.endswith("__in"):
        return None
    relation = normalized.removesuffix("__in")
    if relation in {
        "owner",
        "user",
        "tenant",
        "account",
        "org",
        "organization",
        "workspace",
        "team",
        "project",
        "group",
        "agent",
    }:
        return relation
    return None


def _same_relation_boundary(left: str, right: str) -> bool:
    return _canonical_relation_boundary(left) == _canonical_relation_boundary(right)


def _relation_collection_matches(relation: str, values_field: str) -> bool:
    canonical_relation = _canonical_relation_boundary(relation)
    canonical_values = _canonical_relation_boundary(values_field.removesuffix("s"))
    return canonical_values == canonical_relation


def _canonical_relation_boundary(field_name: str) -> str:
    if field_name in {"org", "organization"}:
        return "organization"
    return field_name


def _canonical_boundary_field(field_name: str) -> str:
    if field_name in {"org_id", "organization_id"}:
        return "organization_id"
    return field_name


def _boundary_collection_matches(field_name: str, values_field: str) -> bool:
    singular = values_field.removesuffix("s")
    if not singular.endswith("_id"):
        return False
    return _canonical_boundary_field(singular) == _canonical_boundary_field(field_name)


def _principal_relation_id_boundary_field(identifier: str) -> str | None:
    parts = identifier.lower().split(".")
    if len(parts) != 3 or parts[0] != "current_user" or parts[2] != "id":
        return None
    relation = _relation_boundary_field(parts[1])
    if relation is None:
        return None
    return f"{relation}_id"


def _principal_boundary_identifier_field(identifier: str) -> str | None:
    normalized = identifier.lower()
    relation_id_field = _principal_relation_id_boundary_field(normalized)
    if relation_id_field is not None:
        return relation_id_field
    parts = normalized.split(".")
    if len(parts) == 2 and parts[0] == "current_user":
        field_name = _normalized_boundary_field(parts[1])
        if field_name in AUTHZ_BOUNDARY_FIELDS:
            return field_name
    if len(parts) == 3 and parts[:2] == ["request", "user"]:
        field_name = _normalized_boundary_field(parts[2])
        if field_name in AUTHZ_BOUNDARY_FIELDS:
            return field_name
    return None


def _principal_alias_boundary_field(
    identifier: str,
    principal_aliases: dict[str, str],
) -> str | None:
    return principal_aliases.get(_identifier_leaf(identifier))


def _is_principal_id_identifier(identifier: str) -> bool:
    return identifier.lower() in PRINCIPAL_ID_IDENTIFIERS


def _is_principal_id_boundary_field(field_name: str) -> bool:
    return field_name in {"owner_id", "user_id", "created_by_id"}


def _is_principal_object_identifier(identifier: str) -> bool:
    return identifier.lower() == "current_user"


def _authz_boundary_hint(field_name: str) -> str:
    if field_name == "owner_id":
        return "owner_or_admin_check"
    return "ownership_boundary_check"


def _dedupe_facts(facts: list[CodebaseFactCandidate]) -> list[CodebaseFactCandidate]:
    seen: set[tuple[object, ...]] = set()
    deduped: list[CodebaseFactCandidate] = []
    for fact in facts:
        caller = None
        handler = None
        if isinstance(fact.payload, dict):
            if fact.fact_type == "service_call":
                caller = fact.payload.get("caller")
            if fact.fact_type in {
                "sensitive_sink",
                "authz_check",
                "authorization_gap_candidate",
                "service_call",
            }:
                handler = fact.payload.get("handler")
        key = (
            fact.fact_type,
            fact.source_path,
            fact.symbol_name,
            fact.route_method,
            fact.route_path,
            fact.authz_hint,
            caller,
            handler,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(fact)
    return deduped


def _dedupe_handler_authz_facts(
    facts: list[CodebaseFactCandidate],
) -> list[CodebaseFactCandidate]:
    deduped: list[CodebaseFactCandidate] = []
    authz_index_by_handler: dict[tuple[str, str], int] = {}
    for fact in facts:
        handler = fact.payload.get("handler") if isinstance(fact.payload, dict) else None
        if fact.fact_type != "authz_check" or not isinstance(handler, str):
            deduped.append(fact)
            continue
        key = (fact.source_path, handler)
        existing_index = authz_index_by_handler.get(key)
        if existing_index is None:
            authz_index_by_handler[key] = len(deduped)
            deduped.append(fact)
            continue
        if _authz_hint_priority(fact.authz_hint) > _authz_hint_priority(
            deduped[existing_index].authz_hint
        ):
            deduped[existing_index] = fact
    return deduped


def _authz_hint_priority(authz_hint: str | None) -> int:
    if authz_hint == "owner_or_admin_check":
        return 4
    if authz_hint == "ownership_boundary_check":
        return 4
    if authz_hint == "ssrf_validation_check":
        return 4
    if authz_hint == "path_validation_check":
        return 4
    if authz_hint == "mass_assignment_check":
        return 4
    if authz_hint == "injection_validation_check":
        return 4
    if authz_hint == "command_injection_validation_check":
        return 4
    if authz_hint == "deserialization_validation_check":
        return 4
    if authz_hint == "file_upload_validation_check":
        return 4
    if authz_hint == "server_authoritative_amount_check":
        return 4
    if authz_hint == "agent_tool_authorization_check":
        return 4
    if authz_hint == "permission_check":
        return 3
    if authz_hint == "role_check":
        return 2
    return 1


def _count_facts(facts: list[CodebaseFactCandidate], fact_type: str) -> int:
    return sum(1 for fact in facts if fact.fact_type == fact_type)
