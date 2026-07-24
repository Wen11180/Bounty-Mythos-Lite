import ast
from collections.abc import Callable
from dataclasses import dataclass, replace
from io import StringIO
import posixpath
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
METHOD_DECORATOR_START_PATTERN = re.compile(
    r"^\s*@(?P<name>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*\("
)
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
# Explicit one-time, quota, and limited-resource transitions only. Generic writes
# remain object-authorization sinks and must not be inferred as race conditions.
STATE_TRANSITION_SINK_NAMES = {
    "advance_one_time_state",
    "claim_limited_resource",
    "consume_one_time_code",
    "consume_one_time_token",
    "consume_quota",
    "decrement_quota",
    "redeem_one_time_code",
    "redeem_one_time_token",
}
SENSITIVE_SINK_NAMES.update(STATE_TRANSITION_SINK_NAMES)
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
    "axios_delete",
    "axios_get",
    "axios_head",
    "axios_options",
    "axios_patch",
    "axios_post",
    "axios_put",
    "http_get",
    "http_post",
    "http_post_form",
    "rest_template_get_for_object",
    "rest_template_get_for_entity",
    "rest_template_post_for_object",
    "rest_template_post_for_entity",
    "rest_template_exchange",
    "rest_template_execute",
    "http_client_get_async",
    "http_client_get_string_async",
    "http_client_get_stream_async",
    "http_client_post_async",
    "http_client_put_async",
    "http_client_patch_async",
    "http_client_delete_async",
}
SENSITIVE_SINK_NAMES.update(OUTBOUND_HTTP_SINK_NAMES)
_TYPESCRIPT_QUALIFIED_OUTBOUND_HTTP_SINKS = {
    "axios.delete": "axios_delete",
    "axios.get": "axios_get",
    "axios.head": "axios_head",
    "axios.options": "axios_options",
    "axios.patch": "axios_patch",
    "axios.post": "axios_post",
    "axios.put": "axios_put",
}
_PYTHON_OUTBOUND_HTTP_MODULES = frozenset({"requests", "httpx"})
_PYTHON_OUTBOUND_HTTP_METHODS = frozenset(
    {"delete", "get", "head", "options", "patch", "post", "put", "request"}
)
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
    "validate_outbound_url",
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
# Explicit transactional, lock, or conditional-write controls for one-time and quota transitions.
STATE_TRANSITION_GUARD_MARKERS = (
    "transactional_guard",
    "transactional_state",
    "with_transaction",
    "in_transaction",
    "select_for_update",
    "lock_for_update",
    "compare_and_set",
    "conditional_update",
    "optimistic_lock",
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
    "missing_ssrf_validation": {
        "ssrf_validation_check",
    },
    "missing_path_validation": {
        "path_validation_check",
    },
    "missing_mass_assignment_guard": {
        "mass_assignment_check",
    },
    "missing_injection_validation": {
        "injection_validation_check",
    },
    "missing_command_injection_validation": {
        "command_injection_validation_check",
    },
    "missing_unsafe_deserialization_guard": {
        "deserialization_validation_check",
    },
    "missing_file_upload_validation": {
        "file_upload_validation_check",
    },
    "missing_agent_tool_authorization_check": {
        "agent_tool_authorization_check",
    },
    "missing_server_authoritative_amount_check": {
        "server_authoritative_amount_check",
    },
    "missing_transactional_state_guard": {
        "transactional_state_guard",
    },
    "missing_jwt_verification": {
        "jwt_verification_check",
    },
}
INPUT_BOUND_STATIC_GAP_GUARD_HINTS = {
    "missing_ssrf_validation": {"ssrf_validation_check"},
    "missing_path_validation": {"path_validation_check"},
    "missing_mass_assignment_guard": {"mass_assignment_check"},
    "missing_injection_validation": {"injection_validation_check"},
    "missing_command_injection_validation": {
        "command_injection_validation_check"
    },
    "missing_unsafe_deserialization_guard": {"deserialization_validation_check"},
    "missing_file_upload_validation": {"file_upload_validation_check"},
}
INPUT_BOUND_STATIC_GUARD_HINTS = frozenset(
    hint
    for hints in INPUT_BOUND_STATIC_GAP_GUARD_HINTS.values()
    for hint in hints
)
INPUT_BOUND_STATIC_GAP_SINK_NAMES = {
    "missing_ssrf_validation": frozenset(OUTBOUND_HTTP_SINK_NAMES),
    "missing_path_validation": frozenset(FILE_PATH_SINK_NAMES),
    "missing_mass_assignment_guard": frozenset(MASS_ASSIGN_SINK_NAMES),
    "missing_injection_validation": frozenset(INJECTION_SINK_NAMES),
    "missing_command_injection_validation": frozenset(COMMAND_EXECUTION_SINK_NAMES),
    "missing_unsafe_deserialization_guard": frozenset(
        UNSAFE_DESERIALIZATION_SINK_NAMES
    ),
    "missing_file_upload_validation": frozenset(FILE_UPLOAD_SINK_NAMES),
}
INPUT_BOUND_SINK_ARGUMENT_INDEXES = {
    "apply_user_update": 1,
    "persist_user": 1,
    "update_user": 1,
}
HTTP_METHOD_NAMES = {"get", "post", "put", "patch", "delete"}
DRF_ACTION_HTTP_METHOD_NAMES = HTTP_METHOD_NAMES | {"head", "options", "trace"}
DRF_ROUTER_COLLECTION_ACTIONS = (
    ("list", "GET"),
    ("create", "POST"),
)
DRF_ROUTER_DETAIL_ACTIONS = (
    ("retrieve", "GET"),
    ("update", "PUT"),
    ("partial_update", "PATCH"),
    ("destroy", "DELETE"),
)
DRF_VIEWSET_BASES = {
    "ModelViewSet": "model",
    "ReadOnlyModelViewSet": "read_only",
    "ViewSet": "action_only",
    "GenericViewSet": "action_only",
}
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
TYPESCRIPT_RUNTIME_IMPORT_SOURCE_SUFFIXES = {
    ".js": (".ts", ".tsx"),
    ".mjs": (".mts",),
    ".cjs": (".cts",),
}
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
TYPESCRIPT_JSONWEBTOKEN_ALIAS_PATTERN = re.compile(
    r"\b(?:import\s+(?:\*\s+as\s+)?(?P<import_alias>[A-Za-z_$][A-Za-z0-9_$]*)"
    r"(?:\s*,[^;]*)?\s+from\s*|(?:const|let|var)\s+"
    r"(?P<require_alias>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require\s*\()"
    r"[\"']jsonwebtoken[\"']",
    re.IGNORECASE,
)
TYPESCRIPT_AXIOS_ALIAS_PATTERN = re.compile(
    r"\b(?:import\s+(?:\*\s+as\s+)?(?P<import_alias>[A-Za-z_$][A-Za-z0-9_$]*)"
    r"(?:\s*,[^;]*)?\s+from\s*|(?:const|let|var)\s+"
    r"(?P<require_alias>[A-Za-z_$][A-Za-z0-9_$]*)(?:\s*:\s*[^=;\n]+)?\s*="
    r"\s*require\s*\()[\"']axios[\"']",
    re.IGNORECASE,
)
TYPESCRIPT_OUTBOUND_HTTP_ALIAS_PATTERN = re.compile(
    r"\b(?:import\s+(?:(?P<namespace>\*)\s+as\s+)?"
    r"(?P<import_alias>[A-Za-z_$][A-Za-z0-9_$]*)"
    r"(?:\s*,[^;]*)?\s+from\s*|(?:const|let|var)\s+"
    r"(?P<require_alias>[A-Za-z_$][A-Za-z0-9_$]*)(?:\s*:\s*[^=;\n]+)?\s*="
    r"\s*require\s*\()[\"'](?P<module>"
    r"node-fetch|cross-fetch|got|undici|node:http|node:https|http|https)[\"']",
    re.IGNORECASE,
)
TYPESCRIPT_UNDICI_NAMED_IMPORT_PATTERN = re.compile(
    r"\b(?:import\s*\{(?P<imported>[^}]*)\}\s*from\s*|"
    r"(?:const|let|var)\s*\{(?P<required>[^}]*)\}\s*=\s*require\s*\()"
    r"[\"']undici[\"']",
    re.IGNORECASE,
)
TYPESCRIPT_TOKEN_ALIAS_PATTERN = re.compile(
    r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)"
    r"(?:\s*:\s*[^=;\n]+)?\s*=\s*(?P<expression>[^;\n]+)"
)
TYPESCRIPT_INPUT_REASSIGNMENT_PATTERN = re.compile(
    r"(?<![.$])(?:\b(?P<declaration>const|let|var)\s+)?"
    r"(?P<path>[A-Za-z_$][A-Za-z0-9_$]*"
    r"(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)(?:\s*:\s*[^=;\n]+)?\s*"
    r"(?:=(?!=|>)|[+*/%\-]=|&&=|\|\|=|\?\?=)"
)
TYPESCRIPT_INPUT_LOOP_BINDING_PATTERN = re.compile(
    r"\bfor\s*\(\s*(?:(?:const|let|var)\s+)?"
    r"(?P<path>[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)"
    r"\s+(?:of|in)\b"
)
TYPESCRIPT_TOKEN_REFERENCE_PATTERN = re.compile(
    r"[A-Za-z_$][A-Za-z0-9_$]*(?:\??\.[A-Za-z_$][A-Za-z0-9_$]*)*"
)
STRUCTURAL_INPUT_REFERENCE_PATTERN = re.compile(
    r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*"
)
SENSITIVE_INPUT_REFERENCE_MARKERS = (
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "header",
    "password",
    "secret",
    "token",
)
INPUT_REFERENCE_KIND_STRAIGHT_LINE = "straight_line"
INPUT_FLOW_UNSAFE_MARKER = "__input_flow_unsafe__"
INPUT_ATTRIBUTE_MUTATION_MARKER = "__attribute_mutation__"


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
class _DjangoLifecycleHook:
    handler_name: str
    action_dependent: bool = False


@dataclass(frozen=True)
class _DjangoViewHandler:
    source_path: str
    handler_name: str
    route_method: str
    service_handlers: tuple[_DjangoLifecycleHook, ...] = ()


@dataclass(frozen=True)
class _DjangoRouterRegistration:
    prefix: str
    view_identity: tuple[str, str]
    lookup_parameter: str | None


@dataclass
class _DjangoRouterState:
    registrations: list[_DjangoRouterRegistration]
    is_static: bool = True


@dataclass(frozen=True)
class _DjangoDRFAction:
    method_name: str
    route_methods: tuple[str, ...]
    detail: bool
    url_path: str


@dataclass
class _DjangoDRFRebindings:
    names: set[str]
    attribute_paths: set[tuple[str, ...]]


@dataclass(frozen=True)
class _DjangoURLPattern:
    route_path: str | None
    line: int
    view_handlers: tuple[_DjangoViewHandler, ...]
    include_source_path: str | None


def structural_input_reference(value: str) -> str | None:
    """Return a safe structural input reference without preserving values."""
    reference = value.strip()
    if STRUCTURAL_INPUT_REFERENCE_PATTERN.fullmatch(reference) is None:
        return None
    if any(
        marker in segment.lower()
        for segment in reference.split(".")
        for marker in SENSITIVE_INPUT_REFERENCE_MARKERS
    ):
        return None
    return f"input:{reference}"


def safe_input_reference(value: object) -> str | None:
    if not isinstance(value, str) or not value.startswith("input:"):
        return None
    return structural_input_reference(value.removeprefix("input:"))


def structural_claim_reference(value: str) -> str | None:
    reference = value.strip().lstrip("$").replace("?.", ".")
    if STRUCTURAL_INPUT_REFERENCE_PATTERN.fullmatch(reference) is None:
        return None
    root = reference.split(".", 1)[0]
    if any(marker in root.lower() for marker in SENSITIVE_INPUT_REFERENCE_MARKERS):
        return None
    return f"claims:{root}"


def safe_claim_reference(value: object) -> str | None:
    if not isinstance(value, str) or not value.startswith("claims:"):
        return None
    return structural_claim_reference(value.removeprefix("claims:"))


def _claim_reference_from_input_reference(value: str | None) -> str | None:
    safe_reference = safe_input_reference(value)
    if safe_reference is None:
        return None
    return structural_claim_reference(safe_reference.removeprefix("input:"))


def _input_binding_payload(
    input_ref: str | None,
    *,
    validated_output_ref: str | None = None,
) -> dict[str, str]:
    if input_ref is None and validated_output_ref is None:
        return {}
    payload = {"input_ref_kind": INPUT_REFERENCE_KIND_STRAIGHT_LINE}
    if input_ref is not None:
        payload["input_ref"] = input_ref
    if validated_output_ref is not None:
        payload["validated_output_ref"] = validated_output_ref
    return payload


def _input_bound_static_call_input_ref(
    call_name: str,
    input_refs: list[str | None],
    *,
    input_index: int | None = None,
) -> str | None:
    if input_index is not None:
        return input_refs[input_index] if input_index < len(input_refs) else None
    input_index = INPUT_BOUND_SINK_ARGUMENT_INDEXES.get(
        _normalized_typescript_name(call_name)
    )
    if input_index is not None and input_index < len(input_refs):
        return input_refs[input_index]
    return input_refs[0] if input_refs else None


def _is_input_bound_static_sink(call_name: str) -> bool:
    normalized_name = _normalized_typescript_name(call_name)
    return any(
        normalized_name in sink_names
        for sink_names in INPUT_BOUND_STATIC_GAP_SINK_NAMES.values()
    )


def map_authorized_code_files(payload: dict) -> CodebaseMapResult:
    files = payload.get("authorized_code_files")
    if not isinstance(files, list):
        return CodebaseMapResult(facts=[], file_count=0)

    typescript_source_paths = _typescript_authorized_source_paths(files)
    route_prefixes = _merge_static_route_prefixes(
        _fastapi_route_prefixes(files),
        _flask_route_prefixes(files),
    )
    django_route_facts, django_class_view_names = _django_route_facts(files)
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
                    typescript_source_paths=typescript_source_paths,
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
            facts.extend(
                _map_file(
                    source_path=source_path,
                    content=content,
                    class_method_view_classes=django_class_view_names.get(
                        source_path,
                        set(),
                    ),
                )
            )
            if source_path.lower().endswith(".py"):
                facts.extend(
                    _strawberry_graphql_operation_facts(
                        source_path=source_path,
                        content=content,
                    )
                )

    facts.extend(django_route_facts)
    facts = _apply_static_route_prefixes(facts, route_prefixes)
    facts = _dedupe_handler_authz_facts(
        _dedupe_facts(_resolve_dependency_wrapper_authz(facts))
    )
    authorization_gaps = [
        *_authorization_gap_candidates(facts),
        *_graphql_authorization_gap_candidates(facts),
    ]
    jwt_gaps = _jwt_verification_gap_candidates(facts)
    jwt_gap_routes = {
        (gap.source_path, gap.symbol_name, gap.route_method, gap.route_path)
        for gap in jwt_gaps
    }
    authorization_gaps = [
        gap
        for gap in authorization_gaps
        if (
            gap.payload.get("root_cause") != "missing_object_ownership_check"
            or (gap.source_path, gap.symbol_name, gap.route_method, gap.route_path)
            not in jwt_gap_routes
        )
    ]
    return CodebaseMapResult(
        facts=_dedupe_facts([*facts, *authorization_gaps, *jwt_gaps]),
        file_count=mapped_file_count,
    )


def _strawberry_graphql_operation_facts(
    *,
    source_path: str,
    content: str,
) -> list[CodebaseFactCandidate]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    if not any(
        isinstance(statement, ast.Import)
        and any(
            alias.name == "strawberry" and alias.asname is None
            for alias in statement.names
        )
        for statement in tree.body
    ):
        return []

    operation_types = {
        "Query": "query",
        "Mutation": "mutation",
        "Subscription": "subscription",
    }
    operations: list[
        tuple[str, str, ast.FunctionDef | ast.AsyncFunctionDef]
    ] = []
    for statement in tree.body:
        if not isinstance(statement, ast.ClassDef):
            continue
        operation_type = operation_types.get(statement.name)
        if operation_type is None or not any(
            _python_call_name(decorator) == "strawberry.type"
            for decorator in statement.decorator_list
        ):
            continue
        for member in statement.body:
            if not isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            operation_names = [
                operation_name
                for decorator in member.decorator_list
                if (
                    operation_name := _strawberry_field_operation_name(
                        member,
                        decorator,
                    )
                )
                is not None
            ]
            if len(operation_names) == 1:
                operations.append((operation_type, operation_names[0], member))

    binding_counts: dict[tuple[str, str], int] = {}
    for operation_type, operation_name, _member in operations:
        binding = (operation_type, operation_name)
        binding_counts[binding] = binding_counts.get(binding, 0) + 1

    facts: list[CodebaseFactCandidate] = []
    for operation_type, operation_name, member in operations:
        if binding_counts[(operation_type, operation_name)] != 1:
            continue
        handler = member.name.lower()
        facts.append(
            CodebaseFactCandidate(
                fact_type="graphql_operation",
                source_path=source_path,
                symbol_name=handler,
                route_method=None,
                route_path=None,
                authz_hint=None,
                sensitivity_label="low",
                payload={
                    "handler": handler,
                    "line": member.lineno,
                    "operation_type": operation_type,
                    "operation_name": operation_name,
                    "framework": "strawberry",
                    "mapping_mode": "static_code_snippet_analysis",
                },
            )
        )
    return facts


def _strawberry_field_operation_name(
    member: ast.FunctionDef | ast.AsyncFunctionDef,
    decorator: ast.expr,
) -> str | None:
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if _python_call_name(target) != "strawberry.field":
        return None
    if not isinstance(decorator, ast.Call):
        return member.name
    if decorator.args or any(keyword.arg is None for keyword in decorator.keywords):
        return None
    name_values = [
        keyword.value for keyword in decorator.keywords if keyword.arg == "name"
    ]
    if not name_values:
        return member.name
    if len(name_values) != 1:
        return None
    value = name_values[0]
    if (
        isinstance(value, ast.Constant)
        and isinstance(value.value, str)
        and value.value
    ):
        return value.value
    return None


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


def _django_route_facts(
    files: list[object],
) -> tuple[list[CodebaseFactCandidate], dict[str, set[str]]]:
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
        return [], {}

    source_by_module = _python_source_by_module(sources)
    function_lines = _python_function_lines(sources)
    view_lookup_parameters = _django_view_lookup_parameters(sources)
    drf_action_routes = _django_drf_action_routes(sources)
    drf_inherited_action_hooks = _django_drf_inherited_action_hooks(sources)
    roots = _django_root_urlconf_sources(sources, source_by_module)
    patterns_by_source = _django_runtime_url_patterns(
        sources,
        source_by_module=source_by_module,
        function_lines=function_lines,
        view_lookup_parameters=view_lookup_parameters,
        drf_action_routes=drf_action_routes,
        drf_inherited_action_hooks=drf_inherited_action_hooks,
        roots=roots,
    )
    if not patterns_by_source:
        return [], {}

    facts: list[CodebaseFactCandidate] = []
    class_view_names: dict[str, set[str]] = {}

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
            for view_handler in pattern.view_handlers:
                view_source_path = view_handler.source_path
                handler_name = view_handler.handler_name
                function_line = function_lines.get((view_source_path, handler_name))
                if "." in handler_name:
                    class_name = handler_name.rsplit(".", 1)[0]
                    class_view_names.setdefault(view_source_path, set()).add(class_name)
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
                        route_method=view_handler.route_method,
                        route_path=route_path,
                        authz_hint=None,
                        sensitivity_label="low",
                        payload=payload,
                    )
                )
                for service_handler in view_handler.service_handlers:
                    facts.append(
                        CodebaseFactCandidate(
                            fact_type="service_call",
                            source_path=view_source_path,
                            symbol_name=service_handler.handler_name,
                            route_method=None,
                            route_path=None,
                            authz_hint=None,
                            sensitivity_label="low",
                            payload={
                                "caller": handler_name,
                                "line": function_line
                                if function_line is not None
                                else pattern.line,
                                "mapping_mode": "static_django_viewset_lifecycle",
                                **(
                                    {"lifecycle_action_dependent": True}
                                    if service_handler.action_dependent
                                    else {}
                                ),
                            },
                        )
                    )

    for root in roots:
        visit(root, "", set())
    return facts, class_view_names


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


def _django_urlpattern_events(tree: ast.Module) -> list[tuple[ast.stmt, ast.expr]]:
    urlpatterns_events: list[tuple[ast.stmt, ast.expr]] = []
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "urlpatterns"
            for target in statement.targets
        ):
            urlpatterns_events = [(statement, statement.value)]
        elif (
            isinstance(statement, ast.AnnAssign)
            and isinstance(statement.target, ast.Name)
            and statement.target.id == "urlpatterns"
        ):
            urlpatterns_events = (
                [(statement, statement.value)] if statement.value is not None else []
            )
        elif (
            isinstance(statement, ast.AugAssign)
            and isinstance(statement.target, ast.Name)
            and statement.target.id == "urlpatterns"
        ):
            if isinstance(statement.op, ast.Add):
                urlpatterns_events.append((statement, statement.value))
            else:
                urlpatterns_events = []
    return urlpatterns_events


def _python_function_lines(
    sources: list[_DjangoURLSource],
) -> dict[tuple[str, str], int]:
    lines: dict[tuple[str, str], int] = {}
    for source in sources:
        for statement in source.tree.body:
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                lines[(source.source_path, statement.name)] = statement.lineno
            elif isinstance(statement, ast.ClassDef):
                for method in statement.body:
                    if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        lines[
                            (
                                source.source_path,
                                f"{statement.name}.{method.name}",
                            )
                        ] = method.lineno
    return lines


def _django_view_lookup_parameters(
    sources: list[_DjangoURLSource],
) -> dict[tuple[str, str], str | None]:
    parameters: dict[tuple[str, str], str | None] = {}
    for source in sources:
        for statement in source.tree.body:
            if not isinstance(statement, ast.ClassDef):
                continue
            lookup_field = "pk"
            lookup_url_kwarg: str | None = None
            unresolved = False
            for member in statement.body:
                value = (
                    member.value
                    if isinstance(member, (ast.Assign, ast.AnnAssign))
                    else None
                )
                targets = (
                    member.targets
                    if isinstance(member, ast.Assign)
                    else [member.target]
                    if isinstance(member, ast.AnnAssign)
                    else []
                )
                for target in targets:
                    if (
                        not isinstance(target, ast.Name)
                        or target.id not in {"lookup_field", "lookup_url_kwarg"}
                    ):
                        continue
                    parameter = _static_string(value) if value is not None else None
                    if parameter is None or not parameter.isidentifier():
                        unresolved = True
                        continue
                    if target.id == "lookup_field":
                        lookup_field = parameter
                    else:
                        lookup_url_kwarg = parameter
            parameters[(source.source_path, statement.name)] = (
                None if unresolved else lookup_url_kwarg or lookup_field
            )
    return parameters


def _django_drf_action_routes(
    sources: list[_DjangoURLSource],
) -> dict[tuple[str, str], tuple[_DjangoDRFAction, ...]]:
    routes: dict[tuple[str, str], tuple[_DjangoDRFAction, ...]] = {}
    for source in sources:
        action_names: set[str] = set()
        decorator_modules: set[tuple[str, ...]] = set()
        direct_bases: dict[str, str] = {}
        module_aliases: set[tuple[str, ...]] = set()
        for statement in source.tree.body:
            if isinstance(statement, ast.ClassDef):
                kind = _django_drf_class_kind(
                    statement,
                    direct_bases=direct_bases,
                    module_aliases=module_aliases,
                    action_names=action_names,
                    decorator_modules=decorator_modules,
                )
                if kind is not None:
                    actions = _django_drf_actions_for_class(
                        statement,
                        action_names=action_names,
                        decorator_modules=decorator_modules,
                    )
                    if actions:
                        routes[(source.source_path, statement.name)] = actions
            _update_django_drf_action_aliases(
                statement,
                action_names=action_names,
                decorator_modules=decorator_modules,
            )
            _update_django_drf_viewset_aliases(
                statement,
                direct_bases=direct_bases,
                module_aliases=module_aliases,
            )
    return routes


def _django_drf_actions_for_class(
    statement: ast.ClassDef,
    *,
    action_names: set[str],
    decorator_modules: set[tuple[str, ...]],
) -> tuple[_DjangoDRFAction, ...]:
    class_action_names = set(action_names)
    class_decorator_modules = set(decorator_modules)
    actions: list[_DjangoDRFAction] = []
    for member in statement.body:
        if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)):
            action: _DjangoDRFAction | None = None
            for decorator in member.decorator_list:
                action = action or _django_drf_action_from_decorator(
                    member,
                    decorator,
                    action_names=class_action_names,
                    decorator_modules=class_decorator_modules,
                )
                _apply_django_drf_action_rebindings(
                    _django_drf_rebindings(ast.Expr(value=decorator)),
                    action_names=class_action_names,
                    decorator_modules=class_decorator_modules,
                )
            if action is not None:
                actions.append(action)
        _update_django_drf_action_aliases(
            member,
            action_names=class_action_names,
            decorator_modules=class_decorator_modules,
        )
    return tuple(actions)


def _django_drf_inherited_action_hooks(
    sources: list[_DjangoURLSource],
) -> dict[tuple[str, str], dict[str, tuple[_DjangoLifecycleHook, ...]]]:
    hooks_by_viewset: dict[
        tuple[str, str], dict[str, tuple[_DjangoLifecycleHook, ...]]
    ] = {}
    for source in sources:
        direct_bases: dict[str, str] = {}
        module_aliases: set[tuple[str, ...]] = set()
        for statement in source.tree.body:
            if isinstance(statement, ast.ClassDef):
                kind = _django_drf_class_kind(
                    statement,
                    direct_bases=direct_bases,
                    module_aliases=module_aliases,
                )
                if kind in {"model", "read_only"}:
                    methods = [
                        member
                        for member in statement.body
                        if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                    ]
                    action_hooks = _django_drf_inherited_action_hooks_for_class(
                        {member.name for member in methods},
                        action_dependent_method_names={
                            member.name
                            for member in methods
                            if _django_drf_method_depends_on_action(member)
                        },
                        kind=kind,
                    )
                    if action_hooks:
                        hooks_by_viewset[(source.source_path, statement.name)] = (
                            action_hooks
                        )
            _update_django_drf_viewset_aliases(
                statement,
                direct_bases=direct_bases,
                module_aliases=module_aliases,
            )
    return hooks_by_viewset


def _update_django_drf_viewset_aliases(
    statement: ast.stmt,
    *,
    direct_bases: dict[str, str],
    module_aliases: set[tuple[str, ...]],
) -> None:
    def clear(name: str) -> None:
        direct_bases.pop(name, None)
        module_aliases.difference_update(
            {alias for alias in module_aliases if alias[0] == name}
        )

    if isinstance(statement, ast.ImportFrom):
        if any(imported.name == "*" for imported in statement.names):
            direct_bases.clear()
            module_aliases.clear()
            return
        for imported in statement.names:
            local_name = imported.asname or imported.name
            clear(local_name)
            if statement.module == "rest_framework.viewsets":
                kind = DRF_VIEWSET_BASES.get(imported.name)
                if kind is not None:
                    direct_bases[local_name] = kind
            elif statement.module == "rest_framework" and imported.name == "viewsets":
                module_aliases.add((local_name,))
        return
    if isinstance(statement, ast.Import):
        for imported in statement.names:
            local_name = imported.asname or imported.name.split(".", 1)[0]
            if imported.asname is None and imported.name.startswith("rest_framework"):
                direct_bases.pop(local_name, None)
                if local_name == "rest_framework":
                    module_aliases.discard(("rest_framework",))
            else:
                clear(local_name)
            if imported.name == "rest_framework.viewsets":
                module_aliases.add(
                    (local_name,)
                    if imported.asname
                    else ("rest_framework", "viewsets")
                )
        return
    _apply_django_drf_viewset_rebindings(
        _django_drf_rebindings(statement),
        direct_bases=direct_bases,
        module_aliases=module_aliases,
    )


def _apply_django_drf_viewset_rebindings(
    rebindings: _DjangoDRFRebindings | None,
    *,
    direct_bases: dict[str, str],
    module_aliases: set[tuple[str, ...]],
) -> None:
    if rebindings is None:
        direct_bases.clear()
        module_aliases.clear()
        return
    for name in rebindings.names:
        direct_bases.pop(name, None)
        module_aliases.difference_update(
            {alias for alias in module_aliases if alias[0] == name}
        )
    for path in rebindings.attribute_paths:
        module_aliases.difference_update(
            {
                alias
                for alias in module_aliases
                if _django_drf_viewset_attribute_overwrites_module_alias(path, alias)
            }
        )


def _django_drf_viewset_attribute_overwrites_module_alias(
    path: tuple[str, ...],
    module_alias: tuple[str, ...],
) -> bool:
    return path == module_alias or (
        len(path) == len(module_alias) + 1
        and path[:-1] == module_alias
        and path[-1] in DRF_VIEWSET_BASES
    )


def _django_drf_rebindings(
    statement: ast.AST,
) -> _DjangoDRFRebindings | None:
    rebindings = _django_drf_nested_rebindings(statement)
    if not isinstance(statement, ast.ClassDef) or rebindings is None:
        return rebindings
    class_body_rebindings = _django_drf_class_body_outer_rebindings(statement)
    if class_body_rebindings is None:
        return None
    rebindings.names.update(class_body_rebindings.names)
    rebindings.attribute_paths.update(class_body_rebindings.attribute_paths)
    return rebindings


def _django_drf_class_body_outer_rebindings(
    statement: ast.ClassDef,
) -> _DjangoDRFRebindings | None:
    class _GlobalNameCollector(ast.NodeVisitor):
        def __init__(self) -> None:
            self.names: set[str] = set()

        def visit_Global(self, node: ast.Global) -> None:
            self.names.update(node.names)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            return

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

    class _ClassBodyBindingCollector(ast.NodeVisitor):
        def __init__(self, global_names: set[str]) -> None:
            self.global_names = global_names
            self.local_names: set[str] = set()
            self.local_module_paths: dict[str, set[tuple[str, ...]]] = {}
            self.loop_break_states: list[
                list[tuple[set[str], dict[str, set[tuple[str, ...]]]]]
            ] = []
            self.rebindings = _DjangoDRFRebindings(
                names=set(),
                attribute_paths=set(),
            )
            self.has_wildcard_import = False

        @staticmethod
        def copy_module_paths(
            module_paths: dict[str, set[tuple[str, ...]]],
        ) -> dict[str, set[tuple[str, ...]]]:
            return {
                name: set(paths)
                for name, paths in module_paths.items()
            }

        @staticmethod
        def merge_module_paths(
            *module_path_sets: dict[str, set[tuple[str, ...]]],
        ) -> dict[str, set[tuple[str, ...]]]:
            merged: dict[str, set[tuple[str, ...]]] = {}
            for module_paths in module_path_sets:
                for name, paths in module_paths.items():
                    merged.setdefault(name, set()).update(paths)
            return merged

        def record_name(self, name: str) -> None:
            self.local_module_paths.pop(name, None)
            if name in self.global_names:
                self.rebindings.names.add(name)
            else:
                self.local_names.add(name)

        def clear_name(self, name: str) -> None:
            self.local_module_paths.pop(name, None)
            if name in self.global_names:
                self.rebindings.names.add(name)
            else:
                self.local_names.discard(name)

        def record_module_import(
            self,
            name: str,
            module_path: tuple[str, ...] | None,
        ) -> None:
            self.record_name(name)
            if module_path is not None:
                self.local_module_paths[name] = {module_path}

        def record_attribute_path(self, path: tuple[str, ...]) -> None:
            module_paths = self.local_module_paths.get(path[0])
            if module_paths is not None:
                self.rebindings.attribute_paths.add(path)
                for module_path in module_paths:
                    self.rebindings.attribute_paths.add(
                        (*module_path, *path[1:])
                    )
            elif path[0] not in self.local_names:
                self.rebindings.attribute_paths.add(path)

        def record_target(self, target: ast.expr) -> None:
            if isinstance(target, ast.Name):
                self.record_name(target.id)
                return
            if isinstance(target, ast.Attribute):
                if path := _django_attribute_parts(target):
                    self.record_attribute_path(path)
                return
            if isinstance(target, (ast.Tuple, ast.List)):
                for item in target.elts:
                    self.record_target(item)
                return
            if isinstance(target, ast.Starred):
                self.record_target(target.value)

        def clear_target(self, target: ast.expr) -> None:
            if isinstance(target, ast.Name):
                self.clear_name(target.id)
                return
            if isinstance(target, ast.Attribute):
                if path := _django_attribute_parts(target):
                    self.record_attribute_path(path)
                return
            if isinstance(target, (ast.Tuple, ast.List)):
                for item in target.elts:
                    self.clear_target(item)
                return
            if isinstance(target, ast.Starred):
                self.clear_target(target.value)

        def visit_branch(
            self,
            statements: list[ast.stmt],
            local_names: set[str],
            local_module_paths: dict[str, set[tuple[str, ...]]],
        ) -> tuple[set[str], dict[str, set[tuple[str, ...]]]]:
            previous_names = self.local_names
            previous_module_paths = self.local_module_paths
            self.local_names = set(local_names)
            self.local_module_paths = self.copy_module_paths(local_module_paths)
            for member in statements:
                self.visit(member)
            result = self.local_names
            result_module_paths = self.local_module_paths
            self.local_names = previous_names
            self.local_module_paths = previous_module_paths
            return result, result_module_paths

        def visit_loop_body(
            self,
            statements: list[ast.stmt],
            local_names: set[str],
            local_module_paths: dict[str, set[tuple[str, ...]]],
            target: ast.expr | None = None,
        ) -> tuple[
            tuple[set[str], dict[str, set[tuple[str, ...]]]],
            list[tuple[set[str], dict[str, set[tuple[str, ...]]]]],
        ]:
            previous_names = self.local_names
            previous_module_paths = self.local_module_paths
            self.local_names = set(local_names)
            self.local_module_paths = self.copy_module_paths(local_module_paths)
            break_states: list[
                tuple[set[str], dict[str, set[tuple[str, ...]]]]
            ] = []
            self.loop_break_states.append(break_states)
            if target is not None:
                self.record_target(target)
            for member in statements:
                self.visit(member)
                if isinstance(member, (ast.Break, ast.Continue)):
                    break
            result = self.local_names, self.local_module_paths
            self.loop_break_states.pop()
            self.local_names = previous_names
            self.local_module_paths = previous_module_paths
            return result, break_states

        def visit_except_handler(
            self,
            handler: ast.ExceptHandler,
            local_names: set[str],
            local_module_paths: dict[str, set[tuple[str, ...]]],
        ) -> tuple[set[str], dict[str, set[tuple[str, ...]]]]:
            previous_names = self.local_names
            previous_module_paths = self.local_module_paths
            self.local_names = set(local_names)
            self.local_module_paths = self.copy_module_paths(local_module_paths)
            if handler.name is not None:
                self.record_name(handler.name)
            for member in handler.body:
                self.visit(member)
            if handler.name is not None:
                self.clear_name(handler.name)
            result = self.local_names, self.local_module_paths
            self.local_names = previous_names
            self.local_module_paths = previous_module_paths
            return result

        @staticmethod
        def statement_may_raise(statement: ast.stmt) -> bool:
            if isinstance(statement, (ast.Import, ast.ImportFrom)):
                return True

            class _RaiseableExpressionVisitor(ast.NodeVisitor):
                def __init__(self) -> None:
                    self.found = False

                def visit_Call(self, node: ast.Call) -> None:
                    self.found = True

                def visit_Await(self, node: ast.Await) -> None:
                    self.found = True

                def visit_Yield(self, node: ast.Yield) -> None:
                    self.found = True

                def visit_YieldFrom(self, node: ast.YieldFrom) -> None:
                    self.found = True

                def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                    return

                def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                    return

                def visit_ClassDef(self, node: ast.ClassDef) -> None:
                    return

                def visit_Lambda(self, node: ast.Lambda) -> None:
                    return

            visitor = _RaiseableExpressionVisitor()
            visitor.visit(statement)
            return visitor.found

        def visit_try_body(
            self,
            statements: list[ast.stmt],
            local_names: set[str],
            local_module_paths: dict[str, set[tuple[str, ...]]],
        ) -> tuple[
            tuple[set[str], dict[str, set[tuple[str, ...]]]] | None,
            list[tuple[set[str], dict[str, set[tuple[str, ...]]]]],
        ]:
            previous_names = self.local_names
            previous_module_paths = self.local_module_paths
            self.local_names = set(local_names)
            self.local_module_paths = self.copy_module_paths(local_module_paths)
            exception_states: list[
                tuple[set[str], dict[str, set[tuple[str, ...]]]]
            ] = []
            normal_state: tuple[
                set[str], dict[str, set[tuple[str, ...]]]
            ] | None = None
            for member in statements:
                if isinstance(member, ast.Raise):
                    if member.exc is not None:
                        self.visit(member.exc)
                    if member.cause is not None:
                        self.visit(member.cause)
                    exception_states.append(
                        (
                            set(self.local_names),
                            self.copy_module_paths(self.local_module_paths),
                        )
                    )
                    break
                if self.statement_may_raise(member):
                    exception_states.append(
                        (
                            set(self.local_names),
                            self.copy_module_paths(self.local_module_paths),
                        )
                    )
                self.visit(member)
            else:
                normal_state = self.local_names, self.local_module_paths
            self.local_names = previous_names
            self.local_module_paths = previous_module_paths
            return normal_state, exception_states

        def visit_Assign(self, node: ast.Assign) -> None:
            self.visit(node.value)
            for target in node.targets:
                self.record_target(target)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            if node.value is None:
                return
            self.visit(node.value)
            self.record_target(node.target)

        def visit_AugAssign(self, node: ast.AugAssign) -> None:
            self.visit(node.value)
            self.record_target(node.target)

        def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
            self.visit(node.value)
            self.record_target(node.target)

        def visit_Delete(self, node: ast.Delete) -> None:
            for target in node.targets:
                self.clear_target(target)

        def visit_Break(self, node: ast.Break) -> None:
            if self.loop_break_states:
                self.loop_break_states[-1].append(
                    (
                        set(self.local_names),
                        self.copy_module_paths(self.local_module_paths),
                    )
                )

        def visit_If(self, node: ast.If) -> None:
            self.visit(node.test)
            initial_names = set(self.local_names)
            initial_module_paths = self.copy_module_paths(self.local_module_paths)
            body_names, body_module_paths = self.visit_branch(
                node.body,
                initial_names,
                initial_module_paths,
            )
            else_names, else_module_paths = self.visit_branch(
                node.orelse,
                initial_names,
                initial_module_paths,
            )
            self.local_names = body_names & else_names
            self.local_module_paths = self.merge_module_paths(
                body_module_paths,
                else_module_paths,
            )

        def visit_While(self, node: ast.While) -> None:
            self.visit(node.test)
            initial_names = set(self.local_names)
            initial_module_paths = self.copy_module_paths(self.local_module_paths)
            (body_names, body_module_paths), break_states = self.visit_loop_body(
                node.body,
                initial_names,
                initial_module_paths,
            )
            zero_names, zero_module_paths = self.visit_branch(
                node.orelse,
                initial_names,
                initial_module_paths,
            )
            normal_names, normal_module_paths = self.visit_branch(
                node.orelse,
                body_names,
                body_module_paths,
            )
            names_by_path = [zero_names, normal_names]
            module_paths_by_path = [zero_module_paths, normal_module_paths]
            names_by_path.extend(names for names, _ in break_states)
            module_paths_by_path.extend(
                module_paths for _, module_paths in break_states
            )
            self.local_names = set.intersection(*names_by_path)
            self.local_module_paths = self.merge_module_paths(*module_paths_by_path)

        def visit_For(self, node: ast.For) -> None:
            self.visit(node.iter)
            initial_names = set(self.local_names)
            initial_module_paths = self.copy_module_paths(self.local_module_paths)
            (body_names, body_module_paths), break_states = self.visit_loop_body(
                node.body,
                initial_names,
                initial_module_paths,
                node.target,
            )
            zero_names, zero_module_paths = self.visit_branch(
                node.orelse,
                initial_names,
                initial_module_paths,
            )
            normal_names, normal_module_paths = self.visit_branch(
                node.orelse,
                body_names,
                body_module_paths,
            )
            names_by_path = [zero_names, normal_names]
            module_paths_by_path = [zero_module_paths, normal_module_paths]
            names_by_path.extend(names for names, _ in break_states)
            module_paths_by_path.extend(
                module_paths for _, module_paths in break_states
            )
            self.local_names = set.intersection(*names_by_path)
            self.local_module_paths = self.merge_module_paths(*module_paths_by_path)

        def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
            self.visit_For(node)

        def visit_With(self, node: ast.With) -> None:
            for item in node.items:
                self.visit(item.context_expr)
                if item.optional_vars is not None:
                    self.record_target(item.optional_vars)
            for member in node.body:
                self.visit(member)

        def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
            self.visit_With(node)

        def visit_Try(self, node: ast.Try) -> None:
            initial_names = set(self.local_names)
            initial_module_paths = self.copy_module_paths(self.local_module_paths)
            body_state, exception_states = self.visit_try_body(
                node.body,
                initial_names,
                initial_module_paths,
            )
            normal_state = (
                self.visit_branch(node.orelse, *body_state)
                if body_state is not None
                else None
            )
            if not exception_states and body_state is not None:
                exception_states = [body_state]
            handler_states = [
                self.visit_except_handler(
                    handler,
                    names,
                    module_paths,
                )
                for handler in node.handlers
                for names, module_paths in exception_states
            ]
            states = [
                state
                for state in (normal_state, *handler_states)
                if state is not None
            ]
            names_by_path = [names for names, _ in states]
            merged_names = set.intersection(*names_by_path) if names_by_path else initial_names
            merged_module_paths = self.merge_module_paths(
                *(module_paths for _, module_paths in states),
            )
            self.local_names, self.local_module_paths = self.visit_branch(
                node.finalbody,
                merged_names,
                merged_module_paths,
            )

        def visit_Match(self, node: ast.Match) -> None:
            self.visit(node.subject)
            initial_names = set(self.local_names)
            initial_module_paths = self.copy_module_paths(self.local_module_paths)
            names_by_path = [initial_names]
            module_paths_by_path = [initial_module_paths]
            for case in node.cases:
                previous_names = self.local_names
                previous_module_paths = self.local_module_paths
                self.local_names = set(initial_names)
                self.local_module_paths = self.copy_module_paths(initial_module_paths)
                self.visit(case.pattern)
                if case.guard is not None:
                    self.visit(case.guard)
                for member in case.body:
                    self.visit(member)
                names_by_path.append(self.local_names)
                module_paths_by_path.append(self.local_module_paths)
                self.local_names = previous_names
                self.local_module_paths = previous_module_paths
            self.local_names = set.intersection(*names_by_path)
            self.local_module_paths = self.merge_module_paths(*module_paths_by_path)

        def visit_MatchAs(self, node: ast.MatchAs) -> None:
            if node.pattern is not None:
                self.visit(node.pattern)
            if node.name is not None:
                self.record_name(node.name)

        def visit_MatchStar(self, node: ast.MatchStar) -> None:
            if node.name is not None:
                self.record_name(node.name)

        def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
            for pattern in node.patterns:
                self.visit(pattern)
            if node.rest is not None:
                self.record_name(node.rest)

        def visit_Import(self, node: ast.Import) -> None:
            for imported in node.names:
                local_name = imported.asname or imported.name.split(".", 1)[0]
                module_path: tuple[str, ...] | None = None
                if imported.name == "rest_framework" or imported.name.startswith(
                    "rest_framework."
                ):
                    module_path = (
                        tuple(imported.name.split("."))
                        if imported.asname is not None
                        else ("rest_framework",)
                    )
                self.record_module_import(local_name, module_path)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            if any(imported.name == "*" for imported in node.names):
                self.has_wildcard_import = True
                return
            for imported in node.names:
                local_name = imported.asname or imported.name
                module_path = (
                    ("rest_framework", imported.name)
                    if node.module == "rest_framework"
                    and imported.name in {"viewsets", "decorators"}
                    else None
                )
                self.record_module_import(local_name, module_path)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            for decorator in node.decorator_list:
                self.visit(decorator)
            self.visit(node.args)
            if node.returns is not None:
                self.visit(node.returns)
            self.record_name(node.name)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self.visit_FunctionDef(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            for decorator in node.decorator_list:
                self.visit(decorator)
            for base in node.bases:
                self.visit(base)
            for keyword in node.keywords:
                self.visit(keyword.value)
            nested_rebindings = _django_drf_class_body_outer_rebindings(node)
            if nested_rebindings is None:
                self.has_wildcard_import = True
            else:
                self.rebindings.names.update(nested_rebindings.names)
                self.rebindings.attribute_paths.update(
                    nested_rebindings.attribute_paths
                )
            self.record_name(node.name)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

    global_collector = _GlobalNameCollector()
    for member in statement.body:
        global_collector.visit(member)
    collector = _ClassBodyBindingCollector(global_collector.names)
    for member in statement.body:
        collector.visit(member)
    return None if collector.has_wildcard_import else collector.rebindings


def _collect_django_drf_assignment_rebindings(
    target: ast.expr,
    *,
    rebindings: _DjangoDRFRebindings,
) -> None:
    if isinstance(target, ast.Name):
        rebindings.names.add(target.id)
        return
    if isinstance(target, ast.Attribute):
        if path := _django_attribute_parts(target):
            rebindings.attribute_paths.add(path)
        return
    if isinstance(target, (ast.Tuple, ast.List)):
        for item in target.elts:
            _collect_django_drf_assignment_rebindings(
                item,
                rebindings=rebindings,
            )
        return
    if isinstance(target, ast.Starred):
        _collect_django_drf_assignment_rebindings(
            target.value,
            rebindings=rebindings,
        )


def _django_drf_nested_rebindings(
    statement: ast.AST,
) -> _DjangoDRFRebindings | None:
    class _BindingCollector(ast.NodeVisitor):
        def __init__(self) -> None:
            self.rebindings = _DjangoDRFRebindings(
                names=set(),
                attribute_paths=set(),
            )
            self.has_wildcard_import = False

        def visit_Assign(self, node: ast.Assign) -> None:
            for target in node.targets:
                _collect_django_drf_assignment_rebindings(
                    target,
                    rebindings=self.rebindings,
                )
            self.visit(node.value)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            if node.value is not None:
                _collect_django_drf_assignment_rebindings(
                    node.target,
                    rebindings=self.rebindings,
                )
                self.visit(node.value)

        def visit_AugAssign(self, node: ast.AugAssign) -> None:
            _collect_django_drf_assignment_rebindings(
                node.target,
                rebindings=self.rebindings,
            )
            self.visit(node.value)

        def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
            _collect_django_drf_assignment_rebindings(
                node.target,
                rebindings=self.rebindings,
            )
            self.visit(node.value)

        def visit_Delete(self, node: ast.Delete) -> None:
            for target in node.targets:
                _collect_django_drf_assignment_rebindings(
                    target,
                    rebindings=self.rebindings,
                )

        def visit_For(self, node: ast.For) -> None:
            _collect_django_drf_assignment_rebindings(
                node.target,
                rebindings=self.rebindings,
            )
            self.generic_visit(node)

        def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
            _collect_django_drf_assignment_rebindings(
                node.target,
                rebindings=self.rebindings,
            )
            self.generic_visit(node)

        def visit_With(self, node: ast.With) -> None:
            for item in node.items:
                if item.optional_vars is not None:
                    _collect_django_drf_assignment_rebindings(
                        item.optional_vars,
                        rebindings=self.rebindings,
                    )
            self.generic_visit(node)

        def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
            for item in node.items:
                if item.optional_vars is not None:
                    _collect_django_drf_assignment_rebindings(
                        item.optional_vars,
                        rebindings=self.rebindings,
                    )
            self.generic_visit(node)

        def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
            if node.name is not None:
                self.rebindings.names.add(node.name)
            self.generic_visit(node)

        def visit_Import(self, node: ast.Import) -> None:
            self.rebindings.names.update(
                imported.asname or imported.name.split(".", 1)[0]
                for imported in node.names
            )

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            if any(imported.name == "*" for imported in node.names):
                self.has_wildcard_import = True
                return
            self.rebindings.names.update(
                imported.asname or imported.name for imported in node.names
            )

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            for decorator in node.decorator_list:
                self.visit(decorator)
            self.visit(node.args)
            if node.returns is not None:
                self.visit(node.returns)
            self.rebindings.names.add(node.name)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            for decorator in node.decorator_list:
                self.visit(decorator)
            self.visit(node.args)
            if node.returns is not None:
                self.visit(node.returns)
            self.rebindings.names.add(node.name)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            for decorator in node.decorator_list:
                self.visit(decorator)
            for base in node.bases:
                self.visit(base)
            for keyword in node.keywords:
                self.visit(keyword.value)
            self.rebindings.names.add(node.name)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

        def visit_MatchAs(self, node: ast.MatchAs) -> None:
            if node.name is not None:
                self.rebindings.names.add(node.name)
            self.generic_visit(node)

        def visit_MatchStar(self, node: ast.MatchStar) -> None:
            if node.name is not None:
                self.rebindings.names.add(node.name)

        def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
            if node.rest is not None:
                self.rebindings.names.add(node.rest)
            self.generic_visit(node)

    collector = _BindingCollector()
    collector.visit(statement)
    return None if collector.has_wildcard_import else collector.rebindings


def _django_drf_class_kind(
    statement: ast.ClassDef,
    *,
    direct_bases: dict[str, str],
    module_aliases: set[tuple[str, ...]],
    action_names: set[str] | None = None,
    decorator_modules: set[tuple[str, ...]] | None = None,
) -> str | None:
    def apply(value: ast.expr) -> None:
        rebindings = _django_drf_rebindings(ast.Expr(value=value))
        _apply_django_drf_viewset_rebindings(
            rebindings,
            direct_bases=direct_bases,
            module_aliases=module_aliases,
        )
        if action_names is not None and decorator_modules is not None:
            _apply_django_drf_action_rebindings(
                rebindings,
                action_names=action_names,
                decorator_modules=decorator_modules,
            )

    for decorator in statement.decorator_list:
        apply(decorator)

    kind: str | None = None
    for base in statement.bases:
        if kind is None:
            kind = _django_drf_viewset_base_kind(
                base,
                direct_bases=direct_bases,
                module_aliases=module_aliases,
            )
        apply(base)

    for keyword in statement.keywords:
        apply(keyword.value)
    return kind


def _django_drf_viewset_base_kind(
    base: ast.expr,
    *,
    direct_bases: dict[str, str],
    module_aliases: set[tuple[str, ...]],
) -> str | None:
    if isinstance(base, ast.Name):
        return direct_bases.get(base.id)
    parts = _django_attribute_parts(base)
    return (
        DRF_VIEWSET_BASES.get(parts[-1])
        if parts is not None and len(parts) >= 2 and parts[:-1] in module_aliases
        else None
    )


def _django_drf_inherited_action_hooks_for_class(
    method_names: set[str],
    *,
    action_dependent_method_names: set[str],
    kind: str,
) -> dict[str, tuple[_DjangoLifecycleHook, ...]]:
    def hook(name: str) -> _DjangoLifecycleHook:
        return _DjangoLifecycleHook(
            handler_name=name,
            action_dependent=name in action_dependent_method_names,
        )

    read_hooks = (
        (hook("get_object"),)
        if "get_object" in method_names
        else (hook("get_queryset"),)
        if "get_queryset" in method_names
        else ()
    )
    action_hooks: dict[str, tuple[_DjangoLifecycleHook, ...]] = {}

    def add(action: str, hooks: tuple[_DjangoLifecycleHook, ...]) -> None:
        if action not in method_names and hooks:
            action_hooks[action] = hooks

    add("list", (hook("get_queryset"),) if "get_queryset" in method_names else ())
    add("retrieve", read_hooks)
    if kind == "model":
        add("create", (hook("perform_create"),) if "perform_create" in method_names else ())
        add(
            "update",
            (
                *read_hooks,
                *((hook("perform_update"),) if "perform_update" in method_names else ()),
            ),
        )
        add(
            "partial_update",
            (
                *read_hooks,
                *((hook("perform_update"),) if "perform_update" in method_names else ()),
            ),
        )
        add(
            "destroy",
            (
                *read_hooks,
                *((hook("perform_destroy"),) if "perform_destroy" in method_names else ()),
            ),
        )
    return action_hooks


def _django_drf_method_depends_on_action(
    member: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    class _ActionReferenceVisitor(ast.NodeVisitor):
        def __init__(
            self,
            aliases: set[str],
            attribute_aliases: set[tuple[str, ...]],
        ) -> None:
            self.aliases = aliases
            self.attribute_aliases = attribute_aliases
            self.found = False

        def visit_Name(self, node: ast.Name) -> None:
            if node.id in self.aliases:
                self.found = True

        def visit_Attribute(self, node: ast.Attribute) -> None:
            if _django_attribute_parts(node) in self.attribute_aliases:
                self.found = True
            if (
                node.attr == "action"
                and isinstance(node.value, ast.Name)
                and node.value.id == "self"
            ):
                self.found = True
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
            ):
                attribute_name = node.args[1].value
                target_path = _django_attribute_parts(node.args[0])
                if (
                    isinstance(node.args[0], ast.Name)
                    and node.args[0].id == "self"
                    and attribute_name == "action"
                ):
                    self.found = True
                if (
                    isinstance(attribute_name, str)
                    and target_path is not None
                    and (*target_path, attribute_name) in self.attribute_aliases
                ):
                    self.found = True
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            return

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

    class _ActionDependencyVisitor(ast.NodeVisitor):
        def __init__(self) -> None:
            self.aliases: set[str] = set()
            self.attribute_aliases: set[tuple[str, ...]] = set()
            self.loop_break_states: list[
                list[tuple[set[str], set[tuple[str, ...]]]]
            ] = []
            self.depends_on_action = False

        def uses_action(self, value: ast.AST | None) -> bool:
            if value is None:
                return False
            visitor = _ActionReferenceVisitor(
                self.aliases,
                self.attribute_aliases,
            )
            visitor.visit(value)
            return visitor.found

        def action_state(self) -> tuple[set[str], set[tuple[str, ...]]]:
            return set(self.aliases), set(self.attribute_aliases)

        def visit_branch(
            self,
            statements: list[ast.stmt],
            state: tuple[set[str], set[tuple[str, ...]]],
        ) -> tuple[set[str], set[tuple[str, ...]]]:
            previous_aliases = self.aliases
            previous_attribute_aliases = self.attribute_aliases
            self.aliases, self.attribute_aliases = map(set, state)
            for statement in statements:
                self.visit(statement)
            result = self.action_state()
            self.aliases = previous_aliases
            self.attribute_aliases = previous_attribute_aliases
            return result

        def visit_for_branch(
            self,
            node: ast.For | ast.AsyncFor,
            state: tuple[set[str], set[tuple[str, ...]]],
        ) -> tuple[
            tuple[set[str], set[tuple[str, ...]]],
            list[tuple[set[str], set[tuple[str, ...]]]],
        ]:
            return self.visit_loop_branch(node.body, state, node.target)

        def visit_loop_branch(
            self,
            statements: list[ast.stmt],
            state: tuple[set[str], set[tuple[str, ...]]],
            target: ast.expr | None = None,
        ) -> tuple[
            tuple[set[str], set[tuple[str, ...]]],
            list[tuple[set[str], set[tuple[str, ...]]]],
        ]:
            previous_aliases = self.aliases
            previous_attribute_aliases = self.attribute_aliases
            self.aliases, self.attribute_aliases = map(set, state)
            break_states: list[tuple[set[str], set[tuple[str, ...]]]] = []
            self.loop_break_states.append(break_states)
            if target is not None:
                self.clear_target(target)
            for statement in statements:
                self.visit(statement)
                if isinstance(statement, (ast.Break, ast.Continue)):
                    break
            result = self.action_state()
            self.loop_break_states.pop()
            self.aliases = previous_aliases
            self.attribute_aliases = previous_attribute_aliases
            return result, break_states

        def merge_action_states(
            self,
            *states: tuple[set[str], set[tuple[str, ...]]],
        ) -> None:
            self.aliases = set().union(*(aliases for aliases, _ in states))
            self.attribute_aliases = set().union(
                *(attribute_aliases for _, attribute_aliases in states)
            )

        @staticmethod
        def is_irrefutable_pattern(pattern: ast.pattern) -> bool:
            return isinstance(pattern, ast.MatchAs) and pattern.pattern is None

        def branches_affect_result(self, branches: list[list[ast.stmt]]) -> bool:
            class _ResultControlVisitor(ast.NodeVisitor):
                def __init__(self) -> None:
                    self.found = False

                def visit_Return(self, node: ast.Return) -> None:
                    self.found = True

                def visit_Yield(self, node: ast.Yield) -> None:
                    self.found = True

                def visit_YieldFrom(self, node: ast.YieldFrom) -> None:
                    self.found = True

                def visit_Raise(self, node: ast.Raise) -> None:
                    self.found = True

                def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                    return

                def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                    return

                def visit_ClassDef(self, node: ast.ClassDef) -> None:
                    return

                def visit_Lambda(self, node: ast.Lambda) -> None:
                    return

            visitor = _ResultControlVisitor()
            for branch in branches:
                for statement in branch:
                    visitor.visit(statement)
            return visitor.found

        def record_action_controlled_branch_targets(
            self,
            branches: list[list[ast.stmt]],
        ) -> None:
            class _BranchTargetVisitor(ast.NodeVisitor):
                def __init__(self) -> None:
                    self.targets: dict[str, tuple[ast.expr, ast.AST | None, int]] = {}

                def record_target(
                    self,
                    target: ast.expr,
                    value: ast.AST | None,
                ) -> None:
                    if isinstance(target, (ast.Name, ast.Attribute)):
                        key = ast.dump(target, include_attributes=False)
                        previous = self.targets.get(key)
                        self.targets[key] = (
                            target,
                            value,
                            1 if previous is None else previous[2] + 1,
                        )
                        return
                    if isinstance(target, (ast.Tuple, ast.List)):
                        for item in target.elts:
                            self.record_target(item, value)
                        return
                    if isinstance(target, ast.Starred):
                        self.record_target(target.value, value)

                @staticmethod
                def is_ownership_filtered(value: ast.AST | None) -> bool:
                    if value is None:
                        return False
                    return any(
                        isinstance(call, ast.Call)
                        and isinstance(call.func, ast.Attribute)
                        and call.func.attr == "filter"
                        and any(
                            keyword.arg is not None
                            and any(
                                marker in keyword.arg.lower()
                                for marker in (
                                    "owner",
                                    "user",
                                    "tenant",
                                    "account",
                                    "org",
                                    "workspace",
                                    "team",
                                    "project",
                                    "group",
                                    "agent",
                                    "created_by",
                                )
                            )
                            for keyword in call.keywords
                        )
                        for call in ast.walk(value)
                    )

                def visit_Assign(self, node: ast.Assign) -> None:
                    for target in node.targets:
                        self.record_target(target, node.value)
                    self.visit(node.value)

                def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
                    if node.value is not None:
                        self.record_target(node.target, node.value)
                        self.visit(node.value)

                def visit_AugAssign(self, node: ast.AugAssign) -> None:
                    self.record_target(node.target, None)
                    self.visit(node.value)

                def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
                    self.record_target(node.target, node.value)
                    self.visit(node.value)

                def visit_For(self, node: ast.For) -> None:
                    self.record_target(node.target, None)
                    self.generic_visit(node)

                def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
                    self.record_target(node.target, None)
                    self.generic_visit(node)

                def visit_With(self, node: ast.With) -> None:
                    for item in node.items:
                        if item.optional_vars is not None:
                            self.record_target(item.optional_vars, None)
                    self.generic_visit(node)

                def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
                    for item in node.items:
                        if item.optional_vars is not None:
                            self.record_target(item.optional_vars, None)
                    self.generic_visit(node)

                def visit_MatchAs(self, node: ast.MatchAs) -> None:
                    if node.name is not None:
                        self.record_target(ast.Name(id=node.name), None)
                    self.generic_visit(node)

                def visit_MatchStar(self, node: ast.MatchStar) -> None:
                    if node.name is not None:
                        self.record_target(ast.Name(id=node.name), None)

                def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
                    if node.rest is not None:
                        self.record_target(ast.Name(id=node.rest), None)
                    self.generic_visit(node)

                def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                    return

                def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                    return

                def visit_ClassDef(self, node: ast.ClassDef) -> None:
                    return

                def visit_Lambda(self, node: ast.Lambda) -> None:
                    return

            targets_by_key: dict[
                str,
                list[tuple[ast.expr, ast.AST | None, int]],
            ] = {}
            for branch in branches:
                target_visitor = _BranchTargetVisitor()
                for statement in branch:
                    target_visitor.visit(statement)
                for key, target_state in target_visitor.targets.items():
                    targets_by_key.setdefault(key, []).append(target_state)
            for target_states in targets_by_key.values():
                if all(
                    _BranchTargetVisitor.is_ownership_filtered(value)
                    for _, value, _ in target_states
                ):
                    continue
                self.record_target(target_states[-1][0])

        def record_targets(self, targets: list[ast.expr], value: ast.AST) -> None:
            value_uses_action = self.uses_action(value)
            for target in targets:
                self.clear_target(target)
            if not value_uses_action:
                return
            for target in targets:
                self.record_target(target)

        def record_target(self, target: ast.expr) -> None:
            if isinstance(target, ast.Name):
                self.aliases.add(target.id)
            elif isinstance(target, ast.Attribute):
                if path := _django_attribute_parts(target):
                    self.attribute_aliases.add(path)
            elif isinstance(target, (ast.Tuple, ast.List)):
                for item in target.elts:
                    self.record_target(item)
            elif isinstance(target, ast.Starred):
                self.record_target(target.value)

        def clear_name(self, name: str) -> None:
            self.aliases.discard(name)
            self.attribute_aliases.difference_update(
                {path for path in self.attribute_aliases if path[0] == name}
            )

        def clear_target(self, target: ast.expr) -> None:
            if isinstance(target, ast.Name):
                self.clear_name(target.id)
            elif isinstance(target, ast.Attribute):
                if path := _django_attribute_parts(target):
                    self.attribute_aliases.difference_update(
                        {
                            candidate
                            for candidate in self.attribute_aliases
                            if candidate[: len(path)] == path
                        }
                    )
            elif isinstance(target, (ast.Tuple, ast.List)):
                for item in target.elts:
                    self.clear_target(item)
            elif isinstance(target, ast.Starred):
                self.clear_target(target.value)

        def target_uses_action(self, target: ast.expr) -> bool:
            if isinstance(target, ast.Name):
                return target.id in self.aliases
            if isinstance(target, ast.Attribute):
                return self.uses_action(target)
            if isinstance(target, (ast.Tuple, ast.List)):
                return any(self.target_uses_action(item) for item in target.elts)
            if isinstance(target, ast.Starred):
                return self.target_uses_action(target.value)
            return False

        def visit_Assign(self, node: ast.Assign) -> None:
            self.record_targets(node.targets, node.value)
            self.visit(node.value)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            if node.value is not None:
                self.record_targets([node.target], node.value)
                self.visit(node.value)

        def visit_AugAssign(self, node: ast.AugAssign) -> None:
            target_uses_action = self.target_uses_action(node.target)
            value_uses_action = self.uses_action(node.value)
            self.clear_target(node.target)
            if target_uses_action or value_uses_action:
                self.record_target(node.target)
            self.visit(node.value)

        def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
            self.record_targets([node.target], node.value)
            self.visit(node.value)

        def visit_Delete(self, node: ast.Delete) -> None:
            for target in node.targets:
                self.clear_target(target)

        def visit_Break(self, node: ast.Break) -> None:
            if self.loop_break_states:
                self.loop_break_states[-1].append(self.action_state())

        def visit_If(self, node: ast.If) -> None:
            condition_uses_action = self.uses_action(node.test)
            self.depends_on_action |= condition_uses_action and self.branches_affect_result(
                [node.body, node.orelse]
            )
            self.visit(node.test)
            state = self.action_state()
            body_state = self.visit_branch(node.body, state)
            else_state = self.visit_branch(node.orelse, state)
            self.merge_action_states(body_state, else_state)
            if condition_uses_action:
                self.record_action_controlled_branch_targets([node.body, node.orelse])

        def visit_While(self, node: ast.While) -> None:
            condition_uses_action = self.uses_action(node.test)
            self.depends_on_action |= condition_uses_action and self.branches_affect_result(
                [node.body, node.orelse]
            )
            self.visit(node.test)
            state = self.action_state()
            body_state, break_states = self.visit_loop_branch(node.body, state)
            if node.orelse:
                zero_state = self.visit_branch(node.orelse, state)
                normal_state = self.visit_branch(node.orelse, body_state)
                states = [zero_state, normal_state]
                states.extend(break_states)
                self.merge_action_states(*states)
            else:
                self.merge_action_states(state, body_state, *break_states)
            if condition_uses_action and (
                not node.orelse or break_states
            ):
                self.record_action_controlled_branch_targets([node.body, node.orelse])

        def visit_For(self, node: ast.For) -> None:
            iterator_uses_action = self.uses_action(node.iter)
            self.depends_on_action |= iterator_uses_action and self.branches_affect_result(
                [node.body, node.orelse]
            )
            self.visit(node.iter)
            state = self.action_state()
            body_state, break_states = self.visit_for_branch(node, state)
            if node.orelse:
                zero_state = self.visit_branch(node.orelse, state)
                normal_state = self.visit_branch(node.orelse, body_state)
                states = [zero_state, normal_state]
                states.extend(break_states)
                self.merge_action_states(*states)
            else:
                self.merge_action_states(state, body_state, *break_states)
            if iterator_uses_action and (
                not node.orelse or break_states
            ):
                self.record_action_controlled_branch_targets([node.body, node.orelse])
                self.record_target(node.target)

        def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
            iterator_uses_action = self.uses_action(node.iter)
            self.depends_on_action |= iterator_uses_action and self.branches_affect_result(
                [node.body, node.orelse]
            )
            self.visit(node.iter)
            state = self.action_state()
            body_state, break_states = self.visit_for_branch(node, state)
            if node.orelse:
                zero_state = self.visit_branch(node.orelse, state)
                normal_state = self.visit_branch(node.orelse, body_state)
                states = [zero_state, normal_state]
                states.extend(break_states)
                self.merge_action_states(*states)
            else:
                self.merge_action_states(state, body_state, *break_states)
            if iterator_uses_action and (
                not node.orelse or break_states
            ):
                self.record_action_controlled_branch_targets([node.body, node.orelse])
                self.record_target(node.target)

        def visit_With(self, node: ast.With) -> None:
            for item in node.items:
                if item.optional_vars is not None:
                    self.clear_target(item.optional_vars)
            self.generic_visit(node)

        def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
            for item in node.items:
                if item.optional_vars is not None:
                    self.clear_target(item.optional_vars)
            self.generic_visit(node)

        def visit_Try(self, node: ast.Try) -> None:
            state = self.action_state()
            body_state = self.visit_branch(node.body, state)
            normal_state = body_state
            normal_state = self.visit_branch(node.orelse, normal_state)
            handler_state = (
                state[0] | body_state[0],
                state[1] | body_state[1],
            )
            handler_states = [
                self.visit_branch(handler.body, handler_state)
                for handler in node.handlers
            ]
            self.merge_action_states(normal_state, *handler_states)
            for statement in node.finalbody:
                self.visit(statement)

        def visit_TryStar(self, node: ast.TryStar) -> None:
            self.visit_Try(node)

        def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
            if node.name is not None:
                self.clear_name(node.name)
            self.generic_visit(node)

        def visit_Match(self, node: ast.Match) -> None:
            subject_uses_action = self.uses_action(node.subject)
            branches = [case.body for case in node.cases]
            self.depends_on_action |= subject_uses_action and self.branches_affect_result(
                branches
            )
            self.visit(node.subject)
            state = self.action_state()
            case_states = []
            can_be_unmatched = True
            for case in node.cases:
                previous_aliases = self.aliases
                previous_attribute_aliases = self.attribute_aliases
                self.aliases, self.attribute_aliases = map(set, state)
                self.visit(case.pattern)
                if case.guard is not None:
                    self.visit(case.guard)
                for statement in case.body:
                    self.visit(statement)
                case_states.append(self.action_state())
                self.aliases = previous_aliases
                self.attribute_aliases = previous_attribute_aliases
                if case.guard is None and self.is_irrefutable_pattern(case.pattern):
                    can_be_unmatched = False
                    break
            self.merge_action_states(
                *([state] if can_be_unmatched else []),
                *case_states,
            )
            if subject_uses_action and not (
                len(node.cases) == 1
                and node.cases[0].guard is None
                and self.is_irrefutable_pattern(node.cases[0].pattern)
            ):
                self.record_action_controlled_branch_targets(branches)

        def visit_MatchAs(self, node: ast.MatchAs) -> None:
            if node.name is not None:
                self.clear_name(node.name)
            self.generic_visit(node)

        def visit_MatchStar(self, node: ast.MatchStar) -> None:
            if node.name is not None:
                self.clear_name(node.name)

        def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
            if node.rest is not None:
                self.clear_name(node.rest)
            self.generic_visit(node)

        def visit_Assert(self, node: ast.Assert) -> None:
            self.depends_on_action |= self.uses_action(node.test)
            self.generic_visit(node)

        def visit_Return(self, node: ast.Return) -> None:
            self.depends_on_action |= self.uses_action(node.value)

        def visit_Yield(self, node: ast.Yield) -> None:
            self.depends_on_action |= self.uses_action(node.value)

        def visit_YieldFrom(self, node: ast.YieldFrom) -> None:
            self.depends_on_action |= self.uses_action(node.value)

        def visit_Import(self, node: ast.Import) -> None:
            for imported in node.names:
                self.clear_name(imported.asname or imported.name.split(".", 1)[0])

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            if any(imported.name == "*" for imported in node.names):
                self.aliases.clear()
                self.attribute_aliases.clear()
                return
            for imported in node.names:
                self.clear_name(imported.asname or imported.name)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self.clear_name(node.name)
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self.clear_name(node.name)
            return

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self.clear_name(node.name)
            return

        def visit_Lambda(self, node: ast.Lambda) -> None:
            return

    visitor = _ActionDependencyVisitor()
    for statement in member.body:
        visitor.visit(statement)
    return visitor.depends_on_action


def _update_django_drf_action_aliases(
    statement: ast.stmt,
    *,
    action_names: set[str],
    decorator_modules: set[tuple[str, ...]],
) -> None:
    def clear(name: str) -> None:
        action_names.discard(name)
        decorator_modules.difference_update(
            {module for module in decorator_modules if module[0] == name}
        )

    if isinstance(statement, ast.ImportFrom):
        if any(imported.name == "*" for imported in statement.names):
            action_names.clear()
            decorator_modules.clear()
            return
        for imported in statement.names:
            local_name = imported.asname or imported.name
            clear(local_name)
            if (
                statement.module == "rest_framework.decorators"
                and imported.name == "action"
            ):
                action_names.add(local_name)
            elif statement.module == "rest_framework" and imported.name == "decorators":
                decorator_modules.add((local_name,))
        return
    if isinstance(statement, ast.Import):
        for imported in statement.names:
            local_name = imported.asname or imported.name.split(".", 1)[0]
            if imported.asname is None and imported.name.startswith("rest_framework"):
                action_names.discard(local_name)
                if local_name == "rest_framework":
                    decorator_modules.discard(("rest_framework",))
            else:
                clear(local_name)
            if imported.name == "rest_framework.decorators":
                decorator_modules.add(
                    (local_name,)
                    if imported.asname
                    else ("rest_framework", "decorators")
                )
            elif imported.name == "rest_framework":
                decorator_modules.add((local_name, "decorators"))
        return
    _apply_django_drf_action_rebindings(
        _django_drf_rebindings(statement),
        action_names=action_names,
        decorator_modules=decorator_modules,
    )


def _apply_django_drf_action_rebindings(
    rebindings: _DjangoDRFRebindings | None,
    *,
    action_names: set[str],
    decorator_modules: set[tuple[str, ...]],
) -> None:
    if rebindings is None:
        action_names.clear()
        decorator_modules.clear()
        return
    for name in rebindings.names:
        action_names.discard(name)
        decorator_modules.difference_update(
            {module for module in decorator_modules if module[0] == name}
        )
    for path in rebindings.attribute_paths:
        decorator_modules.difference_update(
            {
                module
                for module in decorator_modules
                if path == module
                or (
                    len(path) == len(module) + 1
                    and path[:-1] == module
                    and path[-1] == "action"
                )
            }
        )


def _django_drf_action_from_decorator(
    member: ast.FunctionDef | ast.AsyncFunctionDef,
    decorator: ast.expr,
    *,
    action_names: set[str],
    decorator_modules: set[tuple[str, ...]],
) -> _DjangoDRFAction | None:
    if not isinstance(decorator, ast.Call) or not _is_django_drf_action_call(
        decorator,
        action_names=action_names,
        decorator_modules=decorator_modules,
    ):
        return None
    methods = _django_drf_action_methods(decorator)
    detail = _django_drf_action_detail(decorator)
    url_path = _django_drf_action_url_path(decorator, default=member.name)
    if methods is None or detail is None or url_path is None:
        return None
    return _DjangoDRFAction(
        method_name=member.name,
        route_methods=methods,
        detail=detail,
        url_path=url_path,
    )


def _is_django_drf_action_call(
    call: ast.Call,
    *,
    action_names: set[str],
    decorator_modules: set[tuple[str, ...]],
) -> bool:
    if isinstance(call.func, ast.Name):
        return call.func.id in action_names
    return (
        isinstance(call.func, ast.Attribute)
        and call.func.attr == "action"
        and _django_attribute_parts(call.func.value) in decorator_modules
    )


def _django_attribute_parts(value: ast.expr) -> tuple[str, ...] | None:
    if isinstance(value, ast.Name):
        return (value.id,)
    if not isinstance(value, ast.Attribute):
        return None
    prefix = _django_attribute_parts(value.value)
    return (*prefix, value.attr) if prefix is not None else None


def _django_dotted_name(value: ast.expr) -> str | None:
    parts = _django_attribute_parts(value)
    return ".".join(parts) if parts is not None else None


def _django_drf_action_argument(
    call: ast.Call,
    *,
    name: str,
    position: int,
) -> ast.expr | None:
    positional = call.args[position] if len(call.args) > position else None
    keyword_values = [keyword.value for keyword in call.keywords if keyword.arg == name]
    if positional is not None and keyword_values:
        return None
    if positional is not None:
        return positional
    return keyword_values[0] if len(keyword_values) == 1 else None


def _django_drf_action_methods(call: ast.Call) -> tuple[str, ...] | None:
    value = _django_drf_action_argument(call, name="methods", position=0)
    if value is None or (isinstance(value, ast.Constant) and value.value is None):
        return ("GET",)
    if not isinstance(value, (ast.List, ast.Tuple)):
        return None
    methods = tuple(
        item.value.upper()
        for item in value.elts
        if isinstance(item, ast.Constant)
        and isinstance(item.value, str)
        and item.value.lower() in DRF_ACTION_HTTP_METHOD_NAMES
    )
    return methods if len(methods) == len(value.elts) and methods else None


def _django_drf_action_detail(call: ast.Call) -> bool | None:
    value = _django_drf_action_argument(call, name="detail", position=1)
    return value.value if isinstance(value, ast.Constant) and isinstance(value.value, bool) else None


def _django_drf_action_url_path(call: ast.Call, *, default: str) -> str | None:
    value = _django_drf_action_argument(call, name="url_path", position=2)
    if value is None or (isinstance(value, ast.Constant) and value.value is None):
        return default.replace("_", "-")
    path = _static_string(value)
    if path is None or re.fullmatch(r"[A-Za-z0-9_-]+", path) is None:
        return None
    return path


def _django_runtime_url_patterns(
    sources: list[_DjangoURLSource],
    *,
    source_by_module: dict[str, str],
    function_lines: dict[tuple[str, str], int],
    view_lookup_parameters: dict[tuple[str, str], str | None],
    drf_action_routes: dict[tuple[str, str], tuple[_DjangoDRFAction, ...]],
    drf_inherited_action_hooks: dict[
        tuple[str, str], dict[str, tuple[_DjangoLifecycleHook, ...]]
    ],
    roots: list[str],
) -> dict[str, list[_DjangoURLPattern]]:
    source_by_path = {source.source_path: source for source in sources}
    router_states_by_source: dict[str, dict[str, _DjangoRouterState]] = {}
    bound_names_by_source: dict[str, set[str]] = {}
    patterns_by_source: dict[str, list[_DjangoURLPattern]] = {}
    loading_source_paths: set[str] = set()
    loaded_source_paths: set[str] = set()

    def load(source_path: str) -> dict[str, _DjangoRouterState]:
        if source_path in loaded_source_paths:
            return router_states_by_source.get(source_path, {})
        if source_path in loading_source_paths:
            return router_states_by_source.get(source_path, {})
        source = source_by_path.get(source_path)
        if source is None:
            return {}

        router_states: dict[str, _DjangoRouterState] = {}
        bound_names: set[str] = set()
        router_states_by_source[source_path] = router_states
        bound_names_by_source[source_path] = bound_names
        patterns = patterns_by_source.setdefault(source_path, [])
        loading_source_paths.add(source_path)
        try:
            view_aliases, module_aliases = _django_view_import_aliases(
                source,
                source_by_module=source_by_module,
                function_lines=function_lines,
            )
            constructor_names, router_module_names = _django_router_import_names(
                source.tree
            )
            active_urlpattern_events = {
                id(statement): value
                for statement, value in _django_urlpattern_events(source.tree)
            }
            for statement in source.tree.body:
                if isinstance(statement, ast.Import):
                    for imported in statement.names:
                        local_name = imported.asname or imported.name.split(".", 1)[0]
                        _discard_django_router_binding(router_states, local_name)
                        bound_names.add(local_name)
                        imported_source_path = source_by_module.get(imported.name)
                        if imported_source_path is not None:
                            imported_router_states = load(imported_source_path)
                            if imported.asname:
                                for nested_name, nested_router_state in (
                                    imported_router_states.items()
                                ):
                                    router_states[
                                        f"{local_name}.{nested_name}"
                                    ] = nested_router_state
                elif isinstance(statement, ast.ImportFrom):
                    module_name = _django_import_module_name(
                        source.module_name,
                        statement,
                    )
                    imported_states: dict[str, _DjangoRouterState] = {}
                    imported_bound_names: set[str] = set()
                    if module_name is not None:
                        imported_source_path = source_by_module.get(module_name)
                        if imported_source_path is not None:
                            imported_states = load(imported_source_path)
                            imported_bound_names = bound_names_by_source.get(
                                imported_source_path,
                                set(),
                            )
                    for imported in statement.names:
                        local_name = imported.asname or imported.name
                        _discard_django_router_binding(router_states, local_name)
                        bound_names.add(local_name)
                        router_state = imported_states.get(imported.name)
                        if router_state is not None:
                            router_states[local_name] = router_state
                        if (
                            module_name is None
                            or imported.name in imported_bound_names
                        ):
                            continue
                        nested_source_path = source_by_module.get(
                            f"{module_name}.{imported.name}"
                        )
                        if nested_source_path is not None:
                            nested_router_states = load(nested_source_path)
                            for nested_name, nested_router_state in (
                                nested_router_states.items()
                            ):
                                router_states[
                                    f"{local_name}.{nested_name}"
                                ] = nested_router_state

                _apply_django_router_statement(
                    statement,
                    router_states=router_states,
                    router_states_by_source=router_states_by_source,
                    constructor_names=constructor_names,
                    router_module_names=router_module_names,
                    function_lines=function_lines,
                    view_aliases=view_aliases,
                    module_aliases=module_aliases,
                    view_lookup_parameters=view_lookup_parameters,
                )
                _update_django_module_bound_names(statement, bound_names)
                urlpattern_value = active_urlpattern_events.get(id(statement))
                if urlpattern_value is not None:
                    patterns.extend(
                        _django_url_patterns_for_values(
                            source,
                            values=[urlpattern_value],
                            source_by_module=source_by_module,
                            function_lines=function_lines,
                            view_aliases=view_aliases,
                            module_aliases=module_aliases,
                            router_states=router_states,
                            drf_action_routes=drf_action_routes,
                            drf_inherited_action_hooks=drf_inherited_action_hooks,
                            include_callback=load,
                        )
                    )
        finally:
            loading_source_paths.remove(source_path)
        loaded_source_paths.add(source_path)
        return router_states

    for root in roots:
        load(root)
    return patterns_by_source


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
    view_aliases: dict[str, tuple[str, str]] = {}
    for source_path, name in function_lines:
        if source_path != source.source_path:
            continue
        if "." in name:
            class_name = name.rsplit(".", 1)[0]
            view_aliases.setdefault(class_name, (source.source_path, class_name))
            continue
        view_aliases[name] = (source.source_path, name)
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
            if imported_source_path is None:
                continue
            identity = (imported_source_path, imported.name)
            if (
                identity in function_lines
                or _django_class_has_methods(identity, function_lines)
            ):
                view_aliases[local_name] = identity
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
    router_states: dict[str, _DjangoRouterState],
    drf_action_routes: dict[tuple[str, str], tuple[_DjangoDRFAction, ...]],
    drf_inherited_action_hooks: dict[
        tuple[str, str], dict[str, tuple[_DjangoLifecycleHook, ...]]
    ],
) -> list[_DjangoURLPattern]:
    if not isinstance(value, ast.Call) or not _is_django_url_call(
        value,
        "path",
        path_names,
        django_module_names,
    ):
        return []
    if len(value.args) < 2:
        return []
    route_path = _static_string(value.args[0])
    target = value.args[1]
    if isinstance(target, ast.Call) and _is_django_url_call(
        target,
        "include",
        include_names,
        django_module_names,
    ):
        router_name = _django_router_urls_name(target.args[0]) if target.args else None
        if router_name is not None:
            return _django_router_url_patterns(
                router_name,
                mount_path=route_path,
                line=value.lineno,
                router_states=router_states,
                function_lines=function_lines,
                drf_action_routes=drf_action_routes,
                drf_inherited_action_hooks=drf_inherited_action_hooks,
            )
        include_module_name = _django_include_module_name(target)
        return [
            _DjangoURLPattern(
                route_path=route_path,
                line=value.lineno,
                view_handlers=(),
                include_source_path=(
                    source_by_module.get(include_module_name)
                    if include_module_name is not None
                    else None
                ),
            )
        ]
    return [
        _DjangoURLPattern(
            route_path=route_path,
            line=value.lineno,
            view_handlers=_django_view_handlers(
                target,
                function_lines=function_lines,
                view_aliases=view_aliases,
                module_aliases=module_aliases,
            ),
            include_source_path=None,
        )
    ]


def _django_url_patterns_for_values(
    source: _DjangoURLSource,
    *,
    values: list[ast.expr],
    source_by_module: dict[str, str],
    function_lines: dict[tuple[str, str], int],
    view_aliases: dict[str, tuple[str, str]],
    module_aliases: dict[str, str],
    router_states: dict[str, _DjangoRouterState],
    drf_action_routes: dict[tuple[str, str], tuple[_DjangoDRFAction, ...]],
    drf_inherited_action_hooks: dict[
        tuple[str, str], dict[str, tuple[_DjangoLifecycleHook, ...]]
    ],
    include_callback: Callable[[str], object] | None = None,
) -> list[_DjangoURLPattern]:
    path_names, include_names, django_module_names = _django_url_import_names(
        source.tree
    )
    patterns: list[_DjangoURLPattern] = []
    for value in values:
        elements = value.elts if isinstance(value, (ast.List, ast.Tuple)) else [value]
        for element in elements:
            included_source_path = _django_include_source_path(
                element,
                path_names=path_names,
                include_names=include_names,
                django_module_names=django_module_names,
                source_by_module=source_by_module,
            )
            if included_source_path is not None and include_callback is not None:
                include_callback(included_source_path)
            router_state_snapshot = {
                router_name: _DjangoRouterState(
                    registrations=list(router_state.registrations),
                    is_static=router_state.is_static,
                )
                for router_name, router_state in router_states.items()
                if router_state.is_static
            }
            router_name = _django_router_urls_name(element)
            if router_name is not None:
                patterns.extend(
                    _django_router_url_patterns(
                        router_name,
                        mount_path="",
                        line=getattr(element, "lineno", 0),
                        router_states=router_state_snapshot,
                        function_lines=function_lines,
                        drf_action_routes=drf_action_routes,
                        drf_inherited_action_hooks=drf_inherited_action_hooks,
                    )
                )
                continue
            patterns.extend(
                _django_url_pattern(
                    element,
                    path_names=path_names,
                    include_names=include_names,
                    django_module_names=django_module_names,
                    source_by_module=source_by_module,
                    function_lines=function_lines,
                    view_aliases=view_aliases,
                    module_aliases=module_aliases,
                    router_states=router_state_snapshot,
                    drf_action_routes=drf_action_routes,
                    drf_inherited_action_hooks=drf_inherited_action_hooks,
                )
            )
    return patterns


def _django_include_source_path(
    value: ast.expr,
    *,
    path_names: set[str],
    include_names: set[str],
    django_module_names: set[str],
    source_by_module: dict[str, str],
) -> str | None:
    if not isinstance(value, ast.Call) or not _is_django_url_call(
        value,
        "path",
        path_names,
        django_module_names,
    ):
        return None
    if len(value.args) < 2 or _static_string(value.args[0]) is None:
        return None
    target = value.args[1]
    if not isinstance(target, ast.Call) or not _is_django_url_call(
        target,
        "include",
        include_names,
        django_module_names,
    ):
        return None
    module_name = _django_include_module_name(target)
    return source_by_module.get(module_name) if module_name is not None else None


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


def _apply_django_router_statement(
    statement: ast.stmt,
    *,
    router_states: dict[str, _DjangoRouterState],
    router_states_by_source: dict[str, dict[str, _DjangoRouterState]],
    constructor_names: set[str],
    router_module_names: set[str],
    function_lines: dict[tuple[str, str], int],
    view_aliases: dict[str, tuple[str, str]],
    module_aliases: dict[str, str],
    view_lookup_parameters: dict[tuple[str, str], str | None],
) -> None:
    value = (
        statement.value if isinstance(statement, (ast.Assign, ast.AnnAssign)) else None
    )
    targets = (
        statement.targets
        if isinstance(statement, ast.Assign)
        else [statement.target]
        if isinstance(statement, ast.AnnAssign)
        else []
    )
    for target in targets:
        if (
            isinstance(target, ast.Attribute)
            and target.attr == "trailing_slash"
        ):
            router_name = _django_dotted_name(target.value)
            if router_name in router_states:
                router_states[router_name].is_static = False
                continue
        router_name = _django_dotted_name(target)
        if router_name is None:
            continue
        if _is_django_router_constructor(
            value,
            constructor_names=constructor_names,
            router_module_names=router_module_names,
        ):
            _rebuild_django_router_binding(
                router_states,
                name=router_name,
                module_aliases=module_aliases,
                router_states_by_source=router_states_by_source,
            )
        else:
            _discard_django_router_binding(router_states, router_name)

    if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
        return
    call = statement.value
    if (
        not isinstance(call.func, ast.Attribute)
        or call.func.attr != "register"
        or len(call.args) < 2
    ):
        return
    router_name = _django_dotted_name(call.func.value)
    if router_name not in router_states:
        return
    router_state = router_states[router_name]
    if not router_state.is_static:
        return
    prefix = _static_string(call.args[0])
    view_identity = _django_view_target_identity(
        call.args[1],
        view_aliases=view_aliases,
        module_aliases=module_aliases,
    )
    if (
        prefix is None
        or view_identity is None
        or not _django_class_has_methods(view_identity, function_lines)
    ):
        return
    router_state.registrations.append(
        _DjangoRouterRegistration(
            prefix=prefix,
            view_identity=view_identity,
            lookup_parameter=view_lookup_parameters.get(view_identity, "pk"),
        )
    )


def _rebuild_django_router_binding(
    router_states: dict[str, _DjangoRouterState],
    *,
    name: str,
    module_aliases: dict[str, str],
    router_states_by_source: dict[str, dict[str, _DjangoRouterState]],
) -> None:
    old_state = router_states.get(name)
    source_binding = _django_module_alias_router_source(name, module_aliases)
    supports_source_rebuild = (
        source_binding is not None and "." not in source_binding[1]
    )
    _discard_django_router_binding(
        router_states,
        name,
        invalidate_dotted_states="." in name and not supports_source_rebuild,
    )
    new_state = _DjangoRouterState(registrations=[])
    if old_state is not None and supports_source_rebuild and source_binding is not None:
        source_path, nested_name = source_binding
        source_states = router_states_by_source.get(source_path)
        if source_states is not None and source_states.get(nested_name) is old_state:
            source_states[nested_name] = new_state
        for alias_name in _django_equivalent_module_router_names(
            name,
            module_aliases,
        ):
            if router_states.get(alias_name) is old_state:
                router_states[alias_name] = new_state
    router_states[name] = new_state


def _django_equivalent_module_router_names(
    name: str,
    module_aliases: dict[str, str],
) -> tuple[str, ...]:
    source_binding = _django_module_alias_router_source(name, module_aliases)
    if source_binding is None:
        return ()
    module_source_path, nested_name = source_binding
    return tuple(
        f"{alias_name}.{nested_name}"
        for alias_name, alias_source_path in module_aliases.items()
        if alias_source_path == module_source_path
    )


def _django_module_alias_router_source(
    name: str,
    module_aliases: dict[str, str],
) -> tuple[str, str] | None:
    module_alias, separator, nested_name = name.partition(".")
    module_source_path = module_aliases.get(module_alias)
    if not separator or module_source_path is None:
        return None
    return module_source_path, nested_name


def _discard_django_router_binding(
    router_states: dict[str, _DjangoRouterState],
    name: str,
    *,
    invalidate_dotted_states: bool = True,
) -> None:
    prefix = f"{name}."
    matching_names = tuple(
        router_name
        for router_name in router_states
        if router_name == name or router_name.startswith(prefix)
    )
    if invalidate_dotted_states and "." in name:
        for router_name in matching_names:
            router_states[router_name].is_static = False
    for router_name in matching_names:
        router_states.pop(router_name)


def _update_django_module_bound_names(
    statement: ast.stmt,
    bound_names: set[str],
) -> None:
    targets = (
        statement.targets
        if isinstance(statement, ast.Assign)
        else [statement.target]
        if isinstance(statement, ast.AnnAssign)
        else []
    )
    for target in targets:
        if isinstance(target, ast.Name):
            bound_names.add(target.id)
    if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        bound_names.add(statement.name)
    if isinstance(statement, ast.Delete):
        for target in statement.targets:
            if isinstance(target, ast.Name):
                bound_names.discard(target.id)


def _django_router_import_names(tree: ast.Module) -> tuple[set[str], set[str]]:
    constructor_names: set[str] = set()
    router_module_names: set[str] = set()
    for statement in tree.body:
        if isinstance(statement, ast.ImportFrom):
            if statement.module == "rest_framework.routers":
                constructor_names.update(
                    imported.asname or imported.name
                    for imported in statement.names
                    if imported.name in {"DefaultRouter", "SimpleRouter"}
                )
            elif statement.module == "rest_framework":
                router_module_names.update(
                    imported.asname or imported.name
                    for imported in statement.names
                    if imported.name == "routers"
                )
        elif isinstance(statement, ast.Import):
            router_module_names.update(
                imported.asname or imported.name
                for imported in statement.names
                if imported.name == "rest_framework.routers" and imported.asname
            )
    return constructor_names, router_module_names


def _is_django_router_constructor(
    value: ast.expr | None,
    *,
    constructor_names: set[str],
    router_module_names: set[str],
) -> bool:
    if not isinstance(value, ast.Call) or value.args or value.keywords:
        return False
    if isinstance(value.func, ast.Name):
        return value.func.id in constructor_names
    return (
        isinstance(value.func, ast.Attribute)
        and value.func.attr in {"DefaultRouter", "SimpleRouter"}
        and isinstance(value.func.value, ast.Name)
        and value.func.value.id in router_module_names
    )


def _django_router_urls_name(value: ast.expr) -> str | None:
    if isinstance(value, ast.Tuple) and value.elts:
        return _django_router_urls_name(value.elts[0])
    if isinstance(value, ast.Attribute) and value.attr == "urls":
        return _django_dotted_name(value.value)
    return None


def _django_router_url_patterns(
    router_name: str,
    *,
    mount_path: str | None,
    line: int,
    router_states: dict[str, _DjangoRouterState],
    function_lines: dict[tuple[str, str], int],
    drf_action_routes: dict[tuple[str, str], tuple[_DjangoDRFAction, ...]],
    drf_inherited_action_hooks: dict[
        tuple[str, str], dict[str, tuple[_DjangoLifecycleHook, ...]]
    ],
) -> list[_DjangoURLPattern]:
    if mount_path is None:
        return []
    patterns: list[_DjangoURLPattern] = []
    router_state = router_states.get(router_name)
    if router_state is None or not router_state.is_static:
        return []
    for registration in router_state.registrations:
        collection_path = _join_static_route_path(
            mount_path,
            f"{registration.prefix.strip('/')}/",
        )
        detail_path = (
            _join_static_route_path(
                mount_path,
                f"{registration.prefix.strip('/')}/{{{registration.lookup_parameter}}}/",
            )
            if registration.lookup_parameter is not None
            else None
        )
        collection_handlers = _django_router_view_handlers(
            registration.view_identity,
            actions=DRF_ROUTER_COLLECTION_ACTIONS,
            function_lines=function_lines,
            inherited_action_hooks=drf_inherited_action_hooks.get(
                registration.view_identity,
                {},
            ),
        )
        detail_handlers = _django_router_view_handlers(
            registration.view_identity,
            actions=DRF_ROUTER_DETAIL_ACTIONS,
            function_lines=function_lines,
            inherited_action_hooks=drf_inherited_action_hooks.get(
                registration.view_identity,
                {},
            ),
        )
        if collection_handlers:
            patterns.append(
                _DjangoURLPattern(
                    route_path=collection_path,
                    line=line,
                    view_handlers=collection_handlers,
                    include_source_path=None,
                )
            )
        if detail_handlers and detail_path is not None:
            patterns.append(
                _DjangoURLPattern(
                    route_path=detail_path,
                    line=line,
                    view_handlers=detail_handlers,
                    include_source_path=None,
                )
            )
        for action in drf_action_routes.get(registration.view_identity, ()):
            if action.detail:
                if detail_path is None:
                    continue
                action_relative_path = (
                    f"{registration.prefix.strip('/')}/"
                    f"{{{registration.lookup_parameter}}}/{action.url_path}/"
                )
            else:
                action_relative_path = (
                    f"{registration.prefix.strip('/')}/{action.url_path}/"
                )
            action_path = _join_static_route_path(mount_path, action_relative_path)
            if action_path is None:
                continue
            handler_name = f"{registration.view_identity[1]}.{action.method_name}"
            if (registration.view_identity[0], handler_name) not in function_lines:
                continue
            patterns.append(
                _DjangoURLPattern(
                    route_path=action_path,
                    line=line,
                    view_handlers=tuple(
                        _DjangoViewHandler(
                            source_path=registration.view_identity[0],
                            handler_name=handler_name,
                            route_method=route_method,
                        )
                        for route_method in action.route_methods
                    ),
                    include_source_path=None,
                )
            )
    return patterns


def _django_router_view_handlers(
    class_identity: tuple[str, str],
    *,
    actions: tuple[tuple[str, str], ...],
    function_lines: dict[tuple[str, str], int],
    inherited_action_hooks: dict[str, tuple[_DjangoLifecycleHook, ...]],
) -> tuple[_DjangoViewHandler, ...]:
    source_path, class_name = class_identity
    handlers: list[_DjangoViewHandler] = []
    for action_name, route_method in actions:
        handler_name = f"{class_name}.{action_name}"
        if (source_path, handler_name) in function_lines:
            handlers.append(
                _DjangoViewHandler(
                    source_path=source_path,
                    handler_name=handler_name,
                    route_method=route_method,
                )
            )
            continue
        hooks = inherited_action_hooks.get(action_name, ())
        if not hooks:
            continue
        handlers.append(
            _DjangoViewHandler(
                source_path=source_path,
                handler_name=handler_name,
                route_method=route_method,
                service_handlers=tuple(
                    _DjangoLifecycleHook(
                        handler_name=f"{class_name}.{hook.handler_name}",
                        action_dependent=hook.action_dependent,
                    )
                    for hook in hooks
                ),
            )
        )
    return tuple(handlers)


def _django_view_handlers(
    target: ast.expr,
    *,
    function_lines: dict[tuple[str, str], int],
    view_aliases: dict[str, tuple[str, str]],
    module_aliases: dict[str, str],
) -> tuple[_DjangoViewHandler, ...]:
    if (
        isinstance(target, ast.Call)
        and isinstance(target.func, ast.Attribute)
        and target.func.attr == "as_view"
    ):
        class_identity = _django_view_target_identity(
            target.func.value,
            view_aliases=view_aliases,
            module_aliases=module_aliases,
        )
        if class_identity is not None:
            action_handlers = _django_viewset_action_handlers(
                target,
                class_identity,
                function_lines,
            )
            if action_handlers is not None:
                return action_handlers
            return _django_class_method_handlers(class_identity, function_lines)
        return ()

    identity = _django_view_target_identity(
        target,
        view_aliases=view_aliases,
        module_aliases=module_aliases,
    )
    if identity not in function_lines:
        return ()
    return (
        _DjangoViewHandler(
            source_path=identity[0],
            handler_name=identity[1],
            route_method="ANY",
        ),
    )


def _django_view_target_identity(
    target: ast.expr,
    *,
    view_aliases: dict[str, tuple[str, str]],
    module_aliases: dict[str, str],
) -> tuple[str, str] | None:
    if isinstance(target, ast.Name):
        return view_aliases.get(target.id)
    if (
        not isinstance(target, ast.Attribute)
        or not isinstance(target.value, ast.Name)
    ):
        return None
    source_path = module_aliases.get(target.value.id)
    return (source_path, target.attr) if source_path is not None else None


def _django_class_method_identities(
    class_identity: tuple[str, str],
    function_lines: dict[tuple[str, str], int],
) -> tuple[tuple[str, str], ...]:
    source_path, class_name = class_identity
    prefix = f"{class_name}."
    methods = [
        identity
        for identity in function_lines
        if (
            identity[0] == source_path
            and identity[1].startswith(prefix)
            and identity[1].rsplit(".", 1)[-1] in HTTP_METHOD_NAMES
        )
    ]
    return tuple(sorted(methods, key=lambda identity: (function_lines[identity], identity[1])))


def _django_class_has_methods(
    class_identity: tuple[str, str],
    function_lines: dict[tuple[str, str], int],
) -> bool:
    source_path, class_name = class_identity
    return any(
        identity[0] == source_path and identity[1].startswith(f"{class_name}.")
        for identity in function_lines
    )


def _django_class_method_handlers(
    class_identity: tuple[str, str],
    function_lines: dict[tuple[str, str], int],
) -> tuple[_DjangoViewHandler, ...]:
    return tuple(
        _DjangoViewHandler(
            source_path=source_path,
            handler_name=handler_name,
            route_method=handler_name.rsplit(".", 1)[-1].upper(),
        )
        for source_path, handler_name in _django_class_method_identities(
            class_identity,
            function_lines,
        )
    )


def _django_viewset_action_handlers(
    target: ast.Call,
    class_identity: tuple[str, str],
    function_lines: dict[tuple[str, str], int],
) -> tuple[_DjangoViewHandler, ...] | None:
    actions: ast.expr | None = target.args[0] if target.args else None
    has_action_map = actions is not None
    if not has_action_map:
        actions = next(
            (
                keyword.value
                for keyword in target.keywords
                if keyword.arg == "actions"
            ),
            None,
        )
        has_action_map = actions is not None
    if not has_action_map:
        return None
    if not isinstance(actions, ast.Dict):
        return ()

    source_path, class_name = class_identity
    handlers: list[_DjangoViewHandler] = []
    for method_value, action_value in zip(actions.keys, actions.values, strict=True):
        route_method = _static_string(method_value) if method_value is not None else None
        action_name = _static_string(action_value)
        if (
            route_method is None
            or action_name is None
            or route_method.lower() not in HTTP_METHOD_NAMES
        ):
            continue
        handler_name = f"{class_name}.{action_name}"
        if (source_path, handler_name) not in function_lines:
            continue
        handlers.append(
            _DjangoViewHandler(
                source_path=source_path,
                handler_name=handler_name,
                route_method=route_method.upper(),
            )
        )
    return tuple(handlers)


def _map_file(
    *,
    source_path: str,
    content: str,
    class_method_view_classes: set[str] | None = None,
) -> list[CodebaseFactCandidate]:
    facts: list[CodebaseFactCandidate] = []
    pending_route: (
        tuple[str, str, int, list[tuple[str, int]], list[tuple[str, int]]] | None
    ) = None
    pending_decorator_authz_refs: list[tuple[str, int]] = []
    pending_class_method_decorator_authz_refs: list[
        tuple[str, list[tuple[str, int]]]
    ] = []
    pending_method_decorator: tuple[int, list[str]] | None = None
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
    python_outbound_http_aliases = _python_outbound_http_aliases(content)
    yaml_module_aliases = {"yaml"}
    yaml_load_aliases: set[str] = set()
    yaml_safe_loader_aliases: set[str] = set()
    local_call_aliases: dict[str, dict[str, str]] = {}
    jwt_token_aliases: dict[str, dict[str, str]] = {}
    python_ambiguous_input_references = _python_ambiguous_input_references(content)
    python_ambiguous_jwt_token_aliases = _python_ambiguous_jwt_token_aliases(
        content
    )
    python_conditional_call_columns = _python_conditional_call_columns(content)
    class_call_aliases: dict[str, dict[str, str]] = {}
    principal_id_aliases: dict[str, dict[str, str]] = {}
    function_authz_refs: dict[str, list[tuple[str, int]]] = {}
    class_method_decorator_authz_refs: dict[
        tuple[str, str], list[tuple[str, int]]
    ] = {}
    django_class_view_classes = set(class_method_view_classes or ())
    method_view_classes = set(django_class_view_classes)
    method_view_methods: dict[str, set[str]] = {}
    method_view_authz_refs: dict[str, list[tuple[str, int]]] = {}
    method_view_method_authz_refs: dict[tuple[str, str], list[tuple[str, int]]] = {}

    def add_method_decorator_authz(
        method_decorator_authz: tuple[str | None, list[tuple[str, int]]] | None,
    ) -> None:
        nonlocal pending_decorator_authz_refs
        if method_decorator_authz is None:
            return
        method_name, authz_refs = method_decorator_authz
        if not authz_refs:
            return
        if method_name is None:
            pending_decorator_authz_refs = _dedupe_refs(
                [*pending_decorator_authz_refs, *authz_refs]
            )
            return
        pending_class_method_decorator_authz_refs.append(
            (method_name, authz_refs)
        )

    for line_number, line in enumerate(content.splitlines(), start=1):
        if pending_method_decorator is not None:
            decorator_line, decorator_lines = pending_method_decorator
            decorator_lines = [*decorator_lines, line]
            if _method_decorator_closed(decorator_lines):
                add_method_decorator_authz(
                    _method_decorator_authz_refs(
                        "\n".join(decorator_lines),
                        decorator_line,
                        import_aliases,
                    )
                )
                pending_method_decorator = None
            else:
                pending_method_decorator = (decorator_line, decorator_lines)
            continue

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

        if (
            _is_method_decorator_start(line, import_aliases)
            and not _method_decorator_closed([line])
        ):
            pending_method_decorator = (line_number, [line])
            continue

        method_decorator_authz = _method_decorator_authz_refs(
            line,
            line_number,
            import_aliases,
        )
        if method_decorator_authz is not None:
            add_method_decorator_authz(method_decorator_authz)
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
                and CLASS_PATTERN.match(line) is None
            ):
                pending_decorator_authz_refs = []
                pending_class_method_decorator_authz_refs = []
            indent = _indent_width(line)
            class_stack = [
                (class_name, class_indent)
                for class_name, class_indent in class_stack
                if class_indent < indent
            ]
            function_stack = [
                (function_name, function_indent)
                for function_name, function_indent in function_stack
                if (
                    function_indent < indent
                    or (
                        pending_signature_authz is not None
                        and function_name == pending_signature_authz[0]
                        and function_indent == pending_signature_authz[1]
                    )
                )
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
            class_decorator_authz_refs = (
                _dedupe_refs(
                    [
                        *class_method_decorator_authz_refs.get(
                            (class_name, "dispatch"),
                            [],
                        ),
                        *class_method_decorator_authz_refs.get(
                            (class_name, function_name),
                            [],
                        ),
                    ]
                )
                if class_name in django_class_view_classes
                else []
            )
            decorator_authz_refs = _dedupe_refs(
                [*pending_decorator_authz_refs, *class_decorator_authz_refs]
            )
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
                        *decorator_authz_refs,
                    ]
                )
            if class_name in django_class_view_classes:
                handler_name = _qualified_class_view_function(
                    function_match.group(1),
                    class_name,
                    django_class_view_classes,
                )
                for call_name, authz_line in decorator_authz_refs:
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
                pending_decorator_authz_refs = []
            elif is_method_view_method:
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
            class_name = class_match.group(1)
            class_stack.append((class_name, _indent_width(line)))
            for method_name, authz_refs in pending_class_method_decorator_authz_refs:
                key = (class_name, method_name)
                class_method_decorator_authz_refs[key] = _dedupe_refs(
                    [
                        *class_method_decorator_authz_refs.get(key, []),
                        *authz_refs,
                    ]
                )
            pending_class_method_decorator_authz_refs = []

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
        current_function = _qualified_class_view_function(
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
        jwt_call_leaves: set[str] = set()
        python_call_columns = _python_call_columns(line)
        python_call_input_refs = _python_call_input_refs(
            line,
            ambiguous_references=python_ambiguous_input_references.get(
                (current_function or "").rsplit(".", 1)[-1],
                set(),
            ),
            conditional_columns=python_conditional_call_columns.get(
                (current_function or "").rsplit(".", 1)[-1],
                {},
            ).get(line_number, set()),
        )
        python_call_claim_refs = _python_call_claim_refs(
            line,
            ambiguous_references=python_ambiguous_input_references.get(
                (current_function or "").rsplit(".", 1)[-1],
                set(),
            ),
            conditional_columns=python_conditional_call_columns.get(
                (current_function or "").rsplit(".", 1)[-1],
                {},
            ).get(line_number, set()),
        )
        if current_function is not None:
            token_aliases = jwt_token_aliases.setdefault(current_function, {})
            for decoder in _python_unverified_jwt_decodes(
                line,
                token_aliases,
                ambiguous_token_aliases=python_ambiguous_jwt_token_aliases.get(
                    current_function.rsplit(".", 1)[-1],
                    set(),
                ),
                ambiguous_claim_references=python_ambiguous_input_references.get(
                    current_function.rsplit(".", 1)[-1],
                    set(),
                ),
            ):
                decoder_name, decoder_column, token_ref, claims_ref = decoder
                jwt_call_leaves.add("decode")
                payload = {
                    "handler": current_function,
                    "line": line_number,
                    "column": decoder_column,
                    "mapping_mode": "static_code_snippet_analysis",
                }
                if token_ref is not None:
                    payload["token_ref"] = token_ref
                if claims_ref is not None:
                    payload["claims_ref"] = claims_ref
                facts.append(
                    CodebaseFactCandidate(
                        fact_type="unverified_token_decode",
                        source_path=source_path,
                        symbol_name=decoder_name,
                        route_method=None,
                        route_path=None,
                        authz_hint=None,
                        sensitivity_label="high",
                        payload=payload,
                    )
                )
            for validator in _python_jwt_verifications(
                line,
                token_aliases,
                ambiguous_token_aliases=python_ambiguous_jwt_token_aliases.get(
                    current_function.rsplit(".", 1)[-1],
                    set(),
                ),
                ambiguous_claim_references=python_ambiguous_input_references.get(
                    current_function.rsplit(".", 1)[-1],
                    set(),
                ),
            ):
                validator_name, validator_column, token_ref, claims_ref = validator
                jwt_call_leaves.add(validator_name.rsplit(".", 1)[-1])
                payload = {
                    "handler": current_function,
                    "line": line_number,
                    "column": validator_column,
                    "mapping_mode": "static_code_snippet_analysis",
                }
                if token_ref is not None:
                    payload["token_ref"] = token_ref
                if claims_ref is not None:
                    payload["claims_ref"] = claims_ref
                facts.append(
                    CodebaseFactCandidate(
                        fact_type="authz_check",
                        source_path=source_path,
                        symbol_name=validator_name,
                        route_method=None,
                        route_path=None,
                        authz_hint="jwt_verification_check",
                        sensitivity_label="low",
                        payload=payload,
                    )
                )
            _update_python_jwt_token_aliases(
                line,
                token_aliases,
                ambiguous_token_aliases=python_ambiguous_jwt_token_aliases.get(
                    current_function.rsplit(".", 1)[-1],
                    set(),
                ),
            )
        for raw_call_name in _called_names(
            line,
            outbound_http_aliases=python_outbound_http_aliases,
            yaml_module_aliases=yaml_module_aliases,
            yaml_load_aliases=yaml_load_aliases,
            yaml_safe_loader_aliases=yaml_safe_loader_aliases,
        ):
            if raw_call_name in jwt_call_leaves:
                continue
            call_column = _pop_python_call_column(
                python_call_columns,
                raw_call_name,
            )
            call_argument_input_refs, validated_output_ref = _pop_python_call_input_refs(
                python_call_input_refs,
                raw_call_name,
            )
            call_claim_ref = _pop_python_call_claim_ref(
                python_call_claim_refs,
                raw_call_name,
            )
            call_name = _resolved_call_name(
                raw_call_name,
                current_function,
                current_class,
                method_view_classes,
                _self_called_names(line),
                import_aliases,
                python_outbound_http_aliases,
                local_call_aliases,
                class_call_aliases,
            )
            call_input_ref = _input_bound_static_call_input_ref(
                call_name,
                call_argument_input_refs,
                input_index=_python_outbound_http_input_index(
                    raw_call_name,
                    python_outbound_http_aliases,
                ),
            )
            if _is_authz_call(call_name):
                authz_hint = _authz_hint(call_name)
                facts.append(
                    CodebaseFactCandidate(
                        fact_type="authz_check",
                        source_path=source_path,
                        symbol_name=call_name,
                        route_method=None,
                        route_path=None,
                        authz_hint=authz_hint,
                        sensitivity_label="low",
                        payload={
                            "handler": current_function,
                            "line": line_number,
                            **(
                                {"column": call_column}
                                if call_column is not None
                                else {}
                            ),
                            **(
                                _input_binding_payload(
                                    call_input_ref,
                                    validated_output_ref=validated_output_ref,
                                )
                                if (
                                    authz_hint in INPUT_BOUND_STATIC_GUARD_HINTS
                                )
                                else {}
                            ),
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
                            **(
                                {"column": call_column}
                                if call_column is not None
                                else {}
                            ),
                            **(
                                _input_binding_payload(call_input_ref)
                                if (
                                    _is_input_bound_static_sink(call_name)
                                    and call_input_ref is not None
                                )
                                else {}
                            ),
                            **(
                                {"claims_ref": call_claim_ref}
                                if call_claim_ref is not None
                                else {}
                            ),
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
    typescript_source_paths: dict[str, set[str]] | None = None,
) -> list[CodebaseFactCandidate]:
    source = _strip_typescript_comments(content)
    express_objects = _typescript_express_objects(source)
    jsonwebtoken_aliases = _typescript_jsonwebtoken_aliases(source)
    outbound_http_aliases = _typescript_outbound_http_aliases(source)
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
                    jsonwebtoken_aliases=jsonwebtoken_aliases,
                    outbound_http_aliases=outbound_http_aliases,
                )
            )
        facts.extend(
            _map_typescript_nestjs_decorators(
                source_path=source_path,
                source=source,
                typescript_source_paths=typescript_source_paths,
            )
        )
        return facts

    searchable_source = _mask_typescript_strings(source)
    router_authz_refs = _typescript_router_authz_refs(source, express_objects)
    router_mount_prefixes = _typescript_router_mount_prefixes(
        source,
        express_objects,
    )
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
        for mount_prefix in router_mount_prefixes.get(receiver, [""]):
            facts.append(
                CodebaseFactCandidate(
                    fact_type="route_handler",
                    source_path=source_path,
                    symbol_name=handler_name,
                    route_method=match.group("method").upper(),
                    route_path=_join_static_route_path(mount_prefix, route_path),
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
                jsonwebtoken_aliases=jsonwebtoken_aliases,
                outbound_http_aliases=outbound_http_aliases,
            )
        )
    return facts


def _typescript_express_objects(source: str) -> set[str]:
    masked_source = _mask_typescript_strings(source)
    express_aliases = set(
        match.group(1)
        for match in _typescript_code_matches(
            r"(?m)^\s*import\s+([A-Za-z_$][A-Za-z0-9_$]*)"
            r"(?:\s*,\s*\{[^}]*\})?\s+from\s*[\"']express[\"']",
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
        r"(?m)^\s*import\s+(?:[A-Za-z_$][A-Za-z0-9_$]*\s*,\s*)?"
        r"\{([^}]*)\}\s*from\s*[\"']express[\"']",
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


def _typescript_router_mount_prefixes(
    source: str,
    express_objects: set[str],
) -> dict[str, list[str]]:
    mounts_by_parent: dict[str, list[tuple[str, str]]] = {}
    child_objects: set[str] = set()
    for match in TYPESCRIPT_USE_CALL_PATTERN.finditer(_mask_typescript_strings(source)):
        parent = match.group("receiver")
        if parent not in express_objects:
            continue
        call = _typescript_call_arguments(source, match.end() - 1)
        if call is None:
            continue
        arguments, _ = call
        if len(arguments) < 2:
            continue
        mount_path = _typescript_static_string(arguments[0])
        child = _typescript_callable_name(arguments[-1])
        if (
            mount_path is None
            or child is None
            or child not in express_objects
            or child == parent
        ):
            continue
        mounts_by_parent.setdefault(parent, []).append((child, mount_path))
        child_objects.add(child)

    prefixes_by_router: dict[str, set[str]] = {}

    def visit(parent: str, prefix: str, lineage: set[str]) -> None:
        prefixes_by_router.setdefault(parent, set()).add(prefix)
        for child, mount_path in mounts_by_parent.get(parent, []):
            if child in lineage:
                continue
            visit(
                child,
                _join_static_route_path(prefix, mount_path),
                {*lineage, child},
            )

    for root in sorted(express_objects - child_objects):
        visit(root, "", {root})
    return {
        router: sorted(prefixes)
        for router, prefixes in prefixes_by_router.items()
    }


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
TYPESCRIPT_NEST_COMMON_NAMED_IMPORT_PATTERN = re.compile(
    r"\bimport\s*(?:type\s+)?\{(?P<imports>[^}]*)\}\s*from\s*"
    r"(?P<q>[\'\"])@nestjs/common(?P=q)",
    re.MULTILINE,
)
TYPESCRIPT_NAMED_IMPORT_PATTERN = re.compile(
    r"\bimport\s*(?:type\s+)?\{(?P<imports>[^}]*)\}\s*from\s*"
    r"(?P<q>[\'\"])(?P<module>[^\'\"]+)(?P=q)",
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
TYPESCRIPT_NEST_CLASS_PATTERN = re.compile(
    r"\b(?:export\s+(?:default\s+)?)?(?:abstract\s+)?class\s+"
    r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)[^{}]*\{",
    re.MULTILINE,
)
TYPESCRIPT_NEST_DECORATOR_START_PATTERN = re.compile(
    r"(?m)^[ \t]*@[A-Za-z_$][A-Za-z0-9_$.]*"
)
TYPESCRIPT_NEST_METHOD_BODY_TAIL_PATTERN = re.compile(
    r"\s*(?::\s*[A-Za-z_$][A-Za-z0-9_$.]*"
    r"(?:\s*<[^{};()]*>)?(?:\s*\[\])?)?\s*"
)
TYPESCRIPT_NEST_METHOD_NAME_PATTERN = re.compile(
    r"(?:public|private|protected|async|readonly|static|\s)*"
    r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\(",
)
TYPESCRIPT_NEST_CLASS_METHOD_PATTERN = re.compile(
    r"(?m)^[ \t]*(?:(?:public|private|protected|async|readonly|static|"
    r"override|abstract|declare|get|set)\s+)*(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)"
    r"\s*(?:<[^{}()]*>)?\s*\("
)
TYPESCRIPT_NEST_PARAMETER_PROPERTY_PATTERN = re.compile(
    r"\s*(?:(?:public|private|protected|readonly|override)\s+)+"
    r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\??\s*:\s*"
    r"(?P<service>[A-Za-z_$][A-Za-z0-9_$]*)"
    r"(?:\s*<[^{}()]*>)?\s*"
)


def _map_typescript_nestjs_decorators(
    *,
    source_path: str,
    source: str,
    typescript_source_paths: dict[str, set[str]] | None = None,
) -> list[CodebaseFactCandidate]:
    """Map NestJS @Controller/@Get/@UseGuards style ownership guards (static)."""
    injectable_decorator_names = _typescript_nest_injectable_decorator_names(source)
    if (
        "@Controller" not in source
        and "@UseGuards" not in source
        and not injectable_decorator_names
    ):
        return []
    # Match on raw source so decorator string paths survive string masking.
    facts: list[CodebaseFactCandidate] = []
    controller_scopes = _typescript_nest_controller_scopes(source)
    injectable_scopes = _typescript_nest_injectable_scopes(
        source,
        decorator_names=injectable_decorator_names,
    )
    if not controller_scopes and not injectable_scopes:
        return facts
    jsonwebtoken_aliases = _typescript_jsonwebtoken_aliases(source)
    outbound_http_aliases = _typescript_outbound_http_aliases(source)
    function_spans = _typescript_function_spans(source)
    local_service_classes = {
        service_class for _, _, service_class in injectable_scopes
    }
    imported_service_bindings = _typescript_nest_imported_service_bindings(
        source_path=source_path,
        source=source,
        typescript_source_paths=typescript_source_paths or {},
    )

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
        controller_scope = _typescript_nest_controller_scope_for_position(
            controller_scopes,
            method_start,
        )
        if controller_scope is None:
            continue
        (
            class_decorator_start,
            class_start,
            class_body_start,
            class_body_end,
            controller_path,
        ) = controller_scope
        service_bindings = _typescript_nest_class_service_bindings(
            source,
            class_body_start=class_body_start,
            class_body_end=class_body_end,
            source_path=source_path,
            local_service_classes=local_service_classes,
            imported_service_bindings=imported_service_bindings,
        )
        method_decorator_start = _typescript_nest_decorator_block_start(
            source,
            anchor=method_start,
            lower_bound=class_body_start,
        )
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
        method_body = _typescript_nest_method_body_span(
            source,
            method_name_start=name_abs,
        )
        if method_body is not None:
            body_start, body_end = method_body
            nested_ranges = [
                (nested_start, nested_end + 1)
                for _, nested_start, _, nested_end in function_spans
                if name_abs < nested_start and nested_end <= body_end
            ]
            facts.extend(
                _typescript_function_facts(
                    source_path=source_path,
                    source=source,
                    function_name=handler_name,
                    body_start=body_start,
                    body_end=body_end,
                    nested_ranges=nested_ranges,
                    jsonwebtoken_aliases=jsonwebtoken_aliases,
                    outbound_http_aliases=outbound_http_aliases,
                    service_bindings=service_bindings,
                )
            )
        # A Nest guard is meaningful only when it decorates this controller
        # class or this method's own decorator block. Do not leak a guard from
        # an adjacent controller into a later route handler.
        for guard_start, guard_end, guard_names in guard_events:
            class_guard = class_decorator_start <= guard_start < class_start
            method_guard = (
                class_body_start <= guard_start < class_body_end
                and method_decorator_start <= guard_start
                and guard_end <= name_abs
            )
            if not class_guard and not method_guard:
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

    controller_body_ranges = {
        (class_body_start, class_body_end)
        for _, _, class_body_start, class_body_end, _ in controller_scopes
    }
    for class_body_start, class_body_end, service_class in injectable_scopes:
        if (class_body_start, class_body_end) in controller_body_ranges:
            continue
        service_bindings = _typescript_nest_class_service_bindings(
            source,
            class_body_start=class_body_start,
            class_body_end=class_body_end,
            source_path=source_path,
            local_service_classes=local_service_classes,
            imported_service_bindings=imported_service_bindings,
        )
        for function_name, name_start, body_start, body_end in (
            _typescript_nest_class_method_spans(
                source,
                class_body_start=class_body_start,
                class_body_end=class_body_end,
            )
        ):
            if function_name == "constructor":
                continue
            nested_ranges = [
                (nested_start, nested_end + 1)
                for _, nested_start, _, nested_end in function_spans
                if name_start < nested_start and nested_end <= body_end
            ]
            facts.extend(
                _typescript_function_facts(
                    source_path=source_path,
                    source=source,
                    function_name=function_name,
                    body_start=body_start,
                    body_end=body_end,
                    nested_ranges=nested_ranges,
                    jsonwebtoken_aliases=jsonwebtoken_aliases,
                    outbound_http_aliases=outbound_http_aliases,
                    service_class=service_class,
                    service_bindings=service_bindings,
                )
            )
    return facts


def _typescript_nest_controller_scopes(
    source: str,
) -> list[tuple[int, int, int, int, str]]:
    """Return static decorator/class spans for NestJS controllers only."""
    controller_matches = list(TYPESCRIPT_NEST_CONTROLLER_PATTERN.finditer(source))
    if not controller_matches:
        return []

    scopes: list[tuple[int, int, int, int, str]] = []
    masked_source = _mask_typescript_strings(source)
    for class_match in TYPESCRIPT_NEST_CLASS_PATTERN.finditer(masked_source):
        class_decorator_start = _typescript_nest_decorator_block_start(
            source,
            anchor=class_match.start(),
        )
        controllers = [
            match
            for match in controller_matches
            if class_decorator_start <= match.start() < class_match.start()
        ]
        if len(controllers) != 1:
            continue
        class_open_brace = class_match.end() - 1
        class_close_brace = _matching_typescript_delimiter(
            source,
            class_open_brace,
            "{",
            "}",
        )
        if class_close_brace is None:
            continue
        scopes.append(
            (
                class_decorator_start,
                class_match.start(),
                class_open_brace + 1,
                class_close_brace,
                controllers[0].group("path") or "",
            )
        )
    return sorted(scopes, key=lambda scope: (scope[2], scope[3]))


def _typescript_nest_injectable_decorator_names(source: str) -> set[str]:
    """Return local decorator names statically imported from @nestjs/common."""
    aliases: set[str] = set()
    masked_source = _mask_typescript_strings(source)
    for match in TYPESCRIPT_NEST_COMMON_NAMED_IMPORT_PATTERN.finditer(source):
        if masked_source[match.start() : match.start() + len("import")] != "import":
            continue
        for imported in match.group("imports").split(","):
            alias_match = re.fullmatch(
                r"\s*Injectable(?:\s+as\s+(?P<alias>[A-Za-z_$][A-Za-z0-9_$]*))?\s*",
                imported,
            )
            if alias_match is not None:
                aliases.add(alias_match.group("alias") or "Injectable")
    return aliases


def _typescript_nest_injectable_scopes(
    source: str,
    *,
    decorator_names: set[str],
) -> list[tuple[int, int, str]]:
    """Return class-body spans for static NestJS @Injectable services."""
    masked_source = _mask_typescript_strings(source)
    injectable_matches = [
        match
        for decorator_name in decorator_names
        for match in re.finditer(
            rf"@{re.escape(decorator_name)}\b",
            masked_source,
        )
    ]
    if not injectable_matches:
        return []

    scopes: list[tuple[int, int, str]] = []
    for class_match in TYPESCRIPT_NEST_CLASS_PATTERN.finditer(masked_source):
        class_decorator_start = _typescript_nest_decorator_block_start(
            source,
            anchor=class_match.start(),
        )
        injectables = [
            match
            for match in injectable_matches
            if class_decorator_start <= match.start() < class_match.start()
        ]
        if len(injectables) != 1:
            continue
        class_open_brace = class_match.end() - 1
        class_close_brace = _matching_typescript_delimiter(
            source,
            class_open_brace,
            "{",
            "}",
        )
        if class_close_brace is not None:
            scopes.append(
                (
                    class_open_brace + 1,
                    class_close_brace,
                    class_match.group("name"),
                )
            )
    return sorted(scopes)


def _typescript_nest_controller_scope_for_position(
    scopes: list[tuple[int, int, int, int, str]],
    position: int,
) -> tuple[int, int, int, int, str] | None:
    matches = [
        scope
        for scope in scopes
        if scope[2] <= position < scope[3]
    ]
    return max(matches, key=lambda scope: scope[2], default=None)


def _typescript_nest_decorator_block_start(
    source: str,
    *,
    anchor: int,
    lower_bound: int = 0,
) -> int:
    """Find the start of decorators immediately preceding a class or method."""
    cursor = anchor
    while cursor > lower_bound:
        matches = list(
            TYPESCRIPT_NEST_DECORATOR_START_PATTERN.finditer(
                source,
                lower_bound,
                cursor,
            )
        )
        if not matches:
            break
        decorator = matches[-1]
        decorator_end = _typescript_nest_decorator_end(source, decorator.start())
        if (
            decorator_end is None
            or decorator_end > cursor
            or source[decorator_end:cursor].strip()
        ):
            break
        cursor = decorator.start()
    return cursor


def _typescript_nest_decorator_end(source: str, start: int) -> int | None:
    match = re.match(
        r"[ \t]*@[A-Za-z_$][A-Za-z0-9_$.]*",
        source[start:],
    )
    if match is None:
        return None
    cursor = start + match.end()
    while cursor < len(source) and source[cursor] in {" ", "\t"}:
        cursor += 1
    if cursor < len(source) and source[cursor] == "(":
        closing = _matching_typescript_delimiter(source, cursor, "(", ")")
        return closing + 1 if closing is not None else None
    line_end = source.find("\n", cursor)
    return len(source) if line_end < 0 else line_end


def _typescript_nest_method_body_span(
    source: str,
    *,
    method_name_start: int,
) -> tuple[int, int] | None:
    opening_parenthesis = source.find("(", method_name_start)
    if opening_parenthesis < 0:
        return None
    closing_parenthesis = _matching_typescript_delimiter(
        source,
        opening_parenthesis,
        "(",
        ")",
    )
    if closing_parenthesis is None:
        return None
    body_open_brace = source.find("{", closing_parenthesis + 1)
    if body_open_brace < 0:
        return None
    declaration_tail = source[closing_parenthesis + 1 : body_open_brace]
    if TYPESCRIPT_NEST_METHOD_BODY_TAIL_PATTERN.fullmatch(declaration_tail) is None:
        return None
    body_close_brace = _matching_typescript_delimiter(
        source,
        body_open_brace,
        "{",
        "}",
    )
    if body_close_brace is None:
        return None
    return body_open_brace + 1, body_close_brace


def _typescript_nest_class_method_spans(
    source: str,
    *,
    class_body_start: int,
    class_body_end: int,
) -> list[tuple[str, int, int, int]]:
    """Return direct method bodies from one statically resolved NestJS class."""
    masked_body = _mask_typescript_strings(source[class_body_start:class_body_end])
    brace_depth = 0
    cursor = 0
    spans: list[tuple[str, int, int, int]] = []
    for match in TYPESCRIPT_NEST_CLASS_METHOD_PATTERN.finditer(masked_body):
        brace_depth += (
            masked_body[cursor : match.start()].count("{")
            - masked_body[cursor : match.start()].count("}")
        )
        cursor = match.start()
        if brace_depth != 0:
            continue
        name_start = class_body_start + match.start("name")
        body = _typescript_nest_method_body_span(
            source,
            method_name_start=name_start,
        )
        if body is None:
            continue
        body_start, body_end = body
        if body_end > class_body_end:
            continue
        spans.append((match.group("name"), name_start, body_start, body_end))
    return spans


def _typescript_authorized_source_paths(
    files: list[object],
) -> dict[str, set[str]]:
    source_paths: dict[str, set[str]] = {}
    for item in files:
        if not isinstance(item, dict):
            continue
        source_path = item.get("path")
        content = item.get("content")
        if (
            not isinstance(source_path, str)
            or not isinstance(content, str)
            or not source_path.lower().endswith(TYPESCRIPT_SOURCE_SUFFIXES)
        ):
            continue
        normalized_source_path = _typescript_normalized_source_path(source_path)
        if normalized_source_path is not None:
            source_paths.setdefault(normalized_source_path, set()).add(source_path)
    return source_paths


def _typescript_normalized_source_path(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    source_path = value.strip().replace("\\", "/")
    if not source_path or len(source_path) > 500 or source_path.startswith("/"):
        return None
    normalized_source_path = posixpath.normpath(source_path)
    if (
        normalized_source_path in {".", ".."}
        or normalized_source_path.startswith("../")
        or normalized_source_path.startswith("/")
    ):
        return None
    return normalized_source_path


def _typescript_relative_import_candidates(
    source_path: str,
    module_specifier: str,
) -> set[str]:
    source_key = _typescript_normalized_source_path(source_path)
    module_path = module_specifier.strip().replace("\\", "/")
    if source_key is None or not module_path.startswith("."):
        return set()
    candidate = posixpath.normpath(
        posixpath.join(posixpath.dirname(source_key), module_path)
    )
    if candidate in {".", ".."} or candidate.startswith("../"):
        return set()
    if candidate.lower().endswith(TYPESCRIPT_SOURCE_SUFFIXES):
        return {candidate}
    for runtime_suffix, source_suffixes in (
        TYPESCRIPT_RUNTIME_IMPORT_SOURCE_SUFFIXES.items()
    ):
        if candidate.lower().endswith(runtime_suffix):
            source_stem = candidate[: -len(runtime_suffix)]
            return {
                f"{source_stem}{source_suffix}"
                for source_suffix in source_suffixes
            }
    return {
        *(f"{candidate}{suffix}" for suffix in TYPESCRIPT_SOURCE_SUFFIXES),
        *(f"{candidate}/index{suffix}" for suffix in TYPESCRIPT_SOURCE_SUFFIXES),
    }


def _typescript_resolve_relative_import_source_path(
    *,
    source_path: str,
    module_specifier: str,
    typescript_source_paths: dict[str, set[str]],
) -> str | None:
    matches = {
        resolved_source_path
        for candidate in _typescript_relative_import_candidates(
            source_path,
            module_specifier,
        )
        for resolved_source_path in typescript_source_paths.get(candidate, set())
    }
    return next(iter(matches)) if len(matches) == 1 else None


def _typescript_nest_imported_service_bindings(
    *,
    source_path: str,
    source: str,
    typescript_source_paths: dict[str, set[str]],
) -> dict[str, tuple[str, str | None]]:
    """Map locally named service imports to their static authorized source path."""
    bindings: dict[str, tuple[str, str | None]] = {}
    ambiguous_names: set[str] = set()
    masked_source = _mask_typescript_strings(source)
    for match in TYPESCRIPT_NAMED_IMPORT_PATTERN.finditer(source):
        if masked_source[match.start() : match.start() + len("import")] != "import":
            continue
        target_source_path = _typescript_resolve_relative_import_source_path(
            source_path=source_path,
            module_specifier=match.group("module"),
            typescript_source_paths=typescript_source_paths,
        )
        if target_source_path is None:
            continue
        for imported in match.group("imports").split(","):
            imported_match = re.fullmatch(
                r"\s*(?:type\s+)?(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)"
                r"(?:\s+as\s+(?P<alias>[A-Za-z_$][A-Za-z0-9_$]*))?\s*",
                imported,
            )
            if imported_match is None:
                continue
            imported_name = imported_match.group("name")
            local_name = imported_match.group("alias") or imported_name
            if local_name in ambiguous_names:
                continue
            binding = (imported_name, target_source_path)
            previous = bindings.get(local_name)
            if previous is None or previous == binding:
                bindings[local_name] = binding
            else:
                bindings.pop(local_name, None)
                ambiguous_names.add(local_name)
    return bindings


def _typescript_nest_class_service_bindings(
    source: str,
    *,
    class_body_start: int,
    class_body_end: int,
    source_path: str,
    local_service_classes: set[str],
    imported_service_bindings: dict[str, tuple[str, str | None]],
) -> dict[str, tuple[str, str | None]]:
    """Map Nest constructor parameter properties to their declared service class."""
    for function_name, name_start, _, _ in _typescript_nest_class_method_spans(
        source,
        class_body_start=class_body_start,
        class_body_end=class_body_end,
    ):
        if function_name != "constructor":
            continue
        opening_parenthesis = source.find("(", name_start)
        constructor_arguments = _typescript_call_arguments(
            source,
            opening_parenthesis,
        )
        if constructor_arguments is None:
            return {}
        bindings: dict[str, tuple[str, str | None]] = {}
        for argument in constructor_arguments[0]:
            parameter = TYPESCRIPT_NEST_PARAMETER_PROPERTY_PATTERN.fullmatch(argument)
            if parameter is not None:
                service_class = parameter.group("service")
                bindings[parameter.group("name")] = (
                    imported_service_bindings.get(service_class)
                    or (
                        (service_class, source_path)
                        if service_class in local_service_classes
                        else (service_class, None)
                    )
                )
        return bindings
    return {}


def _typescript_nest_service_call_binding(
    callee: str,
    service_bindings: dict[str, tuple[str, str | None]] | None,
) -> tuple[str | None, str | None, str | None]:
    match = re.fullmatch(
        r"this\.(?P<receiver>[A-Za-z_$][A-Za-z0-9_$]*)"
        r"\.[A-Za-z_$][A-Za-z0-9_$]*",
        callee,
    )
    if match is None:
        return None, None, None
    receiver = match.group("receiver")
    target = (service_bindings or {}).get(receiver)
    if target is None:
        return receiver, None, None
    return receiver, target[0], target[1]


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
    jsonwebtoken_aliases: set[str],
    outbound_http_aliases: dict[str, str],
    service_class: str | None = None,
    service_bindings: dict[str, tuple[str, str | None]] | None = None,
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
    ambiguous_input_references = _typescript_ambiguous_input_references(masked_body)
    conditional_call_offsets = _typescript_conditional_call_offsets(masked_body)
    for match in TYPESCRIPT_CALL_PATTERN.finditer(masked_body):
        callee = re.sub(r"\s+", "", match.group("callee"))
        call_name = callee.rsplit(".", 1)[-1]
        sink_name = (
            _typescript_qualified_outbound_http_sink_name(
                callee,
                outbound_http_aliases,
            )
            or call_name
        )
        call_start = body_start + match.start("callee")
        line_number = _source_line_number(source, call_start)
        column_number = _source_column_number(source, call_start)
        call_arguments = _typescript_call_arguments(body, match.end() - 1)
        token_aliases = _typescript_jwt_token_aliases(
            body,
            before=match.start("callee"),
        )
        token_ref = (
            _typescript_jwt_token_reference(call_arguments[0][0], token_aliases)
            if call_arguments is not None and call_arguments[0]
            else None
        )
        input_refs = (
            [
                _typescript_input_reference(
                    argument,
                    ambiguous_references=ambiguous_input_references,
                )
                for argument in call_arguments[0]
            ]
            if (
                call_arguments is not None
                and match.start("callee") not in conditional_call_offsets
            )
            else []
        )
        input_ref = _input_bound_static_call_input_ref(sink_name, input_refs)
        has_jwt_literal_fallback = (
            call_arguments is not None
            and bool(call_arguments[0])
            and _typescript_jwt_literal_fallback(call_arguments[0][0])
        )
        call_claim_ref = (
            _typescript_claim_reference(
                call_arguments[0][0],
                ambiguous_references=ambiguous_input_references,
            )
            if call_arguments is not None and call_arguments[0]
            else None
        )
        validated_output_ref = (
            _typescript_validated_output_reference(
                body,
                call_start=match.start("callee"),
                ambiguous_references=ambiguous_input_references,
            )
            if (
                match.start("callee") not in conditional_call_offsets
                or has_jwt_literal_fallback
            )
            else None
        )
        if _is_typescript_unverified_jwt_decode(callee, jsonwebtoken_aliases):
            facts.append(
                _typescript_function_fact(
                    fact_type="unverified_token_decode",
                    source_path=source_path,
                    symbol_name=callee,
                    function_name=function_name,
                    line_number=line_number,
                    column_number=column_number,
                    token_ref=token_ref,
                    claims_ref=_claim_reference_from_input_reference(
                        validated_output_ref
                    ),
                )
            )
            continue
        if _is_typescript_authz_call(callee):
            authz_hint = _typescript_authz_hint(callee)
            facts.append(
                _typescript_function_fact(
                    fact_type="authz_check",
                    source_path=source_path,
                    symbol_name=call_name,
                    function_name=function_name,
                    line_number=line_number,
                    column_number=column_number,
                    authz_hint=authz_hint,
                    token_ref=(
                        token_ref
                        if authz_hint == "jwt_verification_check"
                        else None
                    ),
                    claims_ref=(
                        _claim_reference_from_input_reference(validated_output_ref)
                        if authz_hint == "jwt_verification_check"
                        else None
                    ),
                    input_ref=(
                        input_ref
                        if authz_hint in INPUT_BOUND_STATIC_GUARD_HINTS
                        else None
                    ),
                    validated_output_ref=(
                        validated_output_ref
                        if authz_hint in INPUT_BOUND_STATIC_GUARD_HINTS
                        else None
                    ),
                )
            )
            continue
        if _is_typescript_sensitive_sink(sink_name):
            facts.append(
                _typescript_function_fact(
                    fact_type="sensitive_sink",
                    source_path=source_path,
                    symbol_name=sink_name,
                    function_name=function_name,
                    line_number=line_number,
                    column_number=column_number,
                    input_ref=(
                        input_ref
                        if _is_input_bound_static_sink(sink_name)
                        else None
                    ),
                    claims_ref=call_claim_ref,
                )
            )
            continue
        if _is_typescript_service_call(callee):
            fact = _typescript_function_fact(
                fact_type="service_call",
                source_path=source_path,
                symbol_name=call_name,
                function_name=function_name,
                line_number=line_number,
            )
            (
                receiver,
                target_service_class,
                target_service_source_path,
            ) = _typescript_nest_service_call_binding(
                callee,
                service_bindings,
            )
            if receiver is not None:
                fact.payload["service_receiver"] = receiver
                if target_service_class is not None:
                    fact.payload["target_service_class"] = target_service_class
                if target_service_source_path is not None:
                    fact.payload["target_service_source_path"] = (
                        target_service_source_path
                    )
            facts.append(fact)

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
    if service_class is not None:
        for fact in facts:
            fact.payload["service_class"] = service_class
    return facts


def _typescript_function_fact(
    *,
    fact_type: str,
    source_path: str,
    symbol_name: str,
    function_name: str,
    line_number: int,
    column_number: int | None = None,
    authz_hint: str | None = None,
    token_ref: str | None = None,
    claims_ref: str | None = None,
    input_ref: str | None = None,
    validated_output_ref: str | None = None,
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
            **({"column": column_number} if column_number is not None else {}),
            **({"token_ref": token_ref} if token_ref is not None else {}),
            **({"claims_ref": claims_ref} if claims_ref is not None else {}),
            **_input_binding_payload(
                input_ref,
                validated_output_ref=validated_output_ref,
            ),
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


def _typescript_jwt_token_aliases(
    body: str,
    *,
    before: int,
) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for match in TYPESCRIPT_TOKEN_ALIAS_PATTERN.finditer(body):
        if match.start() >= before:
            break
        name = match.group("name")
        token_ref = _typescript_jwt_token_reference(
            match.group("expression"),
            aliases,
        )
        if token_ref is None:
            aliases.pop(name, None)
        else:
            aliases[name] = token_ref
    return aliases


def _typescript_jwt_token_reference(
    expression: str,
    aliases: dict[str, str],
) -> str | None:
    value = expression.strip()
    while value.startswith("(") and value.endswith(")"):
        value = value[1:-1].strip()
    logical_parts = re.split(r"\s*(?:\|\||\?\?)\s*", value)
    if len(logical_parts) > 1:
        token_refs = [
            _typescript_jwt_token_reference(part, aliases)
            for part in logical_parts
            if not _typescript_token_fallback_literal(part)
        ]
        return token_refs[0] if len(token_refs) == 1 and token_refs[0] else None
    value = re.sub(r"\s+as\s+[A-Za-z_$][A-Za-z0-9_$<>,.\[\]| ]*$", "", value)
    value = value.rstrip("!").replace("?.", ".")
    if TYPESCRIPT_TOKEN_REFERENCE_PATTERN.fullmatch(value) is None:
        return None
    return aliases.get(value, f"token:{value}")


def _typescript_ambiguous_input_references(body: str) -> set[str]:
    counts: dict[str, int] = {}
    attribute_writes: set[str] = set()
    bare_reassignments: set[str] = set()
    for match in TYPESCRIPT_INPUT_REASSIGNMENT_PATTERN.finditer(body):
        path = match.group("path")
        counts[path] = counts.get(path, 0) + 1
        if "." in path:
            attribute_writes.add(path)
        elif match.group("declaration") is None:
            bare_reassignments.add(path)
    loop_bindings = {
        match.group("path")
        for match in TYPESCRIPT_INPUT_LOOP_BINDING_PATTERN.finditer(body)
    }
    destructured_bindings = _typescript_destructured_reassignment_bindings(body)
    attribute_mutation = bool(attribute_writes) or re.search(
        r"\[[^\]\n]+\]\s*(?:=(?!=|>)|[+*/%\-]=|&&=|\|\|=|\?\?=)",
        body,
    ) is not None
    return {
        *attribute_writes,
        *bare_reassignments,
        *loop_bindings,
        *destructured_bindings,
        *(path for path, count in counts.items() if count > 1),
        *(
            {INPUT_ATTRIBUTE_MUTATION_MARKER}
            if attribute_mutation
            else set()
        ),
    }


def _typescript_is_declaration_binding(body: str, start: int) -> bool:
    statement_start = max(body.rfind("\n", 0, start), body.rfind(";", 0, start)) + 1
    prefix = body[statement_start:start].rstrip()
    return re.search(r"\b(?:const|let|var)\b[^;]*$", prefix) is not None


def _typescript_destructured_reassignment_bindings(body: str) -> set[str]:
    bindings: set[str] = set()
    for match in re.finditer(r"[\{\[]", body):
        opening = match.group()
        if _typescript_is_declaration_binding(body, match.start()):
            continue
        if opening == "[" and _typescript_indexed_reference(body, match.start()):
            continue
        closing = "}" if opening == "{" else "]"
        close = _matching_typescript_delimiter(body, match.start(), opening, closing)
        if close is None:
            continue
        assignment_start = _typescript_skip_whitespace(body, close + 1)
        if assignment_start < len(body) and body[assignment_start] == ")":
            assignment_start = _typescript_skip_whitespace(body, assignment_start + 1)
        if not body.startswith("=", assignment_start) or body.startswith(
            "==",
            assignment_start,
        ) or body.startswith("=>", assignment_start):
            continue
        bindings.update(
            re.findall(
                r"[A-Za-z_$][A-Za-z0-9_$]*",
                body[match.start() + 1 : close],
            )
        )
    return bindings


def _typescript_indexed_reference(body: str, start: int) -> bool:
    previous = start - 1
    while previous >= 0 and body[previous].isspace():
        previous -= 1
    return previous >= 0 and (
        body[previous].isalnum() or body[previous] in {"_", "$", "]", ")"}
    )


def _typescript_conditional_call_offsets(body: str) -> set[int]:
    control_spans: list[tuple[int, int]] = []
    for control in re.finditer(r"\b(?:if|else|for|while|switch|try|catch)\b", body):
        statement_start = _typescript_skip_whitespace(body, control.end())
        if body.startswith("if", statement_start) and control.group() == "else":
            continue
        if control.group() in {"if", "for", "while", "switch", "catch"}:
            if body.startswith("await", statement_start):
                statement_start = _typescript_skip_whitespace(
                    body,
                    statement_start + len("await"),
                )
            if statement_start < len(body) and body[statement_start] == "(":
                close = _matching_typescript_delimiter(body, statement_start, "(", ")")
                if close is None:
                    continue
                control_spans.append((control.start(), close + 1))
                statement_start = _typescript_skip_whitespace(body, close + 1)
        if statement_start < len(body) and body[statement_start] == "{":
            close = _matching_typescript_delimiter(body, statement_start, "{", "}")
            if close is not None:
                control_spans.append((statement_start + 1, close))
                continue
        if control.group() != "try" and statement_start < len(body):
            control_spans.append(
                (
                    statement_start,
                    _typescript_statement_end(body, statement_start),
                )
            )
    call_offsets = {
        call.start("callee")
        for call in TYPESCRIPT_CALL_PATTERN.finditer(body)
        if any(start <= call.start("callee") < end for start, end in control_spans)
    }
    expression_conditional = re.compile(r"&&|\|\||\?\?|\?(?!\.)")
    for call in TYPESCRIPT_CALL_PATTERN.finditer(body):
        line_start = body.rfind("\n", 0, call.start("callee")) + 1
        statement_start = max(
            line_start,
            body.rfind(";", line_start, call.start("callee")) + 1,
        )
        if expression_conditional.search(body[statement_start : call.start("callee")]):
            call_offsets.add(call.start("callee"))
    return call_offsets


def _typescript_skip_whitespace(source: str, start: int) -> int:
    while start < len(source) and source[start].isspace():
        start += 1
    return start


def _typescript_statement_end(source: str, start: int) -> int:
    stack: list[str] = []
    closing_delimiters = {"(": ")", "[": "]", "{": "}"}
    for index in range(start, len(source)):
        character = source[index]
        if character in closing_delimiters:
            stack.append(closing_delimiters[character])
        elif stack and character == stack[-1]:
            stack.pop()
        elif not stack and character == ";":
            return index + 1
        elif not stack and character == "\n":
            return index
    return len(source)


def _typescript_input_reference(
    expression: str,
    *,
    ambiguous_references: set[str] | None = None,
) -> str | None:
    value = expression.strip()
    while value.startswith("(") and value.endswith(")"):
        value = value[1:-1].strip()
    value = re.sub(r"\s+as\s+[A-Za-z_$][A-Za-z0-9_$<>,.\[\]| ]*$", "", value)
    value = value.rstrip("!").replace("?.", ".")
    references = ambiguous_references or set()
    if INPUT_ATTRIBUTE_MUTATION_MARKER in references and "." in value:
        return None
    if any(
        value == reference or value.startswith(reference + ".")
        for reference in references
    ):
        return None
    return structural_input_reference(value)


def _typescript_claim_reference(
    expression: str,
    *,
    ambiguous_references: set[str] | None = None,
) -> str | None:
    value = expression.strip()
    while value.startswith("(") and value.endswith(")"):
        value = value[1:-1].strip()
    value = re.sub(r"\s+as\s+[A-Za-z_$][A-Za-z0-9_$<>,.\[\]| ]*$", "", value)
    value = value.rstrip("!").replace("?.", ".")
    root = value.split(".", 1)[0]
    if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", root) is None:
        return None
    if any(
        root == reference or root.startswith(reference + ".")
        for reference in ambiguous_references or set()
    ):
        return None
    return structural_claim_reference(root)


def _typescript_validated_output_reference(
    body: str,
    *,
    call_start: int,
    ambiguous_references: set[str] | None = None,
) -> str | None:
    statement_start = max(
        body.rfind(";", 0, call_start),
        body.rfind("\n", 0, call_start),
        body.rfind("{", 0, call_start),
        body.rfind("}", 0, call_start),
    ) + 1
    prefix = body[statement_start:call_start]
    binding = re.search(
        r"\b(?:const|let|var)\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)"
        r"(?:\s*:\s*[^=;\n]+)?\s*=\s*(?:await\s+)?$",
        prefix,
    )
    if binding is None:
        return None
    return _typescript_input_reference(
        binding.group("name"),
        ambiguous_references=ambiguous_references,
    )


def _typescript_token_fallback_literal(value: str) -> bool:
    return value.strip() in {"''", '\"\"', "null", "undefined"}


def _typescript_jwt_literal_fallback(expression: str) -> bool:
    parts = re.split(r"\s*(?:\|\||\?\?)\s*", expression)
    return len(parts) > 1 and all(
        _typescript_token_fallback_literal(part) for part in parts[1:]
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
        callee
    ) and not _is_typescript_sensitive_sink(call_name)


def _is_typescript_authz_call(call_name: str) -> bool:
    normalized = _normalized_typescript_name(call_name)
    if _is_jwt_verification_control(call_name):
        return True
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
    if _is_transactional_state_guard_name(normalized):
        return True
    if _is_agent_tool_guard_name(normalized):
        return True
    return _is_injection_guard_name(normalized)


def _typescript_authz_hint(call_name: str) -> str:
    normalized = _normalized_typescript_name(call_name)
    if _is_jwt_verification_control(call_name):
        return "jwt_verification_check"
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
    if _is_transactional_state_guard_name(normalized):
        return "transactional_state_guard"
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


def _typescript_qualified_outbound_http_sink_name(
    callee: str,
    outbound_http_aliases: dict[str, str],
) -> str | None:
    components = [
        _normalized_typescript_name(component)
        for component in callee.split(".")
        if component
    ]
    normalized = ".".join(components)
    canonical_sink = _TYPESCRIPT_QUALIFIED_OUTBOUND_HTTP_SINKS.get(normalized)
    if canonical_sink is not None:
        return canonical_sink
    return outbound_http_aliases.get(normalized)


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


def _is_transactional_state_guard_name(normalized_name: str) -> bool:
    return normalized_name == "transactional" or any(
        marker in normalized_name for marker in STATE_TRANSITION_GUARD_MARKERS
    )


def _is_agent_tool_guard_name(normalized_name: str) -> bool:
    return any(marker in normalized_name for marker in AGENT_TOOL_GUARD_MARKERS)


def _typescript_jsonwebtoken_aliases(source: str) -> set[str]:
    aliases = {"jsonwebtoken"}
    for match in TYPESCRIPT_JSONWEBTOKEN_ALIAS_PATTERN.finditer(source):
        alias = match.group("import_alias") or match.group("require_alias")
        if alias:
            aliases.add(alias.lower())
    return aliases


def _typescript_axios_aliases(source: str) -> set[str]:
    aliases = {"axios"}
    for match in TYPESCRIPT_AXIOS_ALIAS_PATTERN.finditer(source):
        alias = match.group("import_alias") or match.group("require_alias")
        if alias:
            aliases.add(_normalized_typescript_name(alias))
    return aliases


def _typescript_outbound_http_aliases(source: str) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for alias in _typescript_axios_aliases(source):
        for qualified_name, sink_name in (
            _TYPESCRIPT_QUALIFIED_OUTBOUND_HTTP_SINKS.items()
        ):
            method = qualified_name.rsplit(".", 1)[-1]
            aliases[f"{alias}.{method}"] = sink_name

    for match in TYPESCRIPT_OUTBOUND_HTTP_ALIAS_PATTERN.finditer(source):
        alias = match.group("import_alias") or match.group("require_alias")
        if not alias:
            continue
        normalized_alias = _normalized_typescript_name(alias)
        module = match.group("module").lower()
        namespace_import = match.group("namespace") is not None
        if module in {"node-fetch", "cross-fetch"}:
            if not namespace_import:
                aliases[normalized_alias] = "fetch"
            aliases[f"{normalized_alias}.default"] = "fetch"
        elif module == "got":
            if not namespace_import:
                aliases[normalized_alias] = "fetch"
            for method in ("delete", "get", "head", "patch", "post", "put"):
                aliases[f"{normalized_alias}.{method}"] = "fetch"
        elif module == "undici":
            for method in ("fetch", "request"):
                aliases[f"{normalized_alias}.{method}"] = "fetch"
        else:
            for method in ("get", "request"):
                aliases[f"{normalized_alias}.{method}"] = "fetch"

    for match in TYPESCRIPT_UNDICI_NAMED_IMPORT_PATTERN.finditer(source):
        imported = match.group("imported") or match.group("required") or ""
        for binding in imported.split(","):
            named_import = re.fullmatch(
                r"\s*(?P<name>fetch|request)"
                r"(?:\s+as\s+(?P<alias>[A-Za-z_$][A-Za-z0-9_$]*))?\s*",
                binding,
                re.IGNORECASE,
            )
            if named_import is None:
                continue
            alias = named_import.group("alias") or named_import.group("name")
            aliases[_normalized_typescript_name(alias)] = "fetch"
    return aliases


def _is_typescript_unverified_jwt_decode(
    callee: str,
    jsonwebtoken_aliases: set[str],
) -> bool:
    parts = [part for part in callee.lower().split(".") if part]
    return len(parts) == 2 and parts[0] in jsonwebtoken_aliases and parts[1] == "decode"


def _is_jwt_verification_control(call_name: str) -> bool:
    compact = re.sub(r"\s+", "", call_name).lower()
    if compact in {
        "jwt.verify",
        "jwt.validate",
        "jsonwebtoken.verify",
        "jsonwebtoken.validate",
    }:
        return True
    return False


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


def _source_column_number(source: str, position: int) -> int:
    line_start = source.rfind("\n", 0, position)
    return position if line_start < 0 else position - line_start - 1


def _current_function(function_stack: list[tuple[str, int]]) -> str | None:
    if not function_stack:
        return None
    return function_stack[-1][0]


def _current_class(class_stack: list[tuple[str, int]]) -> str | None:
    if not class_stack:
        return None
    return class_stack[-1][0]


def _qualified_class_view_function(
    function_name: str | None,
    class_name: str | None,
    method_view_classes: set[str],
) -> str | None:
    if function_name is not None and class_name in method_view_classes:
        return f"{class_name}.{function_name}"
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
    if service_class := _fact_service_class(fact):
        symbol_name = f"{service_class}.{symbol_name}"
    return source_path, symbol_name


def _fact_service_class(fact: CodebaseFactCandidate) -> str | None:
    if not isinstance(fact.payload, dict):
        return None
    service_class = fact.payload.get("service_class")
    if not isinstance(service_class, str):
        return None
    return (
        service_class
        if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", service_class)
        else None
    )


def _handler_identities_by_symbol(
    facts: list[CodebaseFactCandidate],
) -> dict[str, set[tuple[str, str]]]:
    identities_by_symbol: dict[str, set[tuple[str, str]]] = {}
    for fact in facts:
        if _fact_service_class(fact) is not None:
            continue
        for payload_key in ("handler", "caller"):
            identity = _fact_handler_identity(fact, payload_key)
            if identity is not None:
                identities_by_symbol.setdefault(identity[1], set()).add(identity)
    return identities_by_symbol


def _service_handler_identities(
    facts: list[CodebaseFactCandidate],
) -> dict[tuple[str, str, str], set[tuple[str, str]]]:
    identities: dict[tuple[str, str, str], set[tuple[str, str]]] = {}
    for fact in facts:
        service_class = _fact_service_class(fact)
        if service_class is None or not isinstance(fact.payload, dict):
            continue
        handler = fact.payload.get("handler")
        identity = _fact_handler_identity(fact, "handler")
        if isinstance(handler, str) and identity is not None:
            identities.setdefault(
                (fact.source_path, service_class, handler),
                set(),
            ).add(identity)
    return identities


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


def _resolve_service_call_identity(
    fact: CodebaseFactCandidate,
    *,
    caller_source_path: str,
    identities_by_symbol: dict[str, set[tuple[str, str]]],
    service_identities: dict[tuple[str, str, str], set[tuple[str, str]]],
) -> tuple[str, str] | None:
    if not isinstance(fact.payload, dict) or not isinstance(fact.symbol_name, str):
        return None
    if isinstance(fact.payload.get("service_receiver"), str):
        target_service_class = fact.payload.get("target_service_class")
        target_service_source_path = fact.payload.get("target_service_source_path")
        if (
            not isinstance(target_service_class, str)
            or not isinstance(target_service_source_path, str)
        ):
            return None
        candidates = service_identities.get(
            (
                target_service_source_path,
                target_service_class,
                fact.symbol_name,
            ),
            set(),
        )
        return next(iter(candidates)) if len(candidates) == 1 else None
    return _resolve_handler_identity(
        caller_source_path,
        fact.symbol_name,
        identities_by_symbol,
    )


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
        authz_service_calls = _reachable_service_handlers(
            facts,
            route.source_path,
            handler,
            include_action_dependent_lifecycle=False,
        )
        reachable_handlers = {route_identity, *service_calls}
        authz_reachable_handlers = {route_identity, *authz_service_calls}
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
        if _route_access_is_denied(facts, route_identity):
            continue
        root_cause, security_invariant, authz_hint = _gap_root_for_sinks(sink_symbols)
        if (
            root_cause == "missing_agent_tool_authorization_check"
            and not _is_agent_tool_route_context(route)
        ):
            root_cause, security_invariant, authz_hint = _object_ownership_gap_root()
        if guard_hints := STATIC_GAP_GUARD_HINTS.get(root_cause):
            input_bound_guard_hints = INPUT_BOUND_STATIC_GAP_GUARD_HINTS.get(
                root_cause
            )
            has_prior_guard = (
                _has_prior_input_bound_guard(
                    facts,
                    entry_handler=route_identity,
                    reachable_handlers=authz_reachable_handlers,
                    sink_facts=sink_facts,
                    guard_hints=input_bound_guard_hints,
                )
                if input_bound_guard_hints is not None
                else _has_prior_static_guard(
                    facts,
                    entry_handler=route_identity,
                    reachable_handlers=authz_reachable_handlers,
                    sink_facts=sink_facts,
                    guard_hints=guard_hints,
                )
            )
            if has_prior_guard:
                continue
        else:
            has_authz = any(
                fact.fact_type == "authz_check"
                and _suppresses_object_authorization_gap(fact)
                and _fact_handler_identity(fact, "handler") == route_identity
                and not has_reachable_sink_before_control(
                    facts,
                    control=fact,
                    entry_handlers={route_identity},
                )
                for fact in facts
            )
            if has_authz:
                continue
            has_service_authz = any(
                fact.fact_type == "authz_check"
                and _suppresses_object_authorization_gap(fact)
                and _fact_handler_identity(fact, "handler") in authz_service_calls
                and not has_reachable_sink_before_control(
                    facts,
                    control=fact,
                    entry_handlers={route_identity},
                )
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


def _graphql_authorization_gap_candidates(
    facts: list[CodebaseFactCandidate],
) -> list[CodebaseFactCandidate]:
    candidates: list[CodebaseFactCandidate] = []
    operations = [fact for fact in facts if fact.fact_type == "graphql_operation"]
    for operation in operations:
        payload = operation.payload if isinstance(operation.payload, dict) else {}
        handler = payload.get("handler")
        operation_type = payload.get("operation_type")
        operation_name = payload.get("operation_name")
        if not all(
            isinstance(value, str) and value
            for value in (handler, operation_type, operation_name)
        ):
            continue
        entry_identity = (operation.source_path, handler)
        service_calls = _reachable_service_handlers(
            facts,
            operation.source_path,
            handler,
        )
        reachable_handlers = {entry_identity, *service_calls}
        sink_facts = [
            fact
            for fact in facts
            if fact.fact_type == "sensitive_sink"
            and isinstance(fact.symbol_name, str)
            and _fact_handler_identity(fact, "handler") in reachable_handlers
        ]
        sink_symbols = sorted({fact.symbol_name for fact in sink_facts})
        if not sink_symbols:
            continue
        root_cause, security_invariant, authz_hint = _gap_root_for_sinks(
            sink_symbols
        )
        if (
            root_cause == "missing_agent_tool_authorization_check"
            and operation_type not in {"mutation", "subscription"}
        ):
            root_cause, security_invariant, authz_hint = _object_ownership_gap_root()
        candidates.append(
            CodebaseFactCandidate(
                fact_type="authorization_gap_candidate",
                source_path=operation.source_path,
                symbol_name=handler,
                route_method=None,
                route_path=None,
                authz_hint=authz_hint,
                sensitivity_label="high",
                payload={
                    "handler": handler,
                    "mapping_mode": "static_code_snippet_analysis",
                    "review_state": "needs_human_review",
                    "root_cause": root_cause,
                    "security_invariant": security_invariant,
                    "sink_count": len(sink_symbols),
                    "sink_symbols": sink_symbols,
                    "entrypoint_kind": "graphql_operation",
                    "graphql_operation_type": operation_type,
                    "graphql_operation_name": operation_name,
                },
            )
        )
    return candidates


def _jwt_verification_gap_candidates(
    facts: list[CodebaseFactCandidate],
) -> list[CodebaseFactCandidate]:
    """Emit advisory JWT candidates only for local decode-to-sink traces."""
    candidates: list[CodebaseFactCandidate] = []
    routes = [fact for fact in facts if fact.fact_type == "route_handler"]
    for route in routes:
        handler = route.payload.get("handler") if isinstance(route.payload, dict) else None
        if not isinstance(handler, str):
            continue
        route_identity = (route.source_path, handler)
        if _route_access_is_denied(facts, route_identity):
            continue
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
            and _fact_handler_identity(fact, "handler") in reachable_handlers
        ]
        decoder_facts = [
            fact
            for fact in facts
            if fact.fact_type == "unverified_token_decode"
            and _fact_handler_identity(fact, "handler") in reachable_handlers
        ]
        decoder_sink_pairs: list[
            tuple[CodebaseFactCandidate, list[CodebaseFactCandidate]]
        ] = []
        for decoder in decoder_facts:
            paired_sinks = [
                sink
                for sink in sink_facts
                if _jwt_decoder_precedes_sink(
                    facts,
                    decoder=decoder,
                    sink=sink,
                    reachable_handlers=reachable_handlers,
                )
            ]
            if not paired_sinks:
                continue
            decoder_sink_pairs.append((decoder, paired_sinks))

        if not decoder_sink_pairs:
            continue

        uncovered_decoders: list[CodebaseFactCandidate] = []
        uncovered_sinks: list[CodebaseFactCandidate] = []
        for decoder, paired_sinks in decoder_sink_pairs:
            if _jwt_decoder_has_prior_static_verification(
                facts,
                decoder=decoder,
                reachable_handlers=reachable_handlers,
                sink_facts=paired_sinks,
            ):
                continue
            uncovered_decoders.append(decoder)
            for sink in paired_sinks:
                if not any(existing is sink for existing in uncovered_sinks):
                    uncovered_sinks.append(sink)

        if not uncovered_sinks:
            continue
        decoder_symbols = sorted(
            {
                fact.symbol_name
                for fact in uncovered_decoders
                if isinstance(fact.symbol_name, str)
            }
        )
        sink_symbols = sorted(
            {
                fact.symbol_name
                for fact in uncovered_sinks
                if isinstance(fact.symbol_name, str)
            }
        )
        candidates.append(
            CodebaseFactCandidate(
                fact_type="authorization_gap_candidate",
                source_path=route.source_path,
                symbol_name=handler,
                route_method=route.route_method,
                route_path=route.route_path,
                authz_hint="missing_handler_jwt_verification_check",
                sensitivity_label="high",
                payload={
                    "handler": handler,
                    "mapping_mode": "static_code_snippet_analysis",
                    "review_state": "needs_human_review",
                    "root_cause": "missing_jwt_verification",
                    "security_invariant": (
                        "JWT claims must be signature-verified and validated before they "
                        "influence sensitive operations."
                    ),
                    "decoder_symbols": decoder_symbols,
                    "sink_count": len(sink_symbols),
                    "sink_symbols": sink_symbols,
                },
            )
        )
    return candidates


def _jwt_decoder_has_prior_static_verification(
    facts: list[CodebaseFactCandidate],
    *,
    decoder: CodebaseFactCandidate,
    reachable_handlers: set[tuple[str, str]],
    sink_facts: list[CodebaseFactCandidate],
) -> bool:
    token_ref = _fact_token_ref(decoder)
    decoder_handler = _fact_handler_identity(decoder, "handler")
    if not token_ref or decoder_handler is None:
        return False
    matching_guards = [
        fact
        for fact in facts
        if fact.fact_type == "authz_check"
        and fact.authz_hint == "jwt_verification_check"
        and _fact_handler_identity(fact, "handler") in reachable_handlers
        and _fact_token_ref(fact) == token_ref
    ]
    if not matching_guards:
        return False
    for sink in sink_facts:
        sink_handler = _fact_handler_identity(sink, "handler")
        sink_position = _fact_position(sink)
        sink_claim_ref = _fact_claim_ref(sink)
        if (
            sink_handler != decoder_handler
            or sink_position is None
            or sink_claim_ref is None
        ):
            return False
        if not any(
            _fact_handler_identity(guard, "handler") == sink_handler
            and (guard_position := _fact_position(guard)) is not None
            and guard_position < sink_position
            and _fact_claim_ref(guard) == sink_claim_ref
            for guard in matching_guards
        ):
            return False
    return bool(sink_facts)


def _jwt_decoder_precedes_sink(
    facts: list[CodebaseFactCandidate],
    *,
    decoder: CodebaseFactCandidate,
    sink: CodebaseFactCandidate,
    reachable_handlers: set[tuple[str, str]],
) -> bool:
    decoder_handler = _fact_handler_identity(decoder, "handler")
    decoder_position = _fact_position(decoder)
    sink_handler = _fact_handler_identity(sink, "handler")
    sink_position = _fact_position(sink)
    if (
        decoder_handler is None
        or decoder_position is None
        or sink_handler is None
        or sink_position is None
    ):
        return False

    identities_by_symbol = _handler_identities_by_symbol(facts)
    service_identities = _service_handler_identities(facts)
    calls_by_handler: dict[tuple[str, str], list[CodebaseFactCandidate]] = {}
    for fact in facts:
        if fact.fact_type != "service_call":
            continue
        caller = _fact_handler_identity(fact, "caller")
        if caller in reachable_handlers:
            calls_by_handler.setdefault(caller, []).append(fact)

    def reaches_sink(
        handler_identity: tuple[str, str],
        minimum_position: tuple[int, int] | None,
        visiting: set[tuple[str, str]],
    ) -> bool:
        if handler_identity in visiting:
            return False
        if handler_identity == sink_handler and (
            minimum_position is None or sink_position > minimum_position
        ):
            return True
        next_visiting = {*visiting, handler_identity}
        for call in calls_by_handler.get(handler_identity, []):
            call_position = _fact_position(call)
            if call_position is None or (
                minimum_position is not None and call_position <= minimum_position
            ):
                continue
            callee = call.symbol_name
            if not isinstance(callee, str):
                continue
            callee_identity = _resolve_service_call_identity(
                call,
                caller_source_path=handler_identity[0],
                identities_by_symbol=identities_by_symbol,
                service_identities=service_identities,
            )
            if (
                callee_identity in reachable_handlers
                and callee_identity is not None
                and reaches_sink(callee_identity, None, next_visiting)
            ):
                return True
        return False

    return reaches_sink(decoder_handler, decoder_position, set())


def _suppresses_object_authorization_gap(fact: CodebaseFactCandidate) -> bool:
    return fact.authz_hint not in {
        "public_access",
        "authentication_check",
        "jwt_verification_check",
    }


def _route_access_is_denied(
    facts: list[CodebaseFactCandidate],
    route_identity: tuple[str, str],
) -> bool:
    return any(
        fact.fact_type == "authz_check"
        and fact.authz_hint == "access_denied_check"
        and _fact_handler_identity(fact, "handler") == route_identity
        and not has_reachable_sink_before_control(
            facts,
            control=fact,
            entry_handlers={route_identity},
        )
        for fact in facts
    )


def _is_agent_tool_route_context(route: CodebaseFactCandidate) -> bool:
    route_path = route.route_path.lower() if isinstance(route.route_path, str) else ""
    return "agent" in route_path and "tool" in route_path


def _has_prior_input_bound_guard(
    facts: list[CodebaseFactCandidate],
    *,
    entry_handler: tuple[str, str],
    reachable_handlers: set[tuple[str, str]],
    sink_facts: list[CodebaseFactCandidate],
    guard_hints: set[str],
) -> bool:
    """Require a matching prior guard for every structurally tracked input sink."""
    events_by_handler: dict[
        tuple[str, str], list[tuple[tuple[int, int], int, str, object]]
    ] = {}
    expected_sinks: set[int] = set()

    def add_event(
        handler_identity: tuple[str, str],
        position: tuple[int, int],
        priority: int,
        event_type: str,
        value: object,
    ) -> None:
        events_by_handler.setdefault(handler_identity, []).append(
            (position, priority, event_type, value)
        )

    for sink in sink_facts:
        handler_identity = _fact_handler_identity(sink, "handler")
        position = _fact_position(sink)
        input_ref = _fact_input_ref(sink)
        if handler_identity is None or position is None or input_ref is None:
            return False
        expected_sinks.add(id(sink))
        add_event(handler_identity, position, 0, "sink", (sink, input_ref))

    for guard in facts:
        if (
            guard.fact_type != "authz_check"
            or guard.authz_hint not in guard_hints
        ):
            continue
        handler_identity = _fact_handler_identity(guard, "handler")
        position = _fact_position(guard)
        if (
            handler_identity not in reachable_handlers
            or position is None
        ):
            continue
        for input_ref in _fact_guard_input_refs(guard):
            add_event(handler_identity, position, 1, "guard", input_ref)

    identities_by_symbol = _handler_identities_by_symbol(facts)
    service_identities = _service_handler_identities(facts)
    for fact in facts:
        if fact.fact_type != "service_call":
            continue
        caller = _fact_handler_identity(fact, "caller")
        position = _fact_position(fact)
        if caller not in reachable_handlers or position is None:
            continue
        callee = fact.symbol_name
        if not isinstance(callee, str):
            continue
        target = _resolve_service_call_identity(
            fact,
            caller_source_path=caller[0],
            identities_by_symbol=identities_by_symbol,
            service_identities=service_identities,
        )
        if target not in reachable_handlers:
            continue
        add_event(caller, position, 0, "call", target)

    for events in events_by_handler.values():
        events.sort(key=lambda event: (event[0], event[1]))

    seen_sinks: set[int] = set()
    seen_states: set[tuple[tuple[str, str], frozenset[str]]] = set()
    uncovered_sink = False

    def walk(
        handler_identity: tuple[str, str],
        guarded_inputs: frozenset[str],
        lineage: set[tuple[str, str]],
    ) -> None:
        nonlocal uncovered_sink
        if uncovered_sink or handler_identity in lineage:
            return
        state = (handler_identity, guarded_inputs)
        if state in seen_states:
            return
        seen_states.add(state)
        current_inputs = guarded_inputs
        for _, _, event_type, value in events_by_handler.get(handler_identity, []):
            if event_type == "guard" and isinstance(value, str):
                current_inputs = current_inputs | {value}
                continue
            if event_type == "sink" and isinstance(value, tuple):
                sink, input_ref = value
                if not isinstance(sink, CodebaseFactCandidate) or not isinstance(
                    input_ref, str
                ):
                    uncovered_sink = True
                    return
                seen_sinks.add(id(sink))
                if input_ref not in current_inputs:
                    uncovered_sink = True
                    return
                continue
            if event_type == "call" and isinstance(value, tuple):
                # Parameter/argument flow is not modeled across local helpers.
                walk(value, frozenset(), {*lineage, handler_identity})
                if uncovered_sink:
                    return

    walk(entry_handler, frozenset(), set())
    return bool(expected_sinks) and not uncovered_sink and seen_sinks == expected_sinks


def _has_prior_static_guard(
    facts: list[CodebaseFactCandidate],
    *,
    entry_handler: tuple[str, str],
    reachable_handlers: set[tuple[str, str]],
    sink_facts: list[CodebaseFactCandidate],
    guard_hints: set[str] | None,
    guard_facts: list[CodebaseFactCandidate] | None = None,
) -> bool:
    """Require a matching guard before every reachable static sink."""
    events_by_handler: dict[
        tuple[str, str], list[tuple[tuple[int, int], int, str, object]]
    ] = {}
    expected_sinks: set[int] = set()

    def add_event(
        handler_identity: tuple[str, str],
        position: tuple[int, int],
        priority: int,
        event_type: str,
        value: object,
    ) -> None:
        events_by_handler.setdefault(handler_identity, []).append(
            (position, priority, event_type, value)
        )

    for fact in sink_facts:
        handler_identity = _fact_handler_identity(fact, "handler")
        position = _fact_position(fact)
        if handler_identity is None or position is None:
            return False
        expected_sinks.add(id(fact))
        add_event(handler_identity, position, 0, "sink", fact)

    for fact in guard_facts if guard_facts is not None else facts:
        if fact.fact_type != "authz_check" or (
            guard_hints is not None and fact.authz_hint not in guard_hints
        ):
            continue
        handler_identity = _fact_handler_identity(fact, "handler")
        position = _fact_position(fact)
        if handler_identity not in reachable_handlers or position is None:
            continue
        add_event(handler_identity, position, 1, "guard", fact)

    identities_by_symbol = _handler_identities_by_symbol(facts)
    service_identities = _service_handler_identities(facts)
    for fact in facts:
        if fact.fact_type != "service_call":
            continue
        caller = _fact_handler_identity(fact, "caller")
        position = _fact_position(fact)
        if caller not in reachable_handlers or position is None:
            continue
        callee = fact.symbol_name
        if not isinstance(callee, str):
            continue
        target = _resolve_service_call_identity(
            fact,
            caller_source_path=caller[0],
            identities_by_symbol=identities_by_symbol,
            service_identities=service_identities,
        )
        if target not in reachable_handlers:
            continue
        add_event(caller, position, 0, "call", target)

    for events in events_by_handler.values():
        events.sort(key=lambda event: (event[0], event[1]))

    seen_sinks: set[int] = set()
    seen_states: set[tuple[tuple[str, str], bool]] = set()
    uncovered_sink = False

    def walk(
        handler_identity: tuple[str, str],
        guarded: bool,
        lineage: set[tuple[str, str]],
    ) -> None:
        nonlocal uncovered_sink
        if uncovered_sink or handler_identity in lineage:
            return
        state = (handler_identity, guarded)
        if state in seen_states:
            return
        seen_states.add(state)
        for _, _, event_type, value in events_by_handler.get(handler_identity, []):
            if event_type == "guard":
                guarded = True
                continue
            if event_type == "sink":
                seen_sinks.add(id(value))
                if not guarded:
                    uncovered_sink = True
                    return
                continue
            if event_type == "call" and isinstance(value, tuple):
                walk(value, guarded, {*lineage, handler_identity})
                if uncovered_sink:
                    return

    walk(entry_handler, False, set())
    return bool(expected_sinks) and not uncovered_sink and seen_sinks == expected_sinks


def has_reachable_sink_before_control(
    facts: list[CodebaseFactCandidate],
    *,
    control: CodebaseFactCandidate,
    entry_handlers: set[tuple[str, str]] | None = None,
) -> bool:
    """Return whether an observed sink can run before a proposed control."""
    control_handler = _fact_handler_identity(control, "handler")
    control_position = _fact_position(control)
    if control_handler is None or control_position is None:
        return False

    identities_by_symbol = _handler_identities_by_symbol(facts)
    service_identities = _service_handler_identities(facts)
    calls_by_handler: dict[
        tuple[str, str], list[CodebaseFactCandidate]
    ] = {}
    sink_positions_by_handler: dict[tuple[str, str], list[tuple[int, int]]] = {}
    for fact in facts:
        if fact.fact_type == "service_call":
            caller = _fact_handler_identity(fact, "caller")
            if caller is not None:
                calls_by_handler.setdefault(caller, []).append(fact)
        elif fact.fact_type == "sensitive_sink":
            handler = _fact_handler_identity(fact, "handler")
            position = _fact_position(fact)
            if handler is not None and position is not None:
                sink_positions_by_handler.setdefault(handler, []).append(position)

    roots = entry_handlers or {
        identity
        for fact in facts
        if fact.fact_type == "route_handler"
        if (identity := _fact_handler_identity(fact, "handler")) is not None
    }
    if not roots:
        roots = {control_handler}

    def callee_identity(
        caller: tuple[str, str],
        call: CodebaseFactCandidate,
    ) -> tuple[str, str] | None:
        callee = call.symbol_name
        if not isinstance(callee, str):
            return None
        return _resolve_service_call_identity(
            call,
            caller_source_path=caller[0],
            identities_by_symbol=identities_by_symbol,
            service_identities=service_identities,
        )

    sink_cache: dict[tuple[str, str], bool] = {}
    control_cache: dict[tuple[str, str], bool] = {}

    def reaches_sink(
        handler: tuple[str, str],
        visiting: set[tuple[str, str]],
    ) -> bool:
        if handler in sink_cache:
            return sink_cache[handler]
        if handler in visiting:
            return False
        if sink_positions_by_handler.get(handler):
            sink_cache[handler] = True
            return True
        next_visiting = {*visiting, handler}
        result = any(
            next_handler is not None and reaches_sink(next_handler, next_visiting)
            for call in calls_by_handler.get(handler, [])
            if (next_handler := callee_identity(handler, call)) is not None
        )
        sink_cache[handler] = result
        return result

    def reaches_control(
        handler: tuple[str, str],
        visiting: set[tuple[str, str]],
    ) -> bool:
        if handler == control_handler:
            return True
        if handler in control_cache:
            return control_cache[handler]
        if handler in visiting:
            return False
        next_visiting = {*visiting, handler}
        result = any(
            next_handler is not None
            and reaches_control(next_handler, next_visiting)
            for call in calls_by_handler.get(handler, [])
            if (next_handler := callee_identity(handler, call)) is not None
        )
        control_cache[handler] = result
        return result

    def sink_precedes_control(
        handler: tuple[str, str],
        visiting: set[tuple[str, str]],
    ) -> bool:
        if handler in visiting:
            return False
        if not reaches_sink(handler, set()) or not reaches_control(handler, set()):
            return False
        sink_positions = list(sink_positions_by_handler.get(handler, []))
        control_positions = [control_position] if handler == control_handler else []
        next_visiting = {*visiting, handler}
        for call in calls_by_handler.get(handler, []):
            position = _fact_position(call)
            next_handler = callee_identity(handler, call)
            if position is None or next_handler is None:
                continue
            reaches_a_sink = reaches_sink(next_handler, set())
            reaches_the_control = reaches_control(next_handler, set())
            if reaches_a_sink:
                sink_positions.append(position)
            if reaches_the_control:
                control_positions.append(position)
            if (
                reaches_a_sink
                and reaches_the_control
                and sink_precedes_control(next_handler, next_visiting)
            ):
                return True
        return bool(
            sink_positions
            and control_positions
            and min(sink_positions) < min(control_positions)
        )

    return any(
        sink_precedes_control(root, set())
        for root in roots
        if reaches_sink(root, set()) and reaches_control(root, set())
    )


def _fact_line(fact: CodebaseFactCandidate) -> int | None:
    if not isinstance(fact.payload, dict):
        return None
    line = fact.payload.get("line")
    return line if isinstance(line, int) else None


def _fact_position(fact: CodebaseFactCandidate) -> tuple[int, int] | None:
    line = _fact_line(fact)
    if line is None:
        return None
    column = fact.payload.get("column") if isinstance(fact.payload, dict) else None
    return line, column if isinstance(column, int) else 0


def _fact_token_ref(fact: CodebaseFactCandidate) -> str | None:
    if not isinstance(fact.payload, dict):
        return None
    token_ref = fact.payload.get("token_ref")
    return token_ref if isinstance(token_ref, str) and token_ref.startswith("token:") else None


def _fact_claim_ref(fact: CodebaseFactCandidate) -> str | None:
    if not isinstance(fact.payload, dict):
        return None
    return safe_claim_reference(fact.payload.get("claims_ref"))


def _fact_input_ref(fact: CodebaseFactCandidate) -> str | None:
    if not isinstance(fact.payload, dict):
        return None
    if fact.payload.get("input_ref_kind") != INPUT_REFERENCE_KIND_STRAIGHT_LINE:
        return None
    return safe_input_reference(fact.payload.get("input_ref"))


def _fact_guard_input_refs(fact: CodebaseFactCandidate) -> frozenset[str]:
    if not isinstance(fact.payload, dict):
        return frozenset()
    if fact.payload.get("input_ref_kind") != INPUT_REFERENCE_KIND_STRAIGHT_LINE:
        return frozenset()
    return frozenset(
        input_ref
        for value in (
            fact.payload.get("input_ref"),
            fact.payload.get("validated_output_ref"),
        )
        if (input_ref := safe_input_reference(value)) is not None
    )


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
    if canonicalized and canonicalized.issubset(STATE_TRANSITION_SINK_NAMES):
        return (
            "missing_transactional_state_guard",
            (
                "One-time, quota, and limited-resource state transitions must use an "
                "explicit transactional or conditional-write guard before the transition sink."
            ),
            "missing_handler_transactional_state_check",
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
    *,
    include_action_dependent_lifecycle: bool = True,
) -> set[tuple[str, str]]:
    calls_by_handler: dict[tuple[str, str], list[CodebaseFactCandidate]] = {}
    earliest_sink_position: dict[tuple[str, str], tuple[int, int]] = {}
    identities_by_symbol = _handler_identities_by_symbol(facts)
    service_identities = _service_handler_identities(facts)
    for fact in facts:
        if fact.fact_type == "sensitive_sink" and isinstance(fact.payload, dict):
            sink_handler = _fact_handler_identity(fact, "handler")
            position = _fact_position(fact)
            if sink_handler is not None and position is not None:
                previous = earliest_sink_position.get(sink_handler)
                if previous is None or position < previous:
                    earliest_sink_position[sink_handler] = position
        if fact.fact_type != "service_call" or not isinstance(fact.payload, dict):
            continue
        if (
            not include_action_dependent_lifecycle
            and fact.payload.get("lifecycle_action_dependent") is True
        ):
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
            if not _service_call_precedes_handler_sink(call, earliest_sink_position):
                continue
            callee = call.symbol_name
            if not isinstance(callee, str):
                continue
            callee_identity = _resolve_service_call_identity(
                call,
                caller_source_path=caller[0],
                identities_by_symbol=identities_by_symbol,
                service_identities=service_identities,
            )
            if callee_identity is None or callee_identity in seen:
                continue
            seen.add(callee_identity)
            reachable.add(callee_identity)
            pending.append(callee_identity)
    return reachable


def reachable_service_source_paths(
    facts: list[CodebaseFactCandidate],
    *,
    source_path: str,
    handler: str,
) -> set[str]:
    """Return source files reached through statically unambiguous local calls."""
    if not source_path or not handler:
        return set()
    return {
        source_path,
        *(path for path, _ in _reachable_service_handlers(facts, source_path, handler)),
    }


def _service_call_precedes_handler_sink(
    fact: CodebaseFactCandidate,
    earliest_sink_position: dict[tuple[str, str], tuple[int, int]],
) -> bool:
    caller = _fact_handler_identity(fact, "caller")
    position = _fact_position(fact)
    sink_position = (
        earliest_sink_position.get(caller) if caller is not None else None
    )
    return position is None or sink_position is None or position < sink_position


def _indent_width(line: str) -> int:
    expanded = line.expandtabs()
    return len(expanded) - len(expanded.lstrip(" "))


def _called_names(
    line: str,
    *,
    outbound_http_aliases: dict[str, str],
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
            if token.string in outbound_http_aliases:
                calls.append(token.string)
                continue
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
                qualified_outbound_name = f"{qualifier}.{token.string}"
                if qualified_outbound_name in outbound_http_aliases:
                    calls.append(qualified_outbound_name)
                    continue
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


def _python_outbound_http_aliases(content: str) -> dict[str, str]:
    """Resolve explicit requests/httpx module aliases without generic get/post guesses."""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return {}
    aliases: dict[str, str] = {}
    for statement in tree.body:
        if not isinstance(statement, ast.Import):
            continue
        for imported in statement.names:
            module = imported.name.lower()
            if module not in _PYTHON_OUTBOUND_HTTP_MODULES:
                continue
            alias = imported.asname or module
            for method in _PYTHON_OUTBOUND_HTTP_METHODS:
                aliases[f"{alias}.{method}"] = "fetch"
    return aliases


def _python_outbound_http_input_index(
    call_name: str,
    outbound_http_aliases: dict[str, str],
) -> int | None:
    if call_name not in outbound_http_aliases:
        return None
    return 1 if call_name.rsplit(".", 1)[-1] == "request" else 0


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
    method_view_classes: set[str],
    self_called_names: set[str],
    import_aliases: dict[str, str],
    outbound_http_aliases: dict[str, str],
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
        if current_class in method_view_classes:
            return f"{current_class}.{call_name}"
    if call_name in outbound_http_aliases:
        return outbound_http_aliases[call_name]
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


def _method_decorator_authz_refs(
    line: str,
    line_number: int,
    import_aliases: dict[str, str],
) -> tuple[str | None, list[tuple[str, int]]] | None:
    source = line.strip()
    if not source.startswith("@"):
        return None
    try:
        tree = ast.parse(f"{source}\ndef decorated_method():\n    pass")
    except SyntaxError:
        return None
    if not tree.body or not isinstance(tree.body[0], ast.FunctionDef):
        return None
    decorators = tree.body[0].decorator_list
    if len(decorators) != 1 or not isinstance(decorators[0], ast.Call):
        return None
    decorator = decorators[0]
    decorator_name = _python_call_name(decorator.func)
    if (
        decorator_name is None
        or not _is_method_decorator_name(decorator_name, import_aliases)
    ):
        return None
    method_name_values = [
        _static_string(keyword.value)
        for keyword in decorator.keywords
        if keyword.arg == "name"
    ]
    if method_name_values and method_name_values[0] is None:
        return None
    if method_name_values:
        method_name = method_name_values[0]
    elif len(decorator.args) > 1:
        method_name = _static_string(decorator.args[1])
        if method_name is None:
            return None
    else:
        method_name = None
    wrapped_values = (
        decorator.args[0]
        if decorator.args
        else next(
            (
                keyword.value
                for keyword in decorator.keywords
                if keyword.arg == "decorator"
            ),
            None,
        )
    )
    if wrapped_values is None:
        return None
    wrapped_decorators = (
        wrapped_values.elts
        if isinstance(wrapped_values, (ast.List, ast.Tuple))
        else [wrapped_values]
    )
    refs: list[tuple[str, int]] = []
    for wrapped in wrapped_decorators:
        if isinstance(wrapped, ast.Call):
            wrapped = wrapped.func
        wrapped_name = _python_call_name(wrapped)
        if wrapped_name is None:
            continue
        resolved_name = import_aliases.get(
            wrapped_name,
            import_aliases.get(wrapped_name.rsplit(".", 1)[-1], wrapped_name),
        )
        if _is_authz_call(resolved_name):
            refs.append((resolved_name, line_number))
    return (method_name.lower() if method_name is not None else None), _dedupe_refs(refs)


def _method_decorator_closed(lines: list[str]) -> bool:
    source = "\n".join(lines).strip()
    try:
        ast.parse(f"{source}\ndef decorated_method():\n    pass")
    except SyntaxError:
        return False
    return True


def _is_method_decorator_start(
    line: str,
    import_aliases: dict[str, str],
) -> bool:
    match = METHOD_DECORATOR_START_PATTERN.match(line)
    return (
        match is not None
        and _is_method_decorator_name(match.group("name"), import_aliases)
    )


def _is_method_decorator_name(
    decorator_name: str,
    import_aliases: dict[str, str],
) -> bool:
    resolved_name = import_aliases.get(
        decorator_name,
        import_aliases.get(
            decorator_name.rsplit(".", 1)[-1],
            decorator_name,
        ),
    )
    return resolved_name.rsplit(".", 1)[-1] == "method_decorator"


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


def _python_unverified_jwt_decode(
    line: str,
    token_aliases: dict[str, str],
) -> tuple[str, int, str | None, str | None] | None:
    calls = _python_unverified_jwt_decodes(line, token_aliases)
    return calls[0] if calls else None


def _python_unverified_jwt_decodes(
    line: str,
    token_aliases: dict[str, str],
    *,
    ambiguous_token_aliases: set[str] | None = None,
    ambiguous_claim_references: set[str] | None = None,
) -> list[tuple[str, int, str | None, str | None]]:
    return _python_jwt_calls(
        line,
        token_aliases=token_aliases,
        ambiguous_token_aliases=ambiguous_token_aliases,
        ambiguous_claim_references=ambiguous_claim_references,
        is_match=lambda call_name, call: (
            call_name.lower() == "jwt.decode"
            and _python_decode_disables_signature_verification(call)
        ),
    )


def _python_jwt_verification(
    line: str,
    token_aliases: dict[str, str],
) -> tuple[str, int, str | None, str | None] | None:
    calls = _python_jwt_verifications(line, token_aliases)
    return calls[0] if calls else None


def _python_jwt_verifications(
    line: str,
    token_aliases: dict[str, str],
    *,
    ambiguous_token_aliases: set[str] | None = None,
    ambiguous_claim_references: set[str] | None = None,
) -> list[tuple[str, int, str | None, str | None]]:
    return _python_jwt_calls(
        line,
        token_aliases=token_aliases,
        ambiguous_token_aliases=ambiguous_token_aliases,
        ambiguous_claim_references=ambiguous_claim_references,
        is_match=lambda call_name, _call: call_name.lower()
        in {"jwt.verify", "jwt.validate"},
    )


def _python_jwt_calls(
    line: str,
    *,
    token_aliases: dict[str, str],
    ambiguous_token_aliases: set[str] | None = None,
    ambiguous_claim_references: set[str] | None = None,
    is_match: object,
) -> list[tuple[str, int, str | None, str | None]]:
    tree = _python_line_tree(line)
    if tree is None:
        return []
    indentation = len(line) - len(line.lstrip())
    matched_calls: list[tuple[str, int, str | None, str | None]] = []
    output_claim_refs = _python_direct_jwt_call_claim_refs(
        tree,
        ambiguous_references=ambiguous_claim_references,
    )
    calls = sorted(
        (node for node in ast.walk(tree) if isinstance(node, ast.Call)),
        key=lambda node: node.col_offset,
    )
    for node in calls:
        if not isinstance(node, ast.Call):
            continue
        call_name = _python_call_name(node.func)
        if call_name is None or not callable(is_match) or not is_match(call_name, node):
            continue
        aliases_before_call = _python_jwt_token_aliases_before(
            tree,
            token_aliases,
            before_column=node.col_offset,
            ambiguous_token_aliases=ambiguous_token_aliases,
        )
        token_ref = (
            _python_jwt_token_reference(
                node.args[0],
                aliases_before_call,
                ambiguous_token_aliases=ambiguous_token_aliases,
            )
            if node.args
            else None
        )
        matched_calls.append(
            (
                call_name,
                indentation + node.col_offset,
                token_ref,
                output_claim_refs.get(id(node)),
            )
        )
    return matched_calls


def _python_direct_jwt_call_claim_refs(
    tree: ast.Module,
    *,
    ambiguous_references: set[str] | None = None,
) -> dict[int, str]:
    output_refs: dict[int, str] = {}
    ambiguous = ambiguous_references or set()
    for statement in tree.body:
        call: ast.Call | None = None
        target: ast.expr | None = None
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            call = statement.value if isinstance(statement.value, ast.Call) else None
            target = statement.targets[0]
        elif isinstance(statement, ast.AnnAssign):
            call = statement.value if isinstance(statement.value, ast.Call) else None
            target = statement.target
        if call is None or not isinstance(target, ast.Name) or target.id in ambiguous:
            continue
        if claim_ref := structural_claim_reference(target.id):
            output_refs[id(call)] = claim_ref
    return output_refs


def _python_unverified_jwt_decode_name(line: str) -> str | None:
    result = _python_unverified_jwt_decode(line, {})
    return result[0] if result is not None else None


def _python_jwt_verification_name(line: str) -> str | None:
    result = _python_jwt_verification(line, {})
    return result[0] if result is not None else None


def _python_ambiguous_jwt_token_aliases(content: str) -> dict[str, set[str]]:
    """Reuse assignment ambiguity tracking before equating token aliases."""
    return _python_ambiguous_input_references(content)


def _update_python_jwt_token_aliases(
    line: str,
    token_aliases: dict[str, str],
    *,
    ambiguous_token_aliases: set[str] | None = None,
) -> None:
    tree = _python_line_tree(line)
    if tree is None:
        return
    for statement in tree.body:
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
            value = statement.value
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            target = statement.target
            value = statement.value
        else:
            continue
        if not isinstance(target, ast.Name):
            continue
        if target.id in (ambiguous_token_aliases or set()):
            token_aliases.pop(target.id, None)
            continue
        token_ref = _python_jwt_token_reference(
            value,
            token_aliases,
            ambiguous_token_aliases=ambiguous_token_aliases,
        )
        if token_ref is None:
            token_aliases.pop(target.id, None)
        else:
            token_aliases[target.id] = token_ref


def _python_jwt_token_aliases_before(
    tree: ast.Module,
    token_aliases: dict[str, str],
    *,
    before_column: int,
    ambiguous_token_aliases: set[str] | None = None,
) -> dict[str, str]:
    aliases = dict(token_aliases)
    for statement in tree.body:
        if statement.col_offset >= before_column:
            continue
        if isinstance(statement, ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
            value = statement.value
        elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
            target = statement.target
            value = statement.value
        else:
            continue
        if not isinstance(target, ast.Name):
            continue
        if target.id in (ambiguous_token_aliases or set()):
            aliases.pop(target.id, None)
            continue
        token_ref = _python_jwt_token_reference(
            value,
            aliases,
            ambiguous_token_aliases=ambiguous_token_aliases,
        )
        if token_ref is None:
            aliases.pop(target.id, None)
        else:
            aliases[target.id] = token_ref
    return aliases


def _python_jwt_token_reference(
    value: ast.expr,
    token_aliases: dict[str, str],
    *,
    ambiguous_token_aliases: set[str] | None = None,
) -> str | None:
    if isinstance(value, ast.Name):
        if value.id in (ambiguous_token_aliases or set()):
            return None
        return token_aliases.get(value.id, f"token:{value.id}")
    if isinstance(value, ast.Attribute):
        if path := _python_reference_path(value):
            return f"token:{path}"
        return None
    if isinstance(value, ast.Subscript):
        if path := _python_reference_path(value.value):
            if selector := _python_token_selector(value.slice):
                return f"token:{path}.{selector}"
        return None
    if isinstance(value, ast.Call):
        if name := _python_call_name(value.func):
            if value.args and (selector := _python_token_selector(value.args[0])):
                return f"token:{name}.{selector}"
            return f"token:{name}"
        return None
    if isinstance(value, ast.BoolOp) and isinstance(value.op, (ast.Or, ast.And)):
        refs = {
            ref
            for item in value.values
            if (
                ref := _python_jwt_token_reference(
                    item,
                    token_aliases,
                    ambiguous_token_aliases=ambiguous_token_aliases,
                )
            )
            is not None
        }
        return next(iter(refs)) if len(refs) == 1 else None
    return None


def _python_reference_path(value: ast.expr) -> str | None:
    if isinstance(value, ast.Name):
        return value.id
    if isinstance(value, ast.Attribute):
        parent = _python_reference_path(value.value)
        return f"{parent}.{value.attr}" if parent else None
    return None


def _python_token_selector(value: ast.expr) -> str | None:
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        normalized = re.sub(r"[^A-Za-z0-9]+", "_", value.value).strip("_").lower()
        return f"key_{normalized}" if normalized else None
    if isinstance(value, ast.Name):
        return f"key_{value.id}"
    return None


def _python_call_columns(line: str) -> dict[str, list[int]]:
    tree = _python_line_tree(line)
    if tree is None:
        return {}
    indentation = len(line) - len(line.lstrip())
    columns: dict[str, list[int]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        call_name = _python_call_name(node.func)
        if call_name is None:
            continue
        columns.setdefault(call_name.rsplit(".", 1)[-1], []).append(
            indentation + node.col_offset
        )
    for values in columns.values():
        values.sort()
    return columns


def _python_ambiguous_input_references(content: str) -> dict[str, set[str]]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return {}

    class _AssignmentCollector(ast.NodeVisitor):
        def __init__(self) -> None:
            self.counts: dict[str, int] = {}
            self.attribute_writes = False
            self.loop_writes: set[str] = set()

        def _record_target(
            self,
            target: ast.expr,
            *,
            loop_binding: bool = False,
        ) -> None:
            if isinstance(target, (ast.Tuple, ast.List)):
                for item in target.elts:
                    self._record_target(item, loop_binding=loop_binding)
                return
            if isinstance(target, ast.Starred):
                self._record_target(target.value, loop_binding=loop_binding)
                return
            if isinstance(target, ast.Subscript):
                self.attribute_writes = True
                return
            path = _python_reference_path(target)
            if path is None:
                return
            self.counts[path] = self.counts.get(path, 0) + 1
            if loop_binding:
                self.loop_writes.add(path)
            if "." in path:
                self.attribute_writes = True

        def visit_Assign(self, node: ast.Assign) -> None:
            for target in node.targets:
                self._record_target(target)
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            self._record_target(node.target)
            self.generic_visit(node)

        def visit_AugAssign(self, node: ast.AugAssign) -> None:
            self._record_target(node.target)
            self.generic_visit(node)

        def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
            self._record_target(node.target)
            self.generic_visit(node)

        def visit_For(self, node: ast.For) -> None:
            self._record_target(node.target, loop_binding=True)
            self.generic_visit(node)

        def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
            self._record_target(node.target, loop_binding=True)
            self.generic_visit(node)

        def visit_While(self, node: ast.While) -> None:
            self.generic_visit(node)

        def visit_If(self, node: ast.If) -> None:
            self.generic_visit(node)

        def visit_Try(self, node: ast.Try) -> None:
            self.generic_visit(node)

        def visit_Match(self, node: ast.Match) -> None:
            for case in node.cases:
                for pattern in ast.walk(case.pattern):
                    if isinstance(pattern, ast.MatchAs) and pattern.name:
                        self._record_target(
                            ast.Name(id=pattern.name),
                            loop_binding=True,
                        )
                    elif isinstance(pattern, ast.MatchStar) and pattern.name:
                        self._record_target(
                            ast.Name(id=pattern.name),
                            loop_binding=True,
                        )
                    elif isinstance(pattern, ast.MatchMapping) and pattern.rest:
                        self._record_target(
                            ast.Name(id=pattern.rest),
                            loop_binding=True,
                        )
            self.generic_visit(node)

        def visit_comprehension(self, node: ast.comprehension) -> None:
            self._record_target(node.target, loop_binding=True)
            self.generic_visit(node)

        def visit_With(self, node: ast.With) -> None:
            for item in node.items:
                if item.optional_vars is not None:
                    self._record_target(item.optional_vars)
            self.generic_visit(node)

        def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
            for item in node.items:
                if item.optional_vars is not None:
                    self._record_target(item.optional_vars)
            self.generic_visit(node)

        def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
            if node.name:
                self._record_target(ast.Name(id=node.name))
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            return

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return

    ambiguous_by_function: dict[str, set[str]] = {}
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        collector = _AssignmentCollector()
        for statement in function.body:
            collector.visit(statement)
        parameter_names = {
            argument.arg
            for argument in (
                *function.args.posonlyargs,
                *function.args.args,
                *function.args.kwonlyargs,
            )
        }
        if function.args.vararg is not None:
            parameter_names.add(function.args.vararg.arg)
        if function.args.kwarg is not None:
            parameter_names.add(function.args.kwarg.arg)
        ambiguous = {
            *collector.loop_writes,
            *(path for path, count in collector.counts.items() if count > 1),
            *(
                path
                for path in collector.counts
                if path in parameter_names
            ),
            *(
                {INPUT_ATTRIBUTE_MUTATION_MARKER}
                if collector.attribute_writes
                else set()
            ),
        }
        if ambiguous:
            ambiguous_by_function.setdefault(function.name, set()).update(ambiguous)
    return ambiguous_by_function


def _python_ambiguous_jwt_token_aliases(content: str) -> dict[str, set[str]]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return {}

    class _ConditionalAliasCollector(ast.NodeVisitor):
        def __init__(self) -> None:
            self.depth = 0
            self.aliases: set[str] = set()

        def _visit_conditional(self, node: ast.AST) -> None:
            self.depth += 1
            self.generic_visit(node)
            self.depth -= 1

        def _record_target(self, target: ast.expr) -> None:
            if self.depth and isinstance(target, ast.Name):
                self.aliases.add(target.id)

        def visit_Assign(self, node: ast.Assign) -> None:
            for target in node.targets:
                self._record_target(target)
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            self._record_target(node.target)
            self.generic_visit(node)

        def visit_AugAssign(self, node: ast.AugAssign) -> None:
            self._record_target(node.target)
            self.generic_visit(node)

        def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
            self._record_target(node.target)
            self.generic_visit(node)

        def visit_If(self, node: ast.If) -> None:
            self._visit_conditional(node)

        def visit_For(self, node: ast.For) -> None:
            self._visit_conditional(node)

        def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
            self._visit_conditional(node)

        def visit_While(self, node: ast.While) -> None:
            self._visit_conditional(node)

        def visit_Try(self, node: ast.Try) -> None:
            self._visit_conditional(node)

        def visit_Match(self, node: ast.Match) -> None:
            self._visit_conditional(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            return

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return

    aliases_by_function: dict[str, set[str]] = {}
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        collector = _ConditionalAliasCollector()
        for statement in function.body:
            collector.visit(statement)
        if collector.aliases:
            aliases_by_function[function.name] = collector.aliases
    return aliases_by_function


def _python_conditional_call_columns(
    content: str,
) -> dict[str, dict[int, set[int]]]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return {}

    class _ConditionalCallCollector(ast.NodeVisitor):
        def __init__(self) -> None:
            self.depth = 0
            self.columns: dict[int, set[int]] = {}

        def _visit_conditional(self, node: ast.AST) -> None:
            self.depth += 1
            self.generic_visit(node)
            self.depth -= 1

        def visit_If(self, node: ast.If) -> None:
            self._visit_conditional(node)

        def visit_For(self, node: ast.For) -> None:
            self._visit_conditional(node)

        def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
            self._visit_conditional(node)

        def visit_While(self, node: ast.While) -> None:
            self._visit_conditional(node)

        def visit_Try(self, node: ast.Try) -> None:
            self._visit_conditional(node)

        def visit_Match(self, node: ast.Match) -> None:
            self._visit_conditional(node)

        def visit_BoolOp(self, node: ast.BoolOp) -> None:
            self._visit_conditional(node)

        def visit_IfExp(self, node: ast.IfExp) -> None:
            self._visit_conditional(node)

        def visit_Call(self, node: ast.Call) -> None:
            if self.depth:
                self.columns.setdefault(node.lineno, set()).add(node.col_offset)
            self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            return

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            return

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            return

    columns_by_function: dict[str, dict[int, set[int]]] = {}
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        collector = _ConditionalCallCollector()
        for statement in function.body:
            collector.visit(statement)
        if collector.columns:
            columns_by_function.setdefault(function.name, {}).update(
                collector.columns
            )
    return columns_by_function


def _python_call_input_refs(
    line: str,
    *,
    ambiguous_references: set[str] | None = None,
    conditional_columns: set[int] | None = None,
) -> dict[str, list[tuple[list[str | None], str | None]]]:
    tree = _python_line_tree(line)
    if tree is None:
        return {}
    indentation = len(line) - len(line.lstrip())
    input_refs: dict[str, list[tuple[list[str | None], str | None]]] = {}
    output_refs = _python_direct_call_output_refs(tree)
    calls = sorted(
        (node for node in ast.walk(tree) if isinstance(node, ast.Call)),
        key=lambda node: node.col_offset,
    )
    for node in calls:
        call_name = _python_call_name(node.func)
        if call_name is None:
            continue
        input_refs.setdefault(call_name.rsplit(".", 1)[-1], []).append(
            (
                [
                    _python_input_reference(
                        argument,
                        ambiguous_references=ambiguous_references,
                    )
                    for argument in node.args
                ],
                output_refs.get(id(node)),
            )
            if indentation + node.col_offset not in (conditional_columns or set())
            else ([], None)
        )
    return input_refs


def _pop_python_call_input_refs(
    input_refs: dict[str, list[tuple[list[str | None], str | None]]],
    call_name: str,
) -> tuple[list[str | None], str | None]:
    values = input_refs.get(call_name.rsplit(".", 1)[-1])
    return values.pop(0) if values else ([], None)


def _python_call_claim_refs(
    line: str,
    *,
    ambiguous_references: set[str] | None = None,
    conditional_columns: set[int] | None = None,
) -> dict[str, list[str | None]]:
    tree = _python_line_tree(line)
    if tree is None:
        return {}
    indentation = len(line) - len(line.lstrip())
    claim_refs: dict[str, list[str | None]] = {}
    for node in sorted(
        (node for node in ast.walk(tree) if isinstance(node, ast.Call)),
        key=lambda node: node.col_offset,
    ):
        call_name = _python_call_name(node.func)
        if call_name is None:
            continue
        claim_refs.setdefault(call_name.rsplit(".", 1)[-1], []).append(
            _python_claim_reference(
                node.args[0],
                ambiguous_references=ambiguous_references,
            )
            if (
                node.args
                and indentation + node.col_offset not in (conditional_columns or set())
            )
            else None
        )
    return claim_refs


def _pop_python_call_claim_ref(
    claim_refs: dict[str, list[str | None]],
    call_name: str,
) -> str | None:
    values = claim_refs.get(call_name.rsplit(".", 1)[-1])
    return values.pop(0) if values else None


def _python_claim_reference(
    value: ast.expr,
    *,
    ambiguous_references: set[str] | None = None,
) -> str | None:
    if isinstance(value, (ast.Attribute, ast.Subscript)):
        return _python_claim_reference(
            value.value,
            ambiguous_references=ambiguous_references,
        )
    if not isinstance(value, ast.Name):
        return None
    if value.id in (ambiguous_references or set()):
        return None
    return structural_claim_reference(value.id)


def _python_direct_call_output_refs(tree: ast.Module) -> dict[int, str]:
    output_refs: dict[int, str] = {}
    for node in ast.walk(tree):
        call: ast.Call | None = None
        target: ast.expr | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            call = node.value if isinstance(node.value, ast.Call) else None
            target = node.targets[0]
        elif isinstance(node, ast.AnnAssign):
            call = node.value if isinstance(node.value, ast.Call) else None
            target = node.target
        if call is None or not isinstance(target, ast.Name):
            continue
        if output_ref := structural_input_reference(target.id):
            output_refs[id(call)] = output_ref
    return output_refs


def _python_input_reference(
    value: ast.expr,
    *,
    ambiguous_references: set[str] | None = None,
) -> str | None:
    path = _python_reference_path(value)
    references = ambiguous_references or set()
    if INPUT_FLOW_UNSAFE_MARKER in references:
        return None
    if (
        path is not None
        and INPUT_ATTRIBUTE_MUTATION_MARKER in references
        and "." in path
    ):
        return None
    if path is not None and any(
        path == reference or path.startswith(reference + ".")
        for reference in references
    ):
        return None
    return structural_input_reference(path) if path is not None else None


def _pop_python_call_column(
    columns: dict[str, list[int]],
    call_name: str,
) -> int | None:
    values = columns.get(call_name.rsplit(".", 1)[-1])
    return values.pop(0) if values else None


def _python_line_tree(line: str) -> ast.Module | None:
    try:
        return ast.parse(line.lstrip())
    except SyntaxError:
        return None


def _python_call_name(value: ast.expr) -> str | None:
    if isinstance(value, ast.Name):
        return value.id
    if isinstance(value, ast.Attribute):
        parent = _python_call_name(value.value)
        return f"{parent}.{value.attr}" if parent else None
    return None


def _python_decode_disables_signature_verification(call: ast.Call) -> bool:
    for keyword in call.keywords:
        if keyword.arg == "verify" and _python_false_literal(keyword.value):
            return True
        if keyword.arg == "options" and _python_options_disable_signature_verification(
            keyword.value
        ):
            return True
    return False


def _python_options_disable_signature_verification(value: ast.expr) -> bool:
    if isinstance(value, ast.Dict):
        return any(
            isinstance(key, ast.Constant)
            and key.value == "verify_signature"
            and _python_false_literal(option)
            for key, option in zip(value.keys, value.values, strict=True)
        )
    if _python_call_name(value) != "dict" or not isinstance(value, ast.Call):
        return False
    return any(
        keyword.arg == "verify_signature" and _python_false_literal(keyword.value)
        for keyword in value.keywords
    )


def _python_false_literal(value: ast.expr) -> bool:
    return isinstance(value, ast.Constant) and value.value is False


def _is_authz_call(call_name: str) -> bool:
    normalized = call_name.lower()
    if _is_jwt_verification_control(call_name):
        return True
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
    if _is_transactional_state_guard_name(normalized):
        return True
    if _is_agent_tool_guard_name(normalized):
        return True
    return _is_injection_guard_name(normalized)


def _authz_hint(call_name: str) -> str:
    normalized = call_name.lower()
    if _is_jwt_verification_control(call_name):
        return "jwt_verification_check"
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
    if _is_transactional_state_guard_name(normalized):
        return "transactional_state_guard"
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
        service_class = None
        service_receiver = None
        target_service_class = None
        target_service_source_path = None
        line = None
        column = None
        token_ref = None
        input_ref = None
        if isinstance(fact.payload, dict):
            if fact.fact_type == "service_call":
                caller = fact.payload.get("caller")
            if fact.fact_type in {
                "sensitive_sink",
                "authz_check",
                "authorization_gap_candidate",
                "service_call",
                "unverified_token_decode",
            }:
                handler = fact.payload.get("handler")
            line = fact.payload.get("line")
            column = fact.payload.get("column")
            token_ref = fact.payload.get("token_ref")
            input_ref = fact.payload.get("input_ref")
            service_class = fact.payload.get("service_class")
            service_receiver = fact.payload.get("service_receiver")
            target_service_class = fact.payload.get("target_service_class")
            target_service_source_path = fact.payload.get("target_service_source_path")
        key = (
            fact.fact_type,
            fact.source_path,
            fact.symbol_name,
            fact.route_method,
            fact.route_path,
            fact.authz_hint,
            caller,
            handler,
            service_class,
            service_receiver,
            target_service_class,
            target_service_source_path,
            line,
            column,
            token_ref,
            input_ref,
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
    authz_index_by_handler: dict[tuple[str, str, str], int] = {}
    for fact in facts:
        handler = fact.payload.get("handler") if isinstance(fact.payload, dict) else None
        if fact.fact_type != "authz_check" or not isinstance(handler, str):
            deduped.append(fact)
            continue
        key = (fact.source_path, handler, _fact_service_class(fact) or "")
        if fact.authz_hint in {
            "jwt_verification_check",
            "ssrf_validation_check",
        }:
            deduped.append(fact)
            continue
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
    if authz_hint == "transactional_state_guard":
        return 4
    if authz_hint == "agent_tool_authorization_check":
        return 4
    if authz_hint == "jwt_verification_check":
        return 4
    if authz_hint == "permission_check":
        return 3
    if authz_hint == "role_check":
        return 2
    return 1


def _count_facts(facts: list[CodebaseFactCandidate], fact_type: str) -> int:
    return sum(1 for fact in facts if fact.fact_type == fact_type)
