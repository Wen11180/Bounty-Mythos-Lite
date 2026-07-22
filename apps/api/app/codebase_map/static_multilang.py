"""Static multi-language mapping for Java/Spring, Go, Rails/Ruby, C#, and PHP.

Emits route_handler / authz_check / sensitive_sink / service_call facts so
Candidate Hunter can refute real object-ownership guards (including service
layer, middleware, before_action) and retain invalid role/status/guard-after-sink
patterns outside Python and TypeScript.

Scope remains falsify-first leadership across common server languages
(ownership + high-signal gap families: SSRF / path / injection / mass-assign /
explicit transactional state transitions),
not a full multi-language SAST engine. Breadth expands language×pattern coverage
for held-outs and production-shaped probes.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.codebase_map import CodebaseFactCandidate

MULTILANG_SOURCE_SUFFIXES = (".java", ".go", ".rb", ".cs", ".php", ".kt", ".rs", ".scala")

# Spring MVC / WebFlux style annotations.
_JAVA_MAPPING = re.compile(
    r"@(?P<method>Get|Post|Put|Patch|Delete)Mapping\s*\(\s*(?:value\s*=\s*)?[\"'](?P<path>[^\"']+)[\"']",
    re.IGNORECASE,
)
_JAVA_REQUEST_MAPPING = re.compile(
    r"@(?:[A-Za-z_][A-Za-z0-9_]*\.)*RequestMapping\s*\(\s*"
    r"(?:(?:value|path)\s*=\s*)?[\"'](?P<path>[^\"']+)[\"']\s*\)",
    re.IGNORECASE,
)
_JAVA_REQUEST_MAPPING_MARKER = re.compile(
    r"@(?:[A-Za-z_][A-Za-z0-9_]*\.)*RequestMapping\b",
    re.IGNORECASE,
)
_JAVA_REQUEST_MAPPING_ANNOTATION = re.compile(
    r"@(?:[A-Za-z_][A-Za-z0-9_]*\.)*RequestMapping\s*\("
    r"(?P<arguments>[^)]*)\)",
    re.IGNORECASE | re.DOTALL,
)
_JAVA_REQUEST_MAPPING_PATH_ARGUMENT = re.compile(
    r"(?:^|,)\s*(?:(?:value|path)\s*=\s*)?[\"'](?P<path>[^\"']+)[\"']",
    re.IGNORECASE,
)
_JAVA_REQUEST_MAPPING_METHOD_ARGUMENT = re.compile(
    r"\bmethod\s*=\s*(?P<methods>\{[^}]*\}|"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\.)*RequestMethod\.(?:GET|POST|PUT|PATCH|DELETE))",
    re.IGNORECASE | re.DOTALL,
)
_JAVA_REQUEST_METHOD = re.compile(
    r"(?:[A-Za-z_][A-Za-z0-9_]*\.)*RequestMethod\."
    r"(?P<method>GET|POST|PUT|PATCH|DELETE)\b",
    re.IGNORECASE,
)
_JAVA_METHOD = re.compile(
    r"(?:public|protected|private|static|\s)+\S+\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*?\)\s*(?:throws\s+[^{]+)?\{",
    re.MULTILINE,
)
_JAVA_TRANSACTIONAL_ANNOTATION = re.compile(
    r"@(?:[A-Za-z_][A-Za-z0-9_]*\.)*Transactional\b"
    r"(?P<arguments>\s*\([^)]*\))?"
)
_JAVA_NON_TRANSACTIONAL_PROPAGATION = re.compile(
    r"\bpropagation\s*=\s*(?:[A-Za-z_][A-Za-z0-9_]*\.)*"
    r"(?:NOT_SUPPORTED|NEVER)\b",
    re.IGNORECASE,
)
_JAVA_DECLARATIVE_AUTHZ_ANNOTATION = re.compile(
    r"@(?:[A-Za-z_][A-Za-z0-9_]*\.)*"
    r"(?P<name>PreAuthorize|Secured|RolesAllowed)\b(?:\s*\([^)]*\))?",
    re.IGNORECASE,
)
_JAVA_CLASS_ANNOTATION_TAIL = re.compile(
    r"\s*(?:@(?:[A-Za-z_][A-Za-z0-9_]*\.)*[A-Za-z_][A-Za-z0-9_]*"
    r"(?:\s*\([^)]*\))?\s*)*"
    r"(?:(?:public|protected|private|abstract|final|static)\s*)*$",
    re.DOTALL,
)
_JAVA_CLASS = re.compile(
    r"\b(?:class|interface|enum)\s+[A-Za-z_][A-Za-z0-9_]*[^\{]*\{"
)

# Go: r.GET("/path", mw1, mw2, handler)
_GO_ROUTE_START = re.compile(
    r"\.(?P<method>GET|POST|PUT|PATCH|DELETE|HandleFunc|Handle)\s*\(\s*[\"'](?P<path>[^\"']+)[\"']",
    re.IGNORECASE,
)
_GO_FUNC = re.compile(
    r"\bfunc\s+(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
)
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Rails routes + before_action + method defs.
_RUBY_ROUTE = re.compile(
    r"\b(?P<method>get|post|put|patch|delete)\s+[\"'](?P<path>[^\"']+)[\"']"
    r"(?:\s*,\s*to:\s*[\"'][^\"'#]*#(?P<handler>[A-Za-z_][A-Za-z0-9_]*)[\"'])?",
    re.IGNORECASE,
)
_RUBY_BEFORE_ACTION = re.compile(
    r"\bbefore_action\s+:(?P<name>[A-Za-z_][A-Za-z0-9_?!]*)",
    re.IGNORECASE,
)
_RUBY_BEFORE_ACTION_SCOPE = re.compile(
    r"\b(?P<scope>only|except)\s*:\s*"
    r"(?P<actions>\[[^\]]*\]|%i\[[^\]]*\]|:[A-Za-z_][A-Za-z0-9_?!]*|[\"'][^\"']+[\"'])",
    re.IGNORECASE,
)
_RUBY_DEF = re.compile(r"^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_?!]*)", re.MULTILINE)

_COMPARISON = re.compile(
    r"(?P<left>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?:\s*\(\s*\))?)"
    r"\s*(?:===|!==|==|!=|<>)\s*"
    r"(?P<right>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?:\s*\(\s*\))?)"
)
_EQUALS_CALL = re.compile(
    r"(?P<left>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?:\s*\(\s*\))?)"
    r"\s*\.\s*equals\s*\(\s*"
    r"(?P<right>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*(?:\s*\(\s*\))?)\s*\)",
    re.IGNORECASE,
)
_CALL = re.compile(
    r"\b(?P<callee>[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*)\s*\("
)

_BOUNDARY_FIELDS = {
    "owner_id",
    "ownerid",
    "user_id",
    "userid",
    "created_by_id",
    "created_by",
    "author_id",
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

_PRINCIPAL_EXACT = {
    "user.id",
    "current_user.id",
    "auth.id",
    "auth.name",
    "authentication.id",
    "authentication.name",
    "req.user.id",
    "request.user.id",
    "security_context.user_id",
    "principal.id",
    "principal.name",
}

_PRINCIPAL_ROOTS = {
    "user",
    "current_user",
    "auth",
    "authentication",
    "principal",
    "req",
    "request",
    "security_context",
}

_ROLE_LINE = re.compile(
    r"(?:"
    r"(?:user|current_user|auth|authentication|principal|req\.user|request\.user)"
    r"\.(?:role|is_admin|isadmin|admin|has_role|hasrole)"
    r"|"
    r"(?:has_role|hasrole|is_admin|isadmin)\s*\("
    r"|"
    r"\.get_role\s*\(\s*\)"
    r"|"
    r"getrole\s*\(\s*\)"
    r")",
    re.IGNORECASE,
)

_SENSITIVE_SINKS = {
    "send_file",
    "sendfile",
    "send_payload",
    "read_file",
    "delete_file",
    "export_file",
    "get_blob",
    "transfer",
    "export",
    "delete",
    "update",
    "update_user",
    "apply_user_update",
    "persist_user",
    "fetch",
    "execute_query",
    "run_sql",
    "db_select",
    "advance_one_time_state",
    "claim_limited_resource",
    "consume_one_time_code",
    "consume_one_time_token",
    "consume_quota",
    "decrement_quota",
    "redeem_one_time_code",
    "redeem_one_time_token",
    "file",  # ASP.NET File()
    "physicalfile",
    "download",  # Laravel response download helper leaf
}
_STATE_TRANSITION_SINKS = {
    "advance_one_time_state",
    "claim_limited_resource",
    "consume_one_time_code",
    "consume_one_time_token",
    "consume_quota",
    "decrement_quota",
    "redeem_one_time_code",
    "redeem_one_time_token",
}

# Gap-family protective check markers (mirrored from codebase_map names).
_SSRF_GUARD_MARKERS = (
    "ssrf",
    "private_ip",
    "blocked_hostname",
    "validate_url",
    "is_private_ip",
    "is_blocked_hostname",
)
_PATH_GUARD_MARKERS = (
    "path_base",
    "filepath_base",
    "sanitize_filename",
    "make_filename",
    "safe_path",
    "safe_join",
    "path_traversal",
    "clean_filename",
)
_MASS_ASSIGN_GUARD_MARKERS = (
    "assert_user_change",
    "permission_attrs",
    "mass_assign",
    "field_allowlist",
    "forbid_privilege",
    "exclude_admin",
    "privilege_field",
)
_INJECTION_GUARD_MARKERS = (
    "make_search_string",
    "sanitize_sql",
    "parameterize",
    "bind_query",
    "escape_like",
    "sql_sanitize",
    "full_text_query",
    "regex_full_text",
)
_STATE_TRANSITION_GUARD_MARKERS = (
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
_GO_TRANSACTION_CALLBACK = re.compile(
    r"\b(?P<callee>(?:db|database)\.Transaction)\s*\(\s*func\b"
)
_RUBY_TRANSACTION_BLOCK = re.compile(
    r"\b(?P<callee>ApplicationRecord\.transaction)\b\s+(?P<block>do\b|\{)"
)

# Common non-service calls (noise).
_NON_SERVICE = {
    "if",
    "for",
    "while",
    "switch",
    "return",
    "throw",
    "new",
    "catch",
    "super",
    "this",
    "printf",
    "println",
    "print",
    "fmt",
    "error",
    "errors",
    "http",
    "load_record",
    "loadrecord",
    "deny",
    "next",
    "equals",
    "tostring",
    "valueof",
    "require",
    "include",
    "import",
    "len",
    "append",
    "make",
    "string",
    "int",
    "bool",
}


def is_static_multilang_path(source_path: str) -> bool:
    return source_path.lower().endswith(MULTILANG_SOURCE_SUFFIXES)


def map_static_multilang_file(
    *,
    source_path: str,
    content: str,
) -> list["CodebaseFactCandidate"]:
    lower = source_path.lower()
    if lower.endswith(".java"):
        return _map_java_file(source_path=source_path, content=content)
    if lower.endswith(".go"):
        return _map_go_file(source_path=source_path, content=content)
    if lower.endswith(".rb"):
        return _map_ruby_file(source_path=source_path, content=content)
    if lower.endswith(".cs"):
        return _map_csharp_file(source_path=source_path, content=content)
    if lower.endswith(".php"):
        return _map_php_file(source_path=source_path, content=content)
    if lower.endswith(".kt"):
        return _map_kotlin_file(source_path=source_path, content=content)
    if lower.endswith(".rs"):
        return _map_rust_file(source_path=source_path, content=content)
    if lower.endswith(".scala"):
        return _map_scala_file(source_path=source_path, content=content)
    return []


def _map_java_file(*, source_path: str, content: str) -> list["CodebaseFactCandidate"]:
    facts: list[CodebaseFactCandidate] = []
    methods = _java_methods(content)
    method_names = {name for name, _, _, _ in methods}
    route_handlers: set[str] = set()
    class_transactional_ranges = _java_transactional_class_ranges(content)
    class_route_prefixes = _java_class_route_prefixes(content)

    for method_name, declaration_start, _, _ in methods:
        direct_class_body_start = _java_direct_class_body_start(
            declaration_start,
            class_transactional_ranges,
        )
        annotation_line = _java_transactional_annotation_line(
            content,
            declaration_start=declaration_start,
            class_body_start=direct_class_body_start,
        )
        if annotation_line is None:
            annotation_line = _java_class_transactional_annotation_line(
                declaration_start,
                class_transactional_ranges,
            )
        if annotation_line is not None:
            facts.append(
                _fact(
                    fact_type="authz_check",
                    source_path=source_path,
                    symbol_name="Transactional",
                    route_method=None,
                    route_path=None,
                    handler=method_name,
                    line_number=annotation_line,
                    authz_hint="transactional_state_guard",
                )
            )
        declarative_authz = _java_method_declarative_authz_annotation(
            content,
            declaration_start=declaration_start,
            class_body_start=direct_class_body_start,
        )
        if declarative_authz is not None:
            annotation_name, annotation_line = declarative_authz
            facts.append(
                _fact(
                    fact_type="authz_check",
                    source_path=source_path,
                    symbol_name=annotation_name,
                    route_method=None,
                    route_path=None,
                    handler=method_name,
                    line_number=annotation_line,
                    authz_hint="role_check",
                )
            )

    scanned_route_handlers: set[str] = set()
    for (
        mapping_start,
        mapping_end,
        route_method,
        mapping_path,
    ) in _java_route_mappings(content):
        method_meta = None
        for meta in methods:
            name, decl_start, brace_at, body_text = meta
            if decl_start >= mapping_end:
                method_meta = meta
                break
        if method_meta is None:
            continue
        method_name, declaration_start, brace_at, body_text = method_meta
        route_path = _join_static_route_path(
            _java_class_route_prefix_for_method(
                declaration_start,
                class_route_prefixes,
            ),
            mapping_path,
        )
        route_line = content.count("\n", 0, mapping_start) + 1
        route_handlers.add(method_name)
        facts.append(
            _fact(
                fact_type="route_handler",
                source_path=source_path,
                symbol_name=method_name,
                route_method=route_method,
                route_path=route_path,
                handler=method_name,
                line_number=route_line,
            )
        )
        if method_name in scanned_route_handlers:
            continue
        scanned_route_handlers.add(method_name)
        facts.extend(
            _scan_handler_body(
                source_path=source_path,
                handler=method_name,
                body_text=body_text,
                body_start_offset=brace_at + 1,
                full_source=content,
                local_methods=method_names,
            )
        )

    # Service-layer helpers: scan non-route methods so ownership in service is visible.
    for name, _, brace_at, body_text in methods:
        if name in route_handlers:
            continue
        facts.extend(
            _scan_handler_body(
                source_path=source_path,
                handler=name,
                body_text=body_text,
                body_start_offset=brace_at + 1,
                full_source=content,
                local_methods=method_names,
            )
        )
    return facts


def _java_route_mappings(content: str) -> list[tuple[int, int, str, str]]:
    masked_content = _mask_multilang_non_code(content)
    mappings: list[tuple[int, int, str, str]] = []
    for mapping in _JAVA_MAPPING.finditer(content):
        if masked_content[mapping.start() : mapping.start() + 1] != "@":
            continue
        mappings.append(
            (
                mapping.start(),
                mapping.end(),
                mapping.group("method").upper(),
                mapping.group("path"),
            )
        )
    for mapping in _JAVA_REQUEST_MAPPING_ANNOTATION.finditer(content):
        if (
            masked_content[mapping.start() : mapping.start() + 1] != "@"
            or _java_request_mapping_is_class_annotation(
                masked_content,
                annotation_end=mapping.end(),
            )
        ):
            continue
        path_match = _JAVA_REQUEST_MAPPING_PATH_ARGUMENT.search(
            mapping.group("arguments")
        )
        method_match = _JAVA_REQUEST_MAPPING_METHOD_ARGUMENT.search(
            mapping.group("arguments")
        )
        if path_match is None or method_match is None:
            continue
        for method in {
            request_method.group("method").upper()
            for request_method in _JAVA_REQUEST_METHOD.finditer(
                method_match.group("methods")
            )
        }:
            mappings.append(
                (
                    mapping.start(),
                    mapping.end(),
                    method,
                    path_match.group("path"),
                )
            )
    return sorted(mappings)


def _java_request_mapping_is_class_annotation(
    masked_content: str,
    *,
    annotation_end: int,
) -> bool:
    class_match = _JAVA_CLASS.search(masked_content, annotation_end)
    return (
        class_match is not None
        and _JAVA_CLASS_ANNOTATION_TAIL.fullmatch(
            masked_content[annotation_end : class_match.start()]
        )
        is not None
    )


def _java_methods(content: str) -> list[tuple[str, int, int, str]]:
    methods: list[tuple[str, int, int, str]] = []
    for match in _JAVA_METHOD.finditer(content):
        name = match.group("name")
        if name in {"if", "for", "while", "switch", "catch", "class", "new"}:
            continue
        brace_at = match.end() - 1
        if brace_at < 0 or content[brace_at] != "{":
            brace_at = content.find("{", match.start())
        if brace_at < 0:
            continue
        body = _extract_brace_body(content, brace_at)
        if body is None:
            continue
        body_text, _ = body
        methods.append((name, match.start(), brace_at, body_text))
    return methods


def _java_class_route_prefixes(content: str) -> list[tuple[int, int, str]]:
    masked_content = _mask_multilang_non_code(content)
    ranges: list[tuple[int, int, str]] = []
    for match in _JAVA_CLASS.finditer(masked_content):
        brace_index = masked_content.rfind("{", match.start(), match.end())
        if brace_index < 0:
            continue
        body = _extract_brace_body(masked_content, brace_index)
        if body is None:
            continue
        _, body_end = body
        prefix = _java_class_route_prefix(
            source=content,
            masked_content=masked_content,
            class_start=match.start(),
        )
        if prefix is not None:
            ranges.append((brace_index, body_end, prefix))
    return ranges


def _java_class_route_prefix(
    *,
    source: str,
    masked_content: str,
    class_start: int,
) -> str | None:
    candidates = [
        match
        for match in _JAVA_REQUEST_MAPPING.finditer(source, 0, class_start)
        if _JAVA_REQUEST_MAPPING_MARKER.match(masked_content, match.start())
        and _JAVA_CLASS_ANNOTATION_TAIL.fullmatch(
            source[match.end() : class_start]
        )
    ]
    return candidates[-1].group("path") if candidates else None


def _java_class_route_prefix_for_method(
    declaration_start: int,
    prefixes: list[tuple[int, int, str]],
) -> str | None:
    matching = [
        (body_start, prefix)
        for body_start, body_end, prefix in prefixes
        if body_start < declaration_start < body_end
    ]
    return max(matching)[1] if matching else None


def _join_static_route_path(prefix: str | None, path: str) -> str:
    normalized_path = path.strip()
    if prefix is None or not prefix.strip("/"):
        return normalized_path if normalized_path.startswith("/") else f"/{normalized_path}"
    normalized_prefix = prefix.strip()
    if not normalized_prefix.startswith("/"):
        normalized_prefix = f"/{normalized_prefix}"
    normalized_prefix = normalized_prefix.rstrip("/")
    normalized_path = normalized_path.lstrip("/")
    return (
        normalized_prefix
        if not normalized_path
        else f"{normalized_prefix}/{normalized_path}"
    )


def _java_transactional_annotation_line(
    content: str,
    *,
    declaration_start: int,
    class_body_start: int | None,
) -> int | None:
    masked_prefix = _mask_multilang_non_code(content[:declaration_start])
    if class_body_start is None:
        annotation_start = masked_prefix.rfind("}") + 1
    else:
        annotation_start = max(
            class_body_start + 1,
            masked_prefix.rfind("}", class_body_start, declaration_start) + 1,
        )
    annotation_source = masked_prefix[annotation_start:]
    match = _supported_java_transactional_annotation(annotation_source)
    if match is None:
        return None
    return content.count("\n", 0, annotation_start + match.start()) + 1


def _supported_java_transactional_annotation(source: str) -> re.Match[str] | None:
    for match in _JAVA_TRANSACTIONAL_ANNOTATION.finditer(source):
        arguments = match.group("arguments") or ""
        if not _JAVA_NON_TRANSACTIONAL_PROPAGATION.search(arguments):
            return match
    return None


def _java_method_declarative_authz_annotation(
    content: str,
    *,
    declaration_start: int,
    class_body_start: int | None,
) -> tuple[str, int] | None:
    masked_prefix = _mask_multilang_non_code(content[:declaration_start])
    if class_body_start is None:
        annotation_start = masked_prefix.rfind("}") + 1
    else:
        annotation_start = max(
            class_body_start + 1,
            masked_prefix.rfind("}", class_body_start, declaration_start) + 1,
        )
    annotation_source = masked_prefix[annotation_start:]
    candidates = [
        match
        for match in _JAVA_DECLARATIVE_AUTHZ_ANNOTATION.finditer(annotation_source)
        if _JAVA_CLASS_ANNOTATION_TAIL.fullmatch(
            annotation_source[match.end() :]
        )
    ]
    if not candidates:
        return None
    annotation = candidates[-1]
    return (
        annotation.group("name"),
        content.count("\n", 0, annotation_start + annotation.start()) + 1,
    )


def _java_class_transactional_annotation(
    masked_content: str,
    *,
    class_start: int,
) -> re.Match[str] | None:
    candidates = [
        match
        for match in _JAVA_TRANSACTIONAL_ANNOTATION.finditer(
            masked_content,
            0,
            class_start,
        )
        if not _JAVA_NON_TRANSACTIONAL_PROPAGATION.search(
            match.group("arguments") or ""
        )
        and _JAVA_CLASS_ANNOTATION_TAIL.fullmatch(
            masked_content[match.end() : class_start]
        )
    ]
    return candidates[-1] if candidates else None


def _java_transactional_class_ranges(
    content: str,
) -> list[tuple[int, int, int | None]]:
    masked_content = _mask_multilang_non_code(content)
    ranges: list[tuple[int, int, int | None]] = []
    for match in _JAVA_CLASS.finditer(masked_content):
        brace_index = masked_content.rfind("{", match.start(), match.end())
        if brace_index < 0:
            continue
        body = _extract_brace_body(masked_content, brace_index)
        if body is None:
            continue
        _, body_end = body
        annotation = _java_class_transactional_annotation(
            masked_content,
            class_start=match.start(),
        )
        annotation_line = (
            content.count(
                "\n",
                0,
                annotation.start(),
            )
            + 1
            if annotation is not None
            else None
        )
        ranges.append((brace_index, body_end, annotation_line))
    return ranges


def _java_class_transactional_annotation_line(
    declaration_start: int,
    ranges: list[tuple[int, int, int | None]],
) -> int | None:
    matching = [
        (body_start, annotation_line)
        for body_start, body_end, annotation_line in ranges
        if body_start < declaration_start < body_end
    ]
    if not matching:
        return None
    return max(matching)[1]


def _java_direct_class_body_start(
    declaration_start: int,
    ranges: list[tuple[int, int, int | None]],
) -> int | None:
    containing_classes = [
        body_start
        for body_start, body_end, _ in ranges
        if body_start < declaration_start < body_end
    ]
    return max(containing_classes) if containing_classes else None


def _map_go_file(*, source_path: str, content: str) -> list["CodebaseFactCandidate"]:
    facts: list[CodebaseFactCandidate] = []
    functions = _go_functions(content)
    func_names = set(functions)
    # handler -> list of (method, path, line); middleware names attached per route
    route_handlers: dict[str, list[tuple[str, str, int]]] = {}
    middleware_for_handler: dict[str, list[tuple[str, int]]] = {}

    for match in _GO_ROUTE_START.finditer(content):
        method = match.group("method").upper()
        if method in {"HANDLEFUNC", "HANDLE"}:
            method = "GET"
        path = match.group("path")
        line = content.count("\n", 0, match.start()) + 1
        paren_at = content.find("(", match.start())
        args = _call_ident_args(content, paren_at)
        if not args:
            continue
        handler = args[-1]
        middlewares = args[:-1]
        route_handlers.setdefault(handler, []).append((method, path, line))
        if middlewares:
            middleware_for_handler.setdefault(handler, []).extend(
                (mw, line) for mw in middlewares
            )
        facts.append(
            _fact(
                fact_type="route_handler",
                source_path=source_path,
                symbol_name=handler,
                route_method=method,
                route_path=path,
                handler=handler,
                line_number=line,
            )
        )
        # Mirror TS: middleware symbol authz_check attached to route handler.
        for mw, mw_line in ((m, line) for m in middlewares):
            if any(
                marker in mw.lower()
                for marker in ("owner", "authz", "access", "permission", "guard")
            ):
                facts.append(
                    _fact(
                        fact_type="authz_check",
                        source_path=source_path,
                        symbol_name=mw,
                        route_method=None,
                        route_path=None,
                        handler=handler,
                        line_number=mw_line,
                        authz_hint="ownership_boundary_check"
                        if "owner" in mw.lower() or "access" in mw.lower()
                        else "authorization_boundary_candidate",
                    )
                )
            facts.append(
                _fact(
                    fact_type="service_call",
                    source_path=source_path,
                    symbol_name=mw,
                    route_method=None,
                    route_path=None,
                    handler=handler,
                    line_number=mw_line,
                    caller=handler,
                )
            )

    # Scan only the local call graph reachable from route handlers and middleware.
    scan_targets = set(route_handlers) | {
        mw for mws in middleware_for_handler.values() for mw, _ in mws
    }
    pending = list(scan_targets)
    scanned: set[str] = set()
    while pending:
        name = pending.pop()
        if name in scanned:
            continue
        function = functions.get(name)
        if function is None:
            continue
        scanned.add(name)
        _, brace_at, body_text = function
        scanned_facts = _scan_handler_body(
            source_path=source_path,
            handler=name,
            body_text=body_text,
            body_start_offset=brace_at + 1,
            full_source=content,
            local_methods=func_names,
        )
        facts.extend(scanned_facts)
        pending.extend(
            fact.symbol_name
            for fact in scanned_facts
            if fact.fact_type == "service_call"
            and isinstance(fact.symbol_name, str)
            and fact.symbol_name in functions
            and fact.symbol_name not in scanned
        )
    return facts


def _go_functions(content: str) -> dict[str, tuple[str, int, str]]:
    functions: dict[str, tuple[str, int, str]] = {}
    for match in _GO_FUNC.finditer(content):
        name = match.group("name")
        brace_at = content.find("{", match.end() - 1)
        if brace_at < 0:
            continue
        body = _extract_brace_body(content, brace_at)
        if body is None:
            continue
        body_text, _ = body
        functions[name] = (name, brace_at, body_text)
    return functions


def _call_ident_args(source: str, open_paren_index: int) -> list[str]:
    """Extract top-level identifier arguments from a call starting at '('."""
    if open_paren_index < 0 or open_paren_index >= len(source) or source[open_paren_index] != "(":
        return []
    depth = 0
    in_string: str | None = None
    escaped = False
    current: list[str] = []
    args: list[str] = []
    i = open_paren_index
    while i < len(source):
        ch = source[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_string:
                in_string = None
            i += 1
            continue
        if ch in {"'", '"', "`"}:
            in_string = ch
            i += 1
            continue
        if ch == "(":
            depth += 1
            if depth > 1:
                current.append(ch)
            i += 1
            continue
        if ch == ")":
            depth -= 1
            if depth == 0:
                token = "".join(current).strip()
                if token:
                    args.append(token)
                break
            current.append(ch)
            i += 1
            continue
        if ch == "," and depth == 1:
            token = "".join(current).strip()
            if token:
                args.append(token)
            current = []
            i += 1
            continue
        if depth >= 1:
            current.append(ch)
        i += 1
    # Keep only simple identifiers (drop string path already consumed before).
    idents: list[str] = []
    for arg in args:
        # strip package.func wrappers: take last identifier token
        found = _IDENT.findall(arg)
        if found and "(" not in arg and "[" not in arg:
            idents.append(found[-1] if "." in arg else found[0])
        elif found and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", arg.strip()):
            idents.append(arg.strip())
        elif found and all(c.isalnum() or c in "._" for c in arg.strip()):
            idents.append(found[-1])
    return idents


def _map_ruby_file(*, source_path: str, content: str) -> list["CodebaseFactCandidate"]:
    facts: list[CodebaseFactCandidate] = []
    methods = _ruby_methods(content)
    method_names = set(methods)
    handler_routes: dict[str, list[tuple[str, str, int]]] = {}
    before_actions = _ruby_before_actions(content)

    for match in _RUBY_ROUTE.finditer(content):
        method = match.group("method").upper()
        path = match.group("path")
        handler = match.group("handler")
        line = content.count("\n", 0, match.start()) + 1
        if not handler:
            handler = f"inline_{method.lower()}_{line}"
        handler_routes.setdefault(handler, []).append((method, path, line))
        facts.append(
            _fact(
                fact_type="route_handler",
                source_path=source_path,
                symbol_name=handler,
                route_method=method,
                route_path=path,
                handler=handler,
                line_number=line,
            )
        )
        # Attach only callback filters that apply to this routed action.
        for ba, ba_line, only_actions, except_actions in before_actions:
            if not _ruby_before_action_applies_to(
                handler,
                only_actions=only_actions,
                except_actions=except_actions,
            ):
                continue
            facts.append(
                _fact(
                    fact_type="service_call",
                    source_path=source_path,
                    symbol_name=ba,
                    route_method=None,
                    route_path=None,
                    handler=handler,
                    line_number=ba_line,
                    caller=handler,
                )
            )
            if any(marker in ba.lower() for marker in ("owner", "authz", "access", "authorize")):
                facts.append(
                    _fact(
                        fact_type="authz_check",
                        source_path=source_path,
                        symbol_name=ba,
                        route_method=None,
                        route_path=None,
                        handler=handler,
                        line_number=ba_line,
                        authz_hint="ownership_boundary_check",
                    )
                )

    # Scan only the local call graph reachable from routes and before_action filters.
    pending = list(
        set(handler_routes) | {name for name, _, _, _ in before_actions}
    )
    scanned: set[str] = set()
    while pending:
        name = pending.pop()
        if name in scanned:
            continue
        method = methods.get(name)
        if method is None:
            continue
        scanned.add(name)
        _, body_start, body_text = method
        scanned_facts = _scan_handler_body(
            source_path=source_path,
            handler=name,
            body_text=body_text,
            body_start_offset=body_start,
            full_source=content,
            local_methods=method_names,
        )
        facts.extend(scanned_facts)
        pending.extend(
            fact.symbol_name
            for fact in scanned_facts
            if fact.fact_type == "service_call"
            and isinstance(fact.symbol_name, str)
            and fact.symbol_name in methods
            and fact.symbol_name not in scanned
        )
    return facts


def _ruby_before_actions(
    content: str,
) -> list[tuple[str, int, set[str] | None, set[str]]]:
    callbacks: list[tuple[str, int, set[str] | None, set[str]]] = []
    for match in _RUBY_BEFORE_ACTION.finditer(content):
        name = match.group("name").rstrip("?!")
        line_end = content.find("\n", match.start())
        declaration = content[match.start() : line_end if line_end >= 0 else len(content)]
        only_actions: set[str] | None = None
        except_actions: set[str] = set()
        for scope_match in _RUBY_BEFORE_ACTION_SCOPE.finditer(declaration):
            action_names = _ruby_before_action_scope_names(
                scope_match.group("actions")
            )
            if scope_match.group("scope").lower() == "only":
                only_actions = action_names
            else:
                except_actions.update(action_names)
        callbacks.append(
            (
                name,
                content.count("\n", 0, match.start()) + 1,
                only_actions,
                except_actions,
            )
        )
    return callbacks


def _ruby_before_action_scope_names(value: str) -> set[str]:
    if value.startswith("%i["):
        value = value[3:-1]
    elif value.startswith("["):
        value = value[1:-1]
    return {
        name.rstrip("?!")
        for name in re.findall(r"[A-Za-z_][A-Za-z0-9_?!]*", value)
    }


def _ruby_before_action_applies_to(
    handler: str,
    *,
    only_actions: set[str] | None,
    except_actions: set[str],
) -> bool:
    action = handler.rstrip("?!")
    return (only_actions is None or action in only_actions) and action not in except_actions


def _ruby_methods(content: str) -> dict[str, tuple[str, int, str]]:
    methods: dict[str, tuple[str, int, str]] = {}
    for match in _RUBY_DEF.finditer(content):
        name = match.group("name").rstrip("?!")
        body = _extract_ruby_method_body(content, match.end())
        if body is None:
            continue
        body_text, body_start = body
        methods[name] = (name, body_start, body_text)
    return methods


def _scan_handler_body(
    *,
    source_path: str,
    handler: str,
    body_text: str,
    body_start_offset: int,
    full_source: str,
    local_methods: set[str] | None = None,
) -> list["CodebaseFactCandidate"]:
    facts: list[CodebaseFactCandidate] = []
    local_methods = local_methods or set()
    code_body = _mask_multilang_non_code(body_text)
    scoped_transaction_controls = _scoped_transactional_state_controls(code_body)
    for line_offset, line in enumerate(code_body.splitlines()):
        line_number = full_source.count("\n", 0, body_start_offset) + line_offset + 1
        boundary = _boundary_field_from_line(line)
        if boundary is not None:
            facts.append(
                _fact(
                    fact_type="authz_check",
                    source_path=source_path,
                    symbol_name=f"{boundary}_filter",
                    route_method=None,
                    route_path=None,
                    handler=handler,
                    line_number=line_number,
                    authz_hint=_boundary_hint(boundary),
                )
            )
            continue
        if _ROLE_LINE.search(line):
            facts.append(
                _fact(
                    fact_type="authz_check",
                    source_path=source_path,
                    symbol_name="role_check",
                    route_method=None,
                    route_path=None,
                    handler=handler,
                    line_number=line_number,
                    authz_hint="role_check",
                )
            )
            continue

        sink_columns: dict[str, int] = {}
        service_names: set[str] = set()
        gap_guard_names: dict[str, tuple[str, int]] = {}
        for callee, column in scoped_transaction_controls.get(line_offset, []):
            _record_gap_guard(
                gap_guard_names,
                name=callee,
                authz_hint="transactional_state_guard",
                column=column,
            )
        for call in _CALL.finditer(line):
            callee = call.group("callee")
            leaf = callee.rsplit(".", 1)[-1]
            gap_hint = _gap_guard_hint(callee)
            if gap_hint is not None:
                _record_gap_guard(
                    gap_guard_names,
                    name=leaf,
                    authz_hint=gap_hint,
                    column=call.start("callee"),
                )
                continue
            if _is_sensitive_sink(leaf):
                _record_sink_column(
                    sink_columns,
                    name=leaf,
                    column=call.start("callee"),
                )
                continue
            # Local / service helper calls (ownership helpers, service methods).
            if leaf in local_methods and leaf != handler:
                service_names.add(leaf)
                continue
            if _looks_like_service_or_authz_call(leaf, callee):
                service_names.add(leaf)
        for token_match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", line):
            token = token_match.group(1)
            gap_hint = _gap_guard_hint(token)
            if gap_hint is not None:
                _record_gap_guard(
                    gap_guard_names,
                    name=token,
                    authz_hint=gap_hint,
                    column=token_match.start(1),
                )
            elif _is_sensitive_sink(token):
                _record_sink_column(
                    sink_columns,
                    name=token,
                    column=token_match.start(1),
                )
            elif token in local_methods and token != handler:
                service_names.add(token)

        for leaf, (gap_hint, column) in sorted(gap_guard_names.items()):
            facts.append(
                _fact(
                    fact_type="authz_check",
                    source_path=source_path,
                    symbol_name=leaf,
                    route_method=None,
                    route_path=None,
                    handler=handler,
                    line_number=line_number,
                    authz_hint=gap_hint,
                    column_number=column,
                )
            )
        for leaf, column in sorted(sink_columns.items()):
            facts.append(
                _fact(
                    fact_type="sensitive_sink",
                    source_path=source_path,
                    symbol_name=leaf,
                    route_method=None,
                    route_path=None,
                    handler=handler,
                    line_number=line_number,
                    column_number=column,
                )
            )
        for leaf in sorted(service_names):
            facts.append(
                _fact(
                    fact_type="service_call",
                    source_path=source_path,
                    symbol_name=leaf,
                    route_method=None,
                    route_path=None,
                    handler=handler,
                    line_number=line_number,
                    caller=handler,
                )
            )
            # Ownership helper name itself is an authz_check (TS style).
            if _ownership_helper_name(leaf):
                facts.append(
                    _fact(
                        fact_type="authz_check",
                        source_path=source_path,
                        symbol_name=leaf,
                        route_method=None,
                        route_path=None,
                        handler=handler,
                        line_number=line_number,
                        authz_hint="ownership_boundary_check",
                    )
                )
    return facts


def _looks_like_service_or_authz_call(leaf: str, callee: str) -> bool:
    snake = _to_snake(leaf)
    if snake in _NON_SERVICE or leaf.lower() in _NON_SERVICE:
        return False
    if _is_sensitive_sink(leaf):
        return False
    if _ownership_helper_name(leaf):
        return True
    # recordService.getForUser / service.get_record_for_user
    if "." in callee and any(
        marker in callee.lower()
        for marker in ("service", "repo", "repository", "store", "dao")
    ):
        return True
    if any(
        marker in snake
        for marker in (
            "for_user",
            "get_record",
            "load_for",
            "fetch_for",
            "ensure_",
            "require_",
            "verify_",
            "assert_",
            "check_",
        )
    ):
        return True
    return False


def _ownership_helper_name(name: str) -> bool:
    snake = _to_snake(name)
    markers = (
        "ensure_owner",
        "require_owner",
        "verify_owner",
        "assert_owner",
        "check_ownership",
        "verify_ownership",
        "owner_check",
        "ownership",
        "authorize_owner",
        "ensure_record_owner",
        "require_record_owner",
    )
    if any(m in snake for m in markers):
        return True
    if "owner" in snake and any(
        m in snake for m in ("ensure", "require", "verify", "assert", "check", "guard")
    ):
        return True
    return False


def _gap_guard_hint(name: str) -> str | None:
    """Map protective check names to gap-family authz hints (not ownership)."""
    snake = _to_snake(name)
    if not snake:
        return None
    if any(marker in snake for marker in _SSRF_GUARD_MARKERS):
        return "ssrf_validation_check"
    if any(marker in snake for marker in _PATH_GUARD_MARKERS):
        return "path_validation_check"
    if any(marker in snake for marker in _MASS_ASSIGN_GUARD_MARKERS):
        return "mass_assignment_check"
    if any(marker in snake for marker in _INJECTION_GUARD_MARKERS):
        return "injection_validation_check"
    if _is_state_transition_guard_name(snake):
        return "transactional_state_guard"
    return None


def _is_state_transition_guard_name(snake: str) -> bool:
    return snake == "transactional" or any(
        marker in snake for marker in _STATE_TRANSITION_GUARD_MARKERS
    )


def _scoped_transactional_state_controls(
    code_body: str,
) -> dict[int, list[tuple[str, int]]]:
    state_sink_positions = _state_transition_sink_positions(code_body)
    if not state_sink_positions:
        return {}

    controls: dict[int, list[tuple[str, int]]] = {}
    for match in _GO_TRANSACTION_CALLBACK.finditer(code_body):
        scope = _go_transaction_callback_scope(code_body, match.end())
        if scope is None:
            continue
        _record_scoped_transactional_control(
            controls,
            code_body=code_body,
            callee=match.group("callee"),
            control_start=match.start("callee"),
            scope=scope,
            state_sink_positions=state_sink_positions,
        )
    for match in _RUBY_TRANSACTION_BLOCK.finditer(code_body):
        scope = _ruby_transaction_block_scope(
            code_body,
            transaction_start=match.start("callee"),
            block_start=match.start("block"),
            block=match.group("block"),
        )
        if scope is None:
            continue
        _record_scoped_transactional_control(
            controls,
            code_body=code_body,
            callee=match.group("callee"),
            control_start=match.start("callee"),
            scope=scope,
            state_sink_positions=state_sink_positions,
        )
    return controls


def _state_transition_sink_positions(code_body: str) -> list[int]:
    return [
        match.start("callee")
        for match in _CALL.finditer(code_body)
        if _to_snake(match.group("callee").rsplit(".", 1)[-1])
        in _STATE_TRANSITION_SINKS
    ]


def _go_transaction_callback_scope(
    code_body: str,
    callback_start: int,
) -> tuple[int, int] | None:
    brace_index = code_body.find("{", callback_start)
    if brace_index < 0:
        return None
    body = _extract_brace_body(code_body, brace_index)
    if body is None:
        return None
    _, body_end = body
    return brace_index + 1, body_end


def _ruby_transaction_block_scope(
    code_body: str,
    *,
    transaction_start: int,
    block_start: int,
    block: str,
) -> tuple[int, int] | None:
    if block == "{":
        body = _extract_brace_body(code_body, block_start)
        if body is None:
            return None
        _, body_end = body
        return block_start + 1, body_end

    line_end = code_body.find("\n", transaction_start)
    if line_end < 0:
        return None
    scope_start = line_end + 1
    depth = 1
    cursor = scope_start
    openers = re.compile(
        r"^\s*(?:def|if|unless|while|until|for|begin|case|class|module|do)\b"
    )
    do_suffix = re.compile(r"\bdo\b\s*(?:\|.*\|)?\s*$")
    closer = re.compile(r"^\s*end\b")
    for line in code_body[scope_start:].splitlines(keepends=True):
        if closer.search(line):
            depth -= 1
            if depth == 0:
                return scope_start, cursor
        elif openers.search(line) or do_suffix.search(line):
            depth += 1
        cursor += len(line)
    return None


def _record_scoped_transactional_control(
    controls: dict[int, list[tuple[str, int]]],
    *,
    code_body: str,
    callee: str,
    control_start: int,
    scope: tuple[int, int],
    state_sink_positions: list[int],
) -> None:
    scope_start, scope_end = scope
    if not all(scope_start <= position < scope_end for position in state_sink_positions):
        return
    line_offset = code_body.count("\n", 0, control_start)
    line_start = code_body.rfind("\n", 0, control_start) + 1
    controls.setdefault(line_offset, []).append((callee, control_start - line_start))


def _record_gap_guard(
    guards: dict[str, tuple[str, int]],
    *,
    name: str,
    authz_hint: str,
    column: int,
) -> None:
    existing = guards.get(name)
    if existing is None or column < existing[1]:
        guards[name] = (authz_hint, column)


def _record_sink_column(
    sink_columns: dict[str, int],
    *,
    name: str,
    column: int,
) -> None:
    existing = sink_columns.get(name)
    if existing is None or column < existing:
        sink_columns[name] = column


def _mask_multilang_non_code(source: str) -> str:
    masked: list[str] = []
    quote: str | None = None
    block_comment = False
    line_comment = False
    escaped = False
    index = 0
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if line_comment:
            if char in "\r\n":
                line_comment = False
                masked.append(char)
            else:
                masked.append(" ")
            index += 1
            continue
        if block_comment:
            if char == "*" and next_char == "/":
                masked.extend((" ", " "))
                block_comment = False
                index += 2
            else:
                masked.append(char if char in "\r\n" else " ")
                index += 1
            continue
        if quote is not None:
            if char in "\r\n" and quote != "`":
                quote = None
                escaped = False
                masked.append(char)
            else:
                masked.append(" ")
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
            index += 1
            continue
        if char == "/" and next_char == "/":
            masked.extend((" ", " "))
            line_comment = True
            index += 2
            continue
        if char == "/" and next_char == "*":
            masked.extend((" ", " "))
            block_comment = True
            index += 2
            continue
        if char == "#":
            masked.append(" ")
            line_comment = True
            index += 1
            continue
        if char in {"'", '"', "`"}:
            masked.append(" ")
            quote = char
            index += 1
            continue
        masked.append(char)
        index += 1
    return "".join(masked)


def _boundary_field_from_line(line: str) -> str | None:
    for match in _COMPARISON.finditer(line):
        field = _ownership_boundary_from_pair(match.group("left"), match.group("right"))
        if field is not None:
            return field
    for match in _EQUALS_CALL.finditer(line):
        field = _ownership_boundary_from_pair(match.group("left"), match.group("right"))
        if field is not None:
            return field
    return None


def _ownership_boundary_from_pair(left: str, right: str) -> str | None:
    left_field = _boundary_field(left)
    right_field = _boundary_field(right)
    if left_field is not None and _is_principal(right):
        return left_field
    if right_field is not None and _is_principal(left):
        return right_field
    return None


def _boundary_field(identifier: str) -> str | None:
    normalized = _normalize_identifier(identifier)
    if not normalized:
        return None
    leaf = normalized.rsplit(".", 1)[-1]
    if leaf in _BOUNDARY_FIELDS:
        return "owner_id" if leaf in {"owner_id", "ownerid"} else leaf
    if leaf in {"owner"}:
        return "owner_id"
    return None


def _is_principal(identifier: str) -> bool:
    normalized = _normalize_identifier(identifier)
    if not normalized:
        return False
    if normalized in _PRINCIPAL_EXACT:
        return True
    parts = normalized.split(".")
    if len(parts) >= 2 and parts[0] in _PRINCIPAL_ROOTS:
        leaf = parts[-1]
        if leaf in {"id", "name", "user_id", "uid"}:
            return True
    return False


def _normalize_identifier(identifier: str) -> str:
    cleaned = re.sub(r"\s+", "", identifier)
    cleaned = re.sub(r"\(\s*\)", "", cleaned)
    if not cleaned:
        return ""
    parts = cleaned.split(".")
    return ".".join(_to_snake(part) for part in parts if part)


def _to_snake(name: str) -> str:
    stepped = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    stepped = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", stepped)
    snake = re.sub(r"[^A-Za-z0-9]+", "_", stepped).strip("_").lower()
    if snake.startswith("get_") and len(snake) > 4:
        snake = snake[4:]
    return snake


def _is_sensitive_sink(call_name: str) -> bool:
    snake = _to_snake(call_name)
    return snake in _SENSITIVE_SINKS or call_name.lower() in _SENSITIVE_SINKS


def _boundary_hint(field_name: str) -> str:
    if field_name == "owner_id":
        return "owner_or_admin_check"
    return "ownership_boundary_check"


def _extract_brace_body(source: str, brace_index: int) -> tuple[str, int] | None:
    if brace_index < 0 or brace_index >= len(source) or source[brace_index] != "{":
        return None
    depth = 0
    in_string: str | None = None
    escaped = False
    i = brace_index
    while i < len(source):
        ch = source[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_string:
                in_string = None
            i += 1
            continue
        if ch in {"'", '"', "`"}:
            in_string = ch
            i += 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return source[brace_index + 1 : i], i
        i += 1
    return None


def _extract_ruby_method_body(source: str, start: int) -> tuple[str, int] | None:
    lines = source[start:].splitlines(keepends=True)
    depth = 1
    collected: list[str] = []
    openers = re.compile(
        r"^\s*(?:def|if|unless|while|until|for|begin|case|class|module|do)\b"
    )
    do_suffix = re.compile(r"\bdo\b\s*(?:\|.*\|)?\s*$")
    closer = re.compile(r"^\s*end\b")
    for line in lines:
        if closer.search(line):
            depth -= 1
            if depth == 0:
                return "".join(collected), start
            collected.append(line)
            continue
        if openers.search(line) or do_suffix.search(line):
            depth += 1
        collected.append(line)
    return None



# C# ASP.NET: [HttpGet("/path")] public IActionResult Name(...)
_CSHARP_HTTP = re.compile(
    r"\[Http(?P<method>Get|Post|Put|Patch|Delete)\s*(?:\(\s*[\"'](?P<path>[^\"']+)[\"']\s*\))?\]",
    re.IGNORECASE,
)
_CSHARP_METHOD = re.compile(
    r"(?:public|protected|private|internal|static|\s)+\S+\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;]*?\)\s*\{",
    re.MULTILINE,
)

# PHP Laravel-style: Route::get('/path', ...)
_PHP_ROUTE = re.compile(
    r"Route\s*::\s*(?P<method>get|post|put|patch|delete)\s*\(\s*[\"'](?P<path>[^\"']+)[\"']",
    re.IGNORECASE,
)
_PHP_FUNCTION = re.compile(
    r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
)
_PHP_ROUTE_CONTROLLER = re.compile(
    r"Route\s*::\s*(?P<method>get|post|put|patch|delete)\s*\(\s*[\"'](?P<path>[^\"']+)[\"']"
    r"\s*,\s*(?:"
    r"\[\s*[A-Za-z_][A-Za-z0-9_\\\\]*\s*::\s*class\s*,\s*[\"'](?P<action>[A-Za-z_][A-Za-z0-9_]*)[\"']\s*\]"
    r"|[\"'][A-Za-z_][A-Za-z0-9_\\\\]*@(?P<action2>[A-Za-z_][A-Za-z0-9_]*)[\"']"
    r")",
    re.IGNORECASE | re.DOTALL,
)



# Kotlin Spring MVC: @GetMapping + fun name(...) {
_KOTLIN_MAPPING = _JAVA_MAPPING
_KOTLIN_FUN = re.compile(
    r"\bfun\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)(?:\s*:\s*[^{=]+)?\s*\{",
    re.MULTILINE,
)



# Rust: #[get("/path")] async fn name / .route("/path", get(name))
_RUST_ATTR_ROUTE = re.compile(
    r"#\[(?P<method>get|post|put|patch|delete)\s*\(\s*[\"'](?P<path>[^\"']+)[\"']\s*\)\]",
    re.IGNORECASE,
)
_RUST_ROUTE_CALL = re.compile(
    r"\.route\s*\(\s*[\"'](?P<path>[^\"']+)[\"']\s*,\s*(?:get|post|put|patch|delete)\s*\(\s*(?P<handler>[A-Za-z_][A-Za-z0-9_]*)\s*\)",
    re.IGNORECASE,
)
_RUST_FN = re.compile(
    r"\b(?:async\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)[^{]*\{",
    re.MULTILINE,
)

# Scala Spring-like: @GetMapping("/path") def name(...) = { ... }
_SCALA_MAPPING = re.compile(
    r"@(?P<method>Get|Post|Put|Patch|Delete)Mapping\s*\(\s*(?:value\s*=\s*)?(?:Array\s*\(\s*)?[\"'](?P<path>[^\"']+)[\"']",
    re.IGNORECASE,
)
_SCALA_DEF = re.compile(
    r"\bdef\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*\([^)]*\)[^{=]*=\s*\{",
    re.MULTILINE,
)


def _map_rust_file(*, source_path: str, content: str) -> list["CodebaseFactCandidate"]:
    facts: list[CodebaseFactCandidate] = []
    functions = _rust_functions(content)
    local_methods = set(functions)
    route_handlers: set[str] = set()
    ordered = sorted(functions.items(), key=lambda item: item[1][0])

    for match in _RUST_ATTR_ROUTE.finditer(content):
        handler_name = None
        body_text = ""
        body_start = 0
        for name, (decl_start, brace_at, body) in ordered:
            if decl_start >= match.end():
                handler_name = name
                body_text = body
                body_start = brace_at + 1
                break
        if handler_name is None:
            continue
        route_method = match.group("method").upper()
        route_path = match.group("path")
        route_line = content.count("\n", 0, match.start()) + 1
        route_handlers.add(handler_name)
        facts.append(
            _fact(
                fact_type="route_handler",
                source_path=source_path,
                symbol_name=handler_name,
                route_method=route_method,
                route_path=route_path,
                handler=handler_name,
                line_number=route_line,
            )
        )
        facts.extend(
            _scan_handler_body(
                source_path=source_path,
                handler=handler_name,
                body_text=body_text,
                body_start_offset=body_start,
                full_source=content,
                local_methods=local_methods,
            )
        )

    for match in _RUST_ROUTE_CALL.finditer(content):
        handler_name = match.group("handler")
        meta = functions.get(handler_name)
        if meta is None:
            continue
        _, brace_at, body_text = meta
        route_path = match.group("path")
        route_line = content.count("\n", 0, match.start()) + 1
        route_handlers.add(handler_name)
        facts.append(
            _fact(
                fact_type="route_handler",
                source_path=source_path,
                symbol_name=handler_name,
                route_method="GET",
                route_path=route_path,
                handler=handler_name,
                line_number=route_line,
            )
        )
        facts.extend(
            _scan_handler_body(
                source_path=source_path,
                handler=handler_name,
                body_text=body_text,
                body_start_offset=brace_at + 1,
                full_source=content,
                local_methods=local_methods,
            )
        )

    for name, (_, brace_at, body_text) in functions.items():
        if name in route_handlers:
            continue
        facts.extend(
            _scan_handler_body(
                source_path=source_path,
                handler=name,
                body_text=body_text,
                body_start_offset=brace_at + 1,
                full_source=content,
                local_methods=local_methods,
            )
        )
    return facts


def _rust_functions(content: str) -> dict[str, tuple[int, int, str]]:
    """Map function name -> (decl_start, brace_at, body_text)."""
    out: dict[str, tuple[int, int, str]] = {}
    for match in _RUST_FN.finditer(content):
        name = match.group("name")
        if name in {"if", "for", "while", "match", "loop", "main"}:
            continue
        brace_at = match.end() - 1
        if brace_at < 0 or content[brace_at] != "{":
            brace_at = content.find("{", match.start())
        if brace_at < 0:
            continue
        body = _extract_brace_body(content, brace_at)
        if body is None:
            continue
        body_text, _ = body
        out[name] = (match.start(), brace_at, body_text)
    return out


def _map_scala_file(*, source_path: str, content: str) -> list["CodebaseFactCandidate"]:
    facts: list[CodebaseFactCandidate] = []
    methods = _scala_methods(content)
    method_names = {name for name, _, _, _ in methods}
    route_handlers: set[str] = set()

    for mapping in _SCALA_MAPPING.finditer(content):
        method_meta = None
        for meta in methods:
            name, decl_start, brace_at, body_text = meta
            if decl_start >= mapping.end():
                method_meta = meta
                break
        if method_meta is None:
            continue
        method_name, _, brace_at, body_text = method_meta
        route_method = mapping.group("method").upper()
        route_path = mapping.group("path")
        route_line = content.count("\n", 0, mapping.start()) + 1
        route_handlers.add(method_name)
        facts.append(
            _fact(
                fact_type="route_handler",
                source_path=source_path,
                symbol_name=method_name,
                route_method=route_method,
                route_path=route_path,
                handler=method_name,
                line_number=route_line,
            )
        )
        facts.extend(
            _scan_handler_body(
                source_path=source_path,
                handler=method_name,
                body_text=body_text,
                body_start_offset=brace_at + 1,
                full_source=content,
                local_methods=method_names,
            )
        )

    for name, _, brace_at, body_text in methods:
        if name in route_handlers:
            continue
        facts.extend(
            _scan_handler_body(
                source_path=source_path,
                handler=name,
                body_text=body_text,
                body_start_offset=brace_at + 1,
                full_source=content,
                local_methods=method_names,
            )
        )
    return facts


def _scala_methods(content: str) -> list[tuple[str, int, int, str]]:
    methods: list[tuple[str, int, int, str]] = []
    for match in _SCALA_DEF.finditer(content):
        name = match.group("name")
        if name in {"if", "for", "while", "match", "class", "object", "trait"}:
            continue
        brace_at = match.end() - 1
        if brace_at < 0 or content[brace_at] != "{":
            brace_at = content.find("{", match.start())
        if brace_at < 0:
            continue
        body = _extract_brace_body(content, brace_at)
        if body is None:
            continue
        body_text, _ = body
        methods.append((name, match.start(), brace_at, body_text))
    return methods


def _map_kotlin_file(*, source_path: str, content: str) -> list["CodebaseFactCandidate"]:
    facts: list[CodebaseFactCandidate] = []
    methods = _kotlin_methods(content)
    method_names = {name for name, _, _, _ in methods}
    route_handlers: set[str] = set()

    for mapping in _KOTLIN_MAPPING.finditer(content):
        method_meta = None
        for meta in methods:
            name, decl_start, brace_at, body_text = meta
            if decl_start >= mapping.end():
                method_meta = meta
                break
        if method_meta is None:
            continue
        method_name, _, brace_at, body_text = method_meta
        route_method = mapping.group("method").upper()
        route_path = mapping.group("path")
        route_line = content.count("\n", 0, mapping.start()) + 1
        route_handlers.add(method_name)
        facts.append(
            _fact(
                fact_type="route_handler",
                source_path=source_path,
                symbol_name=method_name,
                route_method=route_method,
                route_path=route_path,
                handler=method_name,
                line_number=route_line,
            )
        )
        facts.extend(
            _scan_handler_body(
                source_path=source_path,
                handler=method_name,
                body_text=body_text,
                body_start_offset=brace_at + 1,
                full_source=content,
                local_methods=method_names,
            )
        )

    for name, _, brace_at, body_text in methods:
        if name in route_handlers:
            continue
        facts.extend(
            _scan_handler_body(
                source_path=source_path,
                handler=name,
                body_text=body_text,
                body_start_offset=brace_at + 1,
                full_source=content,
                local_methods=method_names,
            )
        )
    return facts


def _kotlin_methods(content: str) -> list[tuple[str, int, int, str]]:
    methods: list[tuple[str, int, int, str]] = []
    for match in _KOTLIN_FUN.finditer(content):
        name = match.group("name")
        if name in {"if", "for", "while", "when", "catch", "class", "object"}:
            continue
        brace_at = match.end() - 1
        if brace_at < 0 or content[brace_at] != "{":
            brace_at = content.find("{", match.start())
        if brace_at < 0:
            continue
        body = _extract_brace_body(content, brace_at)
        if body is None:
            continue
        body_text, _ = body
        methods.append((name, match.start(), brace_at, body_text))
    return methods


def _map_csharp_file(*, source_path: str, content: str) -> list["CodebaseFactCandidate"]:
    facts: list[CodebaseFactCandidate] = []
    methods = _csharp_methods(content)
    method_names = {name for name, _, _, _ in methods}
    route_handlers: set[str] = set()

    for mapping in _CSHARP_HTTP.finditer(content):
        method_meta = None
        for meta in methods:
            name, decl_start, brace_at, body_text = meta
            # Method decl may begin immediately after the attribute.
            if decl_start >= mapping.end():
                method_meta = meta
                break
        if method_meta is None:
            continue
        method_name, _, brace_at, body_text = method_meta
        route_method = mapping.group("method").upper()
        route_path = mapping.group("path") or f"/{method_name}"
        route_line = content.count("\n", 0, mapping.start()) + 1
        route_handlers.add(method_name)
        facts.append(
            _fact(
                fact_type="route_handler",
                source_path=source_path,
                symbol_name=method_name,
                route_method=route_method,
                route_path=route_path,
                handler=method_name,
                line_number=route_line,
            )
        )
        facts.extend(
            _scan_handler_body(
                source_path=source_path,
                handler=method_name,
                body_text=body_text,
                body_start_offset=brace_at + 1,
                full_source=content,
                local_methods=method_names,
            )
        )

    for name, _, brace_at, body_text in methods:
        if name in route_handlers:
            continue
        facts.extend(
            _scan_handler_body(
                source_path=source_path,
                handler=name,
                body_text=body_text,
                body_start_offset=brace_at + 1,
                full_source=content,
                local_methods=method_names,
            )
        )
    return facts


def _csharp_methods(content: str) -> list[tuple[str, int, int, str]]:
    methods: list[tuple[str, int, int, str]] = []
    for match in _CSHARP_METHOD.finditer(content):
        name = match.group("name")
        if name in {"if", "for", "while", "switch", "catch", "class", "new", "using", "return"}:
            continue
        brace_at = match.end() - 1
        if brace_at < 0 or content[brace_at] != "{":
            brace_at = content.find("{", match.start())
        if brace_at < 0:
            continue
        body = _extract_brace_body(content, brace_at)
        if body is None:
            continue
        body_text, _ = body
        methods.append((name, match.start(), brace_at, body_text))
    return methods



def _normalize_php_syntax(content: str) -> str:
    """Normalize PHP variables/arrows so shared scanners see JS/Python-like idents."""
    # $user->id -> user.id ; $record->owner_id -> record.owner_id
    text = re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)", r"\1", content)
    text = text.replace("->", ".")
    return text


def _map_php_file(*, source_path: str, content: str) -> list["CodebaseFactCandidate"]:
    facts: list[CodebaseFactCandidate] = []
    content = _normalize_php_syntax(content)
    functions = _php_functions(content)
    local_methods = set(functions)

    for match in _PHP_ROUTE.finditer(content):
        route_method = match.group("method").upper()
        route_path = match.group("path")
        route_line = content.count("\n", 0, match.start()) + 1
        handler_name = f"route_{route_method.lower()}_{route_line}"
        # Prefer a named function referenced near the route registration.
        window = content[match.start() : min(len(content), match.start() + 500)]
        named = None
        for fname in functions:
            if re.search(rf"\b{re.escape(fname)}\b", window):
                named = fname
                break
        if named is not None:
            handler_name = named
            body_text, body_start = functions[named]
        else:
            brace = content.find("{", match.end())
            if brace < 0:
                continue
            extracted = _extract_brace_body(content, brace)
            if extracted is None:
                continue
            body_text, _ = extracted
            body_start = brace + 1

        facts.append(
            _fact(
                fact_type="route_handler",
                source_path=source_path,
                symbol_name=handler_name,
                route_method=route_method,
                route_path=route_path,
                handler=handler_name,
                line_number=route_line,
            )
        )
        facts.extend(
            _scan_handler_body(
                source_path=source_path,
                handler=handler_name,
                body_text=body_text,
                body_start_offset=body_start,
                full_source=content,
                local_methods=local_methods,
            )
        )


    # Controller-style: Route::get(..., [Foo::class, 'show']) or Foo@show
    for match in _PHP_ROUTE_CONTROLLER.finditer(content):
        route_method = match.group("method").upper()
        route_path = match.group("path")
        action = match.group("action") or match.group("action2")
        if not action or action not in functions:
            continue
        route_line = content.count("\n", 0, match.start()) + 1
        body_text, body_start = functions[action]
        facts.append(
            _fact(
                fact_type="route_handler",
                source_path=source_path,
                symbol_name=action,
                route_method=route_method,
                route_path=route_path,
                handler=action,
                line_number=route_line,
            )
        )
        facts.extend(
            _scan_handler_body(
                source_path=source_path,
                handler=action,
                body_text=body_text,
                body_start_offset=body_start,
                full_source=content,
                local_methods=local_methods,
            )
        )

    for name, (body_text, body_start) in functions.items():
        facts.extend(
            _scan_handler_body(
                source_path=source_path,
                handler=name,
                body_text=body_text,
                body_start_offset=body_start,
                full_source=content,
                local_methods=local_methods,
            )
        )
    return facts


def _php_functions(content: str) -> dict[str, tuple[str, int]]:
    """Map function name -> (body_text, body_start_offset)."""
    out: dict[str, tuple[str, int]] = {}
    for match in _PHP_FUNCTION.finditer(content):
        name = match.group("name")
        brace = content.find("{", match.end() - 1)
        if brace < 0:
            continue
        body = _extract_brace_body(content, brace)
        if body is None:
            continue
        body_text, _ = body
        out[name] = (body_text, brace + 1)
    return out


def _fact(
    *,
    fact_type: str,
    source_path: str,
    symbol_name: str,
    route_method: str | None,
    route_path: str | None,
    handler: str,
    line_number: int,
    authz_hint: str | None = None,
    caller: str | None = None,
    column_number: int | None = None,
) -> "CodebaseFactCandidate":
    from app.codebase_map import CodebaseFactCandidate

    payload: dict = {
        "line": line_number,
        "mapping_mode": "static_multilang_analysis",
    }
    if column_number is not None:
        payload["column"] = column_number
    if fact_type == "service_call":
        payload["caller"] = caller or handler
        # Also set handler for reachability helpers that only look at handler.
        payload["handler"] = handler
    else:
        payload["handler"] = handler

    return CodebaseFactCandidate(
        fact_type=fact_type,
        source_path=source_path,
        symbol_name=symbol_name,
        route_method=route_method,
        route_path=route_path,
        authz_hint=authz_hint,
        sensitivity_label="high" if fact_type == "route_handler" else "low",
        payload=payload,
    )
