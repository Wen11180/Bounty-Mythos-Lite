from dataclasses import dataclass
from io import StringIO
import re
import tokenize


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
    r"\b(?P<field>(?:owner|user|tenant|account|org|organization|workspace|created_by|owner_id|user_id|created_by_id|tenant_id|account_id|org_id|organization_id|workspace_id|owner__id|user__id|created_by__id|tenant__id|account__id|org__id|organization__id|workspace__id)(?:__in)?)\s*=\s*"
    r"(?:[\[({]\s*)?"
    r"(?P<value>[A-Za-z_][A-Za-z0-9_.]*)\s*,?\s*[\])}]?",
    re.IGNORECASE,
)
AUTHZ_BOUNDARY_KWARG_START_PATTERN = re.compile(
    r"\b(?P<field>(?:owner|user|tenant|account|org|organization|workspace|created_by|owner_id|user_id|created_by_id|tenant_id|account_id|org_id|organization_id|workspace_id|owner__id|user__id|created_by__id|tenant__id|account__id|org__id|organization__id|workspace__id)__in)\s*=\s*[\[({]?\s*$",
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
    "owner_id",
    "user_id",
    "tenant_id",
    "account_id",
    "org_id",
    "organization_id",
    "workspace_id",
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
    "owner_or_admin",
    "login_required",
)
SENSITIVE_SINK_NAMES = {
    "delete",
    "delete_file",
    "export",
    "export_file",
    "send_file",
    "transfer",
    "update",
    "update_role",
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


def map_authorized_code_files(payload: dict) -> CodebaseMapResult:
    files = payload.get("authorized_code_files")
    if not isinstance(files, list):
        return CodebaseMapResult(facts=[], file_count=0)

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
        facts.extend(_map_file(source_path=source_path, content=content))

    facts = _dedupe_handler_authz_facts(
        _dedupe_facts(_resolve_dependency_wrapper_authz(facts))
    )
    return CodebaseMapResult(
        facts=_dedupe_facts([*facts, *_authorization_gap_candidates(facts)]),
        file_count=mapped_file_count,
    )


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

        imported_aliases = _imported_aliases(line)
        dependency_imported_aliases = _dependency_imported_aliases(line)
        if (imported_aliases or dependency_imported_aliases) and not function_stack:
            for alias_name, call_name in imported_aliases:
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
        for raw_call_name in _called_names(line):
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


def _authorization_gap_candidates(
    facts: list[CodebaseFactCandidate],
) -> list[CodebaseFactCandidate]:
    candidates: list[CodebaseFactCandidate] = []
    routes = [fact for fact in facts if fact.fact_type == "route_handler"]
    for route in routes:
        handler = route.payload.get("handler") if isinstance(route.payload, dict) else None
        if not isinstance(handler, str):
            continue
        has_authz = any(
            fact.fact_type == "authz_check"
            and isinstance(fact.payload, dict)
            and fact.payload.get("handler") == handler
            for fact in facts
        )
        if has_authz:
            continue
        service_calls = _reachable_service_handlers(facts, handler)
        has_service_authz = any(
            fact.fact_type == "authz_check"
            and isinstance(fact.payload, dict)
            and fact.payload.get("handler") in service_calls
            for fact in facts
        )
        if has_service_authz:
            continue
        sink_symbols = sorted(
            {
                fact.symbol_name
                for fact in facts
                if fact.fact_type == "sensitive_sink"
                and isinstance(fact.payload, dict)
                and isinstance(fact.symbol_name, str)
                and (
                    fact.payload.get("handler") == handler
                    or fact.payload.get("handler") in service_calls
                )
            }
        )
        sink_count = len(sink_symbols)
        if sink_count == 0:
            continue
        candidates.append(
            CodebaseFactCandidate(
                fact_type="authorization_gap_candidate",
                source_path=route.source_path,
                symbol_name=handler,
                route_method=route.route_method,
                route_path=route.route_path,
                authz_hint="missing_handler_authz_check",
                sensitivity_label="high",
                payload={
                    "handler": handler,
                    "mapping_mode": "static_code_snippet_analysis",
                    "review_state": "needs_human_review",
                    "sink_count": sink_count,
                    "sink_symbols": sink_symbols,
                },
            )
        )
    return candidates


def _reachable_service_handlers(
    facts: list[CodebaseFactCandidate],
    handler: str,
) -> set[str]:
    calls_by_handler: dict[str, set[str]] = {}
    for fact in facts:
        if fact.fact_type != "service_call" or not isinstance(fact.payload, dict):
            continue
        caller = fact.payload.get("caller")
        callee = fact.symbol_name
        if not isinstance(caller, str) or not isinstance(callee, str):
            continue
        calls_by_handler.setdefault(caller, set()).add(callee)

    reachable: set[str] = set()
    pending = list(calls_by_handler.get(handler, set()))
    while pending:
        callee = pending.pop()
        if callee in reachable:
            continue
        reachable.add(callee)
        pending.extend(calls_by_handler.get(callee, set()) - reachable)
    return reachable


def _indent_width(line: str) -> int:
    expanded = line.expandtabs()
    return len(expanded) - len(expanded.lstrip(" "))


def _called_names(line: str) -> list[str]:
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
            calls.append(token.string)
    return calls


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
    wrapper_authz: dict[str, CodebaseFactCandidate] = {}
    seen_authz: set[tuple[str, str, str | None]] = set()
    dependency_calls = [
        fact
        for fact in facts
        if fact.fact_type == "dependency_call" and isinstance(fact.payload, dict)
    ]
    for fact in facts:
        if fact.fact_type != "authz_check" or not isinstance(fact.payload, dict):
            continue
        handler = fact.payload.get("handler")
        if not isinstance(handler, str):
            continue
        seen_authz.add((fact.source_path, handler, fact.symbol_name))
        existing = wrapper_authz.get(handler)
        if existing is None or _authz_hint_priority(
            fact.authz_hint
        ) > _authz_hint_priority(existing.authz_hint):
            wrapper_authz[handler] = fact

    changed = True
    while changed:
        changed = False
        for fact in dependency_calls:
            caller = fact.payload.get("caller")
            wrapper = fact.symbol_name
            if not isinstance(caller, str) or not isinstance(wrapper, str):
                continue
            authz = wrapper_authz.get(wrapper)
            if authz is None:
                continue
            seen_key = (fact.source_path, caller, authz.symbol_name)
            if seen_key in seen_authz:
                continue
            derived = CodebaseFactCandidate(
                fact_type="authz_check",
                source_path=fact.source_path,
                symbol_name=authz.symbol_name,
                route_method=None,
                route_path=None,
                authz_hint=authz.authz_hint,
                sensitivity_label="low",
                payload={
                    "handler": caller,
                    "line": fact.payload.get("line"),
                    "mapping_mode": "static_code_snippet_analysis",
                },
            )
            resolved.append(derived)
            seen_authz.add(seen_key)
            existing = wrapper_authz.get(caller)
            if existing is None or _authz_hint_priority(
                derived.authz_hint
            ) > _authz_hint_priority(existing.authz_hint):
                wrapper_authz[caller] = derived
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
    return any(marker in normalized for marker in AUTHZ_NAME_MARKERS)


def _authz_hint(call_name: str) -> str:
    normalized = call_name.lower()
    if "owner_or_admin" in normalized:
        return "owner_or_admin_check"
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
        key = (
            fact.fact_type,
            fact.source_path,
            fact.symbol_name,
            fact.route_method,
            fact.route_path,
            fact.authz_hint,
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
    if authz_hint == "permission_check":
        return 3
    if authz_hint == "role_check":
        return 2
    return 1


def _count_facts(facts: list[CodebaseFactCandidate], fact_type: str) -> int:
    return sum(1 for fact in facts if fact.fact_type == fact_type)
