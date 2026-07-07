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
STRING_LITERAL_PATTERN = re.compile(r"[\"']([^\"']+)[\"']")
FUNCTION_PATTERN = re.compile(r"\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
MODEL_PATTERN = re.compile(r"\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)")
DEPENDENCY_CALL_PATTERN = re.compile(r"\b(?:Depends|Security)\(\s*([A-Za-z_][A-Za-z0-9_]*)")
DEPENDENCY_ALIAS_PATTERN = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:Depends|Security)\(\s*([A-Za-z_][A-Za-z0-9_]*)"
)
IMPORT_AUTHZ_ALIAS_PATTERN = re.compile(r"^\s*from\s+[A-Za-z_][A-Za-z0-9_.]*\s+import\s+(.+)$")
IMPORT_ALIAS_ITEM_PATTERN = re.compile(
    r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s+as\s+([A-Za-z_][A-Za-z0-9_]*)\s*$"
)
AUTHZ_NAME_MARKERS = (
    "authorize",
    "authz",
    "permission",
    "require_role",
    "require_user",
    "owner_or_admin",
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
    pending_route: tuple[str, str, int, list[tuple[str, int]]] | None = None
    pending_route_decorator: tuple[str, int, list[str], list[tuple[str, int]]] | None = None
    pending_signature_authz: tuple[str, int] | None = None
    function_stack: list[tuple[str, int]] = []
    dependency_aliases: dict[str, str] = {}

    for line_number, line in enumerate(content.splitlines(), start=1):
        if pending_route_decorator is not None:
            method, decorator_line, decorator_lines, authz_calls = pending_route_decorator
            decorator_lines = [*decorator_lines, line]
            authz_calls = [
                *authz_calls,
                *_dependency_authz_refs(
                    line,
                    line_number,
                    dependency_aliases,
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
                route_path = _route_path_from_decorator_lines(decorator_lines)
                if route_path is not None:
                    pending_route = (
                        method,
                        route_path,
                        decorator_line,
                        authz_calls,
                    )
                pending_route_decorator = None
            else:
                pending_route_decorator = (
                    method,
                    decorator_line,
                    decorator_lines,
                    authz_calls,
                )
            continue

        route_match = ROUTE_DECORATOR_PATTERN.search(line)
        if route_match is not None:
            pending_route = (
                route_match.group(1).upper(),
                route_match.group(2),
                line_number,
                _dependency_authz_refs(line, line_number, dependency_aliases),
            )
            continue
        route_start_match = ROUTE_DECORATOR_START_PATTERN.search(line)
        if route_start_match is not None:
            pending_route_decorator = (
                route_start_match.group(1).upper(),
                line_number,
                [line],
                _dependency_authz_refs(line, line_number, dependency_aliases),
            )
            continue

        if line.strip():
            indent = _indent_width(line)
            function_stack = [
                (function_name, function_indent)
                for function_name, function_indent in function_stack
                if function_indent < indent
            ]

        imported_aliases = _imported_authz_aliases(line)
        if imported_aliases and not function_stack:
            for alias_name, call_name in imported_aliases:
                dependency_aliases[alias_name] = call_name
            continue

        alias = _dependency_alias(line)
        if alias is not None and not function_stack:
            alias_name, call_name = alias
            dependency_aliases[alias_name] = call_name
            continue

        function_match = FUNCTION_PATTERN.match(line)
        if function_match is not None:
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
            method, route_path, decorator_line, decorator_authz_calls = pending_route
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
            for call_name, dependency_line in _dependency_wrapper_refs(
                line,
                line_number,
                dependency_aliases,
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

        model_match = MODEL_PATTERN.match(line)
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
            or model_match is not None
            or pending_signature_authz is not None
            or line.strip().startswith("@")
        ):
            continue

        current_function = _current_function(function_stack)
        for call_name in _called_names(line):
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
        service_calls = [
            fact.symbol_name
            for fact in facts
            if fact.fact_type == "service_call"
            and isinstance(fact.payload, dict)
            and fact.payload.get("caller") == handler
            and isinstance(fact.symbol_name, str)
        ]
        has_service_authz = any(
            fact.fact_type == "authz_check"
            and isinstance(fact.payload, dict)
            and fact.payload.get("handler") in service_calls
            for fact in facts
        )
        if has_service_authz:
            continue
        sink_count = sum(
            1
            for fact in facts
            if fact.fact_type == "sensitive_sink"
            and isinstance(fact.payload, dict)
            and (
                fact.payload.get("handler") == handler
                or fact.payload.get("handler") in service_calls
            )
        )
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
                },
            )
        )
    return candidates


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
        return []

    for index, token in enumerate(tokens[:-1]):
        next_token = tokens[index + 1]
        if token.type == tokenize.NAME and next_token.string == "(":
            calls.append(token.string)
    return calls


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
) -> list[tuple[str, int]]:
    authz_names = {call_name for call_name, _ in _dependency_authz_refs(
        line,
        line_number,
        dependency_aliases,
    )}
    return [
        (call_name, line_number)
        for call_name in _dependency_calls(line)
        if call_name not in authz_names
    ]


def _dependency_calls(line: str) -> list[str]:
    return DEPENDENCY_CALL_PATTERN.findall(line)


def _dependency_alias(line: str) -> tuple[str, str] | None:
    match = DEPENDENCY_ALIAS_PATTERN.match(line)
    if match is None:
        return None
    alias_name = match.group(1)
    call_name = match.group(2)
    if not _is_authz_call(call_name):
        return None
    return alias_name, call_name


def _imported_authz_aliases(line: str) -> list[tuple[str, str]]:
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
        if _is_authz_call(call_name):
            aliases.append((alias_name, call_name))
    return aliases


def _line_references_name(line: str, name: str) -> bool:
    return re.search(rf"\b{re.escape(name)}\b", line) is not None


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


def _route_path_from_decorator_lines(lines: list[str]) -> str | None:
    for line in lines:
        match = STRING_LITERAL_PATTERN.search(line)
        if match is not None:
            return match.group(1)
    return None


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
    if authz_hint == "permission_check":
        return 3
    if authz_hint == "role_check":
        return 2
    return 1


def _count_facts(facts: list[CodebaseFactCandidate], fact_type: str) -> int:
    return sum(1 for fact in facts if fact.fact_type == fact_type)
