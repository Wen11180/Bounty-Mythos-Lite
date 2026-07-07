from dataclasses import dataclass
from io import StringIO
import re
import tokenize


ROUTE_DECORATOR_PATTERN = re.compile(
    r"@\w+\.(get|post|put|patch|delete)\(\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
FUNCTION_PATTERN = re.compile(r"\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
MODEL_PATTERN = re.compile(r"\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)")
DEPENDENCY_CALL_PATTERN = re.compile(r"\bDepends\(\s*([A-Za-z_][A-Za-z0-9_]*)")
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

    facts = _dedupe_handler_authz_facts(_dedupe_facts(facts))
    return CodebaseMapResult(
        facts=_dedupe_facts([*facts, *_authorization_gap_candidates(facts)]),
        file_count=mapped_file_count,
    )


def _map_file(*, source_path: str, content: str) -> list[CodebaseFactCandidate]:
    facts: list[CodebaseFactCandidate] = []
    pending_route: tuple[str, str, int, list[tuple[str, int]]] | None = None
    function_stack: list[tuple[str, int]] = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        route_match = ROUTE_DECORATOR_PATTERN.search(line)
        if route_match is not None:
            pending_route = (
                route_match.group(1).upper(),
                route_match.group(2),
                line_number,
                [(call_name, line_number) for call_name in _dependency_authz_calls(line)],
            )
            continue

        if line.strip():
            indent = _indent_width(line)
            function_stack = [
                (function_name, function_indent)
                for function_name, function_indent in function_stack
                if function_indent < indent
            ]

        function_match = FUNCTION_PATTERN.match(line)
        if function_match is not None:
            function_stack.append((function_match.group(1), _indent_width(line)))
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
                *[(call_name, line_number) for call_name in _dependency_authz_calls(line)],
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
            pending_route = None

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

        if function_match is not None or model_match is not None or line.strip().startswith("@"):
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
