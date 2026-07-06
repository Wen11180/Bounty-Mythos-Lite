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

    return CodebaseMapResult(
        facts=_dedupe_facts(facts),
        file_count=mapped_file_count,
    )


def _map_file(*, source_path: str, content: str) -> list[CodebaseFactCandidate]:
    facts: list[CodebaseFactCandidate] = []
    pending_route: tuple[str, str, int] | None = None
    current_function: str | None = None

    for line_number, line in enumerate(content.splitlines(), start=1):
        route_match = ROUTE_DECORATOR_PATTERN.search(line)
        if route_match is not None:
            pending_route = (
                route_match.group(1).upper(),
                route_match.group(2),
                line_number,
            )
            continue

        function_match = FUNCTION_PATTERN.match(line)
        if function_match is not None:
            current_function = function_match.group(1)
        if function_match is not None and pending_route is not None:
            method, route_path, decorator_line = pending_route
            facts.append(
                CodebaseFactCandidate(
                    fact_type="route_handler",
                    source_path=source_path,
                    symbol_name=function_match.group(1),
                    route_method=method,
                    route_path=route_path,
                    authz_hint=None,
                    sensitivity_label="low",
                    payload={
                        "handler": function_match.group(1),
                        "line": decorator_line,
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

    return facts


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


def _count_facts(facts: list[CodebaseFactCandidate], fact_type: str) -> int:
    return sum(1 for fact in facts if fact.fact_type == fact_type)
