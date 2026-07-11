from __future__ import annotations

import ast
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any

from app.codebase_map import (
    CodebaseFactCandidate,
    SENSITIVE_SINK_NAMES,
    map_authorized_code_files,
)


SAFETY_FIELDS = (
    "execution_allowed",
    "dispatch_allowed",
    "validation_allowed",
    "candidate_promotion_allowed",
    "report_submission_allowed",
    "raw_payload_processed",
)
REQUIRED_ARTIFACT_KINDS = ("scope", "policy", "code", "api", "har")
STAGE_KEYS = (
    "candidate_hunter_snapshot",
    "candidate_hunter_evidence_request",
    "candidate_hunter_decision",
    "candidate_hunter_rerank",
)


def build_candidate_hunter_observations(
    *,
    pipeline_run_id: str,
    candidates: list[dict],
    code_files: list[dict],
    surface_facts: list[dict],
    context_facts: list[dict],
) -> dict[str, Any]:
    run_id = _safe_text(pipeline_run_id)
    mapped_code = map_authorized_code_files(
        {
            "authorized_code_files": [
                {"path": path, "content": content}
                for item in code_files
                if isinstance(item, dict)
                if (path := _safe_text(item.get("path")))
                and isinstance((content := item.get("content")), str)
            ]
        }
    )
    semantic_code_facts = _python_semantic_facts(code_files)
    safe_surface_facts = [
        fact
        for item in surface_facts
        if isinstance(item, dict)
        if (fact := _safe_external_fact(item)) is not None
    ]
    safe_context_facts = [
        fact
        for item in context_facts
        if isinstance(item, dict)
        if (fact := _safe_external_fact(item)) is not None
    ]
    projected_facts = [
        *(_safe_code_fact(fact) for fact in mapped_code.facts),
        *semantic_code_facts,
        *safe_surface_facts,
        *safe_context_facts,
    ]
    states = []
    initial_states = []
    if run_id:
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            candidate_id = _safe_text(candidate.get("hypothesis_id"))
            if not candidate_id:
                continue
            route = _candidate_route(candidate)
            matching_code_facts = _matching_code_facts(mapped_code.facts, route)
            handler = _route_handler(matching_code_facts, route)
            route_source_paths = {
                _safe_source_name(fact.source_path)
                for fact in matching_code_facts
                if fact.fact_type == "route_handler"
                and _route(fact.route_method, fact.route_path) == route
            }
            matching_semantic_facts = [
                fact
                for fact in semantic_code_facts
                if fact.get("handler") == handler
                and fact.get("source_path") in route_source_paths
            ]
            matching_surface_facts = [
                fact
                for fact in safe_surface_facts
                if _fact_matches_route(fact, route) or "route" not in fact
            ]
            candidate_facts = _safe_candidate_source_facts(candidate.get("source_facts"))
            matching_candidate_facts = [
                fact
                for fact in candidate_facts
                if _fact_matches_route(fact, route) or "route" not in fact
            ]
            initial_evidence_refs = _ordered_unique(
                _text(fact.get("fact_ref"))
                for fact in matching_candidate_facts
                if _text(fact.get("fact_ref"))
            )
            initial_observed_kinds = [
                kind
                for kind in REQUIRED_ARTIFACT_KINDS
                if any(
                    fact.get("artifact_kind") == kind
                    for fact in matching_candidate_facts
                )
            ]
            initial_gap_fact = _matching_gap_fact(
                matching_candidate_facts,
                [],
            )
            evidence_facts = [
                *safe_context_facts,
                *matching_candidate_facts,
                *(_safe_code_fact(fact) for fact in matching_code_facts),
                *matching_semantic_facts,
                *matching_surface_facts,
            ]
            evidence_refs = _ordered_unique(
                _text(fact.get("fact_ref"))
                for fact in evidence_facts
                if _text(fact.get("fact_ref"))
            )
            observed_kinds = [
                kind
                for kind in REQUIRED_ARTIFACT_KINDS
                if any(fact.get("artifact_kind") == kind for fact in evidence_facts)
            ]
            gap_fact = _matching_gap_fact(
                matching_candidate_facts,
                matching_code_facts,
            )
            shared_root, shared_ref = _shared_root(
                mapped_code.facts,
                handler,
            )
            root_cause = _text(gap_fact.get("root_cause")) if gap_fact else ""
            root_symbol = _text(gap_fact.get("symbol_name")) if gap_fact else handler
            root_cause_id = _normalized_root_id(root_cause, root_symbol)
            state = {
                "candidate_id": candidate_id,
                "candidate_key": f"{run_id}:{candidate_id}",
                "vuln_type": _safe_text(candidate.get("vuln_type")),
                "root_cause_id": root_cause_id,
                "route": route,
                "source_fact_refs": evidence_refs,
                "observed_artifact_kinds": observed_kinds,
                "required_artifact_kinds": list(REQUIRED_ARTIFACT_KINDS),
                "evidence_trace_status": (
                    "traceable"
                    if set(REQUIRED_ARTIFACT_KINDS).issubset(observed_kinds)
                    else "needs_evidence"
                ),
                "priority_score": _priority_score(candidate.get("priority_score")),
                "gap_evidence_ref": _text(gap_fact.get("fact_ref")) if gap_fact else "",
                "shared_root": shared_root,
                "shared_root_evidence_ref": shared_ref,
                "refutation_questions": _refutation_questions(candidate),
                "reanalysis_status": "completed",
            }
            control_fact = next(
                (
                    fact
                    for fact in matching_semantic_facts
                    if fact.get("fact_type") == "ownership_guard"
                ),
                None,
            )
            public_fact = next(
                (
                    fact
                    for fact in matching_semantic_facts
                    if fact.get("fact_type") == "public_filter"
                ),
                None,
            )
            if control_fact is not None:
                state["control_evidence_ref"] = control_fact["fact_ref"]
            if public_fact is not None:
                state["public_evidence_ref"] = public_fact["fact_ref"]
            initial_root_cause = (
                _text(initial_gap_fact.get("root_cause"))
                if initial_gap_fact
                else ""
            )
            initial_root_symbol = (
                _text(initial_gap_fact.get("symbol_name"))
                if initial_gap_fact
                else handler
            )
            initial_state = {
                **state,
                "root_cause_id": _normalized_root_id(
                    initial_root_cause,
                    initial_root_symbol,
                ),
                "source_fact_refs": initial_evidence_refs,
                "observed_artifact_kinds": initial_observed_kinds,
                "evidence_trace_status": (
                    "traceable"
                    if set(REQUIRED_ARTIFACT_KINDS).issubset(
                        initial_observed_kinds
                    )
                    else "needs_evidence"
                ),
                "gap_evidence_ref": (
                    _text(initial_gap_fact.get("fact_ref"))
                    if initial_gap_fact
                    else ""
                ),
                "shared_root": "",
                "shared_root_evidence_ref": "",
                "reanalysis_status": "pending",
            }
            initial_state.pop("control_evidence_ref", None)
            initial_state.pop("public_evidence_ref", None)
            initial_states.append(initial_state)
            states.append(state)
    return {
        "schema_version": "candidate_hunter_observations_v1",
        "pipeline_run_id": run_id,
        "initial_candidate_states": initial_states,
        "candidate_states": states,
        "facts": projected_facts,
        "safety_status": "safe",
        **_false_safety_fields(),
    }


def _safe_code_fact(fact: CodebaseFactCandidate) -> dict[str, Any]:
    source_path = _safe_source_name(fact.source_path)
    symbol_name = _safe_text(fact.symbol_name)
    projected: dict[str, Any] = {
        "fact_ref": _code_fact_ref(source_path, symbol_name, fact.fact_type),
        "fact_type": _safe_text(fact.fact_type),
        "artifact_kind": "code",
        "source_path": source_path,
    }
    if symbol_name:
        projected["symbol_name"] = symbol_name
    route = _route(fact.route_method, fact.route_path)
    if route:
        projected["route"] = route
    if isinstance(fact.payload, dict):
        for key in ("handler", "caller"):
            if value := _safe_text(fact.payload.get(key)):
                projected[key] = value
        if root_cause := _safe_text(fact.payload.get("root_cause")):
            projected["root_cause"] = root_cause
    return projected


def _python_semantic_facts(code_files: list[dict]) -> list[dict[str, Any]]:
    facts = []
    for item in code_files:
        if not isinstance(item, dict):
            continue
        source_path = _safe_source_name(item.get("path"))
        content = item.get("content")
        if not source_path or not isinstance(content, str) or not source_path.endswith(".py"):
            continue
        try:
            tree = ast.parse(content)
        except SyntaxError:
            continue
        functions = {
            node.name: node
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        ownership_helpers = {
            name for name, function in functions.items() if _function_has_ownership_guard(function)
        }
        public_helpers = {
            name for name, function in functions.items() if _function_has_public_filter(function)
        }
        for handler, function in functions.items():
            facts.extend(
                _handler_semantic_facts(
                    source_path,
                    handler,
                    function,
                    ownership_helpers,
                    public_helpers,
                )
            )
    return facts


def _handler_semantic_facts(
    source_path: str,
    handler: str,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    ownership_helpers: set[str],
    public_helpers: set[str],
) -> list[dict[str, Any]]:
    sink_index = next(
        (
            index
            for index, statement in enumerate(function.body)
            if _statement_sensitive_sink_calls(statement)
        ),
        None,
    )
    if sink_index is None:
        return []
    facts = []
    for index, statement in enumerate(function.body[:sink_index]):
        called_names = _statement_called_names(statement)
        for helper in sorted(ownership_helpers & called_names):
            facts.append(
                _semantic_code_fact(
                    source_path,
                    helper,
                    "ownership_guard",
                    handler=handler,
                )
            )

        assignment = _assigned_call(statement)
        if assignment is None:
            continue
        variable, helper = assignment
        if helper not in public_helpers:
            continue
        if any(
            _sink_call_uses_name(sink_call, variable)
            for later_statement in function.body[index + 1 :]
            for sink_call in _statement_sensitive_sink_calls(later_statement)
        ):
            facts.append(
                _semantic_code_fact(
                    source_path,
                    helper,
                    "public_filter",
                    handler=handler,
                )
            )
    return facts


def _semantic_code_fact(
    source_path: str,
    symbol_name: str,
    fact_type: str,
    *,
    handler: str,
) -> dict[str, Any]:
    return {
        "fact_ref": f"code:{source_path}:{symbol_name}:{fact_type}",
        "fact_type": fact_type,
        "artifact_kind": "code",
        "source_path": source_path,
        "symbol_name": symbol_name,
        "handler": handler,
    }


def _statement_called_names(statement: ast.stmt) -> set[str]:
    if isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call):
        if name := _ast_call_name(statement.value):
            return {name}
    return set()


def _statement_sensitive_sink_calls(statement: ast.stmt) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(statement)
        if isinstance(node, ast.Call)
        and _ast_call_name(node).lower() in SENSITIVE_SINK_NAMES
    ]


def _assigned_call(statement: ast.stmt) -> tuple[str, str] | None:
    if (
        isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and isinstance(statement.value, ast.Call)
    ):
        helper = _ast_call_name(statement.value)
        return (statement.targets[0].id, helper) if helper else None
    return None


def _sink_call_uses_name(call: ast.Call, variable: str) -> bool:
    return any(
        _ast_identifier(node).split(".")[0] == variable
        for argument in [*call.args, *(keyword.value for keyword in call.keywords)]
        for node in ast.walk(argument)
        if isinstance(node, (ast.Name, ast.Attribute))
    )


def _ast_call_name(call: ast.Call) -> str:
    return _ast_identifier(call.func).split(".")[-1]


def _function_has_ownership_guard(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    for node in ast.walk(function):
        if not isinstance(node, ast.If) or not _raises_in_block(node.body):
            continue
        comparison = node.test
        if (
            not isinstance(comparison, ast.Compare)
            or len(comparison.ops) != 1
            or not isinstance(comparison.ops[0], ast.NotEq)
            or len(comparison.comparators) != 1
        ):
            continue
        left = _ast_identifier(comparison.left)
        right = _ast_identifier(comparison.comparators[0])
        if _is_ownership_boundary_pair(left, right):
            return True
    return False


def _raises_in_block(nodes: list[ast.stmt]) -> bool:
    return any(isinstance(nested, ast.Raise) for node in nodes for nested in ast.walk(node))


def _is_ownership_boundary_pair(left: str, right: str) -> bool:
    boundary_fields = {
        "owner_id",
        "user_id",
        "tenant_id",
        "account_id",
        "org_id",
        "workspace_id",
    }
    principals = {
        "current_user.id",
        "request.user.id",
        "user.id",
    }
    return (
        left.split(".")[-1] in boundary_fields and right in principals
        or right.split(".")[-1] in boundary_fields and left in principals
    )


def _function_has_public_filter(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    return any(
        keyword.arg in {"visibility", "access", "audience"}
        and isinstance(keyword.value, ast.Constant)
        and isinstance(keyword.value.value, str)
        and keyword.value.value.lower() == "public"
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        for keyword in node.keywords
    )


def _ast_identifier(value: ast.AST) -> str:
    if isinstance(value, ast.Name):
        return value.id
    if isinstance(value, ast.Attribute):
        parent = _ast_identifier(value.value)
        return f"{parent}.{value.attr}" if parent else value.attr
    return ""


def _safe_external_fact(value: dict) -> dict[str, Any] | None:
    artifact_kind = _safe_text(value.get("artifact_kind"))
    fact_type = _safe_text(value.get("fact_type"))
    if artifact_kind not in REQUIRED_ARTIFACT_KINDS or not fact_type:
        return None
    route = _route(value.get("route_method"), value.get("route_path"))
    fact_ref = f"{artifact_kind}:{fact_type}"
    projected: dict[str, Any] = {
        "fact_ref": fact_ref,
        "fact_type": fact_type,
        "artifact_kind": artifact_kind,
    }
    if route:
        projected["route"] = route
        fact_ref = f"{artifact_kind}:{route['method']}:{route['path']}"
    access_mode = _safe_text(value.get("access_mode"))
    if artifact_kind == "api" and access_mode in {"protected", "public"}:
        projected["access_mode"] = access_mode
        suffix = "security_required" if access_mode == "protected" else "public_access"
        fact_ref = f"{fact_ref}:{suffix}"
    projected["fact_ref"] = fact_ref
    return projected


def _safe_candidate_source_facts(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    facts = []
    for item in value:
        if not isinstance(item, dict):
            continue
        artifact_kind = _safe_text(item.get("artifact_kind"))
        fact_type = _safe_text(item.get("fact_type"))
        if artifact_kind not in REQUIRED_ARTIFACT_KINDS or not fact_type:
            continue
        source_path = _safe_source_name(item.get("source_path"))
        symbol_name = _safe_text(item.get("symbol_name"))
        fact: dict[str, Any] = {
            "fact_ref": (
                _code_fact_ref(source_path, symbol_name, fact_type)
                if artifact_kind == "code"
                else f"{artifact_kind}:{fact_type}"
            ),
            "fact_type": fact_type,
            "artifact_kind": artifact_kind,
        }
        route = _route(item.get("route_method"), item.get("route_path"))
        if route:
            fact["route"] = route
        if source_path:
            fact["source_path"] = source_path
        if symbol_name:
            fact["symbol_name"] = symbol_name
        if root_cause := _safe_text(item.get("root_cause")):
            fact["root_cause"] = root_cause
        facts.append(fact)
    return facts


def _candidate_route(candidate: dict) -> dict[str, str]:
    location = _safe_text(candidate.get("location"))
    parts = location.split(maxsplit=1)
    if len(parts) == 2:
        if route := _route(parts[0], parts[1]):
            return route
    source_facts = candidate.get("source_facts")
    if isinstance(source_facts, list):
        for fact in source_facts:
            if isinstance(fact, dict):
                if route := _route(fact.get("route_method"), fact.get("route_path")):
                    return route
    return {}


def _route(method: object, path: object) -> dict[str, str]:
    safe_method = _safe_text(method).upper()
    safe_path = _safe_text(path)
    if not safe_method or not safe_path.startswith("/"):
        return {}
    return {"method": safe_method, "path": safe_path}


def _fact_matches_route(fact: dict, route: dict[str, str]) -> bool:
    fact_route = fact.get("route")
    return (
        bool(route)
        and isinstance(fact_route, dict)
        and fact_route.get("method") == route.get("method")
        and _route_paths_match(
            _text(fact_route.get("path")),
            _text(route.get("path")),
        )
    )


def _route_paths_match(left: str, right: str) -> bool:
    left_segments = [segment for segment in left.strip("/").split("/") if segment]
    right_segments = [segment for segment in right.strip("/").split("/") if segment]
    if len(left_segments) != len(right_segments):
        return False
    return all(
        _route_segment_matches(left_segment, right_segment)
        or _route_segment_matches(right_segment, left_segment)
        for left_segment, right_segment in zip(
            left_segments,
            right_segments,
            strict=True,
        )
    )


def _route_segment_matches(pattern: str, value: str) -> bool:
    return (
        pattern == value
        or pattern.startswith(":")
        or pattern.startswith("{")
        and pattern.endswith("}")
        or pattern.startswith("<")
        and pattern.endswith(">")
    )


def _matching_code_facts(
    facts: list[CodebaseFactCandidate],
    route: dict[str, str],
) -> list[CodebaseFactCandidate]:
    handlers = {
        _safe_text(fact.payload.get("handler"))
        for fact in facts
        if fact.fact_type == "route_handler"
        and _route(fact.route_method, fact.route_path) == route
        and isinstance(fact.payload, dict)
    }
    calls_by_handler: dict[str, list[CodebaseFactCandidate]] = {}
    for fact in facts:
        if fact.fact_type == "service_call" and isinstance(fact.payload, dict):
            caller = _safe_text(fact.payload.get("caller"))
            if caller:
                calls_by_handler.setdefault(caller, []).append(fact)
    reachable = set(handlers)
    pending = list(handlers)
    while pending:
        caller = pending.pop()
        for fact in calls_by_handler.get(caller, []):
            callee = _safe_text(fact.symbol_name)
            if callee and callee not in reachable:
                reachable.add(callee)
                pending.append(callee)
    return [
        fact
        for fact in facts
        if (
            _route(fact.route_method, fact.route_path) == route
            or (
                isinstance(fact.payload, dict)
                and (
                    _safe_text(fact.payload.get("handler")) in reachable
                    or _safe_text(fact.payload.get("caller")) in reachable
                )
            )
        )
    ]


def _matching_gap_fact(
    candidate_facts: list[dict[str, Any]],
    code_facts: list[CodebaseFactCandidate],
) -> dict[str, Any] | None:
    for fact in candidate_facts:
        if fact.get("fact_type") == "authorization_gap_candidate":
            return fact
    for fact in code_facts:
        if fact.fact_type == "authorization_gap_candidate":
            return _safe_code_fact(fact)
    return None


def _route_handler(
    facts: list[CodebaseFactCandidate],
    route: dict[str, str],
) -> str:
    for fact in facts:
        if (
            fact.fact_type == "route_handler"
            and _route(fact.route_method, fact.route_path) == route
            and isinstance(fact.payload, dict)
        ):
            return _safe_text(fact.payload.get("handler"))
    return ""


def _reachable_code_symbols(
    facts: list[CodebaseFactCandidate],
    handler: str,
) -> set[str]:
    if not handler:
        return set()
    calls: dict[str, set[str]] = {}
    for fact in facts:
        if fact.fact_type != "service_call" or not isinstance(fact.payload, dict):
            continue
        caller = _safe_text(fact.payload.get("caller"))
        callee = _safe_text(fact.symbol_name)
        if caller and callee:
            calls.setdefault(caller, set()).add(callee)
    reachable = {handler}
    pending = [handler]
    while pending:
        current = pending.pop()
        for callee in calls.get(current, set()) - reachable:
            reachable.add(callee)
            pending.append(callee)
    return reachable


def _shared_root(
    facts: list[CodebaseFactCandidate],
    handler: str,
) -> tuple[str, str]:
    if not handler:
        return "", ""
    calls: dict[str, set[str]] = {}
    sinks = set()
    source_by_symbol: dict[str, str] = {}
    for fact in facts:
        if fact.fact_type == "service_call" and isinstance(fact.payload, dict):
            caller = _safe_text(fact.payload.get("caller"))
            callee = _safe_text(fact.symbol_name)
            if caller and callee:
                calls.setdefault(caller, set()).add(callee)
                source_by_symbol.setdefault(callee, _safe_source_name(fact.source_path))
        elif fact.fact_type == "sensitive_sink" and isinstance(fact.payload, dict):
            sink_handler = _safe_text(fact.payload.get("handler"))
            if sink_handler:
                sinks.add(sink_handler)
                source_by_symbol.setdefault(
                    sink_handler,
                    _safe_source_name(fact.source_path),
                )

    def reaches_sink(start: str) -> bool:
        pending = [start]
        seen = set()
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            if current in sinks:
                return True
            pending.extend(calls.get(current, set()) - seen)
        return False

    root = next(
        (callee for callee in sorted(calls.get(handler, set())) if reaches_sink(callee)),
        handler if handler in sinks else "",
    )
    if not root:
        return "", ""
    return root, _code_fact_ref(source_by_symbol.get(root, "code.py"), root, "service_call")


def _normalized_root_id(root_cause: str, symbol_name: str) -> str:
    root = _identifier(root_cause)
    symbol = _identifier(symbol_name)
    return f"{root}:{symbol}" if root and symbol else ""


def _identifier(value: object) -> str:
    text = _safe_text(value).lower()
    return re.sub(r"[^a-z0-9]+", "_", text).strip("_")


def _code_fact_ref(source_path: str, symbol_name: str, fact_type: str) -> str:
    name = source_path or "code.py"
    symbol = symbol_name or _safe_text(fact_type)
    return f"code:{name}:{symbol}"


def _safe_source_name(value: object) -> str:
    text = _safe_text(value)
    return _safe_text(Path(text).name) if text else ""


def _safe_text(value: object) -> str:
    text = _text(value)
    lowered = text.lower()
    unsafe_markers = (
        "authorization:",
        "bearer ",
        "cookie:",
        "set-cookie:",
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "password",
        "client_secret",
        "credential",
        "secret",
        "real user data",
        "production user",
    )
    return "" if any(marker in lowered for marker in unsafe_markers) else text


def _ordered_unique(values: Any) -> list[str]:
    unique = []
    for value in values:
        if value and value not in unique:
            unique.append(value)
    return unique


def advance_candidate_hunter_round(
    *,
    pipeline_run_id: str,
    round_number: int,
    candidate_states: list[dict],
    observations: dict,
    prior_decisions: list[dict],
) -> dict[str, Any]:
    snapshot_candidates = sorted(
        (_snapshot_candidate(state) for state in candidate_states),
        key=lambda state: _text(state.get("candidate_id")),
    )
    safe_candidate_states = snapshot_candidates
    state_digest = _state_digest(
        pipeline_run_id,
        round_number,
        snapshot_candidates,
        prior_decisions,
    )
    unsafe_fields = [
        field
        for field in SAFETY_FIELDS
        if not isinstance(observations, dict) or observations.get(field) is not False
    ]
    if unsafe_fields:
        return {
            "safety_status": "blocked",
            "safety_failures": [f"{field}_must_be_false" for field in unsafe_fields],
            "candidate_decisions": [],
            "evidence_requests": [],
            "final_candidates": [],
            "snapshot_candidates": [],
            "state_digest": state_digest,
            "stop_candidate": "safety_invariant_failed",
            "unresolved_candidates": [],
            **_false_safety_fields(),
        }
    decisions = _safe_prior_decisions(prior_decisions)
    final_candidates = [
        dict(decision["candidate_projection"])
        for decision in decisions
        if decision.get("disposition") == "retained"
        and isinstance(decision.get("candidate_projection"), dict)
    ]
    prior_terminal_ids = {
        decision["candidate_id"] for decision in decisions
    }
    evidence_requests = []
    unresolved_candidates = []
    processable_states = [
        state
        for state in safe_candidate_states
        if _text(state.get("candidate_id")) not in prior_terminal_ids
    ]
    duplicate_targets = _duplicate_targets(processable_states, pipeline_run_id)
    for state in processable_states:
        missing_evidence = _missing_evidence(state, pipeline_run_id)
        if missing_evidence:
            candidate_id = _text(state.get("candidate_id"))
            requested_artifact_kinds = _requested_artifact_kinds(
                state,
                missing_evidence,
            )
            evidence_requests.append(
                {
                    "candidate_id": candidate_id,
                    "candidate_key": _text(state.get("candidate_key")),
                    "missing_evidence": missing_evidence,
                    "requested_artifact_kinds": requested_artifact_kinds,
                    "refutation_questions": _refutation_questions(state),
                    "inspection_targets": _inspection_targets(
                        state,
                        requested_artifact_kinds,
                    ),
                    "reason": "Missing observed evidence prevents a terminal decision.",
                    "decision_change_reason": (
                        "A cited local control may refute or suppress the candidate; "
                        "a complete unguarded trace may retain it for human review."
                    ),
                }
            )
            unresolved_candidates.append(
                {
                    "candidate_id": candidate_id,
                    "candidate_key": _text(state.get("candidate_key")),
                    "missing_evidence": missing_evidence,
                }
            )
            continue
        if not _text(state.get("gap_evidence_ref")):
            continue
        evidence_refs = _string_list(state.get("source_fact_refs"))
        control_ref = _text(state.get("control_evidence_ref"))
        if control_ref and control_ref in evidence_refs:
            decisions.append(
                {
                    "candidate_id": state["candidate_id"],
                    "root_cause_id": state["root_cause_id"],
                    "disposition": "refuted",
                    "evidence_refs": [control_ref],
                }
            )
            continue
        public_ref = _text(state.get("public_evidence_ref"))
        if public_ref and public_ref in evidence_refs:
            decisions.append(
                {
                    "candidate_id": state["candidate_id"],
                    "root_cause_id": state["root_cause_id"],
                    "disposition": "suppressed",
                    "evidence_refs": [public_ref],
                }
            )
            continue
        duplicate_target = duplicate_targets.get(_text(state.get("candidate_id")))
        if duplicate_target is not None:
            canonical_root_id, shared_ref = duplicate_target
            decisions.append(
                {
                    "candidate_id": state["candidate_id"],
                    "root_cause_id": state["root_cause_id"],
                    "disposition": "deduplicated",
                    "evidence_refs": [shared_ref],
                    "duplicate_of": canonical_root_id,
                }
            )
            continue
        candidate_projection = {
            "candidate_id": state["candidate_id"],
            "rank": len(final_candidates) + 1,
            "vuln_type": state["vuln_type"],
            "root_cause_id": state["root_cause_id"],
            "route": state["route"],
            "source_fact_refs": evidence_refs,
            "evidence_trace_status": "traceable",
            "human_validation_readiness": "ready",
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
            "safe_validation_plan": [
                "Review the cited local evidence before any validation request."
            ],
            "next_allowed_action": "Human review of the cited local evidence.",
            "safety_blockers": [
                "execute_live_validation",
                "touch_real_user_data",
                "submit_report",
            ],
        }
        decisions.append(
            {
                "candidate_id": state["candidate_id"],
                "root_cause_id": state["root_cause_id"],
                "disposition": "retained",
                "evidence_refs": evidence_refs,
                "candidate_projection": candidate_projection,
                "priority_score": _priority_score(state.get("priority_score")),
                "evidence_completeness_score": _evidence_completeness_score(state),
            }
        )
        final_candidates.append(candidate_projection)
    ranking_by_id = {
        decision["candidate_id"]: (
            _priority_score(decision.get("evidence_completeness_score")),
            _priority_score(decision.get("priority_score")),
        )
        for decision in decisions
        if decision.get("disposition") == "retained"
    }
    final_candidates.sort(
        key=lambda candidate: (
            -ranking_by_id.get(candidate["candidate_id"], (0, 0))[0],
            -ranking_by_id.get(candidate["candidate_id"], (0, 0))[1],
            candidate["candidate_id"],
        )
    )
    final_candidates = final_candidates[:5]
    for rank, candidate in enumerate(final_candidates, start=1):
        candidate["rank"] = rank
    decided_ids = {
        _text(decision.get("candidate_id"))
        for decision in decisions
        if isinstance(decision, dict)
        and _text(decision.get("disposition"))
        in {"retained", "refuted", "deduplicated", "suppressed"}
    }
    candidate_ids = {
        _text(candidate.get("candidate_id"))
        for candidate in snapshot_candidates
        if _text(candidate.get("candidate_id"))
    }
    if not snapshot_candidates:
        stop_candidate = "no_candidates"
    elif candidate_ids and candidate_ids.issubset(decided_ids):
        stop_candidate = "all_candidates_terminal"
    elif unresolved_candidates:
        stop_candidate = "no_state_change"
    else:
        stop_candidate = "no_processable_candidates"
    return {
        "schema_version": "candidate_hunter_loop_v1",
        "round": round_number,
        "safety_status": "safe",
        "candidate_decisions": decisions,
        "evidence_requests": evidence_requests,
        "final_candidates": final_candidates,
        "snapshot_candidates": snapshot_candidates,
        "state_digest": state_digest,
        "stop_candidate": stop_candidate,
        "unresolved_candidates": unresolved_candidates,
        **_false_safety_fields(),
    }


def run_candidate_hunter_loop(
    *,
    repository: Any,
    record: Any,
    policy_text: str,
    candidates: list[dict],
    observations: dict | None,
) -> dict[str, Any]:
    run_id = _text(getattr(record, "id", None))
    authoritative_record = repository.get_pipeline_run(run_id) if run_id else None
    if (
        authoritative_record is None
        or _text(authoritative_record.scope_status) != "in_scope"
    ):
        return {
            "status": "scope_not_in_scope",
            "pipeline_run_id": run_id,
            "final_candidates": [],
            "candidate_decisions": [],
            **_false_safety_fields(),
        }
    if (
        not isinstance(observations, dict)
        or not isinstance(observations.get("candidate_states"), list)
        or any(observations.get(field) is not False for field in SAFETY_FIELDS)
    ):
        return {
            "status": "blocked",
            "pipeline_run_id": run_id,
            "round_count": 0,
            "stage_refs": [],
            "state_digest": "",
            "stop_reason": "unsafe_observations",
            "final_candidates": [],
            "candidate_decisions": [],
            **_false_safety_fields(),
        }
    owners = _find_candidate_hunter_owners(repository, run_id)
    if len(owners) > 1:
        return {
            "status": "blocked",
            "pipeline_run_id": run_id,
            "round_count": 0,
            "stage_refs": [],
            "state_digest": "",
            "stop_reason": "ambiguous_loop_owner",
            "final_candidates": [],
            "candidate_decisions": [],
            **_false_safety_fields(),
        }
    if not owners:
        campaign_payload = {
            "pipeline_run_id": run_id,
            "source_pipeline_run_ref": f"pipeline_run:{run_id}",
            "submission_blocked": True,
            **_false_safety_fields(),
        }
        campaign = repository.create_campaign(
            program_id=authoritative_record.program_id,
            name=f"Candidate Hunter loop for {run_id}",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text=policy_text,
            default_asset=authoritative_record.asset,
            target_classes=["authorization"],
            allowed_tools=["static_analyzer", "api_artifact_mapper"],
            created_by="candidate_hunter_loop",
            payload=campaign_payload,
        )
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=None,
            token_budget=None,
            tool_call_budget=0,
            validation_budget=0,
        )
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type="candidate_hunter_loop",
            agent_type="candidate_hunter",
            title=f"Review candidates for {run_id}",
            input_refs=[f"pipeline_run:{run_id}"],
            payload={
                "pipeline_run_id": run_id,
                "submission_blocked": True,
                **_false_safety_fields(),
            },
        )
    else:
        campaign, task = owners[0]
    candidate_states = observations.get("candidate_states", [])
    if not isinstance(candidate_states, list):
        candidate_states = []
    initial_candidate_states = observations.get("initial_candidate_states")
    if not isinstance(initial_candidate_states, list):
        initial_candidate_states = candidate_states
    existing_stages = [
        stage
        for stage in repository.list_pipeline_stages_for_run(run_id)
        if stage.stage_key in STAGE_KEYS
        and stage.campaign_id == campaign.id
        and stage.task_id == task.id
    ]
    existing_rounds = [
        stage.payload.get("round")
        for stage in existing_stages
        if isinstance(stage.payload, dict)
        and isinstance(stage.payload.get("round"), int)
        and not isinstance(stage.payload.get("round"), bool)
    ]
    rerank_stages = [
        stage
        for stage in existing_stages
        if stage.stage_key == "candidate_hunter_rerank"
    ]
    latest_rerank = max(
        rerank_stages,
        key=lambda stage: stage.payload.get("round", 0),
        default=None,
    )
    latest_round = latest_rerank.payload["round"] if latest_rerank is not None else 0
    latest_stop = (
        _text(latest_rerank.payload.get("stop_reason"))
        if latest_rerank is not None
        else ""
    )
    if latest_stop in {
        "all_candidates_terminal",
        "no_candidates",
        "max_rounds_reached",
        "safety_invariant_failed",
    }:
        return _persisted_loop_result(repository, run_id, campaign, task)

    round_number = (
        max(existing_rounds)
        if existing_rounds and max(existing_rounds) > latest_round
        else latest_round + 1
    )
    if round_number > 3:
        return _persisted_loop_result(
            repository,
            run_id,
            campaign,
            task,
            stop_reason_override="max_rounds_reached",
        )
    while round_number <= 3:
        prior_decisions = (
            latest_rerank.payload.get("candidate_decisions", [])
            if latest_rerank is not None
            and isinstance(latest_rerank.payload.get("candidate_decisions"), list)
            else []
        )
        round_candidate_states = (
            initial_candidate_states
            if round_number == 1 and latest_rerank is None
            else candidate_states
        )
        round_result = advance_candidate_hunter_round(
            pipeline_run_id=run_id,
            round_number=round_number,
            candidate_states=round_candidate_states,
            observations=observations,
            prior_decisions=prior_decisions,
        )
        state_digest = _text(round_result.get("state_digest"))
        latest_digest = (
            _text(latest_rerank.payload.get("state_digest"))
            if latest_rerank is not None
            else ""
        )
        if latest_rerank is not None and state_digest == latest_digest:
            return _persisted_loop_result(repository, run_id, campaign, task)
        if (
            round_number == 3
            and round_result.get("stop_candidate")
            not in {
                "all_candidates_terminal",
                "no_candidates",
                "safety_invariant_failed",
            }
        ):
            round_result["stop_candidate"] = "max_rounds_reached"
        stage_specs = (
            (
                "candidate_hunter_snapshot",
                {
                    "snapshot_candidates": round_result.get(
                        "snapshot_candidates",
                        [],
                    ),
                    "prior_decisions": prior_decisions,
                },
            ),
            (
                "candidate_hunter_evidence_request",
                {"evidence_requests": round_result.get("evidence_requests", [])},
            ),
            (
                "candidate_hunter_decision",
                {
                    "candidate_decisions": round_result.get(
                        "candidate_decisions",
                        [],
                    ),
                    "unresolved_candidates": round_result.get(
                        "unresolved_candidates",
                        [],
                    ),
                },
            ),
            (
                "candidate_hunter_rerank",
                {
                    "final_candidates": round_result.get("final_candidates", []),
                    "candidate_decisions": round_result.get(
                        "candidate_decisions",
                        [],
                    ),
                    "stop_reason": round_result.get("stop_candidate"),
                },
            ),
        )
        stages = []
        first_stage_order = (round_number - 1) * len(STAGE_KEYS) + 1
        for stage_order, (stage_key, stage_payload) in enumerate(
            stage_specs,
            start=first_stage_order,
        ):
            payload = {
                "schema_version": "candidate_hunter_loop_v1",
                "round": round_number,
                "state_digest": state_digest,
                "idempotency_key": _stage_idempotency_key(
                    run_id,
                    round_number,
                    stage_key,
                    state_digest,
                ),
                **stage_payload,
                **_false_safety_fields(),
            }
            stages.append(
                repository.save_pipeline_stage(
                    pipeline_run_id=run_id,
                    campaign_id=campaign.id,
                    task_id=task.id,
                    stage_key=stage_key,
                    stage_order=stage_order,
                    status="completed",
                    input_refs=[f"pipeline_run:{run_id}"],
                    output_refs=[],
                    safety_gate_state=(
                        "safe"
                        if round_result.get("safety_status") == "safe"
                        else "blocked"
                    ),
                    stop_reason=(
                        _text(round_result.get("stop_candidate"))
                        if stage_key == "candidate_hunter_rerank"
                        else None
                    ),
                    payload=payload,
                )
            )
        stop_candidate = _text(round_result.get("stop_candidate"))
        if stop_candidate in {
            "all_candidates_terminal",
            "no_candidates",
            "max_rounds_reached",
            "safety_invariant_failed",
        }:
            return _persisted_loop_result(repository, run_id, campaign, task)
        current_snapshot = round_result.get("snapshot_candidates", [])
        reanalyzed_snapshot = sorted(
            (_snapshot_candidate(state) for state in candidate_states),
            key=lambda state: _text(state.get("candidate_id")),
        )
        if current_snapshot == reanalyzed_snapshot:
            return _persisted_loop_result(repository, run_id, campaign, task)
        latest_rerank = stages[-1]
        round_number += 1
    return _persisted_loop_result(repository, run_id, campaign, task)


def load_candidate_hunter_projection(
    *,
    repository: Any,
    pipeline_run_id: str,
) -> dict[str, Any]:
    run_id = _text(pipeline_run_id)
    stages = [
        stage
        for stage in repository.list_pipeline_stages_for_run(run_id)
        if stage.stage_key in STAGE_KEYS
    ]
    if not stages:
        return _invalid_projection("candidate_hunter_stages_missing", status="not_ready")

    failures = []
    rounds: dict[int, list[Any]] = {}
    campaign_ids = {stage.campaign_id for stage in stages}
    task_ids = {stage.task_id for stage in stages}
    if len(campaign_ids) != 1 or None in campaign_ids:
        failures.append("campaign_owner_invalid")
    if len(task_ids) != 1 or None in task_ids:
        failures.append("task_owner_invalid")
    if len(campaign_ids) == 1 and len(task_ids) == 1:
        owners = _find_candidate_hunter_owners(repository, run_id)
        if (
            len(owners) != 1
            or owners[0][0].id not in campaign_ids
            or owners[0][1].id not in task_ids
        ):
            failures.append("persisted_owner_relationship_invalid")
    for stage in stages:
        payload = stage.payload if isinstance(stage.payload, dict) else {}
        round_number = payload.get("round")
        if not isinstance(round_number, int) or isinstance(round_number, bool) or round_number < 1:
            failures.append(f"{stage.id}:round_invalid")
            continue
        rounds.setdefault(round_number, []).append(stage)
        if payload.get("schema_version") != "candidate_hunter_loop_v1":
            failures.append(f"{stage.id}:schema_version_invalid")
        if stage.status != "completed" or stage.safety_gate_state != "safe":
            failures.append(f"{stage.id}:stage_not_safe")
        for field in SAFETY_FIELDS:
            if payload.get(field) is not False:
                failures.append(f"{stage.id}:{field}_must_be_false")
        state_digest = _text(payload.get("state_digest"))
        expected_key = _stage_idempotency_key(
            run_id,
            round_number,
            stage.stage_key,
            state_digest,
        )
        if not state_digest or _text(payload.get("idempotency_key")) != expected_key:
            failures.append(f"{stage.id}:idempotency_invalid")

    round_numbers = sorted(rounds)
    if round_numbers != list(range(1, len(round_numbers) + 1)):
        failures.append("round_sequence_invalid")
    if any(round_number > 3 for round_number in round_numbers):
        failures.append("round_limit_exceeded")
    ordered_stages = []
    for round_number in round_numbers:
        round_stages = sorted(rounds[round_number], key=lambda stage: stage.stage_order)
        if [stage.stage_key for stage in round_stages] != list(STAGE_KEYS):
            failures.append(f"round:{round_number}:stage_sequence_invalid")
            continue
        expected_orders = list(
            range((round_number - 1) * len(STAGE_KEYS) + 1, round_number * len(STAGE_KEYS) + 1)
        )
        if [stage.stage_order for stage in round_stages] != expected_orders:
            failures.append(f"round:{round_number}:stage_order_invalid")
        digests = {_text(stage.payload.get("state_digest")) for stage in round_stages}
        if len(digests) != 1:
            failures.append(f"round:{round_number}:state_digest_mismatch")
        snapshot_payload = round_stages[0].payload
        snapshot_candidates = snapshot_payload.get("snapshot_candidates")
        prior_decisions = snapshot_payload.get("prior_decisions")
        if not isinstance(snapshot_candidates, list) or not isinstance(
            prior_decisions,
            list,
        ):
            failures.append(f"round:{round_number}:snapshot_payload_invalid")
        else:
            computed_digest = _state_digest(
                run_id,
                round_number,
                snapshot_candidates,
                prior_decisions,
            )
            if digests != {computed_digest}:
                failures.append(f"round:{round_number}:snapshot_digest_invalid")
        decision_payload = round_stages[2].payload
        rerank_payload = round_stages[3].payload
        if decision_payload.get("candidate_decisions") != rerank_payload.get(
            "candidate_decisions"
        ):
            failures.append(f"round:{round_number}:decision_projection_mismatch")
        ordered_stages.extend(round_stages)

    if failures or not ordered_stages:
        return _invalid_projection(*failures)
    latest_rerank = ordered_stages[-1]
    if latest_rerank.stage_key != "candidate_hunter_rerank":
        return _invalid_projection("latest_stage_not_rerank")
    payload = latest_rerank.payload
    final_candidates = payload.get("final_candidates")
    candidate_decisions = payload.get("candidate_decisions")
    if not isinstance(final_candidates, list) or not isinstance(candidate_decisions, list):
        return _invalid_projection("rerank_projection_invalid")
    if projection_failures := _projection_schema_failures(
        final_candidates,
        candidate_decisions,
    ):
        return _invalid_projection(*projection_failures)
    return {
        "status": "ready",
        "pipeline_run_id": run_id,
        "final_candidates": final_candidates,
        "candidate_decisions": candidate_decisions,
        "audit": {
            "campaign_id": ordered_stages[0].campaign_id,
            "task_id": ordered_stages[0].task_id,
            "round_count": len(round_numbers),
            "stage_refs": [
                {
                    "stage_id": stage.id,
                    "stage_key": stage.stage_key,
                    "round": stage.payload["round"],
                }
                for stage in ordered_stages
            ],
            "state_digest": payload["state_digest"],
            "stop_reason": _text(payload.get("stop_reason")),
        },
        **_false_safety_fields(),
    }


def _invalid_projection(*failures: str, status: str = "invalid_stage_sequence") -> dict[str, Any]:
    return {
        "status": status,
        "failures": [failure for failure in failures if failure],
        "final_candidates": [],
        "candidate_decisions": [],
        **_false_safety_fields(),
    }


def _projection_schema_failures(
    final_candidates: list,
    candidate_decisions: list,
) -> list[str]:
    failures = []
    if len(final_candidates) > 5:
        failures.append("final_candidates_exceed_top_five")
    expected_ranks = list(range(1, len(final_candidates) + 1))
    actual_ranks = [
        candidate.get("rank") if isinstance(candidate, dict) else None
        for candidate in final_candidates
    ]
    if actual_ranks != expected_ranks:
        failures.append("final_candidate_ranks_invalid")

    final_ids = set()
    final_roots = set()
    required_blockers = {
        "execute_live_validation",
        "touch_real_user_data",
        "submit_report",
    }
    for candidate in final_candidates:
        if not isinstance(candidate, dict):
            failures.append("final_candidate_not_object")
            continue
        candidate_id = _text(candidate.get("candidate_id"))
        root_cause_id = _text(candidate.get("root_cause_id"))
        route = candidate.get("route")
        if not candidate_id or candidate_id in final_ids:
            failures.append("final_candidate_id_invalid")
        if not root_cause_id or root_cause_id in final_roots:
            failures.append("final_candidate_root_invalid")
        final_ids.add(candidate_id)
        final_roots.add(root_cause_id)
        if (
            not _text(candidate.get("vuln_type"))
            or not isinstance(route, dict)
            or not _route(route.get("method"), route.get("path"))
            or not _string_list(candidate.get("source_fact_refs"))
            or candidate.get("evidence_trace_status") != "traceable"
            or candidate.get("human_validation_readiness") != "ready"
        ):
            failures.append(f"{candidate_id}:final_candidate_evidence_invalid")
        if any(candidate.get(field) is not False for field in SAFETY_FIELDS[:-1]):
            failures.append(f"{candidate_id}:final_candidate_permissions_invalid")
        if not required_blockers.issubset(
            _string_list(candidate.get("safety_blockers"))
        ):
            failures.append(f"{candidate_id}:final_candidate_blockers_invalid")

    decision_ids = set()
    decision_roots = set()
    retained_projections: dict[str, dict] = {}
    for decision in candidate_decisions:
        if not isinstance(decision, dict):
            failures.append("candidate_decision_not_object")
            continue
        candidate_id = _text(decision.get("candidate_id"))
        root_cause_id = _text(decision.get("root_cause_id"))
        disposition = _text(decision.get("disposition"))
        if not candidate_id or candidate_id in decision_ids:
            failures.append("candidate_decision_id_invalid")
        if not root_cause_id or root_cause_id in decision_roots:
            failures.append("candidate_decision_root_invalid")
        decision_ids.add(candidate_id)
        decision_roots.add(root_cause_id)
        if disposition not in {"retained", "refuted", "deduplicated", "suppressed"}:
            failures.append(f"{candidate_id}:candidate_decision_disposition_invalid")
        if not _string_list(decision.get("evidence_refs")):
            failures.append(f"{candidate_id}:candidate_decision_evidence_invalid")
        if disposition == "deduplicated" and not _text(decision.get("duplicate_of")):
            failures.append(f"{candidate_id}:candidate_decision_duplicate_invalid")
        if disposition == "retained":
            projection = decision.get("candidate_projection")
            if not isinstance(projection, dict):
                failures.append(f"{candidate_id}:retained_projection_missing")
            else:
                retained_projections[candidate_id] = projection

    for candidate in final_candidates:
        if not isinstance(candidate, dict):
            continue
        candidate_id = _text(candidate.get("candidate_id"))
        projection = retained_projections.get(candidate_id)
        if projection is None:
            failures.append(f"{candidate_id}:final_candidate_not_retained")
            continue
        for field in (
            "candidate_id",
            "vuln_type",
            "root_cause_id",
            "route",
            "source_fact_refs",
            "evidence_trace_status",
            "human_validation_readiness",
        ):
            if projection.get(field) != candidate.get(field):
                failures.append(f"{candidate_id}:retained_projection_mismatch")
                break
    return _ordered_unique(failures)


def _persisted_loop_result(
    repository: Any,
    run_id: str,
    campaign: Any,
    task: Any,
    *,
    stop_reason_override: str | None = None,
) -> dict[str, Any]:
    projection = load_candidate_hunter_projection(
        repository=repository,
        pipeline_run_id=run_id,
    )
    if projection.get("status") != "ready":
        repository.update_campaign_task_status(task.id, "blocked", output_refs=[])
        return {
            "status": "blocked",
            "pipeline_run_id": run_id,
            "campaign_id": campaign.id,
            "task_id": task.id,
            "round_count": 0,
            "stage_refs": [],
            "state_digest": "",
            "stop_reason": "invalid_stage_sequence",
            "final_candidates": [],
            "candidate_decisions": [],
            **_false_safety_fields(),
        }
    audit = projection["audit"]
    stop_reason = stop_reason_override or _text(audit.get("stop_reason"))
    status = _task_status_for_stop(stop_reason)
    stage_refs = [item["stage_id"] for item in audit["stage_refs"]]
    repository.update_campaign_task_status(
        task.id,
        status,
        output_refs=stage_refs,
    )
    return {
        "status": status,
        "pipeline_run_id": run_id,
        "campaign_id": campaign.id,
        "task_id": task.id,
        "round_count": audit["round_count"],
        "stage_refs": stage_refs,
        "state_digest": audit["state_digest"],
        "stop_reason": stop_reason,
        "final_candidates": projection["final_candidates"],
        "candidate_decisions": projection["candidate_decisions"],
        **_false_safety_fields(),
    }


def _task_status_for_stop(stop_reason: str) -> str:
    if stop_reason in {"all_candidates_terminal", "no_candidates"}:
        return "completed"
    if stop_reason in {"safety_invariant_failed", "invalid_stage_sequence"}:
        return "blocked"
    return "needs_evidence"


def _find_candidate_hunter_owners(repository: Any, run_id: str) -> list[tuple[Any, Any]]:
    input_ref = f"pipeline_run:{run_id}"
    return [
        (campaign, task)
        for campaign in repository.list_campaigns()
        for task in repository.list_campaign_tasks(campaign.id)
        if task.task_type == "candidate_hunter_loop"
        and input_ref in task.input_refs
        and isinstance(campaign.payload, dict)
        and campaign.payload.get("pipeline_run_id") == run_id
    ]


def _stage_idempotency_key(
    run_id: str,
    round_number: int,
    stage_key: str,
    state_digest: str,
) -> str:
    value = f"{run_id}:{round_number}:{stage_key}:{state_digest}"
    return sha256(value.encode()).hexdigest()


def _false_safety_fields() -> dict[str, bool]:
    return {field: False for field in SAFETY_FIELDS}


def _safe_prior_decisions(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    decisions = []
    for item in value:
        if not isinstance(item, dict):
            continue
        candidate_id = _safe_text(item.get("candidate_id"))
        root_cause_id = _safe_text(item.get("root_cause_id"))
        disposition = _safe_text(item.get("disposition"))
        evidence_refs = [
            safe_ref
            for ref in item.get("evidence_refs", [])
            if (safe_ref := _safe_text(ref))
        ] if isinstance(item.get("evidence_refs"), list) else []
        if (
            not candidate_id
            or not root_cause_id
            or disposition not in {"retained", "refuted", "deduplicated", "suppressed"}
            or not evidence_refs
        ):
            continue
        decision: dict[str, Any] = {
            "candidate_id": candidate_id,
            "root_cause_id": root_cause_id,
            "disposition": disposition,
            "evidence_refs": evidence_refs,
        }
        if disposition == "deduplicated":
            if duplicate_of := _safe_text(item.get("duplicate_of")):
                decision["duplicate_of"] = duplicate_of
        if disposition == "retained":
            projection = _safe_prior_candidate_projection(
                item.get("candidate_projection"),
                candidate_id,
                root_cause_id,
            )
            if projection is None:
                continue
            decision["candidate_projection"] = projection
            decision["priority_score"] = _priority_score(item.get("priority_score"))
            decision["evidence_completeness_score"] = _priority_score(
                item.get("evidence_completeness_score")
            )
        decisions.append(decision)
    return decisions


def _safe_prior_candidate_projection(
    value: object,
    candidate_id: str,
    root_cause_id: str,
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    route = value.get("route")
    safe_route = (
        _route(route.get("method"), route.get("path"))
        if isinstance(route, dict)
        else {}
    )
    source_fact_refs = [
        safe_ref
        for ref in value.get("source_fact_refs", [])
        if (safe_ref := _safe_text(ref))
    ] if isinstance(value.get("source_fact_refs"), list) else []
    if (
        _safe_text(value.get("candidate_id")) != candidate_id
        or _safe_text(value.get("root_cause_id")) != root_cause_id
        or not _safe_text(value.get("vuln_type"))
        or not safe_route
        or not source_fact_refs
        or value.get("evidence_trace_status") != "traceable"
        or any(value.get(field) is not False for field in SAFETY_FIELDS[:-1])
    ):
        return None
    return {
        "candidate_id": candidate_id,
        "rank": _priority_score(value.get("rank")) or 1,
        "vuln_type": _safe_text(value.get("vuln_type")),
        "root_cause_id": root_cause_id,
        "route": safe_route,
        "source_fact_refs": source_fact_refs,
        "evidence_trace_status": "traceable",
        "human_validation_readiness": "ready",
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
        "safe_validation_plan": [
            safe_text
            for item in value.get("safe_validation_plan", [])
            if (safe_text := _safe_text(item))
        ] if isinstance(value.get("safe_validation_plan"), list) else [],
        "next_allowed_action": _safe_text(value.get("next_allowed_action")),
        "safety_blockers": [
            safe_text
            for item in value.get("safety_blockers", [])
            if (safe_text := _safe_text(item))
        ] if isinstance(value.get("safety_blockers"), list) else [],
    }


def _snapshot_candidate(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    snapshot: dict[str, Any] = {}
    for field in (
        "candidate_id",
        "candidate_key",
        "vuln_type",
        "root_cause_id",
        "evidence_trace_status",
        "gap_evidence_ref",
        "control_evidence_ref",
        "public_evidence_ref",
        "shared_root",
        "shared_root_evidence_ref",
        "reanalysis_status",
    ):
        if safe_value := _safe_text(value.get(field)):
            snapshot[field] = safe_value
    route = value.get("route")
    if isinstance(route, dict):
        if safe_route := _route(route.get("method"), route.get("path")):
            snapshot["route"] = safe_route
    for field in (
        "source_fact_refs",
        "observed_artifact_kinds",
        "required_artifact_kinds",
        "refutation_questions",
    ):
        snapshot[field] = [
            safe_value
            for item in value.get(field, [])
            if (safe_value := _safe_text(item))
        ] if isinstance(value.get(field), list) else []
    snapshot["priority_score"] = _priority_score(value.get("priority_score"))
    return snapshot


def _state_digest(
    pipeline_run_id: object,
    round_number: int,
    snapshot_candidates: list[dict[str, Any]],
    prior_decisions: list[dict],
) -> str:
    safe_prior_decisions = sorted(
        (
            {
                "candidate_id": _safe_text(decision.get("candidate_id")),
                "root_cause_id": _safe_text(decision.get("root_cause_id")),
                "disposition": _safe_text(decision.get("disposition")),
            }
            for decision in prior_decisions
            if isinstance(decision, dict)
        ),
        key=lambda decision: (
            decision["candidate_id"],
            decision["disposition"],
        ),
    )
    payload = {
        "pipeline_run_id": _safe_text(pipeline_run_id),
        "candidate_states": snapshot_candidates,
        "prior_decisions": safe_prior_decisions,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return sha256(encoded).hexdigest()


def _duplicate_targets(
    candidate_states: list[dict],
    pipeline_run_id: str,
) -> dict[str, tuple[str, str]]:
    groups: dict[tuple[str, str, str, str], list[dict]] = {}
    for state in candidate_states:
        if not _candidate_is_complete(
            state,
            pipeline_run_id,
        ) or not _text(state.get("gap_evidence_ref")):
            continue
        source_refs = _string_list(state.get("source_fact_refs"))
        if _text(state.get("control_evidence_ref")) in source_refs:
            continue
        if _text(state.get("public_evidence_ref")) in source_refs:
            continue
        shared_root = _text(state.get("shared_root"))
        shared_ref = _text(state.get("shared_root_evidence_ref"))
        if shared_root and shared_ref in source_refs:
            root_cause_class = _text(state.get("root_cause_id")).partition(":")[0]
            group_key = (
                _text(state.get("vuln_type")).lower(),
                root_cause_class,
                shared_root,
                shared_ref,
            )
            groups.setdefault(group_key, []).append(state)

    targets: dict[str, tuple[str, str]] = {}
    for states in groups.values():
        if len(states) < 2:
            continue
        ordered = sorted(
            states,
            key=lambda state: (
                -_priority_score(state.get("priority_score")),
                _text(state.get("candidate_id")),
            ),
        )
        canonical = ordered[0]
        for duplicate in ordered[1:]:
            targets[duplicate["candidate_id"]] = (
                canonical["root_cause_id"],
                duplicate["shared_root_evidence_ref"],
            )
    return targets


def _priority_score(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _evidence_completeness_score(candidate: dict) -> int:
    required = set(_string_list(candidate.get("required_artifact_kinds")))
    observed = set(_string_list(candidate.get("observed_artifact_kinds")))
    return len(required & observed)


def _candidate_is_complete(candidate: object, pipeline_run_id: str = "") -> bool:
    return not _missing_evidence(candidate, pipeline_run_id)


def _refutation_questions(candidate: object) -> list[str]:
    if not isinstance(candidate, dict):
        candidate = {}
    direct_value = candidate.get("refutation_questions")
    direct_questions = (
        [
            safe_question
            for item in direct_value
            if (safe_question := _safe_text(item))
        ]
        if isinstance(direct_value, list)
        else []
    )
    review = candidate.get("refutation_review")
    review_value = review.get("questions") if isinstance(review, dict) else None
    reviewed_questions = (
        [
            safe_question
            for item in review_value
            if (safe_question := _safe_text(item))
        ]
        if isinstance(review_value, list)
        else []
    )
    questions = _ordered_unique([*direct_questions, *reviewed_questions])
    return questions or [
        "Does an observed local authorization guard execute before the sensitive sink?",
        "Does observed local data flow prove the route is public or otherwise non-sensitive?",
    ]


def _requested_artifact_kinds(
    candidate: dict,
    missing_evidence: list[str],
) -> list[str]:
    requested = [
        gap.removeprefix("artifact:")
        for gap in missing_evidence
        if gap.startswith("artifact:")
    ]
    if any(
        gap in missing_evidence
        for gap in (
            "candidate_record",
            "stable_identity",
            "vulnerability_type",
            "root_cause",
            "gap_provenance",
        )
    ):
        requested.append("code")
    if "route" in missing_evidence:
        requested.extend(("code", "api"))
    if "provenance" in missing_evidence:
        requested.extend(
            _string_list(candidate.get("required_artifact_kinds"))
            or REQUIRED_ARTIFACT_KINDS
        )
    if "required_artifact_kinds" in missing_evidence:
        requested.extend(REQUIRED_ARTIFACT_KINDS)
    if "bounded_reanalysis" in missing_evidence:
        requested.extend(("code", "api", "har"))
    requested_set = set(requested)
    return [kind for kind in REQUIRED_ARTIFACT_KINDS if kind in requested_set]


def _inspection_targets(
    candidate: dict,
    artifact_kinds: list[str],
) -> list[dict[str, Any]]:
    route_value = candidate.get("route")
    route = (
        _route(route_value.get("method"), route_value.get("path"))
        if isinstance(route_value, dict)
        else {}
    )
    root_symbol = _text(candidate.get("root_cause_id")).partition(":")[2]
    symbols = _ordered_unique(
        [root_symbol, _text(candidate.get("shared_root"))]
    )
    targets = []
    for artifact_kind in artifact_kinds:
        target: dict[str, Any] = {"artifact_kind": artifact_kind}
        if route:
            target["route"] = route
        if artifact_kind == "code" and symbols:
            target["symbols"] = symbols
        targets.append(target)
    return targets


def _missing_evidence(candidate: object, pipeline_run_id: str = "") -> list[str]:
    if not isinstance(candidate, dict):
        return ["candidate_record"]
    missing = []
    candidate_id = _text(candidate.get("candidate_id"))
    candidate_key = _text(candidate.get("candidate_key"))
    if (
        not candidate_id
        or not candidate_key
        or pipeline_run_id
        and candidate_key != f"{pipeline_run_id}:{candidate_id}"
    ):
        missing.append("stable_identity")
    if not _text(candidate.get("vuln_type")):
        missing.append("vulnerability_type")
    if not _text(candidate.get("root_cause_id")):
        missing.append("root_cause")
    route = candidate.get("route")
    if (
        not isinstance(route, dict)
        or not _text(route.get("method"))
        or not _text(route.get("path")).startswith("/")
    ):
        missing.append("route")
    source_fact_refs = _string_list(candidate.get("source_fact_refs"))
    if not source_fact_refs:
        missing.append("provenance")
    gap_ref = _text(candidate.get("gap_evidence_ref"))
    if gap_ref and gap_ref not in source_fact_refs:
        missing.append("gap_provenance")
    required_kinds = set(_string_list(candidate.get("required_artifact_kinds")))
    observed_kinds = set(_string_list(candidate.get("observed_artifact_kinds")))
    if not required_kinds:
        missing.append("required_artifact_kinds")
    else:
        missing.extend(
            f"artifact:{kind}" for kind in sorted(required_kinds - observed_kinds)
        )
    if candidate.get("evidence_trace_status") != "traceable":
        missing.append("evidence_trace")
    if candidate.get("reanalysis_status") == "pending":
        missing.append("bounded_reanalysis")
    return missing


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [text for item in value if (text := _text(item))]


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


__all__ = [
    "advance_candidate_hunter_round",
    "build_candidate_hunter_observations",
    "load_candidate_hunter_projection",
    "run_candidate_hunter_loop",
]
