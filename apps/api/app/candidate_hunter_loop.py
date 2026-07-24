from __future__ import annotations

import ast
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any

from app.codebase_map import (
    CodebaseFactCandidate,
    INPUT_BOUND_STATIC_GAP_SINK_NAMES,
    INPUT_REFERENCE_KIND_STRAIGHT_LINE,
    SENSITIVE_SINK_NAMES,
    SUPPORTED_CODE_SOURCE_SUFFIXES,
    has_reachable_sink_before_control,
    map_authorized_code_files,
    safe_claim_reference,
    safe_input_reference,
)
from app.falsification_engine import (
    build_falsification_card,
    project_falsification_summary,
    survived_kill_score,
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
ADVISORY_ARTIFACT_KINDS = ("sarif", "sbom")
SUPPORTED_ARTIFACT_KINDS = (*REQUIRED_ARTIFACT_KINDS, *ADVISORY_ARTIFACT_KINDS)
_STATIC_ADVISORY_FACT_REF_PATTERN = re.compile(
    r"^static_advisory:(artifact_[A-Za-z0-9_-]{1,90}):(\d{1,7}):"
    r"((?=.{1,128}$)(?!\.{1,2}(?:/|$))(?!.*(?:/)\.{1,2}(?:/|$))"
    r"[A-Za-z0-9_.:-]+(?:/[A-Za-z0-9_.:-]+)*)$",
    re.ASCII,
)
_CWE_ADVISORY_ID_PATTERN = re.compile(r"\bcwe[-_:]?(\d{1,5})\b", re.IGNORECASE)
_CWE_ADVISORY_FAMILIES = {
    "22": "path_traversal",
    "23": "path_traversal",
    "36": "path_traversal",
    "73": "path_traversal",
    "78": "command_injection",
    "89": "injection",
    "284": "authorization",
    "362": "race_condition",
    "367": "race_condition",
    "502": "unsafe_deserialization",
    "639": "authorization",
    "862": "authorization",
    "863": "authorization",
    "915": "mass_assignment",
    "918": "ssrf",
}
STAGE_KEYS = (
    "candidate_hunter_snapshot",
    "candidate_hunter_evidence_request",
    "candidate_hunter_decision",
    "candidate_hunter_rerank",
)
PUBLIC_FILTER_REFUTABLE_VULN_TYPES = {
    "authorization",
    "authorization_boundary",
    "bola_idor",
    "broken_access_control",
    "idor",
}
SAFE_VALIDATION_STEP = (
    "Do not execute live validation, access production accounts, or submit a report."
)


def build_candidate_hunter_observations(
    *,
    pipeline_run_id: str,
    candidates: list[dict],
    code_files: list[dict],
    supplemental_code_facts: list[CodebaseFactCandidate] | None = None,
    static_advisory_facts: list[dict] | None = None,
    dependency_advisory_facts: list[dict] | None = None,
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
    mapped_code_facts = [
        *mapped_code.facts,
        *(
            fact
            for fact in (supplemental_code_facts or [])
            if isinstance(fact, CodebaseFactCandidate)
        ),
    ]
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
    safe_static_advisory_facts = [
        fact
        for item in static_advisory_facts or []
        if isinstance(item, dict)
        if (fact := _safe_static_advisory_fact(item)) is not None
    ]
    safe_dependency_advisory_facts = [
        fact
        for item in dependency_advisory_facts or []
        if isinstance(item, dict)
        for fact in _safe_candidate_source_facts([item])
        if fact.get("artifact_kind") == "sbom"
        and fact.get("fact_type") == "dependency_signal"
        and _safe_source_name(fact.get("source_path"))
    ]
    projected_facts = [
        *(_safe_code_fact(fact) for fact in mapped_code_facts),
        *semantic_code_facts,
        *safe_surface_facts,
        *safe_context_facts,
        *safe_static_advisory_facts,
        *safe_dependency_advisory_facts,
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
            candidate_facts = [
                fact
                for fact in _safe_candidate_source_facts(candidate.get("source_facts"))
                if not _is_dependency_advisory_fact(fact)
            ]
            route_bound_code_facts = [
                fact
                for fact in candidate_facts
                if fact.get("artifact_kind") == "code"
                and _fact_matches_route(fact, route)
            ]
            route_bound_code_fact_identities = {
                (
                    _safe_source_name(fact.get("source_path")),
                    _safe_text(fact.get("symbol_name")),
                )
                for fact in route_bound_code_facts
                if _safe_source_name(fact.get("source_path"))
                and _safe_text(fact.get("symbol_name"))
            }
            routeless_code_facts = [
                fact
                for fact in candidate_facts
                if fact.get("artifact_kind") == "code"
                and "route" not in fact
                and _safe_source_name(fact.get("source_path"))
                and _safe_text(fact.get("symbol_name"))
            ]
            routeless_code_fact_identities = {
                (
                    _safe_source_name(fact.get("source_path")),
                    _safe_text(fact.get("symbol_name")),
                )
                for fact in routeless_code_facts
            }
            hypothesis_code_fact = {}
            route_bound_code_fact_is_unique = (
                len(route_bound_code_fact_identities) == 1
                and all(
                    _safe_source_name(fact.get("source_path"))
                    and _safe_text(fact.get("symbol_name"))
                    for fact in route_bound_code_facts
                )
            )
            ambiguous_route_bound_code_facts = (
                bool(route_bound_code_facts) and not route_bound_code_fact_is_unique
            )
            routeless_code_fact_is_unique = len(routeless_code_fact_identities) == 1
            ambiguous_routeless_code_facts = (
                not route_bound_code_facts
                and bool(routeless_code_facts)
                and not routeless_code_fact_is_unique
            )
            if route_bound_code_fact_is_unique:
                hypothesis_code_fact = route_bound_code_facts[0]
            elif routeless_code_fact_is_unique:
                hypothesis_code_fact = routeless_code_facts[0]
            hypothesis_source_path = _safe_source_name(
                hypothesis_code_fact.get("source_path")
            )
            matching_code_facts = (
                []
                if ambiguous_route_bound_code_facts
                or ambiguous_routeless_code_facts
                else _matching_code_facts(
                    mapped_code_facts,
                    route,
                    preferred_source_path=hypothesis_source_path,
                    preferred_symbol_name=_safe_text(
                        hypothesis_code_fact.get("symbol_name")
                    ),
                )
            )
            handler = _route_handler(matching_code_facts, route)
            route_source_paths = {
                _safe_source_name(fact.source_path)
                for fact in matching_code_facts
                if fact.fact_type == "route_handler"
                and _code_fact_matches_route(fact, route)
            }
            # Frameworks without decorator routes (e.g. Django function views) use
            # the selected candidate code path and symbol to attach semantic guards.
            if not handler:
                handler = _safe_text(hypothesis_code_fact.get("symbol_name"))
            if not route_source_paths:
                if source_path := _safe_source_name(
                    hypothesis_code_fact.get("source_path")
                ):
                    route_source_paths = {source_path}
            path_matching_static_advisory_facts = [
                fact
                for fact in safe_static_advisory_facts
                if fact.get("source_path") in route_source_paths
            ]
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
            authorized_code_source_paths = {
                _safe_source_name(item.get("path"))
                for item in code_files
                if isinstance(item, dict)
                and _safe_source_name(item.get("path"))
            }
            if not authorized_code_source_paths:
                authorized_code_source_paths = {
                    _safe_source_name(fact.source_path)
                    for fact in mapped_code_facts
                    if _safe_source_name(fact.source_path)
                }
            matching_candidate_facts = [
                fact
                for fact in candidate_facts
                if (
                    _fact_matches_route(fact, route)
                    or "route" not in fact
                )
                and (
                    fact.get("artifact_kind") != "code"
                    or _safe_source_name(fact.get("source_path"))
                    in authorized_code_source_paths
                )
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
            gap_fact = _matching_gap_fact(
                matching_candidate_facts,
                matching_code_facts,
            )
            root_cause = (
                _text(gap_fact.get("root_cause"))
                if gap_fact
                else _text(hypothesis_code_fact.get("root_cause"))
            )
            root_symbol = (
                _text(gap_fact.get("symbol_name"))
                if gap_fact
                else _text(hypothesis_code_fact.get("symbol_name")) or handler
            )
            # Static findings remain advisory and need an exact vulnerability family,
            # source file, and mapped candidate sink location before joining evidence.
            matching_static_advisory_facts = [
                fact
                for fact in path_matching_static_advisory_facts
                if _static_advisory_matches_candidate(
                    fact,
                    candidate=candidate,
                    root_cause=root_cause,
                    code_facts=matching_code_facts,
                )
            ]
            evidence_facts = [
                *safe_context_facts,
                *matching_candidate_facts,
                *(_safe_code_fact(fact) for fact in matching_code_facts),
                *matching_semantic_facts,
                *matching_surface_facts,
                *matching_static_advisory_facts,
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
            shared_root, shared_ref, shared_root_kind = _shared_root(
                matching_code_facts,
                handler,
            )
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
                "model_priority_score": _priority_score(
                    candidate.get("model_priority_score")
                ),
                "gap_evidence_ref": _text(gap_fact.get("fact_ref")) if gap_fact else "",
                "shared_root": shared_root,
                "shared_root_evidence_ref": shared_ref,
                "shared_root_kind": shared_root_kind,
                "refutation_questions": _refutation_questions(candidate),
                "reanalysis_status": "completed",
            }
            graphql_operation = next(
                (
                    fact
                    for fact in matching_code_facts
                    if fact.fact_type == "graphql_operation"
                    and isinstance(fact.payload, dict)
                ),
                None,
            )
            if graphql_operation is not None:
                operation_type = _safe_text(
                    graphql_operation.payload.get("operation_type")
                )
                operation_name = _safe_text(
                    graphql_operation.payload.get("operation_name")
                )
                if operation_type and operation_name:
                    state.update(
                        {
                            "entrypoint_kind": "graphql_operation",
                            "graphql_operation_type": operation_type,
                            "graphql_operation_name": operation_name,
                        }
                    )
            if broken_invariant := _safe_text(candidate.get("broken_invariant")):
                state["broken_invariant"] = broken_invariant
            if validation_mode := _safe_validation_mode(candidate.get("validation_mode")):
                state["validation_mode"] = validation_mode
            if evidence_needed := _safe_research_strings(candidate.get("evidence_needed")):
                state["evidence_needed"] = evidence_needed
            if impact_rationale := _safe_text(candidate.get("impact_rationale")):
                state["impact_rationale"] = impact_rationale
            if impact_score := _priority_score(candidate.get("impact_score")):
                state["impact_score"] = impact_score
            if hypothesis_source_path := _text(hypothesis_code_fact.get("source_path")):
                state["hypothesis_source_path"] = hypothesis_source_path
            if hypothesis_symbol_name := _text(hypothesis_code_fact.get("symbol_name")):
                state["hypothesis_symbol_name"] = hypothesis_symbol_name
            control_fact = (
                next(
                    (
                        fact
                        for fact in matching_semantic_facts
                        if fact.get("fact_type") == "ownership_guard"
                    ),
                    None,
                )
                if _is_object_ownership_root_cause(root_cause)
                else None
            )
            if control_fact is None:
                preferred = set()
                if "ssrf" in root_cause:
                    preferred.add("ssrf_validation_check")
                if "path" in root_cause:
                    preferred.add("path_validation_check")
                if "mass_assignment" in root_cause:
                    preferred.add("mass_assignment_check")
                if "unsafe_deserialization" in root_cause:
                    preferred.add("deserialization_validation_check")
                if "file_upload" in root_cause:
                    preferred.add("file_upload_validation_check")
                if "server_authoritative_amount" in root_cause:
                    preferred.add("server_authoritative_amount_check")
                if "agent_tool_authorization" in root_cause:
                    preferred.add("agent_tool_authorization_check")
                if "jwt_verification" in root_cause:
                    preferred.add("jwt_verification_check")
                if "command_injection" in root_cause:
                    preferred.add("command_injection_validation_check")
                elif "injection" in root_cause:
                    preferred.add("injection_validation_check")
                control_fact = _typescript_control_fact(
                    matching_code_facts,
                    preferred_hints=preferred,
                    root_cause=root_cause,
                )
            public_fact = next(
                (
                    fact
                    for fact in matching_semantic_facts
                    if fact.get("fact_type") == "public_filter"
                ),
                None,
            )
            if public_fact is None:
                public_fact = _typescript_public_filter_fact(matching_code_facts)
            if control_fact is not None:
                state["control_evidence_ref"] = control_fact["fact_ref"]
            if public_fact is not None and _public_filter_refutes_candidate(state):
                state["public_evidence_ref"] = public_fact["fact_ref"]
            initial_root_cause = (
                _text(initial_gap_fact.get("root_cause"))
                if initial_gap_fact
                else root_cause
            )
            initial_root_symbol = (
                _text(initial_gap_fact.get("symbol_name"))
                if initial_gap_fact
                else root_symbol
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
                "shared_root_kind": "",
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


def _typescript_control_fact(
    facts: list[CodebaseFactCandidate],
    *,
    preferred_hints: set[str] | None = None,
    root_cause: str = "",
) -> dict[str, Any] | None:
    decisive_hints = {
        "owner_or_admin_check",
        "ownership_boundary_check",
        "role_check",
        "permission_check",
        "ssrf_validation_check",
        "path_validation_check",
        "mass_assignment_check",
        "injection_validation_check",
        "command_injection_validation_check",
        "deserialization_validation_check",
        "file_upload_validation_check",
        "server_authoritative_amount_check",
        "agent_tool_authorization_check",
        "jwt_verification_check",
    }
    preferred_hints = preferred_hints or set()
    # Pure RBAC (role/permission) does not close object-level ownership gaps (IDOR).
    root_l = (root_cause or "").lower()
    if any(
        marker in root_l
        for marker in (
            "missing_object_ownership",
            "object_ownership",
            "ownership_check",
            "idor",
        )
    ):
        decisive_hints = {
            "owner_or_admin_check",
            "ownership_boundary_check",
        }
    input_bound_sink_refs_by_handler = _input_bound_sink_refs_by_handler(
        facts,
        root_cause=root_l,
    )
    jwt_decoder_facts = [
        fact for fact in facts if fact.fact_type == "unverified_token_decode"
    ]
    jwt_token_refs = {
        token_ref
        for fact in jwt_decoder_facts
        if (token_ref := _code_fact_token_ref(fact)) is not None
    }
    jwt_token_ref = (
        next(iter(jwt_token_refs))
        if len(jwt_decoder_facts) == 1 and len(jwt_token_refs) == 1
        else None
    )
    jwt_sink_claim_refs_by_handler = (
        _jwt_sink_claim_refs_by_handler(facts)
        if "jwt_verification" in root_l
        else None
    )
    # Earliest sensitive sink line per handler — guards at/after sink are ineffective.
    sink_position_by_handler: dict[tuple[str, str], tuple[int, int]] = {}
    for fact in facts:
        if fact.fact_type != "sensitive_sink" or not isinstance(fact.payload, dict):
            continue
        handler = _code_fact_handler_identity(fact)
        position = _code_fact_position(fact)
        if not handler or position is None:
            continue
        previous = sink_position_by_handler.get(handler)
        if previous is None or position < previous:
            sink_position_by_handler[handler] = position

    candidates: list[CodebaseFactCandidate] = []
    for fact in facts:
        if (
            fact.fact_type == "authz_check"
            and fact.authz_hint in decisive_hints
            and fact.source_path.lower().endswith(SUPPORTED_CODE_SOURCE_SUFFIXES)
        ):
            if not _python_static_ownership_control_matches_sink_resource(
                fact,
                facts,
            ):
                continue
            if input_bound_sink_refs_by_handler is not None:
                handler_identity = _code_fact_handler_identity(fact)
                expected_sink_refs = (
                    input_bound_sink_refs_by_handler.get(handler_identity)
                    if handler_identity is not None
                    else None
                )
                if (
                    not expected_sink_refs
                    or not expected_sink_refs.issubset(
                        _code_fact_guard_input_refs(fact)
                    )
                ):
                    continue
            if (
                "jwt_verification" in root_l
                and fact.authz_hint == "jwt_verification_check"
                and not _jwt_control_matches_sink_claims(
                    fact,
                    token_ref=jwt_token_ref,
                    sink_claim_refs_by_handler=jwt_sink_claim_refs_by_handler,
                )
            ):
                continue
            if has_reachable_sink_before_control(facts, control=fact):
                continue
            if isinstance(fact.payload, dict):
                handler = _code_fact_handler_identity(fact)
                position = _code_fact_position(fact)
                sink_position = sink_position_by_handler.get(handler)
                if (
                    sink_position is not None
                    and position is not None
                    and position >= sink_position
                ):
                    # Guard-after-sink does not close the authorization gap.
                    continue
            candidates.append(fact)
    if not candidates:
        return None
    for fact in candidates:
        if fact.authz_hint in preferred_hints:
            return _safe_code_fact(fact)
    if preferred_hints:
        return None
    return _safe_code_fact(candidates[0])


def _is_object_ownership_root_cause(root_cause: str) -> bool:
    normalized = (root_cause or "").lower()
    return any(
        marker in normalized
        for marker in (
            "missing_object_ownership",
            "object_ownership",
            "ownership_check",
            "idor",
        )
    )


def _code_fact_position(
    fact: CodebaseFactCandidate,
) -> tuple[int, int] | None:
    if not isinstance(fact.payload, dict):
        return None
    line = fact.payload.get("line")
    if not isinstance(line, int):
        return None
    column = fact.payload.get("column")
    return line, column if isinstance(column, int) else 0


def _code_fact_token_ref(fact: CodebaseFactCandidate) -> str | None:
    if not isinstance(fact.payload, dict):
        return None
    token_ref = fact.payload.get("token_ref")
    return token_ref if isinstance(token_ref, str) and token_ref.startswith("token:") else None


def _code_fact_claim_ref(fact: CodebaseFactCandidate) -> str | None:
    if not isinstance(fact.payload, dict):
        return None
    return safe_claim_reference(fact.payload.get("claims_ref"))


def _code_fact_handler_identity(
    fact: CodebaseFactCandidate,
) -> tuple[str, str] | None:
    return _code_fact_identity(fact, "handler")


def _code_fact_service_class(fact: CodebaseFactCandidate) -> str | None:
    if not isinstance(fact.payload, dict):
        return None
    service_class = _safe_text(fact.payload.get("service_class"))
    return (
        service_class
        if re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", service_class)
        else None
    )


def _code_fact_input_ref(fact: CodebaseFactCandidate) -> str | None:
    if not isinstance(fact.payload, dict):
        return None
    if fact.payload.get("input_ref_kind") != INPUT_REFERENCE_KIND_STRAIGHT_LINE:
        return None
    return safe_input_reference(fact.payload.get("input_ref"))


def _code_fact_guard_input_refs(fact: CodebaseFactCandidate) -> frozenset[str]:
    if (
        not isinstance(fact.payload, dict)
        or fact.payload.get("input_ref_kind") != INPUT_REFERENCE_KIND_STRAIGHT_LINE
    ):
        return frozenset()
    return frozenset(
        input_ref
        for value in (
            fact.payload.get("input_ref"),
            fact.payload.get("validated_output_ref"),
        )
        if (input_ref := safe_input_reference(value)) is not None
    )


def _input_bound_sink_refs_by_handler(
    facts: list[CodebaseFactCandidate],
    *,
    root_cause: str,
) -> dict[tuple[str, str], set[str]] | None:
    sink_names = INPUT_BOUND_STATIC_GAP_SINK_NAMES.get(
        root_cause.partition(":")[0]
    )
    if sink_names is None:
        return None
    sink_refs_by_handler: dict[tuple[str, str], set[str]] = {}
    for fact in facts:
        if (
            fact.fact_type != "sensitive_sink"
            or _normalized_code_fact_symbol(fact.symbol_name) not in sink_names
        ):
            continue
        handler_identity = _code_fact_handler_identity(fact)
        input_ref = _code_fact_input_ref(fact)
        if handler_identity is None or input_ref is None:
            return {}
        sink_refs_by_handler.setdefault(handler_identity, set()).add(input_ref)
    return sink_refs_by_handler


def _python_static_ownership_control_matches_sink_resource(
    control: CodebaseFactCandidate,
    facts: list[CodebaseFactCandidate],
) -> bool:
    if (
        not control.source_path.lower().endswith(".py")
        or control.authz_hint not in {"owner_or_admin_check", "ownership_boundary_check"}
        or not isinstance(control.payload, dict)
        or control.payload.get("mapping_mode") != "static_code_snippet_analysis"
    ):
        return True
    handler = _code_fact_handler_identity(control)
    if handler is None:
        return False
    sink_resource_names = {
        claim_ref.partition(":")[2]
        for fact in facts
        if fact.fact_type == "sensitive_sink"
        and _code_fact_handler_identity(fact) == handler
        and (claim_ref := _code_fact_claim_ref(fact)) is not None
    }
    control_resources = _ownership_control_resource_terms(
        _safe_text(control.symbol_name)
    )
    sink_resources = set().union(
        *(
            _ownership_control_resource_terms(name)
            for name in sink_resource_names
        )
    )
    return bool(control_resources & sink_resources)


def _jwt_sink_claim_refs_by_handler(
    facts: list[CodebaseFactCandidate],
) -> dict[tuple[str, str], set[str]]:
    sink_refs_by_handler: dict[tuple[str, str], set[str]] = {}
    for fact in facts:
        if fact.fact_type != "sensitive_sink":
            continue
        handler_identity = _code_fact_handler_identity(fact)
        claim_ref = _code_fact_claim_ref(fact)
        if handler_identity is None or claim_ref is None:
            return {}
        sink_refs_by_handler.setdefault(handler_identity, set()).add(claim_ref)
    return sink_refs_by_handler


def _jwt_control_matches_sink_claims(
    fact: CodebaseFactCandidate,
    *,
    token_ref: str | None,
    sink_claim_refs_by_handler: dict[tuple[str, str], set[str]] | None,
) -> bool:
    handler_identity = _code_fact_handler_identity(fact)
    claims_ref = _code_fact_claim_ref(fact)
    if (
        token_ref is None
        or _code_fact_token_ref(fact) != token_ref
        or handler_identity is None
        or claims_ref is None
        or sink_claim_refs_by_handler is None
    ):
        return False
    return sink_claim_refs_by_handler.get(handler_identity) == {claims_ref}


def _normalized_code_fact_symbol(value: object) -> str:
    return re.sub(
        r"(?<=[a-z0-9])(?=[A-Z])",
        "_",
        _safe_text(value),
    ).lower()


def _typescript_public_filter_fact(
    facts: list[CodebaseFactCandidate],
) -> dict[str, Any] | None:
    for fact in facts:
        if (
            fact.fact_type == "authz_check"
            and fact.authz_hint == "public_filter"
            and fact.source_path.lower().endswith(SUPPORTED_CODE_SOURCE_SUFFIXES)
        ):
            return _safe_code_fact(fact)
    return None


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


def _collect_python_functions(
    tree: ast.AST,
) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    """Collect top-level functions and class methods by leaf name."""
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in getattr(tree, "body", []) or []:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions[node.name] = node
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    # Prefer first definition; leaf call names match method names.
                    functions.setdefault(item.name, item)
    return functions



def _function_called_names(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(function):
        if isinstance(node, ast.Call):
            name = _ast_call_name(node)
            if name:
                names.add(name)
    return names


def _transitive_helper_names(
    parsed: list[tuple[str, dict[str, ast.FunctionDef | ast.AsyncFunctionDef]]],
    seed: set[str],
) -> set[str]:
    """Expand helper names through wrappers that call known helpers."""
    if not seed:
        return set(seed)
    callees_by_name: dict[str, set[str]] = {}
    for _source_path, functions in parsed:
        for name, function in functions.items():
            callees_by_name.setdefault(name, set()).update(_function_called_names(function))
    helpers = set(seed)
    changed = True
    while changed:
        changed = False
        for name, callees in callees_by_name.items():
            if name in helpers:
                continue
            if callees & helpers:
                helpers.add(name)
                changed = True
    return helpers


def _python_semantic_facts(code_files: list[dict]) -> list[dict[str, Any]]:
    """Build ownership/public semantic facts across authorized Python files.

    Ownership helpers are resolved globally so route handlers can call helpers
    defined in other authorized files (or class methods) by leaf name.
    """
    parsed: list[tuple[str, dict[str, ast.FunctionDef | ast.AsyncFunctionDef]]] = []
    ownership_helpers: set[str] = set()
    positive_ownership_helpers: set[str] = set()
    public_helpers: set[str] = set()

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
        functions = _collect_python_functions(tree)
        for name, function in functions.items():
            if _function_has_ownership_guard(function):
                ownership_helpers.add(name)
            if _function_returns_ownership_predicate(function):
                positive_ownership_helpers.add(name)
            if _function_has_public_filter(function):
                public_helpers.add(name)
        parsed.append((source_path, functions))

    # Propagate ownership through service-layer wrappers that call ownership helpers.
    ownership_helpers = _transitive_helper_names(parsed, ownership_helpers)
    positive_ownership_helpers = _transitive_helper_names(
        parsed, positive_ownership_helpers
    )
    ownership_helper_resource_terms = _ownership_helper_parameter_terms_by_name(
        parsed,
        ownership_helpers,
    )

    facts: list[dict[str, Any]] = []
    for source_path, functions in parsed:
        for handler, function in functions.items():
            facts.extend(
                _handler_semantic_facts(
                    source_path,
                    handler,
                    function,
                    ownership_helpers,
                    ownership_helper_resource_terms,
                    public_helpers,
                    positive_ownership_helpers,
                )
            )
    return facts


def _handler_semantic_facts(
    source_path: str,
    handler: str,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    ownership_helpers: set[str],
    ownership_helper_resource_terms: dict[str, set[frozenset[str]]],
    public_helpers: set[str],
    positive_ownership_helpers: set[str] | None = None,
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
    positive_helpers = positive_ownership_helpers or set()
    sink_statement = function.body[sink_index]
    sink_resource_names = _function_sink_resource_names(
        function.body[: sink_index + 1],
        sink_statement,
    )
    facts = []
    if _function_has_ownership_decorator(function, sink_resource_names):
        facts.append(
            _semantic_code_fact(
                source_path,
                handler,
                "ownership_guard",
                handler=handler,
            )
        )
    for helper in sorted(ownership_helpers & _signature_dependency_helpers(function)):
        if not _dependency_ownership_helper_matches_sink_resource(
            helper,
            sink_resource_names,
            ownership_helper_resource_terms,
        ):
            continue
        facts.append(
            _semantic_code_fact(
                source_path,
                helper,
                "ownership_guard",
                handler=handler,
            )
        )
    for index, statement in enumerate(function.body[:sink_index]):
        # Inline ownership/tenant guard in the handler before the sink.
        if _statement_has_ownership_guard(statement, sink_resource_names):
            facts.append(
                _semantic_code_fact(
                    source_path,
                    handler,
                    "ownership_guard",
                    handler=handler,
                )
            )
        positive_helper = _statement_has_positive_helper_guard(
            statement,
            positive_helpers,
            sink_resource_names,
        )
        if positive_helper:
            facts.append(
                _semantic_code_fact(
                    source_path,
                    positive_helper,
                    "ownership_guard",
                    handler=handler,
                )
            )
        for helper in sorted(
            _statement_ownership_helper_calls(
                statement,
                ownership_helpers,
                sink_resource_names,
            )
        ):
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
    # Ownership may gate the sink in the same statement (if eq: return send_file).
    if _statement_has_ownership_guard(sink_statement, sink_resource_names):
        facts.append(
            _semantic_code_fact(
                source_path,
                handler,
                "ownership_guard",
                handler=handler,
            )
        )
    positive_helper = _statement_has_positive_helper_guard(
        sink_statement,
        positive_helpers,
        sink_resource_names,
    )
    if positive_helper:
        facts.append(
            _semantic_code_fact(
                source_path,
                positive_helper,
                "ownership_guard",
                handler=handler,
            )
        )
    # Context-manager / same-statement helper calls (with ownership_context(...): sink).
    for helper in sorted(
        _statement_ownership_helper_calls(
            sink_statement,
            ownership_helpers,
            sink_resource_names,
        )
    ):
        facts.append(
            _semantic_code_fact(
                source_path,
                helper,
                "ownership_guard",
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


def _statement_sensitive_sink_calls(statement: ast.stmt) -> list[ast.Call]:
    return [
        node
        for node in ast.walk(statement)
        if isinstance(node, ast.Call)
        and _ast_call_name(node).lower() in SENSITIVE_SINK_NAMES
    ]


_PRINCIPAL_RESOURCE_NAMES = frozenset(
    {"context", "current_user", "g", "info", "req", "request", "user"}
)


def _resource_expression_names(expression: ast.AST) -> set[str]:
    """Resource variable roots used by an expression, excluding principals."""
    if isinstance(expression, ast.Name):
        return (
            set()
            if expression.id in _PRINCIPAL_RESOURCE_NAMES
            else {expression.id}
        )
    if isinstance(expression, ast.Attribute):
        return _resource_expression_names(expression.value)
    if isinstance(expression, ast.Call):
        return set().union(
            *(
                _resource_expression_names(value)
                for value in [
                    *expression.args,
                    *(keyword.value for keyword in expression.keywords),
                ]
            )
        )
    if isinstance(expression, ast.Await):
        return _resource_expression_names(expression.value)
    if isinstance(expression, ast.NamedExpr):
        return _resource_expression_names(expression.value)
    if isinstance(expression, ast.UnaryOp):
        return _resource_expression_names(expression.operand)
    if isinstance(expression, ast.BinOp):
        return _resource_expression_names(expression.left) | _resource_expression_names(
            expression.right
        )
    if isinstance(expression, ast.BoolOp):
        return set().union(
            *(_resource_expression_names(value) for value in expression.values)
        )
    if isinstance(expression, ast.Compare):
        return _resource_expression_names(expression.left) | set().union(
            *(
                _resource_expression_names(value)
                for value in expression.comparators
            )
        )
    if isinstance(expression, ast.IfExp):
        return (
            _resource_expression_names(expression.test)
            | _resource_expression_names(expression.body)
            | _resource_expression_names(expression.orelse)
        )
    if isinstance(expression, ast.Subscript):
        return _resource_expression_names(expression.value) | _resource_expression_names(
            expression.slice
        )
    if isinstance(expression, ast.Starred):
        return _resource_expression_names(expression.value)
    if isinstance(expression, ast.List | ast.Tuple | ast.Set):
        return set().union(
            *(_resource_expression_names(value) for value in expression.elts)
        )
    if isinstance(expression, ast.Dict):
        return set().union(
            *(
                _resource_expression_names(value)
                for value in [
                    *(key for key in expression.keys if key is not None),
                    *expression.values,
                ]
            )
        )
    return set()


def _call_resource_names(call: ast.Call) -> set[str]:
    return set().union(
        *(
            _resource_expression_names(value)
            for value in [*call.args, *(keyword.value for keyword in call.keywords)]
        )
    )


def _function_sink_resource_names(
    statements: list[ast.stmt],
    sink_statement: ast.stmt,
) -> set[str]:
    """Connect sink values to local aliases so helper checks prove the same resource."""
    names = set().union(
        *(
            _call_resource_names(call)
            for call in _statement_sensitive_sink_calls(sink_statement)
        )
    )
    if not names:
        return set()
    for _ in range(12):
        grew = False
        for statement in statements:
            assignments = _iter_simple_assignments(statement)
            assignments.extend(
                (node.target.id, node.value)
                for node in ast.walk(statement)
                if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name)
            )
            for name, value in assignments:
                value_names = _resource_expression_names(value)
                additions = (
                    value_names
                    if name in names
                    else {name}
                    if value_names & names
                    else set()
                )
                if additions - names:
                    names.update(additions)
                    grew = True
        if not grew:
            break
    return names


def _statement_direct_calls(statement: ast.stmt) -> list[ast.Call]:
    if isinstance(statement, ast.Try):
        return [
            call
            for nested in statement.body
            for call in _statement_direct_calls(nested)
        ]
    values: list[ast.AST] = []
    if isinstance(statement, ast.Expr):
        values.append(statement.value)
    elif isinstance(statement, ast.Assign):
        values.append(statement.value)
    elif isinstance(statement, ast.AnnAssign) and statement.value is not None:
        values.append(statement.value)
    elif isinstance(statement, ast.Return) and statement.value is not None:
        values.append(statement.value)
    elif isinstance(statement, (ast.With, ast.AsyncWith)):
        values.extend(item.context_expr for item in statement.items)
    calls = []
    for value in values:
        if isinstance(value, ast.Await):
            value = value.value
        if isinstance(value, ast.Call):
            calls.append(value)
    return calls


def _statement_ownership_helper_calls(
    statement: ast.stmt,
    ownership_helpers: set[str],
    sink_resource_names: set[str],
) -> set[str]:
    if not sink_resource_names:
        return set()
    helpers = set()
    for call in _statement_direct_calls(statement):
        helper = _ast_call_name(call)
        if (
            helper
            and (helper in ownership_helpers or _is_known_ownership_helper_name(helper))
            and _call_resource_names(call) & sink_resource_names
        ):
            helpers.add(helper)
    return helpers


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



def _match_is_ownership_gate(node: ast.Match, linked: set[str] | None = None) -> bool:
    """True for match ownership_eq with sink/deny cases (or boundary deny cases)."""
    subject = node.subject
    subject_eq = _expr_is_ownership_equality(subject, linked)
    subject_boundary = _test_has_ownership_boundary(subject, linked)
    if not subject_eq and not subject_boundary:
        # match True: case _ if owner_eq: ...
        for case in node.cases:
            guard = case.guard
            if guard is None:
                continue
            if _expr_is_ownership_equality(guard, linked) or _test_has_ownership_boundary(guard, linked):
                if _denies_access_in_block(case.body) or _block_has_sensitive_sink(case.body):
                    return True
        return False
    has_sink = any(_block_has_sensitive_sink(case.body) for case in node.cases)
    has_deny = any(_denies_access_in_block(case.body) for case in node.cases)
    return has_sink or has_deny


def _ifexp_is_ownership_gate(node: ast.IfExp, linked: set[str] | None = None) -> bool:
    """True for `sink if owner_eq else deny` or inverted deny-first forms."""
    test_eq = _expr_is_ownership_equality(node.test, linked)
    test_boundary = _test_has_ownership_boundary(node.test, linked)
    body_is_sink = _expr_has_sensitive_sink(node.body)
    orelse_is_sink = _expr_has_sensitive_sink(node.orelse)
    body_is_deny = _expr_is_deny_value(node.body)
    orelse_is_deny = _expr_is_deny_value(node.orelse)
    if test_eq and body_is_sink:
        return True
    if test_boundary and body_is_deny:
        return True
    if test_boundary and orelse_is_sink and body_is_deny:
        return True
    if test_eq and body_is_sink and orelse_is_deny:
        return True
    return False


def _expr_has_sensitive_sink(expr: ast.AST) -> bool:
    return any(
        isinstance(node, ast.Call)
        and _ast_call_name(node).lower() in SENSITIVE_SINK_NAMES
        for node in ast.walk(expr)
    )


def _expr_is_deny_value(expr: ast.AST) -> bool:
    if isinstance(expr, ast.Call):
        if _ast_call_name(expr).lower() in _DENY_CALL_NAMES:
            return True
        if _call_is_forbidden_response(expr):
            return True
    if isinstance(expr, ast.Constant) and expr.value in (False, None, 403):
        return True
    return False



def _function_param_names(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    names: set[str] = set()
    for arg in (
        *function.args.posonlyargs,
        *function.args.args,
        *function.args.kwonlyargs,
    ):
        if arg.arg not in {"self", "cls"}:
            names.add(arg.arg)
    return names


def _iter_simple_assignments(
    statement: ast.stmt,
) -> list[tuple[str, ast.AST]]:
    pairs: list[tuple[str, ast.AST]] = []
    if isinstance(statement, ast.Assign):
        for target in statement.targets:
            if isinstance(target, ast.Name):
                pairs.append((target.id, statement.value))
    elif isinstance(statement, ast.AnnAssign):
        if isinstance(statement.target, ast.Name) and statement.value is not None:
            pairs.append((statement.target.id, statement.value))
    elif isinstance(statement, ast.With):
        for item in statement.items:
            if isinstance(item.optional_vars, ast.Name):
                pairs.append((item.optional_vars.id, item.context_expr))
    elif isinstance(statement, ast.AsyncWith):
        for item in statement.items:
            if isinstance(item.optional_vars, ast.Name):
                pairs.append((item.optional_vars.id, item.context_expr))
    return pairs


def _expr_depends_on_linked(expr: ast.AST, linked: set[str]) -> bool:
    """True when expr transitively uses a resource-linked name (param/derived)."""
    if isinstance(expr, ast.Constant):
        return False
    if isinstance(expr, ast.Name):
        return expr.id in linked
    if isinstance(expr, ast.Attribute):
        return _expr_depends_on_linked(expr.value, linked)
    if isinstance(expr, ast.Call):
        for argument in expr.args:
            if _expr_depends_on_linked(argument, linked):
                return True
        for keyword in expr.keywords:
            if keyword.value is not None and _expr_depends_on_linked(keyword.value, linked):
                return True
        return False
    if isinstance(expr, ast.Await):
        return _expr_depends_on_linked(expr.value, linked)
    if isinstance(expr, ast.NamedExpr):
        return _expr_depends_on_linked(expr.value, linked)
    if isinstance(expr, ast.UnaryOp):
        return _expr_depends_on_linked(expr.operand, linked)
    if isinstance(expr, ast.BinOp):
        return _expr_depends_on_linked(expr.left, linked) or _expr_depends_on_linked(
            expr.right, linked
        )
    if isinstance(expr, ast.BoolOp):
        return any(_expr_depends_on_linked(value, linked) for value in expr.values)
    if isinstance(expr, ast.Compare):
        if _expr_depends_on_linked(expr.left, linked):
            return True
        return any(_expr_depends_on_linked(item, linked) for item in expr.comparators)
    if isinstance(expr, ast.IfExp):
        return (
            _expr_depends_on_linked(expr.test, linked)
            or _expr_depends_on_linked(expr.body, linked)
            or _expr_depends_on_linked(expr.orelse, linked)
        )
    if isinstance(expr, ast.Subscript):
        return _expr_depends_on_linked(expr.value, linked) or _expr_depends_on_linked(
            expr.slice, linked
        )
    if isinstance(expr, ast.Starred):
        return _expr_depends_on_linked(expr.value, linked)
    if isinstance(expr, ast.List | ast.Tuple | ast.Set):
        return any(_expr_depends_on_linked(item, linked) for item in expr.elts)
    if isinstance(expr, ast.Dict):
        for key, value in zip(expr.keys, expr.values):
            if key is not None and _expr_depends_on_linked(key, linked):
                return True
            if value is not None and _expr_depends_on_linked(value, linked):
                return True
        return False
    return False


def _function_resource_linked_names(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    """Names bound to route/resource inputs or derived from them.

    Ownership of an unrelated loaded object (constant id / non-param load) must
    not refute object-level authorization gaps on the path resource.
    """
    linked = _function_param_names(function)
    for _ in range(12):
        grew = False
        for statement in function.body:
            for name, value in _iter_simple_assignments(statement):
                if name in linked:
                    continue
                if _expr_depends_on_linked(value, linked):
                    linked.add(name)
                    grew = True
            # Walrus in statement tests: if (record := load(record_id)):
            for node in ast.walk(statement):
                if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
                    if node.target.id in linked:
                        continue
                    if _expr_depends_on_linked(node.value, linked):
                        linked.add(node.target.id)
                        grew = True
        if not grew:
            break
    return linked


def _identifier_is_principal_side(identifier: str) -> bool:
    if not identifier:
        return False
    if _is_principal_identifier(identifier):
        return True
    field = identifier.split(".")[-1]
    return _is_principal_boundary_field(identifier, field)


def _ownership_pair_is_resource_linked(
    left: str,
    right: str,
    linked: set[str],
) -> bool:
    """Require at least one non-principal side to be resource-linked."""
    subjects: list[str] = []
    for side in (left, right):
        if not side or _identifier_is_principal_side(side):
            continue
        subjects.append(side.split(".")[0])
    if not subjects:
        # No clear resource subject — do not claim object ownership control.
        return False
    return any(subject in linked for subject in subjects)


def _statement_has_ownership_guard(
    statement: ast.stmt,
    linked: set[str] | None = None,
) -> bool:
    """True when a statement encodes ownership/tenant denial or gated access."""
    if isinstance(statement, ast.Assert) and statement.test is not None:
        if _expr_is_ownership_equality(statement.test, linked):
            return True
    # Ternary: return sink if owner_eq else deny()
    if isinstance(statement, ast.Return) and isinstance(statement.value, ast.IfExp):
        if _ifexp_is_ownership_gate(statement.value, linked):
            return True
    # match ownership_eq: case True: sink / case False: deny
    if isinstance(statement, ast.Match) and _match_is_ownership_gate(statement, linked):
        return True
    for node in ast.walk(statement):
        if isinstance(node, ast.Assert) and node.test is not None:
            if _expr_is_ownership_equality(node.test, linked):
                return True
        if isinstance(node, ast.IfExp) and _ifexp_is_ownership_gate(node, linked):
            return True
        if not isinstance(node, ast.If):
            continue
        # if mismatch/membership: deny
        if _denies_access_in_block(node.body) and _test_has_ownership_boundary(
            node.test, linked
        ):
            return True
        # if ownership_eq: allow-path/sink; else: deny  OR gated sink on eq
        if _expr_is_ownership_equality(node.test, linked) or (
            isinstance(node.test, ast.BoolOp)
            and isinstance(node.test.op, (ast.And, ast.Or))
            and any(
                _expr_is_ownership_equality(value, linked) for value in node.test.values
            )
        ):
            if _denies_access_in_block(node.orelse):
                return True
            if _block_has_sensitive_sink(node.body):
                return True
        if _statement_has_ownership_query_filter(node):
            return True
    if _statement_has_ownership_query_filter(statement):
        return True
    return False


def _block_has_sensitive_sink(nodes: list[ast.stmt]) -> bool:
    return any(_statement_sensitive_sink_calls(statement) for statement in nodes)


_OWNERSHIP_DECORATOR_MARKERS = frozenset(
    {
        "require_ownership",
        "require_owner",
        "ownership_required",
        "check_ownership",
        "ensure_owner",
        "ensure_ownership",
        "verify_ownership",
        "owner_required",
        "requires_ownership",
        "owns_object",
        "object_owner_required",
    }
)

# Call-site ownership helpers when definition is not in the authorized snippet
# (imported ensure_owner / verify_record_access style).
_OWNERSHIP_HELPER_NAME_MARKERS = frozenset(
    {
        *_OWNERSHIP_DECORATOR_MARKERS,
        "verify_record_access",
        "verify_owner",
        "assert_owner",
        "assert_ownership",
        "check_owner",
        "require_record_owner",
        "ownership_context",
    }
)

_OWNERSHIP_CONTROL_RESOURCE_STOP_WORDS = frozenset(
    {
        "access",
        "assert",
        "authenticate",
        "authorization",
        "check",
        "context",
        "ensure",
        "get",
        "has",
        "id",
        "ids",
        "is",
        "object",
        "owner",
        "owned",
        "ownership",
        "permission",
        "permissions",
        "require",
        "required",
        "requires",
        "validate",
        "verify",
    }
)


def _is_known_ownership_helper_name(name: str) -> bool:
    leaf = name.split(".")[-1].lower()
    if not leaf:
        return False
    if leaf in _OWNERSHIP_HELPER_NAME_MARKERS:
        return True
    if "ownership" in leaf:
        return True
    if leaf.startswith("ensure_owner") or leaf.startswith("verify_owner"):
        return True
    if leaf.startswith("require_owner") or leaf.startswith("assert_owner"):
        return True
    return False


def _decorator_name(decorator: ast.AST) -> str:
    if isinstance(decorator, ast.Call):
        return _ast_call_name(decorator)
    return _ast_identifier(decorator)


def _function_has_ownership_decorator(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    sink_resource_names: set[str],
) -> bool:
    for decorator in function.decorator_list:
        leaf = _decorator_name(decorator).split(".")[-1].lower()
        if not leaf:
            continue
        if (
            leaf in _OWNERSHIP_DECORATOR_MARKERS
            or "ownership" in leaf
            or leaf.startswith("require_owner")
        ) and _ownership_control_matches_sink_resource(leaf, sink_resource_names):
            return True
    return False


def _ownership_control_matches_sink_resource(
    control_name: str,
    sink_resource_names: set[str],
) -> bool:
    """Accept generic controls or resource-specific controls linked to the sink."""
    if not sink_resource_names:
        return False
    control_resources = _ownership_control_resource_terms(control_name)
    if not control_resources:
        return True
    sink_resources = set().union(
        *(_ownership_control_resource_terms(name) for name in sink_resource_names)
    )
    return bool(control_resources & sink_resources)


_OWNERSHIP_HELPER_PRINCIPAL_PARAMETERS = frozenset(
    {
        "actor",
        "context",
        "current_user",
        "info",
        "principal",
        "req",
        "request",
        "user",
    }
)


def _ownership_helper_parameter_terms_by_name(
    parsed: list[tuple[str, dict[str, ast.FunctionDef | ast.AsyncFunctionDef]]],
    ownership_helpers: set[str],
) -> dict[str, set[frozenset[str]]]:
    terms_by_name: dict[str, set[frozenset[str]]] = {}
    for _source_path, functions in parsed:
        for name, function in functions.items():
            if name not in ownership_helpers:
                continue
            resource_terms = set().union(
                *(
                    _ownership_control_resource_terms(parameter)
                    for parameter in _function_param_names(function)
                    if parameter.lower()
                    not in _OWNERSHIP_HELPER_PRINCIPAL_PARAMETERS
                )
            )
            if resource_terms:
                terms_by_name.setdefault(name, set()).add(frozenset(resource_terms))
    return terms_by_name


def _dependency_ownership_helper_matches_sink_resource(
    helper: str,
    sink_resource_names: set[str],
    helper_resource_terms: dict[str, set[frozenset[str]]],
) -> bool:
    if not sink_resource_names:
        return False
    helper_name_terms = _ownership_control_resource_terms(helper)
    sink_terms = set().union(
        *(_ownership_control_resource_terms(name) for name in sink_resource_names)
    )
    signatures = helper_resource_terms.get(helper, set())
    if len(signatures) == 1:
        signature_matches = next(iter(signatures)) == sink_terms
        return signature_matches and (
            not helper_name_terms or bool(helper_name_terms & sink_terms)
        )
    if signatures:
        return False
    return bool(helper_name_terms & sink_terms)


def _ownership_control_resource_terms(name: str) -> set[str]:
    normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    terms = {
        term.lower()
        for term in re.split(r"[^A-Za-z0-9]+", normalized)
        if term
    }
    return terms - _OWNERSHIP_CONTROL_RESOURCE_STOP_WORDS


def _depends_helper_names(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    names: set[str] = set()
    for nested in ast.walk(node):
        if not isinstance(nested, ast.Call):
            continue
        if _ast_call_name(nested).split(".")[-1] != "Depends":
            continue
        for argument in nested.args:
            if isinstance(argument, (ast.Name, ast.Attribute)):
                leaf = _ast_identifier(argument).split(".")[-1]
                if leaf:
                    names.add(leaf)
            elif isinstance(argument, ast.Call):
                leaf = _ast_call_name(argument)
                if leaf:
                    names.add(leaf)
    return names


def _signature_dependency_helpers(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    helpers: set[str] = set()
    args = function.args
    for default in list(args.defaults) + [
        item for item in (args.kw_defaults or []) if item is not None
    ]:
        helpers |= _depends_helper_names(default)
    for annotation in [
        *(arg.annotation for arg in args.args if arg.annotation is not None),
        *(arg.annotation for arg in args.kwonlyargs if arg.annotation is not None),
    ]:
        helpers |= _depends_helper_names(annotation)
    return helpers


def _statement_has_ownership_query_filter(statement: ast.stmt | ast.AST) -> bool:
    """True for ORM/query filters that pin owner/tenant to the principal."""
    boundary_fields = {
        "owner_id",
        "user_id",
        "tenant_id",
        "account_id",
        "org_id",
        "organization_id",
        "workspace_id",
        "team_id",
        "project_id",
        "created_by_id",
        "creator_id",
        "author_id",
        "agent_id",
        "group_id",
    }
    for node in ast.walk(statement):
        if not isinstance(node, ast.Call):
            continue
        for keyword in node.keywords:
            if not keyword.arg:
                continue
            field = keyword.arg.lower()
            if field not in boundary_fields:
                continue
            value = _ast_identifier(keyword.value)
            if _is_principal_identifier(value) or _is_principal_boundary_field(value, field):
                return True
        for argument in node.args:
            if isinstance(argument, ast.Compare) and _expr_is_ownership_equality(argument):
                return True
    return False


def _test_has_ownership_boundary(
    test: ast.AST,
    linked: set[str] | None = None,
) -> bool:
    """True when an if-test encodes ownership/tenant/membership denial."""
    if isinstance(test, ast.Compare):
        return _compare_has_ownership_boundary(test, linked)
    if isinstance(test, ast.BoolOp) and isinstance(test.op, (ast.And, ast.Or)):
        return any(
            _test_has_ownership_boundary(value, linked) for value in test.values
        )
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        # if not (record.owner_id == user.id): deny
        return _expr_is_ownership_equality(test.operand, linked)
    return False


def _compare_has_ownership_boundary(
    comparison: ast.Compare,
    linked: set[str] | None = None,
) -> bool:
    if len(comparison.ops) != 1 or len(comparison.comparators) != 1:
        return False
    op = comparison.ops[0]
    left = _ast_identifier(comparison.left)
    right = _ast_identifier(comparison.comparators[0])
    if isinstance(op, ast.NotEq):
        if not _is_ownership_boundary_pair(left, right):
            return False
        if linked is not None and not _ownership_pair_is_resource_linked(left, right, linked):
            return False
        return True
    if isinstance(op, ast.NotIn):
        if not _is_membership_boundary_pair(left, right):
            return False
        if linked is not None and not _ownership_pair_is_resource_linked(left, right, linked):
            return False
        return True
    return False


def _expr_is_ownership_equality(
    expr: ast.AST,
    linked: set[str] | None = None,
) -> bool:
    if (
        not isinstance(expr, ast.Compare)
        or len(expr.ops) != 1
        or not isinstance(expr.ops[0], ast.Eq)
        or len(expr.comparators) != 1
    ):
        return False
    left = _ast_identifier(expr.left)
    right = _ast_identifier(expr.comparators[0])
    if not _is_ownership_boundary_pair(left, right):
        return False
    if linked is not None and not _ownership_pair_is_resource_linked(left, right, linked):
        return False
    return True


def _function_has_ownership_guard(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    linked = _function_resource_linked_names(function)
    return any(
        _statement_has_ownership_guard(statement, linked) for statement in function.body
    )


def _function_returns_ownership_predicate(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    """True when a helper returns a positive ownership/tenant equality predicate."""
    linked = _function_resource_linked_names(function)
    for statement in function.body:
        if not isinstance(statement, ast.Return) or statement.value is None:
            continue
        value = statement.value
        if _expr_is_ownership_equality(value, linked):
            return True
        if isinstance(value, ast.BoolOp) and isinstance(value.op, ast.And):
            if any(_expr_is_ownership_equality(item, linked) for item in value.values):
                return True
    return False


def _negated_helper_call(test: ast.AST) -> ast.Call | None:
    """Extract the helper call from `if not helper(...):` denial guards."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        call = test.operand
        if isinstance(call, ast.Await):
            call = call.value
        if isinstance(call, ast.Call):
            return call
        return None
    if (
        isinstance(test, ast.Compare)
        and len(test.ops) == 1
        and len(test.comparators) == 1
        and isinstance(test.ops[0], (ast.Is, ast.Eq))
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value is False
    ):
        call = test.left
        if isinstance(call, ast.Await):
            call = call.value
        if isinstance(call, ast.Call):
            return call
    return None


def _statement_has_positive_helper_guard(
    statement: ast.stmt,
    positive_helpers: set[str],
    sink_resource_names: set[str],
) -> str | None:
    """Return helper name when branch denies on a positive ownership helper result."""
    if not positive_helpers or not sink_resource_names:
        return None
    for node in ast.walk(statement):
        if not isinstance(node, ast.If) or not _denies_access_in_block(node.body):
            continue
        call = _negated_helper_call(node.test)
        helper = _ast_call_name(call) if call is not None else ""
        if (
            helper in positive_helpers
            and call is not None
            and _call_resource_names(call) & sink_resource_names
        ):
            return helper
    return None


def _raises_in_block(nodes: list[ast.stmt]) -> bool:
    return any(isinstance(nested, ast.Raise) for node in nodes for nested in ast.walk(node))


_DENY_CALL_NAMES = frozenset(
    {
        "deny",
        "abort",
        "forbid",
        "forbidden",
        "unauthorized",
        "permission_denied",
        "access_denied",
        "reject",
    }
)


def _denies_access_in_block(nodes: list[ast.stmt]) -> bool:
    """True when the branch rejects access via raise or common deny helpers."""
    if _raises_in_block(nodes):
        return True
    for node in nodes:
        for nested in ast.walk(node):
            if isinstance(nested, ast.Call):
                if _ast_call_name(nested).lower() in _DENY_CALL_NAMES:
                    return True
                if _call_is_forbidden_response(nested):
                    return True
            if isinstance(nested, ast.Return) and isinstance(nested.value, ast.Call):
                if _ast_call_name(nested.value).lower() in _DENY_CALL_NAMES:
                    return True
                if _call_is_forbidden_response(nested.value):
                    return True
            if (
                isinstance(nested, ast.Return)
                and isinstance(nested.value, ast.Constant)
                and nested.value.value in (False, None, 403)
            ):
                return True
    return False


def _call_is_forbidden_response(call: ast.Call) -> bool:
    """True for Response(status=403) / JSONResponse(status_code=403) style denies."""
    name = _ast_call_name(call).lower()
    if name not in {
        "response",
        "jsonresponse",
        "plaintextresponse",
        "plain_text_response",
        "httpresponse",
        "http_response",
    }:
        # still allow any call with explicit forbidden status kwargs
        pass
    for keyword in call.keywords:
        if not keyword.arg:
            continue
        key = keyword.arg.lower()
        if key not in {"status", "status_code", "code"}:
            continue
        if isinstance(keyword.value, ast.Constant) and keyword.value.value in (401, 403, 404):
            return True
    return False


def _is_principal_identifier(identifier: str) -> bool:
    return identifier in {
        "current_user.id",
        "request.user.id",
        "user.id",
        "g.user.id",
        "g.current_user.id",
        "req.user.id",
        "request.state.user.id",
        "info.context.user.id",
        "context.user.id",
    }


def _is_principal_boundary_field(identifier: str, field: str) -> bool:
    parts = [part for part in identifier.split(".") if part]
    if len(parts) < 2 or parts[-1] != field:
        return False
    root = ".".join(parts[:-1])
    return root in {
        "user",
        "current_user",
        "request.user",
        "g.user",
        "g.current_user",
        "req.user",
        "request.state.user",
        "info.context.user",
        "context.user",
    }


def _is_ownership_boundary_pair(left: str, right: str) -> bool:
    boundary_fields = {
        "owner_id",
        "user_id",
        "tenant_id",
        "account_id",
        "org_id",
        "organization_id",
        "workspace_id",
        "team_id",
        "project_id",
        "created_by_id",
        "creator_id",
        "author_id",
        "agent_id",
        "group_id",
    }
    left_field = left.split(".")[-1]
    right_field = right.split(".")[-1]
    if left_field in boundary_fields and _is_principal_identifier(right):
        return True
    if right_field in boundary_fields and _is_principal_identifier(left):
        return True
    # Multi-tenant / org boundary: resource.tenant_id != user.tenant_id
    if left_field in boundary_fields and left_field == right_field:
        if _is_principal_boundary_field(right, left_field) or _is_principal_boundary_field(
            left, left_field
        ):
            return True
    return False


def _is_membership_boundary_pair(left: str, right: str) -> bool:
    """True for principal membership checks like user.id not in record.member_ids."""
    membership_fields = {
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
    left_field = left.split(".")[-1]
    right_field = right.split(".")[-1]
    if _is_principal_identifier(left) and right_field in membership_fields:
        return True
    if _is_principal_identifier(right) and left_field in membership_fields:
        return True
    return False


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
    # Walrus: (owner := record.owner_id) → record.owner_id
    if isinstance(value, ast.NamedExpr):
        return _ast_identifier(value.value)
    # getattr(record, "owner_id") → record.owner_id
    if (
        isinstance(value, ast.Call)
        and _ast_call_name(value) == "getattr"
        and len(value.args) >= 2
        and isinstance(value.args[1], ast.Constant)
        and isinstance(value.args[1].value, str)
    ):
        parent = _ast_identifier(value.args[0])
        field = value.args[1].value
        return f"{parent}.{field}" if parent else field
    return ""


def _safe_external_fact(value: dict) -> dict[str, Any] | None:
    artifact_kind = _safe_text(value.get("artifact_kind"))
    fact_type = _safe_text(value.get("fact_type"))
    if artifact_kind not in SUPPORTED_ARTIFACT_KINDS or not fact_type:
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


def _safe_static_advisory_fact(value: dict) -> dict[str, Any] | None:
    if (
        _safe_text(value.get("fact_type")) != "static_advisory"
        or _safe_text(value.get("artifact_kind")) != "static_advisory"
    ):
        return None
    fact_ref = _safe_text(value.get("fact_ref"))
    match = _STATIC_ADVISORY_FACT_REF_PATTERN.fullmatch(fact_ref)
    source_path = _safe_source_name(value.get("source_path"))
    rule_id = _safe_text(value.get("symbol_name"))
    if (
        match is None
        or not source_path
        or rule_id != match.group(3)
        or int(match.group(2)) < 1
    ):
        return None
    return {
        "fact_ref": fact_ref,
        "fact_type": "static_advisory",
        "artifact_kind": "static_advisory",
        "source_path": source_path,
        "symbol_name": rule_id,
        "line_number": int(match.group(2)),
        "advisory_only": True,
    }


def _static_advisory_matches_candidate(
    fact: dict[str, Any],
    *,
    candidate: dict[str, Any],
    root_cause: str,
    code_facts: list[CodebaseFactCandidate],
) -> bool:
    rule_family = _static_advisory_rule_family(fact.get("symbol_name"))
    candidate_family = _candidate_advisory_family(candidate, root_cause=root_cause)
    return bool(
        rule_family
        and rule_family == candidate_family
        and _static_advisory_matches_code_location(fact, code_facts)
    )


def _static_advisory_matches_code_location(
    fact: dict[str, Any],
    code_facts: list[CodebaseFactCandidate],
) -> bool:
    source_path = _safe_source_name(fact.get("source_path"))
    line_number = fact.get("line_number")
    if not source_path or not isinstance(line_number, int):
        return False
    return any(
        code_fact.fact_type in {"sensitive_sink", "unverified_token_decode"}
        and _safe_source_name(code_fact.source_path) == source_path
        and (position := _code_fact_position(code_fact)) is not None
        and position[0] == line_number
        for code_fact in code_facts
    )


def _static_advisory_rule_family(value: object) -> str:
    tokens = _advisory_tokens(value)
    if "ssrf" in tokens:
        return "ssrf"
    if ({"command", "injection"} <= tokens) or ({"shell", "injection"} <= tokens):
        return "command_injection"
    if "deserialization" in tokens or "deserialize" in tokens:
        return "unsafe_deserialization"
    if (
        {"path", "traversal"} <= tokens
        or {"path", "injection"} <= tokens
        or {"directory", "traversal"} <= tokens
        or {"zip", "slip"} <= tokens
    ):
        return "path_traversal"
    if {"mass", "assignment"} <= tokens:
        return "mass_assignment"
    if ({"file", "upload"} <= tokens) or ({"unrestricted", "upload"} <= tokens):
        return "file_upload"
    if "jwt" in tokens:
        return "jwt_authentication_bypass"
    if {"agent", "tool"} <= tokens and ({"authorization", "authz"} & tokens):
        return "agent_tool_authorization"
    if "idor" in tokens or "bola" in tokens or {"access", "control"} <= tokens:
        return "authorization"
    if "toctou" in tokens or {"race", "condition"} <= tokens:
        return "race_condition"
    if "sql" in tokens and ("injection" in tokens or "raw" in tokens):
        return "injection"
    return _static_advisory_cwe_family(value)


def _static_advisory_cwe_family(value: object) -> str:
    families = {
        family
        for raw_cwe in _CWE_ADVISORY_ID_PATTERN.findall(_safe_text(value))
        if (family := _CWE_ADVISORY_FAMILIES.get(str(int(raw_cwe)))) is not None
    }
    return next(iter(families)) if len(families) == 1 else ""


def _candidate_advisory_family(candidate: dict[str, Any], *, root_cause: str) -> str:
    root_family = _candidate_advisory_family_value(root_cause)
    vuln_family = _candidate_advisory_family_value(candidate.get("vuln_type"))
    if root_family and vuln_family and root_family != vuln_family:
        return ""
    return root_family or vuln_family


def _candidate_advisory_family_value(value: object) -> str:
    tokens = _advisory_tokens(value)
    if "ssrf" in tokens:
        return "ssrf"
    if "jwt" in tokens:
        return "jwt_authentication_bypass"
    if ({"command", "injection"} <= tokens) or ({"shell", "injection"} <= tokens):
        return "command_injection"
    if "deserialization" in tokens or "deserialize" in tokens:
        return "unsafe_deserialization"
    if (
        {"path", "traversal"} <= tokens
        or {"path", "injection"} <= tokens
        or {"directory", "traversal"} <= tokens
        or {"zip", "slip"} <= tokens
    ):
        return "path_traversal"
    if {"mass", "assignment"} <= tokens:
        return "mass_assignment"
    if ({"file", "upload"} <= tokens) or ({"unrestricted", "upload"} <= tokens):
        return "file_upload"
    if "toctou" in tokens or {"race", "condition"} <= tokens:
        return "race_condition"
    if {"agent", "tool"} <= tokens and ({"authorization", "authz"} & tokens):
        return "agent_tool_authorization"
    if "idor" in tokens or "bola" in tokens or "ownership" in tokens or "authorization" in tokens:
        return "authorization"
    if "sql" in tokens or "sqli" in tokens or "injection" in tokens:
        return "injection"
    return ""


def _advisory_tokens(value: object) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", _safe_text(value).lower(), re.ASCII))


def _is_dependency_advisory_fact(fact: dict[str, Any]) -> bool:
    return (
        fact.get("artifact_kind") == "sbom"
        and fact.get("fact_type") == "dependency_signal"
    )


def _safe_candidate_source_facts(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    facts = []
    for item in value:
        if not isinstance(item, dict):
            continue
        artifact_kind = _safe_text(item.get("artifact_kind"))
        fact_type = _safe_text(item.get("fact_type"))
        if artifact_kind == "static_advisory":
            if fact := _safe_static_advisory_fact(item):
                facts.append(fact)
            continue
        if artifact_kind not in SUPPORTED_ARTIFACT_KINDS or not fact_type:
            continue
        source_path = _safe_source_name(item.get("source_path"))
        symbol_name = _safe_text(item.get("symbol_name"))
        route = _route(item.get("route_method"), item.get("route_path"))
        fact_ref = (
            _code_fact_ref(source_path, symbol_name, fact_type)
            if artifact_kind == "code"
            else f"{artifact_kind}:{route['method']}:{route['path']}"
            if route
            else f"{artifact_kind}:{fact_type}"
        )
        if artifact_kind == "sbom":
            fact_ref = _safe_sbom_fact_ref(item.get("fact_ref")) or fact_ref
        fact: dict[str, Any] = {
            "fact_ref": fact_ref,
            "fact_type": fact_type,
            "artifact_kind": artifact_kind,
        }
        if route:
            fact["route"] = route
        if source_path:
            fact["source_path"] = source_path
        if symbol_name:
            fact["symbol_name"] = symbol_name
        if root_cause := _safe_text(item.get("root_cause")):
            fact["root_cause"] = root_cause
        if artifact_kind == "sbom":
            for field in (
                "package_name",
                "package_version",
                "ecosystem",
                "vulnerability_id",
                "severity",
            ):
                if safe_value := _safe_sbom_fact_value(item.get(field)):
                    fact[field] = safe_value
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



def _code_fact_matches_route(
    fact: CodebaseFactCandidate,
    route: dict[str, str],
) -> bool:
    fact_route = _route(fact.route_method, fact.route_path)
    return (
        bool(route)
        and bool(fact_route)
        and fact_route.get("method") == route.get("method")
        and _route_paths_match(
            _text(fact_route.get("path")),
            _text(route.get("path")),
        )
    )


def _fact_matches_route(fact: dict, route: dict[str, str]) -> bool:
    fact_route = fact.get("route")
    return (
        bool(route)
        and isinstance(fact_route, dict)
        and fact_route.get("method") == route.get("method")
        and _route_paths_match(
            _text(fact_route.get("path")),
            _text(route.get("path")),
            allow_observed_route_values=fact.get("artifact_kind") == "har",
        )
    )


def _route_paths_match(
    left: str,
    right: str,
    *,
    allow_observed_route_values: bool = False,
) -> bool:
    left_segments = [segment for segment in left.strip("/").split("/") if segment]
    right_segments = [segment for segment in right.strip("/").split("/") if segment]
    if len(left_segments) != len(right_segments):
        return False
    return all(
        _route_segments_match(
            left_segment,
            right_segment,
            allow_observed_route_values=allow_observed_route_values,
        )
        for left_segment, right_segment in zip(
            left_segments,
            right_segments,
            strict=True,
        )
    )


def _route_segments_match(
    left: str,
    right: str,
    *,
    allow_observed_route_values: bool,
) -> bool:
    if left == right:
        return True
    left_template = _route_segment_is_template(left)
    right_template = _route_segment_is_template(right)
    if left_template and right_template:
        return True
    return allow_observed_route_values and (
        (
            left_template
            and _route_segment_looks_observed_dynamic(right)
        )
        or (
            right_template
            and _route_segment_looks_observed_dynamic(left)
        )
    )


def _route_segment_is_template(segment: str) -> bool:
    return (
        segment.startswith(":")
        or segment.startswith("{")
        and segment.endswith("}")
        or segment.startswith("<")
        and segment.endswith(">")
    )


def _route_segment_looks_observed_dynamic(segment: str) -> bool:
    if segment.isdigit():
        return True
    lowered = segment.lower()
    parts = lowered.split("-")
    if (
        len(parts) == 5
        and [len(part) for part in parts] == [8, 4, 4, 4, 12]
        and all(_is_hex(part) for part in parts)
    ):
        return True
    compact = lowered.replace("-", "")
    return len(compact) >= 16 and compact.isalnum() and not compact.isalpha()


def _is_hex(value: str) -> bool:
    return bool(value) and all(character in "0123456789abcdef" for character in value)


def _matching_code_facts(
    facts: list[CodebaseFactCandidate],
    route: dict[str, str],
    *,
    preferred_source_path: str = "",
    preferred_symbol_name: str = "",
) -> list[CodebaseFactCandidate]:
    route_facts = [
        fact
        for fact in facts
        if fact.fact_type == "route_handler" and _code_fact_matches_route(fact, route)
    ]
    if preferred_source_path:
        route_facts = [
            fact
            for fact in route_facts
            if _safe_source_name(fact.source_path) == preferred_source_path
        ]
    if not route and preferred_source_path and preferred_symbol_name:
        route_facts = [
            fact
            for fact in facts
            if fact.fact_type == "graphql_operation"
            and _safe_source_name(fact.source_path) == preferred_source_path
            and _safe_text(fact.payload.get("handler")) == preferred_symbol_name
        ]

    handlers = {
        identity
        for fact in route_facts
        if (identity := _code_fact_identity(fact, "handler")) is not None
    }
    calls_by_handler: dict[tuple[str, str], list[CodebaseFactCandidate]] = {}
    handlers_by_symbol: dict[str, set[tuple[str, str]]] = {}
    service_handlers_by_method: dict[
        tuple[str, str, str], set[tuple[str, str]]
    ] = {}
    callers_by_symbol: dict[str, set[tuple[str, str]]] = {}
    earliest_sink_line: dict[tuple[str, str], int] = {}
    for fact in facts:
        if handler_identity := _code_fact_identity(fact, "handler"):
            if service_class := _code_fact_service_class(fact):
                handler = _safe_text(fact.payload.get("handler"))
                if handler:
                    service_handlers_by_method.setdefault(
                        (handler_identity[0], service_class, handler),
                        set(),
                    ).add(handler_identity)
            else:
                handlers_by_symbol.setdefault(handler_identity[1], set()).add(
                    handler_identity
                )
        if fact.fact_type == "sensitive_sink":
            handler_identity = _code_fact_identity(fact, "handler")
            line = fact.payload.get("line") if isinstance(fact.payload, dict) else None
            if handler_identity is not None and isinstance(line, int):
                previous_line = earliest_sink_line.get(handler_identity)
                if previous_line is None or line < previous_line:
                    earliest_sink_line[handler_identity] = line
        if fact.fact_type != "service_call":
            continue
        if caller_identity := _code_fact_identity(fact, "caller"):
            calls_by_handler.setdefault(caller_identity, []).append(fact)
            if _code_fact_service_class(fact) is None:
                callers_by_symbol.setdefault(caller_identity[1], set()).add(
                    caller_identity
                )

    reachable = set(handlers)
    verified_access_helpers = {
        identity
        for identity, calls in calls_by_handler.items()
        if _is_typescript_verified_access_helper(identity, calls)
    }
    pending = [(identity, identity in verified_access_helpers) for identity in handlers]
    seen_paths = set(pending)
    while pending:
        caller, through_verified_access = pending.pop()
        for fact in calls_by_handler.get(caller, []):
            if not _service_call_precedes_local_sink(fact, earliest_sink_line):
                continue
            callee = _safe_text(fact.symbol_name)
            service_receiver = (
                _safe_text(fact.payload.get("service_receiver"))
                if isinstance(fact.payload, dict)
                else ""
            )
            target_service_class = (
                _safe_text(fact.payload.get("target_service_class"))
                if isinstance(fact.payload, dict)
                else ""
            )
            target_service_source_path = (
                _safe_source_name(fact.payload.get("target_service_source_path"))
                if isinstance(fact.payload, dict)
                else ""
            )
            if service_receiver:
                candidates = service_handlers_by_method.get(
                    (
                        target_service_source_path,
                        target_service_class,
                        callee,
                    ),
                    set(),
                )
                next_handlers = candidates if len(candidates) == 1 else set()
            else:
                candidates = handlers_by_symbol.get(callee, set())
                same_source = (caller[0], callee)
                next_handlers = (
                    {same_source}
                    if same_source in candidates
                    else candidates
                    if len(candidates) == 1
                    else set()
                )
            if not next_handlers:
                if not service_receiver:
                    call_only_candidates = callers_by_symbol.get(callee, set())
                    call_only_same_source = (caller[0], callee)
                    call_only_handlers = (
                        {call_only_same_source}
                        if call_only_same_source in call_only_candidates
                        else call_only_candidates
                        if len(call_only_candidates) == 1
                        else set()
                    )
                    if (
                        _service_call_precedes_local_sink(fact, earliest_sink_line)
                        and (
                            through_verified_access
                            or bool(call_only_handlers & verified_access_helpers)
                        )
                    ):
                        next_handlers = call_only_handlers
            for next_handler in next_handlers:
                next_through_verified_access = (
                    through_verified_access or next_handler in verified_access_helpers
                )
                path_state = (next_handler, next_through_verified_access)
                if path_state in seen_paths:
                    continue
                seen_paths.add(path_state)
                reachable.add(next_handler)
                pending.append(path_state)

    return [
        fact
        for fact in facts
        if fact in route_facts
        or _code_fact_identity(fact, "handler") in reachable
        or _code_fact_identity(fact, "caller") in reachable
    ]


def _is_typescript_verified_access_helper(
    identity: tuple[str, str],
    calls: list[CodebaseFactCandidate],
) -> bool:
    source_path, function_name = identity
    normalized_name = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", function_name)
    normalized_name = re.sub(r"[^A-Za-z0-9]+", "_", normalized_name).strip("_").lower()
    return (
        source_path.lower().endswith((".ts", ".tsx", ".mts", ".cts"))
        and normalized_name.startswith("verify_")
        and normalized_name.endswith("_access")
        and any(_safe_text(call.symbol_name) == "deny" for call in calls)
    )


def _service_call_precedes_local_sink(
    fact: CodebaseFactCandidate,
    earliest_sink_line: dict[tuple[str, str], int],
) -> bool:
    caller = _code_fact_identity(fact, "caller")
    line = fact.payload.get("line") if isinstance(fact.payload, dict) else None
    sink_line = earliest_sink_line.get(caller) if caller is not None else None
    return not isinstance(line, int) or sink_line is None or line < sink_line


def _code_fact_identity(
    fact: CodebaseFactCandidate,
    symbol_key: str,
) -> tuple[str, str] | None:
    if not isinstance(fact.payload, dict):
        return None
    source_path = _safe_source_name(fact.source_path)
    symbol = _safe_text(fact.payload.get(symbol_key))
    if service_class := _code_fact_service_class(fact):
        symbol = f"{service_class}.{symbol}"
    return (source_path, symbol) if source_path and symbol else None


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
            and _code_fact_matches_route(fact, route)
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
) -> tuple[str, str, str]:
    if not handler:
        return "", "", ""
    calls: dict[str, set[str]] = {}
    sinks = set()
    sink_symbols_by_handler: dict[str, set[str]] = {}
    sink_evidence_refs_by_handler: dict[str, str] = {}
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
            sink_symbol = _safe_text(fact.symbol_name)
            if sink_handler:
                sinks.add(sink_handler)
            if sink_handler and sink_symbol:
                sink_symbols_by_handler.setdefault(sink_handler, set()).add(sink_symbol)
                source_path = _safe_source_name(fact.source_path)
                source_by_symbol.setdefault(sink_symbol, source_path)
                sink_evidence_refs_by_handler.setdefault(
                    sink_handler,
                    _code_fact_ref(
                        source_path or "code.py",
                        sink_symbol,
                        "sensitive_sink",
                    ),
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

    def reachable_sink_evidence_ref(start: str) -> str:
        pending = [start]
        seen = set()
        while pending:
            current = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            if evidence_ref := sink_evidence_refs_by_handler.get(current):
                return evidence_ref
            pending.extend(sorted(calls.get(current, set()) - seen, reverse=True))
        return ""

    root = next(
        (
            callee
            for callee in sorted(calls.get(handler, set()))
            if reaches_sink(callee)
        ),
        "",
    )
    if root:
        return (
            root,
            reachable_sink_evidence_ref(root)
            or _code_fact_ref(
                source_by_symbol.get(root, "code.py"), root, "service_call"
            ),
            "service",
        )
    sink_symbols = sorted(sink_symbols_by_handler.get(handler, set()))
    if not sink_symbols:
        return "", "", ""
    root = sink_symbols[0]
    return (
        root,
        _code_fact_ref(source_by_symbol.get(root, "code.py"), root, "sensitive_sink"),
        "direct_sink",
    )


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
    text = _safe_text(value).replace("\\", "/")
    if (
        not text
        or len(text) > 200
        or text.startswith("/")
        or ":" in text
        or any(segment in {"", ".", ".."} for segment in text.split("/"))
    ):
        return ""
    return text


def _safe_sbom_fact_ref(value: object) -> str:
    text = _safe_text(value)
    return text if re.fullmatch(r"sbom_artifact:dependency:[0-9a-f]{64}", text) else ""


def _safe_sbom_fact_value(value: object) -> str:
    text = _safe_text(value)
    if len(text) > 200 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+/@:-]*", text):
        return ""
    return text


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


def _safe_validation_mode(value: object) -> str:
    text = _safe_text(value)
    return text if re.fullmatch(r"[a-z][a-z0-9_]{0,100}", text) else ""


def _public_filter_refutes_candidate(candidate: object) -> bool:
    if not isinstance(candidate, dict):
        return False
    return (
        _safe_text(candidate.get("vuln_type")).lower()
        in PUBLIC_FILTER_REFUTABLE_VULN_TYPES
    )


def _safe_research_strings(value: object, *, maximum: int = 8) -> list[str]:
    if not isinstance(value, list):
        return []
    values = []
    for item in value:
        safe_value = _safe_text(item)
        if safe_value and safe_value not in values:
            values.append(safe_value)
        if len(values) >= maximum:
            break
    return values


def _local_validation_plan(
    *,
    route_label: str,
    root_symbol: str,
) -> list[str]:
    return [
        f"Local review only for {route_label}: confirm whether an ownership "
        f"or authorization guard runs before the sensitive sink"
        + (f" reached via {root_symbol}" if root_symbol else "")
        + ".",
        SAFE_VALIDATION_STEP,
    ]


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
            needs_card = build_falsification_card(
                state,
                disposition="needs_evidence",
                evidence_refs=_string_list(state.get("source_fact_refs")),
                missing_evidence=missing_evidence,
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
                    "falsification_card": needs_card,
                    "falsification_summary": project_falsification_summary(needs_card),
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
            refute_card = build_falsification_card(
                state,
                disposition="refuted",
                evidence_refs=[control_ref],
            )
            decisions.append(
                {
                    "candidate_id": state["candidate_id"],
                    "root_cause_id": state["root_cause_id"],
                    "disposition": "refuted",
                    "evidence_refs": [control_ref],
                    "falsification_card": refute_card,
                    "falsification_summary": project_falsification_summary(refute_card),
                }
            )
            continue
        public_ref = _text(state.get("public_evidence_ref"))
        if (
            public_ref
            and public_ref in evidence_refs
            and _public_filter_refutes_candidate(state)
        ):
            suppress_card = build_falsification_card(
                state,
                disposition="suppressed",
                evidence_refs=[public_ref],
            )
            decisions.append(
                {
                    "candidate_id": state["candidate_id"],
                    "root_cause_id": state["root_cause_id"],
                    "disposition": "suppressed",
                    "evidence_refs": [public_ref],
                    "falsification_card": suppress_card,
                    "falsification_summary": project_falsification_summary(suppress_card),
                }
            )
            continue
        duplicate_target = duplicate_targets.get(_text(state.get("candidate_id")))
        if duplicate_target is not None:
            canonical_root_id, shared_ref = duplicate_target
            dedupe_card = build_falsification_card(
                state,
                disposition="deduplicated",
                evidence_refs=[shared_ref],
                duplicate_of=canonical_root_id,
            )
            decisions.append(
                {
                    "candidate_id": state["candidate_id"],
                    "root_cause_id": state["root_cause_id"],
                    "disposition": "deduplicated",
                    "evidence_refs": [shared_ref],
                    "duplicate_of": canonical_root_id,
                    "falsification_card": dedupe_card,
                    "falsification_summary": project_falsification_summary(dedupe_card),
                }
            )
            continue
        route = state["route"] if isinstance(state.get("route"), dict) else {}
        route_method = _text(route.get("method")).upper()
        route_path = _text(route.get("path"))
        route_label = f"{route_method} {route_path}".strip()
        root_symbol = _text(state.get("root_cause_id")).rpartition(":")[2]
        code_refs = [
            ref for ref in evidence_refs if _text(ref).startswith("code:")
        ]
        affected_code_path = code_refs[0]
        retain_card = build_falsification_card(
            state,
            disposition="retained",
            evidence_refs=evidence_refs,
        )
        retain_summary = project_falsification_summary(retain_card)
        retain_survived_kill_score = survived_kill_score(retain_card)
        retain_evidence_completeness_score = _evidence_completeness_score(state)
        retain_priority_score = _priority_score(state.get("priority_score"))
        safe_validation_plan = _local_validation_plan(
            route_label=route_label,
            root_symbol=root_symbol,
        )
        impact_rationale = _safe_text(state.get("impact_rationale")) or (
            f"Potential {state['vuln_type']} impact on {route_label}; "
            "the local evidence remains unverified."
        )
        candidate_projection = {
            "candidate_id": state["candidate_id"],
            "rank": len(final_candidates) + 1,
            "vuln_type": state["vuln_type"],
            "root_cause_id": state["root_cause_id"],
            "route": state["route"],
            "source_fact_refs": evidence_refs,
            "survived_kill_score": retain_survived_kill_score,
            "evidence_completeness_score": retain_evidence_completeness_score,
            "priority_score": retain_priority_score,
            "affected_code_path": affected_code_path,
            "evidence_trace_status": "traceable",
            "human_validation_readiness": "ready",
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
            "refutation_questions": _refutation_questions(state),
            "validation_mode": _safe_validation_mode(state.get("validation_mode"))
            or "non_destructive_request_review",
            "evidence_needed": _safe_research_strings(state.get("evidence_needed")),
            "impact_rationale": impact_rationale,
            "impact_score": _priority_score(state.get("impact_score")),
            "safe_validation_plan": safe_validation_plan,
            "next_allowed_action": "Human review of the cited local evidence.",
            "safety_blockers": [
                "execute_live_validation",
                "touch_real_user_data",
                "submit_report",
            ],
            "broken_invariant": _safe_text(state.get("broken_invariant"))
            or retain_card.get("broken_invariant")
            or "",
            "why_still_alive": list(retain_summary.get("why_still_alive") or []),
            "falsification_summary": retain_summary,
            "falsification_card": retain_card,
        }
        decisions.append(
            {
                "candidate_id": state["candidate_id"],
                "root_cause_id": state["root_cause_id"],
                "disposition": "retained",
                "evidence_refs": evidence_refs,
                "candidate_projection": candidate_projection,
                "priority_score": retain_priority_score,
                "evidence_completeness_score": retain_evidence_completeness_score,
                "survived_kill_score": retain_survived_kill_score,
                "falsification_card": retain_card,
                "falsification_summary": retain_summary,
            }
        )
        final_candidates.append(candidate_projection)
    ranking_by_id = {
        decision["candidate_id"]: (
            _priority_score(decision.get("survived_kill_score")),
            _priority_score(decision.get("evidence_completeness_score")),
            _priority_score(decision.get("priority_score")),
        )
        for decision in decisions
        if decision.get("disposition") == "retained"
    }
    final_candidates.sort(
        key=lambda candidate: (
            -ranking_by_id.get(candidate["candidate_id"], (0, 0, 0))[0],
            -ranking_by_id.get(candidate["candidate_id"], (0, 0, 0))[1],
            -ranking_by_id.get(candidate["candidate_id"], (0, 0, 0))[2],
            candidate["candidate_id"],
        )
    )
    final_candidates = final_candidates[:5]
    for rank, candidate in enumerate(final_candidates, start=1):
        candidate["rank"] = rank
        card = candidate.get("falsification_card")
        if isinstance(card, dict) and isinstance(card.get("decision"), dict):
            card["decision"]["rank"] = rank
        summary = candidate.get("falsification_summary")
        if isinstance(summary, dict):
            summary["decision_status"] = "retained"
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
    evidence_context: dict | None = None,
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
        safe_evidence_context = _safe_evidence_context(
            evidence_context,
            asset=authoritative_record.asset,
        )
        campaign_payload = {
            "pipeline_run_id": run_id,
            "source_pipeline_run_ref": f"pipeline_run:{run_id}",
            "submission_blocked": True,
            **_false_safety_fields(),
        }
        if safe_evidence_context is not None:
            campaign_payload.update(safe_evidence_context)
        allowed_tools = ["static_analyzer", "api_artifact_mapper"]
        if safe_evidence_context is not None:
            allowed_tools.append("candidate_hunter_local_evidence_inspector")
        campaign = repository.create_campaign(
            program_id=authoritative_record.program_id,
            name=f"Candidate Hunter loop for {run_id}",
            autonomy_level="level_0_read_only",
            scope_status="in_scope",
            policy_text=policy_text,
            default_asset=authoritative_record.asset,
            target_classes=["authorization"],
            allowed_tools=allowed_tools,
            created_by="candidate_hunter_loop",
            payload=campaign_payload,
        )
        repository.upsert_campaign_budget(
            campaign_id=campaign.id,
            time_budget_minutes=15 if safe_evidence_context is not None else None,
            token_budget=8000 if safe_evidence_context is not None else None,
            tool_call_budget=4 if safe_evidence_context is not None else 0,
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
    has_initial_candidate_states = isinstance(initial_candidate_states, list)
    if not has_initial_candidate_states:
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
            _initial_states_with_safe_context(
                initial_candidate_states,
                candidate_states,
            )
            if (
                round_number == 1
                and latest_rerank is None
                and has_initial_candidate_states
            )
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
        if (
            round_result.get("evidence_requests")
            and _campaign_has_evidence_specialist(campaign)
        ):
            from app.candidate_hunter_evidence import materialize_evidence_inspection_task

            try:
                evidence_task = materialize_evidence_inspection_task(
                    repository=repository,
                    pipeline_run=authoritative_record,
                    campaign=campaign,
                    owner_task=task,
                    evidence_request_stage=stages[1],
                )
            except ValueError:
                return _persisted_loop_result(
                    repository,
                    run_id,
                    campaign,
                    task,
                    stop_reason_override="evidence_task_materialization_failed",
                )
            projection = load_candidate_hunter_projection(
                repository=repository,
                pipeline_run_id=run_id,
            )
            if projection.get("status") != "ready":
                return _persisted_loop_result(
                    repository,
                    run_id,
                    campaign,
                    task,
                    stop_reason_override="invalid_stage_sequence",
                )
            audit = projection["audit"]
            return {
                "status": "awaiting_evidence",
                "pipeline_run_id": run_id,
                "campaign_id": campaign.id,
                "task_id": task.id,
                "evidence_task_id": evidence_task.id,
                "round_count": audit["round_count"],
                "stage_refs": [item["stage_id"] for item in audit["stage_refs"]],
                "state_digest": audit["state_digest"],
                "stop_reason": "awaiting_evidence",
                "final_candidates": projection["final_candidates"],
                "candidate_decisions": projection["candidate_decisions"],
                **_false_safety_fields(),
            }
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
        source_fact_refs = _string_list(candidate.get("source_fact_refs"))
        affected_code_path = _text(candidate.get("affected_code_path"))
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
            or not source_fact_refs
            or candidate.get("evidence_trace_status") != "traceable"
            or candidate.get("human_validation_readiness") != "ready"
        ):
            failures.append(f"{candidate_id}:final_candidate_evidence_invalid")
        if (
            not affected_code_path.startswith("code:")
            or affected_code_path not in source_fact_refs
        ):
            failures.append(f"{candidate_id}:final_candidate_code_path_invalid")
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
            "affected_code_path",
            "evidence_trace_status",
            "human_validation_readiness",
            "broken_invariant",
            "validation_mode",
            "evidence_needed",
            "safe_validation_plan",
            "refutation_questions",
            "impact_rationale",
            "impact_score",
            "survived_kill_score",
            "evidence_completeness_score",
            "priority_score",
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
        if not _runtime_task_execution_owns_status(task):
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
    if not _runtime_task_execution_owns_status(task):
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


def _runtime_task_execution_owns_status(task: Any) -> bool:
    payload = task.payload if isinstance(task.payload, dict) else {}
    return (
        task.task_type == "candidate_refutation"
        and payload.get("runtime_schema") == "autonomous_research_v1"
        and isinstance(task.execution_claim_id, str)
        and bool(task.execution_claim_id)
    )


def _find_candidate_hunter_owners(repository: Any, run_id: str) -> list[tuple[Any, Any]]:
    input_ref = f"pipeline_run:{run_id}"
    return [
        (campaign, task)
        for campaign in repository.list_campaigns()
        for task in repository.list_campaign_tasks(campaign.id)
        if _candidate_hunter_owner_matches(campaign, task, input_ref, run_id)
    ]


def _candidate_hunter_owner_matches(
    campaign: Any,
    task: Any,
    input_ref: str,
    run_id: str,
) -> bool:
    if task.task_type == "candidate_hunter_loop":
        return (
            input_ref in task.input_refs
            and isinstance(campaign.payload, dict)
            and campaign.payload.get("pipeline_run_id") == run_id
        )
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    return (
        task.task_type == "candidate_refutation"
        and input_ref in task.input_refs
        and task_payload.get("runtime_schema") == "autonomous_research_v1"
        and task_payload.get("pipeline_run_id") == run_id
    )


def _safe_evidence_context(value: object, *, asset: object) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    source_snapshot_digest = _bare_source_snapshot_digest(
        value.get("source_snapshot_digest")
    )
    source_manifest = value.get("source_manifest")
    saved_scope_guard = value.get("saved_scope_guard")
    if (
        len(source_snapshot_digest) != 64
        or any(character not in "0123456789abcdef" for character in source_snapshot_digest.lower())
        or not isinstance(source_manifest, list)
        or not isinstance(saved_scope_guard, dict)
        or saved_scope_guard.get("scope_status") != "in_scope"
    ):
        return None
    authorized_root = _safe_text(saved_scope_guard.get("authorized_local_root"))
    asset_path = _safe_text(asset)
    try:
        if (
            not authorized_root
            or not asset_path
            or Path(authorized_root).resolve(strict=True)
            != Path(asset_path).resolve(strict=True)
        ):
            return None
    except OSError:
        return None
    manifest: list[dict[str, str]] = []
    seen_paths: set[str] = set()
    for item in source_manifest:
        if not isinstance(item, dict):
            return None
        source_path = _safe_text(item.get("source_path")).replace("\\", "/")
        content_digest = _safe_text(item.get("content_digest"))
        if (
            not source_path
            or source_path.startswith("/")
            or ":" in source_path
            or ".." in source_path.split("/")
            or source_path in seen_paths
            or len(content_digest) != 64
            or any(character not in "0123456789abcdef" for character in content_digest.lower())
        ):
            return None
        seen_paths.add(source_path)
        manifest.append(
            {
                "source_path": source_path,
                "content_digest": content_digest.lower(),
            }
        )
    if not manifest:
        return None
    return {
        "source_snapshot_digest": source_snapshot_digest.lower(),
        "source_manifest": sorted(manifest, key=lambda item: item["source_path"]),
        "saved_scope_guard": {
            "scope_status": "in_scope",
            "authorized_local_root": authorized_root,
        },
        "inspector_tool_allowlist": ["candidate_hunter_local_evidence_inspector"],
    }


def _campaign_has_evidence_specialist(campaign: Any) -> bool:
    payload = campaign.payload if isinstance(campaign.payload, dict) else {}
    return (
        _bare_source_snapshot_digest(payload.get("source_snapshot_digest"))
        and isinstance(payload.get("source_manifest"), list)
        and isinstance(payload.get("saved_scope_guard"), dict)
        and "candidate_hunter_local_evidence_inspector"
        in payload.get("inspector_tool_allowlist", [])
        and "candidate_hunter_local_evidence_inspector"
        in getattr(campaign, "allowed_tools", [])
    )


def _bare_source_snapshot_digest(value: object) -> str:
    digest = _safe_text(value).lower()
    if digest.startswith("sha256:"):
        digest = digest.removeprefix("sha256:")
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        return ""
    return digest


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
            decision["survived_kill_score"] = _priority_score(
                item.get("survived_kill_score")
            )
        # Preserve audit falsification payloads across multi-round resume.
        if isinstance(item.get("falsification_card"), dict):
            decision["falsification_card"] = item["falsification_card"]
        if isinstance(item.get("falsification_summary"), dict):
            decision["falsification_summary"] = item["falsification_summary"]
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
    code_refs = [ref for ref in source_fact_refs if ref.startswith("code:")]
    affected_code_path = _safe_text(value.get("affected_code_path")) or (
        code_refs[0] if code_refs else ""
    )
    if (
        _safe_text(value.get("candidate_id")) != candidate_id
        or _safe_text(value.get("root_cause_id")) != root_cause_id
        or not _safe_text(value.get("vuln_type"))
        or not safe_route
        or not source_fact_refs
        or affected_code_path not in code_refs
        or value.get("evidence_trace_status") != "traceable"
        or any(value.get(field) is not False for field in SAFETY_FIELDS[:-1])
    ):
        return None
    refutation_questions = [
        safe_text
        for item in value.get("refutation_questions", [])
        if (safe_text := _safe_text(item))
    ] if isinstance(value.get("refutation_questions"), list) else []
    if not refutation_questions:
        refutation_questions = _refutation_questions({})
    safe_validation_plan = _local_validation_plan(
        route_label=f"{safe_route['method']} {safe_route['path']}",
        root_symbol="",
    )
    projection = {
        "candidate_id": candidate_id,
        "rank": _priority_score(value.get("rank")) or 1,
        "vuln_type": _safe_text(value.get("vuln_type")),
        "root_cause_id": root_cause_id,
        "route": safe_route,
        "source_fact_refs": source_fact_refs,
        "affected_code_path": affected_code_path,
        "evidence_trace_status": "traceable",
        "human_validation_readiness": "ready",
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
        "refutation_questions": refutation_questions,
        "validation_mode": _safe_validation_mode(value.get("validation_mode"))
        or "non_destructive_request_review",
        "evidence_needed": _safe_research_strings(value.get("evidence_needed")),
        "impact_rationale": _safe_text(value.get("impact_rationale")),
        "impact_score": _priority_score(value.get("impact_score")),
        "safe_validation_plan": safe_validation_plan,
        "next_allowed_action": _safe_text(value.get("next_allowed_action")),
        "safety_blockers": [
            safe_text
            for item in value.get("safety_blockers", [])
            if (safe_text := _safe_text(item))
        ] if isinstance(value.get("safety_blockers"), list) else [],
        "broken_invariant": _safe_text(value.get("broken_invariant")),
        "why_still_alive": [
            safe_text
            for item in value.get("why_still_alive", [])
            if (safe_text := _safe_text(item))
        ]
        if isinstance(value.get("why_still_alive"), list)
        else [],
    }
    if isinstance(value.get("falsification_summary"), dict):
        projection["falsification_summary"] = value["falsification_summary"]
    if isinstance(value.get("falsification_card"), dict):
        projection["falsification_card"] = value["falsification_card"]
    return projection


def _initial_states_with_safe_context(
    initial_states: list[dict],
    reanalyzed_states: list[dict],
) -> list[dict]:
    reanalyzed_by_id = {
        _text(state.get("candidate_id")): state
        for state in reanalyzed_states
        if isinstance(state, dict) and _text(state.get("candidate_id"))
    }
    states = []
    for initial in initial_states:
        if not isinstance(initial, dict):
            continue
        state = dict(initial)
        reanalyzed = reanalyzed_by_id.get(_text(initial.get("candidate_id")))
        if reanalyzed is None:
            states.append(state)
            continue
        safe_context_refs = [
            ref
            for ref in _string_list(reanalyzed.get("source_fact_refs"))
            if not ref.startswith("code:") and not ref.startswith("evidence:")
        ]
        state["source_fact_refs"] = _ordered_unique(
            [*_string_list(initial.get("source_fact_refs")), *safe_context_refs]
        )
        state["observed_artifact_kinds"] = _ordered_unique(
            [
                *_string_list(initial.get("observed_artifact_kinds")),
                *[
                    kind
                    for kind in _string_list(reanalyzed.get("observed_artifact_kinds"))
                    if kind != "code"
                ],
            ]
        )
        required = _string_list(state.get("required_artifact_kinds"))
        state["evidence_trace_status"] = (
            "traceable"
            if required and set(required).issubset(state["observed_artifact_kinds"])
            else "needs_evidence"
        )
        state["reanalysis_status"] = "pending"
        states.append(state)
    return states


def _snapshot_candidate(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    snapshot: dict[str, Any] = {}
    for field in (
        "candidate_id",
        "candidate_key",
        "vuln_type",
        "root_cause_id",
        "entrypoint_kind",
        "graphql_operation_type",
        "graphql_operation_name",
        "evidence_trace_status",
        "gap_evidence_ref",
        "control_evidence_ref",
        "public_evidence_ref",
        "shared_root",
        "shared_root_evidence_ref",
        "shared_root_kind",
        "reanalysis_status",
        "hypothesis_source_path",
        "hypothesis_symbol_name",
        "broken_invariant",
        "validation_mode",
        "impact_rationale",
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
        "evidence_needed",
    ):
        snapshot[field] = [
            safe_value
            for item in value.get(field, [])
            if (safe_value := _safe_text(item))
        ] if isinstance(value.get(field), list) else []
    snapshot_route = snapshot.get("route")
    snapshot_route_label = (
        f"{snapshot_route['method']} {snapshot_route['path']}"
        if isinstance(snapshot_route, dict)
        else "the mapped local code path"
    )
    snapshot["safe_validation_plan"] = _local_validation_plan(
        route_label=snapshot_route_label,
        root_symbol=_safe_text(value.get("hypothesis_symbol_name")),
    )
    snapshot["priority_score"] = _priority_score(value.get("priority_score"))
    snapshot["model_priority_score"] = _priority_score(
        value.get("model_priority_score")
    )
    snapshot["impact_score"] = _priority_score(value.get("impact_score"))
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
    groups: dict[tuple[str, str, str, str, str, str], list[dict]] = {}
    for state in candidate_states:
        if not _candidate_is_complete(
            state,
            pipeline_run_id,
        ) or not _text(state.get("gap_evidence_ref")):
            continue
        source_refs = _string_list(state.get("source_fact_refs"))
        if _text(state.get("control_evidence_ref")) in source_refs:
            continue
        if (
            _text(state.get("public_evidence_ref")) in source_refs
            and _public_filter_refutes_candidate(state)
        ):
            continue
        shared_root = _text(state.get("shared_root"))
        shared_ref = _text(state.get("shared_root_evidence_ref"))
        shared_root_kind = _text(state.get("shared_root_kind")) or "service"
        if (
            shared_root
            and shared_ref in source_refs
            and shared_root_kind in {"service", "direct_sink"}
        ):
            root_cause_class = _text(state.get("root_cause_id")).partition(":")[0]
            route_family = (
                _direct_sink_route_family(state)
                if shared_root_kind == "direct_sink"
                else ""
            )
            if shared_root_kind == "direct_sink" and not route_family:
                continue
            group_key = (
                _text(state.get("vuln_type")).lower(),
                root_cause_class,
                shared_root_kind,
                route_family,
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
                -_priority_score(state.get("model_priority_score")),
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


def _direct_sink_route_family(state: dict) -> str:
    route = state.get("route")
    if not isinstance(route, dict):
        return ""
    path = _text(route.get("path"))
    static_segments = []
    for segment in path.strip("/").split("/"):
        if not segment or _route_segment_is_template(segment):
            break
        static_segments.append(segment.lower())
    return "/".join(static_segments)


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
    if "code_path" in missing_evidence:
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
    has_graphql_entrypoint = (
        candidate.get("entrypoint_kind") == "graphql_operation"
        and _text(candidate.get("graphql_operation_type"))
        in {"query", "mutation", "subscription"}
        and bool(_text(candidate.get("graphql_operation_name")))
    )
    if not has_graphql_entrypoint and (
        not isinstance(route, dict)
        or not _text(route.get("method"))
        or not _text(route.get("path")).startswith("/")
    ):
        missing.append("route")
    source_fact_refs = _string_list(candidate.get("source_fact_refs"))
    if not source_fact_refs:
        missing.append("provenance")
    if not any(ref.startswith("code:") for ref in source_fact_refs):
        missing.append("code_path")
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
