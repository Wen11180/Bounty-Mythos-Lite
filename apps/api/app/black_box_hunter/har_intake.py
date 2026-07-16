"""HAR intake for black-box plan-only differential hunting.

Builds ObservedWorkflowModel from role-tagged HAR documents without live
requests. Secrets are stripped before any research projection is produced.
"""

from __future__ import annotations

from hashlib import sha256
from typing import Any, Literal
from urllib.parse import urlsplit

from app.black_box_hunter import (
    ObservedTestObject,
    ObservedWorkflow,
    ObservedWorkflowModel,
    SessionAlias,
    WorkflowPathParameter,
    WorkflowStep,
    plan_differential_trials,
    _HEX_ID_SEGMENT,
    _NUMERIC_ID_SEGMENT,
    _ULID_SEGMENT,
    _UUID_SEGMENT,
    _has_secret_marker,
)

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-session-token",
}

SENSITIVE_QUERY_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "cookie",
    "password",
    "secret",
    "session",
    "token",
}


def redact_har_document(har: dict[str, Any]) -> dict[str, Any]:
    """Return a research-safe HAR copy with auth material removed."""
    if not isinstance(har, dict):
        raise ValueError("har_object_required")
    log = har.get("log")
    if not isinstance(log, dict):
        return {"log": {"entries": []}}
    entries_in = log.get("entries")
    if not isinstance(entries_in, list):
        return {"log": {"entries": []}}

    entries_out: list[dict[str, Any]] = []
    for entry in entries_in:
        if not isinstance(entry, dict):
            continue
        request = entry.get("request")
        if not isinstance(request, dict):
            continue
        method = str(request.get("method") or "").upper()
        url = str(request.get("url") or "")
        if not method or not url:
            continue
        safe_url = _redact_url(url)
        redacted_request = {
            "method": method,
            "url": safe_url,
            "headers": _redact_headers(request.get("headers")),
            "queryString": _redact_query_items(request.get("queryString")),
        }
        response = entry.get("response")
        redacted_response: dict[str, Any] | None = None
        if isinstance(response, dict):
            status = response.get("status")
            redacted_response = {
                "status": int(status) if isinstance(status, int) else 0,
                "headers": _redact_headers(response.get("headers")),
                # Never keep response bodies from HAR in research plane.
                "content": {"mimeType": _safe_mime(response.get("content")), "text": ""},
            }
        entries_out.append(
            {
                "request": redacted_request,
                **({"response": redacted_response} if redacted_response else {}),
            }
        )
    return {"log": {"entries": entries_out, "version": str(log.get("version") or "1.2")}}


def build_observed_workflow_model_from_role_hars(
    role_hars: dict[str, dict[str, Any]],
    *,
    role_ranks: dict[str, int] | None = None,
    role_aliases: dict[str, str] | None = None,
    account_aliases: dict[str, str] | None = None,
) -> ObservedWorkflowModel:
    """Build a dual-role ObservedWorkflowModel from role-keyed HAR docs.

    ``role_hars`` keys are stable role labels such as ``role_a`` / ``role_b``.
    Concrete object IDs are aliased; auth headers never enter the model.
    """
    if len(role_hars) < 2:
        raise ValueError("two_role_hars_required")

    ranks = role_ranks or {}
    roles = role_aliases or {}
    accounts = account_aliases or {}
    workflows: list[ObservedWorkflow] = []

    # Shared alias map: raw id -> alias, first-seen owner wins for identity
    # of the raw value, but objects are still attributed per workflow owner.
    global_id_aliases: dict[str, str] = {}

    for index, (role_key, har) in enumerate(sorted(role_hars.items())):
        account_alias = accounts.get(role_key) or f"account_{role_key}"
        role_alias = roles.get(role_key) or role_key
        role_rank = ranks.get(role_key)
        if role_rank is None:
            # Higher rank first in sort order of keys gets higher default rank.
            role_rank = 10 - index
        redacted = redact_har_document(har)
        workflow = _workflow_from_redacted_har(
            redacted,
            account_alias=account_alias,
            role_alias=role_alias,
            role_rank=role_rank,
            workflow_alias=f"har_{role_key}",
            global_id_aliases=global_id_aliases,
        )
        workflows.append(workflow)

    if len({workflow.session.account_alias for workflow in workflows}) < 2:
        raise ValueError("two_account_aliases_required")

    return ObservedWorkflowModel(workflows=workflows)


def project_plan_only_candidates(
    model: ObservedWorkflowModel,
    plans: list[Any],
) -> list[dict[str, Any]]:
    """Project differential plans into submission-blocked research cards."""
    cards: list[dict[str, Any]] = []
    for rank, plan in enumerate(plans, start=1):
        trial = plan.trial
        route = trial.workflow.route_template
        method = trial.workflow.method
        trial_class = plan.trial_class
        cards.append(
            {
                "schema_version": "bb_candidate_v1",
                "candidate_id": f"bbc_plan_{trial_class}",
                "rank": rank,
                "family": trial_class,
                "title": (
                    f"{trial.session.account_alias} may access "
                    f"{trial.test_object.owner_alias}-owned object via "
                    f"{method} {route}"
                ),
                "affected_endpoint": f"{method} {route}",
                "broken_invariant": _invariant_for_class(trial_class),
                "plan_trial_class": trial_class,
                "workflow_aliases": [
                    workflow.workflow_alias for workflow in model.workflows
                ],
                "object_aliases": [
                    trial.test_object.alias,
                ],
                "why_alive": [
                    "supported_by_har_derived_workflow_model",
                    "single_variable_differential_plan_available",
                ],
                "why_dead_or_weak": [],
                "evidence_gaps": [
                    "lease_bound_or_local_lab_observation_required",
                    "negative_controls_not_executed",
                    "stability_not_proven",
                ],
                "safe_validation_plan": [
                    "Review the plan-only differential offline.",
                    "If authorized, run only on operator-owned test objects.",
                    "Do not touch real user data or submit a report automatically.",
                ],
                "decision": "needs_evidence",
                "execution_allowed": False,
                "dispatch_allowed": False,
                "validation_allowed": False,
                "candidate_promotion_allowed": False,
                "report_submission_allowed": False,
                "mode": "plan_only",
            }
        )
    return cards


def run_har_plan_only_pipeline(
    role_hars: dict[str, dict[str, Any]],
    *,
    role_ranks: dict[str, int] | None = None,
    role_aliases: dict[str, str] | None = None,
    account_aliases: dict[str, str] | None = None,
) -> dict[str, Any]:
    """End-to-end HAR -> model -> partial plans -> plan-only candidates."""
    model = build_observed_workflow_model_from_role_hars(
        role_hars,
        role_ranks=role_ranks,
        role_aliases=role_aliases,
        account_aliases=account_aliases,
    )
    plans = plan_differential_trials(model, require_all_classes=False)
    candidates = project_plan_only_candidates(model, plans)
    return {
        "schema_version": "har_plan_only_pipeline_v1",
        "workflow_model": model.safe_projection(),
        "plan_count": len(plans),
        "plan_classes": [plan.trial_class for plan in plans],
        "candidates": candidates,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
        "mode": "plan_only",
        "raw_secrets_persisted": False,
    }


def _workflow_from_redacted_har(
    har: dict[str, Any],
    *,
    account_alias: str,
    role_alias: str,
    role_rank: int,
    workflow_alias: str,
    global_id_aliases: dict[str, str],
) -> ObservedWorkflow:
    entries = har.get("log", {}).get("entries", [])
    if not isinstance(entries, list) or not entries:
        raise ValueError("har_entries_required")

    steps: list[WorkflowStep] = []
    objects_by_alias: dict[str, ObservedTestObject] = {}
    origin: str | None = None
    step_index = 0

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        request = entry.get("request")
        if not isinstance(request, dict):
            continue
        method = str(request.get("method") or "").upper()
        url = str(request.get("url") or "")
        if not method or not url:
            continue
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            continue
        entry_origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin is None:
            origin = entry_origin
        elif entry_origin != origin:
            # Multi-origin HARs are ignored for non-primary origins in V1a.
            continue

        path = parsed.path or "/"
        template, path_params, raw_ids = _path_to_template(path)
        action = _action_for_method(method)
        if action is None:
            continue

        step_index += 1
        steps.append(
            WorkflowStep(
                workflow_index=step_index,
                origin=origin,
                route_template=template,
                path_parameters=path_params,
                method=method,
                action=action,
                state="active",
            )
        )

        # raw_ids is ordered path id appearance. Nested resources use
        # first id as parent and second as child with parent_alias bound.
        parent_raw: str | None = None
        for index, raw_id in enumerate(raw_ids):
            alias = global_id_aliases.get(raw_id)
            if alias is None:
                alias = _alias_for_raw_id(raw_id, account_alias)
                global_id_aliases[raw_id] = alias
            parent_alias = None
            if index == 0:
                parent_raw = raw_id
            elif index == 1 and parent_raw is not None:
                parent_alias = global_id_aliases.get(parent_raw)
            existing = objects_by_alias.get(alias)
            if existing is None:
                objects_by_alias[alias] = ObservedTestObject(
                    alias=alias,
                    owner_alias=account_alias,
                    parent_alias=parent_alias,
                    state="active",
                    reversible=True,
                    provenance="demonstrated_normal_flow",
                )
            elif (
                existing.parent_alias is None
                and parent_alias is not None
                and parent_alias != existing.alias
            ):
                objects_by_alias[alias] = existing.model_copy(
                    update={"parent_alias": parent_alias}
                )

    if not steps:
        raise ValueError("har_plannable_steps_required")
    if not objects_by_alias:
        # Synthesize a placeholder object only when a read/create exists without
        # path ids (e.g. collection POST). Still require at least one object.
        synthetic_alias = _alias_for_raw_id(f"synthetic:{account_alias}", account_alias)
        objects_by_alias[synthetic_alias] = ObservedTestObject(
            alias=synthetic_alias,
            owner_alias=account_alias,
            state="active",
            reversible=True,
            provenance="demonstrated_normal_flow",
        )

    # Prefer a read_only step; planner needs it for cross-account plans.
    if not any(step.action == "read_only_replay" for step in steps):
        raise ValueError("har_read_only_step_required")

    return ObservedWorkflow(
        workflow_alias=workflow_alias,
        session=SessionAlias(
            account_alias=account_alias,
            role_alias=role_alias,
            active=True,
        ),
        steps=steps,
        objects=list(objects_by_alias.values()),
        role_rank=role_rank,
        baseline_stable=True,
        rollback_ready=True,
    )


def _path_to_template(path: str) -> tuple[str, list[WorkflowPathParameter], list[str]]:
    if not path.startswith("/"):
        path = f"/{path}"
    # Drop query-like accidents and normalize trailing junk.
    path = path.split("?", 1)[0]
    segments = path.split("/")
    non_empty_index = 0
    out_segments: list[str] = []
    params: list[WorkflowPathParameter] = []
    raw_ids: list[str] = []

    for segment in segments:
        if segment == "":
            out_segments.append(segment)
            continue
        non_empty_index += 1
        if _is_concrete_id_segment(segment):
            raw_ids.append(segment)
            out_segments.append("{object}")
            params.append(
                WorkflowPathParameter(
                    name="object",
                    segment=non_empty_index,
                    type="string",
                )
            )
        else:
            # Keep static segments; reject control chars via WorkflowStep later.
            if _has_secret_marker(segment):
                raise ValueError("secret_like_path_segment")
            out_segments.append(segment)

    template = "/".join(out_segments) or "/"
    # Nested resources: freeze earlier IDs as opaque static segments; last ID
    # becomes {object}. Keep full raw_ids so parent_alias binding still works.
    if len(params) > 1:
        nested_segments: list[str] = []
        nested_params: list[WorkflowPathParameter] = []
        non_empty_index = 0
        id_count = 0
        total_ids = len(raw_ids)
        for segment in segments:
            if segment == "":
                nested_segments.append(segment)
                continue
            non_empty_index += 1
            if _is_concrete_id_segment(segment):
                id_count += 1
                if id_count < total_ids:
                    nested_segments.append(
                        f"id_{sha256(segment.encode()).hexdigest()[:8]}"
                    )
                else:
                    nested_segments.append("{object}")
                    nested_params.append(
                        WorkflowPathParameter(
                            name="object",
                            segment=non_empty_index,
                            type="string",
                        )
                    )
            else:
                nested_segments.append(segment)
        template = "/".join(nested_segments) or "/"
        params = nested_params
        # raw_ids intentionally unchanged (ordered parent -> child ids)

    return template, params, raw_ids


def _is_concrete_id_segment(segment: str) -> bool:
    return bool(
        _NUMERIC_ID_SEGMENT.fullmatch(segment)
        or _UUID_SEGMENT.fullmatch(segment)
        or _ULID_SEGMENT.fullmatch(segment)
        or _HEX_ID_SEGMENT.fullmatch(segment)
    )


def _action_for_method(method: str) -> str | None:
    if method in {"GET", "HEAD"}:
        return "read_only_replay"
    if method == "POST":
        return "test_object_create"
    if method in {"PUT", "PATCH"}:
        return "reversible_update"
    return None


def _alias_for_raw_id(raw_id: str, owner_alias: str) -> str:
    digest = sha256(f"{owner_alias}:{raw_id}".encode("utf-8")).hexdigest()[:12]
    return f"obj_{digest}"


def _redact_headers(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    out: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        if not name:
            continue
        if name.lower() in SENSITIVE_HEADER_NAMES or _has_secret_marker(name):
            out.append({"name": name, "value": "[REDACTED]"})
            continue
        raw_value = str(item.get("value") or "")
        if _has_secret_marker(raw_value):
            out.append({"name": name, "value": "[REDACTED]"})
            continue
        out.append({"name": name, "value": raw_value[:200]})
    return out


def _redact_query_items(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    out: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        if not name:
            continue
        if name.lower() in SENSITIVE_QUERY_KEYS or _has_secret_marker(name):
            out.append({"name": name, "value": "[REDACTED]"})
            continue
        raw_value = str(item.get("value") or "")
        if _has_secret_marker(raw_value):
            out.append({"name": name, "value": "[REDACTED]"})
            continue
        out.append({"name": name, "value": raw_value[:200]})
    return out


def _redact_url(url: str) -> str:
    parsed = urlsplit(url)
    # Drop query string entirely from research URL projection.
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"


def _safe_mime(content: object) -> str:
    if isinstance(content, dict):
        mime = content.get("mimeType")
        if isinstance(mime, str) and mime and not _has_secret_marker(mime):
            return mime[:128]
    return "application/octet-stream"


def _invariant_for_class(trial_class: str) -> str:
    mapping = {
        "cross_account_object_swap": (
            "Only the owning account may read an object by identifier"
        ),
        "lower_role_replay": (
            "A lower-privileged role must not access higher-privilege object reads"
        ),
        "unauthenticated_read_only_replay": (
            "Unauthenticated callers must not read authenticated object resources"
        ),
        "owned_parent_child_swap": (
            "Child objects remain bound to their demonstrated parent ownership"
        ),
        "reversible_out_of_order_state_transition": (
            "State transitions must respect demonstrated ownership and order"
        ),
    }
    return mapping.get(trial_class, "Authorization boundary must hold under single-variable swap")
