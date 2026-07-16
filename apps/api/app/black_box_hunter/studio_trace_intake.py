"""Studio Playwright recording export intake for black-box dual-session hunting.

Product browser runtime stays in Studio. This module accepts only research-safe
recording exports (templated routes, aliases, no raw secrets/IDs/bodies) and
projects them into ObservedWorkflowModel for plan-only or local-lab observe.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from app.black_box_hunter import (
    ObservedTestObject,
    ObservedWorkflow,
    ObservedWorkflowModel,
    SessionAlias,
    WorkflowPathParameter,
    WorkflowStep,
    plan_differential_trials,
)
from app.black_box_hunter.har_intake import project_plan_only_candidates
from app.black_box_hunter.local_lab import LocalLabMode
from app.black_box_hunter.local_lab_pipeline import run_model_local_lab_pipeline

STUDIO_EXPORT_SCHEMA = "studio_recording_export_v1"
_FORBIDDEN_TRACE_KEYS = {
    "authorization",
    "body",
    "cookie",
    "cookies",
    "credentials",
    "headers",
    "object_id",
    "object_ids",
    "password",
    "query_values",
    "response_content",
    "token",
    "url",
}
_VALUE_TYPE_MAP = {
    "string": "string",
    "integer": "integer",
    "number": "integer",
    "uuid": "uuid",
    "ulid": "ulid",
    "slug": "slug",
    "object_alias": "string",
    "boolean": "string",
}


def build_observed_workflow_model_from_studio_export(
    export: dict[str, Any],
) -> ObservedWorkflowModel:
    """Build dual-role ObservedWorkflowModel from a Studio recording export."""
    if not isinstance(export, dict):
        raise ValueError("studio_export_object_required")

    schema = str(export.get("schema_version") or "")
    if schema and schema != STUDIO_EXPORT_SCHEMA:
        raise ValueError("studio_export_schema_unsupported")

    origin = _require_export_origin(export.get("origin"))
    traces = export.get("traces")
    if not isinstance(traces, list) or not traces:
        raise ValueError("studio_traces_required")

    role_ranks_raw = export.get("role_ranks") or {}
    if role_ranks_raw is not None and not isinstance(role_ranks_raw, dict):
        raise ValueError("studio_role_ranks_mapping_required")
    role_ranks = {
        str(key): int(value) for key, value in dict(role_ranks_raw or {}).items()
    }

    # Group safe traces by account_alias (one ObservedWorkflow per account).
    by_account: dict[str, list[dict[str, Any]]] = {}
    for index, item in enumerate(traces):
        if not isinstance(item, dict):
            raise ValueError("studio_trace_object_required")
        _reject_secret_payload(item, context=f"trace[{index}]")
        aliases = item.get("aliases")
        if not isinstance(aliases, dict):
            raise ValueError("studio_trace_aliases_required")
        _reject_secret_payload(aliases, context=f"trace[{index}].aliases")
        account_alias = str(aliases.get("account_alias") or "").strip()
        if not account_alias:
            raise ValueError("studio_trace_account_alias_required")
        by_account.setdefault(account_alias, []).append(item)

    if len(by_account) < 2:
        raise ValueError("two_account_aliases_required")

    # Default ranks: first-seen account gets higher privilege.
    default_rank = 10
    for account_alias in by_account:
        if account_alias not in role_ranks:
            role_ranks[account_alias] = default_rank
            default_rank = max(1, default_rank - 9)

    workflows: list[ObservedWorkflow] = []
    for account_alias, account_traces in sorted(by_account.items()):
        workflows.append(
            _workflow_from_account_traces(
                account_traces,
                account_alias=account_alias,
                origin=origin,
                role_rank=role_ranks[account_alias],
            )
        )

    return ObservedWorkflowModel(workflows=workflows)


def run_studio_trace_plan_only_pipeline(export: dict[str, Any]) -> dict[str, Any]:
    """Studio export -> model -> partial plans -> plan-only candidates."""
    model = build_observed_workflow_model_from_studio_export(export)
    plans = plan_differential_trials(model, require_all_classes=False)
    candidates = project_plan_only_candidates(model, plans)
    return {
        "schema_version": "studio_plan_only_pipeline_v1",
        "source": "studio_playwright",
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
        "auth_material_exported": False,
    }


def run_studio_trace_local_lab_pipeline(
    export: dict[str, Any],
    *,
    mode: LocalLabMode = "bola",
    local_lab: bool = True,
    trial_classes: set[str] | None = None,
) -> dict[str, Any]:
    """Studio export -> model -> local-lab observe -> ranked research candidates."""
    model = build_observed_workflow_model_from_studio_export(export)
    return run_model_local_lab_pipeline(
        model,
        mode=mode,
        local_lab=local_lab,
        trial_classes=trial_classes,
        schema_version="studio_local_lab_pipeline_v1",
        source="studio_playwright",
    )


def _workflow_from_account_traces(
    traces: list[dict[str, Any]],
    *,
    account_alias: str,
    origin: str,
    role_rank: int,
) -> ObservedWorkflow:
    steps: list[WorkflowStep] = []
    objects_by_alias: dict[str, ObservedTestObject] = {}
    role_alias = "member"
    workflow_alias = f"studio_{account_alias}"
    step_index = 0

    for item in traces:
        aliases = item["aliases"]
        role_alias = str(aliases.get("role_alias") or role_alias).strip() or role_alias
        wf_alias = str(aliases.get("workflow_alias") or "").strip()
        if wf_alias:
            workflow_alias = wf_alias

        method = str(item.get("method") or "").upper()
        route_template = str(item.get("route_template") or "")
        if not method or not route_template:
            continue
        action = _action_for_method(method)
        if action is None:
            continue

        path_parameters = _path_parameters_from_trace(item, route_template)
        step_index += 1
        steps.append(
            WorkflowStep(
                workflow_index=step_index,
                origin=origin,
                route_template=route_template,
                path_parameters=path_parameters,
                method=method,
                action=action,
                state="active",
            )
        )

        object_aliases = aliases.get("object_aliases") or []
        if not isinstance(object_aliases, list):
            raise ValueError("studio_object_aliases_list_required")
        for raw_alias in object_aliases:
            alias = str(raw_alias or "").strip()
            if not alias:
                continue
            if alias not in objects_by_alias:
                objects_by_alias[alias] = ObservedTestObject(
                    alias=alias,
                    owner_alias=account_alias,
                    state="active",
                    reversible=True,
                    provenance="demonstrated_normal_flow",
                )

    if not steps:
        raise ValueError("studio_plannable_steps_required")
    if not any(step.action == "read_only_replay" for step in steps):
        raise ValueError("studio_read_only_step_required")
    if not objects_by_alias:
        raise ValueError("studio_object_aliases_required")

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


def _path_parameters_from_trace(
    trace: dict[str, Any],
    route_template: str,
) -> list[WorkflowPathParameter]:
    """Derive path parameter metadata; Studio traces already use {object}."""
    declared: list[dict[str, Any]] = []
    parameters = trace.get("parameters") or []
    if isinstance(parameters, list):
        for item in parameters:
            if not isinstance(item, dict):
                continue
            if str(item.get("location") or "") != "path":
                continue
            declared.append(item)

    segments = [segment for segment in route_template.split("/") if segment]
    params: list[WorkflowPathParameter] = []
    declared_index = 0
    for segment_index, segment in enumerate(segments, start=1):
        if segment != "{object}" and not (
            segment.startswith("{") and segment.endswith("}")
        ):
            continue
        name = "object"
        value_type = "string"
        if declared_index < len(declared):
            meta = declared[declared_index]
            declared_index += 1
            raw_name = str(meta.get("name") or "object").strip() or "object"
            name = raw_name
            value_type = _map_value_type(meta.get("value_type"))
        params.append(
            WorkflowPathParameter(
                name=name,
                segment=segment_index,
                type=value_type,
            )
        )
    return params


def _map_value_type(value: object) -> str:
    key = str(value or "string").lower()
    return _VALUE_TYPE_MAP.get(key, "string")


def _action_for_method(method: str) -> str | None:
    if method in {"GET", "HEAD"}:
        return "read_only_replay"
    if method == "POST":
        return "test_object_create"
    if method in {"PUT", "PATCH"}:
        return "reversible_update"
    return None


def _require_export_origin(value: object) -> str:
    origin = str(value or "").strip()
    if not origin:
        raise ValueError("studio_export_origin_required")
    parsed = urlsplit(origin)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise ValueError("studio_export_exact_origin_required")
    # Normalize trailing slash away for exact origin form.
    return f"{parsed.scheme}://{parsed.netloc}"


def _reject_secret_payload(payload: dict[str, Any], *, context: str) -> None:
    for key in payload:
        lower = str(key).lower()
        if lower in _FORBIDDEN_TRACE_KEYS or any(
            token in lower
            for token in (
                "authorization",
                "cookie",
                "header",
                "password",
                "secret",
                "token",
                "body",
                "object_id",
            )
        ):
            raise ValueError(f"studio_export_secret_key_forbidden:{context}:{key}")
