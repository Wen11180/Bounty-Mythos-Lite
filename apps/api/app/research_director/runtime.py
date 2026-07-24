"""Campaign-bound local execution for the research director.

This module is the Level 1 automation-plane boundary. It can dispatch only
registered offline static-analysis adapters against a verified local snapshot.
Remote tools, finding promotion, and report submission stay outside this path.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
import re
from typing import Any, Callable

from app.db_models import (
    ApprovalRecord,
    CampaignRecord,
    CampaignTaskRecord,
    PipelineStageRecord,
)
from app.execution_registry import ExecutionAuthorizationRequest
from app.execution_registry.local_runner import (
    RegisteredLocalToolRun,
    RegisteredLocalToolRunRequest,
    local_tool_advisory_artifact_data,
    run_registered_local_tool,
)
from app.program_rule_intake.scope_resolver import (
    intersect_scope_guard_rules,
    resolve_effective_program_rule,
)
from app.repository import DatabaseRepository, approval_record_is_active
from app.scope_guard import ScopeGuardRule
from app.studio_workspace import load_authorized_campaign_inputs

from . import (
    ResearchDirectorContext,
    ResearchDirectorPlan,
    ResearchSignal,
    build_research_director_plan,
)


LOCAL_TOOL_TASK_TYPE = "research_director_local_tool_run"
LOCAL_TOOL_TASK_SCHEMA = "research_director_local_tool_run_v1"
LOCAL_TOOL_APPROVAL_TYPE = "research_director_local_tool"
LOCAL_TOOL_FAILURE_STAGE_KEY = "research_director_local_tool_failure"
LOCAL_TOOL_FAILURE_STAGE_ORDER = 100
_LOCAL_TOOL_LEASE_EXPIRED_STOP_REASON = "execution_lease_expired"
_SOURCE_SNAPSHOT_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_PLAN_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_LOCAL_TOOL_IDS = {"semgrep_local", "codeql_local", "dependency_sbom_local"}
_LOCAL_TOOL_APPROVAL_SCHEMA = "research_director_local_tool_approval_v1"
_LOCAL_TOOL_VALIDATION_MODE = "static_analyzer"
_SAFETY_FIELDS = {
    "execution_allowed": False,
    "dispatch_allowed": False,
    "validation_allowed": False,
    "candidate_promotion_allowed": False,
    "report_submission_allowed": False,
    "raw_payload_processed": False,
}


def tick_campaign_local_execution(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    dispatcher: Callable[..., Any],
    workspace_loader: Callable[[object], dict[str, Any]] | None = None,
    now: datetime | None = None,
) -> dict[str, Any] | None:
    """Plan and dispatch at most one lease-bound local static-analysis task.

    Returning ``None`` means the regular read-only research runtime may proceed.
    It is intentionally not a remote execution path.
    """
    if (
        campaign.autonomy_level != "level_1_local_validation"
        or campaign.status != "running"
    ):
        return None
    campaign_payload = _campaign_payload(campaign)
    source_snapshot_digest = campaign_payload.get("source_snapshot_digest")
    if _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(_text(source_snapshot_digest)) is None:
        return None

    lease_recovery = _recover_expired_local_tool_task(
        campaign=campaign,
        source_snapshot_digest=source_snapshot_digest,
        repository=repository,
        now=now,
    )
    if lease_recovery is not None:
        return lease_recovery

    pending = _pending_local_tool_task(
        campaign=campaign,
        source_snapshot_digest=source_snapshot_digest,
        repository=repository,
    )
    if pending is not None:
        return _result(
            status="awaiting_evidence",
            campaign_task_id=pending.id,
            stop_reason="active_local_tool_task",
            source_snapshot_digest=source_snapshot_digest,
        )
    if _has_active_read_only_runtime_task(campaign=campaign, repository=repository):
        return None

    rule, rule_reason = current_campaign_scope_guard_rule(
        repository=repository,
        campaign=campaign,
        asset=campaign.default_asset,
    )
    if rule is None or rule_reason is not None:
        return None
    try:
        context = build_campaign_research_director_context(
            campaign=campaign,
            rule=rule,
            repository=repository,
        )
    except ValueError:
        return None
    plan = build_research_director_plan(context)
    record_campaign_research_director_plan(
        campaign=campaign,
        plan=plan,
        repository=repository,
    )
    if (
        plan.action_kind != "local_tool"
        or plan.action_id not in _LOCAL_TOOL_IDS
    ):
        return None

    resolved_workspace_loader = workspace_loader or load_authorized_campaign_inputs
    try:
        workspace_inputs = resolved_workspace_loader(
            campaign_payload.get("workspace_snapshot")
        )
    except (FileNotFoundError, ValueError):
        return _result(
            status="blocked",
            campaign_task_id=None,
            stop_reason="workspace_snapshot_invalid",
            source_snapshot_digest=source_snapshot_digest,
        )
    if (
        workspace_inputs.get("source_snapshot_digest") != source_snapshot_digest
        or not isinstance(workspace_inputs.get("authorized_local_root"), str)
        or not Path(workspace_inputs["authorized_local_root"]).is_dir()
        or (
            plan.action_id == "dependency_sbom_local"
            and not isinstance(workspace_inputs.get("dependency_input_manifest"), list)
        )
    ):
        return _result(
            status="blocked",
            campaign_task_id=None,
            stop_reason="source_snapshot_changed",
            source_snapshot_digest=source_snapshot_digest,
        )

    task, _claimed = claim_campaign_local_tool_task(
        campaign=campaign,
        plan=plan,
        repository=repository,
    )
    if task.status in {"dispatched", "running"}:
        return _result(
            status="awaiting_evidence",
            campaign_task_id=task.id,
            stop_reason="active_local_tool_task",
            source_snapshot_digest=source_snapshot_digest,
        )
    if task.status not in {"queued", "ready", "awaiting_approval"}:
        return None
    approval = ensure_campaign_local_tool_approval(
        campaign=campaign,
        task=task,
        source_snapshot_digest=source_snapshot_digest,
        tool_id=plan.action_id,
        plan_digest=plan.plan_digest,
        repository=repository,
    )
    if not campaign_local_tool_approval_is_active(approval):
        if task.status in {"queued", "ready"}:
            task = (
                repository.transition_campaign_task_status_if_currently(
                    task.id,
                    "awaiting_approval",
                    allowed_current_statuses={"queued", "ready"},
                    require_unclaimed_execution=True,
                )
                or task
            )
        return _result(
            status="awaiting_approval",
            campaign_task_id=task.id,
            stop_reason="human_approval_required",
            source_snapshot_digest=source_snapshot_digest,
        )
    return _dispatch_campaign_local_tool_task(
        campaign=campaign,
        task=task,
        source_snapshot_digest=source_snapshot_digest,
        repository=repository,
        dispatcher=dispatcher,
        now=now,
    )


def run_campaign_local_tool_task(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
    workspace_loader: Callable[[object], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Execute one already-leased registered local tool task in a Worker."""
    payload = task.payload if isinstance(task.payload, dict) else {}
    campaign = repository.get_campaign(task.campaign_id)
    if (
        task.task_type != LOCAL_TOOL_TASK_TYPE
        or payload.get("schema_version") != LOCAL_TOOL_TASK_SCHEMA
        or payload.get("execution_lease_required") is not True
        or task.status != "running"
        or not task.execution_claim_id
        or campaign is None
    ):
        return _finish_local_task(
            task=task,
            repository=repository,
            task_status="blocked",
            agent_status="blocked",
            safety_gate_state="blocked",
            stop_reason="local_tool_task_invalid",
            output_refs=[],
            payload=_task_result_payload(task=task, result=None),
        )
    if (
        campaign.autonomy_level != "level_1_local_validation"
        or campaign.status != "running"
        or campaign.scope_status != "in_scope"
    ):
        return _finish_local_task(
            task=task,
            repository=repository,
            task_status="blocked",
            agent_status="blocked",
            safety_gate_state="blocked",
            stop_reason="local_execution_autonomy_required",
            output_refs=[],
            payload=_task_result_payload(task=task, result=None),
        )

    source_snapshot_digest = _text(payload.get("source_snapshot_digest"))
    plan_id = _text(payload.get("research_plan_id"))
    plan_digest = _text(payload.get("research_plan_digest"))
    tool_id = _text(payload.get("tool_id"))
    campaign_payload = _campaign_payload(campaign)
    plan_stage = current_campaign_local_tool_plan(
        campaign=campaign,
        tool_id=tool_id,
        plan_id=plan_id,
        plan_digest=plan_digest,
        repository=repository,
    )
    if (
        _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None
        or _PLAN_DIGEST_PATTERN.fullmatch(plan_digest) is None
        or tool_id not in _LOCAL_TOOL_IDS
        or source_snapshot_digest != campaign_payload.get("source_snapshot_digest")
        or plan_stage is None
    ):
        return _finish_local_task(
            task=task,
            repository=repository,
            task_status="blocked",
            agent_status="blocked",
            safety_gate_state="blocked",
            stop_reason="research_director_plan_not_current",
            output_refs=[],
            payload=_task_result_payload(task=task, result=None),
        )

    approval = ensure_campaign_local_tool_approval(
        campaign=campaign,
        task=task,
        source_snapshot_digest=source_snapshot_digest,
        tool_id=tool_id,
        plan_digest=plan_digest,
        repository=repository,
    )
    if not campaign_local_tool_approval_is_active(approval):
        return _finish_local_task(
            task=task,
            repository=repository,
            task_status="blocked",
            agent_status="blocked",
            safety_gate_state="blocked",
            stop_reason="human_approval_required",
            output_refs=[],
            payload=_task_result_payload(task=task, result=None),
        )

    remaining = campaign_remaining_tool_calls(
        campaign=campaign,
        repository=repository,
    )
    if remaining is not None and remaining <= 0:
        return _finish_local_task(
            task=task,
            repository=repository,
            task_status="blocked",
            agent_status="blocked",
            safety_gate_state="blocked",
            stop_reason="budget_exhausted",
            output_refs=[],
            payload=_task_result_payload(task=task, result=None),
        )
    rule, rule_reason = current_campaign_scope_guard_rule(
        repository=repository,
        campaign=campaign,
        asset=campaign.default_asset,
    )
    if rule is None or rule_reason is not None:
        return _finish_local_task(
            task=task,
            repository=repository,
            task_status="blocked",
            agent_status="blocked",
            safety_gate_state="blocked",
            stop_reason=rule_reason or "scope_guard_rule_missing",
            output_refs=[],
            payload=_task_result_payload(task=task, result=None),
        )
    resolved_workspace_loader = workspace_loader or load_authorized_campaign_inputs
    try:
        workspace_inputs = resolved_workspace_loader(
            campaign_payload.get("workspace_snapshot")
        )
    except (FileNotFoundError, ValueError):
        return _finish_local_task(
            task=task,
            repository=repository,
            task_status="blocked",
            agent_status="blocked",
            safety_gate_state="blocked",
            stop_reason="workspace_snapshot_invalid",
            output_refs=[],
            payload=_task_result_payload(task=task, result=None),
        )
    package_root = workspace_inputs.get("authorized_local_root")
    dependency_input_manifest = workspace_inputs.get("dependency_input_manifest")
    if (
        workspace_inputs.get("source_snapshot_digest") != source_snapshot_digest
        or not isinstance(package_root, str)
        or not Path(package_root).is_dir()
        or (
            tool_id == "dependency_sbom_local"
            and not isinstance(dependency_input_manifest, list)
        )
    ):
        return _finish_local_task(
            task=task,
            repository=repository,
            task_status="blocked",
            agent_status="blocked",
            safety_gate_state="blocked",
            stop_reason="source_snapshot_changed",
            output_refs=[],
            payload=_task_result_payload(task=task, result=None),
        )

    renewed_task = _renew_local_tool_task_lease(task=task, repository=repository)
    if renewed_task is None:
        return _lease_lost_result(task.id)
    task = renewed_task
    reservation = repository.reserve_campaign_local_tool_call(
        campaign_id=campaign.id,
        task_id=task.id,
        execution_claim_id=task.execution_claim_id,
        research_plan_id=plan_id,
        research_plan_digest=plan_digest,
        source_snapshot_digest=source_snapshot_digest,
        tool_id=tool_id,
    )
    if reservation is None:
        remaining = campaign_remaining_tool_calls(
            campaign=campaign,
            repository=repository,
        )
        if remaining is not None and remaining <= 0:
            return _finish_local_task(
                task=task,
                repository=repository,
                task_status="blocked",
                agent_status="blocked",
                safety_gate_state="blocked",
                stop_reason="budget_exhausted",
                output_refs=[],
                payload=_task_result_payload(task=task, result=None),
                renew_lease=False,
            )
        return _lease_lost_result(task.id)
    try:
        result = run_registered_local_tool(
            RegisteredLocalToolRunRequest(
                authorization=ExecutionAuthorizationRequest(
                    tool_id=tool_id,
                    asset=campaign.default_asset,
                    campaign_allowed_tools=campaign.allowed_tools,
                    scope_rule=rule,
                    human_approved=campaign_local_tool_approval_is_active(approval),
                ),
                package_root=package_root,
                package_id=campaign.id,
                dependency_input_manifest=dependency_input_manifest,
            )
        )
    except Exception:
        return _finish_local_task(
            task=task,
            repository=repository,
            task_status="failed",
            agent_status="failed",
            safety_gate_state="allowed",
            stop_reason="local_tool_runtime_failed",
            output_refs=[],
            payload=_task_result_payload(task=task, result=None),
        )

    renewed_task = _renew_local_tool_task_lease(task=task, repository=repository)
    if renewed_task is None:
        return _lease_lost_result(task.id)
    task = renewed_task
    advisory_artifact_id = _save_advisory_artifact(
        campaign=campaign,
        source_snapshot_digest=source_snapshot_digest,
        plan_digest=plan_digest,
        result=result,
        repository=repository,
        commit=False,
    )
    scanner_run_id = _save_scanner_run(
        campaign=campaign,
        source_snapshot_digest=source_snapshot_digest,
        plan_id=plan_id,
        plan_digest=plan_digest,
        result=result,
        advisory_artifact_id=advisory_artifact_id,
        reservation_agent_run_id=reservation.id,
        repository=repository,
        commit=False,
    )
    run_stage = _record_local_tool_run_stage(
        campaign=campaign,
        task=task,
        plan_stage=plan_stage,
        result=result,
        scanner_run_id=scanner_run_id,
        advisory_artifact_id=advisory_artifact_id,
        repository=repository,
        commit=False,
    )
    execution_status = (
        "blocked"
        if result.status == "blocked"
        else "failed"
        if result.status == "failed"
        else "completed"
    )
    stop_reason = result.authorization.reason if result.status == "blocked" else None
    output_refs = [
        f"research_plan:{plan_id}",
        f"pipeline_stage:{run_stage.id}",
        *([f"scanner_run:{scanner_run_id}"] if scanner_run_id else []),
        *([f"artifact:{advisory_artifact_id}"] if advisory_artifact_id else []),
    ]
    return _finish_local_task(
        task=task,
        repository=repository,
        task_status=execution_status,
        agent_status=execution_status,
        safety_gate_state=("blocked" if result.status == "blocked" else "allowed"),
        stop_reason=stop_reason,
        output_refs=output_refs,
        payload=_task_result_payload(task=task, result=result),
        renew_lease=False,
    )


def retry_campaign_local_tool_task(
    campaign_id: str,
    task_id: str,
    *,
    repository: DatabaseRepository,
    dispatcher: Callable[..., Any],
    workspace_loader: Callable[[object], dict[str, Any]] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Explicitly re-dispatch one expired local tool task after human review."""
    campaign = repository.get_campaign(campaign_id)
    if campaign is None:
        return _result(
            status="not_found",
            campaign_task_id=None,
            stop_reason="campaign_not_found",
            source_snapshot_digest="",
        )
    task = repository.session.get(CampaignTaskRecord, task_id)
    if task is None or task.campaign_id != campaign.id:
        return _result(
            status="not_found",
            campaign_task_id=None,
            stop_reason="campaign_task_not_found",
            source_snapshot_digest="",
        )
    payload = task.payload if isinstance(task.payload, dict) else {}
    source_snapshot_digest = _text(payload.get("source_snapshot_digest"))
    expired_agent_run_id = _expired_local_tool_agent_run_id(
        task=task,
        repository=repository,
    )
    if (
        not _local_tool_task_matches_snapshot(
            task=task,
            source_snapshot_digest=source_snapshot_digest,
        )
        or task.status != "failed"
        or expired_agent_run_id is None
    ):
        return _result(
            status="awaiting_review",
            campaign_task_id=task.id,
            stop_reason="human_review_required",
            source_snapshot_digest=source_snapshot_digest,
        )
    _record_local_tool_lease_expiry(
        campaign=campaign,
        task=task,
        source_snapshot_digest=source_snapshot_digest,
        expired_agent_run_id=expired_agent_run_id,
        repository=repository,
    )
    if repository.campaign_task_has_local_tool_call_reservation(task.id):
        return _result(
            status="awaiting_review",
            campaign_task_id=task.id,
            stop_reason="local_tool_execution_outcome_unknown",
            source_snapshot_digest=source_snapshot_digest,
        )
    if (
        campaign.autonomy_level != "level_1_local_validation"
        or campaign.scope_status != "in_scope"
        or source_snapshot_digest != _campaign_payload(campaign).get("source_snapshot_digest")
    ):
        return _result(
            status="blocked",
            campaign_task_id=task.id,
            stop_reason="local_execution_autonomy_required",
            source_snapshot_digest=source_snapshot_digest,
        )

    plan_id = _text(payload.get("research_plan_id"))
    plan_digest = _text(payload.get("research_plan_digest"))
    tool_id = _text(payload.get("tool_id"))
    plan_stage = current_campaign_local_tool_plan(
        campaign=campaign,
        tool_id=tool_id,
        plan_id=plan_id,
        plan_digest=plan_digest,
        repository=repository,
    )
    if (
        _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None
        or _PLAN_DIGEST_PATTERN.fullmatch(plan_digest) is None
        or tool_id not in _LOCAL_TOOL_IDS
        or plan_stage is None
    ):
        return _result(
            status="blocked",
            campaign_task_id=task.id,
            stop_reason="research_director_plan_not_current",
            source_snapshot_digest=source_snapshot_digest,
        )
    approval = ensure_campaign_local_tool_approval(
        campaign=campaign,
        task=task,
        source_snapshot_digest=source_snapshot_digest,
        tool_id=tool_id,
        plan_digest=plan_digest,
        repository=repository,
    )
    if not campaign_local_tool_approval_is_active(approval):
        return _result(
            status="awaiting_approval",
            campaign_task_id=task.id,
            stop_reason="human_approval_required",
            source_snapshot_digest=source_snapshot_digest,
        )
    remaining = campaign_remaining_tool_calls(campaign=campaign, repository=repository)
    if remaining is not None and remaining <= 0:
        return _result(
            status="blocked",
            campaign_task_id=task.id,
            stop_reason="budget_exhausted",
            source_snapshot_digest=source_snapshot_digest,
        )
    rule, rule_reason = current_campaign_scope_guard_rule(
        repository=repository,
        campaign=campaign,
        asset=campaign.default_asset,
    )
    if rule is None or rule_reason is not None:
        return _result(
            status="blocked",
            campaign_task_id=task.id,
            stop_reason=rule_reason or "scope_guard_rule_missing",
            source_snapshot_digest=source_snapshot_digest,
        )
    resolved_workspace_loader = workspace_loader or load_authorized_campaign_inputs
    try:
        workspace_inputs = resolved_workspace_loader(
            _campaign_payload(campaign).get("workspace_snapshot")
        )
    except (FileNotFoundError, ValueError):
        return _result(
            status="blocked",
            campaign_task_id=task.id,
            stop_reason="workspace_snapshot_invalid",
            source_snapshot_digest=source_snapshot_digest,
        )
    if (
        workspace_inputs.get("source_snapshot_digest") != source_snapshot_digest
        or not isinstance(workspace_inputs.get("authorized_local_root"), str)
        or not Path(workspace_inputs["authorized_local_root"]).is_dir()
    ):
        return _result(
            status="blocked",
            campaign_task_id=task.id,
            stop_reason="source_snapshot_changed",
            source_snapshot_digest=source_snapshot_digest,
        )

    retry_task = repository.claim_failed_campaign_task_retry(task.id)
    if retry_task is None:
        return _result(
            status="awaiting_evidence",
            campaign_task_id=task.id,
            stop_reason="active_local_tool_task",
            source_snapshot_digest=source_snapshot_digest,
        )
    campaign = repository.get_campaign(campaign.id) or campaign
    if campaign.status == "awaiting_review":
        campaign = repository.transition_campaign_status_if_currently(
            campaign.id,
            "running",
            allowed_current_statuses={"awaiting_review"},
        )
        if campaign is None:
            repository.update_campaign_task_status(retry_task.id, "failed")
            return _result(
                status="blocked",
                campaign_task_id=retry_task.id,
                stop_reason="campaign_not_running",
                source_snapshot_digest=source_snapshot_digest,
            )
    elif campaign.status != "running":
        repository.update_campaign_task_status(retry_task.id, "failed")
        return _result(
            status="blocked",
            campaign_task_id=retry_task.id,
            stop_reason="campaign_not_running",
            source_snapshot_digest=source_snapshot_digest,
        )
    return _dispatch_campaign_local_tool_task(
        campaign=campaign,
        task=retry_task,
        source_snapshot_digest=source_snapshot_digest,
        repository=repository,
        dispatcher=dispatcher,
        now=now,
    )


def current_campaign_scope_guard_rule(
    *,
    repository: DatabaseRepository,
    campaign: CampaignRecord,
    asset: str,
) -> tuple[ScopeGuardRule | None, str | None]:
    stored = _stored_scope_guard_rule(campaign)
    if campaign.program_id is None:
        return stored, None
    resolution = resolve_effective_program_rule(
        repository,
        campaign.program_id,
        asset,
        datetime.now(UTC),
    )
    if not resolution.source_backed:
        return stored, None
    if resolution.reason is not None or resolution.rule is None:
        return None, resolution.reason or "program_rule_not_authorizing"
    if stored is None:
        return None, "scope_guard_rule_missing"
    return (
        intersect_scope_guard_rules(stored, resolution.rule, asset=asset),
        None,
    )


def build_campaign_research_director_context(
    *,
    campaign: CampaignRecord,
    rule: ScopeGuardRule,
    repository: DatabaseRepository,
) -> ResearchDirectorContext:
    payload = _campaign_payload(campaign)
    source_snapshot_digest = _text(payload.get("source_snapshot_digest"))
    if _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None:
        raise ValueError("source_snapshot_digest_required")
    saved_scope_guard = payload.get("saved_scope_guard")
    authorized_local_root = (
        saved_scope_guard.get("authorized_local_root")
        if isinstance(saved_scope_guard, dict)
        else None
    )
    has_authorized_local_root = isinstance(authorized_local_root, str) and bool(
        authorized_local_root.strip()
    )
    completed_action_ids = [
        run.tool_name
        for run in repository.list_campaign_scanner_runs(campaign.id)
        if isinstance(run.payload, dict)
        and run.payload.get("research_director_tool_run") is True
        and run.payload.get("tool_call_consumed") is True
        and run.payload.get("source_snapshot_digest") == source_snapshot_digest
    ]
    completed_action_ids.extend(
        run.payload["tool_call_reservation_tool_id"]
        for run in repository.list_campaign_local_tool_call_reservations(campaign.id)
        if isinstance(run.payload, dict)
        and run.payload.get("tool_call_reservation_source_snapshot_digest")
        == source_snapshot_digest
        and isinstance(run.payload.get("tool_call_reservation_tool_id"), str)
    )
    return ResearchDirectorContext(
        campaign_id=campaign.id,
        asset=campaign.default_asset,
        autonomy_level=campaign.autonomy_level,
        source_snapshot_digest=source_snapshot_digest,
        scope_rule=rule,
        campaign_allowed_tools=campaign.allowed_tools,
        has_authorized_local_root=has_authorized_local_root,
        local_execution_authorized=(
            campaign.autonomy_level == "level_1_local_validation"
            and campaign.status == "running"
        ),
        remaining_tool_calls=campaign_remaining_tool_calls(
            campaign=campaign,
            repository=repository,
        ),
        completed_action_ids=completed_action_ids,
        signals=campaign_research_signals(
            campaign=campaign,
            has_authorized_local_root=has_authorized_local_root,
            repository=repository,
        ),
        human_review_required=campaign.status == "awaiting_review",
    )


def campaign_research_signals(
    *,
    campaign: CampaignRecord,
    has_authorized_local_root: bool,
    repository: DatabaseRepository,
) -> list[ResearchSignal]:
    payload = _campaign_payload(campaign)
    source_snapshot_digest = _text(payload.get("source_snapshot_digest"))
    if _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None:
        return []
    signals: list[ResearchSignal] = []
    for artifact in repository.list_artifacts(
        program_id=campaign.program_id,
        asset=campaign.default_asset,
    ):
        provenance = artifact.provenance if isinstance(artifact.provenance, dict) else {}
        derived_facts = (
            artifact.derived_facts if isinstance(artifact.derived_facts, dict) else {}
        )
        findings = derived_facts.get("advisory_findings")
        if (
            artifact.source_type != "registered_local_tool"
            or provenance.get("campaign_id") != campaign.id
            or provenance.get("source_snapshot_digest") != source_snapshot_digest
        ):
            continue
        if isinstance(findings, list):
            for index, finding in enumerate(findings[:20], start=1):
                if isinstance(finding, dict):
                    signals.append(
                        ResearchSignal(
                            signal_id=f"static_{artifact.id}_{index}",
                            state="needs_evidence",
                            priority=75,
                            evidence_refs=[f"artifact:{artifact.id}"],
                        )
                    )
        dependency_advisories = derived_facts.get("dependency_advisories")
        if (
            getattr(artifact, "kind", None) == "dependency_sbom_advisory"
            and provenance.get("tool_id") == "dependency_sbom_local"
            and isinstance(dependency_advisories, list)
        ):
            for index, advisory in enumerate(dependency_advisories[:20], start=1):
                if isinstance(advisory, dict):
                    signals.append(
                        ResearchSignal(
                            signal_id=f"dependency_{artifact.id}_{index}",
                            state="needs_evidence",
                            priority=70,
                            evidence_refs=[f"artifact:{artifact.id}"],
                        )
                    )
    static_hints = _static_tool_hints(campaign.allowed_tools)
    for task in repository.list_campaign_tasks(campaign.id):
        if task.status in {"awaiting_evidence", "needs_evidence"}:
            signals.append(
                ResearchSignal(
                    signal_id=f"evidence_{task.id}",
                    state="needs_evidence",
                    priority=90,
                    tool_hints=static_hints,
                    evidence_refs=[f"campaign_task:{task.id}"],
                )
            )
    if has_authorized_local_root and static_hints:
        signals.append(
            ResearchSignal(
                signal_id="source_snapshot_static_coverage",
                state="open",
                priority=60,
                tool_hints=static_hints,
                evidence_refs=[f"campaign:{campaign.id}"],
            )
        )
    return signals


def campaign_remaining_tool_calls(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> int | None:
    budget = repository.get_campaign_budget(campaign.id)
    if budget is None or budget.tool_call_budget is None:
        return None
    if hasattr(repository, "campaign_local_tool_call_count"):
        local_tool_calls = repository.campaign_local_tool_call_count(campaign.id)
    else:
        local_tool_calls = sum(
            isinstance(run.payload, dict)
            and run.payload.get("research_director_tool_run") is True
            and run.payload.get("tool_call_consumed") is True
            for run in repository.list_campaign_scanner_runs(campaign.id)
        )
    return max(0, budget.tool_call_budget - local_tool_calls)


def record_campaign_research_director_plan(
    *,
    campaign: CampaignRecord,
    plan: ResearchDirectorPlan,
    repository: DatabaseRepository,
) -> PipelineStageRecord:
    existing = [
        stage
        for stage in repository.list_campaign_pipeline_stages(campaign.id)
        if stage.stage_key == "research_director_plan"
        and isinstance(stage.payload, dict)
        and stage.payload.get("plan_digest") == plan.plan_digest
    ]
    if existing:
        return existing[0]
    stage_status = {
        "ready": "planned",
        "awaiting_human_review": "awaiting_review",
        "blocked": "blocked",
    }[plan.status]
    payload = plan.model_dump(mode="json")
    payload.update(
        {
            "execution_allowed": False,
            "dispatch_allowed": False,
            "plan_dispatch_allowed": plan.dispatch_allowed,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
            "raw_payload_processed": False,
            "raw_payload_in_dispatch": False,
        }
    )
    return repository.save_pipeline_stage(
        pipeline_run_id=None,
        campaign_id=campaign.id,
        task_id=None,
        stage_key="research_director_plan",
        stage_order=len(repository.list_campaign_pipeline_stages(campaign.id)),
        status=stage_status,
        input_refs=[
            f"campaign:{campaign.id}",
            f"source_snapshot:{plan.source_snapshot_digest}",
        ],
        output_refs=[f"research_plan:{plan.plan_id}"],
        safety_gate_state=("advisory_plan_only" if stage_status != "blocked" else "blocked"),
        stop_reason=plan.stop_reason,
        payload=payload,
    )


def current_campaign_local_tool_plan(
    *,
    campaign: CampaignRecord,
    tool_id: str,
    plan_id: str,
    plan_digest: str,
    repository: DatabaseRepository,
) -> PipelineStageRecord | None:
    matches = [
        stage
        for stage in repository.list_campaign_pipeline_stages(campaign.id)
        if stage.stage_key == "research_director_plan"
        and stage.status == "planned"
        and isinstance(stage.payload, dict)
        and stage.payload.get("plan_id") == plan_id
        and stage.payload.get("plan_digest") == plan_digest
        and stage.payload.get("action_kind") == "local_tool"
        and stage.payload.get("action_id") == tool_id
        and stage.payload.get("plan_dispatch_allowed") is True
    ]
    if len(matches) != 1:
        return None
    consumed = [
        stage
        for stage in repository.list_campaign_pipeline_stages(campaign.id)
        if stage.stage_key == "research_director_local_tool_run"
        and isinstance(stage.payload, dict)
        and stage.payload.get("research_plan_digest") == plan_digest
    ]
    return None if consumed else matches[0]


def claim_campaign_local_tool_task(
    *,
    campaign: CampaignRecord,
    plan: ResearchDirectorPlan,
    repository: DatabaseRepository,
) -> tuple[CampaignTaskRecord, bool]:
    return repository.claim_campaign_task(
        task_id=_local_tool_task_id(plan.plan_digest),
        campaign_id=campaign.id,
        task_type=LOCAL_TOOL_TASK_TYPE,
        agent_type="registered_local_tool",
        title=f"Run registered local {plan.action_id} analysis",
        input_refs=[
            f"campaign:{campaign.id}",
            f"source_snapshot:{plan.source_snapshot_digest}",
            f"research_plan:{plan.plan_id}",
        ],
        payload={
            "schema_version": LOCAL_TOOL_TASK_SCHEMA,
            "execution_lease_required": True,
            "research_plan_id": plan.plan_id,
            "research_plan_digest": plan.plan_digest,
            "source_snapshot_digest": plan.source_snapshot_digest,
            "tool_id": plan.action_id,
            **_SAFETY_FIELDS,
        },
    )


def ensure_campaign_local_tool_approval(
    *,
    campaign: CampaignRecord,
    task: CampaignTaskRecord,
    source_snapshot_digest: str,
    tool_id: str,
    plan_digest: str,
    repository: DatabaseRepository,
) -> ApprovalRecord:
    matching = [
        approval
        for approval in repository.list_campaign_approval_records(campaign.id)
        if _local_tool_approval_matches(
            approval=approval,
            campaign=campaign,
            task=task,
            source_snapshot_digest=source_snapshot_digest,
            tool_id=tool_id,
            plan_digest=plan_digest,
        )
    ]
    if matching:
        latest = matching[0]
        if (
            latest.status in {"pending", "requested", "approved"}
            and approval_record_is_active(latest)
        ) or latest.status in {
            "denied",
            "revoked",
            "used",
        }:
            return latest
    approval_attempt = len(matching)
    return repository.create_approval_record(
        approval_id=_local_tool_approval_record_id(
            task_id=task.id,
            plan_digest=plan_digest,
            attempt=approval_attempt,
        ),
        campaign_id=campaign.id,
        task_id=task.id,
        program_id=campaign.program_id,
        approval_type=LOCAL_TOOL_APPROVAL_TYPE,
        actor="research_director",
        reason="Human approval is required before registered local static analysis.",
        scope_reference=f"source_snapshot:{source_snapshot_digest}",
        requested_action=tool_id,
        asset=campaign.default_asset,
        validation_mode=_LOCAL_TOOL_VALIDATION_MODE,
        plan_digest=plan_digest,
        autonomy_level=campaign.autonomy_level,
        safety_gate_state="awaiting_approval",
        payload={
            "schema_version": _LOCAL_TOOL_APPROVAL_SCHEMA,
            "source_snapshot_digest": source_snapshot_digest,
            "tool_id": tool_id,
            **_SAFETY_FIELDS,
        },
    )


def _local_tool_approval_record_id(
    *,
    task_id: str,
    plan_digest: str,
    attempt: int,
) -> str:
    identity = f"{task_id}:{plan_digest}:{attempt}".encode("utf-8")
    return f"approval_{sha256(identity).hexdigest()}"


def campaign_local_tool_approval_is_active(approval: ApprovalRecord | None) -> bool:
    return bool(
        approval is not None
        and approval.status == "approved"
        and approval_record_is_active(approval)
    )


def _local_tool_approval_matches(
    *,
    approval: ApprovalRecord,
    campaign: CampaignRecord,
    task: CampaignTaskRecord,
    source_snapshot_digest: str,
    tool_id: str,
    plan_digest: str,
) -> bool:
    payload = approval.payload if isinstance(approval.payload, dict) else {}
    return (
        approval.task_id == task.id
        and approval.approval_type == LOCAL_TOOL_APPROVAL_TYPE
        and approval.requested_action == tool_id
        and approval.asset == campaign.default_asset
        and approval.validation_mode == _LOCAL_TOOL_VALIDATION_MODE
        and approval.plan_digest == plan_digest
        and approval.scope_reference == f"source_snapshot:{source_snapshot_digest}"
        and payload.get("schema_version") == _LOCAL_TOOL_APPROVAL_SCHEMA
        and payload.get("source_snapshot_digest") == source_snapshot_digest
        and payload.get("tool_id") == tool_id
        and all(payload.get(field) is False for field in _SAFETY_FIELDS)
    )


def _dispatch_campaign_local_tool_task(
    *,
    campaign: CampaignRecord,
    task: CampaignTaskRecord,
    source_snapshot_digest: str,
    repository: DatabaseRepository,
    dispatcher: Callable[..., Any],
    now: datetime | None,
) -> dict[str, Any]:
    dispatched = repository.dispatch_research_director_local_tool_task(
        task_id=task.id,
        agent_payload=_task_result_payload(task=task, result=None),
        now=now,
    )
    if dispatched is None:
        return _result(
            status="awaiting_evidence",
            campaign_task_id=task.id,
            stop_reason="active_local_tool_task",
            source_snapshot_digest=source_snapshot_digest,
        )
    dispatched_task, agent_run = dispatched
    repository.save_pipeline_stage(
        pipeline_run_id=None,
        campaign_id=campaign.id,
        task_id=task.id,
        stage_key="research_director_local_tool_dispatch",
        stage_order=len(repository.list_campaign_pipeline_stages(campaign.id)),
        status="dispatched",
        input_refs=task.input_refs,
        output_refs=[f"campaign_task:{task.id}", f"agent_run:{agent_run.id}"],
        safety_gate_state="allowed",
        stop_reason=None,
        payload={
            "schema_version": LOCAL_TOOL_TASK_SCHEMA,
            "research_plan_id": task.payload.get("research_plan_id"),
            "research_plan_digest": task.payload.get("research_plan_digest"),
            "source_snapshot_digest": source_snapshot_digest,
            "tool_id": task.payload.get("tool_id"),
            **_SAFETY_FIELDS,
        },
    )
    try:
        dispatcher(campaign_task_id=task.id)
    except Exception:
        repository.finish_campaign_task_execution(
            task_id=task.id,
            execution_claim_id=agent_run.id,
            task_status="failed",
            task_output_refs=[f"agent_run:{agent_run.id}"],
            agent_status="failed",
            agent_output_refs=[],
            safety_gate_state="blocked",
            stop_reason="dispatch_failed",
            payload=_task_result_payload(task=task, result=None),
            expected_execution_statuses={"dispatched"},
        )
        return _result(
            status="blocked",
            campaign_task_id=task.id,
            stop_reason="dispatch_failed",
            source_snapshot_digest=source_snapshot_digest,
        )
    return _result(
        status="dispatched",
        campaign_task_id=task.id,
        stop_reason=None,
        source_snapshot_digest=source_snapshot_digest,
    )


def _save_advisory_artifact(
    *,
    campaign: CampaignRecord,
    source_snapshot_digest: str,
    plan_digest: str,
    result: RegisteredLocalToolRun,
    repository: DatabaseRepository,
    commit: bool = True,
) -> str | None:
    if not result.command_executed:
        return None
    kind, payload_summary, derived_facts = local_tool_advisory_artifact_data(result)
    artifact = repository.save_artifact(
        program_id=campaign.program_id,
        asset=campaign.default_asset,
        kind=kind,
        source_type="registered_local_tool",
        source_hash=_advisory_artifact_hash(
            campaign_id=campaign.id,
            source_snapshot_digest=source_snapshot_digest,
            tool_id=result.tool_id,
            command_hash=result.command_hash,
        ),
        ingestion_status="advisory_only",
        provenance={
            "source": "research_director_local_tool",
            "campaign_id": campaign.id,
            "tool_id": result.tool_id,
            "source_snapshot_digest": source_snapshot_digest,
            "research_plan_digest": plan_digest,
            "raw_payload_processed": False,
        },
        payload_summary=payload_summary,
        derived_facts=derived_facts,
        commit=commit,
    )
    return artifact.id


def _save_scanner_run(
    *,
    campaign: CampaignRecord,
    source_snapshot_digest: str,
    plan_id: str,
    plan_digest: str,
    result: RegisteredLocalToolRun,
    advisory_artifact_id: str | None,
    reservation_agent_run_id: str,
    repository: DatabaseRepository,
    commit: bool = True,
) -> str | None:
    if result.status == "blocked":
        return None
    record = repository.save_scanner_run(
        campaign_id=campaign.id,
        codebase_map_id=None,
        tool_name=result.tool_id,
        command_hash=result.command_hash,
        status=result.runner_status or result.status,
        finding_count=result.finding_count,
        candidate_count=0,
        summary=f"Registered local {result.tool_id} run recorded as advisory evidence only.",
        safety_gate_state="allowed",
        payload={
            "research_plan_id": plan_id,
            "research_plan_digest": plan_digest,
            "source_snapshot_digest": source_snapshot_digest,
            "tool_id": result.tool_id,
            "runner_status": result.runner_status,
            "command_executed": result.command_executed,
            "advisory_artifact_id": advisory_artifact_id,
            "research_director_tool_run": True,
            "tool_call_consumed": True,
            "tool_call_reservation_agent_run_id": reservation_agent_run_id,
            "execution_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
            "raw_payload_processed": False,
        },
        commit=commit,
    )
    return record.id


def _record_local_tool_run_stage(
    *,
    campaign: CampaignRecord,
    task: CampaignTaskRecord,
    plan_stage: PipelineStageRecord,
    result: RegisteredLocalToolRun,
    scanner_run_id: str | None,
    advisory_artifact_id: str | None,
    repository: DatabaseRepository,
    commit: bool = True,
) -> PipelineStageRecord:
    plan_payload = plan_stage.payload if isinstance(plan_stage.payload, dict) else {}
    source_snapshot_digest = _text(plan_payload.get("source_snapshot_digest"))
    return repository.save_pipeline_stage(
        pipeline_run_id=None,
        campaign_id=campaign.id,
        task_id=task.id,
        stage_key="research_director_local_tool_run",
        stage_order=len(repository.list_campaign_pipeline_stages(campaign.id)),
        status=("blocked" if result.status == "blocked" else result.status),
        input_refs=task.input_refs,
        output_refs=[
            *([f"scanner_run:{scanner_run_id}"] if scanner_run_id else []),
            *([f"artifact:{advisory_artifact_id}"] if advisory_artifact_id else []),
        ],
        safety_gate_state=("blocked" if result.status == "blocked" else "allowed"),
        stop_reason=(None if result.status != "blocked" else result.authorization.reason),
        payload={
            "research_plan_id": plan_payload.get("plan_id"),
            "research_plan_digest": plan_payload.get("plan_digest"),
            "source_snapshot_digest": source_snapshot_digest,
            "tool_id": result.tool_id,
            "runner_status": result.runner_status,
            "command_hash": result.command_hash,
            "command_executed": result.command_executed,
            "finding_count": result.finding_count,
            **_SAFETY_FIELDS,
        },
        commit=commit,
    )


def _finish_local_task(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
    task_status: str,
    agent_status: str,
    safety_gate_state: str,
    stop_reason: str | None,
    output_refs: list[str],
    payload: dict[str, Any],
    renew_lease: bool = True,
) -> dict[str, Any]:
    if renew_lease:
        renewed_task = _renew_local_tool_task_lease(task=task, repository=repository)
        if renewed_task is None:
            return _lease_lost_result(task.id)
        task = renewed_task
    payload = {
        **payload,
        **repository.local_tool_call_reservation_metadata(
            task_id=task.id,
            execution_claim_id=task.execution_claim_id,
        ),
    }
    completed = repository.finish_campaign_task_execution(
        task_id=task.id,
        execution_claim_id=task.execution_claim_id,
        task_status=task_status,
        task_output_refs=output_refs,
        agent_status=agent_status,
        agent_output_refs=output_refs,
        safety_gate_state=safety_gate_state,
        stop_reason=stop_reason,
        payload=payload,
        require_active_execution_lease=True,
    )
    if completed is None:
        return {
            "status": "awaiting_evidence",
            "task_id": task.id,
            "stop_reason": "execution_lease_lost",
        }
    completed_task, agent_run = completed
    return {
        "status": completed_task.status,
        "task_id": completed_task.id,
        "agent_run_id": agent_run.id,
        "stop_reason": stop_reason,
    }


def _renew_local_tool_task_lease(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
) -> CampaignTaskRecord | None:
    if not task.execution_claim_id:
        return None
    return repository.renew_campaign_task_execution_lease(
        task.id,
        execution_claim_id=task.execution_claim_id,
    )


def _lease_lost_result(task_id: str) -> dict[str, Any]:
    return {
        "status": "awaiting_evidence",
        "task_id": task_id,
        "stop_reason": "execution_lease_lost",
    }


def _task_result_payload(
    *,
    task: CampaignTaskRecord,
    result: RegisteredLocalToolRun | None,
) -> dict[str, Any]:
    payload = task.payload if isinstance(task.payload, dict) else {}
    return {
        "schema_version": LOCAL_TOOL_TASK_SCHEMA,
        "research_plan_id": payload.get("research_plan_id"),
        "research_plan_digest": payload.get("research_plan_digest"),
        "source_snapshot_digest": payload.get("source_snapshot_digest"),
        "tool_id": payload.get("tool_id"),
        "runner_status": result.runner_status if result is not None else None,
        "command_hash": result.command_hash if result is not None else None,
        "command_executed": result.command_executed if result is not None else False,
        "finding_count": result.finding_count if result is not None else 0,
        **_SAFETY_FIELDS,
    }


def _pending_local_tool_task(
    *,
    campaign: CampaignRecord,
    source_snapshot_digest: str,
    repository: DatabaseRepository,
) -> CampaignTaskRecord | None:
    return next(
        (
            task
            for task in repository.list_campaign_tasks(campaign.id)
            if task.task_type == LOCAL_TOOL_TASK_TYPE
            and task.status in {"queued", "ready", "dispatched", "running"}
            and isinstance(task.payload, dict)
            and task.payload.get("source_snapshot_digest") == source_snapshot_digest
        ),
        None,
    )


def _recover_expired_local_tool_task(
    *,
    campaign: CampaignRecord,
    source_snapshot_digest: str,
    repository: DatabaseRepository,
    now: datetime | None,
) -> dict[str, Any] | None:
    current_snapshot_expired_task: CampaignTaskRecord | None = None
    for task in repository.list_campaign_tasks(campaign.id):
        task_source_snapshot_digest = _local_tool_task_source_snapshot_digest(task)
        if task_source_snapshot_digest is None:
            continue
        if task.status in {"dispatched", "running"}:
            expired_task = repository.expire_campaign_task_execution(task.id, now=now)
            if expired_task is None:
                continue
            task = expired_task
        expired_agent_run_id = _expired_local_tool_agent_run_id(
            task=task,
            repository=repository,
        )
        if expired_agent_run_id is None:
            continue

        _record_local_tool_lease_expiry(
            campaign=campaign,
            task=task,
            source_snapshot_digest=task_source_snapshot_digest,
            expired_agent_run_id=expired_agent_run_id,
            repository=repository,
        )
        if task_source_snapshot_digest == source_snapshot_digest:
            current_snapshot_expired_task = task
    if current_snapshot_expired_task is not None:
        current_campaign = repository.get_campaign(campaign.id)
        if current_campaign is not None and current_campaign.status == "running":
            repository.update_campaign_status(campaign.id, "awaiting_review")
        return _result(
            status="awaiting_review",
            campaign_task_id=current_snapshot_expired_task.id,
            stop_reason=_LOCAL_TOOL_LEASE_EXPIRED_STOP_REASON,
            source_snapshot_digest=source_snapshot_digest,
        )
    return None


def _local_tool_task_matches_snapshot(
    *,
    task: CampaignTaskRecord,
    source_snapshot_digest: str,
) -> bool:
    return (
        _local_tool_task_source_snapshot_digest(task) == source_snapshot_digest
    )


def _local_tool_task_source_snapshot_digest(
    task: CampaignTaskRecord,
) -> str | None:
    payload = task.payload if isinstance(task.payload, dict) else {}
    source_snapshot_digest = _text(payload.get("source_snapshot_digest"))
    if not (
        task.task_type == LOCAL_TOOL_TASK_TYPE
        and payload.get("schema_version") == LOCAL_TOOL_TASK_SCHEMA
        and payload.get("execution_lease_required") is True
        and _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest)
    ):
        return None
    return source_snapshot_digest


def _expired_local_tool_agent_run_id(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
) -> str | None:
    if (
        task.status != "failed"
        or task.execution_claim_id is not None
        or task.execution_lease_expires_at is not None
    ):
        return None
    return next(
        (
            agent_run.id
            for agent_run in repository.list_campaign_agent_runs(task.campaign_id)
            if agent_run.task_id == task.id
            and agent_run.status == "failed"
            and agent_run.stop_reason == _LOCAL_TOOL_LEASE_EXPIRED_STOP_REASON
        ),
        None,
    )


def _record_local_tool_lease_expiry(
    *,
    campaign: CampaignRecord,
    task: CampaignTaskRecord,
    source_snapshot_digest: str,
    expired_agent_run_id: str,
    repository: DatabaseRepository,
) -> PipelineStageRecord:
    payload = task.payload if isinstance(task.payload, dict) else {}
    stage_id = _local_tool_failure_stage_id(
        task_id=task.id,
        source_snapshot_digest=source_snapshot_digest,
        expired_agent_run_id=expired_agent_run_id,
    )
    existing = repository.get_pipeline_stage(stage_id)
    if existing is not None:
        return existing
    return repository.save_pipeline_stage(
        pipeline_run_id=None,
        campaign_id=campaign.id,
        task_id=task.id,
        stage_id=stage_id,
        stage_key=LOCAL_TOOL_FAILURE_STAGE_KEY,
        stage_order=LOCAL_TOOL_FAILURE_STAGE_ORDER,
        status="failed",
        input_refs=task.input_refs,
        output_refs=task.output_refs,
        safety_gate_state="blocked",
        stop_reason=_LOCAL_TOOL_LEASE_EXPIRED_STOP_REASON,
        payload={
            "schema_version": LOCAL_TOOL_TASK_SCHEMA,
            "research_plan_id": payload.get("research_plan_id"),
            "research_plan_digest": payload.get("research_plan_digest"),
            "source_snapshot_digest": source_snapshot_digest,
            "tool_id": payload.get("tool_id"),
            "failed_agent_run_id": expired_agent_run_id,
            "failure_reason": _LOCAL_TOOL_LEASE_EXPIRED_STOP_REASON,
            **_SAFETY_FIELDS,
        },
    )


def _has_active_read_only_runtime_task(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> bool:
    return any(
        task.status in {"queued", "ready", "dispatched", "running"}
        and isinstance(task.payload, dict)
        and task.payload.get("runtime_schema") == "autonomous_research_v1"
        for task in repository.list_campaign_tasks(campaign.id)
    )


def _static_tool_hints(allowed_tools: list[str]) -> list[str]:
    hints: list[str] = []
    if "static_analyzer" in allowed_tools or "semgrep_local" in allowed_tools:
        hints.append("semgrep_local")
    if "codeql_local" in allowed_tools:
        hints.append("codeql_local")
    if "dependency_sbom_local" in allowed_tools:
        hints.append("dependency_sbom_local")
    return hints


def _stored_scope_guard_rule(campaign: CampaignRecord) -> ScopeGuardRule | None:
    stored = _campaign_payload(campaign).get("scope_guard_rule")
    if not isinstance(stored, dict):
        return None
    try:
        return ScopeGuardRule.model_validate(stored)
    except ValueError:
        return None


def _campaign_payload(campaign: CampaignRecord) -> dict[str, Any]:
    return campaign.payload if isinstance(campaign.payload, dict) else {}


def _advisory_artifact_hash(
    *,
    campaign_id: str,
    source_snapshot_digest: str,
    tool_id: str,
    command_hash: str,
) -> str:
    payload = json.dumps(
        {
            "campaign_id": campaign_id,
            "source_snapshot_digest": source_snapshot_digest,
            "tool_id": tool_id,
            "command_hash": command_hash,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return f"sha256:{sha256(payload.encode('utf-8')).hexdigest()}"


def _local_tool_task_id(plan_digest: str) -> str:
    return "research_local_tool_" + plan_digest.removeprefix("sha256:")


def _local_tool_failure_stage_id(
    *,
    task_id: str,
    source_snapshot_digest: str,
    expired_agent_run_id: str,
) -> str:
    identity = (
        f"{task_id}:{source_snapshot_digest}:{expired_agent_run_id}:"
        f"{_LOCAL_TOOL_LEASE_EXPIRED_STOP_REASON}"
    )
    return "pipeline_stage_local_failure_" + sha256(identity.encode("utf-8")).hexdigest()


def _result(
    *,
    status: str,
    campaign_task_id: str | None,
    stop_reason: str | None,
    source_snapshot_digest: str,
) -> dict[str, Any]:
    return {
        "status": status,
        "campaign_task_id": campaign_task_id,
        "stop_reason": stop_reason,
        "source_snapshot_digest": source_snapshot_digest,
        **_SAFETY_FIELDS,
    }


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


__all__ = [
    "LOCAL_TOOL_APPROVAL_TYPE",
    "LOCAL_TOOL_FAILURE_STAGE_KEY",
    "LOCAL_TOOL_FAILURE_STAGE_ORDER",
    "LOCAL_TOOL_TASK_SCHEMA",
    "LOCAL_TOOL_TASK_TYPE",
    "build_campaign_research_director_context",
    "campaign_local_tool_approval_is_active",
    "campaign_remaining_tool_calls",
    "claim_campaign_local_tool_task",
    "current_campaign_scope_guard_rule",
    "current_campaign_local_tool_plan",
    "ensure_campaign_local_tool_approval",
    "record_campaign_research_director_plan",
    "retry_campaign_local_tool_task",
    "run_campaign_local_tool_task",
    "tick_campaign_local_execution",
]
