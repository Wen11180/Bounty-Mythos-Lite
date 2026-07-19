import re
from collections.abc import Callable
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from app.campaign_orchestrator import campaign_elapsed_minutes, campaign_token_used_from_runs
from app.db_models import CampaignRecord, CampaignTaskRecord
from app.program_rule_intake.scope_resolver import (
    intersect_scope_guard_rules,
    resolve_effective_program_rule,
)
from app.repository import DatabaseRepository
from app.scope_guard import ScopeGuardRule


_SAFETY_FIELDS = {
    "execution_allowed": False,
    "dispatch_allowed": False,
    "validation_allowed": False,
    "candidate_promotion_allowed": False,
    "report_submission_allowed": False,
    "raw_payload_processed": False,
    "raw_payload_in_dispatch": False,
}
_RUNTIME_SCHEMA = "autonomous_research_v1"
_RUNTIME_STAGE_PREFIX = "autonomous_research:"
_ACTIVE_TASK_STATUSES = {
    "queued",
    "ready",
    "dispatched",
    "running",
    "awaiting_evidence",
    "awaiting_approval",
    "needs_evidence",
}
_WORK_ITEMS = (
    {
        "task_type": "campaign_observation",
        "agent_type": "orchestrator_agent",
        "title": "Observe authorized campaign state",
    },
    {
        "task_type": "attack_surface_mapping",
        "agent_type": "target_model_agent",
        "title": "Map authorized attack surface facts",
    },
    {
        "task_type": "hypothesis_generation",
        "agent_type": "hypothesis_agent",
        "title": "Generate candidate hypotheses from safe facts",
    },
    {
        "task_type": "candidate_refutation",
        "agent_type": "candidate_hunter_agent",
        "title": "Refute candidate hypotheses from persisted evidence",
    },
    {
        "task_type": "finding_dedup_and_rank",
        "agent_type": "triage_agent",
        "title": "Deduplicate and rank retained candidates",
    },
    {
        "task_type": "report_review",
        "agent_type": "report_agent",
        "title": "Build submission-blocked report review",
    },
)
_WORK_ITEM_TYPES = {work_item["task_type"] for work_item in _WORK_ITEMS}
_EVIDENCE_TASK_TYPE = "candidate_hunter_evidence_inspection"
_EVIDENCE_TASK_SCHEMA = "candidate_hunter_evidence_task_v1"
_HANDLED_WORK_ITEM_TYPES = {
    "campaign_observation",
    "attack_surface_mapping",
    "hypothesis_generation",
    "candidate_refutation",
    "finding_dedup_and_rank",
    "report_review",
}
_SOURCE_SNAPSHOT_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_SAFE_STOP_REASON_PATTERN = re.compile(r"[a-z][a-z0-9_:-]{0,127}")
_MIN_RUNTIME_TICK_INTERVAL_SECONDS = 60
_MAX_RUNTIME_WORK_ITEMS_PER_SNAPSHOT = 20
_FORBIDDEN_RUNTIME_PAYLOAD_KEYS = frozenset(
    {
        "authorized_code_files",
        "authorization_header",
        "authorization_headers",
        "cookie",
        "cookies",
        "credential",
        "credentials",
        "password",
        "pii",
        "raw_code",
        "raw_payload",
        "raw_source",
        "real_user_data",
        "secret",
        "secrets",
        "source_code",
        "token",
        "tokens",
        "user_data",
    }
)


def tick_autonomous_research_campaign(
    campaign_id: str,
    *,
    repository: DatabaseRepository,
    dispatcher: Callable[..., Any],
    now: datetime | None = None,
) -> dict[str, Any]:
    campaign = repository.get_campaign(campaign_id)
    if campaign is None:
        return _tick_result(status="not_found", stop_reason="campaign_not_found")

    recovery = _recover_runtime_task_if_needed(
        campaign=campaign,
        repository=repository,
        dispatcher=dispatcher,
        now=now,
    )
    if recovery is not None:
        return recovery

    evidence_recovery = _dispatch_queued_local_evidence_task_if_needed(
        campaign=campaign,
        repository=repository,
        dispatcher=dispatcher,
        now=now,
    )
    if evidence_recovery is not None:
        return evidence_recovery

    selection = select_autonomous_research_work(
        campaign=campaign,
        repository=repository,
        now=now,
    )
    if selection["status"] != "ready":
        stop_reason = selection["stop_reason"]
        return _tick_result(
            status=_tick_stop_status(stop_reason),
            stop_reason=stop_reason,
            source_snapshot_digest=selection["source_snapshot_digest"],
        )

    task_type = selection["task_type"]
    source_snapshot_digest = selection["source_snapshot_digest"]
    if task_type not in _HANDLED_WORK_ITEM_TYPES:
        return _tick_result(
            status="blocked",
            stop_reason="runtime_task_handler_unavailable",
            source_snapshot_digest=source_snapshot_digest,
        )
    pipeline_run_id = None
    input_refs = [
        f"campaign:{campaign.id}",
        f"source_snapshot:{source_snapshot_digest}",
    ]
    if task_type in {
        "candidate_refutation",
        "finding_dedup_and_rank",
        "report_review",
    }:
        prerequisite_task_type = {
            "candidate_refutation": "hypothesis_generation",
            "finding_dedup_and_rank": "candidate_refutation",
            "report_review": "finding_dedup_and_rank",
        }[task_type]
        pipeline_run_id = _pipeline_run_id_from_completed_runtime_stage(
            campaign=campaign,
            repository=repository,
            source_snapshot_digest=source_snapshot_digest,
            prerequisite_task_type=prerequisite_task_type,
        )
        if pipeline_run_id is None:
            return _tick_result(
                status="blocked",
                stop_reason=(
                    "candidate_hunter_input_missing"
                    if task_type == "candidate_refutation"
                    else "candidate_hunter_projection_missing"
                ),
                source_snapshot_digest=source_snapshot_digest,
            )
        input_refs.append(f"pipeline_run:{pipeline_run_id}")
    tick_stop_reason = _runtime_tick_stop_reason(
        campaign=campaign,
        repository=repository,
        source_snapshot_digest=source_snapshot_digest,
        now=now,
    )
    if tick_stop_reason is not None:
        return _tick_result(
            status="blocked",
            stop_reason=tick_stop_reason,
            source_snapshot_digest=source_snapshot_digest,
        )
    task = _failed_runtime_task_for_selection(
        campaign=campaign,
        repository=repository,
        task_type=task_type,
        source_snapshot_digest=source_snapshot_digest,
    )
    if task is None:
        task, claimed = repository.claim_campaign_task(
            task_id=_runtime_task_id(
                campaign_id=campaign.id,
                task_type=task_type,
                source_snapshot_digest=source_snapshot_digest,
            ),
            campaign_id=campaign.id,
            task_type=task_type,
            agent_type=selection["agent_type"],
            title=selection["title"],
            input_refs=input_refs,
            payload=_runtime_task_payload(
                campaign_id=campaign.id,
                task_type=task_type,
                source_snapshot_digest=source_snapshot_digest,
                pipeline_run_id=pipeline_run_id,
            ),
        )
        if not claimed:
            return _tick_result(
                status="awaiting_evidence",
                campaign_task_id=task.id,
                stop_reason="active_runtime_task",
                source_snapshot_digest=source_snapshot_digest,
            )
    else:
        task = repository.update_campaign_task_status(task.id, "queued") or task
    return _dispatch_runtime_task(
        campaign=campaign,
        task=task,
        source_snapshot_digest=source_snapshot_digest,
        repository=repository,
        dispatcher=dispatcher,
    )


def record_autonomous_research_task_completion(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
) -> None:
    payload = task.payload
    source_snapshot_digest = (
        payload.get("source_snapshot_digest") if isinstance(payload, dict) else None
    )
    if (
        not isinstance(payload, dict)
        or payload.get("runtime_schema") != _RUNTIME_SCHEMA
        or task.task_type not in _WORK_ITEM_TYPES
        or not isinstance(source_snapshot_digest, str)
        or not _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest)
        or not _runtime_payload_is_safe(payload)
    ):
        return
    repository.save_pipeline_stage(
        pipeline_run_id=None,
        campaign_id=task.campaign_id,
        task_id=task.id,
        stage_key=f"{_RUNTIME_STAGE_PREFIX}{task.task_type}",
        stage_order=_stage_order_for(task.task_type),
        status="completed",
        input_refs=task.input_refs,
        output_refs=task.output_refs,
        safety_gate_state="allowed",
        stop_reason=None,
        payload=_runtime_stage_payload(
            campaign_id=task.campaign_id,
            task_type=task.task_type,
            source_snapshot_digest=source_snapshot_digest,
            outcome="completed",
        ),
    )
    if task.task_type == "report_review":
        campaign = repository.get_campaign(task.campaign_id)
        if campaign is not None and campaign.status == "running":
            repository.update_campaign_status(campaign.id, "awaiting_review")


def record_autonomous_research_task_blocked(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
    stop_reason: str,
) -> None:
    payload = task.payload
    source_snapshot_digest = (
        payload.get("source_snapshot_digest") if isinstance(payload, dict) else None
    )
    if (
        not isinstance(payload, dict)
        or payload.get("runtime_schema") != _RUNTIME_SCHEMA
        or task.task_type not in _WORK_ITEM_TYPES
        or not isinstance(source_snapshot_digest, str)
        or not _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest)
        or not _runtime_payload_is_safe(payload)
    ):
        return
    repository.save_pipeline_stage(
        pipeline_run_id=None,
        campaign_id=task.campaign_id,
        task_id=task.id,
        stage_key=f"{_RUNTIME_STAGE_PREFIX}{task.task_type}",
        stage_order=_stage_order_for(task.task_type),
        status="blocked",
        input_refs=task.input_refs,
        output_refs=task.output_refs,
        safety_gate_state="blocked",
        stop_reason=stop_reason,
        payload=_runtime_stage_payload(
            campaign_id=task.campaign_id,
            task_type=task.task_type,
            source_snapshot_digest=source_snapshot_digest,
            outcome=f"blocked:{stop_reason}",
        ),
    )
    campaign = repository.get_campaign(task.campaign_id)
    if campaign is not None and campaign.status == "running":
        repository.update_campaign_status(campaign.id, "blocked")


def record_autonomous_research_task_awaiting_evidence(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
) -> None:
    payload = task.payload
    source_snapshot_digest = (
        payload.get("source_snapshot_digest") if isinstance(payload, dict) else None
    )
    if (
        not isinstance(payload, dict)
        or payload.get("runtime_schema") != _RUNTIME_SCHEMA
        or task.task_type not in _WORK_ITEM_TYPES
        or not isinstance(source_snapshot_digest, str)
        or not _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest)
        or not _runtime_payload_is_safe(payload)
    ):
        return
    repository.save_pipeline_stage(
        pipeline_run_id=None,
        campaign_id=task.campaign_id,
        task_id=task.id,
        stage_key=f"{_RUNTIME_STAGE_PREFIX}{task.task_type}",
        stage_order=_stage_order_for(task.task_type),
        status="awaiting_evidence",
        input_refs=task.input_refs,
        output_refs=task.output_refs,
        safety_gate_state="awaiting_evidence",
        stop_reason="awaiting_evidence",
        payload=_runtime_stage_payload(
            campaign_id=task.campaign_id,
            task_type=task.task_type,
            source_snapshot_digest=source_snapshot_digest,
            outcome="awaiting_evidence",
        ),
    )


def autonomous_research_task_stop_reason(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord | None,
    repository: DatabaseRepository,
) -> str | None:
    payload = task.payload
    if not isinstance(payload, dict) or payload.get("runtime_schema") != _RUNTIME_SCHEMA:
        return None
    if campaign is None:
        return "scope_not_in_scope"
    campaign_stop_reason = _campaign_stop_reason(
        campaign,
        repository,
        now=None,
        excluding_task_id=task.id,
    )
    if campaign_stop_reason is not None:
        return campaign_stop_reason
    campaign_payload = campaign.payload if isinstance(campaign.payload, dict) else {}
    campaign_snapshot_digest = campaign_payload.get("source_snapshot_digest")
    task_snapshot_digest = payload.get("source_snapshot_digest")
    if not isinstance(campaign_snapshot_digest, str) or not _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(
        campaign_snapshot_digest
    ):
        return "source_snapshot_digest_required"
    if (
        task.task_type not in _WORK_ITEM_TYPES
        or not isinstance(task_snapshot_digest, str)
        or not _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(task_snapshot_digest)
        or not _runtime_payload_is_safe(payload)
    ):
        return "malformed_runtime_task"
    if task_snapshot_digest != campaign_snapshot_digest:
        return "source_snapshot_changed"
    if task.task_type in {
        "candidate_refutation",
        "finding_dedup_and_rank",
        "report_review",
    } and not isinstance(
        payload.get("pipeline_run_id"), str
    ):
        return (
            "candidate_hunter_input_missing"
            if task.task_type == "candidate_refutation"
            else "candidate_hunter_projection_missing"
        )
    if task.task_type not in _HANDLED_WORK_ITEM_TYPES:
        return "runtime_task_handler_unavailable"
    return None


def select_autonomous_research_work(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    now: datetime | None = None,
) -> dict[str, Any]:
    stop_reason = _campaign_stop_reason(campaign, repository, now=now)
    if stop_reason is not None:
        return _blocked(stop_reason)
    payload = campaign.payload if isinstance(campaign.payload, dict) else {}
    source_snapshot_digest = payload.get("source_snapshot_digest")
    if not isinstance(source_snapshot_digest, str) or not _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(
        source_snapshot_digest
    ):
        return _blocked("source_snapshot_digest_required")
    if _has_malformed_runtime_stage(campaign=campaign, repository=repository):
        return _blocked("malformed_runtime_stage")
    if _has_runtime_stage_for_different_source_snapshot(
        campaign=campaign,
        repository=repository,
        source_snapshot_digest=source_snapshot_digest,
    ):
        return _blocked("source_snapshot_changed")
    blocked_stage_stop_reason = _blocked_runtime_stage_stop_reason(
        campaign=campaign,
        repository=repository,
        source_snapshot_digest=source_snapshot_digest,
    )
    if blocked_stage_stop_reason is not None:
        return _blocked(blocked_stage_stop_reason)
    if (
        _runtime_work_item_count(
            campaign=campaign,
            repository=repository,
            source_snapshot_digest=source_snapshot_digest,
        )
        >= _MAX_RUNTIME_WORK_ITEMS_PER_SNAPSHOT
    ):
        return _blocked("snapshot_work_item_limit_reached")
    active_task_stop_reason = _active_runtime_task_stop_reason(
        campaign=campaign,
        repository=repository,
        source_snapshot_digest=source_snapshot_digest,
    )
    if active_task_stop_reason is not None:
        return _blocked(active_task_stop_reason)
    completed_task_types = _completed_runtime_task_types(
        campaign=campaign,
        repository=repository,
        source_snapshot_digest=source_snapshot_digest,
    )
    for work_item in _WORK_ITEMS:
        if work_item["task_type"] not in completed_task_types:
            return {
                "status": "ready",
                **work_item,
                "source_snapshot_digest": source_snapshot_digest,
                **_SAFETY_FIELDS,
            }
    if any(
        task.task_type == "validation_handoff" and task.status == "awaiting_approval"
        for task in repository.list_campaign_tasks(campaign.id)
    ):
        return _blocked("human_review_required")
    return _blocked("source_snapshot_completed")


def _campaign_stop_reason(
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    *,
    now: datetime | None,
    excluding_task_id: str | None = None,
) -> str | None:
    if campaign.autonomy_level != "level_0_read_only":
        return "autonomy_level_not_read_only"
    if campaign.scope_status != "in_scope":
        return "scope_not_in_scope"
    scope_guard_rule = _stored_scope_guard_rule(campaign)
    if scope_guard_rule is None:
        return "scope_guard_rule_missing"
    if scope_guard_rule.asset != campaign.default_asset:
        return "scope_guard_changed"
    if scope_guard_rule.scope_status != "in_scope":
        return "scope_not_in_scope"
    if campaign.program_id is not None:
        resolution = resolve_effective_program_rule(
            repository,
            campaign.program_id,
            campaign.default_asset,
            now or datetime.now(UTC),
        )
        if resolution.source_backed:
            if resolution.reason is not None or resolution.rule is None:
                return resolution.reason or "program_rule_not_authorizing"
            scope_guard_rule = intersect_scope_guard_rules(
                scope_guard_rule,
                resolution.rule,
                asset=campaign.default_asset,
            )
            if scope_guard_rule.scope_status != "in_scope":
                return "scope_not_in_scope"
    if campaign.status == "paused":
        return "campaign_paused"
    if campaign.status == "awaiting_review":
        return "human_review_required"
    if campaign.status in {"blocked", "canceled", "completed", "failed"}:
        return f"campaign_{campaign.status}"
    if campaign.status != "running":
        return "campaign_not_running"
    budget = repository.get_campaign_budget(campaign.id)
    if budget is not None and any(
        value is not None and value <= 0
        for value in (
            budget.time_budget_minutes,
            budget.token_budget,
            budget.tool_call_budget,
        )
    ):
        return "budget_exhausted"
    if (
        budget is not None
        and budget.time_budget_minutes is not None
        and campaign_elapsed_minutes(campaign, now=now) >= budget.time_budget_minutes
    ):
        return "budget_exhausted"
    if (
        budget is not None
        and budget.token_budget is not None
        and campaign_token_used_from_runs(repository.list_campaign_agent_runs(campaign.id))
        >= budget.token_budget
    ):
        return "budget_exhausted"
    if (
        budget is not None
        and budget.tool_call_budget is not None
        and sum(
            run.safety_gate_state == "allowed"
            and (excluding_task_id is None or run.task_id != excluding_task_id)
            for run in repository.list_campaign_agent_runs(campaign.id)
        )
        >= budget.tool_call_budget
    ):
        return "budget_exhausted"
    return None


def _runtime_payload_is_safe(payload: dict[str, Any]) -> bool:
    return (
        all(payload.get(field) is False for field in _SAFETY_FIELDS)
        and not _contains_forbidden_runtime_payload_key(payload)
    )


def _contains_forbidden_runtime_payload_key(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            (
                isinstance(key, str)
                and key.lower() in _FORBIDDEN_RUNTIME_PAYLOAD_KEYS
            )
            or _contains_forbidden_runtime_payload_key(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_forbidden_runtime_payload_key(item) for item in value)
    return False


def _stored_scope_guard_rule(campaign: CampaignRecord) -> ScopeGuardRule | None:
    payload = campaign.payload if isinstance(campaign.payload, dict) else {}
    stored_rule = payload.get("scope_guard_rule")
    if not isinstance(stored_rule, dict):
        return None
    try:
        return ScopeGuardRule.model_validate(stored_rule)
    except ValueError:
        return None


def _has_malformed_runtime_stage(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> bool:
    for stage in repository.list_campaign_pipeline_stages(campaign.id):
        if not stage.stage_key.startswith(_RUNTIME_STAGE_PREFIX):
            continue
        payload = stage.payload
        source_snapshot_digest = (
            payload.get("source_snapshot_digest") if isinstance(payload, dict) else None
        )
        task_type = stage.stage_key.removeprefix(_RUNTIME_STAGE_PREFIX)
        if (
            not isinstance(payload, dict)
            or payload.get("runtime_schema") != _RUNTIME_SCHEMA
            or task_type not in _WORK_ITEM_TYPES
            or not isinstance(source_snapshot_digest, str)
            or not _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest)
            or not _runtime_payload_is_safe(payload)
            or (stage.status == "completed" and stage.safety_gate_state != "allowed")
        ):
            return True
    return False


def _has_runtime_stage_for_different_source_snapshot(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    source_snapshot_digest: str,
) -> bool:
    return any(
        stage.stage_key.startswith(_RUNTIME_STAGE_PREFIX)
        and isinstance(stage.payload, dict)
        and stage.payload.get("runtime_schema") == _RUNTIME_SCHEMA
        and stage.payload.get("source_snapshot_digest") != source_snapshot_digest
        for stage in repository.list_campaign_pipeline_stages(campaign.id)
    )


def _blocked_runtime_stage_stop_reason(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    source_snapshot_digest: str,
) -> str | None:
    blocked_stages = [
        stage
        for stage in repository.list_campaign_pipeline_stages(campaign.id)
        if stage.status == "blocked"
        and stage.stage_key.startswith(_RUNTIME_STAGE_PREFIX)
        and isinstance(stage.payload, dict)
        and stage.payload.get("runtime_schema") == _RUNTIME_SCHEMA
        and stage.payload.get("source_snapshot_digest") == source_snapshot_digest
        and _runtime_payload_is_safe(stage.payload)
    ]
    if not blocked_stages:
        return None
    stop_reason = max(blocked_stages, key=lambda stage: stage.created_at).stop_reason
    if isinstance(stop_reason, str) and _SAFE_STOP_REASON_PATTERN.fullmatch(stop_reason):
        return stop_reason
    return "runtime_task_blocked"


def _runtime_work_item_count(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    source_snapshot_digest: str,
) -> int:
    return sum(
        task.task_type in _WORK_ITEM_TYPES
        and isinstance(task.payload, dict)
        and task.payload.get("runtime_schema") == _RUNTIME_SCHEMA
        and task.payload.get("source_snapshot_digest") == source_snapshot_digest
        and _runtime_payload_is_safe(task.payload)
        for task in repository.list_campaign_tasks(campaign.id)
    )


def _runtime_tick_stop_reason(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    source_snapshot_digest: str,
    now: datetime | None,
) -> str | None:
    runtime_stages = [
        stage
        for stage in repository.list_campaign_pipeline_stages(campaign.id)
        if stage.stage_key.startswith(_RUNTIME_STAGE_PREFIX)
        and isinstance(stage.payload, dict)
        and stage.payload.get("runtime_schema") == _RUNTIME_SCHEMA
        and stage.payload.get("source_snapshot_digest") == source_snapshot_digest
        and _runtime_payload_is_safe(stage.payload)
    ]
    if not runtime_stages:
        return None
    latest_stage = max(runtime_stages, key=lambda stage: stage.created_at)
    if latest_stage.status in {"blocked", "failed"}:
        return None
    latest_created_at = _as_utc(latest_stage.created_at)
    current_time = _as_utc(now or datetime.now(UTC))
    if (current_time - latest_created_at).total_seconds() < _MIN_RUNTIME_TICK_INTERVAL_SECONDS:
        return "tick_not_due"
    return None


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _active_runtime_task_stop_reason(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    source_snapshot_digest: str,
) -> str | None:
    for task in repository.list_campaign_tasks(campaign.id):
        if task.status not in _ACTIVE_TASK_STATUSES:
            continue
        payload = task.payload
        if not isinstance(payload, dict) or payload.get("runtime_schema") != _RUNTIME_SCHEMA:
            continue
        task_source_snapshot_digest = payload.get("source_snapshot_digest")
        if (
            task.task_type not in _WORK_ITEM_TYPES
            or not isinstance(task_source_snapshot_digest, str)
            or not _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(task_source_snapshot_digest)
            or not _runtime_payload_is_safe(payload)
        ):
            return "malformed_runtime_task"
        if task_source_snapshot_digest != source_snapshot_digest:
            return "source_snapshot_changed"
        return "active_runtime_task"
    return None


def _completed_runtime_task_types(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    source_snapshot_digest: str,
) -> set[str]:
    return {
        stage.stage_key.removeprefix(_RUNTIME_STAGE_PREFIX)
        for stage in repository.list_campaign_pipeline_stages(campaign.id)
        if stage.status == "completed"
        and stage.stage_key.startswith(_RUNTIME_STAGE_PREFIX)
        and isinstance(stage.payload, dict)
        and stage.payload.get("runtime_schema") == _RUNTIME_SCHEMA
        and stage.payload.get("source_snapshot_digest") == source_snapshot_digest
    }


def _pipeline_run_id_from_completed_runtime_stage(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    source_snapshot_digest: str,
    prerequisite_task_type: str,
) -> str | None:
    pipeline_run_ids = {
        output_ref.removeprefix("pipeline_run:")
        for stage in repository.list_campaign_pipeline_stages(campaign.id)
        if stage.stage_key == f"{_RUNTIME_STAGE_PREFIX}{prerequisite_task_type}"
        and stage.status == "completed"
        and isinstance(stage.payload, dict)
        and stage.payload.get("runtime_schema") == _RUNTIME_SCHEMA
        and stage.payload.get("source_snapshot_digest") == source_snapshot_digest
        for output_ref in stage.output_refs
        if isinstance(output_ref, str) and output_ref.startswith("pipeline_run:")
    }
    if len(pipeline_run_ids) != 1:
        return None
    pipeline_run_id = next(iter(pipeline_run_ids))
    pipeline_run = repository.get_pipeline_run(pipeline_run_id)
    payload = pipeline_run.payload if pipeline_run is not None else {}
    if (
        pipeline_run is None
        or pipeline_run.asset != campaign.default_asset
        or pipeline_run.scope_status != "in_scope"
        or not isinstance(payload, dict)
        or payload.get("campaign_id") != campaign.id
    ):
        return None
    return pipeline_run.id


def _failed_runtime_task_for_selection(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    task_type: str,
    source_snapshot_digest: str,
) -> CampaignTaskRecord | None:
    idempotency_key = _runtime_idempotency_key(
        campaign_id=campaign.id,
        task_type=task_type,
        source_snapshot_digest=source_snapshot_digest,
        outcome="task",
    )
    return next(
        (
            task
            for task in repository.list_campaign_tasks(campaign.id)
            if task.status == "failed"
            and task.task_type == task_type
            and isinstance(task.payload, dict)
            and task.payload.get("runtime_schema") == _RUNTIME_SCHEMA
            and task.payload.get("idempotency_key") == idempotency_key
        ),
        None,
    )


def _recover_runtime_task_if_needed(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    dispatcher: Callable[..., Any],
    now: datetime | None,
) -> dict[str, Any] | None:
    campaign_payload = campaign.payload if isinstance(campaign.payload, dict) else {}
    source_snapshot_digest = campaign_payload.get("source_snapshot_digest")
    if (
        _campaign_stop_reason(campaign, repository, now=None) is not None
        or not isinstance(source_snapshot_digest, str)
        or not _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest)
    ):
        return None

    runtime_tasks = [
        task
        for task in repository.list_campaign_tasks(campaign.id)
        if isinstance(task.payload, dict)
        and task.payload.get("runtime_schema") == _RUNTIME_SCHEMA
    ]
    claimed_tasks = [
        task for task in runtime_tasks if task.status in {"queued", "ready", "running"}
    ]
    if claimed_tasks:
        task = claimed_tasks[0]
        stop_reason = autonomous_research_task_stop_reason(
            task=task,
            campaign=campaign,
            repository=repository,
        )
        if stop_reason is not None:
            return _tick_result(
                status="blocked",
                campaign_task_id=task.id,
                stop_reason=stop_reason,
                source_snapshot_digest=source_snapshot_digest,
            )
        if any(
            run.task_id == task.id
            for run in repository.list_campaign_agent_runs(campaign.id)
        ) or any(
            stage.task_id == task.id
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
        ):
            return _tick_result(
                status="awaiting_evidence",
                campaign_task_id=task.id,
                stop_reason="recovery_dispatch_state_ambiguous",
                source_snapshot_digest=source_snapshot_digest,
            )
        tick_stop_reason = _runtime_tick_stop_reason(
            campaign=campaign,
            repository=repository,
            source_snapshot_digest=source_snapshot_digest,
            now=now,
        )
        if tick_stop_reason is not None:
            return _tick_result(
                status="blocked",
                campaign_task_id=task.id,
                stop_reason=tick_stop_reason,
                source_snapshot_digest=source_snapshot_digest,
            )
        return _dispatch_runtime_task(
            campaign=campaign,
            task=task,
            source_snapshot_digest=source_snapshot_digest,
            repository=repository,
            dispatcher=dispatcher,
        )

    for task in runtime_tasks:
        if task.status != "completed":
            continue
        task_payload = task.payload
        task_source_snapshot_digest = task_payload.get("source_snapshot_digest")
        if (
            task.task_type not in _WORK_ITEM_TYPES
            or not isinstance(task_source_snapshot_digest, str)
            or not _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(task_source_snapshot_digest)
            or not _runtime_payload_is_safe(task_payload)
        ):
            return _tick_result(
                status="blocked",
                campaign_task_id=task.id,
                stop_reason="malformed_runtime_task",
                source_snapshot_digest=source_snapshot_digest,
            )
        if task_source_snapshot_digest != source_snapshot_digest:
            return _tick_result(
                status="blocked",
                campaign_task_id=task.id,
                stop_reason="source_snapshot_changed",
                source_snapshot_digest=source_snapshot_digest,
            )
        if any(
            stage.task_id == task.id
            and stage.stage_key == f"{_RUNTIME_STAGE_PREFIX}{task.task_type}"
            and stage.status == "completed"
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
        ):
            continue
        if not any(
            run.task_id == task.id
            and run.status == "completed"
            and run.safety_gate_state == "allowed"
            for run in repository.list_campaign_agent_runs(campaign.id)
        ):
            return _tick_result(
                status="blocked",
                campaign_task_id=task.id,
                stop_reason="completion_recovery_integrity_invalid",
                source_snapshot_digest=source_snapshot_digest,
            )
        record_autonomous_research_task_completion(task=task, repository=repository)
        return _tick_result(
            status="completed",
            campaign_task_id=task.id,
            stop_reason=None,
            source_snapshot_digest=source_snapshot_digest,
        )
    return None


def _dispatch_queued_local_evidence_task_if_needed(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    dispatcher: Callable[..., Any],
    now: datetime | None,
) -> dict[str, Any] | None:
    if _campaign_stop_reason(campaign, repository, now=now) is not None:
        return None
    campaign_payload = campaign.payload if isinstance(campaign.payload, dict) else {}
    source_snapshot_digest = campaign_payload.get("source_snapshot_digest")
    if not isinstance(source_snapshot_digest, str) or not _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(
        source_snapshot_digest
    ):
        return None

    tasks = repository.list_campaign_tasks(campaign.id)
    for owner_task in tasks:
        if (
            owner_task.task_type != "candidate_refutation"
            or owner_task.status not in {"awaiting_evidence", "needs_evidence"}
        ):
            continue
        owner_payload = owner_task.payload
        if (
            not isinstance(owner_payload, dict)
            or owner_payload.get("runtime_schema") != _RUNTIME_SCHEMA
            or owner_payload.get("source_snapshot_digest") != source_snapshot_digest
            or not _runtime_payload_is_safe(owner_payload)
        ):
            return None

        queued_evidence_tasks = [
            task
            for task in tasks
            if task.task_type == _EVIDENCE_TASK_TYPE
            and task.status == "queued"
            and isinstance(task.payload, dict)
            and task.payload.get("owner_task_id") == owner_task.id
        ]
        if not queued_evidence_tasks:
            continue
        if len(queued_evidence_tasks) != 1:
            return _block_runtime_owner_for_evidence(
                owner_task=owner_task,
                evidence_task_id=None,
                stop_reason="evidence_task_integrity_invalid",
                repository=repository,
                source_snapshot_digest=source_snapshot_digest,
            )

        evidence_task = queued_evidence_tasks[0]
        if not _evidence_task_matches_runtime_owner(
            evidence_task=evidence_task,
            owner_task=owner_task,
            source_snapshot_digest=source_snapshot_digest,
        ):
            return _block_runtime_owner_for_evidence(
                owner_task=owner_task,
                evidence_task_id=evidence_task.id,
                stop_reason="evidence_task_integrity_invalid",
                repository=repository,
                source_snapshot_digest=source_snapshot_digest,
            )

        tick_stop_reason = _runtime_tick_stop_reason(
            campaign=campaign,
            repository=repository,
            source_snapshot_digest=source_snapshot_digest,
            now=now,
        )
        if tick_stop_reason is not None:
            return _tick_result(
                status="blocked",
                campaign_task_id=evidence_task.id,
                stop_reason=tick_stop_reason,
                source_snapshot_digest=source_snapshot_digest,
            )
        return _dispatch_queued_local_evidence_task(
            campaign=campaign,
            owner_task=owner_task,
            evidence_task=evidence_task,
            source_snapshot_digest=source_snapshot_digest,
            repository=repository,
            dispatcher=dispatcher,
        )
    return None


def _evidence_task_matches_runtime_owner(
    *,
    evidence_task: CampaignTaskRecord,
    owner_task: CampaignTaskRecord,
    source_snapshot_digest: str,
) -> bool:
    payload = evidence_task.payload
    if not isinstance(payload, dict):
        return False
    expected_snapshot_digest = source_snapshot_digest.removeprefix("sha256:")
    evidence_snapshot_digest = payload.get("source_snapshot_digest")
    return (
        payload.get("schema_version") == _EVIDENCE_TASK_SCHEMA
        and payload.get("owner_task_id") == owner_task.id
        and payload.get("pipeline_run_id") == owner_task.payload.get("pipeline_run_id")
        and isinstance(evidence_snapshot_digest, str)
        and evidence_snapshot_digest.lower() == expected_snapshot_digest
        and isinstance(payload.get("evidence_request_stage_id"), str)
        and isinstance(payload.get("state_digest"), str)
        and isinstance(payload.get("round"), int)
        and not isinstance(payload.get("round"), bool)
        and payload.get("round") > 0
        and all(
            payload.get(field) is False
            for field in _SAFETY_FIELDS
            if field != "raw_payload_in_dispatch"
        )
    )


def _dispatch_queued_local_evidence_task(
    *,
    campaign: CampaignRecord,
    owner_task: CampaignTaskRecord,
    evidence_task: CampaignTaskRecord,
    source_snapshot_digest: str,
    repository: DatabaseRepository,
    dispatcher: Callable[..., Any],
) -> dict[str, Any]:
    repository.update_campaign_task_status(evidence_task.id, "dispatched")
    try:
        dispatcher(campaign_task_id=evidence_task.id)
    except Exception:
        repository.update_campaign_task_status(evidence_task.id, "failed")
        return _block_runtime_owner_for_evidence(
            owner_task=owner_task,
            evidence_task_id=evidence_task.id,
            stop_reason="dispatch_failed",
            repository=repository,
            source_snapshot_digest=source_snapshot_digest,
        )
    return _tick_result(
        status="dispatched",
        campaign_task_id=evidence_task.id,
        stop_reason=None,
        source_snapshot_digest=source_snapshot_digest,
    )


def _block_runtime_owner_for_evidence(
    *,
    owner_task: CampaignTaskRecord,
    evidence_task_id: str | None,
    stop_reason: str,
    repository: DatabaseRepository,
    source_snapshot_digest: str,
) -> dict[str, Any]:
    output_refs = [ref for ref in owner_task.output_refs if isinstance(ref, str)]
    if evidence_task_id is not None:
        evidence_ref = f"campaign_task:{evidence_task_id}"
        if evidence_ref not in output_refs:
            output_refs.append(evidence_ref)
    blocked_owner_task = repository.update_campaign_task_status(
        owner_task.id,
        "blocked",
        output_refs=output_refs,
    )
    if blocked_owner_task is not None:
        record_autonomous_research_task_blocked(
            task=blocked_owner_task,
            repository=repository,
            stop_reason=stop_reason,
        )
    return _tick_result(
        status="blocked",
        campaign_task_id=evidence_task_id or owner_task.id,
        stop_reason=stop_reason,
        source_snapshot_digest=source_snapshot_digest,
    )


def _dispatch_runtime_task(
    *,
    campaign: CampaignRecord,
    task: CampaignTaskRecord,
    source_snapshot_digest: str,
    repository: DatabaseRepository,
    dispatcher: Callable[..., Any],
) -> dict[str, Any]:
    task_type = task.task_type
    dispatch_attempt = _dispatch_attempt(
        repository=repository,
        campaign_id=campaign.id,
        task_id=task.id,
    )
    agent_run = repository.save_agent_run(
        campaign_id=campaign.id,
        task_id=task.id,
        agent_type=task.agent_type,
        status="dispatched",
        input_refs=[f"campaign_task:{task.id}"],
        output_refs=[],
        tool_calls=[],
        safety_gate_state="allowed",
        stop_reason=None,
        payload={
            "runtime_schema": _RUNTIME_SCHEMA,
            "source_snapshot_digest": source_snapshot_digest,
            "dispatch_contract": "id_only",
            **_SAFETY_FIELDS,
        },
    )
    repository.save_pipeline_stage(
        pipeline_run_id=None,
        campaign_id=campaign.id,
        task_id=task.id,
        stage_key=f"{_RUNTIME_STAGE_PREFIX}{task_type}",
        stage_order=_stage_order_for(task_type),
        status="dispatched",
        input_refs=task.input_refs,
        output_refs=[f"campaign_task:{task.id}", f"agent_run:{agent_run.id}"],
        safety_gate_state="allowed",
        stop_reason=None,
        payload=_runtime_stage_payload(
            campaign_id=campaign.id,
            task_type=task_type,
            source_snapshot_digest=source_snapshot_digest,
            outcome=_dispatch_stage_outcome(dispatch_attempt),
        ),
    )
    repository.update_campaign_task_status(task.id, "dispatched")
    try:
        dispatcher(campaign_task_id=task.id)
    except Exception:
        repository.finish_agent_run(
            agent_run.id,
            status="failed",
            output_refs=[],
            safety_gate_state="blocked",
            stop_reason="dispatch_failed",
            payload={
                "runtime_schema": _RUNTIME_SCHEMA,
                "source_snapshot_digest": source_snapshot_digest,
                "dispatch_contract": "id_only",
                **_SAFETY_FIELDS,
            },
        )
        repository.update_campaign_task_status(
            task.id,
            "failed",
            output_refs=[f"agent_run:{agent_run.id}"],
        )
        repository.save_pipeline_stage(
            pipeline_run_id=None,
            campaign_id=campaign.id,
            task_id=task.id,
            stage_key=f"{_RUNTIME_STAGE_PREFIX}{task_type}",
            stage_order=_stage_order_for(task_type),
            status="failed",
            input_refs=task.input_refs,
            output_refs=[f"agent_run:{agent_run.id}"],
            safety_gate_state="blocked",
            stop_reason="dispatch_failed",
            payload=_runtime_stage_payload(
                campaign_id=campaign.id,
                task_type=task_type,
                source_snapshot_digest=source_snapshot_digest,
                outcome=_dispatch_failure_stage_outcome(dispatch_attempt),
            ),
        )
        return _tick_result(
            status="blocked",
            campaign_task_id=task.id,
            stop_reason="dispatch_failed",
            source_snapshot_digest=source_snapshot_digest,
        )

    return _tick_result(
        status="dispatched",
        campaign_task_id=task.id,
        stop_reason=None,
        source_snapshot_digest=source_snapshot_digest,
    )


def _dispatch_attempt(
    *,
    repository: DatabaseRepository,
    campaign_id: str,
    task_id: str,
) -> int:
    return 1 + sum(
        run.task_id == task_id
        for run in repository.list_campaign_agent_runs(campaign_id)
    )


def _dispatch_stage_outcome(dispatch_attempt: int) -> str:
    if dispatch_attempt == 1:
        return "dispatched"
    return f"retry_dispatched_{dispatch_attempt}"


def _dispatch_failure_stage_outcome(dispatch_attempt: int) -> str:
    if dispatch_attempt == 1:
        return "dispatch_failed"
    return f"retry_dispatch_failed_{dispatch_attempt}"


def _runtime_task_payload(
    *,
    campaign_id: str,
    task_type: str,
    source_snapshot_digest: str,
    pipeline_run_id: str | None = None,
) -> dict[str, Any]:
    payload = {
        "runtime_schema": _RUNTIME_SCHEMA,
        "source_snapshot_digest": source_snapshot_digest,
        "idempotency_key": _runtime_idempotency_key(
            campaign_id=campaign_id,
            task_type=task_type,
            source_snapshot_digest=source_snapshot_digest,
            outcome="task",
        ),
        "dispatch_contract": "id_only",
        "raw_payload_in_dispatch": False,
        **_SAFETY_FIELDS,
    }
    if pipeline_run_id is not None:
        payload["pipeline_run_id"] = pipeline_run_id
    return payload


def _runtime_stage_payload(
    *,
    campaign_id: str,
    task_type: str,
    source_snapshot_digest: str,
    outcome: str,
) -> dict[str, Any]:
    return {
        "runtime_schema": _RUNTIME_SCHEMA,
        "source_snapshot_digest": source_snapshot_digest,
        "idempotency_key": _runtime_idempotency_key(
            campaign_id=campaign_id,
            task_type=task_type,
            source_snapshot_digest=source_snapshot_digest,
            outcome=outcome,
        ),
        "dispatch_contract": "id_only",
        "raw_payload_in_dispatch": False,
        **_SAFETY_FIELDS,
    }


def _runtime_idempotency_key(
    *,
    campaign_id: str,
    task_type: str,
    source_snapshot_digest: str,
    outcome: str,
) -> str:
    identity = ":".join(
        (campaign_id, source_snapshot_digest, task_type, outcome)
    )
    return f"sha256:{sha256(identity.encode('utf-8')).hexdigest()}"


def _runtime_task_id(
    *,
    campaign_id: str,
    task_type: str,
    source_snapshot_digest: str,
) -> str:
    identity = ":".join((campaign_id, source_snapshot_digest, task_type))
    return f"campaign_task_runtime_{sha256(identity.encode('utf-8')).hexdigest()}"


def _stage_order_for(task_type: str) -> int:
    return next(
        index
        for index, work_item in enumerate(_WORK_ITEMS)
        if work_item["task_type"] == task_type
    )


def _tick_stop_status(stop_reason: str) -> str:
    if stop_reason == "active_runtime_task":
        return "awaiting_evidence"
    if stop_reason == "human_review_required":
        return "awaiting_review"
    if stop_reason == "source_snapshot_completed":
        return "completed"
    return "blocked"


def _tick_result(
    *,
    status: str,
    campaign_task_id: str | None = None,
    stop_reason: str | None,
    source_snapshot_digest: str | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "campaign_task_id": campaign_task_id,
        "stop_reason": stop_reason,
        "source_snapshot_digest": source_snapshot_digest,
        **_SAFETY_FIELDS,
    }


def _blocked(stop_reason: str) -> dict[str, Any]:
    return {
        "status": "blocked",
        "stop_reason": stop_reason,
        "task_type": None,
        "source_snapshot_digest": None,
        **_SAFETY_FIELDS,
    }


__all__ = [
    "select_autonomous_research_work",
    "tick_autonomous_research_campaign",
]
