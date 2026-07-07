from collections.abc import Callable
from typing import Any

from app.db_models import ApprovalRecord, CampaignRecord
from app.repository import DatabaseRepository, approval_record_is_active


DispatchCampaignTask = Callable[..., Any]

READ_ONLY_RESEARCH_TASKS = [
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
        "task_type": "report_chain_review",
        "agent_type": "report_agent",
        "title": "Review report-chain readiness gates",
    },
]
ACTIVE_TASK_STATUSES = {
    "queued",
    "ready",
    "dispatched",
    "running",
    "awaiting_approval",
}
READ_ONLY_RESEARCH_TASK_TYPES = {
    task["task_type"] for task in READ_ONLY_RESEARCH_TASKS
}


def tick_campaign(
    campaign_id: str,
    *,
    repository: DatabaseRepository,
    dispatcher: DispatchCampaignTask,
) -> dict:
    campaign = repository.get_campaign(campaign_id)
    if campaign is None:
        return {
            "status": "not_found",
            "dispatched_task_ids": [],
            "stop_reasons": ["campaign_not_found"],
        }

    stop_reason = _campaign_stop_reason(campaign, repository)
    if stop_reason is not None:
        repository.save_pipeline_stage(
            pipeline_run_id=None,
            campaign_id=campaign.id,
            task_id=None,
            stage_key="campaign_tick",
            stage_order=0,
            status="paused" if stop_reason == "campaign_paused" else "blocked",
            input_refs=[f"campaign:{campaign.id}"],
            output_refs=[],
            safety_gate_state="blocked",
            stop_reason=stop_reason,
            payload={"dispatch": "not_started"},
        )
        return {
            "status": "paused" if stop_reason == "campaign_paused" else "blocked",
            "dispatched_task_ids": [],
            "stop_reasons": [stop_reason],
        }

    active_tasks = [
        task for task in repository.list_campaign_tasks(campaign.id)
        if task.status in ACTIVE_TASK_STATUSES
    ]
    if active_tasks:
        return {
            "status": "active_tasks_exist",
            "dispatched_task_ids": [],
            "stop_reasons": ["active_tasks_exist"],
        }

    review_gate = _completed_research_cycle_review(campaign, repository)
    if review_gate is not None:
        return review_gate

    remaining_tool_calls = _remaining_tool_call_budget(campaign, repository)
    task_specs = (
        READ_ONLY_RESEARCH_TASKS
        if remaining_tool_calls is None
        else READ_ONLY_RESEARCH_TASKS[:remaining_tool_calls]
    )

    dispatched_task_ids: list[str] = []
    for stage_order, task_spec in enumerate(task_specs):
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type=task_spec["task_type"],
            agent_type=task_spec["agent_type"],
            title=task_spec["title"],
            input_refs=[f"campaign:{campaign.id}"],
            payload=_read_only_task_payload(campaign, task_spec["task_type"]),
        )
        repository.save_agent_run(
            campaign_id=campaign.id,
            task_id=task.id,
            agent_type=task_spec["agent_type"],
            status="dispatched",
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=[],
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={"dispatch_contract": "id_only"},
        )
        repository.save_pipeline_stage(
            pipeline_run_id=None,
            campaign_id=campaign.id,
            task_id=task.id,
            stage_key=task_spec["task_type"],
            stage_order=stage_order,
            status="dispatched",
            input_refs=[f"campaign:{campaign.id}"],
            output_refs=[f"campaign_task:{task.id}"],
            safety_gate_state="allowed",
            stop_reason=None,
            payload={"dispatch_contract": "id_only"},
        )
        repository.update_campaign_task_status(task.id, "dispatched")
        dispatcher(campaign_task_id=task.id)
        dispatched_task_ids.append(task.id)

    partial_dispatch = len(task_specs) < len(READ_ONLY_RESEARCH_TASKS)
    if partial_dispatch:
        repository.save_pipeline_stage(
            pipeline_run_id=None,
            campaign_id=campaign.id,
            task_id=None,
            stage_key="campaign_tick",
            stage_order=len(dispatched_task_ids),
            status="blocked",
            input_refs=[f"campaign:{campaign.id}"],
            output_refs=[f"campaign_task:{task_id}" for task_id in dispatched_task_ids],
            safety_gate_state="blocked",
            stop_reason="budget_exhausted",
            payload={
                "dispatch": "partially_dispatched",
                "reserved_task_count": len(dispatched_task_ids),
                "remaining_task_count": len(READ_ONLY_RESEARCH_TASKS) - len(dispatched_task_ids),
            },
        )

    return {
        "status": "partially_dispatched" if partial_dispatch else "dispatched",
        "dispatched_task_ids": dispatched_task_ids,
        "stop_reasons": ["budget_exhausted"] if partial_dispatch else [],
    }


def _read_only_task_payload(campaign: CampaignRecord, task_type: str) -> dict:
    payload = {
        "mode": "read_only",
        "raw_payload_in_dispatch": False,
    }
    campaign_payload = campaign.payload if isinstance(campaign.payload, dict) else {}
    authorized_code_files = campaign_payload.get("authorized_code_files")
    if task_type == "attack_surface_mapping" and isinstance(authorized_code_files, list):
        payload["authorized_code_files"] = authorized_code_files
    return payload


def _campaign_stop_reason(
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> str | None:
    if campaign.scope_status != "in_scope":
        return "scope_not_in_scope"
    if campaign.status == "paused":
        return "campaign_paused"
    if campaign.status in {"blocked", "canceled", "completed", "failed"}:
        return f"campaign_{campaign.status}"
    if campaign.status != "running":
        return "campaign_not_running"

    budget = repository.get_campaign_budget(campaign.id)
    if budget is None:
        return None
    budgets = [
        budget.time_budget_minutes,
        budget.token_budget,
        budget.tool_call_budget,
        budget.validation_budget,
    ]
    if any(value is not None and value <= 0 for value in budgets):
        return "budget_exhausted"
    remaining_tool_calls = _remaining_tool_call_budget(campaign, repository)
    if remaining_tool_calls is not None and remaining_tool_calls <= 0:
        return "budget_exhausted"
    return None


def _remaining_tool_call_budget(
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> int | None:
    budget = repository.get_campaign_budget(campaign.id)
    if budget is None or budget.tool_call_budget is None:
        return None
    reserved_or_used = sum(
        1
        for run in repository.list_campaign_agent_runs(campaign.id)
        if run.safety_gate_state == "allowed"
    )
    return budget.tool_call_budget - reserved_or_used


def _completed_research_cycle_review(
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> dict | None:
    tasks = repository.list_campaign_tasks(campaign.id)
    completed_task_types = {
        task.task_type
        for task in tasks
        if task.status == "completed" and task.task_type in READ_ONLY_RESEARCH_TASK_TYPES
    }
    if completed_task_types != READ_ONLY_RESEARCH_TASK_TYPES:
        return None

    approvals = repository.list_campaign_approval_records(campaign.id)
    validation_runs = repository.list_campaign_validation_runs(campaign.id)
    reviewed_output_refs = _completed_cycle_review_output_refs(campaign, repository)
    hypothesis_output_refs = [
        ref
        for task in tasks
        if task.task_type == "hypothesis_generation"
        for ref in task.output_refs
        if ref.startswith("pipeline_run:")
        and ref not in reviewed_output_refs
    ]
    codebase_facts = [
        fact
        for fact in repository.list_campaign_codebase_facts(campaign.id)
        if f"codebase_fact:{fact.id}" not in reviewed_output_refs
    ]

    pending_approvals = [
        approval for approval in approvals
        if approval.status in {"pending", "requested"}
        and approval_record_is_active(approval)
        and f"approval:{approval.id}" not in reviewed_output_refs
    ]
    awaiting_validation_runs = [
        run for run in validation_runs
        if _validation_run_needs_human_review(run, repository)
        and f"validation_run:{run.id}" not in reviewed_output_refs
    ]
    manual_evidence_runs = [
        run for run in validation_runs
        if _validation_run_has_manual_evidence(run)
        and f"validation_run:{run.id}" not in reviewed_output_refs
    ]

    next_actions: list[str] = []
    stop_reasons: list[str] = []
    if pending_approvals:
        next_actions.append("review_approval_queue")
        stop_reasons.append("approval_required")
    if awaiting_validation_runs:
        next_actions.append("review_validation_queue")
        stop_reasons.append("validation_approval_required")
    if manual_evidence_runs:
        next_actions.append("review_evidence_or_report_drafts")
    if hypothesis_output_refs:
        next_actions.append("review_hypothesis_board")
    if codebase_facts:
        next_actions.append("review_attack_surface_map")

    if not next_actions:
        return None

    stop_reason = (
        "validation_approval_required"
        if awaiting_validation_runs
        else stop_reasons[0] if stop_reasons else "campaign_cycle_review_required"
    )
    safety_gate_state = "awaiting_approval" if stop_reasons else "allowed"
    output_refs = [
        *[f"approval:{approval.id}" for approval in pending_approvals],
        *[f"validation_run:{run.id}" for run in awaiting_validation_runs],
        *[f"validation_run:{run.id}" for run in manual_evidence_runs],
        *hypothesis_output_refs,
        *[f"codebase_fact:{fact.id}" for fact in codebase_facts],
    ]
    payload = {
        "review_gate": "human_review_required",
        "completed_task_types": sorted(completed_task_types),
        "pending_approval_count": len(pending_approvals),
        "awaiting_validation_count": len(awaiting_validation_runs),
        "manual_evidence_count": len(manual_evidence_runs),
        "hypothesis_ref_count": len(hypothesis_output_refs),
        "codebase_fact_count": len(codebase_facts),
        "next_actions": next_actions,
    }
    existing_review_stages = [
        stage for stage in repository.list_campaign_pipeline_stages(campaign.id)
        if stage.stage_key == "campaign_cycle_review"
        and stage.status == "awaiting_review"
    ]
    if not existing_review_stages:
        repository.save_pipeline_stage(
            pipeline_run_id=None,
            campaign_id=campaign.id,
            task_id=None,
            stage_key="campaign_cycle_review",
            stage_order=len(READ_ONLY_RESEARCH_TASKS),
            status="awaiting_review",
            input_refs=[f"campaign:{campaign.id}"],
            output_refs=output_refs,
            safety_gate_state=safety_gate_state,
            stop_reason=stop_reason,
            payload=payload,
        )

    return {
        "status": "awaiting_review",
        "dispatched_task_ids": [],
        "stop_reasons": stop_reasons or ["campaign_cycle_review_required"],
        "next_actions": next_actions,
    }


def _validation_run_has_manual_evidence(run: Any) -> bool:
    payload = getattr(run, "payload", None)
    return isinstance(payload, dict) and isinstance(payload.get("manual_result"), dict)


def _validation_run_needs_human_review(
    run: Any,
    repository: DatabaseRepository,
) -> bool:
    return (
        bool(getattr(run, "approval_required", False))
        and not _validation_run_currently_allowed_to_execute(run, repository)
        and (
            getattr(run, "status", None) in {"awaiting_approval", "ready", "preflight_passed"}
            or getattr(run, "safety_gate_state", None)
            in {
                "awaiting_approval",
                "approved_validation_record",
                "scope_guard_preflight_passed",
            }
        )
    )


def _validation_run_currently_allowed_to_execute(
    run: Any,
    repository: DatabaseRepository,
) -> bool:
    if getattr(run, "status", None) != "preflight_passed":
        return False
    if not bool(getattr(run, "allowed_to_execute", False)):
        return False
    campaign = repository.get_campaign(getattr(run, "campaign_id", ""))
    if campaign is None or campaign.scope_status != "in_scope":
        return False
    if not bool(getattr(run, "approval_required", False)):
        return True

    approval_id = getattr(run, "approval_id", None)
    if approval_id is None:
        return False
    approval = repository.session.get(ApprovalRecord, approval_id)
    return approval is not None and _validation_run_approval_matches(
        approval,
        run,
        campaign,
    )


def _validation_run_approval_matches(
    approval: ApprovalRecord,
    run: Any,
    campaign: CampaignRecord | None,
) -> bool:
    if campaign is None or campaign.scope_status != "in_scope":
        return False
    target_ref = getattr(run, "target_ref", "")
    asset = campaign.default_asset if target_ref == f"campaign:{campaign.id}" else target_ref
    return (
        approval.status == "approved"
        and approval_record_is_active(approval)
        and approval.campaign_id == campaign.id
        and approval.task_id == getattr(run, "task_id", None)
        and approval.asset == asset
        and approval.validation_mode == getattr(run, "validation_mode", None)
        and approval.plan_digest == getattr(run, "plan_digest", None)
        and _approval_scope_reference_matches(approval, run)
        and _approval_allowed_accounts_match(approval, run)
    )


def _approval_scope_reference_matches(approval: ApprovalRecord, run: Any) -> bool:
    if approval.scope_reference is None:
        return True
    payload = getattr(run, "payload", None)
    if not isinstance(payload, dict):
        return False
    return payload.get("scope_reference") == approval.scope_reference


def _approval_allowed_accounts_match(approval: ApprovalRecord, run: Any) -> bool:
    approval_accounts = _payload_string_set(approval.payload, "allowed_accounts")
    if not approval_accounts:
        return True
    payload = getattr(run, "payload", None)
    validation_accounts = _payload_string_set(payload, "allowed_accounts")
    return bool(validation_accounts) and validation_accounts <= approval_accounts


def _payload_string_set(payload: Any, key: str) -> set[str]:
    values = payload.get(key) if isinstance(payload, dict) else None
    if not isinstance(values, list):
        return set()
    return {value for value in values if isinstance(value, str) and value}


def _completed_cycle_review_output_refs(
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> set[str]:
    return {
        ref
        for stage in repository.list_campaign_pipeline_stages(campaign.id)
        if stage.stage_key == "campaign_cycle_review"
        and stage.status == "completed"
        and stage.safety_gate_state == "allowed"
        for ref in stage.output_refs
    }
