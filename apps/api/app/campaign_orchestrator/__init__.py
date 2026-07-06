from collections.abc import Callable
from typing import Any

from app.db_models import CampaignRecord
from app.repository import DatabaseRepository


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

    dispatched_task_ids: list[str] = []
    for stage_order, task_spec in enumerate(READ_ONLY_RESEARCH_TASKS):
        task = repository.create_campaign_task(
            campaign_id=campaign.id,
            task_type=task_spec["task_type"],
            agent_type=task_spec["agent_type"],
            title=task_spec["title"],
            input_refs=[f"campaign:{campaign.id}"],
            payload={
                "mode": "read_only",
                "raw_payload_in_dispatch": False,
            },
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
        dispatcher(campaign_task_id=task.id)
        dispatched_task_ids.append(task.id)

    return {
        "status": "dispatched",
        "dispatched_task_ids": dispatched_task_ids,
        "stop_reasons": [],
    }


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
    return None


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
    hypothesis_output_refs = [
        ref
        for task in tasks
        if task.task_type == "hypothesis_generation"
        for ref in task.output_refs
        if ref.startswith("pipeline_run:")
    ]
    codebase_facts = repository.list_campaign_codebase_facts(campaign.id)

    pending_approvals = [
        approval for approval in approvals
        if approval.status in {"pending", "requested"}
    ]
    awaiting_validation_runs = [
        run for run in validation_runs
        if run.approval_required
        and not run.allowed_to_execute
        and (
            run.status == "awaiting_approval"
            or run.safety_gate_state == "awaiting_approval"
        )
    ]
    manual_evidence_runs = [
        run for run in validation_runs
        if _validation_run_has_manual_evidence(run)
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
    return (
        run.status in {"evidence_recorded", "refuted", "needs_evidence"}
        or run.evidence_ref_count > 0
        or str(run.safety_gate_state).startswith("manual_")
    )
