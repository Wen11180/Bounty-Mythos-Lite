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
