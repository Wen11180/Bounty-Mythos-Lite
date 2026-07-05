from collections.abc import Callable
from typing import Any

from app.db_models import CampaignRecord
from app.repository import DatabaseRepository


DispatchCampaignTask = Callable[..., Any]


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

    task = repository.create_campaign_task(
        campaign_id=campaign.id,
        task_type="campaign_observation",
        agent_type="orchestrator_agent",
        title="Observe authorized campaign state",
        input_refs=[f"campaign:{campaign.id}"],
        payload={
            "mode": "read_only",
            "raw_payload_in_dispatch": False,
        },
    )
    repository.save_agent_run(
        campaign_id=campaign.id,
        task_id=task.id,
        agent_type="orchestrator_agent",
        status="dispatched",
        input_refs=[f"campaign_task:{task.id}"],
        output_refs=[],
        tool_calls=[],
        safety_gate_state="allowed",
        stop_reason=None,
        payload={"dispatch_contract": "id_only"},
    )

    dispatcher(campaign_task_id=task.id)
    return {
        "status": "dispatched",
        "dispatched_task_ids": [task.id],
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
