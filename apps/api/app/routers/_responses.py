"""ORM record → Pydantic response converters.

Extracted from main.py so that all router modules can import them without
circular dependencies. No route handlers live here — only pure projection
functions that take a DB record and return a response model.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from app.db_models import (
    AgentRunRecord,
    ApprovalRecord,
    ArtifactRecord,
    CampaignBudgetRecord,
    CampaignRecord,
    CampaignTaskRecord,
    CodebaseFactRecord,
    CodebaseMapRecord,
    LearningSignalRecord,
    PipelineStageRecord,
    ScannerRunRecord,
    ValidationRunRecord,
)
from app.mythos_brain import LearningSignal
from app.mythos_report import safe_preview_text, safe_string_list
from app.repository import DatabaseRepository
from app.campaign_orchestrator import campaign_elapsed_minutes, campaign_token_used_from_runs
from app.schemas import (
    AgentRunResponse,
    ApprovalRecordResponse,
    ArtifactResponse,
    CampaignBudgetResponse,
    CampaignResponse,
)

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# Approval
# ---------------------------------------------------------------------------

def approval_record_response(record: ApprovalRecord):
    return ApprovalRecordResponse(
        id=record.id,
        campaign_id=record.campaign_id,
        task_id=record.task_id,
        run_id=record.run_id,
        program_id=record.program_id,
        approval_type=record.approval_type,
        actor=record.actor,
        reason=record.reason,
        scope_reference=record.scope_reference,
        requested_action=record.requested_action,
        asset=record.asset,
        validation_mode=record.validation_mode,
        plan_digest=record.plan_digest,
        autonomy_level=record.autonomy_level,
        safety_gate_state=record.safety_gate_state,
        status=record.status,
        decision_reason=record.decision_reason,
        decided_by=record.decided_by,
        decided_at=record.decided_at.isoformat() if record.decided_at else None,
        expires_at=record.expires_at.isoformat() if record.expires_at else None,
        created_at=record.created_at.isoformat(),
    )


# ---------------------------------------------------------------------------
# Artifact
# ---------------------------------------------------------------------------

def _artifact_safety(record: ArtifactRecord) -> dict[str, Any]:
    safety = record.provenance.get("safety")
    if not isinstance(safety, dict):
        return {
            "sensitivity_label": "unknown",
            "redaction_status": "unknown",
            "report_chain_allowed": False,
            "safety_blockers": ["missing_safety_metadata"],
        }
    blockers = safety.get("safety_blockers", [])
    known_blockers = {
        "contains_secret_like_value",
        "contains_real_user_data_risk",
        "missing_safety_metadata",
    }
    return {
        "sensitivity_label": safe_preview_text(safety.get("sensitivity_label", "unknown")),
        "redaction_status": safe_preview_text(safety.get("redaction_status", "unknown")),
        "report_chain_allowed": safety.get("report_chain_allowed") is True,
        "safety_blockers": [
            b if b in known_blockers else safe_preview_text(b)
            for b in (blockers if isinstance(blockers, list) else [])
        ],
    }


def _artifact_usage_records(record: ArtifactRecord) -> list[dict]:
    usage_records = record.provenance.get("usage_records", [])
    if not isinstance(usage_records, list):
        return []
    return [u for u in usage_records if isinstance(u, dict)]


def artifact_response(record: ArtifactRecord):
    safety = _artifact_safety(record)
    return ArtifactResponse(
        id=record.id,
        program_id=record.program_id,
        asset=record.asset,
        kind=record.kind,
        source_type=record.source_type,
        source_hash=record.source_hash,
        ingestion_status=record.ingestion_status,
        provenance=record.provenance,
        payload_summary=record.payload_summary,
        derived_facts=record.derived_facts,
        sensitivity_label=safety["sensitivity_label"],
        redaction_status=safety["redaction_status"],
        report_chain_allowed=safety["report_chain_allowed"],
        safety_blockers=safety["safety_blockers"],
        usage_records=_artifact_usage_records(record),
        created_at=record.created_at.isoformat(),
    )


# ---------------------------------------------------------------------------
# Campaign
# ---------------------------------------------------------------------------

def campaign_budget_response(
    record: CampaignBudgetRecord | None,
    *,
    repository: DatabaseRepository | None = None,
):
    if record is None:
        return None
    campaign = repository.get_campaign(record.campaign_id) if repository is not None else None
    agent_runs = (
        repository.list_campaign_agent_runs(record.campaign_id)
        if repository is not None
        else []
    )
    time_budget_used = round(campaign_elapsed_minutes(campaign), 2) if campaign is not None else 0
    time_budget_remaining = (
        None
        if record.time_budget_minutes is None
        else max(record.time_budget_minutes - time_budget_used, 0)
    )
    token_budget_used = campaign_token_used_from_runs(agent_runs)
    token_budget_remaining = (
        None if record.token_budget is None
        else max(record.token_budget - token_budget_used, 0)
    )
    tool_call_used = (
        _campaign_tool_call_used(record.campaign_id, repository)
        if repository is not None else 0
    )
    tool_call_remaining = (
        None if record.tool_call_budget is None
        else max(record.tool_call_budget - tool_call_used, 0)
    )
    validation_budget_used = (
        _campaign_validation_budget_used(
            repository.list_campaign_validation_runs(record.campaign_id)
        )
        if repository is not None else 0
    )
    validation_budget_remaining = (
        None if record.validation_budget is None
        else max(record.validation_budget - validation_budget_used, 0)
    )
    return CampaignBudgetResponse(
        id=record.id,
        campaign_id=record.campaign_id,
        time_budget_minutes=record.time_budget_minutes,
        time_budget_used_minutes=time_budget_used,
        time_budget_remaining_minutes=time_budget_remaining,
        token_budget=record.token_budget,
        token_budget_used=token_budget_used,
        token_budget_remaining=token_budget_remaining,
        tool_call_budget=record.tool_call_budget,
        tool_call_used=tool_call_used,
        tool_call_remaining=tool_call_remaining,
        validation_budget=record.validation_budget,
        validation_budget_used=validation_budget_used,
        validation_budget_remaining=validation_budget_remaining,
        status=record.status,
        created_at=record.created_at.isoformat(),
    )


def _campaign_tool_call_used(campaign_id: str, repository: DatabaseRepository) -> int:
    return sum(
        1
        for run in repository.list_campaign_agent_runs(campaign_id)
        for _ in (run.payload or {}).get("tool_calls", [])
        if isinstance((run.payload or {}).get("tool_calls"), list)
    )


def _campaign_validation_budget_used(validation_runs: list[ValidationRunRecord]) -> int:
    return sum(
        1 for run in validation_runs
        if run.status not in {"cancelled", "rejected", "blocked"}
    )


def campaign_response(record: CampaignRecord, repository: DatabaseRepository):
    current_auth = repository.get_current_campaign_authorization(record.id)
    return CampaignResponse(
        id=record.id,
        program_id=record.program_id,
        name=record.name,
        status=record.status,
        campaign_mode=getattr(record, "campaign_mode", None) or "legacy",
        autonomy_level=record.autonomy_level,
        scope_status=record.scope_status,
        policy_text_hash=record.policy_text_hash,
        default_asset=record.default_asset,
        target_classes=record.target_classes,
        allowed_tools=record.allowed_tools,
        created_by=record.created_by,
        created_at=record.created_at.isoformat(),
        budget=campaign_budget_response(
            repository.get_campaign_budget(record.id),
            repository=repository,
        ),
        current_authorization_digest=(
            current_auth.authorization_digest if current_auth is not None else None
        ),
    )


# ---------------------------------------------------------------------------
# Agent run / pipeline stage
# ---------------------------------------------------------------------------

def agent_run_response(record: AgentRunRecord):
    return AgentRunResponse(
        id=record.id,
        campaign_id=record.campaign_id,
        task_id=record.task_id,
        agent_type=safe_preview_text(record.agent_type),
        status=safe_preview_text(record.status),
        input_refs=safe_string_list(record.input_refs),
        output_refs=safe_string_list(record.output_refs),
        safety_gate_state=safe_preview_text(record.safety_gate_state),
        stop_reason=safe_preview_text(record.stop_reason) if record.stop_reason else None,
        created_at=record.created_at.isoformat(),
        finished_at=record.finished_at.isoformat() if record.finished_at else None,
    )


def agent_run_timeline_indexes(
    agent_runs: list[AgentRunRecord],
) -> tuple[dict[str, AgentRunRecord], dict[str, list[AgentRunRecord]]]:
    by_id: dict[str, AgentRunRecord] = {}
    by_task_id: dict[str, list[AgentRunRecord]] = {}
    for run in agent_runs:
        by_id[run.id] = run
        if run.task_id:
            by_task_id.setdefault(run.task_id, []).append(run)
    return by_id, by_task_id
