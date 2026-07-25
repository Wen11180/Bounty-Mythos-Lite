import re
from collections.abc import Callable
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any
from uuid import uuid4

from app.campaign_orchestrator import campaign_elapsed_minutes, campaign_token_used_from_runs
from app.cross_source_candidate_generator import (
    CandidateModelConfig,
    candidate_model_config_digest,
    candidate_model_config_from_value,
)
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
_RUNTIME_PREFLIGHT_STAGE_KEY = "autonomous_research_preflight"
AUTONOMOUS_RESEARCH_SNAPSHOT_REFRESH_STAGE_KEY = (
    "autonomous_research_snapshot_refresh"
)
AUTONOMOUS_RESEARCH_SNAPSHOT_REFRESH_SCHEMA = (
    "autonomous_research_snapshot_refresh_v1"
)
_ACTIVE_TASK_STATUSES = {
    "queued",
    "ready",
    "dispatched",
    "running",
    "awaiting_evidence",
    "awaiting_approval",
    "needs_evidence",
}
_RETRYABLE_RUNTIME_FAILURE_STOP_REASONS = frozenset(
    {
        "dispatch_failed",
        "execution_lease_expired",
        "recovery_dispatch_integrity_invalid",
        "worker_failed",
    }
)
_RUNTIME_FAILURE_STOP_REASONS = _RETRYABLE_RUNTIME_FAILURE_STOP_REASONS
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
        "task_type": "security_invariant_generation",
        "agent_type": "invariant_agent",
        "title": "Derive security invariants from mapped facts",
    },
    {
        "task_type": "hypothesis_generation",
        "agent_type": "hypothesis_agent",
        "title": "Generate candidate hypotheses from safe facts",
    },
    {
        "task_type": "cross_source_llm_advisory",
        "agent_type": "cross_source_reasoner_agent",
        "title": "Enrich existing hypotheses with bounded model advice",
        "requires_candidate_model": True,
    },
    {
        "task_type": "exploit_chain_reasoning",
        "agent_type": "vuln_chain_builder_agent",
        "title": "Build plan-only vulnerability chains from safe hypotheses",
    },
    {
        "task_type": "variant_analysis",
        "agent_type": "variant_analysis_agent",
        "title": "Plan sibling-variant review from safe hypotheses",
    },
    {
        "task_type": "deep_code_reasoning",
        "agent_type": "deep_code_reasoning_agent",
        "title": "Plan cross-file permission reasoning from safe hypotheses",
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
    "security_invariant_generation",
    "hypothesis_generation",
    "cross_source_llm_advisory",
    "exploit_chain_reasoning",
    "variant_analysis",
    "deep_code_reasoning",
    "candidate_refutation",
    "finding_dedup_and_rank",
    "report_review",
}
_SOURCE_SNAPSHOT_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
_SAFE_STOP_REASON_PATTERN = re.compile(r"[a-z][a-z0-9_:-]{0,127}")
_LEARNING_SIGNAL_ID_PATTERN = re.compile(
    r"learning_signal_[A-Za-z0-9_-]{1,90}",
    re.ASCII,
)
_MIN_RUNTIME_TICK_INTERVAL_SECONDS = 60
_MAX_RUNTIME_WORK_ITEMS_PER_SNAPSHOT = 20
_READ_ONLY_RESEARCH_AUTONOMY_LEVELS = {
    "level_0_read_only",
    "level_1_local_validation",
}
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

    authorization_stop = _autopilot_authorization_stop_reason(
        campaign,
        repository,
        now=now,
    )
    if authorization_stop is not None:
        return _tick_result(status="blocked", stop_reason=authorization_stop)

    failure_stage_recovery = _reconcile_missing_runtime_failure_stage(
        campaign=campaign,
        repository=repository,
    )
    if failure_stage_recovery is not None:
        task, stop_reason = failure_stage_recovery
        task_payload = task.payload if isinstance(task.payload, dict) else {}
        return _tick_result(
            status="awaiting_review",
            campaign_task_id=task.id,
            stop_reason=stop_reason,
            source_snapshot_digest=task_payload.get("source_snapshot_digest"),
        )

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

    if campaign.autonomy_level == "level_1_local_validation":
        from app.research_director.runtime import tick_campaign_local_execution

        local_execution = tick_campaign_local_execution(
            campaign=campaign,
            repository=repository,
            dispatcher=dispatcher,
            now=now,
        )
        if local_execution is not None:
            return local_execution

    selection = select_autonomous_research_work(
        campaign=campaign,
        repository=repository,
        now=now,
    )
    if selection["status"] != "ready":
        stop_reason = selection["stop_reason"]
        _persist_runtime_preflight_stop(
            campaign=campaign,
            repository=repository,
            stop_reason=stop_reason,
            source_snapshot_digest=selection["source_snapshot_digest"],
        )
        if stop_reason == "human_review_required" and campaign.status == "running":
            repository.update_campaign_status(campaign.id, "awaiting_review")
        return _tick_result(
            status=_tick_stop_status(stop_reason),
            stop_reason=stop_reason,
            source_snapshot_digest=selection["source_snapshot_digest"],
        )

    task_type = selection["task_type"]
    source_snapshot_digest = selection["source_snapshot_digest"]
    if task_type not in _HANDLED_WORK_ITEM_TYPES:
        _persist_runtime_preflight_stop(
            campaign=campaign,
            repository=repository,
            stop_reason="runtime_task_handler_unavailable",
            source_snapshot_digest=source_snapshot_digest,
        )
        return _tick_result(
            status="blocked",
            stop_reason="runtime_task_handler_unavailable",
            source_snapshot_digest=source_snapshot_digest,
        )
    candidate_model_config, candidate_model_stop_reason = (
        _campaign_candidate_model_config(campaign)
    )
    if candidate_model_stop_reason is not None:
        return _tick_result(
            status="blocked",
            stop_reason=candidate_model_stop_reason,
            source_snapshot_digest=source_snapshot_digest,
        )
    if task_type == "cross_source_llm_advisory" and candidate_model_config is None:
        return _tick_result(
            status="blocked",
            stop_reason="candidate_model_config_missing",
            source_snapshot_digest=source_snapshot_digest,
        )
    pipeline_run_id = None
    input_refs = [
        f"campaign:{campaign.id}",
        f"source_snapshot:{source_snapshot_digest}",
    ]
    if task_type in {
        "cross_source_llm_advisory",
        "exploit_chain_reasoning",
        "variant_analysis",
        "deep_code_reasoning",
        "candidate_refutation",
        "finding_dedup_and_rank",
        "report_review",
    }:
        prerequisite_task_type = {
            "cross_source_llm_advisory": "hypothesis_generation",
            "exploit_chain_reasoning": "hypothesis_generation",
            "variant_analysis": "exploit_chain_reasoning",
            "deep_code_reasoning": "variant_analysis",
            "candidate_refutation": "deep_code_reasoning",
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
            missing_input_stop_reason = (
                "candidate_model_advisory_input_missing"
                if task_type == "cross_source_llm_advisory"
                else "exploit_chain_input_missing"
                if task_type == "exploit_chain_reasoning"
                else "exploit_chain_projection_missing"
                if task_type == "variant_analysis"
                else "variant_analysis_projection_missing"
                if task_type == "deep_code_reasoning"
                else "deep_code_reasoning_projection_missing"
                if task_type == "candidate_refutation"
                else "candidate_hunter_projection_missing"
            )
            _persist_runtime_preflight_stop(
                campaign=campaign,
                repository=repository,
                stop_reason=missing_input_stop_reason,
                source_snapshot_digest=source_snapshot_digest,
            )
            return _tick_result(
                status="blocked",
                stop_reason=missing_input_stop_reason,
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
        _persist_runtime_preflight_stop(
            campaign=campaign,
            repository=repository,
            stop_reason=tick_stop_reason,
            source_snapshot_digest=source_snapshot_digest,
        )
        return _tick_result(
            status="blocked",
            stop_reason=tick_stop_reason,
            source_snapshot_digest=source_snapshot_digest,
        )
    if task_type == "hypothesis_generation":
        input_refs.extend(
            _hypothesis_generation_learning_signal_refs(
                campaign=campaign,
                repository=repository,
            )
        )
    if task_type == "cross_source_llm_advisory" and candidate_model_config is not None:
        input_refs.append(
            "candidate_model_config:"
            + candidate_model_config_digest(candidate_model_config)
        )
    if task_type == "candidate_refutation":
        if candidate_model_config is not None and pipeline_run_id is not None:
            advisory_projection_refs = (
                _candidate_refutation_advisory_projection_refs(
                    campaign=campaign,
                    repository=repository,
                    source_snapshot_digest=source_snapshot_digest,
                    pipeline_run_id=pipeline_run_id,
                    candidate_model_config=candidate_model_config,
                )
            )
            if not advisory_projection_refs:
                _persist_runtime_preflight_stop(
                    campaign=campaign,
                    repository=repository,
                    stop_reason="candidate_model_advisory_projection_missing",
                    source_snapshot_digest=source_snapshot_digest,
                )
                return _tick_result(
                    status="blocked",
                    stop_reason="candidate_model_advisory_projection_missing",
                    source_snapshot_digest=source_snapshot_digest,
                )
            input_refs.extend(advisory_projection_refs)
        input_refs.extend(
            _candidate_refutation_advisory_artifact_refs(
                campaign=campaign,
                repository=repository,
                source_snapshot_digest=source_snapshot_digest,
            )
        )
    if task_type == "finding_dedup_and_rank" and pipeline_run_id is not None:
        input_refs.extend(
            _finding_dedup_historical_report_stage_refs(
                campaign=campaign,
                repository=repository,
                pipeline_run_id=pipeline_run_id,
                source_snapshot_digest=source_snapshot_digest,
            )
        )
    task = _failed_runtime_task_for_selection(
        campaign=campaign,
        repository=repository,
        task_type=task_type,
        source_snapshot_digest=source_snapshot_digest,
    )
    if task is not None:
        if campaign.status == "running":
            repository.update_campaign_status(campaign.id, "awaiting_review")
        return _tick_result(
            status="awaiting_review",
            campaign_task_id=task.id,
            stop_reason="human_review_required",
            source_snapshot_digest=source_snapshot_digest,
        )
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
            candidate_model_config=(
                candidate_model_config
                if task_type == "cross_source_llm_advisory"
                else None
            ),
        ),
    )
    if not claimed:
        return _tick_result(
            status="awaiting_evidence",
            campaign_task_id=task.id,
            stop_reason="active_runtime_task",
            source_snapshot_digest=source_snapshot_digest,
        )
    return _dispatch_runtime_task(
        campaign=campaign,
        task=task,
        source_snapshot_digest=source_snapshot_digest,
        repository=repository,
        dispatcher=dispatcher,
        now=now,
    )


def retry_autonomous_research_task(
    campaign_id: str,
    task_id: str,
    *,
    repository: DatabaseRepository,
    dispatcher: Callable[..., Any],
) -> dict[str, Any]:
    campaign = repository.get_campaign(campaign_id)
    if campaign is None:
        return _tick_result(status="not_found", stop_reason="campaign_not_found")
    task = repository.session.get(CampaignTaskRecord, task_id)
    if task is None or task.campaign_id != campaign.id:
        return _tick_result(status="not_found", stop_reason="campaign_task_not_found")
    if task.task_type == "research_director_local_tool_run":
        from app.research_director.runtime import retry_campaign_local_tool_task

        return retry_campaign_local_tool_task(
            campaign.id,
            task.id,
            repository=repository,
            dispatcher=dispatcher,
        )

    payload = task.payload if isinstance(task.payload, dict) else {}
    source_snapshot_digest = payload.get("source_snapshot_digest")
    safe_source_snapshot_digest = (
        source_snapshot_digest
        if isinstance(source_snapshot_digest, str)
        and _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest)
        else None
    )
    if task.status != "failed" or payload.get("runtime_schema") != _RUNTIME_SCHEMA:
        return _tick_result(
            status="blocked",
            campaign_task_id=task.id,
            stop_reason="runtime_task_not_retryable",
            source_snapshot_digest=safe_source_snapshot_digest,
        )
    if safe_source_snapshot_digest is None:
        return _tick_result(
            status="blocked",
            campaign_task_id=task.id,
            stop_reason="malformed_runtime_task",
            source_snapshot_digest=None,
        )
    _reconcile_missing_runtime_failure_stage(
        campaign=campaign,
        repository=repository,
        task_id=task.id,
    )
    campaign = repository.get_campaign(campaign.id) or campaign
    if not _has_retryable_runtime_failure(
        task=task,
        repository=repository,
        source_snapshot_digest=safe_source_snapshot_digest,
    ):
        return _tick_result(
            status="awaiting_review",
            campaign_task_id=task.id,
            stop_reason="human_review_required",
            source_snapshot_digest=safe_source_snapshot_digest,
        )
    if any(
        candidate.task_type == "validation_handoff"
        and candidate.status == "awaiting_approval"
        for candidate in repository.list_campaign_tasks(campaign.id)
    ):
        return _tick_result(
            status="awaiting_review",
            campaign_task_id=task.id,
            stop_reason="human_review_required",
            source_snapshot_digest=safe_source_snapshot_digest,
        )

    stop_reason = autonomous_research_task_stop_reason(
        task=task,
        campaign=campaign,
        repository=repository,
        allow_awaiting_review=(
            campaign.status == "awaiting_review"
        ),
    )
    if stop_reason is not None:
        return _tick_result(
            status="blocked",
            campaign_task_id=task.id,
            stop_reason=stop_reason,
            source_snapshot_digest=safe_source_snapshot_digest,
        )
    retry_task = repository.claim_failed_campaign_task_retry(task.id)
    if retry_task is None:
        return _tick_result(
            status="awaiting_evidence",
            campaign_task_id=task.id,
            stop_reason="active_runtime_task",
            source_snapshot_digest=safe_source_snapshot_digest,
        )

    task = retry_task
    campaign = repository.get_campaign(campaign.id) or campaign
    if campaign.status == "awaiting_review":
        campaign = repository.transition_campaign_status_if_currently(
            campaign.id,
            "running",
            allowed_current_statuses={"awaiting_review"},
        )
        if campaign is None:
            return _tick_result(
                status="blocked",
                campaign_task_id=task.id,
                stop_reason="campaign_not_running",
                source_snapshot_digest=safe_source_snapshot_digest,
            )
    elif campaign.status != "running":
        return _tick_result(
            status="blocked",
            campaign_task_id=task.id,
            stop_reason="campaign_not_running",
            source_snapshot_digest=safe_source_snapshot_digest,
        )
    return _dispatch_runtime_task(
        campaign=campaign,
        task=task,
        source_snapshot_digest=safe_source_snapshot_digest,
        repository=repository,
        dispatcher=dispatcher,
    )


def record_autonomous_research_task_completion(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
    terminal_stop_reason: str | None = None,
    terminal_campaign_status: str | None = None,
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
    safe_terminal_stop_reason = (
        terminal_stop_reason
        if isinstance(terminal_stop_reason, str)
        and _SAFE_STOP_REASON_PATTERN.fullmatch(terminal_stop_reason)
        else None
    )
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
        stop_reason=safe_terminal_stop_reason,
        payload=_runtime_stage_payload(
            campaign_id=task.campaign_id,
            task_type=task.task_type,
            source_snapshot_digest=source_snapshot_digest,
            outcome=(
                f"completed:{safe_terminal_stop_reason}"
                if safe_terminal_stop_reason is not None
                else "completed"
            ),
        ),
    )
    if task.task_type == "report_review":
        campaign = repository.get_campaign(task.campaign_id)
        if campaign is not None and campaign.status == "running":
            has_pending_validation_handoff = any(
                candidate.task_type == "validation_handoff"
                and candidate.status == "awaiting_approval"
                for candidate in repository.list_campaign_tasks(campaign.id)
            )
            repository.update_campaign_status(
                campaign.id,
                (
                    "completed"
                    if (
                        terminal_campaign_status == "completed"
                        and not has_pending_validation_handoff
                    )
                    else "awaiting_review"
                ),
            )


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


def record_autonomous_research_task_failure(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
    stop_reason: str,
) -> bool:
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
        return False
    safe_stop_reason = (
        stop_reason
        if isinstance(stop_reason, str)
        and _SAFE_STOP_REASON_PATTERN.fullmatch(stop_reason)
        else "worker_failed"
    )
    try:
        repository.save_pipeline_stage(
            pipeline_run_id=None,
            campaign_id=task.campaign_id,
            task_id=task.id,
            stage_id=_runtime_failure_stage_id(
                task_id=task.id,
                source_snapshot_digest=source_snapshot_digest,
                stop_reason=safe_stop_reason,
            ),
            stage_key=f"{_RUNTIME_STAGE_PREFIX}{task.task_type}",
            stage_order=_stage_order_for(task.task_type),
            status="failed",
            input_refs=task.input_refs,
            output_refs=task.output_refs,
            safety_gate_state="blocked",
            stop_reason=safe_stop_reason,
            payload=_runtime_stage_payload(
                campaign_id=task.campaign_id,
                task_type=task.task_type,
                source_snapshot_digest=source_snapshot_digest,
                outcome=f"failed:{safe_stop_reason}",
            ),
            strict_idempotency=True,
        )
    except ValueError as exc:
        if str(exc) != "pipeline_stage_id_conflict":
            raise
        campaign = repository.get_campaign(task.campaign_id)
        if campaign is not None and campaign.status == "running":
            repository.update_campaign_status(campaign.id, "awaiting_review")
        return False
    campaign = repository.get_campaign(task.campaign_id)
    if campaign is not None and campaign.status == "running":
        repository.update_campaign_status(campaign.id, "awaiting_review")
    return True


def reconcile_autonomous_research_evidence_block(
    *,
    owner_task: CampaignTaskRecord,
    repository: DatabaseRepository,
) -> str | None:
    owner_payload = owner_task.payload if isinstance(owner_task.payload, dict) else {}
    evidence_task_id = owner_payload.get("blocked_by_evidence_task_id")
    stop_reason = owner_payload.get("blocked_stop_reason")
    if (
        owner_task.status != "blocked"
        or owner_task.task_type != "candidate_refutation"
        or owner_payload.get("runtime_schema") != _RUNTIME_SCHEMA
        or not _runtime_payload_is_safe(owner_payload)
        or not isinstance(evidence_task_id, str)
        or not isinstance(stop_reason, str)
        or not _SAFE_STOP_REASON_PATTERN.fullmatch(stop_reason)
        or f"campaign_task:{evidence_task_id}" not in owner_task.output_refs
    ):
        return None
    evidence_task = repository.session.get(CampaignTaskRecord, evidence_task_id)
    source_snapshot_digest = owner_payload.get("source_snapshot_digest")
    if (
        evidence_task is None
        or evidence_task.status != "blocked"
        or evidence_task.task_type != _EVIDENCE_TASK_TYPE
        or evidence_task.campaign_id != owner_task.campaign_id
        or not isinstance(source_snapshot_digest, str)
        or not _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest)
        or not _evidence_task_matches_runtime_owner(
            evidence_task=evidence_task,
            owner_task=owner_task,
            source_snapshot_digest=source_snapshot_digest,
        )
    ):
        return None
    record_autonomous_research_task_blocked(
        task=owner_task,
        repository=repository,
        stop_reason=stop_reason,
    )
    return stop_reason


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
    allow_awaiting_review: bool = False,
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
        allow_awaiting_review=allow_awaiting_review,
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
    if task.task_type == "cross_source_llm_advisory":
        candidate_model_config, candidate_model_stop_reason = (
            _campaign_candidate_model_config(campaign)
        )
        if candidate_model_stop_reason is not None:
            return candidate_model_stop_reason
        if candidate_model_config is None:
            return "candidate_model_config_missing"
        if not _runtime_task_has_candidate_model_config(
            payload,
            candidate_model_config,
        ):
            return "candidate_model_config_changed"
    if task.task_type in {
        "cross_source_llm_advisory",
        "exploit_chain_reasoning",
        "variant_analysis",
        "deep_code_reasoning",
        "candidate_refutation",
        "finding_dedup_and_rank",
        "report_review",
    } and not isinstance(
        payload.get("pipeline_run_id"), str
    ):
        return (
            "candidate_model_advisory_input_missing"
            if task.task_type == "cross_source_llm_advisory"
            else "exploit_chain_input_missing"
            if task.task_type == "exploit_chain_reasoning"
            else "exploit_chain_projection_missing"
            if task.task_type == "variant_analysis"
            else "variant_analysis_projection_missing"
            if task.task_type == "deep_code_reasoning"
            else "deep_code_reasoning_projection_missing"
            if task.task_type == "candidate_refutation"
            else "candidate_hunter_projection_missing"
        )
    if task.task_type not in _HANDLED_WORK_ITEM_TYPES:
        return "runtime_task_handler_unavailable"
    return None


def _research_branch_from_record(record) -> "ResearchBranch":
    from app.bounty_autopilot.branches import (
        BranchBudgetCounters,
        BranchStatus,
        ResearchBranch,
    )
    from app.bounty_autopilot.contracts import RecipeRef, RiskTier

    recipe_ref = None
    if record.recipe_id and record.recipe_version:
        recipe_ref = RecipeRef(recipe_id=record.recipe_id, version=record.recipe_version)
    budget_payload = record.budget_counters if isinstance(record.budget_counters, dict) else {}
    return ResearchBranch(
        branch_id=record.branch_id,
        campaign_id=record.campaign_id,
        asset_id=record.asset_id,
        status=BranchStatus(record.status),
        priority=int(record.priority),
        recipe_ref=recipe_ref,
        risk_tier=RiskTier(record.risk_tier),
        hypothesis_id=record.hypothesis_id,
        account_aliases=tuple(record.account_aliases or ()),
        budget=BranchBudgetCounters.model_validate(budget_payload or {}),
        stop_reason=record.stop_reason,
        version=int(record.version),
    )


def _authorization_bounded_branch_limit(value: Any, ceiling: int) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
        return min(value, ceiling)
    return ceiling


def _select_autopilot_branch_work(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> dict[str, Any] | None:
    """Continue an eligible Autopilot branch while peers wait on R3/WAF/human."""

    from app.bounty_autopilot.authority import authorization_from_payload
    from app.bounty_autopilot.branches import (
        BranchLimits,
        branch_matches_authorization,
        select_next_branch,
    )

    payload = campaign.payload if isinstance(campaign.payload, dict) else {}
    authorization_record = repository.get_current_campaign_authorization(campaign.id)
    if authorization_record is None:
        return None
    try:
        authorization = authorization_from_payload(authorization_record.payload)
    except Exception:  # noqa: BLE001 - scheduler input must remain fail-closed
        return _blocked("authorization_invalid")
    scope_snapshot_digest = payload.get("scope_snapshot_digest")
    if not isinstance(scope_snapshot_digest, str):
        scope_snapshot_digest = authorization.scope_snapshot_digest
    if scope_snapshot_digest != authorization.scope_snapshot_digest:
        return _blocked("authorization_scope_stale")
    if not isinstance(scope_snapshot_digest, str):
        return None
    branch_rows = repository.list_research_branches(campaign.id)
    if not branch_rows:
        return None
    branches = [_research_branch_from_record(row) for row in branch_rows]
    admitted = repository.list_admitted_campaign_asset_ids(
        campaign.id,
        scope_snapshot_digest=scope_snapshot_digest,
    ) & set(authorization.asset_ids)
    branches = [
        branch
        for branch in branches
        if branch_matches_authorization(
            branch,
            authorized_asset_ids=set(authorization.asset_ids),
            authorized_recipe_refs=authorization.recipe_refs,
            risk_ceiling=authorization.risk_ceiling,
            authorized_account_aliases=set(authorization.account_aliases),
        )
    ]
    limits_payload = payload.get("branch_limits") if isinstance(payload.get("branch_limits"), dict) else {}
    budget_usage = repository.get_autopilot_authorization_budget_usage(
        campaign_id=campaign.id,
        authorization_id=authorization_record.id,
    )
    if budget_usage is None:
        return _blocked("authorization_budget_ledger_invalid")
    limits = BranchLimits(
        campaign_max_requests=_authorization_bounded_branch_limit(
            limits_payload.get("campaign_max_requests"),
            authorization.budget.max_requests,
        ),
        campaign_max_time_seconds=_authorization_bounded_branch_limit(
            limits_payload.get("campaign_max_time_seconds"),
            authorization.budget.max_duration_seconds,
        ),
        campaign_max_cost_units=_authorization_bounded_branch_limit(
            limits_payload.get("campaign_max_cost_units"),
            authorization.budget.max_cost_units,
        ),
        per_asset_max_requests=_authorization_bounded_branch_limit(
            limits_payload.get("per_asset_max_requests"),
            authorization.budget.max_requests,
        ),
        per_account_max_requests=_authorization_bounded_branch_limit(
            limits_payload.get("per_account_max_requests"),
            authorization.budget.max_requests,
        ),
        per_hypothesis_max_requests=_authorization_bounded_branch_limit(
            limits_payload.get("per_hypothesis_max_requests"),
            authorization.budget.max_requests,
        ),
    )
    policy_drift = bool(payload.get("policy_drift"))
    selection = select_next_branch(
        branches,
        limits=limits,
        policy_drift=policy_drift,
        admitted_asset_ids=admitted,
        campaign_requests_used=budget_usage["requests_reserved"],
        campaign_time_used=budget_usage["duration_reserved_seconds"],
        campaign_cost_used=budget_usage["cost_units_reserved"],
    )
    if selection.frozen_for_policy_drift:
        return _blocked("policy_drift_freeze")
    if selection.selected_branch_id is None:
        return None
    return {
        "status": "ready",
        "task_type": "autopilot_branch",
        "action_id": "continue_research_branch",
        "branch_id": selection.selected_branch_id,
        "visible_waiting_branch_ids": list(selection.visible_waiting_branch_ids),
        "suppressed_duplicate_branch_ids": list(
            selection.suppressed_duplicate_branch_ids
        ),
        "source_snapshot_digest": payload.get("source_snapshot_digest"),
        **_SAFETY_FIELDS,
    }


def select_autonomous_research_work(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    now: datetime | None = None,
) -> dict[str, Any]:
    stop_reason = _campaign_stop_reason(campaign, repository, now=now)
    if stop_reason is not None:
        return _blocked(stop_reason)
    awaiting_validation_handoff = any(
        task.task_type == "validation_handoff" and task.status == "awaiting_approval"
        for task in repository.list_campaign_tasks(campaign.id)
    )
    if awaiting_validation_handoff:
        # Legacy linear campaigns still stop. Autopilot keeps waiting branches
        # visible and may continue an unrelated eligible research branch.
        campaign_mode = getattr(campaign, "campaign_mode", "legacy") or "legacy"
        if campaign_mode != "bounty_autopilot":
            return _blocked("human_review_required")
        branch_selection = _select_autopilot_branch_work(
            campaign=campaign,
            repository=repository,
        )
        if branch_selection is not None:
            return branch_selection
        return _blocked("human_review_required")
    payload = campaign.payload if isinstance(campaign.payload, dict) else {}
    source_snapshot_digest = payload.get("source_snapshot_digest")
    if not isinstance(source_snapshot_digest, str) or not _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(
        source_snapshot_digest
    ):
        return _blocked("source_snapshot_digest_required")
    candidate_model_config, candidate_model_stop_reason = (
        _campaign_candidate_model_config(campaign)
    )
    if candidate_model_stop_reason is not None:
        return _blocked(candidate_model_stop_reason)
    if _has_candidate_model_advisory_config_mismatch(
        campaign=campaign,
        repository=repository,
        source_snapshot_digest=source_snapshot_digest,
        candidate_model_config=candidate_model_config,
    ):
        return _blocked("candidate_model_config_changed")
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
    for work_item in _runtime_work_items(candidate_model_config):
        if work_item["task_type"] not in completed_task_types:
            return {
                "status": "ready",
                **work_item,
                "source_snapshot_digest": source_snapshot_digest,
                **_SAFETY_FIELDS,
            }
    return _blocked("source_snapshot_completed")


def _campaign_stop_reason(
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    *,
    now: datetime | None,
    allow_awaiting_review: bool = False,
) -> str | None:
    authorization_stop = _autopilot_authorization_stop_reason(
        campaign,
        repository,
        now=now,
    )
    if authorization_stop is not None:
        return authorization_stop
    if campaign.autonomy_level not in _READ_ONLY_RESEARCH_AUTONOMY_LEVELS:
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
        if not allow_awaiting_review:
            return "human_review_required"
    elif campaign.status in {"blocked", "canceled", "completed", "failed"}:
        return f"campaign_{campaign.status}"
    elif campaign.status != "running":
        return "campaign_not_running"
    budget = repository.get_campaign_budget(campaign.id)
    if budget is not None and any(
        value is not None and value <= 0
        for value in (
            budget.time_budget_minutes,
            budget.token_budget,
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
    return None


def _autopilot_authorization_stop_reason(
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    *,
    now: datetime | None,
) -> str | None:
    """Resolve current Autopilot authority before any wakeup work."""

    if (getattr(campaign, "campaign_mode", None) or "legacy") != "bounty_autopilot":
        return None
    from app.bounty_autopilot.authority import (
        AuthorizationValidationError,
        authorization_from_payload,
        validate_current_authorization,
    )

    row = repository.get_current_campaign_authorization(campaign.id)
    if row is None:
        return "authorization_missing"
    try:
        authorization = authorization_from_payload(row.payload)
        expected_policy_digest = "sha256:" + str(
            campaign.policy_text_hash
        ).removeprefix("sha256:")
        validate_current_authorization(
            authorization,
            now=now,
            expected_policy_digest=expected_policy_digest,
        )
    except AuthorizationValidationError as exc:
        return exc.reason
    except Exception:  # noqa: BLE001 - persisted authority fails closed
        return "authorization_invalid"
    payload = campaign.payload if isinstance(campaign.payload, dict) else {}
    if payload.get("current_authorization_id") not in {None, row.id}:
        return "authorization_stale"
    if payload.get("current_authorization_digest") not in {
        None,
        authorization.authorization_digest,
    }:
        return "authorization_stale"
    if payload.get("scope_snapshot_digest") not in {
        None,
        authorization.scope_snapshot_digest,
    }:
        return "authorization_scope_stale"
    return None


def _runtime_payload_is_safe(payload: dict[str, Any]) -> bool:
    return (
        all(payload.get(field) is False for field in _SAFETY_FIELDS)
        and not _contains_forbidden_runtime_payload_key(payload)
    )


def _campaign_candidate_model_config(
    campaign: CampaignRecord,
) -> tuple[CandidateModelConfig | None, str | None]:
    payload = campaign.payload if isinstance(campaign.payload, dict) else {}
    if "candidate_model" not in payload:
        return None, None
    config = candidate_model_config_from_value(payload.get("candidate_model"))
    return (
        (config, None)
        if config is not None
        else (None, "candidate_model_config_invalid")
    )


def _runtime_work_items(
    candidate_model_config: CandidateModelConfig | None,
) -> tuple[dict[str, str | bool], ...]:
    return tuple(
        work_item
        for work_item in _WORK_ITEMS
        if not work_item.get("requires_candidate_model")
        or candidate_model_config is not None
    )


def _runtime_task_has_candidate_model_config(
    payload: dict[str, Any],
    config: CandidateModelConfig,
) -> bool:
    task_config = candidate_model_config_from_value(payload.get("candidate_model"))
    return (
        task_config is not None
        and task_config == config
        and payload.get("candidate_model_config_digest")
        == candidate_model_config_digest(config)
    )


def _has_candidate_model_advisory_config_mismatch(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    source_snapshot_digest: str,
    candidate_model_config: CandidateModelConfig | None,
) -> bool:
    for stage in repository.list_campaign_pipeline_stages(campaign.id):
        if (
            stage.stage_key != f"{_RUNTIME_STAGE_PREFIX}cross_source_llm_advisory"
            or stage.status != "completed"
            or not isinstance(stage.payload, dict)
            or stage.payload.get("runtime_schema") != _RUNTIME_SCHEMA
            or stage.payload.get("source_snapshot_digest") != source_snapshot_digest
        ):
            continue
        task = (
            repository.session.get(CampaignTaskRecord, stage.task_id)
            if isinstance(stage.task_id, str)
            else None
        )
        task_payload = task.payload if task is not None and isinstance(task.payload, dict) else {}
        if (
            candidate_model_config is None
            or not _runtime_task_has_candidate_model_config(
                task_payload,
                candidate_model_config,
            )
        ):
            return True
    return False


def _persist_runtime_preflight_stop(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    stop_reason: str,
    source_snapshot_digest: str | None,
) -> None:
    if campaign.status != "running" or stop_reason in {
        "active_runtime_task",
        "campaign_not_running",
        "campaign_paused",
        "human_review_required",
        "tick_not_due",
    }:
        return
    campaign_status = "paused" if stop_reason == "budget_exhausted" else "blocked"
    stage_status = "paused" if campaign_status == "paused" else "blocked"
    if stop_reason == "source_snapshot_completed":
        campaign_status = "completed"
        stage_status = "completed"
    safe_source_snapshot_digest = (
        source_snapshot_digest
        if isinstance(source_snapshot_digest, str)
        and _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest)
        else None
    )
    source_identity = safe_source_snapshot_digest or "missing"
    input_refs = [f"campaign:{campaign.id}"]
    if safe_source_snapshot_digest is not None:
        input_refs.append(f"source_snapshot:{safe_source_snapshot_digest}")
    payload = {
        "runtime_schema": _RUNTIME_SCHEMA,
        "artifact_kind": "autonomous_research_preflight",
        "outcome": f"{stage_status}:{stop_reason}",
        "idempotency_key": "sha256:"
        + sha256(
            f"{campaign.id}:{source_identity}:preflight:{stage_status}:{stop_reason}".encode(
                "utf-8"
            )
        ).hexdigest(),
        "dispatch_contract": "none",
        "raw_payload_in_dispatch": False,
        **_SAFETY_FIELDS,
    }
    if safe_source_snapshot_digest is not None:
        payload["source_snapshot_digest"] = safe_source_snapshot_digest
    repository.save_pipeline_stage(
        pipeline_run_id=None,
        campaign_id=campaign.id,
        task_id=None,
        stage_key=_RUNTIME_PREFLIGHT_STAGE_KEY,
        stage_order=-1,
        status=stage_status,
        input_refs=input_refs,
        output_refs=[],
        safety_gate_state="allowed" if stage_status == "completed" else "blocked",
        stop_reason=stop_reason,
        payload=payload,
    )
    repository.update_campaign_status(campaign.id, campaign_status)


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
    tasks_by_id = {
        task.id: task for task in repository.list_campaign_tasks(campaign.id)
    }
    for stage in repository.list_campaign_pipeline_stages(campaign.id):
        if not stage.stage_key.startswith(_RUNTIME_STAGE_PREFIX):
            continue
        payload = stage.payload
        source_snapshot_digest = (
            payload.get("source_snapshot_digest") if isinstance(payload, dict) else None
        )
        task_type = stage.stage_key.removeprefix(_RUNTIME_STAGE_PREFIX)
        task = tasks_by_id.get(stage.task_id)
        if (
            not isinstance(payload, dict)
            or payload.get("runtime_schema") != _RUNTIME_SCHEMA
            or task_type not in _WORK_ITEM_TYPES
            or not isinstance(source_snapshot_digest, str)
            or not _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest)
            or not _runtime_payload_is_safe(payload)
            or (
                stage.status == "completed"
                and (
                    stage.safety_gate_state != "allowed"
                    or task is None
                    or task.status != "completed"
                    or task.task_type != task_type
                    or not isinstance(task.payload, dict)
                    or task.payload.get("runtime_schema") != _RUNTIME_SCHEMA
                    or task.payload.get("source_snapshot_digest")
                    != source_snapshot_digest
                    or not _runtime_payload_is_safe(task.payload)
                )
            )
        ):
            return True
    return False


def _has_runtime_stage_for_different_source_snapshot(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    source_snapshot_digest: str,
) -> bool:
    approved_snapshot_digests = _approved_snapshot_lineage(
        campaign=campaign,
        repository=repository,
        source_snapshot_digest=source_snapshot_digest,
    )
    return any(
        stage.stage_key.startswith(_RUNTIME_STAGE_PREFIX)
        and isinstance(stage.payload, dict)
        and stage.payload.get("runtime_schema") == _RUNTIME_SCHEMA
        and stage.payload.get("source_snapshot_digest")
        not in approved_snapshot_digests
        for stage in repository.list_campaign_pipeline_stages(campaign.id)
    )


def build_autonomous_research_snapshot_refresh_payload(
    *,
    campaign_id: str,
    previous_source_snapshot_digest: str,
    source_snapshot_digest: str,
    actor: str,
) -> dict[str, Any]:
    if (
        not isinstance(campaign_id, str)
        or not campaign_id
        or not isinstance(previous_source_snapshot_digest, str)
        or not isinstance(source_snapshot_digest, str)
        or not _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(
            previous_source_snapshot_digest
        )
        or not _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest)
        or previous_source_snapshot_digest == source_snapshot_digest
        or not isinstance(actor, str)
        or not actor.strip()
        or len(actor) > 100
    ):
        raise ValueError("autonomous_snapshot_refresh_invalid")
    return {
        "schema_version": AUTONOMOUS_RESEARCH_SNAPSHOT_REFRESH_SCHEMA,
        "idempotency_key": _snapshot_refresh_idempotency_key(
            campaign_id=campaign_id,
            previous_source_snapshot_digest=previous_source_snapshot_digest,
            source_snapshot_digest=source_snapshot_digest,
        ),
        "previous_source_snapshot_digest": previous_source_snapshot_digest,
        "source_snapshot_digest": source_snapshot_digest,
        "actor": actor.strip(),
        "reason_recorded": True,
        "human_review_completed": True,
        **_SAFETY_FIELDS,
    }


def _approved_snapshot_lineage(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    source_snapshot_digest: str,
) -> set[str]:
    known = {source_snapshot_digest}
    stages = repository.list_campaign_pipeline_stages(campaign.id)
    changed = True
    while changed:
        changed = False
        for stage in stages:
            if not _is_approved_snapshot_refresh_stage(
                campaign_id=campaign.id,
                stage=stage,
            ):
                continue
            payload = stage.payload
            previous = payload["previous_source_snapshot_digest"]
            refreshed = payload["source_snapshot_digest"]
            if refreshed in known and previous not in known:
                known.add(previous)
                changed = True
    return known


def _is_approved_snapshot_refresh_stage(
    *,
    campaign_id: str,
    stage: Any,
) -> bool:
    payload = stage.payload if isinstance(stage.payload, dict) else None
    input_refs = stage.input_refs if isinstance(stage.input_refs, list) else []
    output_refs = stage.output_refs if isinstance(stage.output_refs, list) else []
    if (
        stage.stage_key != AUTONOMOUS_RESEARCH_SNAPSHOT_REFRESH_STAGE_KEY
        or stage.status != "completed"
        or stage.safety_gate_state != "human_review_completed"
        or not isinstance(payload, dict)
        or payload.get("schema_version")
        != AUTONOMOUS_RESEARCH_SNAPSHOT_REFRESH_SCHEMA
    ):
        return False
    previous = payload.get("previous_source_snapshot_digest")
    refreshed = payload.get("source_snapshot_digest")
    if (
        not isinstance(previous, str)
        or not isinstance(refreshed, str)
        or previous == refreshed
        or not _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(previous)
        or not _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(refreshed)
        or payload.get("idempotency_key")
        != _snapshot_refresh_idempotency_key(
            campaign_id=campaign_id,
            previous_source_snapshot_digest=previous,
            source_snapshot_digest=refreshed,
        )
        or payload.get("reason_recorded") is not True
        or payload.get("human_review_completed") is not True
        or any(payload.get(field) is not value for field, value in _SAFETY_FIELDS.items())
    ):
        return False
    return (
        f"source_snapshot:{previous}" in input_refs
        and f"source_snapshot:{refreshed}" in output_refs
    )


def _snapshot_refresh_idempotency_key(
    *,
    campaign_id: str,
    previous_source_snapshot_digest: str,
    source_snapshot_digest: str,
) -> str:
    identity = ":".join(
        (
            campaign_id,
            previous_source_snapshot_digest,
            source_snapshot_digest,
            AUTONOMOUS_RESEARCH_SNAPSHOT_REFRESH_SCHEMA,
        )
    )
    return "sha256:" + sha256(identity.encode("utf-8")).hexdigest()


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


def _has_retryable_runtime_failure(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
    source_snapshot_digest: str,
) -> bool:
    return any(
        _has_verified_runtime_failure_stage(
            task=task,
            repository=repository,
            source_snapshot_digest=source_snapshot_digest,
            stop_reason=stop_reason,
        )
        for stop_reason in _RETRYABLE_RUNTIME_FAILURE_STOP_REASONS
    )


def _reconcile_missing_runtime_failure_stage(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    task_id: str | None = None,
) -> tuple[CampaignTaskRecord, str] | None:
    campaign_payload = campaign.payload if isinstance(campaign.payload, dict) else {}
    source_snapshot_digest = campaign_payload.get("source_snapshot_digest")
    if not isinstance(source_snapshot_digest, str) or not _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(
        source_snapshot_digest
    ):
        return None
    approved_snapshot_digests = _approved_snapshot_lineage(
        campaign=campaign,
        repository=repository,
        source_snapshot_digest=source_snapshot_digest,
    )
    for task in repository.list_campaign_tasks(campaign.id):
        if task_id is not None and task.id != task_id:
            continue
        task_payload = task.payload if isinstance(task.payload, dict) else {}
        task_source_snapshot_digest = task_payload.get("source_snapshot_digest")
        if (
            task.status != "failed"
            or task.task_type not in _WORK_ITEM_TYPES
            or task.execution_claim_id is not None
            or task.execution_lease_expires_at is not None
            or not isinstance(task_source_snapshot_digest, str)
            or task_source_snapshot_digest not in approved_snapshot_digests
            or not _runtime_payload_is_safe(task_payload)
        ):
            continue
        stop_reasons = _verified_runtime_failure_stop_reasons(
            task=task,
            repository=repository,
        )
        if len(stop_reasons) == 1:
            stop_reason = next(iter(stop_reasons))
        elif len(stop_reasons) > 1:
            stop_reason = "recovery_dispatch_integrity_invalid"
        else:
            continue
        if _has_verified_runtime_failure_stage(
            task=task,
            repository=repository,
            source_snapshot_digest=task_source_snapshot_digest,
            stop_reason=stop_reason,
        ):
            continue
        recorded = record_autonomous_research_task_failure(
            task=task,
            repository=repository,
            stop_reason=stop_reason,
        )
        if not recorded or not _has_verified_runtime_failure_stage(
            task=task,
            repository=repository,
            source_snapshot_digest=task_source_snapshot_digest,
            stop_reason=stop_reason,
        ):
            return task, "recovery_dispatch_integrity_invalid"
        return task, stop_reason
    return None


def _verified_runtime_failure_stop_reasons(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
) -> set[str]:
    if not isinstance(task.input_refs, list) or not isinstance(task.output_refs, list):
        return set()
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    source_snapshot_digest = task_payload.get("source_snapshot_digest")
    if not isinstance(source_snapshot_digest, str) or not _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(
        source_snapshot_digest
    ):
        return set()
    expected_agent_payload = build_autonomous_research_agent_payload(
        source_snapshot_digest=source_snapshot_digest,
    )
    stop_reasons: set[str] = set()
    for agent_run in repository.list_campaign_agent_runs(task.campaign_id):
        if agent_run.task_id != task.id:
            continue
        payload = agent_run.payload if isinstance(agent_run.payload, dict) else None
        agent_run_ref = f"agent_run:{agent_run.id}"
        if (
            agent_run.campaign_id != task.campaign_id
            or agent_run.agent_type != task.agent_type
            or agent_run.status != "failed"
            or agent_run.safety_gate_state != "blocked"
            or agent_run.stop_reason not in _RUNTIME_FAILURE_STOP_REASONS
            or agent_run.finished_at is None
            or agent_run.input_refs != [f"campaign_task:{task.id}"]
            or (task.output_refs and agent_run_ref not in task.output_refs)
            or payload != expected_agent_payload
        ):
            continue
        stop_reasons.add(agent_run.stop_reason)
    return stop_reasons


def _verified_runtime_failure_stop_reason(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
) -> str | None:
    stop_reasons = _verified_runtime_failure_stop_reasons(
        task=task,
        repository=repository,
    )
    return next(iter(stop_reasons)) if len(stop_reasons) == 1 else None


def _has_verified_runtime_failure_stage(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
    source_snapshot_digest: str,
    stop_reason: str,
) -> bool:
    if task.task_type not in _WORK_ITEM_TYPES:
        return False
    expected_payload = _runtime_stage_payload(
        campaign_id=task.campaign_id,
        task_type=task.task_type,
        source_snapshot_digest=source_snapshot_digest,
        outcome=f"failed:{stop_reason}",
    )
    expected_stage_id = _runtime_failure_stage_id(
        task_id=task.id,
        source_snapshot_digest=source_snapshot_digest,
        stop_reason=stop_reason,
    )
    return any(
        stage.id == expected_stage_id
        and stage.pipeline_run_id is None
        and stage.campaign_id == task.campaign_id
        and stage.task_id == task.id
        and stage.stage_key == f"{_RUNTIME_STAGE_PREFIX}{task.task_type}"
        and stage.stage_order == _stage_order_for(task.task_type)
        and stage.status == "failed"
        and stage.input_refs == task.input_refs
        and stage.output_refs == task.output_refs
        and stage.safety_gate_state == "blocked"
        and stage.stop_reason == stop_reason
        and stage.payload == expected_payload
        for stage in repository.list_campaign_pipeline_stages(task.campaign_id)
    )


def _verified_orphaned_runtime_dispatch(
    *,
    campaign: CampaignRecord,
    task: CampaignTaskRecord,
    source_snapshot_digest: str,
    task_runs: list[Any],
    task_stages: list[Any],
) -> tuple[Any, int] | None:
    if (
        task.status not in {"queued", "ready"}
        or task.execution_claim_id is not None
        or task.execution_lease_expires_at is not None
    ):
        return None

    active_runs = [
        run
        for run in task_runs
        if run.status in {"dispatched", "running", "awaiting_approval"}
    ]
    if len(active_runs) != 1:
        return None
    agent_run = active_runs[0]
    dispatch_attempt = len(task_runs)
    expected_agent_payload = {
        "runtime_schema": _RUNTIME_SCHEMA,
        "source_snapshot_digest": source_snapshot_digest,
        "dispatch_contract": "id_only",
        **_SAFETY_FIELDS,
    }
    if (
        agent_run.campaign_id != campaign.id
        or agent_run.task_id != task.id
        or agent_run.agent_type != task.agent_type
        or agent_run.status != "dispatched"
        or agent_run.input_refs != [f"campaign_task:{task.id}"]
        or agent_run.output_refs != []
        or agent_run.tool_calls != []
        or agent_run.safety_gate_state != "allowed"
        or agent_run.stop_reason is not None
        or agent_run.payload != expected_agent_payload
    ):
        return None

    expected_stage_payload = _runtime_stage_payload(
        campaign_id=campaign.id,
        task_type=task.task_type,
        source_snapshot_digest=source_snapshot_digest,
        outcome=_dispatch_stage_outcome(dispatch_attempt),
    )
    matching_stages = [
        stage
        for stage in task_stages
        if stage.pipeline_run_id is None
        and stage.campaign_id == campaign.id
        and stage.task_id == task.id
        and stage.stage_key == f"{_RUNTIME_STAGE_PREFIX}{task.task_type}"
        and stage.stage_order == _stage_order_for(task.task_type)
        and stage.status == "dispatched"
        and stage.input_refs == task.input_refs
        and stage.output_refs == [f"campaign_task:{task.id}", f"agent_run:{agent_run.id}"]
        and stage.safety_gate_state == "allowed"
        and stage.stop_reason is None
        and stage.payload == expected_stage_payload
    ]
    if len(matching_stages) != 1:
        return None
    return agent_run, dispatch_attempt


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
    approved_snapshot_digests = _approved_snapshot_lineage(
        campaign=campaign,
        repository=repository,
        source_snapshot_digest=source_snapshot_digest,
    )
    for task in runtime_tasks:
        if task.status not in {"dispatched", "running"}:
            continue
        expired_task = repository.expire_campaign_task_execution(task.id, now=now)
        if expired_task is None:
            continue
        record_autonomous_research_task_failure(
            task=expired_task,
            repository=repository,
            stop_reason="execution_lease_expired",
        )
        return _tick_result(
            status="awaiting_review",
            campaign_task_id=expired_task.id,
            stop_reason="execution_lease_expired",
            source_snapshot_digest=source_snapshot_digest,
        )
    for task in runtime_tasks:
        if task.status not in {"dispatched", "running"}:
            continue
        if (
            task.task_type == "report_review"
            and _has_report_review_recovery_artifact(
                task=task,
                repository=repository,
            )
        ):
            continue
        if (
            task.execution_claim_id is not None
            and task.execution_lease_expires_at is not None
        ):
            continue
        failed_task = repository.fail_incomplete_campaign_task_execution(
            task.id,
            stop_reason="recovery_dispatch_integrity_invalid",
            now=now,
        )
        if failed_task is None:
            continue
        record_autonomous_research_task_failure(
            task=failed_task,
            repository=repository,
            stop_reason="recovery_dispatch_integrity_invalid",
        )
        return _tick_result(
            status="awaiting_review",
            campaign_task_id=failed_task.id,
            stop_reason="recovery_dispatch_integrity_invalid",
            source_snapshot_digest=source_snapshot_digest,
        )
    failure_stage_recovery = _reconcile_missing_runtime_failure_stage(
        campaign=campaign,
        repository=repository,
    )
    if failure_stage_recovery is not None:
        task, stop_reason = failure_stage_recovery
        return _tick_result(
            status="awaiting_review",
            campaign_task_id=task.id,
            stop_reason=stop_reason,
            source_snapshot_digest=source_snapshot_digest,
        )
    for task in runtime_tasks:
        task_payload = task.payload
        if (
            task.status != "blocked"
            or task.task_type != "candidate_refutation"
            or "blocked_by_evidence_task_id" not in task_payload
        ):
            continue
        stop_reason = reconcile_autonomous_research_evidence_block(
            owner_task=task,
            repository=repository,
        )
        if stop_reason is None:
            stop_reason = "evidence_recovery_integrity_invalid"
            record_autonomous_research_task_blocked(
                task=task,
                repository=repository,
                stop_reason=stop_reason,
            )
        return _tick_result(
            status="blocked",
            campaign_task_id=task.id,
            stop_reason=stop_reason,
            source_snapshot_digest=source_snapshot_digest,
        )
    for task in runtime_tasks:
        task_payload = task.payload
        if (
            task.task_type != "report_review"
            or task.status not in {"running", "completed"}
            or not _has_report_review_recovery_artifact(
                task=task,
                repository=repository,
            )
        ):
            continue
        if (
            task.status == "completed"
            and task_payload.get("source_snapshot_digest")
            in approved_snapshot_digests - {source_snapshot_digest}
        ):
            continue
        stop_reason = autonomous_research_task_stop_reason(
            task=task,
            campaign=campaign,
            repository=repository,
        )
        if stop_reason is not None:
            blocked_task = (
                repository.update_campaign_task_status(task.id, "blocked") or task
            )
            record_autonomous_research_task_blocked(
                task=blocked_task,
                repository=repository,
                stop_reason=stop_reason,
            )
            return _tick_result(
                status="blocked",
                campaign_task_id=task.id,
                stop_reason=stop_reason,
                source_snapshot_digest=source_snapshot_digest,
            )
        from app.worker.tasks import recover_report_review_task

        recovered = recover_report_review_task(
            task=task,
            campaign=campaign,
            repository=repository,
        )
        return _tick_result(
            status=("completed" if recovered.get("status") == "completed" else "blocked"),
            campaign_task_id=task.id,
            stop_reason=recovered.get("stop_reason"),
            source_snapshot_digest=source_snapshot_digest,
        )
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
        task_runs = [
            run
            for run in repository.list_campaign_agent_runs(campaign.id)
            if run.task_id == task.id
        ]
        task_stages = [
            stage
            for stage in repository.list_campaign_pipeline_stages(campaign.id)
            if stage.task_id == task.id
        ]
        if task.status in {"queued", "ready"} and (task_runs or task_stages):
            orphaned_dispatch = _verified_orphaned_runtime_dispatch(
                campaign=campaign,
                task=task,
                source_snapshot_digest=source_snapshot_digest,
                task_runs=task_runs,
                task_stages=task_stages,
            )
            if orphaned_dispatch is not None:
                agent_run, dispatch_attempt = orphaned_dispatch
                return _claim_and_dispatch_runtime_task(
                    campaign=campaign,
                    task=task,
                    source_snapshot_digest=source_snapshot_digest,
                    repository=repository,
                    dispatcher=dispatcher,
                    agent_run=agent_run,
                    dispatch_attempt=dispatch_attempt,
                    now=now,
                )
            failed_task = repository.fail_unclaimed_campaign_task(
                task.id,
                stop_reason="recovery_dispatch_integrity_invalid",
                now=now,
            )
            if failed_task is None:
                return _tick_result(
                    status="awaiting_evidence",
                    campaign_task_id=task.id,
                    stop_reason="active_runtime_task",
                    source_snapshot_digest=source_snapshot_digest,
                )
            record_autonomous_research_task_failure(
                task=failed_task,
                repository=repository,
                stop_reason="recovery_dispatch_integrity_invalid",
            )
            return _tick_result(
                status="awaiting_review",
                campaign_task_id=task.id,
                stop_reason="recovery_dispatch_integrity_invalid",
                source_snapshot_digest=source_snapshot_digest,
            )
        if task_runs or task_stages:
            return _tick_result(
                status="awaiting_evidence",
                campaign_task_id=task.id,
                stop_reason="recovery_dispatch_state_ambiguous",
                source_snapshot_digest=source_snapshot_digest,
            )
        return _dispatch_runtime_task(
            campaign=campaign,
            task=task,
            source_snapshot_digest=source_snapshot_digest,
            repository=repository,
            dispatcher=dispatcher,
            now=now,
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
            if task_source_snapshot_digest in approved_snapshot_digests:
                continue
            return _tick_result(
                status="blocked",
                campaign_task_id=task.id,
                stop_reason="source_snapshot_changed",
                source_snapshot_digest=source_snapshot_digest,
            )
        if task.task_type == "report_review":
            return _tick_result(
                status="blocked",
                campaign_task_id=task.id,
                stop_reason="completion_recovery_integrity_invalid",
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


def _has_report_review_recovery_artifact(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
) -> bool:
    payload = task.payload if isinstance(task.payload, dict) else {}
    pipeline_run_id = payload.get("pipeline_run_id")
    source_snapshot_digest = payload.get("source_snapshot_digest")
    if (
        not isinstance(pipeline_run_id, str)
        or not isinstance(source_snapshot_digest, str)
        or _SOURCE_SNAPSHOT_DIGEST_PATTERN.fullmatch(source_snapshot_digest) is None
    ):
        return False
    handoff_task_id = "campaign_task_validation_handoff_" + sha256(
        f"{task.id}:{pipeline_run_id}:validation_handoff".encode("utf-8")
    ).hexdigest()
    if repository.session.get(CampaignTaskRecord, handoff_task_id) is not None:
        return True
    for handoff in repository.list_campaign_tasks(task.campaign_id):
        handoff_payload = handoff.payload if isinstance(handoff.payload, dict) else {}
        candidate_id = handoff_payload.get("candidate_id")
        if (
            handoff.task_type == "validation_handoff"
            and handoff.status in {"queued", "awaiting_approval"}
            and handoff_payload.get("schema_version")
            == "autonomous_validation_handoff_v1"
            and handoff_payload.get("pipeline_run_id") == pipeline_run_id
            and handoff_payload.get("report_review_task_id") == task.id
            and handoff_payload.get("source_snapshot_digest") == source_snapshot_digest
            and isinstance(candidate_id, str)
            and candidate_id
            and handoff_payload.get("candidate_ids") == [candidate_id]
        ):
            return True
    return any(
        stage.task_id == task.id and stage.stage_key == "autonomous_report_review"
        for stage in repository.list_pipeline_stages_for_run(pipeline_run_id)
    )


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

        evidence_tasks = [
            task
            for task in tasks
            if task.task_type == _EVIDENCE_TASK_TYPE
            and isinstance(task.payload, dict)
            and task.payload.get("owner_task_id") == owner_task.id
        ]
        if not evidence_tasks:
            continue
        evidence_task, evidence_stop_reason = _select_runtime_evidence_task(
            evidence_tasks=evidence_tasks,
            owner_task=owner_task,
            source_snapshot_digest=source_snapshot_digest,
            repository=repository,
        )
        if evidence_task is None:
            return _block_runtime_owner_for_evidence(
                owner_task=owner_task,
                evidence_task_id=None,
                stop_reason=evidence_stop_reason or "evidence_task_integrity_invalid",
                repository=repository,
                source_snapshot_digest=source_snapshot_digest,
            )

        if evidence_task.status in {"dispatched", "running"}:
            if (
                evidence_task.execution_claim_id is None
                or evidence_task.execution_lease_expires_at is None
            ):
                failed_task = repository.fail_incomplete_campaign_task_execution(
                    evidence_task.id,
                    stop_reason="evidence_execution_integrity_invalid",
                    now=now,
                )
                if failed_task is not None:
                    return _block_runtime_owner_for_evidence(
                        owner_task=owner_task,
                        evidence_task_id=evidence_task.id,
                        stop_reason="evidence_execution_integrity_invalid",
                        repository=repository,
                        source_snapshot_digest=source_snapshot_digest,
                    )
                return _tick_result(
                    status="awaiting_evidence",
                    campaign_task_id=evidence_task.id,
                    stop_reason="evidence_task_active",
                    source_snapshot_digest=source_snapshot_digest,
                )
            expired_task = repository.expire_campaign_task_execution(
                evidence_task.id,
                now=now,
            )
            if expired_task is not None:
                return _block_runtime_owner_for_evidence(
                    owner_task=owner_task,
                    evidence_task_id=evidence_task.id,
                    stop_reason="execution_lease_expired",
                    repository=repository,
                    source_snapshot_digest=source_snapshot_digest,
                )
            return _tick_result(
                status="awaiting_evidence",
                campaign_task_id=evidence_task.id,
                stop_reason="evidence_task_active",
                source_snapshot_digest=source_snapshot_digest,
            )

        if evidence_task.status == "completed":
            from app.worker.tasks import recover_completed_evidence_task

            recovered = recover_completed_evidence_task(
                task=evidence_task,
                repository=repository,
            )
            recovered_status = recovered.get("status")
            return _tick_result(
                status=(
                    "completed"
                    if recovered_status == "completed"
                    else "awaiting_evidence"
                    if recovered_status in {"awaiting_evidence", "needs_evidence"}
                    else "blocked"
                ),
                campaign_task_id=evidence_task.id,
                stop_reason=(
                    recovered.get("stop_reason")
                    if isinstance(recovered.get("stop_reason"), str)
                    else "evidence_resume_failed"
                ),
                source_snapshot_digest=source_snapshot_digest,
            )

        if evidence_task.status != "queued":
            return _block_runtime_owner_for_evidence(
                owner_task=owner_task,
                evidence_task_id=evidence_task.id,
                stop_reason="evidence_task_terminal_without_resume",
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
            now=now,
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
        and payload.get("execution_lease_required") is True
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


def _select_runtime_evidence_task(
    *,
    evidence_tasks: list[CampaignTaskRecord],
    owner_task: CampaignTaskRecord,
    source_snapshot_digest: str,
    repository: DatabaseRepository,
) -> tuple[CampaignTaskRecord | None, str | None]:
    if not all(
        _evidence_task_matches_runtime_owner(
            evidence_task=task,
            owner_task=owner_task,
            source_snapshot_digest=source_snapshot_digest,
        )
        for task in evidence_tasks
    ):
        return None, "evidence_task_integrity_invalid"

    rounds = [task.payload["round"] for task in evidence_tasks]
    if len(rounds) != len(set(rounds)):
        return None, "evidence_task_integrity_invalid"

    pending_tasks = [
        task
        for task in evidence_tasks
        if task.status in {"queued", "dispatched", "running"}
    ]
    completed_tasks = [
        task for task in evidence_tasks if task.status == "completed"
    ]
    if len(pending_tasks) > 1:
        return None, "evidence_task_integrity_invalid"
    if len(pending_tasks) + len(completed_tasks) != len(evidence_tasks):
        return None, "evidence_task_terminal_without_resume"

    if completed_tasks:
        from app.candidate_hunter_evidence import completed_evidence_result_is_valid

        if not all(
            completed_evidence_result_is_valid(repository=repository, task=task)
            for task in completed_tasks
        ):
            return None, "evidence_task_integrity_invalid"

    if pending_tasks:
        pending_task = pending_tasks[0]
        if any(
            task.payload["round"] >= pending_task.payload["round"]
            for task in completed_tasks
        ):
            return None, "evidence_task_integrity_invalid"
        return pending_task, None

    if completed_tasks:
        return max(completed_tasks, key=lambda task: task.payload["round"]), None
    return None, "evidence_task_integrity_invalid"


def _dispatch_queued_local_evidence_task(
    *,
    campaign: CampaignRecord,
    owner_task: CampaignTaskRecord,
    evidence_task: CampaignTaskRecord,
    source_snapshot_digest: str,
    repository: DatabaseRepository,
    dispatcher: Callable[..., Any],
    now: datetime | None,
) -> dict[str, Any]:
    execution_claim_id = f"agent_run_{uuid4().hex}"
    dispatched_task = repository.mark_campaign_task_dispatched(
        evidence_task.id,
        execution_claim_id=execution_claim_id,
        now=now,
    )
    if dispatched_task is None:
        return _tick_result(
            status="awaiting_evidence",
            campaign_task_id=evidence_task.id,
            stop_reason="evidence_dispatch_state_ambiguous",
            source_snapshot_digest=source_snapshot_digest,
        )
    try:
        dispatcher(campaign_task_id=evidence_task.id)
    except Exception:
        failed_task = repository.update_campaign_task_status(
            evidence_task.id,
            "failed",
            execution_claim_id=execution_claim_id,
            expected_execution_statuses={"dispatched"},
        )
        if failed_task is None:
            persisted_task = repository.session.get(
                CampaignTaskRecord,
                evidence_task.id,
            )
            if (
                persisted_task is not None
                and persisted_task.status in {"dispatched", "running", "completed"}
            ):
                return _tick_result(
                    status="awaiting_evidence",
                    campaign_task_id=evidence_task.id,
                    stop_reason="evidence_task_active",
                    source_snapshot_digest=source_snapshot_digest,
                )
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
    now: datetime | None = None,
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
        payload=build_autonomous_research_agent_payload(
            source_snapshot_digest=source_snapshot_digest,
        ),
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
    return _claim_and_dispatch_runtime_task(
        campaign=campaign,
        task=task,
        source_snapshot_digest=source_snapshot_digest,
        repository=repository,
        dispatcher=dispatcher,
        agent_run=agent_run,
        dispatch_attempt=dispatch_attempt,
        now=now,
    )


def _claim_and_dispatch_runtime_task(
    *,
    campaign: CampaignRecord,
    task: CampaignTaskRecord,
    source_snapshot_digest: str,
    repository: DatabaseRepository,
    dispatcher: Callable[..., Any],
    agent_run: Any,
    dispatch_attempt: int,
    now: datetime | None,
) -> dict[str, Any]:
    task_type = task.task_type
    dispatched_task = repository.mark_campaign_task_dispatched(
        task.id,
        execution_claim_id=agent_run.id,
        now=now,
    )
    if dispatched_task is None:
        return _tick_result(
            status="awaiting_evidence",
            campaign_task_id=task.id,
            stop_reason="active_runtime_task",
            source_snapshot_digest=source_snapshot_digest,
        )
    try:
        dispatcher(campaign_task_id=task.id)
    except Exception:
        failed_execution = repository.finish_campaign_task_execution(
            task_id=task.id,
            execution_claim_id=agent_run.id,
            task_status="failed",
            task_output_refs=[f"agent_run:{agent_run.id}"],
            agent_status="failed",
            agent_output_refs=[],
            safety_gate_state="blocked",
            stop_reason="dispatch_failed",
            payload=build_autonomous_research_agent_payload(
                source_snapshot_digest=source_snapshot_digest,
            ),
            expected_execution_statuses={"dispatched"},
        )
        if failed_execution is None:
            return _tick_result(
                status="awaiting_evidence",
                campaign_task_id=task.id,
                stop_reason="active_runtime_task",
                source_snapshot_digest=source_snapshot_digest,
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
        if campaign.status == "running":
            repository.update_campaign_status(campaign.id, "awaiting_review")
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
    candidate_model_config: CandidateModelConfig | None = None,
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
    if candidate_model_config is not None:
        payload["candidate_model"] = {
            "provider": candidate_model_config.provider.value,
            "model": candidate_model_config.model,
        }
        payload["candidate_model_config_digest"] = candidate_model_config_digest(
            candidate_model_config
        )
    return payload


def _candidate_refutation_advisory_artifact_refs(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    source_snapshot_digest: str,
) -> list[str]:
    from app.cross_source_candidate_generator import (
        registered_local_advisory_artifact_ids,
    )

    artifact_ids = registered_local_advisory_artifact_ids(
        artifacts=repository.list_artifacts(
            program_id=campaign.program_id,
            asset=campaign.default_asset,
        ),
        campaign_id=campaign.id,
        source_snapshot_digest=source_snapshot_digest,
    )
    return [f"artifact:{artifact_id}" for artifact_id in artifact_ids]


def _candidate_refutation_advisory_projection_refs(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    source_snapshot_digest: str,
    pipeline_run_id: str,
    candidate_model_config: CandidateModelConfig,
) -> list[str]:
    matching_refs: list[str] = []
    for task in repository.list_campaign_tasks(campaign.id):
        payload = task.payload if isinstance(task.payload, dict) else {}
        if (
            task.task_type != "cross_source_llm_advisory"
            or task.status != "completed"
            or payload.get("runtime_schema") != _RUNTIME_SCHEMA
            or payload.get("source_snapshot_digest") != source_snapshot_digest
            or payload.get("pipeline_run_id") != pipeline_run_id
            or not _runtime_task_has_candidate_model_config(
                payload,
                candidate_model_config,
            )
        ):
            continue
        projection_ref = f"cross_source_llm_advisory_projection:{task.id}"
        output_refs = task.output_refs if isinstance(task.output_refs, list) else []
        if output_refs.count(projection_ref) == 1:
            matching_refs.append(projection_ref)
    return matching_refs if len(matching_refs) == 1 else []


def _hypothesis_generation_learning_signal_refs(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> list[str]:
    if not isinstance(campaign.program_id, str):
        return []
    signal_ids = {
        signal.id
        for signal in repository.list_learning_signals(campaign.program_id)
        if isinstance(signal.id, str)
        and _LEARNING_SIGNAL_ID_PATTERN.fullmatch(signal.id) is not None
    }
    return [f"learning_signal:{signal_id}" for signal_id in sorted(signal_ids)]


def _finding_dedup_historical_report_stage_refs(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    pipeline_run_id: str,
    source_snapshot_digest: str,
) -> list[str]:
    from app.worker.tasks import historical_report_stage_refs_for_dedup

    return historical_report_stage_refs_for_dedup(
        campaign=campaign,
        repository=repository,
        pipeline_run_id=pipeline_run_id,
        source_snapshot_digest=source_snapshot_digest,
    )


def build_autonomous_research_agent_payload(
    *,
    source_snapshot_digest: str,
) -> dict[str, Any]:
    return {
        "runtime_schema": _RUNTIME_SCHEMA,
        "source_snapshot_digest": source_snapshot_digest,
        "dispatch_contract": "id_only",
        **_SAFETY_FIELDS,
    }


def _runtime_stage_payload(
    *,
    campaign_id: str,
    task_type: str,
    source_snapshot_digest: str,
    outcome: str,
) -> dict[str, Any]:
    safe_outcome = (
        outcome
        if isinstance(outcome, str) and _SAFE_STOP_REASON_PATTERN.fullmatch(outcome)
        else "invalid_outcome"
    )
    return {
        "runtime_schema": _RUNTIME_SCHEMA,
        "source_snapshot_digest": source_snapshot_digest,
        "outcome": safe_outcome,
        "idempotency_key": _runtime_idempotency_key(
            campaign_id=campaign_id,
            task_type=task_type,
            source_snapshot_digest=source_snapshot_digest,
            outcome=safe_outcome,
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


def _runtime_failure_stage_id(
    *,
    task_id: str,
    source_snapshot_digest: str,
    stop_reason: str,
) -> str:
    identity = ":".join((task_id, source_snapshot_digest, stop_reason))
    return "pipeline_stage_runtime_failure_" + sha256(
        identity.encode("utf-8")
    ).hexdigest()


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
    "AUTONOMOUS_RESEARCH_SNAPSHOT_REFRESH_STAGE_KEY",
    "build_autonomous_research_agent_payload",
    "build_autonomous_research_snapshot_refresh_payload",
    "record_autonomous_research_task_failure",
    "retry_autonomous_research_task",
    "select_autonomous_research_work",
    "tick_autonomous_research_campaign",
]
