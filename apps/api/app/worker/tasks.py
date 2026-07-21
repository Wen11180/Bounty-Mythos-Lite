from hashlib import sha256

from app.artifact_ingestion import normalize_artifact
from app.codebase_map import (
    CodebaseFactCandidate,
    CodebaseMapResult,
    map_authorized_code_files,
)
from app.campaign_orchestrator import campaign_elapsed_minutes, campaign_token_used_from_runs
from app.config import get_settings
from app.db import get_session_factory, initialize_database
from app.db_models import (
    CampaignRecord,
    CampaignTaskRecord,
    CodebaseFactRecord,
    LearningSignalRecord,
)
from app.mythos_brain import LearningSignal, MythosLesson, build_mythos_lessons
from app.repository import DatabaseRepository
from app.studio_workspace import load_authorized_campaign_inputs
from app.worker.celery_app import celery_app


_DISPATCHABLE_TASK_STATUSES = {"queued", "ready", "dispatched"}
_NON_DISPATCHABLE_TASK_STATUSES = {
    "awaiting_approval",
    "awaiting_evidence",
    "blocked",
    "canceled",
    "completed",
    "failed",
    "needs_evidence",
    "running",
}


@celery_app.task(name="worker.ping")
def ping() -> str:
    return "pong"


@celery_app.task(name="agent.run")
def run_agent_task_from_queue(campaign_task_id: str) -> dict:
    initialize_database()
    with get_session_factory()() as session:
        return run_agent_task(campaign_task_id, repository=DatabaseRepository(session))


@celery_app.task(name="autonomous_research.wakeup")
def run_autonomous_research_wakeup_from_queue() -> dict:
    from app.autonomous_research_wakeup import run_autonomous_research_wakeup

    initialize_database()
    with get_session_factory()() as session:
        return run_autonomous_research_wakeup(
            repository=DatabaseRepository(session),
            dispatcher=dispatch_agent_task,
        )


def dispatch_agent_task(*, campaign_task_id: str) -> dict:
    if get_settings().worker_dispatch_mode == "inline":
        result = run_agent_task_from_queue.run(campaign_task_id)
        return {
            "campaign_task_id": campaign_task_id,
            "dispatch_mode": "inline",
            "result": result,
        }

    queued_task = run_agent_task_from_queue.delay(campaign_task_id)
    return {
        "campaign_task_id": campaign_task_id,
        "dispatch_mode": "celery",
        "celery_task_id": queued_task.id,
    }


def run_agent_task(
    campaign_task_id: str,
    *,
    repository: DatabaseRepository,
) -> dict:
    task = repository.session.get(CampaignTaskRecord, campaign_task_id)
    if task is None:
        return {
            "status": "not_found",
            "task_id": campaign_task_id,
            "stop_reason": "campaign_task_not_found",
        }

    if task.status in _NON_DISPATCHABLE_TASK_STATUSES:
        return _persisted_task_result(task)
    if task.task_type == "validation_handoff":
        return _await_human_approval(task=task, repository=repository)
    if task.status not in _DISPATCHABLE_TASK_STATUSES:
        return {
            "status": "blocked",
            "task_id": task.id,
            "stop_reason": "task_not_dispatchable",
        }
    claimed_task = repository.claim_campaign_task_execution(task.id)
    if claimed_task is None:
        persisted_task = repository.session.get(CampaignTaskRecord, task.id)
        if persisted_task is None:
            return {
                "status": "not_found",
                "task_id": task.id,
                "stop_reason": "campaign_task_not_found",
            }
        return _persisted_task_result(persisted_task)
    task = claimed_task

    if task.task_type == "candidate_hunter_evidence_inspection":
        from app.candidate_hunter_evidence import (
            resume_candidate_hunter_after_evidence,
            run_evidence_inspection_task,
        )

        result = run_evidence_inspection_task(repository=repository, task_id=task.id)
        if result.get("status") != "completed":
            _record_runtime_evidence_resume(
                evidence_task=task,
                resumed=result,
                repository=repository,
            )
            return result
        resumed = resume_candidate_hunter_after_evidence(
            repository=repository,
            evidence_task_id=task.id,
        )
        _record_runtime_evidence_resume(
            evidence_task=task,
            resumed=resumed,
            repository=repository,
        )
        return resumed

    campaign = repository.get_campaign(task.campaign_id)
    stop_reason = _agent_task_stop_reason(
        campaign=campaign,
        repository=repository,
        task_id=task.id,
    )
    from app.autonomous_research_runtime import (
        autonomous_research_task_stop_reason,
    )

    if stop_reason is None:
        stop_reason = autonomous_research_task_stop_reason(
            task=task,
            campaign=campaign,
            repository=repository,
        )
    if stop_reason is not None:
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason=stop_reason,
        )
    workspace_inputs, workspace_stop_reason = _runtime_workspace_inputs(
        task=task,
        campaign=campaign,
    )
    if workspace_stop_reason is not None:
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason=workspace_stop_reason,
        )

    if task.task_type == "candidate_refutation":
        return _run_candidate_refutation_task(
            task=task,
            campaign=campaign,
            repository=repository,
            workspace_inputs=workspace_inputs,
        )

    if task.task_type == "finding_dedup_and_rank":
        return _run_finding_dedup_and_rank_task(
            task=task,
            campaign=campaign,
            repository=repository,
        )

    if task.task_type == "report_review":
        return _run_report_review_task(
            task=task,
            campaign=campaign,
            repository=repository,
        )

    active_run = repository.find_active_agent_run_for_task(task.id)
    materialized_output_refs, artifact_payload = _materialize_read_only_artifacts(
        task=task,
        campaign=campaign,
        repository=repository,
        workspace_inputs=workspace_inputs,
    )
    agent_run_output_refs = materialized_output_refs or [f"campaign_task:{task.id}:completed"]
    agent_run_payload = {
        **artifact_payload,
        "raw_payload_processed": False,
        "worker_mode": "safe_read_only_artifact_materializer",
    }
    if active_run is not None:
        agent_run = repository.finish_agent_run(
            active_run.id,
            status="completed",
            output_refs=agent_run_output_refs,
            safety_gate_state="allowed",
            stop_reason=None,
            payload=agent_run_payload,
        )
    else:
        agent_run = repository.save_agent_run(
            campaign_id=task.campaign_id,
            task_id=task.id,
            agent_type=task.agent_type,
            status="completed",
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=agent_run_output_refs,
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload=agent_run_payload,
        )
    completed_task = repository.update_campaign_task_status(
        task.id,
        "completed",
        output_refs=[f"agent_run:{agent_run.id}", *materialized_output_refs],
    )
    if completed_task is not None:
        from app.autonomous_research_runtime import (
            record_autonomous_research_task_completion,
        )

        record_autonomous_research_task_completion(
            task=completed_task,
            repository=repository,
        )
    return {
        "status": "completed",
        "task_id": task.id,
        "agent_run_id": agent_run.id,
        "stop_reason": None,
    }


def _runtime_workspace_inputs(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord | None,
) -> tuple[dict | None, str | None]:
    task_payload = task.payload if isinstance(task.payload, dict) else {}
    if task_payload.get("runtime_schema") != "autonomous_research_v1":
        return None, None
    campaign_payload = campaign.payload if campaign is not None and isinstance(campaign.payload, dict) else {}
    snapshot = campaign_payload.get("workspace_snapshot")
    if snapshot is None:
        return None, None
    try:
        inputs = load_authorized_campaign_inputs(snapshot)
    except ValueError as exc:
        reason = str(exc)
        return None, (
            "workspace_snapshot_changed"
            if reason == "workspace_snapshot_changed"
            else "workspace_snapshot_invalid"
        )
    if task_payload.get("source_snapshot_digest") != inputs.get(
        "source_snapshot_digest"
    ):
        return None, "source_snapshot_changed"
    return inputs, None


def _await_human_approval(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
) -> dict:
    repository.update_campaign_task_status(task.id, "awaiting_approval")
    return {
        "status": "awaiting_approval",
        "task_id": task.id,
        "stop_reason": "human_approval_required",
    }


def _persisted_task_result(task: CampaignTaskRecord) -> dict:
    stop_reason = {
        "awaiting_approval": "human_approval_required",
        "awaiting_evidence": "awaiting_evidence",
        "needs_evidence": "awaiting_evidence",
        "running": "task_already_running",
    }.get(task.status)
    return {
        "status": task.status,
        "task_id": task.id,
        "stop_reason": stop_reason,
    }


def _record_runtime_evidence_resume(
    *,
    evidence_task: CampaignTaskRecord,
    resumed: dict,
    repository: DatabaseRepository,
) -> None:
    payload = evidence_task.payload if isinstance(evidence_task.payload, dict) else {}
    owner_task_id = payload.get("owner_task_id")
    if not isinstance(owner_task_id, str):
        return
    owner_task = repository.session.get(CampaignTaskRecord, owner_task_id)
    owner_payload = owner_task.payload if owner_task is not None else {}
    if (
        owner_task is None
        or not isinstance(owner_payload, dict)
        or owner_payload.get("runtime_schema") != "autonomous_research_v1"
    ):
        return

    from app.autonomous_research_runtime import (
        record_autonomous_research_task_awaiting_evidence,
        record_autonomous_research_task_blocked,
        record_autonomous_research_task_completion,
    )

    if owner_task.status == "completed" and resumed.get("status") == "completed":
        pipeline_run_id = _worker_safe_string(payload.get("pipeline_run_id"))
        pipeline_run_ref = f"pipeline_run:{pipeline_run_id}"
        owner_output_refs = [
            ref for ref in owner_task.output_refs if isinstance(ref, str)
        ]
        if pipeline_run_id and pipeline_run_ref not in owner_output_refs:
            owner_task = (
                repository.update_campaign_task_status(
                    owner_task.id,
                    "completed",
                    output_refs=[*owner_output_refs, pipeline_run_ref],
                )
                or owner_task
            )
        record_autonomous_research_task_completion(
            task=owner_task,
            repository=repository,
        )
    elif owner_task.status in {"awaiting_evidence", "needs_evidence"}:
        record_autonomous_research_task_awaiting_evidence(
            task=owner_task,
            repository=repository,
        )
    elif owner_task.status == "blocked":
        record_autonomous_research_task_blocked(
            task=owner_task,
            repository=repository,
            stop_reason=_worker_safe_string(resumed.get("stop_reason"))
            or "candidate_hunter_blocked",
        )


def _block_agent_task(
    *,
    task: CampaignTaskRecord,
    repository: DatabaseRepository,
    stop_reason: str,
) -> dict:
    from app.autonomous_research_runtime import record_autonomous_research_task_blocked

    active_run = repository.find_active_agent_run_for_task(task.id)
    if active_run is not None:
        agent_run = repository.finish_agent_run(
            active_run.id,
            status="blocked",
            output_refs=[],
            safety_gate_state="blocked",
            stop_reason=stop_reason,
            payload={"raw_payload_processed": False},
        )
    else:
        agent_run = repository.save_agent_run(
            campaign_id=task.campaign_id,
            task_id=task.id,
            agent_type=task.agent_type,
            status="blocked",
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=[],
            tool_calls=[],
            safety_gate_state="blocked",
            stop_reason=stop_reason,
            payload={"raw_payload_processed": False},
        )
    blocked_task = repository.update_campaign_task_status(
        task.id,
        "blocked",
        output_refs=[f"agent_run:{agent_run.id}"],
    )
    if blocked_task is not None:
        record_autonomous_research_task_blocked(
            task=blocked_task,
            repository=repository,
            stop_reason=stop_reason,
        )
    return {
        "status": "blocked",
        "task_id": task.id,
        "agent_run_id": agent_run.id,
        "stop_reason": stop_reason,
    }


def _run_candidate_refutation_task(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    workspace_inputs: dict | None,
) -> dict:
    from app.candidate_hunter_loop import (
        build_candidate_hunter_observations,
        run_candidate_hunter_loop,
    )
    from app.autonomous_research_runtime import (
        record_autonomous_research_task_awaiting_evidence,
        record_autonomous_research_task_completion,
    )

    task_payload = task.payload if isinstance(task.payload, dict) else {}
    pipeline_run_id = task_payload.get("pipeline_run_id")
    pipeline_run = (
        repository.get_pipeline_run(pipeline_run_id)
        if isinstance(pipeline_run_id, str)
        else None
    )
    pipeline_payload = pipeline_run.payload if pipeline_run is not None else {}
    hypotheses = pipeline_payload.get("hypotheses") if isinstance(pipeline_payload, dict) else None
    if (
        pipeline_run is None
        or pipeline_run.asset != campaign.default_asset
        or pipeline_run.scope_status != "in_scope"
        or not isinstance(pipeline_payload, dict)
        or pipeline_payload.get("campaign_id") != campaign.id
        or not isinstance(hypotheses, list)
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="candidate_hunter_input_missing",
        )

    candidates = [candidate for candidate in hypotheses if isinstance(candidate, dict)]
    observations = build_candidate_hunter_observations(
        pipeline_run_id=pipeline_run.id,
        candidates=candidates,
        code_files=[],
        supplemental_code_facts=_candidate_hunter_persisted_code_facts(
            repository.list_campaign_codebase_facts(campaign.id)
        ),
        surface_facts=[],
        context_facts=[
            {"artifact_kind": "scope", "fact_type": "scope_context"},
            {"artifact_kind": "policy", "fact_type": "policy_context"},
        ],
    )
    evidence_context = None
    if workspace_inputs is not None:
        evidence_context = {
            "source_snapshot_digest": workspace_inputs["source_snapshot_digest"],
            "source_manifest": workspace_inputs["source_manifest"],
            "saved_scope_guard": {
                "scope_status": "in_scope",
                "authorized_local_root": workspace_inputs["authorized_local_root"],
            },
        }
    loop_result = run_candidate_hunter_loop(
        repository=repository,
        record=pipeline_run,
        policy_text=campaign.policy_text_hash,
        candidates=candidates,
        observations=observations,
        evidence_context=evidence_context,
    )
    loop_status = loop_result.get("status")
    if loop_status in {"blocked", "scope_not_in_scope"}:
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason=_worker_safe_string(loop_result.get("stop_reason"))
            or "candidate_hunter_blocked",
        )

    stage_ids = loop_result.get("stage_refs", [])
    safe_stage_ids = [
        stage_id
        for stage_id in stage_ids
        if isinstance(stage_id, str) and stage_id
    ] if isinstance(stage_ids, list) else []
    output_refs = [
        f"pipeline_run:{pipeline_run.id}",
        *(f"pipeline_stage:{stage_id}" for stage_id in safe_stage_ids),
    ]
    active_run = repository.find_active_agent_run_for_task(task.id)
    agent_run_payload = {
        "artifact_kind": "candidate_hunter_projection",
        "pipeline_run_id": pipeline_run.id,
        "candidate_hunter_status": _worker_safe_string(loop_status),
        "raw_payload_processed": False,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }
    if active_run is not None:
        agent_run = repository.finish_agent_run(
            active_run.id,
            status="completed",
            output_refs=output_refs,
            safety_gate_state="allowed",
            stop_reason=None,
            payload=agent_run_payload,
        )
    else:
        agent_run = repository.save_agent_run(
            campaign_id=task.campaign_id,
            task_id=task.id,
            agent_type=task.agent_type,
            status="completed",
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=output_refs,
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload=agent_run_payload,
        )
    task_output_refs = [f"agent_run:{agent_run.id}", *output_refs]
    if loop_status == "completed":
        completed_task = repository.update_campaign_task_status(
            task.id,
            "completed",
            output_refs=task_output_refs,
        )
        if completed_task is not None:
            record_autonomous_research_task_completion(
                task=completed_task,
                repository=repository,
            )
        return {
            "status": "completed",
            "task_id": task.id,
            "agent_run_id": agent_run.id,
            "stop_reason": None,
        }

    awaiting_task = repository.update_campaign_task_status(
        task.id,
        "awaiting_evidence",
        output_refs=task_output_refs,
    )
    if awaiting_task is not None:
        record_autonomous_research_task_awaiting_evidence(
            task=awaiting_task,
            repository=repository,
        )
    return {
        "status": "awaiting_evidence",
        "task_id": task.id,
        "agent_run_id": agent_run.id,
        "stop_reason": "awaiting_evidence",
    }


def _run_finding_dedup_and_rank_task(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> dict:
    from app.autonomous_research_runtime import record_autonomous_research_task_completion
    from app.candidate_hunter_loop import load_candidate_hunter_projection

    task_payload = task.payload if isinstance(task.payload, dict) else {}
    pipeline_run_id = task_payload.get("pipeline_run_id")
    pipeline_run = (
        repository.get_pipeline_run(pipeline_run_id)
        if isinstance(pipeline_run_id, str)
        else None
    )
    pipeline_payload = pipeline_run.payload if pipeline_run is not None else {}
    if (
        pipeline_run is None
        or pipeline_run.asset != campaign.default_asset
        or pipeline_run.scope_status != "in_scope"
        or not isinstance(pipeline_payload, dict)
        or pipeline_payload.get("campaign_id") != campaign.id
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="candidate_hunter_projection_missing",
        )

    projection = load_candidate_hunter_projection(
        repository=repository,
        pipeline_run_id=pipeline_run.id,
    )
    final_candidates = projection.get("final_candidates")
    decisions = projection.get("candidate_decisions")
    if (
        projection.get("status") != "ready"
        or not isinstance(final_candidates, list)
        or not isinstance(decisions, list)
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="candidate_hunter_projection_invalid",
        )

    retained_ids = {
        _worker_safe_string(decision.get("candidate_id"))
        for decision in decisions
        if isinstance(decision, dict)
        and decision.get("disposition") == "retained"
        and _worker_safe_string(decision.get("candidate_id"))
    }
    excluded_candidate_ids = sorted(
        {
            candidate_id
            for decision in decisions
            if isinstance(decision, dict)
            if decision.get("disposition") != "retained"
            if (candidate_id := _worker_safe_string(decision.get("candidate_id")))
        }
    )
    rankable_candidates = []
    for candidate in final_candidates:
        if not isinstance(candidate, dict):
            return _block_agent_task(
                task=task,
                repository=repository,
                stop_reason="candidate_hunter_projection_invalid",
            )
        candidate_id = _worker_safe_string(candidate.get("candidate_id"))
        if candidate_id not in retained_ids:
            continue
        if any(
            candidate.get(field) is not False
            for field in (
                "execution_allowed",
                "dispatch_allowed",
                "validation_allowed",
                "candidate_promotion_allowed",
                "report_submission_allowed",
            )
        ):
            return _block_agent_task(
                task=task,
                repository=repository,
                stop_reason="candidate_hunter_projection_invalid",
            )
        rankable_candidates.append(
            {
                "candidate_id": candidate_id,
                "survived_kill_score": _projection_score(candidate.get("survived_kill_score")),
                "evidence_completeness_score": _projection_score(
                    candidate.get("evidence_completeness_score")
                ),
                "priority_score": _projection_score(candidate.get("priority_score")),
            }
        )
    ranked_candidates = sorted(
        rankable_candidates,
        key=lambda candidate: (
            -candidate["survived_kill_score"],
            -candidate["evidence_completeness_score"],
            -candidate["priority_score"],
            candidate["candidate_id"],
        ),
    )[:5]
    top_candidates = [
        {
            "candidate_id": candidate["candidate_id"],
            "rank": rank,
            "survived_kill_score": candidate["survived_kill_score"],
            "evidence_completeness_score": candidate["evidence_completeness_score"],
            "priority_score": candidate["priority_score"],
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
        }
        for rank, candidate in enumerate(ranked_candidates, start=1)
    ]
    ranking_stage = repository.save_pipeline_stage(
        pipeline_run_id=pipeline_run.id,
        campaign_id=campaign.id,
        task_id=task.id,
        stage_key="autonomous_finding_dedup_and_rank",
        stage_order=30,
        status="completed",
        input_refs=[f"pipeline_run:{pipeline_run.id}"],
        output_refs=[],
        safety_gate_state="safe",
        stop_reason=None,
        payload={
            "schema_version": "autonomous_finding_dedup_and_rank_v1",
            "pipeline_run_id": pipeline_run.id,
            "idempotency_key": sha256(
                f"{task.id}:{pipeline_run.id}:finding_dedup_and_rank".encode("utf-8")
            ).hexdigest(),
            "top_candidates": top_candidates,
            "excluded_candidate_ids": excluded_candidate_ids,
            "submission_blocked": True,
            "raw_payload_processed": False,
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
        },
    )
    output_refs = [
        f"pipeline_run:{pipeline_run.id}",
        f"pipeline_stage:{ranking_stage.id}",
    ]
    active_run = repository.find_active_agent_run_for_task(task.id)
    agent_run_payload = {
        "artifact_kind": "candidate_dedup_projection",
        "pipeline_run_id": pipeline_run.id,
        "top_candidate_count": len(top_candidates),
        "raw_payload_processed": False,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }
    if active_run is not None:
        agent_run = repository.finish_agent_run(
            active_run.id,
            status="completed",
            output_refs=output_refs,
            safety_gate_state="allowed",
            stop_reason=None,
            payload=agent_run_payload,
        )
    else:
        agent_run = repository.save_agent_run(
            campaign_id=task.campaign_id,
            task_id=task.id,
            agent_type=task.agent_type,
            status="completed",
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=output_refs,
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload=agent_run_payload,
        )
    completed_task = repository.update_campaign_task_status(
        task.id,
        "completed",
        output_refs=[f"agent_run:{agent_run.id}", *output_refs],
    )
    if completed_task is not None:
        record_autonomous_research_task_completion(
            task=completed_task,
            repository=repository,
        )
    return {
        "status": "completed",
        "task_id": task.id,
        "agent_run_id": agent_run.id,
        "stop_reason": None,
    }


def _projection_score(value: object) -> int | float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return max(0, value)
    return 0


def _run_report_review_task(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> dict:
    from app.autonomous_research_runtime import record_autonomous_research_task_completion
    from app.candidate_hunter_loop import load_candidate_hunter_projection
    from app.intelligence_benchmark.candidate_report_bridge import (
        build_submission_blocked_report_bundle,
    )
    from app.mythos_report import build_report_preview_response

    task_payload = task.payload if isinstance(task.payload, dict) else {}
    pipeline_run_id = task_payload.get("pipeline_run_id")
    pipeline_run = (
        repository.get_pipeline_run(pipeline_run_id)
        if isinstance(pipeline_run_id, str)
        else None
    )
    pipeline_payload = pipeline_run.payload if pipeline_run is not None else {}
    if (
        pipeline_run is None
        or pipeline_run.asset != campaign.default_asset
        or pipeline_run.scope_status != "in_scope"
        or not isinstance(pipeline_payload, dict)
        or pipeline_payload.get("campaign_id") != campaign.id
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="report_review_input_missing",
        )

    ranking_stages = [
        stage
        for stage in repository.list_pipeline_stages_for_run(pipeline_run.id)
        if stage.stage_key == "autonomous_finding_dedup_and_rank"
        and stage.campaign_id == campaign.id
        and stage.status == "completed"
        and stage.safety_gate_state == "safe"
    ]
    if len(ranking_stages) != 1 or not isinstance(ranking_stages[0].payload, dict):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="report_review_input_missing",
        )
    ranking_payload = ranking_stages[0].payload
    top_candidates = ranking_payload.get("top_candidates")
    if (
        not isinstance(top_candidates, list)
        or ranking_payload.get("submission_blocked") is not True
        or any(ranking_payload.get(field) is not False for field in (
            "execution_allowed",
            "dispatch_allowed",
            "validation_allowed",
            "candidate_promotion_allowed",
            "report_submission_allowed",
        ))
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="report_review_input_invalid",
        )

    projection = load_candidate_hunter_projection(
        repository=repository,
        pipeline_run_id=pipeline_run.id,
    )
    final_candidates = projection.get("final_candidates")
    decisions = projection.get("candidate_decisions")
    if (
        projection.get("status") != "ready"
        or not isinstance(final_candidates, list)
        or not isinstance(decisions, list)
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="candidate_hunter_projection_invalid",
        )
    retained_ids = {
        _worker_safe_string(decision.get("candidate_id"))
        for decision in decisions
        if isinstance(decision, dict)
        and decision.get("disposition") == "retained"
        and _worker_safe_string(decision.get("candidate_id"))
    }
    candidates_by_id = {
        _worker_safe_string(candidate.get("candidate_id")): candidate
        for candidate in final_candidates
        if isinstance(candidate, dict)
        and _worker_safe_string(candidate.get("candidate_id")) in retained_ids
    }
    ordered_candidate_ids = [
        _worker_safe_string(candidate.get("candidate_id"))
        for candidate in top_candidates
        if isinstance(candidate, dict)
        and _worker_safe_string(candidate.get("candidate_id"))
    ]
    if len(ordered_candidate_ids) != len(set(ordered_candidate_ids)) or any(
        candidate_id not in candidates_by_id for candidate_id in ordered_candidate_ids
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="report_review_input_invalid",
        )
    try:
        report_drafts = [
            build_submission_blocked_report_bundle(candidates_by_id[candidate_id])
            for candidate_id in ordered_candidate_ids
        ]
    except (TypeError, ValueError):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="report_review_bundle_invalid",
        )
    if any(
        not isinstance(draft, dict)
        or draft.get("submission_blocked") is not True
        or draft.get("human_review_required") is not True
        or draft.get("execution_allowed") is not False
        or draft.get("validation_allowed") is not False
        or draft.get("report_submission_allowed") is not False
        for draft in report_drafts
    ):
        return _block_agent_task(
            task=task,
            repository=repository,
            stop_reason="report_review_bundle_invalid",
        )
    try:
        build_report_preview_response(pipeline_run)
    except ValueError:
        report_preview_available = False
    else:
        report_preview_available = True
    handoff_task_id = "campaign_task_validation_handoff_" + sha256(
        f"{task.id}:{pipeline_run.id}:validation_handoff".encode("utf-8")
    ).hexdigest()
    validation_handoff, _ = repository.claim_campaign_task(
        task_id=handoff_task_id,
        campaign_id=campaign.id,
        task_type="validation_handoff",
        agent_type="human_review",
        title="Review submission-blocked validation handoff",
        input_refs=[
            f"pipeline_run:{pipeline_run.id}",
            f"campaign_task:{task.id}",
            f"pipeline_stage:{ranking_stages[0].id}",
        ],
        payload={
            "schema_version": "autonomous_validation_handoff_v1",
            "pipeline_run_id": pipeline_run.id,
            "report_review_task_id": task.id,
            "source_snapshot_digest": task_payload.get("source_snapshot_digest"),
            "candidate_ids": ordered_candidate_ids,
            "submission_blocked": True,
            "human_review_required": True,
            "approval_required": True,
            "allowed_to_execute": False,
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
            "raw_payload_processed": False,
        },
    )
    validation_handoff = (
        repository.update_campaign_task_status(
            validation_handoff.id,
            "awaiting_approval",
        )
        or validation_handoff
    )
    report_stage = repository.save_pipeline_stage(
        pipeline_run_id=pipeline_run.id,
        campaign_id=campaign.id,
        task_id=task.id,
        stage_key="autonomous_report_review",
        stage_order=40,
        status="completed",
        input_refs=[
            f"pipeline_run:{pipeline_run.id}",
            f"pipeline_stage:{ranking_stages[0].id}",
        ],
        output_refs=[f"campaign_task:{validation_handoff.id}"],
        safety_gate_state="awaiting_review",
        stop_reason="human_review_required",
        payload={
            "schema_version": "autonomous_report_review_v1",
            "pipeline_run_id": pipeline_run.id,
            "idempotency_key": sha256(
                f"{task.id}:{pipeline_run.id}:report_review".encode("utf-8")
            ).hexdigest(),
            "submission_blocked": True,
            "human_review_required": True,
            "report_preview_available": report_preview_available,
            "report_drafts": report_drafts,
            "raw_payload_processed": False,
            "execution_allowed": False,
            "dispatch_allowed": False,
            "validation_allowed": False,
            "candidate_promotion_allowed": False,
            "report_submission_allowed": False,
        },
    )
    output_refs = [
        f"pipeline_run:{pipeline_run.id}",
        f"pipeline_stage:{report_stage.id}",
        f"campaign_task:{validation_handoff.id}",
    ]
    active_run = repository.find_active_agent_run_for_task(task.id)
    agent_run_payload = {
        "artifact_kind": "submission_blocked_report_review",
        "pipeline_run_id": pipeline_run.id,
        "report_draft_count": len(report_drafts),
        "raw_payload_processed": False,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }
    if active_run is not None:
        agent_run = repository.finish_agent_run(
            active_run.id,
            status="completed",
            output_refs=output_refs,
            safety_gate_state="allowed",
            stop_reason=None,
            payload=agent_run_payload,
        )
    else:
        agent_run = repository.save_agent_run(
            campaign_id=task.campaign_id,
            task_id=task.id,
            agent_type=task.agent_type,
            status="completed",
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=output_refs,
            tool_calls=[],
            safety_gate_state="allowed",
            stop_reason=None,
            payload=agent_run_payload,
        )
    completed_task = repository.update_campaign_task_status(
        task.id,
        "completed",
        output_refs=[f"agent_run:{agent_run.id}", *output_refs],
    )
    if completed_task is not None:
        record_autonomous_research_task_completion(
            task=completed_task,
            repository=repository,
        )
    return {
        "status": "completed",
        "task_id": task.id,
        "agent_run_id": agent_run.id,
        "stop_reason": "human_review_required",
    }


def _agent_task_stop_reason(
    *,
    campaign: CampaignRecord | None,
    repository: DatabaseRepository,
    task_id: str,
) -> str | None:
    if campaign is None:
        return "scope_not_in_scope"
    if campaign.scope_status != "in_scope":
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
    if budget is None:
        return None
    budgets = [
        budget.time_budget_minutes,
        budget.token_budget,
        budget.tool_call_budget,
    ]
    if any(value is not None and value <= 0 for value in budgets):
        return "budget_exhausted"
    if (
        budget.time_budget_minutes is not None
        and campaign_elapsed_minutes(campaign) >= budget.time_budget_minutes
    ):
        return "budget_exhausted"
    if (
        budget.token_budget is not None
        and campaign_token_used_from_runs(repository.list_campaign_agent_runs(campaign.id))
        >= budget.token_budget
    ):
        return "budget_exhausted"
    if _tool_call_budget_exhausted_for_task(campaign, repository, task_id=task_id):
        return "budget_exhausted"
    return None


def _tool_call_budget_exhausted_for_task(
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    *,
    task_id: str,
) -> bool:
    budget = repository.get_campaign_budget(campaign.id)
    if budget is None or budget.tool_call_budget is None:
        return False
    reserved_or_used = sum(
        1
        for run in repository.list_campaign_agent_runs(campaign.id)
        if run.safety_gate_state == "allowed"
        and run.task_id != task_id
    )
    return reserved_or_used >= budget.tool_call_budget


def _materialize_read_only_artifacts(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    workspace_inputs: dict | None,
) -> tuple[list[str], dict]:
    if task.task_type == "attack_surface_mapping":
        mapping_payload = task.payload
        if workspace_inputs is not None:
            mapping_payload = {
                **task.payload,
                "authorized_code_files": workspace_inputs["code_files"],
                "authorized_api_artifacts": workspace_inputs["api_artifacts"],
            }
        static_map = _map_authorized_attack_surface(mapping_payload)
        if static_map.facts:
            return _materialize_static_codebase_map(
                task=task,
                campaign=campaign,
                repository=repository,
                static_map=static_map,
            )
        codebase_map = repository.save_codebase_map(
            campaign_id=campaign.id,
            source_ref=f"campaign_task:{task.id}",
            repository=campaign.default_asset,
            commit_ref=None,
            status="mapped",
            route_count=1,
            handler_count=1,
            model_count=1,
            authz_check_count=0,
            sensitive_sink_count=1,
            provenance_refs=[f"campaign:{campaign.id}", f"campaign_task:{task.id}"],
            safety_gate_state="allowed",
            payload={"raw_payload_processed": False, "mapping_mode": "metadata_only"},
        )
        fact = repository.save_codebase_fact(
            codebase_map_id=codebase_map.id,
            campaign_id=campaign.id,
            fact_type="route",
            source_path="campaign/default_asset",
            symbol_name="authorized_surface",
            route_method="GET",
            route_path=campaign.default_asset,
            authz_hint="authorization_boundary_candidate",
            sensitivity_label="metadata_only",
            provenance_refs=[f"codebase_map:{codebase_map.id}"],
            payload={"raw_payload_processed": False},
        )
        scanner_run = repository.save_scanner_run(
            campaign_id=campaign.id,
            codebase_map_id=codebase_map.id,
            tool_name="mythos_static_mapper",
            command_hash=_stable_ref_hash(f"campaign_task:{task.id}:static_mapper"),
            status="completed",
            finding_count=0,
            candidate_count=1,
            summary="Static metadata mapped; no live request or scanner stdout stored.",
            safety_gate_state="allowed",
            payload={
                "raw_stdout": None,
                "fact_refs": [f"codebase_fact:{fact.id}"],
            },
        )
        return (
            [
                f"codebase_map:{codebase_map.id}",
                f"codebase_fact:{fact.id}",
                f"scanner_run:{scanner_run.id}",
            ],
            {
                "artifact_kind": "attack_surface_map",
                "codebase_map_id": codebase_map.id,
                "scanner_run_id": scanner_run.id,
            },
        )

    if task.task_type == "hypothesis_generation":
        codebase_facts = repository.list_campaign_codebase_facts(campaign.id)
        hypothesis_payload = (
            _codebase_fact_hypothesis_payload(
                campaign=campaign,
                task=task,
                codebase_facts=codebase_facts,
                learning_signals=repository.list_learning_signals(campaign.program_id),
            )
            if codebase_facts
            else _fallback_hypothesis_payload(campaign=campaign, task=task)
        )
        pipeline_run = repository.save_pipeline_run(
            program_id=campaign.program_id,
            asset=campaign.default_asset,
            policy_text=campaign.policy_text_hash,
            policy_text_is_hash=True,
            scope_status=campaign.scope_status,
            hypothesis_count=len(hypothesis_payload["hypotheses"]),
            blocked_count=1,
            report_title="Campaign hypothesis candidate requires human review",
            payload=hypothesis_payload,
        )
        repository.save_pipeline_stage(
            pipeline_run_id=pipeline_run.id,
            campaign_id=campaign.id,
            task_id=task.id,
            stage_key="campaign_report_preview",
            stage_order=20,
            status="awaiting_review",
            input_refs=[f"campaign_task:{task.id}"],
            output_refs=[f"pipeline_run:{pipeline_run.id}"],
            safety_gate_state="awaiting_review",
            stop_reason=None,
            payload={
                "review_gate": "human_review_required",
                "submission_allowed": False,
                "raw_payload_processed": False,
            },
        )
        return (
            [f"pipeline_run:{pipeline_run.id}"],
            {
                "artifact_kind": "hypothesis_candidates",
                "pipeline_run_id": pipeline_run.id,
            },
        )

    if task.task_type == "report_chain_review":
        validation_target = _validation_target_from_codebase_facts(
            campaign=campaign,
            repository=repository,
        )
        plan_digest = _stable_ref_hash(
            f"campaign_task:{task.id}:validation_plan:{validation_target['target_ref']}"
        )
        approval = repository.create_approval_record(
            campaign_id=campaign.id,
            task_id=task.id,
            program_id=campaign.program_id,
            approval_type="validation_batch",
            actor="worker",
            reason="Validation plan requires human approval before execution.",
            requested_action="two_account_authorization_check",
            asset=campaign.default_asset,
            validation_mode="two_account_authorization_check",
            plan_digest=plan_digest,
            autonomy_level=campaign.autonomy_level,
            safety_gate_state="awaiting_approval",
            payload={"raw_payload_processed": False},
        )
        validation_run = repository.save_validation_run(
            campaign_id=campaign.id,
            task_id=task.id,
            approval_id=None,
            validation_mode="two_account_authorization_check",
            target_ref=validation_target["target_ref"],
            status="planned",
            safety_gate_state="awaiting_approval",
            plan_digest=approval.plan_digest,
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary=validation_target["summary"],
            payload={
                "approval_record_id": approval.id,
                "raw_payload_processed": False,
                "no_live_requests": True,
                **validation_target["payload"],
            },
        )
        return (
            [f"approval:{approval.id}", f"validation_run:{validation_run.id}"],
            {
                "artifact_kind": "report_chain_gate",
                "approval_id": approval.id,
                "validation_run_id": validation_run.id,
            },
        )

    return (
        [],
        {"artifact_kind": "task_completion_marker"},
    )


def _validation_target_from_codebase_facts(
    *,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> dict:
    codebase_facts = repository.list_campaign_codebase_facts(campaign.id)
    route = _first_fact(codebase_facts, "route_handler")
    if route is None:
        return {
            "target_ref": f"campaign:{campaign.id}",
            "summary": "Validation is planned but blocked pending durable human approval.",
            "payload": {},
        }

    authz = _related_fact(codebase_facts, route, "authz_check")
    sink = _related_fact(codebase_facts, route, "sensitive_sink")
    authz_gap = _related_fact(codebase_facts, route, "authorization_gap_candidate")
    route_label = _route_label(route)
    source_facts = _hypothesis_source_facts(
        codebase_facts=codebase_facts,
        route=route,
        authz=authz,
        sink=sink,
        authz_gap=authz_gap,
    )
    return {
        "target_ref": f"codebase_fact:route_handler:{route.route_path}",
        "summary": (
            f"Validation is planned for mapped code fact {route_label} "
            "but blocked pending durable human approval."
        ),
        "payload": {
            "source_fact_refs": [fact["fact_ref"] for fact in source_facts],
            "target_route": route_label,
        },
    }


def _fallback_hypothesis_payload(
    *,
    campaign: CampaignRecord,
    task: CampaignTaskRecord,
) -> dict:
    candidate_id = "campaign_worker_hypothesis_1"
    hypothesis = {
        "hypothesis_id": candidate_id,
        "hypothesis": "Authorized object access may have a review-worthy boundary.",
        "vuln_type": "authorization_boundary",
        "broken_invariant": "Users should only access objects permitted by role and ownership.",
        "validation_mode": "two_account_authorization_check",
        "risk_level": "medium",
        "policy_risk": "medium",
        "evidence_needed": ["test_account_role_matrix", "redacted_request_response_diff"],
    }
    return {
        "campaign_id": campaign.id,
        "source_task_id": task.id,
        "target_model": {
            "objects": ["authorized_surface"],
            "roles": ["user", "owner"],
            "sensitive_actions": [],
        },
        "hypotheses": [hypothesis],
        "hypothesis_assessments": [
            {
                "candidate_id": candidate_id,
                "hypothesis_index": 0,
                "hypothesis": hypothesis,
                "candidate_status": "needs_human_review",
                "refutation": {
                    "status": "needs_human_review",
                    "reasons": ["worker_generated_candidate"],
                    "questions": [
                        "Which blocker must be resolved before any validation planning?",
                        "What safe artifact or manual observation would resolve the blocker?",
                    ],
                    "human_review_required": True,
                },
                "exploit_chain": {
                    "primitives": [
                        "authorization boundary review",
                        "non-destructive evidence comparison",
                    ],
                    "preconditions": [
                        "authorized test accounts only",
                        "human approval before validation",
                        "synthetic fixtures only",
                    ],
                    "impact": "Potential medium impact if the invariant is broken.",
                    "confidence": 0.4,
                    "safety_notes": [
                        "non_executable_chain_summary",
                        "no_payloads_or_requests",
                        "human_review_required",
                    ],
                },
                "validation_plan": {
                    "status": "approval_required",
                    "methods": ["manual_review"],
                    "steps": ["Review with test accounts only."],
                    "human_approval_required": True,
                },
            }
        ],
        "timeline": [
            {
                "name": "hypothesis_generation",
                "status": "completed",
                "summary": "Worker generated one advisory hypothesis candidate.",
                "safety_notes": ["no_live_requests", "human_review_required"],
            }
        ],
    }


def _candidate_hunter_persisted_code_facts(
    codebase_facts: list[CodebaseFactRecord],
) -> list[CodebaseFactCandidate]:
    allowed_fact_types = {
        "route_handler",
        "authz_check",
        "sensitive_sink",
        "service_call",
        "authorization_gap_candidate",
    }
    projected: list[CodebaseFactCandidate] = []
    seen: set[tuple[str, str, str, str, str, str, str, int]] = set()
    for fact in codebase_facts:
        if fact.fact_type not in allowed_fact_types:
            continue
        payload = fact.payload if isinstance(fact.payload, dict) else {}
        if payload.get("mapping_mode") == "authorized_api_artifact":
            continue
        source_path = _worker_safe_string(fact.source_path)
        symbol_name = _worker_safe_string(fact.symbol_name)
        if not source_path or not symbol_name:
            continue
        handler = _worker_safe_string(payload.get("handler")) or symbol_name
        caller = _worker_safe_string(payload.get("caller"))
        line = payload.get("line")
        safe_line = line if isinstance(line, int) and 0 < line <= 1_000_000 else 0
        key = (
            _worker_safe_string(fact.fact_type),
            source_path,
            symbol_name,
            _worker_safe_string(fact.route_method),
            _worker_safe_string(fact.route_path),
            _worker_safe_string(fact.authz_hint),
            handler,
            safe_line,
        )
        if key in seen:
            continue
        seen.add(key)
        safe_payload: dict[str, object] = {
            "handler": handler,
            "mapping_mode": "persisted_codebase_fact_projection",
            "raw_payload_processed": False,
        }
        if caller:
            safe_payload["caller"] = caller
        if safe_line:
            safe_payload["line"] = safe_line
        for name in ("root_cause", "root_symbol"):
            if value := _worker_safe_string(payload.get(name)):
                safe_payload[name] = value
        if sink_symbols := _worker_safe_string_list(payload.get("sink_symbols")):
            safe_payload["sink_symbols"] = sink_symbols
        projected.append(
            CodebaseFactCandidate(
                fact_type=_worker_safe_string(fact.fact_type),
                source_path=source_path,
                symbol_name=symbol_name,
                route_method=_worker_safe_string(fact.route_method) or None,
                route_path=_worker_safe_string(fact.route_path) or None,
                authz_hint=_worker_safe_string(fact.authz_hint) or None,
                sensitivity_label=_worker_safe_string(fact.sensitivity_label)
                or "authorized_local_code",
                payload=safe_payload,
            )
        )
    return projected


def _codebase_fact_hypothesis_payload(
    *,
    campaign: CampaignRecord,
    task: CampaignTaskRecord,
    codebase_facts: list[CodebaseFactRecord],
    learning_signals: list[LearningSignalRecord] | None = None,
) -> dict:
    routes = _worker_candidate_routes(codebase_facts)
    if not routes:
        return _fallback_hypothesis_payload(campaign=campaign, task=task)

    hypotheses: list[dict] = []
    assessments: list[dict] = []
    object_names: list[str] = []
    sensitive_actions: list[str] = []
    source_fact_refs: list[str] = []
    lessons = _worker_mythos_lessons(learning_signals or [])

    for index, route in enumerate(routes, start=1):
        candidate = _codebase_route_hypothesis(
            codebase_facts=codebase_facts,
            route=route,
            index=index,
            lessons=lessons,
        )
        hypotheses.append(candidate["hypothesis"])
        assessments.append(candidate["assessment"])
        _append_unique(object_names, candidate["object_name"])
        _append_unique(sensitive_actions, candidate["route_label"])
        for fact_ref in candidate["source_fact_refs"]:
            _append_unique(source_fact_refs, fact_ref)

    return {
        "campaign_id": campaign.id,
        "source_task_id": task.id,
        "target_model": {
            "objects": object_names,
            "roles": ["user", "owner"],
            "sensitive_actions": sensitive_actions,
            "source_fact_refs": source_fact_refs,
        },
        "hypotheses": hypotheses,
        "hypothesis_assessments": assessments,
        "autonomous_hunt_queue": _worker_autonomous_hunt_queue(assessments),
        "timeline": [
            {
                "name": "hypothesis_generation",
                "status": "completed",
                "summary": (
                    f"Worker generated {len(hypotheses)} advisory hypothesis candidate(s) "
                    "from mapped codebase facts."
                ),
                "safety_notes": [
                    "no_live_requests",
                    "codebase_facts_are_not_confirmed_findings",
                    "human_review_required",
                ],
            }
        ],
    }


def _worker_autonomous_hunt_queue(assessments: list[dict]) -> list[dict]:
    queue = []
    for assessment in assessments:
        hunter_assessment = assessment.get("hunter_assessment", {})
        quality_gate = _worker_candidate_quality_gate(assessment)
        item = {
            "queue_id": f"hunt_queue_{assessment['candidate_id']}",
            "candidate_id": assessment["candidate_id"],
            "playbook_id": hunter_assessment.get(
                "playbook_id",
                "codebase_authorization_boundary",
            ),
            "priority_score": quality_gate["priority_score"],
            "status": quality_gate["status"],
            "next_action": quality_gate["next_action"],
            "human_approval_required": True,
            "blocked_actions": [
                "execute_live_validation",
                "touch_real_user_data",
                "submit_report",
                "bypass_scope_guard",
            ],
            "safety_notes": [
                "scope_guard_required",
                "non_destructive_validation_only",
                "human_review_required",
            ],
        }
        similarity_key = _worker_candidate_similarity_key(assessment)
        if similarity_key:
            item["_candidate_similarity_key"] = similarity_key
        evidence_trace_summary = _worker_evidence_trace_summary(assessment)
        if evidence_trace_summary:
            item["evidence_trace_summary"] = evidence_trace_summary
        if quality_gate["required_evidence"]:
            item["required_evidence"] = quality_gate["required_evidence"]
        if quality_gate["satisfied_evidence"]:
            item["satisfied_evidence"] = quality_gate["satisfied_evidence"]
        review_summary = _worker_queue_review_summary(assessment)
        if review_summary:
            item.update(review_summary)
        if quality_gate["quality_gate_reasons"]:
            item["raw_priority_score"] = quality_gate["raw_priority_score"]
            item["quality_gate_reasons"] = quality_gate["quality_gate_reasons"]
        queue.append(item)
    _worker_apply_candidate_similarity_dedup(queue)
    for item in queue:
        item["report_readiness"] = _worker_report_readiness_summary(item)
    ranked_queue = sorted(queue, key=lambda item: item["priority_score"], reverse=True)[:5]
    for index, item in enumerate(ranked_queue, start=1):
        item.pop("_candidate_similarity_key", None)
        item["top_candidate_rank"] = index
    return ranked_queue


def _worker_queue_review_summary(assessment: dict) -> dict:
    hypothesis = assessment.get("hypothesis")
    if not isinstance(hypothesis, dict):
        return {}
    source_facts = hypothesis.get("source_facts")
    if not isinstance(source_facts, list) or not _source_facts_include_api_or_har(source_facts):
        return {}

    validation_plan = assessment.get("validation_plan")
    validation_steps = []
    validation_status = "approval_required"
    if isinstance(validation_plan, dict):
        validation_steps = _worker_safe_string_list(validation_plan.get("steps", []))
        validation_status = _worker_safe_string(validation_plan.get("status", "approval_required"))

    evidence_needed = _worker_safe_string_list(hypothesis.get("evidence_needed", []))
    if not evidence_needed and not validation_steps:
        return {}
    return {
        "evidence_needed": evidence_needed,
        "safe_validation_plan": validation_steps,
        "safe_validation_step_count": len(validation_steps),
        "validation_plan_status": validation_status,
    }


def _source_facts_include_api_or_har(source_facts: list[object]) -> bool:
    return any(
        isinstance(fact, dict) and fact.get("artifact_kind") in {"api", "har"}
        for fact in source_facts
    )


def _worker_evidence_trace_summary(assessment: dict) -> dict:
    hypothesis = assessment.get("hypothesis")
    if not isinstance(hypothesis, dict):
        return {}
    source_facts = hypothesis.get("source_facts")
    if not isinstance(source_facts, list):
        return {}

    artifact_kinds: list[str] = []
    source_fact_types: list[str] = []
    route_fact_count = 0
    traceable_count = 0
    for fact in source_facts:
        if not isinstance(fact, dict):
            continue
        artifact_kind = _worker_safe_trace_label(fact.get("artifact_kind", ""))
        fact_type = _worker_safe_trace_label(fact.get("fact_type", ""))
        if artifact_kind:
            _append_unique(artifact_kinds, artifact_kind)
        if fact_type:
            _append_unique(source_fact_types, fact_type)
        if fact_type == "route_handler":
            route_fact_count += 1
        if fact.get("fact_ref") and artifact_kind:
            traceable_count += 1

    source_fact_count = sum(1 for fact in source_facts if isinstance(fact, dict))
    trace_status = (
        "traceable"
        if source_fact_count > 0 and traceable_count == source_fact_count
        else "needs_evidence"
    )
    return {
        "trace_status": trace_status,
        "source_fact_count": source_fact_count,
        "traceable_source_fact_count": traceable_count,
        "route_fact_count": route_fact_count,
        "artifact_kinds": artifact_kinds,
        "source_fact_types": source_fact_types,
        "report_submission_allowed": False,
    }


def _worker_report_readiness_summary(item: dict) -> dict:
    required_evidence = _worker_safe_string_list(item.get("required_evidence", []))
    evidence_trace = item.get("evidence_trace_summary")
    trace_status = (
        evidence_trace.get("trace_status", "needs_evidence")
        if isinstance(evidence_trace, dict)
        else "needs_evidence"
    )
    safe_validation_step_count = (
        item.get("safe_validation_step_count")
        if isinstance(item.get("safe_validation_step_count"), int)
        else 0
    )

    if required_evidence:
        status = "blocked_by_required_evidence"
        next_allowed_action = "Resolve required evidence gaps before report drafting."
    elif trace_status != "traceable":
        status = "blocked_by_evidence_trace"
        next_allowed_action = "Confirm candidate source facts are traceable before report drafting."
    elif safe_validation_step_count <= 0:
        status = "needs_safe_validation_plan"
        next_allowed_action = "Draft a non-destructive validation plan before report drafting."
    else:
        status = "submission_blocked_draft_ready"
        next_allowed_action = "Prepare a submission-blocked draft for human redaction review."

    return {
        "status": status,
        "submission_blocked": True,
        "report_submission_allowed": False,
        "required_evidence_count": len(required_evidence),
        "safe_validation_step_count": max(0, safe_validation_step_count),
        "trace_status": _worker_safe_string(trace_status) or "needs_evidence",
        "next_allowed_action": next_allowed_action,
    }


def _worker_safe_trace_label(value: object) -> str:
    text = _worker_safe_string(value).lower().replace("-", "_")
    if not text or any(
        marker in text
        for marker in ("authorization", "cookie", "token", "secret", "password", "session")
    ):
        return ""
    if not all(character.isalnum() or character == "_" for character in text):
        return ""
    return text[:80]


def _worker_candidate_similarity_key(assessment: dict) -> str:
    hypothesis = assessment.get("hypothesis")
    hunter_assessment = assessment.get("hunter_assessment", {})
    if not isinstance(hypothesis, dict) or not isinstance(hunter_assessment, dict):
        return ""
    source_facts = hypothesis.get("source_facts")
    if not isinstance(source_facts, list):
        return ""

    playbook_id = _worker_safe_string(
        hunter_assessment.get("playbook_id", "codebase_authorization_boundary")
    ).lower()
    route_keys: list[str] = []
    for fact in source_facts:
        if not isinstance(fact, dict) or fact.get("fact_type") != "route_handler":
            continue
        route_path = _route_shape_path(
            _route_match_path(_worker_safe_string(fact.get("route_path", "")))
        ).lower().rstrip("/")
        if not route_path:
            continue
        route_method = _worker_safe_string(fact.get("route_method", "")).upper() or "ANY"
        _append_unique(route_keys, f"{route_method} {route_path or '/'}")
    if not route_keys:
        return ""
    return f"{playbook_id}|{sorted(route_keys)[0]}"


def _worker_apply_candidate_similarity_dedup(queue: list[dict]) -> None:
    best_by_key: set[str] = set()
    for item in sorted(queue, key=lambda candidate: candidate["priority_score"], reverse=True):
        similarity_key = item.get("_candidate_similarity_key")
        if not isinstance(similarity_key, str) or not similarity_key:
            continue
        if similarity_key not in best_by_key:
            best_by_key.add(similarity_key)
            continue

        original_priority = item["priority_score"]
        item["priority_score"] = max(0, original_priority - 20)
        item["status"] = "awaiting_deduplication_review"
        item["next_action"] = "deduplicate_candidate"
        if "raw_priority_score" not in item:
            item["raw_priority_score"] = original_priority
        required_evidence = item.setdefault("required_evidence", [])
        _append_unique(required_evidence, "prior_submission_search")
        _append_unique(required_evidence, "candidate_similarity_review")
        quality_gate_reasons = item.setdefault("quality_gate_reasons", [])
        _append_unique(quality_gate_reasons, "similar_candidate_shape")


def _worker_safe_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_worker_safe_string(item) for item in value if _worker_safe_string(item)]


def _worker_safe_string(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()[:500]


def _worker_candidate_quality_gate(assessment: dict) -> dict:
    hunter_assessment = assessment.get("hunter_assessment", {})
    raw_priority_score = hunter_assessment.get("hunter_priority_score", 65)
    priority_score = raw_priority_score
    status = "awaiting_human_approval"
    next_action = "review_validation_plan"
    required_evidence = _worker_required_evidence_from_hunter_reasons(
        hunter_assessment.get("reasons", [])
    )
    satisfied_evidence = _worker_satisfied_evidence_from_source_facts(assessment)
    required_evidence = [
        evidence for evidence in required_evidence if evidence not in satisfied_evidence
    ]
    quality_gate_reasons: list[str] = []

    if required_evidence:
        priority_score = max(0, priority_score - 25)
        status = "awaiting_evidence_review"
        next_action = "resolve_evidence_gaps"
        _append_unique(quality_gate_reasons, "required_evidence_missing")

    if _worker_candidate_source_trace_missing(assessment):
        priority_score = max(0, priority_score - 25)
        status = "awaiting_evidence_review"
        next_action = "resolve_evidence_gaps"
        _append_unique(required_evidence, "traceable_source_fact")
        _append_unique(quality_gate_reasons, "source_trace_missing")

    if hunter_assessment.get("duplicate_risk_score", 0) >= 70:
        priority_score = max(0, priority_score - 30)
        status = "awaiting_deduplication_review"
        next_action = "deduplicate_candidate"
        _append_unique(required_evidence, "prior_submission_search")
        _append_unique(required_evidence, "candidate_similarity_review")
        _append_unique(quality_gate_reasons, "duplicate_risk_high")

    return {
        "raw_priority_score": raw_priority_score,
        "priority_score": priority_score,
        "status": status,
        "next_action": next_action,
        "required_evidence": required_evidence,
        "satisfied_evidence": satisfied_evidence,
        "quality_gate_reasons": quality_gate_reasons,
    }


def _worker_candidate_source_trace_missing(assessment: dict) -> bool:
    hypothesis = assessment.get("hypothesis")
    if not isinstance(hypothesis, dict) or "source_facts" not in hypothesis:
        return False

    source_facts = hypothesis.get("source_facts")
    if not isinstance(source_facts, list) or not source_facts:
        return True

    return not any(
        isinstance(fact, dict)
        and fact.get("fact_ref")
        and fact.get("artifact_kind")
        for fact in source_facts
    )


def _worker_required_evidence_from_hunter_reasons(reasons: object) -> list[str]:
    if not isinstance(reasons, list):
        return []
    required: list[str] = []
    for reason in reasons:
        if not isinstance(reason, str):
            continue
        if "missing_evidence:independent_cross_check" in reason:
            _append_unique(required, "independent_refutation_or_static_rule")
        if "missing_evidence:authz_bypass_or_misbind_trace" in reason:
            _append_unique(required, "authz_bypass_or_misbind_trace")
        if reason == "authorization_gap_candidate":
            _append_unique(required, "independent_refutation_or_static_rule")
        if reason == "api_artifact_candidate":
            _append_unique(required, "local_code_or_har_correlation")
        if reason == "har_artifact_candidate":
            _append_unique(required, "local_code_or_api_schema_correlation")
        if "missing_evidence:declared_authentication_or_scope_model" in reason:
            _append_unique(required, "declared_authentication_or_scope_model")
        if "missing_required_artifact:policy" in reason:
            _append_unique(required, "policy")
    return required


def _worker_satisfied_evidence_from_source_facts(assessment: dict) -> list[str]:
    hypothesis = assessment.get("hypothesis")
    if not isinstance(hypothesis, dict):
        return []
    source_facts = hypothesis.get("source_facts")
    if not isinstance(source_facts, list):
        return []

    artifact_kinds = {
        fact.get("artifact_kind")
        for fact in source_facts
        if isinstance(fact, dict) and fact.get("fact_type") == "route_handler"
    }
    satisfied: list[str] = []
    if "api" in artifact_kinds and artifact_kinds.intersection({"code", "har"}):
        _append_unique(satisfied, "local_code_or_har_correlation")
    if "har" in artifact_kinds and artifact_kinds.intersection({"code", "api"}):
        _append_unique(satisfied, "local_code_or_api_schema_correlation")
    return satisfied


def _codebase_route_hypothesis(
    *,
    codebase_facts: list[CodebaseFactRecord],
    route: CodebaseFactRecord,
    index: int,
    lessons: list[MythosLesson] | None = None,
) -> dict:
    authz = _related_fact(codebase_facts, route, "authz_check")
    sink = _related_fact(codebase_facts, route, "sensitive_sink")
    authz_gap = _related_fact(codebase_facts, route, "authorization_gap_candidate")
    route_label = _route_label(route)
    source_facts = _hypothesis_source_facts(
        codebase_facts=codebase_facts,
        route=route,
        authz=authz,
        sink=sink,
        authz_gap=authz_gap,
    )
    candidate_id = f"codebase_fact_hypothesis_{index}"
    hypothesis = {
        "hypothesis_id": candidate_id,
        "hypothesis": f"Review {route_label} for object authorization boundary drift.",
        "vuln_type": "authorization_boundary",
        "broken_invariant": "Route handlers that touch sensitive sinks must preserve object ownership and role boundaries.",
        "validation_mode": "two_account_authorization_check",
        "risk_level": "medium",
        "policy_risk": "medium",
        "evidence_needed": _worker_evidence_needed(source_facts),
        "source_facts": source_facts,
    }
    primitives = [route_label]
    if authz is not None and authz.authz_hint:
        primitives.append(authz.authz_hint)
    if authz_gap is not None and authz_gap.authz_hint:
        primitives.append(authz_gap.authz_hint)
    if sink is not None and sink.symbol_name:
        primitives.append(sink.symbol_name)
    hunter_assessment = _worker_hunter_assessment(
        route_label=route_label,
        hypothesis=hypothesis["hypothesis"],
        primitives=primitives,
        authz_gap_present=authz_gap is not None,
        sink_present=sink is not None,
    )
    _apply_worker_lessons(
        hunter_assessment,
        lessons or [],
        surface_key=_worker_route_surface_key(route),
    )
    _apply_same_handler_authz_refutation(
        hunter_assessment,
        authz=authz,
        authz_gap_present=authz_gap is not None,
    )
    if _worker_route_from_api_artifact(route):
        _append_unique(hunter_assessment["reasons"], "api_artifact_candidate")
        _append_unique(hunter_assessment["evidence_focus"], "local_code_or_har_correlation")
    if _worker_route_from_har_artifact(route):
        _append_unique(hunter_assessment["reasons"], "har_artifact_candidate")
        _append_unique(hunter_assessment["evidence_focus"], "local_code_or_api_schema_correlation")
    _apply_cross_artifact_route_evidence(hunter_assessment, source_facts)
    _apply_api_shape_signals(hunter_assessment, source_facts)
    hypothesis["hunter_assessment"] = hunter_assessment
    hypothesis["priority_score"] = hunter_assessment["hunter_priority_score"]
    return {
        "assessment": {
            "candidate_id": candidate_id,
            "hypothesis_index": index - 1,
            "hypothesis": hypothesis,
            "candidate_status": "needs_human_review",
            "refutation": {
                "status": "needs_human_review",
                "reasons": ["codebase_fact_candidate_not_validated"],
                "questions": _worker_refutation_questions(authz_gap_present=authz_gap is not None),
                "human_review_required": True,
            },
            "exploit_chain": {
                "primitives": primitives,
                "preconditions": [
                    "authorized code facts only",
                    "authorized test accounts only",
                    "human approval before validation",
                ],
                "impact": "Potential object-level authorization impact if the mapped route and sink can be reached across ownership boundaries.",
                "confidence": 0.45,
                "safety_notes": [
                    "non_executable_chain_summary",
                    "no_payloads_or_requests",
                    "human_review_required",
                ],
            },
            "validation_plan": {
                "status": "approval_required",
                "methods": ["manual_review", "two_account_authorization_check"],
                "steps": _worker_validation_plan_steps(source_facts),
                "human_approval_required": True,
            },
            "hunter_assessment": hunter_assessment,
        },
        "hypothesis": hypothesis,
        "object_name": _object_from_route(route.route_path),
        "route_label": route_label,
        "source_fact_refs": [fact["fact_ref"] for fact in source_facts],
    }


def _worker_hunter_assessment(
    *,
    route_label: str,
    hypothesis: str,
    primitives: list[str],
    authz_gap_present: bool,
    sink_present: bool,
) -> dict:
    signals = " ".join([route_label, *primitives]).lower()
    reasons = ["codebase_route_candidate"]
    if authz_gap_present:
        reasons.append("authorization_gap_candidate")
    if sink_present:
        reasons.append("sensitive_sink_present")
    reasons.append("human_approval_required")

    if any(signal in signals for signal in ["team", "invite", "role_check", "update_role"]):
        assessment = {
            "playbook_id": "role_boundary",
            "playbook_label": "Role boundary / privilege escalation",
            "hunter_priority_score": 72,
            "impact_score": 82,
            "duplicate_risk_score": 20,
            "policy_risk_score": 35,
            "rejection_risk_score": 30,
            "recommendation": "needs_human_review",
            "next_action": "Prepare human-approved, test-account-only validation.",
            "reasons": reasons,
            "evidence_focus": [
                "role_matrix_snapshot",
                "member_vs_admin_request_diff",
                "permission_denial_expected_result",
            ],
            "safety_notes": [
                "advisory_only",
                "scope_guard_required",
                "human_review_required",
                "no_live_requests",
            ],
            "hypothesis": hypothesis,
        }
        _boost_authorization_gap_candidate(assessment, authz_gap_present=authz_gap_present)
        return assessment

    if any(signal in signals for signal in ["file", "export", "download", "send_file"]):
        assessment = {
            "playbook_id": "bola_idor",
            "playbook_label": "BOLA / IDOR object boundary",
            "hunter_priority_score": 68,
            "impact_score": 78,
            "duplicate_risk_score": 25,
            "policy_risk_score": 35,
            "rejection_risk_score": 30,
            "recommendation": "needs_human_review",
            "next_action": "Prepare human-approved, test-account-only validation.",
            "reasons": reasons,
            "evidence_focus": [
                "two_test_accounts",
                "same_object_id_cross_account_diff",
                "request_response_diff",
            ],
            "safety_notes": [
                "advisory_only",
                "scope_guard_required",
                "human_review_required",
                "no_live_requests",
            ],
            "hypothesis": hypothesis,
        }
        _boost_authorization_gap_candidate(assessment, authz_gap_present=authz_gap_present)
        return assessment

    assessment = {
        "playbook_id": "codebase_authorization_boundary",
        "playbook_label": "Codebase authorization boundary",
        "hunter_priority_score": 65,
        "impact_score": 75,
        "duplicate_risk_score": 25,
        "policy_risk_score": 35,
        "rejection_risk_score": 30,
        "recommendation": "needs_human_review",
        "next_action": "Prepare human-approved, test-account-only validation.",
        "reasons": reasons,
        "evidence_focus": [
            "provenance_review",
            "scope_guard_review",
            "minimal_safe_reproduction_plan",
        ],
        "safety_notes": [
            "advisory_only",
            "scope_guard_required",
            "human_review_required",
            "no_live_requests",
        ],
        "hypothesis": hypothesis,
    }
    _boost_authorization_gap_candidate(assessment, authz_gap_present=authz_gap_present)
    return assessment


def _worker_evidence_needed(source_facts: list[dict]) -> list[str]:
    evidence = [
        "redacted_route_authorization_trace",
        "test_account_role_matrix",
        "sanitized_request_response_diff",
    ]
    if _source_facts_have_api_object_identifier(source_facts):
        _append_unique(evidence, "approved_test_object_id_matrix")
    if _source_facts_have_request_body(source_facts):
        _append_unique(evidence, "request_body_field_policy_review")
    if _source_facts_missing_security_declaration(source_facts):
        _append_unique(evidence, "declared_authentication_or_scope_model")
    return evidence


def _worker_validation_plan_steps(source_facts: list[dict]) -> list[str]:
    steps = [
        "Review mapped route, authz hint, and sensitive sink provenance.",
        "Confirm scope, policy, and approved test accounts before any validation.",
    ]
    if _source_facts_have_api_object_identifier(source_facts):
        steps.append(
            "Map API object identifier fields to approved test objects before any two-account comparison."
        )
    if _source_facts_have_request_body(source_facts):
        steps.append(
            "Review request body field names locally; do not store raw body values or secrets."
        )
    if _source_facts_missing_security_declaration(source_facts):
        steps.append(
            "Resolve the declared authentication or scope model before preparing validation evidence."
        )
    if any(fact.get("artifact_kind") == "har" for fact in source_facts if isinstance(fact, dict)):
        steps.append(
            "Use only redacted HAR method and path evidence; ignore headers, cookies, and request values."
        )
    steps.append(
        "Use test accounts only after approval to compare authorized and unauthorized object access."
    )
    return steps


def _source_facts_have_api_object_identifier(source_facts: list[dict]) -> bool:
    return any(
        isinstance(fact, dict)
        and isinstance(fact.get("api_shape"), dict)
        and _api_shape_has_object_identifier(fact["api_shape"])
        for fact in source_facts
    )


def _source_facts_have_request_body(source_facts: list[dict]) -> bool:
    return any(
        isinstance(fact, dict)
        and isinstance(fact.get("api_shape"), dict)
        and bool(fact["api_shape"].get("request_body_present"))
        for fact in source_facts
    )


def _source_facts_missing_security_declaration(source_facts: list[dict]) -> bool:
    return any(
        isinstance(fact, dict)
        and fact.get("artifact_kind") == "api"
        and isinstance(fact.get("api_shape"), dict)
        and not fact["api_shape"].get("security_declared")
        for fact in source_facts
    )


def _worker_refutation_questions(*, authz_gap_present: bool) -> list[str]:
    questions = [
        "Does the mapped authorization check actually enforce the route object's owner boundary?",
        "Can redacted test-account evidence refute cross-object access before validation?",
    ]
    if not authz_gap_present:
        return questions
    return [
        "Can same-handler authorization evidence refute the missing access-control check candidate?",
        *questions,
    ]


def _boost_authorization_gap_candidate(
    assessment: dict,
    *,
    authz_gap_present: bool,
) -> None:
    if not authz_gap_present:
        return

    assessment["hunter_priority_score"] = min(100, assessment["hunter_priority_score"] + 8)
    _append_unique(assessment["evidence_focus"], "same_handler_authz_evidence")
    _append_unique(assessment["evidence_focus"], "missing_check_refutation_trace")


def _apply_same_handler_authz_refutation(
    assessment: dict,
    *,
    authz: CodebaseFactRecord | None,
    authz_gap_present: bool,
) -> None:
    if authz_gap_present or authz is None:
        return
    if authz.authz_hint not in {"owner_or_admin_check", "ownership_boundary_check"}:
        return

    assessment["hunter_priority_score"] = max(0, assessment["hunter_priority_score"] - 12)
    _append_unique(assessment["reasons"], "refutation_evidence:same_handler_object_authz")
    _append_unique(assessment["reasons"], "missing_evidence:authz_bypass_or_misbind_trace")
    _append_unique(assessment["evidence_focus"], "same_handler_object_authz_trace")
    _append_unique(assessment["evidence_focus"], "authz_bypass_or_misbind_trace")


def _worker_mythos_lessons(signals: list[LearningSignalRecord]) -> list[MythosLesson]:
    if not signals:
        return []
    return build_mythos_lessons(
        [
            LearningSignal(
                id=signal.id,
                program_id=signal.program_id,
                playbook_id=signal.playbook_id,
                outcome=signal.outcome,
                surface_key=signal.surface_key,
                notes="",
                bounty_amount=signal.bounty_amount,
                severity_delta=signal.severity_delta,
                evidence_quality=signal.evidence_quality,
                triager_feedback=None,
                target_relationships=(
                    signal.target_relationships
                    if isinstance(signal.target_relationships, list)
                    else []
                ),
                created_at=signal.created_at.isoformat() if signal.created_at else None,
            )
            for signal in signals
        ]
    )


def _apply_worker_lessons(
    hunter_assessment: dict,
    lessons: list[MythosLesson],
    *,
    surface_key: str | None,
) -> None:
    if not surface_key:
        return

    for lesson in lessons:
        if lesson.playbook_id != hunter_assessment["playbook_id"]:
            continue
        if lesson.surface_pattern != surface_key:
            continue
        bounded_delta = max(-10, min(10, lesson.score_delta))
        if lesson.recommendation == "boost":
            hunter_assessment["hunter_priority_score"] = min(
                100,
                hunter_assessment["hunter_priority_score"] + bounded_delta,
            )
            _append_unique(hunter_assessment["reasons"], "lesson:applied:boost")
        elif lesson.recommendation == "duplicate_watch":
            hunter_assessment["duplicate_risk_score"] = min(
                100,
                hunter_assessment["duplicate_risk_score"] + abs(bounded_delta),
            )
            hunter_assessment["hunter_priority_score"] = max(
                0,
                hunter_assessment["hunter_priority_score"] - round(abs(bounded_delta) * 0.5),
            )
            _append_unique(hunter_assessment["reasons"], "lesson:applied:duplicate_watch")
        elif lesson.recommendation in {"penalize", "evidence_needed"}:
            hunter_assessment["hunter_priority_score"] = max(
                0,
                hunter_assessment["hunter_priority_score"] + bounded_delta,
            )
            _append_unique(
                hunter_assessment["reasons"],
                f"lesson:applied:{lesson.recommendation}",
            )

        for reason in lesson.reasons:
            _append_unique(hunter_assessment["reasons"], reason)
        for note in lesson.safety_notes:
            _append_unique(hunter_assessment["safety_notes"], note)


def _worker_route_surface_key(route: CodebaseFactRecord) -> str | None:
    if not route.route_path:
        return None
    segments = [segment for segment in route.route_path.strip("/").split("/") if segment]
    for index, segment in enumerate(segments):
        if segment.startswith("{") and segment.endswith("}"):
            object_key = segment.strip("{}")
            action = next(
                (
                    candidate
                    for candidate in segments[index + 1 :]
                    if not (candidate.startswith("{") and candidate.endswith("}"))
                ),
                None,
            )
            return f"{object_key}:{action or _worker_method_action(route.route_method)}"
    return None


def _worker_method_action(method: str | None) -> str:
    return {
        "GET": "read",
        "POST": "write",
        "PUT": "write",
        "PATCH": "write",
        "DELETE": "delete",
    }.get((method or "GET").upper(), "review")


def _apply_cross_artifact_route_evidence(
    hunter_assessment: dict,
    source_facts: list[dict],
) -> None:
    artifact_kinds = {
        fact.get("artifact_kind")
        for fact in source_facts
        if isinstance(fact, dict) and fact.get("fact_type") == "route_handler"
    }
    if "api" in artifact_kinds and artifact_kinds.intersection({"code", "har"}):
        _append_unique(hunter_assessment["reasons"], "evidence_satisfied:local_code_or_har_correlation")
        _append_unique(hunter_assessment["evidence_focus"], "cross_artifact_route_correlation")
    if "har" in artifact_kinds and artifact_kinds.intersection({"code", "api"}):
        _append_unique(hunter_assessment["reasons"], "evidence_satisfied:local_code_or_api_schema_correlation")
        _append_unique(hunter_assessment["evidence_focus"], "cross_artifact_route_correlation")


def _apply_api_shape_signals(
    hunter_assessment: dict,
    source_facts: list[dict],
) -> None:
    api_shapes = [
        fact.get("api_shape")
        for fact in source_facts
        if isinstance(fact, dict)
        and fact.get("artifact_kind") == "api"
        and isinstance(fact.get("api_shape"), dict)
    ]
    if not api_shapes:
        return

    if any(_api_shape_has_object_identifier(shape) for shape in api_shapes):
        hunter_assessment["hunter_priority_score"] = min(
            100,
            hunter_assessment.get("hunter_priority_score", 65) + 4,
        )
        _append_unique(hunter_assessment["reasons"], "api_shape:object_identifier_present")
        _append_unique(hunter_assessment["evidence_focus"], "api_object_identifier_shape")

    if any(shape.get("request_body_present") for shape in api_shapes):
        _append_unique(hunter_assessment["reasons"], "api_shape:request_body_present")
        _append_unique(hunter_assessment["evidence_focus"], "request_body_field_review")

    if any(not shape.get("security_declared") for shape in api_shapes):
        _append_unique(
            hunter_assessment["reasons"],
            "missing_evidence:declared_authentication_or_scope_model",
        )
        _append_unique(hunter_assessment["evidence_focus"], "declared_authentication_or_scope_model")


def _api_shape_has_object_identifier(shape: dict) -> bool:
    values: list[str] = []
    for key in ("path_parameters", "query_parameters", "body_fields"):
        names = shape.get(key)
        if isinstance(names, list):
            values.extend(name for name in names if isinstance(name, str))
    return any(_api_shape_name_looks_like_object_id(name) for name in values)


def _api_shape_name_looks_like_object_id(name: str) -> bool:
    normalized = name.lower().replace("-", "_")
    return normalized == "id" or normalized.endswith("_id")


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _first_fact(
    facts: list[CodebaseFactRecord],
    fact_type: str,
) -> CodebaseFactRecord | None:
    return next((fact for fact in facts if fact.fact_type == fact_type), None)


def _related_fact(
    facts: list[CodebaseFactRecord],
    route: CodebaseFactRecord,
    fact_type: str,
) -> CodebaseFactRecord | None:
    route_handler = route.payload.get("handler") if isinstance(route.payload, dict) else None
    return next(
        (
            fact
            for fact in facts
            if fact.fact_type == fact_type
            and fact.source_path == route.source_path
            and _same_handler_or_legacy_fact(route_handler, fact)
        ),
        None,
    )


def _worker_candidate_routes(
    codebase_facts: list[CodebaseFactRecord],
) -> list[CodebaseFactRecord]:
    route_groups: list[list[CodebaseFactRecord]] = []
    for fact in codebase_facts:
        if fact.fact_type != "route_handler":
            continue
        group = next(
            (
                group
                for group in route_groups
                if _routes_equivalent(fact, group[0])
            ),
            None,
        )
        if group is None:
            route_groups.append([fact])
            continue
        group.append(fact)

    routes: list[CodebaseFactRecord] = []
    for group in route_groups:
        routes.append(
            sorted(
                group,
                key=lambda fact: (
                    _route_candidate_priority(fact),
                    fact.source_path,
                    fact.symbol_name or "",
                ),
            )[0]
        )
    return sorted(
        routes,
        key=lambda fact: (
            fact.source_path,
            fact.route_method or "",
            fact.route_path or "",
            fact.symbol_name,
        ),
    )


def _route_candidate_priority(fact: CodebaseFactRecord) -> int:
    payload = fact.payload if isinstance(fact.payload, dict) else {}
    if payload.get("mapping_mode") != "authorized_api_artifact":
        return 0
    if payload.get("artifact_kind") == "har":
        return 2
    return 1


def _routes_equivalent(left: CodebaseFactRecord, right: CodebaseFactRecord) -> bool:
    if (left.route_method or "GET").upper() != (right.route_method or "GET").upper():
        return False

    left_path = _route_match_path(left.route_path or left.source_path)
    right_path = _route_match_path(right.route_path or right.source_path)
    if left_path == right_path:
        return True
    if not (
        _route_path_has_template_placeholder(left_path)
        or _route_path_has_template_placeholder(right_path)
    ):
        return False
    return _route_shape_path(left_path) == _route_shape_path(right_path)


def _route_match_path(path: str | None) -> str:
    if not path:
        return ""
    return path.split("?", 1)[0].strip()


def _route_path_has_template_placeholder(path: str) -> bool:
    return any(
        _route_segment_is_template_placeholder(segment)
        for segment in path.strip("/").split("/")
        if segment
    )


def _route_shape_path(path: str) -> str:
    leading_slash = path.startswith("/")
    segments = [segment for segment in path.strip("/").split("/") if segment]
    equivalent_segments = [
        "{}" if _route_segment_is_dynamic(segment) else segment
        for segment in segments
    ]
    equivalent_path = "/".join(equivalent_segments)
    if leading_slash:
        return f"/{equivalent_path}" if equivalent_path else "/"
    return equivalent_path


def _route_segment_is_dynamic(segment: str) -> bool:
    if _route_segment_is_template_placeholder(segment):
        return True
    return _har_route_segment_looks_dynamic(segment)


def _route_segment_is_template_placeholder(segment: str) -> bool:
    if len(segment) >= 2 and segment.startswith("{") and segment.endswith("}"):
        return True
    if len(segment) >= 2 and segment.startswith(":"):
        return True
    if len(segment) >= 2 and segment.startswith("<") and segment.endswith(">"):
        return True
    return False


def _har_route_segment_looks_dynamic(segment: str) -> bool:
    if segment.isdigit():
        return True
    lowered = segment.lower()
    parts = lowered.split("-")
    if (
        len(parts) == 5
        and [len(part) for part in parts] == [8, 4, 4, 4, 12]
        and all(_is_hex(part) for part in parts)
    ):
        return True
    compact = lowered.replace("-", "")
    if len(compact) >= 16 and compact.isalnum() and not compact.isalpha():
        return True
    return False


def _is_hex(value: str) -> bool:
    return bool(value) and all(character in "0123456789abcdef" for character in value)


def _same_handler_or_legacy_fact(
    route_handler: object,
    fact: CodebaseFactRecord,
) -> bool:
    if not route_handler:
        return True
    fact_handler = fact.payload.get("handler") if isinstance(fact.payload, dict) else None
    if _has_static_mapper_scope(fact):
        return fact_handler == route_handler
    return fact_handler in {None, route_handler}


def _has_static_mapper_scope(fact: CodebaseFactRecord) -> bool:
    if not isinstance(fact.payload, dict):
        return False
    return fact.payload.get("mapping_mode") == "static_code_snippet_analysis"


def _route_label(route: CodebaseFactRecord) -> str:
    method = route.route_method or "GET"
    path = route.route_path or route.source_path
    return f"{method} {path}"


def _hypothesis_source_facts(
    *,
    codebase_facts: list[CodebaseFactRecord],
    route: CodebaseFactRecord,
    authz: CodebaseFactRecord | None,
    sink: CodebaseFactRecord | None,
    authz_gap: CodebaseFactRecord | None = None,
) -> list[dict]:
    facts = [_route_source_fact(route)]
    for related_route in _related_route_artifact_facts(codebase_facts, route):
        facts.append(_route_source_fact(related_route))
    if authz is not None:
        facts.append(_authz_source_fact(authz))
    if authz_gap is not None:
        facts.append(_authz_gap_source_fact(authz_gap))
    if sink is not None:
        facts.append(_sink_source_fact(sink))
    return facts


def _related_route_artifact_facts(
    facts: list[CodebaseFactRecord],
    route: CodebaseFactRecord,
) -> list[CodebaseFactRecord]:
    related: list[CodebaseFactRecord] = []
    for fact in facts:
        if fact.id == route.id or fact.fact_type != "route_handler":
            continue
        if not _routes_equivalent(fact, route):
            continue
        if _route_artifact_kind(fact) not in {"api", "har"}:
            continue
        related.append(fact)
    return sorted(related, key=lambda fact: (_route_artifact_kind(fact), fact.source_path))


def _route_source_fact(fact: CodebaseFactRecord) -> dict:
    artifact_kind = _route_artifact_kind(fact)
    payload = fact.payload if isinstance(fact.payload, dict) else {}
    fact_ref = f"codebase_fact:route_handler:{fact.route_path}"
    if artifact_kind in {"api", "har"}:
        fact_ref = f"{artifact_kind}_artifact:route:{fact.route_method}:{fact.route_path}"
    source_fact = {
        "fact_ref": fact_ref,
        "artifact_kind": artifact_kind,
        "fact_type": fact.fact_type,
        "route_method": fact.route_method,
        "route_path": fact.route_path,
        "source_path": fact.source_path,
        "symbol_name": fact.symbol_name,
    }
    api_shape = payload.get("api_shape")
    if isinstance(api_shape, dict) and api_shape:
        source_fact["api_shape"] = api_shape
    return source_fact


def _route_artifact_kind(fact: CodebaseFactRecord) -> str:
    payload = fact.payload if isinstance(fact.payload, dict) else {}
    artifact_kind = payload.get("artifact_kind")
    if artifact_kind == "har":
        return "har"
    if payload.get("mapping_mode") == "authorized_api_artifact":
        return "api"
    return "code"


def _authz_source_fact(fact: CodebaseFactRecord) -> dict:
    return {
        "fact_ref": f"codebase_fact:authz_check:{fact.authz_hint}",
        "artifact_kind": "code",
        "authz_hint": fact.authz_hint,
        "fact_type": fact.fact_type,
        "source_path": fact.source_path,
        "symbol_name": fact.symbol_name,
    }


def _sink_source_fact(fact: CodebaseFactRecord) -> dict:
    return {
        "fact_ref": f"codebase_fact:sensitive_sink:{fact.symbol_name}",
        "artifact_kind": "code",
        "fact_type": fact.fact_type,
        "source_path": fact.source_path,
        "symbol_name": fact.symbol_name,
    }


def _authz_gap_source_fact(fact: CodebaseFactRecord) -> dict:
    payload = fact.payload if isinstance(fact.payload, dict) else {}
    return {
        "fact_ref": f"codebase_fact:authorization_gap_candidate:{fact.route_path}",
        "artifact_kind": "code",
        "authz_hint": fact.authz_hint,
        "fact_type": fact.fact_type,
        "route_method": fact.route_method,
        "route_path": fact.route_path,
        "source_path": fact.source_path,
        "symbol_name": fact.symbol_name,
        "root_cause": payload.get(
            "root_cause",
            "missing_object_ownership_check",
        ),
        "security_invariant": payload.get(
            "security_invariant",
            "Object-level actions must verify requester ownership or role before sensitive sinks run.",
        ),
        "sink_count": payload.get("sink_count", 0),
        "sink_symbols": payload.get("sink_symbols", []),
        "review_state": payload.get("review_state", "needs_human_review"),
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _object_from_route(route_path: str | None) -> str:
    if not route_path:
        return "object"
    first_segment = route_path.strip("/").split("/", 1)[0]
    if first_segment.endswith("ies"):
        return f"{first_segment[:-3]}y"
    if first_segment.endswith("s") and len(first_segment) > 1:
        return first_segment[:-1]
    return first_segment or "object"


def _map_authorized_attack_surface(payload: dict) -> CodebaseMapResult:
    code_map = map_authorized_code_files(payload)
    api_facts = _map_authorized_api_artifacts(payload)
    return CodebaseMapResult(
        facts=[*code_map.facts, *api_facts],
        file_count=code_map.file_count,
    )


def _map_authorized_api_artifacts(payload: dict) -> list[CodebaseFactCandidate]:
    artifacts = payload.get("authorized_api_artifacts")
    if not isinstance(artifacts, list):
        return []

    facts: list[CodebaseFactCandidate] = []
    seen_routes: set[tuple[str, str, str]] = set()
    for index, artifact in enumerate(artifacts, start=1):
        if not isinstance(artifact, dict):
            continue
        kind = artifact.get("kind")
        artifact_payload = artifact.get("payload")
        if not isinstance(kind, str) or not isinstance(artifact_payload, dict):
            continue
        try:
            normalized = normalize_artifact(kind, artifact_payload)
        except ValueError:
            continue
        source_name = (
            artifact.get("source_name")
            if isinstance(artifact.get("source_name"), str)
            else f"authorized_{normalized.kind}_{index}"
        )
        paths = normalized.openapi_like.get("paths", {})
        if not isinstance(paths, dict):
            continue
        for path, path_item in sorted(paths.items()):
            if not isinstance(path, str) or not isinstance(path_item, dict):
                continue
            for method, operation in sorted(path_item.items()):
                if not isinstance(method, str) or not _api_artifact_http_method(method):
                    continue
                route_method = method.upper()
                dedupe_key = (normalized.kind, route_method, path)
                if dedupe_key in seen_routes:
                    continue
                seen_routes.add(dedupe_key)
                operation_id = _api_operation_id(
                    kind=normalized.kind,
                    method=method,
                    operation=operation,
                    path=path,
                )
                facts.append(
                    CodebaseFactCandidate(
                        fact_type="route_handler",
                        source_path=str(source_name),
                        symbol_name=operation_id,
                        route_method=route_method,
                        route_path=path,
                        authz_hint=None,
                        sensitivity_label="authorized_api_artifact",
                        payload={
                            "api_shape": _api_operation_shape(
                                operation=operation,
                                path_item=path_item,
                                artifact_kind=normalized.kind,
                            ),
                            "artifact_kind": normalized.kind,
                            "handler": operation_id,
                            "mapping_mode": "authorized_api_artifact",
                            "operation_id": operation_id,
                            "raw_payload_processed": False,
                            "source_name": str(source_name),
                        },
                    )
                )
    return facts


def _api_operation_shape(
    *,
    operation: object,
    path_item: dict,
    artifact_kind: str,
) -> dict:
    if artifact_kind == "har":
        return {"observed_request_shape": True}
    if not isinstance(operation, dict):
        return {}

    path_parameters: list[str] = []
    query_parameters: list[str] = []
    parameter_sources = [path_item.get("parameters"), operation.get("parameters")]
    for parameters in parameter_sources:
        if not isinstance(parameters, list):
            continue
        for parameter in parameters:
            if not isinstance(parameter, dict):
                continue
            name = parameter.get("name")
            location = parameter.get("in")
            if not isinstance(name, str) or not isinstance(location, str):
                continue
            if not _safe_api_shape_name(name):
                continue
            if location == "path":
                _append_unique(path_parameters, name)
            elif location == "query":
                _append_unique(query_parameters, name)

    request_body = operation.get("requestBody")
    body_fields = _api_request_body_fields(request_body)
    shape = {
        "path_parameters": path_parameters,
        "query_parameters": query_parameters,
        "body_fields": body_fields,
        "request_body_present": isinstance(request_body, dict),
        "security_declared": bool(operation.get("security") or path_item.get("security")),
    }
    return {key: value for key, value in shape.items() if value not in ([], False)}


def _api_artifact_http_method(method: str) -> bool:
    return method.lower() in {
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "options",
        "head",
    }


def _api_request_body_fields(request_body: object) -> list[str]:
    if not isinstance(request_body, dict):
        return []
    content = request_body.get("content")
    if not isinstance(content, dict):
        return []

    fields: list[str] = []
    for media_type in sorted(content):
        media = content.get(media_type)
        if not isinstance(media, dict):
            continue
        schema = media.get("schema")
        for field in _api_schema_property_names(schema):
            if _safe_api_shape_name(field):
                _append_unique(fields, field)
    return fields


def _api_schema_property_names(schema: object) -> list[str]:
    if not isinstance(schema, dict):
        return []
    properties = schema.get("properties")
    if isinstance(properties, dict):
        return [name for name in properties if isinstance(name, str)]
    nested_names: list[str] = []
    for key in ("allOf", "anyOf", "oneOf"):
        variants = schema.get(key)
        if not isinstance(variants, list):
            continue
        for variant in variants:
            for name in _api_schema_property_names(variant):
                _append_unique(nested_names, name)
    return nested_names


def _safe_api_shape_name(name: str) -> bool:
    lowered = name.lower()
    sensitive_terms = (
        "authorization",
        "cookie",
        "token",
        "secret",
        "password",
        "passwd",
        "session",
        "credential",
        "api_key",
        "apikey",
    )
    return not any(term in lowered for term in sensitive_terms)


def _api_operation_id(
    *,
    kind: str,
    method: str,
    operation: object,
    path: str,
) -> str:
    if isinstance(operation, dict) and isinstance(operation.get("operationId"), str):
        operation_id = operation["operationId"].strip()
        if operation_id:
            return operation_id
    suffix = path.strip("/").replace("{", "").replace("}", "").replace("/", "_")
    return f"{kind}_{method.lower()}_{suffix or 'root'}"


def _worker_route_from_api_artifact(route: CodebaseFactRecord) -> bool:
    payload = route.payload if isinstance(route.payload, dict) else {}
    artifact_kind = payload.get("artifact_kind")
    return payload.get("mapping_mode") == "authorized_api_artifact" and artifact_kind != "har"


def _worker_route_from_har_artifact(route: CodebaseFactRecord) -> bool:
    payload = route.payload if isinstance(route.payload, dict) else {}
    return (
        payload.get("mapping_mode") == "authorized_api_artifact"
        and payload.get("artifact_kind") == "har"
    )


def _materialize_static_codebase_map(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
    static_map: CodebaseMapResult,
) -> tuple[list[str], dict]:
    codebase_map = repository.save_codebase_map(
        campaign_id=campaign.id,
        source_ref=f"campaign_task:{task.id}",
        repository=campaign.default_asset,
        commit_ref=None,
        status="mapped",
        route_count=static_map.route_count,
        handler_count=static_map.handler_count,
        model_count=static_map.model_count,
        authz_check_count=static_map.authz_check_count,
        sensitive_sink_count=static_map.sensitive_sink_count,
        provenance_refs=[f"campaign:{campaign.id}", f"campaign_task:{task.id}"],
        safety_gate_state="allowed",
        payload={
            "file_count": static_map.file_count,
            "mapping_mode": _static_map_mapping_mode(static_map),
            **_static_map_api_artifact_counts(static_map),
            "raw_payload_processed": False,
        },
    )
    fact_refs: list[str] = []
    for candidate in static_map.facts:
        fact = repository.save_codebase_fact(
            codebase_map_id=codebase_map.id,
            campaign_id=campaign.id,
            fact_type=candidate.fact_type,
            source_path=candidate.source_path,
            symbol_name=candidate.symbol_name,
            route_method=candidate.route_method,
            route_path=candidate.route_path,
            authz_hint=candidate.authz_hint,
            sensitivity_label=candidate.sensitivity_label,
            provenance_refs=[f"codebase_map:{codebase_map.id}"],
            payload=candidate.payload,
        )
        fact_refs.append(f"codebase_fact:{fact.id}")

    scanner_run = repository.save_scanner_run(
        campaign_id=campaign.id,
        codebase_map_id=codebase_map.id,
        tool_name="mythos_static_code_mapper",
        command_hash=_stable_ref_hash(f"campaign_task:{task.id}:static_code_mapper"),
        status="completed",
        finding_count=0,
        candidate_count=len(fact_refs),
        summary="Authorized static code snippets mapped; no code body or scanner stdout stored.",
        safety_gate_state="allowed",
        payload={
            "raw_stdout": None,
            "fact_refs": fact_refs,
        },
    )
    return (
        [
            f"codebase_map:{codebase_map.id}",
            *fact_refs,
            f"scanner_run:{scanner_run.id}",
        ],
        {
            "artifact_kind": "attack_surface_map",
            "codebase_map_id": codebase_map.id,
            "scanner_run_id": scanner_run.id,
            "static_fact_count": len(fact_refs),
        },
    )


def _static_map_mapping_mode(static_map: CodebaseMapResult) -> str:
    if _static_map_api_artifact_counts(static_map):
        return "authorized_attack_surface_analysis"
    return "static_code_snippet_analysis"


def _static_map_api_artifact_counts(static_map: CodebaseMapResult) -> dict:
    route_count = sum(
        1
        for fact in static_map.facts
        if isinstance(fact.payload, dict)
        and fact.payload.get("mapping_mode") == "authorized_api_artifact"
    )
    if route_count == 0:
        return {}
    return {"api_artifact_route_count": route_count}


def _stable_ref_hash(value: str) -> str:
    return f"sha256:{sha256(value.encode('utf-8')).hexdigest()}"
