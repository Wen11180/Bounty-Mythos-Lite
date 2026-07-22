from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256
import json
from pathlib import Path
from typing import Any

from sqlalchemy.exc import IntegrityError

from app.codebase_map import SUPPORTED_CODE_SOURCE_SUFFIXES
from app.db_models import AgentRunRecord, CampaignTaskRecord, PipelineStageRecord
from app.studio_workspace import (
    StudioWorkspaceAccessError,
    load_authorized_campaign_inputs,
)


SAFETY_FIELDS = (
    "execution_allowed",
    "dispatch_allowed",
    "validation_allowed",
    "candidate_promotion_allowed",
    "report_submission_allowed",
    "raw_payload_processed",
)
TASK_SCHEMA_VERSION = "candidate_hunter_evidence_task_v1"
RESULT_SCHEMA_VERSION = "candidate_hunter_evidence_result_v1"
ATTEMPT_SCHEMA_VERSION = "candidate_hunter_evidence_attempt_v1"
INSPECTOR_TOOL = "candidate_hunter_local_evidence_inspector"
AUTHORIZED_SOURCE_SUFFIXES = set(SUPPORTED_CODE_SOURCE_SUFFIXES) | {
    ".js",
    ".jsx",
}
MAX_AUTHORIZED_SOURCE_FILES = 20
MAX_AUTHORIZED_SOURCE_CHARS = 20_000


def materialize_evidence_inspection_task(
    *,
    repository: Any,
    pipeline_run: Any,
    campaign: Any,
    owner_task: Any,
    evidence_request_stage: Any,
) -> CampaignTaskRecord:
    request_payload = _safe_payload(getattr(evidence_request_stage, "payload", {}))
    state_digest = _text(request_payload.get("state_digest"))
    round_number = request_payload.get("round")
    if (
        getattr(evidence_request_stage, "stage_key", "")
        != "candidate_hunter_evidence_request"
        or not state_digest
        or not isinstance(round_number, int)
        or isinstance(round_number, bool)
        or round_number < 1
        or not _has_false_safety_fields(request_payload)
    ):
        raise ValueError("evidence_request_stage_invalid")

    requests = request_payload.get("evidence_requests")
    if not isinstance(requests, list):
        raise ValueError("evidence_request_payload_invalid")
    safe_requests = [_safe_request(item) for item in requests]
    safe_requests = [item for item in safe_requests if item is not None]
    if not safe_requests:
        raise ValueError("evidence_requests_missing")

    pipeline_run_id = _text(getattr(pipeline_run, "id", ""))
    campaign_id = _text(getattr(campaign, "id", ""))
    owner_task_id = _text(getattr(owner_task, "id", ""))
    stage_id = _text(getattr(evidence_request_stage, "id", ""))
    campaign_payload = _safe_payload(getattr(campaign, "payload", {}))
    source_snapshot_digest = _bare_source_snapshot_digest(
        campaign_payload.get("source_snapshot_digest")
    )
    if not pipeline_run_id or not campaign_id or not owner_task_id or not stage_id:
        raise ValueError("evidence_owner_invalid")
    if not source_snapshot_digest:
        raise ValueError("source_snapshot_missing")

    candidate_ids = _ordered_unique(
        item["candidate_id"] for item in safe_requests if item["candidate_id"]
    )
    requested_artifact_kinds = _ordered_unique(
        kind
        for item in safe_requests
        for kind in item["requested_artifact_kinds"]
    )
    refutation_questions = _ordered_unique(
        question
        for item in safe_requests
        for question in item["refutation_questions"]
    )
    inspection_targets = _ordered_targets(
        target
        for item in safe_requests
        for target in item["inspection_targets"]
    )
    idempotency_key = _task_idempotency_key(
        pipeline_run_id=pipeline_run_id,
        evidence_request_stage_id=stage_id,
        state_digest=state_digest,
    )
    task_id = f"campaign_task_{idempotency_key}"
    owner_payload = _safe_payload(getattr(owner_task, "payload", {}))
    runtime_owner = (
        getattr(owner_task, "task_type", "") == "candidate_refutation"
        and owner_payload.get("runtime_schema") == "autonomous_research_v1"
    )
    payload = {
        "schema_version": TASK_SCHEMA_VERSION,
        "execution_lease_required": runtime_owner,
        "pipeline_run_id": pipeline_run_id,
        "evidence_request_stage_id": stage_id,
        "owner_task_id": owner_task_id,
        "round": round_number,
        "state_digest": state_digest,
        "source_snapshot_digest": source_snapshot_digest,
        "candidate_ids": candidate_ids,
        "requested_artifact_kinds": requested_artifact_kinds,
        "refutation_questions": refutation_questions,
        "inspection_targets": inspection_targets,
        "idempotency_key": idempotency_key,
        **_false_safety_fields(),
    }
    task = _save_task_once(
        repository=repository,
        task_id=task_id,
        campaign_id=campaign_id,
        pipeline_run_id=pipeline_run_id,
        evidence_request_stage_id=stage_id,
        payload=payload,
    )
    if not (
        runtime_owner
        and isinstance(getattr(owner_task, "execution_claim_id", None), str)
        and owner_task.execution_claim_id
    ):
        repository.update_campaign_task_status(
            owner_task_id,
            "needs_evidence",
            output_refs=[],
        )
    return task


def run_evidence_inspection_task(*, repository: Any, task_id: str) -> dict[str, Any]:
    task = repository.session.get(CampaignTaskRecord, task_id)
    if task is None or task.task_type != "candidate_hunter_evidence_inspection":
        return {
            "status": "not_found",
            "task_id": task_id,
            "stop_reason": "evidence_task_not_found",
        }

    existing_result = _canonical_result_stage(repository, task)
    if existing_result is not None:
        if not _result_stage_is_valid(existing_result, task):
            return _block_evidence_task(
                repository=repository,
                task=task,
                stop_reason="result_stage_integrity_invalid",
            )
        if not _complete_existing_evidence_result(
            repository=repository,
            task=task,
            result_stage=existing_result,
        ):
            return {
                "status": "running",
                "task_id": task.id,
                "stop_reason": "execution_lease_lost",
            }
        return {
            "status": "completed",
            "task_id": task.id,
            "result_stage_id": existing_result.id,
            "stop_reason": None,
        }

    context, stop_reason = _inspection_context(repository, task)
    if context is None:
        return _block_evidence_task(
            repository=repository,
            task=task,
            stop_reason=stop_reason or "evidence_context_invalid",
        )

    agent_run, claim_status = _claim_inspection(
        repository=repository,
        task=task,
        campaign=context["campaign"],
    )
    if agent_run is None:
        return {
            "status": claim_status,
            "task_id": task.id,
            "stop_reason": claim_status,
        }

    try:
        result_payload = _build_evidence_result_payload(
            task=task,
            context=context,
            agent_run=agent_run,
        )
    except (OSError, ValueError):
        return _record_failed_inspection(
            repository=repository,
            task=task,
            agent_run=agent_run,
            context=context,
            stop_reason="local_evidence_inspection_failed",
        )

    result_stage = _commit_evidence_result(
        repository=repository,
        task=task,
        agent_run=agent_run,
        context=context,
        payload=result_payload,
    )
    if result_stage is None:
        return {
            "status": "running",
            "task_id": task.id,
            "agent_run_id": agent_run.id,
            "stop_reason": "execution_lease_lost",
        }
    return {
        "status": "completed",
        "task_id": task.id,
        "agent_run_id": agent_run.id,
        "result_stage_id": result_stage.id,
        "stop_reason": None,
    }


def _complete_existing_evidence_result(
    *,
    repository: Any,
    task: CampaignTaskRecord,
    result_stage: PipelineStageRecord,
) -> bool:
    execution_claim_id = task.execution_claim_id
    if execution_claim_id is None:
        repository.update_campaign_task_status(
            task.id,
            "completed",
            output_refs=[f"pipeline_stage:{result_stage.id}"],
        )
        return True
    renewed_task = repository.renew_campaign_task_execution_lease(
        task.id,
        execution_claim_id=execution_claim_id,
    )
    if renewed_task is None:
        return False
    agent_run = repository.session.get(AgentRunRecord, execution_claim_id)
    completed_execution = repository.finish_campaign_task_execution(
        task_id=renewed_task.id,
        execution_claim_id=execution_claim_id,
        task_status="completed",
        task_output_refs=[
            f"agent_run:{execution_claim_id}",
            f"pipeline_stage:{result_stage.id}",
        ],
        agent_status="completed",
        agent_output_refs=[f"pipeline_stage:{result_stage.id}"],
        safety_gate_state="safe",
        stop_reason=None,
        payload=_safe_payload(getattr(agent_run, "payload", {})),
    )
    return completed_execution is not None


def resume_candidate_hunter_after_evidence(
    *,
    repository: Any,
    evidence_task_id: str,
) -> dict[str, Any]:
    task = repository.session.get(CampaignTaskRecord, evidence_task_id)
    if task is None or task.task_type != "candidate_hunter_evidence_inspection":
        return {
            "status": "blocked",
            "pipeline_run_id": "",
            "round_count": 0,
            "stage_refs": [],
            "state_digest": "",
            "stop_reason": "evidence_task_not_found",
            "final_candidates": [],
            "candidate_decisions": [],
            **_false_safety_fields(),
        }
    result_stage = _canonical_result_stage(repository, task)
    task_payload = _safe_payload(task.payload)
    pipeline_run_id = _text(task_payload.get("pipeline_run_id"))
    source_snapshot_digest = _bare_source_snapshot_digest(
        task_payload.get("source_snapshot_digest")
    )
    pipeline_run = repository.get_pipeline_run(pipeline_run_id)
    campaign = repository.get_campaign(task.campaign_id)
    owner_task = repository.session.get(
        CampaignTaskRecord,
        _text(task_payload.get("owner_task_id")),
    )
    linked_owner_task = _linked_runtime_owner_for_evidence_block(
        repository=repository,
        task=task,
    )
    if linked_owner_task is not None and campaign is not None:
        runtime_stop_reason = _runtime_owner_stop_reason(
            repository=repository,
            campaign=campaign,
            owner_task=linked_owner_task,
        )
        if runtime_stop_reason is not None:
            repository.update_campaign_task_status(
                linked_owner_task.id,
                "blocked",
                output_refs=[],
            )
            return {
                "status": "blocked",
                "pipeline_run_id": pipeline_run_id,
                "round_count": 0,
                "stage_refs": [],
                "state_digest": "",
                "stop_reason": runtime_stop_reason,
                "final_candidates": [],
                "candidate_decisions": [],
                **_false_safety_fields(),
            }
    if (
        result_stage is None
        or pipeline_run is None
        or campaign is None
        or owner_task is None
        or pipeline_run.scope_status != "in_scope"
        or campaign.scope_status != "in_scope"
        or campaign.policy_text_hash != pipeline_run.policy_text_hash
        or not _result_stage_is_valid(result_stage, task)
    ):
        if owner_task is not None:
            repository.update_campaign_task_status(owner_task.id, "blocked", output_refs=[])
        return {
            "status": "blocked",
            "pipeline_run_id": pipeline_run_id,
            "round_count": 0,
            "stage_refs": [],
            "state_digest": "",
            "stop_reason": "evidence_result_integrity_invalid",
            "final_candidates": [],
            "candidate_decisions": [],
            **_false_safety_fields(),
        }

    snapshot_stage = _snapshot_stage_for_request(
        repository=repository,
        pipeline_run_id=pipeline_run.id,
        owner_task_id=owner_task.id,
        round_number=task_payload.get("round"),
        state_digest=_text(task_payload.get("state_digest")),
    )
    candidate_states = _resumed_candidate_states(
        snapshot_stage=snapshot_stage,
        result_stage=result_stage,
        campaign=campaign,
        source_snapshot_digest=source_snapshot_digest,
    )
    if candidate_states is None:
        repository.update_campaign_task_status(owner_task.id, "blocked", output_refs=[])
        return {
            "status": "blocked",
            "pipeline_run_id": pipeline_run.id,
            "round_count": 0,
            "stage_refs": [],
            "state_digest": "",
            "stop_reason": "evidence_result_integrity_invalid",
            "final_candidates": [],
            "candidate_decisions": [],
            **_false_safety_fields(),
        }

    from app.candidate_hunter_loop import run_candidate_hunter_loop

    return run_candidate_hunter_loop(
        repository=repository,
        record=pipeline_run,
        policy_text=campaign.policy_text_hash,
        candidates=[],
        observations={
            "candidate_states": candidate_states,
            "initial_candidate_states": candidate_states,
            **_false_safety_fields(),
        },
    )


def _runtime_owner_stop_reason(
    *,
    repository: Any,
    campaign: Any,
    owner_task: CampaignTaskRecord,
) -> str | None:
    from app.autonomous_research_runtime import autonomous_research_task_stop_reason

    return autonomous_research_task_stop_reason(
        task=owner_task,
        campaign=campaign,
        repository=repository,
    )


def _resumed_candidate_states(
    *,
    snapshot_stage: PipelineStageRecord | None,
    result_stage: PipelineStageRecord,
    campaign: Any,
    source_snapshot_digest: str,
) -> list[dict[str, Any]] | None:
    if snapshot_stage is None:
        return None
    snapshot_payload = _safe_payload(snapshot_stage.payload)
    result_payload = _safe_payload(result_stage.payload)
    snapshot_candidates = snapshot_payload.get("snapshot_candidates")
    updates = result_payload.get("candidate_state_updates")
    if not isinstance(snapshot_candidates, list) or not isinstance(updates, list):
        return None
    manifest = _safe_source_manifest(
        _safe_payload(campaign.payload).get("source_manifest")
    )
    if manifest is None or not _result_facts_are_valid(
        result_payload=result_payload,
        source_manifest=manifest,
        source_snapshot_digest=source_snapshot_digest,
    ):
        return None
    new_fact_refs = {
        ref
        for fact in result_payload.get("new_facts", [])
        if isinstance(fact, dict)
        for ref in (
            _safe_text(fact.get("fact_ref")),
            _safe_text(fact.get("observed_fact_ref")),
        )
        if ref
    }
    updates_by_id = {
        _safe_text(update.get("candidate_id")): update
        for update in updates
        if isinstance(update, dict) and _safe_text(update.get("candidate_id"))
    }
    if len(updates_by_id) != len(updates):
        return None
    states: list[dict[str, Any]] = []
    for snapshot in snapshot_candidates:
        if not isinstance(snapshot, dict):
            return None
        candidate_id = _safe_text(snapshot.get("candidate_id"))
        update = updates_by_id.pop(candidate_id, None)
        if update is None:
            return None
        merged = _merge_result_state(
            snapshot=snapshot,
            update=update,
            new_fact_refs=new_fact_refs,
        )
        if merged is None:
            return None
        states.append(merged)
    return states if not updates_by_id else None


def _result_facts_are_valid(
    *,
    result_payload: dict[str, Any],
    source_manifest: list[dict[str, str]],
    source_snapshot_digest: str,
) -> bool:
    result_snapshot_digest = _bare_source_snapshot_digest(
        result_payload.get("source_snapshot_digest")
    )
    if (
        not source_snapshot_digest
        or result_snapshot_digest != source_snapshot_digest
        or _text(result_payload.get("source_manifest_digest"))
        != _source_manifest_digest(source_manifest)
    ):
        return False
    facts = result_payload.get("new_facts")
    if not isinstance(facts, list):
        return False
    file_digests = {
        item["source_path"]: item["content_digest"] for item in source_manifest
    }
    seen_refs: set[str] = set()
    for fact in facts:
        if not isinstance(fact, dict):
            return False
        fact_ref = _safe_text(fact.get("fact_ref"))
        observed_fact_ref = _safe_text(fact.get("observed_fact_ref"))
        source_path = _safe_relative_path(fact.get("source_path"))
        source_file_digest = _text(fact.get("source_file_digest"))
        fact_type = _safe_text(fact.get("fact_type"))
        symbol_name = _safe_text(fact.get("symbol_name"))
        if (
            not fact_ref
            or fact_ref in seen_refs
            or not observed_fact_ref
            or fact.get("artifact_kind") != "code"
            or fact.get("extractor_version") != "candidate_hunter_evidence_v1"
            or _bare_source_snapshot_digest(fact.get("source_snapshot_digest"))
            != source_snapshot_digest
            or not source_path
            or file_digests.get(source_path) != source_file_digest
            or not fact_type
            or not symbol_name
        ):
            return False
        derived_payload: dict[str, Any] = {
            "extractor_version": "candidate_hunter_evidence_v1",
            "source_snapshot_digest": result_snapshot_digest,
            "source_path": source_path,
            "source_file_digest": source_file_digest,
            "fact_type": fact_type,
            "symbol_name": symbol_name,
        }
        route = _safe_route(fact.get("route"))
        if route:
            derived_payload["route"] = route
        for field in ("handler", "caller"):
            value = _safe_text(fact.get(field))
            if value:
                derived_payload[field] = value
        expected_ref = f"evidence:{sha256(json.dumps(derived_payload, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()}"
        if fact_ref != expected_ref:
            return False
        if observed_fact_ref != _observed_code_fact_ref(
            source_path=source_path,
            symbol_name=symbol_name,
            fact_type=fact_type,
        ):
            return False
        seen_refs.add(fact_ref)
    return True


def _merge_result_state(
    *,
    snapshot: dict[str, Any],
    update: dict[str, Any],
    new_fact_refs: set[str],
) -> dict[str, Any] | None:
    identity_fields = (
        "candidate_id",
        "candidate_key",
        "vuln_type",
    )
    if any(
        _safe_text(update.get(field)) != _safe_text(snapshot.get(field))
        for field in identity_fields
    ) or _safe_route(update.get("route")) != _safe_route(snapshot.get("route")):
        return None
    original_root_cause_id = _safe_text(snapshot.get("root_cause_id"))
    updated_root_cause_id = _safe_text(update.get("root_cause_id"))
    if original_root_cause_id and updated_root_cause_id != original_root_cause_id:
        return None
    original_refs = _safe_string_list(snapshot.get("source_fact_refs"))
    updated_refs = _safe_string_list(update.get("source_fact_refs"))
    if not set(original_refs).issubset(updated_refs) or any(
        ref not in original_refs and ref not in new_fact_refs for ref in updated_refs
    ):
        return None
    original_kinds = _safe_artifact_kinds(snapshot.get("observed_artifact_kinds"))
    updated_kinds = _safe_artifact_kinds(update.get("observed_artifact_kinds"))
    required_kinds = _safe_artifact_kinds(snapshot.get("required_artifact_kinds"))
    if (
        not set(original_kinds).issubset(updated_kinds)
        or _safe_artifact_kinds(update.get("required_artifact_kinds")) != required_kinds
        or update.get("reanalysis_status") != "completed"
    ):
        return None
    merged = dict(snapshot)
    if not original_root_cause_id:
        if not updated_root_cause_id:
            return None
        merged["root_cause_id"] = updated_root_cause_id
    for field in ("gap_evidence_ref", "shared_root", "shared_root_evidence_ref"):
        original_value = _safe_text(snapshot.get(field))
        updated_value = _safe_text(update.get(field))
        if original_value and updated_value != original_value:
            return None
        if not original_value and updated_value:
            if field.endswith("_ref") and updated_value not in updated_refs:
                return None
            merged[field] = updated_value
    merged["source_fact_refs"] = updated_refs
    merged["observed_artifact_kinds"] = updated_kinds
    merged["required_artifact_kinds"] = required_kinds
    merged["evidence_trace_status"] = (
        "traceable"
        if required_kinds and set(required_kinds).issubset(updated_kinds)
        else "needs_evidence"
    )
    merged["reanalysis_status"] = "completed"
    for field in ("control_evidence_ref", "public_evidence_ref"):
        value = _safe_text(update.get(field))
        if value:
            if value not in updated_refs:
                return None
            merged[field] = value
        else:
            merged.pop(field, None)
    return merged


def _inspection_context(
    repository: Any,
    task: CampaignTaskRecord,
) -> tuple[dict[str, Any] | None, str | None]:
    payload = _safe_payload(task.payload)
    if (
        payload.get("schema_version") != TASK_SCHEMA_VERSION
        or not _has_false_safety_fields(payload)
    ):
        return None, "evidence_task_payload_invalid"
    pipeline_run_id = _text(payload.get("pipeline_run_id"))
    request_stage_id = _text(payload.get("evidence_request_stage_id"))
    owner_task_id = _text(payload.get("owner_task_id"))
    state_digest = _text(payload.get("state_digest"))
    source_snapshot_digest = _bare_source_snapshot_digest(
        payload.get("source_snapshot_digest")
    )
    if not all(
        (
            pipeline_run_id,
            request_stage_id,
            owner_task_id,
            state_digest,
            source_snapshot_digest,
        )
    ):
        return None, "evidence_task_payload_invalid"

    pipeline_run = repository.get_pipeline_run(pipeline_run_id)
    campaign = repository.get_campaign(task.campaign_id)
    owner_task = repository.session.get(CampaignTaskRecord, owner_task_id)
    request_stage = repository.get_pipeline_stage(request_stage_id)
    if (
        pipeline_run is None
        or campaign is None
        or owner_task is None
        or request_stage is None
        or owner_task.campaign_id != campaign.id
        or request_stage.campaign_id != campaign.id
        or request_stage.task_id != owner_task.id
        or request_stage.pipeline_run_id != pipeline_run.id
    ):
        return None, "evidence_owner_invalid"
    if pipeline_run.scope_status != "in_scope" or campaign.scope_status != "in_scope":
        return None, "scope_not_in_scope"
    if campaign.policy_text_hash != pipeline_run.policy_text_hash:
        return None, "policy_changed"

    runtime_stop_reason = _runtime_owner_stop_reason(
        repository=repository,
        campaign=campaign,
        owner_task=owner_task,
    )
    if runtime_stop_reason is not None:
        return None, runtime_stop_reason

    campaign_payload = _safe_payload(campaign.payload)
    owner_payload = _safe_payload(owner_task.payload)
    if (
        campaign_payload.get("pipeline_run_id") != pipeline_run.id
        and owner_payload.get("pipeline_run_id") != pipeline_run.id
        or not _has_false_safety_fields(campaign_payload)
        or _bare_source_snapshot_digest(
            campaign_payload.get("source_snapshot_digest")
        )
        != source_snapshot_digest
        or INSPECTOR_TOOL
        not in _safe_string_list(campaign_payload.get("inspector_tool_allowlist"))
        or INSPECTOR_TOOL not in _safe_string_list(campaign.allowed_tools)
    ):
        return None, "campaign_evidence_contract_invalid"

    request_payload = _safe_payload(request_stage.payload)
    if (
        request_stage.stage_key != "candidate_hunter_evidence_request"
        or request_stage.status != "completed"
        or request_stage.safety_gate_state != "safe"
        or not _has_false_safety_fields(request_payload)
        or request_payload.get("state_digest") != state_digest
        or request_payload.get("round") != payload.get("round")
    ):
        return None, "evidence_request_stage_invalid"

    snapshot_stage = _snapshot_stage_for_request(
        repository=repository,
        pipeline_run_id=pipeline_run.id,
        owner_task_id=owner_task.id,
        round_number=payload.get("round"),
        state_digest=state_digest,
    )
    if snapshot_stage is None:
        return None, "snapshot_stage_invalid"

    source_manifest = _safe_source_manifest(campaign_payload.get("source_manifest"))
    if source_manifest is None:
        return None, "source_manifest_invalid"
    workspace_snapshot = campaign_payload.get("workspace_snapshot")
    if workspace_snapshot is not None:
        try:
            workspace_inputs = load_authorized_campaign_inputs(workspace_snapshot)
        except (OSError, StudioWorkspaceAccessError, ValueError) as exc:
            return None, (
                "workspace_snapshot_changed"
                if str(exc) == "workspace_snapshot_changed"
                else "workspace_snapshot_invalid"
            )
        if _bare_source_snapshot_digest(
            workspace_inputs.get("source_snapshot_digest")
        ) != source_snapshot_digest:
            return None, "source_snapshot_changed"
        workspace_manifest = _safe_source_manifest(
            workspace_inputs.get("source_manifest")
        )
        if workspace_manifest is None or workspace_manifest != source_manifest:
            return None, "source_snapshot_changed"
        source_root = _workspace_authorized_source_root(
            workspace_inputs=workspace_inputs,
            campaign_payload=campaign_payload,
        )
        if source_root is None:
            return None, "scope_guard_changed"
        code_files = workspace_inputs.get("code_files")
        if not isinstance(code_files, list):
            return None, "workspace_snapshot_invalid"
    else:
        source_root = _authorized_source_root(
            pipeline_run=pipeline_run,
            campaign=campaign,
            campaign_payload=campaign_payload,
        )
        if source_root is None:
            return None, "scope_guard_changed"
        try:
            code_files = _collect_authorized_evidence_files(source_root)
        except OSError:
            return None, "source_snapshot_unavailable"
    actual_manifest = _snapshot_manifest(code_files)
    if actual_manifest is None or actual_manifest != source_manifest:
        return None, "source_snapshot_changed"
    if (
        workspace_snapshot is None
        and _source_snapshot_digest(actual_manifest) != source_snapshot_digest
    ):
        return None, "source_snapshot_changed"

    return {
        "pipeline_run": pipeline_run,
        "campaign": campaign,
        "owner_task": owner_task,
        "request_stage": request_stage,
        "snapshot_stage": snapshot_stage,
        "source_root": source_root,
        "source_manifest": source_manifest,
        "code_files": code_files,
    }, None


def _authorized_source_root(
    *,
    pipeline_run: Any,
    campaign: Any,
    campaign_payload: dict[str, Any],
) -> Path | None:
    saved_scope = campaign_payload.get("saved_scope_guard")
    if not isinstance(saved_scope, dict) or saved_scope.get("scope_status") != "in_scope":
        return None
    authorized_root = _text(saved_scope.get("authorized_local_root"))
    source_asset = _text(getattr(pipeline_run, "asset", ""))
    campaign_asset = _text(getattr(campaign, "default_asset", ""))
    if not authorized_root or not source_asset or not campaign_asset:
        return None
    try:
        root = Path(source_asset).resolve(strict=True)
        saved_root = Path(authorized_root).resolve(strict=True)
        default_root = Path(campaign_asset).resolve(strict=True)
    except OSError:
        return None
    if not root.is_dir() or root != saved_root or root != default_root:
        return None
    return root


def _workspace_authorized_source_root(
    *,
    workspace_inputs: dict[str, Any],
    campaign_payload: dict[str, Any],
) -> Path | None:
    saved_scope = campaign_payload.get("saved_scope_guard")
    if not isinstance(saved_scope, dict) or saved_scope.get("scope_status") != "in_scope":
        return None
    authorized_root = _text(saved_scope.get("authorized_local_root"))
    workspace_root = _text(workspace_inputs.get("authorized_local_root"))
    if not authorized_root or not workspace_root:
        return None
    try:
        saved_root = Path(authorized_root).resolve(strict=True)
        resolved_workspace_root = Path(workspace_root).resolve(strict=True)
    except OSError:
        return None
    if not resolved_workspace_root.is_dir() or resolved_workspace_root != saved_root:
        return None
    return resolved_workspace_root


def _snapshot_stage_for_request(
    *,
    repository: Any,
    pipeline_run_id: str,
    owner_task_id: str,
    round_number: object,
    state_digest: str,
) -> PipelineStageRecord | None:
    if not isinstance(round_number, int) or isinstance(round_number, bool):
        return None
    stages = [
        stage
        for stage in repository.list_pipeline_stages_for_run(pipeline_run_id)
        if stage.task_id == owner_task_id
        and stage.stage_key == "candidate_hunter_snapshot"
        and isinstance(stage.payload, dict)
        and stage.payload.get("round") == round_number
        and stage.payload.get("state_digest") == state_digest
    ]
    if len(stages) != 1:
        return None
    stage = stages[0]
    payload = _safe_payload(stage.payload)
    if (
        stage.status != "completed"
        or stage.safety_gate_state != "safe"
        or not _has_false_safety_fields(payload)
        or not isinstance(payload.get("snapshot_candidates"), list)
    ):
        return None
    return stage


def _claim_inspection(
    *,
    repository: Any,
    task: CampaignTaskRecord,
    campaign: Any,
) -> tuple[AgentRunRecord | None, str]:
    if campaign.status in {
        "paused",
        "awaiting_review",
        "blocked",
        "canceled",
        "completed",
        "failed",
    }:
        return None, f"campaign_{campaign.status}"
    budget_stop = _evidence_budget_stop_reason(repository, campaign, task.id)
    if budget_stop is not None:
        return None, budget_stop
    if campaign.status != "running":
        repository.update_campaign_status(campaign.id, "running")
        campaign = repository.get_campaign(campaign.id)
        if campaign is None:
            return None, "campaign_not_found"

    active = repository.find_active_agent_run_for_task(task.id)
    if active is not None:
        active_payload = _safe_payload(active.payload)
        if active_payload.get("worker_execution_claim") is True:
            prior_attempts = [
                run
                for run in repository.list_campaign_agent_runs(campaign.id)
                if run.task_id == task.id
            ]
            active.agent_type = "candidate_hunter_evidence_specialist"
            active.input_refs = list(task.input_refs)
            active.tool_calls = [{"tool": INSPECTOR_TOOL, "mode": "local_read_only"}]
            active.safety_gate_state = "safe"
            active.stop_reason = None
            active.payload = {
                "schema_version": "candidate_hunter_evidence_agent_run_v1",
                "attempt": len(prior_attempts),
                "token_usage": {"total_tokens": 0},
                **_false_safety_fields(),
            }
            repository.session.add(active)
            repository.session.commit()
            repository.session.refresh(active)
            return active, "claimed"
        return None, "inspection_already_running"
    prior_attempts = [
        run
        for run in repository.list_campaign_agent_runs(campaign.id)
        if run.task_id == task.id
    ]
    attempt_number = len(prior_attempts) + 1
    run_id = f"agent_run_{sha256(f'{task.id}:{attempt_number}'.encode('utf-8')).hexdigest()}"
    agent_run = AgentRunRecord(
        id=run_id,
        campaign_id=campaign.id,
        task_id=task.id,
        agent_type="candidate_hunter_evidence_specialist",
        status="running",
        input_refs=list(task.input_refs),
        output_refs=[],
        tool_calls=[{"tool": INSPECTOR_TOOL, "mode": "local_read_only"}],
        safety_gate_state="safe",
        stop_reason=None,
        payload={
            "schema_version": "candidate_hunter_evidence_agent_run_v1",
            "attempt": attempt_number,
            "token_usage": {"total_tokens": 0},
            **_false_safety_fields(),
        },
    )
    task.status = "running"
    repository.session.add_all([agent_run, task])
    try:
        repository.session.commit()
    except IntegrityError:
        repository.session.rollback()
        active = repository.find_active_agent_run_for_task(task.id)
        if active is not None:
            return None, "inspection_already_running"
        raise
    repository.session.refresh(agent_run)
    return agent_run, "claimed"


def _evidence_budget_stop_reason(
    repository: Any,
    campaign: Any,
    task_id: str,
) -> str | None:
    budget = repository.get_campaign_budget(campaign.id)
    if budget is None:
        return None
    if budget.tool_call_budget is not None:
        used_calls = sum(
            1
            for run in repository.list_campaign_agent_runs(campaign.id)
            if run.safety_gate_state == "safe"
        )
        if used_calls >= budget.tool_call_budget:
            return "budget_exhausted"
    if budget.token_budget is not None:
        used_tokens = sum(
            _agent_run_tokens(run)
            for run in repository.list_campaign_agent_runs(campaign.id)
        )
        if used_tokens >= budget.token_budget:
            return "budget_exhausted"
    if budget.time_budget_minutes is not None:
        elapsed_seconds = sum(
            _agent_run_elapsed_seconds(run)
            for run in repository.list_campaign_agent_runs(campaign.id)
            if run.task_id == task_id
        )
        if elapsed_seconds >= budget.time_budget_minutes * 60:
            return "budget_exhausted"
    return None


def _agent_run_tokens(run: AgentRunRecord) -> int:
    payload = _safe_payload(run.payload)
    usage = payload.get("token_usage")
    if isinstance(usage, int) and not isinstance(usage, bool):
        return max(0, usage)
    if not isinstance(usage, dict):
        return 0
    total = usage.get("total_tokens")
    return max(0, total) if isinstance(total, int) and not isinstance(total, bool) else 0


def _agent_run_elapsed_seconds(run: AgentRunRecord) -> float:
    if run.finished_at is None:
        return 0
    created = _as_utc(run.created_at)
    finished = _as_utc(run.finished_at)
    return max(0, (finished - created).total_seconds())


def _build_evidence_result_payload(
    *,
    task: CampaignTaskRecord,
    context: dict[str, Any],
    agent_run: AgentRunRecord,
) -> dict[str, Any]:
    from app.candidate_hunter_loop import build_candidate_hunter_observations

    task_payload = _safe_payload(task.payload)
    snapshot_payload = _safe_payload(context["snapshot_stage"].payload)
    snapshot_candidates = snapshot_payload.get("snapshot_candidates", [])
    selected_candidates = [
        state
        for state in snapshot_candidates
        if isinstance(state, dict)
        and _safe_text(state.get("candidate_id"))
        in set(_safe_string_list(task_payload.get("candidate_ids")))
    ]
    if not selected_candidates:
        raise ValueError("inspection_candidates_missing")
    candidate_inputs = [
        candidate
        for state in selected_candidates
        if (candidate := _candidate_input_from_snapshot(state)) is not None
    ]
    if not candidate_inputs:
        raise ValueError("inspection_candidate_shape_invalid")
    observations = build_candidate_hunter_observations(
        pipeline_run_id=task_payload["pipeline_run_id"],
        candidates=candidate_inputs,
        code_files=context["code_files"],
        surface_facts=[],
        context_facts=[],
    )
    observed_states = {
        _safe_text(state.get("candidate_id")): state
        for state in observations.get("candidate_states", [])
        if isinstance(state, dict) and _safe_text(state.get("candidate_id"))
    }
    facts_by_ref = {
        _safe_text(fact.get("fact_ref")): fact
        for fact in observations.get("facts", [])
        if isinstance(fact, dict) and _safe_text(fact.get("fact_ref"))
    }
    file_digests = {
        item["source_path"]: item["content_digest"]
        for item in context["source_manifest"]
    }
    new_facts: list[dict[str, Any]] = []
    updates: list[dict[str, Any]] = []
    for state in selected_candidates:
        candidate_id = _safe_text(state.get("candidate_id"))
        observed = observed_states.get(candidate_id)
        if observed is None:
            continue
        update, facts = _candidate_state_update(
            original=state,
            observed=observed,
            facts_by_ref=facts_by_ref,
            source_snapshot_digest=task_payload["source_snapshot_digest"],
            file_digests=file_digests,
        )
        updates.append(update)
        for fact in facts:
            if fact not in new_facts:
                new_facts.append(fact)
    answered_questions = (
        _safe_string_list(task_payload.get("refutation_questions"))
        if any(
            _safe_text(update.get("control_evidence_ref"))
            or _safe_text(update.get("public_evidence_ref"))
            for update in updates
        )
        else []
    )
    all_questions = _safe_string_list(task_payload.get("refutation_questions"))
    unanswered_questions = [
        question for question in all_questions if question not in answered_questions
    ]
    idempotency_key = _result_idempotency_key(
        pipeline_run_id=task_payload["pipeline_run_id"],
        task_id=task.id,
        state_digest=task_payload["state_digest"],
        source_snapshot_digest=task_payload["source_snapshot_digest"],
    )
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "evidence_task_id": task.id,
        "evidence_request_stage_id": task_payload["evidence_request_stage_id"],
        "round": task_payload["round"],
        "state_digest": task_payload["state_digest"],
        "source_snapshot_digest": task_payload["source_snapshot_digest"],
        "source_manifest_digest": _source_manifest_digest(context["source_manifest"]),
        "complete": True,
        "new_facts": new_facts,
        "candidate_state_updates": updates,
        "answered_refutation_questions": answered_questions,
        "unanswered_refutation_questions": unanswered_questions,
        "inspected_targets": _safe_targets(task_payload.get("inspection_targets")),
        "usage": {
            "tool_call_count": 1,
            "model_token_count": 0,
            "execution_seconds": round(_agent_run_elapsed_seconds(agent_run), 6),
        },
        "idempotency_key": idempotency_key,
        **_false_safety_fields(),
    }


def _candidate_input_from_snapshot(state: dict[str, Any]) -> dict[str, Any] | None:
    candidate_id = _safe_text(state.get("candidate_id"))
    vuln_type = _safe_text(state.get("vuln_type"))
    root_cause_id = _safe_text(state.get("root_cause_id"))
    route = state.get("route")
    if not candidate_id or not vuln_type or not isinstance(route, dict):
        return None
    method = _safe_text(route.get("method")).upper()
    path = _safe_text(route.get("path"))
    if not method or not path.startswith("/"):
        return None
    root_cause, _, symbol_name = root_cause_id.partition(":")
    source_path, source_symbol = _snapshot_code_reference(state)
    if not source_path:
        source_path = _safe_relative_path(state.get("hypothesis_source_path"))
    if not source_symbol:
        source_symbol = _safe_text(state.get("hypothesis_symbol_name"))
    candidate = {
        "hypothesis_id": candidate_id,
        "vuln_type": vuln_type,
        "location": f"{method} {path}",
        "priority_score": state.get("priority_score", 0),
        "source_facts": [],
        "false_positive_checks": _safe_string_list(state.get("refutation_questions")),
    }
    if source_path or source_symbol or root_cause:
        candidate["source_facts"] = [
            {
                "fact_type": "authorization_gap_candidate",
                "artifact_kind": "code",
                "source_path": source_path,
                "symbol_name": source_symbol or symbol_name,
                "route_method": method,
                "route_path": path,
                "root_cause": root_cause or "candidate",
            }
        ]
    return candidate


def _snapshot_code_reference(state: dict[str, Any]) -> tuple[str, str]:
    for fact_ref in _safe_string_list(state.get("source_fact_refs")):
        parts = fact_ref.split(":")
        if len(parts) >= 3 and parts[0] == "code":
            source_path = _safe_relative_path(parts[1])
            symbol_name = _safe_text(parts[2])
            if source_path and symbol_name:
                return source_path, symbol_name
    return "", ""


def _candidate_state_update(
    *,
    original: dict[str, Any],
    observed: dict[str, Any],
    facts_by_ref: dict[str, dict[str, Any]],
    source_snapshot_digest: str,
    file_digests: dict[str, str],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    original_refs = _safe_string_list(original.get("source_fact_refs"))
    observed_fact_refs: dict[str, str] = {}
    evidence_fact_refs: list[str] = []
    new_facts: list[dict[str, Any]] = []
    for fact_ref in _safe_string_list(observed.get("source_fact_refs")):
        if fact_ref in original_refs:
            continue
        fact = facts_by_ref.get(fact_ref)
        safe_fact = _evidence_fact(
            fact=fact,
            source_snapshot_digest=source_snapshot_digest,
            file_digests=file_digests,
        )
        if safe_fact is None:
            continue
        observed_fact_refs[fact_ref] = safe_fact["observed_fact_ref"]
        evidence_fact_refs.append(safe_fact["fact_ref"])
        new_facts.append(safe_fact)
    observed_refs = [
        observed_fact_refs.get(ref, ref)
        for ref in _safe_string_list(observed.get("source_fact_refs"))
    ]
    source_fact_refs = _ordered_unique(
        [*original_refs, *observed_refs, *evidence_fact_refs]
    )
    update = {
        "candidate_id": _safe_text(original.get("candidate_id")),
        "candidate_key": _safe_text(original.get("candidate_key")),
        "vuln_type": _safe_text(original.get("vuln_type")),
        "root_cause_id": _safe_text(original.get("root_cause_id"))
        or _safe_text(observed.get("root_cause_id")),
        "route": _safe_route(original.get("route")),
        "source_fact_refs": source_fact_refs,
        "observed_artifact_kinds": _ordered_unique(
            [
                *_safe_artifact_kinds(original.get("observed_artifact_kinds")),
                *_safe_artifact_kinds(observed.get("observed_artifact_kinds")),
            ]
        ),
        "required_artifact_kinds": _safe_artifact_kinds(
            original.get("required_artifact_kinds")
        ),
        "priority_score": _safe_priority(original.get("priority_score")),
        "gap_evidence_ref": _safe_text(original.get("gap_evidence_ref"))
        or observed_fact_refs.get(
            _safe_text(observed.get("gap_evidence_ref")),
            _safe_text(observed.get("gap_evidence_ref")),
        ),
        "shared_root": _safe_text(original.get("shared_root"))
        or _safe_text(observed.get("shared_root")),
        "shared_root_evidence_ref": _safe_text(
            original.get("shared_root_evidence_ref")
        )
        or observed_fact_refs.get(
            _safe_text(observed.get("shared_root_evidence_ref")),
            _safe_text(observed.get("shared_root_evidence_ref")),
        ),
        "refutation_questions": _safe_string_list(
            original.get("refutation_questions")
        ),
        "reanalysis_status": "completed",
    }
    for key in ("control_evidence_ref", "public_evidence_ref"):
        ref = _safe_text(observed.get(key))
        ref = observed_fact_refs.get(ref, ref)
        if ref and ref in source_fact_refs:
            update[key] = ref
    required = set(update["required_artifact_kinds"])
    observed_kinds = set(update["observed_artifact_kinds"])
    update["evidence_trace_status"] = (
        "traceable" if required and required.issubset(observed_kinds) else "needs_evidence"
    )
    return update, new_facts


def _evidence_fact(
    *,
    fact: object,
    source_snapshot_digest: str,
    file_digests: dict[str, str],
) -> dict[str, Any] | None:
    if not isinstance(fact, dict) or fact.get("artifact_kind") != "code":
        return None
    source_path = _safe_relative_path(fact.get("source_path"))
    fact_type = _safe_text(fact.get("fact_type"))
    symbol_name = _safe_text(fact.get("symbol_name"))
    file_digest = file_digests.get(source_path)
    if not source_path or not fact_type or not symbol_name or not file_digest:
        return None
    payload: dict[str, Any] = {
        "extractor_version": "candidate_hunter_evidence_v1",
        "source_snapshot_digest": source_snapshot_digest,
        "source_path": source_path,
        "source_file_digest": file_digest,
        "fact_type": fact_type,
        "symbol_name": symbol_name,
    }
    route = _safe_route(fact.get("route"))
    if route:
        payload["route"] = route
    for field in ("handler", "caller"):
        value = _safe_text(fact.get(field))
        if value:
            payload[field] = value
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return {
        "fact_ref": f"evidence:{sha256(encoded.encode('utf-8')).hexdigest()}",
        "observed_fact_ref": _observed_code_fact_ref(
            source_path=source_path,
            symbol_name=symbol_name,
            fact_type=fact_type,
        ),
        "artifact_kind": "code",
        **payload,
    }


def _observed_code_fact_ref(
    *,
    source_path: str,
    symbol_name: str,
    fact_type: str,
) -> str:
    suffix = f":{fact_type}" if fact_type in {"ownership_guard", "public_filter"} else ""
    return f"code:{source_path}:{symbol_name}{suffix}"


def _commit_evidence_result(
    *,
    repository: Any,
    task: CampaignTaskRecord,
    agent_run: AgentRunRecord,
    context: dict[str, Any],
    payload: dict[str, Any],
) -> PipelineStageRecord | None:
    idempotency_key = _text(payload.get("idempotency_key"))
    stage_id = f"pipeline_stage_{idempotency_key}"
    existing = repository.session.get(PipelineStageRecord, stage_id)
    if existing is not None:
        if not _result_stage_is_valid(existing, task):
            raise ValueError("result_stage_integrity_invalid")
        return existing
    stage = PipelineStageRecord(
        id=stage_id,
        pipeline_run_id=context["pipeline_run"].id,
        campaign_id=context["campaign"].id,
        task_id=task.id,
        stage_key="candidate_hunter_evidence_result",
        stage_order=payload["round"] * 5,
        status="completed",
        input_refs=list(task.input_refs),
        output_refs=[],
        safety_gate_state="safe",
        stop_reason=None,
        payload=payload,
    )
    if task.execution_claim_id is not None:
        if task.execution_claim_id != agent_run.id:
            return None
        renewed_task = repository.renew_campaign_task_execution_lease(
            task.id,
            execution_claim_id=agent_run.id,
        )
        if renewed_task is None:
            return None
        completed_execution = repository.finish_campaign_task_execution(
            task_id=renewed_task.id,
            execution_claim_id=agent_run.id,
            task_status="completed",
            task_output_refs=[f"agent_run:{agent_run.id}", f"pipeline_stage:{stage.id}"],
            agent_status="completed",
            agent_output_refs=[f"pipeline_stage:{stage.id}"],
            safety_gate_state="safe",
            stop_reason=None,
            payload=_safe_payload(agent_run.payload),
            additional_records=[stage],
        )
        if completed_execution is None:
            return None
        return repository.session.get(PipelineStageRecord, stage.id)

    agent_run.status = "completed"
    agent_run.output_refs = [f"pipeline_stage:{stage.id}"]
    agent_run.safety_gate_state = "safe"
    agent_run.stop_reason = None
    agent_run.finished_at = datetime.now(UTC)
    task.status = "completed"
    task.output_refs = [f"agent_run:{agent_run.id}", f"pipeline_stage:{stage.id}"]
    repository.session.add_all([stage, agent_run, task])
    try:
        repository.session.commit()
    except IntegrityError:
        repository.session.rollback()
        existing = repository.session.get(PipelineStageRecord, stage_id)
        if existing is None or not _result_stage_is_valid(existing, task):
            raise
        return existing
    repository.session.refresh(stage)
    return stage


def _record_failed_inspection(
    *,
    repository: Any,
    task: CampaignTaskRecord,
    agent_run: AgentRunRecord,
    context: dict[str, Any],
    stop_reason: str,
) -> dict[str, Any]:
    task_payload = _safe_payload(task.payload)
    idempotency_key = sha256(
        f"{task.id}:{agent_run.id}:{stop_reason}".encode("utf-8")
    ).hexdigest()
    stage_id = f"pipeline_stage_{idempotency_key}"
    stage = repository.session.get(PipelineStageRecord, stage_id)
    stage_is_new = stage is None
    execution_claim_id = task.execution_claim_id
    if execution_claim_id is not None:
        if execution_claim_id != agent_run.id:
            return {
                "status": "running",
                "task_id": task.id,
                "agent_run_id": agent_run.id,
                "stop_reason": "execution_lease_lost",
            }
        renewed_task = repository.renew_campaign_task_execution_lease(
            task.id,
            execution_claim_id=execution_claim_id,
        )
        if renewed_task is None:
            return {
                "status": "running",
                "task_id": task.id,
                "agent_run_id": agent_run.id,
                "stop_reason": "execution_lease_lost",
            }
        task = renewed_task
    if stage is None:
        stage = PipelineStageRecord(
            id=stage_id,
            pipeline_run_id=context["pipeline_run"].id,
            campaign_id=context["campaign"].id,
            task_id=task.id,
            stage_key="candidate_hunter_evidence_attempt",
            stage_order=task_payload["round"] * 5,
            status="failed",
            input_refs=list(task.input_refs),
            output_refs=[],
            safety_gate_state="blocked",
            stop_reason=stop_reason,
            payload={
                "schema_version": ATTEMPT_SCHEMA_VERSION,
                "evidence_task_id": task.id,
                "evidence_request_stage_id": task_payload["evidence_request_stage_id"],
                "round": task_payload["round"],
                "state_digest": task_payload["state_digest"],
                "complete": False,
                "new_facts": [],
                "idempotency_key": idempotency_key,
                **_false_safety_fields(),
            },
        )
    owner_task = _linked_runtime_owner_for_evidence_block(
        repository=repository,
        task=task,
        validated_context=context,
    )
    if owner_task is not None:
        owner_output_refs = [
            ref for ref in owner_task.output_refs if isinstance(ref, str)
        ]
        evidence_ref = f"campaign_task:{task.id}"
        if evidence_ref not in owner_output_refs:
            owner_output_refs.append(evidence_ref)
        owner_task.status = "blocked"
        owner_task.output_refs = owner_output_refs
        owner_task.payload = {
            **_safe_payload(owner_task.payload),
            "blocked_by_evidence_task_id": task.id,
            "blocked_stop_reason": stop_reason,
        }
        repository.session.add(owner_task)

    if execution_claim_id is not None:
        finished_execution = repository.finish_campaign_task_execution(
            task_id=task.id,
            execution_claim_id=execution_claim_id,
            task_status="blocked",
            task_output_refs=[f"agent_run:{agent_run.id}", f"pipeline_stage:{stage.id}"],
            agent_status="failed",
            agent_output_refs=[],
            safety_gate_state="blocked",
            stop_reason=stop_reason,
            payload=_safe_payload(agent_run.payload),
            additional_records=[stage] if stage_is_new else None,
        )
        if finished_execution is None:
            return {
                "status": "running",
                "task_id": task.id,
                "agent_run_id": agent_run.id,
                "stop_reason": "execution_lease_lost",
            }
        return {
            "status": "blocked",
            "task_id": task.id,
            "agent_run_id": agent_run.id,
            "stop_reason": stop_reason,
        }

    if stage_is_new:
        repository.session.add(stage)
    agent_run.status = "failed"
    agent_run.safety_gate_state = "blocked"
    agent_run.stop_reason = stop_reason
    agent_run.finished_at = datetime.now(UTC)
    task.status = "blocked"
    task.output_refs = [f"agent_run:{agent_run.id}", f"pipeline_stage:{stage.id}"]
    repository.session.add_all([agent_run, task])
    repository.session.commit()
    return {
        "status": "blocked",
        "task_id": task.id,
        "agent_run_id": agent_run.id,
        "stop_reason": stop_reason,
    }


def _canonical_result_stage(
    repository: Any,
    task: CampaignTaskRecord,
) -> PipelineStageRecord | None:
    stages = [
        stage
        for stage in repository.list_pipeline_stages_for_run(
            _text(_safe_payload(task.payload).get("pipeline_run_id"))
        )
        if stage.task_id == task.id
        and stage.stage_key == "candidate_hunter_evidence_result"
    ]
    return stages[0] if len(stages) == 1 else None


def _result_stage_is_valid(stage: PipelineStageRecord, task: CampaignTaskRecord) -> bool:
    task_payload = _safe_payload(task.payload)
    payload = _safe_payload(stage.payload)
    expected_key = _result_idempotency_key(
        pipeline_run_id=_text(task_payload.get("pipeline_run_id")),
        task_id=task.id,
        state_digest=_text(task_payload.get("state_digest")),
        source_snapshot_digest=_text(task_payload.get("source_snapshot_digest")),
    )
    return (
        stage.status == "completed"
        and stage.safety_gate_state == "safe"
        and payload.get("schema_version") == RESULT_SCHEMA_VERSION
        and payload.get("evidence_task_id") == task.id
        and payload.get("evidence_request_stage_id")
        == task_payload.get("evidence_request_stage_id")
        and payload.get("state_digest") == task_payload.get("state_digest")
        and payload.get("source_snapshot_digest")
        == task_payload.get("source_snapshot_digest")
        and payload.get("complete") is True
        and payload.get("idempotency_key") == expected_key
        and _has_false_safety_fields(payload)
        and isinstance(payload.get("new_facts"), list)
        and isinstance(payload.get("candidate_state_updates"), list)
    )


def completed_evidence_result_is_valid(
    *,
    repository: Any,
    task: CampaignTaskRecord,
) -> bool:
    if (
        task.task_type != "candidate_hunter_evidence_inspection"
        or task.status != "completed"
    ):
        return False
    result_stage = _canonical_result_stage(repository, task)
    return result_stage is not None and _result_stage_is_valid(result_stage, task)


def _block_evidence_task(
    *,
    repository: Any,
    task: CampaignTaskRecord,
    stop_reason: str,
) -> dict[str, Any]:
    execution_claim_id = task.execution_claim_id
    active_run = (
        repository.session.get(AgentRunRecord, execution_claim_id)
        if execution_claim_id is not None
        else repository.find_active_agent_run_for_task(task.id)
    )
    if execution_claim_id is not None:
        if active_run is None or active_run.task_id != task.id:
            return {
                "status": "running",
                "task_id": task.id,
                "stop_reason": "execution_lease_lost",
            }
        renewed_task = repository.renew_campaign_task_execution_lease(
            task.id,
            execution_claim_id=execution_claim_id,
        )
        if renewed_task is None:
            return {
                "status": "running",
                "task_id": task.id,
                "stop_reason": "execution_lease_lost",
            }
        task = renewed_task
    output_refs: list[str] = []
    if active_run is not None and active_run.campaign_id == task.campaign_id:
        output_refs.append(f"agent_run:{active_run.id}")

    owner_task = _linked_runtime_owner_for_evidence_block(
        repository=repository,
        task=task,
    )
    if owner_task is not None:
        owner_output_refs = [
            ref for ref in owner_task.output_refs if isinstance(ref, str)
        ]
        evidence_ref = f"campaign_task:{task.id}"
        if evidence_ref not in owner_output_refs:
            owner_output_refs.append(evidence_ref)
        owner_task.status = "blocked"
        owner_task.output_refs = owner_output_refs
        owner_task.payload = {
            **_safe_payload(owner_task.payload),
            "blocked_by_evidence_task_id": task.id,
            "blocked_stop_reason": stop_reason,
        }
        repository.session.add(owner_task)

    if execution_claim_id is not None:
        finished_execution = repository.finish_campaign_task_execution(
            task_id=task.id,
            execution_claim_id=execution_claim_id,
            task_status="blocked",
            task_output_refs=output_refs,
            agent_status="blocked",
            agent_output_refs=[],
            safety_gate_state="blocked",
            stop_reason=stop_reason,
            payload={
                "schema_version": "candidate_hunter_evidence_agent_run_v1",
                "token_usage": {"total_tokens": 0},
                **_false_safety_fields(),
            },
        )
        if finished_execution is None:
            return {
                "status": "running",
                "task_id": task.id,
                "stop_reason": "execution_lease_lost",
            }
        return {
            "status": "blocked",
            "task_id": task.id,
            "stop_reason": stop_reason,
        }

    if active_run is not None and active_run.campaign_id == task.campaign_id:
        active_run.status = "blocked"
        active_run.output_refs = []
        active_run.safety_gate_state = "blocked"
        active_run.stop_reason = stop_reason
        active_run.payload = {
            "schema_version": "candidate_hunter_evidence_agent_run_v1",
            "token_usage": {"total_tokens": 0},
            **_false_safety_fields(),
        }
        active_run.finished_at = datetime.now(UTC)
        repository.session.add(active_run)
    task.status = "blocked"
    task.output_refs = output_refs
    repository.session.add(task)
    repository.session.commit()
    return {
        "status": "blocked",
        "task_id": task.id,
        "stop_reason": stop_reason,
    }


def _linked_runtime_owner_for_evidence_block(
    *,
    repository: Any,
    task: CampaignTaskRecord,
    validated_context: dict[str, Any] | None = None,
) -> CampaignTaskRecord | None:
    task_payload = _safe_payload(task.payload)
    owner_task_id = _text(task_payload.get("owner_task_id"))
    context_owner = (
        validated_context.get("owner_task")
        if isinstance(validated_context, dict)
        else None
    )
    owner_task = (
        context_owner
        if isinstance(context_owner, CampaignTaskRecord)
        and context_owner.id == owner_task_id
        else repository.session.get(CampaignTaskRecord, owner_task_id)
    )
    if owner_task is None:
        return None
    owner_payload = _safe_payload(owner_task.payload)
    task_snapshot_digest = _bare_source_snapshot_digest(
        task_payload.get("source_snapshot_digest")
    )
    owner_snapshot_digest = _bare_source_snapshot_digest(
        owner_payload.get("source_snapshot_digest")
    )
    if validated_context is not None:
        context_campaign = validated_context.get("campaign")
        context_pipeline_run = validated_context.get("pipeline_run")
        pipeline_run_id = _text(getattr(context_pipeline_run, "id", ""))
        if (
            _text(getattr(context_campaign, "id", "")) != task.campaign_id
            or task_payload.get("pipeline_run_id") != pipeline_run_id
            or (
                owner_payload.get("pipeline_run_id") != pipeline_run_id
                and f"pipeline_run:{pipeline_run_id}" not in owner_task.input_refs
            )
        ):
            return None
        task_snapshot_digest = owner_snapshot_digest
    if (
        (
            validated_context is None
            and (
                task_payload.get("schema_version") != TASK_SCHEMA_VERSION
                or not _has_false_safety_fields(task_payload)
            )
        )
        or owner_task.campaign_id != task.campaign_id
        or owner_task.task_type != "candidate_refutation"
        or owner_task.status
        not in {"awaiting_evidence", "needs_evidence", "running", "blocked"}
        or owner_payload.get("runtime_schema") != "autonomous_research_v1"
        or not _has_false_safety_fields(owner_payload)
        or owner_payload.get("raw_payload_in_dispatch") is not False
        or (
            validated_context is None
            and task_payload.get("pipeline_run_id")
            != owner_payload.get("pipeline_run_id")
        )
        or not task_snapshot_digest
        or task_snapshot_digest != owner_snapshot_digest
    ):
        return None
    if owner_task.status == "blocked" and (
        owner_payload.get("blocked_by_evidence_task_id") != task.id
        or not _text(owner_payload.get("blocked_stop_reason"))
    ):
        return None
    return owner_task


def _safe_source_manifest(value: object) -> list[dict[str, str]] | None:
    if not isinstance(value, list):
        return None
    manifest: list[dict[str, str]] = []
    seen_paths: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            return None
        source_path = _safe_relative_path(item.get("source_path"))
        content_digest = _text(item.get("content_digest"))
        if (
            not source_path
            or source_path in seen_paths
            or len(content_digest) != 64
            or any(character not in "0123456789abcdef" for character in content_digest.lower())
        ):
            return None
        seen_paths.add(source_path)
        manifest.append(
            {"source_path": source_path, "content_digest": content_digest.lower()}
        )
    return sorted(manifest, key=lambda item: item["source_path"])


def _collect_authorized_evidence_files(root: Path) -> list[dict[str, str]]:
    resolved_root = root.resolve(strict=True)
    files: list[dict[str, str]] = []
    for candidate in sorted(resolved_root.rglob("*")):
        if len(files) >= MAX_AUTHORIZED_SOURCE_FILES:
            break
        try:
            resolved_candidate = candidate.resolve(strict=True)
        except OSError:
            continue
        if not resolved_candidate.is_relative_to(resolved_root):
            raise OSError("evidence_source_symlink_escape")
        if (
            not resolved_candidate.is_file()
            or candidate.suffix.lower() not in AUTHORIZED_SOURCE_SUFFIXES
        ):
            continue
        try:
            content = resolved_candidate.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError):
            continue
        if content.strip():
            files.append(
                {
                    "path": candidate.relative_to(resolved_root).as_posix(),
                    "content": content[:MAX_AUTHORIZED_SOURCE_CHARS],
                }
            )
    return files


def _snapshot_manifest(code_files: list[dict[str, str]]) -> list[dict[str, str]] | None:
    manifest: list[dict[str, str]] = []
    seen_paths: set[str] = set()
    for item in code_files:
        path = item.get("path") if isinstance(item, dict) else None
        content = item.get("content") if isinstance(item, dict) else None
        source_path = _safe_relative_path(path) if isinstance(path, str) else ""
        if not source_path or not isinstance(content, str) or source_path in seen_paths:
            return None
        seen_paths.add(source_path)
        manifest.append(
            {
                "source_path": source_path,
                "content_digest": sha256(content.encode("utf-8")).hexdigest(),
            }
        )
    return sorted(manifest, key=lambda item: item["source_path"])


def _source_snapshot_digest(manifest: list[dict[str, str]]) -> str:
    serialized = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    return sha256(serialized.encode("utf-8")).hexdigest()


def _bare_source_snapshot_digest(value: object) -> str:
    digest = _text(value).lower()
    if digest.startswith("sha256:"):
        digest = digest.removeprefix("sha256:")
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        return ""
    return digest


def _source_manifest_digest(manifest: list[dict[str, str]]) -> str:
    return sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _result_idempotency_key(
    *,
    pipeline_run_id: str,
    task_id: str,
    state_digest: str,
    source_snapshot_digest: str,
) -> str:
    value = ":".join((pipeline_run_id, task_id, state_digest, source_snapshot_digest))
    return sha256(value.encode("utf-8")).hexdigest()


def _safe_route(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    method = _safe_text(value.get("method")).upper()
    path = _safe_text(value.get("path"))
    return {"method": method, "path": path} if method and path.startswith("/") else {}


def _safe_relative_path(value: object) -> str:
    text = _safe_text(value).replace("\\", "/")
    if not text or text.startswith("/") or ":" in text or ".." in text.split("/"):
        return ""
    return text


def _safe_priority(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _save_task_once(
    *,
    repository: Any,
    task_id: str,
    campaign_id: str,
    pipeline_run_id: str,
    evidence_request_stage_id: str,
    payload: dict[str, Any],
) -> CampaignTaskRecord:
    existing = repository.session.get(CampaignTaskRecord, task_id)
    if existing is not None:
        _validate_existing_task(
            existing,
            campaign_id=campaign_id,
            pipeline_run_id=pipeline_run_id,
            evidence_request_stage_id=evidence_request_stage_id,
            payload=payload,
        )
        return existing

    task = CampaignTaskRecord(
        id=task_id,
        campaign_id=campaign_id,
        task_type="candidate_hunter_evidence_inspection",
        agent_type="candidate_hunter_evidence_specialist",
        title="Inspect requested local Candidate Hunter evidence",
        status="queued",
        input_refs=[
            f"pipeline_run:{pipeline_run_id}",
            f"pipeline_stage:{evidence_request_stage_id}",
        ],
        output_refs=[],
        payload=payload,
    )
    repository.session.add(task)
    try:
        repository.session.commit()
    except IntegrityError:
        repository.session.rollback()
        existing = repository.session.get(CampaignTaskRecord, task_id)
        if existing is None:
            raise
        _validate_existing_task(
            existing,
            campaign_id=campaign_id,
            pipeline_run_id=pipeline_run_id,
            evidence_request_stage_id=evidence_request_stage_id,
            payload=payload,
        )
        return existing
    repository.session.refresh(task)
    return task


def _validate_existing_task(
    task: CampaignTaskRecord,
    *,
    campaign_id: str,
    pipeline_run_id: str,
    evidence_request_stage_id: str,
    payload: dict[str, Any],
) -> None:
    expected_refs = [
        f"pipeline_run:{pipeline_run_id}",
        f"pipeline_stage:{evidence_request_stage_id}",
    ]
    if (
        task.campaign_id != campaign_id
        or task.task_type != "candidate_hunter_evidence_inspection"
        or task.agent_type != "candidate_hunter_evidence_specialist"
        or task.input_refs != expected_refs
        or _safe_payload(task.payload) != payload
    ):
        raise ValueError("evidence_task_idempotency_conflict")


def _safe_request(value: object) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    candidate_id = _safe_text(value.get("candidate_id"))
    if not candidate_id:
        return None
    return {
        "candidate_id": candidate_id,
        "requested_artifact_kinds": _safe_artifact_kinds(
            value.get("requested_artifact_kinds")
        ),
        "refutation_questions": _safe_string_list(value.get("refutation_questions")),
        "inspection_targets": _safe_targets(value.get("inspection_targets")),
    }


def _safe_artifact_kinds(value: object) -> list[str]:
    allowed = {"scope", "policy", "code", "api", "har"}
    if not isinstance(value, list):
        return []
    return _ordered_unique(
        kind for item in value if (kind := _safe_text(item)) in allowed
    )


def _safe_targets(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    targets = []
    for item in value:
        if not isinstance(item, dict):
            continue
        artifact_kind = _safe_text(item.get("artifact_kind"))
        if artifact_kind not in {"scope", "policy", "code", "api", "har"}:
            continue
        target: dict[str, Any] = {"artifact_kind": artifact_kind}
        route = item.get("route")
        if isinstance(route, dict):
            method = _safe_text(route.get("method")).upper()
            path = _safe_text(route.get("path"))
            if method and path.startswith("/"):
                target["route"] = {"method": method, "path": path}
        symbols = _safe_string_list(item.get("symbols"))
        if symbols:
            target["symbols"] = symbols
        targets.append(target)
    return targets


def _ordered_targets(values: Any) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []
    for value in values:
        if value and value not in unique:
            unique.append(value)
    return unique


def _safe_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return _ordered_unique(
        text for item in value if (text := _safe_text(item))
    )


def _safe_payload(value: object) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _has_false_safety_fields(payload: dict[str, Any]) -> bool:
    return all(payload.get(field) is False for field in SAFETY_FIELDS)


def _false_safety_fields() -> dict[str, bool]:
    return {field: False for field in SAFETY_FIELDS}


def _task_idempotency_key(
    *,
    pipeline_run_id: str,
    evidence_request_stage_id: str,
    state_digest: str,
) -> str:
    value = ":".join((pipeline_run_id, evidence_request_stage_id, state_digest))
    return sha256(value.encode("utf-8")).hexdigest()


def _ordered_unique(values: Any) -> list[str]:
    unique: list[str] = []
    for value in values:
        if value and value not in unique:
            unique.append(value)
    return unique


def _safe_text(value: object) -> str:
    text = _text(value)
    lowered = text.lower()
    forbidden = (
        "authorization:",
        "bearer ",
        "cookie:",
        "set-cookie:",
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "password",
        "client_secret",
        "credential",
        "secret",
        "real user data",
        "production user",
    )
    return "" if any(marker in lowered for marker in forbidden) else text


def _text(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


__all__ = [
    "completed_evidence_result_is_valid",
    "materialize_evidence_inspection_task",
    "resume_candidate_hunter_after_evidence",
    "run_evidence_inspection_task",
]
