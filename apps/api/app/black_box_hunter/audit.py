"""Durable, alias-only audit records for local black-box differential work."""

from __future__ import annotations

from hashlib import sha256
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.black_box_hunter import (
    BLACK_BOX_VALIDATION_TYPE,
    BlackBoxExecutionLease,
    DifferentialEvidenceBundle,
    DifferentialEvidenceDecision,
    DifferentialPlan,
    ObservedWorkflowModel,
    TrialObservation,
    evaluate_differential_evidence,
)
from app.scope_guard import (
    ScopeGuardRule,
    ValidationRequest,
    evaluate_validation_request,
)
from app.repository import approval_record_is_active


AUDIT_SCHEMA_VERSION = "black_box_audit_v1"
INITIAL_STAGE_KEYS = (
    "black_box_lease",
    "black_box_workflow",
    "black_box_plan",
)
FINAL_STAGE_KEYS = (*INITIAL_STAGE_KEYS, "black_box_trial", "black_box_decision")
SAFE_AUDIT_FLAGS = {
    "execution_allowed": False,
    "validation_allowed": False,
    "report_submission_allowed": False,
    "human_confirmed": False,
    "finding_promotion_allowed": False,
    "submission_blocked": True,
}
SAFE_BLACK_BOX_EVIDENCE_REFS = {
    "sanitized_cross_account_diff",
    "sanitized_parent_child_matrix",
}


class BlackBoxAuditError(ValueError):
    pass


class BlackBoxAuditOwner(BaseModel):
    model_config = ConfigDict(extra="forbid")

    audit_digest: str = Field(min_length=1, max_length=255)
    campaign_id: str = Field(min_length=1, max_length=255)
    task_id: str = Field(min_length=1, max_length=255)
    approval_id: str = Field(min_length=1, max_length=255)
    validation_run_id: str = Field(min_length=1, max_length=255)


class BlackBoxAuditProjection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    audit_digest: str = Field(min_length=1, max_length=255)
    campaign_id: str = Field(min_length=1, max_length=255)
    task_id: str = Field(min_length=1, max_length=255)
    approval_id: str = Field(min_length=1, max_length=255)
    validation_run_id: str = Field(min_length=1, max_length=255)
    status: str = Field(min_length=1, max_length=255)
    evidence_refs: list[str] = Field(default_factory=list)
    candidate: dict[str, Any] | None = None


class BlackBoxBoundedResultRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_index: int = Field(ge=0)
    evidence: DifferentialEvidenceBundle


def open_black_box_audit(
    *,
    repository: Any,
    rule: ScopeGuardRule,
    lease: BlackBoxExecutionLease,
    workflows: ObservedWorkflowModel,
    plans: list[DifferentialPlan],
) -> BlackBoxAuditOwner:
    _require_auditable_scope(rule, lease)
    if not plans:
        raise BlackBoxAuditError("differential_plan_required")

    workflow_projection = workflows.safe_projection()
    plan_projection = _plan_projection(plans)
    audit_digest = _digest(
        {
            "lease": lease.safe_projection(),
            "workflows": workflow_projection,
            "plans": plan_projection,
        }
    )
    existing = _find_existing_owner(repository, audit_digest)
    if existing is not None:
        return existing

    campaign = repository.create_campaign(
        program_id=None,
        name="Black-box local-lab differential audit",
        autonomy_level="level_0_local_lab",
        scope_status="in_scope",
        policy_text=f"black_box_policy_digest:{lease.policy_digest}",
        default_asset=lease.asset,
        target_classes=["authorization"],
        allowed_tools=["black_box_local_lab_audit"],
        created_by="black_box_audit",
        payload={
            "schema_version": AUDIT_SCHEMA_VERSION,
            "audit_digest": audit_digest,
            "policy_digest": lease.policy_digest,
            "scope_digest": lease.scope_digest,
            **SAFE_AUDIT_FLAGS,
        },
    )
    task = repository.create_campaign_task(
        campaign_id=campaign.id,
        task_type="black_box_differential_audit",
        agent_type="black_box_audit",
        title="Review local black-box differential evidence",
        input_refs=[f"black_box_audit:{audit_digest}"],
        payload={
            "schema_version": AUDIT_SCHEMA_VERSION,
            "audit_digest": audit_digest,
            **SAFE_AUDIT_FLAGS,
        },
    )
    approval = repository.create_approval_record(
        campaign_id=campaign.id,
        task_id=task.id,
        approval_type="black_box_local_lab_result",
        actor="black_box_audit",
        reason="Human approval required before recording bounded local-lab evidence.",
        scope_reference=lease.scope_digest,
        requested_action="black_box_differential",
        asset=lease.asset,
        validation_mode=BLACK_BOX_VALIDATION_TYPE,
        plan_digest=lease.plan_digest,
        autonomy_level="level_0_local_lab",
        safety_gate_state="awaiting_approval",
        expires_at=lease.expires_at,
        payload={
            "schema_version": AUDIT_SCHEMA_VERSION,
            "audit_digest": audit_digest,
            "allowed_accounts": lease.account_aliases,
            **SAFE_AUDIT_FLAGS,
        },
    )
    validation_run = repository.save_validation_run(
        campaign_id=campaign.id,
        task_id=task.id,
        approval_id=approval.id,
        validation_mode=BLACK_BOX_VALIDATION_TYPE,
        target_ref=lease.asset,
        status="awaiting_approval",
        safety_gate_state="awaiting_approval",
        plan_digest=lease.plan_digest,
        approval_required=True,
        allowed_to_execute=False,
        evidence_ref_count=0,
        summary="Awaiting human approval before local-lab result recording.",
        payload={
            "schema_version": AUDIT_SCHEMA_VERSION,
            "audit_digest": audit_digest,
            "scope_reference": lease.scope_digest,
            "allowed_accounts": lease.account_aliases,
            **SAFE_AUDIT_FLAGS,
        },
    )
    owner = BlackBoxAuditOwner(
        audit_digest=audit_digest,
        campaign_id=campaign.id,
        task_id=task.id,
        approval_id=approval.id,
        validation_run_id=validation_run.id,
    )
    _save_initial_stages(
        repository=repository,
        owner=owner,
        lease=lease,
        workflows=workflow_projection,
        plans=plan_projection,
    )
    return owner


def record_black_box_bounded_result(
    *,
    repository: Any,
    validation_run_id: str,
    plan_index: int,
    evidence: DifferentialEvidenceBundle,
) -> BlackBoxAuditProjection:
    validation_run = repository.get_validation_run(validation_run_id)
    if validation_run is None:
        raise BlackBoxAuditError("validation_run_not_found")
    owner = _owner_for_validation_run(repository, validation_run)
    existing_result = (
        validation_run.payload.get("black_box_bounded_result")
        if isinstance(validation_run.payload, dict)
        else None
    )
    request_digest = _bounded_result_request_digest(plan_index, evidence)
    if isinstance(existing_result, dict):
        result_payload = existing_result.get("result_payload")
        if (
            not isinstance(result_payload, dict)
            or result_payload.get("request_digest") != request_digest
        ):
            raise BlackBoxAuditError("bounded_result_request_mismatch")
        return load_black_box_audit_projection(
            repository=repository,
            validation_run_id=validation_run_id,
        )
    if validation_run.status != "preflight_passed" or not validation_run.allowed_to_execute:
        raise BlackBoxAuditError("preflight_passed_required")
    _require_active_owner_approval(repository, owner, validation_run)

    stages = _validated_stages(repository, owner)
    decision = evaluate_differential_evidence(evidence)
    plan_stage = stages["black_box_plan"]
    selected_plan = _selected_plan(plan_stage.payload.get("plans"), plan_index)
    evidence_refs = _evidence_refs_for_plan(selected_plan)
    if decision.status == "review_ready" and not evidence_refs:
        decision = DifferentialEvidenceDecision(
            status="reproduced",
            reason="review_evidence_type_unsupported",
        )
    candidate = (
        _candidate_projection(
            audit_digest=owner.audit_digest,
            plan=selected_plan,
            plan_index=plan_index,
            evidence_refs=evidence_refs,
        )
        if decision.status == "review_ready"
        else None
    )
    trial_content = {
        "plan_index": plan_index,
        "trial_class": selected_plan.get("trial_class"),
        "observations": _evidence_projection(evidence),
        "evidence_refs": evidence_refs,
        "stop_reasons": _stop_reasons(evidence),
    }
    decision_content = {
        "decision": decision.model_dump(),
        "candidate": candidate,
        "plan_index": plan_index,
        "evidence_refs": evidence_refs,
        "approval_ref": f"approval:{owner.approval_id}",
        "preflight_ref": f"validation_run:{owner.validation_run_id}",
    }
    for stage_order, (stage_key, content, status) in enumerate(
        (
            ("black_box_trial", trial_content, "recorded"),
            ("black_box_decision", decision_content, decision.status),
        ),
        start=4,
    ):
        repository.save_pipeline_stage(
            pipeline_run_id=None,
            campaign_id=owner.campaign_id,
            task_id=owner.task_id,
            stage_key=stage_key,
            stage_order=stage_order,
            status=status,
            input_refs=[f"validation_run:{owner.validation_run_id}"],
            output_refs=evidence_refs,
            safety_gate_state="preflight_passed",
            stop_reason=(
                _stop_reasons(evidence)[0]
                if _stop_reasons(evidence)
                else None
            ),
            payload=_stage_payload(owner.audit_digest, stage_key, content),
        )
    updated = repository.record_validation_run_bounded_result(
        owner.validation_run_id,
        audit_digest=owner.audit_digest,
        decision_status=decision.status,
        evidence_refs=evidence_refs,
        payload={
            "plan_index": plan_index,
            "request_digest": request_digest,
            "evidence_refs": evidence_refs,
            "stop_reasons": _stop_reasons(evidence),
            "candidate_id": candidate["candidate_id"] if candidate else None,
            **SAFE_AUDIT_FLAGS,
        },
    )
    if updated is None:
        raise BlackBoxAuditError("bounded_result_write_failed")
    return load_black_box_audit_projection(
        repository=repository,
        validation_run_id=owner.validation_run_id,
    )


def load_black_box_audit_projection(
    *,
    repository: Any,
    validation_run_id: str,
) -> BlackBoxAuditProjection:
    validation_run = repository.get_validation_run(validation_run_id)
    if validation_run is None:
        raise BlackBoxAuditError("validation_run_not_found")
    owner = _owner_for_validation_run(repository, validation_run)
    stages = _validated_stages(repository, owner)
    bounded_result = (
        validation_run.payload.get("black_box_bounded_result")
        if isinstance(validation_run.payload, dict)
        else None
    )
    if not isinstance(bounded_result, dict):
        if any(stage_key in stages for stage_key in FINAL_STAGE_KEYS[3:]):
            raise BlackBoxAuditError("terminal_stages_without_bounded_result")
        return BlackBoxAuditProjection(
            **owner.model_dump(),
            status="awaiting_result",
        )
    if bounded_result.get("audit_digest") != owner.audit_digest:
        raise BlackBoxAuditError("validation_run_digest_mismatch")
    if bounded_result.get("execution_started") is not False:
        raise BlackBoxAuditError("execution_started_must_be_false")

    trial_stage = stages.get("black_box_trial")
    decision_stage = stages.get("black_box_decision")
    if trial_stage is None or decision_stage is None:
        raise BlackBoxAuditError("terminal_stages_required")
    decision_payload = decision_stage.payload if isinstance(decision_stage.payload, dict) else {}
    decision = decision_payload.get("decision")
    if not isinstance(decision, dict) or decision.get("status") != bounded_result.get("decision_status"):
        raise BlackBoxAuditError("terminal_decision_mismatch")
    if decision_payload.get("preflight_ref") != f"validation_run:{owner.validation_run_id}":
        raise BlackBoxAuditError("preflight_reference_mismatch")
    if decision_payload.get("approval_ref") != f"approval:{owner.approval_id}":
        raise BlackBoxAuditError("approval_reference_mismatch")
    result_payload = bounded_result.get("result_payload")
    plan_index = result_payload.get("plan_index") if isinstance(result_payload, dict) else None
    if isinstance(plan_index, bool) or not isinstance(plan_index, int):
        raise BlackBoxAuditError("bounded_result_plan_index_required")
    if (
        trial_stage.payload.get("plan_index") != plan_index
        or decision_payload.get("plan_index") != plan_index
        or result_payload.get("request_digest")
        != _digest(
            {
                "plan_index": plan_index,
                "observations": trial_stage.payload.get("observations"),
                "stop_reasons": trial_stage.payload.get("stop_reasons"),
            }
        )
    ):
        raise BlackBoxAuditError("bounded_result_plan_linkage_invalid")
    candidate = decision_payload.get("candidate")
    if decision.get("status") == "review_ready":
        if not isinstance(candidate, dict):
            raise BlackBoxAuditError("review_ready_candidate_required")
        _require_submission_blocked_candidate(
            candidate,
            plan_index=plan_index,
            evidence_refs=decision_payload.get("evidence_refs"),
        )
    elif candidate is not None:
        raise BlackBoxAuditError("terminal_candidate_not_allowed")
    return BlackBoxAuditProjection(
        **owner.model_dump(),
        status=str(decision.get("status")),
        evidence_refs=[str(ref) for ref in decision_payload.get("evidence_refs", [])],
        candidate=candidate if isinstance(candidate, dict) else None,
    )


def _require_auditable_scope(
    rule: ScopeGuardRule,
    lease: BlackBoxExecutionLease,
) -> None:
    decision = evaluate_validation_request(
        rule,
        ValidationRequest(
            asset=lease.asset,
            validation_type=BLACK_BOX_VALIDATION_TYPE,
            human_approved=False,
            plan_digest=lease.plan_digest,
        ),
    )
    if not decision.allowed and decision.reason != "human_approval_required":
        raise BlackBoxAuditError(f"scope_guard:{decision.reason}")


def _find_existing_owner(repository: Any, audit_digest: str) -> BlackBoxAuditOwner | None:
    campaigns = [
        campaign
        for campaign in repository.list_campaigns()
        if isinstance(campaign.payload, dict)
        and campaign.payload.get("audit_digest") == audit_digest
        and campaign.payload.get("schema_version") == AUDIT_SCHEMA_VERSION
    ]
    if len(campaigns) > 1:
        raise BlackBoxAuditError("ambiguous_audit_owner")
    if not campaigns:
        return None

    campaign = campaigns[0]
    tasks = [
        task
        for task in repository.list_campaign_tasks(campaign.id)
        if isinstance(task.payload, dict)
        and task.payload.get("audit_digest") == audit_digest
    ]
    approvals = [
        approval
        for approval in repository.list_campaign_approval_records(campaign.id)
        if isinstance(approval.payload, dict)
        and approval.payload.get("audit_digest") == audit_digest
    ]
    validation_runs = [
        run
        for run in repository.list_campaign_validation_runs(campaign.id)
        if isinstance(run.payload, dict) and run.payload.get("audit_digest") == audit_digest
    ]
    if len(tasks) != 1 or len(approvals) != 1 or len(validation_runs) != 1:
        raise BlackBoxAuditError("corrupt_audit_owner_linkage")
    task = tasks[0]
    approval = approvals[0]
    validation_run = validation_runs[0]
    if (
        approval.task_id != task.id
        or validation_run.task_id != task.id
        or validation_run.approval_id != approval.id
    ):
        raise BlackBoxAuditError("corrupt_audit_owner_linkage")
    return BlackBoxAuditOwner(
        audit_digest=audit_digest,
        campaign_id=campaign.id,
        task_id=task.id,
        approval_id=approval.id,
        validation_run_id=validation_run.id,
    )


def _owner_for_validation_run(repository: Any, validation_run: Any) -> BlackBoxAuditOwner:
    payload = validation_run.payload if isinstance(validation_run.payload, dict) else {}
    audit_digest = payload.get("audit_digest")
    if not isinstance(audit_digest, str) or not audit_digest:
        raise BlackBoxAuditError("audit_digest_required")
    owner = _find_existing_owner(repository, audit_digest)
    if owner is None or owner.validation_run_id != validation_run.id:
        raise BlackBoxAuditError("corrupt_audit_owner_linkage")
    return owner


def _require_active_owner_approval(
    repository: Any,
    owner: BlackBoxAuditOwner,
    validation_run: Any,
) -> None:
    approval = next(
        (
            record
            for record in repository.list_campaign_approval_records(owner.campaign_id)
            if record.id == owner.approval_id
        ),
        None,
    )
    if (
        approval is None
        or approval.status != "approved"
        or not approval_record_is_active(approval)
    ):
        raise BlackBoxAuditError("active_approval_required")
    run_payload = validation_run.payload if isinstance(validation_run.payload, dict) else {}
    if (
        validation_run.approval_required is not True
        or validation_run.approval_id != approval.id
        or approval.campaign_id != owner.campaign_id
        or approval.task_id != owner.task_id
        or approval.approval_type != "black_box_local_lab_result"
        or approval.validation_mode != BLACK_BOX_VALIDATION_TYPE
        or approval.plan_digest != validation_run.plan_digest
        or approval.asset != validation_run.target_ref
        or approval.scope_reference != run_payload.get("scope_reference")
    ):
        raise BlackBoxAuditError("approval_validation_run_mismatch")


def _validated_stages(repository: Any, owner: BlackBoxAuditOwner) -> dict[str, Any]:
    stage_records = [
        stage
        for stage in repository.list_campaign_pipeline_stages(owner.campaign_id)
        if stage.task_id == owner.task_id and stage.stage_key in FINAL_STAGE_KEYS
    ]
    stages: dict[str, Any] = {}
    for stage in stage_records:
        if stage.stage_key in stages:
            raise BlackBoxAuditError("duplicate_audit_stage")
        stages[stage.stage_key] = stage
    for order, stage_key in enumerate(INITIAL_STAGE_KEYS, start=1):
        stage = stages.get(stage_key)
        if stage is None:
            raise BlackBoxAuditError("initial_audit_stages_required")
        _validate_stage(stage, owner.audit_digest, stage_key, order)
    terminal_present = [key for key in FINAL_STAGE_KEYS[3:] if key in stages]
    if terminal_present and len(terminal_present) != 2:
        raise BlackBoxAuditError("incomplete_terminal_stages")
    for order, stage_key in enumerate(FINAL_STAGE_KEYS[3:], start=4):
        stage = stages.get(stage_key)
        if stage is not None:
            _validate_stage(stage, owner.audit_digest, stage_key, order)
    return stages


def _validate_stage(stage: Any, audit_digest: str, stage_key: str, stage_order: int) -> None:
    payload = stage.payload if isinstance(stage.payload, dict) else {}
    if (
        stage.stage_order != stage_order
        or payload.get("schema_version") != AUDIT_SCHEMA_VERSION
        or payload.get("audit_digest") != audit_digest
    ):
        raise BlackBoxAuditError("audit_stage_linkage_invalid")
    if any(payload.get(key) is not value for key, value in SAFE_AUDIT_FLAGS.items()):
        raise BlackBoxAuditError("audit_stage_safety_flags_invalid")
    content = {
        key: value
        for key, value in payload.items()
        if key
        not in {
            "schema_version",
            "audit_digest",
            "content_digest",
            "idempotency_key",
            *SAFE_AUDIT_FLAGS,
        }
    }
    content_digest = _digest(content)
    if (
        payload.get("content_digest") != content_digest
        or payload.get("idempotency_key")
        != f"{audit_digest}:{stage_key}:{content_digest}"
    ):
        raise BlackBoxAuditError("audit_stage_digest_invalid")


def _evidence_projection(evidence: DifferentialEvidenceBundle) -> dict:
    return {
        name: _observation_projection(observation)
        for name, observation in (
            ("baseline_a", evidence.baseline_a),
            ("baseline_b", evidence.baseline_b),
            ("trial", evidence.trial),
            ("owner_control", evidence.owner_control),
            ("alternate_account_control", evidence.session_control),
            ("repeat", evidence.repeat),
            ("rollback", evidence.rollback),
        )
        if observation is not None
    } | {
        "independent_repeat": evidence.independent_repeat,
        "rollback_required": evidence.rollback_required,
    }


def _observation_projection(observation: TrialObservation) -> dict:
    return {
        "status_class": observation.status_class,
        "response_schema_fingerprint": observation.response_schema_fingerprint,
        "timing_bucket": observation.timing_bucket,
        "canary_match": observation.canary_match,
        "structural_identity_match": observation.structural_identity_match,
        "state_effect": observation.state_effect,
        "intended_sharing": observation.intended_sharing,
        "stop_reason": observation.stop.reason if observation.stop else None,
        "redacted": True,
    }


def _stop_reasons(evidence: DifferentialEvidenceBundle) -> list[str]:
    reasons: list[str] = []
    for observation in (
        evidence.baseline_a,
        evidence.baseline_b,
        evidence.trial,
        evidence.owner_control,
        evidence.session_control,
        evidence.repeat,
        evidence.rollback,
    ):
        if observation is not None and observation.stop is not None:
            reason = observation.stop.reason
            if reason not in reasons:
                reasons.append(reason)
    return reasons


def _selected_plan(plans: object, plan_index: int) -> dict:
    if isinstance(plan_index, bool) or not isinstance(plan_index, int):
        raise BlackBoxAuditError("plan_index_required")
    if not isinstance(plans, list):
        raise BlackBoxAuditError("plan_projection_required")
    if plan_index >= len(plans) or not isinstance(plans[plan_index], dict):
        raise BlackBoxAuditError("selected_plan_required")
    return plans[plan_index]


def _evidence_refs_for_plan(plan: dict) -> list[str]:
    trial_class = plan.get("trial_class")
    if trial_class in {
        "cross_account_object_swap",
        "lower_role_replay",
        "unauthenticated_read_only_replay",
    }:
        return ["sanitized_cross_account_diff"]
    if trial_class == "owned_parent_child_swap":
        return ["sanitized_parent_child_matrix"]
    return []


def _candidate_projection(
    *,
    audit_digest: str,
    plan: dict,
    plan_index: int,
    evidence_refs: list[str],
) -> dict:
    stages = plan.get("stages")
    if not isinstance(stages, list):
        raise BlackBoxAuditError("candidate_trial_required")
    trial = next(
        (
            stage
            for stage in stages
            if isinstance(stage, dict) and stage.get("phase") == "trial"
        ),
        None,
    )
    route = trial.get("route") if isinstance(trial, dict) else None
    if (
        not isinstance(route, dict)
        or not isinstance(route.get("method"), str)
        or not isinstance(route.get("path"), str)
        or "?" in route["path"]
    ):
        raise BlackBoxAuditError("normalized_candidate_route_required")
    return {
        "candidate_id": f"black_box_{audit_digest[:16]}",
        "plan_index": plan_index,
        "trial_class": plan.get("trial_class"),
        "vulnerability_type": "authorization_boundary",
        "route": {"method": route["method"], "path": route["path"]},
        "evidence_refs": evidence_refs,
        "status": "review_ready",
        "human_review_required": True,
        "human_confirmed": False,
        "finding_promotion_allowed": False,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "submission_blocked": True,
        "submitted": False,
        "next_allowed_action": "Human review of redacted differential evidence.",
    }


def _require_submission_blocked_candidate(
    candidate: dict,
    *,
    plan_index: int,
    evidence_refs: object,
) -> None:
    if candidate.get("human_review_required") is not True:
        raise BlackBoxAuditError("candidate_human_review_required")
    if candidate.get("submission_blocked") is not True:
        raise BlackBoxAuditError("candidate_submission_must_be_blocked")
    if candidate.get("plan_index") != plan_index:
        raise BlackBoxAuditError("candidate_plan_linkage_invalid")
    if (
        not isinstance(evidence_refs, list)
        or not evidence_refs
        or any(ref not in SAFE_BLACK_BOX_EVIDENCE_REFS for ref in evidence_refs)
    ):
        raise BlackBoxAuditError("candidate_evidence_refs_invalid")
    if candidate.get("evidence_refs") != evidence_refs:
        raise BlackBoxAuditError("candidate_evidence_linkage_invalid")
    if any(
        candidate.get(field) is not False
        for field in (
            "human_confirmed",
            "finding_promotion_allowed",
            "execution_allowed",
            "validation_allowed",
            "report_submission_allowed",
            "submitted",
        )
    ):
        raise BlackBoxAuditError("candidate_permissions_must_be_false")


def _save_initial_stages(
    *,
    repository: Any,
    owner: BlackBoxAuditOwner,
    lease: BlackBoxExecutionLease,
    workflows: dict,
    plans: list[dict],
) -> None:
    records = (
        (
            "black_box_lease",
            {
                "lease_id": lease.lease_id,
                "policy_digest": lease.policy_digest,
                "scope_digest": lease.scope_digest,
                "plan_digest": lease.plan_digest,
                "account_aliases": lease.account_aliases,
                "role_aliases": lease.role_aliases,
            },
        ),
        ("black_box_workflow", workflows),
        ("black_box_plan", {"plans": plans}),
    )
    for stage_order, (stage_key, content) in enumerate(records, start=1):
        payload = _stage_payload(owner.audit_digest, stage_key, content)
        repository.save_pipeline_stage(
            pipeline_run_id=None,
            campaign_id=owner.campaign_id,
            task_id=owner.task_id,
            stage_key=stage_key,
            stage_order=stage_order,
            status="recorded",
            input_refs=[f"black_box_audit:{owner.audit_digest}"],
            output_refs=[f"validation_run:{owner.validation_run_id}"],
            safety_gate_state="awaiting_approval",
            stop_reason=None,
            payload=payload,
        )


def _stage_payload(audit_digest: str, stage_key: str, content: dict) -> dict:
    content_digest = _digest(content)
    return {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "audit_digest": audit_digest,
        "content_digest": content_digest,
        "idempotency_key": f"{audit_digest}:{stage_key}:{content_digest}",
        **SAFE_AUDIT_FLAGS,
        **content,
    }


def _bounded_result_request_digest(
    plan_index: int,
    evidence: DifferentialEvidenceBundle,
) -> str:
    return _digest(
        {
            "plan_index": plan_index,
            "observations": _evidence_projection(evidence),
            "stop_reasons": _stop_reasons(evidence),
        }
    )


def _plan_projection(plans: list[DifferentialPlan]) -> list[dict]:
    return [
        {
            "trial_class": plan.trial_class,
            "stages": [
                _planned_trial_projection(stage)
                for stage in (
                    plan.baseline,
                    plan.trial,
                    plan.owner_control,
                    plan.session_control,
                    plan.repeat,
                    plan.rollback,
                )
                if stage is not None
            ],
        }
        for plan in plans
    ]


def _planned_trial_projection(stage: Any) -> dict:
    return {
        "phase": stage.phase,
        "changed_variable": stage.changed_variable,
        "route": {
            "method": stage.workflow.method,
            "path": stage.workflow.route_template,
        },
        "account_alias": stage.session.account_alias,
        "role_alias": stage.session.role_alias,
        "object_alias": stage.test_object.alias,
        "owner_alias": stage.test_object.owner_alias,
        "parent_object_alias": stage.parent_object_alias,
        "requires_rollback": stage.requires_rollback,
    }


def _digest(value: object) -> str:
    serialized = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return sha256(serialized.encode("utf-8")).hexdigest()
