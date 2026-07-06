from hashlib import sha256

from app.db import get_session_factory, initialize_database
from app.db_models import CampaignRecord, CampaignTaskRecord
from app.repository import DatabaseRepository
from app.worker.celery_app import celery_app


@celery_app.task(name="worker.ping")
def ping() -> str:
    return "pong"


@celery_app.task(name="agent.run")
def run_agent_task_from_queue(campaign_task_id: str) -> dict:
    initialize_database()
    with get_session_factory()() as session:
        return run_agent_task(campaign_task_id, repository=DatabaseRepository(session))


def dispatch_agent_task(*, campaign_task_id: str) -> dict:
    queued_task = run_agent_task_from_queue.delay(campaign_task_id)
    return {
        "campaign_task_id": campaign_task_id,
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

    campaign = repository.get_campaign(task.campaign_id)
    stop_reason = _agent_task_stop_reason(
        campaign_status=campaign.status if campaign else None,
        scope_status=campaign.scope_status if campaign else None,
    )
    if stop_reason is not None:
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
        repository.update_campaign_task_status(
            task.id,
            "blocked",
            output_refs=[f"agent_run:{agent_run.id}"],
        )
        return {
            "status": "blocked",
            "task_id": task.id,
            "agent_run_id": agent_run.id,
            "stop_reason": stop_reason,
        }

    active_run = repository.find_active_agent_run_for_task(task.id)
    materialized_output_refs, artifact_payload = _materialize_read_only_artifacts(
        task=task,
        campaign=campaign,
        repository=repository,
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
    repository.update_campaign_task_status(
        task.id,
        "completed",
        output_refs=[f"agent_run:{agent_run.id}", *materialized_output_refs],
    )
    return {
        "status": "completed",
        "task_id": task.id,
        "agent_run_id": agent_run.id,
        "stop_reason": None,
    }


def _agent_task_stop_reason(
    *,
    campaign_status: str | None,
    scope_status: str | None,
) -> str | None:
    if scope_status != "in_scope":
        return "scope_not_in_scope"
    if campaign_status != "running":
        return "campaign_not_running"
    return None


def _materialize_read_only_artifacts(
    *,
    task: CampaignTaskRecord,
    campaign: CampaignRecord,
    repository: DatabaseRepository,
) -> tuple[list[str], dict]:
    if task.task_type == "attack_surface_mapping":
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
        hypothesis = {
            "hypothesis": "Authorized object access may have a review-worthy boundary.",
            "vuln_type": "authorization_boundary",
            "broken_invariant": "Users should only access objects permitted by role and ownership.",
            "validation_mode": "two_account_authorization_check",
            "risk_level": "medium",
            "policy_risk": "medium",
            "evidence_needed": ["test_account_role_matrix", "redacted_request_response_diff"],
        }
        pipeline_run = repository.save_pipeline_run(
            program_id=campaign.program_id,
            asset=campaign.default_asset,
            policy_text=campaign.policy_text_hash,
            scope_status=campaign.scope_status,
            hypothesis_count=1,
            blocked_count=1,
            report_title="Campaign hypothesis candidate requires human review",
            payload={
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
                        "candidate_id": "campaign_worker_hypothesis_1",
                        "hypothesis_index": 0,
                        "hypothesis": hypothesis,
                        "candidate_status": "needs_human_review",
                        "refutation": {
                            "status": "needs_human_review",
                            "reasons": ["worker_generated_candidate"],
                            "human_review_required": True,
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
            },
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
        plan_digest = _stable_ref_hash(f"campaign_task:{task.id}:validation_plan")
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
            target_ref=f"campaign:{campaign.id}",
            status="planned",
            safety_gate_state="awaiting_approval",
            plan_digest=approval.plan_digest,
            approval_required=True,
            allowed_to_execute=False,
            evidence_ref_count=0,
            summary="Validation is planned but blocked pending durable human approval.",
            payload={
                "approval_record_id": approval.id,
                "raw_payload_processed": False,
                "no_live_requests": True,
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


def _stable_ref_hash(value: str) -> str:
    return f"sha256:{sha256(value.encode('utf-8')).hexdigest()}"
