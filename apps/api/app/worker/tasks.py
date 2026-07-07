from hashlib import sha256

from app.codebase_map import CodebaseMapResult, map_authorized_code_files
from app.db import get_session_factory, initialize_database
from app.db_models import (
    CampaignRecord,
    CampaignTaskRecord,
    CodebaseFactRecord,
    LearningSignalRecord,
)
from app.mythos_brain import LearningSignal, MythosLesson, build_mythos_lessons
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
        campaign=campaign,
        repository=repository,
        task_id=task.id,
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
) -> tuple[list[str], dict]:
    if task.task_type == "attack_surface_mapping":
        static_map = map_authorized_code_files(task.payload)
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
    hypothesis = {
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
                "candidate_id": "campaign_worker_hypothesis_1",
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


def _codebase_fact_hypothesis_payload(
    *,
    campaign: CampaignRecord,
    task: CampaignTaskRecord,
    codebase_facts: list[CodebaseFactRecord],
    learning_signals: list[LearningSignalRecord] | None = None,
) -> dict:
    routes = sorted(
        (fact for fact in codebase_facts if fact.fact_type == "route_handler"),
        key=lambda fact: (
            fact.source_path,
            fact.route_method or "",
            fact.route_path or "",
            fact.symbol_name,
        ),
    )
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
        queue.append(
            {
                "queue_id": f"hunt_queue_{assessment['candidate_id']}",
                "candidate_id": assessment["candidate_id"],
                "playbook_id": hunter_assessment.get(
                    "playbook_id",
                    "codebase_authorization_boundary",
                ),
                "priority_score": hunter_assessment.get("hunter_priority_score", 65),
                "status": "awaiting_human_approval",
                "next_action": "review_validation_plan",
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
        )
    return sorted(queue, key=lambda item: item["priority_score"], reverse=True)


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
        route=route,
        authz=authz,
        sink=sink,
        authz_gap=authz_gap,
    )
    hypothesis = {
        "hypothesis": f"Review {route_label} for object authorization boundary drift.",
        "vuln_type": "authorization_boundary",
        "broken_invariant": "Route handlers that touch sensitive sinks must preserve object ownership and role boundaries.",
        "validation_mode": "two_account_authorization_check",
        "risk_level": "medium",
        "policy_risk": "medium",
        "evidence_needed": [
            "redacted_route_authorization_trace",
            "test_account_role_matrix",
            "sanitized_request_response_diff",
        ],
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
    return {
        "assessment": {
            "candidate_id": f"codebase_fact_hypothesis_{index}",
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
                "steps": [
                    "Review mapped route, authz hint, and sensitive sink provenance.",
                    "Use test accounts only after approval to compare authorized and unauthorized object access.",
                ],
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
    route: CodebaseFactRecord,
    authz: CodebaseFactRecord | None,
    sink: CodebaseFactRecord | None,
    authz_gap: CodebaseFactRecord | None = None,
) -> list[dict]:
    facts = [_route_source_fact(route)]
    if authz is not None:
        facts.append(_authz_source_fact(authz))
    if authz_gap is not None:
        facts.append(_authz_gap_source_fact(authz_gap))
    if sink is not None:
        facts.append(_sink_source_fact(sink))
    return facts


def _route_source_fact(fact: CodebaseFactRecord) -> dict:
    return {
        "fact_ref": f"codebase_fact:route_handler:{fact.route_path}",
        "fact_type": fact.fact_type,
        "route_method": fact.route_method,
        "route_path": fact.route_path,
        "source_path": fact.source_path,
        "symbol_name": fact.symbol_name,
    }


def _authz_source_fact(fact: CodebaseFactRecord) -> dict:
    return {
        "fact_ref": f"codebase_fact:authz_check:{fact.authz_hint}",
        "authz_hint": fact.authz_hint,
        "fact_type": fact.fact_type,
        "source_path": fact.source_path,
        "symbol_name": fact.symbol_name,
    }


def _sink_source_fact(fact: CodebaseFactRecord) -> dict:
    return {
        "fact_ref": f"codebase_fact:sensitive_sink:{fact.symbol_name}",
        "fact_type": fact.fact_type,
        "source_path": fact.source_path,
        "symbol_name": fact.symbol_name,
    }


def _authz_gap_source_fact(fact: CodebaseFactRecord) -> dict:
    return {
        "fact_ref": f"codebase_fact:authorization_gap_candidate:{fact.route_path}",
        "authz_hint": fact.authz_hint,
        "fact_type": fact.fact_type,
        "route_method": fact.route_method,
        "route_path": fact.route_path,
        "source_path": fact.source_path,
        "symbol_name": fact.symbol_name,
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
            "mapping_mode": "static_code_snippet_analysis",
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


def _stable_ref_hash(value: str) -> str:
    return f"sha256:{sha256(value.encode('utf-8')).hexdigest()}"
