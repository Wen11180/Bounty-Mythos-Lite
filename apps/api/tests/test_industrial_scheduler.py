from app.industrial_scheduler import build_industrial_scheduler_plan


def test_build_industrial_scheduler_plan_creates_dag_dedup_risk_and_lifecycle():
    plan = build_industrial_scheduler_plan(
        {
            "scope": {"allowed": True, "reason": "authorized local repository"},
            "hypotheses": [
                {
                    "finding_id": "H-001",
                    "vuln_type": "authorization",
                    "severity": "high",
                    "affected_endpoint": "GET /api/orders/{order_id}",
                    "status": "unverified_hypothesis",
                },
                {
                    "finding_id": "H-002",
                    "vuln_type": "authorization",
                    "severity": "high",
                    "affected_endpoint": "GET /api/orders/{order_id}",
                    "status": "unverified_hypothesis",
                },
                {
                    "finding_id": "H-003",
                    "vuln_type": "static-analysis",
                    "severity": "low",
                    "affected_endpoint": None,
                    "status": "unverified_hypothesis",
                },
            ],
            "crs_fuzzing": {
                "parser_candidates": [{"symbol_name": "decode_frame"}],
            },
            "authorized_bug_bounty": {
                "role_diff_plans": [
                    {
                        "endpoint": "/api/orders/{order_id}",
                        "execution_allowed": False,
                    }
                ],
                "human_gate": {"status": "required"},
            },
        }
    )

    assert plan.stage == "v3_multi_agent_industrial_scheduling"
    assert plan.inspirations == ["MDASH"]
    assert plan.execution_mode == "plan_only_orchestration"
    assert all(task.scope_checked for task in plan.dag_tasks)
    assert all(task.execution_allowed is False for task in plan.dag_tasks)
    assert all(task.input_summary for task in plan.dag_tasks)
    assert all(task.output_summary for task in plan.dag_tasks)
    assert all(task.confidence in {"low", "medium", "high"} for task in plan.dag_tasks)
    assert all(task.safety_gate for task in plan.dag_tasks)
    assert all(task.next_actions for task in plan.dag_tasks)
    assert all(isinstance(task.evidence_refs, list) for task in plan.dag_tasks)
    human_review_tasks = [
        task for task in plan.dag_tasks if task.requires_human_review
    ]
    assert human_review_tasks
    assert all(
        task.safety_gate == "human_review_required"
        for task in human_review_tasks
    )
    task_by_id = {task.task_id: task for task in plan.dag_tasks}
    for batch in plan.parallel_batches:
        assert all(task_by_id[task_id].scope_checked for task_id in batch.task_ids)
    assert {task.agent for task in plan.dag_tasks} >= {
        "scope_agent",
        "code_auditor",
        "crs_fuzzing_agent",
        "bug_bounty_agent",
        "dedup_agent",
        "risk_prioritizer",
        "report_agent",
    }
    assert any(len(batch.task_ids) > 1 for batch in plan.parallel_batches)
    assert plan.finding_clusters[0].finding_ids == ["H-001", "H-002"]
    assert plan.risk_queue[0].finding_id == "H-001"
    assert plan.risk_queue[0].severity == "high"
    assert plan.lifecycle.states == [
        "candidate",
        "triaged",
        "human_review_required",
        "validated",
        "reported",
        "fixed",
        "regression_verified",
    ]
    guard_by_transition = {
        (guard.from_state, guard.to_state): guard
        for guard in plan.lifecycle.transition_guards
    }
    human_review_guard = guard_by_transition[("human_review_required", "validated")]
    assert human_review_guard.required_gates == [
        "human_reviewed",
        "redacted_evidence_attached",
    ]
    assert human_review_guard.status == "blocked_until_gates_satisfied"
    report_guard = guard_by_transition[("validated", "reported")]
    assert report_guard.required_gates == [
        "report_submission_approval",
        "auto_submit_block_confirmed",
    ]
    assert all(
        guard.execution_allowed is False and guard.bypass_allowed is False
        for guard in plan.lifecycle.transition_guards
    )
    assert plan.agent_memory.status == "advisory_update_planned"
    assert plan.continuous_scan.execution_allowed is False
    assert plan.patch_validation.execution_allowed is False
    assert "no_unscoped_agent_execution" in plan.safety_invariants
    assert "no_parallel_task_without_scope_check" in plan.safety_invariants
