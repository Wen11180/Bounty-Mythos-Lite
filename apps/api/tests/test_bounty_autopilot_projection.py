"""Safe Autopilot projection contracts."""

from app.bounty_autopilot.projection import build_autopilot_projection


def test_projection_is_safe_and_submission_blocked():
    proj = build_autopilot_projection(
        campaign_id="camp_1",
        emergency_stopped=False,
        authorization={
            "authorization_digest": "sha256:" + ("a" * 64),
            "scope_snapshot_digest": "sha256:" + ("b" * 64),
            "policy_mode": "authorized_local_lab",
            "budgets": {"max_requests": 10},
        },
        assets=[{"asset_id": "asset_lab", "status": "admitted", "host": "127.0.0.1"}],
        branches=[
            {
                "branch_id": "branch_a",
                "asset_id": "asset_lab",
                "status": "queued",
                "priority": 20,
                "risk_tier": "R1",
            },
            {
                "branch_id": "branch_b",
                "asset_id": "asset_lab",
                "status": "parked",
                "priority": 90,
                "risk_tier": "R1",
                "reason": "waf",
            },
        ],
        plans=[{"plan_id": "p1", "plan_digest": "sha256:" + ("c" * 64), "status": "ready"}],
        leases=[{"lease_id": "l1", "plan_id": "p1", "status": "active"}],
        requests=[{"status": "completed"}, {"status": "reserved"}],
        risk_decisions=[
            {
                "risk_decision_id": "risk_1",
                "branch_id": "branch_a",
                "recipe_id": "lab_browser_mapping",
                "status": "authorized",
            }
        ],
        tool_runs=[
            {
                "tool_run_id": "toolrun_1",
                "branch_id": "branch_a",
                "lease_id": "l1",
                "plan_id": "p1",
                "run_status": "completed",
            }
        ],
        observations=[
            {
                "observation_id": "o1",
                "branch_id": "branch_a",
                "tool_run_id": "toolrun_1",
                "outcome_class": "ok",
                "summary": "Bearer must-not-leak",
            }
        ],
        refutations=[
            {
                "decision_id": "refutation_1",
                "branch_id": "branch_a",
                "verdict": "retained",
            }
        ],
        candidates=[
            {
                "candidate_id": "candidate_1",
                "branch_id": "branch_a",
                "judge_verdict": "retained_candidate",
            }
        ],
        reports=[
            {
                "report_id": "report_1",
                "candidate_id": "candidate_1",
            }
        ],
        approvals=[
            {
                "approval_id": "ap1",
                "status": "pending",
                "plan_digest": "sha256:" + ("c" * 64),
                "exact_diff": [
                    {
                        "field": "max_requests",
                        "before": "1",
                        "after": "2",
                    },
                    {
                        "field": "response_body",
                        "before": "safe",
                        "after": "must-not-render",
                    },
                ],
            }
        ],
        budget_remaining={
            "asset_requests_remaining": 4,
            "account_requests_remaining": 3,
            "branch_requests_remaining": 2,
            "hypothesis_requests_remaining": 2,
            "recipe_requests_remaining": 5,
            "request_slots_remaining": 1,
            "time_seconds_remaining": 30,
            "retry_attempts_remaining": 1,
            "model_cost_units_remaining": 8,
        },
    )
    assert proj.campaign_id == "camp_1"
    assert proj.next_branch_id == "branch_a"
    assert proj.candidate_promotion_allowed is False
    assert proj.report_submission_allowed is False
    assert proj.submission_blocked is True
    assert proj.budgets.campaign_requests_used == 2
    assert proj.budgets.campaign_requests_remaining == 8
    assert proj.budgets.active_leases == 1
    assert proj.budgets.asset_requests_remaining == 4
    assert proj.approvals[0].exact_diff[0].field == "max_requests"
    assert len(proj.approvals[0].exact_diff) == 1
    assert [event.kind for event in proj.events] == [
        "plan",
        "risk",
        "lease",
        "tool_run",
        "observation",
        "refutation",
        "candidate",
        "report",
    ]
    dumped = proj.model_dump(mode="json")
    blob = str(dumped).lower()
    assert "authorization:" not in blob
    assert "cookie" not in blob
    assert "password" not in blob
    assert "bearer" not in blob
    assert "must-not-leak" not in blob


def test_projection_emergency_stop_blocks_next_work():
    proj = build_autopilot_projection(
        campaign_id="camp_1",
        emergency_stopped=True,
        branches=[{"branch_id": "b1", "asset_id": "a1", "status": "queued", "priority": 1}],
    )
    assert proj.next_branch_id is None
    assert proj.next_reason == "emergency_stopped"
