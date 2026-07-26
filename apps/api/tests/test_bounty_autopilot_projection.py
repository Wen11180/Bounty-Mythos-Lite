"""Safe Autopilot projection contracts."""

import pytest

from app.bounty_autopilot.projection import _safe_route_path, build_autopilot_projection


def test_projection_is_safe_and_submission_blocked():
    proj = build_autopilot_projection(
        campaign_id="camp_1",
        emergency_stopped=False,
        authorization={
            "authorization_digest": "sha256:" + ("a" * 64),
            "scope_snapshot_digest": "sha256:" + ("b" * 64),
            "policy_mode": "authorized_local_lab",
            "budgets": {
                "max_requests": 10,
                "max_duration_seconds": 60,
                "max_cost_units": 10,
            },
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
        leases=[
            {
                "lease_id": "l1",
                "plan_id": "p1",
                "status": "active",
                "requests_reserved": 2,
                "duration_reserved_seconds": 20,
                "cost_units_reserved": 2,
            }
        ],
        requests=[{"status": "completed"}, {"status": "reserved"}],
        observations=[{"observation_id": "o1", "branch_id": "branch_a", "outcome_class": "ok", "summary": "sanitized"}],
        approvals=[{"approval_id": "ap1", "status": "pending", "plan_digest": "sha256:" + ("c" * 64)}],
    )
    assert proj.campaign_id == "camp_1"
    assert proj.next_branch_id == "branch_a"
    assert proj.candidate_promotion_allowed is False
    assert proj.report_submission_allowed is False
    assert proj.submission_blocked is True
    assert proj.budgets.campaign_requests_used == 2
    assert proj.budgets.budget_ledger_valid is True
    assert proj.budgets.campaign_requests_remaining == 8
    assert proj.budgets.campaign_duration_remaining_seconds == 40
    assert proj.budgets.campaign_cost_units_remaining == 8
    assert proj.budgets.active_leases == 1
    summaries = {event.summary for event in proj.events}
    assert "计划 p1 已就绪" in summaries
    assert "租约 l1 生效中" in summaries
    dumped = proj.model_dump(mode="json")
    blob = str(dumped).lower()
    assert "authorization:" not in blob
    assert "cookie" not in blob
    assert "password" not in blob
    assert "bearer" not in blob


def test_projection_exposes_only_verified_candidate_hunter_metadata():
    proj = build_autopilot_projection(
        campaign_id="camp_1",
        candidate_queue={
            "status": "ready",
            "pipeline_run_id": "pipeline_run_1",
            "source_stage_ids": [
                "pipeline_stage_1",
                "pipeline_stage_2",
                "pipeline_stage_3",
                "pipeline_stage_4",
            ],
            "candidates": [
                {
                    "candidate_id": "H-001",
                    "rank": 1,
                    "vuln_type": "authorization",
                    "route": {"method": "GET", "path": "/records/{record_id}"},
                    "source_fact_refs": [
                        "scope:scope_context",
                        "policy:policy_context",
                        "code:routes.py:read_record",
                        "api:GET:/records/{record_id}",
                        "har:har_context",
                    ],
                    "affected_code_path": "code:routes.py:read_record",
                    "evidence_trace_status": "traceable",
                    "human_validation_readiness": "ready",
                    "safety_blockers": [
                        "execute_live_validation",
                        "touch_real_user_data",
                        "submit_report",
                    ],
                    "execution_allowed": False,
                    "dispatch_allowed": False,
                    "validation_allowed": False,
                    "candidate_promotion_allowed": False,
                    "report_submission_allowed": False,
                }
            ],
        },
    )

    candidate = proj.candidate_queue.candidates[0]
    assert proj.candidate_queue.status == "ready"
    assert candidate.affected_endpoint == "GET /records/{record_id}"
    assert candidate.source_fact_refs == (
        "scope_ref_1",
        "policy_ref_2",
        "code_ref_3",
        "api_ref_4",
        "har_ref_5",
    )
    assert candidate.refutation_status == "retained"
    assert candidate.validation_allowed is False
    assert candidate.validation_requires_human_approval is True
    assert candidate.candidate_promotion_allowed is False
    assert candidate.report_submission_allowed is False


def test_projection_normalizes_numeric_route_segments():
    assert _safe_route_path("/api/v1/records/42") == "/api/v1/records/{id}"


def test_projection_fails_closed_for_malformed_candidate_queue():
    proj = build_autopilot_projection(
        campaign_id="camp_1",
        candidate_queue={
            "status": "ready",
            "pipeline_run_id": "pipeline_run_1",
            "source_stage_ids": ["stage_1"],
            "candidates": [
                {
                    "candidate_id": "H-001",
                    "rank": 1,
                    "vuln_type": "authorization",
                    "route": {"method": "GET", "path": "/records/{record_id}"},
                    "source_fact_refs": ["code:routes.py:read_record"],
                    "affected_code_path": "code:routes.py:read_record",
                    "evidence_trace_status": "traceable",
                    "human_validation_readiness": "ready",
                    "safety_blockers": [{"blocked": "submit_report"}],
                    "execution_allowed": False,
                    "dispatch_allowed": False,
                    "validation_allowed": False,
                    "candidate_promotion_allowed": False,
                    "report_submission_allowed": False,
                }
            ],
        },
    )

    assert proj.candidate_queue.status == "invalid"
    assert proj.candidate_queue.candidates == []


@pytest.mark.parametrize(
    ("field", "value", "secret_fragment"),
    (
        (
            "vuln_type",
            "context Authorization: Bearer candidate-secret",
            "candidate-secret",
        ),
        ("vuln_type", "context Cookie: session=cookie-secret", "cookie-secret"),
        ("vuln_type", "中文Authorization: unicode-secret", "unicode-secret"),
        ("vuln_type", "备注Cookie: unicode-cookie-secret", "unicode-cookie-secret"),
        ("vuln_type", "x_authorization: underscore-secret", "underscore-secret"),
        (
            "vuln_type",
            '{"Authorization":"ApiKey json-secret"}',
            "json-secret",
        ),
        (
            "vuln_type",
            '{"Cookie":"json-cookie-secret"}',
            "json-cookie-secret",
        ),
        (
            "vuln_type",
            r'{"\u0041uthorization":"unicode-escaped-json-secret"}',
            "unicode-escaped-json-secret",
        ),
        ("vuln_type", "Authorization： fullwidth-secret", "fullwidth-secret"),
        ("route_path", "/records?access_token=query-secret", "query-secret"),
        (
            "route_path",
            "/records?access_token[]=nested-query-secret",
            "nested-query-secret",
        ),
        (
            "route_path",
            "/records?token[primary]=nested-token-secret",
            "nested-token-secret",
        ),
        (
            "route_path",
            "/records?api_key.value=nested-api-key-secret",
            "nested-api-key-secret",
        ),
        (
            "route_path",
            "/oauth?client_secret=client-secret",
            "client-secret",
        ),
        (
            "route_path",
            "/records?x_api_key[]=nested-x-api-key-secret",
            "nested-x-api-key-secret",
        ),
        (
            "vuln_type",
            "client_secret=plain-client-secret",
            "plain-client-secret",
        ),
        (
            "vuln_type",
            "refresh_token: plain-refresh-token",
            "plain-refresh-token",
        ),
        (
            "vuln_type",
            "private_key: plain-private-key",
            "plain-private-key",
        ),
        (
            "vuln_type",
            "中文Bearer unicode-bearer-secret",
            "unicode-bearer-secret",
        ),
        (
            "vuln_type",
            "中文eyJabcdefgh.abcdefgh.abcdefgh",
            "eyJabcdefgh",
        ),
        (
            "source_fact_ref",
            "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789",
            "ghp_",
        ),
        (
            "source_fact_ref",
            "AKIA" + "ABCDEFGHIJKLMNOP",
            "AKIA",
        ),
        (
            "source_fact_ref",
            "-----BEGIN PRIVATE KEY-----",
            "PRIVATE KEY",
        ),
        (
            "candidate_id",
            "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789",
            "ghp_",
        ),
        (
            "route_path",
            "/records%253Faccess_token%253Ddouble-query-secret",
            "double-query-secret",
        ),
        (
            "route_path",
            "/download/" + "sk_" + "live_" + "abcdefghijklmnopqrstuvwxyz0123456789",
            "sk_" + "live_" + "abcdefghijklmnopqrstuvwxyz0123456789",
        ),
        (
            "route_path",
            "/download/abc123def456ghi789",
            "abc123def456ghi789",
        ),
        (
            "route_path",
            "/download/abcdefghijklmnopqrstuvwxyzabcde",
            "abcdefghijklmnopqrstuvwxyzabcde",
        ),
        (
            "route_path",
            "/download/abC123defGHI456jklMNO789pqrSTU012vwxYZ",
            "abC123defGHI456jklMNO789pqrSTU012vwxYZ",
        ),
        (
            "vuln_type",
            "Bearer%2520double-bearer-secret",
            "double-bearer-secret",
        ),
        (
            "vuln_type",
            "eyJabcdefgh%252Eabcdefgh%252Eabcdefgh",
            "eyJabcdefgh",
        ),
    ),
)
def test_projection_discards_candidate_metadata_with_secrets(
    field: str,
    value: str,
    secret_fragment: str,
):
    candidate = {
        "candidate_id": "H-001",
        "rank": 1,
        "vuln_type": "authorization",
        "route": {"method": "GET", "path": "/records/{record_id}"},
        "source_fact_refs": ["code:routes.py:read_record"],
        "affected_code_path": "code:routes.py:read_record",
        "evidence_trace_status": "traceable",
        "human_validation_readiness": "ready",
        "safety_blockers": [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
        ],
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
    }
    if field == "route_path":
        candidate["route"]["path"] = value
    elif field == "source_fact_ref":
        candidate["source_fact_refs"].append(value)
    else:
        candidate[field] = value

    proj = build_autopilot_projection(
        campaign_id="camp_1",
        candidate_queue={
            "status": "ready",
            "pipeline_run_id": "pipeline_run_1",
            "source_stage_ids": [
                "pipeline_stage_1",
                "pipeline_stage_2",
                "pipeline_stage_3",
                "pipeline_stage_4",
            ],
            "candidates": [candidate],
        },
    )

    assert proj.candidate_queue.status == "invalid"
    assert proj.candidate_queue.candidates == []
    assert secret_fragment not in str(proj.model_dump(mode="json"))


def test_projection_discards_secret_stage_metadata():
    proj = build_autopilot_projection(
        campaign_id="camp_1",
        candidate_queue={
            "status": "ready",
            "pipeline_run_id": "pipeline_run_1",
            "source_stage_ids": ["pipeline_stage_1?token=stage-secret"],
            "candidates": [],
        },
    )

    assert proj.candidate_queue.status == "invalid"
    assert proj.candidate_queue.candidates == []
    assert "stage-secret" not in str(proj.model_dump(mode="json"))


def test_projection_discards_unbounded_or_non_string_candidate_queue_metadata():
    proj = build_autopilot_projection(
        campaign_id="camp_1",
        candidate_queue={
            "status": "invalid",
            "pipeline_run_id": "x" * 129,
        },
    )

    assert proj.candidate_queue.status == "invalid"
    assert proj.candidate_queue.pipeline_run_id is None


def test_projection_keeps_terminal_lease_reservations_charged():
    proj = build_autopilot_projection(
        campaign_id="camp_1",
        authorization={
            "authorization_id": "auth_current",
            "budgets": {"max_requests": 10},
        },
        leases=[
            {
                "lease_id": "lease_expired",
                "authorization_id": "auth_current",
                "status": "expired",
                "requests_reserved": 2,
            },
            {
                "lease_id": "lease_revoked",
                "authorization_id": "auth_current",
                "status": "revoked",
                "requests_reserved": 1,
            },
            {
                "lease_id": "lease_previous_generation",
                "authorization_id": "auth_previous",
                "status": "completed",
                "requests_reserved": 7,
            },
        ],
        requests=[
            {"lease_id": "lease_expired", "status": "expired"},
            {"lease_id": "lease_revoked", "status": "revoked"},
        ],
    )
    assert proj.budgets.campaign_requests_used == 3
    assert proj.budgets.campaign_requests_remaining == 7
    assert proj.budgets.budget_ledger_valid is False


def test_projection_blocks_next_work_when_budget_ledger_is_invalid():
    proj = build_autopilot_projection(
        campaign_id="camp_1",
        branches=[
            {"branch_id": "b1", "asset_id": "a1", "status": "queued", "priority": 100}
        ],
        leases=[
            {
                "lease_id": "legacy",
                "status": "active",
                "requests_reserved": 1,
            }
        ],
    )
    assert proj.budgets.budget_ledger_valid is False
    assert proj.next_branch_id is None
    assert proj.next_reason == "authorization_budget_ledger_invalid"


def test_projection_emergency_stop_blocks_next_work():
    proj = build_autopilot_projection(
        campaign_id="camp_1",
        emergency_stopped=True,
        branches=[{"branch_id": "b1", "asset_id": "a1", "status": "queued", "priority": 1}],
    )
    assert proj.next_branch_id is None
    assert proj.next_reason == "emergency_stopped"
