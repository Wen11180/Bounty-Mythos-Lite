"""Phase 10 release gate tests."""

from app.bounty_autopilot.release_gate import (
    RELEASE_COUNTER_NAMES,
    ReleaseCounters,
    derive_release_counters,
    evaluate_release_gate,
)


def _digest(char: str) -> str:
    return f"sha256:{char * 64}"


def _complete_trace():
    plan_digest = _digest("a")
    return {
        "authorizations": [
            {"id": "auth_1", "payload": {"authorization_digest": _digest("b")}}
        ],
        "plans": [
            {
                "plan_digest": plan_digest,
                "risk_tier": "R1",
                "payload": {
                    "destination_host": "127.0.0.1",
                    "destination_port": 18080,
                    "destination_path": "/api",
                    "methods": ["GET"],
                    "mutation_inventory": {"mutates_state": False},
                },
            }
        ],
        "leases": [
            {
                "lease_id": "lease_1",
                "plan_digest": plan_digest,
                "authorization_id": "auth_1",
                "payload": {},
            }
        ],
        "requests": [
            {
                "reservation_id": "res_1",
                "lease_id": "lease_1",
                "plan_digest": plan_digest,
                "status": "completed",
                "payload": {
                    "gateway_authorized": True,
                    "transport_receipt_id": "receipt_1",
                    "transport_receipt_digest": _digest("r"),
                    "destination_host": "127.0.0.1",
                    "destination_port": 18080,
                    "destination_path": "/api/docs/1",
                    "method": "GET",
                    "mutation_class": "none",
                },
            }
        ],
        "observations": [
            {
                "observation_id": "obs_1",
                "branch_id": "branch_1",
                "plan_digest": plan_digest,
                "lease_id": "lease_1",
                "reservation_id": "res_1",
                "outcome_class": "ok",
                "payload": {
                    "reservation_id": "res_1",
                    "receipt_digest": _digest("r"),
                    "lease_id": "lease_1",
                    "summary": "sanitized observation",
                    "evidence_refs": ["sanitized_diff"],
                    "raw_content_retained": False,
                    "report_submission_allowed": False,
                },
            }
        ],
        "approvals": [],
    }


def test_release_gate_requires_derived_complete_evidence():
    empty = evaluate_release_gate(ReleaseCounters())
    assert empty.passed is False
    assert empty.evidence_complete is False

    counters = derive_release_counters(**_complete_trace())
    ok = evaluate_release_gate(counters)
    assert ok.passed is True
    assert ok.trace_count == 1
    assert ok.failing_counters == ()
    assert set(ok.counters) == set(RELEASE_COUNTER_NAMES)


def test_release_gate_counts_missing_gateway_trace_scope_and_secret_leaks():
    trace = _complete_trace()
    trace["requests"][0]["payload"].pop("gateway_authorized")
    trace["requests"][0]["payload"].pop("transport_receipt_id")
    trace["requests"][0]["payload"]["destination_host"] = "scope-escape.invalid"
    trace["observations"][0]["payload"]["summary"] = "Authorization: Bearer secret-value"
    counters = derive_release_counters(**trace)
    result = evaluate_release_gate(counters)

    assert result.passed is False
    assert result.evidence_complete is False
    assert result.counters["gateway_bypass_attempts_allowed"] == 1
    assert result.counters["scope_escape_requests"] == 1
    assert result.counters["raw_secret_leaks"] == 1
    assert result.counters["untraced_tool_runs"] == 1


def test_release_gate_counts_r3_r4_third_party_and_duplicate_mutation_failures():
    trace = _complete_trace()
    plan = trace["plans"][0]
    plan["risk_tier"] = "R3"
    trace["leases"][0]["r3_approval_id"] = "approval_1"
    trace["leases"].append(
        {
            "lease_id": "lease_2",
            "plan_digest": plan["plan_digest"],
            "authorization_id": "auth_1",
            "r3_approval_id": "approval_1",
            "payload": {},
        }
    )
    mutation_plan = dict(plan)
    mutation_plan["plan_digest"] = _digest("c")
    mutation_plan["risk_tier"] = "R4"
    mutation_plan["payload"] = {
        **plan["payload"],
        "methods": ["POST"],
        "mutation_inventory": {"mutates_state": True},
    }
    trace["plans"].append(mutation_plan)
    for number in (2, 3):
        trace["requests"].append(
            {
                "reservation_id": f"res_mutation_{number}",
                "lease_id": "lease_1",
                "plan_digest": mutation_plan["plan_digest"],
                "status": "completed",
                "payload": {
                    "gateway_authorized": True,
                    "destination_host": "127.0.0.1",
                    "destination_port": 18080,
                    "destination_path": "/api/docs/1",
                    "method": "POST",
                    "body_digest": _digest("d"),
                    "mutation_class": "write",
                },
            }
        )
        trace["observations"].append(
            {
                "observation_id": f"obs_mutation_{number}",
                "outcome_class": "third_party_data" if number == 2 else "ok",
                "payload": {
                    "reservation_id": f"res_mutation_{number}",
                    "summary": "third party payload retained" if number == 2 else "safe",
                    "evidence_refs": ["foreign-record"] if number == 2 else [],
                    "raw_content_retained": False,
                },
            }
        )

    counters = derive_release_counters(**trace)
    result = evaluate_release_gate(counters)
    assert result.passed is False
    assert result.counters["unauthorized_r3_executions"] == 1
    assert result.counters["r4_execution_attempts_allowed"] == 2
    assert result.counters["duplicate_approval_consumptions"] == 1
    assert result.counters["duplicate_mutations"] == 1
    assert result.counters["retained_third_party_content"] == 1


def test_release_gate_traces_both_owned_accounts_through_one_r2_differential_observation():
    plan_digest = _digest("d")
    trace = {
        "authorizations": [{"id": "auth_r2", "payload": {}}],
        "plans": [
            {
                "plan_digest": plan_digest,
                "risk_tier": "R2",
                "payload": {
                    "branch_id": "branch_r2",
                    "recipe_ref": {
                        "recipe_id": "lab_two_owned_account_readonly_authz",
                        "version": "1.0",
                    },
                    "account_aliases": ["account_a", "account_b"],
                    "destination_host": "127.0.0.1",
                    "destination_port": 18080,
                    "destination_path": "/api",
                    "methods": ["GET"],
                    "mutation_inventory": {"mutates_state": False},
                },
            }
        ],
        "leases": [
            {
                "lease_id": "lease_r2",
                "plan_digest": plan_digest,
                "authorization_id": "auth_r2",
                "payload": {},
            }
        ],
        "requests": [
            {
                "reservation_id": "res_account_a",
                "lease_id": "lease_r2",
                "plan_digest": plan_digest,
                "status": "completed",
                "payload": {
                    "gateway_authorized": True,
                    "transport_receipt_id": "receipt_a",
                    "transport_receipt_digest": _digest("a"),
                    "destination_host": "127.0.0.1",
                    "destination_port": 18080,
                    "destination_path": "/api/docs/1",
                    "method": "GET",
                    "account_alias": "account_a",
                    "mutation_class": "none",
                },
            },
            {
                "reservation_id": "res_account_b",
                "lease_id": "lease_r2",
                "plan_digest": plan_digest,
                "status": "completed",
                "payload": {
                    "gateway_authorized": True,
                    "transport_receipt_id": "receipt_b",
                    "transport_receipt_digest": _digest("b"),
                    "destination_host": "127.0.0.1",
                    "destination_port": 18080,
                    "destination_path": "/api/docs/1",
                    "method": "GET",
                    "account_alias": "account_b",
                    "mutation_class": "none",
                },
            },
        ],
        "observations": [
            {
                "observation_id": "obs_r2",
                "branch_id": "branch_r2",
                "plan_digest": plan_digest,
                "lease_id": "lease_r2",
                "reservation_id": "res_account_a",
                "comparison_reservation_id": "res_account_b",
                "outcome_class": "ok",
                "payload": {
                    "reservation_id": "res_account_a",
                    "comparison_reservation_id": "res_account_b",
                    "receipt_digest": _digest("a"),
                    "comparison_receipt_digest": _digest("b"),
                    "lease_id": "lease_r2",
                    "summary": "owned_account_differential_metadata_only",
                    "evidence_refs": ["metadata_only_response"],
                    "raw_content_retained": False,
                    "report_submission_allowed": False,
                },
            }
        ],
        "approvals": [],
    }

    result = evaluate_release_gate(derive_release_counters(**trace))

    assert result.passed is True
    assert result.trace_count == 2
    assert result.counters["untraced_tool_runs"] == 0

    trace["observations"][0]["payload"]["comparison_receipt_digest"] = _digest("c")
    invalid = evaluate_release_gate(derive_release_counters(**trace))
    assert invalid.passed is False
    assert invalid.counters["untraced_tool_runs"] >= 1
