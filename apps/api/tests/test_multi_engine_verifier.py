from app.multi_engine_verifier import (
    ENGINE_CRS_FUZZING,
    ENGINE_RESIDUAL_GATE,
    ENGINE_RESIDUAL_RUNNER,
    ENGINE_AUTHORIZED_WEB_API,
    attach_deeper_multi_engine_to_bridge_result,
    deepen_multi_engine_verdict,
    signal_from_crs_fuzzing,
    signal_from_residual_gate,
    signal_from_residual_runner,
    signal_from_authorized_web_api,
    VERDICT_BLOCKED,
    VERDICT_FALSE_POSITIVE_LIKELY,
    VERDICT_LOCAL_STATIC_CONSISTENT,
    VERDICT_NEEDS_HUMAN_REVIEW,
    VERDICT_NEEDS_VERIFICATION,
    build_multi_engine_verdict,
    verdict_from_hunter_and_map,
)


def test_no_engines_needs_verification():
    verdict = build_multi_engine_verdict(candidate={"candidate_id": "H-001"})
    assert verdict.status == VERDICT_NEEDS_VERIFICATION
    assert verdict.execution_allowed is False
    assert verdict.validation_allowed is False
    assert verdict.report_submission_allowed is False
    assert verdict.confirmed_vulnerability is False
    assert "execute_live_validation" in verdict.safety_blockers


def test_all_engines_support_local_static_consistent():
    verdict = build_multi_engine_verdict(
        candidate={
            "candidate_id": "H-001",
            "root_cause_id": "missing_ssrf_validation:deliver",
            "refutation_questions": ["Is SSRF validation present?"],
        },
        hunter_signal={"status": "ready", "supports_candidate": True, "notes": ["retained"]},
        codebase_map_signal={"status": "ready", "supports_candidate": True, "notes": ["gap"]},
        report_bridge_signal={"status": "ready", "supports_candidate": True, "notes": ["submission_blocked"]},
    )
    assert verdict.status == VERDICT_LOCAL_STATIC_CONSISTENT
    assert verdict.agreement_score == 1.0
    assert verdict.execution_allowed is False
    assert verdict.finding_promotion_allowed is False
    assert verdict.confirmed_vulnerability is False


def test_hunter_oppose_only_false_positive_likely():
    verdict = build_multi_engine_verdict(
        candidate={"candidate_id": "H-002", "root_cause_id": "missing_path_validation:serve"},
        hunter_signal={"status": "ready", "supports_candidate": False, "notes": ["refuted"]},
        codebase_map_signal={"status": "ready", "supports_candidate": False, "notes": ["control"]},
    )
    assert verdict.status == VERDICT_FALSE_POSITIVE_LIKELY
    assert verdict.report_submission_allowed is False


def test_engine_disagreement_needs_human_review():
    verdict = build_multi_engine_verdict(
        candidate={"candidate_id": "H-003"},
        hunter_signal={"status": "ready", "supports_candidate": True},
        codebase_map_signal={"status": "ready", "supports_candidate": False},
    )
    assert verdict.status == VERDICT_NEEDS_HUMAN_REVIEW


def test_scope_block_and_unsafe_candidate_flags():
    verdict = build_multi_engine_verdict(
        candidate={
            "candidate_id": "H-004",
            "execution_allowed": True,
        },
        hunter_signal={"status": "ready", "supports_candidate": True},
        scope_allowed=False,
    )
    assert verdict.status == VERDICT_BLOCKED
    assert "scope_not_allowed" in verdict.blocked_reasons
    assert "candidate_execution_allowed_true" in verdict.blocked_reasons


def test_report_bridge_must_stay_submission_blocked():
    verdict = verdict_from_hunter_and_map(
        candidate={
            "candidate_id": "H-005",
            "root_cause_id": "missing_injection_validation:search",
            "disposition": "retained",
            "source_fact_refs": ["code:code.ts:search"],
        },
        gap_root_causes=["missing_injection_validation:search"],
        report_submission_blocked=False,
    )
    assert verdict.status == VERDICT_BLOCKED
    assert any("report_bridge" in r or "engine_report_bridge" in r for r in verdict.blocked_reasons)


def test_convenience_retain_with_matching_gap():
    verdict = verdict_from_hunter_and_map(
        candidate={
            "candidate_id": "H-006",
            "root_cause_id": "missing_ssrf_validation:deliver_local_lab_webhook",
            "disposition": "retained",
            "source_fact_refs": ["code:code.ts:deliver_local_lab_webhook"],
        },
        gap_root_causes=["missing_ssrf_validation:deliver_local_lab_webhook"],
        report_submission_blocked=True,
    )
    assert verdict.status == VERDICT_LOCAL_STATIC_CONSISTENT
    assert verdict.agreement_score == 1.0
    assert verdict.confirmed_vulnerability is False


def test_convenience_refute_with_control():
    verdict = verdict_from_hunter_and_map(
        candidate={
            "candidate_id": "H-007",
            "root_cause_id": "missing_ssrf_validation:deliver",
            "disposition": "refuted",
            "evidence_refs": ["code:code.ts:validateUrlForSSRF"],
        },
        control_refs=["code:code.ts:validateUrlForSSRF"],
        report_submission_blocked=True,
    )
    assert verdict.status == VERDICT_FALSE_POSITIVE_LIKELY


def test_crs_signal_path_overlap_supports():
    signal = signal_from_crs_fuzzing(
        {
            "status": "crs_fuzzing_plan_ready",
            "candidate_count": 1,
            "execution_allowed": False,
            "parser_candidates": [
                {"symbol_name": "parse_message", "source_path": "src/parser.py"}
            ],
        },
        candidate={"affected_code_path": "code:src/parser.py:parse_message"},
    )
    assert signal is not None
    assert signal["supports_candidate"] is True
    assert signal["status"] == "ready"


def test_crs_unsafe_flags_block():
    signal = signal_from_crs_fuzzing(
        {"status": "ready", "execution_allowed": True, "candidate_count": 1}
    )
    assert signal["status"] == "blocked"
    assert signal["supports_candidate"] is False


def test_residual_gate_ready_supports_not_confirmed():
    signal = signal_from_residual_gate(
        [{"candidate_id": "H-1", "status": "ready_for_human_review"}],
        candidate={"candidate_id": "H-1"},
    )
    assert signal["supports_candidate"] is True
    assert "not_confirmed" in " ".join(signal["notes"])


def test_residual_gate_rejected_opposes():
    signal = signal_from_residual_gate(
        [{"candidate_id": "H-2", "status": "human_rejected_or_fp"}],
        candidate={"candidate_id": "H-2"},
    )
    assert signal["supports_candidate"] is False


def test_residual_runner_pending_without_approval():
    signal = signal_from_residual_runner(
        {"status": "skipped_no_human_approval", "execution_allowed": False}
    )
    assert signal["status"] == "pending"
    assert signal["supports_candidate"] is None


def test_web_api_route_overlap():
    signal = signal_from_authorized_web_api(
        {
            "status": "authorized_web_api_plan_ready",
            "operation_count": 1,
            "role_diff_count": 1,
            "api_operations": [{"method": "POST", "path": "/local/lab/webhooks/deliver"}],
            "role_diff_plans": [{"method": "POST", "path": "/local/lab/webhooks/deliver"}],
            "execution_allowed": False,
            "report_submission_allowed": False,
        },
        candidate={"route": {"method": "POST", "path": "/local/lab/webhooks/deliver"}},
    )
    assert signal["supports_candidate"] is True


def test_build_includes_deeper_engines():
    verdict = build_multi_engine_verdict(
        candidate={"candidate_id": "H-D1", "root_cause_id": "missing_ssrf_validation:deliver"},
        hunter_signal={"status": "ready", "supports_candidate": True},
        codebase_map_signal={"status": "ready", "supports_candidate": True},
        report_bridge_signal={"status": "ready", "supports_candidate": True},
        crs_fuzzing_signal={"status": "ready", "supports_candidate": True},
        residual_gate_signal={"status": "ready", "supports_candidate": True},
        residual_runner_signal={"status": "pending", "supports_candidate": None},
        authorized_web_api_signal={"status": "ready", "supports_candidate": True},
    )
    engines = {e.engine for e in verdict.engines}
    assert ENGINE_CRS_FUZZING in engines
    assert ENGINE_RESIDUAL_GATE in engines
    assert ENGINE_RESIDUAL_RUNNER in engines
    assert ENGINE_AUTHORIZED_WEB_API in engines
    assert verdict.execution_allowed is False
    assert verdict.confirmed_vulnerability is False
    assert verdict.report_submission_allowed is False
    # partial unknown residual keeps human review or local consistent depending on agreement
    assert verdict.status in {
        VERDICT_LOCAL_STATIC_CONSISTENT,
        VERDICT_NEEDS_HUMAN_REVIEW,
    }


def test_deepen_and_attach_bridge_safety_floor():
    base = build_multi_engine_verdict(
        candidate={
            "candidate_id": "H-D2",
            "root_cause_id": "missing_ssrf_validation:deliver",
            "affected_code_path": "code:src/parser.py:parse_message",
            "route": {"method": "POST", "path": "/hooks/deliver"},
        },
        hunter_signal={"status": "ready", "supports_candidate": True, "notes": ["retained"]},
        codebase_map_signal={"status": "ready", "supports_candidate": True, "notes": ["gap"]},
        report_bridge_signal={"status": "ready", "supports_candidate": True, "notes": ["submission_blocked"]},
    ).model_dump()

    deep = deepen_multi_engine_verdict(
        base,
        candidate={
            "candidate_id": "H-D2",
            "root_cause_id": "missing_ssrf_validation:deliver",
            "affected_code_path": "code:src/parser.py:parse_message",
            "route": {"method": "POST", "path": "/hooks/deliver"},
        },
        crs_fuzzing={
            "status": "crs_fuzzing_plan_ready",
            "candidate_count": 1,
            "execution_allowed": False,
            "parser_candidates": [
                {"symbol_name": "parse_message", "source_path": "src/parser.py"}
            ],
        },
        residual_runner={"status": "skipped_no_human_approval", "execution_allowed": False},
        authorized_web_api={
            "status": "authorized_web_api_plan_ready",
            "operation_count": 1,
            "role_diff_count": 1,
            "api_operations": [{"method": "POST", "path": "/hooks/deliver"}],
            "execution_allowed": False,
            "report_submission_allowed": False,
        },
        residual_gates=[{"candidate_id": "H-D2", "status": "ready_for_human_review"}],
        semgrep_runner={"status": "skipped_no_human_local_flag", "finding_count": 0},
        codeql_runner={"status": "skipped_no_human_local_flag", "finding_count": 0},
    )
    engines = {e.engine for e in deep.engines}
    assert ENGINE_CRS_FUZZING in engines
    assert ENGINE_AUTHORIZED_WEB_API in engines
    assert ENGINE_RESIDUAL_GATE in engines
    assert deep.execution_allowed is False
    assert deep.confirmed_vulnerability is False
    assert deep.report_submission_allowed is False

    bridge = {
        "package_id": "pkg-deep",
        "submission_blocked": True,
        "execution_allowed": True,  # must be forced false
        "report_submission_allowed": True,
        "drafts": [
            {
                "candidate_id": "H-D2",
                "root_cause_id": "missing_ssrf_validation:deliver",
                "route": {"method": "POST", "path": "/hooks/deliver"},
                "affected_code_path": "code:src/parser.py:parse_message",
                "multi_engine_verdict": base,
            }
        ],
        "multi_engine_verdicts": [base],
        "crs_fuzzing": {
            "status": "crs_fuzzing_plan_ready",
            "candidate_count": 1,
            "execution_allowed": False,
            "parser_candidates": [
                {"symbol_name": "parse_message", "source_path": "src/parser.py"}
            ],
        },
        "residual_runner": {"status": "skipped_no_human_approval"},
        "authorized_web_api": {
            "status": "authorized_web_api_plan_ready",
            "operation_count": 1,
            "api_operations": [{"method": "POST", "path": "/hooks/deliver"}],
            "execution_allowed": False,
            "report_submission_allowed": False,
        },
        "human_residual_gates": [
            {"candidate_id": "H-D2", "status": "ready_for_human_review"}
        ],
        "semgrep_runner": {"status": "skipped_no_human_local_flag"},
        "codeql_runner": {"status": "skipped_no_human_local_flag"},
    }
    out = attach_deeper_multi_engine_to_bridge_result(bridge)
    assert out["multi_engine_deep"] is True
    assert out["multi_engine_engine_count"] >= 5
    assert out["execution_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert out["submission_blocked"] is True
    assert out["multi_engine_verdicts"][0]["deep_stack_attached"] is True
    assert out["multi_engine_verdicts"][0]["confirmed_vulnerability"] is False
    assert out["drafts"][0]["multi_engine_verdict"]["deep_stack_attached"] is True
    assert ENGINE_CRS_FUZZING in set(out["multi_engine_engines"])


def test_scheduler_includes_t006b_verifier():
    from app.industrial_scheduler import build_industrial_scheduler_plan

    plan = build_industrial_scheduler_plan(
        {
            "crs_fuzzing": {"status": "ready"},
            "authorized_bug_bounty": {"role_diff_plans": [{"endpoint": "/x"}]},
        }
    )
    ids = {t.task_id for t in plan.dag_tasks}
    assert "T-006b" in ids
    t = next(x for x in plan.dag_tasks if x.task_id == "T-006b")
    assert t.agent == "verifier_agent"
    assert t.requires_human_review is True
    assert t.execution_allowed is False
    assert "T-006b" in next(x for x in plan.dag_tasks if x.task_id == "T-007").depends_on
    assert any(b.batch_id == "B-003b" for b in plan.parallel_batches)
