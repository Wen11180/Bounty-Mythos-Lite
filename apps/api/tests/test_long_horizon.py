from pathlib import Path

from app.long_horizon import (
    STATUS_EMPTY,
    STATUS_PACKAGE_MISSING,
    STATUS_READY,
    STATUS_WAITING,
    STATUS_WRITTEN,
    attach_long_horizon_to_bridge_result,
    build_long_horizon,
    run_long_horizon,
)
from app.industrial_scheduler import build_industrial_scheduler_plan
from app.multi_engine_verifier import (
    ENGINE_LONG_HORIZON,
    build_multi_engine_verdict,
    signal_from_long_horizon,
)


def _safe_bridge(**extra):
    base = {
        "package_id": "demo-pkg",
        "submission_blocked": True,
        "report_submission_allowed": False,
        "execution_allowed": False,
        "validation_allowed": False,
        "confirmed_vulnerability": False,
        "drafts": [
            {
                "candidate_id": "H-001",
                "root_cause_id": "RC-ssrf",
                "vuln_type": "ssrf",
                "submission_blocked": True,
                "confirmed_vulnerability": False,
                "summary": "SSRF candidate for local retain lab",
            }
        ],
        "human_residual_gates": [
            {
                "candidate_id": "H-001",
                "status": "ready_for_human_review",
                "vuln_type": "ssrf",
                "report_submission_allowed": False,
                "execution_allowed": False,
                "confirmed_vulnerability": False,
            }
        ],
        "deep_research": {
            "status": "deep_research_plan_ready",
            "chain_count": 1,
            "variant_count": 1,
            "unresolved_refutation_count": 1,
            "execution_allowed": False,
            "vulnerability_chains": [
                {
                    "chain_id": "C-001",
                    "stages": ["entrypoint", "authorization_boundary", "impact_review"],
                    "execution_allowed": False,
                }
            ],
            "long_horizon_plan": {
                "iteration_strategy": "refute_then_branch",
                "fallback_paths": ["try_variant_analysis", "protocol_fuzz_plan"],
                "reflections": ["refutation unresolved; switch path"],
            },
        },
        "deep_research_status": "deep_research_plan_ready",
        "deep_research_chain_count": 1,
        "deep_research_variant_count": 1,
        "deep_research_unresolved_refutation_count": 1,
        "agent_memory": {
            "status": "agent_memory_ready",
            "false_positive_pattern_count": 1,
            "candidate_hint_count": 1,
        },
        "crs_fuzzing": {
            "parser_candidates": [
                {"symbol_name": "decode_webhook", "source_path": "app/codec.py"}
            ]
        },
        "multi_engine_deep": True,
    }
    base.update(extra)
    return base


def test_run_long_horizon_from_deep_research_signals():
    result = run_long_horizon(bridge_result=_safe_bridge())
    assert result.status == STATUS_READY
    assert result.execution_mode == "plan_only"
    assert result.path_count >= 1
    assert result.switch_count >= 1
    assert result.iteration_count >= 1
    assert result.execution_allowed is False
    assert result.auto_path_switch_allowed is False
    assert result.report_submission_allowed is False
    assert result.validation_allowed is False
    assert result.confirmed_vulnerability is False
    assert result.ranking_permission_granted is False
    assert result.finding_promotion_allowed is False
    assert result.network_access is False
    assert result.live_validation is False
    payload = result.to_dict()
    assert payload["execution_allowed"] is False
    assert payload["auto_path_switch_allowed"] is False


def test_build_long_horizon_alias():
    result = build_long_horizon(bridge_result=_safe_bridge())
    assert result.status == STATUS_READY
    assert result.path_count >= 1


def test_offline_long_horizon_inputs(tmp_path: Path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "long_horizon.json").write_text(
        (
            '{"paths":[{"path_id":"P-off","name":"offline_path","purpose":"offline seed"}],'
            '"switches":[{"switch_id":"S-off","from_path_id":"P-off","to_path_id":"P-alt",'
            '"trigger":"refutation_failed","reason":"try alternate"}],'
            '"iterations":[{"iteration_id":"I-1","sequence":1,"active_path_id":"P-off",'
            '"goal":"seed","reflection_prompt":"reflect"}],'
            '"reflections":[{"reflection_id":"R-1","trigger":"fail","observation":"blocked",'
            '"next_path_id":"P-alt"}]}'
        ),
        encoding="utf-8",
    )
    result = run_long_horizon(
        package_root=tmp_path,
        package_id="demo-pkg",
        bridge_result=_safe_bridge(drafts=[]),
    )
    assert result.status == STATUS_READY
    assert result.offline_artifact_count >= 1
    assert result.path_count >= 1
    assert result.execution_allowed is False
    assert result.auto_path_switch_allowed is False


def test_export_under_package(tmp_path: Path):
    result = run_long_horizon(
        package_root=tmp_path,
        package_id="demo-pkg",
        bridge_result=_safe_bridge(),
        human_allow_export_write=True,
    )
    assert result.status == STATUS_WRITTEN
    assert result.export_written is True
    assert result.export_count >= 1
    export_root = tmp_path / "_export" / "long_horizon"
    assert export_root.is_dir()
    stamps = list(export_root.iterdir())
    assert stamps
    assert (stamps[0] / "plan.json").is_file()
    assert (stamps[0] / "summary.json").is_file()


def test_export_requires_human_flag(tmp_path: Path):
    result = run_long_horizon(
        package_root=tmp_path,
        package_id="demo-pkg",
        bridge_result=_safe_bridge(),
        human_allow_export_write=False,
    )
    assert result.export_written is False
    assert not (tmp_path / "_export" / "long_horizon").exists()
    assert result.status == STATUS_READY


def test_bridge_attach_forces_safety():
    bridge = _safe_bridge(
        execution_allowed=True,
        report_submission_allowed=True,
        confirmed_vulnerability=True,
        submission_blocked=False,
        validation_allowed=True,
    )
    out = attach_long_horizon_to_bridge_result(bridge)
    assert out["long_horizon_present"] is True
    assert out["execution_allowed"] is False
    assert out["validation_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert out["submission_blocked"] is True
    assert out["long_horizon_auto_path_switch_allowed"] is False
    assert out["long_horizon"]["execution_allowed"] is False
    assert out["long_horizon"]["auto_path_switch_allowed"] is False
    assert out["long_horizon"]["ranking_permission_granted"] is False
    assert out["long_horizon_path_count"] >= 1
    assert out["long_horizon_switch_count"] >= 1


def test_waiting_or_empty_without_signals():
    result = run_long_horizon(bridge_result={"package_id": "empty"})
    assert result.status in {STATUS_EMPTY, STATUS_WAITING, STATUS_READY, STATUS_PACKAGE_MISSING}
    assert result.execution_allowed is False
    assert result.auto_path_switch_allowed is False


def test_package_missing(tmp_path: Path):
    missing = tmp_path / "no-such-pkg"
    result = run_long_horizon(
        package_root=missing,
        package_id="missing",
        bridge_result=_safe_bridge(),
    )
    assert result.status == STATUS_PACKAGE_MISSING
    assert result.execution_allowed is False


def test_mev_signal_and_engine():
    payload = run_long_horizon(bridge_result=_safe_bridge()).to_dict()
    sig = signal_from_long_horizon(payload)
    assert sig is not None
    assert sig["status"] == "ready"
    unsafe = signal_from_long_horizon({**payload, "auto_path_switch_allowed": True})
    assert unsafe["status"] == "blocked"
    unsafe2 = signal_from_long_horizon({**payload, "execution_allowed": True})
    assert unsafe2["status"] == "blocked"
    verdict = build_multi_engine_verdict(
        candidate={"candidate_id": "H-001"},
        long_horizon_signal=sig,
    )
    engines = {e.engine for e in verdict.engines}
    assert ENGINE_LONG_HORIZON in engines
    assert verdict.confirmed_vulnerability is False
    assert verdict.execution_allowed is False
    assert verdict.report_submission_allowed is False


def test_scheduler_includes_t014():
    plan = build_industrial_scheduler_plan(
        {
            "scope": {"allowed": True, "reason": "authorized local repository"},
            "hypotheses": [],
            "crs_fuzzing": {"parser_candidates": [{"symbol_name": "decode_frame"}]},
            "authorized_bug_bounty": {"human_gate": {"status": "required"}},
        }
    )
    task_by_id = {task.task_id: task for task in plan.dag_tasks}
    assert "T-014" in task_by_id
    assert task_by_id["T-014"].agent == "long_horizon_agent"
    assert task_by_id["T-014"].execution_allowed is False
    assert task_by_id["T-014"].requires_human_review is True
    assert "T-013" in task_by_id["T-014"].depends_on
    batches = {b.batch_id: b.task_ids for b in plan.parallel_batches}
    assert batches.get("B-011") == ["T-014"]
    assert plan.long_horizon.execution_allowed is False
    assert plan.long_horizon.auto_path_switch_allowed is False
    assert plan.long_horizon.mode == "path_switch_plan_only"
