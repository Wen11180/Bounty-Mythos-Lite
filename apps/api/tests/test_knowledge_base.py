from pathlib import Path

from app.knowledge_base import (
    STATUS_EMPTY,
    STATUS_PACKAGE_MISSING,
    STATUS_READY,
    STATUS_WAITING,
    STATUS_WRITTEN,
    attach_knowledge_base_to_bridge_result,
    build_knowledge_base,
    run_knowledge_base,
)
from app.industrial_scheduler import build_industrial_scheduler_plan
from app.multi_engine_verifier import (
    ENGINE_KNOWLEDGE_BASE,
    build_multi_engine_verdict,
    signal_from_knowledge_base,
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
            "plan": {
                "knowledge_updates": [
                    {
                        "topic": "ssrf",
                        "source_ref": "H-001",
                        "retained_fields": ["vuln_type", "variant_search_pattern"],
                    }
                ],
                "knowledge_consolidation_queue": [
                    {
                        "source_ref": "H-001",
                        "topic": "ssrf",
                        "retained_fields": ["invariant", "refutation_result"],
                        "human_review_required": True,
                    }
                ],
                "variant_analysis": [
                    {
                        "variant_id": "VA-001",
                        "source_hypothesis_id": "H-001",
                        "search_pattern": "similar_ssrf_boundary",
                        "safe_next_step": "local sibling search only",
                    }
                ],
                "patch_diff_learner": {"status": "waiting_for_patch_diff", "learned_patterns": []},
            },
        },
        "deep_research_status": "deep_research_plan_ready",
        "agent_memory": {
            "status": "agent_memory_ready",
            "entries": [
                {
                    "entry_id": "fp-1",
                    "kind": "false_positive_pattern",
                    "topic": "ssrf",
                    "summary": "Prior FP on metadata endpoint",
                    "false_positive_checks": ["middleware may already block private IP"],
                }
            ],
        },
        "agent_memory_status": "agent_memory_ready",
        "long_horizon": {
            "status": "long_horizon_plan_ready",
            "reflections": [
                {
                    "reflection_id": "R-01",
                    "trigger": "refutation_unresolved",
                    "observation": "switch to variant path",
                    "next_path_id": "P-variant-search",
                }
            ],
        },
        "long_horizon_status": "long_horizon_plan_ready",
        "multi_engine_deep": True,
    }
    base.update(extra)
    return base


def test_run_knowledge_base_from_bridge_signals():
    result = run_knowledge_base(bridge_result=_safe_bridge())
    assert result.status == STATUS_READY
    assert result.execution_mode == "advisory_pattern_catalog_only"
    assert result.pattern_count >= 3
    assert result.execution_allowed is False
    assert result.ranking_permission_granted is False
    assert result.auto_learn_live_sources is False
    assert result.report_submission_allowed is False
    assert result.confirmed_vulnerability is False
    ssrf = [p for p in result.patterns if p.category == "ssrf"]
    assert ssrf
    assert ssrf[0].cwe == "CWE-918"
    assert ssrf[0].code_signals
    assert ssrf[0].verification_strategy
    assert ssrf[0].fix_strategy
    assert ssrf[0].false_positive_checks
    payload = result.to_dict()
    assert payload["ranking_permission_granted"] is False
    assert payload["execution_allowed"] is False


def test_build_knowledge_base_alias():
    result = build_knowledge_base(bridge_result=_safe_bridge())
    assert result.status == STATUS_READY
    assert result.pattern_count >= 1


def test_offline_knowledge_inputs(tmp_path: Path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "knowledge.json").write_text(
        (
            '{"patterns":[{"pattern_id":"WEB-IDOR-001","name":"Object ownership check missing",'
            '"category":"authorization","cwe":"CWE-639",'
            '"applies_to":["REST API"],'
            '"code_signals":["route accepts object id","ownership check missing"],'
            '"verification_strategy":["use two authorized test accounts"],'
            '"fix_strategy":["enforce ownership in service layer"],'
            '"false_positive_checks":["object may be intentionally public"]}]}'
        ),
        encoding="utf-8",
    )
    result = run_knowledge_base(
        package_root=tmp_path,
        package_id="demo-pkg",
        bridge_result=_safe_bridge(drafts=[]),
    )
    assert result.status == STATUS_READY
    assert result.offline_artifact_count >= 1
    ids = {p.pattern_id for p in result.patterns}
    assert "WEB-IDOR-001" in ids
    assert result.execution_allowed is False


def test_export_under_package(tmp_path: Path):
    result = run_knowledge_base(
        package_root=tmp_path,
        package_id="demo-pkg",
        bridge_result=_safe_bridge(),
        human_allow_export_write=True,
    )
    assert result.status == STATUS_WRITTEN
    assert result.export_written is True
    assert result.export_count >= 1
    export_root = tmp_path / "_export" / "knowledge_base"
    assert export_root.is_dir()
    stamps = list(export_root.iterdir())
    assert stamps
    assert (stamps[0] / "catalog.json").is_file()
    assert (stamps[0] / "patterns.json").is_file()
    assert (stamps[0] / "summary.json").is_file()


def test_export_requires_human_flag(tmp_path: Path):
    result = run_knowledge_base(
        package_root=tmp_path,
        package_id="demo-pkg",
        bridge_result=_safe_bridge(),
        human_allow_export_write=False,
    )
    assert result.export_written is False
    assert not (tmp_path / "_export" / "knowledge_base").exists()
    assert result.status == STATUS_READY


def test_bridge_attach_forces_safety():
    bridge = _safe_bridge(
        execution_allowed=True,
        report_submission_allowed=True,
        confirmed_vulnerability=True,
        submission_blocked=False,
        validation_allowed=True,
    )
    out = attach_knowledge_base_to_bridge_result(bridge)
    assert out["knowledge_base_present"] is True
    assert out["execution_allowed"] is False
    assert out["validation_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert out["submission_blocked"] is True
    assert out["knowledge_base_ranking_permission_granted"] is False
    assert out["knowledge_base"]["execution_allowed"] is False
    assert out["knowledge_base"]["ranking_permission_granted"] is False
    assert out["knowledge_base_pattern_count"] >= 1


def test_waiting_or_empty_without_signals():
    result = run_knowledge_base(bridge_result={"package_id": "empty-only"})
    # package_id alone still yields scope anchor pattern
    assert result.status in {STATUS_EMPTY, STATUS_WAITING, STATUS_READY, STATUS_PACKAGE_MISSING}
    assert result.execution_allowed is False
    assert result.ranking_permission_granted is False


def test_package_missing(tmp_path: Path):
    missing = tmp_path / "no-such-pkg"
    result = run_knowledge_base(
        package_root=missing,
        package_id="missing",
        bridge_result=_safe_bridge(),
    )
    assert result.status == STATUS_PACKAGE_MISSING
    assert result.execution_allowed is False


def test_mev_signal_and_engine():
    payload = run_knowledge_base(bridge_result=_safe_bridge()).to_dict()
    sig = signal_from_knowledge_base(payload)
    assert sig is not None
    assert sig["status"] == "ready"
    unsafe = signal_from_knowledge_base({**payload, "ranking_permission_granted": True})
    assert unsafe["status"] == "blocked"
    unsafe2 = signal_from_knowledge_base({**payload, "auto_learn_live_sources": True})
    assert unsafe2["status"] == "blocked"
    verdict = build_multi_engine_verdict(
        candidate={"candidate_id": "H-001"},
        knowledge_base_signal=sig,
    )
    engines = {e.engine for e in verdict.engines}
    assert ENGINE_KNOWLEDGE_BASE in engines
    assert verdict.confirmed_vulnerability is False
    assert verdict.execution_allowed is False
    assert verdict.report_submission_allowed is False


def test_scheduler_includes_t015():
    plan = build_industrial_scheduler_plan(
        {
            "scope": {"allowed": True, "reason": "authorized local repository"},
            "hypotheses": [],
            "crs_fuzzing": {"parser_candidates": [{"symbol_name": "decode_frame"}]},
            "authorized_bug_bounty": {"human_gate": {"status": "required"}},
        }
    )
    task_by_id = {task.task_id: task for task in plan.dag_tasks}
    assert "T-015" in task_by_id
    assert task_by_id["T-015"].agent == "knowledge_base_agent"
    assert task_by_id["T-015"].execution_allowed is False
    assert task_by_id["T-015"].requires_human_review is True
    assert "T-014" in task_by_id["T-015"].depends_on
    batches = {b.batch_id: b.task_ids for b in plan.parallel_batches}
    assert batches.get("B-012") == ["T-015"]
    assert plan.knowledge_base.execution_allowed is False
    assert plan.knowledge_base.ranking_permission_granted is False
    assert plan.knowledge_base.mode == "structured_pattern_catalog_only"
