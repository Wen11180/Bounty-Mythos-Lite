from pathlib import Path

from app.crash_regression import (
    STATUS_NO_CLUSTERS,
    STATUS_READY,
    STATUS_WRITTEN,
    attach_crash_regression_to_bridge_result,
    build_crash_regression_plan,
    run_crash_regression_plan,
)
from app.industrial_scheduler import build_industrial_scheduler_plan
from app.multi_engine_verifier import (
    ENGINE_CRASH_REGRESSION,
    build_multi_engine_verdict,
    signal_from_crash_regression,
)


def _triage_with_clusters() -> dict:
    return {
        "status": "crash_triage_completed",
        "package_id": "demo",
        "input_crash_count": 2,
        "unique_cluster_count": 1,
        "triaged": [
            {
                "crash_id": "crash-a",
                "cluster_id": "cluster-sig1",
                "target_symbol": "parse_message",
                "source_path": "src/parser.py",
                "exception_type": "ValueError",
                "exception_message": "boom-marker",
                "crash_type": "input_validation_exception",
                "signature": "sig1",
                "seed_sha256": "abc",
                "seed_preview": "PREFIX_BOOM_SUFFIX",
                "minimized": True,
                "minimized_seed_len": 4,
                "minimized_seed_sha256": "def",
                "minimized_seed_preview": "BOOM",
                "reproducible": True,
                "promotion_allowed": False,
                "confirmed_vulnerability": False,
                "root_cause": {
                    "status": "advisory",
                    "summary": "Unvalidated marker path in parse_message",
                    "exception_family": "ValueError",
                    "likely_surface": "parser",
                    "needs_human_review": True,
                    "confirmed_vulnerability": False,
                },
            },
            {
                "crash_id": "crash-b",
                "cluster_id": "cluster-sig1",
                "target_symbol": "parse_message",
                "source_path": "src/parser.py",
                "exception_type": "ValueError",
                "exception_message": "boom-marker",
                "crash_type": "input_validation_exception",
                "signature": "sig1",
                "minimized": True,
                "reproducible": True,
            },
        ],
    }


def test_empty_without_triage():
    plan = build_crash_regression_plan()
    assert plan.status in {STATUS_NO_CLUSTERS, "crash_regression_empty"}
    assert plan.execution_mode == "plan_only"
    assert plan.execution_allowed is False
    assert plan.validation_allowed is False
    assert plan.test_auto_execute_allowed is False
    assert plan.crash_promotion_allowed is False
    assert plan.report_submission_allowed is False
    assert plan.confirmed_vulnerability is False


def test_plan_from_triaged_clusters():
    triage = _triage_with_clusters()
    result = run_crash_regression_plan(package_id="demo", crash_triage=triage)
    assert result.status == STATUS_READY
    assert result.suggestion_count == 1  # one per cluster
    assert result.reproducible_linked_count == 1
    assert result.minimized_linked_count == 1
    s = result.suggestions[0]
    assert s.target_symbol == "parse_message"
    assert s.reproducible is True
    assert s.minimized is True
    assert s.auto_execute is False
    assert s.promotion_allowed is False
    assert s.confirmed_vulnerability is False
    assert len(s.steps) >= 3
    assert all(st.auto_execute is False for st in s.steps)
    assert result.execution_allowed is False
    assert result.test_auto_execute_allowed is False


def test_export_under_package(tmp_path: Path):
    triage = _triage_with_clusters()
    result = run_crash_regression_plan(
        package_root=tmp_path,
        package_id="demo",
        crash_triage=triage,
        human_allow_export_write=True,
    )
    assert result.status == STATUS_WRITTEN
    assert result.export_written is True
    assert result.export_count == 1
    assert result.execution_allowed is False
    assert result.test_auto_execute_allowed is False
    export_root = tmp_path / "_export" / "crash_regression"
    assert export_root.is_dir()
    stamps = list(export_root.iterdir())
    assert stamps
    assert (stamps[0] / "index.json").is_file()
    assert (stamps[0] / "README.md").is_file()


def test_bridge_attach_forces_safety():
    triage = _triage_with_clusters()
    bridge = {
        "package_id": "demo",
        "package_root": ".",
        "submission_blocked": True,
        "crash_triage": triage,
        "execution_allowed": True,  # should be forced false
        "report_submission_allowed": True,
        "confirmed_vulnerability": True,
    }
    out = attach_crash_regression_to_bridge_result(bridge)
    assert out["crash_regression_present"] is True
    assert out["crash_regression_suggestion_count"] == 1
    assert out["execution_allowed"] is False
    assert out["validation_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert out["submission_blocked"] is True
    assert out["crash_regression"]["test_auto_execute_allowed"] is False
    assert out["crash_regression"]["crash_promotion_allowed"] is False


def test_mev_signal_and_engine():
    plan = run_crash_regression_plan(
        package_id="demo", crash_triage=_triage_with_clusters()
    ).to_dict()
    sig = signal_from_crash_regression(plan)
    assert sig is not None
    assert sig["status"] == "ready"
    unsafe = signal_from_crash_regression(
        {**plan, "test_auto_execute_allowed": True}
    )
    assert unsafe["status"] == "blocked"
    verdict = build_multi_engine_verdict(
        candidate={"candidate_id": "c1"},
        crash_regression_signal=sig,
    )
    engines = {e.engine for e in verdict.engines}
    assert ENGINE_CRASH_REGRESSION in engines
    assert verdict.execution_allowed is False
    assert verdict.confirmed_vulnerability is False


def test_scheduler_includes_t003f():
    plan = build_industrial_scheduler_plan(
        {
            "scope": {"allowed": True},
            "hypotheses": [],
            "crash_triage": {"triaged_count": 1},
            "crash_regression": {"suggestion_count": 1},
        }
    )
    task_by_id = {t.task_id: t for t in plan.dag_tasks}
    assert "T-003f" in task_by_id
    assert task_by_id["T-003f"].agent == "crash_regression_agent"
    assert task_by_id["T-003f"].depends_on == [
        "T-003",
        "T-003b",
        "T-003c",
        "T-003d",
        "T-003e",
    ]
    assert task_by_id["T-003f"].execution_allowed is False
    assert task_by_id["T-003f"].requires_human_review is True
    batches = {b.batch_id: b.task_ids for b in plan.parallel_batches}
    assert batches.get("B-002h") == ["T-003f"]
    assert "T-003f" in task_by_id["T-006b"].depends_on


def test_codepath_enrichment():
    triage = _triage_with_clusters()
    codepath = {
        "status": "crash_codepath_plan_ready",
        "package_code_execution_allowed": False,
        "crash_promotion_allowed": False,
        "confirmed_vulnerability": False,
        "links": [
            {
                "link_id": "L1",
                "cluster_id": "cluster-sig1",
                "crash_id": "crash-a",
                "primary_code_path": "src/parser.py:parse_message:10-40",
                "confidence": "high",
                "raise_sites": ["src/parser.py:22:raise ValueError"],
                "call_sites": ["src/handler.py:9:parse_message"],
                "related_symbols": ["validate_message"],
                "root_cause_summary": "Static advisory: unvalidated marker near parse_message",
                "promotion_allowed": False,
                "confirmed_vulnerability": False,
            }
        ],
    }
    result = run_crash_regression_plan(
        package_id="demo",
        crash_triage=triage,
        crash_codepath=codepath,
    )
    assert result.status == STATUS_READY
    assert result.codepath_linked_count == 1
    assert result.test_auto_execute_allowed is False
    assert result.crash_promotion_allowed is False
    s = result.suggestions[0]
    assert s.codepath_linked is True
    assert "src/parser.py" in s.codepath_primary
    assert s.priority == "high"
    assert any(st.step_id.endswith("03b") for st in s.steps)
    assert "enriched_from_advisory_crash_codepath" in s.notes
    assert result.confirmed_vulnerability is False


def test_bridge_attach_consumes_existing_codepath():
    triage = _triage_with_clusters()
    bridge = {
        "package_id": "demo",
        "package_root": ".",
        "submission_blocked": True,
        "crash_triage": triage,
        "crash_codepath": {
            "status": "ready",
            "links": [
                {
                    "cluster_id": "cluster-sig1",
                    "crash_id": "crash-a",
                    "primary_code_path": "src/parser.py:parse_message",
                    "confidence": "medium",
                    "raise_sites": ["src/parser.py:22"],
                    "call_sites": [],
                    "related_symbols": [],
                    "promotion_allowed": False,
                    "confirmed_vulnerability": False,
                }
            ],
        },
    }
    out = attach_crash_regression_to_bridge_result(bridge)
    assert out["crash_regression_codepath_linked_count"] == 1
    assert out["execution_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert out["crash_regression"]["test_auto_execute_allowed"] is False
