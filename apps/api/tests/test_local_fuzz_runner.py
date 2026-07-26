import ast
from pathlib import Path

from app.local_fuzz_runner import (
    STATUS_PLANNED,
    STATUS_SKIPPED_NO_FLAG,
    attach_local_fuzz_runner_to_bridge_result,
    build_local_fuzz_runner_plan,
    run_local_fuzz_runner,
)
from app.industrial_scheduler import build_industrial_scheduler_plan


ROOT = Path(__file__).resolve().parents[3]
PKG_SSRF = ROOT / "authorized_packages" / "my-local-ssrf-retain"


def test_default_off_is_plan_only():
    crs = {
        "status": "crs_fuzzing_plan_ready",
        "package_id": "demo",
        "harness_plans": [
            {
                "target_symbol": "parse_message",
                "source_path": "src/parser.py",
                "harness_kind": "local_unit_harness",
            }
        ],
    }
    plan = build_local_fuzz_runner_plan(crs_fuzzing=crs, package_id="demo")
    assert plan.stage == "v1_approved_local_fuzz_execution"
    assert plan.execution_mode == "plan_only"
    assert plan.status in {STATUS_PLANNED, STATUS_SKIPPED_NO_FLAG}
    assert plan.in_process_run_executed is False
    assert plan.execution_allowed is False
    assert plan.process_spawn_allowed is False
    assert plan.external_fuzzer_spawn_allowed is False
    assert plan.network_access is False
    assert plan.crash_promotion_allowed is False
    assert plan.report_submission_allowed is False
    assert plan.finding_promotion_allowed is False
    assert plan.human_approval_required_before_run is True
    assert "no_external_fuzzer_process_spawn" in plan.safety_invariants


def test_flag_cannot_enable_in_process_execution(tmp_path: Path):
    code = tmp_path / "src"
    code.mkdir()
    (code / "parser.py").write_text(
        "def parse_message(raw):\n"
        "    if not raw:\n"
        "        raise ValueError('empty')\n"
        "    if b'A' * 10 in (raw if isinstance(raw, (bytes, bytearray)) else raw.encode()):\n"
        "        raise RuntimeError('boom')\n"
        "    return raw\n",
        encoding="utf-8",
    )
    result = run_local_fuzz_runner(
        package_root=tmp_path,
        human_allow_local_fuzz_run=True,
    )
    assert result.human_allow_local_fuzz_run is True
    assert result.in_process_run_executed is False
    assert result.execution_mode == "plan_only"
    assert result.status == STATUS_PLANNED
    assert result.iterations_total == 0
    assert result.crash_count == 0
    assert result.crash_export_written is False
    assert result.runnable_target_count == 0
    assert "in_process_execution_disabled" in result.notes
    assert not (tmp_path / "_export" / "fuzz_runs").exists()
    assert result.execution_allowed is False
    assert result.process_spawn_allowed is False
    assert result.external_fuzzer_spawn_allowed is False
    assert result.crash_promotion_allowed is False
    assert result.report_submission_allowed is False
    assert result.finding_promotion_allowed is False
    assert result.confirmed_vulnerability is False


def test_local_fuzz_runner_has_no_dynamic_python_execution():
    module_path = ROOT / "apps" / "api" / "app" / "local_fuzz_runner" / "__init__.py"
    tree = ast.parse(module_path.read_text(encoding="utf-8"))
    called_names = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert called_names.isdisjoint({"compile", "eval", "exec"})


def test_without_flag_does_not_execute(tmp_path: Path):
    code = tmp_path / "src"
    code.mkdir()
    (code / "parser.py").write_text(
        "def parse_message(raw):\n    return raw\n",
        encoding="utf-8",
    )
    result = run_local_fuzz_runner(
        package_root=tmp_path,
        human_allow_local_fuzz_run=False,
    )
    assert result.status == STATUS_SKIPPED_NO_FLAG
    assert result.in_process_run_executed is False
    assert result.crash_count == 0
    assert not (tmp_path / "_export" / "fuzz_runs").exists()
    assert result.execution_allowed is False
    assert result.crash_promotion_allowed is False


def test_attach_strips_promotion_flags(tmp_path: Path):
    code = tmp_path / "src"
    code.mkdir()
    (code / "parser.py").write_text(
        "def parse_message(raw):\n"
        "    if not raw:\n"
        "        raise ValueError('empty')\n"
        "    return raw\n",
        encoding="utf-8",
    )
    bridge = {
        "package_id": "demo-fuzz",
        "package_root": str(tmp_path),
        "drafts": [],
        "submission_blocked": True,
        "execution_allowed": True,
        "report_submission_allowed": True,
        "crs_fuzzing": {
            "status": "crs_fuzzing_plan_ready",
            "harness_plans": [
                {
                    "target_symbol": "parse_message",
                    "source_path": "src/parser.py",
                    "harness_kind": "local_unit_harness",
                }
            ],
        },
    }
    out = attach_local_fuzz_runner_to_bridge_result(
        bridge,
        package_root=tmp_path,
        human_allow_local_fuzz_run=True,
    )
    assert out["local_fuzz_runner_present"] is True
    assert out["local_fuzz_runner_executed"] is False
    assert out["local_fuzz_runner"]["execution_mode"] == "plan_only"
    assert "in_process_execution_disabled" in out["local_fuzz_runner"]["notes"]
    assert out["execution_allowed"] is False
    assert out["validation_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert out["submission_blocked"] is True
    assert out["local_fuzz_runner"]["crash_promotion_allowed"] is False
    assert out["local_fuzz_runner"]["process_spawn_allowed"] is False
    assert out["local_fuzz_runner"]["external_fuzzer_spawn_allowed"] is False
    assert out["local_fuzz_runner_crash_promotion_allowed"] is False


def test_package_ingest_smoke_default_off():
    result = run_local_fuzz_runner(package_root=PKG_SSRF, human_allow_local_fuzz_run=False)
    assert result.execution_allowed is False
    assert result.crash_promotion_allowed is False
    assert result.in_process_run_executed is False
    assert result.process_spawn_allowed is False


def test_scheduler_includes_t003d_after_t003c():
    plan = build_industrial_scheduler_plan(
        {
            "scope": {"allowed": True},
            "hypotheses": [],
            "crs_fuzzing": {"parser_candidates": [{"symbol_name": "decode_frame"}]},
            "local_fuzz_sandbox": {"targets": [{"target_symbol": "decode_frame"}]},
            "local_fuzz_runner": {"targets": [{"target_symbol": "decode_frame"}]},
        }
    )
    task_by_id = {task.task_id: task for task in plan.dag_tasks}
    assert "T-003d" in task_by_id
    assert task_by_id["T-003d"].agent == "local_fuzz_runner_agent"
    assert task_by_id["T-003d"].depends_on == ["T-003", "T-003b", "T-003c"]
    assert task_by_id["T-003d"].execution_allowed is False
    assert task_by_id["T-003d"].requires_human_review is True
    assert task_by_id["T-003d"].status == "planned"
    batch_ids = {b.batch_id: b.task_ids for b in plan.parallel_batches}
    assert "B-002f" in batch_ids
    assert batch_ids["B-002f"] == ["T-003d"]
    assert "T-003d" in task_by_id["T-006b"].depends_on
