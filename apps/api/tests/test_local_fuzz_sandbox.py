from pathlib import Path

from app.local_fuzz_sandbox import (
    STATUS_EMPTY,
    STATUS_NO_HARNESS,
    STATUS_READY,
    STATUS_SKIPPED,
    STATUS_WRITTEN,
    attach_local_fuzz_sandbox_to_bridge_result,
    build_local_fuzz_sandbox_plan,
)
from app.industrial_scheduler import build_industrial_scheduler_plan


ROOT = Path(__file__).resolve().parents[3]
PKG_SSRF = ROOT / "authorized_packages" / "my-local-ssrf-retain"


def test_build_plan_from_crs_payload_stays_plan_only():
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
    plan = build_local_fuzz_sandbox_plan(crs_fuzzing=crs, package_id="demo")

    assert plan.stage == "v1_approved_local_fuzz_sandbox"
    assert plan.execution_mode == "plan_only"
    assert plan.status == STATUS_READY
    assert plan.target_count == 1
    assert plan.targets[0].target_symbol == "parse_message"
    assert plan.execution_allowed is False
    assert plan.process_spawn_allowed is False
    assert plan.network_access is False
    assert plan.crash_promotion_allowed is False
    assert plan.report_submission_allowed is False
    assert plan.finding_promotion_allowed is False
    assert plan.human_approval_required_before_run is True
    assert plan.sandbox_export_written is False
    assert "sandbox_write_not_requested" in plan.notes
    assert "no_fuzzer_process_spawn" in plan.safety_invariants


def test_build_plan_package_ingest_detects_targets():
    plan = build_local_fuzz_sandbox_plan(package_root=PKG_SSRF)
    assert plan.package_id
    assert plan.execution_allowed is False
    assert plan.process_spawn_allowed is False
    # SSRF retain package may or may not have parser markers; either ready or no-harness is fine
    assert plan.status in {STATUS_READY, STATUS_NO_HARNESS, STATUS_EMPTY}
    if plan.status == STATUS_READY:
        assert plan.target_count >= 1
        assert plan.harness_source_count >= 1


def test_default_off_does_not_write_export(tmp_path: Path):
    code = tmp_path / "src"
    code.mkdir()
    (code / "parser.py").write_text(
        "def parse_message(raw: bytes):\n    return raw\n",
        encoding="utf-8",
    )
    plan = build_local_fuzz_sandbox_plan(
        package_root=tmp_path, human_allow_sandbox_write=False
    )
    assert plan.sandbox_export_written is False
    assert plan.sandbox_export_count == 0
    assert "sandbox_write_not_requested" in plan.notes
    assert not (tmp_path / "_export" / "fuzz_sandbox").exists()
    assert plan.execution_allowed is False
    assert plan.process_spawn_allowed is False


def test_flag_writes_local_sandbox_export(tmp_path: Path):
    code = tmp_path / "src"
    code.mkdir()
    (code / "parser.py").write_text(
        "def parse_message(raw: bytes):\n    return raw\n",
        encoding="utf-8",
    )
    plan = build_local_fuzz_sandbox_plan(
        package_root=tmp_path, human_allow_sandbox_write=True
    )
    assert plan.human_allow_sandbox_write is True
    assert plan.sandbox_export_written is True
    assert plan.sandbox_export_count >= 1
    assert plan.status == STATUS_WRITTEN
    assert plan.execution_allowed is False
    assert plan.process_spawn_allowed is False
    assert plan.network_access is False
    assert plan.crash_promotion_allowed is False
    assert plan.report_submission_allowed is False
    assert plan.finding_promotion_allowed is False
    export_root = tmp_path / "_export" / "fuzz_sandbox"
    assert export_root.is_dir()
    assert list(export_root.glob("*/Dockerfile.sandbox"))
    assert list(export_root.glob("*/sandbox_recipe.md"))
    assert list(export_root.glob("*/meta.json"))
    assert list(export_root.glob("*/run_notes.md"))
    written = [t for t in plan.targets if t.written]
    assert written
    assert written[0].export_relative_path.startswith("_export/fuzz_sandbox/")


def test_flag_without_root_skips_files():
    crs = {
        "status": "crs_fuzzing_plan_ready",
        "harness_plans": [
            {
                "target_symbol": "parse_x",
                "source_path": "src/p.py",
                "harness_kind": "local_unit_harness",
            }
        ],
    }
    plan = build_local_fuzz_sandbox_plan(
        crs_fuzzing=crs, human_allow_sandbox_write=True
    )
    assert plan.human_allow_sandbox_write is True
    assert plan.sandbox_export_written is False
    assert plan.sandbox_export_count == 0
    assert "sandbox_write_requested_but_package_root_missing" in plan.notes
    assert plan.execution_allowed is False


def test_no_harness_status():
    plan = build_local_fuzz_sandbox_plan(
        crs_fuzzing={"status": "crs_fuzzing_plan_ready", "harness_plans": []},
        package_id="empty",
    )
    assert plan.status == STATUS_NO_HARNESS
    assert plan.target_count == 0
    assert plan.execution_allowed is False


def test_attach_bridge_forces_safety_and_exposes_export(tmp_path: Path):
    code = tmp_path / "src"
    code.mkdir()
    (code / "parser.py").write_text(
        "def parse_message(raw: bytes):\n    return raw\n",
        encoding="utf-8",
    )
    bridge = {
        "package_id": "tmp-sandbox-export",
        "package_root": str(tmp_path),
        "drafts": [],
        "submission_blocked": True,
        "execution_allowed": True,  # must be forced false
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
    out = attach_local_fuzz_sandbox_to_bridge_result(
        bridge,
        package_root=tmp_path,
        human_allow_sandbox_write=True,
    )
    assert out["local_fuzz_sandbox_present"] is True
    assert out["local_fuzz_sandbox_status"] == STATUS_WRITTEN
    assert out["local_fuzz_sandbox_export_written"] is True
    assert out["local_fuzz_sandbox_export_count"] >= 1
    assert out["local_fuzz_sandbox_target_count"] >= 1
    assert out["execution_allowed"] is False
    assert out["validation_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert out["submission_blocked"] is True
    assert out["local_fuzz_sandbox"]["process_spawn_allowed"] is False
    assert out["local_fuzz_sandbox"]["crash_promotion_allowed"] is False


def test_scheduler_includes_t003c_after_t003b():
    plan = build_industrial_scheduler_plan(
        {
            "scope": {"allowed": True},
            "hypotheses": [],
            "crs_fuzzing": {"parser_candidates": [{"symbol_name": "decode_frame"}]},
            "local_fuzz_sandbox": {"targets": [{"target_symbol": "decode_frame"}]},
        }
    )
    task_by_id = {task.task_id: task for task in plan.dag_tasks}
    assert "T-003c" in task_by_id
    assert task_by_id["T-003c"].agent == "local_fuzz_sandbox_agent"
    assert task_by_id["T-003c"].depends_on == ["T-003", "T-003b"]
    assert task_by_id["T-003c"].execution_allowed is False
    assert task_by_id["T-003c"].requires_human_review is True
    assert task_by_id["T-003c"].status == "planned"
    batch_ids = {b.batch_id: b.task_ids for b in plan.parallel_batches}
    assert "B-002e" in batch_ids
    assert batch_ids["B-002e"] == ["T-003c"]
