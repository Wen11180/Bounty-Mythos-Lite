from pathlib import Path

from app.crs_fuzzing import (
    STATUS_EMPTY,
    STATUS_HARNESS_WRITTEN,
    STATUS_READY,
    STATUS_SKIPPED,
    attach_crs_fuzzing_to_bridge_result,
    build_crs_fuzzing_plan,
    collect_authorized_code_files,
)
from app.industrial_scheduler import build_industrial_scheduler_plan


ROOT = Path(__file__).resolve().parents[3]
PKG_SSRF = ROOT / "authorized_packages" / "my-local-ssrf-retain"


def test_build_crs_fuzzing_plan_detects_parser_candidate_and_stays_plan_only():
    plan = build_crs_fuzzing_plan(
        [
            {
                "path": "src/parser.py",
                "content": "\n".join(
                    [
                        "import json",
                        "",
                        "def parse_message(raw: bytes):",
                        "    return json.loads(raw.decode())",
                    ]
                ),
            }
        ]
    )

    assert plan.stage.startswith("v1_crs_fuzzing")
    assert plan.inspirations == ["Buttercup", "ATLANTIS", "OSS-Fuzz", "AFL++"]
    assert plan.execution_mode == "plan_only"
    assert plan.status == STATUS_READY
    assert plan.parser_candidates[0].symbol_name == "parse_message"
    assert plan.parser_candidates[0].candidate_type == "parser"
    assert plan.harness_plans[0].target_symbol == "parse_message"
    assert plan.harness_plans[0].status == "planned"
    assert plan.harness_plans[0].harness_sketch
    assert plan.fuzzer_plan.status == "not_executed"
    assert plan.fuzzer_plan.execution_allowed is False
    assert plan.execution_allowed is False
    assert plan.report_submission_allowed is False
    assert plan.crash_triage.status == "schema_only"
    assert plan.crash_promotion_gate.status == "blocked_until_reproducible_local_crash"
    assert plan.crash_promotion_gate.execution_allowed is False
    assert plan.crash_promotion_gate.promotion_allowed is False
    assert plan.crash_promotion_gate.approval_required is True
    assert plan.crash_promotion_gate.required_evidence == [
        "local_reproducible_crash",
        "minimized_input_ref",
        "sanitized_sanitizer_trace",
        "human_review_decision",
    ]
    assert plan.sanitizer_config.enabled == ["ASAN", "UBSAN"]
    assert plan.root_cause.status == "blocked_until_reproducible_crash"
    assert plan.regression_suggestions[0].test_type == "local_regression_test"
    assert "no_public_target_scanning" in plan.safety_invariants
    assert "no_destructive_validation" in plan.safety_invariants
    assert "no_process_spawn_by_planner" in plan.safety_invariants


def test_build_crs_fuzzing_plan_detects_decoder_and_validator_candidates():
    plan = build_crs_fuzzing_plan(
        [
            {
                "path": "src/codec.py",
                "content": "\n".join(
                    [
                        "def decode_frame(raw: bytes):",
                        "    return raw.decode()",
                        "",
                        "def validate_frame(frame: str):",
                        "    return frame.startswith('MYTHOS')",
                    ]
                ),
            }
        ]
    )

    candidates = {
        candidate.symbol_name: candidate.candidate_type
        for candidate in plan.parser_candidates
    }

    assert candidates == {
        "decode_frame": "parser",
        "validate_frame": "validator",
    }


def test_build_crs_fuzzing_plan_detects_protocol_handler_candidate_without_execution():
    plan = build_crs_fuzzing_plan(
        [
            {
                "path": "src/protocol.py",
                "content": "\n".join(
                    [
                        "import struct",
                        "",
                        "def handle_frame(raw: bytes):",
                        "    message_type, length = struct.unpack('!BH', raw[:3])",
                        "    return message_type, raw[3:3 + length]",
                    ]
                ),
            }
        ]
    )

    assert plan.parser_candidates[0].symbol_name == "handle_frame"
    assert plan.parser_candidates[0].candidate_type == "protocol_handler"
    assert plan.harness_plans[0].target_symbol == "handle_frame"
    assert plan.fuzzer_plan.status == "not_executed"
    assert plan.fuzzer_plan.execution_allowed is False
    assert plan.fuzzer_plan.execution_allowed is False
    assert "execution_allowed=false" in plan.fuzzer_plan.command_preview.lower() or "plan only" in plan.fuzzer_plan.command_preview.lower()
    assert "no_network_access" in plan.fuzzer_plan.safety_notes


def test_build_crs_fuzzing_plan_detects_bom_prefixed_parser_candidate():
    plan = build_crs_fuzzing_plan(
        [
            {
                "path": "src/codec.py",
                "content": "\ufeffdef decode_frame(raw: bytes):\n    return raw.decode()\n",
            }
        ]
    )

    assert plan.parser_candidates[0].symbol_name == "decode_frame"


def test_detects_typescript_function_candidates():
    plan = build_crs_fuzzing_plan(
        [
            {
                "path": "inputs/codec.ts",
                "content": "\n".join(
                    [
                        "export async function parseWebhookBody(raw: string) {",
                        "  return JSON.parse(raw);",
                        "}",
                        "",
                        "export function validateWebhookBody(body: unknown) {",
                        "  return Boolean(body);",
                        "}",
                    ]
                ),
            }
        ]
    )
    names = {c.symbol_name: c.candidate_type for c in plan.parser_candidates}
    assert names["parseWebhookBody"] == "parser"
    assert names["validateWebhookBody"] == "validator"
    assert plan.execution_allowed is False


def test_package_root_ingest_plan_only():
    plan = build_crs_fuzzing_plan(package_root=PKG_SSRF)
    assert plan.package_root
    assert plan.scanned_file_count >= 1
    assert plan.execution_mode == "plan_only"
    assert plan.execution_allowed is False
    assert plan.fuzzer_plan.execution_allowed is False
    assert plan.crash_promotion_gate.promotion_allowed is False
    assert plan.report_submission_allowed is False
    # package may or may not have parser-named symbols; status is ready or empty
    assert plan.status in {STATUS_READY, STATUS_EMPTY}


def test_collect_authorized_code_files_confined():
    files = collect_authorized_code_files(PKG_SSRF)
    assert files
    assert all("path" in f and "content" in f for f in files)
    assert any(f["path"].endswith("code.ts") for f in files)


def test_missing_package_root_skips():
    plan = build_crs_fuzzing_plan(package_root=PKG_SSRF / "does-not-exist")
    assert plan.status == STATUS_SKIPPED
    assert plan.execution_allowed is False


def test_empty_files_status():
    plan = build_crs_fuzzing_plan([])
    assert plan.status in {STATUS_EMPTY, "crs_fuzzing_no_code_files"}
    assert plan.execution_allowed is False


def test_attach_bridge_plan_only():
    bridge = {
        "package_id": "my-local-ssrf-retain",
        "package_root": str(PKG_SSRF),
        "drafts": [],
        "submission_blocked": True,
    }
    out = attach_crs_fuzzing_to_bridge_result(bridge, package_root=PKG_SSRF)
    assert out["crs_fuzzing_present"] is True
    assert out["crs_fuzzing_status"]
    assert out["crs_fuzzing_execution_allowed"] is False
    assert out["execution_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["submission_blocked"] is True
    assert out["crs_fuzzing"]["fuzzer_plan"]["execution_allowed"] is False


def test_scheduler_marks_crs_when_context_present():
    plan = build_industrial_scheduler_plan(
        {
            "scope": {"allowed": True},
            "crs_fuzzing": {"status": STATUS_READY, "candidate_count": 1},
            "hypotheses": [
                {
                    "finding_id": "H-001",
                    "vuln_type": "memory_corruption",
                    "severity": "high",
                    "status": "unverified_hypothesis",
                }
            ],
        }
    )
    by_id = {t.task_id: t for t in plan.dag_tasks}
    assert "T-003" in by_id
    assert by_id["T-003"].agent == "crs_fuzzing_agent"
    assert by_id["T-003"].status == "planned"
    assert by_id["T-003"].execution_allowed is False


def test_harness_write_default_off_no_files(tmp_path: Path):
    code = tmp_path / "src"
    code.mkdir()
    (code / "parser.py").write_text(
        "def parse_message(raw: bytes):\n    return raw\n",
        encoding="utf-8",
    )
    plan = build_crs_fuzzing_plan(package_root=tmp_path, human_allow_harness_write=False)
    assert plan.harness_export_written is False
    assert plan.harness_export_count == 0
    assert "harness_write_not_requested" in plan.notes
    assert not (tmp_path / "_export" / "crs_harness").exists()
    assert plan.execution_allowed is False
    assert plan.fuzzer_plan.execution_allowed is False
    assert plan.crash_promotion_gate.promotion_allowed is False


def test_harness_write_with_flag_writes_local_export(tmp_path: Path):
    code = tmp_path / "src"
    code.mkdir()
    (code / "parser.py").write_text(
        "def parse_message(raw: bytes):\n    return raw\n",
        encoding="utf-8",
    )
    plan = build_crs_fuzzing_plan(package_root=tmp_path, human_allow_harness_write=True)
    assert plan.human_allow_harness_write is True
    assert plan.harness_export_written is True
    assert plan.harness_export_count >= 1
    assert plan.status == STATUS_HARNESS_WRITTEN
    assert plan.execution_allowed is False
    assert plan.fuzzer_plan.status == "not_executed"
    assert plan.fuzzer_plan.execution_allowed is False
    assert plan.crash_promotion_gate.promotion_allowed is False
    assert plan.report_submission_allowed is False
    assert plan.finding_promotion_allowed is False
    export_root = tmp_path / "_export" / "crs_harness"
    assert export_root.is_dir()
    sketch_files = list(export_root.glob("*/harness_sketch.txt"))
    assert sketch_files
    meta_files = list(export_root.glob("*/meta.json"))
    assert meta_files
    written = [h for h in plan.harness_plans if h.written]
    assert written
    assert written[0].export_relative_path.startswith("_export/crs_harness/")


def test_harness_write_flag_without_root_skips_files():
    plan = build_crs_fuzzing_plan(
        [{"path": "src/p.py", "content": "def parse_x(b):\n    return b\n"}],
        human_allow_harness_write=True,
    )
    assert plan.human_allow_harness_write is True
    assert plan.harness_export_written is False
    assert plan.harness_export_count == 0
    assert "harness_write_requested_but_package_root_missing" in plan.notes
    assert plan.execution_allowed is False


def test_attach_bridge_exposes_harness_export_and_forces_safety(tmp_path: Path):
    code = tmp_path / "src"
    code.mkdir()
    (code / "parser.py").write_text(
        "def parse_message(raw: bytes):\n    return raw\n",
        encoding="utf-8",
    )
    bridge = {
        "package_id": "tmp-crs-export",
        "package_root": str(tmp_path),
        "drafts": [],
        "submission_blocked": True,
        "execution_allowed": True,  # must be forced false
        "report_submission_allowed": True,
    }
    out = attach_crs_fuzzing_to_bridge_result(
        bridge,
        package_root=tmp_path,
        human_allow_harness_write=True,
    )
    assert out["crs_fuzzing_present"] is True
    assert out["crs_fuzzing_harness_export_written"] is True
    assert out["crs_fuzzing_harness_export_count"] >= 1
    assert out["crs_fuzzing_status"] == STATUS_HARNESS_WRITTEN
    assert out["crs_fuzzing_execution_allowed"] is False
    assert out["execution_allowed"] is False
    assert out["validation_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert out["submission_blocked"] is True
    payload = out["crs_fuzzing"]
    assert payload["execution_allowed"] is False
    assert payload["fuzzer_plan"]["execution_allowed"] is False
    assert payload["crash_promotion_gate"]["promotion_allowed"] is False


def test_scheduler_includes_t003b_export_task():
    plan = build_industrial_scheduler_plan({"crs_fuzzing": {"status": "ready"}})
    ids = {task.task_id for task in plan.dag_tasks}
    assert "T-003" in ids
    assert "T-003b" in ids
    t003b = next(task for task in plan.dag_tasks if task.task_id == "T-003b")
    assert t003b.requires_human_review is True
    assert t003b.execution_allowed is False
    assert "T-003" in t003b.depends_on
    batch_ids = {b.batch_id for b in plan.parallel_batches}
    assert "B-002d" in batch_ids
