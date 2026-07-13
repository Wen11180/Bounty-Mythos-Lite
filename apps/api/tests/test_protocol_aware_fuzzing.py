from pathlib import Path

from app.protocol_aware_fuzzing import (
    STATUS_EMPTY,
    STATUS_NO_PARSERS,
    STATUS_READY,
    STATUS_SKIPPED,
    STATUS_WRITTEN,
    attach_protocol_aware_fuzzing_to_bridge_result,
    build_protocol_aware_fuzzing_plan,
)
from app.industrial_scheduler import build_industrial_scheduler_plan
from app.multi_engine_verifier import (
    ENGINE_PROTOCOL_AWARE_FUZZING,
    signal_from_protocol_aware_fuzzing,
)


ROOT = Path(__file__).resolve().parents[3]
PKG_SSRF = ROOT / "authorized_packages" / "my-local-ssrf-retain"


def test_build_plan_from_parser_candidates_stays_plan_only():
    crs = {
        "status": "crs_fuzzing_plan_ready",
        "package_id": "demo",
        "parser_candidates": [
            {
                "symbol_name": "parse_message",
                "source_path": "src/parser.py",
                "candidate_type": "parser",
                "language": "python",
            }
        ],
    }
    plan = build_protocol_aware_fuzzing_plan(crs_fuzzing=crs, package_id="demo")

    assert plan.stage == "v4_protocol_aware_fuzzing"
    assert plan.execution_mode == "plan_only"
    assert plan.status == STATUS_READY
    assert plan.target_count == 1
    assert plan.targets[0].target_symbol == "parse_message"
    assert plan.grammar_plan_count == 1
    assert plan.seed_plan_count >= 1
    assert plan.execution_allowed is False
    assert plan.process_spawn_allowed is False
    assert plan.network_access is False
    assert plan.live_validation is False
    assert plan.crash_promotion_allowed is False
    assert plan.report_submission_allowed is False
    assert plan.finding_promotion_allowed is False
    assert plan.confirmed_vulnerability is False
    assert plan.human_approval_required_before_run is True
    assert plan.export_written is False
    assert "export_write_not_requested" in plan.notes
    assert "no_fuzzer_process_spawn" in plan.safety_invariants
    assert plan.targets[0].execution_allowed is False
    assert "derive_protocol_grammar_before_local_harness" in plan.strategy_kinds


def test_safety_flags_forced_false_even_if_input_tries_true():
    payload = {
        "status": STATUS_READY,
        "targets": [{"target_symbol": "x", "source_path": "a.py", "execution_allowed": True}],
        "target_count": 1,
        "execution_allowed": True,
        "process_spawn_allowed": True,
        "network_access": True,
        "live_validation": True,
        "validation_allowed": True,
        "report_submission_allowed": True,
        "confirmed_vulnerability": True,
        "finding_promotion_allowed": True,
        "crash_promotion_allowed": True,
    }
    out = attach_protocol_aware_fuzzing_to_bridge_result(
        {"package_id": "demo", "submission_blocked": True},
        protocol_aware_fuzzing=payload,
    )
    paf = out["protocol_aware_fuzzing"]
    assert paf["execution_allowed"] is False
    assert paf["process_spawn_allowed"] is False
    assert paf["network_access"] is False
    assert paf["live_validation"] is False
    assert paf["validation_allowed"] is False
    assert paf["report_submission_allowed"] is False
    assert paf["confirmed_vulnerability"] is False
    assert paf["finding_promotion_allowed"] is False
    assert paf["crash_promotion_allowed"] is False
    assert out["execution_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["submission_blocked"] is True
    assert out["protocol_aware_fuzzing_present"] is True


def test_empty_without_parsers():
    plan = build_protocol_aware_fuzzing_plan(
        crs_fuzzing={"status": "crs_fuzzing_empty", "parser_candidates": []},
        package_id="empty",
    )
    assert plan.status in {STATUS_EMPTY, STATUS_NO_PARSERS}
    assert plan.target_count == 0
    assert plan.execution_allowed is False


def test_missing_package_skipped():
    plan = build_protocol_aware_fuzzing_plan(
        package_root="Z:/does/not/exist/protocol_pkg_xyz"
    )
    assert plan.status == STATUS_SKIPPED
    assert plan.execution_allowed is False


def test_flag_writes_export(tmp_path: Path):
    code = tmp_path / "src"
    code.mkdir()
    (code / "parser.py").write_text(
        "def parse_message(raw: bytes):\n    return raw\n",
        encoding="utf-8",
    )
    plan = build_protocol_aware_fuzzing_plan(
        package_root=tmp_path, human_allow_export_write=True
    )
    assert plan.human_allow_export_write is True
    # may be ready or no parsers depending on CRS detect; if ready, export written
    if plan.status in {STATUS_READY, STATUS_WRITTEN} and plan.target_count:
        assert plan.export_written is True
        assert plan.export_count >= 1
        assert plan.status == STATUS_WRITTEN
        export_root = tmp_path / "_export" / "protocol_aware_fuzzing"
        assert export_root.is_dir()
        assert (export_root / "index.json").is_file()
        assert list(export_root.glob("*/grammar_plan.md"))
        assert list(export_root.glob("*/meta.json"))
    assert plan.execution_allowed is False
    assert plan.process_spawn_allowed is False
    assert plan.network_access is False


def test_offline_protocol_hint(tmp_path: Path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "protocol_hints.json").write_text(
        '{"target_symbol":"decode_frame","source_path":"src/frame.py","candidate_type":"decoder"}',
        encoding="utf-8",
    )
    plan = build_protocol_aware_fuzzing_plan(package_root=tmp_path)
    assert plan.execution_allowed is False
    assert plan.target_count >= 1
    assert any(t.target_symbol == "decode_frame" for t in plan.targets)
    assert plan.status == STATUS_READY


def test_bridge_attach_and_mev_signal():
    crs = {
        "status": "crs_fuzzing_plan_ready",
        "parser_candidates": [
            {
                "symbol_name": "parse_x",
                "source_path": "src/p.py",
                "candidate_type": "parser",
            }
        ],
    }
    bridged = attach_protocol_aware_fuzzing_to_bridge_result(
        {"package_id": "demo", "submission_blocked": True, "crs_fuzzing": crs},
        crs_fuzzing=crs,
    )
    assert bridged["protocol_aware_fuzzing_present"] is True
    assert bridged["protocol_aware_fuzzing_status"] == STATUS_READY
    assert bridged["protocol_aware_fuzzing_target_count"] == 1
    assert bridged["submission_blocked"] is True
    assert bridged["execution_allowed"] is False

    sig = signal_from_protocol_aware_fuzzing(bridged["protocol_aware_fuzzing"])
    assert sig is not None
    assert sig["status"] == "advisory"
    assert sig["supports_candidate"] is False

    bad = signal_from_protocol_aware_fuzzing(
        {**bridged["protocol_aware_fuzzing"], "execution_allowed": True}
    )
    assert bad["status"] == "blocked"


def test_scheduler_includes_t003h():
    plan = build_industrial_scheduler_plan(
        context={"crs_fuzzing": {"status": "ready"}, "protocol_aware_fuzzing": {"status": "ready"}}
    )
    by_id = {t.task_id: t for t in plan.dag_tasks}
    assert "T-003h" in by_id
    assert by_id["T-003h"].agent == "protocol_aware_fuzzing_agent"
    assert by_id["T-003h"].execution_allowed is False
    assert by_id["T-003h"].requires_human_review is True
    assert "T-003" in by_id["T-003h"].depends_on
    batch_ids = {b.batch_id for b in plan.parallel_batches}
    assert "B-002j" in batch_ids
    assert ENGINE_PROTOCOL_AWARE_FUZZING == "protocol_aware_fuzzing"


def test_package_ingest_ssrf_retain_stays_safe():
    plan = build_protocol_aware_fuzzing_plan(package_root=PKG_SSRF)
    assert plan.execution_allowed is False
    assert plan.process_spawn_allowed is False
    assert plan.network_access is False
    assert plan.report_submission_allowed is False
    assert plan.status in {
        STATUS_READY,
        STATUS_NO_PARSERS,
        STATUS_EMPTY,
        STATUS_WRITTEN,
        STATUS_SKIPPED,
    }