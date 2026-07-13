from pathlib import Path

from app.deep_code_reasoning import (
    STATUS_EMPTY,
    STATUS_READY,
    STATUS_SKIPPED,
    STATUS_WAITING,
    STATUS_WRITTEN,
    attach_deep_code_reasoning_to_bridge_result,
    build_deep_code_reasoning_plan,
)
from app.industrial_scheduler import build_industrial_scheduler_plan
from app.multi_engine_verifier import (
    ENGINE_DEEP_CODE_REASONING,
    signal_from_deep_code_reasoning,
)


ROOT = Path(__file__).resolve().parents[3]
PKG_SSRF = ROOT / "authorized_packages" / "my-local-ssrf-retain"


def test_build_plan_from_hypothesis_stays_plan_only():
    plan = build_deep_code_reasoning_plan(
        package_id="demo",
        source_hypotheses=[
            {
                "hypothesis_id": "hyp-1",
                "family": "authorization",
                "vuln_type": "idor",
                "location": "src/api/items.py:update",
                "title": "missing ownership on item update",
            }
        ],
    )

    assert plan.stage == "v4_deep_code_reasoning"
    assert plan.execution_mode == "plan_only"
    assert plan.status == STATUS_READY
    assert plan.path_count >= 1
    assert plan.permission_model_count >= 1
    assert plan.paths[0].source_hypothesis_id == "hyp-1"
    assert plan.paths[0].layers
    assert plan.paths[0].layers[0].execution_allowed is False
    assert plan.permission_models[0].execution_allowed is False
    assert plan.execution_allowed is False
    assert plan.network_access is False
    assert plan.live_validation is False
    assert plan.process_spawn_allowed is False
    assert plan.validation_allowed is False
    assert plan.report_submission_allowed is False
    assert plan.confirmed_vulnerability is False
    assert plan.finding_promotion_allowed is False


def test_attach_keeps_submission_blocked():
    out = attach_deep_code_reasoning_to_bridge_result(
        {
            "package_id": "demo",
            "submission_blocked": True,
            "source_hypotheses": [
                {
                    "hypothesis_id": "h-ssrf",
                    "family": "ssrf",
                    "location": "fetch.py",
                }
            ],
        }
    )
    dcr = out["deep_code_reasoning"]
    assert dcr["status"] == STATUS_READY
    assert dcr["path_count"] >= 1
    assert dcr["execution_allowed"] is False
    assert dcr["validation_allowed"] is False
    assert dcr["report_submission_allowed"] is False
    assert dcr["confirmed_vulnerability"] is False
    assert dcr["finding_promotion_allowed"] is False
    assert out["execution_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["submission_blocked"] is True
    assert out["deep_code_reasoning_present"] is True
    assert out["deep_code_reasoning_execution_allowed"] is False


def test_waiting_without_seeds():
    plan = build_deep_code_reasoning_plan(package_id="empty")
    assert plan.status in {STATUS_WAITING, STATUS_EMPTY}
    assert plan.path_count == 0
    assert plan.execution_allowed is False


def test_missing_package_skipped():
    plan = build_deep_code_reasoning_plan(
        package_root="Z:/does/not/exist/dcr_pkg_xyz"
    )
    assert plan.status == STATUS_SKIPPED
    assert plan.execution_allowed is False


def test_flag_writes_export(tmp_path: Path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "deep_code_sample.json").write_text(
        (
            '{"source_hypothesis_id":"sample-1","family":"ssrf",'
            '"location":"fetch.py","path_summary":"url open without allowlist"}'
        ),
        encoding="utf-8",
    )
    plan = build_deep_code_reasoning_plan(
        package_root=tmp_path, human_allow_export_write=True
    )
    assert plan.human_allow_export_write is True
    assert plan.status == STATUS_WRITTEN
    assert plan.path_count >= 1
    assert plan.export_written is True
    assert plan.export_count >= 1
    export_root = tmp_path / "_export" / "deep_code_reasoning"
    assert export_root.is_dir()
    assert (export_root / "index.json").is_file()
    assert list(export_root.glob("*/path_plan.md"))
    assert list(export_root.glob("*/meta.json"))
    assert plan.execution_allowed is False
    assert plan.confirmed_vulnerability is False


def test_seeds_from_retained_and_vuln_chain_builder():
    plan = build_deep_code_reasoning_plan(
        package_id="demo",
        retained_candidates=[
            {
                "candidate_id": "c1",
                "family": "mass_assignment",
                "title": "role field writable",
                "location": "models/user.py",
            }
        ],
        vuln_chain_builder={
            "chains": [
                {
                    "chain_id": "CH-001",
                    "source_hypothesis_id": "hyp-vcb",
                    "family": "authorization",
                    "seed_location": "api/items.py",
                    "vuln_type": "idor",
                }
            ]
        },
        role_models=[{"role": "owner"}, {"role": "guest"}],
    )
    assert plan.status == STATUS_READY
    assert plan.path_count >= 2
    assert plan.permission_model_count >= 1
    assert "owner" in plan.permission_models[0].roles
    assert plan.execution_allowed is False


def test_bridge_attach_and_mev_signal():
    bridged = attach_deep_code_reasoning_to_bridge_result(
        {
            "package_id": "demo",
            "submission_blocked": True,
            "source_hypotheses": [
                {
                    "hypothesis_id": "h1",
                    "family": "path_traversal",
                    "location": "files/download.py",
                }
            ],
        }
    )
    assert bridged["deep_code_reasoning_present"] is True
    assert bridged["deep_code_reasoning_status"] == STATUS_READY
    assert bridged["deep_code_reasoning_path_count"] >= 1
    assert bridged["submission_blocked"] is True
    assert bridged["execution_allowed"] is False
    assert bridged["confirmed_vulnerability"] is False

    sig = signal_from_deep_code_reasoning(bridged["deep_code_reasoning"])
    assert sig is not None
    assert sig["status"] == "advisory"
    assert sig["supports_candidate"] is False

    bad = signal_from_deep_code_reasoning(
        {**bridged["deep_code_reasoning"], "execution_allowed": True}
    )
    assert bad["status"] == "blocked"


def test_scheduler_includes_t013d():
    plan = build_industrial_scheduler_plan(
        context={
            "deep_code_reasoning": {"status": "ready"},
            "source_hypotheses": [{"hypothesis_id": "h1"}],
            "vuln_chain_builder": {"status": "ready"},
            "variant_analysis": {"status": "ready"},
        }
    )
    by_id = {t.task_id: t for t in plan.dag_tasks}
    assert "T-013d" in by_id
    assert by_id["T-013d"].agent == "deep_code_reasoning_agent"
    assert by_id["T-013d"].execution_allowed is False
    assert by_id["T-013d"].requires_human_review is True
    assert "T-013c" in by_id["T-013d"].depends_on
    batch_ids = {b.batch_id for b in plan.parallel_batches}
    assert "B-010d" in batch_ids
    assert ENGINE_DEEP_CODE_REASONING == "deep_code_reasoning"
    assert "T-013d" in by_id["T-014"].depends_on


def test_package_ingest_ssrf_retain_stays_safe():
    plan = build_deep_code_reasoning_plan(package_root=PKG_SSRF)
    assert plan.execution_allowed is False
    assert plan.report_submission_allowed is False
    assert plan.confirmed_vulnerability is False
    assert plan.finding_promotion_allowed is False
    assert plan.network_access is False
    assert plan.status in {
        STATUS_READY,
        STATUS_WAITING,
        STATUS_EMPTY,
        STATUS_WRITTEN,
        STATUS_SKIPPED,
    }
