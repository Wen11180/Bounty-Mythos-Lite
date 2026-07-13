from pathlib import Path

from app.vuln_chain_builder import (
    STATUS_EMPTY,
    STATUS_READY,
    STATUS_SKIPPED,
    STATUS_WAITING,
    STATUS_WRITTEN,
    attach_vuln_chain_builder_to_bridge_result,
    build_vuln_chain_builder_plan,
)
from app.industrial_scheduler import build_industrial_scheduler_plan
from app.multi_engine_verifier import (
    ENGINE_VULN_CHAIN_BUILDER,
    signal_from_vuln_chain_builder,
)


ROOT = Path(__file__).resolve().parents[3]
PKG_SSRF = ROOT / "authorized_packages" / "my-local-ssrf-retain"


def test_build_plan_from_hypothesis_stays_plan_only():
    plan = build_vuln_chain_builder_plan(
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

    assert plan.stage == "v4_vuln_chain_builder"
    assert plan.execution_mode == "plan_only"
    assert plan.status == STATUS_READY
    assert plan.chain_count >= 1
    assert plan.chains[0].source_hypothesis_id == "hyp-1"
    assert plan.chains[0].stages
    assert plan.chains[0].stages[0].execution_allowed is False
    assert plan.execution_allowed is False
    assert plan.network_access is False
    assert plan.live_validation is False
    assert plan.process_spawn_allowed is False
    assert plan.validation_allowed is False
    assert plan.report_submission_allowed is False
    assert plan.confirmed_vulnerability is False
    assert plan.finding_promotion_allowed is False
    assert plan.human_approval_required_before_action is True
    assert plan.export_written is False
    assert "export_write_not_requested" in plan.notes
    assert "unverified_chains_never_confirmed" in plan.safety_invariants
    assert plan.chains[0].execution_allowed is False
    assert plan.chains[0].human_review_required is True


def test_safety_flags_forced_false_even_if_input_tries_true():
    payload = {
        "status": STATUS_READY,
        "chains": [{"chain_id": "CH-001", "execution_allowed": True}],
        "chain_count": 1,
        "execution_allowed": True,
        "process_spawn_allowed": True,
        "network_access": True,
        "live_validation": True,
        "validation_allowed": True,
        "report_submission_allowed": True,
        "confirmed_vulnerability": True,
        "finding_promotion_allowed": True,
    }
    out = attach_vuln_chain_builder_to_bridge_result(
        {"package_id": "demo", "submission_blocked": True},
        vuln_chain_builder=payload,
    )
    vcb = out["vuln_chain_builder"]
    assert vcb["execution_allowed"] is False
    assert vcb["process_spawn_allowed"] is False
    assert vcb["network_access"] is False
    assert vcb["live_validation"] is False
    assert vcb["validation_allowed"] is False
    assert vcb["report_submission_allowed"] is False
    assert vcb["confirmed_vulnerability"] is False
    assert vcb["finding_promotion_allowed"] is False
    assert out["execution_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["submission_blocked"] is True
    assert out["vuln_chain_builder_present"] is True
    assert out["vuln_chain_builder_execution_allowed"] is False


def test_waiting_without_seeds():
    plan = build_vuln_chain_builder_plan(package_id="empty")
    assert plan.status in {STATUS_WAITING, STATUS_EMPTY}
    assert plan.chain_count == 0
    assert plan.execution_allowed is False


def test_missing_package_skipped():
    plan = build_vuln_chain_builder_plan(
        package_root="Z:/does/not/exist/vcb_pkg_xyz"
    )
    assert plan.status == STATUS_SKIPPED
    assert plan.execution_allowed is False


def test_flag_writes_export(tmp_path: Path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "chain_sample.json").write_text(
        (
            '{"source_hypothesis_id":"sample-1","family":"ssrf",'
            '"location":"fetch.py","chain_summary":"url open without allowlist"}'
        ),
        encoding="utf-8",
    )
    plan = build_vuln_chain_builder_plan(
        package_root=tmp_path, human_allow_export_write=True
    )
    assert plan.human_allow_export_write is True
    assert plan.status == STATUS_WRITTEN
    assert plan.chain_count >= 1
    assert plan.export_written is True
    assert plan.export_count >= 1
    export_root = tmp_path / "_export" / "vuln_chain_builder"
    assert export_root.is_dir()
    assert (export_root / "index.json").is_file()
    assert list(export_root.glob("*/chain_plan.md"))
    assert list(export_root.glob("*/meta.json"))
    assert plan.execution_allowed is False
    assert plan.confirmed_vulnerability is False


def test_seeds_from_retained_and_variant_analysis():
    plan = build_vuln_chain_builder_plan(
        package_id="demo",
        retained_candidates=[
            {
                "candidate_id": "c1",
                "family": "mass_assignment",
                "title": "role field writable",
                "location": "models/user.py",
            }
        ],
        variant_analysis={
            "variants": [
                {
                    "variant_id": "VA-001",
                    "source_hypothesis_id": "hyp-va",
                    "family": "authorization",
                    "seed_location": "api/items.py",
                    "vuln_type": "idor",
                }
            ]
        },
    )
    assert plan.status == STATUS_READY
    assert plan.chain_count >= 2
    origins = {c.origin for c in plan.chains}
    assert plan.execution_allowed is False
    assert origins  # at least one origin present


def test_bridge_attach_and_mev_signal():
    bridged = attach_vuln_chain_builder_to_bridge_result(
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
    assert bridged["vuln_chain_builder_present"] is True
    assert bridged["vuln_chain_builder_status"] == STATUS_READY
    assert bridged["vuln_chain_builder_chain_count"] >= 1
    assert bridged["submission_blocked"] is True
    assert bridged["execution_allowed"] is False
    assert bridged["confirmed_vulnerability"] is False

    sig = signal_from_vuln_chain_builder(bridged["vuln_chain_builder"])
    assert sig is not None
    assert sig["status"] == "advisory"
    assert sig["supports_candidate"] is False

    bad = signal_from_vuln_chain_builder(
        {**bridged["vuln_chain_builder"], "execution_allowed": True}
    )
    assert bad["status"] == "blocked"


def test_scheduler_includes_t013c():
    plan = build_industrial_scheduler_plan(
        context={
            "vuln_chain_builder": {"status": "ready"},
            "source_hypotheses": [{"hypothesis_id": "h1"}],
            "variant_analysis": {"status": "ready"},
        }
    )
    by_id = {t.task_id: t for t in plan.dag_tasks}
    assert "T-013c" in by_id
    assert by_id["T-013c"].agent == "vuln_chain_builder_agent"
    assert by_id["T-013c"].execution_allowed is False
    assert by_id["T-013c"].requires_human_review is True
    assert "T-013" in by_id["T-013c"].depends_on
    assert "T-013b" in by_id["T-013c"].depends_on
    batch_ids = {b.batch_id for b in plan.parallel_batches}
    assert "B-010c" in batch_ids
    assert ENGINE_VULN_CHAIN_BUILDER == "vuln_chain_builder"
    assert "T-013c" in by_id["T-014"].depends_on


def test_package_ingest_ssrf_retain_stays_safe():
    plan = build_vuln_chain_builder_plan(package_root=PKG_SSRF)
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
