from pathlib import Path

from app.patch_diff_learner import (
    STATUS_EMPTY,
    STATUS_READY,
    STATUS_SKIPPED,
    STATUS_WAITING,
    STATUS_WRITTEN,
    attach_patch_diff_learner_to_bridge_result,
    build_patch_diff_learner_plan,
)
from app.industrial_scheduler import build_industrial_scheduler_plan
from app.multi_engine_verifier import (
    ENGINE_PATCH_DIFF_LEARNER,
    signal_from_patch_diff_learner,
)


ROOT = Path(__file__).resolve().parents[3]
PKG_SSRF = ROOT / "authorized_packages" / "my-local-ssrf-retain"


def test_build_plan_from_patch_diff_stays_plan_only():
    plan = build_patch_diff_learner_plan(
        package_id="demo",
        patch_diff={
            "source_ref": "hyp-1",
            "linked_hypothesis_id": "hyp-1",
            "changed_files": ["src/auth.py"],
            "root_cause": "missing ownership check before update",
            "fix_strategy": "enforce actor-resource ownership at shared control point",
            "regression_test": "local static role-diff recheck on update path",
            "family": "authorization",
        },
    )

    assert plan.stage == "v4_patch_diff_learner"
    assert plan.execution_mode == "plan_only"
    assert plan.status == STATUS_READY
    assert plan.pattern_count == 1
    assert plan.patterns[0].source_ref == "hyp-1"
    assert "ownership" in plan.patterns[0].root_cause_summary
    assert plan.execution_allowed is False
    assert plan.auto_pr_allowed is False
    assert plan.patch_ready is False
    assert plan.pr_opened is False
    assert plan.network_access is False
    assert plan.live_validation is False
    assert plan.report_submission_allowed is False
    assert plan.confirmed_vulnerability is False
    assert plan.finding_promotion_allowed is False
    assert plan.human_approval_required_before_action is True
    assert plan.export_written is False
    assert "export_write_not_requested" in plan.notes
    assert "no_patch_apply" in plan.safety_invariants
    assert plan.patterns[0].execution_allowed is False
    assert plan.patterns[0].human_review_required is True


def test_safety_flags_forced_false_even_if_input_tries_true():
    payload = {
        "status": STATUS_READY,
        "patterns": [{"source_ref": "x", "execution_allowed": True}],
        "pattern_count": 1,
        "execution_allowed": True,
        "process_spawn_allowed": True,
        "network_access": True,
        "live_validation": True,
        "validation_allowed": True,
        "report_submission_allowed": True,
        "confirmed_vulnerability": True,
        "finding_promotion_allowed": True,
        "auto_pr_allowed": True,
        "patch_ready": True,
        "pr_opened": True,
    }
    out = attach_patch_diff_learner_to_bridge_result(
        {"package_id": "demo", "submission_blocked": True},
        patch_diff_learner=payload,
    )
    pdl = out["patch_diff_learner"]
    assert pdl["execution_allowed"] is False
    assert pdl["process_spawn_allowed"] is False
    assert pdl["network_access"] is False
    assert pdl["live_validation"] is False
    assert pdl["validation_allowed"] is False
    assert pdl["report_submission_allowed"] is False
    assert pdl["confirmed_vulnerability"] is False
    assert pdl["finding_promotion_allowed"] is False
    assert pdl["auto_pr_allowed"] is False
    assert pdl["patch_ready"] is False
    assert pdl["pr_opened"] is False
    assert out["execution_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["submission_blocked"] is True
    assert out["patch_diff_learner_present"] is True
    assert out["patch_ready"] is False


def test_waiting_without_diffs():
    plan = build_patch_diff_learner_plan(package_id="empty", patch_diff={})
    assert plan.status in {STATUS_WAITING, STATUS_EMPTY}
    assert plan.pattern_count == 0
    assert plan.execution_allowed is False


def test_missing_package_skipped():
    plan = build_patch_diff_learner_plan(
        package_root="Z:/does/not/exist/patch_pkg_xyz"
    )
    assert plan.status == STATUS_SKIPPED
    assert plan.execution_allowed is False


def test_flag_writes_export(tmp_path: Path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "patch_diff_sample.json").write_text(
        (
            '{"source_ref":"sample-1","changed_files":["a.py"],'
            '"root_cause":"unchecked idor","fix_strategy":"ownership gate",'
            '"regression_test":"static role matrix"}'
        ),
        encoding="utf-8",
    )
    plan = build_patch_diff_learner_plan(
        package_root=tmp_path, human_allow_export_write=True
    )
    assert plan.human_allow_export_write is True
    assert plan.status == STATUS_WRITTEN
    assert plan.pattern_count >= 1
    assert plan.export_written is True
    assert plan.export_count >= 1
    export_root = tmp_path / "_export" / "patch_diff_learner"
    assert export_root.is_dir()
    assert (export_root / "index.json").is_file()
    assert list(export_root.glob("*/pattern.md"))
    assert list(export_root.glob("*/meta.json"))
    assert plan.execution_allowed is False
    assert plan.auto_pr_allowed is False
    assert plan.patch_ready is False


def test_offline_and_industrial_loop_merge():
    loop = {
        "items": [
            {
                "item_id": "loop-1",
                "candidate_id": "c1",
                "family": "ssrf",
                "title": "url fetch without allowlist",
                "fix_strategy": "allowlist + block private ranges",
                "regression_plan": "local offline url matrix",
            }
        ]
    }
    plan = build_patch_diff_learner_plan(
        package_id="demo",
        patch_industrial_loop=loop,
        patch_suggestions=[
            {
                "suggestion_id": "sug-1",
                "candidate_id": "c2",
                "root_cause_summary": "mass assignment on role field",
                "fix_principle": "explicit allowlist of writable fields",
                "regression_suggestion": "static field matrix",
                "family": "mass_assignment",
            }
        ],
    )
    assert plan.status == STATUS_READY
    assert plan.pattern_count >= 2
    refs = {p.source_ref for p in plan.patterns}
    assert "loop-1" in refs
    assert "sug-1" in refs
    assert plan.execution_allowed is False


def test_bridge_attach_and_mev_signal():
    bridged = attach_patch_diff_learner_to_bridge_result(
        {
            "package_id": "demo",
            "submission_blocked": True,
            "patch_industrial_loop": {
                "items": [
                    {
                        "item_id": "p1",
                        "title": "authz miss",
                        "family": "authorization",
                    }
                ]
            },
        }
    )
    assert bridged["patch_diff_learner_present"] is True
    assert bridged["patch_diff_learner_status"] == STATUS_READY
    assert bridged["patch_diff_learner_pattern_count"] == 1
    assert bridged["submission_blocked"] is True
    assert bridged["execution_allowed"] is False
    assert bridged["patch_ready"] is False

    sig = signal_from_patch_diff_learner(bridged["patch_diff_learner"])
    assert sig is not None
    assert sig["status"] == "advisory"
    assert sig["supports_candidate"] is False

    bad = signal_from_patch_diff_learner(
        {**bridged["patch_diff_learner"], "patch_ready": True}
    )
    assert bad["status"] == "blocked"


def test_scheduler_includes_t008d():
    plan = build_industrial_scheduler_plan(
        context={
            "patch_diff_learner": {"status": "ready"},
            "patch_industrial_loop": {"items": [{}]},
        }
    )
    by_id = {t.task_id: t for t in plan.dag_tasks}
    assert "T-008d" in by_id
    assert by_id["T-008d"].agent == "patch_diff_learner_agent"
    assert by_id["T-008d"].execution_allowed is False
    assert by_id["T-008d"].requires_human_review is True
    assert "T-008" in by_id["T-008d"].depends_on
    assert "T-008c" in by_id["T-008d"].depends_on
    batch_ids = {b.batch_id for b in plan.parallel_batches}
    assert "B-005d" in batch_ids
    assert ENGINE_PATCH_DIFF_LEARNER == "patch_diff_learner"
    # human gate depends on T-008d
    assert "T-008d" in by_id["T-009"].depends_on


def test_package_ingest_ssrf_retain_stays_safe():
    plan = build_patch_diff_learner_plan(package_root=PKG_SSRF)
    assert plan.execution_allowed is False
    assert plan.auto_pr_allowed is False
    assert plan.patch_ready is False
    assert plan.report_submission_allowed is False
    assert plan.status in {
        STATUS_READY,
        STATUS_WAITING,
        STATUS_EMPTY,
        STATUS_WRITTEN,
        STATUS_SKIPPED,
    }
