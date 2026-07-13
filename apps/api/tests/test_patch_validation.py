from pathlib import Path

from app.industrial_scheduler import build_industrial_scheduler_plan
from app.multi_engine_verifier import (
    ENGINE_PATCH_VALIDATION,
    build_multi_engine_verdict,
    signal_from_patch_validation,
)
from app.patch_validation import (
    STATUS_EMPTY,
    STATUS_PACKAGE_MISSING,
    STATUS_READY,
    STATUS_WAITING_FIX,
    STATUS_WRITTEN,
    attach_patch_validation_to_bridge_result,
    run_patch_validation,
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
            }
        ],
        "human_residual_gates": [
            {
                "candidate_id": "H-001",
                "status": "ready_for_human_review",
                "report_submission_allowed": False,
                "execution_allowed": False,
                "confirmed_vulnerability": False,
            }
        ],
        "patch_industrial_loop": {
            "status": "plan_ready",
            "items": [
                {
                    "item_id": "P-1",
                    "candidate_id": "H-001",
                    "root_cause_id": "RC-ssrf",
                    "title": "Centralize SSRF allowlist",
                    "family": "ssrf",
                }
            ],
        },
        "patch_suggestions": [
            {
                "candidate_id": "H-001",
                "suggestion_id": "S-1",
                "title": "Validate outbound URL scheme/host",
            }
        ],
        "crash_regression": {
            "status": "ready",
            "suggestions": [
                {
                    "suggestion_id": "R-1",
                    "candidate_id": "H-001",
                    "title": "Regression for decode crash",
                }
            ],
        },
        "multi_engine_deep": True,
    }
    base.update(extra)
    return base


def test_patch_validation_derives_from_loop():
    result = run_patch_validation(bridge_result=_safe_bridge())
    assert result.status == STATUS_READY
    assert result.item_count >= 1
    assert result.ready_item_count >= 1
    assert result.step_count >= 1
    assert result.execution_allowed is False
    assert result.report_submission_allowed is False
    assert result.confirmed_vulnerability is False
    assert result.patch_ready is False
    assert result.live_validation_allowed is False
    assert result.auto_pr_allowed is False
    assert result.network_access is False
    for item in result.items:
        assert item.patch_ready is False
        assert item.execution_allowed is False
        assert item.live_validation_allowed is False
        assert item.auto_pr_allowed is False
        assert item.approval_required is True
        for step in item.steps:
            assert step.execution_allowed is False
            assert step.network_access is False
            assert step.live_validation is False
            assert step.auto_execute is False


def test_patch_validation_offline_artifact(tmp_path: Path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    payload = (
        '{"items":[{"item_id":"pv-offline-1","candidate_id":"H-009",'
        '"status":"planned_ready_for_human_recheck",'
        '"steps":[{"step_id":"PV-offline-01","title":"Static recheck after fix",'
        '"method":"human_local_static_recheck"}]}]}'
    )
    (inputs / "patch_validation.json").write_text(payload, encoding="utf-8")
    result = run_patch_validation(
        package_root=tmp_path,
        package_id="demo-pkg",
        bridge_result=_safe_bridge(
            patch_industrial_loop={},
            patch_suggestions=[],
            crash_regression={},
        ),
    )
    assert result.status in {STATUS_READY, STATUS_WAITING_FIX}
    assert result.offline_artifact_count >= 1
    item_ids = {i.item_id for i in result.items}
    assert "pv-offline-1" in item_ids
    assert result.patch_ready is False
    assert result.live_validation_allowed is False


def test_waiting_when_no_fix_artifacts():
    result = run_patch_validation(
        bridge_result=_safe_bridge(
            patch_industrial_loop={},
            patch_suggestions=[],
            crash_regression={},
            drafts=[],
        )
    )
    assert result.status in {STATUS_EMPTY, STATUS_WAITING_FIX, STATUS_READY}
    assert result.execution_allowed is False
    assert result.patch_ready is False


def test_export_under_package(tmp_path: Path):
    result = run_patch_validation(
        package_root=tmp_path,
        package_id="demo-pkg",
        bridge_result=_safe_bridge(),
        human_allow_export_write=True,
    )
    assert result.status == STATUS_WRITTEN
    assert result.export_written is True
    assert result.export_count >= 1
    export_root = tmp_path / "_export" / "patch_validation"
    assert export_root.is_dir()
    stamps = list(export_root.iterdir())
    assert stamps
    assert (stamps[0] / "index.json").is_file()
    assert (stamps[0] / "README.md").is_file()


def test_bridge_attach_forces_safety():
    bridge = _safe_bridge(
        execution_allowed=True,
        report_submission_allowed=True,
        confirmed_vulnerability=True,
        submission_blocked=False,
        validation_allowed=True,
    )
    out = attach_patch_validation_to_bridge_result(bridge)
    assert out["patch_validation_present"] is True
    assert out["execution_allowed"] is False
    assert out["validation_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert out["submission_blocked"] is True
    assert out["patch_validation_patch_ready"] is False
    assert out["patch_validation"]["patch_ready"] is False
    assert out["patch_validation"]["live_validation_allowed"] is False
    assert out["patch_validation"]["auto_pr_allowed"] is False


def test_mev_signal_and_engine():
    payload = run_patch_validation(bridge_result=_safe_bridge()).to_dict()
    sig = signal_from_patch_validation(payload)
    assert sig is not None
    assert sig["status"] == "ready"
    unsafe = signal_from_patch_validation({**payload, "patch_ready": True})
    assert unsafe["status"] == "blocked"
    unsafe2 = signal_from_patch_validation({**payload, "live_validation_allowed": True})
    assert unsafe2["status"] == "blocked"
    verdict = build_multi_engine_verdict(
        candidate={"candidate_id": "H-001"},
        patch_validation_signal=sig,
    )
    engines = {e.engine for e in verdict.engines}
    assert ENGINE_PATCH_VALIDATION in engines
    assert verdict.confirmed_vulnerability is False
    assert verdict.execution_allowed is False
    assert verdict.report_submission_allowed is False


def test_scheduler_includes_t012():
    plan = build_industrial_scheduler_plan(
        {
            "scope": {"allowed": True, "reason": "authorized local repository"},
            "hypotheses": [],
            "crs_fuzzing": {"parser_candidates": [{"symbol_name": "decode_frame"}]},
            "authorized_bug_bounty": {"human_gate": {"status": "required"}},
        }
    )
    task_by_id = {task.task_id: task for task in plan.dag_tasks}
    assert "T-012" in task_by_id
    assert task_by_id["T-012"].agent == "patch_validation_agent"
    assert task_by_id["T-012"].execution_allowed is False
    assert task_by_id["T-012"].requires_human_review is True
    assert "T-010" in task_by_id["T-012"].depends_on
    batches = {b.batch_id: b.task_ids for b in plan.parallel_batches}
    assert batches.get("B-009") == ["T-012"]
    assert plan.patch_validation.execution_allowed is False
    assert plan.patch_validation.approval_required is True
