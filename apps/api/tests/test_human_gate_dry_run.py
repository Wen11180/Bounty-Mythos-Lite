from pathlib import Path

from app.human_gate_dry_run import (
    STATUS_FAILED_SAFETY,
    STATUS_READY,
    STATUS_WRITTEN,
    attach_human_gate_dry_run_to_bridge_result,
    run_human_gate_dry_run,
)
from app.industrial_scheduler import build_industrial_scheduler_plan
from app.multi_engine_verifier import (
    ENGINE_HUMAN_GATE_DRY_RUN,
    build_multi_engine_verdict,
    signal_from_human_gate_dry_run,
)


def _safe_bridge(**extra):
    base = {
        "package_id": "demo-pkg",
        "submission_blocked": True,
        "report_submission_allowed": False,
        "execution_allowed": False,
        "validation_allowed": False,
        "confirmed_vulnerability": False,
        "drafts": [],
        "human_residual_gates": [
            {
                "status": "ready_for_human_review",
                "report_submission_allowed": False,
                "execution_allowed": False,
                "confirmed_vulnerability": False,
            }
        ],
        "multi_engine_verdicts": [
            {"confirmed_vulnerability": False, "execution_allowed": False}
        ],
        "multi_engine_deep": True,
        "residual_checklist_present": True,
    }
    base.update(extra)
    return base


def test_dry_run_core_chain_ready():
    result = run_human_gate_dry_run(bridge_result=_safe_bridge())
    assert result.status == STATUS_READY
    assert result.chain_safe is True
    assert result.chain_complete is True
    assert result.fail_count == 0
    assert result.pass_count >= 6
    assert result.execution_allowed is False
    assert result.report_submission_allowed is False
    assert result.confirmed_vulnerability is False
    ids = {c.checkpoint_id for c in result.checkpoints}
    assert "HG-01-package" in ids
    assert "HG-02-submission-blocked" in ids
    assert "HG-09-global-safety-scrub" in ids


def test_dry_run_fails_on_submit_unlock():
    result = run_human_gate_dry_run(
        bridge_result=_safe_bridge(
            submission_blocked=False,
            report_submission_allowed=True,
        )
    )
    assert result.status == STATUS_FAILED_SAFETY
    assert result.fail_count >= 1
    assert result.chain_safe is False
    assert result.report_submission_allowed is False


def test_export_under_package(tmp_path: Path):
    root = tmp_path
    result = run_human_gate_dry_run(
        package_root=root,
        package_id="demo-pkg",
        bridge_result=_safe_bridge(),
        human_allow_export_write=True,
    )
    assert result.status == STATUS_WRITTEN
    assert result.export_written is True
    assert result.export_count >= 1
    export_root = root / "_export" / "human_gate_dry_run"
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
    )
    out = attach_human_gate_dry_run_to_bridge_result(bridge)
    assert out["human_gate_dry_run_present"] is True
    assert out["execution_allowed"] is False
    assert out["validation_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert out["submission_blocked"] is True
    assert out["human_gate_dry_run"]["report_submission_allowed"] is False


def test_mev_signal_and_engine():
    payload = run_human_gate_dry_run(bridge_result=_safe_bridge()).to_dict()
    sig = signal_from_human_gate_dry_run(payload)
    assert sig is not None
    assert sig["status"] == "ready"
    unsafe = signal_from_human_gate_dry_run({**payload, "report_submission_allowed": True})
    assert unsafe["status"] == "blocked"
    verdict = build_multi_engine_verdict(
        candidate={"candidate_id": "H-001"},
        human_gate_dry_run_signal=sig,
    )
    engines = {e.engine for e in verdict.engines}
    assert ENGINE_HUMAN_GATE_DRY_RUN in engines
    assert verdict.confirmed_vulnerability is False
    assert verdict.execution_allowed is False
    assert verdict.report_submission_allowed is False


def test_scheduler_includes_t009():
    plan = build_industrial_scheduler_plan(
        {
            "scope": {"allowed": True, "reason": "authorized local repository"},
            "hypotheses": [],
            "crs_fuzzing": {"parser_candidates": [{"symbol_name": "decode_frame"}]},
            "authorized_bug_bounty": {"human_gate": {"status": "required"}},
        }
    )
    task_by_id = {task.task_id: task for task in plan.dag_tasks}
    assert "T-009" in task_by_id
    assert task_by_id["T-009"].agent == "human_gate_dry_run_agent"
    assert task_by_id["T-009"].execution_allowed is False
    assert task_by_id["T-009"].requires_human_review is True
    assert "T-007" in task_by_id["T-009"].depends_on
    assert "T-006b" in task_by_id["T-009"].depends_on
    batches = {b.batch_id: b.task_ids for b in plan.parallel_batches}
    assert batches.get("B-006") == ["T-009"]
