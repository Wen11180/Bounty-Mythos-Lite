from pathlib import Path

from app.continuous_scan import (
    STATUS_EMPTY,
    STATUS_PACKAGE_MISSING,
    STATUS_READY,
    STATUS_WRITTEN,
    attach_continuous_scan_to_bridge_result,
    run_continuous_scan,
)
from app.industrial_scheduler import build_industrial_scheduler_plan
from app.multi_engine_verifier import (
    ENGINE_CONTINUOUS_SCAN,
    build_multi_engine_verdict,
    signal_from_continuous_scan,
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
        "multi_engine_verdicts": [
            {
                "candidate_id": "H-001",
                "status": "needs_human_review",
                "confirmed_vulnerability": False,
                "execution_allowed": False,
            }
        ],
        "multi_engine_deep": True,
        "residual_checklist_present": True,
    }
    base.update(extra)
    return base


def test_continuous_scan_derives_jobs():
    result = run_continuous_scan(bridge_result=_safe_bridge())
    assert result.status == STATUS_READY
    assert result.job_count >= 1
    assert result.watch_path_count >= 1
    assert result.execution_allowed is False
    assert result.report_submission_allowed is False
    assert result.confirmed_vulnerability is False
    assert result.auto_scan_allowed is False
    assert result.network_access is False
    assert result.live_validation is False
    for job in result.jobs:
        assert job.execution_allowed is False
        assert job.network_access is False
        assert job.auto_execute is False
        assert job.requires_human_approval is True


def test_continuous_scan_offline_config(tmp_path: Path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    payload = (
        '{"jobs":[{"job_id":"CS-offline-1","title":"Offline authorized reaudit plan",'
        '"method":"human_local_static_reaudit","triggers":["manual"]}],'
        '"watch_paths":[{"path":"inputs/api.json","reason":"api_surface"}]}'
    )
    (inputs / "continuous_scan.json").write_text(payload, encoding="utf-8")
    result = run_continuous_scan(
        package_root=tmp_path,
        package_id="demo-pkg",
        bridge_result=_safe_bridge(),
    )
    assert result.status == STATUS_READY
    assert result.offline_config_present is True
    job_ids = {j.job_id for j in result.jobs}
    assert "CS-offline-1" in job_ids
    assert result.auto_scan_allowed is False


def test_continuous_scan_forces_safe_cadence(tmp_path: Path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    payload = (
        '{"cadence":"every_5_minutes_auto","auto_scan":true,"network_access":true}'
    )
    (inputs / "scan_cadence.json").write_text(payload, encoding="utf-8")
    result = run_continuous_scan(package_root=tmp_path, bridge_result=_safe_bridge())
    assert result.cadence == "manual_or_approved_ci_only"
    assert result.auto_scan_allowed is False
    assert result.network_access is False


def test_export_under_package(tmp_path: Path):
    result = run_continuous_scan(
        package_root=tmp_path,
        package_id="demo-pkg",
        bridge_result=_safe_bridge(),
        human_allow_export_write=True,
    )
    assert result.status == STATUS_WRITTEN
    assert result.export_written is True
    assert result.export_count >= 1
    export_root = tmp_path / "_export" / "continuous_scan"
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
    out = attach_continuous_scan_to_bridge_result(bridge)
    assert out["continuous_scan_present"] is True
    assert out["execution_allowed"] is False
    assert out["validation_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert out["submission_blocked"] is True
    assert out["continuous_scan_auto_scan_allowed"] is False
    assert out["continuous_scan"]["auto_scan_allowed"] is False
    assert out["continuous_scan"]["network_access"] is False


def test_empty_or_ready_without_rich_context():
    result = run_continuous_scan(bridge_result={"package_id": "empty"})
    assert result.status in {STATUS_EMPTY, STATUS_READY, STATUS_PACKAGE_MISSING}
    assert result.execution_allowed is False
    assert result.auto_scan_allowed is False


def test_mev_signal_and_engine():
    payload = run_continuous_scan(bridge_result=_safe_bridge()).to_dict()
    sig = signal_from_continuous_scan(payload)
    assert sig is not None
    assert sig["status"] == "ready"
    unsafe = signal_from_continuous_scan({**payload, "auto_scan_allowed": True})
    assert unsafe["status"] == "blocked"
    verdict = build_multi_engine_verdict(
        candidate={"candidate_id": "H-001"},
        continuous_scan_signal=sig,
    )
    engines = {e.engine for e in verdict.engines}
    assert ENGINE_CONTINUOUS_SCAN in engines
    assert verdict.confirmed_vulnerability is False
    assert verdict.execution_allowed is False
    assert verdict.report_submission_allowed is False


def test_scheduler_includes_t011():
    plan = build_industrial_scheduler_plan(
        {
            "scope": {"allowed": True, "reason": "authorized local repository"},
            "hypotheses": [],
            "crs_fuzzing": {"parser_candidates": [{"symbol_name": "decode_frame"}]},
            "authorized_bug_bounty": {"human_gate": {"status": "required"}},
        }
    )
    task_by_id = {task.task_id: task for task in plan.dag_tasks}
    assert "T-011" in task_by_id
    assert task_by_id["T-011"].agent == "continuous_scan_agent"
    assert task_by_id["T-011"].execution_allowed is False
    assert task_by_id["T-011"].requires_human_review is True
    assert "T-010" in task_by_id["T-011"].depends_on
    batches = {b.batch_id: b.task_ids for b in plan.parallel_batches}
    assert batches.get("B-008") == ["T-011"]
    assert plan.continuous_scan.execution_allowed is False
    assert plan.continuous_scan.cadence == "manual_or_approved_ci_only"
