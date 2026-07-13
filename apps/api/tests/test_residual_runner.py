from __future__ import annotations

from pathlib import Path

from app.human_review_approvals import (
    APPROVAL_KIND_RESIDUAL,
    STATUS_APPROVED,
    build_human_review_approval,
    decide_human_review_approval,
)
from app.industrial_scheduler import build_industrial_scheduler_plan
from app.residual_runner import (
    STATUS_COMPLETED,
    STATUS_SKIPPED_NO_APPROVAL,
    STATUS_SKIPPED_REJECTED,
    attach_residual_runner_to_bridge_result,
    build_residual_probe_plan,
    run_residual_probes,
)


ROOT = Path(__file__).resolve().parents[3]
PKG_SSRF = ROOT / "authorized_packages" / "my-local-ssrf-retain"
PKG_CAL = ROOT / "authorized_packages" / "my-gh-cal-ssrf"


def test_probe_plan_from_items_never_network():
    plans = build_residual_probe_plan(
        [
            {"item_id": "R1", "question": "Is SSRF guard present before fetch?"},
            {"item_id": "R2", "question": "Is ownership enforced?"},
        ],
        candidate_id="H-1",
    )
    assert len(plans) == 2
    assert all(p.network_access is False for p in plans)
    assert all(p.live_validation is False for p in plans)
    assert all(p.requires_human_approval is True for p in plans)
    assert "ssrf_validate_url" in plans[0].control_tokens


def test_run_without_approval_is_plan_only():
    result = run_residual_probes(package_root=PKG_SSRF, candidate_id="H-1")
    assert result.status == STATUS_SKIPPED_NO_APPROVAL
    assert result.probes_planned >= 1
    assert result.probes_completed == 0
    assert result.execution_allowed is False
    assert result.validation_allowed is False
    assert result.report_submission_allowed is False
    assert result.confirmed_vulnerability is False
    assert result.network_access is False
    assert result.live_validation_executed is False


def test_run_with_approval_local_static_ssrf_retain():
    req = build_human_review_approval(
        approval_kind=APPROVAL_KIND_RESIDUAL,
        package_id="my-local-ssrf-retain",
        candidate_id="H-1",
        status="requested",
    )
    approved = decide_human_review_approval(
        req, decision="approved", actor="reviewer", reason="local residual ok"
    )
    assert approved.status == STATUS_APPROVED

    result = run_residual_probes(
        package_root=PKG_SSRF,
        package_id="my-local-ssrf-retain",
        candidate_id="H-1",
        human_approval=approved,
    )
    assert result.status == STATUS_COMPLETED
    assert result.probes_completed >= 1
    assert result.open_static_gaps >= 1  # teaching sink without guard
    assert result.execution_allowed is False
    assert result.report_submission_allowed is False
    assert result.confirmed_vulnerability is False
    assert result.network_access is False
    assert result.live_validation_executed is False
    assert any(p.control_absent is True for p in result.probe_results)


def test_run_with_approval_cal_ssrf_guards_present():
    approved = build_human_review_approval(
        approval_kind=APPROVAL_KIND_RESIDUAL,
        package_id="my-gh-cal-ssrf",
        status="approved",
    )
    result = run_residual_probes(
        package_root=PKG_CAL,
        human_approval=approved,
    )
    assert result.status == STATUS_COMPLETED
    assert result.control_hits >= 1
    assert result.execution_allowed is False
    assert result.confirmed_vulnerability is False


def test_rejected_approval_skips_probes():
    rejected = build_human_review_approval(
        approval_kind=APPROVAL_KIND_RESIDUAL,
        status="rejected_fp",
        package_id="pkg",
    )
    result = run_residual_probes(package_root=PKG_SSRF, human_approval=rejected)
    assert result.status == STATUS_SKIPPED_REJECTED
    assert result.probes_completed == 0
    assert result.execution_allowed is False


def test_attach_never_unlocks_without_or_with_approval(tmp_path: Path):
    # package with residual checklist + approved residual_review
    extract = tmp_path / "_extract"
    extract.mkdir()
    (extract / "RESIDUAL_CHECKLIST.md").write_text(
        "| ID | Question | Static status |\n| --- | --- | --- |\n| T-R1 | fetch sink without guard? | **not checked** |\n",
        encoding="utf-8",
    )
    (tmp_path / "inputs").mkdir()
    (tmp_path / "inputs" / "code.ts").write_text(
        "async function send(url: string) { return fetch(url); }\n",
        encoding="utf-8",
    )
    (tmp_path / "inputs" / "human_review_approvals.json").write_text(
        '{"approvals":[{"approval_kind":"residual_review","status":"approved","package_id":"tmp","candidate_id":"H-1"}]}',
        encoding="utf-8",
    )

    bridged = attach_residual_runner_to_bridge_result(
        {
            "package_id": "tmp",
            "drafts": [
                {
                    "candidate_id": "H-1",
                    "execution_allowed": True,
                    "report_submission_allowed": True,
                    "confirmed_vulnerability": True,
                }
            ],
            "submission_blocked": True,
            "execution_allowed": True,
            "report_submission_allowed": True,
        },
        package_root=tmp_path,
    )
    assert bridged["execution_allowed"] is False
    assert bridged["validation_allowed"] is False
    assert bridged["report_submission_allowed"] is False
    assert bridged["confirmed_vulnerability"] is False
    assert bridged["submission_blocked"] is True
    assert bridged["residual_runner_present"] is True
    assert bridged["residual_runner_status"] == STATUS_COMPLETED
    assert bridged["residual_runner_completed_count"] >= 1
    draft = bridged["drafts"][0]
    assert draft["execution_allowed"] is False
    assert draft["report_submission_allowed"] is False
    assert draft["confirmed_vulnerability"] is False
    assert draft["residual_runner"]["execution_allowed"] is False


def test_attach_without_approval_stays_skipped():
    bridged = attach_residual_runner_to_bridge_result(
        {
            "package_id": "pkg",
            "drafts": [{"candidate_id": "H-9"}],
            "submission_blocked": True,
        },
        package_root=PKG_SSRF,
    )
    assert bridged["residual_runner_present"] is True
    assert bridged["residual_runner_status"] == STATUS_SKIPPED_NO_APPROVAL
    assert bridged["execution_allowed"] is False
    assert bridged["report_submission_allowed"] is False


def test_industrial_scheduler_includes_residual_runner():
    plan = build_industrial_scheduler_plan(
        {
            "scope": {"allowed": True},
            "hypotheses": [
                {
                    "finding_id": "H-001",
                    "vuln_type": "ssrf",
                    "severity": "high",
                    "status": "unverified_hypothesis",
                }
            ],
        }
    )
    by_id = {task.task_id: task for task in plan.dag_tasks}
    assert "T-007b" in by_id
    assert by_id["T-007b"].agent == "residual_runner"
    assert by_id["T-007b"].depends_on == ["T-007"]
    assert by_id["T-007b"].execution_allowed is False
    assert by_id["T-007b"].requires_human_review is True
    assert by_id["T-008"].depends_on == ["T-007b"]
    assert any(batch.batch_id == "B-004b" for batch in plan.parallel_batches)
    assert "residual_runner" in {task.agent for task in plan.dag_tasks}