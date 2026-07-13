from __future__ import annotations

from pathlib import Path

from app.human_review_approvals import (
    APPROVAL_KIND_PATCH,
    STATUS_APPROVED,
    build_human_review_approval,
    decide_human_review_approval,
)
from app.industrial_scheduler import build_industrial_scheduler_plan
from app.patch_agent import (
    STATUS_LOOP_COMPLETED,
    STATUS_LOOP_EMPTY,
    STATUS_LOOP_SKIPPED_ALL_NA,
    attach_patch_industrial_loop_to_bridge_result,
    build_minimal_diff_sketch,
    build_regression_validation_plan,
    run_patch_industrial_loop,
    sniff_local_code_context,
)
from app.patch_suggestion import STATUS_ADVISORY, STATUS_NOT_APPLICABLE


ROOT = Path(__file__).resolve().parents[3]
PKG_SSRF = ROOT / "authorized_packages" / "my-local-ssrf-retain"
PKG_CAL = ROOT / "authorized_packages" / "my-gh-cal-ssrf"


def test_empty_loop():
    result = run_patch_industrial_loop(package_id="empty")
    assert result.status == STATUS_LOOP_EMPTY
    assert result.item_count == 0
    assert result.auto_pr_allowed is False
    assert result.patch_ready is False
    assert result.execution_allowed is False
    assert result.report_submission_allowed is False
    assert result.confirmed_vulnerability is False
    assert result.live_validation_executed is False


def test_ssrf_retain_loop_has_sink_context_and_sketch():
    result = run_patch_industrial_loop(
        package_root=PKG_SSRF,
        package_id="my-local-ssrf-retain",
        drafts=[
            {
                "candidate_id": "H-1",
                "vuln_type": "ssrf",
                "root_cause_id": "missing_ssrf_validation:deliver_local_lab_webhook",
                "affected_code_path": "code:code.ts:deliver_local_lab_webhook",
                "route": {"method": "POST", "path": "/local/lab/webhooks/deliver"},
                "multi_engine_verdict": {"status": "local_static_consistent"},
            }
        ],
    )
    assert result.status == STATUS_LOOP_COMPLETED
    assert result.advisory_count == 1
    item = result.items[0]
    assert item.status == STATUS_ADVISORY
    assert item.family == "ssrf"
    assert item.sink_present is True
    assert item.minimal_diff_sketch
    assert any("validate_url_for_ssrf" in line for line in item.minimal_diff_sketch)
    assert item.regression_validation_plan
    assert all(step.auto_execute is False for step in item.regression_validation_plan)
    assert all(step.network_access is False for step in item.regression_validation_plan)
    assert all(step.live_validation is False for step in item.regression_validation_plan)
    assert item.patch_ready is False
    assert item.auto_pr_allowed is False
    assert item.report_submission_allowed is False
    assert result.network_access is False
    assert result.live_validation_executed is False


def test_false_positive_verdict_all_na():
    result = run_patch_industrial_loop(
        package_root=PKG_CAL,
        package_id="my-gh-cal-ssrf",
        multi_engine_verdicts=[
            {
                "candidate_id": "H-9",
                "vuln_type": "ssrf",
                "root_cause_id": "missing_ssrf_validation:x",
                "status": "false_positive_likely",
            }
        ],
    )
    assert result.status == STATUS_LOOP_SKIPPED_ALL_NA
    assert result.not_applicable_count == 1
    assert result.items[0].status == STATUS_NOT_APPLICABLE
    assert result.auto_pr_allowed is False


def test_patch_review_acceptance_context_only():
    req = build_human_review_approval(
        approval_kind=APPROVAL_KIND_PATCH,
        package_id="my-local-ssrf-retain",
        candidate_id="H-1",
        status="requested",
    )
    approved = decide_human_review_approval(
        req, decision="approved", actor="reviewer", reason="advisory ok"
    )
    assert approved.status == STATUS_APPROVED
    result = run_patch_industrial_loop(
        package_root=PKG_SSRF,
        package_id="my-local-ssrf-retain",
        drafts=[
            {
                "candidate_id": "H-1",
                "vuln_type": "ssrf",
                "root_cause_id": "missing_ssrf_validation:deliver",
            }
        ],
        human_approvals=[approved.model_dump()],
    )
    item = result.items[0]
    assert item.patch_review_accepted is True
    assert item.human_patch_reviewed is True
    # Acceptance never unlocks patch_ready / auto_pr
    assert item.patch_ready is False
    assert item.auto_pr_allowed is False
    assert result.patch_ready is False


def test_diff_sketch_and_regression_helpers():
    sketch = build_minimal_diff_sketch(family="injection", code_path="db.py")
    assert any("execute" in line for line in sketch)
    plan = build_regression_validation_plan(
        family="ssrf",
        candidate_id="H-1",
        suggestion={
            "regression_tests": [
                {"title": "Block private IP", "intent": "metadata host denied"}
            ]
        },
    )
    assert len(plan) >= 3
    assert plan[-1].method == "safety_stop"
    assert all(s.auto_execute is False for s in plan)


def test_sniff_ssrf_package_finds_fetch():
    hits = sniff_local_code_context(PKG_SSRF, family="ssrf", code_path="inputs/code.ts")
    assert hits
    assert any(h.polarity == "sink_present" for h in hits)


def test_attach_bridge_enriches_drafts():
    bridge = {
        "package_id": "my-local-ssrf-retain",
        "package_root": str(PKG_SSRF),
        "drafts": [
            {
                "candidate_id": "H-1",
                "vuln_type": "ssrf",
                "root_cause_id": "missing_ssrf_validation:deliver",
                "affected_code_path": "code:code.ts:deliver",
                "route": {"method": "POST", "path": "/local/lab/webhooks/deliver"},
                "report_draft": {"title": "SSRF"},
                "patch_suggestion": {
                    "status": STATUS_ADVISORY,
                    "candidate_id": "H-1",
                    "vuln_type": "ssrf",
                    "root_cause_id": "missing_ssrf_validation:deliver",
                    "suggested_changes": ["Add URL validation"],
                    "regression_tests": [
                        {"title": "deny private", "intent": "block metadata"}
                    ],
                    "auto_pr_allowed": False,
                    "patch_ready": False,
                },
                "multi_engine_verdict": {"status": "local_static_consistent"},
            }
        ],
        "multi_engine_verdicts": [],
        "patch_suggestions": [],
        "submission_blocked": True,
    }
    out = attach_patch_industrial_loop_to_bridge_result(bridge, package_root=PKG_SSRF)
    assert out["patch_industrial_loop_present"] is True
    assert out["patch_industrial_loop_status"] == STATUS_LOOP_COMPLETED
    assert out["patch_industrial_loop_advisory_count"] == 1
    assert out["patch_ready"] is False
    assert out["auto_pr_allowed"] is False
    assert out["pr_opened"] is False
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert out["submission_blocked"] is True
    draft = out["drafts"][0]
    assert "patch_industrial_loop_item" in draft
    assert draft["patch_industrial_loop_item"]["auto_pr_allowed"] is False
    assert "patch_diff_sketch" in draft["report_draft"]


def test_scheduler_has_patch_loop_task():
    plan = build_industrial_scheduler_plan(
        {
            "scope": {"allowed": True},
            "hypotheses": [
                {
                    "finding_id": "H-001",
                    "vuln_type": "ssrf",
                    "severity": "high",
                    "affected_endpoint": "POST /hooks",
                    "status": "unverified_hypothesis",
                }
            ],
        }
    )
    by_id = {t.task_id: t for t in plan.dag_tasks}
    assert "T-008b" in by_id
    assert by_id["T-008b"].agent == "patch_industrial_loop"
    assert by_id["T-008b"].execution_allowed is False
    assert by_id["T-008b"].requires_human_review is True
    assert by_id["T-008b"].depends_on == ["T-008"]
    batch_ids = {b.batch_id: b.task_ids for b in plan.parallel_batches}
    assert "B-005b" in batch_ids
    assert "T-008b" in batch_ids["B-005b"]