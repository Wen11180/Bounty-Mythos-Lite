from pathlib import Path

from app.human_review_approvals import APPROVAL_KIND_PATCH, STATUS_APPROVED
from app.industrial_scheduler import build_industrial_scheduler_plan
from app.patch_pr_workflow import (
    STATUS_BLOCKED_REVIEW,
    STATUS_EMPTY,
    STATUS_EXPORTED,
    STATUS_READY,
    STATUS_SKIPPED,
    attach_patch_pr_workflow_to_bridge_result,
    build_patch_pr_workflow,
)


ROOT = Path(__file__).resolve().parents[3]
PKG_SSRF = ROOT / "authorized_packages" / "my-local-ssrf-retain"


def _advisory_loop_item(candidate_id: str = "H-1") -> dict:
    return {
        "item_id": f"PLOOP-{candidate_id}",
        "candidate_id": candidate_id,
        "family": "ssrf",
        "status": "advisory_patch_suggestion",
        "patch_review_accepted": False,
        "minimal_diff_sketch": [
            "# deny private / metadata hosts before fetch",
            "if is_private_or_metadata(url): raise ValueError('blocked')",
        ],
        "regression_validation_plan": [
            {"step": "static_recheck", "auto_execute": False},
            {"step": "safety_stop", "auto_execute": False},
        ],
        "suggestion": {
            "status": "advisory_patch_suggestion",
            "candidate_id": candidate_id,
            "vuln_type": "ssrf",
            "root_cause_summary": "Outbound fetch lacks private-IP / metadata host validation.",
            "suggested_changes": [
                "Validate URL scheme/host before fetch",
                "Block link-local metadata",
            ],
            "regression_tests": [
                {"title": "deny private IP", "intent": "metadata host denied"}
            ],
            "affected_code_path": "code:code.ts:deliver",
            "affected_route": "POST /local/lab/webhooks/deliver",
        },
    }


def test_build_empty_without_sources():
    result = build_patch_pr_workflow(package_id="pkg-empty")
    assert result.status == STATUS_EMPTY
    assert result.item_count == 0
    assert result.auto_pr_allowed is False
    assert result.pr_opened is False
    assert result.patch_ready is False
    assert result.execution_allowed is False
    assert result.report_submission_allowed is False
    assert result.git_operations is False
    assert "no_auto_open_pull_request" in result.safety_invariants


def test_build_skipped_when_package_root_missing(tmp_path: Path):
    missing = tmp_path / "no-such-package"
    result = build_patch_pr_workflow(package_root=missing, package_id="missing")
    assert result.status == STATUS_SKIPPED
    assert result.auto_pr_allowed is False


def test_blocked_until_patch_review_without_approval_or_write():
    result = build_patch_pr_workflow(
        package_root=PKG_SSRF,
        package_id="my-local-ssrf-retain",
        patch_industrial_loop={"items": [_advisory_loop_item()]},
        human_allow_export_write=False,
    )
    assert result.status == STATUS_BLOCKED_REVIEW
    assert result.item_count == 1
    assert result.ready_count == 0
    assert result.blocked_review_count == 1
    item = result.items[0]
    assert item.status == STATUS_BLOCKED_REVIEW
    assert item.branch_name.startswith("mythos/advisory-fix/ssrf/")
    assert item.files
    assert any(f.relative_path.endswith("PR_BODY.md") for f in item.files)
    assert any(f.relative_path.endswith("minimal_diff_sketch.txt") for f in item.files)
    assert item.auto_pr_allowed is False
    assert item.pr_opened is False
    assert item.patch_ready is False
    assert result.export_written is False


def test_ready_with_patch_review_approval_no_write():
    result = build_patch_pr_workflow(
        package_root=PKG_SSRF,
        package_id="my-local-ssrf-retain",
        patch_industrial_loop={"items": [_advisory_loop_item()]},
        human_approvals=[
            {
                "approval_kind": APPROVAL_KIND_PATCH,
                "status": STATUS_APPROVED,
                "package_id": "my-local-ssrf-retain",
                "candidate_id": "H-1",
            }
        ],
        human_allow_export_write=False,
    )
    assert result.status == STATUS_READY
    assert result.ready_count == 1
    assert result.items[0].patch_review_accepted is True
    assert result.items[0].export_write_allowed is False
    assert result.export_written is False
    assert result.auto_pr_allowed is False
    assert result.patch_ready is False


def test_export_write_with_human_flag(tmp_path: Path):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "package.json").write_text(
        '{"package_id": "tmp-export-pkg"}', encoding="utf-8"
    )
    result = build_patch_pr_workflow(
        package_root=pkg,
        package_id="tmp-export-pkg",
        patch_industrial_loop={"items": [_advisory_loop_item("H-9")]},
        human_allow_export_write=True,
    )
    assert result.status == STATUS_EXPORTED
    assert result.export_written is True
    assert result.exported_count == 1
    assert result.ready_count == 1
    item = result.items[0]
    assert item.status == STATUS_EXPORTED
    assert item.export_write_allowed is True
    export_dir = pkg / "_export" / "patch_pr" / item.item_id
    assert (export_dir / "README.md").is_file()
    assert (export_dir / "PR_BODY.md").is_file()
    assert (export_dir / "CHECKLIST.md").is_file()
    assert (export_dir / "minimal_diff_sketch.txt").is_file()
    meta = (export_dir / "meta.json").read_text(encoding="utf-8")
    assert "auto_pr_allowed" in meta
    assert "false" in meta.lower()
    assert result.auto_pr_allowed is False
    assert result.pr_opened is False
    assert result.patch_ready is False
    assert result.git_operations is False


def test_fallback_from_patch_suggestions_only():
    result = build_patch_pr_workflow(
        package_id="sug-only",
        patch_suggestions=[
            {
                "status": "advisory_patch_suggestion",
                "candidate_id": "H-2",
                "vuln_type": "ssrf",
                "root_cause_summary": "missing host validation",
                "suggested_changes": ["block private hosts"],
                "affected_route": "POST /hooks",
            }
        ],
    )
    assert result.item_count == 1
    assert result.items[0].candidate_id == "H-2"
    assert result.status == STATUS_BLOCKED_REVIEW


def test_skips_not_applicable_sources():
    result = build_patch_pr_workflow(
        package_id="na-pkg",
        patch_industrial_loop={
            "items": [
                {
                    "item_id": "skip-1",
                    "candidate_id": "H-na",
                    "status": "not_applicable_refuted_or_unverified",
                    "suggestion": {"status": "not_applicable_refuted_or_unverified"},
                }
            ]
        },
        patch_suggestions=[
            {
                "status": "skipped_no_candidate",
                "candidate_id": "H-skip",
            }
        ],
    )
    assert result.status == STATUS_EMPTY
    assert result.item_count == 0


def test_safety_floor_on_to_dict():
    result = build_patch_pr_workflow(
        package_id="safety",
        patch_industrial_loop={"items": [_advisory_loop_item()]},
        human_allow_export_write=True,
    )
    payload = result.to_dict()
    assert payload["auto_pr_allowed"] is False
    assert payload["pr_opened"] is False
    assert payload["patch_ready"] is False
    assert payload["execution_allowed"] is False
    assert payload["validation_allowed"] is False
    assert payload["report_submission_allowed"] is False
    assert payload["confirmed_vulnerability"] is False
    assert payload["git_operations"] is False
    assert payload["network_access"] is False
    for item in payload["items"]:
        assert item["auto_pr_allowed"] is False
        assert item["pr_opened"] is False
        assert item["patch_ready"] is False


def test_attach_bridge_strips_content_and_forces_safety():
    bridge = {
        "package_id": "my-local-ssrf-retain",
        "package_root": str(PKG_SSRF),
        "drafts": [],
        "patch_industrial_loop": {"items": [_advisory_loop_item()]},
        "patch_suggestions": [],
        "human_review_approvals": [],
        "submission_blocked": True,
    }
    out = attach_patch_pr_workflow_to_bridge_result(
        bridge,
        package_root=PKG_SSRF,
        human_allow_export_write=False,
    )
    assert out["patch_pr_workflow_present"] is True
    assert out["patch_pr_workflow_status"] == STATUS_BLOCKED_REVIEW
    assert out["patch_pr_workflow_item_count"] == 1
    assert out["auto_pr_allowed"] is False
    assert out["pr_opened"] is False
    assert out["patch_ready"] is False
    assert out["execution_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert out["submission_blocked"] is True
    payload = out["patch_pr_workflow"]
    for item in payload["items"]:
        for f in item.get("files") or []:
            assert "content" not in f
            assert "content_preview" in f or f.get("bytes_planned") is not None


def test_scheduler_has_patch_pr_workflow_task():
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
            "patch_industrial_loop": {"items": [_advisory_loop_item()]},
        }
    )
    by_id = {t.task_id: t for t in plan.dag_tasks}
    assert "T-008c" in by_id
    task = by_id["T-008c"]
    assert task.agent == "patch_pr_workflow"
    assert task.execution_allowed is False
    assert task.requires_human_review is True
    assert task.depends_on == ["T-008b"]
    assert task.status == "planned"
    batch_ids = {b.batch_id: b.task_ids for b in plan.parallel_batches}
    assert "B-005c" in batch_ids
    assert "T-008c" in batch_ids["B-005c"]

    plan_empty = build_industrial_scheduler_plan(
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
    by_empty = {t.task_id: t for t in plan_empty.dag_tasks}
    assert by_empty["T-008c"].status in {
        "skipped_no_patch_pr_artifacts",
        "skipped_no_patch_artifacts",
    }
