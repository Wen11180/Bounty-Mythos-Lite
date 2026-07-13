from __future__ import annotations

from pathlib import Path

from app.intake_agent import (
    STATUS_OK,
    STATUS_SKIPPED,
    attach_intake_profile_to_bridge_result,
    build_intake_profile,
)
from app.industrial_scheduler import build_industrial_scheduler_plan


ROOT = Path(__file__).resolve().parents[3]
PKG_SSRF = ROOT / "authorized_packages" / "my-local-ssrf-retain"
PKG_GITEA = ROOT / "authorized_packages" / "my-gh-gitea"
PKG_CAL = ROOT / "authorized_packages" / "my-gh-cal-ssrf"


def test_intake_profile_ssrf_retain_detects_ts_express_routes():
    profile = build_intake_profile(package_root=PKG_SSRF)
    assert profile.status == STATUS_OK
    assert "TypeScript" in profile.language
    assert "Express" in profile.framework
    assert profile.execution_allowed is False
    assert profile.validation_allowed is False
    assert profile.report_submission_allowed is False
    assert profile.confirmed_vulnerability is False
    assert profile.network_access is False
    assert any("webhooks" in ep for ep in profile.entrypoints)
    assert profile.attack_surface_summary["entrypoint_count"] >= 1


def test_intake_profile_gitea_detects_go_and_auth_components():
    profile = build_intake_profile(package_root=PKG_GITEA)
    assert profile.status == STATUS_OK
    assert "Go" in profile.language
    assert "Gitea" in profile.framework or any("permission" in a for a in profile.auth_components)
    assert profile.auth_components
    assert profile.execution_allowed is False


def test_intake_profile_from_authorized_code_files_only():
    code = (PKG_SSRF / "inputs" / "code.ts").read_text(encoding="utf-8")
    profile = build_intake_profile(
        package_id="inline-ssrf",
        authorized_code_files=[{"path": "inputs/code.ts", "content": code}],
    )
    assert profile.status == STATUS_OK
    assert "TypeScript" in profile.language
    assert "Express" in profile.framework
    assert any("POST" in ep for ep in profile.entrypoints)
    assert profile.execution_allowed is False


def test_intake_missing_package_is_skipped_fail_closed():
    profile = build_intake_profile(package_root=ROOT / "authorized_packages" / "does-not-exist-xyz")
    assert profile.status == STATUS_SKIPPED
    assert profile.execution_allowed is False
    assert profile.report_submission_allowed is False


def test_attach_intake_never_unlocks_submission():
    bridged = attach_intake_profile_to_bridge_result(
        {
            "package_id": "pkg",
            "drafts": [{"candidate_id": "H-1"}],
            "submission_blocked": True,
            "execution_allowed": True,  # hostile input; must be forced false
            "report_submission_allowed": True,
        },
        package_root=PKG_CAL,
    )
    assert bridged["execution_allowed"] is False
    assert bridged["validation_allowed"] is False
    assert bridged["report_submission_allowed"] is False
    assert bridged["confirmed_vulnerability"] is False
    assert bridged["submission_blocked"] is True
    assert bridged["intake_profile_present"] is True
    assert isinstance(bridged["intake_profile"], dict)
    assert bridged["intake_profile"]["execution_allowed"] is False
    assert "TypeScript" in bridged["stack_languages"] or "JavaScript" in bridged["stack_languages"]


def test_industrial_scheduler_includes_intake_after_scope():
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
    assert "T-001b" in by_id
    assert by_id["T-001b"].agent == "intake_agent"
    assert by_id["T-001b"].depends_on == ["T-001"]
    assert by_id["T-001b"].execution_allowed is False
    assert by_id["T-001c"].agent == "dependency_agent"
    assert by_id["T-001c"].depends_on == ["T-001b"]
    assert by_id["T-002"].depends_on == ["T-001c"]
    assert by_id["T-003"].depends_on == ["T-001c"]
    assert by_id["T-004"].depends_on == ["T-001c"]
    assert any(batch.batch_id == "B-001b" for batch in plan.parallel_batches)
    assert any(batch.batch_id == "B-001c" for batch in plan.parallel_batches)
    assert "intake_agent" in {task.agent for task in plan.dag_tasks}
    assert "dependency_agent" in {task.agent for task in plan.dag_tasks}


def test_secretish_filenames_skipped():
    profile = build_intake_profile(
        package_id="secret-skip",
        authorized_code_files=[
            {"path": "inputs/api_token.ts", "content": "export const x = 1"},
            {
                "path": "inputs/code.ts",
                "content": "import { Router } from \"express\";\nconst r = Router();\nr.get(\"/api/ok\", () => {});\n",
            },
        ],
    )
    assert any("skipped_blocked_name" in n for n in profile.notes)
    assert "Express" in profile.framework
    assert profile.execution_allowed is False