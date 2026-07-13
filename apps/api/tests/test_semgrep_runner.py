from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from app.industrial_scheduler import build_industrial_scheduler_plan
from app.semgrep_runner import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PLANNED,
    STATUS_SKIPPED_NO_FLAG,
    STATUS_SKIPPED_NOT_INSTALLED,
    attach_semgrep_runner_to_bridge_result,
    build_local_semgrep_plan,
    build_semgrep_signal_from_runner,
    find_semgrep_binary,
    run_local_semgrep,
)


ROOT = Path(__file__).resolve().parents[3]
PKG_SSRF = ROOT / "authorized_packages" / "my-local-ssrf-retain"


def test_plan_only_without_human_flag():
    result = run_local_semgrep(package_root=PKG_SSRF, package_id="my-local-ssrf-retain")
    assert result.status == STATUS_SKIPPED_NO_FLAG
    assert result.command_executed is False
    assert result.human_flag_required is True
    assert result.network_access is False
    assert result.remote_rules is False
    assert result.execution_allowed is False
    assert result.report_submission_allowed is False
    assert result.confirmed_vulnerability is False
    assert result.finding_promotion_allowed is False
    assert result.target_paths


def test_force_plan_only_even_with_flag():
    result = build_local_semgrep_plan(
        PKG_SSRF,
        package_id="my-local-ssrf-retain",
        human_allow_local_semgrep=True,
    )
    assert result.status == STATUS_PLANNED
    assert result.command_executed is False
    assert result.human_allow_local_semgrep is True
    assert result.execution_allowed is False


def test_missing_binary_skips_when_flag_set(monkeypatch):
    monkeypatch.setattr("app.semgrep_runner.find_semgrep_binary", lambda explicit=None: None)
    result = run_local_semgrep(
        package_root=PKG_SSRF,
        package_id="my-local-ssrf-retain",
        human_allow_local_semgrep=True,
    )
    assert result.status == STATUS_SKIPPED_NOT_INSTALLED
    assert result.command_executed is False
    assert result.binary_available is False
    assert result.report_submission_allowed is False


def test_fake_subprocess_completes_and_parses(monkeypatch):
    payload = {
        "results": [
            {
                "check_id": "mythos.local.ssrf-fetch",
                "path": str(PKG_SSRF / "inputs" / "code.ts"),
                "start": {"line": 12},
                "extra": {"message": "fetch without validation"},
            }
        ]
    }

    def fake_run(cmd, **kwargs):
        assert "--metrics" in cmd and "off" in cmd
        assert "--disable-version-check" in cmd
        assert all(not str(part).startswith("p/") for part in cmd)
        assert all(not str(part).startswith("r/") for part in cmd)
        return SimpleNamespace(returncode=1, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr(
        "app.semgrep_runner.find_semgrep_binary",
        lambda explicit=None: "semgrep-fake",
    )
    result = run_local_semgrep(
        package_root=PKG_SSRF,
        package_id="my-local-ssrf-retain",
        human_allow_local_semgrep=True,
        subprocess_runner=fake_run,
    )
    assert result.status == STATUS_COMPLETED
    assert result.command_executed is True
    assert result.finding_count == 1
    assert result.findings[0]["rule_id"] == "mythos.local.ssrf-fetch"
    assert result.findings[0]["source"] == "semgrep_local_cli"
    assert result.execution_allowed is False
    assert result.confirmed_vulnerability is False
    assert result.network_access is False
    assert result.remote_rules is False


def test_fake_subprocess_nonzero_error(monkeypatch):
    def fake_run(cmd, **kwargs):
        return SimpleNamespace(returncode=2, stdout="", stderr="config error")

    monkeypatch.setattr(
        "app.semgrep_runner.find_semgrep_binary",
        lambda explicit=None: "semgrep-fake",
    )
    result = run_local_semgrep(
        package_root=PKG_SSRF,
        human_allow_local_semgrep=True,
        subprocess_runner=fake_run,
    )
    assert result.status == STATUS_FAILED
    assert result.command_executed is True
    assert result.report_submission_allowed is False


def test_config_outside_package_rejected(tmp_path: Path, monkeypatch):
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "inputs").mkdir()
    (pkg / "inputs" / "code.py").write_text("print(1)\n", encoding="utf-8")
    outside = tmp_path / "outside.yml"
    outside.write_text("rules: []\n", encoding="utf-8")

    monkeypatch.setattr(
        "app.semgrep_runner.find_semgrep_binary",
        lambda explicit=None: "semgrep-fake",
    )
    # plan-only path still records rejection note
    result = run_local_semgrep(
        package_root=pkg,
        config_path=outside,
        human_allow_local_semgrep=False,
    )
    assert result.status == STATUS_SKIPPED_NO_FLAG
    assert any("config_outside_package" in n for n in result.notes)


def test_attach_bridge_plan_only_default():
    bridge = {
        "package_id": "my-local-ssrf-retain",
        "package_root": str(PKG_SSRF),
        "drafts": [],
        "submission_blocked": True,
    }
    out = attach_semgrep_runner_to_bridge_result(bridge, package_root=PKG_SSRF)
    assert out["semgrep_runner_present"] is True
    assert out["semgrep_runner_status"] == STATUS_SKIPPED_NO_FLAG
    assert out["semgrep_local_executed"] is False
    assert out["execution_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert out["submission_blocked"] is True


def test_attach_bridge_merges_completed_findings(monkeypatch):
    payload = {
        "results": [
            {
                "check_id": "mythos.local.ssrf-fetch",
                "path": "inputs/code.ts",
                "start": {"line": 1},
                "extra": {"message": "ssrf"},
            }
        ]
    }

    def fake_run(cmd, **kwargs):
        return SimpleNamespace(returncode=1, stdout=json.dumps(payload), stderr="")

    monkeypatch.setattr(
        "app.semgrep_runner.find_semgrep_binary",
        lambda explicit=None: "semgrep-fake",
    )
    bridge = {
        "package_id": "my-local-ssrf-retain",
        "package_root": str(PKG_SSRF),
        "drafts": [],
        "submission_blocked": True,
        "advisory_bundle_present": False,
    }
    out = attach_semgrep_runner_to_bridge_result(
        bridge,
        package_root=PKG_SSRF,
        human_allow_local_semgrep=True,
        subprocess_runner=fake_run,
    )
    assert out["semgrep_runner_status"] == STATUS_COMPLETED
    assert out["semgrep_local_merged_into_advisory"] is True
    assert out["advisory_bundle_present"] is True
    assert len(out["advisory_bundle"]["semgrep_findings"]) >= 1
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False


def test_signal_from_runner_completed():
    signal = build_semgrep_signal_from_runner(
        {
            "status": STATUS_COMPLETED,
            "findings": [
                {
                    "rule_id": "mythos.local.ssrf-fetch",
                    "message": "ssrf",
                    "path": "code.ts",
                    "root_cause_id": "missing_ssrf_validation:deliver",
                }
            ],
        },
        candidate={
            "candidate_id": "H-1",
            "root_cause_id": "missing_ssrf_validation:deliver",
        },
    )
    assert signal is not None
    assert signal["report_submission_allowed"] is False
    assert signal["confirmed_vulnerability"] is False
    assert "from_semgrep_local_cli" in signal["notes"]


def test_signal_none_when_not_completed():
    assert build_semgrep_signal_from_runner({"status": STATUS_SKIPPED_NO_FLAG}) is None


def test_scheduler_has_semgrep_runner_task():
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
    assert "T-002b" in by_id
    assert by_id["T-002b"].agent == "semgrep_runner"
    assert by_id["T-002b"].execution_allowed is False
    assert by_id["T-002b"].requires_human_review is True
    assert "T-001c" in by_id["T-002b"].depends_on or "T-002" in by_id["T-002b"].depends_on
    assert by_id["T-005"].depends_on  # still has deps
    # batch present
    batch_ids = {b.batch_id: b.task_ids for b in plan.parallel_batches}
    assert "B-002b" in batch_ids
    assert "T-002b" in batch_ids["B-002b"]


def test_find_semgrep_binary_none_ok():
    # environment may or may not have semgrep; function should not throw
    _ = find_semgrep_binary()