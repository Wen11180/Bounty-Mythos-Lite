from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from app.codeql_runner import (
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PLANNED,
    STATUS_SKIPPED_NO_DB,
    STATUS_SKIPPED_NO_FLAG,
    STATUS_SKIPPED_NO_SUITE,
    STATUS_SKIPPED_NOT_INSTALLED,
    attach_codeql_runner_to_bridge_result,
    build_codeql_signal_from_runner,
    build_local_codeql_plan,
    find_codeql_binary,
    resolve_local_codeql_query_suite,
    run_local_codeql,
)
from app.industrial_scheduler import build_industrial_scheduler_plan


ROOT = Path(__file__).resolve().parents[3]
PKG_SSRF = ROOT / "authorized_packages" / "my-local-ssrf-retain"


def _write_min_codeql_artifacts(pkg: Path) -> tuple[Path, Path]:
    db = pkg / "inputs" / "codeql" / "database"
    db.mkdir(parents=True, exist_ok=True)
    (db / "codeql-database.yml").write_text("primaryLanguage: javascript\n", encoding="utf-8")
    suite = pkg / "inputs" / "codeql" / "suite.qls"
    suite.write_text("+ my-local-query\n", encoding="utf-8")
    return db, suite


def test_plan_only_without_human_flag():
    result = run_local_codeql(package_root=PKG_SSRF, package_id="my-local-ssrf-retain")
    assert result.status == STATUS_SKIPPED_NO_FLAG
    assert result.command_executed is False
    assert result.human_flag_required is True
    assert result.network_access is False
    assert result.remote_packs is False
    assert result.execution_allowed is False
    assert result.report_submission_allowed is False
    assert result.confirmed_vulnerability is False
    assert result.finding_promotion_allowed is False
    assert result.target_paths


def test_force_plan_only_even_with_flag():
    result = build_local_codeql_plan(
        PKG_SSRF,
        package_id="my-local-ssrf-retain",
        human_allow_local_codeql=True,
    )
    assert result.status == STATUS_PLANNED
    assert result.command_executed is False
    assert result.human_allow_local_codeql is True
    assert result.execution_allowed is False


def test_missing_binary_skips_when_flag_set(monkeypatch):
    monkeypatch.setattr("app.codeql_runner.find_codeql_binary", lambda explicit=None: None)
    result = run_local_codeql(
        package_root=PKG_SSRF,
        package_id="my-local-ssrf-retain",
        human_allow_local_codeql=True,
    )
    assert result.status == STATUS_SKIPPED_NOT_INSTALLED
    assert result.command_executed is False
    assert result.binary_available is False
    assert result.report_submission_allowed is False


def test_missing_database_skips_when_flag_set(tmp_path: Path, monkeypatch):
    pkg = tmp_path / "pkg"
    (pkg / "inputs").mkdir(parents=True)
    (pkg / "inputs" / "code.py").write_text("print(1)\n", encoding="utf-8")
    suite = pkg / "inputs" / "codeql" / "suite.qls"
    suite.parent.mkdir(parents=True, exist_ok=True)
    suite.write_text("+ q\n", encoding="utf-8")
    monkeypatch.setattr(
        "app.codeql_runner.find_codeql_binary",
        lambda explicit=None: "codeql-fake",
    )
    result = run_local_codeql(
        package_root=pkg,
        human_allow_local_codeql=True,
    )
    assert result.status == STATUS_SKIPPED_NO_DB
    assert result.command_executed is False
    assert result.report_submission_allowed is False


def test_missing_suite_skips_when_flag_set(tmp_path: Path, monkeypatch):
    pkg = tmp_path / "pkg"
    (pkg / "inputs").mkdir(parents=True)
    (pkg / "inputs" / "code.py").write_text("print(1)\n", encoding="utf-8")
    db = pkg / "inputs" / "codeql" / "database"
    db.mkdir(parents=True, exist_ok=True)
    (db / "codeql-database.yml").write_text("primaryLanguage: python\n", encoding="utf-8")
    monkeypatch.setattr(
        "app.codeql_runner.find_codeql_binary",
        lambda explicit=None: "codeql-fake",
    )
    result = run_local_codeql(
        package_root=pkg,
        human_allow_local_codeql=True,
    )
    assert result.status == STATUS_SKIPPED_NO_SUITE
    assert result.command_executed is False
    assert result.report_submission_allowed is False


def test_remote_pack_rejected(tmp_path: Path, monkeypatch):
    pkg = tmp_path / "pkg"
    (pkg / "inputs").mkdir(parents=True)
    (pkg / "inputs" / "code.py").write_text("print(1)\n", encoding="utf-8")
    db = pkg / "inputs" / "codeql" / "database"
    db.mkdir(parents=True, exist_ok=True)
    (db / "codeql-database.yml").write_text("primaryLanguage: javascript\n", encoding="utf-8")
    monkeypatch.setattr(
        "app.codeql_runner.find_codeql_binary",
        lambda explicit=None: "codeql-fake",
    )
    result = run_local_codeql(
        package_root=pkg,
        human_allow_local_codeql=True,
        query_suite="codeql/javascript-queries",
    )
    assert result.status == STATUS_SKIPPED_NO_SUITE
    assert result.command_executed is False
    assert any("remote_query_pack_rejected" in n for n in result.notes)
    assert result.remote_packs is False

    suite, source, notes = resolve_local_codeql_query_suite(
        pkg, query_suite="codeql/javascript-queries"
    )
    assert suite is None
    assert source == "remote_pack_rejected"
    assert "remote_query_pack_rejected" in notes


def test_fake_subprocess_completes_and_parses_sarif(tmp_path: Path, monkeypatch):
    pkg = tmp_path / "pkg"
    (pkg / "inputs").mkdir(parents=True)
    (pkg / "inputs" / "code.ts").write_text("fetch(url)\n", encoding="utf-8")
    _write_min_codeql_artifacts(pkg)

    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "js/ssrf",
                        "message": {"text": "Potential SSRF"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "inputs/code.ts"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ]
            }
        ],
    }

    def fake_run(cmd, **kwargs):
        assert cmd[0] == "codeql-fake"
        assert "database" in cmd and "analyze" in cmd
        assert "--search-path=" in cmd
        assert all("codeql/" not in str(part) or part.startswith("--") for part in cmd)
        out = None
        for part in cmd:
            if str(part).startswith("--output="):
                out = Path(str(part).split("=", 1)[1])
                break
        assert out is not None
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(sarif), encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "app.codeql_runner.find_codeql_binary",
        lambda explicit=None: "codeql-fake",
    )
    result = run_local_codeql(
        package_root=pkg,
        package_id="tmp-codeql",
        human_allow_local_codeql=True,
        subprocess_runner=fake_run,
    )
    assert result.status == STATUS_COMPLETED
    assert result.command_executed is True
    assert result.finding_count == 1
    assert result.findings[0]["rule_id"] == "js/ssrf"
    assert result.findings[0]["source"] == "codeql_local_cli"
    assert result.execution_allowed is False
    assert result.confirmed_vulnerability is False
    assert result.network_access is False
    assert result.remote_packs is False


def test_fake_subprocess_nonzero_error(tmp_path: Path, monkeypatch):
    pkg = tmp_path / "pkg"
    (pkg / "inputs").mkdir(parents=True)
    (pkg / "inputs" / "code.py").write_text("print(1)\n", encoding="utf-8")
    _write_min_codeql_artifacts(pkg)

    def fake_run(cmd, **kwargs):
        return SimpleNamespace(returncode=2, stdout="", stderr="analyze failed")

    monkeypatch.setattr(
        "app.codeql_runner.find_codeql_binary",
        lambda explicit=None: "codeql-fake",
    )
    result = run_local_codeql(
        package_root=pkg,
        human_allow_local_codeql=True,
        subprocess_runner=fake_run,
    )
    assert result.status == STATUS_FAILED
    assert result.command_executed is True
    assert result.report_submission_allowed is False


def test_attach_bridge_plan_only_default():
    bridge = {
        "package_id": "my-local-ssrf-retain",
        "package_root": str(PKG_SSRF),
        "drafts": [],
        "submission_blocked": True,
    }
    out = attach_codeql_runner_to_bridge_result(bridge, package_root=PKG_SSRF)
    assert out["codeql_runner_present"] is True
    assert out["codeql_runner_status"] == STATUS_SKIPPED_NO_FLAG
    assert out["codeql_local_executed"] is False
    assert out["execution_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert out["submission_blocked"] is True


def test_attach_bridge_merges_completed_findings(tmp_path: Path, monkeypatch):
    pkg = tmp_path / "pkg"
    (pkg / "inputs").mkdir(parents=True)
    (pkg / "inputs" / "code.ts").write_text("fetch(url)\n", encoding="utf-8")
    _write_min_codeql_artifacts(pkg)

    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "js/ssrf",
                        "message": {"text": "ssrf"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "inputs/code.ts"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ]
            }
        ],
    }

    def fake_run(cmd, **kwargs):
        for part in cmd:
            if str(part).startswith("--output="):
                out = Path(str(part).split("=", 1)[1])
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(json.dumps(sarif), encoding="utf-8")
                break
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(
        "app.codeql_runner.find_codeql_binary",
        lambda explicit=None: "codeql-fake",
    )
    bridge = {
        "package_id": "tmp-codeql",
        "package_root": str(pkg),
        "drafts": [],
        "submission_blocked": True,
        "advisory_bundle_present": False,
    }
    out = attach_codeql_runner_to_bridge_result(
        bridge,
        package_root=pkg,
        human_allow_local_codeql=True,
        subprocess_runner=fake_run,
    )
    assert out["codeql_runner_status"] == STATUS_COMPLETED
    assert out["codeql_local_merged_into_advisory"] is True
    assert out["advisory_bundle_present"] is True
    assert len(out["advisory_bundle"]["codeql_findings"]) >= 1
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False


def test_signal_from_runner_completed():
    signal = build_codeql_signal_from_runner(
        {
            "status": STATUS_COMPLETED,
            "findings": [
                {
                    "rule_id": "js/ssrf",
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
    assert "from_codeql_local_cli" in signal["notes"]


def test_signal_none_when_not_completed():
    assert build_codeql_signal_from_runner({"status": STATUS_SKIPPED_NO_FLAG}) is None


def test_scheduler_has_codeql_runner_task():
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
    assert "T-002c" in by_id
    assert by_id["T-002c"].agent == "codeql_runner"
    assert by_id["T-002c"].execution_allowed is False
    assert by_id["T-002c"].requires_human_review is True
    assert "T-001c" in by_id["T-002c"].depends_on or "T-002" in by_id["T-002c"].depends_on
    assert "T-002c" in by_id["T-005"].depends_on
    assert "T-002c" in by_id["T-006"].depends_on
    batch_ids = {b.batch_id: b.task_ids for b in plan.parallel_batches}
    assert "B-002c" in batch_ids
    assert "T-002c" in batch_ids["B-002c"]


def test_find_codeql_binary_none_ok():
    _ = find_codeql_binary()
