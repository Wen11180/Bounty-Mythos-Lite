from pathlib import Path

import pytest

from app.source_audit import (
    SourceAuditBlocked,
    load_scope_policy,
    normalize_semgrep_json,
    run_semgrep,
    run_source_audit,
)


def test_run_source_audit_reads_allowed_local_repo_and_builds_markdown_report(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "requirements.txt").write_text("fastapi==0.127.0\n", encoding="utf-8")
    (repo / "package.json").write_text('{"dependencies":{"next":"16.2.10"}}', encoding="utf-8")
    route = repo / "routes.py"
    route.write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str):",
                "    return send_file(file_id)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {
            "status": "completed",
            "results": [
                {
                    "check_id": "python.fastapi.security.audit",
                    "path": str(route),
                    "start": {"line": 5},
                    "extra": {
                        "message": "Route returns exported file without an obvious authorization check.",
                        "metadata": {"category": "security", "confidence": "MEDIUM"},
                    },
                }
            ],
        },
        llm_reviewer=lambda context: {
            "status": "completed",
            "summary": f"Reviewed {len(context['hypotheses'])} hypothesis with normalized evidence.",
        },
    )

    assert result.scope.allowed is True
    assert result.intake.languages == ["Python", "TypeScript/JavaScript"]
    assert result.intake.frameworks == ["FastAPI", "Next.js"]
    assert result.semgrep.status == "completed"
    assert result.codeql.status == "skipped"
    assert result.codeql.summary == "codeql_runner_not_configured"
    assert [manifest.path for manifest in result.dependencies.manifests] == [
        "package.json",
        "requirements.txt",
    ]
    assert result.dependencies.package_count == 2
    assert result.semgrep.findings[0].rule_id == "python.fastapi.security.audit"
    assert result.hypotheses[0].vuln_type == "authorization"
    assert result.hypotheses[0].safe_verification is True
    assert result.llm_review.status == "completed"
    assert result.llm_review.summary == "Reviewed 2 hypothesis with normalized evidence."
    assert result.report_markdown.startswith("# Source Audit Report")
    assert "## Scope Confirmation" in result.report_markdown
    assert "authorized local repository" in result.report_markdown
    assert "## Hypotheses" in result.report_markdown
    assert "## Dependencies" in result.report_markdown
    assert "## CodeQL" in result.report_markdown
    assert "## LLM Review" in result.report_markdown
    assert "send_file(file_id)" not in result.report_markdown
    assert result.finding_json[0]["finding_id"] == "H-001"
    assert result.finding_json[0]["status"] == "unverified_hypothesis"
    assert result.finding_json[0]["safe_reproduction"]["environment"] == "local_or_authorized_test_env"
    assert result.audit_log[0]["event"] == "scope_checked"
    assert result.audit_log[-1]["event"] == "report_generated"
    assert "send_file(file_id)" not in str(result.audit_log)


def test_run_source_audit_uses_injected_codeql_runner_and_reports_safe_summary(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "go.mod").write_text("module example.com/app\nrequire golang.org/x/net v0.1.0\n", encoding="utf-8")
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
        codeql_runner=lambda _: {
            "status": "skipped",
            "summary": "codeql_database_not_configured",
        },
    )

    assert result.intake.languages == ["Go"]
    assert result.dependencies.manifests[0].ecosystem == "go"
    assert result.dependencies.manifests[0].package_count == 1
    assert result.codeql.status == "skipped"
    assert result.codeql.summary == "codeql_database_not_configured"
    assert "## CodeQL" in result.report_markdown


def test_run_source_audit_blocks_unallowlisted_repo_before_semgrep(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    scope = tmp_path / "scope.yaml"
    scope.write_text("allowed_repos:\n  - C:/different/repo\n", encoding="utf-8")
    called = False

    def semgrep_runner(_: Path) -> dict:
        nonlocal called
        called = True
        return {"status": "completed", "results": []}

    with pytest.raises(SourceAuditBlocked):
        run_source_audit(repo, scope, semgrep_runner=semgrep_runner)

    assert called is False


def test_normalize_semgrep_json_keeps_only_report_safe_fields():
    findings = normalize_semgrep_json(
        {
            "results": [
                {
                    "check_id": "python.lang.security.audit",
                    "path": "app/routes.py",
                    "start": {"line": 42},
                    "extra": {
                        "message": "Authorization: Bearer live-token should not leak",
                        "metadata": {"category": "injection", "confidence": "HIGH"},
                        "lines": "secret raw code",
                    },
                }
            ]
        }
    )

    assert len(findings) == 1
    assert findings[0].tool == "semgrep"
    assert findings[0].rule_id == "python.lang.security.audit"
    assert findings[0].file == "app/routes.py"
    assert findings[0].line == 42
    assert findings[0].category == "injection"
    assert findings[0].confidence == "high"
    assert findings[0].message == "[REDACTED]"
    assert "secret raw code" not in str(findings[0])


def test_run_semgrep_invokes_json_auto_config_and_normalizes_results(monkeypatch, tmp_path):
    calls = []

    class Completed:
        returncode = 1
        stdout = '{"results":[{"check_id":"rule.one","path":"app.py","start":{"line":7},"extra":{"message":"review","metadata":{"category":"security","confidence":"LOW"}}}]}'

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        return Completed()

    monkeypatch.setattr("app.source_audit.subprocess.run", fake_run)

    payload = run_semgrep(tmp_path)
    findings = normalize_semgrep_json(payload)

    assert calls == [
        (
            ["semgrep", "--json", "--config", "auto", str(tmp_path)],
            {
                "check": False,
                "capture_output": True,
                "text": True,
                "timeout": 120,
            },
        )
    ]
    assert payload["status"] == "completed"
    assert payload["summary"] == "semgrep_json_normalized"
    assert findings[0].rule_id == "rule.one"


def test_load_scope_policy_accepts_utf8_bom_scope_files(tmp_path):
    repo = tmp_path / "target"
    scope = tmp_path / "scope.yaml"
    scope.write_bytes(f"\ufeffallowed_repos:\n  - {repo}\n".encode("utf-8"))

    assert load_scope_policy(scope) == {"allowed_repos": [str(repo)]}
