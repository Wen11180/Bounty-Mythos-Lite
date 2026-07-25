from dataclasses import replace
from pathlib import Path
import io
import json

from fastapi.testclient import TestClient
import pytest

from app.main import app
from app.mythos_chat import run_chat
from app.cli import main as cli_main
from app.codebase_map import CodebaseFactCandidate, map_authorized_code_files
from app.config import get_settings
from app.db import Base
from app.db import get_session
from app.mythos_finding import promote_pipeline_run_to_finding_candidate
from app.mythos_report import build_report_preview_response
from app.repository import DatabaseRepository
from app.source_audit import (
    ScopeCheck,
    SourceAuditBlocked,
    StaticFinding,
    build_finding_json,
    build_intake_profile,
    build_source_audit_pipeline_payload,
    build_source_hypotheses,
    collect_authorized_code_files,
    load_scope_policy,
    normalize_semgrep_json,
    run_semgrep,
    run_source_audit,
    save_source_audit_pipeline_run,
)
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


def build_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


def override_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def _override_get_session():
        with testing_session() as session:
            yield session

    return _override_get_session


client = TestClient(app)


@pytest.fixture(autouse=True)
def _configure_studio_workspace_root(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STUDIO_WORKSPACE_ROOT", str(tmp_path))
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def controlled_source_audit_paths(tmp_path: Path) -> tuple[Path, Path]:
    workspace = tmp_path / "source-audit-workspace"
    repo = workspace / "code" / "target"
    scope = workspace / "scope" / "scope.yaml"
    repo.mkdir(parents=True)
    scope.parent.mkdir(parents=True)
    return repo, scope


def test_collect_authorized_code_files_rejects_symlink_escape(tmp_path: Path):
    repo = tmp_path / "target"
    repo.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("OUTSIDE_SECRET = 'synthetic'", encoding="utf-8")
    link = repo / "linked.py"
    try:
        link.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"file symlinks unavailable: {exc}")

    with pytest.raises(SourceAuditBlocked, match="repo_symlink_escape"):
        collect_authorized_code_files(repo)


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
    parser_file = repo / "parser.py"
    parser_file.write_text(
        "\n".join(
            [
                "import json",
                "",
                "def decode_invoice_payload(raw: bytes):",
                "    return json.loads(raw.decode())",
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
    assert result.hypotheses[0].refutation_status == "unverified"
    assert result.hypotheses[0].priority_score > result.hypotheses[1].priority_score
    assert "traceable_source_fact" in result.hypotheses[0].ranking_reasons
    assert "refutation_status:unverified" in result.hypotheses[0].ranking_reasons
    assert result.hypotheses[0].false_positive_checks == [
        "authorization may be enforced in middleware or dependency injection",
        "service layer may enforce object ownership before returning data",
        "route may only expose public or self-owned resources",
    ]
    assert result.llm_review.status == "completed"
    assert result.llm_review.summary == "Reviewed 2 hypothesis with normalized evidence."
    assert result.report_markdown.startswith("# Source Audit Report")
    assert "## Scope Confirmation" in result.report_markdown
    assert "authorized local repository" in result.report_markdown
    assert "## Hypotheses" in result.report_markdown
    assert "## Dependencies" in result.report_markdown
    assert "## CodeQL" in result.report_markdown
    assert "## LLM Review" in result.report_markdown
    assert "Refutation status: unverified" in result.report_markdown
    assert "Priority score:" in result.report_markdown
    assert "Ranking reasons: traceable_source_fact" in result.report_markdown
    assert (
        "False positive checks: authorization may be enforced in middleware or dependency injection"
        in result.report_markdown
    )
    assert "send_file(file_id)" not in result.report_markdown
    assert result.finding_json[0]["finding_id"] == "H-001"
    assert result.finding_json[0]["status"] == "unverified_hypothesis"
    assert result.finding_json[0]["refutation_status"] == "unverified"
    assert result.finding_json[0]["priority_score"] > result.finding_json[1]["priority_score"]
    assert "traceable_source_fact" in result.finding_json[0]["ranking_reasons"]
    assert result.finding_json[0]["false_positive_checks"] == [
        "authorization may be enforced in middleware or dependency injection",
        "service layer may enforce object ownership before returning data",
        "route may only expose public or self-owned resources",
    ]
    assert result.finding_json[0]["safe_reproduction"]["environment"] == "local_or_authorized_test_env"
    assert result.audit_log[0]["event"] == "scope_checked"
    assert result.audit_log[-1]["event"] == "report_generated"
    assert "send_file(file_id)" not in str(result.audit_log)
    audit_events = {event["event"]: event for event in result.audit_log}
    assert result.crs_fuzzing.execution_mode == "plan_only"
    assert result.crs_fuzzing.parser_candidates[0].symbol_name == "decode_invoice_payload"
    assert result.crs_fuzzing.fuzzer_plan.execution_allowed is False
    assert result.crs_fuzzing.crash_triage.status == "schema_only"
    assert audit_events["crs_fuzzing_planned"]["crash_promotion_gate"] == (
        "blocked_until_reproducible_local_crash"
    )
    assert audit_events["crs_fuzzing_planned"]["crash_promotion_allowed"] is False
    assert "Crash promotion gate: blocked_until_reproducible_local_crash" in (
        result.report_markdown
    )
    assert "## CRS + Fuzzing" in result.report_markdown


def test_run_source_audit_raises_authorization_hypothesis_for_flask_sensitive_route_without_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from flask import Flask, send_file",
                "",
                "app = Flask(__name__)",
                "",
                '@app.route("/files/<file_id>/export", methods=["GET"])',
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
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == [
        "authorization"
    ]
    assert result.hypotheses[0].location == "GET /files/<file_id>/export"
    assert "traceable_source_fact" in result.hypotheses[0].ranking_reasons


def test_run_source_audit_raises_ssrf_hypothesis_for_explicit_stdlib_urllib_call(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "import urllib.request",
                "from fastapi import APIRouter",
                "",
                "router = APIRouter()",
                "",
                '@router.post("/webhooks/deliver")',
                "def deliver_webhook(target: str):",
                "    return urllib.request.urlopen(target)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    hypothesis = next(
        item for item in result.hypotheses if item.vuln_type == "ssrf"
    )
    finding = next(
        item for item in result.finding_json if item["vuln_type"] == "ssrf"
    )

    assert hypothesis.location == "POST /webhooks/deliver"
    assert "outbound HTTP sink" in hypothesis.reason
    assert finding["root_cause"] == "missing_ssrf_validation"
    assert finding["semantic_evidence"] == {
        "authz_hint": "missing_handler_ssrf_check",
        "review_state": "needs_human_review",
        "sink_count": 1,
        "sink_symbols": ["fetch"],
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def test_run_source_audit_raises_authorization_hypothesis_for_flask_add_url_rule_function_without_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from flask import Flask, send_file",
                "",
                "app = Flask(__name__)",
                "",
                "def export_file(file_id: str):",
                "    return send_file(file_id)",
                "",
                "app.add_url_rule(",
                '    "/files/<file_id>/export",',
                "    view_func=export_file,",
                '    methods=["GET"],',
                ")",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == [
        "authorization"
    ]
    assert result.hypotheses[0].location == "GET /files/<file_id>/export"
    assert "traceable_source_fact" in result.hypotheses[0].ranking_reasons


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_flask_add_url_rule_function_decorator_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from flask import Flask, send_file",
                "from flask_login import login_required",
                "",
                "app = Flask(__name__)",
                "",
                "@login_required",
                "def export_file(file_id: str):",
                "    return send_file(file_id)",
                "",
                "app.add_url_rule(",
                '    "/files/<file_id>/export",',
                "    view_func=export_file,",
                '    methods=["GET"],',
                ")",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_raises_authorization_hypothesis_for_flask_method_view_without_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from flask import Flask, send_file",
                "from flask.views import MethodView",
                "",
                "app = Flask(__name__)",
                "",
                "class FileExport(MethodView):",
                "    def get(self, file_id: str):",
                "        return send_file(file_id)",
                "",
                "app.add_url_rule(",
                '    "/files/<file_id>/export",',
                '    view_func=FileExport.as_view("export_file"),',
                ")",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == [
        "authorization"
    ]
    assert result.hypotheses[0].location == "GET /files/<file_id>/export"
    assert "traceable_source_fact" in result.hypotheses[0].ranking_reasons


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_flask_method_view_decorator_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from flask import Flask, send_file",
                "from flask.views import MethodView",
                "from flask_login import login_required",
                "",
                "app = Flask(__name__)",
                "",
                "class FileExport(MethodView):",
                "    decorators = [login_required]",
                "",
                "    def get(self, file_id: str):",
                "        return send_file(file_id)",
                "",
                "app.add_url_rule(",
                '    "/files/<file_id>/export",',
                '    view_func=FileExport.as_view("export_file"),',
                ")",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_flask_method_view_tuple_decorator_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from flask import Flask, send_file",
                "from flask.views import MethodView",
                "from flask_login import login_required",
                "",
                "app = Flask(__name__)",
                "",
                "class FileExport(MethodView):",
                "    decorators = (login_required,)",
                "",
                "    def get(self, file_id: str):",
                "        return send_file(file_id)",
                "",
                "app.add_url_rule(",
                '    "/files/<file_id>/export",',
                '    view_func=FileExport.as_view("export_file"),',
                ")",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_flask_method_view_method_decorator_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from flask import Flask, send_file",
                "from flask.views import MethodView",
                "from flask_login import login_required",
                "",
                "app = Flask(__name__)",
                "",
                "class FileExport(MethodView):",
                "    @login_required",
                "    def get(self, file_id: str):",
                "        return send_file(file_id)",
                "",
                "app.add_url_rule(",
                '    "/files/<file_id>/export",',
                '    view_func=FileExport.as_view("export_file"),',
                ")",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_service_layer_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    services = repo / "services"
    services.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "from services.files import export_file_for_user",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, user_id: str):",
                "    return export_file_for_user(file_id, user_id)",
            ]
        ),
        encoding="utf-8",
    )
    (services / "files.py").write_text(
        "\n".join(
            [
                "def export_file_for_user(file_id: str, user_id: str):",
                "    authorize_owner_or_admin(file_id, user_id)",
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
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_raises_authorization_hypothesis_for_multiline_service_sink_without_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    services = repo / "services"
    services.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "from services.files import export_file_for_user",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    return export_file_for_user(",
                "        file_id,",
                "        current_user,",
                "    )",
            ]
        ),
        encoding="utf-8",
    )
    (services / "files.py").write_text(
        "\n".join(
            [
                "def export_file_for_user(file_id: str, current_user):",
                "    return send_file(",
                "        file_id,",
                "    )",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == [
        "authorization"
    ]
    assert result.hypotheses[0].location == "GET /files/{file_id}/export"
    assert "traceable_source_fact" in result.hypotheses[0].ranking_reasons


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_multiline_membership_filter(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = db.query(File).filter(",
                "        File.id == file_id,",
                "        File.account_id.in_(",
                "            current_user.account_ids",
                "        ),",
                "    ).one()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_bracketed_multiline_membership_filter(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = db.query(File).filter(",
                "        File.id == file_id,",
                "        File.account_id.in_([",
                "            current_user.account_id,",
                "        ]),",
                "    ).one()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_multiline_kwarg_membership_filter(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = File.objects.filter(",
                "        id=file_id,",
                "        account_id__in=[",
                "            current_user.account_id,",
                "        ],",
                "    ).get()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_workspace_id_filter(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.post("/workspaces/{workspace_id}/assistant/query")',
                "def query_workspace(workspace_id: str, current_user):",
                "    docs = db.query(Document).filter(",
                "        Document.workspace_id == current_user.workspace_id,",
                "    ).all()",
                "    return send_file(docs[0].path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_team_id_filter(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.patch("/teams/{team_id}/invite-policy")',
                "def update_invite_policy(team_id: str, current_user):",
                "    policy = db.query(InvitePolicy).filter(",
                "        InvitePolicy.team_id == current_user.team_id,",
                "    ).one()",
                "    return update_role(policy)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_project_id_filter(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/projects/{project_id}/exports/{export_id}")',
                "def download_project_export(project_id: str, export_id: str, current_user):",
                "    export = db.query(ProjectExport).filter(",
                "        ProjectExport.id == export_id,",
                "        ProjectExport.project_id == current_user.project_id,",
                "    ).one()",
                "    return send_file(export.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_group_id_filter(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/groups/{group_id}/exports/{export_id}")',
                "def download_group_export(group_id: str, export_id: str, current_user):",
                "    export = db.query(GroupExport).filter(",
                "        GroupExport.id == export_id,",
                "        GroupExport.group_id == current_user.group_id,",
                "    ).one()",
                "    return send_file(export.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []


def test_run_source_audit_raises_agent_tool_authorization_hypothesis_for_execution_without_policy(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.post("/agents/{agent_id}/tools/execute")',
                "def run_agent_tool(agent_id: str, tool_name: str, current_user):",
                "    return execute_agent_tool(agent_id, tool_name)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == [
        "agent_tool_authz_gap"
    ]
    assert result.hypotheses[0].location == "POST /agents/{agent_id}/tools/execute"
    assert "tool-policy check" in result.hypotheses[0].reason
    assert "tool-policy checks before dispatch" in result.hypotheses[0].evidence_needed[0]
    assert "tool-policy check may run before dispatch" in result.hypotheses[0].false_positive_checks[0]

    payload = build_source_audit_pipeline_payload(result)
    assert payload["hypotheses"][0]["validation_mode"] == "offline_agent_tool_policy_review"
    assert payload["invariants"] == [
        {
            "invariant": (
                "AI agents may only invoke tools and resources explicitly authorized for the "
                "current user, agent policy, and task context."
            ),
            "source": "H-001",
        }
    ]
    assert payload["hunter_intelligence"]["assessments"][0]["playbook_id"] == "agent_tool_authorization"


def test_run_source_audit_raises_agent_tool_authorization_hypothesis_for_dispatch_without_policy(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.post("/agents/{agent_id}/tools/dispatch")',
                "def dispatch_tool(agent_id: str, tool_name: str, current_user):",
                "    return dispatch_agent_tool(agent_id, tool_name)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == [
        "agent_tool_authz_gap"
    ]
    assert result.hypotheses[0].location == "POST /agents/{agent_id}/tools/dispatch"


def test_run_source_audit_raises_agent_tool_authorization_hypothesis_for_agent_id_filter_without_policy(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.post("/agents/{agent_id}/tools/execute")',
                "def run_agent_tool(agent_id: str, tool_name: str, current_user):",
                "    agent = db.query(Agent).filter(",
                "        Agent.agent_id == current_user.agent_id,",
                "    ).one()",
                "    return execute_agent_tool(agent, tool_name)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == [
        "agent_tool_authz_gap"
    ]


def test_run_source_audit_does_not_raise_agent_tool_authorization_hypothesis_for_tool_policy(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.post("/agents/{agent_id}/tools/execute")',
                "def run_agent_tool(agent_id: str, tool_name: str, current_user):",
                "    assert_tool_allowed(agent_id, tool_name)",
                "    return execute_agent_tool(agent_id, tool_name)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []


@pytest.mark.parametrize(
    (
        "root_cause",
        "vuln_type",
        "validation_mode",
        "playbook_id",
        "invariant",
        "reason_fragment",
        "evidence_fragment",
        "false_positive_fragment",
    ),
    [
        pytest.param(
            "missing_command_injection_validation",
            "command_injection",
            "offline_command_execution_boundary_review",
            "command_execution_boundary",
            (
                "Command selection and arguments must be constrained by an explicit local allowlist "
                "or structured validation before command-execution sinks."
            ),
            "command execution",
            "command allowlist",
            "command allowlist",
            id="command-execution",
        ),
        pytest.param(
            "missing_unsafe_deserialization_guard",
            "unsafe_deserialization",
            "offline_deserialization_policy_review",
            "unsafe_deserialization_boundary",
            "Serialized input must pass an explicit type and loader policy before unsafe deserialization sinks.",
            "unsafe deserialization",
            "serialized-payload validation",
            "safe loader",
            id="unsafe-deserialization",
        ),
        pytest.param(
            "missing_file_upload_validation",
            "file_upload",
            "offline_file_upload_policy_review",
            "file_upload_boundary",
            (
                "Uploaded files must pass explicit type, filename, and storage policy checks "
                "before upload-storage sinks."
            ),
            "file-upload",
            "upload validation",
            "upload validation",
            id="file-upload",
        ),
        pytest.param(
            "missing_server_authoritative_amount_check",
            "business_logic",
            "offline_server_amount_policy_review",
            "money_flow_tampering",
            (
                "Financial amounts, credits, and refunds must be derived from trusted server-side "
                "order or account state before financial action sinks."
            ),
            "server-authoritative amount",
            "server-side amount derivation",
            "server-side amount derivation",
            id="server-authoritative-money-flow",
        ),
        pytest.param(
            "missing_jwt_verification",
            "jwt_authentication_bypass",
            "offline_jwt_verification_review",
            "jwt_authentication_boundary",
            (
                "JWT claims must be signature-verified and validated before they "
                "influence sensitive operations."
            ),
            "JWT signature verification",
            "JWT signature verification",
            "JWT verification",
            id="jwt-verification",
        ),
    ],
)
def test_source_audit_preserves_specialized_static_gap_profiles(
    tmp_path,
    root_cause,
    vuln_type,
    validation_mode,
    playbook_id,
    invariant,
    reason_fragment,
    evidence_fragment,
    false_positive_fragment,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "from fastapi import APIRouter\nrouter = APIRouter()\n",
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")
    baseline = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )
    hypotheses = build_source_hypotheses(
        [
            CodebaseFactCandidate(
                fact_type="authorization_gap_candidate",
                source_path="routes.py",
                symbol_name="run_sensitive_operation",
                route_method="POST",
                route_path="/operations",
                authz_hint="missing_handler_specialized_check",
                sensitivity_label="high",
                payload={
                    "handler": "run_sensitive_operation",
                    "root_cause": root_cause,
                    "sink_count": 1,
                },
            )
        ],
        [],
    )

    assert [hypothesis.vuln_type for hypothesis in hypotheses] == [vuln_type]
    assert reason_fragment in hypotheses[0].reason
    assert evidence_fragment in hypotheses[0].evidence_needed[0]
    assert false_positive_fragment in hypotheses[0].false_positive_checks[0]

    payload = build_source_audit_pipeline_payload(replace(baseline, hypotheses=hypotheses))
    assert payload["hypotheses"][0]["validation_mode"] == validation_mode
    assert payload["invariants"][0]["invariant"] == invariant
    assert payload["hunter_intelligence"]["assessments"][0]["playbook_id"] == playbook_id


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_owner_filter_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, user_id: str):",
                "    file = db.query(File).filter(File.id == file_id, File.owner_id == user_id).one()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_tenant_filter_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/invoices/{invoice_id}/export")',
                "def export_invoice(invoice_id: str, current_user):",
                "    invoice = db.query(Invoice).filter(",
                "        Invoice.id == invoice_id,",
                "        Invoice.tenant_id == current_user.tenant_id,",
                "    ).one()",
                "    return send_file(invoice.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_org_id_organization_id_comparison_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = db.query(File).filter(File.id == file_id, File.org_id == current_user.organization_id).one()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_org_id_relation_id_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = File.objects.filter(id=file_id, org_id=current_user.organization.id).get()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_org_id_relation_id_comparison_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = db.query(File).filter(File.id == file_id, File.org_id == current_user.organization.id).one()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_account_relation_comparison_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = db.query(File).filter(File.id == file_id, File.account == current_user.account).one()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_owner_current_user_comparison_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = db.query(File).filter(File.id == file_id, File.owner == current_user).one()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_created_by_id_current_user_id_comparison_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = db.query(File).filter(File.id == file_id, File.created_by_id == current_user.id).one()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_created_by_current_user_comparison_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = db.query(File).filter(File.id == file_id, File.created_by == current_user).one()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_created_by_id_current_user_id_kwarg_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = File.objects.filter(id=file_id, created_by_id=current_user.id).get()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_created_by_current_user_kwarg_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = File.objects.filter(id=file_id, created_by=current_user).get()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_created_by_relation_id_kwarg_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = File.objects.filter(id=file_id, created_by__id=current_user.id).get()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_single_item_created_by_id_current_user_id_membership_list_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = db.query(File).filter(File.id == file_id, File.created_by_id.in_([current_user.id])).one()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_single_item_created_by_id_current_user_id_kwarg_membership_list_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = File.objects.filter(id=file_id, created_by_id__in=[current_user.id]).get()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_created_by_id_current_user_pk_kwarg_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = File.objects.filter(id=file_id, created_by_id=current_user.pk).get()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_created_by_id_user_pk_kwarg_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, user):",
                "    file = File.objects.filter(id=file_id, created_by_id=user.pk).get()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_created_by_id_request_user_id_kwarg_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, request):",
                "    file = File.objects.filter(id=file_id, created_by_id=request.user.id).get()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_created_by_id_request_user_pk_kwarg_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, request):",
                "    file = File.objects.filter(id=file_id, created_by_id=request.user.pk).get()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_filter_by_account_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = db.query(File).filter_by(id=file_id, account_id=current_user.account_id).one()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_local_principal_account_id_alias_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    authorized_account_id = current_user.account_id",
                "    file = db.query(File).filter_by(id=file_id, account_id=authorized_account_id).one()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_account_relation_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = File.objects.filter(id=file_id, account=current_user.account).get()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_owner_current_user_relation_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = File.objects.filter(id=file_id, owner=current_user).get()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_org_relation_alias_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = File.objects.filter(id=file_id, org=current_user.organization).get()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_account_relation_membership_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = File.objects.filter(id=file_id, account__in=current_user.accounts).get()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_double_underscore_account_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = File.objects.filter(id=file_id, account__id=current_user.account_id).get()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_double_underscore_in_account_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = File.objects.filter(id=file_id, account_id__in=current_user.account_ids).get()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_repository_layer_owner_filter(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    services = repo / "services"
    repositories = repo / "repositories"
    services.mkdir()
    repositories.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "from services.files import export_file_for_user",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    return export_file_for_user(file_id, current_user)",
            ]
        ),
        encoding="utf-8",
    )
    (services / "files.py").write_text(
        "\n".join(
            [
                "from repositories.files import load_file_for_user",
                "",
                "def export_file_for_user(file_id: str, current_user):",
                "    file = load_file_for_user(file_id, current_user)",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    (repositories / "files.py").write_text(
        "\n".join(
            [
                "def load_file_for_user(file_id: str, current_user):",
                "    return db.query(File).filter_by(id=file_id, account_id=current_user.account_id).one()",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_organization_id_membership_alias_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = File.objects.filter(id=file_id, organization_id__in=current_user.org_ids).get()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_single_item_org_id_membership_list_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = db.query(File).filter(File.id == file_id, File.org_id.in_([current_user.organization_id])).one()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_single_item_org_relation_id_membership_list_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = db.query(File).filter(File.id == file_id, File.org_id.in_([current_user.organization.id])).one()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_single_item_org_id_membership_tuple_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = db.query(File).filter(File.id == file_id, File.org_id.in_((current_user.organization_id,))).one()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_single_item_org_id_membership_set_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = db.query(File).filter(File.id == file_id, File.org_id.in_({current_user.organization_id})).one()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_membership_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/invoices/{invoice_id}/export")',
                "def export_invoice(invoice_id: str, current_user):",
                "    invoice = db.query(Invoice).filter(",
                "        Invoice.id == invoice_id,",
                "        Invoice.tenant_id.in_(current_user.tenant_ids),",
                "    ).one()",
                "    return send_file(invoice.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_relation_membership_method_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    file = db.query(File).filter(",
                "        File.id == file_id,",
                "        File.account.in_(current_user.accounts),",
                "    ).one()",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_imported_service_alias_owner_filter(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    services = repo / "services"
    repositories = repo / "repositories"
    services.mkdir()
    repositories.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "from services.files import export_file_for_user as export_for_user",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    return export_for_user(file_id, current_user)",
            ]
        ),
        encoding="utf-8",
    )
    (services / "files.py").write_text(
        "\n".join(
            [
                "from repositories.files import load_file_for_user",
                "",
                "def export_file_for_user(file_id: str, current_user):",
                "    file = load_file_for_user(file_id, current_user)",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    (repositories / "files.py").write_text(
        "\n".join(
            [
                "def load_file_for_user(file_id: str, current_user):",
                "    return db.query(File).filter_by(id=file_id, account_id=current_user.account_id).one()",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_local_method_alias_owner_filter(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    services = repo / "services"
    repositories = repo / "repositories"
    services.mkdir()
    repositories.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "from services.files import export_file_for_user",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    return export_file_for_user(file_id, current_user)",
            ]
        ),
        encoding="utf-8",
    )
    (services / "files.py").write_text(
        "\n".join(
            [
                "from repositories.files import FileRepository",
                "",
                "def export_file_for_user(file_id: str, current_user):",
                "    repository = FileRepository()",
                "    loader = repository.load_for_user",
                "    file = loader(file_id, current_user)",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    (repositories / "files.py").write_text(
        "\n".join(
            [
                "class FileRepository:",
                "    def load_for_user(self, file_id: str, current_user):",
                "        return db.query(File).filter_by(id=file_id, account_id=current_user.account_id).one()",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_chained_local_alias_owner_filter(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    services = repo / "services"
    repositories = repo / "repositories"
    services.mkdir()
    repositories.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "from services.files import export_file_for_user",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    return export_file_for_user(file_id, current_user)",
            ]
        ),
        encoding="utf-8",
    )
    (services / "files.py").write_text(
        "\n".join(
            [
                "from repositories.files import FileRepository",
                "",
                "def export_file_for_user(file_id: str, current_user):",
                "    repository = FileRepository()",
                "    loader = repository.load_for_user",
                "    safe_loader = loader",
                "    file = safe_loader(file_id, current_user)",
                "    return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    (repositories / "files.py").write_text(
        "\n".join(
            [
                "class FileRepository:",
                "    def load_for_user(self, file_id: str, current_user):",
                "        return db.query(File).filter_by(id=file_id, account_id=current_user.account_id).one()",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_same_class_field_alias_owner_filter(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    services = repo / "services"
    repositories = repo / "repositories"
    services.mkdir()
    repositories.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "from services.files import FileExportService",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    service = FileExportService()",
                "    return service.export_file_for_user(file_id, current_user)",
            ]
        ),
        encoding="utf-8",
    )
    (services / "files.py").write_text(
        "\n".join(
            [
                "from repositories.files import FileRepository",
                "",
                "class FileExportService:",
                "    def __init__(self):",
                "        repository = FileRepository()",
                "        self.loader = repository.load_for_user",
                "",
                "    def export_file_for_user(self, file_id: str, current_user):",
                "        file = self.loader(file_id, current_user)",
                "        return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    (repositories / "files.py").write_text(
        "\n".join(
            [
                "class FileRepository:",
                "    def load_for_user(self, file_id: str, current_user):",
                "        return db.query(File).filter_by(id=file_id, account_id=current_user.account_id).one()",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_chained_same_class_field_alias_owner_filter(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    services = repo / "services"
    repositories = repo / "repositories"
    services.mkdir()
    repositories.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "from services.files import FileExportService",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, current_user):",
                "    service = FileExportService()",
                "    return service.export_file_for_user(file_id, current_user)",
            ]
        ),
        encoding="utf-8",
    )
    (services / "files.py").write_text(
        "\n".join(
            [
                "from repositories.files import FileRepository",
                "",
                "class FileExportService:",
                "    def __init__(self):",
                "        repository = FileRepository()",
                "        self.loader = repository.load_for_user",
                "        self.safe_loader = self.loader",
                "",
                "    def export_file_for_user(self, file_id: str, current_user):",
                "        file = self.safe_loader(file_id, current_user)",
                "        return send_file(file.path)",
            ]
        ),
        encoding="utf-8",
    )
    (repositories / "files.py").write_text(
        "\n".join(
            [
                "class FileRepository:",
                "    def load_for_user(self, file_id: str, current_user):",
                "        return db.query(File).filter_by(id=file_id, account_id=current_user.account_id).one()",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_dependency_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter, Depends",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, user=Depends(require_user)):",
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
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_keyword_dependency_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter, Depends",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, user=Depends(dependency=require_user)):",
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
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_decorator_dependency_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter, Depends",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export", dependencies=[Depends(require_user)])',
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
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_router_level_dependency_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter, Depends",
                "router = APIRouter(dependencies=[Depends(require_user)])",
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
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_qualified_router_level_dependency_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import Depends",
                "import fastapi",
                "router = fastapi.APIRouter(dependencies=[Depends(require_user)])",
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
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_aliased_router_level_dependency_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter as Router, Depends",
                "router = Router(dependencies=[Depends(require_user)])",
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
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_security_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter, Security",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, user=Security(require_user)):",
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
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_multiline_dependency_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter, Depends",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(",
                "    file_id: str,",
                "    user=Depends(require_user),",
                "):",
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
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_multiline_router_level_dependency_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter, Depends",
                "router = APIRouter(",
                "    dependencies=[",
                "        Depends(",
                "            require_user,",
                "        )",
                "    ]",
                ")",
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
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_multiline_decorator_dependency_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter, Depends",
                "router = APIRouter()",
                "",
                "@router.get(",
                '    "/files/{file_id}/export",',
                "    dependencies=[Depends(require_user)],",
                ")",
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
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_decorator_dependency_wrapper_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter, Depends",
                "from dependencies import current_staff_user",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export", dependencies=[Depends(current_staff_user)])',
                "def export_file(file_id: str):",
                "    return send_file(file_id)",
            ]
        ),
        encoding="utf-8",
    )
    (repo / "dependencies.py").write_text(
        "\n".join(
            [
                "from fastapi import Depends",
                "from auth import require_user",
                "",
                "def current_staff_user(user=Depends(current_user)):",
                "    return user",
                "",
                "def current_user(user=Depends(require_user)):",
                "    return user",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_multiline_decorator_dependency_wrapper_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter, Depends",
                "from dependencies import current_staff_user",
                "router = APIRouter()",
                "",
                "@router.get(",
                '    "/files/{file_id}/export",',
                "    dependencies=[",
                "        Depends(",
                "            current_staff_user,",
                "        )",
                "    ],",
                ")",
                "def export_file(file_id: str):",
                "    return send_file(file_id)",
            ]
        ),
        encoding="utf-8",
    )
    (repo / "dependencies.py").write_text(
        "\n".join(
            [
                "from fastapi import Depends",
                "from auth import require_user",
                "",
                "def current_staff_user(user=Depends(current_user)):",
                "    return user",
                "",
                "def current_user(user=Depends(require_user)):",
                "    return user",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_multiline_scoped_security_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter, Security",
                "router = APIRouter()",
                "",
                "@router.get(",
                '    "/files/{file_id}/export",',
                "    dependencies=[",
                "        Security(",
                "            require_user,",
                '            scopes=["files:export"],',
                "        )",
                "    ],",
                ")",
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
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_imported_authz_alias(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter, Depends",
                "from auth import require_user as RequireUser",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, user=Depends(RequireUser)):",
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
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_dependency_alias_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter, Depends",
                "router = APIRouter()",
                "CurrentUser = Depends(require_user)",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, user=CurrentUser):",
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
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_keyword_dependency_alias_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter, Depends",
                "router = APIRouter()",
                "CurrentUser = Depends(dependency=require_user)",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, user=CurrentUser):",
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
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_dependency_wrapper_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter, Depends",
                "from dependencies import current_user",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, user=Depends(current_user)):",
                "    return send_file(file_id)",
            ]
        ),
        encoding="utf-8",
    )
    (repo / "dependencies.py").write_text(
        "\n".join(
            [
                "from fastapi import Depends",
                "from auth import require_user",
                "",
                "def current_user(user=Depends(require_user)):",
                "    return user",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_dependency_wrapper_chain_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter, Depends",
                "from dependencies import current_active_user",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, user=Depends(current_active_user)):",
                "    return send_file(file_id)",
            ]
        ),
        encoding="utf-8",
    )
    (repo / "dependencies.py").write_text(
        "\n".join(
            [
                "from fastapi import Depends",
                "from auth import require_user",
                "",
                "def current_active_user(user=Depends(current_user)):",
                "    return user",
                "",
                "def current_user(user=Depends(require_user)):",
                "    return user",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_deeper_dependency_wrapper_chain_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter, Depends",
                "from dependencies import current_staff_user",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, user=Depends(current_staff_user)):",
                "    return send_file(file_id)",
            ]
        ),
        encoding="utf-8",
    )
    (repo / "dependencies.py").write_text(
        "\n".join(
            [
                "from fastapi import Depends",
                "from auth import require_user",
                "",
                "def current_staff_user(user=Depends(current_active_user)):",
                "    return user",
                "",
                "def current_active_user(user=Depends(current_user)):",
                "    return user",
                "",
                "def current_user(user=Depends(require_user)):",
                "    return user",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_dependency_alias_to_wrapper_chain_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "from dependencies import CurrentStaffUser",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str, user=CurrentStaffUser):",
                "    return send_file(file_id)",
            ]
        ),
        encoding="utf-8",
    )
    (repo / "dependencies.py").write_text(
        "\n".join(
            [
                "from fastapi import Depends",
                "from auth import require_user",
                "",
                "CurrentStaffUser = Depends(current_staff_user)",
                "",
                "def current_staff_user(user=Depends(current_active_user)):",
                "    return user",
                "",
                "def current_active_user(user=Depends(current_user)):",
                "    return user",
                "",
                "def current_user(user=Depends(require_user)):",
                "    return user",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


def test_run_source_audit_does_not_raise_authorization_hypothesis_for_decorator_dependency_alias_to_wrapper_chain_authz(
    tmp_path,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "from dependencies import CurrentStaffUser",
                "router = APIRouter()",
                "",
                '@router.get("/files/{file_id}/export", dependencies=[CurrentStaffUser])',
                "def export_file(file_id: str):",
                "    return send_file(file_id)",
            ]
        ),
        encoding="utf-8",
    )
    (repo / "dependencies.py").write_text(
        "\n".join(
            [
                "from fastapi import Depends",
                "from auth import require_user",
                "",
                "CurrentStaffUser = Depends(current_staff_user)",
                "",
                "def current_staff_user(user=Depends(current_active_user)):",
                "    return user",
                "",
                "def current_active_user(user=Depends(current_user)):",
                "    return user",
                "",
                "def current_user(user=Depends(require_user)):",
                "    return user",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert [hypothesis.vuln_type for hypothesis in result.hypotheses] == []
    assert (
        "- No high-signal vulnerability hypotheses generated from the current inputs."
        in result.report_markdown
    )


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


def test_source_hypotheses_rank_unverified_traceable_candidates_before_refuted_or_parked():
    hypotheses = build_source_hypotheses(
        [
            CodebaseFactCandidate(
                fact_type="authorization_gap_candidate",
                source_path="routes.py",
                symbol_name="export_file",
                route_method="GET",
                route_path="/files/{file_id}/export",
                authz_hint="missing_handler_authz_check",
                sensitivity_label="high",
                payload={
                    "handler": "export_file",
                    "refutation_status": "refuted",
                    "refutation_reason": "service layer enforces owner_or_admin before file export",
                    "sink_count": 1,
                },
            ),
            CodebaseFactCandidate(
                fact_type="authorization_gap_candidate",
                source_path="routes.py",
                symbol_name="delete_file",
                route_method="DELETE",
                route_path="/files/{file_id}",
                authz_hint="missing_handler_authz_check",
                sensitivity_label="high",
                payload={
                    "handler": "delete_file",
                    "sink_count": 1,
                },
            ),
            CodebaseFactCandidate(
                fact_type="authorization_gap_candidate",
                source_path="routes.py",
                symbol_name="preview_file",
                route_method="GET",
                route_path="/files/{file_id}/preview",
                authz_hint="missing_handler_authz_check",
                sensitivity_label="low",
                payload={
                    "handler": "preview_file",
                    "sink_count": 1,
                },
            ),
        ],
        [
            StaticFinding(
                tool="semgrep",
                rule_id="python.lang.security.audit",
                file="parser.py",
                line=7,
                category="security",
                confidence="low",
                message="Local-only parser warning needs review.",
            )
        ],
    )

    assert [hypothesis.refutation_status for hypothesis in hypotheses] == [
        "unverified",
        "parked",
        "refuted",
        "parked",
    ]
    assert hypotheses[0].location == "DELETE /files/{file_id}"
    assert hypotheses[0].priority_score > hypotheses[1].priority_score
    assert hypotheses[1].priority_score > hypotheses[2].priority_score
    assert hypotheses[2].priority_score > hypotheses[3].priority_score
    assert hypotheses[2].false_positive_checks[0] == (
        "service layer enforces owner_or_admin before file export"
    )
    assert "traceable_source_fact" in hypotheses[0].ranking_reasons
    assert "refutation_status:unverified" in hypotheses[0].ranking_reasons
    assert "refutation_status:refuted" in hypotheses[2].ranking_reasons
    assert hypotheses[0].risk == "high"
    assert hypotheses[3].risk == "low"
    assert all(hypothesis.safe_verification is True for hypothesis in hypotheses)


def test_source_hypotheses_rank_high_impact_sinks_before_lower_impact_sinks():
    hypotheses = build_source_hypotheses(
        [
            CodebaseFactCandidate(
                fact_type="authorization_gap_candidate",
                source_path="routes.py",
                symbol_name="preview_file",
                route_method="GET",
                route_path="/a/files/{file_id}/preview",
                authz_hint="missing_handler_authz_check",
                sensitivity_label="high",
                payload={
                    "handler": "preview_file",
                    "sink_count": 1,
                    "sink_symbols": ["send_file"],
                },
            ),
            CodebaseFactCandidate(
                fact_type="authorization_gap_candidate",
                source_path="routes.py",
                symbol_name="delete_user_role",
                route_method="DELETE",
                route_path="/z/users/{user_id}/role",
                authz_hint="missing_handler_authz_check",
                sensitivity_label="high",
                payload={
                    "handler": "delete_user_role",
                    "sink_count": 1,
                    "sink_symbols": ["update_role"],
                },
            ),
        ],
        [],
    )

    assert hypotheses[0].location == "DELETE /z/users/{user_id}/role"
    assert hypotheses[0].priority_score > hypotheses[1].priority_score
    assert "impact:privilege_or_destructive_sink" in hypotheses[0].ranking_reasons
    assert "sink:update_role" in hypotheses[0].ranking_reasons
    assert "impact:sensitive_data_sink" in hypotheses[1].ranking_reasons


def test_source_hypotheses_attach_semantic_evidence_to_authorization_candidates():
    hypotheses = build_source_hypotheses(
        [
            CodebaseFactCandidate(
                fact_type="authorization_gap_candidate",
                source_path="routes.py",
                symbol_name="delete_file",
                route_method="DELETE",
                route_path="/files/{file_id}",
                authz_hint="missing_handler_authz_check",
                sensitivity_label="high",
                payload={
                    "handler": "delete_file",
                    "review_state": "needs_human_review",
                    "sink_count": 1,
                    "sink_symbols": ["delete_file"],
                },
            )
        ],
        [],
    )

    source_fact = hypotheses[0].source_facts[0]

    assert source_fact["root_cause"] == "missing_object_ownership_check"
    assert source_fact["security_invariant"] == (
        "Object-level actions must verify requester ownership or role before sensitive sinks run."
    )
    assert source_fact["sink_symbols"] == ["delete_file"]
    assert source_fact["sink_count"] == 1
    assert source_fact["review_state"] == "needs_human_review"
    assert source_fact["authz_hint"] == "missing_handler_authz_check"
    assert source_fact["execution_allowed"] is False
    assert source_fact["validation_allowed"] is False
    assert source_fact["report_submission_allowed"] is False


def test_finding_json_uses_semantic_evidence_for_submission_blocked_report_material():
    hypotheses = build_source_hypotheses(
        [
            CodebaseFactCandidate(
                fact_type="authorization_gap_candidate",
                source_path="routes.py",
                symbol_name="delete_file",
                route_method="DELETE",
                route_path="/files/{file_id}",
                authz_hint="missing_handler_authz_check",
                sensitivity_label="high",
                payload={
                    "handler": "delete_file",
                    "review_state": "needs_human_review",
                    "sink_count": 1,
                    "sink_symbols": ["delete_file"],
                },
            )
        ],
        [],
    )

    finding = build_finding_json(
        hypotheses,
        [],
        ScopeCheck(
            allowed=True,
            reason="repository is inside authorized local scope",
            repo_path="target",
        ),
    )[0]

    assert finding["root_cause"] == "missing_object_ownership_check"
    assert finding["security_invariant"] == (
        "Object-level actions must verify requester ownership or role before sensitive sinks run."
    )
    assert finding["semantic_evidence"] == {
        "authz_hint": "missing_handler_authz_check",
        "review_state": "needs_human_review",
        "sink_count": 1,
        "sink_symbols": ["delete_file"],
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }
    assert finding["status"] == "unverified_hypothesis"
    assert finding["safe_reproduction"]["requires_human_review"] is True
    assert "Authorization" not in str(finding)
    assert "secret" not in str(finding).lower()


def test_run_source_audit_integrates_authorized_bug_bounty_plan(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                '@router.get("/api/orders/{order_id}")',
                "def get_order(order_id: str):",
                "    return load_order(order_id)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.json"
    scope.write_text(
        json.dumps(
            {
                "allowed_repos": [str(repo)],
                "bug_bounty": {
                    "allowed_assets": ["api.example.com"],
                    "test_accounts": [
                        {
                            "label": "buyer_a",
                            "role": "buyer",
                            "password": "should-not-leak",
                        },
                        {
                            "label": "buyer_b",
                            "role": "buyer_peer",
                            "token": "should-not-leak-either",
                        },
                    ],
                },
            }
        ),
        encoding="utf-8",
    )

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    serialized = json.dumps(result.authorized_bug_bounty.to_dict())
    assert result.authorized_bug_bounty.stage == "v2_authorized_bug_bounty"
    assert result.authorized_bug_bounty.allowed_assets[0].asset == "api.example.com"
    assert result.authorized_bug_bounty.api_operations[0].path == "/api/orders/{order_id}"
    assert result.authorized_bug_bounty.role_diff_plans[0].execution_allowed is False
    assert result.authorized_bug_bounty.human_gate.status == "required"
    audit_events = {event["event"]: event for event in result.audit_log}
    assert audit_events["authorized_bug_bounty_planned"]["blocked_preflight_checks"] == [
        "durable_human_approval",
        "redacted_evidence_package",
    ]
    assert "Validation preflight blocked checks: durable_human_approval" in (
        result.report_markdown
    )
    assert "should-not-leak" not in serialized
    assert "should-not-leak-either" not in serialized
    assert "## Authorized Bug Bounty" in result.report_markdown
    assert any(
        event["event"] == "authorized_bug_bounty_planned"
        for event in result.audit_log
    )


def test_run_source_audit_integrates_industrial_scheduler_plan(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                '@router.get("/api/orders/{order_id}")',
                "def get_order(order_id: str):",
                "    return send_file(order_id)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert result.industrial_scheduler.stage == "v3_multi_agent_industrial_scheduling"
    assert result.industrial_scheduler.inspirations == ["MDASH"]
    assert result.industrial_scheduler.execution_mode == "plan_only_orchestration"
    assert all(task.scope_checked for task in result.industrial_scheduler.dag_tasks)
    assert any(
        len(batch.task_ids) > 1
        for batch in result.industrial_scheduler.parallel_batches
    )
    assert result.industrial_scheduler.lifecycle.states[0] == "candidate"
    assert result.industrial_scheduler.patch_validation.execution_allowed is False
    audit_events = {event["event"]: event for event in result.audit_log}
    assert audit_events["industrial_scheduler_planned"]["blocked_transition_guard_count"] == 5
    assert "Lifecycle transition guards: 5 blocked" in result.report_markdown
    assert "## Industrial Scheduling" in result.report_markdown
    assert any(
        event["event"] == "industrial_scheduler_planned"
        for event in result.audit_log
    )


def test_run_source_audit_integrates_deep_research_plan(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                '@router.get("/api/orders/{order_id}")',
                "def get_order(order_id: str):",
                "    return send_file(order_id)",
                "",
                "def decode_order_token(raw: bytes):",
                "    return raw.decode()",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "\n".join(
            [
                "allowed_repos:",
                f"  - {repo}",
                "bug_bounty:",
                "  test_accounts:",
                "    - label: buyer_a",
                "      role: buyer",
                "    - label: admin_a",
                "      role: admin",
            ]
        ),
        encoding="utf-8",
    )

    result = run_source_audit(
        repo,
        scope,
        semgrep_runner=lambda _: {"status": "completed", "results": []},
    )

    assert result.deep_research.stage == "v4_deep_vulnerability_research"
    assert result.deep_research.inspirations == ["Mythos", "Big Sleep"]
    assert result.deep_research.execution_mode == "deep_reasoning_plan_only"
    assert result.deep_research.permission_model.roles == ["admin", "buyer"]
    assert result.deep_research.vulnerability_chains[0].execution_allowed is False
    audit_events = {event["event"]: event for event in result.audit_log}
    assert audit_events["deep_research_planned"]["unresolved_refutation_count"] == 1
    assert "Refutation matrix: 1 unresolved chain(s) require human review" in (
        result.report_markdown
    )
    assert result.deep_research.long_horizon_plan.iteration_strategy == "refute_then_branch"
    assert result.deep_research.evidence_graph.edges[0].relationship == "supports_chain"
    assert result.deep_research.knowledge_consolidation_queue[0].human_review_required is True
    assert "## Deep Research" in result.report_markdown
    assert "Evidence graph nodes" in result.report_markdown
    assert "Knowledge queue items" in result.report_markdown
    assert any(event["event"] == "deep_research_planned" for event in result.audit_log)


def test_cli_scan_writes_report_findings_and_audit_log(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "requirements.txt").write_text("fastapi==0.127.0\n", encoding="utf-8")
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str):",
                "    return send_file(file_id)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")
    report = tmp_path / "report.md"
    findings = tmp_path / "findings.json"
    audit_log = tmp_path / "audit-log.json"
    crs_plan = tmp_path / "crs-plan.json"

    exit_code = cli_main(
        [
            "scan",
            "--repo",
            str(repo),
            "--scope",
            str(scope),
            "--output",
            str(report),
            "--findings-output",
            str(findings),
            "--audit-log",
            str(audit_log),
            "--crs-plan-output",
            str(crs_plan),
        ]
    )

    assert exit_code == 0
    assert "## Dependencies" in report.read_text(encoding="utf-8")
    assert json.loads(findings.read_text(encoding="utf-8"))[0]["finding_id"] == "H-001"
    assert json.loads(audit_log.read_text(encoding="utf-8"))[0]["event"] == "scope_checked"
    assert json.loads(crs_plan.read_text(encoding="utf-8"))["execution_mode"] == "plan_only"


def test_cli_scan_writes_authorized_bug_bounty_plan(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                '@router.post("/api/admin/users/{user_id}/role")',
                "def change_role(user_id: str):",
                "    return update_role(user_id)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.json"
    scope.write_text(
        json.dumps(
            {
                "allowed_repos": [str(repo)],
                "bug_bounty": {
                    "allowed_assets": ["api.example.com"],
                    "test_accounts": [
                        {"label": "admin_a", "role": "admin", "api_key": "secret-api-key"},
                        {"label": "user_a", "role": "user", "password": "secret-password"},
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    report = tmp_path / "report.md"
    v2_plan = tmp_path / "v2-plan.json"

    exit_code = cli_main(
        [
            "scan",
            "--repo",
            str(repo),
            "--scope",
            str(scope),
            "--output",
            str(report),
            "--v2-plan-output",
            str(v2_plan),
        ]
    )

    plan = json.loads(v2_plan.read_text(encoding="utf-8"))
    serialized = json.dumps(plan)
    assert exit_code == 0
    assert plan["stage"] == "v2_authorized_bug_bounty"
    assert plan["execution_mode"] == "plan_only"
    assert plan["report_draft"]["auto_submit_allowed"] is False
    assert "secret-api-key" not in serialized
    assert "secret-password" not in serialized


def test_cli_scan_writes_industrial_scheduler_plan(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                '@router.get("/api/orders/{order_id}")',
                "def get_order(order_id: str):",
                "    return send_file(order_id)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")
    report = tmp_path / "report.md"
    v3_plan = tmp_path / "v3-plan.json"

    exit_code = cli_main(
        [
            "scan",
            "--repo",
            str(repo),
            "--scope",
            str(scope),
            "--output",
            str(report),
            "--v3-plan-output",
            str(v3_plan),
        ]
    )

    plan = json.loads(v3_plan.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert plan["stage"] == "v3_multi_agent_industrial_scheduling"
    assert plan["execution_mode"] == "plan_only_orchestration"
    assert plan["continuous_scan"]["execution_allowed"] is False
    assert plan["patch_validation"]["approval_required"] is True


def test_cli_scan_writes_deep_research_plan(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                '@router.get("/api/orders/{order_id}")',
                "def get_order(order_id: str):",
                "    return send_file(order_id)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")
    report = tmp_path / "report.md"
    v4_plan = tmp_path / "v4-plan.json"

    exit_code = cli_main(
        [
            "scan",
            "--repo",
            str(repo),
            "--scope",
            str(scope),
            "--output",
            str(report),
            "--v4-plan-output",
            str(v4_plan),
        ]
    )

    plan = json.loads(v4_plan.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert plan["stage"] == "v4_deep_vulnerability_research"
    assert plan["execution_mode"] == "deep_reasoning_plan_only"
    assert plan["vulnerability_chains"][0]["execution_allowed"] is False
    assert plan["evidence_graph"]["storage_policy"] == "metadata_only_no_raw_secret_or_user_data"
    assert plan["knowledge_consolidation_queue"][0]["human_review_required"] is True
    assert "no_exploit_generation" in plan["safety_invariants"]


def test_cli_scan_accepts_patch_diff_metadata_for_v4_advisory_learning(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                '@router.get("/api/orders/{order_id}")',
                "def get_order(order_id: str):",
                "    return send_file(order_id)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")
    patch_diff = tmp_path / "patch-diff.json"
    patch_diff.write_text(
        json.dumps(
            {
                "linked_hypothesis_id": "H-001",
                "changed_files": ["app/services/orders.py"],
                "root_cause": "missing_object_ownership_check",
                "fix_strategy": "service_layer_owner_guard",
                "regression_test": "test_user_cannot_read_peer_order",
                "raw_diff": "Authorization: Bearer should-not-leak",
            }
        ),
        encoding="utf-8",
    )
    report = tmp_path / "report.md"
    v4_plan = tmp_path / "v4-plan.json"
    knowledge = tmp_path / "knowledge.json"

    exit_code = cli_main(
        [
            "scan",
            "--repo",
            str(repo),
            "--scope",
            str(scope),
            "--output",
            str(report),
            "--patch-diff-metadata",
            str(patch_diff),
            "--v4-plan-output",
            str(v4_plan),
            "--knowledge-output",
            str(knowledge),
        ]
    )

    plan = json.loads(v4_plan.read_text(encoding="utf-8"))
    artifact = json.loads(knowledge.read_text(encoding="utf-8"))
    serialized = json.dumps({"plan": plan, "artifact": artifact})
    assert exit_code == 0
    assert plan["patch_diff_learner"]["status"] == "advisory_pattern_ready"
    assert plan["patch_diff_learner"]["learned_patterns"][0]["execution_allowed"] is False
    assert plan["patch_diff_learner"]["learned_patterns"][0]["human_review_required"] is True
    assert any(
        entry["source_ref"] == "patch_diff:H-001"
        and entry["review_required"] is True
        for entry in artifact["entries"]
    )
    assert "should-not-leak" not in serialized


def test_cli_scan_writes_advisory_knowledge_artifact(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                '@router.get("/api/orders/{order_id}")',
                "def get_order(order_id: str):",
                "    return send_file(order_id)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")
    report = tmp_path / "report.md"
    knowledge = tmp_path / "knowledge.json"

    exit_code = cli_main(
        [
            "scan",
            "--repo",
            str(repo),
            "--scope",
            str(scope),
            "--output",
            str(report),
            "--knowledge-output",
            str(knowledge),
        ]
    )

    artifact = json.loads(knowledge.read_text(encoding="utf-8"))
    assert exit_code == 0
    assert artifact["artifact_type"] == "v4_advisory_knowledge"
    assert artifact["status"] == "requires_human_review"
    assert artifact["entries"][0]["review_required"] is True
    assert artifact["storage_policy"] == "metadata_only_no_raw_secret_or_user_data"


def test_cli_scan_can_persist_source_audit_pipeline_run(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str):",
                "    return send_file(file_id)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")
    report = tmp_path / "report.md"
    run_output = tmp_path / "pipeline-run.json"
    database_path = tmp_path / "aegis.sqlite"

    exit_code = cli_main(
        [
            "scan",
            "--repo",
            str(repo),
            "--scope",
            str(scope),
            "--output",
            str(report),
            "--pipeline-db",
            f"sqlite:///{database_path.as_posix()}",
            "--pipeline-run-output",
            str(run_output),
        ]
    )

    engine = create_engine(
        f"sqlite:///{database_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        repository = DatabaseRepository(session)
        saved = json.loads(run_output.read_text(encoding="utf-8"))
        record = repository.get_pipeline_run(saved["run_id"])
        assert exit_code == 0
        assert record is not None
        assert record.payload["artifact_kind"] == "source_audit"
        assert record.payload["crs_fuzzing"]["execution_mode"] == "plan_only"
        assert record.payload["authorized_bug_bounty"]["execution_mode"] == "plan_only"
        assert (
            record.payload["industrial_scheduler"]["execution_mode"]
            == "plan_only_orchestration"
        )
        assert (
            record.payload["deep_research"]["execution_mode"]
            == "deep_reasoning_plan_only"
        )
        assert record.payload["hypotheses"][0]["refutation_status"] == "unverified"
        assert record.payload["hypotheses"][0]["false_positive_checks"] == [
            "authorization may be enforced in middleware or dependency injection",
            "service layer may enforce object ownership before returning data",
            "route may only expose public or self-owned resources",
        ]
        assert record.payload["report_draft"]["human_review_required"] is True
        assert record.payload["validation_gate"]["status"] == "awaiting_approval"
        assert build_report_preview_response(record).submission_blocked is True
        artifact = repository.get_artifact(record.payload["artifact"]["artifact_id"])
        assert artifact is not None
        assert any(
            usage["usage_type"] == "pipeline_run"
            and usage["run_id"] == record.id
            for usage in artifact.provenance["usage_records"]
        )
        assert "send_file(file_id)" not in str(record.payload)
    finally:
        session.close()


def test_cli_scan_writes_reproducible_v0_to_v4_smoke_receipt(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                '@router.post("/api/orders/{order_id}/refund")',
                "def refund_order(order_id: str):",
                "    return send_file(order_id)",
            ]
        ),
        encoding="utf-8",
    )
    (repo / "parser.py").write_text(
        "\n".join(
            [
                "import json",
                "def decode_invoice_payload(raw: bytes):",
                "    return json.loads(raw.decode())",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.json"
    scope.write_text(
        json.dumps(
            {
                "allowed_repos": [str(repo)],
                "bug_bounty": {
                    "allowed_assets": ["api.example.com"],
                    "test_accounts": [
                        {"label": "admin_a", "role": "admin", "password": "secret-password"},
                        {"label": "buyer_a", "role": "buyer", "api_key": "secret-api-key"},
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    outputs = {
        "report": tmp_path / "report.md",
        "findings": tmp_path / "findings.json",
        "audit_log": tmp_path / "audit-log.json",
        "crs_plan": tmp_path / "crs-plan.json",
        "v2_plan": tmp_path / "v2-plan.json",
        "v3_plan": tmp_path / "v3-plan.json",
        "v4_plan": tmp_path / "v4-plan.json",
        "knowledge": tmp_path / "knowledge.json",
        "run": tmp_path / "pipeline-run.json",
    }
    database_path = tmp_path / "aegis.sqlite"

    exit_code = cli_main(
        [
            "scan",
            "--repo",
            str(repo),
            "--scope",
            str(scope),
            "--output",
            str(outputs["report"]),
            "--findings-output",
            str(outputs["findings"]),
            "--audit-log",
            str(outputs["audit_log"]),
            "--crs-plan-output",
            str(outputs["crs_plan"]),
            "--v2-plan-output",
            str(outputs["v2_plan"]),
            "--v3-plan-output",
            str(outputs["v3_plan"]),
            "--v4-plan-output",
            str(outputs["v4_plan"]),
            "--knowledge-output",
            str(outputs["knowledge"]),
            "--pipeline-db",
            f"sqlite:///{database_path.as_posix()}",
            "--pipeline-run-output",
            str(outputs["run"]),
        ]
    )

    receipt = json.loads(outputs["run"].read_text(encoding="utf-8"))
    assert exit_code == 0
    assert receipt["run_id"].startswith("pipeline_run_")
    assert receipt["written_outputs"] == {
        key: str(path)
        for key, path in outputs.items()
        if key != "run"
    }
    assert receipt["safety_gate_summary"] == {
        "scope_guard_required": True,
        "execution_allowed": False,
        "human_review_required": True,
        "auto_submit_allowed": False,
    }
    assert receipt["audit_gate_summary"] == {
        "crash_promotion_gate": "blocked_until_reproducible_local_crash",
        "crash_promotion_allowed": False,
        "blocked_preflight_checks": [
            "durable_human_approval",
            "redacted_evidence_package",
        ],
        "blocked_transition_guard_count": 5,
        "unresolved_refutation_count": 1,
    }
    assert {
        stage["name"]: stage["execution_allowed"]
        for stage in receipt["timeline_stages"]
    } == {
        "source_scope": False,
        "source_intake": False,
        "static_analysis": False,
        "hypotheses": False,
        "crs_fuzzing": False,
        "authorized_bug_bounty": False,
        "industrial_scheduler": False,
        "deep_research": False,
        "report_draft": False,
    }
    for path in outputs.values():
        assert path.exists()

    serialized_outputs = "\n".join(
        path.read_text(encoding="utf-8")
        for path in outputs.values()
        if path.suffix in {".json", ".md"}
    )
    assert "secret-password" not in serialized_outputs
    assert "secret-api-key" not in serialized_outputs


def test_cli_scan_persists_patch_diff_v4_plan_in_pipeline_run(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                '@router.get("/api/orders/{order_id}")',
                "def get_order(order_id: str):",
                "    return send_file(order_id)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")
    patch_diff = tmp_path / "patch-diff.json"
    patch_diff.write_text(
        json.dumps(
            {
                "linked_hypothesis_id": "H-001",
                "changed_files": ["app/services/orders.py"],
                "root_cause": "missing_object_ownership_check",
                "fix_strategy": "service_layer_owner_guard",
                "regression_test": "test_user_cannot_read_peer_order",
                "raw_diff": "Authorization: Bearer should-not-leak",
            }
        ),
        encoding="utf-8",
    )
    report = tmp_path / "report.md"
    run_output = tmp_path / "pipeline-run.json"
    database_path = tmp_path / "aegis.sqlite"

    exit_code = cli_main(
        [
            "scan",
            "--repo",
            str(repo),
            "--scope",
            str(scope),
            "--output",
            str(report),
            "--patch-diff-metadata",
            str(patch_diff),
            "--pipeline-db",
            f"sqlite:///{database_path.as_posix()}",
            "--pipeline-run-output",
            str(run_output),
        ]
    )

    engine = create_engine(
        f"sqlite:///{database_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )
    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        repository = DatabaseRepository(session)
        saved = json.loads(run_output.read_text(encoding="utf-8"))
        record = repository.get_pipeline_run(saved["run_id"])
        assert exit_code == 0
        assert record is not None
        patch_plan = record.payload["deep_research"]["patch_diff_learner"]
        serialized = json.dumps(record.payload)
        assert patch_plan["status"] == "advisory_pattern_ready"
        assert patch_plan["learned_patterns"][0]["execution_allowed"] is False
        assert patch_plan["learned_patterns"][0]["human_review_required"] is True
        assert "should-not-leak" not in serialized
    finally:
        session.close()


def test_chat_help_lists_safe_terminal_actions():
    output = run_chat(["help", "exit"])

    assert "mythos chat" in output
    assert "repo <path>" in output
    assert "scope <path>" in output
    assert "scan" in output
    assert "validation execution: disabled" in output


def test_chat_runs_source_audit_with_human_gated_summary(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str):",
                "    return send_file(file_id)",
            ]
        ),
        encoding="utf-8",
    )
    scope = tmp_path / "scope.yaml"
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    output = run_chat(
        [
            f"repo {repo}",
            f"scope {scope}",
            "scan",
            "status",
            "exit",
        ]
    )

    assert "repo set:" in output
    assert "scope set:" in output
    assert "source audit complete" in output
    assert "scope: allowed" in output
    assert "validation execution: disabled" in output
    assert "human review: required" in output
    assert "last run: source audit" in output
    assert "send_file(file_id)" not in output


def test_cli_chat_reads_terminal_commands(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("help\nexit\n"))

    exit_code = cli_main(["chat"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "mythos>" in captured.out
    assert "mythos chat" in captured.out
    assert "validation execution: disabled" in captured.out


def test_source_audit_api_creates_pipeline_run_and_report_preview(tmp_path):
    repo, scope = controlled_source_audit_paths(tmp_path)
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str):",
                "    return send_file(file_id)",
            ]
        ),
        encoding="utf-8",
    )
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/source-audit/scans",
            json={
                "repo_path": str(repo),
                "scope_path": str(scope),
                "policy_text": "local source audit scope policy",
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["run_id"].startswith("pipeline_run_")
        assert body["artifact_id"].startswith("artifact_")
        assert body["scope_status"] == "in_scope"
        assert body["hypothesis_count"] >= 1
        assert body["submission_blocked"] is True
        assert body["safety_notes"] == [
            "scope_guard_required",
            "local_files_only",
            "no_live_requests",
            "no_auto_submission",
        ]
        assert body["safety_gate_summary"] == {
            "scope_guard_required": True,
            "execution_allowed": False,
            "human_review_required": True,
            "auto_submit_allowed": False,
        }
        assert body["audit_gate_summary"] == {
            "crash_promotion_gate": "blocked_until_reproducible_local_crash",
                "crash_promotion_allowed": False,
                "blocked_preflight_checks": [
                    "test_account_roles",
                    "durable_human_approval",
                "redacted_evidence_package",
            ],
            "blocked_transition_guard_count": 5,
            "unresolved_refutation_count": 1,
        }
        assert {
            stage["name"]: stage["execution_allowed"]
            for stage in body["timeline_stage_summary"]
        } == {
            "source_scope": False,
            "source_intake": False,
            "static_analysis": False,
            "hypotheses": False,
            "crs_fuzzing": False,
            "authorized_bug_bounty": False,
            "industrial_scheduler": False,
            "deep_research": False,
            "report_draft": False,
        }

        list_response = client.get("/mythos/pipeline/runs")
        assert list_response.status_code == 200
        summary = next(
            run for run in list_response.json() if run["id"] == body["run_id"]
        )
        assert summary["safety_gate_summary"] == body["safety_gate_summary"]
        assert summary["audit_gate_summary"] == body["audit_gate_summary"]
        assert summary["timeline_stage_summary"] == body["timeline_stage_summary"]

        detail = client.get(f"/mythos/pipeline/runs/{body['run_id']}")
        assert detail.status_code == 200
        detail_payload = detail.json()["payload"]
        assert detail_payload["artifact_kind"] == "source_audit"
        assert detail_payload["safety_gate_summary"] == body["safety_gate_summary"]
        assert detail_payload["audit_gate_summary"] == body["audit_gate_summary"]
        assert detail_payload["timeline_stage_summary"] == body["timeline_stage_summary"]
        timeline_by_name = {
            stage["name"]: stage
            for stage in detail_payload["timeline"]
        }
        for stage_name in (
            "crs_fuzzing",
            "authorized_bug_bounty",
            "industrial_scheduler",
            "deep_research",
        ):
            assert stage_name in timeline_by_name
            stage = timeline_by_name[stage_name]
            assert stage["details"]["agent_boundary"]["execution_allowed"] is False
            assert stage["safety_notes"]
        assert timeline_by_name["authorized_bug_bounty"]["status"] == (
            "human_review_required"
        )
        assert timeline_by_name["deep_research"]["status"] == "human_review_required"
        workspace = detail_payload["validation_workspace"]
        assert workspace["status"] == "awaiting_approval"
        assert workspace["allowed_to_execute"] is False
        assert workspace["approval_gate"]["human_approved"] is False
        claim_tasks = workspace["claim_validation_tasks"]
        assert any(
            task["claim_type"] == "observed_fact"
            and task["human_review_required"] is True
            for task in claim_tasks
        )
        closed_loop = detail_payload["closed_loop_summary"]
        assert closed_loop["status"] == "not_started"
        assert closed_loop["safety_notes"] == [
            "source_audit_hypotheses_only",
            "local_files_only",
            "no_live_requests",
            "human_review_required",
            "submission_blocked",
        ]
        steps_by_key = {step["key"]: step for step in closed_loop["steps"]}
        assert steps_by_key["source_audit_review"]["next_allowed_action"] == (
            "Open the validation workspace and attach sanitized local evidence."
        )
        assert steps_by_key["report_preview"]["next_allowed_action"] == (
            "Review the submission-blocked report preview before claim review."
        )
        assert steps_by_key["finding_candidate"]["next_allowed_action"] == (
            "Wait for sanitized evidence and human claim review before promotion."
        )

        preview = client.get(f"/mythos/pipeline/runs/{body['run_id']}/report-preview")
        assert preview.status_code == 200
        preview_body = preview.json()
        assert preview_body["submission_blocked"] is True
        assert preview_body["safety_gate_summary"] == body["safety_gate_summary"]
        assert preview_body["audit_gate_summary"] == body["audit_gate_summary"]
        assert "send_file(file_id)" not in str(detail.json())
    finally:
        app.dependency_overrides.clear()


def test_source_audit_api_accepts_patch_diff_metadata_for_v4_plan(tmp_path):
    repo, scope = controlled_source_audit_paths(tmp_path)
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                '@router.get("/api/orders/{order_id}")',
                "def get_order(order_id: str):",
                "    return send_file(order_id)",
            ]
        ),
        encoding="utf-8",
    )
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/source-audit/scans",
            json={
                "repo_path": str(repo),
                "scope_path": str(scope),
                "policy_text": "local source audit scope policy",
                "patch_diff_metadata": {
                    "linked_hypothesis_id": "H-001",
                    "changed_files": ["app/services/orders.py"],
                    "root_cause": "missing_object_ownership_check",
                    "fix_strategy": "service_layer_owner_guard",
                    "regression_test": "test_user_cannot_read_peer_order",
                    "raw_diff": "Authorization: Bearer should-not-leak",
                },
            },
        )

        assert response.status_code == 200
        run_id = response.json()["run_id"]
        detail = client.get(f"/mythos/pipeline/runs/{run_id}")
        assert detail.status_code == 200
        payload = detail.json()["payload"]
        patch_plan = payload["deep_research"]["patch_diff_learner"]
        serialized = json.dumps(payload)
        assert patch_plan["status"] == "advisory_pattern_ready"
        assert patch_plan["learned_patterns"][0]["execution_allowed"] is False
        assert patch_plan["learned_patterns"][0]["human_review_required"] is True
        assert "should-not-leak" not in serialized
    finally:
        app.dependency_overrides.clear()


def test_source_audit_api_promotes_candidate_only_after_manual_evidence_gates(tmp_path):
    repo, scope = controlled_source_audit_paths(tmp_path)
    (repo / "routes.py").write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
                '@router.get("/files/{file_id}/export")',
                "def export_file(file_id: str):",
                "    return send_file(file_id)",
            ]
        ),
        encoding="utf-8",
    )
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")
    app.dependency_overrides[get_session] = override_session()
    try:
        scan_response = client.post(
            "/mythos/source-audit/scans",
            json={
                "repo_path": str(repo),
                "scope_path": str(scope),
                "policy_text": "local source audit scope policy",
            },
        )
        assert scan_response.status_code == 200
        run_id = scan_response.json()["run_id"]

        blocked_candidate = client.post(
            f"/mythos/pipeline/runs/{run_id}/finding-candidates"
        )
        assert blocked_candidate.status_code == 422
        assert blocked_candidate.json()["detail"] == (
            "No claim is ready for candidate promotion"
        )

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        preview = preview_response.json()
        assert preview["submission_blocked"] is True
        observed_claim = next(
            claim
            for claim in preview["claim_ledger"]
            if claim["claim_type"] == "observed_fact"
        )

        observation_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/manual-observations",
            json={
                "claim_id": observed_claim["claim_id"],
                "observation_type": "request_response_diff",
                "observer": "lead_reviewer",
                "observation": "Reviewer attached a sanitized local fixture diff.",
                "evidence_refs": ["request_response_diff"],
                "safety_notes": [
                    "test_accounts_only",
                    "no_real_user_data",
                    "human_review_required",
                ],
            },
        )
        assert observation_response.status_code == 200
        observation = observation_response.json()
        assert observation["observation_type"] == "request_response_diff"
        assert observation["evidence_refs"] == ["request_response_diff"]

        review_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/claim-review-decisions",
            json={
                "claim_id": observed_claim["claim_id"],
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Confirmed from sanitized local fixture only.",
                "evidence_refs": ["request_response_diff"],
            },
        )
        assert review_response.status_code == 200
        review = review_response.json()
        assert review["decision"] == "confirmed_observed_fact"
        assert review["evidence_refs"] == ["request_response_diff"]

        candidate_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/finding-candidates"
        )
        assert candidate_response.status_code == 200
        candidate = candidate_response.json()
        assert candidate["id"].startswith("finding_candidate_")
        assert candidate["validation_status"] == "validation_plan_ready"
        assert candidate["submission_recommendation"] == "promote_to_finding_candidate"
        assert candidate["evidence_refs"] == ["request_response_diff"]

        detail_response = client.get(f"/mythos/pipeline/runs/{run_id}")
        assert detail_response.status_code == 200
        detail = detail_response.json()
        assert detail["closed_loop_summary"]["status"] == "finding_candidate_created"
        assert detail["payload"]["report_draft"]["auto_submit_allowed"] is False
        assert "send_file(file_id)" not in str(detail)
        assert "send_file(file_id)" not in str(candidate)
    finally:
        app.dependency_overrides.clear()


def test_source_audit_api_blocks_unallowlisted_repo_without_pipeline_run(tmp_path):
    repo, scope = controlled_source_audit_paths(tmp_path)
    scope.write_text("allowed_repos:\n  - C:/different/repo\n", encoding="utf-8")
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/source-audit/scans",
            json={
                "repo_path": str(repo),
                "scope_path": str(scope),
                "policy_text": "local source audit scope policy",
            },
        )

        assert response.status_code == 403
        assert response.json()["detail"] == "repo_not_allowlisted"
        assert client.get("/mythos/pipeline/runs").json() == []
    finally:
        app.dependency_overrides.clear()


def test_source_audit_result_persists_as_human_gated_pipeline_run(tmp_path):
    repo = tmp_path / "target"
    repo.mkdir()
    route = repo / "routes.py"
    route.write_text(
        "\n".join(
            [
                "from fastapi import APIRouter",
                "router = APIRouter()",
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
                        "message": "Review exported file authorization.",
                        "metadata": {"category": "security", "confidence": "MEDIUM"},
                    },
                }
            ],
        },
    )

    session = build_session()
    try:
        repository = DatabaseRepository(session)
        record = save_source_audit_pipeline_run(
            repository=repository,
            result=result,
            policy_text="local source audit scope policy",
        )
        preview = build_report_preview_response(record)

        assert record.id.startswith("pipeline_run_")
        assert record.scope_status == "in_scope"
        assert record.hypothesis_count == len(result.hypotheses)
        assert record.payload["artifact_kind"] == "source_audit"
        assert record.payload["source_audit"]["semgrep"]["finding_count"] == 1
        assert record.payload["report_draft"]["human_review_required"] is True
        assert record.payload["validation_gate"]["status"] == "awaiting_approval"
        assert record.payload["artifact"]["report_chain_allowed"] is True
        for stage in record.payload["timeline"]:
            assert stage["input_summary"]
            assert stage["output_summary"]
            assert stage["safety_notes"]
            assert stage["details"]["agent_boundary"]["execution_allowed"] is False
            assert stage["details"]["agent_boundary"]["requires_human_review"] in {
                True,
                False,
            }
        assert "send_file(file_id)" not in str(record.payload)
        artifact = repository.get_artifact(record.payload["artifact"]["artifact_id"])
        assert artifact is not None
        usage_records = artifact.provenance["usage_records"]
        assert {
            "usage_type": "pipeline_run",
            "ref": f"run:{record.id}",
            "run_id": record.id,
            "stage": "pipeline_persistence",
        } in usage_records
        assert any(
            usage["usage_type"] == "evidence_bundle"
            and usage["run_id"] == record.id
            and usage["stage"] == "evidence_model"
            for usage in usage_records
        )
        assert any(
            usage["usage_type"] == "report_claim"
            and usage["run_id"] == record.id
            and usage["stage"] == "report_preview"
            for usage in usage_records
        )

        assert preview.submission_blocked is True
        observed_claim = next(
            claim for claim in preview.claim_ledger if claim.claim_type == "observed_fact"
        )
        assert observed_claim.readiness_level == "needs_human_review"
        assert observed_claim.evidence_refs
        with pytest.raises(ValueError, match="No claim is ready for candidate promotion"):
            promote_pipeline_run_to_finding_candidate(
                repository=repository,
                record=record,
                preview=preview,
            )

        updated = repository.append_manual_observation(
            run_id=record.id,
            claim_exists=True,
            claim_type="observed_fact",
            observation={
                "claim_id": observed_claim.claim_id,
                "observation_type": "request_response_diff",
                "observer": "lead_reviewer",
                "observation": "Reviewer attached a sanitized local fixture diff.",
                "evidence_refs": ["request_response_diff"],
            },
        )
        assert updated is not None
        reviewed = repository.append_claim_review_decision(
            run_id=record.id,
            claim_type="observed_fact",
            evidence_refs_supported=True,
            decision={
                "claim_id": observed_claim.claim_id,
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Confirmed from sanitized local fixture only.",
                "evidence_refs": ["request_response_diff"],
                "reviewed_at": "2026-07-07T00:00:00+00:00",
            },
        )
        assert reviewed is not None
        reviewed_preview = build_report_preview_response(reviewed)
        candidate = promote_pipeline_run_to_finding_candidate(
            repository=repository,
            record=reviewed,
            preview=reviewed_preview,
        )

        assert candidate.id.startswith("finding_candidate_")
        assert candidate.validation_status == "validation_plan_ready"
        assert candidate.submission_recommendation == "promote_to_finding_candidate"
        assert candidate.evidence_refs == ["request_response_diff"]
    finally:
        session.close()


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


def test_run_source_audit_default_does_not_launch_semgrep(monkeypatch, tmp_path):
    repo, scope = controlled_source_audit_paths(tmp_path)
    (repo / "app.py").write_text("print('safe fixture')\n", encoding="utf-8")
    scope.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")

    def fail_if_called(*args, **kwargs):
        raise AssertionError("default source audit must not launch semgrep")

    monkeypatch.setattr("subprocess.run", fail_if_called)

    result = run_source_audit(repo, scope)

    assert result.semgrep.status == "skipped"
    assert result.semgrep.summary == "semgrep_requires_explicit_human_runner"
    assert result.semgrep.findings == []


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


def test_run_semgrep_is_plan_only_compatibility_shim(monkeypatch, tmp_path):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("legacy run_semgrep must not launch a subprocess")

    monkeypatch.setattr("subprocess.run", fail_if_called)

    payload = run_semgrep(tmp_path)
    findings = normalize_semgrep_json(payload)

    assert payload == {
        "status": "skipped",
        "results": [],
        "summary": "semgrep_requires_explicit_human_runner",
    }
    assert findings == []


def test_load_scope_policy_accepts_utf8_bom_scope_files(tmp_path):
    repo = tmp_path / "target"
    scope = tmp_path / "scope.yaml"
    scope.write_bytes(f"\ufeffallowed_repos:\n  - {repo}\n".encode("utf-8"))

    assert load_scope_policy(scope) == {"allowed_repos": [str(repo)]}


def test_load_scope_policy_accepts_bug_bounty_yaml_fields(tmp_path):
    repo = tmp_path / "target"
    scope = tmp_path / "scope.yaml"
    scope.write_text(
        "\n".join(
            [
                "allowed_repos:",
                f"  - {repo}",
                "bug_bounty:",
                "  allowed_assets:",
                "    - api.example.com",
                "  test_accounts:",
                "    - label: buyer_a",
                "      role: buyer",
                "      password: should-not-leak",
                "    - label: admin_a",
                "      role: admin",
            ]
        ),
        encoding="utf-8",
    )

    assert load_scope_policy(scope) == {
        "allowed_repos": [str(repo)],
        "bug_bounty": {
            "allowed_assets": ["api.example.com"],
            "test_accounts": [
                {
                    "label": "buyer_a",
                    "role": "buyer",
                    "password": "should-not-leak",
                },
                {
                    "label": "admin_a",
                    "role": "admin",
                },
            ],
        },
    }


def test_build_source_hypotheses_labels_graphql_operations_without_http_verb():
    mapped = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "gql/records.py",
                    "content": """
import strawberry


@strawberry.type
class Query:
    @strawberry.field
    def record(self, info, record_id: str):
        return send_file(record_id)
""",
                }
            ]
        }
    )

    hypotheses = build_source_hypotheses(mapped.facts, [])

    assert len(hypotheses) == 1
    hypothesis = hypotheses[0]
    assert hypothesis.location == "GraphQL query record"
    assert hypothesis.source_facts[0]["entrypoint_kind"] == "graphql_operation"
    assert hypothesis.source_facts[0]["graphql_operation_type"] == "query"
    assert hypothesis.source_facts[0]["graphql_operation_name"] == "record"


def test_graphql_operations_have_distinct_intake_and_evidence_references(tmp_path):
    authorized_files = [
        {
            "path": "gql/records.py",
            "content": """
import strawberry


@strawberry.type
class Query:
    @strawberry.field
    def record(self, info, record_id: str):
        return send_file(record_id)

    @strawberry.field
    def invoice(self, info, invoice_id: str):
        return send_file(invoice_id)
""",
        }
    ]
    mapped = map_authorized_code_files({"authorized_code_files": authorized_files})

    intake = build_intake_profile(tmp_path, authorized_files, mapped.facts)
    hypotheses = build_source_hypotheses(mapped.facts, [])

    assert intake.entrypoints == ["GraphQL query invoice", "GraphQL query record"]
    assert {
        hypothesis.source_facts[0]["fact_ref"] for hypothesis in hypotheses
    } == {
        "codebase_fact:authorization_gap_candidate:graphql:gql/records.py:query:invoice",
        "codebase_fact:authorization_gap_candidate:graphql:gql/records.py:query:record",
    }


def test_graphql_operation_evidence_references_keep_the_source_path():
    authorized_files = [
        {
            "path": "gql/a.py",
            "content": """
import strawberry


@strawberry.type
class Query:
    @strawberry.field
    def record(self, info, record_id: str):
        return send_file(record_id)
""",
        },
        {
            "path": "gql/b.py",
            "content": """
import strawberry


@strawberry.type
class Query:
    @strawberry.field
    def record(self, info, record_id: str):
        return send_file(record_id)
""",
        },
    ]
    mapped = map_authorized_code_files({"authorized_code_files": authorized_files})

    hypotheses = build_source_hypotheses(mapped.facts, [])

    assert {
        hypothesis.source_facts[0]["fact_ref"] for hypothesis in hypotheses
    } == {
        "codebase_fact:authorization_gap_candidate:graphql:gql/a.py:query:record",
        "codebase_fact:authorization_gap_candidate:graphql:gql/b.py:query:record",
    }


def test_build_source_hypotheses_labels_graphene_operations_without_http_verb():
    mapped = map_authorized_code_files(
        {
            "authorized_code_files": [
                {
                    "path": "gql/records.py",
                    "content": """
import graphene


class Query(graphene.ObjectType):
    record = graphene.Field(str)

    def resolve_record(self, info, record_id):
        return send_file(record_id)
""",
                }
            ]
        }
    )

    hypotheses = build_source_hypotheses(mapped.facts, [])

    assert len(hypotheses) == 1
    hypothesis = hypotheses[0]
    assert hypothesis.location == "GraphQL query record"
    assert hypothesis.source_facts[0]["entrypoint_kind"] == "graphql_operation"
    assert hypothesis.source_facts[0]["graphql_operation_type"] == "query"
    assert hypothesis.source_facts[0]["graphql_operation_name"] == "record"
