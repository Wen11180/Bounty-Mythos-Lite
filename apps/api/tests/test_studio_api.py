from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_session
from app.main import (
    app,
    _studio_fuzzing_surface_facts,
    _studio_report_candidate_guidance,
)
from app.repository import DatabaseRepository


client = TestClient(app)


def test_studio_report_candidate_guidance_skips_redacted_values():
    record = SimpleNamespace(
        payload={
            "hypotheses": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization_gap",
                    "suggested_fix": "Rotate Authorization: Bearer secret-token",
                    "regression_test": "Store cookie: session=secret-token in a fixture",
                }
            ]
        }
    )

    guidance = _studio_report_candidate_guidance(record, {})

    assert "suggested_fix" not in guidance
    assert "regression_test" not in guidance
    assert "secret-token" not in str(guidance)


def test_studio_report_candidate_guidance_includes_evidence_gap_labels():
    record = SimpleNamespace(
        payload={
            "hypotheses": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization_gap",
                }
            ]
        }
    )

    guidance = _studio_report_candidate_guidance(record, {})

    assert guidance["evidence_gaps"] == [
        "scope: missing_required_artifact",
        "policy: missing_required_artifact",
        "code: missing_required_artifact",
        "api: missing_required_artifact",
        "har: missing_required_artifact",
    ]


def test_studio_report_candidate_guidance_includes_advisory_signal_labels():
    record = SimpleNamespace(
        payload={
            "hypotheses": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization_gap",
                    "source_facts": [
                        {
                            "fact_type": "scanner_signal",
                            "artifact_kind": "sarif",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                            "advisory_only": "true",
                        },
                        {
                            "fact_type": "dependency_signal",
                            "artifact_kind": "sbom",
                            "package_name": "django",
                            "package_version": "4.2.1",
                            "vulnerability_id": "CVE-2099-0001",
                            "severity": "high",
                            "advisory_only": "true",
                        },
                        {
                            "fact_type": "fuzzing_signal",
                            "artifact_kind": "fuzzing",
                            "target_symbol": "parse_export_manifest",
                            "candidate_type": "parser",
                            "harness_status": "planned",
                            "fuzzer_status": "not_executed",
                            "advisory_only": "true",
                        },
                    ],
                }
            ]
        }
    )

    guidance = _studio_report_candidate_guidance(record, {})

    assert guidance["advisory_signals"] == [
        "SARIF scanner advisory: GET /files/{file_id}/export",
        "SBOM dependency advisory: django 4.2.1 (CVE-2099-0001, high)",
        "Fuzzing plan advisory: parse_export_manifest (parser, planned, not_executed)",
    ]


def test_studio_fuzzing_surface_facts_ignore_executable_plans():
    facts = _studio_fuzzing_surface_facts(
        {
            "execution_mode": "approved_local_run",
            "parser_candidates": [
                {
                    "symbol_name": "parse_export_manifest",
                    "candidate_type": "parser",
                }
            ],
            "fuzzer_plan": {
                "engine": "libFuzzer",
                "status": "ready",
                "execution_allowed": True,
            },
        }
    )

    assert facts == []


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


def studio_test_session_override():
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

    return _override_get_session, testing_session


def write_policy_artifact(tmp_path: Path) -> Path:
    policy_path = tmp_path / "policy.md"
    policy_path.write_text(
        "Authorized local code plus API/HAR materials only. No live validation.",
        encoding="utf-8",
    )
    return policy_path


def write_api_artifact(tmp_path: Path, *, operation_id: str = "exportFile") -> Path:
    api_path = tmp_path / "openapi.json"
    api_path.write_text(
        f"""
{{
  "openapi": "3.0.0",
  "paths": {{
    "/files/{{file_id}}/export": {{
      "get": {{
        "operationId": "{operation_id}"
      }}
    }}
  }}
}}
""",
        encoding="utf-8",
    )
    return api_path


def write_har_artifact(tmp_path: Path) -> Path:
    har_path = tmp_path / "traffic.har"
    har_path.write_text(
        """
{
  "log": {
    "entries": [
      {
        "request": {
          "method": "GET",
          "url": "https://api.example.test/files/123/export"
        }
      }
    ]
  }
}
""",
        encoding="utf-8",
    )
    return har_path


def test_create_workspace_and_import_scope_updates_manifest(tmp_path: Path):
    response = client.post(
        "/mythos/studio/workspaces",
        json={"root_path": str(tmp_path), "name": "acme-api"},
    )

    assert response.status_code == 200
    workspace = response.json()
    assert workspace["path"] == str(tmp_path / "acme-api")

    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text("in_scope:\n  - api.example.com\n", encoding="utf-8")

    import_response = client.post(
        "/mythos/studio/workspaces/imports",
        json={
            "workspace_path": workspace["path"],
            "kind": "scope",
            "source_path": str(scope_path),
        },
    )

    assert import_response.status_code == 200
    manifest = import_response.json()
    assert manifest["safety"]["scope_guard_status"] == "scope_imported"
    assert manifest["artifacts"][0]["kind"] == "scope"


def test_import_missing_policy_source_returns_404(tmp_path: Path):
    response = client.post(
        "/mythos/studio/workspaces",
        json={"root_path": str(tmp_path), "name": "acme-api"},
    )
    assert response.status_code == 200

    import_response = client.post(
        "/mythos/studio/workspaces/imports",
        json={
            "workspace_path": response.json()["path"],
            "kind": "policy",
            "source_path": str(tmp_path / "missing-policy.md"),
        },
    )

    assert import_response.status_code == 404
    assert import_response.json()["detail"] == "artifact_source_not_found"


def test_studio_run_lists_candidates_and_exports_submission_blocked_report(
    tmp_path: Path,
):
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
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")
    policy_path = write_policy_artifact(tmp_path)
    api_path = write_api_artifact(tmp_path)
    har_path = write_har_artifact(tmp_path)

    app.dependency_overrides[get_session] = override_session()
    try:
        workspace_response = client.post(
            "/mythos/studio/workspaces",
            json={"root_path": str(tmp_path), "name": "acme-api"},
        )
        assert workspace_response.status_code == 200
        workspace_path = workspace_response.json()["path"]

        for kind, source_path in (
            ("scope", scope_path),
            ("policy", policy_path),
            ("code", repo),
            ("api", api_path),
            ("har", har_path),
        ):
            import_response = client.post(
                "/mythos/studio/workspaces/imports",
                json={
                    "workspace_path": workspace_path,
                    "kind": kind,
                    "source_path": str(source_path),
                },
            )
            assert import_response.status_code == 200

        run_response = client.post(
            "/mythos/studio/workspaces/runs",
            json={"workspace_path": workspace_path},
        )
        assert run_response.status_code == 200
        run_body = run_response.json()
        assert run_body["run_id"].startswith("pipeline_run_")
        assert run_body["submission_blocked"] is True
        assert run_body["candidate_count"] >= 1

        candidates_response = client.get(
            "/mythos/studio/workspaces/candidates",
            params={"workspace_path": workspace_path},
        )
        assert candidates_response.status_code == 200
        candidates = candidates_response.json()["candidates"]
        assert 1 <= len(candidates) <= 5
        assert candidates[0]["hypothesis_id"].startswith("H-")
        assert candidates[0]["safe_verification"] is True
        assert candidates[0]["broken_invariant"]
        assert candidates[0]["repair_guidance"]
        assert candidates[0]["regression_test"]
        assert candidates[0]["ranking_reasons"]
        assert candidates[0]["refutation_status"] == "unverified"
        assert candidates[0]["refutation_review"] == {
            "status": "needs_human_review",
            "questions": [
                "Does an upstream middleware or policy layer already enforce the claimed boundary?",
                "Can the affected endpoint and code path be reached under the authorized scope?",
                "Does a local two-account or role-fixture check refute the suspected impact?",
            ],
        }
        assert candidates[0]["duplicate_risk_score"] <= 49
        assert candidates[0]["deduplication_review"] == {
            "status": "needs_human_review",
            "duplicate_risk_score": candidates[0]["duplicate_risk_score"],
            "review_items": [
                "Compare endpoint, code path, invariant, and impact against prior submissions.",
                "Treat similar scanner, dependency, fuzzing, or strategy signals as advisory until novelty is reviewed.",
            ],
        }
        assert candidates[0]["policy_risk"] == "low"
        assert candidates[0]["policy_risk_score"] == 10
        assert candidates[0]["evidence_gaps"] == []
        assert candidates[0]["evidence_review"] == {
            "status": "needs_human_review",
            "required_items": [
                "Confirm the affected endpoint and code path using authorized local artifacts.",
                "Resolve evidence gaps and false-positive checks before validation.",
                "Complete redaction review before report export or sharing.",
            ],
        }
        assert candidates[0]["suggested_fix"] == (
            "Enforce the affected authorization or input boundary in the backend service layer before returning sensitive data or performing state changes."
        )
        assert candidates[0]["regression_test"] == (
            "Add a non-destructive local regression test proving the protected boundary rejects unauthorized cross-object access."
        )
        assert candidates[0]["validation_mode"] == "two_account_authorization_check"
        assert candidates[0]["safe_validation_plan"] == [
            "Prepare two authorized test accounts in a local or explicitly approved test environment.",
            "Confirm the target object belongs to account A before any access comparison.",
            "Have a human reviewer approve any non-destructive role or ownership check before execution.",
        ]
        assert candidates[0]["safety_blockers"] == [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
        ]
        assert candidates[0]["report_readiness"] == {
            "status": "submission_blocked",
            "report_submission_allowed": False,
            "next_allowed_action": "Review evidence, refutation checks, and safety blockers before exporting a report preview.",
        }
        assert any(
            fact.get("artifact_kind") == "code"
            and fact.get("source_path", "").endswith("routes.py")
            and fact.get("symbol_name") == "export_file"
            for fact in candidates[0]["source_facts"]
        )
        assert {"scope", "policy"}.issubset(
            {
                fact.get("artifact_kind")
                for fact in candidates[0]["source_facts"]
                if fact.get("fact_type", "").endswith("_context")
            }
        )
        assert "send_file(file_id)" not in str(candidates)

        template_response = client.post(
            "/mythos/studio/workspaces/benchmarks/template",
            json={"workspace_path": workspace_path, "run_id": run_body["run_id"]},
        )
        assert template_response.status_code == 200
        template_body = template_response.json()
        assert template_body["template_path"].endswith("-expectations-template.json")
        assert template_body["template"]["draft_review_required"] is True
        assert template_body["template"]["expected_candidates"][0]["code_path"] == (
            "routes.py:export_file"
        )
        assert template_body["template"]["expected_candidates"][0][
            "required_artifacts"
        ] == ["scope", "policy", "code", "api", "har"]
        assert template_body["manifest"]["benchmark_templates"][-1][
            "draft_review_required"
        ] is True
        assert template_body["manifest"]["runs"][-1]["benchmark_template_path"].endswith(
            "-expectations-template.json"
        )
        persisted_template = Path(template_body["template_path"]).read_text(
            encoding="utf-8"
        )
        assert "send_file(file_id)" not in persisted_template

        benchmark_response = client.post(
            "/mythos/studio/workspaces/benchmarks/run",
            json={
                "workspace_path": workspace_path,
                "run_id": run_body["run_id"],
                "expectations_path": template_body["template_path"],
            },
        )
        assert benchmark_response.status_code == 200
        benchmark = benchmark_response.json()
        assert benchmark["benchmark"]["status"] == "passed"
        assert benchmark["benchmark"]["matched"] == 1
        assert benchmark["benchmark"]["failures"] == []
        assert benchmark["benchmark_path"].endswith("-benchmark-result.json")
        assert benchmark["manifest"]["benchmarks"][-1]["status"] == "passed"
        assert benchmark["manifest"]["runs"][-1]["benchmark_status"] == "passed"
        persisted_benchmark = Path(benchmark["benchmark_path"]).read_text(
            encoding="utf-8"
        )
        assert '"status": "passed"' in persisted_benchmark
        assert "send_file(file_id)" not in persisted_benchmark

        export_response = client.post(
            "/mythos/studio/workspaces/reports/export",
            json={"workspace_path": workspace_path, "run_id": run_body["run_id"]},
        )
        assert export_response.status_code == 200
        export = export_response.json()
        assert export["run_id"] == run_body["run_id"]
        assert export["submission_blocked"] is True
        assert export["report_submission_allowed"] is False
        assert export["manifest"]["runs"][-1]["report_path"].endswith(".json")
        assert export["report_markdown_path"].endswith("-report-draft.md")
        assert export["manifest"]["runs"][-1]["report_markdown_path"].endswith(
            "-report-draft.md"
        )
        studio_context = export["report"]["studio_context"]
        assert studio_context["required_artifacts"] == [
            "scope",
            "policy",
            "code",
            "api",
            "har",
        ]
        assert {
            (fact.get("artifact_kind"), fact.get("route_method"), fact.get("route_path"))
            for fact in studio_context["surface_facts"]
        } >= {
            ("api", "GET", "/files/{file_id}/export"),
            ("har", "GET", "/files/123/export"),
        }
        markdown = Path(export["report_markdown_path"]).read_text(encoding="utf-8")
        assert "## Studio A+B context" in markdown
        assert "- Required artifacts: scope, policy, code, api, har" in markdown
        assert "- API GET /files/{file_id}/export" in markdown
        assert "- HAR GET /files/123/export" in markdown
        assert "## Candidate summary" in markdown
        assert "- Affected endpoint: GET /files/{file_id}/export" in markdown
        assert "- Affected code path: routes.py:export_file" in markdown
        assert candidates[0]["broken_invariant"] in markdown
        assert "- Policy risk: low" in markdown
        assert "- Policy risk score: 10" in markdown
        assert "## Ranking reasons" in markdown
        assert candidates[0]["ranking_reasons"][0] in markdown
        assert "## Refutation review" in markdown
        assert "- Status: needs_human_review" in markdown
        assert candidates[0]["refutation_review"]["questions"][0] in markdown
        assert "## Report readiness" in markdown
        assert "- Status: submission_blocked" in markdown
        assert candidates[0]["report_readiness"]["next_allowed_action"] in markdown
        assert "## Evidence review" in markdown
        assert "- Status: needs_human_review" in markdown
        assert candidates[0]["evidence_review"]["required_items"][0] in markdown
        assert "## Deduplication review" in markdown
        assert "- Status: needs_human_review" in markdown
        assert candidates[0]["deduplication_review"]["review_items"][0] in markdown
        assert "## Evidence needs" in markdown
        assert candidates[0]["evidence_needed"][0] in markdown
        assert "## False-positive checks" in markdown
        assert candidates[0]["false_positive_checks"][0] in markdown
        assert "## Suggested fix" in markdown
        assert candidates[0]["suggested_fix"] in markdown
        assert "## Regression test" in markdown
        assert candidates[0]["regression_test"] in markdown
        assert "## Safe validation plan" in markdown
        assert candidates[0]["safe_validation_plan"][0] in markdown
        assert "## Safety blockers" in markdown
        assert "- execute_live_validation" in markdown
        assert "- submit_report" in markdown
        assert "send_file(file_id)" not in str(export)
    finally:
        app.dependency_overrides.clear()


def test_studio_run_uses_imported_policy_artifact_for_audit_hash(tmp_path: Path):
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
    scope_path = tmp_path / "scope.yaml"
    scope_text = f"allowed_repos:\n  - {repo}\n"
    scope_path.write_text(scope_text, encoding="utf-8")
    policy_path = write_policy_artifact(tmp_path)
    policy_text = policy_path.read_text(encoding="utf-8")
    api_path = write_api_artifact(tmp_path)
    har_path = write_har_artifact(tmp_path)

    session_override, testing_session = studio_test_session_override()
    app.dependency_overrides[get_session] = session_override
    try:
        workspace_response = client.post(
            "/mythos/studio/workspaces",
            json={"root_path": str(tmp_path), "name": "acme-api"},
        )
        assert workspace_response.status_code == 200
        workspace_path = workspace_response.json()["path"]

        for kind, source_path in (
            ("scope", scope_path),
            ("policy", policy_path),
            ("code", repo),
            ("api", api_path),
            ("har", har_path),
        ):
            import_response = client.post(
                "/mythos/studio/workspaces/imports",
                json={
                    "workspace_path": workspace_path,
                    "kind": kind,
                    "source_path": str(source_path),
                },
            )
            assert import_response.status_code == 200

        run_response = client.post(
            "/mythos/studio/workspaces/runs",
            json={"workspace_path": workspace_path},
        )
        assert run_response.status_code == 200

        with testing_session() as session:
            record = DatabaseRepository(session).get_pipeline_run(
                run_response.json()["run_id"]
            )

        assert record is not None
        assert record.policy_text_hash == sha256(policy_text.encode("utf-8")).hexdigest()
        assert record.policy_text_hash != sha256(scope_text.encode("utf-8")).hexdigest()
    finally:
        app.dependency_overrides.clear()


def test_studio_candidates_include_imported_api_surface_context(tmp_path: Path):
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
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")
    policy_path = write_policy_artifact(tmp_path)
    api_path = write_api_artifact(tmp_path)
    har_path = write_har_artifact(tmp_path)

    app.dependency_overrides[get_session] = override_session()
    try:
        workspace_response = client.post(
            "/mythos/studio/workspaces",
            json={"root_path": str(tmp_path), "name": "acme-api"},
        )
        assert workspace_response.status_code == 200
        workspace_path = workspace_response.json()["path"]

        for kind, source_path in (
            ("scope", scope_path),
            ("policy", policy_path),
            ("code", repo),
            ("api", api_path),
            ("har", har_path),
        ):
            import_response = client.post(
                "/mythos/studio/workspaces/imports",
                json={
                    "workspace_path": workspace_path,
                    "kind": kind,
                    "source_path": str(source_path),
                },
            )
            assert import_response.status_code == 200

        run_response = client.post(
            "/mythos/studio/workspaces/runs",
            json={"workspace_path": workspace_path},
        )
        assert run_response.status_code == 200

        candidates_response = client.get(
            "/mythos/studio/workspaces/candidates",
            params={"workspace_path": workspace_path},
        )
        assert candidates_response.status_code == 200
        candidates = candidates_response.json()["candidates"]
        api_facts = [
            fact
            for candidate in candidates
            for fact in candidate["source_facts"]
            if fact.get("artifact_kind") == "api"
        ]

        assert api_facts
        assert api_facts[0]["route_path"] == "/files/{file_id}/export"
        assert api_facts[0]["operation_id"] == "exportFile"
        assert "openapi.json" not in str(candidates)
    finally:
        app.dependency_overrides.clear()


def test_studio_candidates_include_imported_har_context_without_secrets(
    tmp_path: Path,
):
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
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")
    policy_path = write_policy_artifact(tmp_path)
    api_path = write_api_artifact(tmp_path)
    har_path = tmp_path / "session.har"
    har_path.write_text(
        """
{
  "log": {
    "entries": [
      {
        "request": {
          "method": "GET",
          "url": "https://api.example.test/files/123/export?download_token=secret-token",
          "headers": [
            {"name": "Authorization", "value": "Bearer secret-token"},
            {"name": "Cookie", "value": "session=secret-token"}
          ]
        }
      }
    ]
  }
}
""",
        encoding="utf-8",
    )

    app.dependency_overrides[get_session] = override_session()
    try:
        workspace_response = client.post(
            "/mythos/studio/workspaces",
            json={"root_path": str(tmp_path), "name": "acme-api"},
        )
        assert workspace_response.status_code == 200
        workspace_path = workspace_response.json()["path"]

        for kind, source_path in (
            ("scope", scope_path),
            ("policy", policy_path),
            ("code", repo),
            ("api", api_path),
            ("har", har_path),
        ):
            import_response = client.post(
                "/mythos/studio/workspaces/imports",
                json={
                    "workspace_path": workspace_path,
                    "kind": kind,
                    "source_path": str(source_path),
                },
            )
            assert import_response.status_code == 200

        run_response = client.post(
            "/mythos/studio/workspaces/runs",
            json={"workspace_path": workspace_path},
        )
        assert run_response.status_code == 200

        candidates_response = client.get(
            "/mythos/studio/workspaces/candidates",
            params={"workspace_path": workspace_path},
        )
        assert candidates_response.status_code == 200
        candidates = candidates_response.json()["candidates"]
        har_facts = [
            fact
            for candidate in candidates
            for fact in candidate["source_facts"]
            if fact.get("artifact_kind") == "har"
        ]

        assert har_facts
        assert har_facts[0]["route_path"] == "/files/123/export"
        assert har_facts[0]["route_method"] == "GET"
        assert any(fact.get("advisory_only") == "true" for fact in har_facts)
        assert "session.har" not in str(candidates)
        assert "download_token" not in str(candidates)
        assert "secret-token" not in str(candidates)
        assert "Authorization" not in str(candidates)
        assert "Cookie" not in str(candidates)
    finally:
        app.dependency_overrides.clear()


def test_studio_candidates_match_imported_api_and_har_template_routes(
    tmp_path: Path,
):
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
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")
    policy_path = write_policy_artifact(tmp_path)
    api_path = tmp_path / "openapi.json"
    api_path.write_text(
        """
{
  "openapi": "3.0.0",
  "paths": {
    "/files/{id}/export": {
      "get": {
        "operationId": "exportFile"
      }
    }
  }
}
""",
        encoding="utf-8",
    )
    har_path = tmp_path / "traffic.har"
    har_path.write_text(
        """
{
  "log": {
    "entries": [
      {
        "request": {
          "method": "GET",
          "url": "https://api.example.test/files/123/export"
        }
      },
      {
        "request": {
          "method": "GET",
          "url": "https://api.example.test/admin/users"
        }
      }
    ]
  }
}
""",
        encoding="utf-8",
    )

    app.dependency_overrides[get_session] = override_session()
    try:
        workspace_response = client.post(
            "/mythos/studio/workspaces",
            json={"root_path": str(tmp_path), "name": "acme-api"},
        )
        assert workspace_response.status_code == 200
        workspace_path = workspace_response.json()["path"]

        for kind, source_path in (
            ("scope", scope_path),
            ("policy", policy_path),
            ("code", repo),
            ("api", api_path),
            ("har", har_path),
        ):
            import_response = client.post(
                "/mythos/studio/workspaces/imports",
                json={
                    "workspace_path": workspace_path,
                    "kind": kind,
                    "source_path": str(source_path),
                },
            )
            assert import_response.status_code == 200

        run_response = client.post(
            "/mythos/studio/workspaces/runs",
            json={"workspace_path": workspace_path},
        )
        assert run_response.status_code == 200

        candidates_response = client.get(
            "/mythos/studio/workspaces/candidates",
            params={"workspace_path": workspace_path},
        )
        assert candidates_response.status_code == 200
        candidates = candidates_response.json()["candidates"]
        matched_candidate = next(
            candidate
            for candidate in candidates
            if candidate["location"] == "GET /files/{file_id}/export"
        )
        matched_facts = matched_candidate["source_facts"]

        assert any(
            fact.get("artifact_kind") == "api"
            and fact.get("route_path") == "/files/{id}/export"
            for fact in matched_facts
        )
        assert any(
            fact.get("artifact_kind") == "har"
            and fact.get("route_path") == "/files/123/export"
            for fact in matched_facts
        )
        assert not any(
            fact.get("route_path") == "/admin/users" for fact in matched_facts
        )
    finally:
        app.dependency_overrides.clear()


def test_studio_candidates_include_imported_sarif_scanner_context_as_advisory(
    tmp_path: Path,
):
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
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")
    policy_path = write_policy_artifact(tmp_path)
    api_path = write_api_artifact(tmp_path)
    har_path = write_har_artifact(tmp_path)
    sarif_path = tmp_path / "scanner.sarif"
    sarif_path.write_text(
        """
{
  "runs": [
    {
      "tool": {"driver": {"name": "CodeQL"}},
      "results": [
        {
          "ruleId": "py/path-injection",
          "message": {
            "text": "Review GET /files/{file_id}/export Authorization: Bearer secret-token"
          }
        }
      ]
    }
  ]
}
""",
        encoding="utf-8",
    )

    app.dependency_overrides[get_session] = override_session()
    try:
        workspace_response = client.post(
            "/mythos/studio/workspaces",
            json={"root_path": str(tmp_path), "name": "acme-api"},
        )
        assert workspace_response.status_code == 200
        workspace_path = workspace_response.json()["path"]

        for kind, source_path in (
            ("scope", scope_path),
            ("policy", policy_path),
            ("code", repo),
            ("api", api_path),
            ("har", har_path),
            ("sarif", sarif_path),
        ):
            import_response = client.post(
                "/mythos/studio/workspaces/imports",
                json={
                    "workspace_path": workspace_path,
                    "kind": kind,
                    "source_path": str(source_path),
                },
            )
            assert import_response.status_code == 200

        run_response = client.post(
            "/mythos/studio/workspaces/runs",
            json={"workspace_path": workspace_path},
        )
        assert run_response.status_code == 200

        candidates_response = client.get(
            "/mythos/studio/workspaces/candidates",
            params={"workspace_path": workspace_path},
        )
        assert candidates_response.status_code == 200
        candidates = candidates_response.json()["candidates"]
        scanner_facts = [
            fact
            for candidate in candidates
            for fact in candidate["source_facts"]
            if fact.get("fact_type") == "scanner_signal"
        ]

        assert scanner_facts
        assert scanner_facts[0]["artifact_kind"] == "sarif"
        assert scanner_facts[0]["route_path"] == "/files/{file_id}/export"
        assert scanner_facts[0]["route_method"] == "GET"
        assert scanner_facts[0]["operation_id"] == "sarif_get_files_file_id_export"
        assert scanner_facts[0]["advisory_only"] == "true"
        assert "scanner.sarif" not in str(candidates)
        assert "secret-token" not in str(candidates)
        assert "Authorization: Bearer" not in str(candidates)

        template_response = client.post(
            "/mythos/studio/workspaces/benchmarks/template",
            json={
                "workspace_path": workspace_path,
                "run_id": run_response.json()["run_id"],
            },
        )
        assert template_response.status_code == 200
        template = template_response.json()["template"]
        assert template["expected_candidates"][0]["required_artifacts"] == [
            "scope",
            "policy",
            "code",
            "api",
            "har",
            "sarif",
        ]

        benchmark_response = client.post(
            "/mythos/studio/workspaces/benchmarks/run",
            json={
                "workspace_path": workspace_path,
                "run_id": run_response.json()["run_id"],
                "expectations_path": template_response.json()["template_path"],
            },
        )
        assert benchmark_response.status_code == 200
        assert benchmark_response.json()["benchmark"]["status"] == "passed"
    finally:
        app.dependency_overrides.clear()


def test_studio_candidates_include_imported_sbom_dependency_context_as_advisory(
    tmp_path: Path,
):
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
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")
    policy_path = write_policy_artifact(tmp_path)
    api_path = write_api_artifact(tmp_path)
    har_path = write_har_artifact(tmp_path)
    sbom_path = tmp_path / "deps.cdx.json"
    sbom_path.write_text(
        """
{
  "bomFormat": "CycloneDX",
  "components": [
    {
      "type": "library",
      "name": "django",
      "version": "4.2.1",
      "purl": "pkg:pypi/django@4.2.1",
      "description": "Authorization: Bearer secret-token should not leak"
    }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-2099-0001",
      "ratings": [{"severity": "high"}],
      "affects": [{"ref": "pkg:pypi/django@4.2.1"}],
      "description": "secret-token should not leak"
    }
  ]
}
""",
        encoding="utf-8",
    )

    app.dependency_overrides[get_session] = override_session()
    try:
        workspace_response = client.post(
            "/mythos/studio/workspaces",
            json={"root_path": str(tmp_path), "name": "acme-api"},
        )
        assert workspace_response.status_code == 200
        workspace_path = workspace_response.json()["path"]

        for kind, source_path in (
            ("scope", scope_path),
            ("policy", policy_path),
            ("code", repo),
            ("api", api_path),
            ("har", har_path),
            ("sbom", sbom_path),
        ):
            import_response = client.post(
                "/mythos/studio/workspaces/imports",
                json={
                    "workspace_path": workspace_path,
                    "kind": kind,
                    "source_path": str(source_path),
                },
            )
            assert import_response.status_code == 200

        run_response = client.post(
            "/mythos/studio/workspaces/runs",
            json={"workspace_path": workspace_path},
        )
        assert run_response.status_code == 200

        candidates_response = client.get(
            "/mythos/studio/workspaces/candidates",
            params={"workspace_path": workspace_path},
        )
        assert candidates_response.status_code == 200
        candidates = candidates_response.json()["candidates"]
        dependency_facts = [
            fact
            for candidate in candidates
            for fact in candidate["source_facts"]
            if fact.get("fact_type") == "dependency_signal"
        ]

        assert dependency_facts
        assert dependency_facts[0] == {
            "fact_type": "dependency_signal",
            "artifact_kind": "sbom",
            "package_name": "django",
            "package_version": "4.2.1",
            "ecosystem": "pypi",
            "vulnerability_id": "CVE-2099-0001",
            "severity": "high",
            "advisory_only": "true",
        }
        assert "deps.cdx.json" not in str(candidates)
        assert "secret-token" not in str(candidates)
        assert "Authorization: Bearer" not in str(candidates)
    finally:
        app.dependency_overrides.clear()


def test_studio_candidates_include_imported_fuzzing_plan_context_as_advisory(
    tmp_path: Path,
):
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
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")
    policy_path = write_policy_artifact(tmp_path)
    api_path = write_api_artifact(tmp_path)
    har_path = write_har_artifact(tmp_path)
    fuzzing_path = tmp_path / "fuzz-plan.json"
    fuzzing_path.write_text(
        """
{
  "stage": "v1_crs_fuzzing",
  "execution_mode": "plan_only",
  "parser_candidates": [
    {
      "source_path": "src/parser.py",
      "symbol_name": "parse_export_manifest",
      "candidate_type": "parser",
      "reason": "Authorization: Bearer secret-token should not leak"
    }
  ],
  "harness_plans": [
    {
      "target_symbol": "parse_export_manifest",
      "harness_kind": "local_unit_harness",
      "status": "planned"
    }
  ],
  "fuzzer_plan": {
    "engine": "libFuzzer",
    "status": "not_executed",
    "execution_allowed": false,
    "command_preview": "Cookie: session=secret-token should not leak"
  }
}
""",
        encoding="utf-8",
    )

    app.dependency_overrides[get_session] = override_session()
    try:
        workspace_response = client.post(
            "/mythos/studio/workspaces",
            json={"root_path": str(tmp_path), "name": "acme-api"},
        )
        assert workspace_response.status_code == 200
        workspace_path = workspace_response.json()["path"]

        for kind, source_path in (
            ("scope", scope_path),
            ("policy", policy_path),
            ("code", repo),
            ("api", api_path),
            ("har", har_path),
            ("fuzzing", fuzzing_path),
        ):
            import_response = client.post(
                "/mythos/studio/workspaces/imports",
                json={
                    "workspace_path": workspace_path,
                    "kind": kind,
                    "source_path": str(source_path),
                },
            )
            assert import_response.status_code == 200

        run_response = client.post(
            "/mythos/studio/workspaces/runs",
            json={"workspace_path": workspace_path},
        )
        assert run_response.status_code == 200

        candidates_response = client.get(
            "/mythos/studio/workspaces/candidates",
            params={"workspace_path": workspace_path},
        )
        assert candidates_response.status_code == 200
        candidates = candidates_response.json()["candidates"]
        fuzzing_facts = [
            fact
            for candidate in candidates
            for fact in candidate["source_facts"]
            if fact.get("fact_type") == "fuzzing_signal"
        ]

        assert fuzzing_facts
        assert fuzzing_facts[0] == {
            "fact_type": "fuzzing_signal",
            "artifact_kind": "fuzzing",
            "target_symbol": "parse_export_manifest",
            "candidate_type": "parser",
            "harness_status": "planned",
            "fuzzer_engine": "libFuzzer",
            "fuzzer_status": "not_executed",
            "execution_allowed": "false",
            "advisory_only": "true",
        }
        assert "fuzz-plan.json" not in str(candidates)
        assert "secret-token" not in str(candidates)
        assert "Authorization: Bearer" not in str(candidates)
        assert "Cookie:" not in str(candidates)

        template_response = client.post(
            "/mythos/studio/workspaces/benchmarks/template",
            json={
                "workspace_path": workspace_path,
                "run_id": run_response.json()["run_id"],
            },
        )
        assert template_response.status_code == 200
        template = template_response.json()["template"]
        assert template["expected_candidates"][0]["required_artifacts"] == [
            "scope",
            "policy",
            "code",
            "api",
            "har",
            "fuzzing",
        ]

        export_response = client.post(
            "/mythos/studio/workspaces/reports/export",
            json={
                "workspace_path": workspace_path,
                "run_id": run_response.json()["run_id"],
            },
        )
        assert export_response.status_code == 200
        export = export_response.json()
        assert export["report"]["advisory_signals"] == [
            "Fuzzing plan advisory: parse_export_manifest (parser, planned, not_executed)"
        ]
        markdown = Path(export["report_markdown_path"]).read_text(encoding="utf-8")
        assert "## Advisory signals" in markdown
        assert (
            "Advisory-only signals are not confirmed vulnerabilities and require human review."
            in markdown
        )
        assert (
            "- Fuzzing plan advisory: parse_export_manifest (parser, planned, not_executed)"
            in markdown
        )
        assert "secret-token" not in str(export)
        assert "secret-token" not in markdown
    finally:
        app.dependency_overrides.clear()


def test_studio_candidates_include_imported_strategy_context_as_advisory(
    tmp_path: Path,
):
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
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text(f"allowed_repos:\n  - {repo}\n", encoding="utf-8")
    policy_path = write_policy_artifact(tmp_path)
    api_path = write_api_artifact(tmp_path)
    har_path = write_har_artifact(tmp_path)
    strategy_path = tmp_path / "strategy-notes.md"
    strategy_path.write_text(
        "\n".join(
            [
                "# Strategy",
                "focus: Cross-tenant file export authorization",
                "risk_family: IDOR",
                "note: Prioritize workspace boundary checks before validation.",
                "note: Authorization: Bearer secret-token should not leak",
            ]
        ),
        encoding="utf-8",
    )

    app.dependency_overrides[get_session] = override_session()
    try:
        workspace_response = client.post(
            "/mythos/studio/workspaces",
            json={"root_path": str(tmp_path), "name": "acme-api"},
        )
        assert workspace_response.status_code == 200
        workspace_path = workspace_response.json()["path"]

        for kind, source_path in (
            ("scope", scope_path),
            ("policy", policy_path),
            ("code", repo),
            ("api", api_path),
            ("har", har_path),
            ("strategy", strategy_path),
        ):
            import_response = client.post(
                "/mythos/studio/workspaces/imports",
                json={
                    "workspace_path": workspace_path,
                    "kind": kind,
                    "source_path": str(source_path),
                },
            )
            assert import_response.status_code == 200

        run_response = client.post(
            "/mythos/studio/workspaces/runs",
            json={"workspace_path": workspace_path},
        )
        assert run_response.status_code == 200

        candidates_response = client.get(
            "/mythos/studio/workspaces/candidates",
            params={"workspace_path": workspace_path},
        )
        assert candidates_response.status_code == 200
        candidates = candidates_response.json()["candidates"]
        strategy_facts = [
            fact
            for candidate in candidates
            for fact in candidate["source_facts"]
            if fact.get("fact_type") == "strategy_signal"
        ]

        assert strategy_facts
        assert strategy_facts[0] == {
            "fact_type": "strategy_signal",
            "artifact_kind": "strategy",
            "focus": "Cross-tenant file export authorization",
            "risk_family": "IDOR",
            "note": "Prioritize workspace boundary checks before validation.",
            "advisory_only": "true",
        }
        assert "strategy-notes.md" not in str(candidates)
        assert "secret-token" not in str(candidates)
        assert "Authorization: Bearer" not in str(candidates)

        export_response = client.post(
            "/mythos/studio/workspaces/reports/export",
            json={
                "workspace_path": workspace_path,
                "run_id": run_response.json()["run_id"],
            },
        )
        assert export_response.status_code == 200
        export = export_response.json()
        assert export["report"]["advisory_signals"] == [
            "Strategy advisory: Cross-tenant file export authorization (IDOR)"
        ]
        markdown = Path(export["report_markdown_path"]).read_text(encoding="utf-8")
        assert "## Advisory signals" in markdown
        assert (
            "- Strategy advisory: Cross-tenant file export authorization (IDOR)"
            in markdown
        )
        assert "secret-token" not in str(export)
        assert "secret-token" not in markdown
    finally:
        app.dependency_overrides.clear()


def test_studio_run_requires_ab_authorized_artifacts(tmp_path: Path):
    workspace_response = client.post(
        "/mythos/studio/workspaces",
        json={"root_path": str(tmp_path), "name": "acme-api"},
    )
    assert workspace_response.status_code == 200

    response = client.post(
        "/mythos/studio/workspaces/runs",
        json={"workspace_path": workspace_response.json()["path"]},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "studio_ab_artifacts_required"
