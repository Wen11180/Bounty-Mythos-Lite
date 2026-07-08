from hashlib import sha256
import json
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
    _studio_knowledge_surface_facts,
    _studio_mission_agent_queue,
    _studio_mission_candidate_summary,
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
                        {
                            "fact_type": "knowledge_signal",
                            "artifact_kind": "knowledge",
                            "pattern_id": "WEB-IDOR-001",
                            "vuln_type": "authorization_gap",
                            "source": "local_milvus",
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
        "Knowledge advisory: WEB-IDOR-001 (authorization_gap) from local_milvus",
    ]


def test_studio_report_candidate_guidance_lists_top_candidates_without_execution():
    record = SimpleNamespace(
        payload={
            "hypotheses": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization_gap",
                    "risk": "high",
                    "location": "GET /files/{file_id}/export",
                    "evidence_needed": ["Confirm ownership boundary with authorized local artifacts."],
                    "false_positive_checks": ["Check whether the service layer enforces ownership."],
                    "validation_mode": "two_account_authorization_check",
                },
                {
                    "hypothesis_id": "H-002",
                    "vuln_type": "webhook_egress_boundary",
                    "risk": "medium",
                    "location": "POST /webhooks/test",
                    "evidence_needed": ["Confirm outbound destination policy from authorized config."],
                    "false_positive_checks": ["Check whether webhook URLs are allowlisted."],
                    "validation_mode": "manual_review",
                },
            ]
        }
    )

    guidance = _studio_report_candidate_guidance(record, {})

    assert [item["hypothesis_id"] for item in guidance["top_candidate_reviews"]] == [
        "H-001",
        "H-002",
    ]
    assert guidance["top_candidate_reviews"][0]["report_status"] == "submission_blocked"
    assert guidance["top_candidate_reviews"][0]["execution_allowed"] is False
    assert guidance["top_candidate_reviews"][0]["evidence_need_count"] == 1
    assert guidance["top_candidate_reviews"][0]["false_positive_check_count"] == 1
    assert (
        "Validation execution remains blocked pending human approval."
        in guidance["top_candidate_reviews"][0]["safety_blockers"]
    )
    assert (
        "Report submission remains blocked pending human review."
        in guidance["top_candidate_reviews"][0]["safety_blockers"]
    )
    assert guidance["top_candidate_reviews"][1]["affected_endpoint"] == "POST /webhooks/test"
    assert "execute_live_validation" not in str(guidance["top_candidate_reviews"])
    assert "submit_report" not in str(guidance["top_candidate_reviews"])


def test_studio_mission_candidate_summary_includes_safe_review_packet():
    summary = _studio_mission_candidate_summary(
        {
            "hypothesis_id": "H-001",
            "vuln_type": "authorization_gap",
            "risk": "high",
            "location": "GET /files/{file_id}/export",
            "evidence_needed": [
                "Confirm the object owner boundary from authorized local artifacts.",
                "Do not copy Authorization: Bearer secret-token into the dossier.",
            ],
            "false_positive_checks": [
                "Check whether the service layer enforces tenant ownership.",
            ],
            "safe_validation_plan": [
                "Prepare a non-destructive two-account check for human approval.",
            ],
            "safety_blockers": ["Requires human approval before validation."],
            "evidence_gaps": [
                {"artifact_kind": "api", "reason": "missing_required_artifact"},
            ],
        }
    )

    assert summary["execution_allowed"] is False
    assert summary["evidence_needed"] == [
        "Confirm the object owner boundary from authorized local artifacts.",
    ]
    assert summary["false_positive_checks"] == [
        "Check whether the service layer enforces tenant ownership.",
    ]
    assert summary["safe_validation_plan"] == [
        "Prepare a non-destructive two-account check for human approval.",
    ]
    assert summary["safety_blockers"] == ["Requires human approval before validation."]
    assert summary["evidence_gaps"] == ["api: missing_required_artifact"]
    assert summary["hallucination_guard"] == {
        "status": "blocked",
        "model_output_status": "unverified_claim_not_fact",
        "high_confidence_allowed": False,
        "local_evidence_sources": [],
        "advisory_sources": [],
        "cross_validation_sources": [],
        "required_consensus": [
            "local_artifact_trace",
            "independent_refutation_review",
            "human_evidence_review",
        ],
        "blockers": [
            "no_local_evidence_source",
            "missing_endpoint_or_code_path_trace",
        ],
    }
    assert summary["quality_status"] == "needs_review"
    assert "hallucination_guard_needs_cross_validation" in summary["quality_reasons"]
    assert "secret-token" not in str(summary)
    assert "Authorization: Bearer" not in str(summary)


def test_studio_mission_agent_queue_surfaces_candidate_quality_gaps_without_execution():
    queue = _studio_mission_agent_queue(
        ["scope", "policy", "code", "api", "har"],
        [],
        "pipeline_run_1",
        [
            {
                "hypothesis_id": "H-weak",
                "affected_endpoint": "",
                "affected_code_path": "",
                "quality_status": "needs_review",
                "quality_reasons": ["evidence_needs_present"],
                "evidence_gap_count": 1,
            }
        ],
    )

    by_task = {task["task_id"]: task for task in queue}
    assert by_task["semantic_candidate_hunt"]["review_focus"] == [
        "security_invariants",
        "affected_code_paths",
        "candidate_quality",
    ]
    assert by_task["evidence_validation_plan_review"]["review_focus"] == [
        "evidence_needs",
        "evidence_gaps",
        "safe_validation_plan",
    ]
    assert "H-weak:missing_endpoint_or_code_path_trace" in by_task[
        "semantic_candidate_hunt"
    ]["candidate_quality_gaps"]
    assert "H-weak:missing_safe_validation_plan" in by_task[
        "evidence_validation_plan_review"
    ]["candidate_quality_gaps"]
    assert "execute_live_validation" not in str(queue)
    assert "submit_report" not in str(queue)
    assert "run_fuzzer" not in str(queue)


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


def test_studio_knowledge_surface_facts_are_advisory_few_shot_context():
    facts = _studio_knowledge_surface_facts(
        {
            "entries": [
                {
                    "pattern_id": "WEB-IDOR-001",
                    "vuln_type": "authorization_gap",
                    "source": "local_milvus",
                },
                {
                    "pattern_id": "Authorization: Bearer secret-token",
                    "vuln_type": "token leak",
                    "source": "raw_notes",
                },
            ]
        }
    )

    assert facts == [
        {
            "fact_type": "knowledge_signal",
            "artifact_kind": "knowledge",
            "advisory_only": "true",
            "model_input_role": "few_shot_context_only",
            "source": "local_milvus",
            "pattern_id": "WEB-IDOR-001",
            "vuln_type": "authorization_gap",
        }
    ]
    assert "secret-token" not in str(facts)
    assert "Authorization: Bearer" not in str(facts)


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
        assert candidates[0]["policy_review"] == {
            "status": "needs_human_review",
            "policy_risk": "low",
            "policy_risk_score": 10,
            "review_items": [
                "Confirm the candidate remains inside the imported policy and scope artifacts.",
                "Check that the validation plan avoids prohibited actions before any execution.",
                "Keep report submission blocked until policy, evidence, and redaction review are complete.",
            ],
        }
        assert candidates[0]["evidence_gaps"] == []
        assert candidates[0]["evidence_review"] == {
            "status": "needs_human_review",
            "required_items": [
                "Confirm the affected endpoint and code path using authorized local artifacts.",
                "Resolve evidence gaps and false-positive checks before validation.",
                "Complete redaction review before report export or sharing.",
            ],
        }
        assert candidates[0]["provenance_review"] == {
            "status": "needs_human_review",
            "artifact_kinds": ["scope", "policy", "code", "api", "har"],
            "review_items": [
                "Confirm every candidate claim is traceable to imported authorized artifacts.",
                "Review only normalized artifact summaries; raw paths, headers, tokens, and bodies remain excluded.",
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
        assert candidates[0]["validation_review"] == {
            "status": "needs_human_approval",
            "execution_allowed": False,
            "review_items": [
                "Confirm Scope Guard allows the exact asset, route, and validation mode.",
                "Confirm validation remains non-destructive and uses only authorized test data.",
                "Record human approval before executing any validation step.",
            ],
        }
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
        assert "## Policy review" in markdown
        assert "- Policy risk: low" in markdown
        assert candidates[0]["policy_review"]["review_items"][0] in markdown
        assert "## Report readiness" in markdown
        assert "- Status: submission_blocked" in markdown
        assert candidates[0]["report_readiness"]["next_allowed_action"] in markdown
        assert "## Evidence review" in markdown
        assert "- Status: needs_human_review" in markdown
        assert candidates[0]["evidence_review"]["required_items"][0] in markdown
        assert "## Provenance review" in markdown
        assert "- Artifact kinds: scope, policy, code, api, har" in markdown
        assert candidates[0]["provenance_review"]["review_items"][0] in markdown
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
        assert "## Validation review" in markdown
        assert "- Status: needs_human_approval" in markdown
        assert "- Execution allowed: false" in markdown
        assert candidates[0]["validation_review"]["review_items"][0] in markdown
        assert "## Safety blockers" in markdown
        assert "- Validation execution remains blocked pending human approval." in markdown
        assert "- Report submission remains blocked pending human review." in markdown
        assert "execute_live_validation" not in markdown
        assert "submit_report" not in markdown
        assert "send_file(file_id)" not in str(export)
    finally:
        app.dependency_overrides.clear()


def test_studio_mission_summary_exposes_desktop_workbench_state(tmp_path: Path):
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
        run_id = run_response.json()["run_id"]

        mission_response = client.get(
            "/mythos/studio/workspaces/mission",
            params={"workspace_path": workspace_path},
        )

        assert mission_response.status_code == 200
        mission = mission_response.json()
        assert mission["mode"] == "local_ai_vulnerability_research_workbench"
        assert mission["run_id"] == run_id
        assert mission["scope_guard_status"] == "scope_imported"
        assert mission["artifacts"] == {
            "required": ["scope", "policy", "code", "api", "har"],
            "present": ["scope", "policy", "code", "api", "har"],
            "missing": [],
        }
        assert 1 <= mission["candidate_count"] <= 5
        assert mission["quality_gates"] == {
            "top_candidates_limited": True,
            "submission_blocked": True,
            "report_submission_allowed": False,
            "validation_execution_allowed": False,
            "human_review_required": True,
            "top_candidate_quality_gate": True,
        }
        assert mission["quality_summary"]["status"] == "review_ready"
        assert mission["quality_summary"]["top_candidate_quality_gate"] == "passed"
        assert mission["quality_summary"]["candidate_count"] == mission["candidate_count"]
        assert mission["quality_summary"]["review_ready_count"] == mission["candidate_count"]
        assert mission["quality_summary"]["average_quality_score"] >= 90
        assert mission["quality_summary"]["blockers"] == []
        assert mission["quality_summary"]["improvement_actions"] == []
        assert mission["blocked_actions"] == [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
        ]
        assert mission["next_actions"] == [
            "review_top_candidates",
            "create_benchmark_template",
            "export_submission_blocked_report",
        ]
        candidate = mission["top_candidates"][0]
        assert candidate["hypothesis_id"].startswith("H-")
        assert candidate["affected_endpoint"] == "GET /files/{file_id}/export"
        assert candidate["affected_code_path"] == "routes.py:export_file"
        assert candidate["report_status"] == "submission_blocked"
        assert candidate["next_report_action"].startswith("Review evidence")
        assert "report preview" in candidate["next_report_action"]
        assert candidate["evidence_review_status"] == "needs_human_review"
        assert candidate["deduplication_review_status"] == "needs_human_review"
        assert candidate["refutation_status"] == "unverified"
        assert candidate["refutation_review_status"] == "needs_human_review"
        assert candidate["policy_review_status"] == "needs_human_review"
        assert candidate["validation_status"] == "needs_human_approval"
        assert candidate["provenance_review_status"] == "needs_human_review"
        assert candidate["execution_allowed"] is False
        assert candidate["provenance_artifacts"] == ["scope", "policy", "code", "api", "har"]
        assert candidate["evidence_need_count"] >= 1
        assert candidate["false_positive_check_count"] >= 1
        assert candidate["evidence_gap_count"] == 0
        assert candidate["safe_validation_step_count"] >= 1
        assert candidate["quality_score"] >= 90
        assert candidate["quality_status"] == "review_ready"
        assert candidate["hallucination_guard"]["status"] == "cross_checked"
        assert (
            candidate["hallucination_guard"]["model_output_status"]
            == "unverified_claim_not_fact"
        )
        assert candidate["hallucination_guard"]["high_confidence_allowed"] is True
        assert {"code", "api", "har"}.issubset(
            set(candidate["hallucination_guard"]["local_evidence_sources"])
        )
        assert "endpoint_and_code_path_traced" in candidate["quality_reasons"]
        assert "provenance_review_present" in candidate["quality_reasons"]
        assert "refutation_checks_present" in candidate["quality_reasons"]
        assert "safe_validation_plan_present" in candidate["quality_reasons"]
        assert "hallucination_guard_cross_checked" in candidate["quality_reasons"]
        research_loop = mission["research_loop"]
        assert [stage["key"] for stage in research_loop] == [
            "scope_guard",
            "target_intake",
            "attack_surface_modeling",
            "semantic_audit",
            "hypothesis_generation",
            "refutation_review",
            "deduplication_review",
            "safe_validation_planning",
            "evidence_review",
            "submission_blocked_report",
        ]
        stage_statuses = {stage["key"]: stage["status"] for stage in research_loop}
        assert stage_statuses == {
            "scope_guard": "complete",
            "target_intake": "complete",
            "attack_surface_modeling": "complete",
            "semantic_audit": "complete",
            "hypothesis_generation": "complete",
            "refutation_review": "needs_review",
            "deduplication_review": "needs_review",
            "safe_validation_planning": "needs_review",
            "evidence_review": "needs_review",
            "submission_blocked_report": "blocked",
        }
        assert all(
            stage["status"] in {"complete", "needs_review", "blocked", "not_started"}
            for stage in research_loop
        )
        assert "send_file(file_id)" not in str(research_loop)
        assert str(repo) not in str(research_loop)
        assert "execute_live_validation" not in str(research_loop)
        assert "submit_report" not in str(research_loop)
        agent_queue = mission["agent_queue"]
        assert [task["task_id"] for task in agent_queue] == [
            "scope_guard_intake",
            "artifact_intake",
            "surface_modeling",
            "semantic_candidate_hunt",
            "refutation_dedup_review",
            "evidence_validation_plan_review",
            "report_draft_review",
        ]
        queue_statuses = {task["task_id"]: task["status"] for task in agent_queue}
        assert queue_statuses == {
            "scope_guard_intake": "complete",
            "artifact_intake": "complete",
            "surface_modeling": "complete",
            "semantic_candidate_hunt": "complete",
            "refutation_dedup_review": "needs_review",
            "evidence_validation_plan_review": "needs_review",
            "report_draft_review": "blocked",
        }
        assert agent_queue[0]["agent"] == "Scope Guard"
        assert agent_queue[0]["input_refs"] == ["scope"]
        assert agent_queue[0]["review_focus"] == [
            "scope_guard_status",
            "policy_alignment",
        ]
        assert agent_queue[3]["target_candidates"] == [
            candidate["hypothesis_id"]
            for candidate in mission["top_candidates"]
        ]
        assert agent_queue[3]["review_focus"] == [
            "security_invariants",
            "affected_code_paths",
            "candidate_quality",
        ]
        assert agent_queue[3]["candidate_quality_gaps"] == []
        assert agent_queue[5]["review_focus"] == [
            "evidence_needs",
            "evidence_gaps",
            "safe_validation_plan",
        ]
        assert all(task["safety_gate"] for task in agent_queue)
        assert all(
            task["status"] in {"complete", "needs_review", "blocked", "not_started"}
            for task in agent_queue
        )
        assert "send_file(file_id)" not in str(agent_queue)
        assert str(repo) not in str(agent_queue)
        assert "execute_live_validation" not in str(agent_queue)
        assert "submit_report" not in str(agent_queue)
        assert "run_fuzzer" not in str(agent_queue)

        dossier_response = client.post(
            "/mythos/studio/workspaces/mission/export",
            json={"workspace_path": workspace_path, "run_id": run_id},
        )
        assert dossier_response.status_code == 200
        dossier = dossier_response.json()
        assert dossier["run_id"] == run_id
        assert dossier["report_submission_allowed"] is False
        assert dossier["validation_execution_allowed"] is False
        assert dossier["mission_dossier_path"].endswith("-mission-dossier.json")
        assert dossier["mission_dossier_markdown_path"].endswith("-mission-dossier.md")
        assert dossier["agent_queue_path"].endswith("-agent-queue.json")
        assert dossier["agent_queue_markdown_path"].endswith("-agent-queue.md")
        assert dossier["manifest"]["mission_dossiers"][-1]["report_submission_allowed"] is False
        assert dossier["manifest"]["agent_queue_audits"][-1]["task_count"] == len(
            agent_queue
        )
        assert dossier["manifest"]["agent_queue_audits"][-1]["timeline_stage_count"] == len(
            agent_queue
        )
        assert (
            dossier["manifest"]["agent_queue_audits"][-1]["agent_queue_markdown_path"]
            == dossier["agent_queue_markdown_path"]
        )
        assert (
            dossier["manifest"]["runs"][-1]["mission_dossier_markdown_path"]
            == dossier["mission_dossier_markdown_path"]
        )
        assert (
            dossier["manifest"]["runs"][-1]["agent_queue_markdown_path"]
            == dossier["agent_queue_markdown_path"]
        )
        dossier_json = json.loads(
            Path(dossier["mission_dossier_path"]).read_text(encoding="utf-8")
        )
        dossier_markdown = Path(dossier["mission_dossier_markdown_path"]).read_text(
            encoding="utf-8"
        )
        queue_json = json.loads(
            Path(dossier["agent_queue_path"]).read_text(encoding="utf-8")
        )
        queue_markdown = Path(dossier["agent_queue_markdown_path"]).read_text(
            encoding="utf-8"
        )
        assert dossier_json["agent_queue"][0]["task_id"] == "scope_guard_intake"
        assert dossier_json["quality_summary"]["top_candidate_quality_gate"] == "passed"
        assert queue_json["agent_queue"][0]["task_id"] == "scope_guard_intake"
        assert queue_json["agent_queue"][3]["review_focus"] == [
            "security_invariants",
            "affected_code_paths",
            "candidate_quality",
        ]
        assert queue_json["task_timeline"][3]["stage_id"] == (
            "agent_queue:semantic_candidate_hunt"
        )
        assert queue_json["task_timeline"][3]["gate_decision"] == "review_recorded"
        assert queue_json["task_timeline"][4]["gate_decision"] == "human_review_required"
        assert queue_json["task_timeline"][6]["gate_decision"] == "blocked"
        assert queue_json["task_timeline"][3]["report_submission_allowed"] is False
        assert queue_json["task_timeline"][3]["validation_execution_allowed"] is False
        assert queue_json["quality_summary"]["top_candidate_quality_gate"] == "passed"
        assert "# Mythos Studio agent queue audit" in queue_markdown
        assert "## Mission quality" in queue_markdown
        assert "## Agent queue" in queue_markdown
        assert "## Agent task timeline" in queue_markdown
        assert "agent_queue:semantic_candidate_hunt" in queue_markdown
        assert "focus: security_invariants, affected_code_paths, candidate_quality" in queue_markdown
        assert "# Mythos Studio mission dossier" in dossier_markdown
        assert "## Research loop" in dossier_markdown
        assert "## Mission quality" in dossier_markdown
        assert "Top candidate quality gate: passed" in dossier_markdown
        assert "## Agent queue" in dossier_markdown
        assert "## Hallucination guard" in dossier_markdown
        assert "unverified_claim_not_fact" in dossier_markdown
        assert "## Candidate quality" in dossier_markdown
        assert "review_ready (100/100)" in dossier_markdown
        assert "endpoint_and_code_path_traced" in dossier_markdown
        assert "## Top candidates" in dossier_markdown
        assert candidate["hypothesis_id"] in dossier_markdown
        assert "send_file(file_id)" not in str(dossier)
        assert str(repo) not in str(dossier)
        assert "send_file(file_id)" not in dossier_markdown
        assert "send_file(file_id)" not in queue_markdown
        assert str(repo) not in dossier_markdown
        assert str(repo) not in queue_markdown
        assert "execute_live_validation" not in queue_markdown
        assert "submit_report" not in queue_markdown
        assert "send_file(file_id)" not in str(mission)
        assert str(repo) not in str(mission)
    finally:
        app.dependency_overrides.clear()


def test_studio_mission_export_writes_review_only_dossier(tmp_path: Path):
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
        run_id = run_response.json()["run_id"]

        export_response = client.post(
            "/mythos/studio/workspaces/mission/export",
            json={"workspace_path": workspace_path, "run_id": run_id},
        )

        assert export_response.status_code == 200
        body = export_response.json()
        assert body["run_id"] == run_id
        assert body["report_submission_allowed"] is False
        assert body["validation_execution_allowed"] is False
        assert body["mission"]["quality_gates"]["report_submission_allowed"] is False
        assert body["mission"]["quality_gates"]["validation_execution_allowed"] is False
        assert body["mission_dossier_path"].endswith("mission-dossier.json")
        assert body["mission_dossier_markdown_path"].endswith("mission-dossier.md")
        assert body["agent_queue_path"].endswith("agent-queue.json")
        assert body["agent_queue_markdown_path"].endswith("agent-queue.md")
        assert body["manifest"]["mission_dossiers"][0]["report_submission_allowed"] is False
        assert body["manifest"]["mission_dossiers"][0]["validation_execution_allowed"] is False
        assert body["manifest"]["agent_queue_audits"][0]["report_submission_allowed"] is False
        assert body["manifest"]["agent_queue_audits"][0]["validation_execution_allowed"] is False

        markdown = Path(body["mission_dossier_markdown_path"]).read_text(encoding="utf-8")
        queue_markdown = Path(body["agent_queue_markdown_path"]).read_text(encoding="utf-8")
        assert "## Agent queue" in markdown
        assert "## Top candidates" in markdown
        assert "# Mythos Studio agent queue audit" in queue_markdown
        assert "## Agent queue" in queue_markdown
        assert "send_file(file_id)" not in markdown
        assert "send_file(file_id)" not in queue_markdown
        assert str(repo) not in markdown
        assert str(repo) not in queue_markdown
        assert "Validation execution remains blocked pending human approval." in markdown
        assert "Report submission remains blocked pending human review." in markdown
        assert "execute_live_validation" not in markdown
        assert "submit_report" not in markdown
        assert "execute_live_validation" not in queue_markdown
        assert "submit_report" not in queue_markdown
    finally:
        app.dependency_overrides.clear()


def test_studio_mission_summary_exposes_strategy_as_advisory_context(tmp_path: Path):
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
        """
# Strategy
focus: authorization boundaries
risk_family: object_access
note: Prioritize export endpoints with policy and code provenance.
Authorization: Bearer secret-token
""",
        encoding="utf-8",
    )
    knowledge_path = tmp_path / "knowledge.json"
    knowledge_path.write_text(
        json.dumps(
            {
                "entries": [
                    {
                        "pattern_id": "WEB-IDOR-001",
                        "vuln_type": "authorization_gap",
                        "source": "local_milvus",
                    }
                ]
            }
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
            ("knowledge", knowledge_path),
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
        mission_response = client.get(
            "/mythos/studio/workspaces/mission",
            params={"workspace_path": workspace_path},
        )

        assert mission_response.status_code == 200
        mission = mission_response.json()
        assert mission["artifacts"] == {
            "required": ["scope", "policy", "code", "api", "har"],
            "present": ["scope", "policy", "code", "api", "har"],
            "missing": [],
        }
        assert mission["advisory_artifacts"] == {
            "supported": ["sarif", "sbom", "fuzzing", "strategy", "knowledge"],
            "present": ["strategy", "knowledge"],
        }
        assert "knowledge" in mission["top_candidates"][0]["hallucination_guard"]["advisory_sources"]
        assert mission["quality_gates"]["validation_execution_allowed"] is False
        assert mission["quality_gates"]["report_submission_allowed"] is False
        assert "strategy-notes.md" not in str(mission)
        assert "secret-token" not in str(mission)
        assert "Authorization: Bearer" not in str(mission)
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
