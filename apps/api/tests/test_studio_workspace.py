from pathlib import Path

from app.studio_workspace import (
    StudioArtifactImport,
    create_workspace,
    import_workspace_artifact,
    load_workspace_manifest,
    record_workspace_mission_dossier,
    record_workspace_report_export,
    record_workspace_run,
)


def test_create_workspace_writes_local_manifest(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")

    manifest = load_workspace_manifest(workspace.path)

    assert workspace.path == tmp_path / "acme-api"
    assert manifest["name"] == "acme-api"
    assert manifest["safety"]["scope_guard_status"] == "missing_scope"
    assert manifest["artifacts"] == []
    assert manifest["runs"] == []


def test_create_workspace_creates_local_artifact_directories(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")

    for directory_name in (
        "policy",
        "scope",
        "api",
        "har",
        "code",
        "sbom",
        "sarif",
        "fuzzing",
        "evidence",
        "reports",
        "runs",
    ):
        assert (workspace.path / directory_name).is_dir()


def test_create_workspace_uses_safe_path_name_and_keeps_manifest_name(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="Acme API/Prod")

    manifest = load_workspace_manifest(workspace.path)

    assert workspace.path == tmp_path / "Acme-API-Prod"
    assert manifest["name"] == "Acme API/Prod"


def test_create_workspace_preserves_existing_manifest(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")
    policy_path = tmp_path / "policy.md"
    policy_path.write_text("in scope api.example.com", encoding="utf-8")
    import_workspace_artifact(
        workspace.path,
        StudioArtifactImport(kind="policy", source_path=str(policy_path)),
    )

    reopened = create_workspace(tmp_path, name="acme-api")

    assert reopened.path == workspace.path
    assert reopened.manifest["artifacts"][0]["kind"] == "policy"


def test_import_workspace_artifact_records_reference_without_copying_secret_text(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")
    policy_path = tmp_path / "policy.md"
    policy_path.write_text(
        "Authorization: Bearer secret-token\nin scope api.example.com",
        encoding="utf-8",
    )

    updated = import_workspace_artifact(
        workspace.path,
        StudioArtifactImport(kind="policy", source_path=str(policy_path)),
    )

    artifact = updated["artifacts"][0]
    assert artifact["kind"] == "policy"
    assert artifact["source_path"] == str(policy_path)
    assert artifact["source_hash"].startswith("sha256:")
    assert "source_sha256" not in artifact
    assert artifact["sensitivity_label"] == "sensitive"
    assert artifact["redaction_status"] == "needs_review"
    assert "secret-token" not in str(updated)


def test_import_workspace_artifact_marks_non_sensitive_text_low(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")
    policy_path = tmp_path / "policy.md"
    policy_path.write_text("in scope api.example.com", encoding="utf-8")

    updated = import_workspace_artifact(
        workspace.path,
        StudioArtifactImport(kind="policy", source_path=str(policy_path)),
    )

    artifact = updated["artifacts"][0]
    assert artifact["sensitivity_label"] == "low"
    assert artifact["redaction_status"] == "not_required"


def test_import_workspace_artifact_accepts_code_directory(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")
    repo = tmp_path / "target-repo"
    repo.mkdir()
    (repo / "routes.py").write_text("def route():\n    return 'ok'\n", encoding="utf-8")

    updated = import_workspace_artifact(
        workspace.path,
        StudioArtifactImport(kind="code", source_path=str(repo)),
    )

    artifact = updated["artifacts"][0]
    assert artifact["kind"] == "code"
    assert artifact["source_path"] == str(repo)
    assert artifact["source_hash"].startswith("sha256:")
    assert artifact["sensitivity_label"] == "low"


def test_import_workspace_artifact_redacts_secret_like_path(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")
    policy_path = tmp_path / "scope-secret-token.yaml"
    policy_path.write_text("in scope api.example.com", encoding="utf-8")

    updated = import_workspace_artifact(
        workspace.path,
        StudioArtifactImport(kind="policy", source_path=str(policy_path)),
    )

    artifact = updated["artifacts"][0]
    assert artifact["source_path"] == "[REDACTED_PATH]"
    assert "secret-token" not in str(updated)


def test_import_workspace_artifact_handles_binary_without_raw_content(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")
    binary_path = tmp_path / "traffic.har"
    binary_path.write_bytes(b"\xff\xfe\x00\x00")

    updated = import_workspace_artifact(
        workspace.path,
        StudioArtifactImport(kind="har", source_path=str(binary_path)),
    )

    artifact = updated["artifacts"][0]
    assert artifact["sensitivity_label"] == "unknown"
    assert artifact["redaction_status"] == "needs_review"


def test_record_workspace_run_accepts_missing_report_path(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")

    updated = record_workspace_run(
        workspace.path,
        run_id="run-1",
        status="blocked",
        report_path=None,
        candidate_count=3,
    )

    run = updated["runs"][0]
    assert run["run_id"] == "run-1"
    assert run["report_path"] is None
    assert run["candidate_count"] == 3


def test_record_workspace_run_redacts_secret_like_report_path(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")

    updated = record_workspace_run(
        workspace.path,
        run_id="run-1",
        status="blocked",
        report_path=str(tmp_path / "report-token-preview.json"),
        candidate_count=1,
    )

    assert updated["runs"][0]["report_path"] == "[REDACTED_PATH]"
    assert "report-token" not in str(updated)


def test_report_export_uses_safe_workspace_report_path(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")

    updated = record_workspace_report_export(
        workspace.path,
        run_id="run-1",
        report={"submission_blocked": True},
    )

    report_path = updated["runs"][0]["report_path"]
    assert report_path.endswith("run-1-report-preview.json")
    assert "submission_blocked" not in str(updated)


def test_report_export_writes_submission_blocked_markdown_draft(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")

    updated = record_workspace_report_export(
        workspace.path,
        run_id="run-1",
        report={
            "title": "Authorization gap candidate",
            "summary": "Object access needs evidence review.",
            "submission_blocked": True,
            "report_submission_allowed": False,
            "safety_notes": ["no_auto_submission"],
        },
    )

    markdown_path = Path(updated["runs"][0]["report_markdown_path"])

    assert markdown_path.name == "run-1-report-draft.md"
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "# Authorization gap candidate" in markdown
    assert "Submission status: blocked" in markdown
    assert "Report submission allowed: false" in markdown
    assert "Object access needs evidence review." in markdown
    assert "Object access needs evidence review." not in str(updated)


def test_report_export_markdown_includes_preview_claim_sections(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")

    updated = record_workspace_report_export(
        workspace.path,
        run_id="run-1",
        report={
            "title": "Authorization gap candidate",
            "sections": {
                "observed_facts": ["GET /files/{file_id}/export is routed locally."],
                "model_reasoning": ["Ownership enforcement needs manual review."],
                "unverified_claims": ["Changing file_id may cross tenant boundaries."],
            },
        },
    )

    markdown = Path(updated["runs"][0]["report_markdown_path"]).read_text(
        encoding="utf-8"
    )

    assert "## Observed facts" in markdown
    assert "- GET /files/{file_id}/export is routed locally." in markdown
    assert "## Model reasoning" in markdown
    assert "- Ownership enforcement needs manual review." in markdown
    assert "## Unverified claims" in markdown
    assert "- Changing file_id may cross tenant boundaries." in markdown
    assert "Changing file_id may cross tenant boundaries." not in str(updated)


def test_report_export_markdown_includes_top_candidate_reviews_without_secrets(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")

    updated = record_workspace_report_export(
        workspace.path,
        run_id="run-1",
        report={
            "title": "A+B candidate review",
            "top_candidate_reviews": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization_gap",
                    "risk": "high",
                    "affected_endpoint": "GET /files/{file_id}/export",
                    "affected_code_path": "routes.py:export_file",
                    "report_status": "submission_blocked",
                    "validation_status": "needs_human_approval",
                    "evidence_need_count": 2,
                    "false_positive_check_count": 1,
                },
                {
                    "hypothesis_id": "H-002",
                    "vuln_type": "Authorization: Bearer secret-token",
                    "risk": "medium",
                    "affected_endpoint": "POST /webhooks/test",
                    "affected_code_path": "routes.py:test_webhook",
                    "report_status": "submission_blocked",
                    "validation_status": "needs_human_review",
                    "evidence_need_count": 1,
                    "false_positive_check_count": 1,
                },
            ],
        },
    )

    markdown = Path(updated["runs"][0]["report_markdown_path"]).read_text(
        encoding="utf-8"
    )

    assert "## Top candidate reviews" in markdown
    assert "H-001: high authorization_gap at GET /files/{file_id}/export -> routes.py:export_file" in markdown
    assert "evidence needs: 2" in markdown
    assert "false-positive checks: 1" in markdown
    assert "H-002: medium candidate at POST /webhooks/test -> routes.py:test_webhook" in markdown
    assert "secret-token" not in markdown
    assert "Authorization: Bearer" not in markdown


def test_record_workspace_mission_dossier_writes_review_only_markdown(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")
    record_workspace_run(
        workspace.path,
        run_id="run-1",
        status="completed",
        report_path=None,
        candidate_count=1,
    )

    updated = record_workspace_mission_dossier(
        workspace.path,
        run_id="run-1",
        mission={
            "mode": "local_ai_vulnerability_research_workbench",
            "run_id": "run-1",
            "scope_guard_status": "scope_imported",
            "artifacts": {
                "required": ["scope", "policy", "code", "api", "har"],
                "present": ["scope", "policy", "code", "api", "har"],
                "missing": [],
            },
            "agent_queue": [
                {
                    "task_id": "semantic_candidate_hunt",
                    "agent": "Semantic Auditor",
                    "status": "complete",
                    "safety_gate": "local_static_analysis_only",
                    "input_refs": ["code", "api", "har"],
                    "target_candidates": ["H-001"],
                    "next_action": "Review top candidate invariants.",
                }
            ],
            "top_candidates": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "Authorization: Bearer secret-token",
                    "affected_endpoint": "GET /files/{file_id}/export",
                    "affected_code_path": "routes.py:export_file",
                    "report_status": "submission_blocked",
                    "next_report_action": "Review evidence before exporting a report preview.",
                    "evidence_needed": [
                        "Confirm the owner boundary from authorized local artifacts.",
                        "Do not include Authorization: Bearer secret-token.",
                    ],
                    "false_positive_checks": [
                        "Check whether the service layer enforces tenant ownership.",
                    ],
                    "safe_validation_plan": [
                        "Prepare a non-destructive two-account check for human approval.",
                    ],
                    "safety_blockers": [
                        "execute_live_validation",
                        "submit_report",
                        "Do not touch real user data.",
                    ],
                }
            ],
        },
    )

    dossier = updated["mission_dossiers"][0]
    markdown = Path(dossier["dossier_markdown_path"]).read_text(encoding="utf-8")

    assert dossier["report_submission_allowed"] is False
    assert dossier["validation_execution_allowed"] is False
    assert updated["runs"][0]["mission_dossier_path"] == dossier["dossier_path"]
    assert "## Agent queue" in markdown
    assert "semantic_candidate_hunt: Semantic Auditor" in markdown
    assert "## Top candidates" in markdown
    assert "H-001: candidate; endpoint: GET /files/{file_id}/export" in markdown
    assert "Evidence needed: Confirm the owner boundary" in markdown
    assert "Refutation questions: Check whether the service layer" in markdown
    assert "Safe validation plan: Prepare a non-destructive two-account check" in markdown
    assert "Validation execution remains blocked pending human approval." in markdown
    assert "Report submission remains blocked pending human review." in markdown
    assert "Do not touch real user data." in markdown
    assert "Next report action: Review evidence before exporting" in markdown
    assert "secret-token" not in markdown
    assert "Authorization: Bearer" not in markdown
    assert "execute_live_validation" not in markdown
    assert "submit_report" not in markdown


def test_report_export_markdown_skips_secret_like_section_items(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")

    updated = record_workspace_report_export(
        workspace.path,
        run_id="run-1",
        report={
            "title": "Authorization gap candidate",
            "sections": {
                "observed_facts": [
                    "GET /files/{file_id}/export is routed locally.",
                    "Authorization: Bearer secret-token",
                ],
            },
        },
    )

    markdown = Path(updated["runs"][0]["report_markdown_path"]).read_text(
        encoding="utf-8"
    )

    assert "GET /files/{file_id}/export is routed locally." in markdown
    assert "secret-token" not in markdown
    assert "Authorization: Bearer" not in markdown
    assert "secret-token" not in str(updated)


def test_report_export_markdown_includes_repair_guidance_and_regression_test(
    tmp_path: Path,
):
    workspace = create_workspace(tmp_path, name="acme-api")

    updated = record_workspace_report_export(
        workspace.path,
        run_id="run-1",
        report={
            "title": "Authorization gap candidate",
            "suggested_fix": "Enforce ownership in the service layer before returning files.",
            "regression_test": "Add a local test proving user B cannot export user A's file.",
        },
    )

    markdown = Path(updated["runs"][0]["report_markdown_path"]).read_text(
        encoding="utf-8"
    )

    assert "## Suggested fix" in markdown
    assert "Enforce ownership in the service layer before returning files." in markdown
    assert "## Regression test" in markdown
    assert "Add a local test proving user B cannot export user A's file." in markdown
    assert "Enforce ownership in the service layer" not in str(updated)


def test_report_export_markdown_includes_evidence_and_false_positive_checks(
    tmp_path: Path,
):
    workspace = create_workspace(tmp_path, name="acme-api")

    updated = record_workspace_report_export(
        workspace.path,
        run_id="run-1",
        report={
            "title": "Authorization gap candidate",
            "evidence_needed": [
                "Two authorized local test accounts.",
                "Authorization: Bearer secret-token",
            ],
            "false_positive_checks": [
                "Does the service enforce ownership before returning the file?",
                "Cookie: session=secret-token",
            ],
        },
    )

    markdown = Path(updated["runs"][0]["report_markdown_path"]).read_text(
        encoding="utf-8"
    )

    assert "## Evidence needs" in markdown
    assert "- Two authorized local test accounts." in markdown
    assert "## False-positive checks" in markdown
    assert "- Does the service enforce ownership before returning the file?" in markdown
    assert "secret-token" not in markdown
    assert "Authorization: Bearer" not in markdown


def test_report_export_markdown_includes_evidence_gaps(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")

    updated = record_workspace_report_export(
        workspace.path,
        run_id="run-1",
        report={
            "title": "Authorization gap candidate",
            "evidence_gaps": [
                "code: missing_code_path",
                "har: missing_required_artifact",
                "Authorization: Bearer secret-token",
            ],
        },
    )

    markdown = Path(updated["runs"][0]["report_markdown_path"]).read_text(
        encoding="utf-8"
    )

    assert "## Evidence gaps" in markdown
    assert "- code: missing_code_path" in markdown
    assert "- har: missing_required_artifact" in markdown
    assert "secret-token" not in markdown
    assert "Authorization: Bearer" not in markdown


def test_report_export_markdown_includes_validation_plan_and_safety_blockers(
    tmp_path: Path,
):
    workspace = create_workspace(tmp_path, name="acme-api")

    updated = record_workspace_report_export(
        workspace.path,
        run_id="run-1",
        report={
            "title": "Authorization gap candidate",
            "safe_validation_plan": [
                "Prepare two authorized local test accounts.",
                "Replay Authorization: Bearer secret-token",
            ],
            "safety_blockers": [
                "execute_live_validation",
                "submit_report",
                "Cookie: session=secret-token",
            ],
        },
    )

    markdown = Path(updated["runs"][0]["report_markdown_path"]).read_text(
        encoding="utf-8"
    )

    assert "## Safe validation plan" in markdown
    assert "- Prepare two authorized local test accounts." in markdown
    assert "## Safety blockers" in markdown
    assert "- Validation execution remains blocked pending human approval." in markdown
    assert "- Report submission remains blocked pending human review." in markdown
    assert "execute_live_validation" not in markdown
    assert "submit_report" not in markdown
    assert "secret-token" not in markdown
    assert "Authorization: Bearer" not in markdown


def test_report_export_markdown_includes_candidate_summary_and_ranking_reasons(
    tmp_path: Path,
):
    workspace = create_workspace(tmp_path, name="acme-api")

    updated = record_workspace_report_export(
        workspace.path,
        run_id="run-1",
        report={
            "title": "Authorization gap candidate",
            "candidate_summary": [
                "Affected endpoint: GET /files/{file_id}/export",
                "Affected code path: routes.py:export_file",
                "Authorization: Bearer secret-token",
            ],
            "ranking_reasons": [
                "impact:sensitive_data_sink",
                "Cookie: session=secret-token",
            ],
        },
    )

    markdown = Path(updated["runs"][0]["report_markdown_path"]).read_text(
        encoding="utf-8"
    )

    assert "## Candidate summary" in markdown
    assert "- Affected endpoint: GET /files/{file_id}/export" in markdown
    assert "- Affected code path: routes.py:export_file" in markdown
    assert "## Ranking reasons" in markdown
    assert "- impact:sensitive_data_sink" in markdown
    assert "secret-token" not in markdown
    assert "Authorization: Bearer" not in markdown


def test_report_export_markdown_includes_report_readiness_next_action(
    tmp_path: Path,
):
    workspace = create_workspace(tmp_path, name="acme-api")

    updated = record_workspace_report_export(
        workspace.path,
        run_id="run-1",
        report={
            "title": "Authorization gap candidate",
            "report_readiness": {
                "status": "submission_blocked",
                "report_submission_allowed": False,
                "next_allowed_action": "Review evidence gaps before exporting a report preview.",
            },
        },
    )

    markdown = Path(updated["runs"][0]["report_markdown_path"]).read_text(
        encoding="utf-8"
    )

    assert "## Report readiness" in markdown
    assert "- Status: submission_blocked" in markdown
    assert "- Report submission allowed: false" in markdown
    assert "- Next allowed action: Review evidence gaps before exporting a report preview." in markdown


def test_report_export_markdown_skips_secret_like_report_next_action(
    tmp_path: Path,
):
    workspace = create_workspace(tmp_path, name="acme-api")

    updated = record_workspace_report_export(
        workspace.path,
        run_id="run-1",
        report={
            "title": "Authorization gap candidate",
            "report_readiness": {
                "status": "submission_blocked",
                "report_submission_allowed": False,
                "next_allowed_action": "Review Authorization: Bearer secret-token.",
            },
        },
    )

    markdown = Path(updated["runs"][0]["report_markdown_path"]).read_text(
        encoding="utf-8"
    )

    assert "## Report readiness" in markdown
    assert "- Status: submission_blocked" in markdown
    assert "Next allowed action" not in markdown
    assert "secret-token" not in markdown
    assert "Authorization: Bearer" not in markdown


def test_report_export_markdown_includes_evidence_review_items(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")

    updated = record_workspace_report_export(
        workspace.path,
        run_id="run-1",
        report={
            "title": "Authorization gap candidate",
            "evidence_review": {
                "status": "needs_human_review",
                "required_items": [
                    "Confirm affected code path with local artifacts.",
                    "Review Authorization: Bearer secret-token before sharing.",
                ],
            },
        },
    )

    markdown = Path(updated["runs"][0]["report_markdown_path"]).read_text(
        encoding="utf-8"
    )

    assert "## Evidence review" in markdown
    assert "- Status: needs_human_review" in markdown
    assert "- Confirm affected code path with local artifacts." in markdown
    assert "secret-token" not in markdown
    assert "Authorization: Bearer" not in markdown


def test_report_export_markdown_includes_deduplication_review_items(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")

    updated = record_workspace_report_export(
        workspace.path,
        run_id="run-1",
        report={
            "title": "Authorization gap candidate",
            "deduplication_review": {
                "status": "needs_human_review",
                "duplicate_risk_score": 10,
                "review_items": [
                    "Compare endpoint and invariant against prior submissions.",
                    "Review Authorization: Bearer secret-token before sharing.",
                ],
            },
        },
    )

    markdown = Path(updated["runs"][0]["report_markdown_path"]).read_text(
        encoding="utf-8"
    )

    assert "## Deduplication review" in markdown
    assert "- Status: needs_human_review" in markdown
    assert "- Duplicate risk score: 10" in markdown
    assert "- Compare endpoint and invariant against prior submissions." in markdown
    assert "secret-token" not in markdown
    assert "Authorization: Bearer" not in markdown


def test_report_export_markdown_includes_refutation_review_questions(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")

    updated = record_workspace_report_export(
        workspace.path,
        run_id="run-1",
        report={
            "title": "Authorization gap candidate",
            "refutation_review": {
                "status": "needs_human_review",
                "questions": [
                    "Does middleware already enforce this boundary?",
                    "Review Authorization: Bearer secret-token before sharing.",
                ],
            },
        },
    )

    markdown = Path(updated["runs"][0]["report_markdown_path"]).read_text(
        encoding="utf-8"
    )

    assert "## Refutation review" in markdown
    assert "- Status: needs_human_review" in markdown
    assert "- Does middleware already enforce this boundary?" in markdown
    assert "secret-token" not in markdown
    assert "Authorization: Bearer" not in markdown


def test_report_export_markdown_includes_validation_review_items(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")

    updated = record_workspace_report_export(
        workspace.path,
        run_id="run-1",
        report={
            "title": "Authorization gap candidate",
            "validation_review": {
                "status": "needs_human_approval",
                "execution_allowed": False,
                "review_items": [
                    "Confirm Scope Guard allows this validation mode.",
                    "Review Authorization: Bearer secret-token before sharing.",
                ],
            },
        },
    )

    markdown = Path(updated["runs"][0]["report_markdown_path"]).read_text(
        encoding="utf-8"
    )

    assert "## Validation review" in markdown
    assert "- Status: needs_human_approval" in markdown
    assert "- Execution allowed: false" in markdown
    assert "- Confirm Scope Guard allows this validation mode." in markdown
    assert "secret-token" not in markdown
    assert "Authorization: Bearer" not in markdown


def test_report_export_markdown_includes_policy_review_items(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")

    updated = record_workspace_report_export(
        workspace.path,
        run_id="run-1",
        report={
            "title": "Authorization gap candidate",
            "policy_review": {
                "status": "needs_human_review",
                "policy_risk": "low",
                "policy_risk_score": 10,
                "review_items": [
                    "Confirm candidate remains inside imported scope and policy.",
                    "Review Authorization: Bearer secret-token before sharing.",
                ],
            },
        },
    )

    markdown = Path(updated["runs"][0]["report_markdown_path"]).read_text(
        encoding="utf-8"
    )

    assert "## Policy review" in markdown
    assert "- Status: needs_human_review" in markdown
    assert "- Policy risk: low" in markdown
    assert "- Policy risk score: 10" in markdown
    assert "- Confirm candidate remains inside imported scope and policy." in markdown
    assert "secret-token" not in markdown
    assert "Authorization: Bearer" not in markdown


def test_report_export_markdown_includes_provenance_review_items(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")

    updated = record_workspace_report_export(
        workspace.path,
        run_id="run-1",
        report={
            "title": "Authorization gap candidate",
            "provenance_review": {
                "status": "needs_human_review",
                "artifact_kinds": ["scope", "policy", "code", "api", "har"],
                "review_items": [
                    "Confirm claims are traceable to imported artifacts.",
                    "Review Authorization: Bearer secret-token before sharing.",
                ],
            },
        },
    )

    markdown = Path(updated["runs"][0]["report_markdown_path"]).read_text(
        encoding="utf-8"
    )

    assert "## Provenance review" in markdown
    assert "- Status: needs_human_review" in markdown
    assert "- Artifact kinds: scope, policy, code, api, har" in markdown
    assert "- Confirm claims are traceable to imported artifacts." in markdown
    assert "secret-token" not in markdown
    assert "Authorization: Bearer" not in markdown


def test_report_export_markdown_skips_secret_like_repair_guidance(tmp_path: Path):
    workspace = create_workspace(tmp_path, name="acme-api")

    updated = record_workspace_report_export(
        workspace.path,
        run_id="run-1",
        report={
            "title": "Authorization gap candidate",
            "suggested_fix": "Rotate Authorization: Bearer secret-token",
            "regression_test": "Store cookie: session=secret-token in a fixture",
        },
    )

    markdown = Path(updated["runs"][0]["report_markdown_path"]).read_text(
        encoding="utf-8"
    )

    assert "## Suggested fix" not in markdown
    assert "## Regression test" not in markdown
    assert "secret-token" not in markdown
    assert "Authorization: Bearer" not in markdown
