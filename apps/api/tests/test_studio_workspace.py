import json
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
                    "review_focus": [
                        "security_invariants",
                        "affected_code_paths",
                        "candidate_quality",
                    ],
                    "candidate_quality_gaps": ["H-002:missing_safe_validation_plan"],
                    "next_action": "Review top candidate invariants.",
                }
            ],
            "quality_summary": {
                "status": "needs_review",
                "top_candidate_quality_gate": "needs_review",
                "candidate_count": 1,
                "review_ready_count": 0,
                "average_quality_score": 72,
                "blockers": ["Some Top candidates still need quality review."],
                "improvement_actions": [
                    "Draft a non-destructive validation plan for H-002.",
                ],
            },
            "candidate_hunter_backlog": [
                {
                    "work_item_id": "H-002:draft_validation_plan",
                    "candidate_id": "H-002",
                    "gap": "missing_safe_validation_plan",
                    "status": "needs_review",
                    "review_focus": ["safe_validation_plan", "non_destructive_plan_only"],
                    "required_evidence": ["non_destructive_validation_plan"],
                    "next_action": "Draft a non-destructive validation plan for H-002.",
                    "safety_gate": "review_only_no_execution",
                    "execution_allowed": True,
                    "validation_allowed": True,
                    "report_submission_allowed": True,
                }
            ],
            "candidate_hunter_iteration": {
                "iteration_id": "candidate_hunter:next_review",
                "status": "needs_review",
                "work_item_count": 1,
                "priority_order": ["H-002:draft_validation_plan"],
                "next_review_agent": "Evidence Planner",
                "review_focus": ["safe_validation_plan"],
                "success_criteria": [
                    "H-002:draft_validation_plan has traceable evidence: non_destructive_validation_plan.",
                    "No validation, fuzzing, or report submission is executed.",
                ],
                "safety_gate": "review_only_no_execution",
                "completion_gate": "human_review_required",
                "execution_allowed": True,
                "validation_allowed": True,
                "report_submission_allowed": True,
            },
            "agent_handoff_pack": {
                "pack_id": "studio:agent_handoff:next_review",
                "status": "needs_review",
                "handoff_item_count": 1,
                "next_review_agent": "Evidence Planner",
                "priority_order": ["H-002:draft_validation_plan"],
                "review_focus": ["safe_validation_plan"],
                "success_criteria": [
                    "H-002:draft_validation_plan is reviewed against authorized local artifacts.",
                ],
                "handoff_items": [
                    {
                        "handoff_id": "handoff:H-002:draft_validation_plan",
                        "work_item_id": "H-002:draft_validation_plan",
                        "candidate_id": "H-002",
                        "status": "needs_review",
                        "assigned_agent": "Evidence Planner",
                        "gap": "missing_safe_validation_plan",
                        "input_refs": ["scope", "policy", "code", "api", "har"],
                        "review_focus": ["safe_validation_plan"],
                        "required_evidence": ["non_destructive_validation_plan"],
                        "success_criteria": [
                            "No validation, fuzzing, or report submission is executed.",
                        ],
                        "next_action": "Draft a non-destructive validation plan for H-002.",
                        "safety_gate": "review_only_no_execution",
                        "execution_allowed": True,
                        "validation_allowed": True,
                        "report_submission_allowed": True,
                    }
                ],
                "agent_queue_refs": ["semantic_candidate_hunt"],
                "timeline_gate_counts": {"review_recorded": 1},
                "safety_gate": "unsafe_override",
                "completion_gate": "unsafe_override",
                "blocked_actions": [
                    "execute_live_validation",
                    "run_fuzzer",
                    "submit_report",
                ],
                "execution_allowed": True,
                "validation_allowed": True,
                "report_submission_allowed": True,
            },
            "candidate_review_packets": [
                {
                    "candidate_id": "H-001",
                    "status": "needs_review",
                    "completed_items": ["endpoint_trace", "code_path_trace"],
                    "missing_items": ["safe_validation_plan"],
                    "checklist": [
                        {
                            "key": "endpoint_trace",
                            "status": "complete",
                            "label": "Affected endpoint is traced.",
                        },
                        {
                            "key": "safe_validation_plan",
                            "status": "needs_review",
                            "label": "Non-destructive validation plan is drafted.",
                        },
                    ],
                    "next_human_action": "Draft a non-destructive validation plan.",
                    "safety_gate": "human_review_required",
                    "evidence_need_count": 2,
                    "false_positive_check_count": 1,
                    "safe_validation_step_count": 0,
                    "quality_score": 85,
                    "report_review_priority": "resolve_review_gaps",
                    "report_status": "submission_blocked",
                    "hallucination_guard_status": "needs_review",
                    "execution_allowed": True,
                    "validation_allowed": True,
                    "report_submission_allowed": True,
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
    queue_audit = updated["agent_queue_audits"][0]
    markdown = Path(dossier["dossier_markdown_path"]).read_text(encoding="utf-8")
    queue_json = json.loads(Path(queue_audit["agent_queue_path"]).read_text(encoding="utf-8"))
    queue_markdown = Path(queue_audit["agent_queue_markdown_path"]).read_text(
        encoding="utf-8"
    )

    assert dossier["report_submission_allowed"] is False
    assert dossier["validation_execution_allowed"] is False
    assert dossier["agent_queue_path"] == queue_audit["agent_queue_path"]
    assert dossier["agent_queue_markdown_path"] == queue_audit["agent_queue_markdown_path"]
    assert queue_audit["task_count"] == 1
    assert queue_audit["timeline_stage_count"] == 1
    assert queue_audit["timeline_blocked_stage_count"] == 0
    assert queue_audit["timeline_needs_review_stage_count"] == 0
    assert queue_audit["timeline_pending_stage_count"] == 0
    assert queue_audit["candidate_review_packet_count"] == 1
    assert queue_audit["candidate_review_ready_packet_count"] == 0
    assert queue_audit["submission_blocked_report_status"] == "needs_human_review"
    assert queue_audit["submission_blocked_report_ready_candidate_count"] == 0
    assert queue_audit["agent_handoff_item_count"] == 1
    assert queue_audit["agent_handoff_status"] == "needs_review"
    assert queue_audit["report_submission_allowed"] is False
    assert queue_audit["validation_execution_allowed"] is False
    assert updated["runs"][0]["mission_dossier_path"] == dossier["dossier_path"]
    assert updated["runs"][0]["agent_queue_path"] == queue_audit["agent_queue_path"]
    assert queue_json["agent_queue"][0]["review_focus"] == [
        "security_invariants",
        "affected_code_paths",
        "candidate_quality",
    ]
    assert queue_json["agent_queue"][0]["candidate_quality_gaps"] == [
        "H-002:missing_safe_validation_plan",
    ]
    assert queue_json["quality_summary"]["top_candidate_quality_gate"] == "needs_review"
    assert queue_json["candidate_hunter_backlog"][0]["work_item_id"] == (
        "H-002:draft_validation_plan"
    )
    assert queue_json["candidate_hunter_backlog"][0]["execution_allowed"] is False
    assert queue_json["candidate_hunter_backlog"][0]["validation_allowed"] is False
    assert queue_json["candidate_hunter_backlog"][0]["report_submission_allowed"] is False
    assert queue_json["candidate_hunter_iteration"]["status"] == "needs_review"
    assert queue_json["candidate_hunter_iteration"]["priority_order"] == [
        "H-002:draft_validation_plan",
    ]
    assert queue_json["candidate_hunter_iteration"]["execution_allowed"] is False
    assert queue_json["candidate_hunter_iteration"]["validation_allowed"] is False
    assert queue_json["candidate_hunter_iteration"]["report_submission_allowed"] is False
    assert queue_json["candidate_hunter_plan"]["plan_id"] == (
        "candidate_hunter:autonomous_review_plan"
    )
    assert queue_json["candidate_hunter_plan"]["status"] == "needs_review"
    assert queue_json["candidate_hunter_plan"]["work_item_count"] == 1
    assert queue_json["candidate_hunter_plan"]["step_count"] == 1
    assert queue_json["candidate_hunter_plan"]["next_review_agent"] == (
        "Evidence Planner"
    )
    assert queue_json["candidate_hunter_plan"]["safety_gate"] == (
        "review_only_no_execution"
    )
    assert queue_json["candidate_hunter_plan"]["completion_gate"] == (
        "human_review_required"
    )
    assert queue_json["candidate_hunter_plan"]["execution_allowed"] is False
    assert queue_json["candidate_hunter_plan"]["validation_allowed"] is False
    assert queue_json["candidate_hunter_plan"]["report_submission_allowed"] is False
    assert queue_json["candidate_hunter_plan"]["hallucination_governance"] == {
        "claim_promotion_rule": "no_verified_evidence_no_high_confidence",
        "model_output_policy": "llm_claims_start_unverified",
        "knowledge_policy": "rag_few_shot_context_only_not_cross_validation",
        "required_consensus": [
            "authorized_local_artifact_evidence",
            "independent_refutation_or_static_rule",
            "human_review_decision",
        ],
        "independent_challenge_sources": [
            "sarif_static_analysis",
            "fuzzing_artifact",
            "second_model_refutation",
            "manual_code_review",
        ],
        "candidate_promotion_allowed": False,
    }
    assert queue_json["candidate_hunter_plan"]["plan_steps"][0] == {
        "step_id": "candidate_hunter:plan:H-002:draft_validation_plan",
        "work_item_id": "H-002:draft_validation_plan",
        "candidate_id": "H-002",
        "assigned_agent": "Evidence Planner",
        "gap": "missing_safe_validation_plan",
        "input_refs": ["scope", "policy", "code", "api", "har"],
        "review_focus": ["safe_validation_plan", "non_destructive_plan_only"],
        "required_evidence": ["non_destructive_validation_plan"],
        "next_action": "Draft a non-destructive validation plan for H-002.",
        "success_criteria": [
            "H-002:draft_validation_plan is reviewed against authorized local artifacts.",
            "Evidence refs required: non_destructive_validation_plan.",
            "No validation, fuzzing, or report submission is executed.",
        ],
        "review_checklist": [
            {
                "key": "authorized_artifact_trace",
                "label": "Trace the step to scope, policy, code, API, and HAR artifacts.",
                "status": "needs_review",
                "required": True,
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            },
            {
                "key": "evidence_requirements",
                "label": "Record traceable evidence refs: non_destructive_validation_plan.",
                "status": "needs_review",
                "required": True,
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            },
            {
                "key": "refutation_review",
                "label": "Record false-positive questions or confirm existing refutation coverage.",
                "status": "confirm_current_state",
                "required": True,
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            },
            {
                "key": "deduplication_review",
                "label": "Compare endpoint, code path, invariant, and impact against prior candidates.",
                "status": "confirm_current_state",
                "required": True,
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            },
            {
                "key": "safe_validation_plan",
                "label": "Draft or review a non-destructive validation plan without execution.",
                "status": "needs_review",
                "required": True,
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            },
            {
                "key": "submission_blocked_report_draft",
                "label": "Confirm report draft readiness while keeping submission blocked.",
                "status": "confirm_current_state",
                "required": True,
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            },
        ],
        "hallucination_governance_refs": [
            "LLM output remains an unverified claim until local evidence is traced.",
            "Knowledge/RAG context is few-shot guidance only and cannot satisfy cross-validation.",
        ],
        "safety_gate": "review_only_no_execution",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }
    assert queue_json["candidate_hunter_review_loop"]["loop_id"] == (
        "candidate_hunter:next_review_loop"
    )
    assert queue_json["candidate_hunter_review_loop"]["status"] == "needs_review"
    assert queue_json["candidate_hunter_review_loop"]["active_step_count"] == 1
    assert queue_json["candidate_hunter_review_loop"]["next_review_agent"] == (
        "Evidence Planner"
    )
    assert queue_json["candidate_hunter_review_loop"]["review_agents"] == [
        "Evidence Planner"
    ]
    assert queue_json["candidate_hunter_review_loop"]["required_evidence"] == [
        "non_destructive_validation_plan"
    ]
    assert (
        queue_json["candidate_hunter_review_loop"]["governance_summary"][
            "candidate_promotion_allowed"
        ]
        is False
    )
    assert queue_json["candidate_hunter_review_loop"]["active_steps"][0][
        "review_checklist"
    ][4] == {
        "key": "safe_validation_plan",
        "label": "Draft or review a non-destructive validation plan without execution.",
        "status": "needs_review",
        "required": True,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }
    assert queue_json["candidate_hunter_review_loop"]["execution_allowed"] is False
    assert queue_json["candidate_hunter_review_loop"]["validation_allowed"] is False
    assert (
        queue_json["candidate_hunter_review_loop"]["report_submission_allowed"] is False
    )
    assert markdown.find("## Candidate hunter review loop") > -1
    assert "candidate_hunter:next_review_loop" in markdown
    assert queue_json["agent_handoff_pack"]["status"] == "needs_review"
    assert queue_json["agent_handoff_pack"]["handoff_item_count"] == 1
    assert queue_json["agent_handoff_pack"]["safety_gate"] == (
        "review_only_no_execution"
    )
    assert queue_json["agent_handoff_pack"]["completion_gate"] == (
        "human_review_required"
    )
    assert queue_json["agent_handoff_pack"]["execution_allowed"] is False
    assert queue_json["agent_handoff_pack"]["validation_allowed"] is False
    assert queue_json["agent_handoff_pack"]["report_submission_allowed"] is False
    assert queue_json["agent_handoff_pack"]["handoff_items"][0]["work_item_id"] == (
        "H-002:draft_validation_plan"
    )
    assert (
        queue_json["agent_handoff_pack"]["handoff_items"][0]["execution_allowed"]
        is False
    )
    assert (
        queue_json["agent_handoff_pack"]["handoff_items"][0]["validation_allowed"]
        is False
    )
    assert (
        queue_json["agent_handoff_pack"]["handoff_items"][0][
            "report_submission_allowed"
        ]
        is False
    )
    assert queue_json["candidate_review_packets"][0]["candidate_id"] == "H-001"
    assert queue_json["candidate_review_packets"][0]["missing_items"] == [
        "safe_validation_plan"
    ]
    assert queue_json["candidate_review_packets"][0]["quality_score"] == 85
    assert queue_json["candidate_review_packets"][0]["report_review_priority"] == (
        "resolve_review_gaps"
    )
    assert queue_json["candidate_review_packets"][0]["execution_allowed"] is False
    assert queue_json["candidate_review_packets"][0]["validation_allowed"] is False
    assert (
        queue_json["candidate_review_packets"][0]["report_submission_allowed"] is False
    )
    assert queue_json["submission_blocked_report_summary"] == {
        "status": "needs_human_review",
        "candidate_count": 1,
        "ready_candidate_ids": [],
        "needs_review_candidate_ids": ["H-001"],
        "missing_review_items": {"H-001": ["safe_validation_plan"]},
        "report_review_queue": [
            {
                "candidate_id": "H-001",
                "priority": "resolve_review_gaps",
                "quality_score": 85,
                "next_human_action": "Draft a non-destructive validation plan.",
                "safety_gate": "submission_blocked_human_review",
                "report_submission_allowed": False,
                "validation_execution_allowed": False,
            }
        ],
        "next_human_actions": ["Draft a non-destructive validation plan."],
        "safety_gate": "submission_blocked_human_review",
        "redaction_review_required": True,
        "report_submission_allowed": False,
        "validation_execution_allowed": False,
    }
    assert queue_json["studio_timeline_summary"] == {
        "total_stages": 1,
        "gate_decision_counts": {"review_recorded": 1},
        "blocked_stage_ids": [],
        "needs_review_stage_ids": [],
        "pending_stage_ids": [],
        "next_human_actions": ["Review top candidate invariants."],
        "safety_gate": "review_only_no_execution",
        "report_submission_allowed": False,
        "validation_execution_allowed": False,
    }
    assert queue_json["task_timeline"][0] == {
        "stage_id": "agent_queue:semantic_candidate_hunt",
        "task_id": "semantic_candidate_hunt",
        "attempt": 1,
        "agent": "Semantic Auditor",
        "status": "complete",
        "safety_gate": "local_static_analysis_only",
        "gate_decision": "review_recorded",
        "input_summary": "Input refs: code, api, har",
        "output_summary": (
            "candidates: H-001; focus: security_invariants, affected_code_paths, "
            "candidate_quality; quality gaps: H-002:missing_safe_validation_plan"
        ),
        "next_human_action": "Review top candidate invariants.",
        "report_submission_allowed": False,
        "validation_execution_allowed": False,
    }
    assert "# Mythos Studio agent queue audit" in queue_markdown
    assert "## Candidate hunter backlog" in queue_markdown
    assert "H-002:draft_validation_plan" in queue_markdown
    assert "## Candidate hunter iteration" in queue_markdown
    assert "## Candidate hunter plan" in queue_markdown
    assert "candidate_hunter:plan:H-002:draft_validation_plan" in queue_markdown
    assert "## Candidate hunter review loop" in queue_markdown
    assert "candidate_hunter:next_review_loop" in queue_markdown
    assert "Hallucination governance" in queue_markdown
    assert "no_verified_evidence_no_high_confidence" in queue_markdown
    assert "LLM output remains an unverified claim" in queue_markdown
    assert "Review checklist: authorized_artifact_trace: needs_review" in queue_markdown
    assert "safe_validation_plan: needs_review" in queue_markdown
    assert "## Studio timeline summary" in queue_markdown
    assert "## Candidate review packets" in queue_markdown
    assert "## Submission-blocked report summary" in queue_markdown
    assert "H-001: safe_validation_plan" in queue_markdown
    assert "H-001: resolve_review_gaps (85/100)" in queue_markdown
    assert "## Agent handoff pack" in queue_markdown
    assert "handoff items: 1" in queue_markdown
    assert "agent: Evidence Planner" in queue_markdown
    assert "safe_validation_plan=needs_review" in queue_markdown
    assert "review_recorded: 1" in queue_markdown
    assert "execution allowed: false" in queue_markdown
    assert "quality gaps: H-002:missing_safe_validation_plan" in queue_markdown
    assert "## Mission quality" in queue_markdown
    assert "## Agent task timeline" in queue_markdown
    assert "agent_queue:semantic_candidate_hunt" in queue_markdown
    assert "gate: review_recorded" in queue_markdown
    assert "## Agent queue" in markdown
    assert "## Candidate hunter iteration" in markdown
    assert "## Candidate hunter plan" in markdown
    assert "## Candidate hunter review loop" in markdown
    assert "Hallucination governance" in markdown
    assert "## Studio timeline summary" in markdown
    assert "## Candidate review packets" in markdown
    assert "## Submission-blocked report summary" in markdown
    assert "## Agent handoff pack" in markdown
    assert "semantic_candidate_hunt: Semantic Auditor" in markdown
    assert "focus: security_invariants, affected_code_paths, candidate_quality" in markdown
    assert "quality gaps: H-002:missing_safe_validation_plan" in markdown
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
    assert "execute_live_validation" not in queue_markdown
    assert "submit_report" not in queue_markdown


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
