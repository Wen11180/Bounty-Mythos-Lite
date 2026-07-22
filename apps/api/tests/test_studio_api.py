import asyncio
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import json
from pathlib import Path
from shutil import copy2, copytree
from types import SimpleNamespace

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_session
from app.db_models import CampaignTaskRecord
from app.config import get_settings
from app.cross_source_candidate_generator import ReplayCandidateReasoner
from app.main import (
    app,
    _studio_candidate_hunter_backlog,
    _studio_candidate_hunter_iteration,
    _studio_candidate_hunter_execution_loop,
    _studio_candidate_hunter_plan,
    _studio_candidate_hunter_review_loop,
    _studio_candidates_for_run,
    _studio_empty_surface_context_fact,
    _studio_fuzzing_surface_facts,
    _studio_knowledge_surface_facts,
    _studio_mission_agent_queue,
    _studio_mission_candidate_summary,
    _studio_openapi_surface_facts,
    _studio_report_candidate_guidance,
    _studio_authorized_code_files,
    _studio_fact_pack_code_files,
)
from app.llm.base import LLMMode, LLMResponse, ProviderName
from app.llm.registry import LLMRegistry
from app.repository import DatabaseRepository
from app.repository import seed_sample_data
from app.worker.tasks import run_agent_task
import app.main as main_module


client = TestClient(app)


@pytest.fixture(autouse=True)
def _configure_studio_workspace_root(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("STUDIO_WORKSPACE_ROOT", str(tmp_path))
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_studio_manifest_rejects_workspace_outside_configured_root(tmp_path: Path):
    outside_workspace = tmp_path.parent / f"{tmp_path.name}-outside"
    outside_workspace.mkdir()

    response = client.get(
        "/mythos/studio/workspaces/manifest",
        params={"workspace_path": str(outside_workspace)},
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "studio_workspace_not_authorized"}


def test_studio_workspace_creation_uses_configured_root_not_request_root(tmp_path: Path):
    response = client.post(
        "/mythos/studio/workspaces",
        json={
            "root_path": str(tmp_path.parent),
            "name": "acme-api",
        },
    )

    assert response.status_code == 200
    assert response.json()["path"] == str(tmp_path / "acme-api")


def test_studio_authorized_code_files_rejects_symlink_escape(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("OUTSIDE_SECRET = 'synthetic'", encoding="utf-8")
    link = repo / "linked.py"
    try:
        link.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"file symlinks unavailable: {exc}")

    with pytest.raises(main_module.HTTPException) as exc_info:
        _studio_authorized_code_files(str(repo))

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == "studio_artifact_not_authorized"


def test_studio_authorized_code_files_preserve_relative_paths_for_fact_packs(
    tmp_path: Path,
):
    repo = tmp_path / "repo"
    (repo / "api").mkdir(parents=True)
    (repo / "admin").mkdir()
    (repo / "api" / "routes.py").write_text("def api_route(): pass\n")
    (repo / "admin" / "routes.py").write_text("def admin_route(): pass\n")

    code_files = _studio_authorized_code_files(str(repo))
    fact_pack_files = _studio_fact_pack_code_files(code_files)

    assert [item["path"] for item in code_files] == [
        "admin/routes.py",
        "api/routes.py",
    ]
    assert [item["path"] for item in fact_pack_files] == [
        "admin/routes.py",
        "api/routes.py",
    ]


def test_studio_authorized_code_files_include_all_mapped_extensions(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    filenames = [
        "Controller.cs",
        "handler.rs",
        "routes.cts",
        "routes.mts",
        "service.scala",
    ]
    for filename in filenames:
        (repo / filename).write_text("local source fixture\n", encoding="utf-8")

    code_files = _studio_authorized_code_files(str(repo))

    assert {item["path"] for item in code_files} == set(filenames)


def test_studio_api_allows_only_configured_loopback_web_origin():
    response = client.options(
        "/mythos/studio/workspaces",
        headers={
            "Origin": "http://127.0.0.1:3000",
            "Access-Control-Request-Method": "POST",
        },
    )
    external_response = client.options(
        "/mythos/studio/workspaces",
        headers={
            "Origin": "https://example.com",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.headers["access-control-allow-origin"] == "http://127.0.0.1:3000"
    assert "access-control-allow-origin" not in external_response.headers


def test_studio_openapi_surface_facts_project_only_safe_access_mode():
    facts = _studio_openapi_surface_facts(
        {
            "openapi": "3.0.0",
            "paths": {
                "/protected/{record_id}": {
                    "get": {
                        "operationId": "readProtected",
                        "security": [{"privateScheme": []}],
                    }
                },
                "/public/{record_id}": {
                    "get": {
                        "operationId": "readPublic",
                        "security": [],
                    }
                },
                "/unspecified/{record_id}": {
                    "get": {"operationId": "readUnspecified"}
                },
            },
        }
    )

    assert [fact.get("access_mode") for fact in facts] == [
        "protected",
        "public",
        None,
    ]
    assert "privateScheme" not in str(facts)


def test_studio_empty_surface_context_requires_structurally_valid_json(
    tmp_path: Path,
):
    valid_har = tmp_path / "empty.har.json"
    valid_har.write_text(
        json.dumps({"log": {"version": "1.2", "entries": []}}),
        encoding="utf-8",
    )
    invalid_har = tmp_path / "invalid.har.json"
    invalid_har.write_text("not json", encoding="utf-8")

    assert _studio_empty_surface_context_fact(
        {"artifacts": [{"kind": "har", "source_path": str(valid_har)}]},
        "har",
    ) == {"fact_type": "har_context", "artifact_kind": "har"}
    assert (
        _studio_empty_surface_context_fact(
            {"artifacts": [{"kind": "har", "source_path": str(invalid_har)}]},
            "har",
        )
        is None
    )


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


def test_studio_report_candidate_guidance_includes_hunter_evidence_focus():
    record = SimpleNamespace(
        payload={
            "hypotheses": [
                {
                    "hypothesis_id": "H-001",
                    "vuln_type": "authorization_gap",
                    "hunter_assessment": {
                        "evidence_focus": [
                            "learned_target_relationship_review",
                            "parent_child_authorization_matrix",
                            "Authorization: Bearer secret-token",
                        ],
                    },
                }
            ]
        }
    )

    guidance = _studio_report_candidate_guidance(record, {})

    assert guidance["evidence_focus"] == [
        "learned_target_relationship_review",
        "parent_child_authorization_matrix",
    ]
    assert "secret-token" not in str(guidance)


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
                            "cve_id": "CVE-2024-12345",
                            "framework": "fastapi",
                            "similarity_score": "0.92",
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
        "Knowledge advisory: WEB-IDOR-001 (authorization_gap) from local_milvus; fastapi, CVE-2024-12345, similarity 0.92",
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
            "evidence_trace_summary": {
                "status": "traceable",
                "required_artifact_kinds": ["scope", "policy", "code", "api", "har"],
                "present_required_artifact_kinds": ["scope", "policy", "code", "api", "har"],
                "advisory_artifact_kinds": ["sarif"],
                "missing_required_artifact_kinds": [],
                "source_fact_count": 6,
                "endpoint_traced": True,
                "code_path_traced": True,
                "independent_cross_check_count": 1,
                "next_action": "Review trace summary and refutation questions before any validation.",
                "execution_allowed": True,
                "validation_allowed": True,
                "report_submission_allowed": True,
            },
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
    assert summary["evidence_trace_summary"] == {
        "status": "traceable",
        "required_artifact_kinds": ["scope", "policy", "code", "api", "har"],
        "present_required_artifact_kinds": ["scope", "policy", "code", "api", "har"],
        "advisory_artifact_kinds": ["sarif"],
        "missing_required_artifact_kinds": [],
        "source_fact_count": 6,
        "endpoint_traced": True,
        "code_path_traced": True,
        "independent_cross_check_count": 1,
        "next_action": "Review trace summary and refutation questions before any validation.",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }
    assert summary["hallucination_guard"] == {
        "status": "blocked",
        "model_output_status": "unverified_claim_not_fact",
        "high_confidence_allowed": False,
        "local_evidence_sources": [],
        "advisory_sources": [],
        "independent_cross_check_sources": [],
        "cross_validation_sources": [],
        "required_consensus": [
            "local_artifact_trace",
            "independent_static_or_fuzzing_challenge",
            "independent_refutation_review",
            "human_evidence_review",
        ],
        "blockers": [
            "no_local_evidence_source",
            "missing_endpoint_or_code_path_trace",
            "missing_independent_cross_check",
        ],
    }
    assert summary["quality_status"] == "needs_review"
    assert "hallucination_guard_needs_cross_validation" in summary["quality_reasons"]
    assert "secret-token" not in str(summary)
    assert "Authorization: Bearer" not in str(summary)


def test_studio_mission_candidate_requires_independent_cross_check_for_high_confidence():
    summary = _studio_mission_candidate_summary(
        {
            "hypothesis_id": "H-local-only",
            "vuln_type": "authorization_gap",
            "risk": "high",
            "evidence_needed": ["Confirm ownership boundary from local artifacts."],
            "false_positive_checks": ["Check whether service authorization exists."],
            "safe_validation_plan": ["Draft a non-destructive plan for human review."],
            "report_readiness": {"status": "submission_blocked"},
            "evidence_review": {"status": "needs_human_review"},
            "deduplication_review": {"status": "needs_human_review"},
            "refutation_review": {"status": "needs_human_review"},
            "validation_review": {"status": "needs_human_approval"},
            "provenance_review": {
                "status": "needs_human_review",
                "artifact_kinds": ["scope", "policy", "code", "api", "har"],
            },
            "source_facts": [
                {"fact_type": "scope_context", "artifact_kind": "scope"},
                {"fact_type": "policy_context", "artifact_kind": "policy"},
                {
                    "fact_type": "code_symbol",
                    "artifact_kind": "code",
                    "source_path": "routes.py",
                    "symbol_name": "export_file",
                },
                {
                    "fact_type": "api_surface",
                    "artifact_kind": "api",
                    "route_method": "GET",
                    "route_path": "/files/{file_id}/export",
                },
                {
                    "fact_type": "api_surface",
                    "artifact_kind": "har",
                    "route_method": "GET",
                    "route_path": "/files/123/export",
                },
                {
                    "fact_type": "knowledge_signal",
                    "artifact_kind": "knowledge",
                    "pattern_id": "WEB-IDOR-001",
                    "advisory_only": "true",
                },
            ],
        }
    )

    guard = summary["hallucination_guard"]
    assert guard["status"] == "needs_review"
    assert guard["high_confidence_allowed"] is False
    assert guard["independent_cross_check_sources"] == []
    assert guard["advisory_sources"] == ["knowledge"]
    assert "knowledge" not in guard["cross_validation_sources"]
    assert "missing_independent_cross_check" in guard["blockers"]
    assert summary["quality_status"] == "needs_review"
    assert "hallucination_guard_needs_cross_validation" in summary["quality_reasons"]


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


def test_studio_candidate_hunter_backlog_turns_quality_gaps_into_review_work():
    backlog = _studio_candidate_hunter_backlog(
        [
            {
                "hypothesis_id": "H-weak",
                "affected_endpoint": "",
                "affected_code_path": "",
                "quality_status": "needs_review",
                "quality_score": 55,
                "quality_reasons": ["evidence_needs_present"],
                "evidence_review_status": "needs_human_review",
                "evidence_need_count": 1,
                "false_positive_check_count": 0,
                "safe_validation_step_count": 0,
                "report_status": "needs_draft",
                "hallucination_guard": {"status": "blocked"},
                "evidence_gap_count": 1,
            }
        ],
        [],
    )

    work_by_gap = {item["gap"]: item for item in backlog}
    assert work_by_gap["missing_endpoint"]["candidate_id"] == "H-weak"
    assert work_by_gap["missing_code_path"]["required_evidence"] == [
        "local_code_reference",
        "handler_symbol",
    ]
    assert work_by_gap["missing_refutation_checks"]["review_focus"] == [
        "false_positive_checks",
        "independent_refutation_review",
    ]
    assert work_by_gap["missing_cross_validation_consensus"]["safety_gate"] == (
        "review_only_no_execution"
    )
    assert all(item["execution_allowed"] is False for item in backlog)
    assert all(item["validation_allowed"] is False for item in backlog)
    assert all(item["report_submission_allowed"] is False for item in backlog)
    assert "execute_live_validation" not in str(backlog)
    assert "submit_report" not in str(backlog)
    assert "run_fuzzer" not in str(backlog)


def test_studio_candidate_hunter_iteration_prioritizes_review_only_backlog():
    backlog = _studio_candidate_hunter_backlog(
        [
            {
                "hypothesis_id": "H-weak",
                "affected_endpoint": "GET /files/{file_id}/export",
                "affected_code_path": "routes.py:export_file",
                "quality_status": "needs_review",
                "quality_score": 60,
                "quality_reasons": ["endpoint_and_code_path_traced"],
                "provenance_review_status": "needs_human_review",
                "evidence_review_status": "needs_human_review",
                "evidence_need_count": 0,
                "false_positive_check_count": 0,
                "safe_validation_step_count": 0,
                "report_status": "needs_draft",
                "hallucination_guard": {"status": "needs_review"},
            }
        ],
        [],
    )
    iteration = _studio_candidate_hunter_iteration(
        backlog,
        {"top_candidate_quality_gate": "needs_review"},
    )

    assert iteration["iteration_id"] == "candidate_hunter:next_review"
    assert iteration["status"] == "needs_review"
    assert iteration["next_review_agent"] == "Evidence Planner"
    assert iteration["priority_order"][0] == "H-weak:define_evidence_needs"
    assert iteration["work_item_count"] == len(backlog)
    assert "No validation, fuzzing, or report submission is executed." in iteration[
        "success_criteria"
    ]
    assert iteration["safety_gate"] == "review_only_no_execution"
    assert iteration["completion_gate"] == "human_review_required"
    assert iteration["execution_allowed"] is False
    assert iteration["validation_allowed"] is False
    assert iteration["report_submission_allowed"] is False
    assert "execute_live_validation" not in str(iteration)
    assert "submit_report" not in str(iteration)
    assert "run_fuzzer" not in str(iteration)


def test_studio_candidate_hunter_plan_materializes_review_only_steps():
    backlog = _studio_candidate_hunter_backlog(
        [
            {
                "hypothesis_id": "H-weak",
                "affected_endpoint": "GET /files/{file_id}/export",
                "affected_code_path": "routes.py:export_file",
                "quality_status": "needs_review",
                "quality_score": 60,
                "quality_reasons": ["endpoint_and_code_path_traced"],
                "provenance_review_status": "needs_human_review",
                "evidence_review_status": "needs_human_review",
                "evidence_need_count": 0,
                "false_positive_check_count": 0,
                "safe_validation_step_count": 0,
                "report_status": "needs_draft",
                "hallucination_guard": {"status": "needs_review"},
            }
        ],
        [],
    )
    iteration = _studio_candidate_hunter_iteration(
        backlog,
        {"top_candidate_quality_gate": "needs_review"},
    )

    plan = _studio_candidate_hunter_plan(backlog, iteration)

    assert plan["plan_id"] == "candidate_hunter:autonomous_review_plan"
    assert plan["status"] == "needs_review"
    assert plan["next_review_agent"] == "Evidence Planner"
    assert plan["work_item_count"] == len(backlog)
    assert plan["step_count"] == len(backlog)
    assert plan["safety_gate"] == "review_only_no_execution"
    assert plan["completion_gate"] == "human_review_required"
    assert plan["execution_allowed"] is False
    assert plan["validation_allowed"] is False
    assert plan["report_submission_allowed"] is False
    assert plan["hallucination_governance"] == {
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
    first_step = plan["plan_steps"][0]
    assert first_step == {
        "step_id": "candidate_hunter:plan:H-weak:define_evidence_needs",
        "work_item_id": "H-weak:define_evidence_needs",
        "candidate_id": "H-weak",
        "assigned_agent": "Evidence Planner",
        "gap": "missing_evidence_needs",
        "input_refs": ["scope", "policy", "code", "api", "har"],
        "review_focus": ["evidence_needs", "human_evidence_review"],
        "required_evidence": ["sanitized_evidence_plan"],
        "next_action": "Define report-safe evidence needs for H-weak.",
        "success_criteria": [
            "H-weak:define_evidence_needs is reviewed against authorized local artifacts.",
            "Evidence refs required: sanitized_evidence_plan.",
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
                "label": "Record traceable evidence refs: sanitized_evidence_plan.",
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
                "status": "confirm_current_state",
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
    assert "executeValidation" not in str(plan)
    assert "submitReport" not in str(plan)
    assert "send_file" not in str(plan)


def test_studio_candidate_hunter_review_loop_summarizes_next_review_cycle():
    plan = {
        "plan_id": "candidate_hunter:autonomous_review_plan",
        "status": "needs_review",
        "next_review_agent": "Evidence Planner",
        "plan_steps": [
            {
                "step_id": "candidate_hunter:plan:H-weak:define_evidence_needs",
                "work_item_id": "H-weak:define_evidence_needs",
                "candidate_id": "H-weak",
                "assigned_agent": "Evidence Planner",
                "gap": "missing_evidence_needs",
                "input_refs": ["scope", "policy", "code", "api", "har"],
                "review_focus": ["evidence_needs", "human_evidence_review"],
                "required_evidence": ["sanitized_evidence_plan"],
                "next_action": "Define report-safe evidence needs for H-weak.",
                "success_criteria": [
                    "H-weak:define_evidence_needs is reviewed against authorized local artifacts.",
                    "Evidence refs required: sanitized_evidence_plan.",
                    "No validation, fuzzing, or report submission is executed.",
                ],
                "hallucination_governance_refs": [
                    "LLM output remains an unverified claim until local evidence is traced.",
                ],
                "review_checklist": [
                    {
                        "key": "evidence_requirements",
                        "label": "Record traceable evidence refs: sanitized_evidence_plan.",
                        "status": "needs_review",
                        "required": True,
                        "execution_allowed": True,
                        "validation_allowed": True,
                        "report_submission_allowed": True,
                    }
                ],
                "safety_gate": "review_only_no_execution",
                "execution_allowed": True,
                "validation_allowed": True,
                "report_submission_allowed": True,
            }
        ],
        "hallucination_governance": {
            "claim_promotion_rule": "no_verified_evidence_no_high_confidence",
            "model_output_policy": "llm_claims_start_unverified",
            "knowledge_policy": "rag_few_shot_context_only_not_cross_validation",
            "required_consensus": [
                "authorized_local_artifact_evidence",
                "human_review_decision",
            ],
            "independent_challenge_sources": ["manual_code_review"],
            "candidate_promotion_allowed": True,
        },
        "safety_gate": "unsafe_override",
        "completion_gate": "unsafe_override",
        "execution_allowed": True,
        "validation_allowed": True,
        "report_submission_allowed": True,
    }

    review_loop = _studio_candidate_hunter_review_loop(plan)

    assert review_loop == {
        "loop_id": "candidate_hunter:next_review_loop",
        "status": "needs_review",
        "source_plan_id": "candidate_hunter:autonomous_review_plan",
        "active_step_count": 1,
        "next_review_agent": "Evidence Planner",
        "review_agents": ["Evidence Planner"],
        "required_evidence": ["sanitized_evidence_plan"],
        "active_steps": [
            {
                "step_id": "candidate_hunter:plan:H-weak:define_evidence_needs",
                "work_item_id": "H-weak:define_evidence_needs",
                "candidate_id": "H-weak",
                "assigned_agent": "Evidence Planner",
                "gap": "missing_evidence_needs",
                "required_evidence": ["sanitized_evidence_plan"],
                "governance_refs": [
                    "LLM output remains an unverified claim until local evidence is traced.",
                ],
                "review_checklist": [
                    {
                        "key": "evidence_requirements",
                        "label": "Record traceable evidence refs: sanitized_evidence_plan.",
                        "status": "needs_review",
                        "required": True,
                        "execution_allowed": False,
                        "validation_allowed": False,
                        "report_submission_allowed": False,
                    }
                ],
                "next_action": "Define report-safe evidence needs for H-weak.",
                "success_criteria": [
                    "H-weak:define_evidence_needs is reviewed against authorized local artifacts.",
                    "Evidence refs required: sanitized_evidence_plan.",
                    "No validation, fuzzing, or report submission is executed.",
                ],
                "safety_gate": "review_only_no_execution",
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            }
        ],
        "governance_summary": {
            "claim_promotion_rule": "no_verified_evidence_no_high_confidence",
            "required_consensus": [
                "authorized_local_artifact_evidence",
                "human_review_decision",
            ],
            "candidate_promotion_allowed": False,
        },
        "blocked_actions": [
            "execute_live_validation",
            "run_fuzzer",
            "submit_report",
        ],
        "safety_gate": "review_only_no_execution",
        "completion_gate": "human_review_required",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }
    assert "executeValidation" not in str(review_loop)
    assert "submitReport" not in str(review_loop)
    assert "send_file" not in str(review_loop)


def test_studio_candidate_hunter_execution_loop_materializes_bounded_safe_state_machine():
    review_loop = {
        "loop_id": "candidate_hunter:next_review_loop",
        "status": "needs_review",
        "source_plan_id": "candidate_hunter:autonomous_review_plan",
        "active_step_count": 1,
        "next_review_agent": "Evidence Planner",
        "review_agents": ["Evidence Planner"],
        "required_evidence": ["non_destructive_validation_plan"],
        "active_steps": [
            {
                "step_id": "candidate_hunter:plan:H-weak:draft_validation_plan",
                "work_item_id": "H-weak:draft_validation_plan",
                "candidate_id": "H-weak",
                "assigned_agent": "Evidence Planner",
                "gap": "missing_safe_validation_plan",
                "required_evidence": ["non_destructive_validation_plan"],
                "next_action": "Draft a non-destructive validation plan for H-weak.",
                "success_criteria": [
                    "No validation, fuzzing, or report submission is executed.",
                ],
                "safety_gate": "unsafe_override",
                "execution_allowed": True,
                "validation_allowed": True,
                "report_submission_allowed": True,
            }
        ],
        "governance_summary": {
            "claim_promotion_rule": "no_verified_evidence_no_high_confidence",
            "required_consensus": ["authorized_local_artifact_evidence"],
            "candidate_promotion_allowed": True,
        },
        "blocked_actions": [
            "execute_live_validation",
            "run_fuzzer",
            "submit_report",
        ],
        "safety_gate": "unsafe_override",
        "completion_gate": "unsafe_override",
        "execution_allowed": True,
        "validation_allowed": True,
        "report_submission_allowed": True,
    }

    execution_loop = _studio_candidate_hunter_execution_loop(review_loop)

    assert execution_loop == {
        "loop_id": "candidate_hunter:bounded_execution_loop",
        "status": "needs_review",
        "iteration": 1,
        "source_review_loop_id": "candidate_hunter:next_review_loop",
        "source_plan_id": "candidate_hunter:autonomous_review_plan",
        "candidate_budget": 5,
        "top_candidate_limit": 5,
        "current_phase": "safe_validation_work",
        "phase_count": 8,
        "phases": [
            {
                "phase_id": "surface_modeling",
                "label": "Attack surface modeling",
                "status": "complete",
                "input_refs": ["scope", "policy", "api", "har"],
                "output_refs": ["affected_endpoints", "surface_facts"],
                "safety_gate": "authorized_artifacts_only",
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            },
            {
                "phase_id": "semantic_audit",
                "label": "Semantic code/API audit",
                "status": "complete",
                "input_refs": ["code", "api", "har"],
                "output_refs": ["affected_code_paths", "security_invariants"],
                "safety_gate": "local_static_analysis_only",
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            },
            {
                "phase_id": "hypothesis_generation",
                "label": "High-value hypothesis generation",
                "status": "complete",
                "input_refs": ["surface_facts", "security_invariants"],
                "output_refs": ["candidate_hypotheses"],
                "safety_gate": "model_claims_unverified",
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            },
            {
                "phase_id": "refutation",
                "label": "Refutation review",
                "status": "needs_review",
                "input_refs": ["candidate_hypotheses"],
                "output_refs": ["false_positive_questions"],
                "safety_gate": "review_only_no_execution",
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            },
            {
                "phase_id": "deduplication",
                "label": "Candidate deduplication",
                "status": "complete",
                "input_refs": ["candidate_hypotheses"],
                "output_refs": ["candidate_similarity_review"],
                "safety_gate": "review_only_no_execution",
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            },
            {
                "phase_id": "ranking",
                "label": "Top candidate ranking",
                "status": "complete",
                "input_refs": ["candidate_hypotheses", "refutation_notes"],
                "output_refs": ["top_1_to_5_candidates"],
                "safety_gate": "review_only_no_execution",
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            },
            {
                "phase_id": "safe_validation_work",
                "label": "Safe validation work planning",
                "status": "needs_review",
                "input_refs": ["top_1_to_5_candidates"],
                "output_refs": ["non_destructive_validation_plan"],
                "safety_gate": "human_approval_required",
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            },
            {
                "phase_id": "report_draft_readiness",
                "label": "Submission-blocked report draft readiness",
                "status": "pending",
                "input_refs": ["evidence_review", "safe_validation_plan"],
                "output_refs": ["submission_blocked_report_draft"],
                "safety_gate": "submission_blocked_human_review",
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            },
        ],
        "active_work_items": [
            {
                "work_item_id": "H-weak:draft_validation_plan",
                "candidate_id": "H-weak",
                "gap": "missing_safe_validation_plan",
                "assigned_agent": "Evidence Planner",
                "phase_id": "safe_validation_work",
                "required_evidence": ["non_destructive_validation_plan"],
                "next_action": "Draft a non-destructive validation plan for H-weak.",
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            }
        ],
        "candidate_evidence_summary": {
            "candidate_count": 0,
            "review_ready_count": 0,
            "review_needed_count": 0,
            "endpoint_traced_count": 0,
            "code_path_traced_count": 0,
            "local_artifact_kinds": [],
            "advisory_artifact_kinds": [],
            "average_quality_score": 0,
            "evidence_ready_candidate_ids": [],
            "review_needed_candidate_ids": [],
        },
        "candidate_evidence_matrix": [],
        "ranked_top_candidates": [],
        "next_candidate_actions": [],
        "refutation_queue": [],
        "deduplication_queue": [],
        "safe_validation_queue": [],
        "report_draft_queue": [],
        "learning_feedback_target": {
            "target_id": "candidate_hunter:learning_feedback:next_actions",
            "status": "awaiting_human_outcome",
            "source_loop_id": "candidate_hunter:bounded_execution_loop",
            "candidate_ids": [],
            "action_count": 0,
            "allowed_outcomes": [
                "confirmed",
                "refuted",
                "needs_more_evidence",
                "duplicate",
            ],
            "next_action": "Record human-reviewed outcomes for candidate hunter next actions before updating future ranking.",
            "safety_gate": "human_review_required",
            "learning_write_allowed": False,
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        },
        "learning_review_actions": [],
        "promotion_policy": {
            "candidate_promotion_allowed": False,
            "requires_local_artifact_trace": True,
            "requires_independent_refutation": True,
            "requires_human_review": True,
        },
        "blocked_actions": [
            "execute_live_validation",
            "run_fuzzer",
            "submit_report",
            "touch_real_user_data",
            "store_raw_secret",
        ],
        "safety_gate": "bounded_autonomous_review_only",
        "completion_gate": "human_review_required",
        "execution_allowed": False,
        "validation_allowed": False,
        "validation_execution_allowed": False,
        "report_submission_allowed": False,
        "candidate_promotion_allowed": False,
    }
    assert "executeValidation" not in str(execution_loop)
    assert "submitReport" not in str(execution_loop)
    assert "send_file" not in str(execution_loop)


def test_studio_candidate_hunter_execution_loop_summarizes_candidate_evidence_coverage():
    review_loop = {
        "loop_id": "candidate_hunter:next_review_loop",
        "status": "needs_review",
        "source_plan_id": "candidate_hunter:autonomous_review_plan",
        "active_steps": [],
    }
    candidates = [
        {
            "hypothesis_id": "H-ready",
            "affected_endpoint": "GET /files/{file_id}/export",
            "affected_code_path": "routes.py:export_file",
            "quality_score": 95,
            "quality_status": "review_ready",
            "provenance_artifacts": ["scope", "policy", "code", "api", "har"],
            "hallucination_guard": {
                "local_evidence_sources": ["code", "api", "har"],
                "advisory_sources": ["knowledge"],
                "independent_cross_check_sources": ["sarif"],
                "blockers": [],
            },
            "execution_allowed": True,
            "validation_allowed": True,
            "report_submission_allowed": True,
        },
        {
            "hypothesis_id": "H-weak",
            "affected_endpoint": "",
            "affected_code_path": "",
            "quality_score": 55,
            "quality_status": "needs_review",
            "provenance_artifacts": ["scope", "policy", "code"],
            "hallucination_guard": {
                "local_evidence_sources": ["code"],
                "advisory_sources": [],
                "independent_cross_check_sources": [],
                "blockers": [
                    "missing_endpoint_or_code_path_trace",
                    "missing_independent_cross_check",
                ],
            },
            "execution_allowed": True,
            "validation_allowed": True,
            "report_submission_allowed": True,
        },
    ]

    execution_loop = _studio_candidate_hunter_execution_loop(review_loop, candidates)

    assert execution_loop["candidate_evidence_summary"] == {
        "candidate_count": 2,
        "review_ready_count": 1,
        "review_needed_count": 1,
        "endpoint_traced_count": 1,
        "code_path_traced_count": 1,
        "local_artifact_kinds": ["scope", "policy", "code", "api", "har"],
        "advisory_artifact_kinds": ["knowledge", "sarif"],
        "average_quality_score": 75,
        "evidence_ready_candidate_ids": ["H-ready"],
        "review_needed_candidate_ids": ["H-weak"],
    }
    assert execution_loop["candidate_evidence_matrix"] == [
        {
            "candidate_id": "H-ready",
            "affected_endpoint": "GET /files/{file_id}/export",
            "affected_code_path": "routes.py:export_file",
            "quality_score": 95,
            "quality_status": "review_ready",
            "local_evidence_sources": ["code", "api", "har"],
            "advisory_sources": ["knowledge"],
            "independent_cross_check_sources": ["sarif"],
            "missing_evidence": [],
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        },
        {
            "candidate_id": "H-weak",
            "affected_endpoint": "",
            "affected_code_path": "",
            "quality_score": 55,
            "quality_status": "needs_review",
            "local_evidence_sources": ["code"],
            "advisory_sources": [],
            "independent_cross_check_sources": [],
            "missing_evidence": [
                "affected_endpoint",
                "affected_code_path",
                "independent_cross_check",
            ],
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        },
    ]
    assert execution_loop["next_candidate_actions"] == [
        {
            "candidate_id": "H-ready",
            "phase_id": "report_draft_readiness",
            "priority_score": 95,
            "reason": "candidate_evidence_ready",
            "required_evidence": ["submission_blocked_report_draft"],
            "next_action": "Prepare submission-blocked report readiness review for H-ready.",
            "safety_gate": "submission_blocked_human_review",
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        },
        {
            "candidate_id": "H-weak",
            "phase_id": "surface_modeling",
            "priority_score": 25,
            "reason": "missing_affected_endpoint",
            "required_evidence": ["affected_endpoint", "api_har_route_trace"],
            "next_action": "Trace affected endpoint evidence for H-weak from authorized API/HAR artifacts.",
            "safety_gate": "authorized_artifacts_only",
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        },
    ]
    assert execution_loop["learning_feedback_target"] == {
        "target_id": "candidate_hunter:learning_feedback:next_actions",
        "status": "awaiting_human_outcome",
        "source_loop_id": "candidate_hunter:bounded_execution_loop",
        "candidate_ids": ["H-ready", "H-weak"],
        "action_count": 2,
        "allowed_outcomes": [
            "confirmed",
            "refuted",
            "needs_more_evidence",
            "duplicate",
        ],
        "next_action": "Record human-reviewed outcomes for candidate hunter next actions before updating future ranking.",
        "safety_gate": "human_review_required",
        "learning_write_allowed": False,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }
    assert execution_loop["learning_review_actions"] == [
        {
            "action_id": "candidate_hunter:learning_feedback:next_actions:H-ready",
            "candidate_id": "H-ready",
            "source_loop_id": "candidate_hunter:bounded_execution_loop",
            "suggested_outcome": "confirmed",
            "evidence_ready": True,
            "trace_status": "needs_evidence",
            "missing_evidence": [],
            "missing_required_artifact_kinds": [],
            "allowed_outcomes": [
                "confirmed",
                "refuted",
                "needs_more_evidence",
                "duplicate",
            ],
            "next_action": "Review H-ready and record a human outcome before updating future ranking.",
            "safety_gate": "human_review_required",
            "learning_write_allowed": False,
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        },
        {
            "action_id": "candidate_hunter:learning_feedback:next_actions:H-weak",
            "candidate_id": "H-weak",
            "source_loop_id": "candidate_hunter:bounded_execution_loop",
            "suggested_outcome": "needs_more_evidence",
            "evidence_ready": False,
            "trace_status": "needs_evidence",
            "missing_evidence": [
                "affected_endpoint",
                "affected_code_path",
                "independent_cross_check",
            ],
            "missing_required_artifact_kinds": [],
            "allowed_outcomes": [
                "confirmed",
                "refuted",
                "needs_more_evidence",
                "duplicate",
            ],
            "next_action": "Review H-weak and record a human outcome before updating future ranking.",
            "safety_gate": "human_review_required",
            "learning_write_allowed": False,
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        },
    ]
    assert execution_loop["candidate_evidence_matrix"][0]["execution_allowed"] is False
    assert "Authorization: Bearer" not in str(execution_loop)


def test_studio_candidate_hunter_learning_actions_include_hunter_lesson_template():
    candidates = [
        {
            "hypothesis_id": "codebase_fact_hypothesis_1",
            "affected_endpoint": "GET /files/{file_id}/export",
            "affected_code_path": "routes.py:export_file",
            "quality_score": 90,
            "quality_status": "review_ready",
            "duplicate_risk_score": 10,
            "hunter_assessment": {
                "playbook_id": "bola_idor",
                "hunter_priority_score": 76,
            },
            "hallucination_guard": {
                "local_evidence_sources": ["scope", "policy", "code", "api", "har"],
                "independent_cross_check_sources": ["sarif"],
            },
            "evidence_trace_summary": {
                "status": "traceable",
                "missing_required_artifact_kinds": [],
                "endpoint_traced": True,
                "code_path_traced": True,
                "independent_cross_check_count": 1,
            },
        }
    ]

    execution_loop = _studio_candidate_hunter_execution_loop({}, candidates)

    assert execution_loop["learning_review_actions"] == [
        {
            "action_id": "candidate_hunter:learning_feedback:next_actions:codebase_fact_hypothesis_1",
            "candidate_id": "codebase_fact_hypothesis_1",
            "source_loop_id": "candidate_hunter:bounded_execution_loop",
            "suggested_outcome": "confirmed",
            "evidence_ready": True,
            "trace_status": "traceable",
            "missing_evidence": [],
            "missing_required_artifact_kinds": [],
            "allowed_outcomes": [
                "confirmed",
                "refuted",
                "needs_more_evidence",
                "duplicate",
            ],
            "learning_signal_template": {
                "playbook_id": "bola_idor",
                "surface_key": "file_id:export",
                "target_relationships": [
                    "candidate:codebase_fact_hypothesis_1",
                    "candidate_hunter:bounded_execution_loop",
                ],
                "human_review_required": True,
                "learning_write_allowed": False,
            },
            "next_action": "Review codebase_fact_hypothesis_1 and record a human outcome before updating future ranking.",
            "safety_gate": "human_review_required",
            "learning_write_allowed": False,
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        }
    ]


def test_studio_candidate_hunter_execution_loop_ranks_traceable_ab_candidate_first():
    candidates = [
        {
            "hypothesis_id": "H-high-raw",
            "affected_endpoint": "GET /exports/{export_id}",
            "affected_code_path": "routes.py:export",
            "quality_score": 99,
            "quality_status": "review_ready",
            "hallucination_guard": {
                "local_evidence_sources": ["code", "api", "har"],
                "independent_cross_check_sources": ["sarif"],
            },
            "evidence_trace_summary": {
                "status": "needs_evidence",
                "missing_required_artifact_kinds": ["scope", "policy"],
                "endpoint_traced": True,
                "code_path_traced": True,
                "independent_cross_check_count": 1,
            },
        },
        {
            "hypothesis_id": "H-traceable",
            "affected_endpoint": "GET /files/{file_id}/export",
            "affected_code_path": "routes.py:export_file",
            "quality_score": 84,
            "quality_status": "review_ready",
            "hallucination_guard": {
                "local_evidence_sources": ["scope", "policy", "code", "api", "har"],
                "independent_cross_check_sources": ["sarif"],
            },
            "evidence_trace_summary": {
                "status": "traceable",
                "missing_required_artifact_kinds": [],
                "endpoint_traced": True,
                "code_path_traced": True,
                "independent_cross_check_count": 1,
            },
        },
    ]

    execution_loop = _studio_candidate_hunter_execution_loop({}, candidates)

    assert [
        item["candidate_id"] for item in execution_loop["next_candidate_actions"]
    ] == ["H-traceable", "H-high-raw"]
    assert execution_loop["candidate_evidence_matrix"][0][
        "missing_required_artifact_kinds"
    ] == ["scope", "policy"]
    assert execution_loop["candidate_evidence_matrix"][1]["evidence_trace_status"] == (
        "traceable"
    )
    assert execution_loop["next_candidate_actions"][0]["priority_score"] > (
        execution_loop["next_candidate_actions"][1]["priority_score"]
    )
    assert execution_loop["next_candidate_actions"][0]["execution_allowed"] is False
    assert execution_loop["next_candidate_actions"][0]["validation_allowed"] is False
    assert (
        execution_loop["next_candidate_actions"][0]["report_submission_allowed"]
        is False
    )


def test_studio_candidate_hunter_execution_loop_prioritizes_hunter_assessment_signal():
    candidates = [
        {
            "hypothesis_id": "H-generic-quality",
            "affected_endpoint": "GET /exports/{export_id}",
            "affected_code_path": "routes.py:export",
            "quality_score": 95,
            "quality_status": "review_ready",
            "duplicate_risk_score": 10,
            "report_status": "submission_blocked",
            "safe_validation_plan": ["Use local authorized fixtures only."],
            "hunter_assessment": {
                "hunter_priority_score": 60,
                "impact_score": 70,
                "rejection_risk_score": 35,
                "policy_risk_score": 20,
            },
            "hallucination_guard": {
                "local_evidence_sources": ["scope", "policy", "code", "api", "har"],
                "independent_cross_check_sources": ["sarif"],
            },
            "evidence_trace_summary": {
                "status": "traceable",
                "missing_required_artifact_kinds": [],
                "endpoint_traced": True,
                "code_path_traced": True,
                "independent_cross_check_count": 1,
            },
        },
        {
            "hypothesis_id": "H-hunter-high-signal",
            "affected_endpoint": "POST /teams/{team_id}/invites",
            "affected_code_path": "teams.py:create_invite",
            "quality_score": 72,
            "quality_status": "review_ready",
            "duplicate_risk_score": 10,
            "report_status": "submission_blocked",
            "safe_validation_plan": ["Use local authorized fixtures only."],
            "hunter_assessment": {
                "hunter_priority_score": 96,
                "impact_score": 92,
                "rejection_risk_score": 15,
                "policy_risk_score": 20,
            },
            "hallucination_guard": {
                "local_evidence_sources": ["scope", "policy", "code", "api", "har"],
                "independent_cross_check_sources": ["sarif"],
            },
            "evidence_trace_summary": {
                "status": "traceable",
                "missing_required_artifact_kinds": [],
                "endpoint_traced": True,
                "code_path_traced": True,
                "independent_cross_check_count": 1,
            },
        },
    ]

    execution_loop = _studio_candidate_hunter_execution_loop({}, candidates)

    assert [
        item["candidate_id"] for item in execution_loop["next_candidate_actions"]
    ] == ["H-hunter-high-signal", "H-generic-quality"]
    assert execution_loop["candidate_evidence_matrix"][1]["hunter_priority_score"] == 96
    assert execution_loop["candidate_evidence_matrix"][1]["impact_score"] == 92
    assert execution_loop["candidate_evidence_matrix"][1]["rejection_risk_score"] == 15
    assert execution_loop["candidate_evidence_matrix"][1][
        "ranking_signal_breakdown"
    ] == [
        "quality_score:72",
        "hunter_priority_floor:96",
        "traceable_evidence_bonus:+20",
        "independent_cross_check_bonus:+5",
        "final_priority_score:121",
    ]
    assert execution_loop["next_candidate_actions"][0]["priority_score"] == 121
    assert execution_loop["ranked_top_candidates"] == [
        {
            "rank": 1,
            "candidate_id": "H-hunter-high-signal",
            "phase_id": "report_draft_readiness",
            "priority_score": 121,
            "reason": "candidate_evidence_ready",
            "required_evidence": ["submission_blocked_report_draft"],
            "next_action": "Prepare submission-blocked report readiness review for H-hunter-high-signal.",
            "affected_endpoint": "POST /teams/{team_id}/invites",
            "affected_code_path": "teams.py:create_invite",
            "quality_status": "review_ready",
            "evidence_ready": True,
            "trace_status": "traceable",
            "missing_evidence": [],
            "missing_required_artifact_kinds": [],
            "ranking_signal_breakdown": [
                "quality_score:72",
                "hunter_priority_floor:96",
                "traceable_evidence_bonus:+20",
                "independent_cross_check_bonus:+5",
                "final_priority_score:121",
            ],
            "safety_gate": "submission_blocked_human_review",
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        },
        {
            "rank": 2,
            "candidate_id": "H-generic-quality",
            "phase_id": "report_draft_readiness",
            "priority_score": 120,
            "reason": "candidate_evidence_ready",
            "required_evidence": ["submission_blocked_report_draft"],
            "next_action": "Prepare submission-blocked report readiness review for H-generic-quality.",
            "affected_endpoint": "GET /exports/{export_id}",
            "affected_code_path": "routes.py:export",
            "quality_status": "review_ready",
            "evidence_ready": True,
            "trace_status": "traceable",
            "missing_evidence": [],
            "missing_required_artifact_kinds": [],
            "ranking_signal_breakdown": [
                "quality_score:95",
                "hunter_priority_floor:60",
                "traceable_evidence_bonus:+20",
                "independent_cross_check_bonus:+5",
                "final_priority_score:120",
            ],
            "safety_gate": "submission_blocked_human_review",
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        },
    ]
    assert execution_loop["safe_validation_queue"][0]["candidate_id"] == (
        "H-hunter-high-signal"
    )
    assert execution_loop["report_draft_queue"][0]["candidate_id"] == (
        "H-hunter-high-signal"
    )
    assert execution_loop["next_candidate_actions"][0]["execution_allowed"] is False
    assert execution_loop["safe_validation_queue"][0]["validation_execution_allowed"] is False
    assert execution_loop["report_draft_queue"][0]["report_submission_allowed"] is False


def test_studio_candidate_hunter_execution_loop_uses_learning_evidence_needed_reasons():
    candidates = [
        {
            "hypothesis_id": "H-learned-gap",
            "affected_endpoint": "GET /files/{file_id}/export",
            "affected_code_path": "routes.py:export_file",
            "quality_score": 90,
            "quality_status": "review_ready",
            "duplicate_risk_score": 10,
            "report_status": "submission_blocked",
            "safe_validation_plan": ["Use local authorized fixtures only."],
            "hunter_assessment": {
                "playbook_id": "bola_idor",
                "hunter_priority_score": 88,
                "impact_score": 90,
                "rejection_risk_score": 15,
                "policy_risk_score": 20,
                "reasons": [
                    "lesson:evidence_needed:candidate_gap",
                    "lesson:evidence_needed:missing_evidence:independent_cross_check",
                    "lesson:evidence_needed:missing_required_artifact:policy",
                ],
            },
            "hallucination_guard": {
                "local_evidence_sources": ["scope", "policy", "code", "api", "har"],
                "independent_cross_check_sources": ["sarif"],
            },
            "evidence_trace_summary": {
                "status": "traceable",
                "missing_required_artifact_kinds": [],
                "endpoint_traced": True,
                "code_path_traced": True,
                "independent_cross_check_count": 1,
            },
        }
    ]

    execution_loop = _studio_candidate_hunter_execution_loop({}, candidates)

    assert execution_loop["candidate_evidence_matrix"][0]["missing_evidence"] == [
        "learned_independent_cross_check"
    ]
    assert execution_loop["candidate_evidence_matrix"][0][
        "missing_required_artifact_kinds"
    ] == ["policy"]
    assert execution_loop["candidate_evidence_matrix"][0][
        "learning_evidence_needed_reasons"
    ] == [
        "lesson:evidence_needed:candidate_gap",
        "lesson:evidence_needed:missing_evidence:independent_cross_check",
        "lesson:evidence_needed:missing_required_artifact:policy",
    ]
    assert execution_loop["next_candidate_actions"][0] == {
        "candidate_id": "H-learned-gap",
        "phase_id": "surface_modeling",
        "priority_score": 90,
        "reason": "missing_ab_artifacts",
        "required_evidence": ["policy"],
        "next_action": (
            "Attach required A+B artifacts for H-learned-gap before report readiness."
        ),
        "safety_gate": "authorized_artifacts_only",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }
    assert execution_loop["ranked_top_candidates"][0]["evidence_ready"] is False
    assert "learned_independent_cross_check" in execution_loop["ranked_top_candidates"][
        0
    ]["missing_evidence"]


def test_studio_candidate_hunter_execution_loop_routes_missing_ab_artifacts_before_report_readiness():
    candidates = [
        {
            "hypothesis_id": "H-missing-ab",
            "affected_endpoint": "GET /files/{file_id}/export",
            "affected_code_path": "routes.py:export_file",
            "quality_score": 95,
            "quality_status": "review_ready",
            "hallucination_guard": {
                "local_evidence_sources": ["code", "api", "har"],
                "independent_cross_check_sources": ["sarif"],
            },
            "evidence_trace_summary": {
                "status": "needs_evidence",
                "missing_required_artifact_kinds": ["scope", "policy"],
                "endpoint_traced": True,
                "code_path_traced": True,
                "independent_cross_check_count": 1,
            },
        }
    ]

    execution_loop = _studio_candidate_hunter_execution_loop({}, candidates)

    assert execution_loop["candidate_evidence_summary"]["evidence_ready_candidate_ids"] == []
    assert execution_loop["candidate_evidence_summary"]["review_needed_candidate_ids"] == [
        "H-missing-ab"
    ]
    assert execution_loop["next_candidate_actions"] == [
        {
            "candidate_id": "H-missing-ab",
            "phase_id": "surface_modeling",
            "priority_score": 70,
            "reason": "missing_ab_artifacts",
            "required_evidence": ["scope", "policy"],
            "next_action": "Attach required A+B artifacts for H-missing-ab before report readiness.",
            "safety_gate": "authorized_artifacts_only",
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        }
    ]
    assert execution_loop["ranked_top_candidates"][0]["missing_required_artifact_kinds"] == [
        "scope",
        "policy",
    ]
    assert execution_loop["safe_validation_queue"] == []
    assert execution_loop["report_draft_queue"] == []


def test_studio_candidate_hunter_execution_loop_builds_refutation_queue_from_trace_gaps():
    candidates = [
        {
            "hypothesis_id": "H-needs-cross-check",
            "affected_endpoint": "GET /files/{file_id}/export",
            "affected_code_path": "routes.py:export_file",
            "quality_score": 88,
            "quality_status": "needs_review",
            "hallucination_guard": {
                "local_evidence_sources": ["scope", "policy", "code", "api", "har"],
                "independent_cross_check_sources": [],
            },
            "evidence_trace_summary": {
                "status": "traceable",
                "missing_required_artifact_kinds": [],
                "endpoint_traced": True,
                "code_path_traced": True,
                "independent_cross_check_count": 0,
            },
        },
        {
            "hypothesis_id": "H-missing-policy",
            "affected_endpoint": "POST /webhooks/test",
            "affected_code_path": "webhooks.py:test_webhook",
            "quality_score": 80,
            "quality_status": "needs_review",
            "hallucination_guard": {
                "local_evidence_sources": ["code", "api", "har"],
                "independent_cross_check_sources": ["sarif"],
            },
            "evidence_trace_summary": {
                "status": "needs_evidence",
                "missing_required_artifact_kinds": ["scope", "policy"],
                "endpoint_traced": True,
                "code_path_traced": True,
                "independent_cross_check_count": 1,
            },
        },
    ]

    execution_loop = _studio_candidate_hunter_execution_loop({}, candidates)

    assert execution_loop["refutation_queue"] == [
        {
            "queue_id": "candidate_hunter:refutation:H-needs-cross-check",
            "candidate_id": "H-needs-cross-check",
            "priority_score": 78,
            "trace_status": "traceable",
            "missing_evidence": ["independent_cross_check"],
            "missing_required_artifact_kinds": [],
            "questions": [
                "Can an independent static rule, SARIF finding, fuzzing plan, or local fixture challenge this candidate without live execution?",
                "Does a local two-account or role-fixture review refute the suspected impact?",
            ],
            "required_evidence": ["independent_refutation_or_static_rule"],
            "next_action": "Refute H-needs-cross-check using independent local evidence before report readiness.",
            "safety_gate": "review_only_no_execution",
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        },
        {
            "queue_id": "candidate_hunter:refutation:H-missing-policy",
            "candidate_id": "H-missing-policy",
            "priority_score": 60,
            "trace_status": "needs_evidence",
            "missing_evidence": [],
            "missing_required_artifact_kinds": ["scope", "policy"],
            "questions": [
                "Which required A+B artifacts are still missing from the candidate evidence trace?",
                "Can the candidate be downgraded until scope, policy, code, API, and HAR provenance are all present?",
            ],
            "required_evidence": ["scope", "policy"],
            "next_action": "Refute H-missing-policy using independent local evidence before report readiness.",
            "safety_gate": "review_only_no_execution",
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        },
    ]
    assert "execute_live_validation" not in str(execution_loop["refutation_queue"])


def test_studio_candidate_hunter_execution_loop_routes_semantic_gaps_before_report_draft():
    candidates = [
        {
            "hypothesis_id": "H-semantic-gap",
            "affected_endpoint": "GET /files/{file_id}/export",
            "affected_code_path": "routes.py:export_file",
            "quality_score": 92,
            "quality_status": "review_ready",
            "duplicate_risk_score": 10,
            "report_status": "submission_blocked",
            "safe_validation_plan": ["Use local authorized fixtures only."],
            "evidence_gaps": [
                {"artifact_kind": "semantic", "reason": "missing_root_cause"},
                {"artifact_kind": "semantic", "reason": "missing_security_invariant"},
                {"artifact_kind": "semantic", "reason": "missing_sink_symbols"},
            ],
            "hallucination_guard": {
                "local_evidence_sources": ["scope", "policy", "code", "api", "har"],
                "independent_cross_check_sources": ["sarif"],
            },
            "evidence_trace_summary": {
                "status": "traceable",
                "missing_required_artifact_kinds": [],
                "endpoint_traced": True,
                "code_path_traced": True,
                "independent_cross_check_count": 1,
            },
        }
    ]

    execution_loop = _studio_candidate_hunter_execution_loop({}, candidates)

    assert execution_loop["candidate_evidence_summary"]["review_ready_count"] == 0
    assert execution_loop["candidate_evidence_summary"]["review_needed_count"] == 1
    assert execution_loop["candidate_evidence_summary"]["evidence_ready_candidate_ids"] == []
    assert execution_loop["candidate_evidence_summary"]["review_needed_candidate_ids"] == [
        "H-semantic-gap"
    ]
    assert execution_loop["candidate_evidence_matrix"][0]["missing_evidence"] == [
        "semantic_evidence"
    ]
    assert execution_loop["next_candidate_actions"] == [
        {
            "candidate_id": "H-semantic-gap",
            "phase_id": "semantic_audit",
            "priority_score": 107,
            "reason": "missing_semantic_evidence",
            "required_evidence": [
                "root_cause",
                "security_invariant",
                "sink_symbols",
            ],
            "next_action": "Complete semantic root cause, invariant, and sink-symbol review for H-semantic-gap from authorized local code.",
            "safety_gate": "local_static_analysis_only",
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        }
    ]
    assert execution_loop["refutation_queue"][0]["candidate_id"] == "H-semantic-gap"
    assert execution_loop["refutation_queue"][0]["required_evidence"] == [
        "root_cause",
        "security_invariant",
        "sink_symbols",
    ]
    assert execution_loop["safe_validation_queue"] == []
    assert execution_loop["report_draft_queue"] == []
    assert "submit_report" in execution_loop["blocked_actions"]
    assert execution_loop["report_submission_allowed"] is False


def test_studio_candidate_hunter_execution_loop_routes_summarized_semantic_gap_labels():
    candidates = [
        {
            "hypothesis_id": "H-summary-semantic-gap",
            "affected_endpoint": "GET /files/{file_id}/export",
            "affected_code_path": "routes.py:export_file",
            "quality_score": 88,
            "quality_status": "review_ready",
            "evidence_gaps": [
                "semantic: missing_root_cause",
                "semantic: missing_security_invariant",
                "semantic: missing_sink_symbols",
            ],
            "hallucination_guard": {
                "local_evidence_sources": ["scope", "policy", "code", "api", "har"],
                "independent_cross_check_sources": ["sarif"],
            },
            "evidence_trace_summary": {
                "status": "traceable",
                "missing_required_artifact_kinds": [],
                "endpoint_traced": True,
                "code_path_traced": True,
                "independent_cross_check_count": 1,
            },
        }
    ]

    execution_loop = _studio_candidate_hunter_execution_loop({}, candidates)

    assert execution_loop["candidate_evidence_matrix"][0]["missing_evidence"] == [
        "semantic_evidence"
    ]
    assert execution_loop["next_candidate_actions"][0]["reason"] == (
        "missing_semantic_evidence"
    )
    assert execution_loop["next_candidate_actions"][0]["required_evidence"] == [
        "root_cause",
        "security_invariant",
        "sink_symbols",
    ]
    assert execution_loop["candidate_evidence_summary"]["evidence_ready_candidate_ids"] == []
    assert execution_loop["candidate_evidence_summary"]["review_needed_candidate_ids"] == [
        "H-summary-semantic-gap"
    ]


def test_studio_candidate_hunter_execution_loop_builds_deduplication_queue_from_duplicate_risk():
    candidates = [
        {
            "hypothesis_id": "H-duplicate-risk",
            "affected_endpoint": "GET /files/{file_id}/export",
            "affected_code_path": "routes.py:export_file",
            "quality_score": 86,
            "quality_status": "review_ready",
            "duplicate_risk_score": 72,
            "deduplication_review": {
                "status": "needs_human_review",
                "duplicate_risk_score": 72,
            },
            "hallucination_guard": {
                "local_evidence_sources": ["scope", "policy", "code", "api", "har"],
                "independent_cross_check_sources": ["sarif"],
            },
        },
        {
            "hypothesis_id": "H-novel",
            "affected_endpoint": "POST /webhooks/test",
            "affected_code_path": "webhooks.py:test_webhook",
            "quality_score": 80,
            "quality_status": "review_ready",
            "duplicate_risk_score": 20,
            "deduplication_review": {
                "status": "needs_human_review",
                "duplicate_risk_score": 20,
            },
            "hallucination_guard": {
                "local_evidence_sources": ["scope", "policy", "code", "api", "har"],
                "independent_cross_check_sources": ["sarif"],
            },
        },
    ]

    execution_loop = _studio_candidate_hunter_execution_loop({}, candidates)

    assert execution_loop["candidate_evidence_summary"]["evidence_ready_candidate_ids"] == [
        "H-novel"
    ]
    assert execution_loop["candidate_evidence_summary"]["review_needed_candidate_ids"] == [
        "H-duplicate-risk"
    ]
    assert execution_loop["deduplication_queue"] == [
        {
            "queue_id": "candidate_hunter:deduplication:H-duplicate-risk",
            "candidate_id": "H-duplicate-risk",
            "priority_score": 72,
            "duplicate_risk_score": 72,
            "affected_endpoint": "GET /files/{file_id}/export",
            "affected_code_path": "routes.py:export_file",
            "similarity_keys": [
                "endpoint:GET /files/{file_id}/export",
                "code_path:routes.py:export_file",
            ],
            "questions": [
                "Does this candidate overlap an existing report, prior candidate, scanner finding, or known program pattern?",
                "Is the affected endpoint, code path, invariant, and impact distinct enough to keep this candidate in the Top 1-5?",
            ],
            "required_evidence": [
                "prior_submission_search",
                "endpoint_code_path_similarity_review",
            ],
            "next_action": "Deduplicate H-duplicate-risk against prior candidates before promotion or report readiness.",
            "safety_gate": "review_only_no_execution",
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        }
    ]
    assert "H-novel" not in str(execution_loop["deduplication_queue"])
    assert "submit_report" not in str(execution_loop["deduplication_queue"])
    duplicate_action = next(
        action
        for action in execution_loop["next_candidate_actions"]
        if action["candidate_id"] == "H-duplicate-risk"
    )
    assert duplicate_action == {
        "candidate_id": "H-duplicate-risk",
        "phase_id": "deduplication",
        "priority_score": 86,
        "reason": "duplicate_risk_needs_review",
        "required_evidence": [
            "prior_submission_search",
            "endpoint_code_path_similarity_review",
        ],
        "next_action": "Deduplicate H-duplicate-risk against prior candidates before report readiness.",
        "safety_gate": "review_only_no_execution",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }
    duplicate_learning_action = next(
        action
        for action in execution_loop["learning_review_actions"]
        if action["candidate_id"] == "H-duplicate-risk"
    )
    assert duplicate_learning_action["suggested_outcome"] == "duplicate"


def test_studio_candidate_hunter_execution_loop_builds_safe_validation_queue_for_ready_candidates():
    candidates = [
        {
            "hypothesis_id": "H-ready",
            "affected_endpoint": "GET /files/{file_id}/export",
            "affected_code_path": "routes.py:export_file",
            "quality_score": 90,
            "quality_status": "review_ready",
            "duplicate_risk_score": 10,
            "safe_validation_plan": [
                "Use only local authorized test accounts.",
                "Confirm cross-object access is denied without touching real user data.",
            ],
            "hallucination_guard": {
                "local_evidence_sources": ["scope", "policy", "code", "api", "har"],
                "independent_cross_check_sources": ["sarif"],
            },
            "evidence_trace_summary": {
                "status": "traceable",
                "missing_required_artifact_kinds": [],
                "endpoint_traced": True,
                "code_path_traced": True,
                "independent_cross_check_count": 1,
            },
        },
        {
            "hypothesis_id": "H-needs-refutation",
            "affected_endpoint": "POST /webhooks/test",
            "affected_code_path": "webhooks.py:test_webhook",
            "quality_score": 91,
            "quality_status": "review_ready",
            "duplicate_risk_score": 10,
            "safe_validation_plan": ["Prepare a local review only."],
            "hallucination_guard": {
                "local_evidence_sources": ["scope", "policy", "code", "api", "har"],
                "independent_cross_check_sources": [],
            },
        },
    ]

    execution_loop = _studio_candidate_hunter_execution_loop({}, candidates)

    assert execution_loop["safe_validation_queue"] == [
        {
            "queue_id": "candidate_hunter:safe_validation:H-ready",
            "candidate_id": "H-ready",
            "priority_score": 115,
            "affected_endpoint": "GET /files/{file_id}/export",
            "affected_code_path": "routes.py:export_file",
            "validation_mode": "human_approved_non_destructive_plan",
            "plan_steps": [
                "Use only local authorized test accounts.",
            ],
            "required_approvals": [
                "scope_guard_route_approval",
                "human_validation_approval",
                "redaction_review",
            ],
            "next_action": "Review and approve the non-destructive validation plan for H-ready; execution remains blocked.",
            "safety_gate": "human_approval_required",
            "execution_allowed": False,
            "validation_allowed": False,
            "validation_execution_allowed": False,
            "report_submission_allowed": False,
        }
    ]
    assert "H-needs-refutation" not in str(execution_loop["safe_validation_queue"])
    assert "execute_live_validation" not in str(execution_loop["safe_validation_queue"])


def test_studio_candidate_hunter_execution_loop_keeps_ready_candidate_in_top_budget():
    candidates = [
        {
            "hypothesis_id": f"H-missing-ab-{index}",
            "affected_endpoint": f"GET /raw/{index}",
            "affected_code_path": f"routes.py:raw_{index}",
            "quality_score": 99 - index,
            "quality_status": "review_ready",
            "duplicate_risk_score": 10,
            "safe_validation_plan": ["Prepare a local review only."],
            "report_status": "submission_blocked",
            "hallucination_guard": {
                "local_evidence_sources": ["code", "api", "har"],
                "independent_cross_check_sources": ["sarif"],
            },
            "evidence_trace_summary": {
                "status": "needs_evidence",
                "missing_required_artifact_kinds": ["scope", "policy"],
                "endpoint_traced": True,
                "code_path_traced": True,
                "independent_cross_check_count": 1,
            },
        }
        for index in range(5)
    ]
    candidates.append(
        {
            "hypothesis_id": "H-ready-sixth",
            "affected_endpoint": "GET /files/{file_id}/export",
            "affected_code_path": "routes.py:export_file",
            "quality_score": 90,
            "quality_status": "review_ready",
            "duplicate_risk_score": 10,
            "safe_validation_plan": ["Use only local authorized test accounts."],
            "report_status": "submission_blocked",
            "hallucination_guard": {
                "local_evidence_sources": ["scope", "policy", "code", "api", "har"],
                "independent_cross_check_sources": ["sarif"],
            },
            "evidence_trace_summary": {
                "status": "traceable",
                "missing_required_artifact_kinds": [],
                "endpoint_traced": True,
                "code_path_traced": True,
                "independent_cross_check_count": 1,
            },
        }
    )

    execution_loop = _studio_candidate_hunter_execution_loop({}, candidates)

    assert "H-ready-sixth" in [
        item["candidate_id"] for item in execution_loop["candidate_evidence_matrix"]
    ]
    assert execution_loop["safe_validation_queue"][0]["candidate_id"] == "H-ready-sixth"
    assert execution_loop["report_draft_queue"][0]["candidate_id"] == "H-ready-sixth"
    assert execution_loop["safe_validation_queue"][0]["execution_allowed"] is False
    assert execution_loop["report_draft_queue"][0]["report_submission_allowed"] is False


def test_studio_candidate_hunter_execution_loop_builds_submission_blocked_report_draft_queue():
    candidates = [
        {
            "hypothesis_id": "H-ready",
            "affected_endpoint": "GET /files/{file_id}/export",
            "affected_code_path": "routes.py:export_file",
            "quality_score": 90,
            "quality_status": "review_ready",
            "duplicate_risk_score": 10,
            "report_status": "submission_blocked",
            "safe_validation_plan": ["Use only local authorized test accounts."],
            "hunter_assessment": {
                "evidence_focus": [
                    "learned_target_relationship_review",
                    "parent_child_authorization_matrix",
                    "Authorization: Bearer secret-token",
                ],
            },
            "hallucination_guard": {
                "local_evidence_sources": ["scope", "policy", "code", "api", "har"],
                "independent_cross_check_sources": ["sarif"],
            },
            "evidence_trace_summary": {
                "status": "traceable",
                "missing_required_artifact_kinds": [],
                "endpoint_traced": True,
                "code_path_traced": True,
                "independent_cross_check_count": 1,
            },
        },
        {
            "hypothesis_id": "H-needs-refutation",
            "affected_endpoint": "POST /webhooks/test",
            "affected_code_path": "webhooks.py:test_webhook",
            "quality_score": 91,
            "quality_status": "review_ready",
            "duplicate_risk_score": 10,
            "report_status": "submission_blocked",
            "safe_validation_plan": ["Prepare a local review only."],
            "hallucination_guard": {
                "local_evidence_sources": ["scope", "policy", "code", "api", "har"],
                "independent_cross_check_sources": [],
            },
        },
    ]

    execution_loop = _studio_candidate_hunter_execution_loop({}, candidates)

    assert execution_loop["report_draft_queue"] == [
        {
            "queue_id": "candidate_hunter:report_draft:H-ready",
            "candidate_id": "H-ready",
            "priority_score": 115,
            "report_status": "submission_blocked",
            "affected_endpoint": "GET /files/{file_id}/export",
            "affected_code_path": "routes.py:export_file",
            "required_sections": [
                "impact_summary",
                "affected_endpoint_and_code_path",
                "evidence_trace",
                "safe_validation_plan",
                "redaction_review",
            ],
            "evidence_focus": [
                "learned_target_relationship_review",
                "parent_child_authorization_matrix",
            ],
            "redaction_checks": [
                "Remove raw secrets, cookies, tokens, credentials, and authorization headers.",
                "Use only normalized endpoint, code path, and evidence summaries.",
            ],
            "next_action": "Draft a submission-blocked report for H-ready and keep submission disabled pending human review.",
            "safety_gate": "submission_blocked_human_review",
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        }
    ]
    assert "H-needs-refutation" not in str(execution_loop["report_draft_queue"])
    assert "submit_report" not in str(execution_loop["report_draft_queue"])
    assert "secret-token" not in str(execution_loop["report_draft_queue"])


def test_studio_candidate_hunter_execution_loop_uses_next_candidate_action_as_current_phase():
    execution_loop = _studio_candidate_hunter_execution_loop(
        {
            "loop_id": "candidate_hunter:next_review_loop",
            "status": "needs_review",
            "source_plan_id": "candidate_hunter:autonomous_review_plan",
            "active_steps": [],
        },
        [
            {
                "hypothesis_id": "H-weak",
                "affected_endpoint": "",
                "affected_code_path": "",
                "quality_score": 55,
                "quality_status": "needs_review",
                "provenance_artifacts": ["scope", "policy", "code"],
                "hallucination_guard": {
                    "local_evidence_sources": ["code"],
                    "advisory_sources": [],
                    "independent_cross_check_sources": [],
                },
            }
        ],
    )

    assert execution_loop["current_phase"] == "surface_modeling"
    assert execution_loop["next_candidate_actions"][0]["phase_id"] == "surface_modeling"
    phase_by_id = {
        phase["phase_id"]: phase for phase in execution_loop["phases"]
    }
    assert phase_by_id["surface_modeling"]["status"] == "needs_review"
    assert phase_by_id["semantic_audit"]["status"] == "pending"
    assert phase_by_id["report_draft_readiness"]["status"] == "pending"
    assert execution_loop["execution_allowed"] is False
    assert execution_loop["validation_allowed"] is False
    assert execution_loop["report_submission_allowed"] is False


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
                    "cve_id": "CVE-2024-12345",
                    "framework": "fastapi",
                    "case_title": "Historical object export authorization bypass",
                    "similarity_score": 0.923,
                    "retrieval_rank": "1",
                    "exploit_code": "requests.get('https://target.example/private')",
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
            "exploit_code_allowed": "false",
            "source": "local_milvus",
            "pattern_id": "WEB-IDOR-001",
            "vuln_type": "authorization_gap",
            "cve_id": "CVE-2024-12345",
            "framework": "fastapi",
            "case_title": "Historical object export authorization bypass",
            "similarity_score": "0.92",
            "retrieval_rank": "1",
        }
    ]
    assert "requests.get" not in str(facts)
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


def write_sarif_artifact(tmp_path: Path) -> Path:
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
    return sarif_path


def stage_workspace_artifacts(
    workspace_path: str | Path,
    artifacts: tuple[tuple[str, Path], ...],
) -> list[tuple[str, Path]]:
    workspace = Path(workspace_path)
    staged: list[tuple[str, Path]] = []
    code_path_rewrites: dict[str, str] = {}

    for kind, source_path in artifacts:
        source = Path(source_path)
        destination = workspace / kind / source.name
        if source.is_dir():
            copytree(source, destination)
        else:
            copy2(source, destination)
        staged.append((kind, destination))
        if kind == "code":
            code_path_rewrites[str(source.resolve())] = str(destination.resolve())

    for kind, source_path in staged:
        if kind != "scope":
            continue
        scope_text = source_path.read_text(encoding="utf-8")
        for source_code_path, staged_code_path in code_path_rewrites.items():
            scope_text = scope_text.replace(source_code_path, staged_code_path)
        source_path.write_text(scope_text, encoding="utf-8")

    return staged


def create_runnable_studio_workspace(tmp_path: Path) -> str:
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
    artifacts = (
        ("scope", scope_path),
        ("policy", write_policy_artifact(tmp_path)),
        ("code", repo),
        ("api", write_api_artifact(tmp_path)),
        ("har", write_har_artifact(tmp_path)),
        ("sarif", write_sarif_artifact(tmp_path)),
    )
    workspace_response = client.post(
        "/mythos/studio/workspaces",
        json={"root_path": str(tmp_path), "name": "acme-api"},
    )
    assert workspace_response.status_code == 200
    workspace_path = workspace_response.json()["path"]
    for kind, source_path in stage_workspace_artifacts(workspace_path, artifacts):
        import_response = client.post(
            "/mythos/studio/workspaces/imports",
            json={
                "workspace_path": workspace_path,
                "kind": kind,
                "source_path": str(source_path),
            },
        )
        assert import_response.status_code == 200
    return workspace_path


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
    scope_path = stage_workspace_artifacts(
        workspace["path"],
        (("scope", scope_path),),
    )[0][1]

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
            "source_path": str(
                Path(response.json()["path"]) / "policy" / "missing-policy.md"
            ),
        },
    )

    assert import_response.status_code == 404
    assert import_response.json()["detail"] == "artifact_source_not_found"


def test_studio_import_rejects_existing_source_outside_workspace(tmp_path: Path):
    workspace_response = client.post(
        "/mythos/studio/workspaces",
        json={"root_path": str(tmp_path), "name": "acme-api"},
    )
    assert workspace_response.status_code == 200
    external_policy = tmp_path.parent / f"{tmp_path.name}-policy.md"
    external_policy.write_text("in scope api.example.com", encoding="utf-8")

    response = client.post(
        "/mythos/studio/workspaces/imports",
        json={
            "workspace_path": workspace_response.json()["path"],
            "kind": "policy",
            "source_path": str(external_policy),
        },
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "studio_artifact_not_authorized"}


def test_studio_campaign_launch_rejects_out_of_scope_policy_before_persistence(
    tmp_path: Path,
    monkeypatch,
):
    repo = tmp_path / "target"
    repo.mkdir()
    (repo / "routes.py").write_text(
        "def export_file(file_id: str):\n    return send_file(file_id)\n",
        encoding="utf-8",
    )
    scope_path = tmp_path / "scope.yaml"
    scope_path.write_text("in_scope:\n  - api.example.com\n", encoding="utf-8")
    policy_path = tmp_path / "policy.md"
    policy_path.write_text("api.example.com is out of scope.", encoding="utf-8")
    api_path = write_api_artifact(tmp_path)
    har_path = write_har_artifact(tmp_path)

    override_get_session, testing_session = studio_test_session_override()
    with testing_session() as session:
        seed_sample_data(session)

    monkeypatch.setattr(
        main_module,
        "dispatch_agent_task",
        lambda *, campaign_task_id: {"campaign_task_id": campaign_task_id},
    )
    app.dependency_overrides[get_session] = override_get_session
    try:
        workspace_response = client.post(
            "/mythos/studio/workspaces",
            json={"root_path": str(tmp_path), "name": "out-of-scope"},
        )
        assert workspace_response.status_code == 200
        workspace_path = workspace_response.json()["path"]

        for kind, source_path in stage_workspace_artifacts(
            workspace_path,
            (
                ("scope", scope_path),
                ("policy", policy_path),
                ("code", repo),
                ("api", api_path),
                ("har", har_path),
            ),
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

        launch_response = client.post(
            "/mythos/studio/workspaces/campaigns/launch",
            json={
                "workspace_path": workspace_path,
                "default_asset": "api.example.com",
            },
        )

        assert launch_response.status_code == 409
        assert launch_response.json() == {"detail": "scope_not_in_scope"}
        with testing_session() as session:
            assert DatabaseRepository(session).list_campaigns() == []
    finally:
        app.dependency_overrides.clear()


def test_studio_workspace_campaign_launch_rejects_pending_redaction_without_persistence(
    tmp_path: Path,
):
    override_get_session, testing_session = studio_test_session_override()
    with testing_session() as session:
        seed_sample_data(session)

    app.dependency_overrides[get_session] = override_get_session
    try:
        workspace_path = create_runnable_studio_workspace(tmp_path)
        manifest_path = Path(workspace_path) / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        policy_artifact = next(
            artifact
            for artifact in manifest["artifacts"]
            if artifact["kind"] == "policy"
        )
        policy_artifact["redaction_status"] = "needs_review"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        response = client.post(
            "/mythos/studio/workspaces/campaigns/launch",
            json={
                "workspace_path": workspace_path,
                "default_asset": "api.example.com",
            },
        )

        assert response.status_code == 409
        assert response.json() == {
            "detail": "workspace_snapshot_redaction_review_required"
        }
        with testing_session() as session:
            repository = DatabaseRepository(session)
            assert repository.list_campaigns() == []
            assert session.query(CampaignTaskRecord).all() == []
    finally:
        app.dependency_overrides.clear()


def test_studio_workspace_can_launch_campaign_hunter_from_authorized_artifacts(
    tmp_path: Path,
    monkeypatch,
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
    scope_path.write_text("in_scope:\n  - api.example.com\n", encoding="utf-8")
    policy_path = write_policy_artifact(tmp_path)
    api_path = write_api_artifact(tmp_path)
    har_path = write_har_artifact(tmp_path)

    override_get_session, testing_session = studio_test_session_override()
    with testing_session() as session:
        seed_sample_data(session)

    def inline_dispatcher(*, campaign_task_id: str):
        with testing_session() as session:
            return run_agent_task(
                campaign_task_id,
                repository=DatabaseRepository(session),
            )

    monkeypatch.setattr(main_module, "dispatch_agent_task", inline_dispatcher)
    app.dependency_overrides[get_session] = override_get_session
    try:
        workspace_response = client.post(
            "/mythos/studio/workspaces",
            json={"root_path": str(tmp_path), "name": "acme-api"},
        )
        assert workspace_response.status_code == 200
        workspace_path = workspace_response.json()["path"]

        for kind, source_path in stage_workspace_artifacts(workspace_path, (
            ("scope", scope_path),
            ("policy", policy_path),
            ("code", repo),
            ("api", api_path),
            ("har", har_path),
        )):
            import_response = client.post(
                "/mythos/studio/workspaces/imports",
                json={
                    "workspace_path": workspace_path,
                    "kind": kind,
                    "source_path": str(source_path),
                },
            )
            assert import_response.status_code == 200

        launch_response = client.post(
            "/mythos/studio/workspaces/campaigns/launch",
            json={
                "workspace_path": workspace_path,
                "name": "Studio campaign hunter",
                "default_asset": "api.example.com",
            },
        )

        assert launch_response.status_code == 200
        body = launch_response.json()
        campaign = body["campaign"]
        assert campaign["status"] == "running"
        assert campaign["autonomy_level"] == "level_0_read_only"
        assert body["execution_allowed"] is False
        assert body["validation_allowed"] is False
        assert body["report_submission_allowed"] is False
        assert len(body["dispatched_task_ids"]) == 1
        with testing_session() as session:
            repository = DatabaseRepository(session)
            stored_campaign = repository.get_campaign(campaign["id"])
            assert stored_campaign is not None
            assert stored_campaign.payload["scope_guard_rule"]["scope_status"] == "in_scope"
            assert "workspace_snapshot" in stored_campaign.payload
            assert "return send_file" not in json.dumps(stored_campaign.payload)
            assert [
                task.task_type for task in repository.list_campaign_tasks(campaign["id"])
            ] == ["campaign_observation"]
            tick_result = main_module.tick_autonomous_research_campaign(
                campaign["id"],
                repository=repository,
                dispatcher=inline_dispatcher,
                now=datetime.now(UTC) + timedelta(seconds=61),
            )
            assert tick_result["status"] == "dispatched"
        manifest = body["manifest"]
        hunter_run = manifest["campaign_hunter_runs"][-1]
        assert hunter_run["campaign_id"] == campaign["id"]
        assert hunter_run["campaign_name"] == "Studio campaign hunter"
        assert hunter_run["campaign_status"] == "running"
        assert hunter_run["suggestion_count"] == len(
            body["control_center"]["research_queue_suggestions"]
        )
        assert hunter_run["dispatched_task_count"] == 1
        assert hunter_run["autonomy_level"] == "level_0_read_only"
        assert hunter_run["safety_gate"] == "review_only_no_execution"
        assert hunter_run["execution_allowed"] is False
        assert hunter_run["validation_allowed"] is False
        assert hunter_run["report_submission_allowed"] is False

        export_response = client.post(
            "/mythos/studio/workspaces/campaigns/reports/export",
            json={
                "workspace_path": workspace_path,
                "campaign_id": campaign["id"],
            },
        )
        assert export_response.status_code == 200
        export = export_response.json()
        assert export["campaign_id"] == campaign["id"]
        assert export["run_id"] == campaign["id"]
        assert export["submission_blocked"] is True
        assert export["report_submission_allowed"] is False
        assert export["report_markdown_path"].endswith(
            "-campaign-hunter-report-draft.md"
        )
        assert export["manifest"]["campaign_hunter_runs"][-1][
            "report_markdown_path"
        ].endswith("-campaign-hunter-report-draft.md")
        assert export["manifest"]["campaign_hunter_runs"][-1][
            "report_submission_allowed"
        ] is False
        markdown = Path(export["report_markdown_path"]).read_text(encoding="utf-8")
        assert "Submission status: blocked" in markdown
        assert "Report submission allowed: false" in markdown
        assert "Campaign hunter report export is local and submission-blocked." in markdown
        assert "secret-token" not in str(export)
        assert "Authorization" not in str(export)

        map_response = client.get(
            f"/mythos/campaigns/{campaign['id']}/codebase-map"
        )
        assert map_response.status_code == 200
        facts = map_response.json()["facts"]
        assert any(
            fact["fact_type"] == "route_handler"
            and fact["route_path"] == "/files/{file_id}/export"
            for fact in facts
        )
        assert "secret-token" not in str(body)
        assert "Authorization" not in str(body)
    finally:
        app.dependency_overrides.clear()


def test_studio_workspace_campaign_launch_uses_verified_snapshot_for_runtime_mapping(
    tmp_path: Path,
    monkeypatch,
):
    override_get_session, testing_session = studio_test_session_override()
    with testing_session() as session:
        seed_sample_data(session)

    def inline_dispatcher(*, campaign_task_id: str):
        with testing_session() as session:
            return run_agent_task(
                campaign_task_id,
                repository=DatabaseRepository(session),
            )

    monkeypatch.setattr(main_module, "dispatch_agent_task", inline_dispatcher)
    app.dependency_overrides[get_session] = override_get_session
    try:
        workspace_path = create_runnable_studio_workspace(tmp_path)
        scope_path = Path(workspace_path) / "scope" / "scope.yaml"
        scope_path.write_text("in_scope:\n  - api.example.com\n", encoding="utf-8")
        scope_import = client.post(
            "/mythos/studio/workspaces/imports",
            json={
                "workspace_path": workspace_path,
                "kind": "scope",
                "source_path": str(scope_path),
            },
        )
        assert scope_import.status_code == 200
        launch_response = client.post(
            "/mythos/studio/workspaces/campaigns/launch",
            json={
                "workspace_path": workspace_path,
                "name": "Snapshot-backed campaign hunter",
                "default_asset": "api.example.com",
            },
        )

        assert launch_response.status_code == 200
        body = launch_response.json()
        campaign_id = body["campaign"]["id"]
        assert len(body["dispatched_task_ids"]) == 1
        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.get_campaign(campaign_id)
            assert campaign is not None
            snapshot = campaign.payload["workspace_snapshot"]
            assert snapshot["source_snapshot_digest"].startswith("sha256:")
            assert "def export_file" not in json.dumps(snapshot)
            assert [task.task_type for task in repository.list_campaign_tasks(campaign.id)] == [
                "campaign_observation"
            ]
            result = main_module.tick_autonomous_research_campaign(
                campaign.id,
                repository=repository,
                dispatcher=inline_dispatcher,
                now=datetime.now(UTC) + timedelta(seconds=61),
            )
            assert result["status"] == "dispatched"

        with testing_session() as session:
            facts = DatabaseRepository(session).list_campaign_codebase_facts(campaign_id)
            assert any(
                fact.fact_type == "route_handler"
                and fact.route_path == "/files/{file_id}/export"
                for fact in facts
            )
            assert "def export_file" not in json.dumps(
                [fact.payload for fact in facts]
            )
    finally:
        app.dependency_overrides.clear()


def test_workspace_runtime_dispatches_queued_local_evidence_on_the_next_tick(
    tmp_path: Path,
    monkeypatch,
):
    override_get_session, testing_session = studio_test_session_override()
    with testing_session() as session:
        seed_sample_data(session)

    def inline_dispatcher(*, campaign_task_id: str):
        with testing_session() as session:
            return run_agent_task(
                campaign_task_id,
                repository=DatabaseRepository(session),
            )

    monkeypatch.setattr(main_module, "dispatch_agent_task", inline_dispatcher)
    app.dependency_overrides[get_session] = override_get_session
    try:
        workspace_path = create_runnable_studio_workspace(tmp_path)
        scope_path = Path(workspace_path) / "scope" / "scope.yaml"
        scope_path.write_text("in_scope:\n  - api.example.com\n", encoding="utf-8")
        assert client.post(
            "/mythos/studio/workspaces/imports",
            json={
                "workspace_path": workspace_path,
                "kind": "scope",
                "source_path": str(scope_path),
            },
        ).status_code == 200
        launch = client.post(
            "/mythos/studio/workspaces/campaigns/launch",
            json={
                "workspace_path": workspace_path,
                "default_asset": "api.example.com",
            },
        )
        assert launch.status_code == 200
        campaign_id = launch.json()["campaign"]["id"]

        def advance() -> dict:
            with testing_session() as session:
                repository = DatabaseRepository(session)
                return main_module.tick_autonomous_research_campaign(
                    campaign_id,
                    repository=repository,
                    dispatcher=inline_dispatcher,
                    now=datetime.now(UTC) + timedelta(seconds=61),
                )

        first_advance = advance()
        assert first_advance["status"] == "dispatched", json.dumps(first_advance)
        second_advance = advance()
        assert second_advance["status"] == "dispatched", json.dumps(second_advance)
        third_advance = advance()
        assert third_advance["status"] == "dispatched", json.dumps(third_advance)
        fourth_advance = advance()
        assert fourth_advance["status"] == "dispatched", json.dumps(fourth_advance)
        fifth_advance = advance()
        assert fifth_advance["status"] == "dispatched", json.dumps(fifth_advance)
        with testing_session() as session:
            repository = DatabaseRepository(session)
            evidence_task = next(
                task
                for task in repository.list_campaign_tasks(campaign_id)
                if task.task_type == "candidate_hunter_evidence_inspection"
            )
            candidate_refutation_task = next(
                task
                for task in repository.list_campaign_tasks(campaign_id)
                if task.task_type == "candidate_refutation"
            )
            candidate_refutation_runs = [
                run
                for run in repository.list_campaign_agent_runs(campaign_id)
                if run.task_id == candidate_refutation_task.id
            ]
            assert evidence_task.status == "queued"
            assert candidate_refutation_task.status == "awaiting_evidence"
            assert candidate_refutation_task.execution_claim_id is None
            assert [run.status for run in candidate_refutation_runs] == ["completed"]

        result = advance()

        assert result["status"] == "dispatched"
        assert result["campaign_task_id"] == evidence_task.id
        with testing_session() as session:
            evidence_task = DatabaseRepository(session).session.get(
                type(evidence_task),
                evidence_task.id,
            )
            assert evidence_task is not None
            assert evidence_task.status == "completed"

        ranking_tick = advance()
        report_tick = advance()
        review_tick = advance()

        assert ranking_tick["status"] == "dispatched"
        assert report_tick["status"] == "dispatched"
        assert review_tick["status"] == "awaiting_review"
        assert review_tick["stop_reason"] == "human_review_required"
        review_wake_results = [advance() for _ in range(12)]

        assert all(
            result["status"] == "awaiting_review"
            and result["stop_reason"] == "human_review_required"
            for result in review_wake_results
        )
        with testing_session() as session:
            tasks = DatabaseRepository(session).list_campaign_tasks(campaign_id)
            runtime_tasks = [
                task
                for task in tasks
                if isinstance(task.payload, dict)
                and task.payload.get("runtime_schema") == "autonomous_research_v1"
            ]
            assert {
                task.task_type for task in runtime_tasks
            } == {
                "campaign_observation",
                "attack_surface_mapping",
                "security_invariant_generation",
                "hypothesis_generation",
                "exploit_chain_reasoning",
                "candidate_refutation",
                "finding_dedup_and_rank",
                "report_review",
            }
            assert len(runtime_tasks) == 8
            assert all(task.status == "completed" for task in runtime_tasks)
            assert len(
                [
                    task
                    for task in tasks
                    if task.task_type == "candidate_hunter_evidence_inspection"
                ]
            ) == 1
            campaign = DatabaseRepository(session).get_campaign(campaign_id)
            assert campaign is not None
            assert campaign.status == "awaiting_review"
            validation_handoff = next(
                task for task in tasks if task.task_type == "validation_handoff"
            )
            assert validation_handoff.status == "awaiting_approval"
            report_task = next(task for task in runtime_tasks if task.task_type == "report_review")
            pipeline_run_id = report_task.payload["pipeline_run_id"]
            report_stage = next(
                stage
                for stage in DatabaseRepository(session).list_pipeline_stages_for_run(
                    pipeline_run_id
                )
                if stage.stage_key == "autonomous_report_review"
            )
            deep_code_reasoning_stage = next(
                stage
                for stage in DatabaseRepository(session).list_pipeline_stages_for_run(
                    pipeline_run_id
                )
                if stage.stage_key == "autonomous_deep_code_reasoning"
            )
            variant_analysis_stage = next(
                stage
                for stage in DatabaseRepository(session).list_pipeline_stages_for_run(
                    pipeline_run_id
                )
                if stage.stage_key == "autonomous_variant_analysis"
            )
            finding_dedup_risk_stage = next(
                stage
                for stage in DatabaseRepository(session).list_pipeline_stages_for_run(
                    pipeline_run_id
                )
                if stage.stage_key == "autonomous_finding_dedup_risk"
            )
            report_bundle = report_stage.payload["report_drafts"][0]
            pipeline_run = DatabaseRepository(session).get_pipeline_run(pipeline_run_id)
            assert pipeline_run is not None
            source_hypothesis = pipeline_run.payload["hypotheses"][0]
            assert report_stage.payload["deep_code_reasoning_attached"] is True
            assert report_stage.payload["variant_analysis_attached"] is True
            assert report_stage.payload["finding_dedup_risk_attached"] is True
            assert report_stage.payload["deep_code_reasoning_stage_id"] == (
                deep_code_reasoning_stage.id
            )
            assert report_stage.payload["variant_analysis_stage_id"] == (
                variant_analysis_stage.id
            )
            assert report_stage.payload["finding_dedup_risk_stage_id"] == (
                finding_dedup_risk_stage.id
            )
            assert report_bundle["autonomous_provenance"][
                "deep_code_reasoning_stage_id"
            ] == deep_code_reasoning_stage.id
            assert report_bundle["autonomous_provenance"][
                "variant_analysis_stage_id"
            ] == variant_analysis_stage.id
            assert report_bundle["autonomous_provenance"][
                "finding_dedup_risk_stage_id"
            ] == finding_dedup_risk_stage.id
            assert report_bundle["autonomous_provenance"][
                "deep_code_reasoning_projection_digest"
            ] == deep_code_reasoning_stage.payload["deep_code_reasoning_digest"]
            assert report_bundle["autonomous_provenance"][
                "variant_analysis_projection_digest"
            ] == variant_analysis_stage.payload["variant_analysis_digest"]
            assert report_bundle["autonomous_provenance"][
                "finding_dedup_risk_projection_digest"
            ] == finding_dedup_risk_stage.payload["finding_dedup_risk_digest"]
            assert any(
                engine["engine"] == "deep_code_reasoning"
                for engine in report_bundle["multi_engine_verdict"]["engines"]
            )
            assert any(
                engine["engine"] == "variant_analysis"
                for engine in report_bundle["multi_engine_verdict"]["engines"]
            )
            assert any(
                engine["engine"] == "finding_dedup_risk"
                for engine in report_bundle["multi_engine_verdict"]["engines"]
            )
            assert report_bundle["status"] == "unverified_hypothesis"
            assert report_bundle["submission_blocked"] is True
            assert report_bundle["human_review_required"] is True
            assert report_bundle["execution_allowed"] is False
            assert report_bundle["validation_allowed"] is False
            assert report_bundle["report_submission_allowed"] is False
            assert report_bundle["confirmed_vulnerability"] is False
            assert report_bundle["source_fact_refs"]
            assert report_bundle["broken_invariant"] == source_hypothesis[
                "broken_invariant"
            ]
            assert report_bundle["validation_mode"] == source_hypothesis[
                "validation_mode"
            ]
            assert report_bundle["evidence_needed"] == source_hypothesis[
                "evidence_needed"
            ]
            assert report_bundle["impact_rationale"] == source_hypothesis[
                "impact_rationale"
            ]
            assert report_bundle["impact_score"] == source_hypothesis["impact_score"]
            assert "No live validation was executed" in report_bundle["report_draft"][
                "actual_result"
            ]
            assert "def export_file" not in json.dumps(report_bundle)
    finally:
        app.dependency_overrides.clear()


def test_studio_campaign_snapshot_refresh_starts_a_new_audited_runtime_cycle(
    tmp_path: Path,
    monkeypatch,
):
    override_get_session, testing_session = studio_test_session_override()
    with testing_session() as session:
        seed_sample_data(session)

    def inline_dispatcher(*, campaign_task_id: str):
        with testing_session() as session:
            return run_agent_task(
                campaign_task_id,
                repository=DatabaseRepository(session),
            )

    monkeypatch.setattr(main_module, "dispatch_agent_task", inline_dispatcher)
    app.dependency_overrides[get_session] = override_get_session
    try:
        workspace_path = create_runnable_studio_workspace(tmp_path)
        scope_path = Path(workspace_path) / "scope" / "scope.yaml"
        scope_path.write_text("in_scope:\n  - api.example.com\n", encoding="utf-8")
        assert client.post(
            "/mythos/studio/workspaces/imports",
            json={
                "workspace_path": workspace_path,
                "kind": "scope",
                "source_path": str(scope_path),
            },
        ).status_code == 200
        launch = client.post(
            "/mythos/studio/workspaces/campaigns/launch",
            json={
                "workspace_path": workspace_path,
                "default_asset": "api.example.com",
            },
        )
        assert launch.status_code == 200
        campaign_id = launch.json()["campaign"]["id"]

        def advance() -> dict:
            with testing_session() as session:
                return main_module.tick_autonomous_research_campaign(
                    campaign_id,
                    repository=DatabaseRepository(session),
                    dispatcher=inline_dispatcher,
                    now=datetime.now(UTC) + timedelta(seconds=61),
                )

        for _ in range(5):
            assert advance()["status"] == "dispatched"
        assert advance()["status"] == "dispatched"
        assert advance()["status"] == "dispatched"
        assert advance()["status"] == "dispatched"
        assert advance()["status"] == "awaiting_review"

        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.get_campaign(campaign_id)
            assert campaign is not None
            old_snapshot_digest = campaign.payload["source_snapshot_digest"]
            handoff = next(
                task
                for task in repository.list_campaign_tasks(campaign_id)
                if task.task_type == "validation_handoff"
            )
            assert handoff.status == "awaiting_approval"

        blocked_refresh = client.post(
            f"/mythos/studio/workspaces/campaigns/{campaign_id}/snapshot-refresh",
            json={
                "workspace_path": workspace_path,
                "actor": "operator",
                "reason": "Awaiting validation review must remain closed.",
            },
        )
        assert blocked_refresh.status_code == 409
        assert blocked_refresh.json() == {"detail": "human_review_required"}

        review = client.post(
            f"/mythos/campaigns/{campaign_id}/validation-handoffs/{handoff.id}/review",
            json={
                "decision": "dismissed",
                "reviewer": "operator",
                "reason": "No local validation is requested for the prior snapshot.",
            },
        )
        assert review.status_code == 200

        with testing_session() as session:
            repository = DatabaseRepository(session)
            repository.upsert_campaign_budget(
                campaign_id=campaign_id,
                time_budget_minutes=60,
                token_budget=10000,
                tool_call_budget=30,
                validation_budget=1,
            )

        source_path = Path(workspace_path) / "code" / "target" / "routes.py"
        source_path.write_text(
            source_path.read_text(encoding="utf-8")
            + "\n# authorized snapshot refresh marker\n",
            encoding="utf-8",
        )
        assert client.post(
            "/mythos/studio/workspaces/imports",
            json={
                "workspace_path": workspace_path,
                "kind": "code",
                "source_path": str(source_path.parent),
            },
        ).status_code == 200
        refreshed_snapshot = main_module.build_authorized_campaign_snapshot(
            workspace_path
        )
        assert main_module.load_authorized_campaign_inputs(refreshed_snapshot)[
            "source_snapshot_digest"
        ] == refreshed_snapshot["source_snapshot_digest"]
        refreshed = client.post(
            f"/mythos/studio/workspaces/campaigns/{campaign_id}/snapshot-refresh",
            json={
                "workspace_path": workspace_path,
                "actor": "operator",
                "reason": "Start a new review cycle for the authorized local change.",
            },
        )

        assert refreshed.status_code == 200, refreshed.json()
        body = refreshed.json()
        assert body["previous_source_snapshot_digest"] == old_snapshot_digest
        assert body["source_snapshot_digest"] != old_snapshot_digest
        assert body["execution_allowed"] is False
        assert body["validation_allowed"] is False
        assert body["report_submission_allowed"] is False
        assert len(body["dispatched_task_ids"]) == 1

        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.get_campaign(campaign_id)
            assert campaign is not None
            new_snapshot_digest = campaign.payload["source_snapshot_digest"]
            assert campaign.status == "running", [
                (stage.stage_key, stage.status, stage.stop_reason)
                for stage in repository.list_campaign_pipeline_stages(campaign_id)
                if stage.status in {"blocked", "failed"}
            ]
            new_runtime_tasks = [
                task
                for task in repository.list_campaign_tasks(campaign_id)
                if isinstance(task.payload, dict)
                and task.payload.get("runtime_schema") == "autonomous_research_v1"
                and task.payload.get("source_snapshot_digest") == new_snapshot_digest
            ]
            refresh_stage = next(
                stage
                for stage in repository.list_campaign_pipeline_stages(campaign_id)
                if stage.stage_key == "autonomous_research_snapshot_refresh"
            )

            assert [task.task_type for task in new_runtime_tasks] == [
                "campaign_observation"
            ]
            assert new_runtime_tasks[0].status == "completed"
            assert refresh_stage.payload["previous_source_snapshot_digest"] == (
                old_snapshot_digest
            )
            assert refresh_stage.payload["source_snapshot_digest"] == new_snapshot_digest
            assert refresh_stage.payload["execution_allowed"] is False
            assert refresh_stage.safety_gate_state == "human_review_completed"
            assert all(
                refresh_stage.payload[field] is False
                for field in (
                    "dispatch_allowed",
                    "validation_allowed",
                    "candidate_promotion_allowed",
                    "report_submission_allowed",
                    "raw_payload_processed",
                    "raw_payload_in_dispatch",
                )
            )
            assert "authorized snapshot refresh marker" not in json.dumps(
                refresh_stage.payload
            )

        next_cycle = advance()
        assert next_cycle["status"] == "dispatched"
        with testing_session() as session:
            repository = DatabaseRepository(session)
            new_task_types = {
                task.task_type
                for task in repository.list_campaign_tasks(campaign_id)
                if isinstance(task.payload, dict)
                and task.payload.get("runtime_schema") == "autonomous_research_v1"
                and task.payload.get("source_snapshot_digest") == new_snapshot_digest
            }
            assert new_task_types == {
                "campaign_observation",
                "attack_surface_mapping",
            }
    finally:
        app.dependency_overrides.clear()


def test_studio_campaign_snapshot_refresh_blocks_unsettled_validation_run(
    tmp_path: Path,
    monkeypatch,
):
    override_get_session, testing_session = studio_test_session_override()
    with testing_session() as session:
        seed_sample_data(session)

    def inline_dispatcher(*, campaign_task_id: str):
        with testing_session() as session:
            return run_agent_task(
                campaign_task_id,
                repository=DatabaseRepository(session),
            )

    monkeypatch.setattr(main_module, "dispatch_agent_task", inline_dispatcher)
    app.dependency_overrides[get_session] = override_get_session
    try:
        workspace_path = create_runnable_studio_workspace(tmp_path)
        scope_path = Path(workspace_path) / "scope" / "scope.yaml"
        scope_path.write_text("in_scope:\n  - api.example.com\n", encoding="utf-8")
        assert client.post(
            "/mythos/studio/workspaces/imports",
            json={
                "workspace_path": workspace_path,
                "kind": "scope",
                "source_path": str(scope_path),
            },
        ).status_code == 200
        launch = client.post(
            "/mythos/studio/workspaces/campaigns/launch",
            json={
                "workspace_path": workspace_path,
                "default_asset": "api.example.com",
            },
        )
        assert launch.status_code == 200
        campaign_id = launch.json()["campaign"]["id"]

        with testing_session() as session:
            repository = DatabaseRepository(session)
            campaign = repository.get_campaign(campaign_id)
            assert campaign is not None
            repository.save_validation_run(
                campaign_id=campaign.id,
                task_id=None,
                approval_id=None,
                validation_mode="two_account_authorization_check",
                target_ref=f"campaign:{campaign.id}",
                status="awaiting_approval",
                safety_gate_state="awaiting_approval",
                plan_digest="sha256:" + "c" * 64,
                approval_required=True,
                allowed_to_execute=False,
                evidence_ref_count=0,
                summary="Awaiting human validation review.",
                payload={"source": "snapshot_refresh_guard"},
            )
            completed = repository.update_campaign_status(campaign.id, "completed")
            assert completed is not None

        refreshed = client.post(
            f"/mythos/studio/workspaces/campaigns/{campaign_id}/snapshot-refresh",
            json={
                "workspace_path": workspace_path,
                "actor": "operator",
                "reason": "An open validation run must block refresh.",
            },
        )

        assert refreshed.status_code == 409
        assert refreshed.json() == {"detail": "validation_review_required"}
    finally:
        app.dependency_overrides.clear()


def test_workspace_runtime_blocks_local_evidence_when_snapshot_changes(
    tmp_path: Path,
    monkeypatch,
):
    override_get_session, testing_session = studio_test_session_override()
    with testing_session() as session:
        seed_sample_data(session)

    def inline_dispatcher(*, campaign_task_id: str):
        with testing_session() as session:
            return run_agent_task(
                campaign_task_id,
                repository=DatabaseRepository(session),
            )

    monkeypatch.setattr(main_module, "dispatch_agent_task", inline_dispatcher)
    app.dependency_overrides[get_session] = override_get_session
    try:
        workspace_path = create_runnable_studio_workspace(tmp_path)
        scope_path = Path(workspace_path) / "scope" / "scope.yaml"
        scope_path.write_text("in_scope:\n  - api.example.com\n", encoding="utf-8")
        assert client.post(
            "/mythos/studio/workspaces/imports",
            json={
                "workspace_path": workspace_path,
                "kind": "scope",
                "source_path": str(scope_path),
            },
        ).status_code == 200
        launch = client.post(
            "/mythos/studio/workspaces/campaigns/launch",
            json={
                "workspace_path": workspace_path,
                "default_asset": "api.example.com",
            },
        )
        assert launch.status_code == 200
        campaign_id = launch.json()["campaign"]["id"]

        def advance() -> dict:
            with testing_session() as session:
                return main_module.tick_autonomous_research_campaign(
                    campaign_id,
                    repository=DatabaseRepository(session),
                    dispatcher=inline_dispatcher,
                    now=datetime.now(UTC) + timedelta(seconds=61),
                )

        for _ in range(5):
            assert advance()["status"] == "dispatched"
        with testing_session() as session:
            repository = DatabaseRepository(session)
            evidence_task = next(
                task
                for task in repository.list_campaign_tasks(campaign_id)
                if task.task_type == "candidate_hunter_evidence_inspection"
            )
            assert evidence_task.status == "queued"

        (Path(workspace_path) / "api" / "openapi.json").write_text(
            '{"openapi":"3.0.0","paths":{}}',
            encoding="utf-8",
        )
        result = advance()

        assert result["status"] == "dispatched"
        assert result["campaign_task_id"] == evidence_task.id
        with testing_session() as session:
            repository = DatabaseRepository(session)
            blocked_task = repository.session.get(type(evidence_task), evidence_task.id)
            assert blocked_task is not None
            assert blocked_task.status == "blocked"
            owner_task = repository.session.get(
                type(evidence_task),
                blocked_task.payload["owner_task_id"],
            )
            assert owner_task is not None
            assert owner_task.status == "blocked"
            evidence_runs = [
                run
                for run in repository.list_campaign_agent_runs(campaign_id)
                if run.task_id == blocked_task.id
            ]
            assert [run.status for run in evidence_runs] == ["blocked"]
            blocked_campaign = repository.get_campaign(campaign_id)
            assert blocked_campaign is not None
            assert blocked_campaign.status == "blocked"
            assert any(
                stage.task_id == owner_task.id
                and stage.stage_key == "autonomous_research:candidate_refutation"
                and stage.status == "blocked"
                and stage.stop_reason == "workspace_snapshot_changed"
                for stage in repository.list_campaign_pipeline_stages(campaign_id)
            )

        post_blocked_tick = advance()

        assert post_blocked_tick["status"] == "blocked"
        assert post_blocked_tick["stop_reason"] == "campaign_blocked"
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize(
    "candidate_model",
    [
        {"enabled": True, "model": "gpt-4.1-mini"},
        {"enabled": True, "provider": "openai"},
        {"enabled": True, "provider": "openai", "model": "   "},
        {"enabled": False, "provider": "openai"},
        {"enabled": False, "model": "gpt-4.1-mini"},
        {
            "enabled": True,
            "provider": "openai",
            "model": "gpt-4.1-mini",
            "api_key": "must-not-be-accepted",
        },
    ],
)
def test_studio_run_rejects_ambiguous_candidate_model_before_persistence(
    tmp_path: Path,
    monkeypatch,
    candidate_model: dict,
):
    load_calls = 0

    def track_manifest_load(_workspace_path: str) -> dict:
        nonlocal load_calls
        load_calls += 1
        return {}

    monkeypatch.setattr(main_module, "load_workspace_manifest", track_manifest_load)
    session_override, testing_session = studio_test_session_override()
    app.dependency_overrides[get_session] = session_override
    try:
        response = client.post(
            "/mythos/studio/workspaces/runs",
            json={
                "workspace_path": str(tmp_path),
                "candidate_model": candidate_model,
            },
        )

        assert response.status_code == 422
        assert isinstance(response.json()["detail"], list)
        assert load_calls == 0
        with testing_session() as session:
            repository = DatabaseRepository(session)
            assert repository.list_pipeline_runs() == []
            assert repository.list_llm_runs() == []
    finally:
        app.dependency_overrides.clear()


def test_internal_studio_service_runs_replay_with_safe_audit(
    tmp_path: Path,
    monkeypatch,
):
    service = getattr(
        main_module,
        "_run_mythos_studio_workspace_research_service",
        None,
    )
    assert callable(service)

    def fail_if_registry_is_built():
        raise AssertionError("replay must not build an LLM registry")

    monkeypatch.setattr(main_module, "build_default_registry", fail_if_registry_is_built)
    raw_marker = "fixture-replay-impact-marker"
    payload = {
        "schema_version": "cross_source_candidate_model_v1",
        "proposals": [
            {
                "vulnerability_family": "authorization",
                "affected_endpoint": {
                    "method": "GET",
                    "path": "/files/{file_id}/export",
                },
                "affected_code_path": {
                    "source_path": "routes.py",
                    "symbol_name": "export_file",
                },
                "suspected_broken_invariant": (
                    "Object export should verify ownership before a sensitive sink."
                ),
                "impact_rationale": raw_marker,
                "evidence_requirements": ["Review local ownership checks."],
                "refutation_questions": [
                    "Does observed middleware enforce object ownership?"
                ],
                "root_cause_summary": "missing_object_ownership_check",
                "risk_estimate": "high",
                "cited_fact_refs": [
                    "code:routes.py:export_file",
                    "api:GET:/files/{file_id}/export",
                ],
            }
        ],
    }
    received_fact_packs = []
    replay_reasoner = ReplayCandidateReasoner(
        payload,
        allow_legacy_unbound=True,
    )

    class RecordingReplayReasoner:
        async def generate(self, *, fact_pack, model_config, request_key):
            received_fact_packs.append(fact_pack)
            return await replay_reasoner.generate(
                fact_pack=fact_pack,
                model_config=model_config,
                request_key=request_key,
            )

    session_override, testing_session = studio_test_session_override()
    app.dependency_overrides[get_session] = session_override
    try:
        workspace_path = create_runnable_studio_workspace(tmp_path)
        request = main_module.StudioWorkspaceRunRequest.model_validate(
            {
                "workspace_path": workspace_path,
                "candidate_model": {
                    "enabled": True,
                    "provider": "openai",
                    "model": "fixture-replay-v1",
                },
            }
        )
        with testing_session() as session:
            body = asyncio.run(
                service(
                    request,
                    session,
                    reasoner_override=RecordingReplayReasoner(),
                    audit_mode="replay",
                )
            )
            repository = DatabaseRepository(session)
            llm_runs = repository.list_llm_runs()
            generation_stage = next(
                stage
                for stage in repository.list_pipeline_stages_for_run(body["run_id"])
                if stage.stage_key == "cross_source_candidate_generation"
            )

        assert body["candidate_generation"]["model_status"] == "completed"
        assert body["candidate_generation"]["accepted_count"] == 1, (
            generation_stage.payload.get("rejection_reason_counts"),
            generation_stage.payload.get("model_failure_reason"),
            received_fact_packs[0].allowed_fact_refs,
        )
        for key in (
            "model_request_key",
            "model_response_digest",
            "model_response_schema",
            "model_reasoner",
            "model_replay_binding",
            "raw_payload_processed",
        ):
            assert body["candidate_generation"][key] == generation_stage.payload[key]
        assert len(body["candidate_generation"]["model_request_key"]) == 64
        assert len(body["candidate_generation"]["model_response_digest"]) == 64
        assert body["candidate_generation"]["model_response_schema"] == (
            "cross_source_candidate_model_v1"
        )
        assert body["candidate_generation"]["model_reasoner"] == "replay"
        assert body["candidate_generation"]["model_replay_binding"] == "legacy_unbound"
        assert body["candidate_generation"]["raw_payload_processed"] is False
        assert len(llm_runs) == 1
        assert llm_runs[0].mode == "replay"
        assert "synthetic_replay_no_provider_call" in llm_runs[0].safety_notes
        serialized = json.dumps(
            {
                "body": body,
                "llm_run": {
                    "provider": llm_runs[0].provider,
                    "model": llm_runs[0].model,
                    "mode": llm_runs[0].mode,
                    "prompt_hash": llm_runs[0].prompt_hash,
                    "safety_notes": llm_runs[0].safety_notes,
                },
                "generation_stage": generation_stage.payload,
            }
        )
        assert raw_marker not in serialized
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize(
    ("candidate_model", "include_reasoner", "expected_reason"),
    (
        (None, True, "replay_reasoner_requires_enabled_model_request"),
        (
            {"enabled": False},
            True,
            "replay_reasoner_requires_enabled_model_request",
        ),
        (
            {
                "enabled": True,
                "provider": "openai",
                "model": "fixture-replay-v1",
            },
            False,
            "replay_audit_requires_reasoner",
        ),
    ),
)
def test_internal_studio_service_rejects_invalid_replay_boundary_before_persistence(
    tmp_path: Path,
    monkeypatch,
    candidate_model: dict | None,
    include_reasoner: bool,
    expected_reason: str,
):
    manifest_loads = []

    def track_manifest_load(workspace_path: str):
        manifest_loads.append(workspace_path)
        return {}

    monkeypatch.setattr(main_module, "load_workspace_manifest", track_manifest_load)
    request_payload = {"workspace_path": str(tmp_path)}
    if candidate_model is not None:
        request_payload["candidate_model"] = candidate_model
    request = main_module.StudioWorkspaceRunRequest.model_validate(request_payload)
    reasoner = (
        ReplayCandidateReasoner(
            {
                "schema_version": "cross_source_candidate_model_v1",
                "proposals": [],
            },
            allow_legacy_unbound=True,
        )
        if include_reasoner
        else None
    )
    _, testing_session = studio_test_session_override()
    with testing_session() as session:
        with pytest.raises(ValueError, match=expected_reason):
            asyncio.run(
                main_module._run_mythos_studio_workspace_research_service(
                    request,
                    session,
                    reasoner_override=reasoner,
                    audit_mode="replay",
                )
            )
        repository = DatabaseRepository(session)
        assert repository.list_pipeline_runs() == []
        assert repository.list_llm_runs() == []
    assert manifest_loads == []


def test_studio_run_routes_explicit_candidate_model_through_registry_reasoner(
    tmp_path: Path,
    monkeypatch,
):
    class FactBoundProvider:
        name = ProviderName.OPENAI

        def __init__(self):
            self.requests = []

        async def generate(self, request):
            self.requests.append(request)
            fact_pack = json.loads(request.prompt)["fact_pack"]
            code_fact = next(
                fact
                for fact in fact_pack["code_facts"]
                if fact["fact_type"] == "authorization_gap_candidate"
                and fact.get("route")
            )
            api_fact = next(
                fact
                for fact in fact_pack["surface_facts"]
                if fact["artifact_kind"] == "api" and fact.get("route")
            )
            proposal = {
                "vulnerability_family": "authorization",
                "affected_endpoint": code_fact["route"],
                "affected_code_path": {
                    "source_path": code_fact["source_path"],
                    "symbol_name": code_fact["symbol_name"],
                },
                "suspected_broken_invariant": (
                    "Object export must verify ownership before a sensitive sink."
                ),
                "impact_rationale": (
                    "An unauthorized object export could expose another account's file."
                ),
                "evidence_requirements": ["Review local ownership checks."],
                "refutation_questions": [
                    "Does observed middleware enforce object ownership?"
                ],
                "root_cause_summary": code_fact["root_cause"],
                "risk_estimate": "high",
                "cited_fact_refs": [
                    code_fact["fact_ref"],
                    api_fact["fact_ref"],
                ],
            }
            return LLMResponse(
                provider=request.provider,
                model=request.model,
                text=json.dumps(
                    {
                        "schema_version": "cross_source_candidate_model_v1",
                        "proposals": [proposal],
                    }
                ),
                mode=request.mode,
                prompt_hash="provider-placeholder",
                latency_ms=1,
                error=None,
            )

    provider = FactBoundProvider()
    monkeypatch.setattr(
        main_module,
        "build_default_registry",
        lambda: LLMRegistry({ProviderName.OPENAI: provider}),
    )
    captured_hunter_inputs: list[dict] = []
    original_run_candidate_hunter_loop = main_module.run_candidate_hunter_loop

    def capture_hunter_inputs(**kwargs):
        captured_hunter_inputs.extend(kwargs["candidates"])
        return original_run_candidate_hunter_loop(**kwargs)

    monkeypatch.setattr(
        main_module,
        "run_candidate_hunter_loop",
        capture_hunter_inputs,
    )
    session_override, testing_session = studio_test_session_override()
    app.dependency_overrides[get_session] = session_override
    try:
        workspace_path = create_runnable_studio_workspace(tmp_path)

        response = client.post(
            "/mythos/studio/workspaces/runs",
            json={
                "workspace_path": workspace_path,
                "candidate_model": {
                    "enabled": True,
                    "provider": "openai",
                    "model": "test-model",
                },
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert provider.requests
        prompt_fact_pack = json.loads(provider.requests[0].prompt)["fact_pack"]
        assert any(
            fact["fact_type"] == "authorization_gap_candidate"
            and fact.get("route")
            for fact in prompt_fact_pack["code_facts"]
        ), prompt_fact_pack["code_facts"]
        assert any(
            fact["artifact_kind"] == "api" and fact.get("route")
            for fact in prompt_fact_pack["surface_facts"]
        ), prompt_fact_pack["surface_facts"]
        assert body["candidate_generation"]["model_requested"] is True
        assert body["candidate_generation"]["provider"] == "openai"
        assert body["candidate_generation"]["model"] == "test-model"
        assert body["candidate_generation"]["model_failure_reason"] is None
        assert body["candidate_generation"]["model_status"] == "completed"
        assert body["candidate_generation"]["proposed_count"] == 1
        assert body["candidate_generation"]["accepted_count"] == 1
        assert body["candidate_generation"]["rejected_count"] == 0
        assert all(
            body["candidate_generation"][field] is False
            for field in (
                "execution_allowed",
                "dispatch_allowed",
                "validation_allowed",
                "candidate_promotion_allowed",
                "report_submission_allowed",
            )
        )
        assert body["submission_blocked"] is True
        assert len(provider.requests) == 1
        model_request = provider.requests[0]
        assert model_request.mode == LLMMode.LIVE
        assert model_request.purpose == "cross_source_candidate_generation"
        assert model_request.temperature == 0
        assert model_request.max_tokens == 2400
        assert captured_hunter_inputs
        hunter_candidate = captured_hunter_inputs[0]
        assert hunter_candidate["refutation_status"] == "unverified"
        assert (
            "Does observed middleware enforce object ownership?"
            in hunter_candidate["false_positive_checks"]
        )
        assert {fact["artifact_kind"] for fact in hunter_candidate["source_facts"]} >= {
            "code",
            "api",
        }

        with testing_session() as session:
            repository = DatabaseRepository(session)
            llm_runs = repository.list_llm_runs()
            assert len(llm_runs) == 1
            llm_run = llm_runs[0]
            assert llm_run.provider == "openai"
            assert llm_run.model == "test-model"
            assert llm_run.purpose == "cross_source_candidate_generation"
            assert llm_run.mode == "live"
            assert len(llm_run.prompt_hash) == 64
            assert llm_run.latency_ms is not None
            assert llm_run.error is None
            assert "prompt_hash_only" in llm_run.safety_notes
            assert "no_prompt_storage" in llm_run.safety_notes
            assert "provider_response_not_fact" in llm_run.safety_notes
            generation_stage = next(
                stage
                for stage in repository.list_pipeline_stages_for_run(body["run_id"])
                if stage.stage_key == "cross_source_candidate_generation"
            )
            accepted = generation_stage.payload["accepted_candidates"][0]
            assert accepted["origin"] == "model"
            assert accepted["evidence_trace_status"] == "traceable"
            assert all(
                accepted[field] is False
                for field in (
                    "execution_allowed",
                    "dispatch_allowed",
                    "validation_allowed",
                    "candidate_promotion_allowed",
                    "report_submission_allowed",
                )
            )
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize(
    ("failure_kind", "expected_reason"),
    [
        ("provider_error", "provider_error"),
        ("timeout", "timeout"),
    ],
)
def test_studio_run_model_failure_is_audited_and_keeps_baseline_candidates(
    tmp_path: Path,
    monkeypatch,
    failure_kind: str,
    expected_reason: str,
):
    raw_provider_error = "Authorization: Bearer raw-provider-secret"

    class FailingProvider:
        name = ProviderName.OPENAI

        def __init__(self):
            self.calls = 0

        async def generate(self, _request):
            self.calls += 1
            if failure_kind == "timeout":
                raise TimeoutError(raw_provider_error)
            raise RuntimeError(raw_provider_error)

    provider = FailingProvider()
    monkeypatch.setattr(
        main_module,
        "build_default_registry",
        lambda: LLMRegistry({ProviderName.OPENAI: provider}),
    )
    session_override, testing_session = studio_test_session_override()
    app.dependency_overrides[get_session] = session_override
    try:
        workspace_path = create_runnable_studio_workspace(tmp_path)

        response = client.post(
            "/mythos/studio/workspaces/runs",
            json={
                "workspace_path": workspace_path,
                "candidate_model": {
                    "enabled": True,
                    "provider": "openai",
                    "model": "test-model",
                },
            },
        )

        assert response.status_code == 200
        body = response.json()
        summary = body["candidate_generation"]
        assert summary["model_status"] == "needs_model_review"
        assert summary["model_failure_reason"] == expected_reason
        assert summary["accepted_count"] == 0
        assert summary["working_candidate_count"] == summary["baseline_count"]
        assert summary["working_candidate_count"] >= 1
        assert body["candidate_count"] == summary["working_candidate_count"]
        assert body["submission_blocked"] is True
        assert provider.calls == 1
        assert all(
            summary[field] is False
            for field in (
                "execution_allowed",
                "dispatch_allowed",
                "validation_allowed",
                "candidate_promotion_allowed",
                "report_submission_allowed",
            )
        )

        manifest_response = client.get(
            "/mythos/studio/workspaces/manifest",
            params={"workspace_path": workspace_path},
        )
        assert manifest_response.status_code == 200
        assert "candidate_model" not in json.dumps(manifest_response.json())
        with testing_session() as session:
            repository = DatabaseRepository(session)
            llm_runs = repository.list_llm_runs()
            assert len(llm_runs) == 1
            llm_run = llm_runs[0]
            assert llm_run.error == expected_reason
            assert "model_failure_recorded" in llm_run.safety_notes
            generation_stage = next(
                stage
                for stage in repository.list_pipeline_stages_for_run(body["run_id"])
                if stage.stage_key == "cross_source_candidate_generation"
            )
            assert generation_stage.payload["working_candidates"]
            serialized = json.dumps(
                {
                    "response": body,
                    "generation_stage": generation_stage.payload,
                    "llm_run": {
                        "provider": llm_run.provider,
                        "model": llm_run.model,
                        "purpose": llm_run.purpose,
                        "prompt_hash": llm_run.prompt_hash,
                        "mode": llm_run.mode,
                        "latency_ms": llm_run.latency_ms,
                        "error": llm_run.error,
                        "safety_notes": llm_run.safety_notes,
                    },
                    "manifest": manifest_response.json(),
                }
            )
            assert raw_provider_error not in serialized
            assert "raw-provider-secret" not in serialized
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize(
    (
        "output_kind",
        "expected_status",
        "expected_failure_reason",
        "expected_rejection_counts",
        "expected_audit_error",
    ),
    [
        ("invalid_schema", "needs_model_review", "invalid_schema", {}, "invalid_schema"),
        ("sensitive", "completed", None, {"sensitive_content": 1}, None),
    ],
)
def test_studio_run_rejects_invalid_or_sensitive_model_output_without_persisting_raw_text(
    tmp_path: Path,
    monkeypatch,
    output_kind: str,
    expected_status: str,
    expected_failure_reason: str | None,
    expected_rejection_counts: dict[str, int],
    expected_audit_error: str | None,
):
    raw_marker = (
        "raw-invalid-schema-marker"
        if output_kind == "invalid_schema"
        else "Authorization: Bearer raw-model-secret"
    )

    class InvalidOutputProvider:
        name = ProviderName.OPENAI

        async def generate(self, request):
            fact_pack = json.loads(request.prompt)["fact_pack"]
            code_fact = next(
                fact
                for fact in fact_pack["code_facts"]
                if fact["fact_type"] == "authorization_gap_candidate"
                and fact.get("route")
            )
            api_fact = next(
                fact
                for fact in fact_pack["surface_facts"]
                if fact["artifact_kind"] == "api" and fact.get("route")
            )
            proposal = {
                "vulnerability_family": "authorization",
                "affected_endpoint": code_fact["route"],
                "affected_code_path": {
                    "source_path": code_fact["source_path"],
                    "symbol_name": code_fact["symbol_name"],
                },
                "suspected_broken_invariant": (
                    "Object export must verify ownership before a sensitive sink."
                ),
                "impact_rationale": "Potential cross-account file disclosure.",
                "evidence_requirements": ["Review local ownership checks."],
                "refutation_questions": [
                    "Does observed middleware enforce object ownership?"
                ],
                "root_cause_summary": code_fact["root_cause"],
                "risk_estimate": "high",
                "cited_fact_refs": [
                    code_fact["fact_ref"],
                    api_fact["fact_ref"],
                ],
            }
            if output_kind == "invalid_schema":
                proposal["unexpected_permission"] = raw_marker
            else:
                proposal["impact_rationale"] = raw_marker
            return LLMResponse(
                provider=request.provider,
                model=request.model,
                text=json.dumps(
                    {
                        "schema_version": "cross_source_candidate_model_v1",
                        "proposals": [proposal],
                    }
                ),
                mode=request.mode,
                prompt_hash="provider-placeholder",
                latency_ms=1,
                error=None,
            )

    monkeypatch.setattr(
        main_module,
        "build_default_registry",
        lambda: LLMRegistry(
            {ProviderName.OPENAI: InvalidOutputProvider()}
        ),
    )
    captured_hunter_inputs: list[dict] = []
    original_run_candidate_hunter_loop = main_module.run_candidate_hunter_loop

    def capture_hunter_inputs(**kwargs):
        captured_hunter_inputs.extend(kwargs["candidates"])
        return original_run_candidate_hunter_loop(**kwargs)

    monkeypatch.setattr(
        main_module,
        "run_candidate_hunter_loop",
        capture_hunter_inputs,
    )
    session_override, testing_session = studio_test_session_override()
    app.dependency_overrides[get_session] = session_override
    try:
        workspace_path = create_runnable_studio_workspace(tmp_path)

        response = client.post(
            "/mythos/studio/workspaces/runs",
            json={
                "workspace_path": workspace_path,
                "candidate_model": {
                    "enabled": True,
                    "provider": "openai",
                    "model": "test-model",
                },
            },
        )

        assert response.status_code == 200
        body = response.json()
        summary = body["candidate_generation"]
        assert summary["model_status"] == expected_status
        assert summary["model_failure_reason"] == expected_failure_reason
        assert summary["accepted_count"] == 0
        assert summary["rejected_count"] == sum(expected_rejection_counts.values())
        assert summary["working_candidate_count"] == summary["baseline_count"]
        assert all(
            summary[field] is False
            for field in (
                "execution_allowed",
                "dispatch_allowed",
                "validation_allowed",
                "candidate_promotion_allowed",
                "report_submission_allowed",
            )
        )
        assert captured_hunter_inputs
        assert all(raw_marker not in json.dumps(item) for item in captured_hunter_inputs)

        manifest_response = client.get(
            "/mythos/studio/workspaces/manifest",
            params={"workspace_path": workspace_path},
        )
        assert manifest_response.status_code == 200
        assert "candidate_model" not in json.dumps(manifest_response.json())
        with testing_session() as session:
            repository = DatabaseRepository(session)
            llm_runs = repository.list_llm_runs()
            assert len(llm_runs) == 1
            llm_run = llm_runs[0]
            assert llm_run.error == expected_audit_error
            generation_stage = next(
                stage
                for stage in repository.list_pipeline_stages_for_run(body["run_id"])
                if stage.stage_key == "cross_source_candidate_generation"
            )
            assert (
                generation_stage.payload["rejection_reason_counts"]
                == expected_rejection_counts
            )
            serialized = json.dumps(
                {
                    "response": body,
                    "generation_stage": generation_stage.payload,
                    "llm_run": {
                        "error": llm_run.error,
                        "safety_notes": llm_run.safety_notes,
                    },
                    "manifest": manifest_response.json(),
                }
            )
            assert raw_marker not in serialized
            assert "raw-model-secret" not in serialized
    finally:
        app.dependency_overrides.clear()


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
    sarif_path = write_sarif_artifact(tmp_path)

    session_override, testing_session = studio_test_session_override()
    app.dependency_overrides[get_session] = session_override
    try:
        workspace_response = client.post(
            "/mythos/studio/workspaces",
            json={"root_path": str(tmp_path), "name": "acme-api"},
        )
        assert workspace_response.status_code == 200
        workspace_path = workspace_response.json()["path"]

        for kind, source_path in stage_workspace_artifacts(workspace_path, (
            ("scope", scope_path),
            ("policy", policy_path),
            ("code", repo),
            ("api", api_path),
            ("har", har_path),
            ("sarif", sarif_path),
        )):
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

        with testing_session() as session:
            repository = DatabaseRepository(session)
            generation_stages = [
                stage
                for stage in repository.list_pipeline_stages_for_run(run_body["run_id"])
                if stage.stage_key == "cross_source_candidate_generation"
            ]
            assert len(generation_stages) == 1
            generation_stage = generation_stages[0]
            assert generation_stage.stage_order == 0
            assert generation_stage.status == "completed"
            assert generation_stage.safety_gate_state == "safe"
            assert generation_stage.payload["model_status"] == "model_not_requested"
            assert generation_stage.payload["working_candidates"]
            assert generation_stage.payload["execution_allowed"] is False
            assert generation_stage.payload["validation_allowed"] is False
            assert generation_stage.payload["report_submission_allowed"] is False
            assert "return send_file" not in json.dumps(generation_stage.payload)
            assert generation_stage.payload["source_manifest"]
            loop_campaigns = [
                campaign
                for campaign in repository.list_campaigns()
                if campaign.payload.get("pipeline_run_id") == run_body["run_id"]
            ]
            assert len(loop_campaigns) == 1
            loop_tasks = repository.list_campaign_tasks(loop_campaigns[0].id)
            owner_task = next(
                task
                for task in loop_tasks
                if task.task_type == "candidate_hunter_loop"
            )
            evidence_task = next(
                task
                for task in loop_tasks
                if task.task_type == "candidate_hunter_evidence_inspection"
            )
            assert owner_task.status == "needs_evidence"
            assert evidence_task.status == "queued"
            loop_stages = [
                stage
                for stage in repository.list_pipeline_stages_for_run(run_body["run_id"])
                if stage.task_id == owner_task.id
            ]
            assert [stage.stage_key for stage in loop_stages] == [
                "candidate_hunter_snapshot",
                "candidate_hunter_evidence_request",
                "candidate_hunter_decision",
                "candidate_hunter_rerank",
            ]
            assert [stage.payload["round"] for stage in loop_stages] == [
                1,
                1,
                1,
                1,
            ]
            assert loop_stages[1].payload["evidence_requests"]
            assert loop_stages[2].payload["candidate_decisions"] == []
            serialized_stages = json.dumps(
                [stage.payload for stage in loop_stages]
            )
            assert "send_file(file_id)" not in serialized_stages
            assert "Authorization:" not in serialized_stages
            assert "Bearer " not in serialized_stages
            assert str(tmp_path) not in serialized_stages
            assert all(
                stage.payload[field] is False
                for stage in loop_stages
                for field in (
                    "execution_allowed",
                    "dispatch_allowed",
                    "validation_allowed",
                    "candidate_promotion_allowed",
                    "report_submission_allowed",
                    "raw_payload_processed",
                )
            )

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
            "artifact_kinds": ["scope", "policy", "code", "api", "har", "sarif"],
            "review_items": [
                "Confirm every candidate claim is traceable to imported authorized artifacts.",
                "Review only normalized artifact summaries; raw paths, headers, tokens, and bodies remain excluded.",
            ],
        }
        assert candidates[0]["evidence_trace_summary"] == {
            "status": "traceable",
            "required_artifact_kinds": ["scope", "policy", "code", "api", "har"],
            "present_required_artifact_kinds": ["scope", "policy", "code", "api", "har"],
            "advisory_artifact_kinds": ["sarif"],
            "missing_required_artifact_kinds": [],
            "source_fact_count": len(candidates[0]["source_facts"]),
            "endpoint_traced": True,
            "code_path_traced": True,
            "independent_cross_check_count": 1,
            "next_action": "Review trace summary and refutation questions before any validation.",
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
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
        ] == ["scope", "policy", "code", "api", "har", "sarif"]
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
        assert "- Artifact kinds: scope, policy, code, api, har, sarif" in markdown
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
    sarif_path = write_sarif_artifact(tmp_path)
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

        for kind, source_path in stage_workspace_artifacts(workspace_path, (
            ("scope", scope_path),
            ("policy", policy_path),
            ("code", repo),
            ("api", api_path),
            ("har", har_path),
            ("sarif", sarif_path),
            ("knowledge", knowledge_path),
        )):
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
        assert mission["attack_surface_model"] == {
            "status": "modeled",
            "source_artifact_kinds": ["api", "har", "knowledge", "sarif"],
            "route_count": 2,
            "api_route_count": 1,
            "har_route_count": 1,
            "advisory_signal_count": 2,
            "methods": ["GET"],
            "top_routes": [
                {
                    "method": "GET",
                    "path": "/files/{file_id}/export",
                    "artifact_kinds": ["api", "sarif"],
                },
                {
                    "method": "GET",
                    "path": "/files/123/export",
                    "artifact_kinds": ["har"],
                },
            ],
            "next_action": "Review normalized API/HAR/code surface coverage before candidate promotion.",
            "safety_gate": "authorized_artifacts_only",
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
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
        assert mission["candidate_hunter_backlog"] == []
        assert mission["candidate_hunter_iteration"] == {
            "iteration_id": "candidate_hunter:next_review",
            "status": "ready_for_human_review",
            "work_item_count": 0,
            "priority_order": [],
            "next_review_agent": "Human Reviewer",
            "review_focus": [],
            "success_criteria": [
                "Top candidates remain review-ready after human evidence review.",
                "Submission-blocked report draft is ready for redaction review.",
            ],
            "safety_gate": "review_only_no_execution",
            "completion_gate": "human_review_required",
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        }
        assert mission["candidate_hunter_plan"] == {
            "plan_id": "candidate_hunter:autonomous_review_plan",
            "status": "ready_for_human_review",
            "work_item_count": 0,
            "step_count": 0,
            "next_review_agent": "Human Reviewer",
            "plan_steps": [],
            "hallucination_governance": {
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
            },
            "safety_gate": "review_only_no_execution",
            "completion_gate": "human_review_required",
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        }
        assert mission["candidate_hunter_review_loop"] == {
            "loop_id": "candidate_hunter:next_review_loop",
            "status": "ready_for_human_review",
            "source_plan_id": "candidate_hunter:autonomous_review_plan",
            "active_step_count": 0,
            "next_review_agent": "Human Reviewer",
            "review_agents": [],
            "required_evidence": [],
            "active_steps": [],
            "governance_summary": {
                "claim_promotion_rule": "no_verified_evidence_no_high_confidence",
                "required_consensus": [
                    "authorized_local_artifact_evidence",
                    "independent_refutation_or_static_rule",
                    "human_review_decision",
                ],
                "candidate_promotion_allowed": False,
            },
            "blocked_actions": [
                "execute_live_validation",
                "run_fuzzer",
                "submit_report",
            ],
            "safety_gate": "review_only_no_execution",
            "completion_gate": "human_review_required",
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        }
        handoff_pack = mission["agent_handoff_pack"]
        assert handoff_pack["pack_id"] == "studio:agent_handoff:next_review"
        assert handoff_pack["status"] == "ready_for_human_review"
        assert handoff_pack["handoff_item_count"] == 0
        assert handoff_pack["next_review_agent"] == "Human Reviewer"
        assert handoff_pack["handoff_items"] == []
        assert handoff_pack["safety_gate"] == "review_only_no_execution"
        assert handoff_pack["completion_gate"] == "human_review_required"
        assert handoff_pack["execution_allowed"] is False
        assert handoff_pack["validation_allowed"] is False
        assert handoff_pack["report_submission_allowed"] is False
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
        assert {"scope", "policy", "code", "api", "har", "sarif"}.issubset(
            set(candidate["provenance_artifacts"])
        )
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
        assert candidate["hallucination_guard"]["independent_cross_check_sources"] == [
            "sarif"
        ]
        assert "sarif" in candidate["hallucination_guard"]["cross_validation_sources"]
        assert "endpoint_and_code_path_traced" in candidate["quality_reasons"]
        assert "provenance_review_present" in candidate["quality_reasons"]
        assert "refutation_checks_present" in candidate["quality_reasons"]
        assert "safe_validation_plan_present" in candidate["quality_reasons"]
        assert "hallucination_guard_cross_checked" in candidate["quality_reasons"]
        review_packet = mission["candidate_review_packets"][0]
        assert review_packet["candidate_id"] == candidate["hypothesis_id"]
        assert review_packet["status"] == "review_ready"
        assert review_packet["missing_items"] == []
        assert "evidence_needs" in review_packet["completed_items"]
        assert "refutation_checks" in review_packet["completed_items"]
        assert "safe_validation_plan" in review_packet["completed_items"]
        assert "submission_blocked_report" in review_packet["completed_items"]
        assert "independent_cross_check" in review_packet["completed_items"]
        assert review_packet["next_human_action"].startswith("Review evidence")
        assert review_packet["safety_gate"] == "human_review_required"
        assert review_packet["quality_score"] == candidate["quality_score"]
        assert review_packet["report_review_priority"] == "redaction_review_ready"
        assert review_packet["execution_allowed"] is False
        assert review_packet["validation_allowed"] is False
        assert review_packet["report_submission_allowed"] is False
        report_summary = mission["submission_blocked_report_summary"]
        assert report_summary["status"] == "ready_for_redaction_review"
        assert report_summary["candidate_count"] == mission["candidate_count"]
        assert report_summary["ready_candidate_ids"] == [
            candidate["hypothesis_id"]
        ]
        assert report_summary["needs_review_candidate_ids"] == []
        assert report_summary["missing_review_items"] == {}
        assert report_summary["report_review_queue"] == [
            {
                "candidate_id": candidate["hypothesis_id"],
                "priority": "redaction_review_ready",
                "quality_score": candidate["quality_score"],
                "next_human_action": review_packet["next_human_action"],
                "safety_gate": "submission_blocked_human_review",
                "report_submission_allowed": False,
                "validation_execution_allowed": False,
            }
        ]
        assert report_summary["redaction_review_required"] is True
        assert report_summary["safety_gate"] == "submission_blocked_human_review"
        assert report_summary["report_submission_allowed"] is False
        assert report_summary["validation_execution_allowed"] is False
        readiness_audit = mission["readiness_audit"]
        assert readiness_audit["status"] == "demo_ready_for_human_review"
        assert readiness_audit["required_check_count"] == 8
        assert readiness_audit["passed_check_count"] == 8
        assert readiness_audit["execution_allowed"] is False
        assert readiness_audit["validation_allowed"] is False
        assert readiness_audit["report_submission_allowed"] is False
        readiness_checks = {
            check["key"]: check for check in readiness_audit["checks"]
        }
        assert readiness_checks["authorized_ab_intake"]["status"] == "passed"
        assert readiness_checks["hallucination_governed_candidates"]["status"] == "passed"
        assert readiness_checks["advisory_knowledge_context"]["status"] == "passed"
        assert readiness_checks["cross_validation_refutation"]["status"] == "passed"
        assert readiness_checks["candidate_hunter_backlog"]["status"] == "passed"
        assert readiness_checks["safe_validation_planning"]["status"] == "passed"
        assert readiness_checks["submission_blocked_report"]["status"] == "passed"
        assert readiness_checks["review_only_handoff"]["status"] == "passed"
        assert "knowledge" in readiness_checks["advisory_knowledge_context"]["evidence_refs"]
        assert "sarif" in readiness_checks["cross_validation_refutation"]["evidence_refs"]
        assert readiness_checks["review_only_handoff"]["safety_gate"] == (
            "review_only_no_execution"
        )
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
        agent_task_timeline = mission["agent_task_timeline"]
        assert len(agent_task_timeline) == len(agent_queue)
        assert agent_task_timeline[3]["stage_id"] == "agent_queue:semantic_candidate_hunt"
        assert agent_task_timeline[3]["gate_decision"] == "review_recorded"
        assert agent_task_timeline[4]["gate_decision"] == "human_review_required"
        assert agent_task_timeline[6]["gate_decision"] == "blocked"
        assert agent_task_timeline[3]["report_submission_allowed"] is False
        assert agent_task_timeline[3]["validation_execution_allowed"] is False
        assert "execute_live_validation" not in str(agent_task_timeline)
        assert "submit_report" not in str(agent_task_timeline)
        assert "run_fuzzer" not in str(agent_task_timeline)
        timeline_summary = mission["studio_timeline_summary"]
        assert timeline_summary["total_stages"] == len(agent_task_timeline)
        assert timeline_summary["gate_decision_counts"]["review_recorded"] >= 1
        assert timeline_summary["gate_decision_counts"]["human_review_required"] >= 1
        assert timeline_summary["gate_decision_counts"]["blocked"] >= 1
        assert "agent_queue:report_draft_review" in timeline_summary["blocked_stage_ids"]
        assert timeline_summary["needs_review_stage_ids"]
        assert "Review top candidate invariants." in timeline_summary["next_human_actions"]
        assert timeline_summary["safety_gate"] == "review_only_no_execution"
        assert timeline_summary["report_submission_allowed"] is False
        assert timeline_summary["validation_execution_allowed"] is False

        handoff_response = client.get(
            "/mythos/studio/workspaces/mission/handoff",
            params={"workspace_path": workspace_path, "run_id": run_id},
        )
        assert handoff_response.status_code == 200
        handoff = handoff_response.json()
        assert handoff["run_id"] == run_id
        assert handoff["scope_guard_status"] == "scope_imported"
        assert handoff["candidate_count"] == mission["candidate_count"]
        assert handoff["artifacts"] == mission["artifacts"]
        assert handoff["quality_summary"]["top_candidate_quality_gate"] == "passed"
        assert handoff["agent_handoff_pack"] == mission["agent_handoff_pack"]
        assert handoff["candidate_hunter_plan"] == mission["candidate_hunter_plan"]
        assert handoff["candidate_hunter_review_loop"] == mission[
            "candidate_hunter_review_loop"
        ]
        assert handoff["candidate_hunter_plan"]["safety_gate"] == (
            "review_only_no_execution"
        )
        assert handoff["candidate_hunter_plan"]["execution_allowed"] is False
        assert handoff["candidate_hunter_plan"]["validation_allowed"] is False
        assert handoff["candidate_hunter_plan"]["report_submission_allowed"] is False
        assert handoff["safety_gate"] == "review_only_no_execution"
        assert handoff["completion_gate"] == "human_review_required"
        assert handoff["execution_allowed"] is False
        assert handoff["validation_allowed"] is False
        assert handoff["report_submission_allowed"] is False
        handoff_manifest = json.loads(
            (Path(workspace_path) / "manifest.json").read_text(encoding="utf-8")
        )
        assert handoff_manifest.get("mission_dossiers", []) == []
        assert handoff_manifest.get("agent_queue_audits", []) == []

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
            dossier["manifest"]["agent_queue_audits"][-1][
                "timeline_blocked_stage_count"
            ]
            >= 1
        )
        assert (
            dossier["manifest"]["agent_queue_audits"][-1][
                "timeline_needs_review_stage_count"
            ]
            >= 1
        )
        assert dossier["manifest"]["agent_queue_audits"][-1][
            "candidate_review_packet_count"
        ] == mission["candidate_count"]
        assert dossier["manifest"]["agent_queue_audits"][-1][
            "candidate_review_ready_packet_count"
        ] == mission["candidate_count"]
        assert dossier["manifest"]["agent_queue_audits"][-1][
            "submission_blocked_report_status"
        ] == "ready_for_redaction_review"
        assert dossier["manifest"]["agent_queue_audits"][-1][
            "submission_blocked_report_ready_candidate_count"
        ] == mission["candidate_count"]
        assert (
            dossier["manifest"]["agent_queue_audits"][-1][
                "agent_handoff_item_count"
            ]
            == 0
        )
        assert dossier["manifest"]["agent_queue_audits"][-1][
            "agent_handoff_status"
        ] == "ready_for_human_review"
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
        assert dossier_json["candidate_review_packets"][0]["status"] == "review_ready"
        assert (
            dossier_json["candidate_review_packets"][0]["report_submission_allowed"]
            is False
        )
        assert dossier_json["submission_blocked_report_summary"]["status"] == (
            "ready_for_redaction_review"
        )
        assert (
            dossier_json["submission_blocked_report_summary"][
                "report_submission_allowed"
            ]
            is False
        )
        assert dossier_json["readiness_audit"]["status"] == (
            "demo_ready_for_human_review"
        )
        assert dossier_json["readiness_audit"]["report_submission_allowed"] is False
        assert dossier_json["studio_timeline_summary"]["blocked_stage_ids"]
        assert (
            dossier_json["studio_timeline_summary"]["validation_execution_allowed"]
            is False
        )
        assert dossier_json["candidate_hunter_iteration"]["status"] == (
            "ready_for_human_review"
        )
        assert dossier_json["candidate_hunter_iteration"]["execution_allowed"] is False
        assert dossier_json["candidate_hunter_review_loop"] == mission[
            "candidate_hunter_review_loop"
        ]
        assert (
            dossier_json["candidate_hunter_review_loop"]["execution_allowed"] is False
        )
        assert dossier_json["agent_handoff_pack"]["handoff_item_count"] == 0
        assert dossier_json["agent_handoff_pack"]["execution_allowed"] is False
        assert dossier_json["agent_handoff_pack"]["validation_allowed"] is False
        assert (
            dossier_json["agent_handoff_pack"]["report_submission_allowed"] is False
        )
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
        assert queue_json["candidate_review_packets"][0]["status"] == "review_ready"
        assert queue_json["candidate_review_packets"][0]["report_review_priority"] == (
            "redaction_review_ready"
        )
        assert queue_json["candidate_review_packets"][0]["validation_allowed"] is False
        assert queue_json["submission_blocked_report_summary"]["ready_candidate_ids"] == [
            candidate["hypothesis_id"]
        ]
        assert queue_json["submission_blocked_report_summary"]["report_review_queue"][
            0
        ] == {
            "candidate_id": candidate["hypothesis_id"],
            "priority": "redaction_review_ready",
            "quality_score": candidate["quality_score"],
            "next_human_action": queue_json["candidate_review_packets"][0][
                "next_human_action"
            ],
            "safety_gate": "submission_blocked_human_review",
            "report_submission_allowed": False,
            "validation_execution_allowed": False,
        }
        assert (
            queue_json["submission_blocked_report_summary"][
                "validation_execution_allowed"
            ]
            is False
        )
        assert queue_json["readiness_audit"]["passed_check_count"] == 8
        assert queue_json["readiness_audit"]["execution_allowed"] is False
        assert queue_json["candidate_hunter_backlog"] == []
        assert queue_json["studio_timeline_summary"]["total_stages"] == len(
            queue_json["task_timeline"]
        )
        assert queue_json["studio_timeline_summary"]["blocked_stage_ids"]
        assert queue_json["studio_timeline_summary"]["report_submission_allowed"] is False
        assert queue_json["candidate_hunter_iteration"]["status"] == (
            "ready_for_human_review"
        )
        assert queue_json["candidate_hunter_iteration"]["validation_allowed"] is False
        assert queue_json["candidate_hunter_review_loop"] == mission[
            "candidate_hunter_review_loop"
        ]
        assert queue_json["candidate_hunter_review_loop"]["active_steps"] == []
        assert (
            queue_json["candidate_hunter_review_loop"]["report_submission_allowed"]
            is False
        )
        assert queue_json["agent_handoff_pack"]["status"] == (
            "ready_for_human_review"
        )
        assert queue_json["agent_handoff_pack"]["handoff_item_count"] == 0
        assert queue_json["agent_handoff_pack"]["handoff_items"] == []
        assert queue_json["agent_handoff_pack"]["execution_allowed"] is False
        assert queue_json["agent_handoff_pack"]["validation_allowed"] is False
        assert (
            queue_json["agent_handoff_pack"]["report_submission_allowed"] is False
        )
        assert "# Mythos Studio agent queue audit" in queue_markdown
        assert "## Mission quality" in queue_markdown
        assert "## Candidate hunter iteration" in queue_markdown
        assert "candidate_hunter:next_review" in queue_markdown
        assert "## Candidate hunter review loop" in queue_markdown
        assert "candidate_hunter:next_review_loop" in queue_markdown
        assert "## Studio timeline summary" in queue_markdown
        assert "## Candidate review packets" in queue_markdown
        assert "## Submission-blocked report summary" in queue_markdown
        assert "## Readiness audit" in queue_markdown
        assert "## Agent handoff pack" in queue_markdown
        assert "handoff items: 0" in queue_markdown
        assert "## Agent queue" in queue_markdown
        assert "## Agent task timeline" in queue_markdown
        assert "agent_queue:semantic_candidate_hunt" in queue_markdown
        assert "focus: security_invariants, affected_code_paths, candidate_quality" in queue_markdown
        assert "# Mythos Studio mission dossier" in dossier_markdown
        assert "## Research loop" in dossier_markdown
        assert "## Mission quality" in dossier_markdown
        assert "Top candidate quality gate: passed" in dossier_markdown
        assert "## Candidate hunter iteration" in dossier_markdown
        assert "## Candidate hunter review loop" in dossier_markdown
        assert "## Studio timeline summary" in dossier_markdown
        assert "## Candidate review packets" in dossier_markdown
        assert "## Submission-blocked report summary" in dossier_markdown
        assert "## Readiness audit" in dossier_markdown
        assert "## Agent handoff pack" in dossier_markdown
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

        for kind, source_path in stage_workspace_artifacts(workspace_path, (
            ("scope", scope_path),
            ("policy", policy_path),
            ("code", repo),
            ("api", api_path),
            ("har", har_path),
        )):
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

        for kind, source_path in stage_workspace_artifacts(workspace_path, (
            ("scope", scope_path),
            ("policy", policy_path),
            ("code", repo),
            ("api", api_path),
            ("har", har_path),
            ("strategy", strategy_path),
            ("knowledge", knowledge_path),
        )):
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

        for kind, source_path in stage_workspace_artifacts(workspace_path, (
            ("scope", scope_path),
            ("policy", policy_path),
            ("code", repo),
            ("api", api_path),
            ("har", har_path),
        )):
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

        for kind, source_path in stage_workspace_artifacts(workspace_path, (
            ("scope", scope_path),
            ("policy", policy_path),
            ("code", repo),
            ("api", api_path),
            ("har", har_path),
        )):
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

        for kind, source_path in stage_workspace_artifacts(workspace_path, (
            ("scope", scope_path),
            ("policy", policy_path),
            ("code", repo),
            ("api", api_path),
            ("har", har_path),
        )):
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

        for kind, source_path in stage_workspace_artifacts(workspace_path, (
            ("scope", scope_path),
            ("policy", policy_path),
            ("code", repo),
            ("api", api_path),
            ("har", har_path),
        )):
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


def test_studio_candidates_prioritize_modeled_attack_surface_matches(
    tmp_path: Path,
):
    api_path = write_api_artifact(tmp_path)
    har_path = write_har_artifact(tmp_path)
    sarif_path = write_sarif_artifact(tmp_path)
    manifest = {
        "artifacts": [
            {"kind": "scope", "source_path": str(tmp_path / "scope.yaml")},
            {"kind": "policy", "source_path": str(tmp_path / "policy.md")},
            {"kind": "api", "source_path": str(api_path)},
            {"kind": "har", "source_path": str(har_path)},
            {"kind": "sarif", "source_path": str(sarif_path)},
        ]
    }
    record = SimpleNamespace(
        payload={
            "hypotheses": [
                {
                    "hypothesis_id": f"H-GENERIC-{index}",
                    "vuln_type": "authorization_gap",
                    "location": f"GET /generic/{index}",
                    "priority_score": 55,
                }
                for index in range(1, 6)
            ]
            + [
                {
                    "hypothesis_id": "H-SURFACE",
                    "vuln_type": "authorization_gap",
                    "location": "GET /files/{file_id}/export",
                    "priority_score": 20,
                }
            ]
        }
    )

    candidates = _studio_candidates_for_run(record, manifest)

    assert len(candidates) == 5
    assert candidates[0]["hypothesis_id"] == "H-SURFACE"
    assert candidates[0]["priority_score"] > candidates[1]["priority_score"]
    assert (
        "surface_model_priority: matched api, har, sarif route evidence"
        in candidates[0]["ranking_reasons"]
    )
    assert "H-GENERIC-5" not in {
        candidate["hypothesis_id"] for candidate in candidates
    }
    assert candidates[0]["safe_verification"] is True
    assert candidates[0]["report_readiness"]["report_submission_allowed"] is False


def test_studio_candidates_inherit_worker_assessment_candidate_ids():
    record = SimpleNamespace(
        payload={
            "hypotheses": [
                {
                    "hypothesis": "Review GET /files/{file_id}/export for object authorization boundary drift.",
                    "vuln_type": "authorization_boundary",
                    "validation_mode": "two_account_authorization_check",
                    "priority_score": 70,
                    "source_facts": [
                        {
                            "fact_type": "authorization_gap_candidate",
                            "artifact_kind": "code",
                            "source_path": "routes.py",
                            "symbol_name": "export_file",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                            "root_cause": "missing_object_ownership_check",
                            "security_invariant": "File exports require owner or admin authorization.",
                            "sink_symbols": ["send_file"],
                        }
                    ],
                }
            ],
            "hypothesis_assessments": [
                {
                    "candidate_id": "codebase_fact_hypothesis_1",
                    "hypothesis_index": 0,
                }
            ],
        }
    )

    candidates = _studio_candidates_for_run(record, {})
    execution_loop = _studio_candidate_hunter_execution_loop({}, candidates)

    assert candidates[0]["hypothesis_id"] == "codebase_fact_hypothesis_1"
    assert execution_loop["candidate_evidence_matrix"][0]["candidate_id"] == (
        "codebase_fact_hypothesis_1"
    )
    assert execution_loop["learning_feedback_target"]["candidate_ids"] == [
        "codebase_fact_hypothesis_1"
    ]


def test_studio_candidates_redact_raw_secret_source_fact_fields():
    record = SimpleNamespace(
        payload={
            "hypotheses": [
                {
                    "hypothesis_id": "H-RAW-SECRET",
                    "hypothesis": "Review GET /files/{file_id}/export.",
                    "vuln_type": "authorization_boundary",
                    "validation_mode": "two_account_authorization_check",
                    "priority_score": 70,
                    "source_facts": [
                        {
                            "fact_type": "authorization_gap_candidate",
                            "artifact_kind": "code",
                            "source_path": "routes.py",
                            "symbol_name": "export_file",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                            "request_headers": {
                                "Authorization": "Bearer secret-token",
                                "Cookie": "session=secret-token",
                            },
                            "request_body": "password=secret-token",
                            "raw_url": "/files/123/export?download_token=secret-token",
                            "root_cause": "missing_object_ownership_check",
                            "security_invariant": "File exports require owner or admin authorization.",
                            "sink_symbols": ["send_file"],
                        }
                    ],
                }
            ]
        }
    )

    candidates = _studio_candidates_for_run(record, {})

    assert candidates[0]["source_facts"][0]["route_path"] == "/files/{file_id}/export"
    serialized = str(candidates)
    assert "secret-token" not in serialized
    assert "Authorization" not in serialized
    assert "Cookie" not in serialized
    assert "session=" not in serialized
    assert "password=" not in serialized
    assert "download_token" not in serialized


def test_studio_candidates_require_semantic_evidence_for_report_readiness(
    tmp_path: Path,
):
    api_path = write_api_artifact(tmp_path)
    har_path = write_har_artifact(tmp_path)
    manifest = {
        "artifacts": [
            {"kind": "scope", "source_path": str(tmp_path / "scope.yaml")},
            {"kind": "policy", "source_path": str(tmp_path / "policy.md")},
            {"kind": "api", "source_path": str(api_path)},
            {"kind": "har", "source_path": str(har_path)},
        ]
    }
    record = SimpleNamespace(
        payload={
            "hypotheses": [
                {
                    "hypothesis_id": "H-SEMANTIC-GAP",
                    "vuln_type": "authorization_gap",
                    "location": "GET /files/{file_id}/export",
                    "priority_score": 80,
                    "source_facts": [
                        {
                            "fact_type": "authorization_gap_candidate",
                            "artifact_kind": "code",
                            "source_path": "routes.py",
                            "symbol_name": "export_file",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                        }
                    ],
                }
            ]
        }
    )

    candidate = _studio_candidates_for_run(record, manifest)[0]

    assert candidate["evidence_gaps"] == [
        {"artifact_kind": "semantic", "reason": "missing_root_cause"},
        {"artifact_kind": "semantic", "reason": "missing_security_invariant"},
        {"artifact_kind": "semantic", "reason": "missing_sink_symbols"},
    ]
    assert candidate["evidence_review"]["status"] == "needs_human_review"
    assert (
        "Review semantic root cause, security invariant, and sink symbols before report drafting."
        in candidate["evidence_review"]["required_items"]
    )
    assert candidate["report_readiness"] == {
        "status": "submission_blocked",
        "report_submission_allowed": False,
        "next_allowed_action": (
            "Resolve semantic evidence gaps before exporting a report preview."
        ),
    }


def test_studio_candidates_prioritize_complete_semantic_evidence_before_gap_candidates(
    tmp_path: Path,
):
    manifest = {
        "artifacts": [
            {"kind": "scope", "source_path": str(tmp_path / "scope.yaml")},
            {"kind": "policy", "source_path": str(tmp_path / "policy.md")},
        ]
    }
    record = SimpleNamespace(
        payload={
            "hypotheses": [
                {
                    "hypothesis_id": "H-SEMANTIC-GAP",
                    "vuln_type": "authorization_gap",
                    "location": "GET /files/{file_id}/export",
                    "priority_score": 80,
                    "source_facts": [
                        {
                            "fact_type": "authorization_gap_candidate",
                            "artifact_kind": "code",
                            "source_path": "routes.py",
                            "symbol_name": "export_file",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                        }
                    ],
                },
                {
                    "hypothesis_id": "H-SEMANTIC-COMPLETE",
                    "vuln_type": "authorization_gap",
                    "location": "GET /files/{file_id}/export",
                    "priority_score": 70,
                    "source_facts": [
                        {
                            "fact_type": "authorization_gap_candidate",
                            "artifact_kind": "code",
                            "source_path": "routes.py",
                            "symbol_name": "export_file",
                            "route_method": "GET",
                            "route_path": "/files/{file_id}/export",
                            "root_cause": "missing_object_ownership_check",
                            "security_invariant": "File exports require owner or admin authorization.",
                            "sink_symbols": ["send_file"],
                        }
                    ],
                },
            ]
        }
    )

    candidates = _studio_candidates_for_run(record, manifest)

    assert [candidate["hypothesis_id"] for candidate in candidates[:2]] == [
        "H-SEMANTIC-COMPLETE",
        "H-SEMANTIC-GAP",
    ]
    assert (
        "semantic_evidence_priority: root cause, invariant, and sink symbols present"
        in candidates[0]["ranking_reasons"]
    )
    assert candidates[0]["priority_score"] > candidates[1]["priority_score"]
    assert candidates[0]["report_readiness"]["report_submission_allowed"] is False


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
    sarif_path = write_sarif_artifact(tmp_path)

    app.dependency_overrides[get_session] = override_session()
    try:
        workspace_response = client.post(
            "/mythos/studio/workspaces",
            json={"root_path": str(tmp_path), "name": "acme-api"},
        )
        assert workspace_response.status_code == 200
        workspace_path = workspace_response.json()["path"]

        for kind, source_path in stage_workspace_artifacts(workspace_path, (
            ("scope", scope_path),
            ("policy", policy_path),
            ("code", repo),
            ("api", api_path),
            ("har", har_path),
            ("sarif", sarif_path),
        )):
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

        for kind, source_path in stage_workspace_artifacts(workspace_path, (
            ("scope", scope_path),
            ("policy", policy_path),
            ("code", repo),
            ("api", api_path),
            ("har", har_path),
            ("sbom", sbom_path),
        )):
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

        for kind, source_path in stage_workspace_artifacts(workspace_path, (
            ("scope", scope_path),
            ("policy", policy_path),
            ("code", repo),
            ("api", api_path),
            ("har", har_path),
            ("fuzzing", fuzzing_path),
        )):
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

        for kind, source_path in stage_workspace_artifacts(workspace_path, (
            ("scope", scope_path),
            ("policy", policy_path),
            ("code", repo),
            ("api", api_path),
            ("har", har_path),
            ("strategy", strategy_path),
        )):
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
