from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_session
from app.main import app, _safe_string_list
from app.repository import DatabaseRepository, seed_sample_data


client = TestClient(app)


def override_session():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    with testing_session() as session:
        seed_sample_data(session)

    def _override_get_session():
        with testing_session() as session:
            yield session

    return _override_get_session


def test_mythos_pipeline_dry_run_returns_first_safe_chain():
    response = client.post(
        "/mythos/pipeline/dry-run",
        json={
            "asset": "api.example.com",
            "policy_text": "In scope: api.example.com. Automation limited. DoS is forbidden.",
            "openapi": {
                "paths": {
                    "/files/{file_id}/export": {
                        "get": {"operationId": "exportFile"},
                    }
                }
            },
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["scope_rule"]["scope_status"] == "in_scope"
    assert body["target_model"]["sensitive_actions"][0]["action"] == "export"
    assert body["invariants"][0]["rule_id"] == "private_file_access_control"
    assert body["hypotheses"][0]["validation_mode"] == "two_account_authorization_check"
    assert body["refutation"]["status"] == "blocked"
    assert body["validation_plan"]["status"] == "blocked"
    assert body["report_draft"]["human_review_required"] is True


def test_mythos_pipeline_dry_run_assesses_each_hypothesis_lifecycle():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "In scope: api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        },
                        "/teams/{team_id}/invite": {
                            "post": {"operationId": "inviteMember"},
                        },
                        "/invoices/{invoice_id}/refund": {
                            "post": {"operationId": "refundInvoice"},
                        },
                    }
                },
            },
        )

        assert response.status_code == 200
        body = response.json()
        assessments = body["hypothesis_assessments"]

        assert len(body["hypotheses"]) == 3
        assert len(assessments) == len(body["hypotheses"])
        assert {item["hypothesis"]["validation_mode"] for item in assessments} == {
            "two_account_authorization_check",
            "role_based_authorization_check",
            "non_destructive_request_review",
        }
        assert all(item["scope_decision"]["reason"] for item in assessments)
        assert all(item["refutation"]["status"] == "blocked" for item in assessments)
        assert all(item["validation_plan"]["human_approval_required"] is True for item in assessments)
        assert all(item["evidence_hints"] for item in assessments)
        assert {
            item["hunter_assessment"]["playbook_id"]
            for item in assessments
        } == {
            "bola_idor",
            "role_boundary",
            "money_flow_tampering",
        }

        top_assessment = max(
            assessments,
            key=lambda item: item["hunter_assessment"]["hunter_priority_score"],
        )
        assert body["report_draft"]["title"] == top_assessment["report_draft"]["title"]
        assert body["refutation"] == top_assessment["refutation"]
        assert body["validation_plan"] == top_assessment["validation_plan"]

        runs_response = client.get("/mythos/pipeline/runs")
        assert runs_response.status_code == 200
        run = runs_response.json()[0]
        assert run["hypothesis_count"] == 3
        assert run["blocked_count"] == 3

        detail_response = client.get(f"/mythos/pipeline/runs/{body['run_id']}")
        assert detail_response.status_code == 200
        detail_payload = detail_response.json()["payload"]
        assert detail_payload["hypothesis_assessments"] == assessments
        by_name = {stage["name"]: stage for stage in detail_payload["timeline"]}
        assert "3 candidate lifecycle(s)" in by_name["hypotheses"]["output_summary"]

        artifact_response = client.get(f"/mythos/artifacts/{body['artifact']['artifact_id']}")
        assert artifact_response.status_code == 200
        candidate_usage_records = [
            usage
            for usage in artifact_response.json()["usage_records"]
            if usage["usage_type"] == "hypothesis_candidate"
        ]
        assert len(candidate_usage_records) == 3
        assert {usage["candidate_id"] for usage in candidate_usage_records} == {
            item["candidate_id"] for item in assessments
        }
        assert {
            usage["playbook_id"]
            for usage in candidate_usage_records
        } == {
            "bola_idor",
            "role_boundary",
            "money_flow_tampering",
        }
        assert all(usage["run_id"] == body["run_id"] for usage in candidate_usage_records)
        assert all(usage["stage"] == "hypothesis_lifecycle" for usage in candidate_usage_records)
        assert all("hypothesis" not in usage for usage in candidate_usage_records)

        filtered_response = client.get(
            "/mythos/artifacts",
            params={
                "usage_type": "hypothesis_candidate",
                "usage_run_id": body["run_id"],
            },
        )
        assert filtered_response.status_code == 200
        assert [artifact["id"] for artifact in filtered_response.json()] == [
            body["artifact"]["artifact_id"]
        ]
    finally:
        app.dependency_overrides.clear()


def test_mythos_pipeline_dry_run_persists_artifact_run_without_plaintext_policy():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "artifact_kind": "postman",
                "artifact_payload": {
                    "item": [
                        {
                            "request": {
                                "method": "GET",
                                "url": "https://api.example.com/files/{file_id}/export",
                            }
                        }
                    ]
                },
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["run_id"].startswith("pipeline_run_")
        assert body["artifact_kind"] == "postman"
        assert body["target_model"]["sensitive_actions"][0]["action"] == "export"

        runs_response = client.get("/mythos/pipeline/runs")
        assert runs_response.status_code == 200
        runs = runs_response.json()
        assert len(runs) == 1
        assert runs[0]["id"] == body["run_id"]
        assert runs[0]["asset"] == "api.example.com"
        assert runs[0]["policy_text_hash"]
        assert runs[0]["hypothesis_count"] == len(body["hypotheses"])
        assert runs[0]["blocked_count"] == 1
        assert runs[0]["evidence_count"] == 1
        assert runs[0]["report_title"] == body["report_draft"]["title"]

        detail_response = client.get(f"/mythos/pipeline/runs/{body['run_id']}")
        assert detail_response.status_code == 200
        detail = detail_response.json()
        serialized_detail = str(detail)
        assert detail["payload"]["artifact_kind"] == "postman"
        assert "SECRET POLICY" not in serialized_detail
        assert "policy_text" not in detail["payload"]
    finally:
        app.dependency_overrides.clear()


def test_mythos_pipeline_dry_run_links_artifact_and_validation_gate():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "artifact_kind": "postman",
                "artifact_payload": {
                    "item": [
                        {
                            "request": {
                                "method": "GET",
                                "url": "https://api.example.com/files/{file_id}/export",
                                "header": [{"key": "Authorization", "value": "Bearer live-token"}],
                            }
                        }
                    ]
                },
            },
        )

        assert response.status_code == 200
        body = response.json()
        assert body["artifact"]["artifact_id"].startswith("artifact_")
        assert body["artifact"]["kind"] == "postman"
        assert body["artifact"]["source_type"] == "dry_run_inline"
        assert body["artifact"]["evidence_count"] == 1
        assert body["validation_gate"]["status"] == "awaiting_approval"
        assert body["validation_gate"]["approval_required"] is True
        assert body["validation_workspace"]["allowed_to_execute"] is False
        assert body["validation_workspace"]["test_accounts_only"] is True
        assert body["validation_workspace"]["no_real_user_data"] is True
        assert body["validation_workspace"]["non_destructive_only"] is True
        assert body["hunter_intelligence"]["top_recommendation"] == "needs_human_review"
        hunter_assessment = body["hunter_intelligence"]["assessments"][0]
        assert hunter_assessment["playbook_id"] == "bola_idor"
        assert hunter_assessment["hunter_priority_score"] >= 55
        assert hunter_assessment["next_action"] == "Prepare human-approved, test-account-only validation."

        runs_response = client.get("/mythos/pipeline/runs")
        assert runs_response.status_code == 200
        run = runs_response.json()[0]
        assert run["artifact"]["artifact_id"] == body["artifact"]["artifact_id"]
        assert run["validation_gate"]["status"] == "awaiting_approval"
        assert run["hunter_intelligence"]["top_recommendation"] == "needs_human_review"
        assert run["timeline"][0]["name"] == "policy_ingestion"

        artifacts_response = client.get("/mythos/artifacts")
        assert artifacts_response.status_code == 200
        artifact = artifacts_response.json()[0]
        serialized_artifact = str(artifact)
        assert artifact["id"] == body["artifact"]["artifact_id"]
        assert artifact["payload_summary"]["path_count"] == 1
        assert artifact["derived_facts"]["objects"] == [
            {
                "name": "file_id",
                "provenance_refs": ["openapi.paths./files/{file_id}/export"],
                "provenance_edges": [
                    {
                        "ref": "openapi.paths./files/{file_id}/export",
                        "source_type": "openapi",
                        "stage": "target_model",
                        "source_path": "/files/{file_id}/export",
                        "source_method": None,
                        "fact_type": "object",
                    }
                ],
            }
        ]
        assert artifact["derived_facts"]["sensitive_actions"][0]["provenance_refs"] == [
            "openapi.paths./files/{file_id}/export.get"
        ]
        assert artifact["derived_facts"]["sensitive_actions"][0]["provenance_edges"] == [
            {
                "ref": "openapi.paths./files/{file_id}/export.get",
                "source_type": "openapi",
                "stage": "target_model",
                "source_path": "/files/{file_id}/export",
                "source_method": "get",
                "fact_type": "sensitive_action",
            }
        ]
        assert "live-token" not in serialized_artifact
        assert "SECRET POLICY" not in serialized_artifact

        artifact_detail_response = client.get(f"/mythos/artifacts/{body['artifact']['artifact_id']}")
        assert artifact_detail_response.status_code == 200
        artifact_detail = artifact_detail_response.json()
        assert artifact_detail["source_hash"] == artifact["source_hash"]
        usage_records = artifact_detail["usage_records"]
        assert {
            "usage_type": "pipeline_run",
            "ref": f"run:{body['run_id']}",
            "run_id": body["run_id"],
            "stage": "pipeline_persistence",
        } in usage_records
        assert any(
            usage["usage_type"] == "evidence_bundle"
            and usage["run_id"] == body["run_id"]
            and usage["stage"] == "evidence_model"
            for usage in usage_records
        )
        assert any(
            usage["usage_type"] == "report_claim"
            and usage["run_id"] == body["run_id"]
            and usage["stage"] == "report_preview"
            and usage.get("claim_id", "").startswith("claim_")
            for usage in usage_records
        )
    finally:
        app.dependency_overrides.clear()


def test_mythos_pipeline_dry_run_uses_program_learning_for_hunter_duplicate_risk():
    app.dependency_overrides[get_session] = override_session()
    try:
        signal_response = client.post(
            "/mythos/brain/learning-signals",
            json={
                "program_id": "program_example",
                "playbook_id": "bola_idor",
                "outcome": "duplicate",
                "surface_key": "file_id:export",
                "notes": "Prior BOLA file export report was marked duplicate.",
            },
        )
        assert signal_response.status_code == 200

        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope: api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )

        assert response.status_code == 200
        assessment = response.json()["hunter_intelligence"]["assessments"][0]

        assert assessment["playbook_id"] == "bola_idor"
        assert assessment["duplicate_risk_score"] > 42
        assert "learning:duplicate_history" in assessment["reasons"]
    finally:
        app.dependency_overrides.clear()


def test_mythos_pipeline_records_program_learning_stage_when_memory_adjusts_hunter():
    app.dependency_overrides[get_session] = override_session()
    try:
        signal_response = client.post(
            "/mythos/brain/learning-signals",
            json={
                "program_id": "program_example",
                "playbook_id": "bola_idor",
                "outcome": "duplicate",
                "surface_key": "file_id:export",
                "notes": "Prior BOLA file export report was marked duplicate.",
            },
        )
        assert signal_response.status_code == 200
        signal_id = signal_response.json()["id"]

        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope: api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )

        assert response.status_code == 200
        body = response.json()
        by_name = {stage["name"]: stage for stage in body["timeline"]}
        learning_stage = by_name["program_learning"]

        assert learning_stage["status"] == "completed"
        assert "1 program learning signal(s)" in learning_stage["input_summary"]
        assert "adjusted hunter intelligence" in learning_stage["output_summary"]
        assert "learning:duplicate_history" in learning_stage["output_summary"]
        assert learning_stage["details"]["lesson_traces"] == [
            {
                "lesson_id": "program:program_example:bola_idor:file_id:export:duplicate_watch",
                "playbook_id": "bola_idor",
                "surface_pattern": "file_id:export",
                "recommendation": "duplicate_watch",
                "action": "applied",
                "source_signal_count": 1,
                "source_signal_ids": [signal_id],
                "reasons": ["lesson:duplicate_watch:repeated_duplicate"],
            }
        ]
        assert "advisory_memory_only" in learning_stage["safety_notes"]
        assert learning_stage["details"]["agent_boundary"]["role"] == "Learning Agent"
        assert learning_stage["details"]["agent_boundary"]["allowed_actions"] == [
            "review_program_memory",
            "adjust_hunter_priority",
        ]
        assert (
            "bypass_scope_guard"
            in learning_stage["details"]["agent_boundary"]["blocked_actions"]
        )
        assert (
            learning_stage["details"]["agent_boundary"]["requires_human_review"]
            is True
        )

        detail_response = client.get(f"/mythos/pipeline/runs/{body['run_id']}")
        assert detail_response.status_code == 200
        detail_timeline = detail_response.json()["payload"]["timeline"]
        detail_learning_stage = {
            stage["name"]: stage for stage in detail_timeline
        }["program_learning"]
        assert (
            detail_learning_stage["details"]["lesson_traces"]
            == learning_stage["details"]["lesson_traces"]
        )
    finally:
        app.dependency_overrides.clear()


def test_mythos_pipeline_dry_run_uses_accepted_learning_for_hunter_priority():
    app.dependency_overrides[get_session] = override_session()
    try:
        baseline_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope: api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert baseline_response.status_code == 200
        baseline_assessment = baseline_response.json()["hunter_intelligence"]["assessments"][0]

        signal_ids = []
        for index in range(2):
            signal_response = client.post(
                "/mythos/brain/learning-signals",
                json={
                    "program_id": "program_example",
                    "playbook_id": "bola_idor",
                    "outcome": "accepted",
                    "surface_key": "file_id:export",
                    "notes": f"Prior BOLA file export report {index} was accepted.",
                    "evidence_quality": "strong",
                },
            )
            assert signal_response.status_code == 200
            signal_ids.append(signal_response.json()["id"])

        learned_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope: api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )

        assert learned_response.status_code == 200
        learned_assessment = learned_response.json()["hunter_intelligence"]["assessments"][0]

        assert learned_assessment["playbook_id"] == "bola_idor"
        assert (
            learned_assessment["hunter_priority_score"]
            > baseline_assessment["hunter_priority_score"]
        )
        assert "learning:accepted_history" in learned_assessment["reasons"]
        assert "advisory_memory_only" in learned_assessment["safety_notes"]
        learning_stage = {
            stage["name"]: stage for stage in learned_response.json()["timeline"]
        }["program_learning"]
        assert learning_stage["details"]["lesson_traces"] == [
            {
                "lesson_id": "program:program_example:bola_idor:file_id:export:boost",
                "playbook_id": "bola_idor",
                "surface_pattern": "file_id:export",
                "recommendation": "boost",
                "action": "applied",
                "source_signal_count": 2,
                "source_signal_ids": sorted(signal_ids),
                "reasons": ["lesson:boost:accepted_strong_evidence"],
            }
        ]
    finally:
        app.dependency_overrides.clear()


def test_mythos_pipeline_single_accepted_learning_does_not_boost_hunter_priority():
    app.dependency_overrides[get_session] = override_session()
    try:
        baseline_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope: api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert baseline_response.status_code == 200
        baseline_assessment = baseline_response.json()["hunter_intelligence"]["assessments"][0]

        signal_response = client.post(
            "/mythos/brain/learning-signals",
            json={
                "program_id": "program_example",
                "playbook_id": "bola_idor",
                "outcome": "accepted",
                "surface_key": "file_id:export",
                "notes": "One accepted signal is not enough to form a boost lesson.",
                "evidence_quality": "strong",
            },
        )
        assert signal_response.status_code == 200

        learned_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope: api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )

        assert learned_response.status_code == 200
        learned_assessment = learned_response.json()["hunter_intelligence"]["assessments"][0]

        assert (
            learned_assessment["hunter_priority_score"]
            == baseline_assessment["hunter_priority_score"]
        )
        assert "learning:accepted_history" not in learned_assessment["reasons"]
        learning_stage = {
            stage["name"]: stage for stage in learned_response.json()["timeline"]
        }["program_learning"]
        assert "learning:lesson_not_ready" in learning_stage["output_summary"]
    finally:
        app.dependency_overrides.clear()


def test_mythos_pipeline_weak_accepted_learning_does_not_boost_hunter_priority():
    app.dependency_overrides[get_session] = override_session()
    try:
        baseline_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope: api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert baseline_response.status_code == 200
        baseline_assessment = baseline_response.json()["hunter_intelligence"]["assessments"][0]

        signal_response = client.post(
            "/mythos/brain/learning-signals",
            json={
                "program_id": "program_example",
                "playbook_id": "bola_idor",
                "outcome": "accepted",
                "surface_key": "file_id:export",
                "notes": "Accepted outcome came from a generic reviewed run fact.",
                "evidence_quality": "weak",
            },
        )
        assert signal_response.status_code == 200

        learned_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope: api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )

        assert learned_response.status_code == 200
        learned_body = learned_response.json()
        learned_assessment = learned_body["hunter_intelligence"]["assessments"][0]
        by_name = {stage["name"]: stage for stage in learned_body["timeline"]}
        learning_stage = by_name["program_learning"]

        assert learned_assessment["playbook_id"] == "bola_idor"
        assert (
            learned_assessment["hunter_priority_score"]
            == baseline_assessment["hunter_priority_score"]
        )
        assert "learning:accepted_history" not in learned_assessment["reasons"]
        assert learning_stage["status"] == "skipped"
        assert "learning:weak_accepted_evidence_not_boosted" in learning_stage["output_summary"]
        assert "advisory_memory_only" in learning_stage["safety_notes"]
    finally:
        app.dependency_overrides.clear()


def test_mythos_pipeline_learning_boost_does_not_raise_blocked_hunter_priority():
    app.dependency_overrides[get_session] = override_session()
    try:
        for index in range(2):
            signal_response = client.post(
                "/mythos/brain/learning-signals",
                json={
                    "program_id": "program_example",
                    "playbook_id": "bola_idor",
                    "outcome": "accepted",
                    "surface_key": "file_id:export",
                    "notes": f"Prior BOLA file export report {index} was accepted.",
                    "evidence_quality": "strong",
                },
            )
            assert signal_response.status_code == 200

        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "staging.example.com",
                "policy_text": "In scope: api.example.com. Out of scope: staging.example.com.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )

        assert response.status_code == 200
        assessment = response.json()["hunter_intelligence"]["assessments"][0]

        assert response.json()["scope_rule"]["scope_status"] == "out_of_scope"
        assert response.json()["refutation"]["status"] == "blocked"
        assert assessment["recommendation"] == "blocked"
        assert assessment["hunter_priority_score"] == 0
        assert "learning:accepted_history" not in assessment["reasons"]
        by_name = {stage["name"]: stage for stage in response.json()["timeline"]}
        learning_stage = by_name["program_learning"]
        assert learning_stage["status"] == "skipped"
        assert "learning:safety_gate_blocked" in learning_stage["output_summary"]
        assert "no_execution_permission" in learning_stage["safety_notes"]
    finally:
        app.dependency_overrides.clear()


def test_mythos_pipeline_learning_penalty_does_not_change_blocked_hunter_scores():
    app.dependency_overrides[get_session] = override_session()
    try:
        signal_response = client.post(
            "/mythos/brain/learning-signals",
            json={
                "program_id": "program_example",
                "playbook_id": "bola_idor",
                "outcome": "duplicate",
                "surface_key": "file_id:export",
                "notes": "Prior BOLA file export report was marked duplicate.",
            },
        )
        assert signal_response.status_code == 200

        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "staging.example.com",
                "policy_text": "In scope: api.example.com. Out of scope: staging.example.com.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )

        assert response.status_code == 200
        assessment = response.json()["hunter_intelligence"]["assessments"][0]
        by_name = {stage["name"]: stage for stage in response.json()["timeline"]}
        learning_stage = by_name["program_learning"]

        assert assessment["recommendation"] == "blocked"
        assert assessment["hunter_priority_score"] == 0
        assert assessment["duplicate_risk_score"] == 42
        assert "learning:duplicate_history" not in assessment["reasons"]
        assert learning_stage["status"] == "skipped"
        assert "learning:safety_gate_blocked" in learning_stage["output_summary"]
    finally:
        app.dependency_overrides.clear()


def test_artifact_repository_filters_by_provenance_ref_and_fact_type():
    app.dependency_overrides[get_session] = override_session()
    try:
        file_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert file_response.status_code == 200

        invite_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/teams/{team_id}/invite": {
                            "post": {"operationId": "inviteMember"},
                        }
                    }
                },
            },
        )
        assert invite_response.status_code == 200

        filtered_response = client.get(
            "/mythos/artifacts",
            params={
                "provenance_ref": "openapi.paths./files/{file_id}/export.get",
                "fact_type": "sensitive_action",
            },
        )

        assert filtered_response.status_code == 200
        artifacts = filtered_response.json()
        assert [artifact["id"] for artifact in artifacts] == [
            file_response.json()["artifact"]["artifact_id"]
        ]
        assert artifacts[0]["derived_facts"]["sensitive_actions"][0]["provenance_edges"][0] == {
            "ref": "openapi.paths./files/{file_id}/export.get",
            "source_type": "openapi",
            "stage": "target_model",
            "source_path": "/files/{file_id}/export",
            "source_method": "get",
            "fact_type": "sensitive_action",
        }
    finally:
        app.dependency_overrides.clear()


def test_artifact_repository_persists_path_object_relationship_facts():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/orgs/{org_id}/teams/{team_id}/files/{file_id}/export": {
                            "get": {"operationId": "exportTeamFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200

        filtered_response = client.get(
            "/mythos/artifacts",
            params={
                "provenance_ref": (
                    "openapi.paths./orgs/{org_id}/teams/{team_id}/files/"
                    "{file_id}/export"
                ),
                "fact_type": "object_relationship",
            },
        )

        assert filtered_response.status_code == 200
        artifacts = filtered_response.json()
        assert [artifact["id"] for artifact in artifacts] == [
            response.json()["artifact"]["artifact_id"]
        ]
        assert artifacts[0]["payload_summary"]["relationship_count"] == 2
        assert artifacts[0]["derived_facts"]["relationships"] == [
            {
                "parent_object": "org_id",
                "child_object": "team_id",
                "relationship": "contains",
                "path": "/orgs/{org_id}/teams/{team_id}/files/{file_id}/export",
                "provenance_refs": [
                    (
                        "openapi.paths./orgs/{org_id}/teams/{team_id}/files/"
                        "{file_id}/export"
                    )
                ],
                "provenance_edges": [
                    {
                        "ref": (
                            "openapi.paths./orgs/{org_id}/teams/{team_id}/files/"
                            "{file_id}/export"
                        ),
                        "source_type": "openapi",
                        "stage": "target_model",
                        "source_path": "/orgs/{org_id}/teams/{team_id}/files/{file_id}/export",
                        "source_method": None,
                        "fact_type": "object_relationship",
                    }
                ],
            },
            {
                "parent_object": "team_id",
                "child_object": "file_id",
                "relationship": "contains",
                "path": "/orgs/{org_id}/teams/{team_id}/files/{file_id}/export",
                "provenance_refs": [
                    (
                        "openapi.paths./orgs/{org_id}/teams/{team_id}/files/"
                        "{file_id}/export"
                    )
                ],
                "provenance_edges": [
                    {
                        "ref": (
                            "openapi.paths./orgs/{org_id}/teams/{team_id}/files/"
                            "{file_id}/export"
                        ),
                        "source_type": "openapi",
                        "stage": "target_model",
                        "source_path": "/orgs/{org_id}/teams/{team_id}/files/{file_id}/export",
                        "source_method": None,
                        "fact_type": "object_relationship",
                    }
                ],
            },
        ]
    finally:
        app.dependency_overrides.clear()


def test_artifact_repository_filters_by_program_asset_source_type_and_status_api():
    app.dependency_overrides[get_session] = override_session()
    try:
        matching_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert matching_response.status_code == 200

        other_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "app.example.com",
                "policy_text": "SECRET POLICY: In scope app.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/teams/{team_id}/invite": {
                            "post": {"operationId": "inviteMember"},
                        }
                    }
                },
            },
        )
        assert other_response.status_code == 200

        filtered_response = client.get(
            "/mythos/artifacts",
            params={
                "program_id": "program_example",
                "asset": "api.example.com",
                "source_type": "dry_run_inline",
                "ingestion_status": "normalized",
            },
        )

        assert filtered_response.status_code == 200
        assert [artifact["id"] for artifact in filtered_response.json()] == [
            matching_response.json()["artifact"]["artifact_id"]
        ]
    finally:
        app.dependency_overrides.clear()


def test_artifact_repository_filters_by_usage_type_and_run_api():
    app.dependency_overrides[get_session] = override_session()
    try:
        file_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert file_response.status_code == 200

        invite_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/teams/{team_id}/invite": {
                            "post": {"operationId": "inviteMember"},
                        }
                    }
                },
            },
        )
        assert invite_response.status_code == 200

        filtered_response = client.get(
            "/mythos/artifacts",
            params={
                "usage_type": "report_claim",
                "usage_run_id": file_response.json()["run_id"],
            },
        )
        missing_usage_response = client.get(
            "/mythos/artifacts",
            params={"usage_type": "finding_candidate"},
        )

        assert filtered_response.status_code == 200
        assert [artifact["id"] for artifact in filtered_response.json()] == [
            file_response.json()["artifact"]["artifact_id"]
        ]
        assert all(
            any(
                usage["usage_type"] == "report_claim"
                and usage["run_id"] == file_response.json()["run_id"]
                for usage in artifact["usage_records"]
            )
            for artifact in filtered_response.json()
        )
        assert missing_usage_response.status_code == 200
        assert missing_usage_response.json() == []
    finally:
        app.dependency_overrides.clear()


def test_artifact_repository_filters_by_safety_metadata_api():
    app.dependency_overrides[get_session] = override_session()
    try:
        clean_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "In scope: api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert clean_response.status_code == 200

        sensitive_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "In scope: api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export/sk-proj-derived-secret": {
                            "get": {"operationId": "exportFileWithSecretMarker"},
                        }
                    }
                },
            },
        )
        assert sensitive_response.status_code == 200

        filtered_response = client.get(
            "/mythos/artifacts",
            params={
                "sensitivity_label": "sensitive",
                "redaction_status": "redacted",
                "report_chain_allowed": "false",
            },
        )
        safe_response = client.get(
            "/mythos/artifacts",
            params={
                "sensitivity_label": "low",
                "report_chain_allowed": "true",
            },
        )

        assert filtered_response.status_code == 200
        sensitive_artifacts = filtered_response.json()
        assert [artifact["id"] for artifact in sensitive_artifacts] == [
            sensitive_response.json()["artifact"]["artifact_id"]
        ]
        assert sensitive_artifacts[0]["sensitivity_label"] == "sensitive"
        assert sensitive_artifacts[0]["redaction_status"] == "redacted"
        assert sensitive_artifacts[0]["report_chain_allowed"] is False
        assert sensitive_artifacts[0]["safety_blockers"] == ["contains_secret_like_value"]
        assert sensitive_artifacts[0]["provenance"]["safety"] == {
            "sensitivity_label": "sensitive",
            "redaction_status": "redacted",
            "report_chain_allowed": False,
            "safety_blockers": ["contains_secret_like_value"],
        }
        detail_response = client.get(
            f"/mythos/artifacts/{sensitive_response.json()['artifact']['artifact_id']}"
        )
        assert detail_response.status_code == 200
        assert detail_response.json()["sensitivity_label"] == "sensitive"
        assert detail_response.json()["report_chain_allowed"] is False
        assert safe_response.status_code == 200
        safe_artifacts = safe_response.json()
        assert [artifact["id"] for artifact in safe_artifacts] == [
            clean_response.json()["artifact"]["artifact_id"]
        ]
        assert safe_artifacts[0]["sensitivity_label"] == "low"
        assert safe_artifacts[0]["redaction_status"] == "clean"
        assert safe_artifacts[0]["report_chain_allowed"] is True
        assert safe_artifacts[0]["safety_blockers"] == []
    finally:
        app.dependency_overrides.clear()


def test_pipeline_run_report_preview_separates_fact_reasoning_and_unverified_claims():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )

        assert response.status_code == 200
        run_id = response.json()["run_id"]

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        preview = preview_response.json()
        serialized_preview = str(preview)

        assert preview["run_id"] == run_id
        assert preview["title"] == response.json()["report_draft"]["title"]
        assert preview["human_review_required"] is True
        assert preview["submission_blocked"] is True
        assert preview["sections"]["observed_facts"]
        assert preview["sections"]["model_reasoning"]
        assert preview["sections"]["unverified_claims"]
        assert preview["claim_labels"]["observed_facts"] == "observed_fact"
        assert preview["claim_labels"]["model_reasoning"] == "model_reasoning"
        assert preview["claim_labels"]["unverified_claims"] == "unverified_claim"
        assert "SECRET POLICY" not in serialized_preview
        assert "policy_text" not in serialized_preview
    finally:
        app.dependency_overrides.clear()


def test_report_preview_includes_claim_ledger_with_readiness_gates():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )

        assert response.status_code == 200
        run_id = response.json()["run_id"]

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        preview = preview_response.json()
        ledger = preview["claim_ledger"]

        assert ledger
        assert {claim["claim_type"] for claim in ledger} >= {
            "observed_fact",
            "model_reasoning",
            "unverified_claim",
        }
        assert any(
            claim["claim_type"] == "observed_fact"
            and claim["evidence_refs"]
            and claim["provenance_refs"]
            for claim in ledger
        )

        for claim in ledger:
            assert claim["claim_id"].startswith("claim_")
            assert claim["text"]
            assert claim["status"] != "report_ready"
            assert claim["redaction_status"] == "redacted"
            assert claim["human_review_required"] is True
            assert claim["readiness_blockers"]

        assert all(
            claim["status"] != "report_ready"
            for claim in ledger
            if claim["claim_type"] in {"model_reasoning", "unverified_claim"}
        )
        assert any("human_review_required" in claim["readiness_blockers"] for claim in ledger)

        serialized_preview = str(preview)
        assert "SECRET POLICY" not in serialized_preview
        assert "policy_text" not in serialized_preview
        assert "Bearer" not in serialized_preview
        assert "sk-" not in serialized_preview
    finally:
        app.dependency_overrides.clear()


def test_report_preview_claim_ledger_uses_artifact_target_provenance():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        ledger = preview_response.json()["claim_ledger"]
        observed_claim = next(
            claim for claim in ledger if claim["claim_type"] == "observed_fact"
        )
        model_claim = next(
            claim for claim in ledger if claim["claim_type"] == "model_reasoning"
        )
        unverified_claim = next(
            claim for claim in ledger if claim["claim_type"] == "unverified_claim"
        )

        assert response.json()["artifact"]["artifact_id"] in observed_claim["provenance_refs"]
        assert "openapi.paths./files/{file_id}/export" in observed_claim["provenance_refs"]
        assert "openapi.paths./files/{file_id}/export.get" in model_claim["provenance_refs"]
        assert response.json()["artifact"]["artifact_id"] in unverified_claim["provenance_refs"]
        assert "report_draft" in unverified_claim["provenance_refs"]
        assert "hypothesis_engine" in model_claim["provenance_refs"]
        assert {
            edge["ref"]
            for edge in observed_claim["provenance_edges"]
        } >= {
            "openapi.paths./files/{file_id}/export",
            "openapi.paths./files/{file_id}/export.get",
        }
        assert model_claim["provenance_edges"][0]["stage"] == "target_model"
        assert model_claim["provenance_edges"][0]["fact_type"] in {
            "endpoint",
            "object",
            "sensitive_action",
        }
    finally:
        app.dependency_overrides.clear()


def test_report_preview_claim_ledger_includes_object_relationship_provenance():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/orgs/{org_id}/teams/{team_id}/files/{file_id}/export": {
                            "get": {"operationId": "exportTeamFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        observed_claim = next(
            claim
            for claim in preview_response.json()["claim_ledger"]
            if claim["claim_type"] == "observed_fact"
        )

        relationship_edges = [
            edge
            for edge in observed_claim["provenance_edges"]
            if edge["fact_type"] == "object_relationship"
        ]
        assert relationship_edges == [
            {
                "ref": (
                    "openapi.paths./orgs/{org_id}/teams/{team_id}/files/"
                    "{file_id}/export"
                ),
                "source_type": "openapi",
                "stage": "target_model",
                "source_path": "/orgs/{org_id}/teams/{team_id}/files/{file_id}/export",
                "source_method": None,
                "fact_type": "object_relationship",
            }
        ]
    finally:
        app.dependency_overrides.clear()


def test_report_preview_scores_claim_quality_without_unblocking_submission():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        preview = preview_response.json()
        observed_claim = next(
            claim for claim in preview["claim_ledger"] if claim["claim_type"] == "observed_fact"
        )
        model_claim = next(
            claim for claim in preview["claim_ledger"] if claim["claim_type"] == "model_reasoning"
        )
        unverified_claim = next(
            claim for claim in preview["claim_ledger"] if claim["claim_type"] == "unverified_claim"
        )

        assert observed_claim["quality_score"] > model_claim["quality_score"]
        assert model_claim["quality_score"] >= unverified_claim["quality_score"]
        assert observed_claim["readiness_level"] == "needs_human_review"
        assert model_claim["readiness_level"] == "model_reasoning_only"
        assert unverified_claim["readiness_level"] == "unverified_claim"
        assert "type:observed_fact" in observed_claim["quality_reasons"]
        assert "has_evidence_refs" in observed_claim["quality_reasons"]
        assert "has_provenance_refs" in observed_claim["quality_reasons"]
        assert "gate:human_review_required" in observed_claim["quality_reasons"]
        assert preview["submission_blocked"] is True
        assert observed_claim["status"] != "report_ready"
    finally:
        app.dependency_overrides.clear()


def test_report_preview_blocks_claims_backed_by_report_chain_blocked_artifact():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export/sk-proj-derived-secret": {
                            "get": {"operationId": "exportFileWithSecretMarker"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")

        assert preview_response.status_code == 200
        preview = preview_response.json()
        observed_claim = next(
            claim for claim in preview["claim_ledger"] if claim["claim_type"] == "observed_fact"
        )
        unverified_claim = next(
            claim for claim in preview["claim_ledger"] if claim["claim_type"] == "unverified_claim"
        )

        assert preview["submission_blocked"] is True
        assert "artifact_report_chain_blocked" in observed_claim["readiness_blockers"]
        assert "artifact_report_chain_blocked" in unverified_claim["readiness_blockers"]
        assert "gate:artifact_report_chain_blocked" in observed_claim["quality_reasons"]
        assert observed_claim["redaction_status"] == "redacted"
    finally:
        app.dependency_overrides.clear()


def test_report_chain_blocked_claim_cannot_promote_to_finding_candidate():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export/sk-proj-derived-secret": {
                            "get": {"operationId": "exportFileWithSecretMarker"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        body = response.json()
        run_id = body["run_id"]
        artifact_id = body["artifact"]["artifact_id"]
        assert body["artifact"]["report_chain_allowed"] is False

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        observed_claim = next(
            claim
            for claim in preview_response.json()["claim_ledger"]
            if claim["claim_type"] == "observed_fact"
        )
        assert "artifact_report_chain_blocked" in observed_claim["readiness_blockers"]

        decision_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/claim-review-decisions",
            json={
                "claim_id": observed_claim["claim_id"],
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Confirmed only from sanitized fixture.",
                "evidence_refs": ["sanitized_request_response"],
            },
        )
        assert decision_response.status_code == 200

        reviewed_preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert reviewed_preview_response.status_code == 200
        reviewed_claim = next(
            claim
            for claim in reviewed_preview_response.json()["claim_ledger"]
            if claim["claim_id"] == observed_claim["claim_id"]
        )
        assert reviewed_claim["quality_score"] >= 80
        assert "artifact_report_chain_blocked" in reviewed_claim["readiness_blockers"]

        candidate_response = client.post(f"/mythos/pipeline/runs/{run_id}/finding-candidates")

        assert candidate_response.status_code == 422
        assert candidate_response.json()["detail"] == "No claim is ready for candidate promotion"

        artifact_response = client.get(f"/mythos/artifacts/{artifact_id}")
        assert artifact_response.status_code == 200
        assert all(
            usage["usage_type"] != "finding_candidate"
            for usage in artifact_response.json()["usage_records"]
        )
    finally:
        app.dependency_overrides.clear()


def test_report_preview_keeps_claim_ledger_human_gated_even_when_payload_claims_approved():
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

    app.dependency_overrides[get_session] = _override_get_session
    try:
        with testing_session() as session:
            record = DatabaseRepository(session).save_pipeline_run(
                asset="api.example.com",
                policy_text="SECRET POLICY: In scope api.example.com. Automation limited.",
                scope_status="in_scope",
                hypothesis_count=1,
                blocked_count=0,
                report_title="Optimistic draft",
                payload={
                    "report_draft": {
                        "title": "Optimistic draft",
                        "severity": "medium",
                        "scope_status": "in_scope",
                        "actual_result": "Actual result was observed in a safe fixture.",
                        "human_review_required": False,
                        "safety_notes": ["human_review_required"],
                    },
                    "validation_gate": {"status": "approved"},
                    "evidence_bundle": {"items": [{"type": "sanitized_request_response"}]},
                    "hypotheses": [{"hypothesis": "Candidate authorization bypass."}],
                    "invariants": [{"invariant": "Private files require owner access."}],
                    "timeline": [{"name": "validation_gate", "status": "approved"}],
                },
            )

        preview_response = client.get(f"/mythos/pipeline/runs/{record.id}/report-preview")

        assert preview_response.status_code == 200
        preview = preview_response.json()

        assert preview["submission_blocked"] is True
        assert all(claim["status"] != "report_ready" for claim in preview["claim_ledger"])
        assert all(claim["human_review_required"] is True for claim in preview["claim_ledger"])
        assert any(
            "human_review_required" in claim["readiness_blockers"]
            for claim in preview["claim_ledger"]
        )
        assert "SECRET POLICY" not in str(preview)
    finally:
        app.dependency_overrides.clear()


def test_claim_review_decision_is_recorded_on_report_preview_without_unblocking_submission():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        claim_id = next(
            claim["claim_id"]
            for claim in preview_response.json()["claim_ledger"]
            if claim["claim_type"] == "observed_fact"
        )

        decision_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/claim-review-decisions",
            json={
                "claim_id": claim_id,
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Authorization: Bearer live-token; observed in sanitized fixture.",
                "evidence_refs": ["sanitized_request_response"],
            },
        )
        assert decision_response.status_code == 200
        decision = decision_response.json()
        assert decision["claim_id"] == claim_id
        assert decision["rationale"] == "[REDACTED]"
        assert decision["reviewer"] == "lead_reviewer"
        assert decision["reviewed_at"]

        updated_preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert updated_preview_response.status_code == 200
        updated_preview = updated_preview_response.json()
        reviewed_claim = next(
            claim for claim in updated_preview["claim_ledger"] if claim["claim_id"] == claim_id
        )

        assert updated_preview["submission_blocked"] is True
        assert reviewed_claim["status"] != "report_ready"
        assert reviewed_claim["review_status"] == "confirmed_observed_fact"
        assert reviewed_claim["reviewer"] == "lead_reviewer"
        assert reviewed_claim["review_rationale"] == "[REDACTED]"
        assert reviewed_claim["review_evidence_refs"] == ["sanitized_request_response"]
        artifact_id = response.json()["artifact"]["artifact_id"]
        artifact_response = client.get(f"/mythos/artifacts/{artifact_id}")
        assert artifact_response.status_code == 200
        artifact_usage_records = artifact_response.json()["usage_records"]
        review_usage = next(
            usage
            for usage in artifact_usage_records
            if usage["usage_type"] == "claim_review_decision"
        )
        assert review_usage == {
            "usage_type": "claim_review_decision",
            "ref": f"claim_review:{claim_id}",
            "run_id": run_id,
            "stage": "report_review",
            "claim_id": claim_id,
            "decision": "confirmed_observed_fact",
            "reviewer": "lead_reviewer",
            "reviewed_at": decision["reviewed_at"],
            "evidence_refs": ["sanitized_request_response"],
        }
        assert "Authorization" not in str(review_usage)
        assert "observed in sanitized fixture" not in str(review_usage)
        serialized_preview = str(updated_preview)
        assert "SECRET POLICY" not in serialized_preview
        assert "Bearer" not in serialized_preview
        assert "live-token" not in serialized_preview
    finally:
        app.dependency_overrides.clear()


def test_claim_review_decision_improves_claim_quality_but_keeps_submission_blocked():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        observed_claim = next(
            claim
            for claim in preview_response.json()["claim_ledger"]
            if claim["claim_type"] == "observed_fact"
        )

        decision_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/claim-review-decisions",
            json={
                "claim_id": observed_claim["claim_id"],
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Confirmed using sanitized fixture.",
                "evidence_refs": ["sanitized_request_response"],
            },
        )
        assert decision_response.status_code == 200

        updated_preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert updated_preview_response.status_code == 200
        updated_preview = updated_preview_response.json()
        reviewed_claim = next(
            claim
            for claim in updated_preview["claim_ledger"]
            if claim["claim_id"] == observed_claim["claim_id"]
        )

        assert reviewed_claim["quality_score"] > observed_claim["quality_score"]
        assert reviewed_claim["readiness_level"] == "human_reviewed_gated"
        assert "review:confirmed_observed_fact" in reviewed_claim["quality_reasons"]
        assert "review:evidence_refs" in reviewed_claim["quality_reasons"]
        assert reviewed_claim["status"] != "report_ready"
        assert updated_preview["submission_blocked"] is True
    finally:
        app.dependency_overrides.clear()


def test_unreviewed_claim_cannot_promote_to_finding_candidate():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        observed_claim = next(
            claim
            for claim in preview_response.json()["claim_ledger"]
            if claim["claim_type"] == "observed_fact"
        )
        assert observed_claim["review_status"] == "unreviewed"
        assert observed_claim["quality_score"] >= 80

        candidate_response = client.post(f"/mythos/pipeline/runs/{run_id}/finding-candidates")

        assert candidate_response.status_code == 422
        assert candidate_response.json()["detail"] == "No claim is ready for candidate promotion"
    finally:
        app.dependency_overrides.clear()


def test_redacted_only_review_evidence_cannot_promote_to_finding_candidate():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]
        claim_id = next(
            claim["claim_id"]
            for claim in client.get(f"/mythos/pipeline/runs/{run_id}/report-preview").json()[
                "claim_ledger"
            ]
            if claim["claim_type"] == "observed_fact"
        )

        decision_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/claim-review-decisions",
            json={
                "claim_id": claim_id,
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Confirmed with a sensitive value that must not enter reports.",
                "evidence_refs": ["Authorization: Bearer live-token"],
            },
        )
        assert decision_response.status_code == 200

        reviewed_preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert reviewed_preview_response.status_code == 200
        reviewed_claim = next(
            claim
            for claim in reviewed_preview_response.json()["claim_ledger"]
            if claim["claim_id"] == claim_id
        )
        assert reviewed_claim["review_evidence_refs"] == ["[REDACTED]"]
        assert reviewed_claim["quality_score"] >= 80
        assert "review:evidence_refs" not in reviewed_claim["quality_reasons"]

        candidate_response = client.post(f"/mythos/pipeline/runs/{run_id}/finding-candidates")

        assert candidate_response.status_code == 422
        assert candidate_response.json()["detail"] == "No claim is ready for candidate promotion"
    finally:
        app.dependency_overrides.clear()


def test_generic_reviewed_run_fact_cannot_promote_to_finding_candidate():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]
        claim_id = next(
            claim["claim_id"]
            for claim in client.get(f"/mythos/pipeline/runs/{run_id}/report-preview").json()[
                "claim_ledger"
            ]
            if claim["claim_type"] == "observed_fact"
        )

        decision_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/claim-review-decisions",
            json={
                "claim_id": claim_id,
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Confirmed with sanitized fixture.",
                "evidence_refs": ["sanitized_request_response"],
            },
        )
        assert decision_response.status_code == 200

        candidate_response = client.post(f"/mythos/pipeline/runs/{run_id}/finding-candidates")

        assert candidate_response.status_code == 422
        assert candidate_response.json()["detail"] == "No claim is ready for candidate promotion"
    finally:
        app.dependency_overrides.clear()


def test_pipeline_run_can_promote_impact_observation_to_finding_candidate_without_validation():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]
        claim_id = next(
            claim["claim_id"]
            for claim in client.get(f"/mythos/pipeline/runs/{run_id}/report-preview").json()[
                "claim_ledger"
            ]
            if claim["claim_type"] == "observed_fact"
        )

        observation_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/manual-observations",
            json={
                "claim_id": claim_id,
                "observation_type": "request_response_diff",
                "observer": "lead_reviewer",
                "observation": "Safe test-account diff showed an authorization boundary.",
                "evidence_refs": ["sanitized_request_response"],
                "safety_notes": ["test_accounts_only", "no_real_user_data"],
            },
        )
        assert observation_response.status_code == 200

        decision_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/claim-review-decisions",
            json={
                "claim_id": claim_id,
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Confirmed with sanitized fixture.",
                "evidence_refs": ["sanitized_request_response"],
            },
        )
        assert decision_response.status_code == 200

        reviewed_preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert reviewed_preview_response.status_code == 200
        reviewed_claim = next(
            claim
            for claim in reviewed_preview_response.json()["claim_ledger"]
            if claim["claim_id"] == claim_id
        )
        assert "has_security_impact_observation" in reviewed_claim["quality_reasons"]
        assert "missing_security_impact_observation" not in reviewed_claim["readiness_blockers"]

        candidate_response = client.post(f"/mythos/pipeline/runs/{run_id}/finding-candidates")

        assert candidate_response.status_code == 200
        candidate = candidate_response.json()
        assert candidate["id"].startswith("finding_candidate_")
        assert candidate["program"] == "Example Program"
        assert candidate["asset"] == "api.example.com"
        assert candidate["validation_status"] == "validation_plan_ready"
        assert candidate["submission_recommendation"] == "promote_to_finding_candidate"
        assert candidate["evidence_refs"] == ["sanitized_request_response"]
        assert "hunter_recommendation:needs_human_review" in candidate["operating_reasons"]
        assert "claim_quality:high" in candidate["operating_reasons"]
        assert 0 < candidate["confidence"] < 1

        findings_response = client.get("/findings")
        assert findings_response.status_code == 200
        assert any(item["id"] == candidate["id"] for item in findings_response.json())
        assert candidate["submission_recommendation"] != "report_ready"

        artifact_id = response.json()["artifact"]["artifact_id"]
        artifact_response = client.get(f"/mythos/artifacts/{artifact_id}")
        assert artifact_response.status_code == 200
        artifact_usage_records = artifact_response.json()["usage_records"]
        finding_usage = next(
            usage
            for usage in artifact_usage_records
            if usage["usage_type"] == "finding_candidate"
        )
        assert finding_usage == {
            "usage_type": "finding_candidate",
            "ref": f"finding_candidate:{candidate['id']}",
            "run_id": run_id,
            "stage": "finding_promotion",
            "claim_id": claim_id,
            "finding_id": candidate["id"],
            "submission_recommendation": "promote_to_finding_candidate",
            "evidence_refs": ["sanitized_request_response"],
        }
        assert candidate["title"] not in str(finding_usage)
        assert candidate["broken_invariant"] not in str(finding_usage)

        filtered_response = client.get(
            "/mythos/artifacts",
            params={
                "usage_type": "finding_candidate",
                "usage_run_id": run_id,
            },
        )
        assert filtered_response.status_code == 200
        assert [artifact["id"] for artifact in filtered_response.json()] == [artifact_id]
    finally:
        app.dependency_overrides.clear()


def test_report_preview_surfaces_impact_observations_as_observed_facts():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        claim_id = next(
            claim["claim_id"]
            for claim in preview_response.json()["claim_ledger"]
            if claim["claim_type"] == "observed_fact"
        )

        observation_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/manual-observations",
            json={
                "claim_id": claim_id,
                "observation_type": "request_response_diff",
                "observer": "lead_reviewer",
                "observation": "Cross-account test returned 403 for the unauthorized request.",
                "evidence_refs": [
                    "sanitized_cross_account_diff",
                    "Authorization: Bearer live-token",
                ],
                "safety_notes": ["test_accounts_only", "no_real_user_data"],
            },
        )
        assert observation_response.status_code == 200

        updated_preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")

        assert updated_preview_response.status_code == 200
        updated_preview = updated_preview_response.json()
        assert (
            "Security impact observation request_response_diff was recorded for "
            f"{claim_id} with evidence sanitized_cross_account_diff."
        ) in updated_preview["sections"]["observed_facts"]
        assert "live-token" not in str(updated_preview)
        assert "Authorization" not in str(updated_preview)
    finally:
        app.dependency_overrides.clear()


def test_boundary_matrix_observation_becomes_finding_promotion_reason():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/orgs/{org_id}/teams/{team_id}/files/{file_id}/export": {
                            "get": {"operationId": "exportTeamFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]
        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        claim_id = next(
            claim["claim_id"]
            for claim in preview_response.json()["claim_ledger"]
            if claim["claim_type"] == "observed_fact"
        )

        observation_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/manual-observations",
            json={
                "claim_id": claim_id,
                "observation_type": "role_matrix_observation",
                "observer": "lead_reviewer",
                "observation": "Safe test-account matrix checked org, team, and file boundaries.",
                "evidence_refs": ["sanitized_parent_child_matrix"],
                "safety_notes": ["test_accounts_only", "no_real_user_data"],
            },
        )
        assert observation_response.status_code == 200

        decision_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/claim-review-decisions",
            json={
                "claim_id": claim_id,
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Confirmed from sanitized parent-child authorization matrix.",
                "evidence_refs": ["sanitized_parent_child_matrix"],
            },
        )
        assert decision_response.status_code == 200

        reviewed_preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert reviewed_preview_response.status_code == 200
        reviewed_claim = next(
            claim
            for claim in reviewed_preview_response.json()["claim_ledger"]
            if claim["claim_id"] == claim_id
        )
        assert "has_security_impact_observation" in reviewed_claim["quality_reasons"]
        assert "has_boundary_matrix_observation" in reviewed_claim["quality_reasons"]
        assert "missing_security_impact_observation" not in reviewed_claim["readiness_blockers"]

        candidate_response = client.post(f"/mythos/pipeline/runs/{run_id}/finding-candidates")

        assert candidate_response.status_code == 200
        candidate = candidate_response.json()
        assert candidate["submission_recommendation"] == "promote_to_finding_candidate"
        assert candidate["evidence_refs"] == ["sanitized_parent_child_matrix"]
        assert "claim_quality:boundary_matrix_observed" in candidate["operating_reasons"]
        assert "target_relationship:org_id>team_id>file_id" in candidate["operating_reasons"]
        assert "Safe test-account matrix" not in str(candidate)
    finally:
        app.dependency_overrides.clear()


def test_pipeline_run_detail_exposes_closed_loop_summary_after_candidate_learning():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        claim_id = next(
            claim["claim_id"]
            for claim in preview_response.json()["claim_ledger"]
            if claim["claim_type"] == "observed_fact"
        )

        observation_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/manual-observations",
            json={
                "claim_id": claim_id,
                "observation_type": "request_response_diff",
                "observer": "lead_reviewer",
                "observation": "Safe test-account diff confirmed the authorization boundary.",
                "evidence_refs": ["sanitized_request_response"],
                "safety_notes": ["test_accounts_only", "no_real_user_data"],
            },
        )
        assert observation_response.status_code == 200

        review_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/claim-review-decisions",
            json={
                "claim_id": claim_id,
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Confirmed with sanitized evidence.",
                "evidence_refs": ["sanitized_request_response"],
            },
        )
        assert review_response.status_code == 200

        candidate_response = client.post(f"/mythos/pipeline/runs/{run_id}/finding-candidates")
        assert candidate_response.status_code == 200
        candidate = candidate_response.json()
        assert candidate["validation_status"] == "validation_plan_ready"
        assert candidate["submission_recommendation"] == "promote_to_finding_candidate"

        outcome_response = client.post(
            "/mythos/brain/outcomes",
            json={
                "run_id": run_id,
                "outcome": "accepted",
                "notes": "Outcome recorded from the safe fixture loop.",
                "bounty_amount": 500,
                "severity_delta": "up",
            },
        )
        assert outcome_response.status_code == 200
        profile = outcome_response.json()
        assert profile["learning_summary"]["accepted_count"] == 1
        assert profile["learning_summary"]["strong_evidence_count"] == 1

        detail_response = client.get(f"/mythos/pipeline/runs/{run_id}")
        assert detail_response.status_code == 200
        detail = detail_response.json()
        summary = detail["payload"]["closed_loop_summary"]

        assert summary == {
            "status": "candidate_learning_recorded",
            "manual_observation_count": 1,
            "reviewed_claim_count": 1,
            "finding_candidate_count": 1,
            "learning_signal_count": 1,
            "lesson_count": 0,
            "brain_memory_status": "learning_recorded",
            "memory_lessons": [],
            "blocked_reasons": [],
            "safety_notes": [
                "no_live_requests",
                "test_accounts_only",
                "human_review_required",
                "candidate_not_validated",
            ],
            "steps": [
                {
                    "key": "manual_observation",
                    "label": "Manual Observation",
                    "status": "complete",
                    "reason": "1 sanitized manual observation recorded.",
                    "safety_gate": "test_accounts_only",
                    "next_allowed_action": "Review the observed claim against redacted evidence.",
                },
                {
                    "key": "claim_review",
                    "label": "Claim Review",
                    "status": "complete",
                    "reason": "1 claim review decision recorded.",
                    "safety_gate": "human_review_required",
                    "next_allowed_action": "Promote eligible observed claims to finding candidates.",
                },
                {
                    "key": "finding_candidate",
                    "label": "Finding Candidate",
                    "status": "complete",
                    "reason": "1 finding candidate created.",
                    "safety_gate": "candidate_not_validated",
                    "next_allowed_action": "Record an advisory learning outcome without changing validation state.",
                },
                {
                    "key": "learning_signal",
                    "label": "Learning Signal",
                    "status": "complete",
                    "reason": "1 learning signal linked to this run.",
                    "safety_gate": "advisory_memory_only",
                    "next_allowed_action": "Refresh the Mythos Brain profile for future prioritization.",
                },
                {
                    "key": "brain_memory",
                    "label": "Brain Memory",
                    "status": "waiting",
                    "reason": "Learning signal is recorded; reusable lesson needs more evidence.",
                    "safety_gate": "no_execution_permission",
                    "next_allowed_action": "Record another corroborating outcome before advisory lesson use.",
                },
            ],
        }
        assert "Safe test-account diff" not in str(summary)
        assert "SECRET POLICY" not in str(detail)

        artifact_id = response.json()["artifact"]["artifact_id"]
        artifact_response = client.get(f"/mythos/artifacts/{artifact_id}")
        assert artifact_response.status_code == 200
        usage_records = artifact_response.json()["usage_records"]
        assert any(usage["usage_type"] == "finding_candidate" for usage in usage_records)
        assert any(usage["usage_type"] == "learning_signal" for usage in usage_records)
        assert "Safe test-account diff" not in str(usage_records)
    finally:
        app.dependency_overrides.clear()


def test_pipeline_run_detail_marks_brain_memory_complete_when_lesson_is_ready():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]

        signal_ids = []
        for index in range(2):
            outcome_response = client.post(
                "/mythos/brain/outcomes",
                json={
                    "run_id": run_id,
                    "outcome": "accepted",
                    "notes": f"Accepted safe fixture outcome {index}.",
                    "evidence_quality": "strong",
                },
            )
            assert outcome_response.status_code == 200
            signal_ids.append(outcome_response.json()["recent_learning_signals"][0]["id"])

        detail_response = client.get(f"/mythos/pipeline/runs/{run_id}")
        assert detail_response.status_code == 200
        summary = detail_response.json()["payload"]["closed_loop_summary"]
        brain_step = next(
            step for step in summary["steps"] if step["key"] == "brain_memory"
        )

        assert summary["learning_signal_count"] == 2
        assert summary["lesson_count"] == 1
        assert summary["status"] == "brain_memory_ready"
        assert summary["brain_memory_status"] == "lesson_ready"
        assert summary["memory_lessons"] == [
            {
                "lesson_id": "program:program_example:bola_idor:file_id:export:boost",
                "scope_type": "program",
                "scope_key": "program_example",
                "playbook_id": "bola_idor",
                "surface_pattern": "file_id:export",
                "recommendation": "boost",
                "confidence": 76,
                "source_signal_count": 2,
                "source_signal_ids": sorted(signal_ids),
                "reasons": ["lesson:boost:accepted_strong_evidence"],
                "safety_notes": [
                    "advisory_memory_only",
                    "human_review_required",
                    "no_live_requests",
                    "no_real_user_data",
                    "scope_guard_wins",
                    "test_accounts_only",
                ],
            }
        ]
        assert "Accepted safe fixture outcome" not in str(summary["memory_lessons"])
        assert brain_step == {
            "key": "brain_memory",
            "label": "Brain Memory",
            "status": "complete",
            "reason": "1 reusable advisory lesson available for future prioritization.",
            "safety_gate": "no_execution_permission",
            "next_allowed_action": "Use lesson memory as advisory context only.",
        }

        list_response = client.get("/mythos/pipeline/runs")
        assert list_response.status_code == 200
        list_summary = next(
            run for run in list_response.json() if run["id"] == run_id
        )
        assert list_summary["closed_loop_summary"]["status"] == "brain_memory_ready"
        assert list_summary["closed_loop_summary"]["lesson_count"] == 1
    finally:
        app.dependency_overrides.clear()


def test_pipeline_run_detail_blocks_closed_loop_when_reviewed_claim_is_not_promotable():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        claim_id = next(
            claim["claim_id"]
            for claim in preview_response.json()["claim_ledger"]
            if claim["claim_type"] == "observed_fact"
        )

        review_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/claim-review-decisions",
            json={
                "claim_id": claim_id,
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Confirmed, but the supplied evidence ref is unsafe.",
                "evidence_refs": ["Authorization: Bearer raw-token"],
            },
        )
        assert review_response.status_code == 200
        assert review_response.json()["evidence_refs"] == ["[REDACTED]"]

        detail_response = client.get(f"/mythos/pipeline/runs/{run_id}")
        assert detail_response.status_code == 200
        summary = detail_response.json()["payload"]["closed_loop_summary"]

        assert summary["status"] == "blocked"
        assert summary["reviewed_claim_count"] == 1
        assert summary["finding_candidate_count"] == 0
        assert summary["blocked_reasons"] == ["no_promotion_eligible_claim"]
        assert summary["steps"][0]["status"] == "waiting"
        assert summary["steps"][0]["next_allowed_action"] == "Record a sanitized manual observation."
        assert summary["steps"][1]["status"] == "blocked"
        assert summary["steps"][1]["reason"] == "Reviewed claim is not promotion eligible."
        assert summary["steps"][1]["safety_gate"] == "no_promotion_eligible_claim"
        assert summary["steps"][2]["status"] == "blocked"
        assert summary["steps"][2]["next_allowed_action"] == "Resolve blockers before promotion."
    finally:
        app.dependency_overrides.clear()


def test_pipeline_run_detail_and_list_expose_evidence_support_summary():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        preview = preview_response.json()

        detail_response = client.get(f"/mythos/pipeline/runs/{run_id}")
        assert detail_response.status_code == 200
        detail_summary = detail_response.json()["payload"]["evidence_support_summary"]

        assert detail_summary["total_count"] == len(preview["claim_ledger"])
        assert detail_summary["missing_required_count"] >= 1
        assert detail_summary["partially_supported_count"] >= 1
        assert detail_summary["satisfied_human_gated_count"] == 0
        assert detail_summary["unsafe_or_redacted_requirement_count"] == 0
        assert detail_summary["top_support_status"] == "missing_required_evidence"
        assert detail_summary["status_counts"]["missing_required_evidence"] >= 1
        assert detail_summary["safety_notes"] == [
            "claim_ledger_derived",
            "advisory_only",
            "human_review_required",
            "no_submission_unblock",
        ]

        list_response = client.get("/mythos/pipeline/runs")
        assert list_response.status_code == 200
        run_summary = next(run for run in list_response.json() if run["id"] == run_id)
        assert run_summary["evidence_support_summary"] == detail_summary
    finally:
        app.dependency_overrides.clear()


def test_evidence_support_summary_tracks_human_gated_and_redacted_claims():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        claim_id = next(
            claim["claim_id"]
            for claim in preview_response.json()["claim_ledger"]
            if claim["claim_type"] == "observed_fact"
        )

        observation_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/manual-observations",
            json={
                "claim_id": claim_id,
                "observation_type": "request_response_diff",
                "observer": "lead_reviewer",
                "observation": "Safe test-account diff confirmed the authorization boundary.",
                "evidence_refs": ["sanitized_request_response"],
                "safety_notes": ["test_accounts_only", "no_real_user_data"],
            },
        )
        assert observation_response.status_code == 200

        review_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/claim-review-decisions",
            json={
                "claim_id": claim_id,
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Confirmed with sanitized evidence.",
                "evidence_refs": ["sanitized_request_response"],
            },
        )
        assert review_response.status_code == 200

        detail_response = client.get(f"/mythos/pipeline/runs/{run_id}")
        assert detail_response.status_code == 200
        summary = detail_response.json()["payload"]["evidence_support_summary"]

        assert summary["satisfied_human_gated_count"] == 1
        assert summary["top_support_status"] == "human_gated_supported"
        assert summary["status_counts"]["human_gated_supported"] == 1

        unsafe_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/claim-review-decisions",
            json={
                "claim_id": claim_id,
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Confirmed, but the supplied evidence ref is unsafe.",
                "evidence_refs": ["Authorization: Bearer raw-token"],
            },
        )
        assert unsafe_response.status_code == 200

        unsafe_detail_response = client.get(f"/mythos/pipeline/runs/{run_id}")
        assert unsafe_detail_response.status_code == 200
        unsafe_summary = unsafe_detail_response.json()["payload"]["evidence_support_summary"]

        assert unsafe_summary["unsafe_or_redacted_requirement_count"] == 1
        assert unsafe_summary["top_support_status"] == "unsafe_or_redacted_evidence"
        assert unsafe_summary["status_counts"]["unsafe_or_redacted_evidence"] == 1
    finally:
        app.dependency_overrides.clear()


def test_validation_workspace_exposes_claim_tasks_and_promotion_eligibility():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]

        detail_response = client.get(f"/mythos/pipeline/runs/{run_id}")

        assert detail_response.status_code == 200
        workspace = detail_response.json()["payload"]["validation_workspace"]
        observed_task = next(
            task
            for task in workspace["claim_validation_tasks"]
            if task["claim_type"] == "observed_fact"
        )
        assert observed_task["status"] == "needs_security_impact_observation"
        assert observed_task["promotion_eligible"] is False
        assert observed_task["required_observation_types"] == [
            "request_response_diff",
            "role_matrix_observation",
        ]
        assert "missing_security_impact_observation" in observed_task["readiness_blockers"]
        assert "human_review_required" in observed_task["readiness_blockers"]

        claim_id = observed_task["claim_id"]
        observation_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/manual-observations",
            json={
                "claim_id": claim_id,
                "observation_type": "request_response_diff",
                "observer": "lead_reviewer",
                "observation": "Safe cross-account diff showed an authorization boundary.",
                "evidence_refs": ["sanitized_request_response"],
                "safety_notes": ["test_accounts_only", "no_real_user_data"],
            },
        )
        assert observation_response.status_code == 200

        review_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/claim-review-decisions",
            json={
                "claim_id": claim_id,
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Confirmed with sanitized impact evidence.",
                "evidence_refs": ["sanitized_request_response"],
            },
        )
        assert review_response.status_code == 200

        updated_detail_response = client.get(f"/mythos/pipeline/runs/{run_id}")

        assert updated_detail_response.status_code == 200
        updated_workspace = updated_detail_response.json()["payload"]["validation_workspace"]
        updated_task = next(
            task
            for task in updated_workspace["claim_validation_tasks"]
            if task["claim_id"] == claim_id
        )
        assert updated_task["status"] == "promotion_eligible"
        assert updated_task["promotion_eligible"] is True
        assert updated_task["required_observation_types"] == []
        assert updated_task["review_status"] == "confirmed_observed_fact"
        assert "missing_security_impact_observation" not in updated_task["readiness_blockers"]
        assert updated_task["evidence_refs"] == ["request_response_diff", "sanitized_request_response"]
        assert "Safe cross-account diff" not in str(updated_task)
    finally:
        app.dependency_overrides.clear()


def test_validation_workspace_claim_tasks_include_relationship_boundary_focus():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/orgs/{org_id}/teams/{team_id}/files/{file_id}/export": {
                            "get": {"operationId": "exportTeamFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]

        detail_response = client.get(f"/mythos/pipeline/runs/{run_id}")

        assert detail_response.status_code == 200
        workspace = detail_response.json()["payload"]["validation_workspace"]
        observed_task = next(
            task
            for task in workspace["claim_validation_tasks"]
            if task["claim_type"] == "observed_fact"
        )

        assert observed_task["status"] == "needs_boundary_matrix_observation"
        assert observed_task["relationship_contexts"] == ["org_id>team_id>file_id"]
        assert observed_task["evidence_focus"] == ["parent_child_authorization_matrix"]
        assert "role_matrix_observation" in observed_task["required_observation_types"]
        assert "request_response_diff" in observed_task["required_observation_types"]
        assert observed_task["execution_allowed"] is False
        assert "test_accounts_only" in observed_task["safety_notes"]
        assert "SECRET POLICY" not in str(observed_task)
    finally:
        app.dependency_overrides.clear()


def test_claim_review_decision_rejects_unknown_claim_id():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "In scope api.example.com. Automation limited.",
                "openapi": {"paths": {"/files/{file_id}/export": {"get": {}}}},
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]

        decision_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/claim-review-decisions",
            json={
                "claim_id": "claim_missing_1",
                "decision": "refuted",
                "reviewer": "lead_reviewer",
                "rationale": "No matching claim.",
            },
        )

        assert decision_response.status_code == 404
        assert decision_response.json()["detail"] == "Claim not found"
    finally:
        app.dependency_overrides.clear()


def test_manual_observation_is_recorded_in_validation_workspace_with_claim_mapping():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        claim_id = next(
            claim["claim_id"]
            for claim in preview_response.json()["claim_ledger"]
            if claim["claim_type"] == "observed_fact"
        )

        observation_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/manual-observations",
            json={
                "claim_id": claim_id,
                "observation_type": "manual_observation",
                "observer": "lead_reviewer",
                "observation": "Observed a safe fixture response using test accounts only.",
                "evidence_refs": [
                    "sanitized_response_403",
                    "Authorization: Bearer live-token",
                ],
                "safety_notes": ["test_accounts_only", "no_real_user_data"],
            },
        )
        assert observation_response.status_code == 200
        observation = observation_response.json()

        assert observation["observation_id"].startswith("manual_observation_")
        assert observation["claim_id"] == claim_id
        assert observation["observer"] == "lead_reviewer"
        assert observation["evidence_refs"] == ["sanitized_response_403", "[REDACTED]"]
        assert observation["redaction_status"] == "redacted"
        assert observation["execution_allowed"] is False
        assert observation["report_chain_blocked"] is True

        detail_response = client.get(f"/mythos/pipeline/runs/{run_id}")
        assert detail_response.status_code == 200
        detail = detail_response.json()
        workspace = detail["payload"]["validation_workspace"]
        workspace_observation = workspace["manual_observations"][0]

        assert workspace["allowed_to_execute"] is False
        assert workspace_observation["claim_id"] == claim_id
        assert workspace_observation["observation_type"] == "manual_observation"
        assert workspace_observation["evidence_refs"] == ["sanitized_response_403", "[REDACTED]"]
        assert workspace_observation["report_chain_blocked"] is True

        updated_preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert updated_preview_response.status_code == 200
        updated_preview = updated_preview_response.json()
        observed_claim = next(
            claim for claim in updated_preview["claim_ledger"] if claim["claim_id"] == claim_id
        )
        assert updated_preview["submission_blocked"] is True
        assert "sanitized_response_403" in observed_claim["evidence_refs"]
        assert "[REDACTED]" not in observed_claim["evidence_refs"]
        assert "has_manual_observation" in observed_claim["quality_reasons"]
        assert all(claim["status"] != "report_ready" for claim in updated_preview["claim_ledger"])
        assert "Observed a safe fixture response" not in str(updated_preview)

        artifact_id = response.json()["artifact"]["artifact_id"]
        artifact_response = client.get(f"/mythos/artifacts/{artifact_id}")
        assert artifact_response.status_code == 200
        artifact_usage_records = artifact_response.json()["usage_records"]
        manual_observation_usage = next(
            usage
            for usage in artifact_usage_records
            if usage["usage_type"] == "manual_observation"
        )
        assert manual_observation_usage == {
            "usage_type": "manual_observation",
            "ref": f"manual_observation:{observation['observation_id']}",
            "run_id": run_id,
            "stage": "validation_workspace",
            "claim_id": claim_id,
            "observation_id": observation["observation_id"],
            "observation_type": "manual_observation",
            "evidence_refs": ["sanitized_response_403", "[REDACTED]"],
            "safety_notes": ["test_accounts_only", "no_real_user_data"],
        }
        assert "Observed a safe fixture response" not in str(manual_observation_usage)

        serialized_detail = str(detail)
        assert "SECRET POLICY" not in serialized_detail
        assert "Bearer" not in serialized_detail
        assert "live-token" not in serialized_detail
    finally:
        app.dependency_overrides.clear()


def test_manual_observation_with_only_redacted_evidence_does_not_count_as_safe_evidence():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "SECRET POLICY: In scope api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile"},
                        }
                    }
                },
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        claim_id = next(
            claim["claim_id"]
            for claim in preview_response.json()["claim_ledger"]
            if claim["claim_type"] == "observed_fact"
        )

        observation_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/manual-observations",
            json={
                "claim_id": claim_id,
                "observation_type": "manual_observation",
                "observer": "lead_reviewer",
                "observation": "Authorization: Bearer live-token",
                "evidence_refs": ["Authorization: Bearer live-token"],
                "safety_notes": ["test_accounts_only"],
            },
        )
        assert observation_response.status_code == 200
        observation = observation_response.json()
        assert observation["observation"] == "[REDACTED]"
        assert observation["evidence_refs"] == ["[REDACTED]"]

        updated_preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert updated_preview_response.status_code == 200
        updated_preview = updated_preview_response.json()
        observed_claim = next(
            claim for claim in updated_preview["claim_ledger"] if claim["claim_id"] == claim_id
        )

        assert "[REDACTED]" not in observed_claim["evidence_refs"]
        assert "has_manual_observation" not in observed_claim["quality_reasons"]
        assert "manual_observation_missing_safe_evidence" in observed_claim["quality_reasons"]
        assert "Bearer" not in str(updated_preview)
        assert "live-token" not in str(updated_preview)

        workspace_response = client.get(f"/mythos/pipeline/runs/{run_id}")
        assert workspace_response.status_code == 200
        workspace = workspace_response.json()["payload"]["validation_workspace"]
        observed_task = next(
            task
            for task in workspace["claim_validation_tasks"]
            if task["claim_id"] == claim_id
        )
        assert observed_task["status"] == "needs_report_safe_evidence"
        assert "manual_observation_missing_safe_evidence" in observed_task["readiness_blockers"]
        assert "request_response_diff" in observed_task["required_observation_types"]

        artifact_id = response.json()["artifact"]["artifact_id"]
        artifact_response = client.get(f"/mythos/artifacts/{artifact_id}")
        assert artifact_response.status_code == 200
        manual_observation_usage = next(
            usage
            for usage in artifact_response.json()["usage_records"]
            if usage["usage_type"] == "manual_observation"
        )
        assert manual_observation_usage["evidence_refs"] == ["[REDACTED]"]
        assert "Authorization" not in str(manual_observation_usage)
        assert "live-token" not in str(manual_observation_usage)
    finally:
        app.dependency_overrides.clear()


def test_manual_observation_rejects_unknown_claim_id():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "In scope api.example.com. Automation limited.",
                "openapi": {"paths": {"/files/{file_id}/export": {"get": {}}}},
            },
        )
        assert response.status_code == 200
        run_id = response.json()["run_id"]

        observation_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/manual-observations",
            json={
                "claim_id": "claim_missing_1",
                "observation_type": "manual_observation",
                "observer": "lead_reviewer",
                "observation": "No matching claim.",
            },
        )

        assert observation_response.status_code == 404
        assert observation_response.json()["detail"] == "Claim not found"
    finally:
        app.dependency_overrides.clear()


def test_report_preview_safe_string_list_redacts_secret_like_values():
    assert _safe_string_list(
        [
            "Authorization: Bearer live-token",
            "sk-proj-secret",
            "alice@example.com",
            "session=live-cookie-value",
            (
                "eyJhbGciOiJIUzI1NiJ9."
                "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
            ),
            "customer data appeared in response body",
            "artifact_digest:abc123",
        ]
    ) == [
        "[REDACTED]",
        "[REDACTED]",
        "[REDACTED]",
        "[REDACTED]",
        "[REDACTED]",
        "[REDACTED]",
        "artifact_digest:abc123",
    ]


def test_pipeline_run_detail_redacts_secret_like_derived_payload_values():
    app.dependency_overrides[get_session] = override_session()
    try:
        secret_path = "/files/{file_id}/export/sk-proj-derived-secret"
        response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "asset": "api.example.com",
                "policy_text": "In scope: api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        secret_path: {
                            "get": {
                                "operationId": "Authorization: Bearer derived-live-token",
                            },
                        }
                    }
                },
            },
        )

        assert response.status_code == 200
        detail_response = client.get(f"/mythos/pipeline/runs/{response.json()['run_id']}")

        assert detail_response.status_code == 200
        serialized_detail = str(detail_response.json())
        assert "sk-proj-derived-secret" not in serialized_detail
        assert "derived-live-token" not in serialized_detail
        assert "[REDACTED]" in serialized_detail
    finally:
        app.dependency_overrides.clear()
