from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_session
from app.main import app
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


def test_learning_signal_repository_persists_program_feedback():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()
    try:
        repository = DatabaseRepository(session)

        saved = repository.save_learning_signal(
            program_id="program_example",
            playbook_id="bola_idor",
            outcome="accepted",
            surface_key="file_id:export",
            notes="Accepted with bounty.",
        )
        signals = repository.list_learning_signals("program_example")

        assert saved.id.startswith("learning_signal_")
        assert saved.program_id == "program_example"
        assert saved.outcome == "accepted"
        assert saved.surface_key == "file_id:export"
        assert signals[0].id == saved.id
    finally:
        session.close()


def test_learning_signal_repository_persists_evidence_context_safely():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()
    try:
        repository = DatabaseRepository(session)

        saved = repository.save_learning_signal(
            program_id="program_example",
            playbook_id="bola_idor",
            outcome="accepted",
            surface_key="file_id:export",
            notes="Accepted with bounty.",
            bounty_amount=3000,
            severity_delta="up",
            evidence_quality="strong",
            triager_feedback="Authorization: Bearer live-token; clear evidence.",
        )
        signals = repository.list_learning_signals("program_example")

        assert saved.bounty_amount == 3000
        assert saved.severity_delta == "up"
        assert saved.evidence_quality == "strong"
        assert saved.triager_feedback == "[REDACTED]"
        assert signals[0].triager_feedback == "[REDACTED]"
    finally:
        session.close()


def test_learning_signal_repository_persists_target_relationships_safely():
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()
    try:
        repository = DatabaseRepository(session)

        saved = repository.save_learning_signal(
            program_id="program_example",
            playbook_id="bola_idor",
            outcome="accepted",
            surface_key="file_id:export",
            notes="Accepted with boundary matrix evidence.",
            target_relationships=[
                "org_id>team_id>file_id",
                "Authorization: Bearer live-token",
            ],
        )
        signals = repository.list_learning_signals("program_example")

        assert saved.target_relationships == [
            "org_id>team_id>file_id",
            "[REDACTED]",
        ]
        assert signals[0].target_relationships == saved.target_relationships
    finally:
        session.close()


def test_mythos_brain_api_builds_profile_from_runs_and_learning_signals():
    app.dependency_overrides[get_session] = override_session()
    try:
        dry_run_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope: api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile", "tags": ["member"]},
                        }
                    }
                },
            },
        )
        assert dry_run_response.status_code == 200

        signal_response = client.post(
            "/mythos/brain/learning-signals",
            json={
                "program_id": "program_example",
                "playbook_id": "bola_idor",
                "outcome": "accepted",
                "surface_key": "file_id:export",
                "notes": "Accepted BOLA report; bounty paid.",
            },
        )
        assert signal_response.status_code == 200
        signal = signal_response.json()
        assert signal["id"].startswith("learning_signal_")
        assert signal["program_id"] == "program_example"
        assert signal["created_at"]

        profile_response = client.get("/mythos/brain/programs/program_example")
        assert profile_response.status_code == 200
        profile = profile_response.json()

        assert profile["program_id"] == "program_example"
        assert profile["program_score"] >= 80
        assert profile["attack_surface_memory"]["objects"] == ["file_id"]
        assert profile["attack_surface_memory"]["sensitive_actions"][0]["action"] == "export"
        assert profile["high_value_surfaces"][0]["surface_key"] == "file_id:export"
        assert profile["learning_summary"]["accepted_count"] == 1
        assert profile["recent_learning_signals"][0]["outcome"] == "accepted"
        assert "no_live_requests" in profile["safety_notes"]
    finally:
        app.dependency_overrides.clear()


def test_mythos_brain_outcome_intake_derives_signal_from_run_and_returns_updated_profile():
    app.dependency_overrides[get_session] = override_session()
    try:
        dry_run_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope: api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile", "tags": ["member"]},
                        }
                    }
                },
            },
        )
        assert dry_run_response.status_code == 200
        run_id = dry_run_response.json()["run_id"]

        outcome_response = client.post(
            "/mythos/brain/outcomes",
            json={
                "run_id": run_id,
                "outcome": "accepted",
                "notes": "Authorization: Bearer live-token; triager confirmed impact.",
            },
        )

        assert outcome_response.status_code == 200
        profile = outcome_response.json()
        signal = profile["recent_learning_signals"][0]

        assert profile["program_id"] == "program_example"
        assert profile["learning_summary"]["accepted_count"] == 1
        assert profile["learning_summary"]["boosted_playbooks"] == ["bola_idor"]
        assert profile["high_value_surfaces"][0]["surface_key"] == "file_id:export"
        assert signal["outcome"] == "accepted"
        assert signal["playbook_id"] == "bola_idor"
        assert signal["surface_key"] == "file_id:export"
        assert signal["notes"] == "[REDACTED]"
        assert "advisory_memory_only" in profile["safety_notes"]
    finally:
        app.dependency_overrides.clear()


def test_mythos_brain_outcome_intake_accepts_evidence_context_and_redacts_feedback():
    app.dependency_overrides[get_session] = override_session()
    try:
        dry_run_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope: api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile", "tags": ["member"]},
                        }
                    }
                },
            },
        )
        assert dry_run_response.status_code == 200
        run_id = dry_run_response.json()["run_id"]

        outcome_response = client.post(
            "/mythos/brain/outcomes",
            json={
                "run_id": run_id,
                "outcome": "accepted",
                "bounty_amount": 3000,
                "severity_delta": "up",
                "evidence_quality": "strong",
                "triager_feedback": "Authorization: Bearer live-token; great evidence.",
            },
        )

        assert outcome_response.status_code == 200
        profile = outcome_response.json()
        signal = profile["recent_learning_signals"][0]

        assert profile["learning_summary"]["bounty_total"] == 3000
        assert profile["learning_summary"]["strong_evidence_count"] == 1
        assert "learning:bounty_paid" in profile["high_value_surfaces"][0]["reasons"]
        assert "learning:strong_evidence" in profile["high_value_surfaces"][0]["reasons"]
        assert "learning:severity_up" in profile["high_value_surfaces"][0]["reasons"]
        assert signal["bounty_amount"] == 3000
        assert signal["severity_delta"] == "up"
        assert signal["evidence_quality"] == "strong"
        assert signal["triager_feedback"] == "[REDACTED]"
        assert "advisory_memory_only" in profile["safety_notes"]

        artifact_id = dry_run_response.json()["artifact"]["artifact_id"]
        artifact_response = client.get(f"/mythos/artifacts/{artifact_id}")
        assert artifact_response.status_code == 200
        learning_usage = next(
            usage
            for usage in artifact_response.json()["usage_records"]
            if usage["usage_type"] == "learning_signal"
        )
        assert learning_usage == {
            "usage_type": "learning_signal",
            "ref": f"learning_signal:{signal['id']}",
            "run_id": run_id,
            "stage": "mythos_brain",
            "learning_signal_id": signal["id"],
            "outcome": "accepted",
            "playbook_id": "bola_idor",
            "surface_key": "file_id:export",
            "bounty_amount": 3000,
            "severity_delta": "up",
            "evidence_quality": "strong",
        }
        assert "Authorization" not in str(learning_usage)
        assert "great evidence" not in str(learning_usage)
    finally:
        app.dependency_overrides.clear()


def test_mythos_brain_outcome_intake_infers_strong_evidence_from_impact_reviewed_claim():
    app.dependency_overrides[get_session] = override_session()
    try:
        dry_run_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope: api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile", "tags": ["member"]},
                        }
                    }
                },
            },
        )
        assert dry_run_response.status_code == 200
        run_id = dry_run_response.json()["run_id"]

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
                "observation": "Safe test-account diff showed an authorization boundary.",
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
                "rationale": "Confirmed with sanitized fixture.",
                "evidence_refs": ["sanitized_request_response"],
            },
        )
        assert review_response.status_code == 200

        outcome_response = client.post(
            "/mythos/brain/outcomes",
            json={
                "run_id": run_id,
                "outcome": "accepted",
            },
        )

        assert outcome_response.status_code == 200
        profile = outcome_response.json()
        signal = profile["recent_learning_signals"][0]

        assert signal["evidence_quality"] == "strong"
        assert profile["learning_summary"]["strong_evidence_count"] == 1
        assert "learning:strong_evidence" in profile["high_value_surfaces"][0]["reasons"]
    finally:
        app.dependency_overrides.clear()


def test_mythos_brain_outcome_intake_infers_weak_evidence_from_generic_reviewed_claim():
    app.dependency_overrides[get_session] = override_session()
    try:
        dry_run_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope: api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile", "tags": ["member"]},
                        }
                    }
                },
            },
        )
        assert dry_run_response.status_code == 200
        run_id = dry_run_response.json()["run_id"]

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
                "rationale": "Confirmed the pipeline run fact only.",
                "evidence_refs": ["sanitized_request_response"],
            },
        )
        assert review_response.status_code == 200

        outcome_response = client.post(
            "/mythos/brain/outcomes",
            json={
                "run_id": run_id,
                "outcome": "accepted",
            },
        )

        assert outcome_response.status_code == 200
        profile = outcome_response.json()
        signal = profile["recent_learning_signals"][0]

        assert signal["evidence_quality"] == "weak"
        assert profile["learning_summary"]["weak_evidence_count"] == 1
        assert profile["learning_summary"]["strong_evidence_count"] == 0
        assert "learning:weak_evidence" in profile["high_value_surfaces"][0]["reasons"]
        assert "learning:strong_evidence" not in profile["high_value_surfaces"][0]["reasons"]
    finally:
        app.dependency_overrides.clear()


def test_mythos_brain_outcome_intake_infers_weak_evidence_from_claim_needing_evidence():
    app.dependency_overrides[get_session] = override_session()
    try:
        dry_run_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope: api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile", "tags": ["member"]},
                        }
                    }
                },
            },
        )
        assert dry_run_response.status_code == 200
        run_id = dry_run_response.json()["run_id"]

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
                "decision": "needs_evidence",
                "reviewer": "lead_reviewer",
                "rationale": "Manual check did not prove cross-account impact yet.",
            },
        )
        assert review_response.status_code == 200

        outcome_response = client.post(
            "/mythos/brain/outcomes",
            json={
                "run_id": run_id,
                "outcome": "informative",
            },
        )

        assert outcome_response.status_code == 200
        profile = outcome_response.json()
        signal = profile["recent_learning_signals"][0]

        assert signal["evidence_quality"] == "weak"
        assert profile["learning_summary"]["weak_evidence_count"] == 1
        assert "learning:weak_evidence" in profile["high_value_surfaces"][0]["reasons"]
    finally:
        app.dependency_overrides.clear()


def test_mythos_brain_outcome_intake_infers_adequate_evidence_from_provenance_backed_claim():
    app.dependency_overrides[get_session] = override_session()
    try:
        dry_run_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope: api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        "/files/{file_id}/export": {
                            "get": {"operationId": "exportFile", "tags": ["member"]},
                        }
                    }
                },
            },
        )
        assert dry_run_response.status_code == 200
        run_id = dry_run_response.json()["run_id"]

        preview_response = client.get(f"/mythos/pipeline/runs/{run_id}/report-preview")
        assert preview_response.status_code == 200
        observed_claim = next(
            claim
            for claim in preview_response.json()["claim_ledger"]
            if claim["claim_type"] == "observed_fact"
        )
        assert observed_claim["provenance_edges"]

        observation_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/manual-observations",
            json={
                "claim_id": observed_claim["claim_id"],
                "observation_type": "role_matrix_observation",
                "observer": "lead_reviewer",
                "observation": "Safe role matrix check showed a protected boundary.",
                "evidence_refs": ["sanitized_role_matrix"],
                "safety_notes": ["test_accounts_only", "no_real_user_data"],
            },
        )
        assert observation_response.status_code == 200

        review_response = client.post(
            f"/mythos/pipeline/runs/{run_id}/claim-review-decisions",
            json={
                "claim_id": observed_claim["claim_id"],
                "decision": "confirmed_observed_fact",
                "reviewer": "lead_reviewer",
                "rationale": "Confirmed from the run timeline and source provenance.",
            },
        )
        assert review_response.status_code == 200

        outcome_response = client.post(
            "/mythos/brain/outcomes",
            json={
                "run_id": run_id,
                "outcome": "accepted",
            },
        )

        assert outcome_response.status_code == 200
        profile = outcome_response.json()
        signal = profile["recent_learning_signals"][0]

        assert signal["evidence_quality"] == "adequate"
        assert profile["learning_summary"]["adequate_evidence_count"] == 1
        assert "learning:adequate_evidence" in profile["high_value_surfaces"][0]["reasons"]
    finally:
        app.dependency_overrides.clear()


def test_mythos_brain_outcome_persists_target_relationship_context():
    app.dependency_overrides[get_session] = override_session()
    try:
        path = "/orgs/{org_id}/teams/{team_id}/files/{file_id}/export"
        dry_run_response = client.post(
            "/mythos/pipeline/dry-run",
            json={
                "program_id": "program_example",
                "asset": "api.example.com",
                "policy_text": "In scope: api.example.com. Automation limited.",
                "openapi": {
                    "paths": {
                        path: {
                            "get": {"operationId": "exportTeamFile", "tags": ["member"]},
                        }
                    }
                },
            },
        )
        assert dry_run_response.status_code == 200
        run_id = dry_run_response.json()["run_id"]

        outcome_response = client.post(
            "/mythos/brain/outcomes",
            json={
                "run_id": run_id,
                "outcome": "accepted",
                "evidence_quality": "strong",
            },
        )

        assert outcome_response.status_code == 200
        profile = outcome_response.json()
        signal = profile["recent_learning_signals"][0]

        assert signal["surface_key"] == "file_id:export"
        assert signal["target_relationships"] == ["org_id>team_id>file_id"]
        assert "target_relationship:org_id>team_id>file_id" in profile["high_value_surfaces"][0]["reasons"]

        artifact_id = dry_run_response.json()["artifact"]["artifact_id"]
        artifact_response = client.get(f"/mythos/artifacts/{artifact_id}")
        assert artifact_response.status_code == 200
        learning_usage = next(
            usage
            for usage in artifact_response.json()["usage_records"]
            if usage["usage_type"] == "learning_signal"
        )
        assert learning_usage["target_relationships"] == ["org_id>team_id>file_id"]
    finally:
        app.dependency_overrides.clear()


def test_mythos_brain_api_returns_404_for_unknown_program():
    app.dependency_overrides[get_session] = override_session()
    try:
        response = client.get("/mythos/brain/programs/missing_program")

        assert response.status_code == 404
        assert response.json()["detail"] == "Program not found"
    finally:
        app.dependency_overrides.clear()
