from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, get_session
from app.main import app


client = TestClient(app)


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


def test_dry_run_response_and_detail_include_stage_timeline():
    app.dependency_overrides[get_session] = override_session()
    try:
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
        timeline = body["timeline"]
        assert [stage["name"] for stage in timeline] == [
            "policy_ingestion",
            "artifact_normalization",
            "target_model",
            "invariants",
            "hypotheses",
            "refutation",
            "validation_plan",
            "report_draft",
            "evidence",
        ]
        for stage in timeline:
            assert set(stage) == {
                "name",
                "status",
                "input_summary",
                "output_summary",
                "safety_notes",
                "details",
            }
            assert stage["input_summary"]
            assert stage["output_summary"]
            assert isinstance(stage["safety_notes"], list)
            assert stage["details"]["agent_boundary"]["role"]
            assert stage["details"]["agent_boundary"]["allowed_actions"]
            assert "execute_live_validation" in stage["details"]["agent_boundary"]["blocked_actions"]

        by_name = {stage["name"]: stage for stage in timeline}
        assert by_name["refutation"]["status"] == "blocked"
        assert "scope_guard:human_approval_required" in by_name["refutation"]["safety_notes"]
        assert "human_review_required" in by_name["report_draft"]["safety_notes"]
        assert by_name["validation_plan"]["details"]["agent_boundary"]["requires_human_review"] is True

        detail_response = client.get(f"/mythos/pipeline/runs/{body['run_id']}")
        assert detail_response.status_code == 200
        detail = detail_response.json()
        assert detail["payload"]["timeline"] == timeline
    finally:
        app.dependency_overrides.clear()
