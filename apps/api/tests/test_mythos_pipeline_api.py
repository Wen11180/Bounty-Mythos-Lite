from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


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
