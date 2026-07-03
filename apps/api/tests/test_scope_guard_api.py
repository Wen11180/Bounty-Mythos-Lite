from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_scope_guard_api_allows_approved_allowed_validation():
    response = client.post(
        "/scope-guard/evaluate",
        json={
            "rule": {
                "asset": "api.example.com",
                "scope_status": "in_scope",
                "automation": "limited",
                "allowed_validation": ["two_account_authorization_check"],
                "forbidden": ["DoS"],
                "human_approval_required": True,
            },
            "request": {
                "asset": "api.example.com",
                "validation_type": "two_account_authorization_check",
                "human_approved": True,
            },
        },
    )

    assert response.status_code == 200
    assert response.json() == {"allowed": True, "reason": "allowed_validation"}


def test_scope_guard_api_blocks_forbidden_validation():
    response = client.post(
        "/scope-guard/evaluate",
        json={
            "rule": {
                "asset": "api.example.com",
                "scope_status": "in_scope",
                "automation": "limited",
                "allowed_validation": ["two_account_authorization_check"],
                "forbidden": ["DoS"],
                "human_approval_required": False,
            },
            "request": {
                "asset": "api.example.com",
                "validation_type": "DoS",
                "human_approved": False,
            },
        },
    )

    assert response.status_code == 200
    assert response.json() == {"allowed": False, "reason": "forbidden_validation"}
