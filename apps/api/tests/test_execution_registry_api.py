from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_execution_capabilities_endpoint_exposes_only_registered_safe_metadata():
    response = client.get("/mythos/execution-capabilities")

    assert response.status_code == 200
    capabilities = {item["tool_id"]: item for item in response.json()}
    assert {
        "semgrep_local",
        "codeql_local",
        "dependency_sbom_local",
        "two_account_authorization_check",
    } <= set(
        capabilities
    )
    assert capabilities["semgrep_local"]["execution_tier"] == "local"
    assert capabilities["semgrep_local"]["network_access"] is False
    assert capabilities["dependency_sbom_local"]["execution_tier"] == "local"
    assert capabilities["dependency_sbom_local"]["network_access"] is False
    assert capabilities["two_account_authorization_check"]["execution_tier"] == "remote"
    assert capabilities["two_account_authorization_check"]["dispatch_allowed"] is False
    assert all(item["candidate_promotion_allowed"] is False for item in capabilities.values())
    assert all(item["report_submission_allowed"] is False for item in capabilities.values())
