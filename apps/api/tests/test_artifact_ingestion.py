from app.artifact_ingestion import (
    NormalizedArtifact,
    normalize_artifact,
    normalize_har,
    normalize_openapi,
    normalize_postman,
)
from app.target_model import Endpoint, build_target_model


def test_normalize_openapi_preserves_paths_for_target_model():
    openapi = {
        "openapi": "3.0.0",
        "info": {"title": "Example", "version": "1.0.0"},
        "paths": {
            "/orgs/{org_id}/users": {
                "get": {"operationId": "listUsers"},
            }
        },
    }

    normalized = normalize_openapi(openapi)

    assert normalized == {"paths": openapi["paths"]}
    assert build_target_model(normalized).endpoints == [
        Endpoint(
            method="GET",
            path="/orgs/{org_id}/users",
            operation_id="listUsers",
            roles=[],
        )
    ]


def test_normalize_postman_extracts_paths_from_nested_items():
    collection = {
        "item": [
            {
                "name": "Users",
                "item": [
                    {
                        "request": {
                            "method": "GET",
                            "url": {
                                "raw": "https://api.example.com/orgs/{org_id}/users?limit=10",
                            },
                        }
                    },
                    {
                        "request": {
                            "method": "POST",
                            "url": {
                                "path": ["orgs", "{org_id}", "users"],
                            },
                        }
                    },
                ],
            }
        ]
    }

    normalized = normalize_postman(collection)

    assert normalized == {
        "paths": {
            "/orgs/{org_id}/users": {
                "get": {},
                "post": {},
            }
        }
    }
    assert [endpoint.method for endpoint in build_target_model(normalized).endpoints] == [
        "GET",
        "POST",
    ]


def test_normalize_har_extracts_request_paths():
    har = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://api.example.com/files/{file_id}/export?download=1",
                    }
                },
                {
                    "request": {
                        "method": "DELETE",
                        "url": "https://api.example.com/files/{file_id}",
                    }
                },
            ]
        }
    }

    normalized = normalize_har(har)

    assert normalized == {
        "paths": {
            "/files/{file_id}/export": {"get": {}},
            "/files/{file_id}": {"delete": {}},
        }
    }
    assert [endpoint.path for endpoint in build_target_model(normalized).endpoints] == [
        "/files/{file_id}/export",
        "/files/{file_id}",
    ]


def test_normalize_artifact_dispatches_to_normalized_artifact_model():
    collection = {
        "item": [
            {
                "request": {
                    "method": "PATCH",
                    "url": "https://api.example.com/teams/{team_id}",
                }
            }
        ]
    }

    normalized = normalize_artifact("postman", collection)

    assert normalized == NormalizedArtifact(
        kind="postman",
        openapi_like={"paths": {"/teams/{team_id}": {"patch": {}}}},
    )
