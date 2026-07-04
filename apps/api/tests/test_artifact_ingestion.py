from app.artifact_ingestion import (
    NormalizedArtifact,
    normalize_artifact,
    normalize_har,
    normalize_openapi,
    normalize_postman,
)
import app.artifact_ingestion as artifact_ingestion
from app.provenance import openapi_operation_edge
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
            provenance_refs=["openapi.paths./orgs/{org_id}/users.get"],
            provenance_edges=[
                openapi_operation_edge(
                    "/orgs/{org_id}/users",
                    "get",
                    fact_type="endpoint",
                )
            ],
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


def test_normalize_notes_extracts_endpoint_mentions_for_target_model():
    notes = {
        "text": """
        Test account A can call GET /files/{file_id}/export.
        Admin review is needed before POST /teams/{team_id}/invite.
        Ignore https://api.example.com/static/logo.png because no method was named.
        """
    }

    normalized = artifact_ingestion.normalize_notes(notes)

    assert normalized == {
        "paths": {
            "/files/{file_id}/export": {"get": {"operationId": "notes_get_files_file_id_export"}},
            "/teams/{team_id}/invite": {"post": {"operationId": "notes_post_teams_team_id_invite"}},
        }
    }
    target_model = build_target_model(normalized)
    assert [action.action for action in target_model.sensitive_actions] == [
        "export",
        "invite",
    ]


def test_normalize_code_excerpt_extracts_route_decorators():
    code_excerpt = {
        "content": """
        @router.get("/orgs/{org_id}/files/{file_id}/export")
        def export_file(): ...

        app.post('/invoices/{invoice_id}/refund', refund_invoice)
        """
    }

    normalized = artifact_ingestion.normalize_code_excerpt(code_excerpt)

    assert normalized == {
        "paths": {
            "/orgs/{org_id}/files/{file_id}/export": {
                "get": {"operationId": "code_excerpt_get_orgs_org_id_files_file_id_export"}
            },
            "/invoices/{invoice_id}/refund": {
                "post": {"operationId": "code_excerpt_post_invoices_invoice_id_refund"}
            },
        }
    }
    assert [detected.name for detected in build_target_model(normalized).objects] == [
        "file_id",
        "invoice_id",
        "org_id",
    ]


def test_normalize_policy_extracts_endpoint_mentions_without_claiming_scope_completeness():
    policy = {
        "text": """
        In scope: api.example.com.
        Low-risk review may use GET /members/{member_id}/export with test accounts only.
        Do not perform DELETE /members/{member_id}.
        """
    }

    normalized = artifact_ingestion.normalize_policy(policy)

    assert normalized == {
        "paths": {
            "/members/{member_id}/export": {
                "get": {"operationId": "policy_get_members_member_id_export"}
            },
            "/members/{member_id}": {
                "delete": {"operationId": "policy_delete_members_member_id"}
            },
        }
    }


def test_normalize_sarif_extracts_endpoint_mentions_from_messages_and_locations():
    sarif = {
        "runs": [
            {
                "results": [
                    {
                        "message": {
                            "text": "Authorization issue near GET /files/{file_id}/export."
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "src/routes/invoices/{invoice_id}/refund.py"
                                    }
                                }
                            }
                        ],
                    }
                ]
            }
        ]
    }

    normalized = artifact_ingestion.normalize_sarif(sarif)

    assert normalized == {
        "paths": {
            "/files/{file_id}/export": {
                "get": {"operationId": "sarif_get_files_file_id_export"}
            },
            "/routes/invoices/{invoice_id}/refund": {
                "post": {"operationId": "sarif_post_routes_invoices_invoice_id_refund"}
            },
        }
    }


def test_normalize_artifact_dispatches_textual_and_sarif_artifacts():
    assert normalize_artifact(
        "notes",
        {"text": "Review PATCH /workspaces/{workspace_id}/settings."},
    ) == NormalizedArtifact(
        kind="notes",
        openapi_like={
            "paths": {
                "/workspaces/{workspace_id}/settings": {
                    "patch": {"operationId": "notes_patch_workspaces_workspace_id_settings"}
                }
            }
        },
    )
    assert normalize_artifact(
        "sarif",
        {"runs": [{"results": [{"message": {"text": "Check POST /teams/{team_id}/invite"}}]}]},
    ).openapi_like["paths"]["/teams/{team_id}/invite"]["post"]["operationId"] == (
        "sarif_post_teams_team_id_invite"
    )
