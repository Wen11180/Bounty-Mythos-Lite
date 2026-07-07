from app.provenance import openapi_operation_edge, openapi_path_edge
from app.target_model import (
    Endpoint,
    SensitiveAction,
    TargetModel,
    build_target_model,
)


def test_build_target_model_extracts_endpoints_objects_and_roles():
    openapi = {
        "paths": {
            "/orgs/{org_id}/users/{user_id}": {
                "get": {
                    "operationId": "readUser",
                    "tags": ["Admin"],
                    "security": [{"BearerAuth": ["org:admin"]}],
                    "parameters": [
                        {"name": "org_id", "in": "path"},
                        {"name": "user_id", "in": "path"},
                    ],
                },
                "patch": {
                    "operationId": "updateUser",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "team_id": {"type": "string"},
                                        "display_name": {"type": "string"},
                                    },
                                }
                            }
                        }
                    },
                },
            }
        }
    }

    target_model = build_target_model(openapi)

    assert target_model.endpoints == [
        Endpoint(
            method="GET",
            path="/orgs/{org_id}/users/{user_id}",
            operation_id="readUser",
            roles=["admin"],
            provenance_refs=["openapi.paths./orgs/{org_id}/users/{user_id}.get"],
            provenance_edges=[
                openapi_operation_edge(
                    "/orgs/{org_id}/users/{user_id}",
                    "get",
                    fact_type="endpoint",
                )
            ],
        ),
        Endpoint(
            method="PATCH",
            path="/orgs/{org_id}/users/{user_id}",
            operation_id="updateUser",
            roles=[],
            provenance_refs=["openapi.paths./orgs/{org_id}/users/{user_id}.patch"],
            provenance_edges=[
                openapi_operation_edge(
                    "/orgs/{org_id}/users/{user_id}",
                    "patch",
                    fact_type="endpoint",
                )
            ],
        ),
    ]
    assert [detected.name for detected in target_model.objects] == [
        "org_id",
        "team_id",
        "user_id",
    ]
    assert target_model.roles == ["admin"]


def test_build_target_model_ignores_secret_like_role_sources():
    openapi = {
        "paths": {
            "/orgs/{org_id}/users/{user_id}": {
                "get": {
                    "operationId": "readUser",
                    "tags": ["admin_token=sk-proj-derived-secret"],
                    "security": [
                        {
                            "BearerAuth": [
                                "user_token=Authorization: Bearer derived-live-token",
                                "org:member",
                            ]
                        }
                    ],
                },
            },
        },
    }

    target_model = build_target_model(openapi)

    assert target_model.endpoints[0].roles == ["member"]
    assert target_model.roles == ["member"]


def test_build_target_model_labels_sensitive_actions():
    openapi = {
        "paths": {
            "/teams/{team_id}/invite": {
                "post": {"operationId": "inviteMember"},
            },
            "/files/{file_id}/export": {
                "get": {"operationId": "exportFile"},
            },
            "/invoices/{invoice_id}/refund": {
                "post": {"operationId": "refundInvoice"},
            },
            "/files/{file_id}/share": {
                "post": {"operationId": "shareFile"},
            },
            "/files/{file_id}": {
                "delete": {"operationId": "deleteFile"},
            },
        }
    }

    target_model = build_target_model(openapi)

    assert target_model.sensitive_actions == [
        SensitiveAction(
            action="invite",
            method="POST",
            path="/teams/{team_id}/invite",
            operation_id="inviteMember",
            roles=[],
            provenance_refs=["openapi.paths./teams/{team_id}/invite.post"],
            provenance_edges=[
                openapi_operation_edge(
                    "/teams/{team_id}/invite",
                    "post",
                    fact_type="sensitive_action",
                )
            ],
        ),
        SensitiveAction(
            action="export",
            method="GET",
            path="/files/{file_id}/export",
            operation_id="exportFile",
            roles=[],
            provenance_refs=["openapi.paths./files/{file_id}/export.get"],
            provenance_edges=[
                openapi_operation_edge(
                    "/files/{file_id}/export",
                    "get",
                    fact_type="sensitive_action",
                )
            ],
        ),
        SensitiveAction(
            action="refund",
            method="POST",
            path="/invoices/{invoice_id}/refund",
            operation_id="refundInvoice",
            roles=[],
            provenance_refs=["openapi.paths./invoices/{invoice_id}/refund.post"],
            provenance_edges=[
                openapi_operation_edge(
                    "/invoices/{invoice_id}/refund",
                    "post",
                    fact_type="sensitive_action",
                )
            ],
        ),
        SensitiveAction(
            action="share",
            method="POST",
            path="/files/{file_id}/share",
            operation_id="shareFile",
            roles=[],
            provenance_refs=["openapi.paths./files/{file_id}/share.post"],
            provenance_edges=[
                openapi_operation_edge(
                    "/files/{file_id}/share",
                    "post",
                    fact_type="sensitive_action",
                )
            ],
        ),
        SensitiveAction(
            action="delete",
            method="DELETE",
            path="/files/{file_id}",
            operation_id="deleteFile",
            roles=[],
            provenance_refs=["openapi.paths./files/{file_id}.delete"],
            provenance_edges=[
                openapi_operation_edge(
                    "/files/{file_id}",
                    "delete",
                    fact_type="sensitive_action",
                )
            ],
        ),
    ]
    assert [detected.name for detected in target_model.objects] == [
        "file_id",
        "invoice_id",
        "team_id",
    ]


def test_build_target_model_attaches_provenance_refs_to_facts():
    openapi = {
        "paths": {
            "/orgs/{org_id}/files/{file_id}/export": {
                "get": {
                    "operationId": "exportFile",
                    "security": [{"BearerAuth": ["org:admin"]}],
                }
            }
        }
    }

    target_model = build_target_model(openapi)

    assert target_model.endpoints[0].provenance_refs == [
        "openapi.paths./orgs/{org_id}/files/{file_id}/export.get"
    ]
    assert target_model.sensitive_actions[0].provenance_refs == [
        "openapi.paths./orgs/{org_id}/files/{file_id}/export.get"
    ]
    assert {
        detected.name: detected.provenance_refs
        for detected in target_model.objects
    } == {
        "file_id": ["openapi.paths./orgs/{org_id}/files/{file_id}/export"],
        "org_id": ["openapi.paths./orgs/{org_id}/files/{file_id}/export"],
    }


def test_build_target_model_attaches_structured_provenance_edges():
    openapi = {
        "paths": {
            "/files/{file_id}/export": {
                "get": {"operationId": "exportFile"},
            }
        }
    }

    target_model = build_target_model(openapi)

    assert target_model.endpoints[0].provenance_edges[0].model_dump(mode="json") == {
        "ref": "openapi.paths./files/{file_id}/export.get",
        "source_type": "openapi",
        "stage": "target_model",
        "source_path": "/files/{file_id}/export",
        "source_method": "get",
        "fact_type": "endpoint",
    }
    assert target_model.objects[0].provenance_edges[0].model_dump(mode="json") == {
        "ref": "openapi.paths./files/{file_id}/export",
        "source_type": "openapi",
        "stage": "target_model",
        "source_path": "/files/{file_id}/export",
        "source_method": None,
        "fact_type": "object",
    }
    assert target_model.sensitive_actions[0].provenance_edges[0].model_dump(mode="json") == {
        "ref": "openapi.paths./files/{file_id}/export.get",
        "source_type": "openapi",
        "stage": "target_model",
        "source_path": "/files/{file_id}/export",
        "source_method": "get",
        "fact_type": "sensitive_action",
    }


def test_build_target_model_derives_path_object_relationships_with_provenance():
    openapi = {
        "paths": {
            "/orgs/{org_id}/teams/{team_id}/files/{file_id}/export": {
                "get": {"operationId": "exportTeamFile"},
            }
        }
    }

    target_model = build_target_model(openapi)
    payload = target_model.model_dump(mode="json")

    assert "relationships" in payload
    assert payload["relationships"] == [
        {
            "parent_object": "org_id",
            "child_object": "team_id",
            "relationship": "contains",
            "path": "/orgs/{org_id}/teams/{team_id}/files/{file_id}/export",
            "provenance_refs": [
                "openapi.paths./orgs/{org_id}/teams/{team_id}/files/{file_id}/export"
            ],
            "provenance_edges": [
                openapi_path_edge(
                    "/orgs/{org_id}/teams/{team_id}/files/{file_id}/export",
                    fact_type="object_relationship",
                ).model_dump(mode="json")
            ],
        },
        {
            "parent_object": "team_id",
            "child_object": "file_id",
            "relationship": "contains",
            "path": "/orgs/{org_id}/teams/{team_id}/files/{file_id}/export",
            "provenance_refs": [
                "openapi.paths./orgs/{org_id}/teams/{team_id}/files/{file_id}/export"
            ],
            "provenance_edges": [
                openapi_path_edge(
                    "/orgs/{org_id}/teams/{team_id}/files/{file_id}/export",
                    fact_type="object_relationship",
                ).model_dump(mode="json")
            ],
        },
    ]


def test_build_target_model_attaches_operation_edges_to_parameter_and_schema_objects():
    openapi = {
        "paths": {
            "/search/files": {
                "get": {
                    "operationId": "searchFiles",
                    "parameters": [
                        {"name": "workspace_id", "in": "query", "schema": {"type": "string"}},
                    ],
                }
            },
            "/shares": {
                "post": {
                    "operationId": "createShare",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "file_id": {"type": "string"},
                                        "team_id": {"type": "string"},
                                        "context": {
                                            "type": "object",
                                            "properties": {
                                                "org_id": {"type": "string"},
                                            },
                                        },
                                    },
                                }
                            }
                        }
                    },
                }
            },
        }
    }

    target_model = build_target_model(openapi)

    objects_by_name = {detected.name: detected for detected in target_model.objects}
    assert sorted(objects_by_name) == ["file_id", "org_id", "team_id", "workspace_id"]
    assert objects_by_name["workspace_id"].provenance_refs == [
        "openapi.paths./search/files.get.parameters.0"
    ]
    assert objects_by_name["file_id"].provenance_refs == [
        "openapi.paths./shares.post.requestBody.content.application/json.schema.properties"
    ]
    assert objects_by_name["org_id"].provenance_refs == [
        (
            "openapi.paths./shares.post.requestBody.content.application/json.schema."
            "properties.context.properties"
        )
    ]
    assert objects_by_name["workspace_id"].provenance_edges == [
        openapi_operation_edge("/search/files", "get", fact_type="object")
    ]
    assert objects_by_name["file_id"].provenance_edges == [
        openapi_operation_edge("/shares", "post", fact_type="object")
    ]
    assert objects_by_name["team_id"].provenance_edges == [
        openapi_operation_edge("/shares", "post", fact_type="object")
    ]
    assert objects_by_name["org_id"].provenance_edges == [
        openapi_operation_edge("/shares", "post", fact_type="object")
    ]


def test_build_target_model_returns_empty_model_for_missing_paths():
    assert build_target_model({}) == TargetModel()
