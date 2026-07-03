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
        ),
        Endpoint(
            method="PATCH",
            path="/orgs/{org_id}/users/{user_id}",
            operation_id="updateUser",
            roles=[],
        ),
    ]
    assert [detected.name for detected in target_model.objects] == [
        "org_id",
        "team_id",
        "user_id",
    ]
    assert target_model.roles == ["admin"]


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
        ),
        SensitiveAction(
            action="export",
            method="GET",
            path="/files/{file_id}/export",
            operation_id="exportFile",
            roles=[],
        ),
        SensitiveAction(
            action="refund",
            method="POST",
            path="/invoices/{invoice_id}/refund",
            operation_id="refundInvoice",
            roles=[],
        ),
        SensitiveAction(
            action="share",
            method="POST",
            path="/files/{file_id}/share",
            operation_id="shareFile",
            roles=[],
        ),
        SensitiveAction(
            action="delete",
            method="DELETE",
            path="/files/{file_id}",
            operation_id="deleteFile",
            roles=[],
        ),
    ]
    assert [detected.name for detected in target_model.objects] == [
        "file_id",
        "invoice_id",
        "team_id",
    ]


def test_build_target_model_returns_empty_model_for_missing_paths():
    assert build_target_model({}) == TargetModel()
