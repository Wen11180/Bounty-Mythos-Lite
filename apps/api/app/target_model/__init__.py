import re
from typing import Any

from pydantic import BaseModel, Field


class Endpoint(BaseModel):
    method: str
    path: str
    operation_id: str | None = None
    roles: list[str] = Field(default_factory=list)


class DetectedObject(BaseModel):
    name: str


class SensitiveAction(BaseModel):
    action: str
    method: str
    path: str
    operation_id: str | None = None
    roles: list[str] = Field(default_factory=list)


class TargetModel(BaseModel):
    endpoints: list[Endpoint] = Field(default_factory=list)
    objects: list[DetectedObject] = Field(default_factory=list)
    sensitive_actions: list[SensitiveAction] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}
OBJECT_NAMES = {
    "account_id",
    "file_id",
    "invoice_id",
    "member_id",
    "org_id",
    "organization_id",
    "project_id",
    "role_id",
    "team_id",
    "user_id",
    "workspace_id",
}
ROLE_NAMES = {"admin", "auditor", "manager", "member", "owner", "support", "user"}
SPECIAL_ACTIONS = ("invite", "export", "refund", "share")


def build_target_model(openapi: dict) -> TargetModel:
    endpoints: list[Endpoint] = []
    sensitive_actions: list[SensitiveAction] = []
    object_names = set(_find_object_names(openapi))
    role_names: set[str] = set()

    for path, path_item in openapi.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue

        object_names.update(_find_path_object_names(path))

        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue

            roles = _extract_roles(operation)
            role_names.update(roles)

            endpoint = Endpoint(
                method=method.upper(),
                path=path,
                operation_id=operation.get("operationId"),
                roles=roles,
            )
            endpoints.append(endpoint)

            action = _detect_action(method, path, operation)
            if action:
                sensitive_actions.append(
                    SensitiveAction(
                        action=action,
                        method=endpoint.method,
                        path=path,
                        operation_id=endpoint.operation_id,
                        roles=roles,
                    )
                )

    return TargetModel(
        endpoints=endpoints,
        objects=[DetectedObject(name=name) for name in sorted(object_names)],
        sensitive_actions=sensitive_actions,
        roles=sorted(role_names),
    )


def _find_path_object_names(path: str) -> set[str]:
    return {name for name in re.findall(r"{([^}]+)}", path) if _is_object_name(name)}


def _find_object_names(value: Any) -> set[str]:
    names: set[str] = set()

    if isinstance(value, dict):
        for key, nested_value in value.items():
            if _is_object_name(key):
                names.add(key)
            if key == "name" and isinstance(nested_value, str) and _is_object_name(nested_value):
                names.add(nested_value)
            names.update(_find_object_names(nested_value))
    elif isinstance(value, list):
        for item in value:
            names.update(_find_object_names(item))

    return names


def _is_object_name(name: str) -> bool:
    return name in OBJECT_NAMES


def _extract_roles(operation: dict) -> list[str]:
    roles: set[str] = set()

    for tag in operation.get("tags", []):
        if isinstance(tag, str):
            roles.update(_role_tokens(tag))

    for requirement in operation.get("security", []):
        if not isinstance(requirement, dict):
            continue
        for scopes in requirement.values():
            if isinstance(scopes, list):
                for scope in scopes:
                    if isinstance(scope, str):
                        roles.update(_role_tokens(scope))

    return sorted(roles)


def _role_tokens(value: str) -> set[str]:
    return {token for token in re.split(r"[^a-zA-Z]+", value.lower()) if token in ROLE_NAMES}


def _detect_action(method: str, path: str, operation: dict) -> str | None:
    text = f"{path} {operation.get('operationId', '')}".lower()
    for action in SPECIAL_ACTIONS:
        if action in text:
            return action

    method = method.lower()
    if method == "get":
        return "read"
    if method in {"post", "put", "patch"}:
        return "write"
    if method == "delete":
        return "delete"

    return None
