import re
from typing import Any

from pydantic import BaseModel, Field

from app.provenance import ProvenanceEdge, openapi_operation_edge, openapi_path_edge


class Endpoint(BaseModel):
    method: str
    path: str
    operation_id: str | None = None
    roles: list[str] = Field(default_factory=list)
    provenance_refs: list[str] = Field(default_factory=list)
    provenance_edges: list[ProvenanceEdge] = Field(default_factory=list)


class DetectedObject(BaseModel):
    name: str
    provenance_refs: list[str] = Field(default_factory=list)
    provenance_edges: list[ProvenanceEdge] = Field(default_factory=list)


class SensitiveAction(BaseModel):
    action: str
    method: str
    path: str
    operation_id: str | None = None
    roles: list[str] = Field(default_factory=list)
    provenance_refs: list[str] = Field(default_factory=list)
    provenance_edges: list[ProvenanceEdge] = Field(default_factory=list)


class ObjectRelationship(BaseModel):
    parent_object: str
    child_object: str
    relationship: str = "contains"
    path: str
    provenance_refs: list[str] = Field(default_factory=list)
    provenance_edges: list[ProvenanceEdge] = Field(default_factory=list)


class TargetModel(BaseModel):
    endpoints: list[Endpoint] = Field(default_factory=list)
    objects: list[DetectedObject] = Field(default_factory=list)
    sensitive_actions: list[SensitiveAction] = Field(default_factory=list)
    relationships: list[ObjectRelationship] = Field(default_factory=list)
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
    relationships: list[ObjectRelationship] = []
    relationship_keys: set[tuple[str, str, str]] = set()
    object_provenance = _find_object_provenance(openapi)
    object_edges: dict[str, list[ProvenanceEdge]] = {}
    role_names: set[str] = set()

    for path, path_item in openapi.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue

        safe_path = _safe_path(path)
        path_provenance_ref = _path_provenance_ref(safe_path)
        path_edge = openapi_path_edge(safe_path, fact_type="object")
        path_object_names = _find_path_object_names_in_order(path)
        for object_name in path_object_names:
            object_provenance.setdefault(object_name, [])
            _append_unique(object_provenance[object_name], path_provenance_ref)
            object_edges.setdefault(object_name, [])
            _append_unique_edge(object_edges[object_name], path_edge)
        relationship_edge = openapi_path_edge(safe_path, fact_type="object_relationship")
        for parent_object, child_object in zip(path_object_names, path_object_names[1:]):
            relationship_key = (parent_object, child_object, safe_path)
            if relationship_key in relationship_keys:
                continue
            relationship_keys.add(relationship_key)
            relationships.append(
                ObjectRelationship(
                    parent_object=parent_object,
                    child_object=child_object,
                    path=safe_path,
                    provenance_refs=[path_provenance_ref],
                    provenance_edges=[relationship_edge],
                )
            )

        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue

            roles = _extract_roles(operation)
            role_names.update(roles)
            operation_provenance_ref = _operation_provenance_ref(safe_path, method)
            endpoint_edge = openapi_operation_edge(safe_path, method, fact_type="endpoint")
            operation_id = _safe_operation_id(operation.get("operationId"))

            endpoint = Endpoint(
                method=method.upper(),
                path=safe_path,
                operation_id=operation_id,
                roles=roles,
                provenance_refs=[operation_provenance_ref],
                provenance_edges=[endpoint_edge],
            )
            endpoints.append(endpoint)

            action = _detect_action(method, safe_path, operation)
            if action:
                sensitive_actions.append(
                    SensitiveAction(
                        action=action,
                        method=endpoint.method,
                        path=safe_path,
                        operation_id=endpoint.operation_id,
                        roles=roles,
                        provenance_refs=[operation_provenance_ref],
                        provenance_edges=[
                            openapi_operation_edge(
                                safe_path,
                                method,
                                fact_type="sensitive_action",
                            )
                        ],
                    )
                )

            object_edge = openapi_operation_edge(safe_path, method, fact_type="object")
            for object_name in _find_object_names(operation):
                object_provenance.setdefault(object_name, [])
                object_edges.setdefault(object_name, [])
                _append_unique_edge(object_edges[object_name], object_edge)

    return TargetModel(
        endpoints=endpoints,
        objects=[
            DetectedObject(
                name=name,
                provenance_refs=object_provenance[name],
                provenance_edges=object_edges.get(name, []),
            )
            for name in sorted(object_provenance)
        ],
        sensitive_actions=sensitive_actions,
        relationships=relationships,
        roles=sorted(role_names),
    )


def _find_path_object_names(path: str) -> set[str]:
    return set(_find_path_object_names_in_order(path))


def _find_path_object_names_in_order(path: str) -> list[str]:
    names: list[str] = []
    for name in re.findall(r"{([^}]+)}", path):
        if _is_object_name(name) and name not in names:
            names.append(name)
    return names


def _find_object_provenance(value: Any) -> dict[str, list[str]]:
    names: dict[str, list[str]] = {}
    _collect_object_provenance(value, names, ["openapi"])
    return names


def _find_object_names(value: Any) -> set[str]:
    names: set[str] = set()
    _collect_object_names(value, names)
    return names


def _collect_object_names(value: Any, names: set[str]) -> None:
    if isinstance(value, dict):
        for key, nested_value in value.items():
            if _is_object_name(key):
                names.add(key)
            if key == "name" and isinstance(nested_value, str) and _is_object_name(nested_value):
                names.add(nested_value)
            _collect_object_names(nested_value, names)
    elif isinstance(value, list):
        for item in value:
            _collect_object_names(item, names)


def _collect_object_provenance(
    value: Any,
    names: dict[str, list[str]],
    path: list[str],
) -> None:
    provenance_ref = ".".join(_safe_provenance_component(part) for part in path)

    if isinstance(value, dict):
        for key, nested_value in value.items():
            if _is_object_name(key):
                names.setdefault(key, [])
                _append_unique(names[key], provenance_ref)
            if key == "name" and isinstance(nested_value, str) and _is_object_name(nested_value):
                names.setdefault(nested_value, [])
                _append_unique(names[nested_value], provenance_ref)
            _collect_object_provenance(nested_value, names, [*path, str(key)])
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _collect_object_provenance(item, names, [*path, str(index)])


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
    if _is_secret_like(value):
        return set()
    return {token for token in re.split(r"[^a-zA-Z]+", value.lower()) if token in ROLE_NAMES}


def _detect_action(method: str, path: str, operation: dict) -> str | None:
    text = f"{path} {_safe_operation_id(operation.get('operationId')) or ''}".lower()
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


def _safe_operation_id(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return "[REDACTED]" if _is_secret_like(text) else text


def _safe_path(value: Any) -> str:
    text = str(value)
    segments = text.split("/")
    safe_segments = [
        "[REDACTED]" if _is_secret_like(segment) else segment
        for segment in segments
    ]
    return "/".join(safe_segments)


def _safe_provenance_component(value: str) -> str:
    return _safe_path(value)


def _is_secret_like(value: str) -> bool:
    import re

    lowered = value.lower()
    secret_markers = (
        "authorization:",
        "api-key:",
        "bearer ",
        "cookie:",
        "set-cookie:",
        "api_key",
        "apikey",
        "password",
        "credential",
        "session=",
        "secret",
        "token",
        "x-api-key:",
    )
    return any(marker in lowered for marker in secret_markers) or (
        re.search(r"\bsk-[a-z0-9]", lowered) is not None
    )


def _path_provenance_ref(path: str) -> str:
    return f"openapi.paths.{path}"


def _operation_provenance_ref(path: str, method: str) -> str:
    return f"{_path_provenance_ref(path)}.{method.lower()}"


def _append_unique(values: list[str], value: str) -> None:
    if value not in values:
        values.append(value)


def _append_unique_edge(values: list[ProvenanceEdge], value: ProvenanceEdge) -> None:
    if value not in values:
        values.append(value)
