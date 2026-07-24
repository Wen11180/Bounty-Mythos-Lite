"""Sanitized, digest-bound browser workflow projections."""

from __future__ import annotations

import re
from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from app.bounty_autopilot.contracts import (
    RecipeRef,
    StrictContract,
    canonical_sha256,
)
from app.bounty_autopilot.recipes import default_recipe_registry


_SAFE_ID = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$", re.ASCII)
_SAFE_ALIAS = re.compile(r"^[a-z][a-z0-9_-]{0,31}$", re.ASCII)
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$", re.ASCII)
_STATIC_ROUTE_SEGMENT = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$", re.ASCII)
_LONG_HEX = re.compile(r"^[0-9a-f]{16,}$", re.ASCII | re.IGNORECASE)
_SENSITIVE_ROUTE_TERM = re.compile(
    r"(?:password|passwd|secret|token|cookie|authorization|session[_-]?id)",
    re.ASCII | re.IGNORECASE,
)


class WorkflowActionClass(str, Enum):
    READ = "read"


class MappedSubject(StrictContract):
    account_alias: str = Field(min_length=1, max_length=32)
    role_alias: str = Field(min_length=1, max_length=32)
    session_alias: str = Field(min_length=1, max_length=32)
    session_generation: int = Field(ge=1, le=2_147_483_647)

    @field_validator("account_alias", "role_alias", "session_alias")
    @classmethod
    def require_safe_alias(cls, value: str) -> str:
        return validate_safe_alias(value)


class MappedObject(StrictContract):
    object_alias: str = Field(min_length=1, max_length=32)
    object_type: str = Field(min_length=1, max_length=128)
    owner_account_alias: str = Field(min_length=1, max_length=32)
    ownership_proof_digest: str = Field(min_length=71, max_length=71)

    @field_validator("object_alias", "owner_account_alias")
    @classmethod
    def require_safe_alias(cls, value: str) -> str:
        return validate_safe_alias(value)

    @field_validator("object_type")
    @classmethod
    def require_safe_type(cls, value: str) -> str:
        return validate_safe_id(value)

    @field_validator("ownership_proof_digest")
    @classmethod
    def require_proof_digest(cls, value: str) -> str:
        return validate_sha256(value)


class MappedAction(StrictContract):
    action_class: Literal["read"] = "read"
    method: Literal["GET", "HEAD"]
    route_template: str = Field(min_length=1, max_length=512)
    path_parameters: tuple[Literal["object"], ...] = ("object",)
    query_parameters: tuple[str, ...] = ()
    mutates_state: Literal[False] = False

    @field_validator("route_template")
    @classmethod
    def require_normalized_template(cls, value: str) -> str:
        return validate_route_template(value)

    @model_validator(mode="after")
    def require_fixed_parameter_shape(self) -> MappedAction:
        if self.path_parameters != ("object",) or self.query_parameters:
            raise ValueError("fixed_owned_object_parameter_required")
        return self


class MappedWorkflow(StrictContract):
    schema_version: Literal["bounty-autopilot-browser-mapping/v1"] = (
        "bounty-autopilot-browser-mapping/v1"
    )
    mapping_id: str = Field(min_length=1, max_length=128)
    asset_id: str = Field(min_length=1, max_length=128)
    recipe_ref: RecipeRef
    subject: MappedSubject
    obj: MappedObject
    action: MappedAction
    source_projection_digest: str = Field(min_length=71, max_length=71)
    mapping_digest: str = Field(min_length=71, max_length=71)

    @field_validator("mapping_id", "asset_id")
    @classmethod
    def require_safe_identifier(cls, value: str) -> str:
        return validate_safe_id(value)

    @field_validator("source_projection_digest", "mapping_digest")
    @classmethod
    def require_digest(cls, value: str) -> str:
        return validate_sha256(value)

    @model_validator(mode="after")
    def require_registered_recipe_and_digest(self) -> MappedWorkflow:
        expected = default_recipe_registry().require("lab_browser_mapping", "1.0.0")
        if self.recipe_ref != expected.ref:
            raise ValueError("browser_mapping_recipe_required")
        expected_digest = canonical_sha256(
            self.model_dump(mode="python", exclude={"mapping_digest"})
        )
        if self.mapping_digest != expected_digest:
            raise ValueError("mapping_digest_mismatch")
        return self


def build_browser_mapping(
    *,
    mapping_id: str,
    asset_id: str,
    account_alias: str,
    role_alias: str,
    session_alias: str,
    session_generation: int,
    object_alias: str,
    object_type: str,
    owner_account_alias: str,
    ownership_proof_digest: str,
    method: str,
    route_template: str,
    source_projection_digest: str,
) -> MappedWorkflow:
    """Build an allowlisted projection; raw browser material has no input slot."""

    recipe_ref = default_recipe_registry().require(
        "lab_browser_mapping", "1.0.0"
    ).ref
    payload = {
        "schema_version": "bounty-autopilot-browser-mapping/v1",
        "mapping_id": mapping_id,
        "asset_id": asset_id,
        "recipe_ref": recipe_ref,
        "subject": MappedSubject(
            account_alias=account_alias,
            role_alias=role_alias,
            session_alias=session_alias,
            session_generation=session_generation,
        ),
        "obj": MappedObject(
            object_alias=object_alias,
            object_type=object_type,
            owner_account_alias=owner_account_alias,
            ownership_proof_digest=ownership_proof_digest,
        ),
        "action": MappedAction(
            method=method.upper(),
            route_template=route_template,
        ),
        "source_projection_digest": source_projection_digest,
    }
    return MappedWorkflow(
        **payload,
        mapping_digest=canonical_sha256(payload),
    )


def build_authz_workflow(
    *,
    workflow_id: str,
    asset_id: str,
    actor_alias: str,
    actor_role: str,
    session_alias: str,
    session_generation: int,
    owner_alias: str,
    object_alias: str,
    object_type: str,
    ownership_proof_digest: str,
    method: str,
    path_template: str,
    source_projection_digest: str,
    recipe_id: str = "lab_browser_mapping",
    recipe_version: str = "1.0.0",
    action_class: WorkflowActionClass = WorkflowActionClass.READ,
) -> MappedWorkflow:
    """Compatibility name for callers migrating from the Phase 7 scaffold."""

    if (
        recipe_id != "lab_browser_mapping"
        or recipe_version != "1.0.0"
        or action_class is not WorkflowActionClass.READ
    ):
        raise ValueError("browser_mapping_recipe_required")
    return build_browser_mapping(
        mapping_id=workflow_id,
        asset_id=asset_id,
        account_alias=actor_alias,
        role_alias=actor_role,
        session_alias=session_alias,
        session_generation=session_generation,
        object_alias=object_alias,
        object_type=object_type,
        owner_account_alias=owner_alias,
        ownership_proof_digest=ownership_proof_digest,
        method=method,
        route_template=path_template,
        source_projection_digest=source_projection_digest,
    )


def validate_safe_alias(value: str) -> str:
    if _SAFE_ALIAS.fullmatch(value) is None or _LONG_HEX.fullmatch(value):
        raise ValueError("safe_alias_required")
    return value


def validate_safe_id(value: str) -> str:
    if _SAFE_ID.fullmatch(value) is None:
        raise ValueError("safe_identifier_required")
    return value


def validate_sha256(value: str) -> str:
    if _SHA256.fullmatch(value) is None:
        raise ValueError("sha256_digest_required")
    return value


def validate_route_template(value: str) -> str:
    if (
        not value.isascii()
        or not value.startswith("/")
        or value.startswith("//")
        or any(character in value for character in ("?", "#", "%", "\\"))
        or "://" in value
        or "//" in value
        or _SENSITIVE_ROUTE_TERM.search(value)
    ):
        raise ValueError("normalized_route_template_required")
    segments = value.split("/")[1:]
    if (
        not segments
        or any(segment in {"", ".", ".."} for segment in segments)
        or segments.count("{object}") != 1
        or any(
            segment != "{object}" and _STATIC_ROUTE_SEGMENT.fullmatch(segment) is None
            for segment in segments
        )
        or any(
            "{" in segment or "}" in segment
            for segment in segments
            if segment != "{object}"
        )
    ):
        raise ValueError("normalized_route_template_required")
    return value


__all__ = [
    "MappedAction",
    "MappedObject",
    "MappedSubject",
    "MappedWorkflow",
    "WorkflowActionClass",
    "build_authz_workflow",
    "build_browser_mapping",
    "validate_route_template",
    "validate_safe_alias",
    "validate_safe_id",
    "validate_sha256",
]
