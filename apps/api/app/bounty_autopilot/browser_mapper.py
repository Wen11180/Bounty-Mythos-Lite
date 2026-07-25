"""Sanitized browser mapping models for owned-account workflows."""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from app.bounty_autopilot.contracts import StrictContract


class WorkflowActionClass(str, Enum):
    READ = "read"
    LIST = "list"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    TRANSITION = "transition"


class MappedSubject(StrictContract):
    alias: str
    role_label: str


class MappedObject(StrictContract):
    object_type: str
    owner_alias: str
    object_key_class: str = "opaque_id"


class MappedAction(StrictContract):
    action_class: WorkflowActionClass
    path_template: str
    method: str


class MappedWorkflow(StrictContract):
    workflow_id: str
    subject: MappedSubject
    obj: MappedObject
    action: MappedAction
    recipe_id: str
    recipe_version: str
    requires_two_accounts: bool = False


def build_authz_workflow(
    *,
    workflow_id: str,
    actor_alias: str,
    actor_role: str,
    owner_alias: str,
    object_type: str,
    method: str,
    path_template: str,
    recipe_id: str,
    recipe_version: str,
    action_class: WorkflowActionClass = WorkflowActionClass.READ,
) -> MappedWorkflow:
    return MappedWorkflow(
        workflow_id=workflow_id,
        subject=MappedSubject(alias=actor_alias, role_label=actor_role),
        obj=MappedObject(object_type=object_type, owner_alias=owner_alias),
        action=MappedAction(
            action_class=action_class,
            path_template=path_template,
            method=method.upper(),
        ),
        recipe_id=recipe_id,
        recipe_version=recipe_version,
        requires_two_accounts=actor_alias != owner_alias,
    )


__all__ = [
    "MappedAction",
    "MappedObject",
    "MappedSubject",
    "MappedWorkflow",
    "WorkflowActionClass",
    "build_authz_workflow",
]
