"""Digest-bound demonstrated workflows derived from sanitized browser maps."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator

from app.bounty_autopilot.browser_mapper import (
    MappedWorkflow,
    validate_safe_id,
    validate_sha256,
)
from app.bounty_autopilot.contracts import StrictContract, canonical_sha256


class DemonstratedOwnedWorkflow(StrictContract):
    schema_version: Literal["bounty-autopilot-demonstrated-workflow/v1"] = (
        "bounty-autopilot-demonstrated-workflow/v1"
    )
    workflow_id: str = Field(min_length=1, max_length=128)
    mapping: MappedWorkflow
    demonstration_observation_digest: str = Field(min_length=71, max_length=71)
    ownership_demonstrated: Literal[True] = True
    workflow_digest: str = Field(min_length=71, max_length=71)

    @field_validator("workflow_id")
    @classmethod
    def require_safe_workflow_id(cls, value: str) -> str:
        return validate_safe_id(value)

    @field_validator("demonstration_observation_digest", "workflow_digest")
    @classmethod
    def require_digest(cls, value: str) -> str:
        return validate_sha256(value)

    @model_validator(mode="after")
    def require_owned_source_and_digest(self) -> DemonstratedOwnedWorkflow:
        if self.mapping.subject.account_alias != self.mapping.obj.owner_account_alias:
            raise ValueError("demonstrated_owned_object_required")
        expected = canonical_sha256(
            self.model_dump(mode="python", exclude={"workflow_digest"})
        )
        if self.workflow_digest != expected:
            raise ValueError("workflow_digest_mismatch")
        return self


def build_demonstrated_owned_workflow(
    *,
    workflow_id: str,
    mapping: MappedWorkflow,
    demonstration_observation_digest: str,
) -> DemonstratedOwnedWorkflow:
    """Promote only an owned, sanitized mapping into a demonstrated workflow."""

    if mapping.subject.account_alias != mapping.obj.owner_account_alias:
        raise ValueError("demonstrated_owned_object_required")
    payload = {
        "schema_version": "bounty-autopilot-demonstrated-workflow/v1",
        "workflow_id": workflow_id,
        "mapping": mapping,
        "demonstration_observation_digest": demonstration_observation_digest,
        "ownership_demonstrated": True,
    }
    return DemonstratedOwnedWorkflow(
        **payload,
        workflow_digest=canonical_sha256(payload),
    )


__all__ = [
    "DemonstratedOwnedWorkflow",
    "build_demonstrated_owned_workflow",
]
