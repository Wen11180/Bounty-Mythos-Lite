"""Fixed two-owned-account read-only authorization templates."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator

from app.bounty_autopilot.browser_mapper import (
    validate_route_template,
    validate_safe_alias,
    validate_safe_id,
    validate_sha256,
)
from app.bounty_autopilot.contracts import (
    RecipeRef,
    StrictContract,
    canonical_sha256,
)
from app.bounty_autopilot.recipes import default_recipe_registry
from app.bounty_autopilot.workflow_model import DemonstratedOwnedWorkflow


class SessionGenerationBinding(StrictContract):
    session_alias: str = Field(min_length=1, max_length=32)
    account_alias: str = Field(min_length=1, max_length=32)
    role_alias: str = Field(min_length=1, max_length=32)
    generation: int = Field(ge=1, le=2_147_483_647)

    @field_validator("session_alias", "account_alias", "role_alias")
    @classmethod
    def require_safe_alias(cls, value: str) -> str:
        return validate_safe_alias(value)


class ReadOnlyDifferentialTemplate(StrictContract):
    schema_version: Literal["bounty-autopilot-readonly-differential/v1"] = (
        "bounty-autopilot-readonly-differential/v1"
    )
    template_id: str = Field(min_length=1, max_length=128)
    campaign_id: str = Field(min_length=1, max_length=128)
    authorization_digest: str = Field(min_length=71, max_length=71)
    asset_id: str = Field(min_length=1, max_length=128)
    recipe_ref: RecipeRef
    demonstrated_workflow_digest: str = Field(min_length=71, max_length=71)
    mapping_digest: str = Field(min_length=71, max_length=71)
    source_session: SessionGenerationBinding
    comparison_session: SessionGenerationBinding
    authorized_account_aliases: tuple[str, str]
    object_alias: str = Field(min_length=1, max_length=32)
    object_owner_account_alias: str = Field(min_length=1, max_length=32)
    ownership_proof_digest: str = Field(min_length=71, max_length=71)
    method: Literal["GET", "HEAD"]
    route_template: str = Field(min_length=1, max_length=512)
    query_parameter_names: tuple[str, ...] = ()
    max_requests: Literal[2] = 2
    max_concurrency: Literal[1] = 1
    mutation_allowed: Literal[False] = False
    enumeration_allowed: Literal[False] = False
    pagination_allowed: Literal[False] = False
    object_substitution_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False
    template_digest: str = Field(min_length=71, max_length=71)

    @field_validator("template_id", "campaign_id", "asset_id")
    @classmethod
    def require_safe_identifier(cls, value: str) -> str:
        return validate_safe_id(value)

    @field_validator(
        "authorization_digest",
        "demonstrated_workflow_digest",
        "mapping_digest",
        "ownership_proof_digest",
        "template_digest",
    )
    @classmethod
    def require_digest(cls, value: str) -> str:
        return validate_sha256(value)

    @field_validator("object_alias", "object_owner_account_alias")
    @classmethod
    def require_safe_alias(cls, value: str) -> str:
        return validate_safe_alias(value)

    @field_validator("route_template")
    @classmethod
    def require_normalized_route(cls, value: str) -> str:
        return validate_route_template(value)

    @field_validator("authorized_account_aliases")
    @classmethod
    def require_two_safe_accounts(cls, value: tuple[str, str]) -> tuple[str, str]:
        for alias in value:
            validate_safe_alias(alias)
        if len(set(value)) != 2:
            raise ValueError("distinct_owned_accounts_required")
        return value

    @model_validator(mode="after")
    def require_fixed_differential_shape(self) -> ReadOnlyDifferentialTemplate:
        recipe = default_recipe_registry().require(
            "lab_two_account_authorization_differential", "1.0.0"
        )
        if self.recipe_ref != recipe.ref:
            raise ValueError("two_account_read_only_recipe_required")
        if self.source_session.account_alias != self.object_owner_account_alias:
            raise ValueError("source_must_own_demonstrated_object")
        if (
            self.source_session.account_alias == self.comparison_session.account_alias
            or self.source_session.session_alias
            == self.comparison_session.session_alias
        ):
            raise ValueError("distinct_owned_accounts_required")
        expected_accounts = (
            self.source_session.account_alias,
            self.comparison_session.account_alias,
        )
        if self.authorized_account_aliases != expected_accounts:
            raise ValueError("exact_two_authorized_accounts_required")
        if self.query_parameter_names:
            raise ValueError("pagination_and_query_parameters_forbidden")
        expected_digest = canonical_sha256(
            self.model_dump(mode="python", exclude={"template_digest"})
        )
        if self.template_digest != expected_digest:
            raise ValueError("template_digest_mismatch")
        return self


class DifferentialRequestIntent(StrictContract):
    schema_version: Literal["bounty-autopilot-readonly-intent/v1"] = (
        "bounty-autopilot-readonly-intent/v1"
    )
    template_digest: str = Field(min_length=71, max_length=71)
    campaign_id: str = Field(min_length=1, max_length=128)
    authorization_digest: str = Field(min_length=71, max_length=71)
    asset_id: str = Field(min_length=1, max_length=128)
    recipe_ref: RecipeRef
    ordinal: int = Field(ge=1, le=2)
    session_alias: str = Field(min_length=1, max_length=32)
    account_alias: str = Field(min_length=1, max_length=32)
    role_alias: str = Field(min_length=1, max_length=32)
    session_generation: int = Field(ge=1, le=2_147_483_647)
    method: Literal["GET", "HEAD"]
    route_template: str = Field(min_length=1, max_length=512)
    object_alias: str = Field(min_length=1, max_length=32)
    query_parameter_names: tuple[str, ...] = ()
    report_submission_allowed: Literal[False] = False
    request_digest: str = Field(min_length=71, max_length=71)

    @field_validator("campaign_id", "asset_id")
    @classmethod
    def require_safe_identifier(cls, value: str) -> str:
        return validate_safe_id(value)

    @field_validator("session_alias", "account_alias", "role_alias", "object_alias")
    @classmethod
    def require_safe_alias(cls, value: str) -> str:
        return validate_safe_alias(value)

    @field_validator("route_template")
    @classmethod
    def require_normalized_route(cls, value: str) -> str:
        return validate_route_template(value)

    @field_validator(
        "template_digest",
        "authorization_digest",
        "request_digest",
    )
    @classmethod
    def require_digest(cls, value: str) -> str:
        return validate_sha256(value)

    @model_validator(mode="after")
    def require_empty_query_and_digest(self) -> DifferentialRequestIntent:
        if self.query_parameter_names:
            raise ValueError("pagination_and_query_parameters_forbidden")
        expected = canonical_sha256(
            self.model_dump(mode="python", exclude={"request_digest"})
        )
        if self.request_digest != expected:
            raise ValueError("request_digest_mismatch")
        return self


def build_two_account_read_only_template(
    *,
    template_id: str,
    campaign_id: str,
    authorization_digest: str,
    workflow: DemonstratedOwnedWorkflow,
    source_session_generation: int,
    comparison_account_alias: str,
    comparison_role_alias: str,
    comparison_session_alias: str,
    comparison_session_generation: int,
    authorized_account_aliases: tuple[str, ...],
) -> ReadOnlyDifferentialTemplate:
    """Bind a demonstrated owned workflow to one fixed cross-account trial."""

    mapping = workflow.mapping
    if source_session_generation != mapping.subject.session_generation:
        raise ValueError("stale_source_session_generation")
    if comparison_account_alias == mapping.subject.account_alias:
        raise ValueError("distinct_owned_accounts_required")
    expected_accounts = (
        mapping.subject.account_alias,
        comparison_account_alias,
    )
    if tuple(authorized_account_aliases) != expected_accounts:
        raise ValueError("exact_two_authorized_accounts_required")
    payload = {
        "schema_version": "bounty-autopilot-readonly-differential/v1",
        "template_id": template_id,
        "campaign_id": campaign_id,
        "authorization_digest": authorization_digest,
        "asset_id": mapping.asset_id,
        "recipe_ref": default_recipe_registry()
        .require("lab_two_account_authorization_differential", "1.0.0")
        .ref,
        "demonstrated_workflow_digest": workflow.workflow_digest,
        "mapping_digest": mapping.mapping_digest,
        "source_session": SessionGenerationBinding(
            session_alias=mapping.subject.session_alias,
            account_alias=mapping.subject.account_alias,
            role_alias=mapping.subject.role_alias,
            generation=source_session_generation,
        ),
        "comparison_session": SessionGenerationBinding(
            session_alias=comparison_session_alias,
            account_alias=comparison_account_alias,
            role_alias=comparison_role_alias,
            generation=comparison_session_generation,
        ),
        "authorized_account_aliases": expected_accounts,
        "object_alias": mapping.obj.object_alias,
        "object_owner_account_alias": mapping.obj.owner_account_alias,
        "ownership_proof_digest": mapping.obj.ownership_proof_digest,
        "method": mapping.action.method,
        "route_template": mapping.action.route_template,
        "query_parameter_names": (),
        "max_requests": 2,
        "max_concurrency": 1,
        "mutation_allowed": False,
        "enumeration_allowed": False,
        "pagination_allowed": False,
        "object_substitution_allowed": False,
        "report_submission_allowed": False,
    }
    return ReadOnlyDifferentialTemplate(
        **payload,
        template_digest=canonical_sha256(payload),
    )


def build_differential_request_intents(
    template: ReadOnlyDifferentialTemplate,
) -> tuple[DifferentialRequestIntent, DifferentialRequestIntent]:
    sessions = (template.source_session, template.comparison_session)
    intents: list[DifferentialRequestIntent] = []
    for ordinal, session in enumerate(sessions, start=1):
        payload = {
            "schema_version": "bounty-autopilot-readonly-intent/v1",
            "template_digest": template.template_digest,
            "campaign_id": template.campaign_id,
            "authorization_digest": template.authorization_digest,
            "asset_id": template.asset_id,
            "recipe_ref": template.recipe_ref,
            "ordinal": ordinal,
            "session_alias": session.session_alias,
            "account_alias": session.account_alias,
            "role_alias": session.role_alias,
            "session_generation": session.generation,
            "method": template.method,
            "route_template": template.route_template,
            "object_alias": template.object_alias,
            "query_parameter_names": (),
            "report_submission_allowed": False,
        }
        intents.append(
            DifferentialRequestIntent(
                **payload,
                request_digest=canonical_sha256(payload),
            )
        )
    return intents[0], intents[1]


def validate_differential_request_intent(
    template: ReadOnlyDifferentialTemplate,
    intent: DifferentialRequestIntent,
) -> DifferentialRequestIntent:
    expected = build_differential_request_intents(template)[intent.ordinal - 1]
    if intent != expected:
        raise ValueError("request_intent_template_mismatch")
    return intent


__all__ = [
    "DifferentialRequestIntent",
    "ReadOnlyDifferentialTemplate",
    "SessionGenerationBinding",
    "build_differential_request_intents",
    "build_two_account_read_only_template",
    "validate_differential_request_intent",
]
