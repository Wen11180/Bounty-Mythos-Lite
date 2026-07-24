"""Independent, deterministic refutation decisions."""

from __future__ import annotations

import re
from enum import Enum
from typing import Literal

from pydantic import Field, field_validator

from app.bounty_autopilot.contracts import DIGEST_PATTERN, StrictContract, canonical_sha256

_SAFE_REF = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,127}$", re.ASCII)


class RefutationVerdict(str, Enum):
    REFUTED = "refuted"
    RETAINED = "retained"
    NEEDS_EVIDENCE = "needs_evidence"
    DUPLICATE_REVIEW = "duplicate_review"
    BLOCKED_BY_POLICY = "blocked_by_policy"


class RefutationCheck(str, Enum):
    GLOBAL_OR_GATEWAY_CONTROL = "global_or_gateway_control"
    PUBLIC_BY_DESIGN = "public_by_design"
    SAME_ACCOUNT_IMPACT = "same_account_impact"
    ROLE_PRECONDITION = "role_precondition"
    TENANT_PRECONDITION = "tenant_precondition"
    OWNERSHIP = "ownership"
    WORKFLOW_PRECONDITION = "workflow_precondition"
    EXPECTED_BEHAVIOR = "expected_behavior"
    STALE_SESSION_OR_CACHE = "stale_session_or_cache"
    SCOPE = "scope"
    REPRODUCIBILITY = "reproducibility"


REQUIRED_REFUTATION_CHECKS = tuple(RefutationCheck)


class RefutationCase(StrictContract):
    case_id: str
    hypothesis_id: str
    branch_id: str
    counter_questions: tuple[str, ...] = Field(min_length=1, max_length=16)
    observations_cited: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    public_by_design: bool = False
    same_account_only: bool = False
    global_or_gateway_control_protects: bool = False
    role_precondition_missing: bool = False
    tenant_precondition_missing: bool = False
    ownership_not_proven: bool = False
    workflow_precondition_missing: bool = False
    expected_behavior: bool = False
    stale_session_or_cache: bool = False
    scope_invalid: bool = False
    reproducible: bool = False
    completed_checks: tuple[RefutationCheck, ...] = Field(default_factory=tuple)
    evidence_gap_codes: tuple[str, ...] = Field(default_factory=tuple, max_length=16)
    duplicate_candidate_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=16)
    policy_block_reason: str | None = Field(default=None, max_length=128)

    @field_validator(
        "case_id",
        "hypothesis_id",
        "branch_id",
        "observations_cited",
        "evidence_gap_codes",
        "duplicate_candidate_ids",
    )
    @classmethod
    def require_safe_refs(cls, value):
        values = value if isinstance(value, tuple) else (value,)
        if any(_SAFE_REF.fullmatch(item) is None for item in values):
            raise ValueError("safe_refutation_reference_required")
        return value

    @field_validator("completed_checks")
    @classmethod
    def require_unique_completed_checks(
        cls, values: tuple[RefutationCheck, ...]
    ) -> tuple[RefutationCheck, ...]:
        if len(set(values)) != len(values):
            raise ValueError("duplicate_refutation_check")
        return tuple(sorted(values, key=lambda item: item.value))


class RefutationResult(StrictContract):
    case_id: str
    hypothesis_id: str
    branch_id: str
    observations_cited: tuple[str, ...]
    completed_checks: tuple[RefutationCheck, ...]
    lineage_digest: str
    verdict: RefutationVerdict
    reasons: tuple[str, ...] = Field(min_length=1, max_length=16)
    duplicate_recommendation_ids: tuple[str, ...] = Field(default_factory=tuple)
    duplicate_review_required: bool = False
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False

    @field_validator(
        "case_id", "hypothesis_id", "branch_id", "observations_cited"
    )
    @classmethod
    def require_safe_result_refs(cls, value):
        values = value if isinstance(value, tuple) else (value,)
        if any(_SAFE_REF.fullmatch(item) is None for item in values):
            raise ValueError("safe_refutation_result_reference_required")
        return value

    @field_validator("lineage_digest")
    @classmethod
    def require_lineage_digest(cls, value: str) -> str:
        if DIGEST_PATTERN.fullmatch(value) is None:
            raise ValueError("refutation_lineage_digest_required")
        return value


def refutation_lineage_digest(
    *,
    case_id: str,
    hypothesis_id: str,
    branch_id: str,
    observations_cited: tuple[str, ...],
    completed_checks: tuple[RefutationCheck, ...],
) -> str:
    return canonical_sha256(
        {
            "schema_version": "bounty-autopilot-refutation-lineage/v1",
            "case_id": case_id,
            "hypothesis_id": hypothesis_id,
            "branch_id": branch_id,
            "observations_cited": tuple(sorted(observations_cited)),
            "completed_checks": tuple(item.value for item in completed_checks),
        }
    )


def _result(
    case: RefutationCase,
    *,
    verdict: RefutationVerdict,
    reasons: tuple[str, ...],
    duplicate_recommendation_ids: tuple[str, ...] = (),
    duplicate_review_required: bool = False,
) -> RefutationResult:
    return RefutationResult(
        case_id=case.case_id,
        hypothesis_id=case.hypothesis_id,
        branch_id=case.branch_id,
        observations_cited=case.observations_cited,
        completed_checks=case.completed_checks,
        lineage_digest=refutation_lineage_digest(
            case_id=case.case_id,
            hypothesis_id=case.hypothesis_id,
            branch_id=case.branch_id,
            observations_cited=case.observations_cited,
            completed_checks=case.completed_checks,
        ),
        verdict=verdict,
        reasons=reasons,
        duplicate_recommendation_ids=duplicate_recommendation_ids,
        duplicate_review_required=duplicate_review_required,
    )


def refute_candidate(case: RefutationCase) -> RefutationResult:
    if case.policy_block_reason is not None or case.scope_invalid:
        return _result(
            case,
            verdict=RefutationVerdict.BLOCKED_BY_POLICY,
            reasons=(case.policy_block_reason or "scope_invalid",),
        )
    refuting_checks = (
        (case.public_by_design, "public_by_design"),
        (case.same_account_only, "no_cross_account_impact"),
        (case.global_or_gateway_control_protects, "global_or_gateway_control"),
        (case.role_precondition_missing, "role_precondition_missing"),
        (case.tenant_precondition_missing, "tenant_precondition_missing"),
        (case.ownership_not_proven, "ownership_not_proven"),
        (case.workflow_precondition_missing, "workflow_precondition_missing"),
        (case.expected_behavior, "expected_behavior"),
        (case.stale_session_or_cache, "stale_session_or_cache"),
    )
    reasons = tuple(reason for active, reason in refuting_checks if active)
    if reasons:
        return _result(
            case,
            verdict=RefutationVerdict.REFUTED,
            reasons=reasons,
        )
    if case.duplicate_candidate_ids:
        return _result(
            case,
            verdict=RefutationVerdict.DUPLICATE_REVIEW,
            reasons=("duplicate_similarity_requires_review",),
            duplicate_recommendation_ids=tuple(sorted(case.duplicate_candidate_ids)),
            duplicate_review_required=True,
        )
    missing_checks = tuple(
        check
        for check in REQUIRED_REFUTATION_CHECKS
        if check not in case.completed_checks
    )
    if (
        not case.observations_cited
        or case.evidence_gap_codes
        or not case.reproducible
        or missing_checks
    ):
        if case.evidence_gap_codes:
            reasons = tuple(sorted(case.evidence_gap_codes))
        elif missing_checks:
            reasons = ("missing_refutation_checks",)
        elif not case.observations_cited:
            reasons = ("missing_observations",)
        else:
            reasons = ("reproducibility_missing",)
        return _result(
            case,
            verdict=RefutationVerdict.NEEDS_EVIDENCE,
            reasons=reasons,
        )
    return _result(
        case,
        verdict=RefutationVerdict.RETAINED,
        reasons=("refutation_checks_passed",),
    )


__all__ = [
    "RefutationCase",
    "RefutationCheck",
    "RefutationResult",
    "RefutationVerdict",
    "REQUIRED_REFUTATION_CHECKS",
    "refutation_lineage_digest",
    "refute_candidate",
]
