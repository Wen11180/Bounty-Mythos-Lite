"""Independent refutation for Autopilot candidates."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import Field

from app.bounty_autopilot.contracts import StrictContract


class RefutationVerdict(str, Enum):
    REFUTED = "refuted"
    RETAINED = "retained"
    NEEDS_EVIDENCE = "needs_evidence"
    DUPLICATE = "duplicate"


class RefutationCase(StrictContract):
    case_id: str
    hypothesis_id: str
    branch_id: str
    claim_summary: str = Field(min_length=1, max_length=512)
    counter_questions: tuple[str, ...] = Field(min_length=1, max_length=16)
    observations_cited: tuple[str, ...] = Field(default_factory=tuple, max_length=32)
    duplicate_of_hypothesis_id: str | None = Field(default=None, max_length=128)
    public_by_design: bool = False
    same_account_only: bool = False
    global_middleware_protects: bool = False


class RefutationResult(StrictContract):
    case_id: str
    verdict: RefutationVerdict
    reasons: tuple[str, ...] = Field(min_length=1, max_length=16)
    duplicate_of_hypothesis_id: str | None = None
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False


def refute_candidate(case: RefutationCase) -> RefutationResult:
    reasons: list[str] = []
    if case.duplicate_of_hypothesis_id:
        return RefutationResult(
            case_id=case.case_id,
            verdict=RefutationVerdict.DUPLICATE,
            reasons=("duplicate_hypothesis",),
            duplicate_of_hypothesis_id=case.duplicate_of_hypothesis_id,
        )
    if case.public_by_design:
        return RefutationResult(
            case_id=case.case_id,
            verdict=RefutationVerdict.REFUTED,
            reasons=("public_by_design",),
        )
    if case.same_account_only:
        return RefutationResult(
            case_id=case.case_id,
            verdict=RefutationVerdict.REFUTED,
            reasons=("no_cross_account_impact",),
        )
    if case.global_middleware_protects:
        return RefutationResult(
            case_id=case.case_id,
            verdict=RefutationVerdict.REFUTED,
            reasons=("global_middleware_protection",),
        )
    if not case.observations_cited:
        return RefutationResult(
            case_id=case.case_id,
            verdict=RefutationVerdict.NEEDS_EVIDENCE,
            reasons=("missing_observations",),
        )
    reasons.append("independent_refutation_incomplete")
    # Without stronger refute signals, retain for human evidence judge.
    return RefutationResult(
        case_id=case.case_id,
        verdict=RefutationVerdict.RETAINED,
        reasons=tuple(reasons),
    )


__all__ = [
    "RefutationCase",
    "RefutationResult",
    "RefutationVerdict",
    "refute_candidate",
]
