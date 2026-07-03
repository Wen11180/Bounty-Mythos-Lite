from typing import Any

from pydantic import BaseModel, Field


DEFAULT_BLOCKED_STEP = "Do not validate until refutation findings are resolved."
HUMAN_APPROVAL_REASON = "human_approval_required"
PREPARATION_STATUS_READY = "ready_for_human_controlled_validation"
STATUS_AWAITING_APPROVAL = "awaiting_approval"
STATUS_BLOCKED = "blocked"
STATUS_READY = "ready"


class ApprovalGate(BaseModel):
    human_approval_required: bool = True
    human_approved: bool = False
    status: str = STATUS_AWAITING_APPROVAL
    reason: str = "human_approval_required"


class ValidationStep(BaseModel):
    instruction: str
    method: str
    status: str
    evidence_hints: list[dict[str, Any]] = Field(default_factory=list)


class ValidationWorkspace(BaseModel):
    status: str
    scope_decision: dict[str, Any]
    validation_plan_status: str
    refutation_status: str
    blocked_reasons: list[str] = Field(default_factory=list)
    human_approval_required: bool = True
    allowed_to_execute: bool = False
    test_accounts_only: bool = True
    no_real_user_data: bool = True
    non_destructive_only: bool = True
    approval_gate: ApprovalGate
    steps: list[ValidationStep] = Field(default_factory=list)
    evidence_hints: list[dict[str, Any]] = Field(default_factory=list)


def build_validation_workspace(
    validation_plan: dict[str, Any],
    scope_decision: dict[str, Any],
    refutation: dict[str, Any],
    evidence_hints: list[dict[str, Any]] | None = None,
    human_approved: bool = False,
) -> ValidationWorkspace:
    normalized_evidence_hints = evidence_hints or []
    human_approval_required = bool(validation_plan.get("human_approval_required", True))
    refutation_status = str(refutation.get("status", "blocked"))
    refutation_reasons = [str(reason) for reason in refutation.get("reasons", [])]
    blocked_reasons = [
        reason for reason in refutation_reasons if reason != HUMAN_APPROVAL_REASON
    ]
    if refutation_status == STATUS_BLOCKED and not refutation_reasons:
        blocked_reasons.append("refutation_blocked")

    scope_reason = str(scope_decision.get("reason", "scope_guard_blocked"))
    if (
        scope_decision.get("allowed") is False
        and scope_reason != HUMAN_APPROVAL_REASON
        and scope_reason not in blocked_reasons
    ):
        blocked_reasons.append(scope_reason)

    if blocked_reasons:
        workspace_status = STATUS_BLOCKED
        step_status = STATUS_BLOCKED
        approval_gate = ApprovalGate(
            human_approval_required=human_approval_required,
            human_approved=human_approved,
            status=STATUS_BLOCKED,
            reason="; ".join(blocked_reasons),
        )
    elif human_approval_required and not human_approved:
        workspace_status = STATUS_AWAITING_APPROVAL
        step_status = STATUS_AWAITING_APPROVAL
        approval_gate = ApprovalGate(
            human_approval_required=True,
            human_approved=False,
            status=STATUS_AWAITING_APPROVAL,
            reason="human_approval_required",
        )
    else:
        workspace_status = PREPARATION_STATUS_READY
        step_status = STATUS_READY
        approval_gate = ApprovalGate(
            human_approval_required=human_approval_required,
            human_approved=human_approved,
            status="approved" if human_approved else STATUS_READY,
            reason="human_approval_recorded" if human_approved else "human_approval_not_required",
        )

    return ValidationWorkspace(
        status=workspace_status,
        scope_decision=scope_decision.copy(),
        validation_plan_status=str(validation_plan.get("status", "unknown")),
        refutation_status=refutation_status,
        blocked_reasons=blocked_reasons,
        human_approval_required=human_approval_required,
        approval_gate=approval_gate,
        steps=_build_steps(validation_plan, step_status, normalized_evidence_hints),
        evidence_hints=normalized_evidence_hints,
    )


def _build_steps(
    validation_plan: dict[str, Any],
    step_status: str,
    evidence_hints: list[dict[str, Any]],
) -> list[ValidationStep]:
    raw_steps = validation_plan.get("steps") or [DEFAULT_BLOCKED_STEP]
    methods = [str(method) for method in validation_plan.get("methods", [])]
    steps: list[ValidationStep] = []

    for index, raw_step in enumerate(raw_steps):
        method = methods[index] if index < len(methods) else "manual_preparation"
        steps.append(
            ValidationStep(
                instruction=str(raw_step),
                method=method,
                status=step_status,
                evidence_hints=evidence_hints.copy(),
            )
        )

    return steps


__all__ = [
    "ApprovalGate",
    "ValidationStep",
    "ValidationWorkspace",
    "build_validation_workspace",
]
