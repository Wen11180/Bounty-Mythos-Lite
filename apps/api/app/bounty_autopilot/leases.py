"""Durable execution leases and atomic R3 approval consumption."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import Field, model_validator

from app.bounty_autopilot.contracts import (
    DIGEST_PATTERN,
    PolicyMode,
    RecipeRef,
    RiskTier,
    StrictContract,
)
from app.bounty_autopilot.plans import ValidationPlan


class LeaseStatus(str, Enum):
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    COMPLETED = "completed"
    AWAITING_HUMAN = "awaiting_human"


class R3ApprovalToken(StrictContract):
    approval_id: str = Field(min_length=1, max_length=128)
    plan_digest: str
    scope_snapshot_digest: str
    authorization_digest: str
    account_aliases: tuple[str, ...] = Field(default_factory=tuple)
    nonce_digest: str
    expires_at: str = Field(min_length=1, max_length=64)
    consumed_at: str | None = None
    consumed_by_lease_id: str | None = None

    @model_validator(mode="after")
    def require_digests(self) -> R3ApprovalToken:
        for value in (
            self.plan_digest,
            self.scope_snapshot_digest,
            self.authorization_digest,
            self.nonce_digest,
        ):
            if DIGEST_PATTERN.fullmatch(value) is None:
                raise ValueError("digest_required")
        return self


class ExecutionLease(StrictContract):
    lease_id: str = Field(min_length=1, max_length=128)
    plan_id: str
    plan_digest: str
    campaign_id: str
    authorization_digest: str
    scope_snapshot_digest: str
    asset_id: str
    branch_id: str
    recipe_ref: RecipeRef
    risk_tier: RiskTier
    status: LeaseStatus = LeaseStatus.ACTIVE
    r3_approval_id: str | None = None
    max_requests: int = Field(ge=1)
    requests_reserved: int = Field(ge=0, default=0)
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False
    emergency_stopped: bool = False


class LeaseIssuanceResult(StrictContract):
    allowed: bool
    reason: str
    lease: ExecutionLease | None = None
    consumed_approval_id: str | None = None


class ApprovalStore:
    """In-memory CAS store for tests; repository wraps durable rows."""

    def __init__(self) -> None:
        self._tokens: dict[str, R3ApprovalToken] = {}

    def put(self, token: R3ApprovalToken) -> None:
        self._tokens[token.approval_id] = token

    def get(self, approval_id: str) -> R3ApprovalToken | None:
        return self._tokens.get(approval_id)

    def consume(
        self,
        approval_id: str,
        *,
        lease_id: str,
        plan_digest: str,
        now_iso: str,
    ) -> R3ApprovalToken:
        token = self._tokens.get(approval_id)
        if token is None:
            raise ValueError("approval_not_found")
        if token.consumed_at is not None:
            raise ValueError("approval_already_consumed")
        if token.plan_digest != plan_digest:
            raise ValueError("approval_plan_mismatch")
        if token.expires_at <= now_iso:
            raise ValueError("approval_expired")
        updated = token.model_copy(
            update={
                "consumed_at": now_iso,
                "consumed_by_lease_id": lease_id,
            }
        )
        self._tokens[approval_id] = updated
        return updated


def execution_lease_authority_stop_reason(
    *,
    plan: ValidationPlan,
    policy_mode: PolicyMode,
    authorization_recipe_allowed: bool,
    authorization_digest: str,
    scope_snapshot_digest: str,
    emergency_stopped: bool = False,
) -> str | None:
    if emergency_stopped:
        return "emergency_stopped"
    if plan.risk_tier == RiskTier.R4:
        return "r4_cannot_create_lease"
    if plan.authorization_digest != authorization_digest:
        return "authorization_digest_mismatch"
    if plan.scope_snapshot_digest != scope_snapshot_digest:
        return "scope_snapshot_mismatch"
    if not authorization_recipe_allowed:
        return "recipe_not_authorized"
    if plan.plan_digest is None:
        return "plan_digest_required"
    if policy_mode != PolicyMode.AUTHORIZED_LOCAL_LAB and plan.risk_tier in {
        RiskTier.R1,
        RiskTier.R2,
    }:
        return "policy_mode_blocks_active_execution"
    return None


def issue_execution_lease(
    *,
    plan: ValidationPlan,
    policy_mode: PolicyMode,
    authorization_recipe_allowed: bool,
    authorization_digest: str,
    scope_snapshot_digest: str,
    lease_id: str,
    now_iso: str,
    emergency_stopped: bool = False,
    approval_store: ApprovalStore | None = None,
    approval_token: R3ApprovalToken | None = None,
) -> LeaseIssuanceResult:
    """Validate authority and optionally consume a single-use R3 approval."""

    stop_reason = execution_lease_authority_stop_reason(
        plan=plan,
        policy_mode=policy_mode,
        authorization_recipe_allowed=authorization_recipe_allowed,
        authorization_digest=authorization_digest,
        scope_snapshot_digest=scope_snapshot_digest,
        emergency_stopped=emergency_stopped,
    )
    if stop_reason is not None:
        return LeaseIssuanceResult(allowed=False, reason=stop_reason)

    if plan.risk_tier == RiskTier.R3:
        if approval_token is None or approval_store is None:
            return LeaseIssuanceResult(allowed=False, reason="r3_approval_required")
        if approval_token.plan_digest != plan.plan_digest:
            return LeaseIssuanceResult(allowed=False, reason="approval_plan_mismatch")
        if approval_token.scope_snapshot_digest != scope_snapshot_digest:
            return LeaseIssuanceResult(allowed=False, reason="approval_scope_mismatch")
        if approval_token.authorization_digest != authorization_digest:
            return LeaseIssuanceResult(allowed=False, reason="approval_authorization_mismatch")
        try:
            consumed = approval_store.consume(
                approval_token.approval_id,
                lease_id=lease_id,
                plan_digest=plan.plan_digest,
                now_iso=now_iso,
            )
        except ValueError as exc:
            return LeaseIssuanceResult(allowed=False, reason=str(exc))
        lease = ExecutionLease(
            lease_id=lease_id,
            plan_id=plan.plan_id,
            plan_digest=plan.plan_digest,
            campaign_id=plan.campaign_id,
            authorization_digest=authorization_digest,
            scope_snapshot_digest=scope_snapshot_digest,
            asset_id=plan.asset_id,
            branch_id=plan.branch_id,
            recipe_ref=plan.recipe_ref,
            risk_tier=plan.risk_tier,
            status=LeaseStatus.ACTIVE,
            r3_approval_id=consumed.approval_id,
            max_requests=plan.max_requests,
        )
        return LeaseIssuanceResult(
            allowed=True,
            reason="issued",
            lease=lease,
            consumed_approval_id=consumed.approval_id,
        )

    lease = ExecutionLease(
        lease_id=lease_id,
        plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
        campaign_id=plan.campaign_id,
        authorization_digest=authorization_digest,
        scope_snapshot_digest=scope_snapshot_digest,
        asset_id=plan.asset_id,
        branch_id=plan.branch_id,
        recipe_ref=plan.recipe_ref,
        risk_tier=plan.risk_tier,
        status=LeaseStatus.ACTIVE,
        max_requests=plan.max_requests,
    )
    return LeaseIssuanceResult(allowed=True, reason="issued", lease=lease)


def emergency_stop_leases(leases: list[ExecutionLease]) -> list[ExecutionLease]:
    stopped: list[ExecutionLease] = []
    for lease in leases:
        if lease.status is LeaseStatus.ACTIVE:
            stopped.append(
                lease.model_copy(
                    update={
                        "status": LeaseStatus.REVOKED,
                        "emergency_stopped": True,
                    }
                )
            )
        else:
            stopped.append(lease)
    return stopped


__all__ = [
    "ApprovalStore",
    "ExecutionLease",
    "LeaseIssuanceResult",
    "LeaseStatus",
    "R3ApprovalToken",
    "emergency_stop_leases",
    "execution_lease_authority_stop_reason",
    "issue_execution_lease",
]
