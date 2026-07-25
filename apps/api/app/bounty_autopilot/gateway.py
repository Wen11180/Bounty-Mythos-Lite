"""Gateway authorize/complete decisions for lab Autopilot pods."""

from __future__ import annotations

import ipaddress
from enum import Enum
from typing import Literal
from urllib.parse import unquote, urlsplit

from pydantic import Field, model_validator

from app.bounty_autopilot.contracts import PolicyMode, StrictContract
from app.bounty_autopilot.leases import ExecutionLease, LeaseStatus
from app.bounty_autopilot.plans import ValidationPlan


class GatewayDecisionStatus(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    PARK_BRANCH = "park_branch"
    STOP_ACCOUNT = "stop_account"
    STOP_CAMPAIGN = "stop_campaign"


class GatewayOutcomeClass(str, Enum):
    OK = "ok"
    WAF_CAPTCHA = "waf_captcha"
    RATE_LIMIT = "rate_limit"
    ACCOUNT_LOCK = "account_lock"
    OFF_SCOPE_REDIRECT = "off_scope_redirect"
    SESSION_EXPIRED = "session_expired"
    THIRD_PARTY_DATA = "third_party_data"
    SIZE_CEILING = "size_ceiling"
    SCOPE_ESCAPE = "scope_escape"
    DNS_REBIND = "dns_rebind"
    STALE_ADMISSION = "stale_admission"
    METHOD_MISMATCH = "method_mismatch"
    BODY_DIGEST_MISMATCH = "body_digest_mismatch"
    LEASE_INACTIVE = "lease_inactive"
    EMERGENCY_STOPPED = "emergency_stopped"


class GatewayAuthorizeRequest(StrictContract):
    url: str
    method: str
    account_alias: str | None = Field(default=None, min_length=1, max_length=64)
    body_digest: str | None = None
    is_redirect: bool = False
    is_subresource: bool = False
    resolved_ips: tuple[str, ...] = Field(default_factory=tuple)


class GatewayExecutionBinding(StrictContract):
    """Minimal server-derived request binding for the local execution pod."""

    campaign_id: str = Field(min_length=1, max_length=128)
    lease_id: str = Field(min_length=1, max_length=128)
    reservation_id: str = Field(min_length=1, max_length=128)
    plan_id: str = Field(min_length=1, max_length=128)
    plan_digest: str = Field(min_length=1, max_length=100)
    branch_id: str = Field(min_length=1, max_length=128)
    recipe_id: str = Field(min_length=1, max_length=64)
    recipe_version: str = Field(min_length=1, max_length=32)
    policy_mode: PolicyMode
    scheme: Literal["http", "https"]
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    path: str = Field(min_length=1, max_length=1024)
    method: str = Field(min_length=1, max_length=16)
    account_alias: str | None = Field(default=None, min_length=1, max_length=64)
    max_response_bytes: int = Field(ge=1, le=5_000_000)
    max_duration_seconds: int = Field(ge=1, le=86_400)
    admitted_ips: tuple[str, ...] = Field(min_length=1, max_length=32)
    transport_challenge: str = Field(min_length=32, max_length=256)

    @model_validator(mode="after")
    def enforce_account_binding(self):
        if self.recipe_id == _R2_RECIPE_ID:
            if self.account_alias not in _R2_ACCOUNT_ALIASES:
                raise ValueError("r2_account_alias_required")
            if self.method.upper() not in _R2_METHODS:
                raise ValueError("r2_method_not_allowed")
        elif self.account_alias is not None:
            raise ValueError("account_alias_not_applicable")
        return self


class GatewayAuthorizeDecision(StrictContract):
    status: GatewayDecisionStatus
    reason: str
    outcome_class: GatewayOutcomeClass | None = None
    execution_binding: GatewayExecutionBinding | None = None
    # Opaque server challenge that must be echoed in the post-send receipt.
    transport_challenge: str | None = None
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False


_LAB_HOSTS = {"127.0.0.1", "localhost", "::1"}
_R2_RECIPE_ID = "lab_two_owned_account_readonly_authz"
_R2_RECIPE_VERSION = "1.0"
_R2_ACCOUNT_ALIASES = frozenset({"account_a", "account_b"})
_R2_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _is_lab_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(addr.is_loopback or addr.is_private)


def authorize_gateway_request(
    *,
    plan: ValidationPlan,
    lease: ExecutionLease,
    request: GatewayAuthorizeRequest,
    policy_mode: PolicyMode,
    admitted_asset_id: str,
    current_scope_snapshot_digest: str,
    asset_identity_digest_current: bool,
    allowed_methods: tuple[str, ...] | None = None,
    emergency_stopped: bool = False,
) -> GatewayAuthorizeDecision:
    """Fail-closed pre-send checks. No network I/O."""

    if emergency_stopped or lease.emergency_stopped:
        return GatewayAuthorizeDecision(
            status=GatewayDecisionStatus.BLOCKED,
            reason="emergency_stopped",
            outcome_class=GatewayOutcomeClass.EMERGENCY_STOPPED,
        )
    if lease.status is not LeaseStatus.ACTIVE:
        return GatewayAuthorizeDecision(
            status=GatewayDecisionStatus.BLOCKED,
            reason="lease_inactive",
            outcome_class=GatewayOutcomeClass.LEASE_INACTIVE,
        )
    if policy_mode is not PolicyMode.AUTHORIZED_LOCAL_LAB and plan.risk_tier.value in {
        "R1",
        "R2",
        "R3",
    }:
        return GatewayAuthorizeDecision(
            status=GatewayDecisionStatus.BLOCKED,
            reason="policy_mode_blocks_active_execution",
        )
    if plan.asset_id != admitted_asset_id:
        return GatewayAuthorizeDecision(
            status=GatewayDecisionStatus.BLOCKED,
            reason="asset_not_admitted",
            outcome_class=GatewayOutcomeClass.STALE_ADMISSION,
        )
    if plan.scope_snapshot_digest != current_scope_snapshot_digest:
        return GatewayAuthorizeDecision(
            status=GatewayDecisionStatus.BLOCKED,
            reason="scope_snapshot_mismatch",
            outcome_class=GatewayOutcomeClass.STALE_ADMISSION,
        )
    if not asset_identity_digest_current:
        return GatewayAuthorizeDecision(
            status=GatewayDecisionStatus.BLOCKED,
            reason="identity_stale",
            outcome_class=GatewayOutcomeClass.STALE_ADMISSION,
        )

    is_r2 = plan.risk_tier.value == "R2"
    if is_r2:
        if (
            plan.recipe_ref.recipe_id != _R2_RECIPE_ID
            or plan.recipe_ref.version != _R2_RECIPE_VERSION
        ):
            return GatewayAuthorizeDecision(
                status=GatewayDecisionStatus.BLOCKED,
                reason="r2_recipe_not_supported",
            )
        if set(plan.account_aliases) != _R2_ACCOUNT_ALIASES or len(plan.account_aliases) != 2:
            return GatewayAuthorizeDecision(
                status=GatewayDecisionStatus.BLOCKED,
                reason="r2_owned_account_pair_required",
            )
        if request.account_alias is None:
            return GatewayAuthorizeDecision(
                status=GatewayDecisionStatus.BLOCKED,
                reason="r2_account_alias_required",
            )
        if request.account_alias not in _R2_ACCOUNT_ALIASES:
            return GatewayAuthorizeDecision(
                status=GatewayDecisionStatus.BLOCKED,
                reason="r2_account_alias_not_allowed",
            )
    elif request.account_alias is not None:
        return GatewayAuthorizeDecision(
            status=GatewayDecisionStatus.BLOCKED,
            reason="account_alias_not_applicable",
        )

    parsed = urlsplit(request.url.strip())
    if parsed.scheme not in {"http", "https"}:
        return GatewayAuthorizeDecision(
            status=GatewayDecisionStatus.BLOCKED,
            reason="unsupported_scheme",
            outcome_class=GatewayOutcomeClass.SCOPE_ESCAPE,
        )
    host = (parsed.hostname or "").lower().rstrip(".")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    decoded_path = unquote(path)
    if parsed.query or parsed.fragment:
        return GatewayAuthorizeDecision(
            status=GatewayDecisionStatus.BLOCKED,
            reason="query_or_fragment_not_authorized",
            outcome_class=GatewayOutcomeClass.SCOPE_ESCAPE,
        )
    if (
        not path.startswith("/")
        or decoded_path != path
        or "%" in path
        or any(segment in {".", ".."} for segment in decoded_path.split("/"))
        or "\\" in decoded_path
    ):
        return GatewayAuthorizeDecision(
            status=GatewayDecisionStatus.BLOCKED,
            reason="path_traversal",
            outcome_class=GatewayOutcomeClass.SCOPE_ESCAPE,
        )
    if (
        parsed.scheme != plan.destination_scheme
        or host != plan.destination_host.lower()
        or port != plan.destination_port
    ):
        return GatewayAuthorizeDecision(
            status=GatewayDecisionStatus.BLOCKED,
            reason="destination_mismatch",
            outcome_class=GatewayOutcomeClass.SCOPE_ESCAPE
            if not request.is_redirect
            else GatewayOutcomeClass.OFF_SCOPE_REDIRECT,
        )
    path_authority = plan.destination_path.rstrip("/") or "/"
    if path_authority != "/" and path not in {
        path_authority,
    } and not path.startswith(f"{path_authority}/"):
        return GatewayAuthorizeDecision(
            status=GatewayDecisionStatus.BLOCKED,
            reason="path_not_authorized",
            outcome_class=GatewayOutcomeClass.SCOPE_ESCAPE,
        )
    if host not in _LAB_HOSTS and policy_mode is PolicyMode.AUTHORIZED_LOCAL_LAB:
        # lab mode requires loopback/private destinations only
        if not any(_is_lab_ip(ip) for ip in request.resolved_ips) and host not in _LAB_HOSTS:
            return GatewayAuthorizeDecision(
                status=GatewayDecisionStatus.BLOCKED,
                reason="non_lab_destination",
                outcome_class=GatewayOutcomeClass.SCOPE_ESCAPE,
            )
    for ip in request.resolved_ips:
        if not _is_lab_ip(ip):
            return GatewayAuthorizeDecision(
                status=GatewayDecisionStatus.BLOCKED,
                reason="dns_rebind_or_public_ip",
                outcome_class=GatewayOutcomeClass.DNS_REBIND,
            )

    method = request.method.upper()
    methods = allowed_methods or plan.methods
    if is_r2 and method not in _R2_METHODS:
        return GatewayAuthorizeDecision(
            status=GatewayDecisionStatus.BLOCKED,
            reason="r2_method_not_allowed",
            outcome_class=GatewayOutcomeClass.METHOD_MISMATCH,
        )
    if method not in methods:
        return GatewayAuthorizeDecision(
            status=GatewayDecisionStatus.BLOCKED,
            reason="method_not_allowed",
            outcome_class=GatewayOutcomeClass.METHOD_MISMATCH,
        )
    if method in {"POST", "PUT", "PATCH", "DELETE"} and request.body_digest is None:
        return GatewayAuthorizeDecision(
            status=GatewayDecisionStatus.BLOCKED,
            reason="body_digest_required",
            outcome_class=GatewayOutcomeClass.BODY_DIGEST_MISMATCH,
        )

    return GatewayAuthorizeDecision(
        status=GatewayDecisionStatus.ALLOWED,
        reason="authorized",
        outcome_class=GatewayOutcomeClass.OK,
    )


def classify_response_outcome(
    *,
    status_code: int,
    response_bytes: int,
    max_response_bytes: int,
    body_markers: set[str] | frozenset[str] | None = None,
) -> GatewayOutcomeClass:
    markers = {item.lower() for item in (body_markers or set())}
    if response_bytes > max_response_bytes:
        return GatewayOutcomeClass.SIZE_CEILING
    if status_code in {429}:
        return GatewayOutcomeClass.RATE_LIMIT
    if status_code in {401, 403} and ("captcha" in markers or "waf" in markers):
        return GatewayOutcomeClass.WAF_CAPTCHA
    if "account_locked" in markers:
        return GatewayOutcomeClass.ACCOUNT_LOCK
    if "third_party" in markers or "pii_foreign" in markers:
        return GatewayOutcomeClass.THIRD_PARTY_DATA
    if "session_expired" in markers:
        return GatewayOutcomeClass.SESSION_EXPIRED
    return GatewayOutcomeClass.OK


def outcome_to_branch_action(outcome: GatewayOutcomeClass) -> GatewayDecisionStatus:
    if outcome is GatewayOutcomeClass.WAF_CAPTCHA:
        return GatewayDecisionStatus.PARK_BRANCH
    if outcome is GatewayOutcomeClass.ACCOUNT_LOCK:
        return GatewayDecisionStatus.STOP_ACCOUNT
    if outcome in {
        GatewayOutcomeClass.SCOPE_ESCAPE,
        GatewayOutcomeClass.DNS_REBIND,
        GatewayOutcomeClass.THIRD_PARTY_DATA,
    }:
        return GatewayDecisionStatus.STOP_CAMPAIGN
    if outcome is GatewayOutcomeClass.RATE_LIMIT:
        return GatewayDecisionStatus.PARK_BRANCH
    return GatewayDecisionStatus.ALLOWED


__all__ = [
    "GatewayAuthorizeDecision",
    "GatewayAuthorizeRequest",
    "GatewayDecisionStatus",
    "GatewayExecutionBinding",
    "GatewayOutcomeClass",
    "authorize_gateway_request",
    "classify_response_outcome",
    "outcome_to_branch_action",
]
