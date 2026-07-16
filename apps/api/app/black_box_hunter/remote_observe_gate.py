"""Remote observe fail-closed gate for dual-intake black-box plans.

Sits in front of RemoteLeaseRuntime. Never sends HTTP and never requires a real
bounty target. Without an enabled profile, active lease runtime, and two live
session refs, the engine stays plan-only.

Per-request authorization still goes through RemoteLeaseRuntime.authorize when
an operator supplies a dry-run context; this module only packages that decision
into a research-safe gate result.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Sequence

from app.black_box_hunter import LeaseApproval
from app.black_box_hunter.browser_demo_intake import demo_package_to_role_hars
from app.black_box_hunter.har_intake import run_har_plan_only_pipeline
from app.black_box_hunter.remote_profile import (
    REMOTE_PROFILE,
    RemoteAuthorizationDecision,
    RemoteLeaseRuntime,
    RemoteRequestAuthorization,
)
from app.scope_guard import ScopeGuardRule

GateMode = Literal["plan_only", "lease_bound_observe_eligible"]


def assess_remote_observe_gate(
    *,
    profile_enabled: bool = False,
    runtime: RemoteLeaseRuntime | None = None,
    live_session_refs: Sequence[str] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Decide whether remote observation may be attempted.

    Eligibility is not execution permission. Report submission stays blocked.
    """
    clock = now or datetime.now(timezone.utc)
    if clock.tzinfo is None or clock.utcoffset() is None:
        raise ValueError("timezone_aware_time_required")

    sessions = [str(item) for item in (live_session_refs or []) if str(item)]
    base = {
        "profile": REMOTE_PROFILE,
        "profile_enabled": bool(profile_enabled),
        "live_session_count": len(set(sessions)),
        "live_session_refs": sorted(set(sessions)),
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
        "human_confirmation_allowed": False,
        "http_requests_attempted": 0,
        "raw_secrets_persisted": False,
    }

    if not profile_enabled:
        return {
            **base,
            "mode": "plan_only",
            "observe_allowed": False,
            "reason": "remote_profile_disabled",
            "lease_status": None,
        }

    if runtime is None:
        return {
            **base,
            "mode": "plan_only",
            "observe_allowed": False,
            "reason": "remote_lease_runtime_required",
            "lease_status": None,
        }

    # Runtime must not be serializable; only safe_status enters research plane.
    lease_status = runtime.safe_status(now=clock)
    if lease_status.get("state") != "active":
        reason = "remote_lease_not_active"
        if lease_status.get("stop_reason"):
            reason = f"remote_lease_stopped:{lease_status['stop_reason']}"
        elif lease_status.get("state") == "expired":
            reason = "remote_lease_expired"
        return {
            **base,
            "mode": "plan_only",
            "observe_allowed": False,
            "reason": reason,
            "lease_status": lease_status,
        }

    if len(set(sessions)) < 2:
        return {
            **base,
            "mode": "plan_only",
            "observe_allowed": False,
            "reason": "two_live_sessions_required",
            "lease_status": lease_status,
        }

    return {
        **base,
        "mode": "lease_bound_observe_eligible",
        "observe_allowed": True,
        "reason": "lease_and_sessions_present",
        "lease_status": lease_status,
        # Still not auto-executing remote traffic; caller must authorize each request.
        "execution_allowed": False,
        "validation_allowed": False,
    }


def dry_run_remote_authorize(
    runtime: RemoteLeaseRuntime,
    *,
    rule: ScopeGuardRule,
    approval: LeaseApproval,
    request: RemoteRequestAuthorization,
    current_policy_digest: str,
    current_scope_digest: str,
    current_plan_digest: str,
    lease_digest: str,
    now: datetime,
) -> dict[str, Any]:
    """Run one authorize check without performing HTTP.

    Returns a research-safe projection of RemoteAuthorizationDecision.
    """
    decision = runtime.authorize(
        rule=rule,
        approval=approval,
        request=request,
        current_policy_digest=current_policy_digest,
        current_scope_digest=current_scope_digest,
        current_plan_digest=current_plan_digest,
        lease_digest=lease_digest,
        now=now,
    )
    return _project_decision(decision)


def run_remote_fail_closed_pipeline(
    role_hars: dict[str, dict[str, Any]],
    *,
    profile_enabled: bool = False,
    runtime: RemoteLeaseRuntime | None = None,
    live_session_refs: Sequence[str] | None = None,
    now: datetime | None = None,
    account_aliases: dict[str, str] | None = None,
    role_aliases: dict[str, str] | None = None,
    role_ranks: dict[str, int] | None = None,
    source: Literal["har", "browser_demo"] = "har",
    dry_run: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Dual-intake plans + remote fail-closed gate. Never sends HTTP."""
    plan_result = run_har_plan_only_pipeline(
        role_hars,
        account_aliases=account_aliases,
        role_aliases=role_aliases,
        role_ranks=role_ranks,
    )
    gate = assess_remote_observe_gate(
        profile_enabled=profile_enabled,
        runtime=runtime,
        live_session_refs=live_session_refs,
        now=now,
    )

    authorize_projection: dict[str, Any] | None = None
    if dry_run is not None:
        if not gate["observe_allowed"]:
            authorize_projection = {
                "allowed": False,
                "reason": "gate_blocks_authorize",
                "gate_reason": gate["reason"],
                "request_grant_id": None,
                "report_submission_allowed": False,
                "human_confirmation_allowed": False,
            }
        else:
            if runtime is None:
                raise ValueError("remote_lease_runtime_required")
            authorize_projection = dry_run_remote_authorize(
                runtime,
                rule=dry_run["rule"],
                approval=dry_run["approval"],
                request=dry_run["request"],
                current_policy_digest=str(dry_run["current_policy_digest"]),
                current_scope_digest=str(dry_run["current_scope_digest"]),
                current_plan_digest=str(dry_run["current_plan_digest"]),
                lease_digest=str(dry_run["lease_digest"]),
                now=dry_run["now"],
            )

    return {
        "schema_version": "remote_fail_closed_pipeline_v1",
        "source": source,
        "profile": REMOTE_PROFILE,
        "gate": gate,
        "mode": gate["mode"],
        "plan_only": plan_result,
        "candidates": plan_result.get("candidates", []),
        "authorize_dry_run": authorize_projection,
        "execution_allowed": False,
        "dispatch_allowed": False,
        "validation_allowed": False,
        "candidate_promotion_allowed": False,
        "report_submission_allowed": False,
        "http_requests_attempted": 0,
        "raw_secrets_persisted": False,
    }


def run_har_remote_fail_closed_pipeline(
    role_hars: dict[str, dict[str, Any]],
    **kwargs: Any,
) -> dict[str, Any]:
    return run_remote_fail_closed_pipeline(role_hars, source="har", **kwargs)


def run_browser_demo_remote_fail_closed_pipeline(
    demo_a: dict[str, Any],
    demo_b: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any]:
    role_hars, account_aliases, role_aliases, role_ranks = demo_package_to_role_hars(
        demo_a, demo_b
    )
    # Caller kwargs may override aliases; defaults from demo packages win if absent.
    kwargs.setdefault("account_aliases", account_aliases)
    kwargs.setdefault("role_aliases", role_aliases)
    kwargs.setdefault("role_ranks", role_ranks)
    return run_remote_fail_closed_pipeline(
        role_hars,
        source="browser_demo",
        **kwargs,
    )


def _project_decision(decision: RemoteAuthorizationDecision) -> dict[str, Any]:
    return {
        "allowed": decision.allowed,
        "reason": decision.reason,
        "request_grant_id": decision.request_grant_id,
        "stop_reason": decision.stop.reason if decision.stop is not None else None,
        "report_submission_allowed": decision.report_submission_allowed,
        "human_confirmation_allowed": decision.human_confirmation_allowed,
    }
