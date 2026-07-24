"""Safe Autopilot campaign projection for API / Control Center / Studio.

Never includes secrets, cookies, tokens, raw response bodies, or authorization
headers. Report and candidate promotion remain permanently blocked in this
surface.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import Field

from app.bounty_autopilot.contracts import StrictContract


_SAFE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.:-]{0,159}$", re.ASCII)
_SENSITIVE_TEXT = re.compile(
    r"(?i)(?:\bbearer\b|\bcookie\b|\bcredential\b|\bpassword\b|"
    r"\bsecret\b|\bsession\b|\btoken\b|@)"
)
_EXACT_DIFF_FIELDS = {
    "account_aliases",
    "asset_id",
    "authorization_digest",
    "branch_id",
    "container_profile",
    "max_duration_seconds",
    "max_requests",
    "max_response_bytes",
    "methods",
    "plan_digest",
    "recipe_id",
    "recipe_version",
    "risk_tier",
    "rollback_plan",
    "scope_snapshot_digest",
    "stop_conditions",
    "tool_profile",
}


class AutopilotBudgetProjection(StrictContract):
    campaign_max_requests: int = Field(ge=0, default=0)
    campaign_requests_used: int = Field(ge=0, default=0)
    campaign_requests_remaining: int = Field(ge=0, default=0)
    active_leases: int = Field(ge=0, default=0)
    reserved_requests: int = Field(ge=0, default=0)
    completed_requests: int = Field(ge=0, default=0)
    open_approvals: int = Field(ge=0, default=0)
    asset_requests_remaining: int | None = Field(default=None, ge=0)
    account_requests_remaining: int | None = Field(default=None, ge=0)
    branch_requests_remaining: int | None = Field(default=None, ge=0)
    hypothesis_requests_remaining: int | None = Field(default=None, ge=0)
    recipe_requests_remaining: int | None = Field(default=None, ge=0)
    request_slots_remaining: int | None = Field(default=None, ge=0)
    time_seconds_remaining: int | None = Field(default=None, ge=0)
    retry_attempts_remaining: int | None = Field(default=None, ge=0)
    model_cost_units_remaining: int | None = Field(default=None, ge=0)


class AutopilotAssetProjection(StrictContract):
    asset_id: str
    alias: str | None = None
    status: str
    host: str | None = None
    scheme: str | None = None
    port: int | None = None
    admitted: bool = False
    reason: str | None = None


class AutopilotBranchProjection(StrictContract):
    branch_id: str
    asset_id: str
    status: str
    priority: int = 0
    risk_tier: str | None = None
    reason: str | None = None
    dependencies: list[str] = Field(default_factory=list)
    handoff_from: str | None = None
    handoff_to: str | None = None
    specialist: str | None = None
    queue_rank: int | None = Field(default=None, ge=0)


class AutopilotExactDiffProjection(StrictContract):
    field: str
    before: str
    after: str


class AutopilotApprovalProjection(StrictContract):
    approval_id: str
    status: str
    plan_digest: str | None = None
    risk_tier: str | None = None
    consumed: bool = False
    expired: bool = False
    plan_changed: bool = False
    expires_at: str | None = None
    exact_diff: list[AutopilotExactDiffProjection] = Field(default_factory=list)


class AutopilotEventProjection(StrictContract):
    event_id: str
    kind: str
    summary: str
    created_at: str | None = None
    refs: dict[str, str] = Field(default_factory=dict)


class AutopilotCampaignProjection(StrictContract):
    campaign_id: str
    campaign_mode: str
    emergency_stopped: bool = False
    authorization_digest: str | None = None
    scope_snapshot_digest: str | None = None
    policy_mode: str | None = None
    next_branch_id: str | None = None
    next_reason: str | None = None
    budgets: AutopilotBudgetProjection
    assets: list[AutopilotAssetProjection] = Field(default_factory=list)
    branches: list[AutopilotBranchProjection] = Field(default_factory=list)
    approvals: list[AutopilotApprovalProjection] = Field(default_factory=list)
    events: list[AutopilotEventProjection] = Field(default_factory=list)
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False
    submission_blocked: Literal[True] = True


def build_autopilot_projection(
    *,
    campaign_id: str,
    campaign_mode: str = "bounty_autopilot",
    emergency_stopped: bool = False,
    authorization: dict[str, Any] | None = None,
    assets: list[dict[str, Any]] | None = None,
    branches: list[dict[str, Any]] | None = None,
    plans: list[dict[str, Any]] | None = None,
    leases: list[dict[str, Any]] | None = None,
    requests: list[dict[str, Any]] | None = None,
    observations: list[dict[str, Any]] | None = None,
    risk_decisions: list[dict[str, Any]] | None = None,
    tool_runs: list[dict[str, Any]] | None = None,
    refutations: list[dict[str, Any]] | None = None,
    candidates: list[dict[str, Any]] | None = None,
    reports: list[dict[str, Any]] | None = None,
    approvals: list[dict[str, Any]] | None = None,
    budget_remaining: dict[str, int | None] | None = None,
) -> AutopilotCampaignProjection:
    assets = assets or []
    branches = branches or []
    plans = plans or []
    leases = leases or []
    requests = requests or []
    observations = observations or []
    risk_decisions = risk_decisions or []
    tool_runs = tool_runs or []
    refutations = refutations or []
    candidates = candidates or []
    reports = reports or []
    approvals = approvals or []
    budget_remaining = budget_remaining or {}
    auth = authorization or {}

    budget_payload = auth.get("budgets") or auth.get("budget") or {}
    campaign_max = int(
        budget_payload.get("max_requests")
        or budget_payload.get("campaign_max_requests")
        or 0
    )
    used = len(
        [
            r
            for r in requests
            if str(r.get("status") or "")
            in {"reserved", "sent", "completed", "awaiting_human"}
        ]
    )
    active_leases = len([l for l in leases if str(l.get("status") or "") == "active"])
    reserved = len([r for r in requests if str(r.get("status") or "") == "reserved"])
    completed = len([r for r in requests if str(r.get("status") or "") == "completed"])
    open_approvals = len(
        [
            a
            for a in approvals
            if str(a.get("status") or "") in {"pending", "approved"}
            and not a.get("consumed")
        ]
    )

    remaining = max(0, campaign_max - used) if campaign_max else 0
    next_branch_id = None
    next_reason = "no_eligible_branch"
    ranked = sorted(
        [
            b
            for b in branches
            if str(b.get("status") or "") in {"queued", "active", "running"}
        ],
        key=lambda b: (-int(b.get("priority") or 0), str(b.get("branch_id") or "")),
    )
    if emergency_stopped:
        next_reason = "emergency_stopped"
    elif ranked:
        next_branch_id = str(ranked[0].get("branch_id"))
        next_reason = "highest_priority_eligible"

    asset_rows = [
        AutopilotAssetProjection(
            asset_id=str(a.get("asset_id") or a.get("id") or ""),
            alias=_safe_optional_text(a.get("alias"), max_length=120),
            status=str(a.get("status") or "unknown"),
            host=(a.get("host") or (a.get("identity") or {}).get("host")),
            scheme=(a.get("scheme") or (a.get("identity") or {}).get("scheme")),
            port=a.get("port") or (a.get("identity") or {}).get("port"),
            admitted=bool(a.get("admitted") or str(a.get("status") or "") == "admitted"),
            reason=_safe_optional_text(
                a.get("reason") or a.get("admission_reason"),
                max_length=200,
            ),
        )
        for a in assets
        if str(a.get("asset_id") or a.get("id") or "")
    ]
    branch_rows = [
        AutopilotBranchProjection(
            branch_id=str(b.get("branch_id") or b.get("id") or ""),
            asset_id=str(b.get("asset_id") or ""),
            status=str(b.get("status") or "unknown"),
            priority=int(b.get("priority") or 0),
            risk_tier=b.get("risk_tier"),
            reason=b.get("reason") or b.get("park_reason"),
            dependencies=_safe_id_list(b.get("dependencies")),
            handoff_from=_safe_optional_id(b.get("handoff_from")),
            handoff_to=_safe_optional_id(b.get("handoff_to")),
            specialist=_safe_optional_text(
                b.get("specialist") or b.get("specialist_alias") or b.get("agent_type"),
                max_length=80,
            ),
            queue_rank=_optional_non_negative_int(b.get("queue_rank")),
        )
        for b in branches
        if str(b.get("branch_id") or b.get("id") or "")
    ]
    approval_rows = [
        AutopilotApprovalProjection(
            approval_id=str(a.get("approval_id") or a.get("id") or ""),
            status=str(a.get("status") or "unknown"),
            plan_digest=a.get("plan_digest"),
            risk_tier=a.get("risk_tier"),
            consumed=bool(a.get("consumed") or a.get("consumed_at")),
            expired=bool(a.get("expired")),
            plan_changed=bool(a.get("plan_changed")),
            expires_at=_safe_optional_text(a.get("expires_at"), max_length=40),
            exact_diff=_safe_exact_diff(a.get("exact_diff")),
        )
        for a in approvals
        if str(a.get("approval_id") or a.get("id") or "")
    ]

    events = _build_events(
        plans=plans,
        risk_decisions=risk_decisions,
        leases=leases,
        tool_runs=tool_runs,
        observations=observations,
        refutations=refutations,
        candidates=candidates,
        reports=reports,
    )

    return AutopilotCampaignProjection(
        campaign_id=campaign_id,
        campaign_mode=campaign_mode,
        emergency_stopped=emergency_stopped,
        authorization_digest=auth.get("authorization_digest"),
        scope_snapshot_digest=auth.get("scope_snapshot_digest"),
        policy_mode=auth.get("policy_mode"),
        next_branch_id=next_branch_id,
        next_reason=next_reason,
        budgets=AutopilotBudgetProjection(
            campaign_max_requests=campaign_max,
            campaign_requests_used=used,
            campaign_requests_remaining=remaining,
            active_leases=active_leases,
            reserved_requests=reserved,
            completed_requests=completed,
            open_approvals=open_approvals,
            asset_requests_remaining=_budget_value(
                budget_remaining,
                "asset_requests_remaining",
            ),
            account_requests_remaining=_budget_value(
                budget_remaining,
                "account_requests_remaining",
            ),
            branch_requests_remaining=_budget_value(
                budget_remaining,
                "branch_requests_remaining",
            ),
            hypothesis_requests_remaining=_budget_value(
                budget_remaining,
                "hypothesis_requests_remaining",
            ),
            recipe_requests_remaining=_budget_value(
                budget_remaining,
                "recipe_requests_remaining",
            ),
            request_slots_remaining=_budget_value(
                budget_remaining,
                "request_slots_remaining",
            ),
            time_seconds_remaining=_budget_value(
                budget_remaining,
                "time_seconds_remaining",
            ),
            retry_attempts_remaining=_budget_value(
                budget_remaining,
                "retry_attempts_remaining",
            ),
            model_cost_units_remaining=_budget_value(
                budget_remaining,
                "model_cost_units_remaining",
            ),
        ),
        assets=asset_rows,
        branches=branch_rows,
        approvals=approval_rows,
        events=events,
    )


def _build_events(
    *,
    plans: list[dict[str, Any]],
    risk_decisions: list[dict[str, Any]],
    leases: list[dict[str, Any]],
    tool_runs: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    refutations: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    reports: list[dict[str, Any]],
) -> list[AutopilotEventProjection]:
    events: list[AutopilotEventProjection] = []
    groups = (
        ("plan", plans, "plan_id", "status", ("plan_id", "plan_digest", "recipe_id")),
        (
            "risk",
            risk_decisions,
            "risk_decision_id",
            "status",
            ("branch_id", "recipe_id", "risk_decision_id"),
        ),
        ("lease", leases, "lease_id", "status", ("lease_id", "plan_id")),
        (
            "tool_run",
            tool_runs,
            "tool_run_id",
            "run_status",
            ("branch_id", "lease_id", "plan_id", "tool_run_id"),
        ),
        (
            "observation",
            observations,
            "observation_id",
            "outcome_class",
            ("branch_id", "observation_id", "tool_run_id"),
        ),
        (
            "refutation",
            refutations,
            "decision_id",
            "verdict",
            ("branch_id", "decision_id"),
        ),
        (
            "candidate",
            candidates,
            "candidate_id",
            "judge_verdict",
            ("branch_id", "candidate_id"),
        ),
        (
            "report",
            reports,
            "report_id",
            "status",
            ("candidate_id", "report_id"),
        ),
    )
    ref_aliases = {
        "decision_id": "refutation_id",
        "risk_decision_id": "risk_id",
    }
    for kind, rows, id_field, status_field, ref_fields in groups:
        for row in rows[:100]:
            record_id = _safe_optional_id(row.get(id_field) or row.get("id"))
            if record_id is None:
                continue
            status = _safe_optional_text(
                row.get(status_field) or "recorded",
                max_length=64,
            ) or "recorded"
            refs: dict[str, str] = {}
            for field in ref_fields:
                value = _safe_optional_id(row.get(field))
                if value is not None:
                    refs[ref_aliases.get(field, field)] = value
            created_at = _safe_optional_text(
                row.get("created_at") or row.get("occurred_at"),
                max_length=40,
            )
            events.append(
                AutopilotEventProjection(
                    event_id=f"{kind}:{record_id}",
                    kind=kind,
                    summary=f"{kind} {record_id} {status}",
                    created_at=created_at,
                    refs=refs,
                )
            )
    order = {
        "plan": 0,
        "risk": 1,
        "lease": 2,
        "tool_run": 3,
        "observation": 4,
        "refutation": 5,
        "candidate": 6,
        "report": 7,
    }
    return sorted(
        events,
        key=lambda item: (
            item.created_at or "",
            order.get(item.kind, 99),
            item.event_id,
        ),
    )[:200]


def _safe_exact_diff(value: object) -> list[AutopilotExactDiffProjection]:
    if not isinstance(value, list):
        return []
    result: list[AutopilotExactDiffProjection] = []
    for item in value[:30]:
        if not isinstance(item, dict) or item.get("field") not in _EXACT_DIFF_FIELDS:
            continue
        before = _safe_diff_value(item.get("before"))
        after = _safe_diff_value(item.get("after"))
        if before is None or after is None:
            continue
        result.append(
            AutopilotExactDiffProjection(
                field=str(item["field"]),
                before=before,
                after=after,
            )
        )
    return result


def _safe_diff_value(value: object) -> str | None:
    if value is None:
        return "empty"
    if isinstance(value, bool | int):
        return str(value).lower()
    if not isinstance(value, str):
        return None
    return _safe_optional_text(value, max_length=240)


def _safe_optional_text(value: object, *, max_length: int) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > max_length
        or _SENSITIVE_TEXT.search(normalized)
    ):
        return None
    return normalized


def _safe_optional_id(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized if _SAFE_ID.fullmatch(normalized) is not None else None


def _safe_id_list(value: object) -> list[str]:
    if not isinstance(value, list | tuple):
        return []
    return [
        safe
        for item in value[:20]
        if (safe := _safe_optional_id(item)) is not None
    ]


def _optional_non_negative_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _budget_value(values: dict[str, int | None], key: str) -> int | None:
    return _optional_non_negative_int(values.get(key))


__all__ = [
    "AutopilotApprovalProjection",
    "AutopilotAssetProjection",
    "AutopilotBranchProjection",
    "AutopilotBudgetProjection",
    "AutopilotCampaignProjection",
    "AutopilotEventProjection",
    "AutopilotExactDiffProjection",
    "build_autopilot_projection",
]
