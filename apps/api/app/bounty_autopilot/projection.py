"""Safe Autopilot campaign projection for API / Control Center / Studio.

Never includes secrets, cookies, tokens, raw response bodies, or authorization
headers. Report and candidate promotion remain permanently blocked in this
surface.
"""

from __future__ import annotations

import re
from typing import Any, Literal
from urllib.parse import unquote_plus

from pydantic import Field

from app.bounty_autopilot.contracts import StrictContract


class AutopilotBudgetProjection(StrictContract):
    budget_ledger_valid: bool = True
    campaign_max_requests: int = Field(ge=0, default=0)
    campaign_requests_used: int = Field(ge=0, default=0)
    campaign_requests_remaining: int = Field(ge=0, default=0)
    campaign_max_duration_seconds: int = Field(ge=0, default=0)
    campaign_duration_reserved_seconds: int = Field(ge=0, default=0)
    campaign_duration_remaining_seconds: int = Field(ge=0, default=0)
    campaign_max_cost_units: int = Field(ge=0, default=0)
    campaign_cost_units_reserved: int = Field(ge=0, default=0)
    campaign_cost_units_remaining: int = Field(ge=0, default=0)
    active_leases: int = Field(ge=0, default=0)
    reserved_requests: int = Field(ge=0, default=0)
    completed_requests: int = Field(ge=0, default=0)
    open_approvals: int = Field(ge=0, default=0)


class AutopilotAssetProjection(StrictContract):
    asset_id: str
    status: str
    host: str | None = None
    scheme: str | None = None
    port: int | None = None
    admitted: bool = False


class AutopilotBranchProjection(StrictContract):
    branch_id: str
    asset_id: str
    status: str
    priority: int = 0
    risk_tier: str | None = None
    reason: str | None = None


class AutopilotCandidateProjection(StrictContract):
    """A retained Candidate Hunter result, never an executable branch."""

    candidate_id: str = Field(min_length=1, max_length=128)
    rank: int = Field(ge=1, le=5)
    vuln_type: str = Field(min_length=1, max_length=128)
    affected_endpoint: str = Field(min_length=1, max_length=256)
    affected_code_path: str = Field(min_length=1, max_length=512)
    source_fact_refs: tuple[str, ...] = Field(min_length=1, max_length=64)
    evidence_trace_status: Literal["traceable"] = "traceable"
    human_validation_readiness: Literal["ready"] = "ready"
    refutation_status: Literal["retained"] = "retained"
    safety_blockers: tuple[str, ...] = Field(min_length=1, max_length=16)
    validation_allowed: Literal[False] = False
    validation_requires_human_approval: Literal[True] = True
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False
    submission_blocked: Literal[True] = True


class AutopilotCandidateQueueProjection(StrictContract):
    status: Literal["unavailable", "ready", "invalid"] = "unavailable"
    pipeline_run_id: str | None = Field(default=None, max_length=128)
    source_stage_ids: tuple[str, ...] = Field(default_factory=tuple, max_length=12)
    candidates: list[AutopilotCandidateProjection] = Field(
        default_factory=list,
        max_length=5,
    )
    validation_allowed: Literal[False] = False
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False
    submission_blocked: Literal[True] = True


class AutopilotApprovalProjection(StrictContract):
    approval_id: str
    status: str
    plan_digest: str | None = None
    risk_tier: str | None = None
    consumed: bool = False
    expired: bool = False
    approval_diff: dict[str, Any] = Field(default_factory=dict)


class AutopilotEventProjection(StrictContract):
    event_id: str
    kind: str
    summary: str
    created_at: str | None = None
    refs: dict[str, str] = Field(default_factory=dict)


class AutopilotCampaignProjection(StrictContract):
    campaign_id: str
    campaign_mode: str
    projection_generated_at: str | None = None
    emergency_stopped: bool = False
    authorization_digest: str | None = None
    scope_snapshot_digest: str | None = None
    policy_mode: str | None = None
    next_branch_id: str | None = None
    next_reason: str | None = None
    budgets: AutopilotBudgetProjection
    assets: list[AutopilotAssetProjection] = Field(default_factory=list)
    branches: list[AutopilotBranchProjection] = Field(default_factory=list)
    candidate_queue: AutopilotCandidateQueueProjection = Field(
        default_factory=AutopilotCandidateQueueProjection
    )
    approvals: list[AutopilotApprovalProjection] = Field(default_factory=list)
    events: list[AutopilotEventProjection] = Field(default_factory=list)
    candidate_promotion_allowed: Literal[False] = False
    report_submission_allowed: Literal[False] = False
    submission_blocked: Literal[True] = True


def _status_label(value: Any) -> str:
    labels = {
        "active": "生效中",
        "approved": "已批准",
        "awaiting_human": "等待人工处理",
        "awaiting_r3": "等待 R3 审批",
        "completed": "已完成",
        "denied": "已拒绝",
        "draft": "草稿",
        "expired": "已过期",
        "issued": "已签发",
        "no_send_failure": "未发送失败",
        "pending": "待处理",
        "ready": "已就绪",
        "reserved": "已预留",
        "revoked": "已撤销",
        "sent": "已发送",
        "used": "已使用",
    }
    return labels.get(str(value or "").lower(), "未知状态")


_REQUIRED_CANDIDATE_BLOCKERS = (
    "execute_live_validation",
    "touch_real_user_data",
    "submit_report",
)
_REQUIRED_CANDIDATE_BLOCKER_SET = frozenset(_REQUIRED_CANDIDATE_BLOCKERS)
_SENSITIVE_QUERY_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "cookie",
        "password",
        "secret",
        "session",
        "token",
    }
)
_SENSITIVE_METADATA_PATTERNS = (
    re.compile(
        r"(?i)(?<![A-Za-z0-9_-])(?:x[_-]?authorization|authorization|proxy[_-]authorization|cookie|set[_-]cookie|x[_-]api[_-]?key|x[_-]auth[_-]?token|x[_-]access[_-]?token|x[_-]csrf[_-]?token|x[_-]session[_-]?token)\s*[:=]\s*\S+"
    ),
    re.compile(
        r"(?i)\b(?:access[_-]?token|api[_-]?key|authorization|cookie|password|passwd|secret|session|token)\s*=\s*\S+"
    ),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)\bbasic\s+[A-Za-z0-9+/=]{8,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
)
_MAX_METADATA_DECODE_PASSES = 8


def _contains_sensitive_metadata(value: str) -> bool:
    decoded = value
    for _ in range(_MAX_METADATA_DECODE_PASSES):
        if any(pattern.search(decoded) for pattern in _SENSITIVE_METADATA_PATTERNS):
            return True
        query = decoded.partition("?")[2].partition("#")[0]
        if any(
            unquote_plus(item.partition("=")[0]).strip().lower()
            in _SENSITIVE_QUERY_KEYS
            for item in re.split(r"[&;]", query)
            if item
        ):
            return True
        next_decoded = unquote_plus(decoded)
        if next_decoded == decoded:
            return False
        decoded = next_decoded
    return True


def _invalid_candidate_queue(
    pipeline_run_id: str | None,
) -> AutopilotCandidateQueueProjection:
    return AutopilotCandidateQueueProjection(
        status="invalid",
        pipeline_run_id=pipeline_run_id,
    )


def _candidate_queue_projection(
    value: dict[str, Any] | None,
) -> AutopilotCandidateQueueProjection:
    """Project only verified Candidate Hunter metadata into the safe API surface."""

    if not isinstance(value, dict):
        return AutopilotCandidateQueueProjection()
    raw_pipeline_run_id = value.get("pipeline_run_id")
    pipeline_run_id = (
        raw_pipeline_run_id
        if (
            isinstance(raw_pipeline_run_id, str)
            and len(raw_pipeline_run_id) <= 128
            and not _contains_sensitive_metadata(raw_pipeline_run_id)
        )
        else None
    )
    if value.get("status") == "unavailable":
        return AutopilotCandidateQueueProjection()
    if (
        value.get("status") != "ready"
        or not isinstance(pipeline_run_id, str)
        or not pipeline_run_id
        or len(pipeline_run_id) > 128
    ):
        return _invalid_candidate_queue(pipeline_run_id)

    source_stage_ids = value.get("source_stage_ids")
    candidates = value.get("candidates")
    if (
        not isinstance(source_stage_ids, list)
        or not source_stage_ids
        or len(source_stage_ids) > 12
        or any(
            not isinstance(stage_id, str)
            or not stage_id
            or len(stage_id) > 128
            or _contains_sensitive_metadata(stage_id)
            for stage_id in source_stage_ids
        )
        or len(set(source_stage_ids)) != len(source_stage_ids)
        or not isinstance(candidates, list)
        or len(candidates) > 5
    ):
        return _invalid_candidate_queue(pipeline_run_id)

    projected: list[AutopilotCandidateProjection] = []
    for item in candidates:
        if not isinstance(item, dict):
            return _invalid_candidate_queue(pipeline_run_id)
        route = item.get("route")
        refs = item.get("source_fact_refs")
        blockers = item.get("safety_blockers")
        code_path = item.get("affected_code_path")
        if (
            not isinstance(route, dict)
            or not isinstance(route.get("method"), str)
            or not isinstance(route.get("path"), str)
            or not route["method"]
            or not route["path"].startswith("/")
            or not isinstance(refs, list)
            or not refs
            or any(
                not isinstance(ref, str)
                or not ref
                or len(ref) > 512
                or _contains_sensitive_metadata(ref)
                for ref in refs
            )
            or not isinstance(code_path, str)
            or not code_path.startswith("code:")
            or code_path not in refs
            or not isinstance(blockers, list)
            or not all(
                isinstance(blocker, str)
                and blocker
                and len(blocker) <= 128
                and not _contains_sensitive_metadata(blocker)
                for blocker in blockers
            )
            or not _REQUIRED_CANDIDATE_BLOCKER_SET.issubset(set(blockers))
            or item.get("evidence_trace_status") != "traceable"
            or item.get("human_validation_readiness") != "ready"
            or any(
                item.get(field) is not False
                for field in (
                    "execution_allowed",
                    "dispatch_allowed",
                    "validation_allowed",
                    "candidate_promotion_allowed",
                    "report_submission_allowed",
                )
            )
        ):
            return _invalid_candidate_queue(pipeline_run_id)
        candidate_strings = (
            item.get("candidate_id"),
            item.get("vuln_type"),
            route["method"],
            route["path"],
            code_path,
        )
        if any(
            not isinstance(candidate_string, str)
            or _contains_sensitive_metadata(candidate_string)
            for candidate_string in candidate_strings
        ):
            return _invalid_candidate_queue(pipeline_run_id)
        try:
            projected.append(
                AutopilotCandidateProjection(
                    candidate_id=item.get("candidate_id"),
                    rank=item.get("rank"),
                    vuln_type=item.get("vuln_type"),
                    affected_endpoint=f"{route['method'].upper()} {route['path']}",
                    affected_code_path=code_path,
                    source_fact_refs=tuple(refs),
                    safety_blockers=_REQUIRED_CANDIDATE_BLOCKERS,
                )
            )
        except (TypeError, ValueError):
            return _invalid_candidate_queue(pipeline_run_id)

    if (
        [candidate.rank for candidate in projected]
        != list(range(1, len(projected) + 1))
        or len({candidate.candidate_id for candidate in projected}) != len(projected)
    ):
        return _invalid_candidate_queue(pipeline_run_id)
    return AutopilotCandidateQueueProjection(
        status="ready",
        pipeline_run_id=pipeline_run_id,
        source_stage_ids=tuple(source_stage_ids),
        candidates=projected,
    )


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
    approvals: list[dict[str, Any]] | None = None,
    candidate_queue: dict[str, Any] | None = None,
    projection_generated_at: str | None = None,
) -> AutopilotCampaignProjection:
    assets = assets or []
    branches = branches or []
    plans = plans or []
    leases = leases or []
    requests = requests or []
    observations = observations or []
    approvals = approvals or []
    auth = authorization or {}

    budget_payload = auth.get("budgets") or auth.get("budget") or {}
    campaign_max = int(
        budget_payload.get("max_requests")
        or budget_payload.get("campaign_max_requests")
        or 0
    )
    campaign_max_duration = int(
        budget_payload.get("max_duration_seconds")
        or budget_payload.get("campaign_max_time_seconds")
        or 0
    )
    campaign_max_cost = int(
        budget_payload.get("max_cost_units")
        or budget_payload.get("campaign_max_cost_units")
        or 0
    )
    authorization_id = auth.get("authorization_id")
    budget_leases = [
        lease
        for lease in leases
        if not authorization_id or lease.get("authorization_id") == authorization_id
    ]
    budget_lease_ids = {str(lease.get("lease_id") or "") for lease in budget_leases}
    budget_requests = [
        request
        for request in requests
        if not authorization_id or str(request.get("lease_id") or "") in budget_lease_ids
    ]
    budget_ledger_valid = all(
        lease.get("duration_reserved_seconds") is not None
        and lease.get("cost_units_reserved") is not None
        for lease in budget_leases
    )
    used = sum(int(lease.get("requests_reserved") or 0) for lease in budget_leases)
    duration_reserved = sum(
        int(lease.get("duration_reserved_seconds") or 0)
        for lease in budget_leases
    )
    cost_reserved = sum(
        int(lease.get("cost_units_reserved") or 0) for lease in budget_leases
    )
    active_leases = len(
        [lease for lease in budget_leases if str(lease.get("status") or "") == "active"]
    )
    reserved = len(
        [request for request in budget_requests if str(request.get("status") or "") == "reserved"]
    )
    completed = len(
        [request for request in budget_requests if str(request.get("status") or "") == "completed"]
    )
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
    elif not budget_ledger_valid:
        next_reason = "authorization_budget_ledger_invalid"
    elif ranked:
        next_branch_id = str(ranked[0].get("branch_id"))
        next_reason = "highest_priority_eligible"

    asset_rows = [
        AutopilotAssetProjection(
            asset_id=str(a.get("asset_id") or a.get("id") or ""),
            status=str(a.get("status") or "unknown"),
            host=(a.get("host") or (a.get("identity") or {}).get("host")),
            scheme=(a.get("scheme") or (a.get("identity") or {}).get("scheme")),
            port=a.get("port") or (a.get("identity") or {}).get("port"),
            admitted=bool(a.get("admitted") or str(a.get("status") or "") == "admitted"),
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
            approval_diff=dict(a.get("approval_diff") or {}),
        )
        for a in approvals
        if str(a.get("approval_id") or a.get("id") or "")
    ]

    events: list[AutopilotEventProjection] = []
    for plan in plans[:20]:
        events.append(
            AutopilotEventProjection(
                event_id=f"plan:{plan.get('plan_id') or plan.get('id')}",
                kind="plan",
                summary=(
                    f"计划 {plan.get('plan_id') or plan.get('id')} "
                    f"{_status_label(plan.get('status'))}"
                ),
                created_at=plan.get("created_at"),
                refs={
                    "plan_id": str(plan.get("plan_id") or plan.get("id") or ""),
                    "plan_digest": str(plan.get("plan_digest") or ""),
                },
            )
        )
    for lease in leases[:20]:
        events.append(
            AutopilotEventProjection(
                event_id=f"lease:{lease.get('lease_id')}",
                kind="lease",
                summary=(
                    f"租约 {lease.get('lease_id')} "
                    f"{_status_label(lease.get('status'))}"
                ),
                created_at=lease.get("created_at"),
                refs={
                    "lease_id": str(lease.get("lease_id") or ""),
                    "plan_id": str(lease.get("plan_id") or ""),
                },
            )
        )
    for request in requests[:20]:
        events.append(
            AutopilotEventProjection(
                event_id=f"tool_run:{request.get('reservation_id')}",
                kind="tool_run",
                summary=(
                    f"工具运行 {request.get('reservation_id')} "
                    f"{_status_label(request.get('status'))}"
                ),
                created_at=request.get("created_at"),
                refs={
                    "reservation_id": str(request.get("reservation_id") or ""),
                    "lease_id": str(request.get("lease_id") or ""),
                },
            )
        )
    for approval in approvals[:20]:
        events.append(
            AutopilotEventProjection(
                event_id=f"risk:{approval.get('approval_id')}",
                kind="risk",
                summary=(
                    f"审批 {approval.get('approval_id')} "
                    f"{_status_label(approval.get('status'))}"
                ),
                created_at=approval.get("created_at"),
                refs={
                    "approval_id": str(approval.get("approval_id") or ""),
                    "plan_digest": str(approval.get("plan_digest") or ""),
                },
            )
        )
    for obs in observations[:20]:
        events.append(
            AutopilotEventProjection(
                event_id=f"obs:{obs.get('observation_id')}",
                kind="observation",
                summary=str(obs.get("summary") or obs.get("outcome_class") or "观察记录"),
                created_at=obs.get("created_at"),
                refs={
                    "observation_id": str(obs.get("observation_id") or ""),
                    "branch_id": str(obs.get("branch_id") or ""),
                },
            )
        )

    return AutopilotCampaignProjection(
        campaign_id=campaign_id,
        campaign_mode=campaign_mode,
        projection_generated_at=projection_generated_at,
        emergency_stopped=emergency_stopped,
        authorization_digest=auth.get("authorization_digest"),
        scope_snapshot_digest=auth.get("scope_snapshot_digest"),
        policy_mode=auth.get("policy_mode"),
        next_branch_id=next_branch_id,
        next_reason=next_reason,
        budgets=AutopilotBudgetProjection(
            budget_ledger_valid=budget_ledger_valid,
            campaign_max_requests=campaign_max,
            campaign_requests_used=used,
            campaign_requests_remaining=remaining,
            campaign_max_duration_seconds=campaign_max_duration,
            campaign_duration_reserved_seconds=duration_reserved,
            campaign_duration_remaining_seconds=max(
                0,
                campaign_max_duration - duration_reserved,
            ),
            campaign_max_cost_units=campaign_max_cost,
            campaign_cost_units_reserved=cost_reserved,
            campaign_cost_units_remaining=max(0, campaign_max_cost - cost_reserved),
            active_leases=active_leases,
            reserved_requests=reserved,
            completed_requests=completed,
            open_approvals=open_approvals,
        ),
        assets=asset_rows,
        branches=branch_rows,
        candidate_queue=_candidate_queue_projection(candidate_queue),
        approvals=approval_rows,
        events=events,
    )


__all__ = [
    "AutopilotApprovalProjection",
    "AutopilotAssetProjection",
    "AutopilotBranchProjection",
    "AutopilotBudgetProjection",
    "AutopilotCandidateProjection",
    "AutopilotCandidateQueueProjection",
    "AutopilotCampaignProjection",
    "AutopilotEventProjection",
    "build_autopilot_projection",
]
