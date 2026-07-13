"""Durable / offline human review approvals for residual + patch stages.

Lawful research only:
- Records human residual_review and patch_review decisions
- Never unlocks live validation, report submission, auto-PR, or patch_ready
- Supports in-memory audit payloads, package-file offline records, and optional DB ApprovalRecord

Fail-closed:
- Missing / expired / denied / rejected_fp => no residual ready-context or patch acceptance
- Approvals only affect human-review context flags
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


APPROVAL_KIND_RESIDUAL = "residual_review"
APPROVAL_KIND_PATCH = "patch_review"
ALLOWED_KINDS = {APPROVAL_KIND_RESIDUAL, APPROVAL_KIND_PATCH}

STATUS_REQUESTED = "requested"
STATUS_PENDING = "pending"
STATUS_APPROVED = "approved"
STATUS_DENIED = "denied"
STATUS_REJECTED_FP = "rejected_fp"
STATUS_WAIVED = "waived"
STATUS_EXPIRED = "expired"
STATUS_REVOKED = "revoked"

INITIAL_STATUSES = {STATUS_REQUESTED, STATUS_PENDING}
TERMINAL_STATUSES = {
    STATUS_APPROVED,
    STATUS_DENIED,
    STATUS_REJECTED_FP,
    STATUS_WAIVED,
    STATUS_EXPIRED,
    STATUS_REVOKED,
}
DECISION_STATUSES = {
    STATUS_APPROVED,
    STATUS_DENIED,
    STATUS_REJECTED_FP,
    STATUS_WAIVED,
    STATUS_EXPIRED,
    STATUS_REVOKED,
}

_BLOCKED_NAME_PARTS = (
    "secret",
    "token",
    "cookie",
    "credential",
    "password",
    "apikey",
    "api_key",
)

_SECRET_KEY_RE = re.compile(
    r"(secret|token|cookie|password|authorization|api[_-]?key|credential|bearer)",
    re.IGNORECASE,
)
_SECRET_VALUE_RE = re.compile(
    r"(?i)(bearer\s+[a-z0-9._\-+=/]{8,}|api[_-]?key\s*[:=]\s*\S+|password\s*[:=]\s*\S+)"
)


class HumanReviewApprovalError(ValueError):
    pass


class HumanReviewApproval(BaseModel):
    """Audit-safe human residual/patch review decision (context only)."""

    approval_id: str = ""
    approval_kind: str
    status: str = STATUS_REQUESTED
    package_id: str = ""
    candidate_id: str = ""
    root_cause_id: str = ""
    actor: str = ""
    reason: str = ""
    decision_reason: str = ""
    decided_by: str = ""
    decided_at: str | None = None
    expires_at: str | None = None
    source: str = "memory"  # memory | package_file | database
    source_path: str = ""
    payload: dict[str, Any] = Field(default_factory=dict)
    residual_context_cleared: bool = False
    residual_rejected: bool = False
    patch_review_accepted: bool = False
    patch_review_rejected: bool = False
    human_review_required: bool = True
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    auto_pr_allowed: bool = False
    patch_ready: bool = False
    pr_opened: bool = False
    next_allowed_action: str = (
        "Human residual/patch review record only; no execution or submission."
    )
    safety_blockers: list[str] = Field(
        default_factory=lambda: [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
            "auto_promote_finding",
            "auto_open_pull_request",
            "write_exploit_poc",
        ]
    )

def build_human_review_approval(
    *,
    approval_kind: str,
    package_id: str = "",
    candidate_id: str = "",
    root_cause_id: str = "",
    actor: str = "unknown",
    reason: str = "",
    status: str = STATUS_REQUESTED,
    decision_reason: str = "",
    decided_by: str = "",
    decided_at: str | datetime | None = None,
    expires_at: str | datetime | None = None,
    payload: dict[str, Any] | None = None,
    source: str = "memory",
    source_path: str = "",
    approval_id: str | None = None,
) -> HumanReviewApproval:
    """Create a fail-closed residual/patch review approval audit record."""
    kind = _normalize_kind(approval_kind)
    st = _normalize_status(status)
    record = HumanReviewApproval(
        approval_id=str(approval_id or f"hreview_{uuid4().hex}"),
        approval_kind=kind,
        status=st,
        package_id=str(package_id or ""),
        candidate_id=str(candidate_id or ""),
        root_cause_id=str(root_cause_id or ""),
        actor=_safe_text(actor) or "unknown",
        reason=_safe_text(reason),
        decision_reason=_safe_text(decision_reason),
        decided_by=_safe_text(decided_by),
        decided_at=_as_iso(decided_at),
        expires_at=_as_iso(expires_at),
        source=str(source or "memory"),
        source_path=str(source_path or ""),
        payload=_safe_payload(payload or {}),
    )
    return _apply_decision_context(_force_safety_model(record))


def decide_human_review_approval(
    approval: HumanReviewApproval | dict[str, Any],
    *,
    decision: str,
    actor: str,
    reason: str = "",
    now: datetime | None = None,
) -> HumanReviewApproval:
    """Apply a human decision; never unlocks execution/submit/auto-PR."""
    record = (
        approval
        if isinstance(approval, HumanReviewApproval)
        else HumanReviewApproval.model_validate(approval)
    )
    if record.status in TERMINAL_STATUSES and record.status not in INITIAL_STATUSES:
        return _apply_decision_context(_force_safety_model(record))

    dec = _normalize_status(decision)
    if dec not in DECISION_STATUSES:
        raise HumanReviewApprovalError(f"unsupported_decision:{decision}")

    if _is_expired(record, now=now) and dec == STATUS_APPROVED:
        dec = STATUS_EXPIRED

    record = record.model_copy(
        update={
            "status": dec,
            "decided_by": _safe_text(actor) or "unknown",
            "decision_reason": _safe_text(reason),
            "decided_at": _as_iso(now or datetime.now(UTC)),
        }
    )
    return _apply_decision_context(_force_safety_model(record))


def residual_flags_from_approval(
    approval: HumanReviewApproval | dict[str, Any] | None,
    *,
    now: datetime | None = None,
) -> dict[str, bool]:
    """Map residual_review decision into gate context flags only."""
    empty = {
        "human_approved": False,
        "human_rejected": False,
        "residual_context_cleared": False,
        "has_decision": False,
        "active": False,
    }
    if approval is None:
        return empty
    record = (
        approval
        if isinstance(approval, HumanReviewApproval)
        else HumanReviewApproval.model_validate(approval)
    )
    if record.approval_kind != APPROVAL_KIND_RESIDUAL:
        return empty
    if _is_expired(record, now=now):
        return {**empty, "has_decision": True, "active": False}
    status = record.status
    if status in {STATUS_APPROVED, STATUS_WAIVED}:
        return {
            "human_approved": True,
            "human_rejected": False,
            "residual_context_cleared": True,
            "has_decision": True,
            "active": True,
        }
    if status in {STATUS_DENIED, STATUS_REJECTED_FP, STATUS_REVOKED}:
        return {
            "human_approved": False,
            "human_rejected": True,
            "residual_context_cleared": False,
            "has_decision": True,
            "active": True,
        }
    return {**empty, "has_decision": status not in INITIAL_STATUSES, "active": False}


def patch_context_from_approval(
    approval: HumanReviewApproval | dict[str, Any] | None,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Map patch_review decision into advisory context only (never patch_ready)."""
    empty = {
        "human_patch_reviewed": False,
        "patch_review_accepted": False,
        "patch_review_rejected": False,
        "disposition": "none",
        "has_decision": False,
        "active": False,
        "patch_ready": False,
        "auto_pr_allowed": False,
        "pr_opened": False,
    }
    if approval is None:
        return empty
    record = (
        approval
        if isinstance(approval, HumanReviewApproval)
        else HumanReviewApproval.model_validate(approval)
    )
    if record.approval_kind != APPROVAL_KIND_PATCH:
        return empty
    if _is_expired(record, now=now):
        return {
            **empty,
            "has_decision": True,
            "disposition": "expired",
            "active": False,
        }
    status = record.status
    if status == STATUS_APPROVED:
        return {
            "human_patch_reviewed": True,
            "patch_review_accepted": True,
            "patch_review_rejected": False,
            "disposition": "accepted_advisory_only",
            "has_decision": True,
            "active": True,
            "patch_ready": False,
            "auto_pr_allowed": False,
            "pr_opened": False,
        }
    if status == STATUS_WAIVED:
        return {
            "human_patch_reviewed": True,
            "patch_review_accepted": False,
            "patch_review_rejected": False,
            "disposition": "waived_no_patch",
            "has_decision": True,
            "active": True,
            "patch_ready": False,
            "auto_pr_allowed": False,
            "pr_opened": False,
        }
    if status in {STATUS_DENIED, STATUS_REJECTED_FP, STATUS_REVOKED}:
        return {
            "human_patch_reviewed": True,
            "patch_review_accepted": False,
            "patch_review_rejected": True,
            "disposition": "rejected",
            "has_decision": True,
            "active": True,
            "patch_ready": False,
            "auto_pr_allowed": False,
            "pr_opened": False,
        }
    return {
        **empty,
        "has_decision": status not in INITIAL_STATUSES,
        "disposition": status,
    }

def load_package_human_review_approvals(
    package_root: str | Path | None,
) -> dict[str, Any]:
    """Optional offline human review approvals auto-ingest from an authorized package.

    Looks for:
    - inputs/human_review_approvals.json
    - inputs/approvals.json
    - inputs/approvals/*.json
    - _extract/HUMAN_REVIEW_APPROVALS.json
    - HUMAN_REVIEW_APPROVALS.json
    """
    empty = {
        "present": False,
        "package_root": str(package_root or ""),
        "sources": [],
        "approvals": [],
        "skipped": [],
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
        "auto_pr_allowed": False,
        "patch_ready": False,
    }
    if package_root is None or str(package_root).strip() == "":
        return empty
    root = Path(package_root).resolve()
    if not root.is_dir():
        return {**empty, "package_root": str(root), "skipped": ["package_root_missing"]}

    candidate_paths: list[Path] = [
        root / "inputs" / "human_review_approvals.json",
        root / "inputs" / "approvals.json",
        root / "_extract" / "HUMAN_REVIEW_APPROVALS.json",
        root / "HUMAN_REVIEW_APPROVALS.json",
    ]
    approvals_dir = root / "inputs" / "approvals"
    if approvals_dir.is_dir():
        candidate_paths.extend(
            sorted(p for p in approvals_dir.rglob("*.json") if p.is_file())
        )

    seen: set[str] = set()
    files: list[Path] = []
    for path in candidate_paths:
        if not path.is_file():
            continue
        key = str(path.resolve())
        if key in seen:
            continue
        seen.add(key)
        files.append(path)
    if not files:
        return {**empty, "package_root": str(root)}

    approvals: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    skipped: list[str] = []
    seen_ids: set[str] = set()

    for path in files:
        try:
            resolved = path.resolve()
            resolved.relative_to(root)
        except Exception:
            skipped.append(f"outside_package:{path.name}")
            continue
        name_l = path.name.lower()
        if any(part in name_l for part in _BLOCKED_NAME_PARTS):
            skipped.append(f"blocked_filename:{path.name}")
            continue
        try:
            raw = json.loads(resolved.read_text(encoding="utf-8"))
        except Exception:
            skipped.append(f"unreadable:{path.name}")
            continue
        parsed = _parse_approvals_json(
            raw,
            package_id=root.name,
            source_path=str(resolved.relative_to(root)).replace("\\", "/"),
        )
        for item in parsed:
            aid = str(item.get("approval_id") or "")
            if aid and aid in seen_ids:
                continue
            if aid:
                seen_ids.add(aid)
            approvals.append(item)
        sources.append(
            {
                "path": str(resolved.relative_to(root)).replace("\\", "/"),
                "count": len(parsed),
            }
        )

    return {
        "present": bool(approvals),
        "package_root": str(root),
        "sources": sources,
        "approvals": approvals,
        "skipped": skipped,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
        "auto_pr_allowed": False,
        "patch_ready": False,
    }


def resolve_human_review_approvals(
    *,
    approvals: list[HumanReviewApproval | dict[str, Any]] | None = None,
    approvals_bundle: dict[str, Any] | None = None,
    package_root: str | Path | None = None,
    bridge_result: dict[str, Any] | None = None,
    trial_result: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Prefer explicit approvals, then bundle, then trial/bridge, then package load."""
    if approvals is not None:
        return [_dump_approval(a) for a in approvals]

    if isinstance(approvals_bundle, dict) and approvals_bundle.get("present"):
        items = approvals_bundle.get("approvals") or []
        return [
            _dump_approval(a)
            for a in items
            if isinstance(a, (dict, HumanReviewApproval))
        ]

    trial = trial_result if isinstance(trial_result, dict) else {}
    bridge = bridge_result if isinstance(bridge_result, dict) else {}
    for source in (trial, bridge):
        raw = source.get("human_review_approvals")
        if isinstance(raw, list) and raw:
            return [_dump_approval(a) for a in raw]
        bundle = source.get("human_review_approvals_bundle")
        if isinstance(bundle, dict) and bundle.get("present"):
            items = bundle.get("approvals") or []
            return [
                _dump_approval(a)
                for a in items
                if isinstance(a, (dict, HumanReviewApproval))
            ]

    root = (
        package_root
        or trial.get("package_root")
        or bridge.get("package_root")
        or None
    )
    if root:
        loaded = load_package_human_review_approvals(root)
        if loaded.get("present"):
            return list(loaded.get("approvals") or [])
    return []


def select_approval_for_candidate(
    approvals: list[HumanReviewApproval | dict[str, Any]],
    *,
    approval_kind: str,
    package_id: str = "",
    candidate_id: str = "",
) -> dict[str, Any] | None:
    """Pick the best matching approval for a candidate (exact id, then package-wide)."""
    kind = _normalize_kind(approval_kind)
    items = [_dump_approval(a) for a in approvals]
    kind_items = [a for a in items if a.get("approval_kind") == kind]
    if not kind_items:
        return None

    cid = str(candidate_id or "")
    pid = str(package_id or "")

    def package_matches(approval: dict[str, Any]) -> bool:
        approval_package_id = str(approval.get("package_id") or "")
        if not pid:
            return not approval_package_id
        return not approval_package_id or approval_package_id == pid

    if cid:
        exact = [
            a
            for a in kind_items
            if str(a.get("candidate_id") or "") == cid
            and package_matches(a)
        ]
        if exact:
            return _prefer_decided(exact)

    package_wide = [
        a
        for a in kind_items
        if not str(a.get("candidate_id") or "")
        and package_matches(a)
    ]
    if package_wide:
        return _prefer_decided(package_wide)
    return None

def attach_human_review_approvals_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    approvals: list[HumanReviewApproval | dict[str, Any]] | None = None,
    approvals_bundle: dict[str, Any] | None = None,
    package_root: str | Path | None = None,
    trial_result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Attach residual/patch human review approvals as audit context on bridge result.

    Does not unlock execution, validation, submission, auto-PR, or patch_ready.
    """
    if not isinstance(bridge_result, dict):
        raise HumanReviewApprovalError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")
    resolved = resolve_human_review_approvals(
        approvals=approvals,
        approvals_bundle=approvals_bundle,
        package_root=resolved_root,
        bridge_result=bridge_result,
        trial_result=trial_result,
    )
    safe_list = [_dump_approval(a) for a in resolved]

    residual_approvals = [
        a for a in safe_list if a.get("approval_kind") == APPROVAL_KIND_RESIDUAL
    ]
    patch_approvals = [
        a for a in safe_list if a.get("approval_kind") == APPROVAL_KIND_PATCH
    ]

    drafts = bridge_result.get("drafts") if isinstance(bridge_result.get("drafts"), list) else []
    enriched_drafts: list[dict[str, Any]] = []
    for draft in drafts:
        if not isinstance(draft, dict):
            continue
        cid = str(draft.get("candidate_id") or "")
        residual = select_approval_for_candidate(
            residual_approvals,
            approval_kind=APPROVAL_KIND_RESIDUAL,
            package_id=package_id,
            candidate_id=cid,
        )
        patch = select_approval_for_candidate(
            patch_approvals,
            approval_kind=APPROVAL_KIND_PATCH,
            package_id=package_id,
            candidate_id=cid,
        )
        residual_flags = residual_flags_from_approval(residual)
        patch_ctx = patch_context_from_approval(patch)
        enriched = {
            **draft,
            "human_review_residual_approval": residual,
            "human_review_patch_approval": patch,
            "human_review_residual_flags": residual_flags,
            "human_review_patch_context": patch_ctx,
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
            "confirmed_vulnerability": False,
        }
        if isinstance(enriched.get("patch_suggestion"), dict):
            ps = dict(enriched["patch_suggestion"])
            ps["human_patch_reviewed"] = bool(patch_ctx.get("human_patch_reviewed"))
            ps["patch_review_accepted"] = bool(patch_ctx.get("patch_review_accepted"))
            ps["patch_review_rejected"] = bool(patch_ctx.get("patch_review_rejected"))
            ps["patch_review_disposition"] = patch_ctx.get("disposition")
            ps["patch_ready"] = False
            ps["auto_pr_allowed"] = False
            ps["pr_opened"] = False
            ps["execution_allowed"] = False
            ps["report_submission_allowed"] = False
            ps["confirmed_vulnerability"] = False
            enriched["patch_suggestion"] = ps
        enriched_drafts.append(enriched)

    present = bool(safe_list)
    if isinstance(approvals_bundle, dict):
        loaded_bundle = approvals_bundle
    elif resolved_root:
        loaded_bundle = load_package_human_review_approvals(resolved_root)
    else:
        loaded_bundle = {
            "present": present,
            "approvals": safe_list,
            "sources": [],
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
            "confirmed_vulnerability": False,
            "auto_pr_allowed": False,
            "patch_ready": False,
        }

    decided_statuses = {
        STATUS_APPROVED,
        STATUS_DENIED,
        STATUS_REJECTED_FP,
        STATUS_WAIVED,
        STATUS_EXPIRED,
        STATUS_REVOKED,
    }
    decided_n = sum(1 for a in safe_list if str(a.get("status") or "") in decided_statuses)
    approved_n = sum(1 for a in safe_list if str(a.get("status") or "") == STATUS_APPROVED)
    denied_n = sum(
        1
        for a in safe_list
        if str(a.get("status") or "") in {STATUS_DENIED, STATUS_REJECTED_FP, STATUS_REVOKED}
    )
    waived_n = sum(1 for a in safe_list if str(a.get("status") or "") == STATUS_WAIVED)
    residual_decided_n = sum(
        1
        for a in residual_approvals
        if str(a.get("status") or "") in decided_statuses
    )
    patch_decided_n = sum(
        1 for a in patch_approvals if str(a.get("status") or "") in decided_statuses
    )
    residual_cleared_n = sum(
        1
        for a in residual_approvals
        if str(a.get("status") or "") in {STATUS_APPROVED, STATUS_WAIVED}
    )
    patch_accepted_n = sum(
        1 for a in patch_approvals if str(a.get("status") or "") == STATUS_APPROVED
    )

    if present and decided_n:
        status = "human_review_approvals_ready"
    elif present:
        status = "human_review_approvals_pending"
    else:
        status = "human_review_approvals_empty"

    summary = {
        "status": status,
        "present": present,
        "approval_count": len(safe_list),
        "residual_count": len(residual_approvals),
        "patch_count": len(patch_approvals),
        "decided_count": decided_n,
        "approved_count": approved_n,
        "denied_count": denied_n,
        "waived_count": waived_n,
        "residual_decided_count": residual_decided_n,
        "patch_decided_count": patch_decided_n,
        "residual_context_cleared_count": residual_cleared_n,
        "patch_accepted_advisory_count": patch_accepted_n,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
        "auto_pr_allowed": False,
        "patch_ready": False,
        "pr_opened": False,
        "finding_promotion_allowed": False,
    }

    return {
        **bridge_result,
        "package_root": str(resolved_root or bridge_result.get("package_root") or ""),
        "drafts": enriched_drafts if enriched_drafts else drafts,
        "human_review_approvals": safe_list,
        "human_review_approvals_bundle": {
            **(loaded_bundle if isinstance(loaded_bundle, dict) else {}),
            "present": present
            or bool(isinstance(loaded_bundle, dict) and loaded_bundle.get("present")),
            "approvals": safe_list
            or list(
                (loaded_bundle or {}).get("approvals")
                if isinstance(loaded_bundle, dict)
                else []
            ),
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
            "confirmed_vulnerability": False,
            "auto_pr_allowed": False,
            "patch_ready": False,
        },
        "human_review_approvals_present": present,
        "human_review_approvals_status": status,
        "human_review_approvals_count": len(safe_list),
        "human_review_approvals_residual_count": len(residual_approvals),
        "human_review_approvals_patch_count": len(patch_approvals),
        "human_review_approvals_decided_count": decided_n,
        "human_review_approvals_approved_count": approved_n,
        "human_review_approvals_denied_count": denied_n,
        "human_review_approvals_waived_count": waived_n,
        "human_review_approvals_residual_decided_count": residual_decided_n,
        "human_review_approvals_patch_decided_count": patch_decided_n,
        "human_review_approvals_residual_context_cleared_count": residual_cleared_n,
        "human_review_approvals_patch_accepted_advisory_count": patch_accepted_n,
        "human_review_approvals_summary": summary,
        "human_residual_approvals": residual_approvals,
        "human_patch_approvals": patch_approvals,
        "human_review_required": True,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
        "auto_pr_allowed": False,
        "patch_ready": False,
        "pr_opened": False,
        "finding_promotion_allowed": False,
        "next_allowed_action": (
            "Human residual/patch review audit only; submission and auto-PR remain blocked."
        ),
    }



def persist_human_review_approval(
    repository: Any,
    approval: HumanReviewApproval | dict[str, Any],
    *,
    campaign_id: str | None = None,
    run_id: str | None = None,
    program_id: str | None = None,
) -> Any:
    """Persist via existing ApprovalRecord repository when a session is available.

    Maps residual_review / patch_review into approval_type. Decision is NOT applied
    as validation permission — payload records factory context only.
    """
    record = (
        approval
        if isinstance(approval, HumanReviewApproval)
        else HumanReviewApproval.model_validate(approval)
    )
    record = _apply_decision_context(_force_safety_model(record))
    if not hasattr(repository, "create_approval_record"):
        raise HumanReviewApprovalError("repository_missing_create_approval_record")

    payload = {
        "factory_stage": "human_review",
        "approval_kind": record.approval_kind,
        "package_id": record.package_id,
        "candidate_id": record.candidate_id,
        "root_cause_id": record.root_cause_id,
        "residual_context_cleared": record.residual_context_cleared,
        "residual_rejected": record.residual_rejected,
        "patch_review_accepted": record.patch_review_accepted,
        "patch_review_rejected": record.patch_review_rejected,
        "source": record.source,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
        "auto_pr_allowed": False,
        "patch_ready": False,
        "human_review_payload": record.payload,
    }
    if record.status == STATUS_REJECTED_FP:
        payload["fp_mark"] = "rejected_fp"
    if record.status == STATUS_WAIVED:
        payload["disposition"] = "waived_no_patch"

    db_record = repository.create_approval_record(
        campaign_id=campaign_id,
        run_id=run_id,
        program_id=program_id,
        approval_type=record.approval_kind,
        actor=record.actor or "unknown",
        reason=record.reason or f"{record.approval_kind} review",
        requested_action=f"factory_{record.approval_kind}",
        safety_gate_state="human_review_context_only",
        status=STATUS_REQUESTED,
        expires_at=_parse_dt(record.expires_at),
        payload=payload,
    )
    if record.status in DECISION_STATUSES and record.status not in INITIAL_STATUSES:
        if hasattr(repository, "decide_approval_record"):
            decision = record.status
            if decision == STATUS_REJECTED_FP:
                decision = STATUS_DENIED
            elif decision == STATUS_WAIVED:
                decision = STATUS_APPROVED
            if decision in {"approved", "denied", "revoked", "expired", "used"}:
                decided = repository.decide_approval_record(
                    approval_id=db_record.id,
                    decision=decision,
                    actor=record.decided_by or record.actor or "unknown",
                    reason=record.decision_reason
                    or record.reason
                    or f"{record.approval_kind}:{record.status}",
                )
                if decided is not None:
                    db_record = decided
    return db_record


def human_review_approval_from_db_record(db_record: Any) -> HumanReviewApproval:
    """Rehydrate a factory HumanReviewApproval from ApprovalRecord-like object."""
    payload = getattr(db_record, "payload", None) or {}
    if not isinstance(payload, dict):
        payload = {}
    kind = str(
        payload.get("approval_kind")
        or getattr(db_record, "approval_type", None)
        or APPROVAL_KIND_RESIDUAL
    )
    status = str(getattr(db_record, "status", STATUS_REQUESTED) or STATUS_REQUESTED)
    if status == STATUS_APPROVED and str(payload.get("disposition") or "") == "waived_no_patch":
        status = STATUS_WAIVED
    if status == STATUS_DENIED and str(payload.get("fp_mark") or "") == "rejected_fp":
        status = STATUS_REJECTED_FP

    return build_human_review_approval(
        approval_id=str(getattr(db_record, "id", "") or f"hreview_{uuid4().hex}"),
        approval_kind=kind,
        package_id=str(payload.get("package_id") or ""),
        candidate_id=str(payload.get("candidate_id") or ""),
        root_cause_id=str(payload.get("root_cause_id") or ""),
        actor=str(getattr(db_record, "actor", "") or "unknown"),
        reason=str(getattr(db_record, "reason", "") or ""),
        status=status,
        decision_reason=str(getattr(db_record, "decision_reason", "") or ""),
        decided_by=str(getattr(db_record, "decided_by", "") or ""),
        decided_at=getattr(db_record, "decided_at", None),
        expires_at=getattr(db_record, "expires_at", None),
        payload={
            k: v
            for k, v in payload.items()
            if k not in {
                "execution_allowed",
                "validation_allowed",
                "report_submission_allowed",
                "confirmed_vulnerability",
                "auto_pr_allowed",
                "patch_ready",
            }
        },
        source="database",
    )

def _prefer_decided(items: list[dict[str, Any]]) -> dict[str, Any]:
    decided = [a for a in items if str(a.get("status") or "") not in INITIAL_STATUSES]
    pool = decided or items
    rank = {
        STATUS_APPROVED: 0,
        STATUS_WAIVED: 1,
        STATUS_REJECTED_FP: 2,
        STATUS_DENIED: 3,
        STATUS_REVOKED: 4,
        STATUS_EXPIRED: 5,
        STATUS_REQUESTED: 6,
        STATUS_PENDING: 7,
    }
    pool_sorted = sorted(
        pool,
        key=lambda a: (
            rank.get(str(a.get("status") or ""), 99),
            str(a.get("decided_at") or ""),
        ),
    )
    return pool_sorted[0]


def _parse_approvals_json(
    raw: Any,
    *,
    package_id: str,
    source_path: str,
) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        items = raw
    elif isinstance(raw, dict):
        if isinstance(raw.get("approvals"), list):
            items = raw["approvals"]
        elif isinstance(raw.get("items"), list):
            items = raw["items"]
        elif raw.get("approval_kind") or raw.get("kind"):
            items = [raw]
        else:
            items = []
    else:
        items = []

    out: list[dict[str, Any]] = []
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        kind_raw = item.get("approval_kind") or item.get("kind") or item.get("type")
        if not kind_raw:
            continue
        try:
            kind = _normalize_kind(str(kind_raw))
        except HumanReviewApprovalError:
            continue
        status = _normalize_status(
            str(item.get("status") or item.get("decision") or STATUS_REQUESTED)
        )
        approval = build_human_review_approval(
            approval_id=str(
                item.get("approval_id") or item.get("id") or f"pkg_{uuid4().hex[:12]}_{idx}"
            ),
            approval_kind=kind,
            package_id=str(item.get("package_id") or package_id or ""),
            candidate_id=str(item.get("candidate_id") or ""),
            root_cause_id=str(item.get("root_cause_id") or ""),
            actor=str(item.get("actor") or item.get("requester") or "package_file"),
            reason=str(item.get("reason") or ""),
            status=status,
            decision_reason=str(
                item.get("decision_reason") or item.get("decision_note") or ""
            ),
            decided_by=str(item.get("decided_by") or item.get("actor") or ""),
            decided_at=item.get("decided_at"),
            expires_at=item.get("expires_at"),
            payload=item.get("payload") if isinstance(item.get("payload"), dict) else {},
            source="package_file",
            source_path=source_path,
        )
        out.append(_dump_approval(approval))
    return out


def _dump_approval(approval: HumanReviewApproval | dict[str, Any]) -> dict[str, Any]:
    if isinstance(approval, HumanReviewApproval):
        model = _apply_decision_context(_force_safety_model(approval))
        return model.model_dump()
    model = build_human_review_approval(
        approval_id=str(approval.get("approval_id") or f"hreview_{uuid4().hex}"),
        approval_kind=str(
            approval.get("approval_kind") or approval.get("kind") or APPROVAL_KIND_RESIDUAL
        ),
        package_id=str(approval.get("package_id") or ""),
        candidate_id=str(approval.get("candidate_id") or ""),
        root_cause_id=str(approval.get("root_cause_id") or ""),
        actor=str(approval.get("actor") or "unknown"),
        reason=str(approval.get("reason") or ""),
        status=str(approval.get("status") or STATUS_REQUESTED),
        decision_reason=str(approval.get("decision_reason") or ""),
        decided_by=str(approval.get("decided_by") or ""),
        decided_at=approval.get("decided_at"),
        expires_at=approval.get("expires_at"),
        payload=approval.get("payload") if isinstance(approval.get("payload"), dict) else {},
        source=str(approval.get("source") or "memory"),
        source_path=str(approval.get("source_path") or ""),
    )
    return model.model_dump()


def _apply_decision_context(record: HumanReviewApproval) -> HumanReviewApproval:
    residual_cleared = False
    residual_rejected = False
    patch_accepted = False
    patch_rejected = False
    if record.approval_kind == APPROVAL_KIND_RESIDUAL:
        if record.status in {STATUS_APPROVED, STATUS_WAIVED} and not _is_expired(record):
            residual_cleared = True
        if record.status in {STATUS_DENIED, STATUS_REJECTED_FP, STATUS_REVOKED}:
            residual_rejected = True
        next_action = (
            "Residual human decision recorded; report submission still blocked."
            if residual_cleared or residual_rejected
            else "Residual review requested; answer residuals with local evidence only."
        )
    else:
        if record.status == STATUS_APPROVED and not _is_expired(record):
            patch_accepted = True
        if record.status in {STATUS_DENIED, STATUS_REJECTED_FP, STATUS_REVOKED}:
            patch_rejected = True
        next_action = (
            "Patch human decision recorded; auto-PR and patch_ready remain false."
            if patch_accepted or patch_rejected or record.status == STATUS_WAIVED
            else "Patch review requested; suggestion remains advisory only."
        )
    return record.model_copy(
        update={
            "residual_context_cleared": residual_cleared,
            "residual_rejected": residual_rejected,
            "patch_review_accepted": patch_accepted,
            "patch_review_rejected": patch_rejected,
            "next_allowed_action": next_action,
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
            "confirmed_vulnerability": False,
            "finding_promotion_allowed": False,
            "auto_pr_allowed": False,
            "patch_ready": False,
            "pr_opened": False,
            "human_review_required": True,
        }
    )


def _force_safety_model(record: HumanReviewApproval) -> HumanReviewApproval:
    blockers = list(record.safety_blockers or [])
    for required in (
        "execute_live_validation",
        "touch_real_user_data",
        "submit_report",
        "auto_promote_finding",
        "auto_open_pull_request",
        "write_exploit_poc",
    ):
        if required not in blockers:
            blockers.append(required)
    return record.model_copy(
        update={
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
            "confirmed_vulnerability": False,
            "finding_promotion_allowed": False,
            "auto_pr_allowed": False,
            "patch_ready": False,
            "pr_opened": False,
            "human_review_required": True,
            "reason": _safe_text(record.reason),
            "decision_reason": _safe_text(record.decision_reason),
            "actor": _safe_text(record.actor) or "unknown",
            "decided_by": _safe_text(record.decided_by),
            "payload": _safe_payload(record.payload or {}),
            "safety_blockers": blockers,
        }
    )


def _normalize_kind(value: str) -> str:
    raw = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "residual": APPROVAL_KIND_RESIDUAL,
        "residual_review": APPROVAL_KIND_RESIDUAL,
        "human_residual": APPROVAL_KIND_RESIDUAL,
        "human_residual_review": APPROVAL_KIND_RESIDUAL,
        "patch": APPROVAL_KIND_PATCH,
        "patch_review": APPROVAL_KIND_PATCH,
        "human_patch": APPROVAL_KIND_PATCH,
        "human_patch_review": APPROVAL_KIND_PATCH,
    }
    kind = aliases.get(raw, raw)
    if kind not in ALLOWED_KINDS:
        raise HumanReviewApprovalError(f"unsupported_approval_kind:{value}")
    return kind


def _normalize_status(value: str) -> str:
    raw = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    aliases = {
        "approve": STATUS_APPROVED,
        "approved": STATUS_APPROVED,
        "accept": STATUS_APPROVED,
        "accepted": STATUS_APPROVED,
        "deny": STATUS_DENIED,
        "denied": STATUS_DENIED,
        "reject": STATUS_REJECTED_FP,
        "rejected": STATUS_REJECTED_FP,
        "rejected_fp": STATUS_REJECTED_FP,
        "false_positive": STATUS_REJECTED_FP,
        "fp": STATUS_REJECTED_FP,
        "waive": STATUS_WAIVED,
        "waived": STATUS_WAIVED,
        "request": STATUS_REQUESTED,
        "requested": STATUS_REQUESTED,
        "pending": STATUS_PENDING,
        "expire": STATUS_EXPIRED,
        "expired": STATUS_EXPIRED,
        "revoke": STATUS_REVOKED,
        "revoked": STATUS_REVOKED,
    }
    status = aliases.get(raw, raw)
    if status not in (INITIAL_STATUSES | TERMINAL_STATUSES):
        return STATUS_REQUESTED
    return status


def _is_expired(
    record: HumanReviewApproval,
    *,
    now: datetime | None = None,
) -> bool:
    if record.status == STATUS_EXPIRED:
        return True
    if not record.expires_at:
        return False
    exp = _parse_dt(record.expires_at)
    if exp is None:
        return False
    current = now or datetime.now(UTC)
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return exp <= current


def _as_iso(value: str | datetime | None) -> str | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value if value.tzinfo else value.replace(tzinfo=UTC)
        return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")
    text = str(value).strip()
    return text or None


def _parse_dt(value: str | datetime | None) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _safe_text(value: Any) -> str:
    text = str(value or "")
    if _SECRET_VALUE_RE.search(text):
        return "[REDACTED]"
    if _SECRET_KEY_RE.search(text) and len(text) > 40:
        return "[REDACTED]"
    return text


def _safe_payload(payload: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in payload.items():
        key_s = str(key)
        if _SECRET_KEY_RE.search(key_s):
            out[key_s] = "[REDACTED]"
            continue
        if isinstance(value, dict):
            out[key_s] = _safe_payload(value)
        elif isinstance(value, list):
            out[key_s] = [
                _safe_payload(v)
                if isinstance(v, dict)
                else (_safe_text(v) if isinstance(v, str) else v)
                for v in value
            ]
        elif isinstance(value, str):
            out[key_s] = _safe_text(value)
        else:
            out[key_s] = value
    for forbidden in (
        "execution_allowed",
        "validation_allowed",
        "report_submission_allowed",
        "confirmed_vulnerability",
        "auto_pr_allowed",
        "patch_ready",
        "pr_opened",
        "finding_promotion_allowed",
    ):
        if forbidden in out:
            out[forbidden] = False
    return out


__all__ = [
    "APPROVAL_KIND_PATCH",
    "APPROVAL_KIND_RESIDUAL",
    "DECISION_STATUSES",
    "HumanReviewApproval",
    "HumanReviewApprovalError",
    "STATUS_APPROVED",
    "STATUS_DENIED",
    "STATUS_REJECTED_FP",
    "STATUS_REQUESTED",
    "STATUS_WAIVED",
    "attach_human_review_approvals_to_bridge_result",
    "build_human_review_approval",
    "decide_human_review_approval",
    "human_review_approval_from_db_record",
    "load_package_human_review_approvals",
    "patch_context_from_approval",
    "persist_human_review_approval",
    "residual_flags_from_approval",
    "resolve_human_review_approvals",
    "select_approval_for_candidate",
]
