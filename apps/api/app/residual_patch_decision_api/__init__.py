"""Residual/patch decision API thin wrap.

Factory human-review decisions for residual_review and patch_review only.

Hard safety:
- Never unlocks execution / live validation / report submission
- Never sets patch_ready / auto_pr / pr_opened / confirmed_vulnerability
- rejected_fp / denied / waived map to context flags only
- Uses app.human_review_approvals + optional ApprovalRecord persistence
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4
import json

from pydantic import BaseModel, Field

from app.human_review_approvals import (
    ALLOWED_KINDS,
    APPROVAL_KIND_PATCH,
    APPROVAL_KIND_RESIDUAL,
    DECISION_STATUSES,
    HumanReviewApproval,
    HumanReviewApprovalError,
    STATUS_APPROVED,
    STATUS_DENIED,
    STATUS_EXPIRED,
    STATUS_PENDING,
    STATUS_REJECTED_FP,
    STATUS_REQUESTED,
    STATUS_REVOKED,
    STATUS_WAIVED,
    build_human_review_approval,
    decide_human_review_approval,
    human_review_approval_from_db_record,
    load_package_human_review_approvals,
    patch_context_from_approval,
    persist_human_review_approval,
    residual_flags_from_approval,
)


class ResidualPatchDecisionApiError(ValueError):
    pass


STATUS_EMPTY = "residual_patch_decision_api_empty"
STATUS_READY = "residual_patch_decision_api_ready"
STATUS_PENDING = "residual_patch_decision_api_pending"
STATUS_WRITTEN = "residual_patch_decision_api_export_written"
STATUS_IMPORTED = "residual_patch_decision_api_imported"



class ResidualPatchDecisionCreate(BaseModel):
    """Create a residual_review or patch_review decision request (context only)."""

    approval_kind: str
    package_id: str = ""
    candidate_id: str = ""
    root_cause_id: str = ""
    actor: str = "unknown"
    reason: str = ""
    status: str = STATUS_REQUESTED
    run_id: str | None = None
    program_id: str | None = None
    campaign_id: str | None = None
    expires_at: datetime | str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    persist: bool = True


class ResidualPatchDecisionApply(BaseModel):
    """Apply a human decision; never grants execution or submit."""

    decision: str
    actor: str
    reason: str = ""


class ResidualPatchDecisionView(BaseModel):
    """API response view with forced safety floor."""

    approval_id: str
    approval_kind: str
    status: str
    package_id: str = ""
    candidate_id: str = ""
    root_cause_id: str = ""
    actor: str = ""
    reason: str = ""
    decision_reason: str = ""
    decided_by: str = ""
    decided_at: str | None = None
    expires_at: str | None = None
    source: str = "memory"
    source_path: str = ""
    db_approval_id: str | None = None
    residual_flags: dict[str, bool] = Field(default_factory=dict)
    patch_context: dict[str, Any] = Field(default_factory=dict)
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
        "Human residual/patch review decision only; no execution, submit, or auto-PR."
    )
    safety_blockers: list[str] = Field(
        default_factory=lambda: [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
            "auto_promote_finding",
            "auto_open_pull_request",
            "write_exploit_poc",
            "set_patch_ready",
        ]
    )


def create_residual_patch_decision(
    body: ResidualPatchDecisionCreate | dict[str, Any],
    *,
    repository: Any | None = None,
) -> ResidualPatchDecisionView:
    """Create residual/patch decision; optional DB persist via ApprovalRecord."""
    req = (
        body
        if isinstance(body, ResidualPatchDecisionCreate)
        else ResidualPatchDecisionCreate.model_validate(body)
    )
    kind = str(req.approval_kind or "").strip().lower()
    if kind in {"residual", "human_residual", "human_residual_review"}:
        kind = APPROVAL_KIND_RESIDUAL
    if kind in {"patch", "human_patch", "human_patch_review"}:
        kind = APPROVAL_KIND_PATCH
    if kind not in ALLOWED_KINDS:
        raise ResidualPatchDecisionApiError(f"unsupported_approval_kind:{req.approval_kind}")

    record = build_human_review_approval(
        approval_kind=kind,
        package_id=req.package_id,
        candidate_id=req.candidate_id,
        root_cause_id=req.root_cause_id,
        actor=req.actor,
        reason=req.reason,
        status=req.status or STATUS_REQUESTED,
        expires_at=req.expires_at,
        payload=req.payload,
        source="api",
    )
    db_id: str | None = None
    if req.persist and repository is not None:
        try:
            db_record = persist_human_review_approval(
                repository,
                record,
                campaign_id=req.campaign_id,
                run_id=req.run_id,
                program_id=req.program_id,
            )
            db_id = str(getattr(db_record, "id", "") or "") or None
            if db_id:
                # Prefer DB id as approval_id for decide/list round-trips.
                record = record.model_copy(
                    update={"approval_id": db_id, "source": "database"}
                )
        except HumanReviewApprovalError as exc:
            raise ResidualPatchDecisionApiError(str(exc)) from exc
    return to_decision_view(record, db_approval_id=db_id)


def decide_residual_patch_decision(
    *,
    approval_id: str,
    body: ResidualPatchDecisionApply | dict[str, Any],
    repository: Any | None = None,
    current: HumanReviewApproval | dict[str, Any] | None = None,
) -> ResidualPatchDecisionView:
    """Decide residual/patch review; never unlocks execution/submit/auto-PR."""
    apply = (
        body
        if isinstance(body, ResidualPatchDecisionApply)
        else ResidualPatchDecisionApply.model_validate(body)
    )
    record: HumanReviewApproval | None = None
    db_id: str | None = None

    if current is not None:
        record = (
            current
            if isinstance(current, HumanReviewApproval)
            else HumanReviewApproval.model_validate(current)
        )
    elif repository is not None:
        db_record = repository.session.get(
            __import__("app.db_models", fromlist=["ApprovalRecord"]).ApprovalRecord,
            approval_id,
        )
        if db_record is None:
            raise ResidualPatchDecisionApiError("approval_not_found")
        atype = str(getattr(db_record, "approval_type", "") or "")
        payload = getattr(db_record, "payload", None) or {}
        kind = ""
        if isinstance(payload, dict):
            kind = str(payload.get("approval_kind") or "")
        kind = kind or atype
        if kind not in ALLOWED_KINDS and kind not in {
            "residual",
            "patch",
            APPROVAL_KIND_RESIDUAL,
            APPROVAL_KIND_PATCH,
        }:
            # Still allow if payload marks factory human review.
            if not (
                isinstance(payload, dict)
                and payload.get("factory_stage") == "human_review"
            ):
                raise ResidualPatchDecisionApiError("not_residual_or_patch_approval")
        record = human_review_approval_from_db_record(db_record)
        db_id = str(getattr(db_record, "id", "") or approval_id)
    else:
        raise ResidualPatchDecisionApiError("approval_not_found")

    assert record is not None
    try:
        decided = decide_human_review_approval(
            record,
            decision=apply.decision,
            actor=apply.actor,
            reason=apply.reason,
        )
    except HumanReviewApprovalError as exc:
        raise ResidualPatchDecisionApiError(str(exc)) from exc

    # Persist decision onto ApprovalRecord when possible.
    if repository is not None and (db_id or approval_id):
        target_id = db_id or approval_id
        db_decision = _map_factory_decision_to_db(decided.status)
        if db_decision and hasattr(repository, "decide_approval_record"):
            # Re-fetch: terminal check handled by repository.
            updated = repository.decide_approval_record(
                approval_id=target_id,
                decision=db_decision,
                actor=apply.actor,
                reason=apply.reason or f"{decided.approval_kind}:{decided.status}",
            )
            if updated is not None:
                # Keep factory-specific status (e.g. rejected_fp) in view even if DB maps denied.
                db_id = str(getattr(updated, "id", target_id))
                # Enrich payload marker if possible without breaking safety.
                payload = getattr(updated, "payload", None)
                if isinstance(payload, dict):
                    payload = dict(payload)
                    payload["factory_decision_status"] = decided.status
                    payload["execution_allowed"] = False
                    payload["validation_allowed"] = False
                    payload["report_submission_allowed"] = False
                    payload["confirmed_vulnerability"] = False
                    payload["auto_pr_allowed"] = False
                    payload["patch_ready"] = False
                    try:
                        updated.payload = payload
                        repository.session.add(updated)
                        repository.session.commit()
                        repository.session.refresh(updated)
                    except Exception:
                        try:
                            repository.session.rollback()
                        except Exception:
                            pass
                # Rehydrate context flags from factory decision, not only DB status.
                rehydrated = human_review_approval_from_db_record(updated)
                # Prefer factory-mapped decision status when rejected_fp/waived.
                if decided.status in {STATUS_REJECTED_FP, STATUS_WAIVED}:
                    rehydrated = decide_human_review_approval(
                        rehydrated.model_copy(
                            update={"status": STATUS_REQUESTED, "decided_at": None}
                        )
                        if rehydrated.status in DECISION_STATUSES
                        else rehydrated,
                        decision=decided.status,
                        actor=apply.actor,
                        reason=apply.reason,
                    )
                    # If rehydrate already terminal as denied, build from decided.
                    decided = decided.model_copy(
                        update={
                            "approval_id": db_id or decided.approval_id,
                            "source": "database",
                        }
                    )
                else:
                    decided = decided.model_copy(
                        update={
                            "approval_id": str(getattr(rehydrated, "approval_id", db_id)
                            or db_id
                            or decided.approval_id),
                            "source": "database",
                        }
                    )

    return to_decision_view(decided, db_approval_id=db_id or approval_id)


def list_residual_patch_decisions(
    *,
    repository: Any | None = None,
    package_id: str | None = None,
    candidate_id: str | None = None,
    approval_kind: str | None = None,
    run_id: str | None = None,
    package_root: str | None = None,
    limit: int = 100,
) -> list[ResidualPatchDecisionView]:
    """List residual/patch decisions from DB and/or package offline files."""
    views: list[ResidualPatchDecisionView] = []
    kind_filter = None
    if approval_kind:
        k = approval_kind.strip().lower()
        if k in {"residual", "human_residual", APPROVAL_KIND_RESIDUAL}:
            kind_filter = APPROVAL_KIND_RESIDUAL
        elif k in {"patch", "human_patch", APPROVAL_KIND_PATCH}:
            kind_filter = APPROVAL_KIND_PATCH
        elif k in ALLOWED_KINDS:
            kind_filter = k
        else:
            raise ResidualPatchDecisionApiError(f"unsupported_approval_kind:{approval_kind}")

    if repository is not None:
        from app.db_models import ApprovalRecord
        from sqlalchemy import select

        query = select(ApprovalRecord)
        if run_id is not None:
            query = query.where(ApprovalRecord.run_id == run_id)
        # Prefer factory kinds; also include payload factory_stage later.
        query = query.order_by(ApprovalRecord.created_at.desc(), ApprovalRecord.id.desc())
        rows = list(repository.session.scalars(query).all())
        for row in rows:
            atype = str(getattr(row, "approval_type", "") or "")
            payload = getattr(row, "payload", None) or {}
            payload_kind = ""
            if isinstance(payload, dict):
                payload_kind = str(payload.get("approval_kind") or "")
            kind = payload_kind or atype
            if kind in {"residual", "human_residual"}:
                kind = APPROVAL_KIND_RESIDUAL
            if kind in {"patch", "human_patch"}:
                kind = APPROVAL_KIND_PATCH
            is_factory = kind in ALLOWED_KINDS or (
                isinstance(payload, dict) and payload.get("factory_stage") == "human_review"
            )
            if not is_factory:
                continue
            if kind_filter and kind != kind_filter:
                continue
            try:
                rec = human_review_approval_from_db_record(row)
            except Exception:
                continue
            if package_id and str(rec.package_id or "") not in {"", package_id}:
                # also check payload
                pkg = ""
                if isinstance(payload, dict):
                    pkg = str(payload.get("package_id") or "")
                if pkg and pkg != package_id and str(rec.package_id or "") != package_id:
                    continue
                if not pkg and str(rec.package_id or "") != package_id:
                    continue
            if candidate_id and str(rec.candidate_id or "") not in {"", candidate_id}:
                cid = ""
                if isinstance(payload, dict):
                    cid = str(payload.get("candidate_id") or "")
                if cid != candidate_id and str(rec.candidate_id or "") != candidate_id:
                    continue
            # Factory status override from payload when present
            if isinstance(payload, dict) and payload.get("factory_decision_status"):
                rec = rec.model_copy(
                    update={"status": str(payload.get("factory_decision_status"))}
                )
            views.append(
                to_decision_view(rec, db_approval_id=str(getattr(row, "id", "") or None))
            )

    if package_root:
        loaded = load_package_human_review_approvals(package_root)
        for item in loaded.get("approvals") or []:
            try:
                rec = (
                    item
                    if isinstance(item, HumanReviewApproval)
                    else HumanReviewApproval.model_validate(item)
                )
            except Exception:
                continue
            if kind_filter and rec.approval_kind != kind_filter:
                continue
            if package_id and str(rec.package_id or "") not in {"", package_id}:
                continue
            if candidate_id and str(rec.candidate_id or "") not in {"", candidate_id}:
                continue
            views.append(to_decision_view(rec))

    # Dedup by approval_id, prefer database source.
    dedup: dict[str, ResidualPatchDecisionView] = {}
    for view in views:
        key = view.approval_id or f"{view.approval_kind}:{view.package_id}:{view.candidate_id}:{view.status}"
        prev = dedup.get(key)
        if prev is None or (view.source == "database" and prev.source != "database"):
            dedup[key] = view
    out = list(dedup.values())
    return out[: max(1, min(int(limit or 100), 500))]


def get_residual_patch_decision(
    approval_id: str,
    *,
    repository: Any | None = None,
) -> ResidualPatchDecisionView:
    if repository is None:
        raise ResidualPatchDecisionApiError("approval_not_found")
    from app.db_models import ApprovalRecord

    row = repository.session.get(ApprovalRecord, approval_id)
    if row is None:
        raise ResidualPatchDecisionApiError("approval_not_found")
    payload = getattr(row, "payload", None) or {}
    atype = str(getattr(row, "approval_type", "") or "")
    kind = ""
    if isinstance(payload, dict):
        kind = str(payload.get("approval_kind") or "")
    kind = kind or atype
    if kind in {"residual", "human_residual"}:
        kind = APPROVAL_KIND_RESIDUAL
    if kind in {"patch", "human_patch"}:
        kind = APPROVAL_KIND_PATCH
    is_factory = kind in ALLOWED_KINDS or (
        isinstance(payload, dict) and payload.get("factory_stage") == "human_review"
    )
    if not is_factory:
        raise ResidualPatchDecisionApiError("not_residual_or_patch_approval")
    rec = human_review_approval_from_db_record(row)
    if isinstance(payload, dict) and payload.get("factory_decision_status"):
        rec = rec.model_copy(update={"status": str(payload.get("factory_decision_status"))})
    return to_decision_view(rec, db_approval_id=str(getattr(row, "id", "") or approval_id))


def to_decision_view(
    approval: HumanReviewApproval | dict[str, Any],
    *,
    db_approval_id: str | None = None,
) -> ResidualPatchDecisionView:
    record = (
        approval
        if isinstance(approval, HumanReviewApproval)
        else HumanReviewApproval.model_validate(approval)
    )
    residual = residual_flags_from_approval(record)
    patch = patch_context_from_approval(record)
    return ResidualPatchDecisionView(
        approval_id=str(record.approval_id or db_approval_id or ""),
        approval_kind=record.approval_kind,
        status=record.status,
        package_id=record.package_id,
        candidate_id=record.candidate_id,
        root_cause_id=record.root_cause_id,
        actor=record.actor,
        reason=record.reason,
        decision_reason=record.decision_reason,
        decided_by=record.decided_by,
        decided_at=record.decided_at,
        expires_at=record.expires_at,
        source=record.source,
        source_path=record.source_path,
        db_approval_id=db_approval_id,
        residual_flags={
            "human_approved": bool(residual.get("human_approved")),
            "human_rejected": bool(residual.get("human_rejected")),
            "residual_context_cleared": bool(residual.get("residual_context_cleared")),
            "has_decision": bool(residual.get("has_decision")),
            "active": bool(residual.get("active")),
        },
        patch_context={
            "human_patch_reviewed": bool(patch.get("human_patch_reviewed")),
            "patch_review_accepted": bool(patch.get("patch_review_accepted")),
            "patch_review_rejected": bool(patch.get("patch_review_rejected")),
            "disposition": patch.get("disposition") or "none",
            "has_decision": bool(patch.get("has_decision")),
            "active": bool(patch.get("active")),
            "patch_ready": False,
            "auto_pr_allowed": False,
            "pr_opened": False,
        },
        human_review_required=True,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        auto_pr_allowed=False,
        patch_ready=False,
        pr_opened=False,
    )


def _map_factory_decision_to_db(status: str) -> str | None:
    if status == STATUS_APPROVED:
        return "approved"
    if status == STATUS_WAIVED:
        return "approved"
    if status == STATUS_DENIED:
        return "denied"
    if status == STATUS_REJECTED_FP:
        return "denied"
    if status == STATUS_REVOKED:
        return "revoked"
    if status == STATUS_EXPIRED:
        return "expired"
    if status in {STATUS_REQUESTED, STATUS_PENDING}:
        return None
    return None



def build_residual_patch_decision_snapshot(
    *,
    package_id: str = "",
    package_root: str | Path | None = None,
    bridge_result: dict[str, Any] | None = None,
    approvals: list[dict[str, Any] | HumanReviewApproval] | None = None,
) -> dict[str, Any]:
    """Build offline residual/patch decision snapshot from package/bridge approvals.

    Context/audit only. Never unlocks execute/submit/patch_ready.
    """
    bridge = bridge_result if isinstance(bridge_result, dict) else {}
    pid = str(package_id or bridge.get("package_id") or "")
    root = package_root or bridge.get("package_root")

    items: list[dict[str, Any]] = []
    if approvals is not None:
        for a in approvals:
            try:
                view = to_decision_view(a)
                items.append(view.model_dump())
            except Exception:
                continue
    else:
        raw_list = bridge.get("human_review_approvals")
        if isinstance(raw_list, list) and raw_list:
            for a in raw_list:
                if not isinstance(a, (dict, HumanReviewApproval)):
                    continue
                try:
                    items.append(to_decision_view(a).model_dump())
                except Exception:
                    continue
        else:
            bundle = load_package_human_review_approvals(root) if root else {"approvals": []}
            for a in bundle.get("approvals") or []:
                if not isinstance(a, (dict, HumanReviewApproval)):
                    continue
                try:
                    items.append(to_decision_view(a).model_dump())
                except Exception:
                    continue

    residual = [i for i in items if i.get("approval_kind") == APPROVAL_KIND_RESIDUAL]
    patch = [i for i in items if i.get("approval_kind") == APPROVAL_KIND_PATCH]
    decided = [
        i
        for i in items
        if str(i.get("status") or "")
        in {
            STATUS_APPROVED,
            STATUS_DENIED,
            STATUS_REJECTED_FP,
            STATUS_WAIVED,
            STATUS_EXPIRED,
            STATUS_REVOKED,
        }
    ]
    if items and decided:
        status = STATUS_READY
    elif items:
        status = STATUS_PENDING
    else:
        status = STATUS_EMPTY

    return _force_safety_snapshot(
        {
            "status": status,
            "package_id": pid,
            "package_root": str(root or ""),
            "snapshot_id": f"rpda_{uuid4().hex[:16]}",
            "decisions": items,
            "decision_count": len(items),
            "residual_count": len(residual),
            "patch_count": len(patch),
            "decided_count": len(decided),
            "approved_count": sum(1 for i in items if i.get("status") == STATUS_APPROVED),
            "denied_count": sum(
                1
                for i in items
                if i.get("status") in {STATUS_DENIED, STATUS_REJECTED_FP, STATUS_REVOKED}
            ),
            "export_written": False,
            "export_count": 0,
            "export_root_relative": "",
            "import_written": False,
            "import_path_relative": "",
            "source": "bridge_or_package_approvals",
            "human_review_required": True,
            "execution_mode": "offline_decision_snapshot_only",
            "next_allowed_action": (
                "Offline residual/patch decision snapshot only; "
                "human may export/import under explicit flag; never auto-submit."
            ),
        }
    )


def export_residual_patch_decision_snapshot(
    snapshot: dict[str, Any],
    *,
    package_root: str | Path | None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    """Write decision snapshot under package _export only when human flag is set."""
    out = _force_safety_snapshot(dict(snapshot) if isinstance(snapshot, dict) else {})
    if not human_allow_export_write:
        out["export_written"] = False
        out["notes"] = list(out.get("notes") or []) + ["export_blocked_until_human_flag"]
        return out
    if package_root is None or str(package_root).strip() == "":
        out["export_written"] = False
        out["notes"] = list(out.get("notes") or []) + ["export_skipped_no_package_root"]
        return out
    root = Path(package_root).resolve()
    if not root.is_dir():
        out["export_written"] = False
        out["notes"] = list(out.get("notes") or []) + ["export_skipped_package_missing"]
        return out
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    export_root = root / "_export" / "residual_patch_decision_api" / stamp
    try:
        export_root.mkdir(parents=True, exist_ok=True)
        payload = _force_safety_snapshot(
            {
                **out,
                "exported_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "export_written": True,
            }
        )
        files = {
            "snapshot.json": payload,
            "decisions.json": {
                "decisions": payload.get("decisions") or [],
                "execution_allowed": False,
                "report_submission_allowed": False,
                "patch_ready": False,
                "auto_pr_allowed": False,
            },
            "summary.json": {
                "status": payload.get("status"),
                "package_id": payload.get("package_id"),
                "decision_count": payload.get("decision_count"),
                "decided_count": payload.get("decided_count"),
                "residual_count": payload.get("residual_count"),
                "patch_count": payload.get("patch_count"),
                "execution_allowed": False,
                "report_submission_allowed": False,
                "patch_ready": False,
                "auto_pr_allowed": False,
                "confirmed_vulnerability": False,
            },
        }
        for name, body in files.items():
            (export_root / name).write_text(
                json.dumps(body, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        rel = f"_export/residual_patch_decision_api/{stamp}"
        out["export_written"] = True
        out["export_count"] = len(files)
        out["export_root_relative"] = rel
        out["status"] = STATUS_WRITTEN if out.get("decision_count") else out.get("status") or STATUS_EMPTY
        out["notes"] = list(out.get("notes") or []) + ["export_written_under_human_flag"]
        return _force_safety_snapshot(out)
    except Exception as exc:
        out["export_written"] = False
        out["notes"] = list(out.get("notes") or []) + [f"export_failed:{type(exc).__name__}"]
        return _force_safety_snapshot(out)


def import_residual_patch_decisions_to_package(
    snapshot_or_decisions: dict[str, Any] | list[dict[str, Any]],
    *,
    package_root: str | Path,
    human_allow_import_write: bool = False,
) -> dict[str, Any]:
    """Write offline approvals JSON into package inputs under human flag only.

    Converts decision snapshot / decision list into human_review_approvals.json shape.
    Never unlocks gates. Overwrites only inputs/human_review_approvals.json.
    """
    empty = _force_safety_snapshot(
        {
            "status": STATUS_EMPTY,
            "import_written": False,
            "import_path_relative": "",
            "decision_count": 0,
        }
    )
    if not human_allow_import_write:
        empty["notes"] = ["import_blocked_until_human_flag"]
        return empty
    root = Path(package_root).resolve()
    if not root.is_dir():
        empty["notes"] = ["import_skipped_package_missing"]
        return empty

    if isinstance(snapshot_or_decisions, list):
        decisions = [d for d in snapshot_or_decisions if isinstance(d, dict)]
    elif isinstance(snapshot_or_decisions, dict):
        raw = snapshot_or_decisions.get("decisions") or snapshot_or_decisions.get("approvals") or []
        decisions = [d for d in raw if isinstance(d, dict)]
    else:
        empty["notes"] = ["import_invalid_payload"]
        return empty

    approvals: list[dict[str, Any]] = []
    for d in decisions:
        try:
            view = to_decision_view(d)
        except Exception:
            continue
        approvals.append(
            {
                "approval_id": view.approval_id,
                "approval_kind": view.approval_kind,
                "status": view.status,
                "package_id": view.package_id,
                "candidate_id": view.candidate_id,
                "root_cause_id": view.root_cause_id,
                "actor": view.actor,
                "reason": view.reason,
                "decision_reason": view.decision_reason,
                "decided_by": view.decided_by,
                "decided_at": view.decided_at,
                "expires_at": view.expires_at,
                "source": "decision_api_import",
            }
        )

    inputs = root / "inputs"
    inputs.mkdir(parents=True, exist_ok=True)
    target = inputs / "human_review_approvals.json"
    body = {
        "approvals": approvals,
        "imported_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "source": "residual_patch_decision_api_import",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
        "auto_pr_allowed": False,
        "patch_ready": False,
    }
    target.write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return _force_safety_snapshot(
        {
            "status": STATUS_IMPORTED if approvals else STATUS_EMPTY,
            "import_written": True,
            "import_path_relative": "inputs/human_review_approvals.json",
            "decision_count": len(approvals),
            "decisions": [to_decision_view(a).model_dump() for a in approvals],
            "package_root": str(root),
            "notes": ["import_written_under_human_flag"],
        }
    )


def attach_residual_patch_decision_api_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    residual_patch_decision_api: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    """Attach offline residual/patch decision snapshot; optional human-gated export.

    Does not unlock execution, validation, submission, auto-PR, or patch_ready.
    """
    if not isinstance(bridge_result, dict):
        raise ResidualPatchDecisionApiError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")

    if isinstance(residual_patch_decision_api, dict):
        payload = _force_safety_snapshot(dict(residual_patch_decision_api))
    else:
        payload = build_residual_patch_decision_snapshot(
            package_id=package_id,
            package_root=resolved_root,
            bridge_result=bridge_result,
        )
        if human_allow_export_write:
            payload = export_residual_patch_decision_snapshot(
                payload,
                package_root=resolved_root,
                human_allow_export_write=True,
            )

    payload = _force_safety_snapshot(payload)
    out = dict(bridge_result)
    out["residual_patch_decision_api"] = payload
    out["residual_patch_decision_api_present"] = bool(payload.get("decision_count") or payload.get("export_written"))
    out["residual_patch_decision_api_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["residual_patch_decision_api_count"] = int(payload.get("decision_count") or 0)
    out["residual_patch_decision_api_decided_count"] = int(payload.get("decided_count") or 0)
    out["residual_patch_decision_api_residual_count"] = int(payload.get("residual_count") or 0)
    out["residual_patch_decision_api_patch_count"] = int(payload.get("patch_count") or 0)
    out["residual_patch_decision_api_export_written"] = bool(payload.get("export_written"))
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    out["auto_pr_allowed"] = False
    out["patch_ready"] = False
    out["pr_opened"] = False
    out["finding_promotion_allowed"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    out["next_allowed_action"] = (
        "Offline residual/patch decision API snapshot only; submission and auto-PR remain blocked."
    )
    return out


def _force_safety_snapshot(payload: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload) if isinstance(payload, dict) else {}
    for key in (
        "execution_allowed",
        "validation_allowed",
        "report_submission_allowed",
        "confirmed_vulnerability",
        "finding_promotion_allowed",
        "auto_pr_allowed",
        "patch_ready",
        "pr_opened",
        "ranking_permission_granted",
        "network_access",
        "live_validation",
    ):
        out[key] = False
    out["human_review_required"] = True
    if "safety_blockers" not in out or not isinstance(out.get("safety_blockers"), list):
        out["safety_blockers"] = [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
            "auto_promote_finding",
            "auto_open_pull_request",
            "write_exploit_poc",
            "set_patch_ready",
        ]
    # sanitize nested decisions
    decisions = out.get("decisions")
    if isinstance(decisions, list):
        cleaned: list[dict[str, Any]] = []
        for item in decisions:
            if not isinstance(item, dict):
                continue
            d = dict(item)
            for key in (
                "execution_allowed",
                "validation_allowed",
                "report_submission_allowed",
                "confirmed_vulnerability",
                "finding_promotion_allowed",
                "auto_pr_allowed",
                "patch_ready",
                "pr_opened",
            ):
                d[key] = False
            cleaned.append(d)
        out["decisions"] = cleaned
    return out


__all__ = [
    "ResidualPatchDecisionApiError",
    "ResidualPatchDecisionApply",
    "ResidualPatchDecisionCreate",
    "ResidualPatchDecisionView",
    "STATUS_EMPTY",
    "STATUS_IMPORTED",
    "STATUS_PENDING",
    "STATUS_READY",
    "STATUS_WRITTEN",
    "attach_residual_patch_decision_api_to_bridge_result",
    "build_residual_patch_decision_snapshot",
    "create_residual_patch_decision",
    "decide_residual_patch_decision",
    "export_residual_patch_decision_snapshot",
    "get_residual_patch_decision",
    "import_residual_patch_decisions_to_package",
    "list_residual_patch_decisions",
    "to_decision_view",
]
