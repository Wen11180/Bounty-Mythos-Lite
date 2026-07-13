"""Human residual review gate — final factory stage before any report use.

Lawful research only:
- Never auto-submits reports
- Never executes live validation
- Never promotes multi-engine verdicts to confirmed vulnerabilities
- Collects residual questions / evidence gaps for human decision

This is the Human Review / Human Gate slice from the final scheme.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from app.human_review_approvals import (
    APPROVAL_KIND_RESIDUAL,
    attach_human_review_approvals_to_bridge_result,
    residual_flags_from_approval,
    resolve_human_review_approvals,
    select_approval_for_candidate,
)


GATE_HOLD = "hold_for_human"
GATE_READY_FOR_REVIEW = "ready_for_human_review"
GATE_BLOCKED = "blocked"
GATE_REJECTED = "human_rejected_or_fp"

ALLOWED_GATES = {GATE_HOLD, GATE_READY_FOR_REVIEW, GATE_BLOCKED, GATE_REJECTED}

_BLOCKED_NAME_PARTS = (
    "secret",
    "token",
    "cookie",
    "credential",
    "password",
    "apikey",
    "api_key",
)

_TABLE_ROW_RE = re.compile(
    r"^\|\s*(?P<id>[^|]+?)\s*\|\s*(?P<question>[^|]+?)\s*(?:\|\s*(?P<status>[^|]*?)\s*)?\|?\s*$"
)
_BULLET_RE = re.compile(
    r"^\s*(?:[-*]|\d+[.)])\s+(?P<body>.+?)\s*$"
)
_ID_PREFIX_RE = re.compile(
    r"^(?P<id>[A-Za-z][A-Za-z0-9_-]{1,31})\s*[:\-—]\s+(?P<body>.+)$"
)


class ResidualItem(BaseModel):
    item_id: str
    question: str
    status: str = "open"  # open | answered | waived
    evidence_refs: list[str] = Field(default_factory=list)


class HumanResidualGateResult(BaseModel):
    status: str
    package_id: str = ""
    candidate_id: str = ""
    root_cause_id: str = ""
    multi_engine_status: str = ""
    residual_items: list[ResidualItem] = Field(default_factory=list)
    open_residual_count: int = 0
    human_review_required: bool = True
    human_approved: bool = False
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    finding_promotion_allowed: bool = False
    confirmed_vulnerability: bool = False
    next_allowed_action: str = "Human residual review only."
    safety_blockers: list[str] = Field(
        default_factory=lambda: [
            "execute_live_validation",
            "touch_real_user_data",
            "submit_report",
            "auto_promote_finding",
        ]
    )
    blocked_reasons: list[str] = Field(default_factory=list)


class HumanResidualGateError(ValueError):
    pass


def load_package_residual_checklist(
    package_root: str | Path | None,
) -> dict[str, Any]:
    """Optional offline residual checklist auto-ingest from an authorized package.

    Looks for (first hits win; all readable sources are merged, de-duped by question):
    - _extract/RESIDUAL_CHECKLIST.md
    - RESIDUAL_CHECKLIST.md
    - inputs/residual_checklist.md
    - inputs/residual.json
    - inputs/residual_checklist.json
    - inputs/residual/*.json

    Safety:
    - Missing files are OK (present=False)
    - Paths must stay under package_root
    - Filenames containing secret/token/cookie/credential are skipped
    - Never executes validation or network checks
    """
    empty = {
        "present": False,
        "package_root": str(package_root or ""),
        "sources": [],
        "items": [],
        "skipped": [],
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
    }
    if package_root is None or str(package_root).strip() == "":
        return empty
    root = Path(package_root).resolve()
    if not root.is_dir():
        return {**empty, "package_root": str(root), "skipped": ["package_root_missing"]}

    candidate_paths: list[Path] = [
        root / "_extract" / "RESIDUAL_CHECKLIST.md",
        root / "RESIDUAL_CHECKLIST.md",
        root / "inputs" / "residual_checklist.md",
        root / "inputs" / "residual.json",
        root / "inputs" / "residual_checklist.json",
    ]
    residual_dir = root / "inputs" / "residual"
    if residual_dir.is_dir():
        candidate_paths.extend(
            sorted(p for p in residual_dir.rglob("*.json") if p.is_file())
        )

    seen_paths: set[str] = set()
    files: list[Path] = []
    for path in candidate_paths:
        if not path.is_file():
            continue
        key = str(path.resolve())
        if key in seen_paths:
            continue
        seen_paths.add(key)
        files.append(path)

    if not files:
        return {**empty, "package_root": str(root)}

    items: list[dict[str, Any]] = []
    sources: list[dict[str, Any]] = []
    skipped: list[str] = []
    seen_questions: set[str] = set()

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
            parsed = _parse_residual_file(resolved)
        except Exception as exc:  # noqa: BLE001 - fail soft per file
            skipped.append(f"unreadable:{path.name}:{exc}")
            continue

        kept = 0
        for item in parsed:
            q = str(item.get("question") or "").strip()
            if not q or q.lower() in seen_questions:
                continue
            seen_questions.add(q.lower())
            items.append(item)
            kept += 1
        sources.append(
            {
                "path": str(resolved.relative_to(root)).replace("\\", "/"),
                "item_count": kept,
            }
        )

    return {
        "present": bool(items) or bool(sources),
        "package_root": str(root),
        "sources": sources,
        "items": items[:40],
        "skipped": skipped,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
    }


def residual_checklist_from_bundle(
    bundle: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Return residual checklist list suitable for build_human_residual_gate."""
    if not isinstance(bundle, dict) or not bundle.get("present"):
        return []
    items = bundle.get("items")
    if not isinstance(items, list):
        return []
    out: list[dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict) and str(item.get("question") or "").strip():
            out.append(item)
        elif isinstance(item, str) and item.strip():
            out.append({"question": item.strip(), "status": "open"})
    return out[:40]


def resolve_residual_checklist(
    *,
    residual_checklist: list[dict[str, Any]] | list[str] | None = None,
    residual_checklist_bundle: dict[str, Any] | None = None,
    package_root: str | Path | None = None,
    trial_result: dict[str, Any] | None = None,
    bridge_result: dict[str, Any] | None = None,
) -> list[dict[str, Any]] | list[str] | None:
    """Prefer explicit checklist, then bundle, then trial/bridge, then package load."""
    if residual_checklist is not None:
        return residual_checklist
    if isinstance(residual_checklist_bundle, dict) and residual_checklist_bundle.get(
        "present"
    ):
        return residual_checklist_from_bundle(residual_checklist_bundle)

    trial = trial_result if isinstance(trial_result, dict) else {}
    bridge = bridge_result if isinstance(bridge_result, dict) else {}
    for source in (trial, bridge):
        if residual_checklist is None and source.get("residual_checklist") is not None:
            raw = source.get("residual_checklist")
            if isinstance(raw, list):
                return raw  # type: ignore[return-value]
        bundle = source.get("residual_checklist_bundle")
        if isinstance(bundle, dict) and bundle.get("present"):
            return residual_checklist_from_bundle(bundle)

    root = (
        package_root
        or trial.get("package_root")
        or bridge.get("package_root")
        or None
    )
    if root:
        loaded = load_package_residual_checklist(root)
        if loaded.get("present"):
            return residual_checklist_from_bundle(loaded)
    return None


def build_human_residual_gate(
    *,
    package_id: str = "",
    candidate: dict[str, Any] | None = None,
    multi_engine_verdict: dict[str, Any] | None = None,
    report_draft: dict[str, Any] | None = None,
    residual_checklist: list[dict[str, Any]] | list[str] | None = None,
    human_approved: bool = False,
    human_rejected: bool = False,
    scope_allowed: bool = True,
) -> HumanResidualGateResult:
    """Build a non-executing human residual gate decision.

    human_approved only means the human finished residual review for drafting
    readiness context — it still never unlocks submission/execution.
    """
    candidate = candidate if isinstance(candidate, dict) else {}
    multi_engine_verdict = (
        multi_engine_verdict if isinstance(multi_engine_verdict, dict) else {}
    )
    report_draft = report_draft if isinstance(report_draft, dict) else {}

    candidate_id = str(
        candidate.get("candidate_id")
        or multi_engine_verdict.get("candidate_id")
        or report_draft.get("candidate_id")
        or ""
    )
    root_cause_id = str(
        candidate.get("root_cause_id")
        or multi_engine_verdict.get("root_cause_id")
        or ""
    )
    mev_status = str(multi_engine_verdict.get("status") or "")

    blocked: list[str] = []
    if scope_allowed is False:
        blocked.append("scope_not_allowed")
    for flag, reason in (
        ("execution_allowed", "candidate_execution_allowed_true"),
        ("validation_allowed", "candidate_validation_allowed_true"),
        ("report_submission_allowed", "candidate_report_submission_allowed_true"),
        ("confirmed_vulnerability", "candidate_confirmed_vulnerability_true"),
    ):
        if candidate.get(flag) is True or multi_engine_verdict.get(flag) is True:
            blocked.append(reason)
    if multi_engine_verdict.get("report_submission_allowed") is True:
        blocked.append("multi_engine_report_submission_allowed_true")

    residual_items = _normalize_residuals(
        residual_checklist,
        candidate=candidate,
        multi_engine_verdict=multi_engine_verdict,
        report_draft=report_draft,
    )
    open_count = sum(1 for item in residual_items if item.status == "open")

    if human_rejected:
        status = GATE_REJECTED
        next_action = (
            "Human marked residual as false positive / not worth pursuit. "
            "Do not submit a report."
        )
    elif blocked:
        status = GATE_BLOCKED
        next_action = (
            "Residual gate blocked; resolve safety/scope issues without live exploit attempts."
        )
    elif open_count > 0:
        status = GATE_HOLD
        next_action = (
            f"Answer {open_count} open residual question(s) with local evidence only. "
            "Do not execute live validation or submit a report."
        )
    elif human_approved:
        # Human finished residual checklist, still no auto-submit.
        status = GATE_READY_FOR_REVIEW
        next_action = (
            "Residuals cleared for human report-draft review only. "
            "Submission remains blocked until explicit human submit action outside this system."
        )
    else:
        status = GATE_READY_FOR_REVIEW
        next_action = (
            "Residuals prepared for human review. "
            "No open checklist items, but human must still decide disposition. "
            "Submission blocked."
        )

    return HumanResidualGateResult(
        status=status,
        package_id=str(package_id or ""),
        candidate_id=candidate_id,
        root_cause_id=root_cause_id,
        multi_engine_status=mev_status,
        residual_items=residual_items,
        open_residual_count=open_count,
        human_review_required=True,
        human_approved=bool(human_approved) and not human_rejected and not blocked,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        finding_promotion_allowed=False,
        confirmed_vulnerability=False,
        next_allowed_action=next_action,
        blocked_reasons=blocked,
    )


def attach_human_residual_gates_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    residual_checklist: list[dict[str, Any]] | list[str] | None = None,
    residual_checklist_bundle: dict[str, Any] | None = None,
    package_root: str | Path | None = None,
    trial_result: dict[str, Any] | None = None,
    human_approved: bool = False,
    human_rejected: bool = False,
    human_review_approvals: list[dict[str, Any]] | None = None,
    human_review_approvals_bundle: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Attach residual gates to each draft / multi_engine verdict in a bridge result.

    Optional durable residual_review approvals can set human_approved/human_rejected
    context only - never unlocks submission or execution.
    """
    if not isinstance(bridge_result, dict):
        raise HumanResidualGateError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root
    if not resolved_root:
        resolved_root = bridge_result.get("package_root")
    if not resolved_root and isinstance(trial_result, dict):
        resolved_root = trial_result.get("package_root")
    resolved_bundle = residual_checklist_bundle
    if not isinstance(resolved_bundle, dict):
        if isinstance(trial_result, dict) and isinstance(
            trial_result.get("residual_checklist_bundle"), dict
        ):
            resolved_bundle = trial_result.get("residual_checklist_bundle")
        elif isinstance(bridge_result.get("residual_checklist_bundle"), dict):
            resolved_bundle = bridge_result.get("residual_checklist_bundle")
        elif resolved_root:
            resolved_bundle = load_package_residual_checklist(resolved_root)
        else:
            resolved_bundle = None

    resolved_checklist = resolve_residual_checklist(
        residual_checklist=residual_checklist,
        residual_checklist_bundle=resolved_bundle
        if isinstance(resolved_bundle, dict)
        else None,
        package_root=resolved_root,
        trial_result=trial_result,
        bridge_result=bridge_result,
    )

    # Durable residual_review approvals (optional; fail-closed context only)
    resolved_approvals = resolve_human_review_approvals(
        approvals=human_review_approvals,
        approvals_bundle=human_review_approvals_bundle,
        package_root=resolved_root,
        bridge_result=bridge_result,
        trial_result=trial_result,
    )
    package_residual_approval = select_approval_for_candidate(
        resolved_approvals,
        approval_kind=APPROVAL_KIND_RESIDUAL,
        package_id=package_id,
        candidate_id="",
    )
    package_residual_flags = residual_flags_from_approval(package_residual_approval)
    if package_residual_flags.get("human_approved"):
        human_approved = True
    if package_residual_flags.get("human_rejected"):
        human_rejected = True

    drafts = bridge_result.get("drafts") if isinstance(bridge_result.get("drafts"), list) else []
    gates: list[dict[str, Any]] = []
    enriched_drafts: list[dict[str, Any]] = []

    for draft in drafts:
        if not isinstance(draft, dict):
            continue
        cid = str(draft.get("candidate_id") or "")
        cand_approval = select_approval_for_candidate(
            resolved_approvals,
            approval_kind=APPROVAL_KIND_RESIDUAL,
            package_id=package_id,
            candidate_id=cid,
        )
        cand_flags = residual_flags_from_approval(cand_approval)
        draft_approved = bool(human_approved) or bool(cand_flags.get("human_approved"))
        draft_rejected = bool(human_rejected) or bool(cand_flags.get("human_rejected"))
        gate = build_human_residual_gate(
            package_id=package_id,
            candidate={
                "candidate_id": draft.get("candidate_id"),
                "root_cause_id": draft.get("root_cause_id"),
                "refutation_questions": draft.get("refutation_questions"),
                "execution_allowed": draft.get("execution_allowed"),
                "validation_allowed": draft.get("validation_allowed"),
                "report_submission_allowed": draft.get("report_submission_allowed"),
                "confirmed_vulnerability": draft.get("confirmed_vulnerability"),
            },
            multi_engine_verdict=draft.get("multi_engine_verdict")
            if isinstance(draft.get("multi_engine_verdict"), dict)
            else {},
            report_draft=draft.get("report_draft")
            if isinstance(draft.get("report_draft"), dict)
            else {},
            residual_checklist=resolved_checklist,
            human_approved=draft_approved,
            human_rejected=draft_rejected,
            scope_allowed=True,
        )
        payload = gate.model_dump()
        gates.append(payload)
        enriched = {
            **draft,
            "human_residual_gate": payload,
            # re-force safety floor
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
            "confirmed_vulnerability": False,
        }
        enriched_drafts.append(enriched)

    # also gate multi_engine verdicts without drafts (refute packages)
    if not gates:
        for verdict in bridge_result.get("multi_engine_verdicts") or []:
            if not isinstance(verdict, dict):
                continue
            cid = str(verdict.get("candidate_id") or "")
            cand_approval = select_approval_for_candidate(
                resolved_approvals,
                approval_kind=APPROVAL_KIND_RESIDUAL,
                package_id=package_id,
                candidate_id=cid,
            )
            cand_flags = residual_flags_from_approval(cand_approval)
            v_approved = bool(human_approved) or bool(cand_flags.get("human_approved"))
            v_rejected = (
                bool(human_rejected)
                or bool(cand_flags.get("human_rejected"))
                or str(verdict.get("status") or "") == "false_positive_likely"
            )
            gate = build_human_residual_gate(
                package_id=package_id,
                candidate={
                    "candidate_id": verdict.get("candidate_id"),
                    "root_cause_id": verdict.get("root_cause_id"),
                    "execution_allowed": verdict.get("execution_allowed"),
                    "validation_allowed": verdict.get("validation_allowed"),
                    "report_submission_allowed": verdict.get("report_submission_allowed"),
                    "confirmed_vulnerability": verdict.get("confirmed_vulnerability"),
                },
                multi_engine_verdict=verdict,
                residual_checklist=resolved_checklist
                or [
                    "If multi-engine says false_positive_likely, confirm control evidence is complete.",
                    "Do not reopen live validation without new authorized local evidence.",
                ],
                human_approved=v_approved,
                human_rejected=v_rejected,
                scope_allowed=True,
            )
            gates.append(gate.model_dump())

    present = bool(
        isinstance(resolved_bundle, dict) and resolved_bundle.get("present")
    ) or bool(resolved_checklist)
    out = {
        **bridge_result,
        "package_root": str(resolved_root or bridge_result.get("package_root") or ""),
        "residual_checklist_bundle": resolved_bundle
        if isinstance(resolved_bundle, dict)
        else {
            "present": bool(resolved_checklist),
            "items": list(resolved_checklist or [])
            if isinstance(resolved_checklist, list)
            else [],
            "sources": [],
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
            "confirmed_vulnerability": False,
        },
        "residual_checklist_present": present,
        "drafts": enriched_drafts if enriched_drafts else drafts,
        "human_residual_gates": gates,
        "human_review_required": True,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
        "next_allowed_action": (
            "Human residual review of gate items only; submission remains blocked."
        ),
    }
    # Attach durable residual/patch approval audit (context only)
    out = attach_human_review_approvals_to_bridge_result(
        out,
        approvals=resolved_approvals or human_review_approvals,
        approvals_bundle=human_review_approvals_bundle,
        package_root=resolved_root,
        trial_result=trial_result,
    )
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    out["auto_pr_allowed"] = False
    out["patch_ready"] = False
    return out


def _normalize_residuals(
    residual_checklist: list[dict[str, Any]] | list[str] | None,
    *,
    candidate: dict[str, Any],
    multi_engine_verdict: dict[str, Any],
    report_draft: dict[str, Any],
) -> list[ResidualItem]:
    items: list[ResidualItem] = []
    if residual_checklist:
        for index, raw in enumerate(residual_checklist):
            if isinstance(raw, str) and raw.strip():
                items.append(
                    ResidualItem(
                        item_id=f"R-{index+1:02d}",
                        question=raw.strip(),
                        status="open",
                    )
                )
            elif isinstance(raw, dict):
                q = str(
                    raw.get("question") or raw.get("text") or raw.get("item") or ""
                ).strip()
                if not q:
                    continue
                status = _normalize_item_status(str(raw.get("status") or "open"))
                refs = [
                    str(r)
                    for r in (raw.get("evidence_refs") or [])
                    if str(r).strip()
                ]
                items.append(
                    ResidualItem(
                        item_id=str(raw.get("item_id") or f"R-{index+1:02d}"),
                        question=q,
                        status=status,
                        evidence_refs=refs[:12],
                    )
                )

    if items:
        return items[:20]

    # Default residual questions from available signals.
    defaults: list[str] = []
    for q in candidate.get("refutation_questions") or multi_engine_verdict.get(
        "review_questions"
    ) or []:
        if str(q).strip():
            defaults.append(str(q).strip())
    mev_status = str(multi_engine_verdict.get("status") or "")
    if mev_status == "local_static_consistent":
        defaults.append(
            "Local engines agree on an unverified candidate — what non-destructive local evidence would still refute it?"
        )
    elif mev_status == "false_positive_likely":
        defaults.append(
            "Confirm control/refutation evidence is complete enough to close without report draft."
        )
    elif mev_status == "needs_human_review":
        defaults.append(
            "Resolve multi-engine disagreement with package-local evidence only."
        )
    defaults.append("Has live validation been avoided (required default)?")
    defaults.append("Is report submission still intentionally blocked?")
    if report_draft and report_draft.get("title"):
        defaults.append("Is the draft title accurate for an unverified hypothesis only?")

    # unique preserve order
    seen: set[str] = set()
    out: list[ResidualItem] = []
    for index, q in enumerate(defaults):
        if q in seen:
            continue
        seen.add(q)
        out.append(ResidualItem(item_id=f"R-{index+1:02d}", question=q, status="open"))
    return out[:12]


def _parse_residual_file(path: Path) -> list[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        raw = json.loads(path.read_text(encoding="utf-8"))
        return _parse_residual_json(raw)
    text = path.read_text(encoding="utf-8")
    return _parse_residual_markdown(text)


def _parse_residual_json(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        source_items = raw
    elif isinstance(raw, dict):
        source_items = (
            raw.get("items")
            or raw.get("residuals")
            or raw.get("checklist")
            or raw.get("questions")
            or []
        )
    else:
        return []
    if not isinstance(source_items, list):
        return []
    out: list[dict[str, Any]] = []
    for index, item in enumerate(source_items):
        if isinstance(item, str) and item.strip():
            out.append(
                {
                    "item_id": f"R-{index+1:02d}",
                    "question": item.strip(),
                    "status": "open",
                    "evidence_refs": [],
                }
            )
            continue
        if not isinstance(item, dict):
            continue
        q = str(item.get("question") or item.get("text") or item.get("item") or "").strip()
        if not q:
            continue
        out.append(
            {
                "item_id": str(item.get("item_id") or item.get("id") or f"R-{index+1:02d}"),
                "question": q,
                "status": _normalize_item_status(str(item.get("status") or "open")),
                "evidence_refs": [
                    str(r)
                    for r in (item.get("evidence_refs") or [])
                    if str(r).strip()
                ][:12],
            }
        )
    return out


def _parse_residual_markdown(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        # skip pure separator rows
        if re.match(r"^\|\s*:?-{2,}", stripped):
            continue
        table = _TABLE_ROW_RE.match(stripped)
        if table:
            item_id = table.group("id").strip()
            question = table.group("question").strip()
            status_raw = (table.group("status") or "").strip()
            # header row
            if item_id.lower() in {"id", "item", "item_id"} and "question" in question.lower():
                continue
            if not question or question.lower() in seen:
                continue
            # ignore non-question rows that look like section labels without a Q
            if item_id.lower() in {"live residual", "note", "notes"}:
                continue
            seen.add(question.lower())
            out.append(
                {
                    "item_id": item_id or f"R-{len(out)+1:02d}",
                    "question": question,
                    "status": _normalize_item_status(status_raw or "open"),
                    "evidence_refs": [],
                }
            )
            continue

        bullet = _BULLET_RE.match(stripped)
        if not bullet:
            continue
        body = bullet.group("body").strip()
        item_id = f"R-{len(out)+1:02d}"
        status = "open"
        id_match = _ID_PREFIX_RE.match(body)
        if id_match:
            item_id = id_match.group("id").strip()
            body = id_match.group("body").strip()
        # trailing status markers like "... — held" or "(held)"
        status_match = re.search(
            r"(?:\s+[—-]\s+|\s+\()(?P<st>held(?:_documented)?|open|answered|waived|not[ _]checked|pending|intentional)\)?\s*$",
            body,
            flags=re.IGNORECASE,
        )
        if status_match:
            status = _normalize_item_status(status_match.group("st"))
            body = body[: status_match.start()].strip()
        if not body or body.lower() in seen:
            continue
        # skip narrative bullets that are not residual questions
        if body.lower().startswith("live residual"):
            continue
        seen.add(body.lower())
        out.append(
            {
                "item_id": item_id,
                "question": body,
                "status": status,
                "evidence_refs": [],
            }
        )
    return out


def _normalize_item_status(raw: str) -> str:
    s = re.sub(r"[*`]+", "", str(raw or "")).strip().lower()
    if not s:
        return "open"
    # answered / closed by static evidence
    if any(
        token in s
        for token in (
            "answered",
            "complete",
            "confirmed",
            "held",
            "yes",
            "pass",
            "present",
        )
    ) and "not checked" not in s and "not_checked" not in s and "mostly" not in s:
        # held_documented is waived documentation residual, not open work
        if "documented" in s or "intentional" in s or "teaching" in s:
            return "waived"
        if s in {"held", "yes"} or s.startswith("held") or s.startswith("yes"):
            return "answered"
        return "answered"
    if any(
        token in s
        for token in (
            "waived",
            "documented",
            "intentional",
            "absent",
            "not product",
            "n/a",
            "na",
            "skip",
        )
    ):
        return "waived"
    if any(
        token in s
        for token in (
            "open",
            "pending",
            "not checked",
            "not_checked",
            "residual",
            "soft",
            "mostly",
            "todo",
        )
    ):
        return "open"
    if s in {"open", "answered", "waived"}:
        return s
    return "open"


__all__ = [
    "ALLOWED_GATES",
    "GATE_BLOCKED",
    "GATE_HOLD",
    "GATE_READY_FOR_REVIEW",
    "GATE_REJECTED",
    "HumanResidualGateError",
    "HumanResidualGateResult",
    "ResidualItem",
    "attach_human_residual_gates_to_bridge_result",
    "build_human_residual_gate",
    "load_package_residual_checklist",
    "residual_checklist_from_bundle",
    "resolve_residual_checklist",
]