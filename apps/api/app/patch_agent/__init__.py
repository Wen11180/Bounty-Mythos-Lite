"""Patch Agent industrial loop — advisory fix + regression plans only.

Final-scheme 5.11 / V3 Patch Validation seed:
- Batch candidates into an industrial patch program
- Enrich suggestions with local code context (static sniff only)
- Produce non-executing regression validation plans
- Integrate patch_review human approvals as context only
- Never open PRs, apply diffs, run exploits, or unlock submit/promote

Uses app.patch_suggestion playbooks underneath.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from app.human_review_approvals import (
    APPROVAL_KIND_PATCH,
    patch_context_from_approval,
    resolve_human_review_approvals,
    select_approval_for_candidate,
)
from app.patch_suggestion import (
    STATUS_ADVISORY,
    STATUS_NOT_APPLICABLE,
    STATUS_SKIPPED,
    build_patch_suggestion,
)


STATUS_LOOP_EMPTY = "patch_loop_empty"
STATUS_LOOP_PLANNED = "patch_loop_planned_advisory"
STATUS_LOOP_COMPLETED = "patch_loop_completed_advisory"
STATUS_LOOP_SKIPPED_ALL_NA = "patch_loop_skipped_all_not_applicable"
STATUS_LOOP_PARTIAL = "patch_loop_partial_advisory"

_MAX_CANDIDATES = 20
_MAX_FILE_BYTES = 200_000
_MAX_SNIFF = 40_000
_MAX_CONTEXT_HITS = 12

_SKIP_DIR_NAMES = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".tox", "dist", "build", "coverage",
    ".idea", ".vscode", "target", "vendor",
}

_CONTROL_SNIFF = {
    "ssrf": [
        re.compile(r"validateUrlForSSRF|isPrivateIP|isBlockedHostname|blocked.?hostname", re.I),
        re.compile(r"\bfetch\s*\(|requests\.(get|post)|httpx\.", re.I),
    ],
    "authorization": [
        re.compile(r"\bcan\?\(|authorize_|requireAuth|hasPermission|ownership", re.I),
    ],
    "path_traversal": [
        re.compile(r"path\.normalize|realpath|safeJoin|os\.path\.abspath|basename\(", re.I),
    ],
    "mass_assignment": [
        re.compile(r"allowed_fields|permit\(|only\(|exclude\(|safe_params", re.I),
    ],
    "injection": [
        re.compile(r"parameterized|prepared.?statement|execute\(|raw\s+sql", re.I),
    ],
}


class PatchAgentError(ValueError):
    pass


class CodeContextHit(BaseModel):
    path: str
    token: str
    line: int | None = None
    snippet: str = ""
    polarity: str = "observe"


class RegressionValidationStep(BaseModel):
    step_id: str
    title: str
    method: str = "human_local_static_recheck"
    intent: str = ""
    requires_human_approval: bool = True
    network_access: bool = False
    live_validation: bool = False
    auto_execute: bool = False
    status: str = "planned"


class PatchLoopItem(BaseModel):
    item_id: str
    candidate_id: str = ""
    package_id: str = ""
    family: str = "generic"
    status: str = STATUS_SKIPPED
    suggestion: dict[str, Any] = Field(default_factory=dict)
    code_context: list[CodeContextHit] = Field(default_factory=list)
    control_present: bool | None = None
    sink_present: bool | None = None
    minimal_diff_sketch: list[str] = Field(default_factory=list)
    regression_validation_plan: list[RegressionValidationStep] = Field(default_factory=list)
    human_patch_reviewed: bool = False
    patch_review_accepted: bool = False
    patch_review_rejected: bool = False
    patch_ready: bool = False
    auto_pr_allowed: bool = False
    pr_opened: bool = False
    exploit_poc_included: bool = False
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    notes: list[str] = Field(default_factory=list)
    next_allowed_action: str = (
        "Human reviews advisory patch loop item; no auto-PR or live validation."
    )


class PatchIndustrialLoopResult(BaseModel):
    status: str = STATUS_LOOP_EMPTY
    package_id: str = ""
    package_root: str = ""
    items: list[PatchLoopItem] = Field(default_factory=list)
    item_count: int = 0
    advisory_count: int = 0
    not_applicable_count: int = 0
    accepted_review_count: int = 0
    rejected_review_count: int = 0
    regression_plans_count: int = 0
    code_context_hits: int = 0
    loop_phases: list[str] = Field(
        default_factory=lambda: [
            "suggest",
            "enrich_local_context",
            "plan_regression",
            "human_patch_review_context",
            "stop_no_auto_pr",
        ]
    )
    patch_ready: bool = False
    auto_pr_allowed: bool = False
    pr_opened: bool = False
    exploit_poc_included: bool = False
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    network_access: bool = False
    live_validation_executed: bool = False
    notes: list[str] = Field(default_factory=list)
    next_allowed_action: str = (
        "Industrial patch loop is advisory only. Human reviews suggestions and "
        "planned regression steps; do not auto-open PRs or execute validation."
    )
    safety_blockers: list[str] = Field(
        default_factory=lambda: [
            "auto_open_pull_request",
            "apply_git_diff",
            "write_exploit_poc",
            "execute_live_validation",
            "submit_report",
            "auto_promote_finding",
            "set_patch_ready",
        ]
    )

def build_minimal_diff_sketch(
    *,
    family: str,
    code_path: str = "",
    route: str = "",
    root_cause_id: str = "",
) -> list[str]:
    """Pseudocode-level sketch only — not a real patch/PR."""
    path = code_path or "<shared-service-layer>"
    rc = root_cause_id or "root_cause"
    sketches = {
        "ssrf": [
            "# advisory sketch only — do not auto-apply",
            f"# target: {path}",
            "def validate_url_for_ssrf(url):",
            "    # scheme allowlist + block private/metadata hosts",
            "    ...",
            f"# before outbound fetch on {route or 'affected route'}:",
            f"validate_url_for_ssrf(user_url)  # root: {rc}",
        ],
        "authorization": [
            "# advisory sketch only — do not auto-apply",
            f"# target: {path}",
            "def authorize_object(user, obj):",
            "    # ownership / permission check",
            "    ...",
            f"authorize_object(current_user, resource)  # before return; root: {rc}",
        ],
        "path_traversal": [
            "# advisory sketch only — do not auto-apply",
            f"# target: {path}",
            "safe = root.joinpath(user_path).resolve()",
            f"assert safe.is_relative_to(root)  # root: {rc}",
        ],
        "mass_assignment": [
            "# advisory sketch only — do not auto-apply",
            f"# target: {path}",
            "allowed = {'title', 'body'}  # explicit allowlist",
            f"data = {{k: v for k, v in payload.items() if k in allowed}}  # root: {rc}",
        ],
        "injection": [
            "# advisory sketch only — do not auto-apply",
            f"# target: {path}",
            f"cursor.execute('SELECT ... WHERE id = ?', (user_id,))  # root: {rc}",
        ],
        "generic": [
            "# advisory sketch only — do not auto-apply",
            f"# target: {path}",
            f"# Confirm root cause ({rc}) with human before coding a fix.",
        ],
    }
    return list(sketches.get(family, sketches["generic"]))


def build_regression_validation_plan(
    *,
    family: str,
    candidate_id: str = "",
    suggestion: dict[str, Any] | None = None,
) -> list[RegressionValidationStep]:
    """Non-executing regression validation plan (human/local static recheck)."""
    suggestion = suggestion if isinstance(suggestion, dict) else {}
    steps: list[RegressionValidationStep] = []
    base = candidate_id or "cand"
    steps.append(
        RegressionValidationStep(
            step_id=f"PV-{base}-01",
            title="Confirm root-cause fix lands in shared layer",
            intent=(
                "Human verifies the suggested control is applied at the shared "
                f"service/auth layer for family={family}, not only one controller."
            ),
        )
    )
    steps.append(
        RegressionValidationStep(
            step_id=f"PV-{base}-02",
            title="Static recheck of alternate entrypoints",
            intent=(
                "Local static search for sibling routes/functions that still call "
                "the sink without the new guard (no live traffic)."
            ),
            method="human_local_static_recheck",
        )
    )
    for index, item in enumerate(suggestion.get("regression_tests") or [], start=3):
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or f"regression-{index}")
        intent = str(item.get("intent") or "Human designs non-destructive regression.")
        steps.append(
            RegressionValidationStep(
                step_id=f"PV-{base}-{index:02d}",
                title=title[:160],
                intent=intent[:400],
                method="planned_regression_test_text_only",
            )
        )
        if len(steps) >= 6:
            break
    steps.append(
        RegressionValidationStep(
            step_id=f"PV-{base}-99",
            title="Stop before auto-PR / live validation",
            intent=(
                "Do not open pull requests, apply diffs, run exploit PoCs, or "
                "mark patch_ready from this system."
            ),
            method="safety_stop",
        )
    )
    for step in steps:
        step.requires_human_approval = True
        step.network_access = False
        step.live_validation = False
        step.auto_execute = False
        step.status = "planned"
    return steps


def sniff_local_code_context(
    package_root: str | Path | None,
    *,
    family: str,
    code_path: str = "",
) -> list[CodeContextHit]:
    """Static package-local sniff for control/sink tokens. No network."""
    if package_root is None or str(package_root).strip() == "":
        return []
    root = Path(package_root).resolve()
    if not root.is_dir():
        return []

    patterns = list(_CONTROL_SNIFF.get(family) or [])
    if not patterns:
        patterns = [re.compile(r"TODO|FIXME|security", re.I)]

    preferred_files: list[Path] = []
    hinted = _resolve_hinted_path(root, code_path)
    if hinted is not None:
        preferred_files.append(hinted)

    for sub in ("inputs", "_extract", "src", "app", "backend"):
        base = root / sub
        if base.is_dir():
            preferred_files.extend(_iter_code_files(base, root, limit=40))
    if not preferred_files:
        preferred_files.extend(_iter_code_files(root, root, limit=40))

    hits: list[CodeContextHit] = []
    seen: set[str] = set()
    for path in preferred_files:
        try:
            rel = str(path.resolve().relative_to(root)).replace("\\", "/")
        except Exception:
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")[:_MAX_SNIFF]
        except Exception:
            continue
        for pattern in patterns:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                token = match.group(0)[:80]
                key = f"{rel}:{line}:{token}"
                if key in seen:
                    continue
                seen.add(key)
                polarity = "observe"
                low = token.lower()
                if any(
                    x in low
                    for x in (
                        "validate",
                        "private",
                        "blocked",
                        "authorize",
                        "permission",
                        "ownership",
                        "safe",
                        "allowlist",
                        "permit",
                        "parameter",
                    )
                ):
                    polarity = "control_present"
                elif any(x in low for x in ("fetch", "request", "httpx", "execute", "query")):
                    polarity = "sink_present"
                snippet = _line_snippet(text, match.start())
                hits.append(
                    CodeContextHit(
                        path=rel,
                        token=token,
                        line=line,
                        snippet=snippet,
                        polarity=polarity,
                    )
                )
                if len(hits) >= _MAX_CONTEXT_HITS:
                    return hits
    return hits

def run_patch_industrial_loop(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    candidates: list[dict[str, Any]] | None = None,
    multi_engine_verdicts: list[dict[str, Any]] | None = None,
    drafts: list[dict[str, Any]] | None = None,
    human_approvals: list[dict[str, Any]] | None = None,
    existing_suggestions: list[dict[str, Any]] | None = None,
) -> PatchIndustrialLoopResult:
    """Run advisory industrial patch loop for a package (no PR / no live validation)."""
    root: Path | None = None
    if package_root is not None and str(package_root).strip():
        root = Path(package_root).resolve()

    resolved_id = package_id
    if not resolved_id and root is not None:
        resolved_id = _read_package_id(root) or root.name

    targets = _collect_targets(
        candidates=candidates,
        multi_engine_verdicts=multi_engine_verdicts,
        drafts=drafts,
        existing_suggestions=existing_suggestions,
    )

    approvals = human_approvals
    if approvals is None:
        approvals = resolve_human_review_approvals(package_root=root)

    items: list[PatchLoopItem] = []
    notes: list[str] = ["advisory_only", "no_auto_pr", "no_live_validation"]

    for index, target in enumerate(targets[:_MAX_CANDIDATES], start=1):
        cand_id = str(target.get("candidate_id") or f"C-{index:03d}")
        existing = target.get("existing_suggestion")
        if isinstance(existing, dict) and existing:
            suggestion = _force_safety_dict(dict(existing))
        else:
            built = build_patch_suggestion(
                package_id=resolved_id,
                candidate=target,
                multi_engine_verdict=target.get("multi_engine_verdict")
                if isinstance(target.get("multi_engine_verdict"), dict)
                else {},
                report_draft=target.get("report_draft")
                if isinstance(target.get("report_draft"), dict)
                else {},
            )
            suggestion = _force_safety_dict(built.model_dump())

        mev = (
            target.get("multi_engine_verdict")
            if isinstance(target.get("multi_engine_verdict"), dict)
            else {}
        )
        if str(mev.get("status") or "") == "false_positive_likely":
            suggestion["status"] = STATUS_NOT_APPLICABLE
            suggestion["next_allowed_action"] = (
                "Controls appear to oppose candidate; patch suggestion not applicable."
            )

        family = _detect_family(
            str(target.get("vuln_type") or suggestion.get("vuln_type") or ""),
            str(target.get("root_cause_id") or suggestion.get("root_cause_id") or ""),
        )
        code_path = str(
            target.get("affected_code_path")
            or suggestion.get("affected_code_path")
            or ""
        )
        route = str(
            suggestion.get("affected_route") or _format_route(target.get("route")) or ""
        )

        context = sniff_local_code_context(root, family=family, code_path=code_path)
        control_present = any(h.polarity == "control_present" for h in context) or None
        sink_present = any(h.polarity == "sink_present" for h in context) or None
        if context:
            if control_present is None:
                control_present = False
            if sink_present is None:
                sink_present = False

        sketch = build_minimal_diff_sketch(
            family=family,
            code_path=code_path,
            route=route,
            root_cause_id=str(suggestion.get("root_cause_id") or ""),
        )
        reg_plan = build_regression_validation_plan(
            family=family,
            candidate_id=cand_id,
            suggestion=suggestion,
        )

        approval = select_approval_for_candidate(
            approvals or [],
            approval_kind=APPROVAL_KIND_PATCH,
            candidate_id=cand_id,
            package_id=resolved_id,
        )
        pctx = patch_context_from_approval(approval)

        item_status = str(suggestion.get("status") or STATUS_SKIPPED)
        item_notes: list[str] = []
        if pctx.get("patch_review_rejected"):
            item_notes.append("human_patch_review_rejected")
        if pctx.get("patch_review_accepted"):
            item_notes.append("human_patch_review_accepted_context_only")
        if control_present:
            item_notes.append("local_control_tokens_observed")
        if sink_present:
            item_notes.append("local_sink_tokens_observed")

        item = PatchLoopItem(
            item_id=f"PL-{index:03d}",
            candidate_id=cand_id,
            package_id=resolved_id,
            family=family,
            status=item_status,
            suggestion=suggestion,
            code_context=context,
            control_present=control_present,
            sink_present=sink_present,
            minimal_diff_sketch=sketch,
            regression_validation_plan=reg_plan,
            human_patch_reviewed=bool(pctx.get("human_patch_reviewed")),
            patch_review_accepted=bool(pctx.get("patch_review_accepted")),
            patch_review_rejected=bool(pctx.get("patch_review_rejected")),
            notes=item_notes,
            next_allowed_action=(
                "Human reviews advisory fix sketch + planned regression steps only."
                if item_status == STATUS_ADVISORY
                else str(suggestion.get("next_allowed_action") or "No patch action.")
            ),
        )
        items.append(_force_safety_item(item))

    advisory_count = sum(1 for i in items if i.status == STATUS_ADVISORY)
    na_count = sum(1 for i in items if i.status == STATUS_NOT_APPLICABLE)
    accepted = sum(1 for i in items if i.patch_review_accepted)
    rejected = sum(1 for i in items if i.patch_review_rejected)
    reg_count = sum(len(i.regression_validation_plan) for i in items)
    ctx_hits = sum(len(i.code_context) for i in items)

    if not items:
        status = STATUS_LOOP_EMPTY
        next_action = "No candidates for patch industrial loop."
    elif advisory_count == 0 and na_count > 0:
        status = STATUS_LOOP_SKIPPED_ALL_NA
        next_action = "All candidates not applicable for patch; keep controls as-is."
    elif advisory_count > 0 and (na_count > 0 or len(items) > advisory_count):
        status = STATUS_LOOP_PARTIAL
        next_action = (
            "Partial advisory patch program ready for human review; no auto-PR."
        )
    elif advisory_count > 0:
        status = STATUS_LOOP_COMPLETED
        next_action = (
            "Advisory patch industrial loop completed for package; "
            "human reviews sketches and regression plans only."
        )
    else:
        status = STATUS_LOOP_PLANNED
        next_action = "Patch loop planned; awaiting actionable candidates."

    result = PatchIndustrialLoopResult(
        status=status,
        package_id=resolved_id,
        package_root=str(root or ""),
        items=items,
        item_count=len(items),
        advisory_count=advisory_count,
        not_applicable_count=na_count,
        accepted_review_count=accepted,
        rejected_review_count=rejected,
        regression_plans_count=reg_count,
        code_context_hits=ctx_hits,
        notes=notes,
        next_allowed_action=next_action,
    )
    return _force_safety_result(result)

def attach_patch_industrial_loop_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    patch_loop: dict[str, Any] | PatchIndustrialLoopResult | None = None,
    human_approvals: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Attach industrial patch loop summary onto report-bridge result."""
    if not isinstance(bridge_result, dict):
        raise PatchAgentError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")

    if patch_loop is not None:
        if isinstance(patch_loop, PatchIndustrialLoopResult):
            loop = _force_safety_result(patch_loop).model_dump()
        else:
            loop = _force_safety_dict(dict(patch_loop))
    else:
        drafts = (
            bridge_result.get("drafts")
            if isinstance(bridge_result.get("drafts"), list)
            else []
        )
        verdicts = (
            bridge_result.get("multi_engine_verdicts")
            if isinstance(bridge_result.get("multi_engine_verdicts"), list)
            else []
        )
        suggestions = (
            bridge_result.get("patch_suggestions")
            if isinstance(bridge_result.get("patch_suggestions"), list)
            else []
        )
        approvals = human_approvals
        if approvals is None:
            approvals = (
                bridge_result.get("human_review_approvals")
                if isinstance(bridge_result.get("human_review_approvals"), list)
                else None
            )
        loop = run_patch_industrial_loop(
            package_root=resolved_root,
            package_id=package_id,
            drafts=drafts,
            multi_engine_verdicts=verdicts,
            existing_suggestions=suggestions,
            human_approvals=approvals,
        ).model_dump()

    out = dict(bridge_result)
    out["patch_industrial_loop"] = loop
    out["patch_industrial_loop_present"] = True
    out["patch_industrial_loop_status"] = str(loop.get("status") or STATUS_LOOP_EMPTY)
    out["patch_industrial_loop_item_count"] = int(loop.get("item_count") or 0)
    out["patch_industrial_loop_advisory_count"] = int(loop.get("advisory_count") or 0)
    out["patch_ready"] = False
    out["auto_pr_allowed"] = False
    out["pr_opened"] = False
    out["exploit_poc_included"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True

    items_by_cand = {
        str(i.get("candidate_id") or ""): i
        for i in (loop.get("items") or [])
        if isinstance(i, dict)
    }
    new_drafts: list[Any] = []
    for draft in out.get("drafts") or []:
        if not isinstance(draft, dict):
            new_drafts.append(draft)
            continue
        d = dict(draft)
        item = items_by_cand.get(str(d.get("candidate_id") or ""))
        if isinstance(item, dict):
            d["patch_industrial_loop_item"] = {
                "item_id": item.get("item_id"),
                "status": item.get("status"),
                "family": item.get("family"),
                "control_present": item.get("control_present"),
                "sink_present": item.get("sink_present"),
                "minimal_diff_sketch": item.get("minimal_diff_sketch"),
                "regression_validation_plan": item.get("regression_validation_plan"),
                "patch_review_accepted": item.get("patch_review_accepted"),
                "patch_ready": False,
                "auto_pr_allowed": False,
            }
            rd = d.get("report_draft") if isinstance(d.get("report_draft"), dict) else {}
            rd = dict(rd)
            if item.get("minimal_diff_sketch"):
                rd["patch_diff_sketch"] = "\n".join(
                    str(x) for x in item.get("minimal_diff_sketch") or []
                )
            rd["patch_loop_status"] = item.get("status")
            d["report_draft"] = rd
        d["execution_allowed"] = False
        d["validation_allowed"] = False
        d["report_submission_allowed"] = False
        d["confirmed_vulnerability"] = False
        new_drafts.append(d)
    if "drafts" in out:
        out["drafts"] = new_drafts
    return out


def _collect_targets(
    *,
    candidates: list[dict[str, Any]] | None,
    multi_engine_verdicts: list[dict[str, Any]] | None,
    drafts: list[dict[str, Any]] | None,
    existing_suggestions: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(item: dict[str, Any], *, existing: dict[str, Any] | None = None) -> None:
        cid = str(item.get("candidate_id") or "")
        key = cid or json.dumps(item, sort_keys=True, default=str)[:120]
        if key in seen:
            return
        seen.add(key)
        row = dict(item)
        if existing:
            row["existing_suggestion"] = existing
        targets.append(row)

    for draft in drafts or []:
        if not isinstance(draft, dict):
            continue
        existing = None
        if isinstance(draft.get("patch_suggestion"), dict):
            existing = draft["patch_suggestion"]
        add(
            {
                "candidate_id": draft.get("candidate_id"),
                "root_cause_id": draft.get("root_cause_id"),
                "vuln_type": draft.get("vuln_type"),
                "affected_code_path": draft.get("affected_code_path"),
                "route": draft.get("route"),
                "multi_engine_verdict": draft.get("multi_engine_verdict"),
                "report_draft": draft.get("report_draft"),
            },
            existing=existing,
        )

    sug_by: dict[str, dict[str, Any]] = {}
    for sug in existing_suggestions or []:
        if isinstance(sug, dict) and sug.get("candidate_id"):
            sug_by[str(sug["candidate_id"])] = sug

    for cand in candidates or []:
        if not isinstance(cand, dict):
            continue
        cid = str(cand.get("candidate_id") or "")
        add(cand, existing=sug_by.get(cid))

    for verdict in multi_engine_verdicts or []:
        if not isinstance(verdict, dict):
            continue
        cid = str(verdict.get("candidate_id") or "")
        add(
            {
                "candidate_id": cid,
                "root_cause_id": verdict.get("root_cause_id"),
                "vuln_type": verdict.get("vuln_type"),
                "affected_code_path": verdict.get("affected_code_path"),
                "route": verdict.get("route"),
                "multi_engine_verdict": verdict,
            },
            existing=sug_by.get(cid),
        )

    for sug in existing_suggestions or []:
        if not isinstance(sug, dict):
            continue
        cid = str(sug.get("candidate_id") or "")
        if cid and cid not in seen:
            add(
                {
                    "candidate_id": cid,
                    "root_cause_id": sug.get("root_cause_id"),
                    "vuln_type": sug.get("vuln_type"),
                    "affected_code_path": sug.get("affected_code_path"),
                    "route": sug.get("affected_route"),
                },
                existing=sug,
            )
    return targets


def _resolve_hinted_path(root: Path, code_path: str) -> Path | None:
    if not code_path:
        return None
    raw = code_path
    if raw.startswith("code:"):
        raw = raw[5:]
    raw = raw.split(":")[0]
    candidates = [
        root / raw,
        root / "inputs" / Path(raw).name,
        root / "_extract" / Path(raw).name,
        root / Path(raw).name,
    ]
    for path in candidates:
        try:
            resolved = path.resolve()
            resolved.relative_to(root)
            if resolved.is_file():
                return resolved
        except Exception:
            continue
    return None


def _iter_code_files(base: Path, root: Path, *, limit: int) -> list[Path]:
    out: list[Path] = []
    suffixes = {
        ".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".rb", ".php", ".java", ".rs", ".cs",
    }
    try:
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in suffixes:
                continue
            if any(part in _SKIP_DIR_NAMES for part in path.parts):
                continue
            try:
                path.resolve().relative_to(root.resolve())
            except Exception:
                continue
            name_l = path.name.lower()
            if any(b in name_l for b in ("secret", "token", "password", "credential")):
                continue
            out.append(path)
            if len(out) >= limit:
                break
    except Exception:
        return out
    return out


def _line_snippet(text: str, index: int) -> str:
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    if end < 0:
        end = min(len(text), start + 160)
    return text[start:end].strip()[:160]


def _format_route(route: Any) -> str:
    if isinstance(route, dict):
        method = str(route.get("method") or "").upper()
        path = str(route.get("path") or "")
        return f"{method} {path}".strip()
    return str(route or "")


def _detect_family(vuln_type: str, root_cause_id: str) -> str:
    blob = f"{vuln_type} {root_cause_id}".lower()
    if "ssrf" in blob:
        return "ssrf"
    if any(x in blob for x in ("authz", "authoriz", "idor", "ownership", "permission")):
        return "authorization"
    if any(x in blob for x in ("path", "traversal", "lfi")):
        return "path_traversal"
    if any(x in blob for x in ("mass", "overpost", "assignment")):
        return "mass_assignment"
    if any(x in blob for x in ("inject", "sqli", "xss", "command")):
        return "injection"
    return "generic"


def _read_package_id(root: Path) -> str:
    for name in ("package.json", "gold.json"):
        path = root / name
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                for key in ("package_id", "id", "name"):
                    if data.get(key):
                        return str(data[key])
        except Exception:
            continue
    return root.name


def _force_safety_item(item: PatchLoopItem) -> PatchLoopItem:
    item.patch_ready = False
    item.auto_pr_allowed = False
    item.pr_opened = False
    item.exploit_poc_included = False
    item.execution_allowed = False
    item.validation_allowed = False
    item.report_submission_allowed = False
    item.confirmed_vulnerability = False
    item.finding_promotion_allowed = False
    if isinstance(item.suggestion, dict):
        item.suggestion = _force_safety_dict(item.suggestion)
    for step in item.regression_validation_plan:
        step.auto_execute = False
        step.network_access = False
        step.live_validation = False
        step.requires_human_approval = True
    return item


def _force_safety_result(result: PatchIndustrialLoopResult) -> PatchIndustrialLoopResult:
    result.patch_ready = False
    result.auto_pr_allowed = False
    result.pr_opened = False
    result.exploit_poc_included = False
    result.execution_allowed = False
    result.validation_allowed = False
    result.report_submission_allowed = False
    result.confirmed_vulnerability = False
    result.finding_promotion_allowed = False
    result.network_access = False
    result.live_validation_executed = False
    result.items = [_force_safety_item(i) for i in result.items]
    return result


def _force_safety_dict(payload: dict[str, Any]) -> dict[str, Any]:
    payload = dict(payload)
    for key in (
        "patch_ready",
        "auto_pr_allowed",
        "pr_opened",
        "exploit_poc_included",
        "execution_allowed",
        "validation_allowed",
        "report_submission_allowed",
        "confirmed_vulnerability",
        "finding_promotion_allowed",
        "network_access",
        "live_validation_executed",
    ):
        payload[key] = False
    return payload


__all__ = [
    "STATUS_LOOP_COMPLETED",
    "STATUS_LOOP_EMPTY",
    "STATUS_LOOP_PARTIAL",
    "STATUS_LOOP_PLANNED",
    "STATUS_LOOP_SKIPPED_ALL_NA",
    "CodeContextHit",
    "PatchAgentError",
    "PatchIndustrialLoopResult",
    "PatchLoopItem",
    "RegressionValidationStep",
    "attach_patch_industrial_loop_to_bridge_result",
    "build_minimal_diff_sketch",
    "build_regression_validation_plan",
    "run_patch_industrial_loop",
    "sniff_local_code_context",
]