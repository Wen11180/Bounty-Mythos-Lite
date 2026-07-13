from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.human_review_approvals import APPROVAL_KIND_PATCH


STATUS_READY = "patch_pr_export_ready"
STATUS_PLANNED = "patch_pr_export_planned"
STATUS_EMPTY = "patch_pr_export_empty"
STATUS_SKIPPED = "patch_pr_export_package_missing"
STATUS_BLOCKED_REVIEW = "patch_pr_export_blocked_until_patch_review"
STATUS_EXPORTED = "patch_pr_export_written_local"

SAFETY_INVARIANTS = [
    "human_opens_pr_outside_system",
    "no_auto_open_pull_request",
    "no_git_apply_by_planner",
    "no_git_push",
    "no_gh_cli_execution",
    "no_network_access",
    "no_exploit_poc",
    "no_report_submission",
    "advisory_diff_sketch_only",
    "human_approval_required_before_export_write",
]


class PatchPrWorkflowError(ValueError):
    pass


@dataclass
class ExportFile:
    relative_path: str
    purpose: str
    content_preview: str = ""
    content: str = ""
    bytes_planned: int = 0
    written: bool = False


@dataclass
class HumanPrSteps:
    steps: list[str] = field(default_factory=list)
    forbidden: list[str] = field(default_factory=list)


@dataclass
class PatchPrExportItem:
    item_id: str
    candidate_id: str = ""
    family: str = "generic"
    status: str = STATUS_PLANNED
    branch_name: str = ""
    pr_title: str = ""
    base_branch: str = "main"
    files: list[ExportFile] = field(default_factory=list)
    patch_review_accepted: bool = False
    export_write_allowed: bool = False
    auto_pr_allowed: bool = False
    pr_opened: bool = False
    patch_ready: bool = False
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    next_allowed_action: str = (
        "Human copies export artifacts and opens a PR outside Mythos if appropriate."
    )


@dataclass
class PatchPrWorkflowResult:
    stage: str = "v1_external_patch_pr_workflow"
    inspirations: list[str] = field(default_factory=lambda: ["final_scheme_5.11_patch_agent"])
    execution_mode: str = "plan_only_external_human_pr"
    status: str = STATUS_EMPTY
    package_id: str = ""
    package_root: str = ""
    export_root_relative: str = "_export/patch_pr"
    items: list[PatchPrExportItem] = field(default_factory=list)
    item_count: int = 0
    ready_count: int = 0
    exported_count: int = 0
    blocked_review_count: int = 0
    human_steps: HumanPrSteps = field(default_factory=HumanPrSteps)
    human_allow_export_write: bool = False
    export_written: bool = False
    auto_pr_allowed: bool = False
    pr_opened: bool = False
    patch_ready: bool = False
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    network_access: bool = False
    live_validation: bool = False
    git_operations: bool = False
    notes: list[str] = field(default_factory=list)
    safety_invariants: list[str] = field(default_factory=lambda: list(SAFETY_INVARIANTS))
    safety_blockers: list[str] = field(
        default_factory=lambda: [
            "auto_open_pull_request",
            "apply_git_diff",
            "git_push",
            "gh_pr_create",
            "write_exploit_poc",
            "submit_report",
            "auto_promote_finding",
            "set_patch_ready",
        ]
    )
    next_allowed_action: str = (
        "Review advisory export package; open PR manually outside this system only after human judgment."
    )

    def to_dict(self) -> dict[str, Any]:
        return _force_safety_dict(asdict(self))

def build_patch_pr_workflow(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    patch_industrial_loop: dict[str, Any] | None = None,
    patch_suggestions: list[dict[str, Any]] | None = None,
    human_approvals: list[dict[str, Any]] | None = None,
    human_allow_export_write: bool = False,
    base_branch: str = "main",
) -> PatchPrWorkflowResult:
    """Build plan-only external PR export package from advisory patch artifacts.

    Never opens PRs, runs git, or talks to GitHub. Optional export write is local-only
    and still requires explicit human flag + accepted patch_review when available.
    """
    notes: list[str] = [
        "plan_only",
        "external_human_pr",
        "no_auto_pr",
        "no_git_operations",
        "no_network_access",
    ]
    root: Path | None = None
    pkg_id = str(package_id or "").strip()
    if package_root is not None and str(package_root).strip():
        root = Path(package_root).resolve()
        if not root.is_dir():
            return _empty(
                status=STATUS_SKIPPED,
                package_id=pkg_id,
                package_root=str(root),
                notes=notes + ["package_root_missing"],
                next_action="Provide authorized local package_root.",
            )
        if not pkg_id:
            pkg_id = _read_package_id(root)

    sources = _collect_sources(
        patch_industrial_loop=patch_industrial_loop,
        patch_suggestions=patch_suggestions,
    )
    if not sources:
        result = _empty(
            status=STATUS_EMPTY,
            package_id=pkg_id,
            package_root=str(root or ""),
            notes=notes + ["no_advisory_patch_items"],
            next_action="Run patch industrial loop / suggestions first.",
        )
        result.human_allow_export_write = bool(human_allow_export_write)
        return _force_safety_result(result)

    approval_accepted = _patch_review_accepted(human_approvals)
    items: list[PatchPrExportItem] = []
    for index, src in enumerate(sources, start=1):
        items.append(
            _build_item(
                index=index,
                source=src,
                package_id=pkg_id,
                base_branch=base_branch or "main",
                approval_accepted=approval_accepted,
                human_allow_export_write=bool(human_allow_export_write),
            )
        )

    ready_count = sum(1 for i in items if i.status in {STATUS_READY, STATUS_EXPORTED})
    blocked = sum(1 for i in items if i.status == STATUS_BLOCKED_REVIEW)
    exported = 0
    export_written = False

    if human_allow_export_write and root is not None and ready_count:
        # only write when human flag set; still never open PR
        exported, export_written = _write_exports(root, items, package_id=pkg_id)
        notes.append("local_export_write_attempted")
        if export_written:
            notes.append("local_export_written")
    elif human_allow_export_write:
        notes.append("export_write_requested_but_no_ready_items_or_root")
    else:
        notes.append("export_write_not_requested")

    if export_written and exported:
        status = STATUS_EXPORTED
    elif ready_count:
        status = STATUS_READY
    elif blocked and not ready_count:
        status = STATUS_BLOCKED_REVIEW
    else:
        status = STATUS_PLANNED

    result = PatchPrWorkflowResult(
        status=status,
        package_id=pkg_id,
        package_root=str(root or ""),
        items=items,
        item_count=len(items),
        ready_count=ready_count,
        exported_count=exported,
        blocked_review_count=blocked,
        human_steps=_human_steps(),
        human_allow_export_write=bool(human_allow_export_write),
        export_written=export_written,
        notes=notes,
        next_allowed_action=(
            "Open PR outside Mythos using exported files if human accepts the fix; "
            "never auto-create PR from this planner."
            if ready_count or export_written
            else "Obtain accepted patch_review (or review advisory items) before treating export as ready."
        ),
    )
    return _force_safety_result(result)


def attach_patch_pr_workflow_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    human_allow_export_write: bool = False,
    patch_pr_workflow: dict[str, Any] | PatchPrWorkflowResult | None = None,
) -> dict[str, Any]:
    """Attach external patch-PR workflow plan; never unlocks auto-PR/submit."""
    if not isinstance(bridge_result, dict):
        raise PatchPrWorkflowError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")

    if isinstance(patch_pr_workflow, PatchPrWorkflowResult):
        payload = patch_pr_workflow.to_dict()
    elif isinstance(patch_pr_workflow, dict):
        payload = _force_safety_dict(dict(patch_pr_workflow))
    else:
        loop = bridge_result.get("patch_industrial_loop")
        suggestions = bridge_result.get("patch_suggestions")
        approvals = bridge_result.get("human_review_approvals")
        payload = build_patch_pr_workflow(
            package_root=resolved_root,
            package_id=package_id,
            patch_industrial_loop=loop if isinstance(loop, dict) else None,
            patch_suggestions=suggestions if isinstance(suggestions, list) else None,
            human_approvals=approvals if isinstance(approvals, list) else None,
            human_allow_export_write=bool(human_allow_export_write),
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)
    payload = _strip_file_content_for_bridge(payload)

    out = dict(bridge_result)
    out["patch_pr_workflow"] = payload
    out["patch_pr_workflow_present"] = True
    out["patch_pr_workflow_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["patch_pr_workflow_item_count"] = int(payload.get("item_count") or 0)
    out["patch_pr_workflow_ready_count"] = int(payload.get("ready_count") or 0)
    out["patch_pr_workflow_exported_count"] = int(payload.get("exported_count") or 0)
    out["patch_pr_export_written"] = bool(payload.get("export_written"))
    out["auto_pr_allowed"] = False
    out["pr_opened"] = False
    out["patch_ready"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out

def _empty(
    *,
    status: str,
    package_id: str,
    package_root: str,
    notes: list[str],
    next_action: str,
) -> PatchPrWorkflowResult:
    return PatchPrWorkflowResult(
        status=status,
        package_id=package_id,
        package_root=package_root,
        notes=list(notes),
        human_steps=_human_steps(),
        next_allowed_action=next_action,
    )


def _human_steps() -> HumanPrSteps:
    return HumanPrSteps(
        steps=[
            "Review advisory root-cause summary and minimal_diff_sketch for correctness.",
            "Confirm residual/patch human review disposition for the candidate.",
            "Copy export files from package `_export/patch_pr/<item_id>/` (if written) or from plan preview.",
            "Create a branch outside Mythos (example name provided in item.branch_name).",
            "Apply or re-implement the fix manually in your authorized local checkout.",
            "Run human-approved local tests / regression checklist (no Mythos auto-execute).",
            "Open a PR on the authorized host using your own credentials and process.",
            "Keep Mythos report submission blocked until a separate human report gate passes.",
        ],
        forbidden=[
            "Do not let Mythos open the PR.",
            "Do not push tokens or secrets into export files.",
            "Do not include exploit PoC payloads.",
            "Do not mark patch_ready inside Mythos solely because export files exist.",
            "Do not auto-submit bounty reports.",
        ],
    )


def _collect_sources(
    *,
    patch_industrial_loop: dict[str, Any] | None,
    patch_suggestions: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    sources: list[dict[str, Any]] = []
    seen: set[str] = set()

    if isinstance(patch_industrial_loop, dict):
        for item in patch_industrial_loop.get("items") or []:
            if not isinstance(item, dict):
                continue
            suggestion = item.get("suggestion") if isinstance(item.get("suggestion"), dict) else {}
            status = str(item.get("status") or suggestion.get("status") or "")
            if "not_applicable" in status or status.endswith("skipped"):
                # still allow NA for transparency but mark as blocked/planned only if advisory
                if status in {"not_applicable_refuted_or_unverified", "skipped_no_candidate"}:
                    continue
            cand = str(item.get("candidate_id") or suggestion.get("candidate_id") or "")
            key = cand or str(item.get("item_id") or "")
            if key in seen:
                continue
            seen.add(key)
            sources.append(
                {
                    "candidate_id": cand,
                    "item_id": str(item.get("item_id") or ""),
                    "family": str(item.get("family") or suggestion.get("vuln_type") or "generic"),
                    "status": status,
                    "suggestion": suggestion,
                    "minimal_diff_sketch": list(item.get("minimal_diff_sketch") or []),
                    "regression_validation_plan": list(
                        item.get("regression_validation_plan") or []
                    ),
                    "code_context": list(item.get("code_context") or []),
                    "patch_review_accepted": bool(item.get("patch_review_accepted")),
                    "affected_code_path": str(
                        suggestion.get("affected_code_path")
                        or item.get("affected_code_path")
                        or ""
                    ),
                    "affected_route": str(
                        suggestion.get("affected_route") or item.get("affected_route") or ""
                    ),
                    "root_cause_summary": str(suggestion.get("root_cause_summary") or ""),
                    "suggested_changes": list(suggestion.get("suggested_changes") or []),
                    "regression_tests": list(suggestion.get("regression_tests") or []),
                    "vuln_type": str(suggestion.get("vuln_type") or item.get("family") or ""),
                }
            )

    if isinstance(patch_suggestions, list):
        for sug in patch_suggestions:
            if not isinstance(sug, dict):
                continue
            status = str(sug.get("status") or "")
            if status in {"not_applicable_refuted_or_unverified", "skipped_no_candidate"}:
                continue
            cand = str(sug.get("candidate_id") or "")
            key = cand or str(sug.get("root_cause_id") or "")
            if key in seen:
                continue
            seen.add(key)
            sources.append(
                {
                    "candidate_id": cand,
                    "item_id": "",
                    "family": str(sug.get("vuln_type") or "generic"),
                    "status": status,
                    "suggestion": sug,
                    "minimal_diff_sketch": [],
                    "regression_validation_plan": [],
                    "code_context": [],
                    "patch_review_accepted": bool(sug.get("patch_review_accepted")),
                    "affected_code_path": str(sug.get("affected_code_path") or ""),
                    "affected_route": str(sug.get("affected_route") or ""),
                    "root_cause_summary": str(sug.get("root_cause_summary") or ""),
                    "suggested_changes": list(sug.get("suggested_changes") or []),
                    "regression_tests": list(sug.get("regression_tests") or []),
                    "vuln_type": str(sug.get("vuln_type") or ""),
                }
            )
    return sources


def _patch_review_accepted(human_approvals: list[dict[str, Any]] | None) -> bool:
    if not human_approvals:
        return False
    for raw in human_approvals:
        if not isinstance(raw, dict):
            continue
        kind = str(raw.get("approval_kind") or raw.get("kind") or "")
        if kind and kind != APPROVAL_KIND_PATCH:
            continue
        # residual_flags_from_approval is residual-oriented; inspect status directly
        status = str(raw.get("status") or "").lower()
        if status in {"approved", "waived"}:
            return True
        if raw.get("patch_review_accepted") is True:
            return True
    return False


def _build_item(
    *,
    index: int,
    source: dict[str, Any],
    package_id: str,
    base_branch: str,
    approval_accepted: bool,
    human_allow_export_write: bool,
) -> PatchPrExportItem:
    cand = str(source.get("candidate_id") or f"CAND-{index:03d}")
    family = _slug(str(source.get("family") or "generic")) or "generic"
    item_id = str(source.get("item_id") or f"PPR-{index:03d}")
    slug_cand = _slug(cand) or f"{index:03d}"
    branch = f"mythos/advisory-fix/{family}/{slug_cand}"
    title = _pr_title(source, package_id=package_id, cand=cand)

    files = _plan_files(source, item_id=item_id, branch=branch, title=title, base_branch=base_branch)
    accepted = bool(source.get("patch_review_accepted")) or approval_accepted
    advisory = "advisory" in str(source.get("status") or "") or bool(
        source.get("suggested_changes") or source.get("minimal_diff_sketch")
    )

    if not advisory:
        status = STATUS_PLANNED
        export_write_allowed = False
    elif not accepted and not human_allow_export_write:
        # plan is still useful; mark blocked for write readiness
        status = STATUS_BLOCKED_REVIEW
        export_write_allowed = False
    elif human_allow_export_write and accepted:
        status = STATUS_READY
        export_write_allowed = True
    elif human_allow_export_write and not accepted:
        # explicit write flag alone allows local export of advisory artifacts for human handoff
        status = STATUS_READY
        export_write_allowed = True
    elif accepted:
        status = STATUS_READY
        export_write_allowed = False
    else:
        status = STATUS_BLOCKED_REVIEW
        export_write_allowed = False

    return PatchPrExportItem(
        item_id=item_id,
        candidate_id=cand,
        family=family,
        status=status,
        branch_name=branch,
        pr_title=title,
        base_branch=base_branch,
        files=files,
        patch_review_accepted=accepted,
        export_write_allowed=export_write_allowed,
    )

def _plan_files(
    source: dict[str, Any],
    *,
    item_id: str,
    branch: str,
    title: str,
    base_branch: str,
) -> list[ExportFile]:
    sketch_lines = [str(x) for x in (source.get("minimal_diff_sketch") or []) if str(x).strip()]
    if not sketch_lines:
        for change in source.get("suggested_changes") or []:
            if isinstance(change, str) and change.strip():
                sketch_lines.append(f"# advisory: {change.strip()[:200]}")

    readme = _render_readme(source, branch=branch, title=title, base_branch=base_branch)
    pr_body = _render_pr_body(source, title=title)
    checklist = _render_checklist(source)
    sketch = "\n".join(sketch_lines) + ("\n" if sketch_lines else "")
    meta = {
        "item_id": item_id,
        "candidate_id": source.get("candidate_id"),
        "family": source.get("family"),
        "branch_name": branch,
        "pr_title": title,
        "base_branch": base_branch,
        "auto_pr_allowed": False,
        "pr_opened": False,
        "patch_ready": False,
        "mythos_export_only": True,
        "affected_code_path": source.get("affected_code_path"),
        "affected_route": source.get("affected_route"),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    meta_text = json.dumps(meta, ensure_ascii=False, indent=2) + "\n"

    planned = [
        (f"{item_id}/README.md", "human_operator_instructions", readme),
        (f"{item_id}/PR_BODY.md", "manual_pr_description", pr_body),
        (f"{item_id}/CHECKLIST.md", "human_regression_and_safety_checklist", checklist),
        (f"{item_id}/minimal_diff_sketch.txt", "advisory_diff_sketch_not_applied", sketch),
        (f"{item_id}/meta.json", "export_metadata_no_secrets", meta_text),
    ]
    files: list[ExportFile] = []
    for rel, purpose, content in planned:
        files.append(
            ExportFile(
                relative_path=rel,
                purpose=purpose,
                content=content,
                content_preview=content[:400],
                bytes_planned=len(content.encode("utf-8")),
            )
        )
    return files


def _render_readme(
    source: dict[str, Any],
    *,
    branch: str,
    title: str,
    base_branch: str,
) -> str:
    return "\n".join(
        [
            "# Mythos external patch PR export (advisory)",
            "",
            "This package is **plan-only**. Mythos does **not** open PRs, push git, or apply diffs.",
            "",
            f"- Suggested branch: `{branch}`",
            f"- Base branch: `{base_branch}`",
            f"- Suggested PR title: {title}",
            f"- Candidate: `{source.get('candidate_id') or '-'}`",
            f"- Family: `{source.get('family') or '-'}`",
            f"- Route: `{source.get('affected_route') or '-'}`",
            f"- Code path: `{source.get('affected_code_path') or '-'}`",
            "",
            "## Operator steps",
            "1. Review root-cause and sketch for correctness.",
            "2. Re-implement the fix in your authorized checkout.",
            "3. Run local tests under your own process.",
            "4. Open the PR yourself on the authorized host.",
            "",
            "## Forbidden",
            "- No auto-PR from Mythos",
            "- No secrets in commits",
            "- No exploit PoC",
            "- No bounty auto-submit",
            "",
        ]
    )


def _render_pr_body(source: dict[str, Any], *, title: str) -> str:
    changes = source.get("suggested_changes") or []
    tests = source.get("regression_tests") or []
    lines = [
        f"## {title}",
        "",
        "### Summary",
        str(source.get("root_cause_summary") or "Advisory fix derived from Mythos patch planner."),
        "",
        "### Suggested changes (advisory)",
    ]
    if changes:
        for c in changes:
            lines.append(f"- {c}")
    else:
        lines.append("- See minimal_diff_sketch.txt")
    lines.extend(["", "### Regression ideas (human-run)"])
    if tests:
        for t in tests:
            lines.append(f"- {t}")
    else:
        lines.append("- Follow CHECKLIST.md")
    lines.extend(
        [
            "",
            "### Safety",
            "- Generated by Bounty Mythos-Lite as **advisory** content only.",
            "- Not an automatic PR. Not a confirmed vulnerability by itself.",
            "",
        ]
    )
    return "\n".join(lines)


def _render_checklist(source: dict[str, Any]) -> str:
    lines = [
        "# Human checklist before opening PR",
        "",
        "- [ ] Root cause is understood (not just a single payload filter)",
        "- [ ] Fix is at the correct service/authz layer when shared",
        "- [ ] No secrets, tokens, or real user data in the patch",
        "- [ ] No exploit PoC committed",
        "- [ ] Local tests / static recheck planned and executed by human",
        "- [ ] Scope still authorized for this repository",
        "- [ ] Mythos report submission remains separately gated",
        "",
        "## Planner regression steps (non-executing)",
    ]
    for step in source.get("regression_validation_plan") or []:
        if isinstance(step, dict):
            title = step.get("title") or step.get("step_id") or "step"
            lines.append(f"- [ ] {title}: {step.get('intent') or step.get('method') or ''}")
        else:
            lines.append(f"- [ ] {step}")
    if not source.get("regression_validation_plan"):
        lines.append("- [ ] Manual local static recheck of affected path")
    lines.append("")
    return "\n".join(lines)

def _write_exports(
    root: Path,
    items: list[PatchPrExportItem],
    *,
    package_id: str,
) -> tuple[int, bool]:
    export_root = root / "_export" / "patch_pr"
    written_items = 0
    any_written = False
    for item in items:
        if not item.export_write_allowed:
            continue
        new_files: list[ExportFile] = []
        ok = True
        for planned in item.files:
            content = planned.content or planned.content_preview or ""
            if planned.relative_path.endswith("meta.json"):
                # stamp package_id into meta if possible
                try:
                    meta = json.loads(content) if content.strip() else {}
                except json.JSONDecodeError:
                    meta = {}
                if isinstance(meta, dict):
                    meta["package_id"] = package_id
                    meta["auto_pr_allowed"] = False
                    meta["pr_opened"] = False
                    meta["patch_ready"] = False
                    content = json.dumps(meta, ensure_ascii=False, indent=2) + "\n"
            target = export_root / planned.relative_path
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8", newline="\n")
                new_files.append(
                    ExportFile(
                        relative_path=planned.relative_path,
                        purpose=planned.purpose,
                        content=content,
                        content_preview=content[:400],
                        bytes_planned=len(content.encode("utf-8")),
                        written=True,
                    )
                )
                any_written = True
            except OSError:
                ok = False
                new_files.append(
                    ExportFile(
                        relative_path=planned.relative_path,
                        purpose=planned.purpose,
                        content=planned.content,
                        content_preview=planned.content_preview,
                        bytes_planned=planned.bytes_planned,
                        written=False,
                    )
                )
        item.files = new_files
        if ok and new_files:
            item.status = STATUS_EXPORTED
            written_items += 1
    return written_items, any_written


def _pr_title(source: dict[str, Any], *, package_id: str, cand: str) -> str:
    family = str(source.get("family") or source.get("vuln_type") or "security")
    route = str(source.get("affected_route") or "").strip()
    base = f"fix({family}): advisory remediation for {cand}"
    if route:
        base = f"fix({family}): harden {route}"
    if package_id:
        base = f"{base} [{package_id}]"
    return base[:180]


def _slug(value: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower())
    text = re.sub(r"-{2,}", "-", text).strip("-")
    return text[:80]


def _read_package_id(root: Path) -> str:
    meta_path = root / "package.json"
    if meta_path.is_file():
        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("package_id"), str):
                return data["package_id"].strip()[:120]
        except (OSError, json.JSONDecodeError):
            pass
    return root.name[:120]


def _force_safety_result(result: PatchPrWorkflowResult) -> PatchPrWorkflowResult:
    result.execution_mode = "plan_only_external_human_pr"
    result.auto_pr_allowed = False
    result.pr_opened = False
    result.patch_ready = False
    result.execution_allowed = False
    result.validation_allowed = False
    result.report_submission_allowed = False
    result.confirmed_vulnerability = False
    result.finding_promotion_allowed = False
    result.network_access = False
    result.live_validation = False
    result.git_operations = False
    result.safety_invariants = list(SAFETY_INVARIANTS)
    result.safety_blockers = [
        "auto_open_pull_request",
        "apply_git_diff",
        "git_push",
        "gh_pr_create",
        "write_exploit_poc",
        "submit_report",
        "auto_promote_finding",
        "set_patch_ready",
    ]
    for item in result.items:
        item.auto_pr_allowed = False
        item.pr_opened = False
        item.patch_ready = False
        item.execution_allowed = False
        item.validation_allowed = False
        item.report_submission_allowed = False
        item.confirmed_vulnerability = False
    result.item_count = len(result.items)
    result.ready_count = sum(
        1 for i in result.items if i.status in {STATUS_READY, STATUS_EXPORTED}
    )
    result.exported_count = sum(1 for i in result.items if i.status == STATUS_EXPORTED)
    result.blocked_review_count = sum(
        1 for i in result.items if i.status == STATUS_BLOCKED_REVIEW
    )
    return result


def _force_safety_dict(payload: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    out["execution_mode"] = "plan_only_external_human_pr"
    out["auto_pr_allowed"] = False
    out["pr_opened"] = False
    out["patch_ready"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    out["finding_promotion_allowed"] = False
    out["network_access"] = False
    out["live_validation"] = False
    out["git_operations"] = False
    out["safety_invariants"] = list(SAFETY_INVARIANTS)
    out["safety_blockers"] = [
        "auto_open_pull_request",
        "apply_git_diff",
        "git_push",
        "gh_pr_create",
        "write_exploit_poc",
        "submit_report",
        "auto_promote_finding",
        "set_patch_ready",
    ]
    items = out.get("items")
    if isinstance(items, list):
        cleaned = []
        for item in items:
            if not isinstance(item, dict):
                continue
            row = dict(item)
            row["auto_pr_allowed"] = False
            row["pr_opened"] = False
            row["patch_ready"] = False
            row["execution_allowed"] = False
            row["validation_allowed"] = False
            row["report_submission_allowed"] = False
            row["confirmed_vulnerability"] = False
            cleaned.append(row)
        out["items"] = cleaned
    return out



def _strip_file_content_for_bridge(payload: dict[str, Any]) -> dict[str, Any]:
    """Keep bridge JSON lean: drop full file content, retain previews."""
    out = dict(payload)
    items = out.get("items")
    if not isinstance(items, list):
        return out
    cleaned_items = []
    for item in items:
        if not isinstance(item, dict):
            continue
        row = dict(item)
        files = row.get("files")
        if isinstance(files, list):
            new_files = []
            for f in files:
                if not isinstance(f, dict):
                    continue
                fr = dict(f)
                fr.pop("content", None)
                new_files.append(fr)
            row["files"] = new_files
        cleaned_items.append(row)
    out["items"] = cleaned_items
    return out

__all__ = [
    "ExportFile",
    "HumanPrSteps",
    "PatchPrExportItem",
    "PatchPrWorkflowError",
    "PatchPrWorkflowResult",
    "SAFETY_INVARIANTS",
    "STATUS_BLOCKED_REVIEW",
    "STATUS_EMPTY",
    "STATUS_EXPORTED",
    "STATUS_PLANNED",
    "STATUS_READY",
    "STATUS_SKIPPED",
    "attach_patch_pr_workflow_to_bridge_result",
    "build_patch_pr_workflow",
]
