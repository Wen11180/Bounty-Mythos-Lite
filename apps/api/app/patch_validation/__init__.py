"""Patch Validation — advisory post-fix recheck planner (final-scheme V3).

Lawful research only:
- Aggregate patch industrial loop + crash regression + PR workflow into validation plans
- Optional offline patch_validation.json under package inputs/
- Optional export under package _export/patch_validation/ with human flag
- Never applies patches, never runs exploit PoCs, never auto-opens PRs
- Never grants live validation / submit / promote permission
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STATUS_READY = "patch_validation_plan_ready"
STATUS_EMPTY = "patch_validation_empty"
STATUS_PACKAGE_MISSING = "patch_validation_package_missing"
STATUS_WRITTEN = "patch_validation_export_written"
STATUS_WAITING_FIX = "patch_validation_waiting_for_fix_artifacts"

SAFETY_INVARIANTS = [
    "authorized_package_or_bridge_only",
    "no_public_target_scanning",
    "no_network_access",
    "no_auto_patch_apply",
    "no_auto_pr",
    "no_exploit_poc",
    "no_live_validation_execution",
    "no_automatic_report_submission",
    "no_finding_promotion",
    "human_approval_required",
    "no_export_write_without_human_flag",
]

_SECRET_HINTS = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|session|bearer|private[_-]?key|ssh-rsa|BEGIN [A-Z ]*PRIVATE)"
)
_MAX_ITEMS = 24
_MAX_STEPS = 12


class PatchValidationError(ValueError):
    """Raised when bridge attach receives invalid input."""


@dataclass(frozen=True)
class PatchValidationStep:
    step_id: str
    title: str
    intent: str
    method: str = "human_local_static_recheck"
    requires_human_approval: bool = True
    execution_allowed: bool = False
    network_access: bool = False
    live_validation: bool = False
    auto_execute: bool = False
    status: str = "planned"


@dataclass(frozen=True)
class PatchValidationItem:
    item_id: str
    candidate_id: str
    root_cause_id: str
    source: str
    status: str
    steps: list[PatchValidationStep] = field(default_factory=list)
    step_count: int = 0
    approval_required: bool = True
    execution_allowed: bool = False
    live_validation_allowed: bool = False
    patch_ready: bool = False
    auto_pr_allowed: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class PatchValidationResult:
    stage: str
    inspirations: list[str]
    execution_mode: str
    status: str
    package_id: str = ""
    package_root: str = ""
    items: list[PatchValidationItem] = field(default_factory=list)
    item_count: int = 0
    ready_item_count: int = 0
    waiting_fix_count: int = 0
    step_count: int = 0
    offline_artifact_count: int = 0
    human_allow_export_write: bool = False
    export_written: bool = False
    export_count: int = 0
    export_root_relative: str = "_export/patch_validation"
    run_stamp: str = ""
    execution_allowed: bool = False
    validation_allowed: bool = False
    live_validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    patch_ready: bool = False
    auto_pr_allowed: bool = False
    network_access: bool = False
    live_validation: bool = False
    safety_invariants: list[str] = field(default_factory=list)
    next_allowed_action: str = (
        "Human reviews non-destructive regression recheck plan; Mythos never applies patches or live-validates."
    )
    notes: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _force_safety_dict(asdict(self))


def build_patch_validation(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    bridge_result: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> PatchValidationResult:
    return run_patch_validation(
        package_root=package_root,
        package_id=package_id,
        bridge_result=bridge_result,
        human_allow_export_write=human_allow_export_write,
    )


def run_patch_validation(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    bridge_result: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> PatchValidationResult:
    """Build advisory patch-validation plan from bridge patch/crash artifacts."""
    root: Path | None = None
    root_s = ""
    if package_root is not None and str(package_root).strip():
        root = Path(package_root)
        root_s = str(root)
        if not root.is_dir():
            return _empty(
                status=STATUS_PACKAGE_MISSING,
                package_id=package_id,
                package_root=root_s,
                notes=["package_root_missing_or_not_directory"],
                human_allow_export_write=bool(human_allow_export_write),
            )

    bridge = bridge_result if isinstance(bridge_result, dict) else {}
    pid = package_id or str(bridge.get("package_id") or "")
    offline_items, offline_n = _load_offline_items(root)
    derived = _derive_items(bridge)
    items = _merge_items(offline_items + derived)

    ready_n = sum(1 for i in items if i.status == "planned_ready_for_human_recheck")
    waiting_n = sum(1 for i in items if i.status == "waiting_for_fix_artifacts")
    step_n = sum(i.step_count for i in items)

    notes = [
        "advisory_patch_validation_only",
        "never_applies_patches",
        "never_live_validates",
        "never_auto_pr",
        "non_destructive_regression_recheck_only",
    ]

    if not items:
        status = STATUS_EMPTY
    elif ready_n == 0 and waiting_n > 0:
        status = STATUS_WAITING_FIX
    else:
        status = STATUS_READY

    result = PatchValidationResult(
        stage="v3_patch_validation",
        inspirations=["MDASH", "final-scheme-V3", "final-scheme-5.11"],
        execution_mode="plan_only",
        status=status,
        package_id=pid,
        package_root=root_s,
        items=items,
        item_count=len(items),
        ready_item_count=ready_n,
        waiting_fix_count=waiting_n,
        step_count=step_n,
        offline_artifact_count=offline_n,
        human_allow_export_write=bool(human_allow_export_write),
        safety_invariants=list(SAFETY_INVARIANTS),
        notes=notes,
        summary=(
            f"items={len(items)} ready={ready_n} waiting_fix={waiting_n} "
            f"steps={step_n} offline_artifacts={offline_n}"
        ),
    )

    if human_allow_export_write and root is not None:
        written, count, stamp = _export_plan(root, result)
        if written:
            result = PatchValidationResult(
                stage=result.stage,
                inspirations=list(result.inspirations),
                execution_mode=result.execution_mode,
                status=STATUS_WRITTEN,
                package_id=result.package_id,
                package_root=result.package_root,
                items=list(result.items),
                item_count=result.item_count,
                ready_item_count=result.ready_item_count,
                waiting_fix_count=result.waiting_fix_count,
                step_count=result.step_count,
                offline_artifact_count=result.offline_artifact_count,
                human_allow_export_write=True,
                export_written=True,
                export_count=count,
                export_root_relative=result.export_root_relative,
                run_stamp=stamp,
                safety_invariants=list(result.safety_invariants),
                next_allowed_action=result.next_allowed_action,
                notes=list(result.notes) + ["export_written_under_package_tmp"],
                summary=result.summary,
            )
        else:
            result = PatchValidationResult(
                stage=result.stage,
                inspirations=list(result.inspirations),
                execution_mode=result.execution_mode,
                status=result.status,
                package_id=result.package_id,
                package_root=result.package_root,
                items=list(result.items),
                item_count=result.item_count,
                ready_item_count=result.ready_item_count,
                waiting_fix_count=result.waiting_fix_count,
                step_count=result.step_count,
                offline_artifact_count=result.offline_artifact_count,
                human_allow_export_write=True,
                safety_invariants=list(result.safety_invariants),
                next_allowed_action=result.next_allowed_action,
                notes=list(result.notes) + ["export_skipped_or_failed_still_advisory"],
                summary=result.summary,
            )
    elif human_allow_export_write and root is None:
        result = PatchValidationResult(
            stage=result.stage,
            inspirations=list(result.inspirations),
            execution_mode=result.execution_mode,
            status=result.status,
            package_id=result.package_id,
            package_root=result.package_root,
            items=list(result.items),
            item_count=result.item_count,
            ready_item_count=result.ready_item_count,
            waiting_fix_count=result.waiting_fix_count,
            step_count=result.step_count,
            offline_artifact_count=result.offline_artifact_count,
            human_allow_export_write=True,
            safety_invariants=list(result.safety_invariants),
            next_allowed_action=result.next_allowed_action,
            notes=list(result.notes) + ["export_requested_but_no_package_root"],
            summary=result.summary,
        )

    return _force_safety(result)


def attach_patch_validation_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    patch_validation: dict[str, Any] | PatchValidationResult | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    """Attach patch validation plan; never unlocks live validation/submit/PR."""
    if not isinstance(bridge_result, dict):
        raise PatchValidationError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")

    if isinstance(patch_validation, PatchValidationResult):
        payload = patch_validation.to_dict()
    elif isinstance(patch_validation, dict):
        payload = _force_safety_dict(dict(patch_validation))
    else:
        payload = run_patch_validation(
            package_root=resolved_root,
            package_id=package_id,
            bridge_result=bridge_result,
            human_allow_export_write=bool(human_allow_export_write),
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["patch_validation"] = payload
    out["patch_validation_present"] = True
    out["patch_validation_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["patch_validation_item_count"] = int(payload.get("item_count") or 0)
    out["patch_validation_ready_item_count"] = int(payload.get("ready_item_count") or 0)
    out["patch_validation_step_count"] = int(payload.get("step_count") or 0)
    out["patch_validation_export_written"] = bool(payload.get("export_written"))
    out["patch_validation_patch_ready"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out


def _load_offline_items(root: Path | None) -> tuple[list[PatchValidationItem], int]:
    if root is None:
        return [], 0
    paths: list[Path] = []
    for p in (
        root / "inputs" / "patch_validation.json",
        root / "inputs" / "patch_validation" / "plan.json",
    ):
        if p.is_file():
            paths.append(p)
    pdir = root / "inputs" / "patch_validation"
    if pdir.is_dir():
        paths.extend(sorted(pdir.glob("*.json")))

    items: list[PatchValidationItem] = []
    artifact_n = 0
    seen_paths: set[str] = set()
    for path in paths:
        key = str(path.resolve())
        if key in seen_paths:
            continue
        seen_paths.add(key)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        artifact_n += 1
        raw_items: list[Any] = []
        if isinstance(data, dict):
            raw_items = list(data.get("items") or data.get("plans") or [])
            if not raw_items and data.get("candidate_id"):
                raw_items = [data]
        elif isinstance(data, list):
            raw_items = data
        for raw in raw_items:
            item = _item_from_dict(raw, source_ref=str(path.as_posix()))
            if item is not None:
                items.append(item)
            if len(items) >= _MAX_ITEMS:
                return items[:_MAX_ITEMS], artifact_n
    return items[:_MAX_ITEMS], artifact_n


def _item_from_dict(raw: Any, *, source_ref: str) -> PatchValidationItem | None:
    if not isinstance(raw, dict):
        return None
    candidate_id = str(raw.get("candidate_id") or raw.get("item_id") or "").strip()
    if not candidate_id:
        return None
    steps_raw = raw.get("steps") or raw.get("regression_validation_plan") or []
    steps: list[PatchValidationStep] = []
    if isinstance(steps_raw, list):
        for idx, s in enumerate(steps_raw, start=1):
            if isinstance(s, dict):
                steps.append(
                    PatchValidationStep(
                        step_id=str(s.get("step_id") or f"PV-OFF-{candidate_id}-{idx:02d}")[:80],
                        title=_scrub_text(str(s.get("title") or f"step {idx}"))[:160],
                        intent=_scrub_text(str(s.get("intent") or s.get("summary") or ""))[:400],
                        method=str(s.get("method") or "human_local_static_recheck"),
                    )
                )
            if len(steps) >= _MAX_STEPS:
                break
    if not steps:
        steps = _default_steps(candidate_id, family=str(raw.get("family") or raw.get("vuln_type") or "generic"))
    return _force_item(
        PatchValidationItem(
            item_id=str(raw.get("item_id") or f"pv-offline-{candidate_id}")[:80],
            candidate_id=candidate_id[:80],
            root_cause_id=str(raw.get("root_cause_id") or "")[:80],
            source=source_ref,
            status=str(raw.get("status") or "planned_ready_for_human_recheck"),
            steps=steps,
            step_count=len(steps),
            notes=["offline_artifact"],
        )
    )


def _derive_items(bridge: dict[str, Any]) -> list[PatchValidationItem]:
    items: list[PatchValidationItem] = []

    loop = bridge.get("patch_industrial_loop") if isinstance(bridge.get("patch_industrial_loop"), dict) else {}
    for raw in loop.get("items") or []:
        if not isinstance(raw, dict):
            continue
        cid = str(raw.get("candidate_id") or raw.get("item_id") or "").strip()
        if not cid:
            continue
        steps: list[PatchValidationStep] = []
        for s in raw.get("regression_validation_plan") or []:
            if not isinstance(s, dict):
                continue
            steps.append(
                PatchValidationStep(
                    step_id=str(s.get("step_id") or f"PV-{cid}-{len(steps)+1:02d}")[:80],
                    title=_scrub_text(str(s.get("title") or "regression step"))[:160],
                    intent=_scrub_text(str(s.get("intent") or ""))[:400],
                    method=str(s.get("method") or "human_local_static_recheck"),
                )
            )
            if len(steps) >= _MAX_STEPS:
                break
        if not steps:
            steps = _default_steps(cid, family=str(raw.get("family") or "generic"))
        status = "planned_ready_for_human_recheck"
        item_status = str(raw.get("status") or "")
        if "not_applicable" in item_status or item_status.endswith("_na"):
            status = "waiting_for_fix_artifacts"
        items.append(
            _force_item(
                PatchValidationItem(
                    item_id=f"pv-loop-{cid}"[:80],
                    candidate_id=cid[:80],
                    root_cause_id=str(raw.get("root_cause_id") or "")[:80],
                    source="patch_industrial_loop",
                    status=status,
                    steps=steps,
                    step_count=len(steps),
                    notes=["from_patch_industrial_loop"],
                )
            )
        )
        if len(items) >= _MAX_ITEMS:
            return items[:_MAX_ITEMS]

    suggestions = bridge.get("patch_suggestions") or []
    if isinstance(suggestions, list):
        for raw in suggestions:
            if not isinstance(raw, dict):
                continue
            cid = str(raw.get("candidate_id") or "").strip()
            if not cid:
                continue
            if any(i.candidate_id == cid for i in items):
                continue
            steps = _default_steps(cid, family=str(raw.get("vuln_type") or raw.get("family") or "generic"))
            extra: list[PatchValidationStep] = []
            for idx, rt in enumerate(raw.get("regression_tests") or [], start=1):
                if not isinstance(rt, dict):
                    continue
                extra.append(
                    PatchValidationStep(
                        step_id=f"PV-{cid}-S{idx:02d}"[:80],
                        title=_scrub_text(str(rt.get("title") or f"suggestion regression {idx}"))[:160],
                        intent=_scrub_text(str(rt.get("intent") or ""))[:400],
                        method="planned_regression_test_text_only",
                    )
                )
            if extra:
                steps = (steps[:-1] + extra + steps[-1:])[:_MAX_STEPS]
            items.append(
                _force_item(
                    PatchValidationItem(
                        item_id=f"pv-sug-{cid}"[:80],
                        candidate_id=cid[:80],
                        root_cause_id=str(raw.get("root_cause_id") or "")[:80],
                        source="patch_suggestions",
                        status="planned_ready_for_human_recheck",
                        steps=steps,
                        step_count=len(steps),
                        notes=["from_patch_suggestions"],
                    )
                )
            )
            if len(items) >= _MAX_ITEMS:
                break

    creg = bridge.get("crash_regression") if isinstance(bridge.get("crash_regression"), dict) else {}
    for raw in creg.get("suggestions") or creg.get("items") or []:
        if not isinstance(raw, dict):
            continue
        cid = str(raw.get("cluster_id") or raw.get("candidate_id") or raw.get("suggestion_id") or "").strip()
        if not cid:
            continue
        if any(i.candidate_id == cid for i in items):
            continue
        steps = _default_steps(cid, family="crash_regression")
        for idx, st in enumerate(raw.get("steps") or raw.get("plan_steps") or [], start=1):
            if isinstance(st, dict):
                title = str(st.get("title") or st.get("step") or f"crash step {idx}")
                intent = str(st.get("intent") or st.get("detail") or "")
            else:
                title = str(st)
                intent = ""
            steps.insert(
                max(len(steps) - 1, 0),
                PatchValidationStep(
                    step_id=f"PV-CRASH-{cid}-{idx:02d}"[:80],
                    title=_scrub_text(title)[:160],
                    intent=_scrub_text(intent)[:400],
                    method="planned_crash_regression_text_only",
                ),
            )
        steps = steps[:_MAX_STEPS]
        items.append(
            _force_item(
                PatchValidationItem(
                    item_id=f"pv-crash-{cid}"[:80],
                    candidate_id=cid[:80],
                    root_cause_id=str(raw.get("root_cause_id") or "")[:80],
                    source="crash_regression",
                    status="planned_ready_for_human_recheck",
                    steps=steps,
                    step_count=len(steps),
                    notes=["from_crash_regression"],
                )
            )
        )
        if len(items) >= _MAX_ITEMS:
            break

    ppr = bridge.get("patch_pr_workflow") if isinstance(bridge.get("patch_pr_workflow"), dict) else {}
    if not items and ppr:
        items.append(
            _force_item(
                PatchValidationItem(
                    item_id="pv-pr-waiting",
                    candidate_id="patch-pr",
                    root_cause_id="",
                    source="patch_pr_workflow",
                    status="waiting_for_fix_artifacts",
                    steps=_default_steps("patch-pr", family="generic"),
                    step_count=3,
                    notes=["from_patch_pr_workflow_empty_items"],
                )
            )
        )

    return items[:_MAX_ITEMS]


def _default_steps(candidate_id: str, *, family: str) -> list[PatchValidationStep]:
    base = candidate_id or "cand"
    return [
        PatchValidationStep(
            step_id=f"PV-{base}-01",
            title="Confirm fix lands at shared control point",
            intent=(
                f"Human verifies the intended control for family={family} is applied once "
                "in a shared layer, not only a single route."
            ),
            method="human_local_static_recheck",
        ),
        PatchValidationStep(
            step_id=f"PV-{base}-02",
            title="Static sibling-entrypoint recheck",
            intent="Local static search for sibling sinks still missing the guard (no live traffic).",
            method="human_local_static_recheck",
        ),
        PatchValidationStep(
            step_id=f"PV-{base}-99",
            title="Stop before auto-PR / live validation / exploit PoC",
            intent="Do not apply diffs, open PRs, run exploits, or mark patch_ready from this system.",
            method="safety_stop",
        ),
    ]


def _merge_items(items: list[PatchValidationItem]) -> list[PatchValidationItem]:
    out: list[PatchValidationItem] = []
    seen: set[str] = set()
    for item in items:
        key = f"{item.candidate_id}|{item.source}|{item.item_id}"
        if key in seen:
            continue
        seen.add(key)
        out.append(_force_item(item))
        if len(out) >= _MAX_ITEMS:
            break
    return out


def _force_item(item: PatchValidationItem) -> PatchValidationItem:
    steps = [_force_step(s) for s in list(item.steps or [])][:_MAX_STEPS]
    status = str(item.status or "planned_ready_for_human_recheck")
    if status not in {
        "planned_ready_for_human_recheck",
        "waiting_for_fix_artifacts",
        "planned",
        "blocked_safety",
    }:
        status = "planned_ready_for_human_recheck"
    return PatchValidationItem(
        item_id=str(item.item_id)[:80],
        candidate_id=str(item.candidate_id)[:80],
        root_cause_id=str(item.root_cause_id)[:80],
        source=str(item.source)[:80],
        status=status,
        steps=steps,
        step_count=len(steps),
        approval_required=True,
        execution_allowed=False,
        live_validation_allowed=False,
        patch_ready=False,
        auto_pr_allowed=False,
        notes=[_scrub_text(n) for n in list(item.notes or [])][:12],
    )


def _force_step(step: PatchValidationStep | dict[str, Any]) -> PatchValidationStep:
    if isinstance(step, PatchValidationStep):
        return PatchValidationStep(
            step_id=str(step.step_id)[:80],
            title=_scrub_text(step.title)[:160],
            intent=_scrub_text(step.intent)[:400],
            method=str(step.method or "human_local_static_recheck"),
            requires_human_approval=True,
            execution_allowed=False,
            network_access=False,
            live_validation=False,
            auto_execute=False,
            status="planned",
        )
    return PatchValidationStep(
        step_id=str(step.get("step_id") or "PV-unknown")[:80],
        title=_scrub_text(str(step.get("title") or ""))[:160],
        intent=_scrub_text(str(step.get("intent") or ""))[:400],
        method=str(step.get("method") or "human_local_static_recheck"),
        requires_human_approval=True,
        execution_allowed=False,
        network_access=False,
        live_validation=False,
        auto_execute=False,
        status="planned",
    )


def _export_plan(root: Path, result: PatchValidationResult) -> tuple[bool, int, str]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = root / "_export" / "patch_validation" / stamp
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        payload = result.to_dict()
        (out_dir / "index.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        lines = [
            "# Patch Validation plan (advisory only)",
            "",
            f"- status: `{result.status}`",
            f"- package_id: `{result.package_id}`",
            f"- items: {result.item_count}",
            f"- ready: {result.ready_item_count}",
            f"- steps: {result.step_count}",
            f"- patch_ready: false",
            f"- live_validation_allowed: false",
            "",
            "## Items",
            "",
        ]
        for item in result.items:
            lines.append(
                f"- `{item.item_id}` cand=`{item.candidate_id}` status=`{item.status}` steps={item.step_count}"
            )
            for step in item.steps[:6]:
                lines.append(f"  - `{step.step_id}`: {step.title}")
        lines.extend(
            [
                "",
                "## Safety",
                "",
                "- Never apply patches, open PRs, run exploit PoCs, or live-validate from Mythos.",
                "- Human non-destructive recheck only.",
                "",
            ]
        )
        (out_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")
        return True, 2, stamp
    except Exception:
        return False, 0, ""


def _scrub_text(value: str) -> str:
    text = str(value or "")
    if _SECRET_HINTS.search(text):
        return "[redacted_secret_like_content]"
    return text[:500]


def _empty(
    *,
    status: str,
    package_id: str = "",
    package_root: str = "",
    notes: list[str] | None = None,
    human_allow_export_write: bool = False,
) -> PatchValidationResult:
    return _force_safety(
        PatchValidationResult(
            stage="v3_patch_validation",
            inspirations=["MDASH", "final-scheme-V3"],
            execution_mode="plan_only",
            status=status,
            package_id=package_id,
            package_root=package_root,
            human_allow_export_write=bool(human_allow_export_write),
            safety_invariants=list(SAFETY_INVARIANTS),
            notes=list(notes or []),
            summary="empty_or_missing_inputs",
        )
    )


def _force_safety(result: PatchValidationResult) -> PatchValidationResult:
    coerced: list[PatchValidationItem] = []
    for i in list(result.items or []):
        if isinstance(i, PatchValidationItem):
            coerced.append(_force_item(i))
            continue
        if not isinstance(i, dict):
            continue
        steps = [_force_step(s) for s in (i.get("steps") or [])]
        coerced.append(
            _force_item(
                PatchValidationItem(
                    item_id=str(i.get("item_id") or ""),
                    candidate_id=str(i.get("candidate_id") or ""),
                    root_cause_id=str(i.get("root_cause_id") or ""),
                    source=str(i.get("source") or "unknown"),
                    status=str(i.get("status") or "planned_ready_for_human_recheck"),
                    steps=steps,
                    step_count=len(steps),
                    notes=list(i.get("notes") or []),
                )
            )
        )
    items = [i for i in coerced if i.candidate_id]
    ready_n = sum(1 for i in items if i.status == "planned_ready_for_human_recheck")
    waiting_n = sum(1 for i in items if i.status == "waiting_for_fix_artifacts")
    step_n = sum(i.step_count for i in items)
    return PatchValidationResult(
        stage="v3_patch_validation",
        inspirations=list(result.inspirations) or ["MDASH", "final-scheme-V3"],
        execution_mode="plan_only",
        status=result.status,
        package_id=result.package_id,
        package_root=result.package_root,
        items=items,
        item_count=len(items),
        ready_item_count=ready_n,
        waiting_fix_count=waiting_n,
        step_count=step_n,
        offline_artifact_count=int(result.offline_artifact_count or 0),
        human_allow_export_write=bool(result.human_allow_export_write),
        export_written=bool(result.export_written),
        export_count=int(result.export_count or 0),
        export_root_relative="_export/patch_validation",
        run_stamp=result.run_stamp,
        execution_allowed=False,
        validation_allowed=False,
        live_validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        patch_ready=False,
        auto_pr_allowed=False,
        network_access=False,
        live_validation=False,
        safety_invariants=list(SAFETY_INVARIANTS),
        next_allowed_action=result.next_allowed_action,
        notes=list(result.notes),
        summary=result.summary,
    )


def _force_safety_dict(payload: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    out["execution_mode"] = "plan_only"
    for key in (
        "execution_allowed",
        "validation_allowed",
        "live_validation_allowed",
        "report_submission_allowed",
        "confirmed_vulnerability",
        "finding_promotion_allowed",
        "patch_ready",
        "auto_pr_allowed",
        "network_access",
        "live_validation",
    ):
        out[key] = False
    out["safety_invariants"] = list(SAFETY_INVARIANTS)
    cleaned_items = []
    for item in out.get("items") or []:
        if not isinstance(item, dict):
            continue
        ii = dict(item)
        ii["execution_allowed"] = False
        ii["live_validation_allowed"] = False
        ii["patch_ready"] = False
        ii["auto_pr_allowed"] = False
        ii["approval_required"] = True
        steps = []
        for s in ii.get("steps") or []:
            if not isinstance(s, dict):
                continue
            ss = dict(s)
            ss["execution_allowed"] = False
            ss["network_access"] = False
            ss["live_validation"] = False
            ss["auto_execute"] = False
            ss["requires_human_approval"] = True
            ss["status"] = "planned"
            ss["title"] = _scrub_text(str(ss.get("title") or ""))
            ss["intent"] = _scrub_text(str(ss.get("intent") or ""))
            steps.append(ss)
        ii["steps"] = steps
        ii["step_count"] = len(steps)
        cleaned_items.append(ii)
    out["items"] = cleaned_items
    out["item_count"] = len(cleaned_items)
    out["ready_item_count"] = sum(
        1 for i in cleaned_items if i.get("status") == "planned_ready_for_human_recheck"
    )
    out["waiting_fix_count"] = sum(
        1 for i in cleaned_items if i.get("status") == "waiting_for_fix_artifacts"
    )
    out["step_count"] = sum(int(i.get("step_count") or 0) for i in cleaned_items)
    return out


__all__ = [
    "PatchValidationError",
    "PatchValidationItem",
    "PatchValidationResult",
    "PatchValidationStep",
    "STATUS_EMPTY",
    "STATUS_PACKAGE_MISSING",
    "STATUS_READY",
    "STATUS_WAITING_FIX",
    "STATUS_WRITTEN",
    "attach_patch_validation_to_bridge_result",
    "build_patch_validation",
    "run_patch_validation",
]
