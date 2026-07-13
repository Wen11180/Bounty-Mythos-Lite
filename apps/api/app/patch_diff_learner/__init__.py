"""Patch Diff Learner ? plan/export only under human gate.

Final-scheme V4 residual beyond nested deep_research._patch_diff_learner:
- Learn advisory root-cause / fix-strategy / regression patterns from offline
  patch_diff inputs or bridge patch industrial loop / suggestions metadata
- Optional offline package inputs/patch_diff*.json hints
- Optional write under package _export/patch_diff_learner/ with human flag
- Never applies patches, never opens PRs, never live-validates, never submits
- Never unlocks execution_allowed / validation_allowed / report_submission_allowed
- Never sets patch_ready / auto_pr / pr_opened / confirmed_vulnerability
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


STATUS_READY = "patch_diff_learner_plan_ready"
STATUS_EMPTY = "patch_diff_learner_empty"
STATUS_SKIPPED = "patch_diff_learner_package_missing"
STATUS_WAITING = "patch_diff_learner_waiting_for_patch_diff"
STATUS_WRITTEN = "patch_diff_learner_export_written"

SAFETY_INVARIANTS = [
    "local_or_authorized_package_only",
    "no_public_target_scanning",
    "no_patch_apply",
    "no_auto_pr",
    "no_git_push",
    "no_network_access",
    "no_live_validation",
    "no_report_submission",
    "no_export_write_without_human_flag",
    "patch_diff_plan_export_local_package_only",
    "human_approval_required_before_any_action",
    "execution_always_blocked_in_planner",
    "patterns_only_no_raw_secret_or_user_data",
    "never_sets_patch_ready",
]

_MAX_PATTERNS = 24
_MAX_DIFFS = 16
_MAX_QUESTIONS = 10
_MAX_CHANGED_FILES = 20

_PATCH_DIFF_HINT_RE = re.compile(r"^patch_diff.*\.json$", re.IGNORECASE)


class PatchDiffLearnerError(ValueError):
    """Raised when bridge attach receives invalid input."""


@dataclass(frozen=True)
class LearnedPatchPattern:
    source_ref: str
    changed_files: list[str] = field(default_factory=list)
    root_cause_summary: str = ""
    fix_strategy: str = ""
    regression_test_suggestion: str = ""
    applicability_boundary: str = "reviewed_patch_diff_patterns_only"
    linked_hypothesis_id: str = ""
    family: str = ""
    status: str = "advisory_pattern"
    export_relative_path: str = ""
    written: bool = False
    execution_allowed: bool = False
    human_review_required: bool = True
    human_questions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["execution_allowed"] = False
        payload["human_review_required"] = True
        return payload


@dataclass(frozen=True)
class PatchDiffLearnerPlan:
    stage: str
    inspirations: list[str]
    execution_mode: str
    status: str
    package_id: str = ""
    package_root: str = ""
    patterns: list[LearnedPatchPattern] = field(default_factory=list)
    pattern_count: int = 0
    offline_diff_count: int = 0
    bridge_diff_count: int = 0
    required_inputs: list[str] = field(default_factory=list)
    network_access: bool = False
    live_validation: bool = False
    process_spawn_allowed: bool = False
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    auto_pr_allowed: bool = False
    patch_ready: bool = False
    pr_opened: bool = False
    human_approval_required_before_action: bool = True
    human_allow_export_write: bool = False
    export_written: bool = False
    export_count: int = 0
    export_root_relative: str = "_export/patch_diff_learner"
    safety_invariants: list[str] = field(default_factory=list)
    next_allowed_action: str = (
        "Review learned patch-diff patterns offline; never apply patches, open PRs, "
        "or mark patch_ready without explicit human work outside Mythos."
    )
    notes: list[str] = field(default_factory=list)
    human_questions: list[str] = field(default_factory=list)
    retained_signal_policy: str = "patterns_only_no_raw_secret_or_user_data"

    def to_dict(self) -> dict[str, Any]:
        return _force_safety_dict(asdict(self))


def build_patch_diff_learner_plan(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    patch_diff: dict[str, Any] | list[dict[str, Any]] | None = None,
    patch_industrial_loop: dict[str, Any] | None = None,
    patch_suggestions: list[dict[str, Any]] | None = None,
    human_allow_export_write: bool = False,
) -> PatchDiffLearnerPlan:
    notes: list[str] = [
        "plan_only",
        "no_patch_apply",
        "no_auto_pr",
        "advisory_patterns_only",
    ]
    root: Path | None = None
    if package_root is not None and str(package_root).strip():
        candidate = Path(package_root).resolve()
        if candidate.is_dir():
            root = candidate
        else:
            notes.append("package_root_not_a_directory")

    if root is None and not patch_diff and not patch_industrial_loop and not patch_suggestions:
        return _empty_plan(
            status=STATUS_SKIPPED if package_root else STATUS_EMPTY,
            package_id=package_id,
            package_root=str(package_root or ""),
            notes=notes + ["no_package_root_and_no_patch_diff_payload"],
            human_allow_export_write=bool(human_allow_export_write),
            required_inputs=[
                "patch_diff",
                "linked_finding_or_regression_test",
                "human_labeled_root_cause",
            ],
        )

    pkg_id = package_id or (root.name if root is not None else "")
    offline_diffs = _load_offline_patch_diffs(root) if root is not None else []
    bridge_diffs = _collect_bridge_diffs(
        patch_diff=patch_diff,
        patch_industrial_loop=patch_industrial_loop,
        patch_suggestions=patch_suggestions,
    )
    if offline_diffs:
        notes.append(f"offline_patch_diffs={len(offline_diffs)}")
    if bridge_diffs:
        notes.append(f"bridge_patch_diffs={len(bridge_diffs)}")

    merged = _merge_diff_sources(offline_diffs=offline_diffs, bridge_diffs=bridge_diffs)
    if not merged:
        return _empty_plan(
            status=STATUS_WAITING,
            package_id=pkg_id,
            package_root=str(root) if root is not None else str(package_root or ""),
            notes=notes + ["waiting_for_patch_diff_or_industrial_loop_items"],
            human_allow_export_write=bool(human_allow_export_write),
            offline_diff_count=len(offline_diffs),
            bridge_diff_count=len(bridge_diffs),
            required_inputs=[
                "inputs/patch_diff*.json",
                "bridge.patch_diff",
                "patch_industrial_loop.items",
                "patch_suggestions",
            ],
        )

    patterns = _build_patterns(merged)
    human_questions = _global_human_questions(patterns)

    plan = PatchDiffLearnerPlan(
        stage="v4_patch_diff_learner",
        inspirations=[
            "Patch Diff Learner",
            "Google Project Zero variant analysis",
            "security patch root-cause mining",
            "deep_research_nested_stub_superseded",
        ],
        execution_mode="plan_only",
        status=STATUS_READY,
        package_id=pkg_id,
        package_root=str(root) if root is not None else str(package_root or ""),
        patterns=patterns,
        pattern_count=len(patterns),
        offline_diff_count=len(offline_diffs),
        bridge_diff_count=len(bridge_diffs),
        required_inputs=[],
        network_access=False,
        live_validation=False,
        process_spawn_allowed=False,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        auto_pr_allowed=False,
        patch_ready=False,
        pr_opened=False,
        human_approval_required_before_action=True,
        human_allow_export_write=bool(human_allow_export_write),
        export_written=False,
        export_count=0,
        export_root_relative="_export/patch_diff_learner",
        safety_invariants=list(SAFETY_INVARIANTS),
        next_allowed_action=(
            "Review learned patch-diff patterns; optional human "
            "--allow-patch-diff-learner-export writes pattern files only "
            "(never applies patches or opens PRs)."
        ),
        notes=notes + [
            f"patterns={len(patterns)}",
            "export_write_not_requested"
            if not human_allow_export_write
            else "export_write_requested",
        ],
        human_questions=human_questions,
        retained_signal_policy="patterns_only_no_raw_secret_or_user_data",
    )
    plan = _force_safety_plan(plan)
    return _maybe_write_exports(
        plan,
        root=root,
        human_allow_export_write=bool(human_allow_export_write),
    )


def load_package_patch_diff_learner_plan(
    package_root: str | Path,
    *,
    package_id: str = "",
    patch_diff: dict[str, Any] | list[dict[str, Any]] | None = None,
    patch_industrial_loop: dict[str, Any] | None = None,
    patch_suggestions: list[dict[str, Any]] | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    return build_patch_diff_learner_plan(
        package_root=package_root,
        package_id=package_id,
        patch_diff=patch_diff,
        patch_industrial_loop=patch_industrial_loop,
        patch_suggestions=patch_suggestions,
        human_allow_export_write=human_allow_export_write,
    ).to_dict()


def attach_patch_diff_learner_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    patch_diff: dict[str, Any] | list[dict[str, Any]] | None = None,
    patch_industrial_loop: dict[str, Any] | None = None,
    patch_suggestions: list[dict[str, Any]] | None = None,
    patch_diff_learner: dict[str, Any] | PatchDiffLearnerPlan | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    """Attach plan-only patch-diff learner profile; never unlocks apply/PR/submit."""
    if not isinstance(bridge_result, dict):
        raise PatchDiffLearnerError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")

    resolved_diff = patch_diff
    if resolved_diff is None and isinstance(bridge_result.get("patch_diff"), (dict, list)):
        resolved_diff = bridge_result.get("patch_diff")

    resolved_loop = patch_industrial_loop
    if resolved_loop is None and isinstance(bridge_result.get("patch_industrial_loop"), dict):
        resolved_loop = bridge_result.get("patch_industrial_loop")

    resolved_suggestions = patch_suggestions
    if resolved_suggestions is None:
        raw_sugs = bridge_result.get("patch_suggestions")
        if isinstance(raw_sugs, list):
            resolved_suggestions = [s for s in raw_sugs if isinstance(s, dict)]
        elif isinstance(bridge_result.get("patch_suggestion"), dict):
            resolved_suggestions = [bridge_result["patch_suggestion"]]

    if isinstance(patch_diff_learner, PatchDiffLearnerPlan):
        payload = patch_diff_learner.to_dict()
    elif isinstance(patch_diff_learner, dict):
        payload = _force_safety_dict(dict(patch_diff_learner))
    else:
        payload = build_patch_diff_learner_plan(
            package_root=resolved_root,
            package_id=package_id,
            patch_diff=resolved_diff if isinstance(resolved_diff, (dict, list)) else None,
            patch_industrial_loop=resolved_loop if isinstance(resolved_loop, dict) else None,
            patch_suggestions=resolved_suggestions,
            human_allow_export_write=bool(human_allow_export_write),
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["patch_diff_learner"] = payload
    out["patch_diff_learner_present"] = True
    out["patch_diff_learner_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["patch_diff_learner_pattern_count"] = int(payload.get("pattern_count") or 0)
    out["patch_diff_learner_offline_diff_count"] = int(payload.get("offline_diff_count") or 0)
    out["patch_diff_learner_bridge_diff_count"] = int(payload.get("bridge_diff_count") or 0)
    out["patch_diff_learner_export_written"] = bool(payload.get("export_written"))
    out["patch_diff_learner_export_count"] = int(payload.get("export_count") or 0)
    out["patch_diff_learner_execution_allowed"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    out["patch_ready"] = False
    out["auto_pr_allowed"] = False
    out["pr_opened"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out


def _load_offline_patch_diffs(root: Path) -> list[dict[str, Any]]:
    diffs: list[dict[str, Any]] = []
    inputs = root / "inputs"
    if not inputs.is_dir():
        return diffs
    for path in sorted(inputs.iterdir()):
        if not path.is_file():
            continue
        if not _PATCH_DIFF_HINT_RE.match(path.name):
            continue
        if path.stat().st_size > 256_000:
            continue
        try:
            raw = path.read_text(encoding="utf-8-sig")
            data = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            diffs.append({**data, "_diff_file": path.name})
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    diffs.append({**item, "_diff_file": path.name})
        if len(diffs) >= _MAX_DIFFS:
            break
    return diffs[:_MAX_DIFFS]


def _collect_bridge_diffs(
    *,
    patch_diff: dict[str, Any] | list[dict[str, Any]] | None,
    patch_industrial_loop: dict[str, Any] | None,
    patch_suggestions: list[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if isinstance(patch_diff, dict) and patch_diff:
        out.append({**patch_diff, "_source": "bridge.patch_diff"})
    elif isinstance(patch_diff, list):
        for item in patch_diff:
            if isinstance(item, dict) and item:
                out.append({**item, "_source": "bridge.patch_diff_list"})

    if isinstance(patch_industrial_loop, dict):
        items = patch_industrial_loop.get("items") or []
        if isinstance(items, list):
            for item in items:
                if not isinstance(item, dict):
                    continue
                out.append(
                    {
                        "source_ref": str(
                            item.get("item_id")
                            or item.get("candidate_id")
                            or item.get("root_cause_id")
                            or "patch_industrial_loop"
                        ),
                        "linked_hypothesis_id": str(
                            item.get("candidate_id")
                            or item.get("root_cause_id")
                            or ""
                        ),
                        "changed_files": list(item.get("changed_files") or [])
                        if isinstance(item.get("changed_files"), list)
                        else [],
                        "root_cause": str(
                            item.get("root_cause_summary")
                            or item.get("title")
                            or item.get("family")
                            or "patch_loop_item"
                        ),
                        "fix_strategy": str(
                            item.get("fix_strategy")
                            or item.get("suggested_fix")
                            or "shared_control_point"
                        ),
                        "regression_test": str(
                            item.get("regression_test")
                            or item.get("regression_plan")
                            or "human_local_static_recheck"
                        ),
                        "family": str(item.get("family") or ""),
                        "_source": "bridge.patch_industrial_loop",
                    }
                )

    if isinstance(patch_suggestions, list):
        for item in patch_suggestions:
            if not isinstance(item, dict):
                continue
            out.append(
                {
                    "source_ref": str(
                        item.get("suggestion_id")
                        or item.get("candidate_id")
                        or item.get("root_cause_id")
                        or "patch_suggestion"
                    ),
                    "linked_hypothesis_id": str(
                        item.get("candidate_id") or item.get("root_cause_id") or ""
                    ),
                    "changed_files": list(item.get("changed_files") or [])
                    if isinstance(item.get("changed_files"), list)
                    else [],
                    "root_cause": str(
                        item.get("root_cause_summary")
                        or item.get("summary")
                        or item.get("title")
                        or "patch_suggestion"
                    ),
                    "fix_strategy": str(
                        item.get("fix_strategy")
                        or item.get("suggested_fix")
                        or item.get("fix_principle")
                        or "advisory_fix_review"
                    ),
                    "regression_test": str(
                        item.get("regression_test")
                        or item.get("regression_suggestion")
                        or "human_local_static_recheck"
                    ),
                    "family": str(item.get("family") or item.get("vuln_class") or ""),
                    "_source": "bridge.patch_suggestions",
                }
            )
    return out[:_MAX_DIFFS]


def _merge_diff_sources(
    *,
    offline_diffs: list[dict[str, Any]],
    bridge_diffs: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in list(offline_diffs) + list(bridge_diffs):
        if not isinstance(item, dict):
            continue
        key = _diff_key(item)
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
        if len(merged) >= _MAX_DIFFS:
            break
    return merged


def _diff_key(item: dict[str, Any]) -> str:
    ref = str(
        item.get("source_ref")
        or item.get("linked_hypothesis_id")
        or item.get("_diff_file")
        or item.get("root_cause")
        or item.get("root_cause_summary")
        or ""
    ).strip().lower()
    files = item.get("changed_files") or []
    file_part = ",".join(
        str(f).strip().lower() for f in files if isinstance(f, str)
    )[:120]
    return f"{ref}|{file_part}" or "anonymous_diff"


def _build_patterns(diffs: list[dict[str, Any]]) -> list[LearnedPatchPattern]:
    patterns: list[LearnedPatchPattern] = []
    for index, item in enumerate(diffs, start=1):
        if len(patterns) >= _MAX_PATTERNS:
            break
        source_ref = _safe_text(
            item.get("source_ref")
            or item.get("linked_hypothesis_id")
            or item.get("_diff_file")
            or f"patch_diff_{index}",
            f"patch_diff_{index}",
        )
        changed_files = [
            _safe_text(path, "unknown")
            for path in (item.get("changed_files") or [])
            if isinstance(path, str)
        ][:_MAX_CHANGED_FILES]
        root_cause = _safe_advisory_text(
            item.get("root_cause") or item.get("root_cause_summary"),
            "human_labeled_root_cause_required",
        )
        fix_strategy = _safe_advisory_text(
            item.get("fix_strategy") or item.get("suggested_fix"),
            "fix_strategy_required",
        )
        regression = _safe_advisory_text(
            item.get("regression_test")
            or item.get("regression_test_suggestion")
            or item.get("regression_plan"),
            "regression_test_required",
        )
        family = _safe_text(item.get("family") or item.get("vuln_class") or "", "")
        linked = _safe_text(
            item.get("linked_hypothesis_id") or item.get("candidate_id") or "",
            "",
        )
        questions = [
            f"Confirm root cause for {source_ref} is accurate and complete.",
            f"Confirm fix strategy for {source_ref} does not introduce new privilege paths.",
            "Confirm regression plan is non-destructive and local-only.",
        ]
        if family:
            questions.append(f"Check sibling variants for family={family} offline.")
        patterns.append(
            LearnedPatchPattern(
                source_ref=source_ref,
                changed_files=changed_files,
                root_cause_summary=root_cause,
                fix_strategy=fix_strategy,
                regression_test_suggestion=regression,
                applicability_boundary="reviewed_patch_diff_patterns_only",
                linked_hypothesis_id=linked,
                family=family,
                status="advisory_pattern",
                execution_allowed=False,
                human_review_required=True,
                human_questions=questions[:_MAX_QUESTIONS],
            )
        )
    return patterns


def _global_human_questions(patterns: list[LearnedPatchPattern]) -> list[str]:
    questions: list[str] = [
        "Are learned patterns free of secrets and real user data?",
        "Should any pattern be discarded as too package-specific?",
        "Do not treat patterns as confirmed vulnerabilities or patch_ready.",
    ]
    for pattern in patterns[:4]:
        questions.extend(pattern.human_questions[:2])
    seen: set[str] = set()
    out: list[str] = []
    for q in questions:
        if q in seen:
            continue
        seen.add(q)
        out.append(q)
        if len(out) >= _MAX_QUESTIONS:
            break
    return out


def _maybe_write_exports(
    plan: PatchDiffLearnerPlan,
    *,
    root: Path | None,
    human_allow_export_write: bool,
) -> PatchDiffLearnerPlan:
    if not human_allow_export_write:
        return plan
    if root is None or not root.is_dir():
        return _rebuild_plan(
            plan,
            notes=list(plan.notes) + ["export_skipped_no_package_root"],
        )
    if not plan.patterns:
        return _rebuild_plan(
            plan,
            notes=list(plan.notes) + ["export_skipped_no_patterns"],
        )

    export_root = root / "_export" / "patch_diff_learner"
    export_root.mkdir(parents=True, exist_ok=True)
    written_patterns: list[LearnedPatchPattern] = []
    export_count = 0

    for pattern in plan.patterns:
        slug = _slug(pattern.source_ref)
        target_dir = export_root / slug
        target_dir.mkdir(parents=True, exist_ok=True)
        rel = f"_export/patch_diff_learner/{slug}"
        meta = {
            "source_ref": pattern.source_ref,
            "package_id": plan.package_id,
            "changed_files": list(pattern.changed_files),
            "root_cause_summary": pattern.root_cause_summary,
            "fix_strategy": pattern.fix_strategy,
            "regression_test_suggestion": pattern.regression_test_suggestion,
            "family": pattern.family,
            "linked_hypothesis_id": pattern.linked_hypothesis_id,
            "execution_allowed": False,
            "auto_pr_allowed": False,
            "patch_ready": False,
            "pr_opened": False,
            "human_review_required": True,
        }
        (target_dir / "meta.json").write_text(
            json.dumps(meta, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        (target_dir / "pattern.md").write_text(
            _render_pattern_md(pattern, package_id=plan.package_id),
            encoding="utf-8",
        )
        (target_dir / "README.md").write_text(
            _render_readme(pattern, package_id=plan.package_id, export_dir=rel),
            encoding="utf-8",
        )
        export_count += 3
        written_patterns.append(
            LearnedPatchPattern(
                source_ref=pattern.source_ref,
                changed_files=list(pattern.changed_files),
                root_cause_summary=pattern.root_cause_summary,
                fix_strategy=pattern.fix_strategy,
                regression_test_suggestion=pattern.regression_test_suggestion,
                applicability_boundary=pattern.applicability_boundary,
                linked_hypothesis_id=pattern.linked_hypothesis_id,
                family=pattern.family,
                status="exported",
                export_relative_path=rel,
                written=True,
                execution_allowed=False,
                human_review_required=True,
                human_questions=list(pattern.human_questions),
            )
        )

    index = {
        "package_id": plan.package_id,
        "status": STATUS_WRITTEN,
        "pattern_count": len(written_patterns),
        "export_count": export_count,
        "execution_allowed": False,
        "auto_pr_allowed": False,
        "patch_ready": False,
        "pr_opened": False,
        "patterns": [
            {
                "source_ref": p.source_ref,
                "export_relative_path": p.export_relative_path,
                "family": p.family,
            }
            for p in written_patterns
        ],
        "safety_invariants": list(SAFETY_INVARIANTS),
    }
    (export_root / "index.json").write_text(
        json.dumps(index, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    export_count += 1

    return _rebuild_plan(
        plan,
        patterns=written_patterns,
        status=STATUS_WRITTEN,
        export_written=True,
        export_count=export_count,
        human_allow_export_write=True,
        notes=list(plan.notes)
        + [f"export_written={export_count}", f"export_root={export_root}"],
        next_allowed_action=(
            "Human reviews exported pattern files offline; never apply/open PR from Mythos."
        ),
    )


def _render_pattern_md(pattern: LearnedPatchPattern, *, package_id: str) -> str:
    files = "\n".join(f"- `{f}`" for f in pattern.changed_files) or "- (none listed)"
    questions = "\n".join(f"- {q}" for q in pattern.human_questions) or "- (none)"
    return (
        f"# Patch-diff learned pattern (plan-only)\n\n"
        f"- package_id: `{package_id}`\n"
        f"- source_ref: `{pattern.source_ref}`\n"
        f"- family: `{pattern.family or 'n/a'}`\n"
        f"- linked_hypothesis_id: `{pattern.linked_hypothesis_id or 'n/a'}`\n"
        f"- execution_allowed: `false`\n"
        f"- patch_ready: `false`\n"
        f"- auto_pr_allowed: `false`\n\n"
        f"## Root cause summary\n\n{pattern.root_cause_summary}\n\n"
        f"## Fix strategy\n\n{pattern.fix_strategy}\n\n"
        f"## Regression test suggestion\n\n{pattern.regression_test_suggestion}\n\n"
        f"## Changed files (metadata only)\n\n{files}\n\n"
        f"## Human questions\n\n{questions}\n\n"
        f"## Safety\n\n"
        f"- Never apply this pattern automatically.\n"
        f"- Never open a PR from this file.\n"
        f"- Never treat this as a confirmed vulnerability.\n"
        f"- Patterns only; no raw secrets or user data.\n"
    )


def _render_readme(
    pattern: LearnedPatchPattern, *, package_id: str, export_dir: str
) -> str:
    return (
        f"# Patch Diff Learner export\n\n"
        f"Package `{package_id}` source `{pattern.source_ref}`.\n\n"
        f"Export dir: `{export_dir}`\n\n"
        f"This export is **plan-only**. Mythos never applies patches, never opens PRs, "
        f"never live-validates, and never sets patch_ready from this folder.\n"
    )


def _empty_plan(
    *,
    status: str,
    package_id: str = "",
    package_root: str = "",
    notes: list[str] | None = None,
    human_allow_export_write: bool = False,
    offline_diff_count: int = 0,
    bridge_diff_count: int = 0,
    required_inputs: list[str] | None = None,
) -> PatchDiffLearnerPlan:
    return _force_safety_plan(
        PatchDiffLearnerPlan(
            stage="v4_patch_diff_learner",
            inspirations=[
                "Patch Diff Learner",
                "Google Project Zero variant analysis",
                "security patch root-cause mining",
            ],
            execution_mode="plan_only",
            status=status,
            package_id=package_id,
            package_root=package_root,
            patterns=[],
            pattern_count=0,
            offline_diff_count=offline_diff_count,
            bridge_diff_count=bridge_diff_count,
            required_inputs=list(
                required_inputs
                or [
                    "patch_diff",
                    "linked_finding_or_regression_test",
                    "human_labeled_root_cause",
                ]
            ),
            human_allow_export_write=bool(human_allow_export_write),
            safety_invariants=list(SAFETY_INVARIANTS),
            notes=list(notes or []),
            next_allowed_action=(
                "Add offline inputs/patch_diff*.json or bridge patch_diff / "
                "patch_industrial_loop / patch_suggestions; execution remains blocked."
            ),
        )
    )


def _rebuild_plan(
    plan: PatchDiffLearnerPlan,
    *,
    patterns: list[LearnedPatchPattern] | None = None,
    notes: list[str] | None = None,
    status: str | None = None,
    next_allowed_action: str | None = None,
    human_allow_export_write: bool | None = None,
    export_written: bool | None = None,
    export_count: int | None = None,
    export_root_relative: str | None = None,
) -> PatchDiffLearnerPlan:
    pats = list(patterns) if patterns is not None else list(plan.patterns)
    return _force_safety_plan(
        PatchDiffLearnerPlan(
            stage=plan.stage,
            inspirations=list(plan.inspirations),
            execution_mode="plan_only",
            status=status if status is not None else plan.status,
            package_id=plan.package_id,
            package_root=plan.package_root,
            patterns=pats,
            pattern_count=len(pats),
            offline_diff_count=int(plan.offline_diff_count or 0),
            bridge_diff_count=int(plan.bridge_diff_count or 0),
            required_inputs=list(plan.required_inputs),
            human_allow_export_write=(
                bool(human_allow_export_write)
                if human_allow_export_write is not None
                else bool(plan.human_allow_export_write)
            ),
            export_written=(
                bool(export_written)
                if export_written is not None
                else bool(plan.export_written)
            ),
            export_count=(
                int(export_count)
                if export_count is not None
                else int(plan.export_count or 0)
            ),
            export_root_relative=(
                export_root_relative
                if export_root_relative is not None
                else plan.export_root_relative
            )
            or "_export/patch_diff_learner",
            safety_invariants=list(SAFETY_INVARIANTS),
            next_allowed_action=(
                next_allowed_action
                if next_allowed_action is not None
                else plan.next_allowed_action
            ),
            notes=list(notes) if notes is not None else list(plan.notes),
            human_questions=list(plan.human_questions),
            retained_signal_policy=plan.retained_signal_policy,
        )
    )


def _slug(value: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower())
    text = re.sub(r"-{2,}", "-", text).strip("-")
    return (text or "pattern")[:80]


def _safe_text(value: Any, default: str) -> str:
    text = str(value if value is not None else "").strip()
    if not text:
        return default
    lowered = text.lower()
    if any(
        token in lowered
        for token in (
            "password",
            "secret",
            "api_key",
            "apikey",
            "token=",
            "authorization:",
        )
    ):
        return default if default else "redacted_sensitive_text"
    return text[:500]


def _safe_advisory_text(value: Any, default: str) -> str:
    text = _safe_text(value, "")
    return text if text else default


def _force_safety_plan(plan: PatchDiffLearnerPlan) -> PatchDiffLearnerPlan:
    safe_patterns = [
        LearnedPatchPattern(
            source_ref=p.source_ref,
            changed_files=list(p.changed_files),
            root_cause_summary=p.root_cause_summary,
            fix_strategy=p.fix_strategy,
            regression_test_suggestion=p.regression_test_suggestion,
            applicability_boundary=p.applicability_boundary
            or "reviewed_patch_diff_patterns_only",
            linked_hypothesis_id=p.linked_hypothesis_id,
            family=p.family,
            status=p.status,
            export_relative_path=p.export_relative_path,
            written=bool(p.written),
            execution_allowed=False,
            human_review_required=True,
            human_questions=list(p.human_questions),
        )
        for p in plan.patterns
    ]
    return PatchDiffLearnerPlan(
        stage=plan.stage,
        inspirations=list(plan.inspirations),
        execution_mode="plan_only",
        status=plan.status,
        package_id=plan.package_id,
        package_root=plan.package_root,
        patterns=safe_patterns,
        pattern_count=len(safe_patterns),
        offline_diff_count=int(plan.offline_diff_count or 0),
        bridge_diff_count=int(plan.bridge_diff_count or 0),
        required_inputs=list(plan.required_inputs),
        network_access=False,
        live_validation=False,
        process_spawn_allowed=False,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        auto_pr_allowed=False,
        patch_ready=False,
        pr_opened=False,
        human_approval_required_before_action=True,
        human_allow_export_write=bool(plan.human_allow_export_write),
        export_written=bool(plan.export_written),
        export_count=int(plan.export_count or 0),
        export_root_relative=plan.export_root_relative or "_export/patch_diff_learner",
        safety_invariants=list(SAFETY_INVARIANTS),
        next_allowed_action=plan.next_allowed_action,
        notes=list(plan.notes),
        human_questions=list(plan.human_questions),
        retained_signal_policy=plan.retained_signal_policy
        or "patterns_only_no_raw_secret_or_user_data",
    )


def _force_safety_dict(payload: dict[str, Any]) -> dict[str, Any]:
    payload = dict(payload)
    payload["execution_mode"] = "plan_only"
    payload["network_access"] = False
    payload["live_validation"] = False
    payload["process_spawn_allowed"] = False
    payload["execution_allowed"] = False
    payload["validation_allowed"] = False
    payload["report_submission_allowed"] = False
    payload["confirmed_vulnerability"] = False
    payload["finding_promotion_allowed"] = False
    payload["auto_pr_allowed"] = False
    payload["patch_ready"] = False
    payload["pr_opened"] = False
    payload["human_approval_required_before_action"] = True
    payload["human_allow_export_write"] = bool(payload.get("human_allow_export_write"))
    payload["export_written"] = bool(payload.get("export_written"))
    payload["export_count"] = int(payload.get("export_count") or 0)
    payload["export_root_relative"] = str(
        payload.get("export_root_relative") or "_export/patch_diff_learner"
    )
    payload["safety_invariants"] = list(SAFETY_INVARIANTS)
    payload["retained_signal_policy"] = str(
        payload.get("retained_signal_policy")
        or "patterns_only_no_raw_secret_or_user_data"
    )
    patterns = payload.get("patterns")
    if isinstance(patterns, list):
        payload["pattern_count"] = len(patterns)
        safe_patterns: list[Any] = []
        for item in patterns:
            if isinstance(item, dict):
                pitem = dict(item)
                pitem["execution_allowed"] = False
                pitem["human_review_required"] = True
                safe_patterns.append(pitem)
            else:
                safe_patterns.append(item)
        payload["patterns"] = safe_patterns
    learned = payload.get("learned_patterns")
    if isinstance(learned, list) and not isinstance(patterns, list):
        payload["patterns"] = learned
        payload["pattern_count"] = len(learned)
    return payload


__all__ = [
    "STATUS_EMPTY",
    "STATUS_READY",
    "STATUS_SKIPPED",
    "STATUS_WAITING",
    "STATUS_WRITTEN",
    "LearnedPatchPattern",
    "PatchDiffLearnerError",
    "PatchDiffLearnerPlan",
    "attach_patch_diff_learner_to_bridge_result",
    "build_patch_diff_learner_plan",
    "load_package_patch_diff_learner_plan",
]
