"""Approved local fuzz sandbox planner — plan/export only under human gate.

Final-scheme residual gap after CRS harness export:
- Build a local-only fuzz sandbox recipe from CRS harness plans
- Optional write under package _export/fuzz_sandbox/ with human flag
- Never spawns AFL++/libFuzzer/process, never network, never promote crashes
- Never unlocks execution_allowed / validation_allowed / report_submission_allowed
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from app.crs_fuzzing import (
    STATUS_EMPTY as CRS_STATUS_EMPTY,
    STATUS_EMPTY_INPUT as CRS_STATUS_EMPTY_INPUT,
    STATUS_READY as CRS_STATUS_READY,
    STATUS_SKIPPED as CRS_STATUS_SKIPPED,
    build_crs_fuzzing_plan,
)


STATUS_READY = "local_fuzz_sandbox_plan_ready"
STATUS_EMPTY = "local_fuzz_sandbox_empty"
STATUS_SKIPPED = "local_fuzz_sandbox_package_missing"
STATUS_NO_HARNESS = "local_fuzz_sandbox_no_harness_plans"
STATUS_WRITTEN = "local_fuzz_sandbox_export_written"

SAFETY_INVARIANTS = [
    "local_or_authorized_package_only",
    "no_public_target_scanning",
    "no_fuzzer_process_spawn",
    "no_network_access",
    "no_crash_promotion",
    "no_report_submission",
    "no_sandbox_write_without_human_flag",
    "sandbox_export_local_package_only",
    "human_approval_required_before_any_run",
    "execution_always_blocked_in_planner",
]


class LocalFuzzSandboxError(ValueError):
    """Raised when bridge attach receives invalid input."""


@dataclass(frozen=True)
class SandboxTarget:
    target_symbol: str
    source_path: str
    harness_kind: str
    status: str
    export_relative_path: str = ""
    written: bool = False
    recipe_files: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class LocalFuzzSandboxPlan:
    stage: str
    inspirations: list[str]
    execution_mode: str
    status: str
    package_id: str = ""
    package_root: str = ""
    targets: list[SandboxTarget] = field(default_factory=list)
    target_count: int = 0
    harness_source_count: int = 0
    network_access: bool = False
    live_validation: bool = False
    process_spawn_allowed: bool = False
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    crash_promotion_allowed: bool = False
    human_approval_required_before_run: bool = True
    human_allow_sandbox_write: bool = False
    sandbox_export_written: bool = False
    sandbox_export_count: int = 0
    sandbox_export_root_relative: str = "_export/fuzz_sandbox"
    safety_invariants: list[str] = field(default_factory=list)
    next_allowed_action: str = (
        "Review sandbox recipes locally; never run fuzzers without explicit human approval."
    )
    notes: list[str] = field(default_factory=list)
    crs_status: str = ""
    recipe_kinds: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _force_safety_dict(asdict(self))


def build_local_fuzz_sandbox_plan(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    crs_fuzzing: dict[str, Any] | None = None,
    human_allow_sandbox_write: bool = False,
) -> LocalFuzzSandboxPlan:
    notes: list[str] = [
        "plan_only",
        "no_fuzzer_execution",
        "local_sandbox_recipe_only",
    ]
    root: Path | None = None
    if package_root is not None and str(package_root).strip():
        candidate = Path(package_root).resolve()
        if candidate.is_dir():
            root = candidate
        else:
            notes.append("package_root_not_a_directory")

    if root is None and not crs_fuzzing:
        return _empty_plan(
            status=STATUS_SKIPPED if package_root else STATUS_EMPTY,
            package_id=package_id,
            package_root=str(package_root or ""),
            notes=notes + ["no_package_root_and_no_crs_payload"],
            human_allow_sandbox_write=bool(human_allow_sandbox_write),
        )

    crs_payload = _resolve_crs_payload(
        crs_fuzzing=crs_fuzzing,
        package_root=root,
        package_id=package_id,
    )
    pkg_id = (
        package_id
        or str(crs_payload.get("package_id") or "")
        or (root.name if root is not None else "")
    )
    harness_plans = [
        h for h in list(crs_payload.get("harness_plans") or []) if isinstance(h, dict)
    ]
    crs_status = str(crs_payload.get("status") or "")

    if not harness_plans:
        empty_status = STATUS_NO_HARNESS
        if crs_status in {CRS_STATUS_SKIPPED, CRS_STATUS_EMPTY_INPUT}:
            empty_status = STATUS_SKIPPED if crs_status == CRS_STATUS_SKIPPED else STATUS_EMPTY
        elif crs_status in {CRS_STATUS_EMPTY, ""}:
            empty_status = STATUS_EMPTY if not root else STATUS_NO_HARNESS
        return _empty_plan(
            status=empty_status,
            package_id=pkg_id,
            package_root=str(root or package_root or ""),
            notes=notes + ["no_harness_plans_from_crs", f"crs_status={crs_status or 'none'}"],
            human_allow_sandbox_write=bool(human_allow_sandbox_write),
            crs_status=crs_status,
            harness_source_count=0,
        )

    targets = [
        SandboxTarget(
            target_symbol=str(h.get("target_symbol") or f"target_{index}"),
            source_path=str(h.get("source_path") or ""),
            harness_kind=str(h.get("harness_kind") or "local_unit_harness"),
            status="planned",
            recipe_files=[
                "Dockerfile.sandbox",
                "sandbox_recipe.md",
                "README.md",
                "meta.json",
                "run_notes.md",
            ],
        )
        for index, h in enumerate(harness_plans, start=1)
    ]

    plan = LocalFuzzSandboxPlan(
        stage="v1_approved_local_fuzz_sandbox",
        inspirations=["Buttercup", "OSS-Fuzz", "AFL++", "libFuzzer"],
        execution_mode="plan_only",
        status=STATUS_READY,
        package_id=pkg_id,
        package_root=str(root) if root is not None else str(package_root or ""),
        targets=targets,
        target_count=len(targets),
        harness_source_count=len(harness_plans),
        network_access=False,
        live_validation=False,
        process_spawn_allowed=False,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        crash_promotion_allowed=False,
        human_approval_required_before_run=True,
        human_allow_sandbox_write=bool(human_allow_sandbox_write),
        sandbox_export_written=False,
        sandbox_export_count=0,
        sandbox_export_root_relative="_export/fuzz_sandbox",
        safety_invariants=list(SAFETY_INVARIANTS),
        next_allowed_action=(
            "Review sandbox recipes; optional human --allow-local-fuzz-sandbox-write "
            "exports recipe files only (never runs fuzzers)."
        ),
        notes=notes + [f"crs_status={crs_status or 'ready'}", f"targets={len(targets)}"],
        crs_status=crs_status or CRS_STATUS_READY,
        recipe_kinds=["dockerfile", "markdown_recipe", "run_notes"],
    )
    plan = _force_safety_plan(plan)
    return _maybe_write_sandbox_exports(
        plan,
        root=root,
        human_allow_sandbox_write=bool(human_allow_sandbox_write),
    )


def load_package_local_fuzz_sandbox_plan(
    package_root: str | Path,
    *,
    package_id: str = "",
    crs_fuzzing: dict[str, Any] | None = None,
    human_allow_sandbox_write: bool = False,
) -> dict[str, Any]:
    return build_local_fuzz_sandbox_plan(
        package_root=package_root,
        package_id=package_id,
        crs_fuzzing=crs_fuzzing,
        human_allow_sandbox_write=human_allow_sandbox_write,
    ).to_dict()


def attach_local_fuzz_sandbox_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    crs_fuzzing: dict[str, Any] | None = None,
    local_fuzz_sandbox: dict[str, Any] | LocalFuzzSandboxPlan | None = None,
    human_allow_sandbox_write: bool = False,
) -> dict[str, Any]:
    """Attach plan-only local fuzz sandbox profile; never unlocks execute/submit."""
    if not isinstance(bridge_result, dict):
        raise LocalFuzzSandboxError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")
    crs_payload = crs_fuzzing
    if crs_payload is None and isinstance(bridge_result.get("crs_fuzzing"), dict):
        crs_payload = bridge_result.get("crs_fuzzing")

    if isinstance(local_fuzz_sandbox, LocalFuzzSandboxPlan):
        payload = local_fuzz_sandbox.to_dict()
    elif isinstance(local_fuzz_sandbox, dict):
        payload = _force_safety_dict(dict(local_fuzz_sandbox))
    else:
        payload = build_local_fuzz_sandbox_plan(
            package_root=resolved_root,
            package_id=package_id,
            crs_fuzzing=crs_payload if isinstance(crs_payload, dict) else None,
            human_allow_sandbox_write=bool(human_allow_sandbox_write),
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["local_fuzz_sandbox"] = payload
    out["local_fuzz_sandbox_present"] = True
    out["local_fuzz_sandbox_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["local_fuzz_sandbox_target_count"] = int(payload.get("target_count") or 0)
    out["local_fuzz_sandbox_export_written"] = bool(payload.get("sandbox_export_written"))
    out["local_fuzz_sandbox_export_count"] = int(payload.get("sandbox_export_count") or 0)
    out["local_fuzz_sandbox_execution_allowed"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out


def _resolve_crs_payload(
    *,
    crs_fuzzing: dict[str, Any] | None,
    package_root: Path | None,
    package_id: str,
) -> dict[str, Any]:
    if isinstance(crs_fuzzing, dict):
        return dict(crs_fuzzing)
    if package_root is not None:
        return build_crs_fuzzing_plan(
            package_root=package_root,
            package_id=package_id,
            human_allow_harness_write=False,
        ).to_dict()
    return {}


def _maybe_write_sandbox_exports(
    plan: LocalFuzzSandboxPlan,
    *,
    root: Path | None,
    human_allow_sandbox_write: bool,
) -> LocalFuzzSandboxPlan:
    notes = list(plan.notes)
    if not human_allow_sandbox_write:
        notes.append("sandbox_write_not_requested")
        return _rebuild_plan(
            plan,
            notes=notes,
            human_allow_sandbox_write=False,
        )

    if root is None:
        notes.append("sandbox_write_requested_but_package_root_missing")
        return _rebuild_plan(
            plan,
            notes=notes,
            human_allow_sandbox_write=True,
        )

    if not plan.targets:
        notes.append("sandbox_write_requested_but_no_targets")
        return _rebuild_plan(
            plan,
            notes=notes,
            human_allow_sandbox_write=True,
        )

    written_targets, export_count, any_written = _write_sandbox_export_files(
        root=root,
        targets=list(plan.targets),
        package_id=plan.package_id or root.name,
    )
    notes.append("local_sandbox_export_write_attempted")
    status = plan.status
    next_action = plan.next_allowed_action
    if any_written:
        notes.append("local_sandbox_export_written")
        status = STATUS_WRITTEN
        next_action = (
            "Review exported sandbox recipes under package _export/fuzz_sandbox/; "
            "Mythos still never spawns fuzzers or promotes crashes."
        )
    else:
        notes.append("local_sandbox_export_write_produced_no_files")

    return _rebuild_plan(
        plan,
        targets=written_targets,
        notes=notes,
        status=status,
        next_allowed_action=next_action,
        human_allow_sandbox_write=True,
        sandbox_export_written=bool(any_written),
        sandbox_export_count=int(export_count),
        sandbox_export_root_relative="_export/fuzz_sandbox",
    )


def _write_sandbox_export_files(
    *,
    root: Path,
    targets: list[SandboxTarget],
    package_id: str,
) -> tuple[list[SandboxTarget], int, bool]:
    export_root = (root / "_export" / "fuzz_sandbox").resolve()
    try:
        export_root.relative_to(root.resolve())
    except ValueError:
        return targets, 0, False

    export_root.mkdir(parents=True, exist_ok=True)
    written_targets: list[SandboxTarget] = []
    export_count = 0
    any_written = False

    for index, target in enumerate(targets, start=1):
        slug = _slug(f"{index:02d}-{target.target_symbol or 'target'}")
        target_dir = export_root / slug
        rel_dir = f"_export/fuzz_sandbox/{slug}"
        files = {
            "Dockerfile.sandbox": _render_dockerfile(target, package_id=package_id),
            "sandbox_recipe.md": _render_recipe_md(
                target, package_id=package_id, export_dir=rel_dir
            ),
            "README.md": _render_readme(target, package_id=package_id, export_dir=rel_dir),
            "meta.json": json.dumps(
                {
                    "package_id": package_id,
                    "target_symbol": target.target_symbol,
                    "source_path": target.source_path,
                    "harness_kind": target.harness_kind,
                    "status": "exported_recipe_only",
                    "execution_allowed": False,
                    "process_spawn_allowed": False,
                    "network_access": False,
                    "crash_promotion_allowed": False,
                    "export_relative_path": rel_dir,
                    "safety": [
                        "plan_only",
                        "no_fuzzer_execution",
                        "no_network",
                        "no_crash_promotion",
                        "human_approval_required_before_run",
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
            + "\n",
            "run_notes.md": _render_run_notes(target, package_id=package_id),
        }
        ok = True
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            for rel_name, content in files.items():
                out_path = target_dir / rel_name
                out_path.write_text(
                    content if content.endswith("\n") else content + "\n",
                    encoding="utf-8",
                    newline="\n",
                )
        except OSError:
            ok = False

        if ok:
            export_count += 1
            any_written = True
            written_targets.append(
                SandboxTarget(
                    target_symbol=target.target_symbol,
                    source_path=target.source_path,
                    harness_kind=target.harness_kind,
                    status="exported_recipe_only",
                    export_relative_path=rel_dir,
                    written=True,
                    recipe_files=list(files.keys()),
                )
            )
        else:
            written_targets.append(
                SandboxTarget(
                    target_symbol=target.target_symbol,
                    source_path=target.source_path,
                    harness_kind=target.harness_kind,
                    status=target.status,
                    export_relative_path="",
                    written=False,
                    recipe_files=list(target.recipe_files),
                )
            )

    return written_targets, export_count, any_written


def _render_dockerfile(target: SandboxTarget, *, package_id: str) -> str:
    return "\n".join(
        [
            f"# Local-only fuzz sandbox recipe for {target.target_symbol}",
            f"# package_id: {package_id}",
            f"# source_path: {target.source_path}",
            "# SAFETY: plan/export only — Mythos never builds or runs this image.",
            "# Human must approve and run outside the research factory.",
            "",
            "FROM debian:bookworm-slim",
            "# Intentionally minimal placeholder — do not treat as production hardening.",
            "WORKDIR /sandbox",
            "# Example local tools (human installs/runs only):",
            "# RUN apt-get update && apt-get install -y clang llvm && rm -rf /var/lib/apt/lists/*",
            "# COPY harness/ /sandbox/harness/",
            "# COPY seeds/ /sandbox/seeds/",
            "# CMD is intentionally absent — no auto-run",
            "",
        ]
    )


def _render_recipe_md(
    target: SandboxTarget,
    *,
    package_id: str,
    export_dir: str,
) -> str:
    return "\n".join(
        [
            f"# Local fuzz sandbox recipe — {target.target_symbol}",
            "",
            f"- package_id: `{package_id}`",
            f"- source_path: `{target.source_path}`",
            f"- harness_kind: `{target.harness_kind}`",
            f"- export_dir: `{export_dir}`",
            "- status: exported recipe only (not executed)",
            "",
            "## Intent",
            "",
            "Prepare a **local-only** sandbox handoff for a future human-approved fuzzer run",
            "against authorized package code. This is not a live campaign against public targets.",
            "",
            "## Suggested human steps (outside Mythos)",
            "",
            "1. Review CRS harness sketch under `_export/crs_harness/` if present.",
            "2. Confirm package remains in authorized scope.",
            "3. Build this sandbox image only on an isolated researcher machine.",
            "4. Point fuzzer at local seeds only — never production data or network sources.",
            "5. Keep crash samples offline; do not auto-promote into reports.",
            "",
            "## Hard blocks",
            "",
            "- Mythos `execution_allowed=false`",
            "- Mythos does not spawn AFL++/libFuzzer/process",
            "- `network_access=false`",
            "- crash promotion blocked until human-reviewed local evidence",
            "- report submission remains blocked",
            "",
        ]
    )


def _render_readme(
    target: SandboxTarget,
    *,
    package_id: str,
    export_dir: str,
) -> str:
    return "\n".join(
        [
            f"# Local fuzz sandbox export — {target.target_symbol}",
            "",
            f"- package_id: `{package_id}`",
            f"- source_path: `{target.source_path}`",
            f"- harness_kind: `{target.harness_kind}`",
            f"- export_dir: `{export_dir}`",
            "- status: exported recipe only (not executed)",
            "",
            "## Safety",
            "",
            "- execution_allowed=false",
            "- process_spawn_allowed=false",
            "- no network",
            "- no crash promotion / report submission",
            "- human must approve any future local sandbox run outside this planner",
            "",
            "## Contents",
            "",
            "- `Dockerfile.sandbox` — advisory container recipe only",
            "- `sandbox_recipe.md` — human runbook",
            "- `meta.json` — non-secret metadata",
            "- `run_notes.md` — safety checklist before any manual run",
            "",
            "Do not treat this export as a confirmed vulnerability or runnable exploit.",
            "",
        ]
    )


def _render_run_notes(target: SandboxTarget, *, package_id: str) -> str:
    return "\n".join(
        [
            "# Run notes (human-only)",
            "",
            f"Target: `{target.target_symbol}` ({package_id})",
            f"Source: `{target.source_path}`",
            "",
            "Before any manual local run:",
            "",
            "- [ ] Scope still authorized",
            "- [ ] Isolated machine / no production credentials",
            "- [ ] Seeds are synthetic/local only",
            "- [ ] Network disabled for fuzzer process",
            "- [ ] Crashes stay offline until human triage",
            "- [ ] Mythos will not auto-import crashes or unlock submit",
            "",
            "Mythos never executes these steps for you.",
            "",
        ]
    )


def _empty_plan(
    *,
    status: str,
    package_id: str = "",
    package_root: str = "",
    notes: list[str] | None = None,
    human_allow_sandbox_write: bool = False,
    crs_status: str = "",
    harness_source_count: int = 0,
) -> LocalFuzzSandboxPlan:
    return _force_safety_plan(
        LocalFuzzSandboxPlan(
            stage="v1_approved_local_fuzz_sandbox",
            inspirations=["Buttercup", "OSS-Fuzz", "AFL++", "libFuzzer"],
            execution_mode="plan_only",
            status=status,
            package_id=package_id,
            package_root=package_root,
            targets=[],
            target_count=0,
            harness_source_count=harness_source_count,
            human_allow_sandbox_write=bool(human_allow_sandbox_write),
            safety_invariants=list(SAFETY_INVARIANTS),
            next_allowed_action=(
                "Provide authorized package with CRS harness plans before sandbox export."
            ),
            notes=list(notes or []),
            crs_status=crs_status,
            recipe_kinds=["dockerfile", "markdown_recipe", "run_notes"],
        )
    )


def _rebuild_plan(
    plan: LocalFuzzSandboxPlan,
    *,
    targets: list[SandboxTarget] | None = None,
    notes: list[str] | None = None,
    status: str | None = None,
    next_allowed_action: str | None = None,
    human_allow_sandbox_write: bool | None = None,
    sandbox_export_written: bool | None = None,
    sandbox_export_count: int | None = None,
    sandbox_export_root_relative: str | None = None,
) -> LocalFuzzSandboxPlan:
    tlist = list(targets) if targets is not None else list(plan.targets)
    return _force_safety_plan(
        LocalFuzzSandboxPlan(
            stage=plan.stage,
            inspirations=list(plan.inspirations),
            execution_mode="plan_only",
            status=status if status is not None else plan.status,
            package_id=plan.package_id,
            package_root=plan.package_root,
            targets=tlist,
            target_count=len(tlist),
            harness_source_count=plan.harness_source_count,
            network_access=False,
            live_validation=False,
            process_spawn_allowed=False,
            execution_allowed=False,
            validation_allowed=False,
            report_submission_allowed=False,
            confirmed_vulnerability=False,
            finding_promotion_allowed=False,
            crash_promotion_allowed=False,
            human_approval_required_before_run=True,
            human_allow_sandbox_write=(
                bool(human_allow_sandbox_write)
                if human_allow_sandbox_write is not None
                else bool(plan.human_allow_sandbox_write)
            ),
            sandbox_export_written=(
                bool(sandbox_export_written)
                if sandbox_export_written is not None
                else bool(plan.sandbox_export_written)
            ),
            sandbox_export_count=(
                int(sandbox_export_count)
                if sandbox_export_count is not None
                else int(plan.sandbox_export_count or 0)
            ),
            sandbox_export_root_relative=(
                sandbox_export_root_relative
                if sandbox_export_root_relative is not None
                else (plan.sandbox_export_root_relative or "_export/fuzz_sandbox")
            ),
            safety_invariants=list(SAFETY_INVARIANTS),
            next_allowed_action=(
                next_allowed_action
                if next_allowed_action is not None
                else plan.next_allowed_action
            ),
            notes=list(notes) if notes is not None else list(plan.notes),
            crs_status=plan.crs_status,
            recipe_kinds=list(plan.recipe_kinds),
        )
    )


def _slug(value: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower())
    text = re.sub(r"-{2,}", "-", text).strip("-")
    return (text or "target")[:80]


def _force_safety_plan(plan: LocalFuzzSandboxPlan) -> LocalFuzzSandboxPlan:
    return LocalFuzzSandboxPlan(
        stage=plan.stage,
        inspirations=list(plan.inspirations),
        execution_mode="plan_only",
        status=plan.status,
        package_id=plan.package_id,
        package_root=plan.package_root,
        targets=list(plan.targets),
        target_count=len(plan.targets),
        harness_source_count=int(plan.harness_source_count or 0),
        network_access=False,
        live_validation=False,
        process_spawn_allowed=False,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        crash_promotion_allowed=False,
        human_approval_required_before_run=True,
        human_allow_sandbox_write=bool(plan.human_allow_sandbox_write),
        sandbox_export_written=bool(plan.sandbox_export_written),
        sandbox_export_count=int(plan.sandbox_export_count or 0),
        sandbox_export_root_relative=plan.sandbox_export_root_relative or "_export/fuzz_sandbox",
        safety_invariants=list(SAFETY_INVARIANTS),
        next_allowed_action=plan.next_allowed_action,
        notes=list(plan.notes),
        crs_status=plan.crs_status,
        recipe_kinds=list(plan.recipe_kinds or ["dockerfile", "markdown_recipe", "run_notes"]),
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
    payload["crash_promotion_allowed"] = False
    payload["human_approval_required_before_run"] = True
    payload["human_allow_sandbox_write"] = bool(payload.get("human_allow_sandbox_write"))
    payload["sandbox_export_written"] = bool(payload.get("sandbox_export_written"))
    payload["sandbox_export_count"] = int(payload.get("sandbox_export_count") or 0)
    payload["sandbox_export_root_relative"] = str(
        payload.get("sandbox_export_root_relative") or "_export/fuzz_sandbox"
    )
    payload["safety_invariants"] = list(SAFETY_INVARIANTS)
    targets = payload.get("targets")
    if isinstance(targets, list):
        payload["target_count"] = len(targets)
    return payload


__all__ = [
    "STATUS_EMPTY",
    "STATUS_NO_HARNESS",
    "STATUS_READY",
    "STATUS_SKIPPED",
    "STATUS_WRITTEN",
    "LocalFuzzSandboxError",
    "LocalFuzzSandboxPlan",
    "SandboxTarget",
    "attach_local_fuzz_sandbox_to_bridge_result",
    "build_local_fuzz_sandbox_plan",
    "load_package_local_fuzz_sandbox_plan",
]
