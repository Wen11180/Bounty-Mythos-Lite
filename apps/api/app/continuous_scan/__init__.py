"""Continuous Scan ? advisory cadence planner for authorized packages (final-scheme V3).

Lawful research only:
- Plan repeated static/advisory re-audits over authorized package roots
- Optional offline cadence config under package inputs/
- Optional export under package _export/continuous_scan/ with human flag
- Never auto-runs scans, never network, never public target scanning
- Never grants execution / submit / promote permission
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STATUS_READY = "continuous_scan_plan_ready"
STATUS_EMPTY = "continuous_scan_empty"
STATUS_PACKAGE_MISSING = "continuous_scan_package_missing"
STATUS_WRITTEN = "continuous_scan_export_written"
STATUS_BLOCKED_SCOPE = "continuous_scan_blocked_scope"

SAFETY_INVARIANTS = [
    "authorized_package_or_bridge_only",
    "no_public_target_scanning",
    "no_network_access",
    "no_auto_scan_execution",
    "no_automatic_report_submission",
    "no_finding_promotion",
    "manual_or_approved_ci_only",
    "scope_checked_required",
    "no_export_write_without_human_flag",
]

_SECRET_HINTS = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|session|bearer|private[_-]?key|ssh-rsa|BEGIN [A-Z ]*PRIVATE)"
)
_MAX_JOBS = 24
_MAX_WATCHES = 32


class ContinuousScanError(ValueError):
    """Raised when bridge attach receives invalid input."""


@dataclass(frozen=True)
class ScanWatchPath:
    path: str
    reason: str
    change_trigger: str = "content_or_manifest_change"


@dataclass(frozen=True)
class ScanJobPlan:
    job_id: str
    title: str
    cadence: str
    method: str
    scope_requirement: str
    triggers: list[str] = field(default_factory=list)
    inputs: list[str] = field(default_factory=list)
    outputs: list[str] = field(default_factory=list)
    requires_human_approval: bool = True
    execution_allowed: bool = False
    network_access: bool = False
    auto_execute: bool = False
    status: str = "planned"


@dataclass(frozen=True)
class ContinuousScanResult:
    stage: str
    inspirations: list[str]
    execution_mode: str
    status: str
    package_id: str = ""
    package_root: str = ""
    cadence: str = "manual_or_approved_ci_only"
    scope_requirement: str = "allowed_repos_scope_checked"
    scope_allowed: bool = True
    jobs: list[ScanJobPlan] = field(default_factory=list)
    job_count: int = 0
    watch_paths: list[ScanWatchPath] = field(default_factory=list)
    watch_path_count: int = 0
    offline_config_present: bool = False
    human_allow_export_write: bool = False
    export_written: bool = False
    export_count: int = 0
    export_root_relative: str = "_export/continuous_scan"
    run_stamp: str = ""
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    auto_scan_allowed: bool = False
    network_access: bool = False
    live_validation: bool = False
    safety_invariants: list[str] = field(default_factory=list)
    next_allowed_action: str = (
        "Human schedules approved re-audit manually or in authorized CI; Mythos never auto-scans."
    )
    notes: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _force_safety_dict(asdict(self))


def build_continuous_scan(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    bridge_result: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> ContinuousScanResult:
    return run_continuous_scan(
        package_root=package_root,
        package_id=package_id,
        bridge_result=bridge_result,
        human_allow_export_write=human_allow_export_write,
    )


def run_continuous_scan(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    bridge_result: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> ContinuousScanResult:
    """Build advisory continuous-scan plan from package + bridge context."""
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
    scope_allowed = _scope_allowed(bridge, root)
    offline_cfg, offline_present = _load_offline_config(root)
    cadence = str(offline_cfg.get("cadence") or "manual_or_approved_ci_only")
    cadence = _sanitize_cadence(cadence)

    notes = [
        "advisory_continuous_scan_plan_only",
        "never_auto_executes_scans",
        "authorized_package_or_ci_only",
        "scope_must_remain_checked",
    ]

    if not scope_allowed:
        result = ContinuousScanResult(
            stage="v3_continuous_scan",
            inspirations=["MDASH", "final-scheme-V3", "ClusterFuzzLite"],
            execution_mode="plan_only",
            status=STATUS_BLOCKED_SCOPE,
            package_id=pid,
            package_root=root_s,
            cadence=cadence,
            scope_requirement="allowed_repos_scope_checked",
            scope_allowed=False,
            offline_config_present=offline_present,
            human_allow_export_write=bool(human_allow_export_write),
            safety_invariants=list(SAFETY_INVARIANTS),
            notes=notes + ["scope_not_allowed_or_missing"],
            summary="scope_blocked job_count=0",
        )
        return _force_safety(result)

    watches = _watch_paths(root, bridge, offline_cfg)
    jobs = _job_plans(bridge, offline_cfg, cadence=cadence, package_id=pid)
    status = STATUS_READY if jobs else STATUS_EMPTY
    result = ContinuousScanResult(
        stage="v3_continuous_scan",
        inspirations=["MDASH", "final-scheme-V3", "ClusterFuzzLite"],
        execution_mode="plan_only",
        status=status,
        package_id=pid,
        package_root=root_s,
        cadence=cadence,
        scope_requirement="allowed_repos_scope_checked",
        scope_allowed=True,
        jobs=jobs,
        job_count=len(jobs),
        watch_paths=watches,
        watch_path_count=len(watches),
        offline_config_present=offline_present,
        human_allow_export_write=bool(human_allow_export_write),
        safety_invariants=list(SAFETY_INVARIANTS),
        notes=notes,
        summary=f"jobs={len(jobs)} watches={len(watches)} cadence={cadence} offline_cfg={offline_present}",
    )

    if human_allow_export_write and root is not None:
        written, count, stamp = _export_plan(root, result)
        if written:
            result = ContinuousScanResult(
                stage=result.stage,
                inspirations=list(result.inspirations),
                execution_mode=result.execution_mode,
                status=STATUS_WRITTEN,
                package_id=result.package_id,
                package_root=result.package_root,
                cadence=result.cadence,
                scope_requirement=result.scope_requirement,
                scope_allowed=result.scope_allowed,
                jobs=list(result.jobs),
                job_count=result.job_count,
                watch_paths=list(result.watch_paths),
                watch_path_count=result.watch_path_count,
                offline_config_present=result.offline_config_present,
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
            result = ContinuousScanResult(
                stage=result.stage,
                inspirations=list(result.inspirations),
                execution_mode=result.execution_mode,
                status=result.status,
                package_id=result.package_id,
                package_root=result.package_root,
                cadence=result.cadence,
                scope_requirement=result.scope_requirement,
                scope_allowed=result.scope_allowed,
                jobs=list(result.jobs),
                job_count=result.job_count,
                watch_paths=list(result.watch_paths),
                watch_path_count=result.watch_path_count,
                offline_config_present=result.offline_config_present,
                human_allow_export_write=True,
                safety_invariants=list(result.safety_invariants),
                next_allowed_action=result.next_allowed_action,
                notes=list(result.notes) + ["export_skipped_or_failed_still_advisory"],
                summary=result.summary,
            )
    elif human_allow_export_write and root is None:
        result = ContinuousScanResult(
            stage=result.stage,
            inspirations=list(result.inspirations),
            execution_mode=result.execution_mode,
            status=result.status,
            package_id=result.package_id,
            package_root=result.package_root,
            cadence=result.cadence,
            scope_requirement=result.scope_requirement,
            scope_allowed=result.scope_allowed,
            jobs=list(result.jobs),
            job_count=result.job_count,
            watch_paths=list(result.watch_paths),
            watch_path_count=result.watch_path_count,
            offline_config_present=result.offline_config_present,
            human_allow_export_write=True,
            safety_invariants=list(result.safety_invariants),
            next_allowed_action=result.next_allowed_action,
            notes=list(result.notes) + ["export_requested_but_no_package_root"],
            summary=result.summary,
        )

    return _force_safety(result)


def attach_continuous_scan_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    continuous_scan: dict[str, Any] | ContinuousScanResult | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    """Attach continuous scan plan; never unlocks execute/scan/submit."""
    if not isinstance(bridge_result, dict):
        raise ContinuousScanError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")

    if isinstance(continuous_scan, ContinuousScanResult):
        payload = continuous_scan.to_dict()
    elif isinstance(continuous_scan, dict):
        payload = _force_safety_dict(dict(continuous_scan))
    else:
        payload = run_continuous_scan(
            package_root=resolved_root,
            package_id=package_id,
            bridge_result=bridge_result,
            human_allow_export_write=bool(human_allow_export_write),
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["continuous_scan"] = payload
    out["continuous_scan_present"] = True
    out["continuous_scan_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["continuous_scan_job_count"] = int(payload.get("job_count") or 0)
    out["continuous_scan_watch_path_count"] = int(payload.get("watch_path_count") or 0)
    out["continuous_scan_export_written"] = bool(payload.get("export_written"))
    out["continuous_scan_auto_scan_allowed"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out


def _scope_allowed(bridge: dict[str, Any], root: Path | None) -> bool:
    scope = bridge.get("scope") if isinstance(bridge.get("scope"), dict) else {}
    if scope:
        if scope.get("allowed") is False:
            return False
        if scope.get("allowed") is True:
            return True
    # package present is treated as authorized lab package intake
    if root is not None and root.is_dir():
        scope_file = root / "inputs" / "scope.json"
        if scope_file.is_file():
            try:
                data = json.loads(scope_file.read_text(encoding="utf-8"))
            except Exception:
                data = {}
            if isinstance(data, dict) and data.get("allowed") is False:
                return False
        return True
    if bridge.get("package_id"):
        return True
    return False


def _load_offline_config(root: Path | None) -> tuple[dict[str, Any], bool]:
    if root is None:
        return {}, False
    candidates = [
        root / "inputs" / "continuous_scan.json",
        root / "inputs" / "scan_cadence.json",
        root / "inputs" / "continuous_scan" / "plan.json",
    ]
    for path in candidates:
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict):
            return data, True
    return {}, False


def _watch_paths(
    root: Path | None,
    bridge: dict[str, Any],
    offline_cfg: dict[str, Any],
) -> list[ScanWatchPath]:
    watches: list[ScanWatchPath] = []
    seen: set[str] = set()

    def _add(path: str, reason: str, trigger: str = "content_or_manifest_change") -> None:
        p = _scrub_text(str(path or "").strip().replace("\\", "/"))
        if not p or p in seen:
            return
        seen.add(p)
        watches.append(ScanWatchPath(path=p, reason=_scrub_text(reason), change_trigger=trigger))

    for item in offline_cfg.get("watch_paths") or []:
        if isinstance(item, str):
            _add(item, "offline_config_watch")
        elif isinstance(item, dict):
            _add(str(item.get("path") or ""), str(item.get("reason") or "offline_config_watch"),
                 str(item.get("change_trigger") or "content_or_manifest_change"))
        if len(watches) >= _MAX_WATCHES:
            return watches[:_MAX_WATCHES]

    defaults = [
        ("inputs/scope.json", "scope_policy_changes"),
        ("inputs/policy.md", "policy_changes"),
        ("inputs/api.json", "api_surface_changes"),
        ("inputs/code.ts", "primary_code_artifact"),
        ("package.json", "manifest_dependency_changes"),
        ("_extract/RESIDUAL_CHECKLIST.md", "residual_checklist_updates"),
    ]
    for path, reason in defaults:
        if root is None or (root / path).exists() or path.startswith("inputs/"):
            _add(path, reason)
        if len(watches) >= _MAX_WATCHES:
            break

    langs = bridge.get("stack_languages") or []
    if langs:
        _add("inputs/", f"stack_languages={','.join(str(x) for x in langs[:6])}", "language_surface_change")

    return watches[:_MAX_WATCHES]


def _job_plans(
    bridge: dict[str, Any],
    offline_cfg: dict[str, Any],
    *,
    cadence: str,
    package_id: str,
) -> list[ScanJobPlan]:
    jobs: list[ScanJobPlan] = []
    custom = offline_cfg.get("jobs") if isinstance(offline_cfg.get("jobs"), list) else []
    for index, raw in enumerate(custom, start=1):
        if not isinstance(raw, dict):
            continue
        job_id = str(raw.get("job_id") or f"CS-OFF-{index:02d}")
        jobs.append(
            ScanJobPlan(
                job_id=job_id[:80],
                title=_scrub_text(str(raw.get("title") or f"offline job {index}"))[:160],
                cadence=_sanitize_cadence(str(raw.get("cadence") or cadence)),
                method=str(raw.get("method") or "human_local_static_reaudit"),
                scope_requirement=str(raw.get("scope_requirement") or "allowed_repos_scope_checked"),
                triggers=[str(x) for x in (raw.get("triggers") or ["manual"]) if str(x).strip()][:8],
                inputs=[str(x) for x in (raw.get("inputs") or []) if str(x).strip()][:12],
                outputs=[str(x) for x in (raw.get("outputs") or ["advisory_candidate_diff"]) if str(x).strip()][:8],
            )
        )
        if len(jobs) >= _MAX_JOBS:
            break

    if jobs:
        return [_force_job(j) for j in jobs[:_MAX_JOBS]]

    pid = package_id or "pkg"
    base_jobs = [
        ScanJobPlan(
            job_id="CS-01-scope-policy",
            title="Re-check authorized scope and policy artifacts",
            cadence=cadence,
            method="human_local_static_reaudit",
            scope_requirement="allowed_repos_scope_checked",
            triggers=["manual", "scope_or_policy_change"],
            inputs=["inputs/scope.json", "inputs/policy.md"],
            outputs=["scope_guard_delta"],
        ),
        ScanJobPlan(
            job_id="CS-02-static-surface",
            title="Re-run intake + hunter static surface on authorized package",
            cadence=cadence,
            method="bridge_operator_trial_plan",
            scope_requirement="allowed_repos_scope_checked",
            triggers=["manual", "code_or_api_change", "approved_ci"],
            inputs=["inputs/code*", "inputs/api.json", "inputs/traffic.har.json"],
            outputs=["candidate_delta", "refutation_delta"],
        ),
        ScanJobPlan(
            job_id="CS-03-residual-gates",
            title="Refresh residual checklist dispositions without live validation",
            cadence=cadence,
            method="human_residual_gate_refresh",
            scope_requirement="allowed_repos_scope_checked",
            triggers=["manual", "residual_checklist_change"],
            inputs=["_extract/RESIDUAL_CHECKLIST.md", "inputs/residual*"],
            outputs=["residual_gate_delta"],
        ),
        ScanJobPlan(
            job_id="CS-04-advisory-static",
            title="Optional local Semgrep/CodeQL plan refresh (human flag only)",
            cadence=cadence,
            method="local_static_runner_plan",
            scope_requirement="allowed_repos_scope_checked",
            triggers=["manual", "human_local_flag"],
            inputs=["inputs/advisory/*", "local rules/db if present"],
            outputs=["advisory_finding_delta"],
        ),
        ScanJobPlan(
            job_id="CS-99-stop",
            title="Stop before auto-scan / public targets / submit",
            cadence="always",
            method="safety_stop",
            scope_requirement="allowed_repos_scope_checked",
            triggers=["always"],
            inputs=[],
            outputs=["safety_hold"],
        ),
    ]

    # include agent-memory refresh when bridge already has memory/drafts
    if bridge.get("agent_memory") or bridge.get("drafts") or bridge.get("human_residual_gates"):
        base_jobs.insert(
            4,
            ScanJobPlan(
                job_id="CS-05-memory-rank",
                title="Refresh advisory agent-memory rank hints from new residuals",
                cadence=cadence,
                method="agent_memory_refresh_plan",
                scope_requirement="allowed_repos_scope_checked",
                triggers=["manual", "after_residual_or_draft_change"],
                inputs=["inputs/agent_memory.json", "bridge residual/drafts"],
                outputs=["rank_hint_delta"],
            ),
        )

    # package-specific note in first job title if present
    if pid and base_jobs:
        j0 = base_jobs[0]
        base_jobs[0] = ScanJobPlan(
            job_id=j0.job_id,
            title=f"{j0.title} ({pid})",
            cadence=j0.cadence,
            method=j0.method,
            scope_requirement=j0.scope_requirement,
            triggers=list(j0.triggers),
            inputs=list(j0.inputs),
            outputs=list(j0.outputs),
        )

    return [_force_job(j) for j in base_jobs[:_MAX_JOBS]]


def _sanitize_cadence(value: str) -> str:
    """Force cadence away from any auto/interval language."""
    raw = str(value or "").strip().lower()
    if raw in {"manual_or_approved_ci_only", "manual", "approved_ci_only", "on_change_manual"}:
        return "manual_or_approved_ci_only"
    return "manual_or_approved_ci_only"


def _force_job(job: ScanJobPlan) -> ScanJobPlan:
    return ScanJobPlan(
        job_id=str(job.job_id),
        title=_scrub_text(str(job.title)),
        cadence=_sanitize_cadence(str(job.cadence or "manual_or_approved_ci_only")),
        method=str(job.method or "human_local_static_reaudit"),
        scope_requirement=str(job.scope_requirement or "allowed_repos_scope_checked"),
        triggers=list(job.triggers or ["manual"])[:8],
        inputs=list(job.inputs or [])[:12],
        outputs=list(job.outputs or [])[:8],
        requires_human_approval=True,
        execution_allowed=False,
        network_access=False,
        auto_execute=False,
        status="planned",
    )


def _export_plan(root: Path, result: ContinuousScanResult) -> tuple[bool, int, str]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = root / "_export" / "continuous_scan" / stamp
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        payload = result.to_dict()
        (out_dir / "index.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        lines = [
            "# Continuous Scan plan (advisory only)",
            "",
            f"- status: `{result.status}`",
            f"- package_id: `{result.package_id}`",
            f"- cadence: `{result.cadence}`",
            f"- jobs: {result.job_count}",
            f"- watches: {result.watch_path_count}",
            f"- auto_scan_allowed: false",
            f"- execution_allowed: false",
            "",
            "## Jobs",
            "",
        ]
        for job in result.jobs:
            lines.append(f"- `{job.job_id}`: {job.title} ({job.cadence} / {job.method})")
        lines.extend(["", "## Safety", "", "- Never auto-scan public targets.", "- Human or approved CI only.", ""])
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
) -> ContinuousScanResult:
    return _force_safety(
        ContinuousScanResult(
            stage="v3_continuous_scan",
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


def _force_safety(result: ContinuousScanResult) -> ContinuousScanResult:
    jobs = [
        _force_job(j) if isinstance(j, ScanJobPlan) else _force_job(
            ScanJobPlan(
                job_id=str(getattr(j, "job_id", "") or (j.get("job_id") if isinstance(j, dict) else "")),
                title=str(getattr(j, "title", "") or (j.get("title") if isinstance(j, dict) else "")),
                cadence=str(getattr(j, "cadence", "") or (j.get("cadence") if isinstance(j, dict) else "") or "manual_or_approved_ci_only"),
                method=str(getattr(j, "method", "") or (j.get("method") if isinstance(j, dict) else "") or "human_local_static_reaudit"),
                scope_requirement=str(
                    getattr(j, "scope_requirement", "")
                    or (j.get("scope_requirement") if isinstance(j, dict) else "")
                    or "allowed_repos_scope_checked"
                ),
                triggers=list(getattr(j, "triggers", None) or (j.get("triggers") if isinstance(j, dict) else []) or []),
                inputs=list(getattr(j, "inputs", None) or (j.get("inputs") if isinstance(j, dict) else []) or []),
                outputs=list(getattr(j, "outputs", None) or (j.get("outputs") if isinstance(j, dict) else []) or []),
            )
        )
        for j in list(result.jobs or [])
    ]
    watches: list[ScanWatchPath] = []
    for w in list(result.watch_paths or []):
        if isinstance(w, ScanWatchPath):
            watches.append(
                ScanWatchPath(
                    path=_scrub_text(w.path),
                    reason=_scrub_text(w.reason),
                    change_trigger=str(w.change_trigger or "content_or_manifest_change"),
                )
            )
        elif isinstance(w, dict):
            path = str(w.get("path") or "").strip()
            if path:
                watches.append(
                    ScanWatchPath(
                        path=_scrub_text(path),
                        reason=_scrub_text(str(w.get("reason") or "")),
                        change_trigger=str(w.get("change_trigger") or "content_or_manifest_change"),
                    )
                )
    return ContinuousScanResult(
        stage="v3_continuous_scan",
        inspirations=list(result.inspirations) or ["MDASH", "final-scheme-V3"],
        execution_mode="plan_only",
        status=result.status,
        package_id=result.package_id,
        package_root=result.package_root,
        cadence=_sanitize_cadence(str(result.cadence or "manual_or_approved_ci_only")),
        scope_requirement="allowed_repos_scope_checked",
        scope_allowed=bool(result.scope_allowed),
        jobs=jobs,
        job_count=len(jobs),
        watch_paths=watches,
        watch_path_count=len(watches),
        offline_config_present=bool(result.offline_config_present),
        human_allow_export_write=bool(result.human_allow_export_write),
        export_written=bool(result.export_written),
        export_count=int(result.export_count or 0),
        export_root_relative="_export/continuous_scan",
        run_stamp=result.run_stamp,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        auto_scan_allowed=False,
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
        "report_submission_allowed",
        "confirmed_vulnerability",
        "finding_promotion_allowed",
        "auto_scan_allowed",
        "network_access",
        "live_validation",
    ):
        out[key] = False
    out["safety_invariants"] = list(SAFETY_INVARIANTS)
    out["scope_requirement"] = "allowed_repos_scope_checked"
    cleaned_jobs = []
    for j in out.get("jobs") or []:
        if not isinstance(j, dict):
            continue
        jj = dict(j)
        jj["execution_allowed"] = False
        jj["network_access"] = False
        jj["auto_execute"] = False
        jj["requires_human_approval"] = True
        jj["status"] = "planned"
        jj["title"] = _scrub_text(str(jj.get("title") or ""))
        cleaned_jobs.append(jj)
    out["jobs"] = cleaned_jobs
    out["job_count"] = len(cleaned_jobs)
    cleaned_watches = []
    for w in out.get("watch_paths") or []:
        if not isinstance(w, dict):
            continue
        ww = dict(w)
        ww["path"] = _scrub_text(str(ww.get("path") or ""))
        ww["reason"] = _scrub_text(str(ww.get("reason") or ""))
        if ww["path"]:
            cleaned_watches.append(ww)
    out["watch_paths"] = cleaned_watches
    out["watch_path_count"] = len(cleaned_watches)
    return out


__all__ = [
    "ContinuousScanError",
    "ContinuousScanResult",
    "STATUS_BLOCKED_SCOPE",
    "STATUS_EMPTY",
    "STATUS_PACKAGE_MISSING",
    "STATUS_READY",
    "STATUS_WRITTEN",
    "ScanJobPlan",
    "ScanWatchPath",
    "attach_continuous_scan_to_bridge_result",
    "build_continuous_scan",
    "run_continuous_scan",
]
