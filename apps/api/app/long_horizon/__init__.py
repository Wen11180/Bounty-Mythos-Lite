"""Long-Horizon Agent — plan-only path switching & reflection (final-scheme V4).

Lawful research only:
- Consume deep_research / residual / memory signals from authorized packages
- Emit multi-iteration path graph with failure-triggered path switches
- Optional offline plan under package inputs/
- Optional export under package _export/long_horizon/ with human flag
- Never auto-executes paths, never exploits/PoCs, never submit/promote
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STATUS_READY = "long_horizon_plan_ready"
STATUS_EMPTY = "long_horizon_empty"
STATUS_PACKAGE_MISSING = "long_horizon_package_missing"
STATUS_WRITTEN = "long_horizon_export_written"
STATUS_WAITING = "long_horizon_waiting_for_signals"

SAFETY_INVARIANTS = [
    "authorized_package_or_bridge_only",
    "no_public_target_scanning",
    "no_network_access",
    "no_raw_secrets_or_user_data",
    "no_automatic_report_submission",
    "no_finding_promotion",
    "no_auto_path_execution",
    "plan_only_reflection_and_path_switch",
    "human_review_required_before_any_path_execution",
    "no_export_write_without_human_flag",
]

_SECRET_HINTS = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|session|bearer|private[_-]?key|ssh-rsa|BEGIN [A-Z ]*PRIVATE)"
)
_MAX_PATHS = 24
_MAX_SWITCHES = 32
_MAX_ITERATIONS = 12
_MAX_REFLECTIONS = 16


class LongHorizonError(ValueError):
    """Raised when bridge attach receives invalid input."""


@dataclass(frozen=True)
class HorizonPath:
    path_id: str
    name: str
    purpose: str
    entry_conditions: list[str] = field(default_factory=list)
    exit_conditions: list[str] = field(default_factory=list)
    required_evidence: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    priority: int = 0
    execution_allowed: bool = False
    human_review_required: bool = True


@dataclass(frozen=True)
class PathSwitch:
    switch_id: str
    from_path_id: str
    to_path_id: str
    trigger: str
    reason: str
    observation: str
    requires_human_review: bool = True
    execution_allowed: bool = False


@dataclass(frozen=True)
class HorizonIteration:
    iteration_id: str
    sequence: int
    active_path_id: str
    goal: str
    reflection_prompt: str
    stop_if: list[str] = field(default_factory=list)
    next_if_fail: str = ""
    execution_allowed: bool = False


@dataclass(frozen=True)
class HorizonReflection:
    reflection_id: str
    trigger: str
    observation: str
    next_path_id: str
    source_ref: str = ""
    human_review_required: bool = True


@dataclass
class LongHorizonResult:
    stage: str
    inspirations: list[str]
    execution_mode: str
    status: str
    package_id: str = ""
    package_root: str = ""
    paths: list[HorizonPath] = field(default_factory=list)
    path_count: int = 0
    switches: list[PathSwitch] = field(default_factory=list)
    switch_count: int = 0
    iterations: list[HorizonIteration] = field(default_factory=list)
    iteration_count: int = 0
    reflections: list[HorizonReflection] = field(default_factory=list)
    reflection_count: int = 0
    active_path_id: str = ""
    failure_triggers: list[str] = field(default_factory=list)
    offline_artifact_count: int = 0
    deep_research_status: str = ""
    unresolved_refutation_count: int = 0
    human_allow_export_write: bool = False
    export_written: bool = False
    export_count: int = 0
    export_root_relative: str = "_export/long_horizon"
    run_stamp: str = ""
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    ranking_permission_granted: bool = False
    auto_path_switch_allowed: bool = False
    network_access: bool = False
    live_validation: bool = False
    safety_invariants: list[str] = field(default_factory=list)
    next_allowed_action: str = (
        "Human reviews path switches offline; Mythos never auto-executes long-horizon paths."
    )
    notes: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _force_safety_dict(asdict(self))


def build_long_horizon(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    bridge_result: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> LongHorizonResult:
    return run_long_horizon(
        package_root=package_root,
        package_id=package_id,
        bridge_result=bridge_result,
        human_allow_export_write=human_allow_export_write,
    )


def run_long_horizon(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    bridge_result: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> LongHorizonResult:
    """Build plan-only long-horizon path switches for an authorized package."""
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
    offline, offline_n = _load_offline(root)
    dres = bridge.get("deep_research") if isinstance(bridge.get("deep_research"), dict) else {}
    dres_status = str(bridge.get("deep_research_status") or dres.get("status") or "")
    unresolved = int(
        bridge.get("deep_research_unresolved_refutation_count")
        or dres.get("unresolved_refutation_count")
        or 0
    )
    chain_n = int(bridge.get("deep_research_chain_count") or dres.get("chain_count") or 0)
    variant_n = int(bridge.get("deep_research_variant_count") or dres.get("variant_count") or 0)

    paths, switches, iterations, reflections, failure_triggers = _build_from_signals(
        bridge=bridge,
        offline=offline,
        dres=dres,
        unresolved=unresolved,
        chain_n=chain_n,
        variant_n=variant_n,
    )

    notes = [
        "advisory_long_horizon_plan_only",
        "never_auto_executes_path_switches",
        "never_grants_execution_or_submit",
        "failure_triggered_path_switches_require_human_review",
        "authorized_package_or_bridge_only",
    ]
    if offline_n:
        notes.append(f"offline_artifacts={offline_n}")

    has_signal = bool(paths or switches or iterations or offline_n or chain_n or variant_n or unresolved)
    if not has_signal:
        status = STATUS_WAITING if bridge else STATUS_EMPTY
    else:
        status = STATUS_READY

    active = paths[0].path_id if paths else ""
    result = LongHorizonResult(
        stage="v4_long_horizon_agent",
        inspirations=["Mythos", "Big Sleep", "final-scheme-V4"],
        execution_mode="plan_only",
        status=status,
        package_id=pid,
        package_root=root_s,
        paths=paths,
        path_count=len(paths),
        switches=switches,
        switch_count=len(switches),
        iterations=iterations,
        iteration_count=len(iterations),
        reflections=reflections,
        reflection_count=len(reflections),
        active_path_id=active,
        failure_triggers=failure_triggers,
        offline_artifact_count=offline_n,
        deep_research_status=dres_status,
        unresolved_refutation_count=unresolved,
        human_allow_export_write=bool(human_allow_export_write),
        safety_invariants=list(SAFETY_INVARIANTS),
        notes=notes,
        summary=(
            f"paths={len(paths)} switches={len(switches)} iterations={len(iterations)} "
            f"reflections={len(reflections)} unresolved={unresolved} offline={offline_n}"
        ),
    )
    result = _force_safety(result)

    if human_allow_export_write and root is not None:
        written, count, stamp = _export_plan(root, result)
        if written:
            result.export_written = True
            result.export_count = count
            result.run_stamp = stamp
            result.status = STATUS_WRITTEN
            result.notes = list(result.notes) + ["export_written_under_package"]
            result = _force_safety(result)

    return result


def attach_long_horizon_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    long_horizon: dict[str, Any] | LongHorizonResult | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    """Attach long-horizon path-switch plan; never unlocks execute/submit/promote."""
    if not isinstance(bridge_result, dict):
        raise LongHorizonError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")

    if isinstance(long_horizon, LongHorizonResult):
        payload = long_horizon.to_dict()
    elif isinstance(long_horizon, dict):
        payload = _force_safety_dict(dict(long_horizon))
    else:
        payload = run_long_horizon(
            package_root=resolved_root,
            package_id=package_id,
            bridge_result=bridge_result,
            human_allow_export_write=bool(human_allow_export_write),
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["long_horizon"] = payload
    out["long_horizon_present"] = True
    out["long_horizon_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["long_horizon_path_count"] = int(payload.get("path_count") or 0)
    out["long_horizon_switch_count"] = int(payload.get("switch_count") or 0)
    out["long_horizon_iteration_count"] = int(payload.get("iteration_count") or 0)
    out["long_horizon_reflection_count"] = int(payload.get("reflection_count") or 0)
    out["long_horizon_export_written"] = bool(payload.get("export_written"))
    out["long_horizon_auto_path_switch_allowed"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out


def _build_from_signals(
    *,
    bridge: dict[str, Any],
    offline: dict[str, Any],
    dres: dict[str, Any],
    unresolved: int,
    chain_n: int,
    variant_n: int,
) -> tuple[
    list[HorizonPath],
    list[PathSwitch],
    list[HorizonIteration],
    list[HorizonReflection],
    list[str],
]:
    if offline.get("paths") or offline.get("switches"):
        paths = _paths_from_offline(offline)
        switches = _switches_from_offline(offline)
        iterations = _iterations_from_offline(offline, paths)
        reflections = _reflections_from_offline(offline)
        triggers = [
            _scrub_text(str(t))
            for t in (offline.get("failure_triggers") or [])
            if str(t).strip()
        ][:_MAX_SWITCHES]
        if not triggers:
            triggers = _default_failure_triggers()
        return (
            paths[:_MAX_PATHS],
            switches[:_MAX_SWITCHES],
            iterations[:_MAX_ITERATIONS],
            reflections[:_MAX_REFLECTIONS],
            triggers,
        )

    amem = bridge.get("agent_memory") if isinstance(bridge.get("agent_memory"), dict) else {}
    fp_n = int(
        amem.get("false_positive_pattern_count")
        or bridge.get("agent_memory_false_positive_pattern_count")
        or 0
    )
    crs = bridge.get("crs_fuzzing") if isinstance(bridge.get("crs_fuzzing"), dict) else {}
    parsers = crs.get("parser_candidates") if isinstance(crs.get("parser_candidates"), list) else []
    plan = dres.get("plan") if isinstance(dres.get("plan"), dict) else {}
    long_plan = plan.get("long_horizon_plan") if isinstance(plan.get("long_horizon_plan"), dict) else {}
    fallbacks = [
        _scrub_text(str(x))
        for x in (long_plan.get("fallback_paths") or [])
        if str(x).strip()
    ]
    gates = bridge.get("human_residual_gates") if isinstance(bridge.get("human_residual_gates"), list) else []
    drafts = bridge.get("drafts") if isinstance(bridge.get("drafts"), list) else []

    paths: list[HorizonPath] = [
        HorizonPath(
            path_id="P-primary-chain",
            name="primary_chain_refutation",
            purpose="Refute multi-stage vulnerability chains before any promotion.",
            entry_conditions=["deep_research_plan_ready_or_drafts_present"],
            exit_conditions=["all_refutations_resolved_or_human_closed"],
            required_evidence=["local_code_trace", "human_review_decision"],
            blockers=["missing_refutation_evidence"] if unresolved else [],
            priority=1,
        ),
        HorizonPath(
            path_id="P-variant-search",
            name="variant_analysis",
            purpose="Search sibling endpoints/code paths for same root-cause pattern.",
            entry_conditions=["primary_chain_unresolved_or_confirmed_seed"],
            exit_conditions=["variant_queue_reviewed"],
            required_evidence=["variant_search_pattern", "local_static_diff"],
            priority=2,
        ),
        HorizonPath(
            path_id="P-permission-model",
            name="permission_model_tightening",
            purpose="Tighten role/ownership model assumptions using authorized role labels only.",
            entry_conditions=["authorization_or_bola_hypothesis"],
            exit_conditions=["role_boundary_human_confirmed"],
            required_evidence=["role_model_labels", "handler_guard_map"],
            priority=3,
        ),
        HorizonPath(
            path_id="P-patch-diff-learn",
            name="patch_diff_learning",
            purpose="Learn advisory patterns from reviewed patch diffs without executing fixes.",
            entry_conditions=["patch_diff_or_patch_validation_artifacts"],
            exit_conditions=["advisory_patterns_queued_for_human"],
            required_evidence=["patch_diff", "human_labeled_root_cause"],
            priority=4,
        ),
        HorizonPath(
            path_id="P-protocol-fuzz-plan",
            name="protocol_aware_fuzz_plan",
            purpose="Plan protocol-aware local fuzz harness only; never spawn network fuzzers.",
            entry_conditions=["crs_parser_candidates_present"],
            exit_conditions=["harness_plan_reviewed"],
            required_evidence=["parser_symbol", "local_harness_plan"],
            blockers=[] if parsers else ["no_parser_candidates"],
            priority=5,
        ),
        HorizonPath(
            path_id="P-defer-evidence",
            name="defer_until_new_evidence",
            purpose="Stop active chain work until human supplies redacted local evidence.",
            entry_conditions=["insufficient_evidence_or_fp_pressure"],
            exit_conditions=["new_authorized_artifact_ingested"],
            required_evidence=["human_supplied_redacted_artifact"],
            priority=9,
        ),
    ]
    if not parsers and not fallbacks:
        paths = [p for p in paths if p.path_id != "P-protocol-fuzz-plan"]

    for i, name in enumerate(fallbacks):
        pid = f"P-fallback-{i+1}"
        if any(p.path_id == pid or p.name == name for p in paths):
            continue
        paths.append(
            HorizonPath(
                path_id=pid,
                name=name[:80],
                purpose=f"Deep-research fallback path: {name[:120]}",
                entry_conditions=["deep_research_fallback_listed"],
                exit_conditions=["human_closed_or_new_evidence"],
                required_evidence=["human_review_decision"],
                priority=6 + i,
            )
        )

    failure_triggers = _default_failure_triggers()
    if unresolved:
        failure_triggers.insert(0, "unresolved_refutation_matrix")
    if fp_n:
        failure_triggers.insert(0, "agent_memory_false_positive_pressure")
    if not drafts and not chain_n:
        failure_triggers.insert(0, "no_retain_hypothesis_signal")

    switches: list[PathSwitch] = []
    switch_specs = [
        ("S-01", "P-primary-chain", "P-variant-search", "refutation_stalled", "Primary chain remains unresolved after local static pass."),
        ("S-02", "P-primary-chain", "P-permission-model", "authz_assumption_weak", "Authorization boundary evidence is incomplete."),
        ("S-03", "P-variant-search", "P-patch-diff-learn", "variant_queue_empty", "No high-quality variants; learn from patch diffs if available."),
        ("S-04", "P-variant-search", "P-defer-evidence", "insufficient_static_siblings", "Sibling search lacks local evidence."),
        ("S-05", "P-permission-model", "P-defer-evidence", "role_labels_insufficient", "Role model cannot be confirmed from authorized labels."),
        ("S-06", "P-patch-diff-learn", "P-primary-chain", "pattern_ready_revisit_chain", "Advisory patch pattern ready; revisit primary chain offline."),
        ("S-07", "P-primary-chain", "P-protocol-fuzz-plan", "parser_surface_available", "Parser candidates exist; plan local protocol fuzz only."),
        ("S-08", "P-protocol-fuzz-plan", "P-defer-evidence", "harness_plan_blocked", "Harness remains plan-only without human local fuzz flag."),
        ("S-09", "P-primary-chain", "P-defer-evidence", "fp_memory_pressure", "Agent memory indicates false-positive pressure."),
        ("S-10", "any", "P-defer-evidence", "human_gate_fail", "Human-gate dry-run or residual gate not ready."),
    ]
    path_ids = {p.path_id for p in paths}
    for sid, src, dst, trigger, reason in switch_specs:
        if dst not in path_ids:
            continue
        if src != "any" and src not in path_ids:
            continue
        switches.append(
            PathSwitch(
                switch_id=sid,
                from_path_id=src,
                to_path_id=dst,
                trigger=trigger,
                reason=reason,
                observation=_observation_for(
                    trigger,
                    unresolved=unresolved,
                    fp_n=fp_n,
                    chain_n=chain_n,
                    variant_n=variant_n,
                ),
            )
        )

    iterations: list[HorizonIteration] = []
    preferred = [
        "P-primary-chain",
        "P-variant-search",
        "P-permission-model",
        "P-patch-diff-learn",
        "P-protocol-fuzz-plan",
        "P-defer-evidence",
    ]
    ordered = [p for p in paths if p.path_id in set(preferred)]
    if not ordered:
        ordered = paths[:4]
    for idx, path in enumerate(ordered[:_MAX_ITERATIONS], start=1):
        fail_next = "P-defer-evidence"
        if path.path_id == "P-primary-chain":
            fail_next = "P-variant-search" if "P-variant-search" in path_ids else "P-defer-evidence"
        elif path.path_id == "P-variant-search":
            fail_next = "P-patch-diff-learn" if "P-patch-diff-learn" in path_ids else "P-defer-evidence"
        iterations.append(
            HorizonIteration(
                iteration_id=f"I-{idx:02d}",
                sequence=idx,
                active_path_id=path.path_id,
                goal=path.purpose,
                reflection_prompt=_reflection_prompt(path.name),
                stop_if=[
                    "human_rejects_path",
                    "scope_not_allowed",
                    "confirmed_vulnerability_never_auto",
                ],
                next_if_fail=fail_next if fail_next in path_ids else "P-defer-evidence",
            )
        )

    reflections: list[HorizonReflection] = [
        HorizonReflection(
            reflection_id="R-01",
            trigger="initial_horizon_planning",
            observation="All paths are advisory; unresolved refutations block promotion.",
            next_path_id=paths[0].path_id if paths else "P-defer-evidence",
            source_ref="deep_research" if dres else "bridge",
        ),
        HorizonReflection(
            reflection_id="R-02",
            trigger="failure_path_switch",
            observation="On failure, switch only among planned paths; never execute live validation.",
            next_path_id="P-variant-search" if "P-variant-search" in path_ids else "P-defer-evidence",
            source_ref="long_horizon",
        ),
        HorizonReflection(
            reflection_id="R-03",
            trigger="fp_or_empty_signal",
            observation="False-positive memory or empty drafts should defer rather than force promotion.",
            next_path_id="P-defer-evidence",
            source_ref="agent_memory" if amem else "bridge",
        ),
    ]
    if unresolved:
        reflections.append(
            HorizonReflection(
                reflection_id="R-04",
                trigger="unresolved_refutation",
                observation=(
                    f"{unresolved} unresolved refutation item(s) require human review "
                    "before any path advance."
                ),
                next_path_id="P-primary-chain" if "P-primary-chain" in path_ids else "P-defer-evidence",
                source_ref="deep_research.refutation_matrix",
            )
        )
    if gates and isinstance(gates[0], dict):
        gate_status = str(gates[0].get("status") or "")
        if "fp" in gate_status or "reject" in gate_status:
            reflections.append(
                HorizonReflection(
                    reflection_id="R-05",
                    trigger="residual_gate_fp_or_reject",
                    observation=(
                        "Residual gate disposition is FP/reject; prefer defer path over chain expansion."
                    ),
                    next_path_id="P-defer-evidence",
                    source_ref="human_residual_gates",
                )
            )

    return (
        paths[:_MAX_PATHS],
        switches[:_MAX_SWITCHES],
        iterations[:_MAX_ITERATIONS],
        reflections[:_MAX_REFLECTIONS],
        failure_triggers[:_MAX_SWITCHES],
    )


def _default_failure_triggers() -> list[str]:
    return [
        "refutation_stalled",
        "authz_assumption_weak",
        "variant_queue_empty",
        "insufficient_static_siblings",
        "role_labels_insufficient",
        "harness_plan_blocked",
        "fp_memory_pressure",
        "human_gate_fail",
        "missing_redacted_evidence",
    ]


def _observation_for(
    trigger: str,
    *,
    unresolved: int,
    fp_n: int,
    chain_n: int,
    variant_n: int,
) -> str:
    return _scrub_text(
        f"trigger={trigger}; unresolved={unresolved}; fp_patterns={fp_n}; "
        f"chains={chain_n}; variants={variant_n}; auto_execute=false"
    )


def _reflection_prompt(path_name: str) -> str:
    return _scrub_text(
        f"What evidence would disprove path '{path_name}' without live validation?"
    )


def _paths_from_offline(offline: dict[str, Any]) -> list[HorizonPath]:
    paths: list[HorizonPath] = []
    for i, raw in enumerate(offline.get("paths") or [], start=1):
        if not isinstance(raw, dict):
            continue
        pid = _scrub_text(str(raw.get("path_id") or f"P-off-{i}"))
        paths.append(
            HorizonPath(
                path_id=pid[:64],
                name=_scrub_text(str(raw.get("name") or pid))[:80],
                purpose=_scrub_text(str(raw.get("purpose") or "offline path"))[:240],
                entry_conditions=[
                    _scrub_text(str(x))
                    for x in (raw.get("entry_conditions") or [])
                    if str(x).strip()
                ][:8],
                exit_conditions=[
                    _scrub_text(str(x))
                    for x in (raw.get("exit_conditions") or [])
                    if str(x).strip()
                ][:8],
                required_evidence=[
                    _scrub_text(str(x))
                    for x in (raw.get("required_evidence") or [])
                    if str(x).strip()
                ][:8],
                blockers=[
                    _scrub_text(str(x))
                    for x in (raw.get("blockers") or [])
                    if str(x).strip()
                ][:8],
                priority=int(raw.get("priority") or i),
            )
        )
    return paths or [
        HorizonPath(
            path_id="P-offline-default",
            name="offline_default",
            purpose="Offline long-horizon placeholder requiring human review.",
            entry_conditions=["offline_artifact_present"],
            exit_conditions=["human_review"],
            required_evidence=["human_review_decision"],
            priority=1,
        )
    ]


def _switches_from_offline(offline: dict[str, Any]) -> list[PathSwitch]:
    switches: list[PathSwitch] = []
    for i, raw in enumerate(offline.get("switches") or [], start=1):
        if not isinstance(raw, dict):
            continue
        switches.append(
            PathSwitch(
                switch_id=_scrub_text(str(raw.get("switch_id") or f"S-off-{i}"))[:32],
                from_path_id=_scrub_text(str(raw.get("from_path_id") or "any"))[:64],
                to_path_id=_scrub_text(str(raw.get("to_path_id") or "P-defer-evidence"))[:64],
                trigger=_scrub_text(str(raw.get("trigger") or "offline_trigger")),
                reason=_scrub_text(str(raw.get("reason") or "offline switch")),
                observation=_scrub_text(str(raw.get("observation") or "offline path switch plan")),
            )
        )
    return switches


def _iterations_from_offline(
    offline: dict[str, Any], paths: list[HorizonPath]
) -> list[HorizonIteration]:
    items: list[HorizonIteration] = []
    for i, raw in enumerate(offline.get("iterations") or [], start=1):
        if not isinstance(raw, dict):
            continue
        items.append(
            HorizonIteration(
                iteration_id=_scrub_text(str(raw.get("iteration_id") or f"I-off-{i}"))[:32],
                sequence=int(raw.get("sequence") or i),
                active_path_id=_scrub_text(
                    str(
                        raw.get("active_path_id")
                        or (paths[0].path_id if paths else "P-defer-evidence")
                    )
                )[:64],
                goal=_scrub_text(str(raw.get("goal") or "offline iteration")),
                reflection_prompt=_scrub_text(
                    str(raw.get("reflection_prompt") or "What evidence is still missing?")
                ),
                stop_if=[
                    _scrub_text(str(x))
                    for x in (raw.get("stop_if") or ["human_rejects_path"])
                    if str(x).strip()
                ][:8],
                next_if_fail=_scrub_text(str(raw.get("next_if_fail") or "P-defer-evidence"))[:64],
            )
        )
    if items:
        return items
    return [
        HorizonIteration(
            iteration_id="I-01",
            sequence=1,
            active_path_id=paths[0].path_id if paths else "P-defer-evidence",
            goal=paths[0].purpose if paths else "defer",
            reflection_prompt=_reflection_prompt(paths[0].name if paths else "defer"),
            stop_if=["human_rejects_path", "scope_not_allowed"],
            next_if_fail="P-defer-evidence",
        )
    ]


def _reflections_from_offline(offline: dict[str, Any]) -> list[HorizonReflection]:
    items: list[HorizonReflection] = []
    for i, raw in enumerate(offline.get("reflections") or [], start=1):
        if not isinstance(raw, dict):
            continue
        items.append(
            HorizonReflection(
                reflection_id=_scrub_text(str(raw.get("reflection_id") or f"R-off-{i}"))[:32],
                trigger=_scrub_text(str(raw.get("trigger") or "offline")),
                observation=_scrub_text(str(raw.get("observation") or "offline reflection")),
                next_path_id=_scrub_text(str(raw.get("next_path_id") or "P-defer-evidence"))[:64],
                source_ref=_scrub_text(str(raw.get("source_ref") or "offline")),
            )
        )
    return items or [
        HorizonReflection(
            reflection_id="R-off-1",
            trigger="offline_plan",
            observation="Offline long-horizon plan loaded; human review required.",
            next_path_id="P-offline-default",
            source_ref="inputs/long_horizon.json",
        )
    ]


def _load_offline(root: Path | None) -> tuple[dict[str, Any], int]:
    if root is None:
        return {}, 0
    candidates = [
        root / "inputs" / "long_horizon.json",
        root / "inputs" / "long_horizon" / "plan.json",
        root / "inputs" / "v4_long_horizon.json",
    ]
    lh_dir = root / "inputs" / "long_horizon"
    paths: list[Path] = []
    if lh_dir.is_dir():
        paths.extend(sorted(lh_dir.glob("*.json")))
    for candidate in candidates:
        if candidate.is_file():
            paths.append(candidate)
    merged: dict[str, Any] = {}
    artifact_n = 0
    seen: set[str] = set()
    for path in paths:
        key = str(path.resolve()) if path.exists() else str(path)
        if key in seen:
            continue
        seen.add(key)
        if not path.is_file():
            continue
        artifact_n += 1
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(raw, dict):
            continue
        for k, v in raw.items():
            if k not in merged:
                merged[k] = v
            elif isinstance(merged.get(k), list) and isinstance(v, list):
                merged[k] = list(merged[k]) + list(v)
    return merged, artifact_n


def _export_plan(root: Path, result: LongHorizonResult) -> tuple[bool, int, str]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = root / "_export" / "long_horizon" / stamp
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        payload = result.to_dict()
        payload["package_root"] = str(root.name)
        (out_dir / "plan.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        summary = {
            "status": result.status,
            "path_count": result.path_count,
            "switch_count": result.switch_count,
            "iteration_count": result.iteration_count,
            "reflection_count": result.reflection_count,
            "execution_allowed": False,
            "auto_path_switch_allowed": False,
            "export_stamp": stamp,
        }
        (out_dir / "summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return True, 2, stamp
    except OSError:
        return False, 0, ""


def _empty(
    *,
    status: str,
    package_id: str = "",
    package_root: str = "",
    notes: list[str] | None = None,
    human_allow_export_write: bool = False,
) -> LongHorizonResult:
    return _force_safety(
        LongHorizonResult(
            stage="v4_long_horizon_agent",
            inspirations=["Mythos", "Big Sleep", "final-scheme-V4"],
            execution_mode="plan_only",
            status=status,
            package_id=package_id,
            package_root=package_root,
            human_allow_export_write=bool(human_allow_export_write),
            safety_invariants=list(SAFETY_INVARIANTS),
            notes=list(notes or []),
            summary=f"status={status}",
        )
    )


def _scrub_text(value: str) -> str:
    text = str(value or "")
    text = _SECRET_HINTS.sub("[REDACTED]", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:400]


def _force_safety(result: LongHorizonResult) -> LongHorizonResult:
    paths = [
        HorizonPath(
            path_id=item.path_id,
            name=_scrub_text(item.name),
            purpose=_scrub_text(item.purpose),
            entry_conditions=[_scrub_text(x) for x in item.entry_conditions],
            exit_conditions=[_scrub_text(x) for x in item.exit_conditions],
            required_evidence=[_scrub_text(x) for x in item.required_evidence],
            blockers=[_scrub_text(x) for x in item.blockers],
            priority=int(item.priority),
            execution_allowed=False,
            human_review_required=True,
        )
        for item in list(result.paths or [])
    ]
    switches = [
        PathSwitch(
            switch_id=item.switch_id,
            from_path_id=item.from_path_id,
            to_path_id=item.to_path_id,
            trigger=_scrub_text(item.trigger),
            reason=_scrub_text(item.reason),
            observation=_scrub_text(item.observation),
            requires_human_review=True,
            execution_allowed=False,
        )
        for item in list(result.switches or [])
    ]
    iterations = [
        HorizonIteration(
            iteration_id=item.iteration_id,
            sequence=int(item.sequence),
            active_path_id=item.active_path_id,
            goal=_scrub_text(item.goal),
            reflection_prompt=_scrub_text(item.reflection_prompt),
            stop_if=[_scrub_text(x) for x in item.stop_if],
            next_if_fail=item.next_if_fail,
            execution_allowed=False,
        )
        for item in list(result.iterations or [])
    ]
    reflections = [
        HorizonReflection(
            reflection_id=item.reflection_id,
            trigger=_scrub_text(item.trigger),
            observation=_scrub_text(item.observation),
            next_path_id=item.next_path_id,
            source_ref=_scrub_text(item.source_ref),
            human_review_required=True,
        )
        for item in list(result.reflections or [])
    ]
    return LongHorizonResult(
        stage="v4_long_horizon_agent",
        inspirations=list(result.inspirations) or ["Mythos", "Big Sleep", "final-scheme-V4"],
        execution_mode="plan_only",
        status=result.status,
        package_id=result.package_id,
        package_root=result.package_root,
        paths=paths,
        path_count=len(paths),
        switches=switches,
        switch_count=len(switches),
        iterations=iterations,
        iteration_count=len(iterations),
        reflections=reflections,
        reflection_count=len(reflections),
        active_path_id=result.active_path_id or (paths[0].path_id if paths else ""),
        failure_triggers=[_scrub_text(t) for t in list(result.failure_triggers or [])],
        offline_artifact_count=int(result.offline_artifact_count or 0),
        deep_research_status=result.deep_research_status,
        unresolved_refutation_count=int(result.unresolved_refutation_count or 0),
        human_allow_export_write=bool(result.human_allow_export_write),
        export_written=bool(result.export_written),
        export_count=int(result.export_count or 0),
        export_root_relative="_export/long_horizon",
        run_stamp=result.run_stamp,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        ranking_permission_granted=False,
        auto_path_switch_allowed=False,
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
        "ranking_permission_granted",
        "auto_path_switch_allowed",
        "network_access",
        "live_validation",
    ):
        out[key] = False
    out["safety_invariants"] = list(SAFETY_INVARIANTS)
    cleaned_paths = []
    for item in out.get("paths") or []:
        if not isinstance(item, dict):
            continue
        row = dict(item)
        row["execution_allowed"] = False
        row["human_review_required"] = True
        row["name"] = _scrub_text(str(row.get("name") or ""))
        row["purpose"] = _scrub_text(str(row.get("purpose") or ""))
        cleaned_paths.append(row)
    out["paths"] = cleaned_paths
    out["path_count"] = len(cleaned_paths)
    cleaned_switches = []
    for item in out.get("switches") or []:
        if not isinstance(item, dict):
            continue
        row = dict(item)
        row["execution_allowed"] = False
        row["requires_human_review"] = True
        row["trigger"] = _scrub_text(str(row.get("trigger") or ""))
        row["reason"] = _scrub_text(str(row.get("reason") or ""))
        row["observation"] = _scrub_text(str(row.get("observation") or ""))
        cleaned_switches.append(row)
    out["switches"] = cleaned_switches
    out["switch_count"] = len(cleaned_switches)
    cleaned_iters = []
    for item in out.get("iterations") or []:
        if not isinstance(item, dict):
            continue
        row = dict(item)
        row["execution_allowed"] = False
        row["goal"] = _scrub_text(str(row.get("goal") or ""))
        row["reflection_prompt"] = _scrub_text(str(row.get("reflection_prompt") or ""))
        cleaned_iters.append(row)
    out["iterations"] = cleaned_iters
    out["iteration_count"] = len(cleaned_iters)
    cleaned_ref = []
    for item in out.get("reflections") or []:
        if not isinstance(item, dict):
            continue
        row = dict(item)
        row["human_review_required"] = True
        row["observation"] = _scrub_text(str(row.get("observation") or ""))
        cleaned_ref.append(row)
    out["reflections"] = cleaned_ref
    out["reflection_count"] = len(cleaned_ref)
    return out


__all__ = [
    "HorizonIteration",
    "HorizonPath",
    "HorizonReflection",
    "LongHorizonError",
    "LongHorizonResult",
    "PathSwitch",
    "STATUS_EMPTY",
    "STATUS_PACKAGE_MISSING",
    "STATUS_READY",
    "STATUS_WAITING",
    "STATUS_WRITTEN",
    "attach_long_horizon_to_bridge_result",
    "build_long_horizon",
    "run_long_horizon",
]
