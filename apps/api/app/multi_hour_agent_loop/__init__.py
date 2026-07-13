"""Multi-Hour Agent Loop - plan-only multi-session research loop (beyond V4 long_horizon).

Lawful research only:
- Compose residual stack into multi-session phases with budgets and human gates
- Optional offline plan under package inputs/
- Optional export under package _export/multi_hour_agent_loop/ with human flag
- Never auto-ticks, never auto-executes, never exploits/PoCs, never submit/promote
- Never grants ranking/execute permission; never live network validation
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STATUS_READY = "multi_hour_agent_loop_plan_ready"
STATUS_EMPTY = "multi_hour_agent_loop_empty"
STATUS_PACKAGE_MISSING = "multi_hour_agent_loop_package_missing"
STATUS_WRITTEN = "multi_hour_agent_loop_export_written"
STATUS_WAITING = "multi_hour_agent_loop_waiting_for_signals"

SAFETY_INVARIANTS = [
    "authorized_package_or_bridge_only",
    "no_public_target_scanning",
    "no_network_access",
    "no_raw_secrets_or_user_data",
    "no_automatic_report_submission",
    "no_finding_promotion",
    "no_auto_tick_or_session_execution",
    "plan_only_multi_session_budget",
    "human_review_required_before_any_session_execution",
    "no_export_write_without_human_flag",
    "no_ranking_permission_from_plan",
]

_SECRET_HINTS = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|session|bearer|private[_-]?key|ssh-rsa|BEGIN [A-Z ]*PRIVATE)"
)
_MAX_PHASES = 16
_MAX_SESSIONS = 24
_MAX_GATES = 20
_MAX_HANDOFFS = 32
_DEFAULT_SESSION_MINUTES = 45
_DEFAULT_WALL_HOURS = 4


class MultiHourAgentLoopError(ValueError):
    """Raised when bridge attach receives invalid input."""


@dataclass(frozen=True)
class LoopPhase:
    phase_id: str
    name: str
    purpose: str
    depends_on: list[str] = field(default_factory=list)
    inputs: list[str] = field(default_factory=list)
    outputs: list[str] = field(default_factory=list)
    estimated_minutes: int = 30
    human_review_required: bool = True
    execution_allowed: bool = False
    auto_advance: bool = False


@dataclass(frozen=True)
class LoopSession:
    session_id: str
    sequence: int
    phase_id: str
    goal: str
    budget_minutes: int
    max_tool_calls: int
    stop_if: list[str] = field(default_factory=list)
    handoff_to: str = ""
    human_gate_required: bool = True
    execution_allowed: bool = False
    auto_tick: bool = False


@dataclass(frozen=True)
class LoopHumanGate:
    gate_id: str
    name: str
    when: str
    required_artifacts: list[str] = field(default_factory=list)
    blocks: list[str] = field(default_factory=list)
    auto_approve: bool = False


@dataclass(frozen=True)
class LoopHandoff:
    handoff_id: str
    from_session_id: str
    to_session_id: str
    reason: str
    carries: list[str] = field(default_factory=list)
    requires_human_review: bool = True
    auto_handoff: bool = False

@dataclass
class MultiHourAgentLoopResult:
    stage: str
    inspirations: list[str]
    execution_mode: str
    status: str
    package_id: str = ""
    package_root: str = ""
    wall_clock_hours: float = float(_DEFAULT_WALL_HOURS)
    session_budget_minutes: int = _DEFAULT_SESSION_MINUTES
    max_sessions: int = 0
    phases: list[LoopPhase] = field(default_factory=list)
    phase_count: int = 0
    sessions: list[LoopSession] = field(default_factory=list)
    session_count: int = 0
    human_gates: list[LoopHumanGate] = field(default_factory=list)
    human_gate_count: int = 0
    handoffs: list[LoopHandoff] = field(default_factory=list)
    handoff_count: int = 0
    active_phase_id: str = ""
    active_session_id: str = ""
    offline_artifact_count: int = 0
    residual_signal_count: int = 0
    knowledge_base_pattern_count: int = 0
    long_horizon_path_count: int = 0
    human_allow_export_write: bool = False
    export_written: bool = False
    export_count: int = 0
    export_root_relative: str = "_export/multi_hour_agent_loop"
    run_stamp: str = ""
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    ranking_permission_granted: bool = False
    auto_tick_allowed: bool = False
    auto_session_advance_allowed: bool = False
    network_access: bool = False
    live_validation: bool = False
    safety_invariants: list[str] = field(default_factory=list)
    next_allowed_action: str = (
        "Human reviews multi-hour session plan offline; Mythos never auto-ticks agent sessions."
    )
    notes: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _force_safety_dict(asdict(self))


def build_multi_hour_agent_loop(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    bridge_result: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> MultiHourAgentLoopResult:
    return run_multi_hour_agent_loop(
        package_root=package_root,
        package_id=package_id,
        bridge_result=bridge_result,
        human_allow_export_write=human_allow_export_write,
    )


def run_multi_hour_agent_loop(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    bridge_result: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> MultiHourAgentLoopResult:
    """Build plan-only multi-hour agent loop for an authorized package."""
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
    pkg_id = str(package_id or bridge.get("package_id") or (root.name if root else "") or "")

    offline, offline_n = _load_offline_plan(root)
    phases, sessions, gates, handoffs, residual_n, kb_n, lh_n = _build_from_signals(
        bridge=bridge,
        offline=offline,
        package_id=pkg_id,
    )

    has_signal = bool(phases or sessions or gates or offline_n or residual_n or kb_n or lh_n or bridge)
    if not has_signal and not bridge and root is None:
        status = STATUS_EMPTY
    elif not (phases or sessions) and bridge:
        status = STATUS_WAITING
    elif phases or sessions:
        status = STATUS_READY
    else:
        status = STATUS_WAITING if bridge or offline_n else STATUS_EMPTY

    wall_hours = float(offline.get("wall_clock_hours") or _DEFAULT_WALL_HOURS)
    session_minutes = int(offline.get("session_budget_minutes") or _DEFAULT_SESSION_MINUTES)
    if session_minutes < 15:
        session_minutes = 15
    if session_minutes > 180:
        session_minutes = 180
    if wall_hours < 1:
        wall_hours = 1.0
    if wall_hours > 12:
        wall_hours = 12.0

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    result = MultiHourAgentLoopResult(
        stage="multi_hour_agent_loop",
        inspirations=[
            "final_scheme_v4_long_horizon_beyond_plan",
            "campaign_orchestrator_read_only_tick",
            "authorized_package_bridge_residual_stack",
        ],
        execution_mode="advisory_multi_session_plan_only",
        status=status,
        package_id=pkg_id,
        package_root=root_s,
        wall_clock_hours=wall_hours,
        session_budget_minutes=session_minutes,
        max_sessions=len(sessions),
        phases=phases,
        phase_count=len(phases),
        sessions=sessions,
        session_count=len(sessions),
        human_gates=gates,
        human_gate_count=len(gates),
        handoffs=handoffs,
        handoff_count=len(handoffs),
        active_phase_id=phases[0].phase_id if phases else "",
        active_session_id=sessions[0].session_id if sessions else "",
        offline_artifact_count=offline_n,
        residual_signal_count=residual_n,
        knowledge_base_pattern_count=kb_n,
        long_horizon_path_count=lh_n,
        human_allow_export_write=bool(human_allow_export_write),
        run_stamp=stamp,
        safety_invariants=list(SAFETY_INVARIANTS),
        notes=_notes_for(status, residual_n, kb_n, lh_n, offline_n),
        summary=(
            f"status={status} phases={len(phases)} sessions={len(sessions)} "
            f"gates={len(gates)} handoffs={len(handoffs)} wall_h={wall_hours} "
            f"session_min={session_minutes}"
        ),
    )

    if bool(human_allow_export_write) and root is not None and root.is_dir() and (phases or sessions):
        written, count, rel = _export_plan(root, result, stamp)
        if written:
            result.export_written = True
            result.export_count = count
            result.export_root_relative = rel
            result.status = STATUS_WRITTEN
            result.summary += f" export_count={count}"

    return result

def attach_multi_hour_agent_loop_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    multi_hour_agent_loop: dict[str, Any] | MultiHourAgentLoopResult | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    """Attach multi-hour agent loop plan; never unlocks execute/submit/promote/tick."""
    if not isinstance(bridge_result, dict):
        raise MultiHourAgentLoopError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")

    if isinstance(multi_hour_agent_loop, MultiHourAgentLoopResult):
        payload = multi_hour_agent_loop.to_dict()
    elif isinstance(multi_hour_agent_loop, dict):
        payload = _force_safety_dict(dict(multi_hour_agent_loop))
    else:
        payload = run_multi_hour_agent_loop(
            package_root=resolved_root,
            package_id=package_id,
            bridge_result=bridge_result,
            human_allow_export_write=bool(human_allow_export_write),
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["multi_hour_agent_loop"] = payload
    out["multi_hour_agent_loop_present"] = True
    out["multi_hour_agent_loop_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["multi_hour_agent_loop_phase_count"] = int(payload.get("phase_count") or 0)
    out["multi_hour_agent_loop_session_count"] = int(payload.get("session_count") or 0)
    out["multi_hour_agent_loop_gate_count"] = int(payload.get("human_gate_count") or 0)
    out["multi_hour_agent_loop_handoff_count"] = int(payload.get("handoff_count") or 0)
    out["multi_hour_agent_loop_export_written"] = bool(payload.get("export_written"))
    out["multi_hour_agent_loop_auto_tick_allowed"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out


def _count_residual_signals(bridge: dict[str, Any]) -> int:
    keys = [
        "deep_research",
        "long_horizon",
        "knowledge_base",
        "agent_memory",
        "continuous_scan",
        "patch_validation",
        "human_gate_dry_run",
        "drafts",
        "human_residual_gates",
    ]
    n = 0
    for k in keys:
        v = bridge.get(k)
        if isinstance(v, dict) and v:
            n += 1
        elif isinstance(v, list) and v:
            n += 1
    return n


def _notes_for(status: str, residual_n: int, kb_n: int, lh_n: int, offline_n: int) -> list[str]:
    notes = [
        "plan_only_multi_session_budget",
        "never_auto_tick",
        "never_auto_session_advance",
        f"residual_signals={residual_n}",
        f"knowledge_base_patterns={kb_n}",
        f"long_horizon_paths={lh_n}",
        f"offline_artifacts={offline_n}",
    ]
    if status == STATUS_WAITING:
        notes.append("waiting_for_residual_or_offline_signals")
    if status == STATUS_EMPTY:
        notes.append("no_package_or_bridge_signals")
    return notes


def _load_offline_plan(root: Path | None) -> tuple[dict[str, Any], int]:
    if root is None:
        return {}, 0
    candidates = [
        root / "inputs" / "multi_hour_agent_loop.json",
        root / "inputs" / "multi_hour_loop.json",
        root / "inputs" / "agent_loop.json",
        root / "inputs" / "v4_multi_hour.json",
    ]
    merged: dict[str, Any] = {}
    count = 0
    for path in candidates:
        if not path.is_file():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(raw, dict):
            continue
        count += 1
        for k, v in raw.items():
            if k not in merged:
                merged[k] = v
            elif isinstance(merged[k], list) and isinstance(v, list):
                merged[k] = list(merged[k]) + list(v)
    return merged, count

def _build_from_signals(
    *,
    bridge: dict[str, Any],
    offline: dict[str, Any],
    package_id: str,
) -> tuple[
    list[LoopPhase],
    list[LoopSession],
    list[LoopHumanGate],
    list[LoopHandoff],
    int,
    int,
    int,
]:
    del package_id  # reserved for future package-specific templates
    if offline:
        phases = _phases_from_offline(offline)
        sessions = _sessions_from_offline(offline, phases)
        gates = _gates_from_offline(offline)
        handoffs = _handoffs_from_offline(offline)
        if phases or sessions:
            residual_n = _count_residual_signals(bridge)
            kb = bridge.get("knowledge_base") if isinstance(bridge.get("knowledge_base"), dict) else {}
            lh = bridge.get("long_horizon") if isinstance(bridge.get("long_horizon"), dict) else {}
            kb_n = int(kb.get("pattern_count") or bridge.get("knowledge_base_pattern_count") or 0)
            lh_n = int(lh.get("path_count") or bridge.get("long_horizon_path_count") or 0)
            return (
                phases[:_MAX_PHASES],
                sessions[:_MAX_SESSIONS],
                gates[:_MAX_GATES],
                handoffs[:_MAX_HANDOFFS],
                residual_n,
                kb_n,
                lh_n,
            )

    residual_n = _count_residual_signals(bridge)
    kb = bridge.get("knowledge_base") if isinstance(bridge.get("knowledge_base"), dict) else {}
    lh = bridge.get("long_horizon") if isinstance(bridge.get("long_horizon"), dict) else {}
    dres = bridge.get("deep_research") if isinstance(bridge.get("deep_research"), dict) else {}
    hg = bridge.get("human_gate_dry_run") if isinstance(bridge.get("human_gate_dry_run"), dict) else {}

    kb_n = int(kb.get("pattern_count") or bridge.get("knowledge_base_pattern_count") or 0)
    lh_n = int(lh.get("path_count") or bridge.get("long_horizon_path_count") or 0)
    dres_chains = int(
        dres.get("chain_count")
        or bridge.get("deep_research_chain_count")
        or 0
    )
    retained = int(bridge.get("retained_count") or 0)

    phases: list[LoopPhase] = [
        LoopPhase(
            phase_id="PH-01-intake-scope",
            name="Authorized intake and scope reaffirm",
            purpose="Confirm package policy/scope and residual stack presence before multi-session work.",
            depends_on=[],
            inputs=["package_scope", "policy", "bridge_result"],
            outputs=["scope_snapshot", "session_budget"],
            estimated_minutes=20,
        ),
        LoopPhase(
            phase_id="PH-02-surface-model",
            name="Attack-surface and codebase model",
            purpose="Refresh codebase map, web/api planner, and residual runners as plan-only inputs.",
            depends_on=["PH-01-intake-scope"],
            inputs=["codebase_map", "authorized_web_api", "sbom"],
            outputs=["surface_model", "priority_assets"],
            estimated_minutes=40,
        ),
        LoopPhase(
            phase_id="PH-03-deep-hypothesis",
            name="Deep research and hypothesis expansion",
            purpose="Use deep_research / variant / chain plans without executing validation.",
            depends_on=["PH-02-surface-model"],
            inputs=["deep_research", "agent_memory", "knowledge_base"],
            outputs=["hypothesis_queue", "variant_queue"],
            estimated_minutes=50,
        ),
        LoopPhase(
            phase_id="PH-04-path-switch",
            name="Long-horizon path switches",
            purpose="Plan failure-triggered path switches from long_horizon reflections.",
            depends_on=["PH-03-deep-hypothesis"],
            inputs=["long_horizon", "unresolved_refutations"],
            outputs=["active_path_plan", "switch_plan"],
            estimated_minutes=40,
        ),
        LoopPhase(
            phase_id="PH-05-evidence-prep",
            name="Evidence and safe validation planning",
            purpose="Prepare non-destructive validation and patch-validation plans for human approval.",
            depends_on=["PH-04-path-switch"],
            inputs=["patch_validation", "human_gate_dry_run", "drafts"],
            outputs=["validation_plan", "report_draft_readiness"],
            estimated_minutes=45,
        ),
        LoopPhase(
            phase_id="PH-06-knowledge-consolidate",
            name="Knowledge consolidate and handoff",
            purpose="Deposit structured patterns into knowledge_base catalog; prepare next-day handoff.",
            depends_on=["PH-05-evidence-prep"],
            inputs=["knowledge_base", "agent_memory", "continuous_scan"],
            outputs=["knowledge_catalog_delta", "next_session_handoff"],
            estimated_minutes=30,
        ),
    ]

    session_minutes = int(offline.get("session_budget_minutes") or _DEFAULT_SESSION_MINUTES)
    sessions: list[LoopSession] = []
    for seq, phase in enumerate(phases, start=1):
        tool_budget = 8
        if "deep" in phase.phase_id or "path" in phase.phase_id:
            tool_budget = 12
        if "evidence" in phase.phase_id:
            tool_budget = 10
        goal_bits = [phase.purpose]
        if retained and "hypothesis" in phase.phase_id:
            goal_bits.append(f"retained_candidates={retained}")
        if kb_n and "knowledge" in phase.phase_id:
            goal_bits.append(f"kb_patterns={kb_n}")
        if lh_n and "path" in phase.phase_id:
            goal_bits.append(f"lh_paths={lh_n}")
        if dres_chains and "hypothesis" in phase.phase_id:
            goal_bits.append(f"deep_chains={dres_chains}")
        sessions.append(
            LoopSession(
                session_id=f"S-{seq:02d}",
                sequence=seq,
                phase_id=phase.phase_id,
                goal="; ".join(goal_bits)[:400],
                budget_minutes=min(session_minutes, max(20, phase.estimated_minutes)),
                max_tool_calls=tool_budget,
                stop_if=[
                    "human_gate_required",
                    "budget_minutes_exhausted",
                    "tool_call_budget_exhausted",
                    "scope_uncertainty",
                    "unsafe_permission_request",
                ],
                handoff_to=f"S-{seq + 1:02d}" if seq < len(phases) else "S-END-human-review",
            )
        )

    gates: list[LoopHumanGate] = [
        LoopHumanGate(
            gate_id="MHG-01-scope",
            name="Scope reaffirm before multi-session work",
            when="before_PH-01-complete",
            required_artifacts=["policy", "scope_assets"],
            blocks=["PH-02-surface-model"],
        ),
        LoopHumanGate(
            gate_id="MHG-02-hypothesis-promote",
            name="Human review before evidence planning",
            when="after_PH-03-deep-hypothesis",
            required_artifacts=["hypothesis_queue", "refutation_notes"],
            blocks=["PH-05-evidence-prep"],
        ),
        LoopHumanGate(
            gate_id="MHG-03-validation-plan",
            name="Approve non-destructive validation plan",
            when="after_PH-05-evidence-prep",
            required_artifacts=["validation_plan", "submission_blocked_draft"],
            blocks=["any_live_validation"],
        ),
        LoopHumanGate(
            gate_id="MHG-04-day-handoff",
            name="End-of-day handoff review",
            when="after_PH-06-knowledge-consolidate",
            required_artifacts=["knowledge_catalog_delta", "next_session_handoff"],
            blocks=["auto_next_day_tick"],
        ),
    ]
    if hg:
        gates.append(
            LoopHumanGate(
                gate_id="MHG-05-dry-run-align",
                name="Align with offline human-gate dry-run chain",
                when="any_session_start",
                required_artifacts=["human_gate_dry_run"],
                blocks=["skip_human_gates"],
            )
        )

    handoffs: list[LoopHandoff] = []
    for i in range(len(sessions) - 1):
        cur = sessions[i]
        nxt = sessions[i + 1]
        carries = ["session_notes", "open_questions", "blocked_items"]
        if "knowledge" in nxt.phase_id:
            carries.append("pattern_candidates")
        if "path" in nxt.phase_id:
            carries.append("active_path_id")
        handoffs.append(
            LoopHandoff(
                handoff_id=f"HO-{i + 1:02d}",
                from_session_id=cur.session_id,
                to_session_id=nxt.session_id,
                reason="session_budget_or_phase_boundary",
                carries=carries,
            )
        )
    if sessions:
        handoffs.append(
            LoopHandoff(
                handoff_id=f"HO-{len(sessions):02d}-END",
                from_session_id=sessions[-1].session_id,
                to_session_id="S-END-human-review",
                reason="multi_hour_plan_complete_human_only",
                carries=["report_draft_readiness", "knowledge_catalog_delta", "residual_open_items"],
            )
        )

    return (
        phases[:_MAX_PHASES],
        sessions[:_MAX_SESSIONS],
        gates[:_MAX_GATES],
        handoffs[:_MAX_HANDOFFS],
        residual_n,
        kb_n,
        lh_n,
    )

def _phases_from_offline(offline: dict[str, Any]) -> list[LoopPhase]:
    items: list[LoopPhase] = []
    raw = offline.get("phases") or offline.get("phase_plans") or []
    if not isinstance(raw, list):
        return items
    for i, item in enumerate(raw[:_MAX_PHASES], start=1):
        if not isinstance(item, dict):
            continue
        pid = str(item.get("phase_id") or item.get("id") or f"PH-OFF-{i:02d}")
        items.append(
            LoopPhase(
                phase_id=_clean_text(pid, 64),
                name=_clean_text(item.get("name") or item.get("title") or pid, 120),
                purpose=_clean_text(item.get("purpose") or item.get("goal") or "offline_phase", 400),
                depends_on=_str_list(item.get("depends_on"), 8),
                inputs=_str_list(item.get("inputs"), 12),
                outputs=_str_list(item.get("outputs"), 12),
                estimated_minutes=int(item.get("estimated_minutes") or 30),
                human_review_required=True,
                execution_allowed=False,
                auto_advance=False,
            )
        )
    return items


def _sessions_from_offline(offline: dict[str, Any], phases: list[LoopPhase]) -> list[LoopSession]:
    items: list[LoopSession] = []
    raw = offline.get("sessions") or offline.get("session_plans") or []
    if not isinstance(raw, list):
        if phases:
            for i, phase in enumerate(phases[:_MAX_SESSIONS], start=1):
                items.append(
                    LoopSession(
                        session_id=f"S-OFF-{i:02d}",
                        sequence=i,
                        phase_id=phase.phase_id,
                        goal=phase.purpose,
                        budget_minutes=int(offline.get("session_budget_minutes") or phase.estimated_minutes or 45),
                        max_tool_calls=8,
                        stop_if=["human_gate_required", "budget_minutes_exhausted"],
                        handoff_to=f"S-OFF-{i + 1:02d}" if i < len(phases) else "S-END-human-review",
                    )
                )
        return items
    for i, item in enumerate(raw[:_MAX_SESSIONS], start=1):
        if not isinstance(item, dict):
            continue
        sid = str(item.get("session_id") or item.get("id") or f"S-OFF-{i:02d}")
        items.append(
            LoopSession(
                session_id=_clean_text(sid, 64),
                sequence=int(item.get("sequence") or i),
                phase_id=_clean_text(
                    item.get("phase_id") or (phases[0].phase_id if phases else f"PH-OFF-{i:02d}"),
                    64,
                ),
                goal=_clean_text(item.get("goal") or item.get("purpose") or "offline_session", 400),
                budget_minutes=int(item.get("budget_minutes") or offline.get("session_budget_minutes") or 45),
                max_tool_calls=int(item.get("max_tool_calls") or 8),
                stop_if=_str_list(item.get("stop_if"), 10) or ["human_gate_required"],
                handoff_to=_clean_text(item.get("handoff_to") or "", 64),
                human_gate_required=True,
                execution_allowed=False,
                auto_tick=False,
            )
        )
    return items


def _gates_from_offline(offline: dict[str, Any]) -> list[LoopHumanGate]:
    items: list[LoopHumanGate] = []
    raw = offline.get("human_gates") or offline.get("gates") or []
    if not isinstance(raw, list):
        return items
    for i, item in enumerate(raw[:_MAX_GATES], start=1):
        if not isinstance(item, dict):
            continue
        gid = str(item.get("gate_id") or item.get("id") or f"MHG-OFF-{i:02d}")
        items.append(
            LoopHumanGate(
                gate_id=_clean_text(gid, 64),
                name=_clean_text(item.get("name") or gid, 120),
                when=_clean_text(item.get("when") or "manual", 120),
                required_artifacts=_str_list(item.get("required_artifacts"), 12),
                blocks=_str_list(item.get("blocks"), 12),
                auto_approve=False,
            )
        )
    return items


def _handoffs_from_offline(offline: dict[str, Any]) -> list[LoopHandoff]:
    items: list[LoopHandoff] = []
    raw = offline.get("handoffs") or []
    if not isinstance(raw, list):
        return items
    for i, item in enumerate(raw[:_MAX_HANDOFFS], start=1):
        if not isinstance(item, dict):
            continue
        hid = str(item.get("handoff_id") or item.get("id") or f"HO-OFF-{i:02d}")
        items.append(
            LoopHandoff(
                handoff_id=_clean_text(hid, 64),
                from_session_id=_clean_text(item.get("from_session_id") or "", 64),
                to_session_id=_clean_text(item.get("to_session_id") or "", 64),
                reason=_clean_text(item.get("reason") or "offline_handoff", 200),
                carries=_str_list(item.get("carries"), 12),
                requires_human_review=True,
                auto_handoff=False,
            )
        )
    return items


def _export_plan(
    root: Path,
    result: MultiHourAgentLoopResult,
    stamp: str,
) -> tuple[bool, int, str]:
    export_root = root / "_export" / "multi_hour_agent_loop" / stamp
    try:
        export_root.mkdir(parents=True, exist_ok=True)
        payload = result.to_dict()
        files = {
            "plan.json": payload,
            "sessions.json": {
                "sessions": payload.get("sessions") or [],
                "phases": payload.get("phases") or [],
                "execution_allowed": False,
                "auto_tick_allowed": False,
            },
            "summary.json": {
                "status": payload.get("status"),
                "phase_count": payload.get("phase_count"),
                "session_count": payload.get("session_count"),
                "human_gate_count": payload.get("human_gate_count"),
                "handoff_count": payload.get("handoff_count"),
                "wall_clock_hours": payload.get("wall_clock_hours"),
                "session_budget_minutes": payload.get("session_budget_minutes"),
                "execution_allowed": False,
                "auto_tick_allowed": False,
                "report_submission_allowed": False,
                "summary": payload.get("summary"),
            },
        }
        for name, body in files.items():
            (export_root / name).write_text(
                json.dumps(body, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        rel = f"_export/multi_hour_agent_loop/{stamp}"
        return True, len(files), rel
    except OSError:
        return False, 0, "_export/multi_hour_agent_loop"


def _empty(
    *,
    status: str,
    package_id: str = "",
    package_root: str = "",
    notes: list[str] | None = None,
    human_allow_export_write: bool = False,
) -> MultiHourAgentLoopResult:
    return MultiHourAgentLoopResult(
        stage="multi_hour_agent_loop",
        inspirations=["final_scheme_v4_long_horizon_beyond_plan"],
        execution_mode="advisory_multi_session_plan_only",
        status=status,
        package_id=package_id,
        package_root=package_root,
        human_allow_export_write=bool(human_allow_export_write),
        safety_invariants=list(SAFETY_INVARIANTS),
        notes=list(notes or []),
        summary=f"status={status}",
    )


def _force_safety_dict(payload: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    out["finding_promotion_allowed"] = False
    out["ranking_permission_granted"] = False
    out["auto_tick_allowed"] = False
    out["auto_session_advance_allowed"] = False
    out["network_access"] = False
    out["live_validation"] = False
    out["execution_mode"] = "advisory_multi_session_plan_only"
    for key in ("phases", "sessions", "human_gates", "handoffs"):
        items = out.get(key)
        if not isinstance(items, list):
            continue
        cleaned = []
        for item in items:
            if not isinstance(item, dict):
                continue
            row = dict(item)
            row["execution_allowed"] = False
            if "auto_tick" in row:
                row["auto_tick"] = False
            if "auto_advance" in row:
                row["auto_advance"] = False
            if "auto_handoff" in row:
                row["auto_handoff"] = False
            if "auto_approve" in row:
                row["auto_approve"] = False
            if "human_review_required" in row or key in {"phases", "handoffs"}:
                row["human_review_required"] = True
            if "human_gate_required" in row or key == "sessions":
                row["human_gate_required"] = True
            cleaned.append(row)
        out[key] = cleaned
    inv = out.get("safety_invariants")
    if not isinstance(inv, list) or not inv:
        out["safety_invariants"] = list(SAFETY_INVARIANTS)
    return out


def _clean_text(value: Any, limit: int) -> str:
    text = str(value or "").strip()
    text = _SECRET_HINTS.sub("[redacted]", text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


def _str_list(value: Any, limit: int) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        s = _clean_text(item, 200)
        if s:
            out.append(s)
        if len(out) >= limit:
            break
    return out


__all__ = [
    "STATUS_EMPTY",
    "STATUS_PACKAGE_MISSING",
    "STATUS_READY",
    "STATUS_WAITING",
    "STATUS_WRITTEN",
    "SAFETY_INVARIANTS",
    "MultiHourAgentLoopError",
    "LoopPhase",
    "LoopSession",
    "LoopHumanGate",
    "LoopHandoff",
    "MultiHourAgentLoopResult",
    "build_multi_hour_agent_loop",
    "run_multi_hour_agent_loop",
    "attach_multi_hour_agent_loop_to_bridge_result",
]
