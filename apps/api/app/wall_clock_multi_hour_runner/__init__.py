"""Wall-Clock Multi-Hour Runner - plan/tick-ledger only (beyond multi_hour plan).

Lawful research only:
- Convert multi_hour_agent_loop sessions into a wall-clock schedule + human-gated tick ledger
- Optional offline plan under package inputs/
- Optional export under package _export/wall_clock_multi_hour_runner/ with human flag
- Never auto-ticks, never auto-executes, never exploits/PoCs, never submit/promote
- Never grants ranking/execute permission; never live network validation
- This is NOT a live autonomous runner; ticks require explicit human approval offline
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STATUS_READY = "wall_clock_multi_hour_runner_plan_ready"
STATUS_EMPTY = "wall_clock_multi_hour_runner_empty"
STATUS_PACKAGE_MISSING = "wall_clock_multi_hour_runner_package_missing"
STATUS_WRITTEN = "wall_clock_multi_hour_runner_export_written"
STATUS_WAITING = "wall_clock_multi_hour_runner_waiting_for_signals"

SAFETY_INVARIANTS = [
    "authorized_package_or_bridge_only",
    "no_public_target_scanning",
    "no_network_access",
    "no_raw_secrets_or_user_data",
    "no_automatic_report_submission",
    "no_finding_promotion",
    "no_auto_tick_or_session_execution",
    "wall_clock_schedule_and_tick_ledger_only",
    "human_review_required_before_any_tick",
    "no_export_write_without_human_flag",
    "no_ranking_permission_from_plan",
    "never_live_autonomous_runner",
]

_SECRET_HINTS = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|session|bearer|private[_-]?key|ssh-rsa|BEGIN [A-Z ]*PRIVATE)"
)
_MAX_TICKS = 48
_MAX_SCHEDULE_SLOTS = 32
_MAX_STOP_CONDITIONS = 24
_DEFAULT_TICK_MINUTES = 15
_DEFAULT_WALL_HOURS = 4


class WallClockMultiHourRunnerError(ValueError):
    """Raised when bridge attach receives invalid input."""


@dataclass(frozen=True)
class ScheduleSlot:
    slot_id: str
    sequence: int
    session_id: str
    phase_id: str
    offset_minutes: int
    budget_minutes: int
    goal: str
    human_gate_required: bool = True
    execution_allowed: bool = False
    auto_tick: bool = False


@dataclass(frozen=True)
class TickLedgerEntry:
    tick_id: str
    sequence: int
    session_id: str
    phase_id: str
    offset_minutes: int
    planned_action: str
    requires_human_approval: bool = True
    dry_run_only: bool = True
    execution_allowed: bool = False
    auto_tick: bool = False
    stop_if: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class StopCondition:
    condition_id: str
    name: str
    when: str
    blocks: list[str] = field(default_factory=list)
    auto_resume: bool = False


@dataclass
class WallClockMultiHourRunnerResult:
    stage: str
    inspirations: list[str]
    execution_mode: str
    status: str
    package_id: str = ""
    package_root: str = ""
    wall_clock_hours: float = float(_DEFAULT_WALL_HOURS)
    tick_interval_minutes: int = _DEFAULT_TICK_MINUTES
    schedule: list[ScheduleSlot] = field(default_factory=list)
    schedule_slot_count: int = 0
    tick_ledger: list[TickLedgerEntry] = field(default_factory=list)
    tick_count: int = 0
    stop_conditions: list[StopCondition] = field(default_factory=list)
    stop_condition_count: int = 0
    multi_hour_session_count: int = 0
    multi_hour_phase_count: int = 0
    multi_hour_gate_count: int = 0
    offline_artifact_count: int = 0
    residual_signal_count: int = 0
    human_allow_export_write: bool = False
    export_written: bool = False
    export_count: int = 0
    export_root_relative: str = "_export/wall_clock_multi_hour_runner"
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
        "Human reviews wall-clock tick ledger offline; Mythos never auto-ticks or auto-executes."
    )
    notes: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _force_safety_dict(asdict(self))

def build_wall_clock_multi_hour_runner(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    bridge_result: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> WallClockMultiHourRunnerResult:
    return run_wall_clock_multi_hour_runner(
        package_root=package_root,
        package_id=package_id,
        bridge_result=bridge_result,
        human_allow_export_write=human_allow_export_write,
    )


def run_wall_clock_multi_hour_runner(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    bridge_result: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> WallClockMultiHourRunnerResult:
    """Build plan-only wall-clock schedule + human-gated tick ledger."""
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
    (
        schedule,
        ticks,
        stops,
        residual_n,
        mhal_sessions,
        mhal_phases,
        mhal_gates,
        wall_hours,
        tick_minutes,
    ) = _build_from_signals(
        bridge=bridge,
        offline=offline,
        package_id=pkg_id,
    )

    has_signal = bool(
        schedule or ticks or offline_n or residual_n or mhal_sessions or mhal_phases or bridge
    )
    if not has_signal and not bridge and root is None:
        status = STATUS_EMPTY
    elif not (schedule or ticks) and bridge:
        status = STATUS_WAITING
    elif schedule or ticks:
        status = STATUS_READY
    else:
        status = STATUS_WAITING if bridge or offline_n else STATUS_EMPTY

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    result = WallClockMultiHourRunnerResult(
        stage="wall_clock_multi_hour_runner",
        inspirations=[
            "final_scheme_multi_hour_beyond_plan",
            "multi_hour_agent_loop_session_budget",
            "human_gated_tick_ledger_only",
        ],
        execution_mode="advisory_wall_clock_tick_ledger_only",
        status=status,
        package_id=pkg_id,
        package_root=root_s,
        wall_clock_hours=wall_hours,
        tick_interval_minutes=tick_minutes,
        schedule=schedule,
        schedule_slot_count=len(schedule),
        tick_ledger=ticks,
        tick_count=len(ticks),
        stop_conditions=stops,
        stop_condition_count=len(stops),
        multi_hour_session_count=mhal_sessions,
        multi_hour_phase_count=mhal_phases,
        multi_hour_gate_count=mhal_gates,
        offline_artifact_count=offline_n,
        residual_signal_count=residual_n,
        human_allow_export_write=bool(human_allow_export_write),
        run_stamp=stamp,
        safety_invariants=list(SAFETY_INVARIANTS),
        notes=_notes_for(status, residual_n, mhal_sessions, offline_n, len(ticks)),
        summary=(
            f"status={status} slots={len(schedule)} ticks={len(ticks)} "
            f"stops={len(stops)} wall_h={wall_hours} tick_min={tick_minutes} "
            f"mhal_sessions={mhal_sessions}"
        ),
    )

    if bool(human_allow_export_write) and root is not None and root.is_dir() and (schedule or ticks):
        written, count, rel = _export_plan(root, result, stamp)
        if written:
            result.export_written = True
            result.export_count = count
            result.export_root_relative = rel
            result.status = STATUS_WRITTEN
            result.summary = (
                f"status={STATUS_WRITTEN} slots={len(schedule)} ticks={len(ticks)} "
                f"stops={len(stops)} wall_h={wall_hours} export={rel}"
            )
            result.notes = list(result.notes) + ["export_written_under_human_flag"]

    return result


def attach_wall_clock_multi_hour_runner_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    wall_clock_multi_hour_runner: dict[str, Any] | WallClockMultiHourRunnerResult | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    """Attach wall-clock tick ledger plan; never unlocks execute/submit/promote/tick."""
    if not isinstance(bridge_result, dict):
        raise WallClockMultiHourRunnerError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")

    if isinstance(wall_clock_multi_hour_runner, WallClockMultiHourRunnerResult):
        payload = wall_clock_multi_hour_runner.to_dict()
    elif isinstance(wall_clock_multi_hour_runner, dict):
        payload = _force_safety_dict(dict(wall_clock_multi_hour_runner))
    else:
        payload = run_wall_clock_multi_hour_runner(
            package_root=resolved_root,
            package_id=package_id,
            bridge_result=bridge_result,
            human_allow_export_write=bool(human_allow_export_write),
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["wall_clock_multi_hour_runner"] = payload
    out["wall_clock_multi_hour_runner_present"] = True
    out["wall_clock_multi_hour_runner_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["wall_clock_multi_hour_runner_slot_count"] = int(payload.get("schedule_slot_count") or 0)
    out["wall_clock_multi_hour_runner_tick_count"] = int(payload.get("tick_count") or 0)
    out["wall_clock_multi_hour_runner_stop_count"] = int(payload.get("stop_condition_count") or 0)
    out["wall_clock_multi_hour_runner_export_written"] = bool(payload.get("export_written"))
    out["wall_clock_multi_hour_runner_auto_tick_allowed"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out

def _count_residual_signals(bridge: dict[str, Any]) -> int:
    keys = [
        "multi_hour_agent_loop",
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


def _notes_for(
    status: str,
    residual_n: int,
    mhal_sessions: int,
    offline_n: int,
    tick_n: int,
) -> list[str]:
    notes = [
        "wall_clock_schedule_and_tick_ledger_only",
        "never_auto_tick",
        "never_auto_session_advance",
        "never_live_autonomous_runner",
        f"residual_signals={residual_n}",
        f"multi_hour_sessions={mhal_sessions}",
        f"offline_artifacts={offline_n}",
        f"ticks={tick_n}",
    ]
    if status == STATUS_WAITING:
        notes.append("waiting_for_multi_hour_or_offline_signals")
    if status == STATUS_EMPTY:
        notes.append("no_package_or_bridge_signals")
    return notes


def _load_offline_plan(root: Path | None) -> tuple[dict[str, Any], int]:
    if root is None:
        return {}, 0
    candidates = [
        root / "inputs" / "wall_clock_multi_hour_runner.json",
        root / "inputs" / "wall_clock_multi_hour.json",
        root / "inputs" / "wall_clock_runner.json",
        root / "inputs" / "v4_wall_clock.json",
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
    list[ScheduleSlot],
    list[TickLedgerEntry],
    list[StopCondition],
    int,
    int,
    int,
    int,
    float,
    int,
]:
    del package_id
    residual_n = _count_residual_signals(bridge)
    mhal = bridge.get("multi_hour_agent_loop") if isinstance(bridge.get("multi_hour_agent_loop"), dict) else {}
    sessions = mhal.get("sessions") if isinstance(mhal.get("sessions"), list) else []
    phases = mhal.get("phases") if isinstance(mhal.get("phases"), list) else []
    gates = mhal.get("human_gates") if isinstance(mhal.get("human_gates"), list) else []

    mhal_sessions = int(
        mhal.get("session_count")
        or bridge.get("multi_hour_agent_loop_session_count")
        or len(sessions)
        or 0
    )
    mhal_phases = int(
        mhal.get("phase_count")
        or bridge.get("multi_hour_agent_loop_phase_count")
        or len(phases)
        or 0
    )
    mhal_gates = int(
        mhal.get("human_gate_count")
        or bridge.get("multi_hour_agent_loop_gate_count")
        or len(gates)
        or 0
    )

    wall_hours = float(
        offline.get("wall_clock_hours")
        or mhal.get("wall_clock_hours")
        or _DEFAULT_WALL_HOURS
    )
    tick_minutes = int(offline.get("tick_interval_minutes") or _DEFAULT_TICK_MINUTES)
    if tick_minutes < 5:
        tick_minutes = 5
    if tick_minutes > 60:
        tick_minutes = 60
    if wall_hours < 1:
        wall_hours = 1.0
    if wall_hours > 12:
        wall_hours = 12.0

    offline_schedule = offline.get("schedule") if isinstance(offline.get("schedule"), list) else []
    offline_ticks = offline.get("tick_ledger") if isinstance(offline.get("tick_ledger"), list) else []
    offline_stops = offline.get("stop_conditions") if isinstance(offline.get("stop_conditions"), list) else []

    if offline_schedule or offline_ticks:
        schedule = _schedule_from_offline(offline)
        ticks = _ticks_from_offline(offline)
        stops = _stops_from_offline(offline) if offline_stops else _default_stops()
        if not ticks and schedule:
            ticks = _ticks_from_schedule(schedule, tick_minutes)
        return (
            schedule[:_MAX_SCHEDULE_SLOTS],
            ticks[:_MAX_TICKS],
            stops[:_MAX_STOP_CONDITIONS],
            residual_n,
            mhal_sessions,
            mhal_phases,
            mhal_gates,
            wall_hours,
            tick_minutes,
        )

    schedule: list[ScheduleSlot] = []
    offset = 0
    if sessions:
        for idx, sess in enumerate(sessions, start=1):
            if not isinstance(sess, dict):
                continue
            sid = _clean_text(sess.get("session_id") or f"S-{idx:02d}", 64)
            pid = _clean_text(sess.get("phase_id") or "", 64)
            goal = _clean_text(sess.get("goal") or "session_work", 400)
            budget = int(sess.get("budget_minutes") or mhal.get("session_budget_minutes") or 45)
            if budget < 15:
                budget = 15
            if budget > 180:
                budget = 180
            schedule.append(
                ScheduleSlot(
                    slot_id=f"WC-SLOT-{idx:02d}",
                    sequence=idx,
                    session_id=sid,
                    phase_id=pid,
                    offset_minutes=offset,
                    budget_minutes=budget,
                    goal=goal,
                )
            )
            offset += budget
            if len(schedule) >= _MAX_SCHEDULE_SLOTS:
                break
    elif mhal_sessions > 0:
        session_budget = int(mhal.get("session_budget_minutes") or 45)
        if session_budget < 15:
            session_budget = 15
        if session_budget > 180:
            session_budget = 180
        n = min(mhal_sessions, _MAX_SCHEDULE_SLOTS)
        for idx in range(1, n + 1):
            schedule.append(
                ScheduleSlot(
                    slot_id=f"WC-SLOT-{idx:02d}",
                    sequence=idx,
                    session_id=f"S-{idx:02d}",
                    phase_id=f"PH-{idx:02d}",
                    offset_minutes=(idx - 1) * session_budget,
                    budget_minutes=session_budget,
                    goal=f"multi_hour_session_{idx}_plan_only",
                )
            )
    elif residual_n or bridge:
        session_budget = 45
        for idx, name in enumerate(
            [
                "scope_reaffirm",
                "surface_model",
                "hypothesis_queue",
                "refutation",
                "evidence_prep",
                "knowledge_consolidate",
            ],
            start=1,
        ):
            schedule.append(
                ScheduleSlot(
                    slot_id=f"WC-SLOT-{idx:02d}",
                    sequence=idx,
                    session_id=f"S-{idx:02d}",
                    phase_id=f"PH-{idx:02d}-{name}",
                    offset_minutes=(idx - 1) * session_budget,
                    budget_minutes=session_budget,
                    goal=f"residual_fallback_{name}",
                )
            )

    max_minutes = int(wall_hours * 60)
    capped: list[ScheduleSlot] = []
    for slot in schedule:
        if slot.offset_minutes >= max_minutes and capped:
            break
        budget = min(slot.budget_minutes, max(15, max_minutes - slot.offset_minutes))
        if budget < 15 and capped:
            break
        if budget < 15:
            budget = 15
        capped.append(
            ScheduleSlot(
                slot_id=slot.slot_id,
                sequence=len(capped) + 1,
                session_id=slot.session_id,
                phase_id=slot.phase_id,
                offset_minutes=slot.offset_minutes,
                budget_minutes=budget,
                goal=slot.goal,
            )
        )
    schedule = capped[:_MAX_SCHEDULE_SLOTS]

    ticks = _ticks_from_schedule(schedule, tick_minutes)
    stops = _default_stops()
    if mhal_gates:
        stops = list(stops) + [
            StopCondition(
                condition_id="WC-STOP-mhal-gates",
                name="Align with multi-hour human gates",
                when="any_tick_start",
                blocks=["skip_multi_hour_human_gates"],
            )
        ]

    return (
        schedule[:_MAX_SCHEDULE_SLOTS],
        ticks[:_MAX_TICKS],
        stops[:_MAX_STOP_CONDITIONS],
        residual_n,
        mhal_sessions if mhal_sessions else len(sessions),
        mhal_phases if mhal_phases else len(phases),
        mhal_gates if mhal_gates else len(gates),
        wall_hours,
        tick_minutes,
    )

def _ticks_from_schedule(
    schedule: list[ScheduleSlot],
    tick_minutes: int,
) -> list[TickLedgerEntry]:
    ticks: list[TickLedgerEntry] = []
    seq = 0
    for slot in schedule:
        remaining = slot.budget_minutes
        local_offset = 0
        tick_in_session = 0
        while remaining > 0 and seq < _MAX_TICKS:
            seq += 1
            tick_in_session += 1
            chunk = min(tick_minutes, remaining)
            if tick_in_session == 1:
                action = (
                    f"human_approve_then_start_session:{slot.session_id} "
                    f"goal={slot.goal}"
                )
            elif remaining - chunk <= 0:
                action = (
                    f"human_approve_then_close_session:{slot.session_id} "
                    f"handoff_notes_only"
                )
            else:
                action = (
                    f"human_approve_then_continue_session:{slot.session_id} "
                    f"minute_window={local_offset}-{local_offset + chunk}"
                )
            ticks.append(
                TickLedgerEntry(
                    tick_id=f"WC-TICK-{seq:02d}",
                    sequence=seq,
                    session_id=slot.session_id,
                    phase_id=slot.phase_id,
                    offset_minutes=slot.offset_minutes + local_offset,
                    planned_action=_clean_text(action, 400),
                    stop_if=[
                        "human_gate_required",
                        "human_approval_missing",
                        "budget_minutes_exhausted",
                        "scope_uncertainty",
                        "unsafe_permission_request",
                        "wall_clock_exhausted",
                    ],
                )
            )
            remaining -= chunk
            local_offset += chunk
    return ticks


def _default_stops() -> list[StopCondition]:
    return [
        StopCondition(
            condition_id="WC-STOP-01-scope",
            name="Stop on scope uncertainty",
            when="any_tick",
            blocks=["continue_without_scope"],
        ),
        StopCondition(
            condition_id="WC-STOP-02-human",
            name="Stop until human approves next tick",
            when="before_every_tick",
            blocks=["auto_tick"],
        ),
        StopCondition(
            condition_id="WC-STOP-03-budget",
            name="Stop when wall-clock budget exhausted",
            when="wall_clock_hours_exhausted",
            blocks=["extend_without_human"],
        ),
        StopCondition(
            condition_id="WC-STOP-04-unsafe",
            name="Stop on unsafe permission request",
            when="permission_escalation_requested",
            blocks=["execute", "submit", "promote", "network"],
        ),
        StopCondition(
            condition_id="WC-STOP-05-end",
            name="Final human review; no auto next-day run",
            when="after_last_tick",
            blocks=["auto_next_day_tick"],
        ),
    ]


def _schedule_from_offline(offline: dict[str, Any]) -> list[ScheduleSlot]:
    rows = offline.get("schedule") if isinstance(offline.get("schedule"), list) else []
    out: list[ScheduleSlot] = []
    for idx, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            continue
        out.append(
            ScheduleSlot(
                slot_id=_clean_text(row.get("slot_id") or f"WC-SLOT-{idx:02d}", 64),
                sequence=int(row.get("sequence") or idx),
                session_id=_clean_text(row.get("session_id") or f"S-{idx:02d}", 64),
                phase_id=_clean_text(row.get("phase_id") or "", 64),
                offset_minutes=max(0, int(row.get("offset_minutes") or 0)),
                budget_minutes=max(15, min(180, int(row.get("budget_minutes") or 45))),
                goal=_clean_text(row.get("goal") or "offline_slot", 400),
            )
        )
        if len(out) >= _MAX_SCHEDULE_SLOTS:
            break
    return out


def _ticks_from_offline(offline: dict[str, Any]) -> list[TickLedgerEntry]:
    rows = offline.get("tick_ledger") if isinstance(offline.get("tick_ledger"), list) else []
    out: list[TickLedgerEntry] = []
    for idx, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            continue
        out.append(
            TickLedgerEntry(
                tick_id=_clean_text(row.get("tick_id") or f"WC-TICK-{idx:02d}", 64),
                sequence=int(row.get("sequence") or idx),
                session_id=_clean_text(row.get("session_id") or "", 64),
                phase_id=_clean_text(row.get("phase_id") or "", 64),
                offset_minutes=max(0, int(row.get("offset_minutes") or 0)),
                planned_action=_clean_text(row.get("planned_action") or "human_gated_tick", 400),
                stop_if=_str_list(row.get("stop_if"), 8)
                or [
                    "human_gate_required",
                    "human_approval_missing",
                    "budget_minutes_exhausted",
                ],
            )
        )
        if len(out) >= _MAX_TICKS:
            break
    return out


def _stops_from_offline(offline: dict[str, Any]) -> list[StopCondition]:
    rows = offline.get("stop_conditions") if isinstance(offline.get("stop_conditions"), list) else []
    out: list[StopCondition] = []
    for idx, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            continue
        out.append(
            StopCondition(
                condition_id=_clean_text(row.get("condition_id") or f"WC-STOP-{idx:02d}", 64),
                name=_clean_text(row.get("name") or "stop", 120),
                when=_clean_text(row.get("when") or "any_tick", 120),
                blocks=_str_list(row.get("blocks"), 8),
            )
        )
        if len(out) >= _MAX_STOP_CONDITIONS:
            break
    return out


def _export_plan(
    root: Path,
    result: WallClockMultiHourRunnerResult,
    stamp: str,
) -> tuple[bool, int, str]:
    try:
        export_root = root / "_export" / "wall_clock_multi_hour_runner" / stamp
        export_root.mkdir(parents=True, exist_ok=True)
        payload = result.to_dict()
        files = {
            "plan.json": {
                "status": payload.get("status"),
                "package_id": payload.get("package_id"),
                "wall_clock_hours": payload.get("wall_clock_hours"),
                "tick_interval_minutes": payload.get("tick_interval_minutes"),
                "schedule": payload.get("schedule"),
                "stop_conditions": payload.get("stop_conditions"),
                "execution_allowed": False,
                "auto_tick_allowed": False,
                "report_submission_allowed": False,
            },
            "tick_ledger.json": {
                "tick_count": payload.get("tick_count"),
                "tick_ledger": payload.get("tick_ledger"),
                "execution_allowed": False,
                "auto_tick_allowed": False,
                "dry_run_only": True,
            },
            "summary.json": {
                "status": payload.get("status"),
                "schedule_slot_count": payload.get("schedule_slot_count"),
                "tick_count": payload.get("tick_count"),
                "stop_condition_count": payload.get("stop_condition_count"),
                "wall_clock_hours": payload.get("wall_clock_hours"),
                "tick_interval_minutes": payload.get("tick_interval_minutes"),
                "multi_hour_session_count": payload.get("multi_hour_session_count"),
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
        rel = f"_export/wall_clock_multi_hour_runner/{stamp}"
        return True, len(files), rel
    except OSError:
        return False, 0, "_export/wall_clock_multi_hour_runner"


def _empty(
    *,
    status: str,
    package_id: str = "",
    package_root: str = "",
    notes: list[str] | None = None,
    human_allow_export_write: bool = False,
) -> WallClockMultiHourRunnerResult:
    return WallClockMultiHourRunnerResult(
        stage="wall_clock_multi_hour_runner",
        inspirations=["final_scheme_multi_hour_beyond_plan"],
        execution_mode="advisory_wall_clock_tick_ledger_only",
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
    out["execution_mode"] = "advisory_wall_clock_tick_ledger_only"
    for key in ("schedule", "tick_ledger", "stop_conditions"):
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
            if "auto_resume" in row:
                row["auto_resume"] = False
            if "requires_human_approval" in row or key == "tick_ledger":
                row["requires_human_approval"] = True
            if "dry_run_only" in row or key == "tick_ledger":
                row["dry_run_only"] = True
            if "human_gate_required" in row or key == "schedule":
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
    "WallClockMultiHourRunnerError",
    "ScheduleSlot",
    "TickLedgerEntry",
    "StopCondition",
    "WallClockMultiHourRunnerResult",
    "build_wall_clock_multi_hour_runner",
    "run_wall_clock_multi_hour_runner",
    "attach_wall_clock_multi_hour_runner_to_bridge_result",
]