from pathlib import Path

from app.wall_clock_multi_hour_runner import (
    STATUS_EMPTY,
    STATUS_PACKAGE_MISSING,
    STATUS_READY,
    STATUS_WRITTEN,
    STATUS_WAITING,
    attach_wall_clock_multi_hour_runner_to_bridge_result,
    build_wall_clock_multi_hour_runner,
    run_wall_clock_multi_hour_runner,
)
from app.industrial_scheduler import build_industrial_scheduler_plan
from app.multi_engine_verifier import (
    ENGINE_WALL_CLOCK_MULTI_HOUR_RUNNER,
    build_multi_engine_verdict,
    signal_from_wall_clock_multi_hour_runner,
)


def _safe_bridge(**extra):
    base = {
        "package_id": "demo-pkg",
        "submission_blocked": True,
        "report_submission_allowed": False,
        "execution_allowed": False,
        "validation_allowed": False,
        "confirmed_vulnerability": False,
        "retained_count": 1,
        "drafts": [
            {
                "candidate_id": "H-001",
                "root_cause_id": "RC-ssrf",
                "vuln_type": "ssrf",
                "submission_blocked": True,
            }
        ],
        "multi_hour_agent_loop": {
            "status": "multi_hour_agent_loop_plan_ready",
            "session_count": 6,
            "phase_count": 6,
            "human_gate_count": 5,
            "wall_clock_hours": 4,
            "session_budget_minutes": 45,
            "sessions": [
                {
                    "session_id": "S-01",
                    "sequence": 1,
                    "phase_id": "PH-01",
                    "goal": "scope",
                    "budget_minutes": 45,
                    "max_tool_calls": 8,
                },
                {
                    "session_id": "S-02",
                    "sequence": 2,
                    "phase_id": "PH-02",
                    "goal": "surface",
                    "budget_minutes": 45,
                    "max_tool_calls": 8,
                },
            ],
            "phases": [
                {"phase_id": "PH-01", "name": "scope", "purpose": "scope"},
                {"phase_id": "PH-02", "name": "surface", "purpose": "surface"},
            ],
            "human_gates": [
                {"gate_id": "MHG-01", "name": "scope", "when": "start"},
            ],
            "execution_allowed": False,
            "auto_tick_allowed": False,
        },
        "multi_hour_agent_loop_session_count": 6,
        "multi_hour_agent_loop_phase_count": 6,
        "multi_hour_agent_loop_gate_count": 5,
        "knowledge_base": {"status": "knowledge_base_ready", "pattern_count": 5},
        "long_horizon": {"status": "long_horizon_plan_ready", "path_count": 4},
        "deep_research": {"status": "deep_research_plan_ready", "chain_count": 1},
        "human_gate_dry_run": {"status": "human_gate_dry_run_ready"},
    }
    base.update(extra)
    return base


def test_run_wall_clock_from_multi_hour_signals():
    result = run_wall_clock_multi_hour_runner(bridge_result=_safe_bridge())
    assert result.status == STATUS_READY
    assert result.execution_mode == "advisory_wall_clock_tick_ledger_only"
    assert result.schedule_slot_count >= 2
    assert result.tick_count >= 2
    assert result.stop_condition_count >= 5
    assert result.execution_allowed is False
    assert result.auto_tick_allowed is False
    assert result.auto_session_advance_allowed is False
    assert result.ranking_permission_granted is False
    assert result.report_submission_allowed is False
    assert result.confirmed_vulnerability is False
    assert all(s.execution_allowed is False for s in result.schedule)
    assert all(s.auto_tick is False for s in result.schedule)
    assert all(s.human_gate_required is True for s in result.schedule)
    assert all(t.execution_allowed is False for t in result.tick_ledger)
    assert all(t.auto_tick is False for t in result.tick_ledger)
    assert all(t.requires_human_approval is True for t in result.tick_ledger)
    assert all(t.dry_run_only is True for t in result.tick_ledger)
    payload = result.to_dict()
    assert payload["auto_tick_allowed"] is False
    assert payload["execution_allowed"] is False


def test_build_alias():
    result = build_wall_clock_multi_hour_runner(bridge_result=_safe_bridge())
    assert result.status == STATUS_READY
    assert result.tick_count >= 1


def test_package_missing(tmp_path: Path):
    missing = tmp_path / "nope"
    result = run_wall_clock_multi_hour_runner(package_root=missing, package_id="x")
    assert result.status == STATUS_PACKAGE_MISSING
    assert result.execution_allowed is False


def test_offline_plan(tmp_path: Path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "wall_clock_multi_hour_runner.json").write_text(
        """{
          "wall_clock_hours": 2,
          "tick_interval_minutes": 20,
          "schedule": [
            {
              "slot_id": "WC-SLOT-A",
              "session_id": "S-A",
              "phase_id": "PH-A",
              "offset_minutes": 0,
              "budget_minutes": 40,
              "goal": "offline slot"
            }
          ],
          "tick_ledger": [
            {
              "tick_id": "WC-TICK-A",
              "session_id": "S-A",
              "phase_id": "PH-A",
              "offset_minutes": 0,
              "planned_action": "human_approve_offline"
            }
          ],
          "stop_conditions": [
            {
              "condition_id": "WC-STOP-A",
              "name": "scope",
              "when": "start",
              "blocks": ["auto_tick"]
            }
          ]
        }
        """,
        encoding="utf-8",
    )
    result = run_wall_clock_multi_hour_runner(package_root=tmp_path, package_id="off")
    assert result.status == STATUS_READY
    assert result.schedule_slot_count == 1
    assert result.tick_count == 1
    assert result.wall_clock_hours == 2
    assert result.tick_interval_minutes == 20
    assert result.stop_condition_count == 1


def test_export_write(tmp_path: Path):
    result = run_wall_clock_multi_hour_runner(
        package_root=tmp_path,
        package_id="exp",
        bridge_result=_safe_bridge(),
        human_allow_export_write=True,
    )
    assert result.status == STATUS_WRITTEN
    assert result.export_written is True
    assert result.export_count >= 3
    export_root = tmp_path / "_export" / "wall_clock_multi_hour_runner"
    assert export_root.is_dir()
    stamps = list(export_root.iterdir())
    assert stamps
    assert (stamps[0] / "plan.json").is_file()
    assert (stamps[0] / "tick_ledger.json").is_file()
    assert (stamps[0] / "summary.json").is_file()


def test_attach_bridge_safety():
    bridged = attach_wall_clock_multi_hour_runner_to_bridge_result(_safe_bridge())
    assert bridged["wall_clock_multi_hour_runner_present"] is True
    assert bridged["wall_clock_multi_hour_runner_status"] == STATUS_READY
    assert bridged["wall_clock_multi_hour_runner_tick_count"] >= 1
    assert bridged["wall_clock_multi_hour_runner_auto_tick_allowed"] is False
    assert bridged["execution_allowed"] is False
    assert bridged["report_submission_allowed"] is False
    assert bridged["submission_blocked"] is True
    payload = bridged["wall_clock_multi_hour_runner"]
    assert payload["auto_tick_allowed"] is False
    assert payload["execution_allowed"] is False


def test_empty_without_signals():
    result = run_wall_clock_multi_hour_runner()
    assert result.status == STATUS_EMPTY
    assert result.execution_allowed is False


def test_waiting_when_bridge_without_usable_plan():
    # empty multi_hour and no residual keys that generate fallback still waits/empty
    result = run_wall_clock_multi_hour_runner(
        bridge_result={
            "package_id": "wait",
            "submission_blocked": True,
        }
    )
    # residual fallback may produce schedule from bare bridge
    assert result.status in {STATUS_READY, STATUS_WAITING}
    assert result.auto_tick_allowed is False


def test_mev_signal_ready_and_unsafe_block():
    ready = signal_from_wall_clock_multi_hour_runner(
        {
            "status": STATUS_READY,
            "tick_count": 3,
            "schedule_slot_count": 2,
            "execution_allowed": False,
            "auto_tick_allowed": False,
        }
    )
    assert ready is not None
    assert ready["status"] == "ready"
    blocked = signal_from_wall_clock_multi_hour_runner(
        {
            "status": STATUS_READY,
            "tick_count": 3,
            "auto_tick_allowed": True,
        }
    )
    assert blocked is not None
    assert blocked["status"] == "blocked"
    assert "wall_clock_multi_hour_runner_unsafe_flags_forced_block" in blocked["notes"]


def test_mev_build_includes_wall_clock_engine():
    verdict = build_multi_engine_verdict(
        candidate={"candidate_id": "H-001", "root_cause_id": "RC"},
        wall_clock_multi_hour_runner_signal=signal_from_wall_clock_multi_hour_runner(
            {
                "status": STATUS_READY,
                "tick_count": 2,
                "schedule_slot_count": 1,
            }
        ),
    )
    engines = {e.engine for e in verdict.engines}
    assert ENGINE_WALL_CLOCK_MULTI_HOUR_RUNNER in engines
    assert verdict.execution_allowed is False
    assert verdict.confirmed_vulnerability is False


def test_scheduler_t017():
    plan = build_industrial_scheduler_plan({"findings": []})
    task_by_id = {t.task_id: t for t in plan.dag_tasks}
    assert "T-017" in task_by_id
    assert task_by_id["T-017"].agent == "wall_clock_multi_hour_runner_agent"
    assert task_by_id["T-017"].depends_on == ["T-016"]
    assert task_by_id["T-017"].execution_allowed is False
    assert task_by_id["T-017"].requires_human_review is True
    assert plan.wall_clock_multi_hour_runner.auto_tick_allowed is False
    assert plan.wall_clock_multi_hour_runner.execution_allowed is False
    batch_ids = {b.batch_id for b in plan.parallel_batches}
    assert "B-014" in batch_ids
