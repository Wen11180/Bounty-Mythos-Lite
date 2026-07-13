from pathlib import Path

from app.multi_hour_agent_loop import (
    STATUS_EMPTY,
    STATUS_PACKAGE_MISSING,
    STATUS_READY,
    STATUS_WRITTEN,
    STATUS_WAITING,
    attach_multi_hour_agent_loop_to_bridge_result,
    build_multi_hour_agent_loop,
    run_multi_hour_agent_loop,
)
from app.industrial_scheduler import build_industrial_scheduler_plan
from app.multi_engine_verifier import (
    ENGINE_MULTI_HOUR_AGENT_LOOP,
    build_multi_engine_verdict,
    signal_from_multi_hour_agent_loop,
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
        "knowledge_base": {
            "status": "knowledge_base_ready",
            "pattern_count": 5,
            "execution_allowed": False,
            "ranking_permission_granted": False,
        },
        "knowledge_base_pattern_count": 5,
        "long_horizon": {
            "status": "long_horizon_plan_ready",
            "path_count": 4,
            "iteration_count": 3,
        },
        "long_horizon_path_count": 4,
        "deep_research": {"status": "deep_research_plan_ready", "chain_count": 1},
        "deep_research_chain_count": 1,
        "human_gate_dry_run": {"status": "human_gate_dry_run_ready"},
        "agent_memory": {"status": "agent_memory_ready", "entry_count": 2},
    }
    base.update(extra)
    return base


def test_run_multi_hour_from_bridge_signals():
    result = run_multi_hour_agent_loop(bridge_result=_safe_bridge())
    assert result.status == STATUS_READY
    assert result.execution_mode == "advisory_multi_session_plan_only"
    assert result.phase_count >= 6
    assert result.session_count >= 6
    assert result.human_gate_count >= 4
    assert result.handoff_count >= 5
    assert result.execution_allowed is False
    assert result.auto_tick_allowed is False
    assert result.auto_session_advance_allowed is False
    assert result.ranking_permission_granted is False
    assert result.report_submission_allowed is False
    assert result.confirmed_vulnerability is False
    assert all(s.execution_allowed is False for s in result.sessions)
    assert all(s.auto_tick is False for s in result.sessions)
    assert all(s.human_gate_required is True for s in result.sessions)
    payload = result.to_dict()
    assert payload["auto_tick_allowed"] is False
    assert payload["execution_allowed"] is False


def test_build_alias():
    result = build_multi_hour_agent_loop(bridge_result=_safe_bridge())
    assert result.status == STATUS_READY
    assert result.session_count >= 1


def test_package_missing(tmp_path: Path):
    missing = tmp_path / "nope"
    result = run_multi_hour_agent_loop(package_root=missing, package_id="x")
    assert result.status == STATUS_PACKAGE_MISSING
    assert result.execution_allowed is False


def test_offline_plan(tmp_path: Path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "multi_hour_agent_loop.json").write_text(
        """{
          "wall_clock_hours": 3,
          "session_budget_minutes": 30,
          "phases": [
            {"phase_id": "PH-A", "name": "A", "purpose": "scope", "estimated_minutes": 25}
          ],
          "sessions": [
            {
              "session_id": "S-A",
              "phase_id": "PH-A",
              "goal": "offline goal",
              "budget_minutes": 30,
              "max_tool_calls": 5
            }
          ],
          "human_gates": [
            {"gate_id": "G1", "name": "scope", "when": "start", "required_artifacts": ["policy"]}
          ],
          "handoffs": [
            {
              "handoff_id": "H1",
              "from_session_id": "S-A",
              "to_session_id": "S-END-human-review",
              "reason": "done"
            }
          ]
        }
        """,
        encoding="utf-8",
    )
    result = run_multi_hour_agent_loop(package_root=tmp_path, package_id="off")
    assert result.status == STATUS_READY
    assert result.phase_count == 1
    assert result.session_count == 1
    assert result.wall_clock_hours == 3
    assert result.session_budget_minutes == 30
    assert result.human_gate_count == 1
    assert result.handoff_count == 1


def test_export_write(tmp_path: Path):
    result = run_multi_hour_agent_loop(
        package_root=tmp_path,
        package_id="exp",
        bridge_result=_safe_bridge(),
        human_allow_export_write=True,
    )
    assert result.status == STATUS_WRITTEN
    assert result.export_written is True
    assert result.export_count >= 3
    export_root = tmp_path / "_export" / "multi_hour_agent_loop"
    assert export_root.is_dir()
    stamps = list(export_root.iterdir())
    assert stamps
    assert (stamps[0] / "plan.json").is_file()


def test_attach_forces_safety():
    out = attach_multi_hour_agent_loop_to_bridge_result(
        {
            "package_id": "p",
            "submission_blocked": False,
            "execution_allowed": True,
            "knowledge_base": {"status": "knowledge_base_ready", "pattern_count": 1},
        }
    )
    assert out["submission_blocked"] is True
    assert out["execution_allowed"] is False
    assert out["multi_hour_agent_loop_present"] is True
    assert out["multi_hour_agent_loop_status"] == STATUS_READY
    assert out["multi_hour_agent_loop_session_count"] >= 1
    assert out["multi_hour_agent_loop"]["auto_tick_allowed"] is False
    assert out["multi_hour_agent_loop"]["ranking_permission_granted"] is False


def test_unsafe_signal_blocked():
    sig = signal_from_multi_hour_agent_loop(
        {
            "status": "multi_hour_agent_loop_plan_ready",
            "session_count": 2,
            "auto_tick_allowed": True,
        }
    )
    assert sig is not None
    assert sig["status"] == "blocked"


def test_mev_includes_engine():
    sig = signal_from_multi_hour_agent_loop(
        {
            "status": "multi_hour_agent_loop_plan_ready",
            "session_count": 6,
            "phase_count": 6,
            "execution_allowed": False,
        }
    )
    verdict = build_multi_engine_verdict(
        candidate={"candidate_id": "c1"},
        multi_hour_agent_loop_signal=sig,
    )
    engines = [e.engine for e in verdict.engines]
    assert ENGINE_MULTI_HOUR_AGENT_LOOP in engines
    assert verdict.execution_allowed is False


def test_scheduler_has_t016():
    plan = build_industrial_scheduler_plan({"scope": {"allowed": True}})
    ids = {t.task_id for t in plan.dag_tasks}
    assert "T-016" in ids
    batches = {b.batch_id: b.task_ids for b in plan.parallel_batches}
    assert batches.get("B-013") == ["T-016"]
    assert plan.multi_hour_agent_loop.mode == "advisory_multi_session_plan_only"
    assert plan.multi_hour_agent_loop.auto_tick_allowed is False
    assert plan.multi_hour_agent_loop.execution_allowed is False
    t016 = next(t for t in plan.dag_tasks if t.task_id == "T-016")
    assert t016.execution_allowed is False
    assert t016.requires_human_review is True
    assert "T-015" in t016.depends_on


def test_empty_without_signals():
    result = run_multi_hour_agent_loop()
    assert result.status in {STATUS_EMPTY, STATUS_READY, STATUS_WAITING}
    assert result.execution_allowed is False
    assert result.auto_tick_allowed is False
