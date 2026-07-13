from pathlib import Path

from app.agent_memory import (
    STATUS_EMPTY,
    STATUS_READY,
    STATUS_WRITTEN,
    attach_agent_memory_to_bridge_result,
    run_agent_memory,
)
from app.industrial_scheduler import build_industrial_scheduler_plan
from app.multi_engine_verifier import (
    ENGINE_AGENT_MEMORY,
    build_multi_engine_verdict,
    signal_from_agent_memory,
)


def _safe_bridge(**extra):
    base = {
        "package_id": "demo-pkg",
        "submission_blocked": True,
        "report_submission_allowed": False,
        "execution_allowed": False,
        "validation_allowed": False,
        "confirmed_vulnerability": False,
        "drafts": [
            {
                "candidate_id": "H-001",
                "root_cause_id": "RC-ssrf",
                "vuln_type": "ssrf",
                "submission_blocked": True,
                "confirmed_vulnerability": False,
            }
        ],
        "human_residual_gates": [
            {
                "candidate_id": "H-001",
                "status": "ready_for_human_review",
                "report_submission_allowed": False,
                "execution_allowed": False,
                "confirmed_vulnerability": False,
            },
            {
                "candidate_id": "H-002",
                "status": "human_rejected_or_fp",
                "false_positive_reason": "out of scope test fixture",
                "report_submission_allowed": False,
                "execution_allowed": False,
                "confirmed_vulnerability": False,
            },
        ],
        "multi_engine_verdicts": [
            {
                "candidate_id": "H-001",
                "status": "needs_human_review",
                "confirmed_vulnerability": False,
                "execution_allowed": False,
            }
        ],
        "multi_engine_deep": True,
        "residual_checklist_present": True,
    }
    base.update(extra)
    return base


def test_agent_memory_derives_from_bridge():
    result = run_agent_memory(bridge_result=_safe_bridge())
    assert result.status == STATUS_READY
    assert result.entry_count >= 2
    assert result.false_positive_pattern_count >= 1
    assert result.retain_signal_count >= 1
    assert result.candidate_hint_count >= 1
    assert result.execution_allowed is False
    assert result.report_submission_allowed is False
    assert result.confirmed_vulnerability is False
    assert result.ranking_permission_granted is False
    assert result.finding_promotion_allowed is False
    for hint in result.candidate_hints:
        assert hint.action_hint == "human_review_priority_only"
        assert hint.execution_allowed is False
        assert hint.report_submission_allowed is False


def test_agent_memory_offline_artifact(tmp_path: Path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "agent_memory.json").write_text(
        """
{
  "entries": [
    {
      "entry_id": "mem-offline-1",
      "kind": "knowledge_pattern",
      "topic": "ssrf-redirect-chain",
      "summary": "Prefer checking redirect allowlist before SSRF retain.",
      "source_ref": "inputs/agent_memory.json",
      "confidence": "medium",
      "applies_to": ["ssrf"]
    }
  ]
}
""".strip(),
        encoding="utf-8",
    )
    result = run_agent_memory(
        package_root=tmp_path,
        package_id="demo-pkg",
        bridge_result=_safe_bridge(),
    )
    assert result.status == STATUS_READY
    assert result.offline_artifact_count >= 1
    assert result.knowledge_pattern_count >= 1
    kinds = {e.kind for e in result.entries}
    assert "knowledge_pattern" in kinds
    assert result.execution_allowed is False


def test_agent_memory_scrubs_secret_like_text(tmp_path: Path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "memory.json").write_text(
        """
{
  "entries": [
    {
      "entry_id": "mem-secret",
      "kind": "retain_signal",
      "topic": "auth",
      "summary": "token=supersecretvalue must never be stored raw",
      "source_ref": "inputs/memory.json"
    }
  ]
}
""".strip(),
        encoding="utf-8",
    )
    result = run_agent_memory(package_root=tmp_path, bridge_result=_safe_bridge())
    blob = " ".join(e.summary for e in result.entries)
    assert "supersecretvalue" not in blob
    assert "[redacted]" in blob or "redact" in blob.lower() or "[REDACTED]" in blob or "REDACTED" in blob.upper() or "***" in blob


def test_export_under_package(tmp_path: Path):
    result = run_agent_memory(
        package_root=tmp_path,
        package_id="demo-pkg",
        bridge_result=_safe_bridge(),
        human_allow_export_write=True,
    )
    assert result.status == STATUS_WRITTEN
    assert result.export_written is True
    assert result.export_count >= 1
    export_root = tmp_path / "_export" / "agent_memory"
    assert export_root.is_dir()
    stamps = list(export_root.iterdir())
    assert stamps
    assert (stamps[0] / "index.json").is_file()
    assert (stamps[0] / "README.md").is_file()


def test_bridge_attach_forces_safety():
    bridge = _safe_bridge(
        execution_allowed=True,
        report_submission_allowed=True,
        confirmed_vulnerability=True,
        submission_blocked=False,
    )
    out = attach_agent_memory_to_bridge_result(bridge)
    assert out["agent_memory_present"] is True
    assert out["execution_allowed"] is False
    assert out["validation_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert out["submission_blocked"] is True
    assert out["agent_memory_ranking_permission_granted"] is False
    assert out["agent_memory"]["ranking_permission_granted"] is False
    assert out["agent_memory"]["report_submission_allowed"] is False


def test_empty_without_signals():
    result = run_agent_memory(bridge_result={"package_id": "empty"})
    assert result.status in {STATUS_EMPTY, STATUS_READY}
    assert result.execution_allowed is False
    assert result.ranking_permission_granted is False


def test_mev_signal_and_engine():
    payload = run_agent_memory(bridge_result=_safe_bridge()).to_dict()
    sig = signal_from_agent_memory(payload)
    assert sig is not None
    assert sig["status"] == "ready"
    unsafe = signal_from_agent_memory({**payload, "ranking_permission_granted": True})
    assert unsafe["status"] == "blocked"
    verdict = build_multi_engine_verdict(
        candidate={"candidate_id": "H-001"},
        agent_memory_signal=sig,
    )
    engines = {e.engine for e in verdict.engines}
    assert ENGINE_AGENT_MEMORY in engines
    assert verdict.confirmed_vulnerability is False
    assert verdict.execution_allowed is False
    assert verdict.report_submission_allowed is False


def test_scheduler_includes_t010():
    plan = build_industrial_scheduler_plan(
        {
            "scope": {"allowed": True, "reason": "authorized local repository"},
            "hypotheses": [],
            "crs_fuzzing": {"parser_candidates": [{"symbol_name": "decode_frame"}]},
            "authorized_bug_bounty": {"human_gate": {"status": "required"}},
        }
    )
    task_by_id = {task.task_id: task for task in plan.dag_tasks}
    assert "T-010" in task_by_id
    assert task_by_id["T-010"].agent == "agent_memory_agent"
    assert task_by_id["T-010"].execution_allowed is False
    assert task_by_id["T-010"].requires_human_review is True
    assert "T-009" in task_by_id["T-010"].depends_on
    assert "T-007" in task_by_id["T-010"].depends_on
    batches = {b.batch_id: b.task_ids for b in plan.parallel_batches}
    assert batches.get("B-007") == ["T-010"]
    assert "candidate_rank_hint" in plan.agent_memory.retained_signals
