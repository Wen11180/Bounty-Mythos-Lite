from pathlib import Path

from app.finding_dedup_risk import (
    STATUS_EMPTY,
    STATUS_READY,
    STATUS_WRITTEN,
    attach_finding_dedup_risk_to_bridge_result,
    run_finding_dedup_risk,
)
from app.industrial_scheduler import build_industrial_scheduler_plan
from app.multi_engine_verifier import (
    ENGINE_FINDING_DEDUP_RISK,
    build_multi_engine_verdict,
    signal_from_finding_dedup_risk,
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
                "affected_code_path": "src/fetch.ts",
                "severity": "high",
                "confidence": "high",
                "source_fact_refs": ["code:src/fetch.ts:validateUrl"],
                "submission_blocked": True,
                "confirmed_vulnerability": False,
            },
            {
                "candidate_id": "H-002",
                "root_cause_id": "RC-ssrf",
                "vuln_type": "ssrf",
                "affected_code_path": "src/fetch.ts",
                "severity": "high",
                "confidence": "medium",
                "source_fact_refs": ["code:src/fetch.ts:validateUrl"],
                "submission_blocked": True,
                "confirmed_vulnerability": False,
            },
            {
                "candidate_id": "H-003",
                "root_cause_id": "RC-idor",
                "vuln_type": "idor",
                "affected_code_path": "src/user.ts",
                "severity": "medium",
                "confidence": "low",
                "submission_blocked": True,
                "confirmed_vulnerability": False,
            },
        ],
        "human_residual_gates": [
            {
                "candidate_id": "H-001",
                "status": "ready_for_human_review",
                "report_submission_allowed": False,
                "execution_allowed": False,
                "confirmed_vulnerability": False,
            }
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


def test_finding_dedup_clusters_duplicates():
    result = run_finding_dedup_risk(bridge_result=_safe_bridge())
    assert result.status == STATUS_READY
    assert result.seed_count >= 3
    assert result.cluster_count >= 2
    # H-001 and H-002 share component+type+root_cause+evidence
    multi = [c for c in result.clusters if c.member_count >= 2]
    assert multi, "expected at least one multi-member cluster"
    assert result.risk_queue_count >= 3
    assert result.risk_queue[0].priority == 1
    assert result.execution_allowed is False
    assert result.finding_promotion_allowed is False
    assert result.ranking_permission_granted is False
    assert result.report_submission_allowed is False
    assert result.network_access is False
    for item in result.risk_queue:
        assert item.ranking_permission_granted is False
        assert item.execution_allowed is False
        assert item.human_review_only is True


def test_finding_dedup_offline_hints(tmp_path: Path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "finding_dedup.json").write_text(
        """
{
  "findings": [
    {
      "finding_id": "OFF-1",
      "vuln_type": "path_traversal",
      "affected_component": "files/store.py",
      "root_cause_id": "RC-path",
      "evidence_ref": "code:files/store.py:join",
      "severity": "critical",
      "confidence": "high"
    }
  ]
}
""".strip(),
        encoding="utf-8",
    )
    result = run_finding_dedup_risk(
        package_root=tmp_path,
        package_id="demo-pkg",
        bridge_result=_safe_bridge(),
    )
    assert result.status == STATUS_READY
    assert result.offline_artifact_present is True
    assert result.offline_hint_count >= 1
    ids = {s.seed_id for s in result.seeds}
    assert "OFF-1" in ids
    assert result.execution_allowed is False


def test_finding_dedup_scrubs_secrets(tmp_path: Path):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    (inputs / "risk_prioritization.json").write_text(
        """
{
  "findings": [
    {
      "finding_id": "SEC-1",
      "vuln_type": "ssrf",
      "title": "token=supersecretvalue",
      "affected_component": "api",
      "severity": "low"
    }
  ]
}
""".strip(),
        encoding="utf-8",
    )
    result = run_finding_dedup_risk(
        package_root=tmp_path,
        bridge_result=_safe_bridge(drafts=[]),
    )
    titles = [s.title for s in result.seeds if s.seed_id == "SEC-1"]
    assert titles
    assert "supersecretvalue" not in titles[0]
    assert titles[0] == "[redacted]"


def test_export_under_package(tmp_path: Path):
    result = run_finding_dedup_risk(
        package_root=tmp_path,
        package_id="demo-pkg",
        bridge_result=_safe_bridge(),
        human_allow_export_write=True,
    )
    assert result.status == STATUS_WRITTEN
    assert result.export_written is True
    export = tmp_path / "_export" / "finding_dedup_risk"
    assert (export / "plan.json").is_file()
    assert (export / "clusters.md").is_file()
    assert (export / "risk_queue.md").is_file()


def test_attach_forces_submission_blocked():
    out = attach_finding_dedup_risk_to_bridge_result(
        _safe_bridge(submission_blocked=False)
    )
    assert out["submission_blocked"] is True
    assert out["finding_dedup_risk_present"] is True
    assert out["finding_dedup_risk_cluster_count"] >= 1
    assert out["execution_allowed"] is False
    assert out["ranking_permission_granted"] is False
    payload = out["finding_dedup_risk"]
    assert payload["execution_allowed"] is False
    assert payload["ranking_permission_granted"] is False


def test_unsafe_payload_forced_safe():
    out = attach_finding_dedup_risk_to_bridge_result(
        _safe_bridge(),
        finding_dedup_risk={
            "status": "finding_dedup_risk_plan_ready",
            "cluster_count": 1,
            "risk_queue_count": 1,
            "seed_count": 1,
            "clusters": [{"cluster_id": "C1", "seed_ids": ["H-001"]}],
            "risk_queue": [{"seed_id": "H-001", "priority": 1}],
            "execution_allowed": True,
            "ranking_permission_granted": True,
            "report_submission_allowed": True,
            "finding_promotion_allowed": True,
        },
    )
    payload = out["finding_dedup_risk"]
    assert payload["execution_allowed"] is False
    assert payload["ranking_permission_granted"] is False
    assert payload["report_submission_allowed"] is False
    assert payload["finding_promotion_allowed"] is False


def test_mev_signal_ready_and_blocked():
    ready = signal_from_finding_dedup_risk(
        {
            "status": STATUS_READY,
            "cluster_count": 2,
            "risk_queue_count": 3,
            "seed_count": 3,
            "execution_allowed": False,
        }
    )
    assert ready is not None
    assert ready["status"] == "ready"
    blocked = signal_from_finding_dedup_risk(
        {
            "status": STATUS_READY,
            "cluster_count": 1,
            "execution_allowed": True,
        }
    )
    assert blocked["status"] == "blocked"
    verdict = build_multi_engine_verdict(
        candidate={"candidate_id": "H-001"},
        finding_dedup_risk_signal=ready,
    )
    engines = {e.engine for e in verdict.engines}
    assert ENGINE_FINDING_DEDUP_RISK in engines
    assert verdict.confirmed_vulnerability is False
    assert verdict.execution_allowed is False


def test_empty_without_seeds():
    result = run_finding_dedup_risk(
        bridge_result={
            "package_id": "empty-pkg",
            "submission_blocked": True,
            "drafts": [],
            "candidates": [],
            "findings": [],
        }
    )
    assert result.status == STATUS_EMPTY
    assert result.seed_count == 0


def test_scheduler_still_has_dedup_and_risk_tasks():
    plan = build_industrial_scheduler_plan({"findings": []})
    by_id = {task.task_id: task for task in plan.dag_tasks}
    assert "T-005" in by_id
    assert by_id["T-005"].agent == "dedup_agent"
    assert by_id["T-005"].execution_allowed is False
    assert "T-006" in by_id
    assert by_id["T-006"].agent == "risk_prioritizer"
    assert by_id["T-006"].execution_allowed is False
