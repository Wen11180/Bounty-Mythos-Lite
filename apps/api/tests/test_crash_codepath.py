from pathlib import Path

from app.crash_codepath import (
    STATUS_NO_CLUSTERS,
    STATUS_READY,
    STATUS_WRITTEN,
    attach_crash_codepath_to_bridge_result,
    build_crash_codepath_plan,
    run_crash_codepath_link,
)
from app.industrial_scheduler import build_industrial_scheduler_plan
from app.multi_engine_verifier import (
    ENGINE_CRASH_CODEPATH,
    build_multi_engine_verdict,
    signal_from_crash_codepath,
)


def _triage_with_clusters() -> dict:
    return {
        "status": "crash_triage_completed",
        "package_id": "demo",
        "input_crash_count": 2,
        "unique_cluster_count": 1,
        "triaged": [
            {
                "crash_id": "crash-a",
                "cluster_id": "cluster-sig1",
                "target_symbol": "parse_message",
                "source_path": "src/parser.py",
                "exception_type": "ValueError",
                "exception_message": "boom-marker",
                "crash_type": "input_validation_exception",
                "signature": "sig1",
                "seed_sha256": "abc",
                "seed_preview": "PREFIX_BOOM_SUFFIX",
                "minimized": True,
                "minimized_seed_len": 4,
                "minimized_seed_sha256": "def",
                "minimized_seed_preview": "BOOM",
                "reproducible": True,
                "promotion_allowed": False,
                "confirmed_vulnerability": False,
                "root_cause": {
                    "status": "advisory",
                    "summary": "Unvalidated marker path in parse_message",
                    "exception_family": "ValueError",
                    "likely_surface": "parser",
                    "needs_human_review": True,
                    "confirmed_vulnerability": False,
                },
            },
            {
                "crash_id": "crash-b",
                "cluster_id": "cluster-sig1",
                "target_symbol": "parse_message",
                "source_path": "src/parser.py",
                "exception_type": "ValueError",
                "exception_message": "boom-marker",
                "crash_type": "input_validation_exception",
                "signature": "sig1",
                "minimized": True,
                "reproducible": True,
            },
        ],
    }


def _pkg_with_parser(tmp_path: Path) -> Path:
    code = tmp_path / "src"
    code.mkdir()
    (code / "parser.py").write_text(
        "def parse_message(raw):\n"
        "    data = raw if isinstance(raw, (bytes, bytearray)) else str(raw).encode()\n"
        "    if b'BOOM' in data:\n"
        "        raise ValueError('boom-marker')\n"
        "    if not data:\n"
        "        raise ValueError('empty')\n"
        "    return data\n",
        encoding="utf-8",
    )
    return tmp_path


def test_empty_without_triage():
    plan = build_crash_codepath_plan()
    assert plan.status in {STATUS_NO_CLUSTERS, "crash_codepath_empty"}
    assert plan.execution_mode == "static_advisory_only"
    assert plan.execution_allowed is False
    assert plan.validation_allowed is False
    assert plan.package_code_execution_allowed is False
    assert plan.crash_promotion_allowed is False
    assert plan.report_submission_allowed is False
    assert plan.confirmed_vulnerability is False


def test_link_resolves_function_span(tmp_path: Path):
    root = _pkg_with_parser(tmp_path)
    triage = _triage_with_clusters()
    result = run_crash_codepath_link(
        package_root=root, package_id="demo", crash_triage=triage
    )
    assert result.status == STATUS_READY
    assert result.link_count == 1
    assert result.resolved_count == 1
    link = result.links[0]
    assert link.target_symbol == "parse_message"
    assert link.resolved is True
    assert "parse_message" in link.primary_code_path
    assert link.hits
    assert link.hits[0].start_line == 1
    assert link.promotion_allowed is False
    assert link.confirmed_vulnerability is False
    assert result.execution_allowed is False
    assert result.package_code_execution_allowed is False
    assert any("ValueError" in s or "message_match" in s for s in link.raise_sites) or link.confidence in {
        "high",
        "medium",
    }


def test_export_under_package(tmp_path: Path):
    root = _pkg_with_parser(tmp_path)
    triage = _triage_with_clusters()
    result = run_crash_codepath_link(
        package_root=root,
        package_id="demo",
        crash_triage=triage,
        human_allow_export_write=True,
    )
    assert result.status == STATUS_WRITTEN
    assert result.export_written is True
    assert result.export_count == 1
    assert result.execution_allowed is False
    assert result.package_code_execution_allowed is False
    export_root = root / "_export" / "crash_codepath"
    assert export_root.is_dir()
    stamps = list(export_root.iterdir())
    assert stamps
    assert (stamps[0] / "index.json").is_file()
    assert (stamps[0] / "README.md").is_file()


def test_bridge_attach_forces_safety(tmp_path: Path):
    root = _pkg_with_parser(tmp_path)
    triage = _triage_with_clusters()
    bridge = {
        "package_id": "demo",
        "package_root": str(root),
        "submission_blocked": True,
        "crash_triage": triage,
        "execution_allowed": True,
        "report_submission_allowed": True,
        "confirmed_vulnerability": True,
    }
    out = attach_crash_codepath_to_bridge_result(bridge, package_root=root)
    assert out["crash_codepath_present"] is True
    assert out["crash_codepath_link_count"] == 1
    assert out["crash_codepath_resolved_count"] == 1
    assert out["execution_allowed"] is False
    assert out["validation_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert out["submission_blocked"] is True
    assert out["crash_codepath"]["package_code_execution_allowed"] is False
    assert out["crash_codepath"]["crash_promotion_allowed"] is False


def test_mev_signal_and_engine(tmp_path: Path):
    root = _pkg_with_parser(tmp_path)
    plan = run_crash_codepath_link(
        package_root=root, package_id="demo", crash_triage=_triage_with_clusters()
    ).to_dict()
    sig = signal_from_crash_codepath(plan)
    assert sig is not None
    assert sig["status"] == "ready"
    unsafe = signal_from_crash_codepath({**plan, "crash_promotion_allowed": True})
    assert unsafe["status"] == "blocked"
    verdict = build_multi_engine_verdict(
        candidate={"candidate_id": "c1"},
        crash_codepath_signal=sig,
    )
    engines = {e.engine for e in verdict.engines}
    assert ENGINE_CRASH_CODEPATH in engines
    assert verdict.execution_allowed is False
    assert verdict.confirmed_vulnerability is False


def test_scheduler_includes_t003g():
    plan = build_industrial_scheduler_plan(
        {
            "scope": {"allowed": True},
            "hypotheses": [],
            "crash_triage": {"triaged_count": 1},
            "crash_codepath": {"link_count": 1},
        }
    )
    task_by_id = {t.task_id: t for t in plan.dag_tasks}
    assert "T-003g" in task_by_id
    assert task_by_id["T-003g"].agent == "crash_codepath_agent"
    assert task_by_id["T-003g"].depends_on == [
        "T-003",
        "T-003b",
        "T-003c",
        "T-003d",
        "T-003e",
    ]
    assert task_by_id["T-003g"].execution_allowed is False
    assert task_by_id["T-003g"].requires_human_review is True
    batches = {b.batch_id: b.task_ids for b in plan.parallel_batches}
    assert batches.get("B-002i") == ["T-003g"]
    assert "T-003g" in task_by_id["T-006b"].depends_on