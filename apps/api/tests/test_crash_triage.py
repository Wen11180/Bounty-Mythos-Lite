from pathlib import Path

from app.crash_triage import (
    STATUS_COMPLETED,
    STATUS_EXPORT_WRITTEN,
    STATUS_READY,
    STATUS_SKIPPED_NO_CRASHES,
    attach_crash_triage_to_bridge_result,
    build_crash_triage_plan,
    run_crash_triage,
)
from app.local_fuzz_runner import run_local_fuzz_runner
from app.industrial_scheduler import build_industrial_scheduler_plan


def _crashy_pkg(tmp_path: Path) -> Path:
    code = tmp_path / "src"
    code.mkdir()
    # Crash only when input contains marker; long seed enables minimization
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


def test_plan_only_default_classifies_without_execute(tmp_path: Path):
    root = _crashy_pkg(tmp_path)
    runner = run_local_fuzz_runner(package_root=root, human_allow_local_fuzz_run=True).to_dict()
    # Inject a synthetic crash with BOOM seed so triage has material even if corpus missed it
    if not runner.get("crash_candidates"):
        runner["crash_candidates"] = [
            {
                "crash_id": "crash-demo",
                "target_symbol": "parse_message",
                "source_path": "src/parser.py",
                "exception_type": "ValueError",
                "exception_message": "boom-marker",
                "seed_sha256": "x",
                "seed_preview": "xxxxBOOMyyyy",
                "seed_hex": b"xxxxBOOMyyyy".hex(),
            }
        ]
        runner["crash_count"] = 1

    plan = build_crash_triage_plan(
        package_root=root,
        local_fuzz_runner=runner,
        human_allow_crash_triage=False,
    )
    assert plan.execution_mode == "plan_only"
    assert plan.triage_executed is False
    assert plan.status == STATUS_READY
    assert plan.triaged_count >= 1
    assert plan.execution_allowed is False
    assert plan.crash_promotion_allowed is False
    assert plan.report_submission_allowed is False
    assert plan.confirmed_vulnerability is False
    assert plan.process_spawn_allowed is False


def test_flag_dedupes_minimizes_and_marks_reproducible(tmp_path: Path):
    root = _crashy_pkg(tmp_path)
    long_seed = b"PREFIX_" + b"BOOM" + b"_SUFFIX_EXTRA"
    runner = {
        "status": "local_fuzz_runner_crashes_recorded",
        "crash_candidates": [
            {
                "crash_id": "crash-a",
                "target_symbol": "parse_message",
                "source_path": "src/parser.py",
                "exception_type": "ValueError",
                "exception_message": "boom-marker",
                "seed_sha256": "1",
                "seed_preview": long_seed.decode(),
                "seed_hex": long_seed.hex(),
            },
            {
                "crash_id": "crash-b",
                "target_symbol": "parse_message",
                "source_path": "src/parser.py",
                "exception_type": "ValueError",
                "exception_message": "boom-marker",
                "seed_sha256": "2",
                "seed_preview": (b"ZZ" + long_seed).decode(),
                "seed_hex": (b"ZZ" + long_seed).hex(),
            },
        ],
        "crash_count": 2,
    }
    result = run_crash_triage(
        package_root=root,
        local_fuzz_runner=runner,
        human_allow_crash_triage=True,
    )
    assert result.triage_executed is True
    assert result.status in {STATUS_COMPLETED, STATUS_EXPORT_WRITTEN}
    assert result.unique_cluster_count == 1
    assert result.deduped_away_count == 1
    assert result.reproducible_count >= 1
    assert result.minimized_count >= 1
    assert result.execution_allowed is False
    assert result.crash_promotion_allowed is False
    assert result.finding_promotion_allowed is False
    assert result.confirmed_vulnerability is False
    t0 = result.triaged[0]
    assert t0.reproducible is True
    assert t0.minimized is True
    assert t0.minimized_seed_len is not None
    assert t0.minimized_seed_len < t0.original_seed_len
    assert t0.root_cause is not None
    assert t0.root_cause.confirmed_vulnerability is False
    assert t0.root_cause.needs_human_review is True
    assert result.triage_export_written is True
    assert (root / "_export" / "crash_triage").is_dir()


def test_no_crashes_status():
    result = run_crash_triage(
        local_fuzz_runner={"status": "local_fuzz_runner_completed", "crash_candidates": []},
        human_allow_crash_triage=True,
    )
    assert result.status == STATUS_SKIPPED_NO_CRASHES
    assert result.triage_executed is False
    assert result.crash_promotion_allowed is False


def test_attach_strips_flags(tmp_path: Path):
    root = _crashy_pkg(tmp_path)
    seed = b"xxBOOMyy"
    bridge = {
        "package_id": "demo",
        "package_root": str(root),
        "submission_blocked": True,
        "execution_allowed": True,
        "report_submission_allowed": True,
        "local_fuzz_runner": {
            "status": "local_fuzz_runner_crashes_recorded",
            "crash_candidates": [
                {
                    "crash_id": "c1",
                    "target_symbol": "parse_message",
                    "source_path": "src/parser.py",
                    "exception_type": "ValueError",
                    "exception_message": "boom-marker",
                    "seed_sha256": "a",
                    "seed_preview": seed.decode(),
                    "seed_hex": seed.hex(),
                }
            ],
            "crash_count": 1,
        },
    }
    out = attach_crash_triage_to_bridge_result(
        bridge,
        package_root=root,
        human_allow_crash_triage=True,
    )
    assert out["crash_triage_present"] is True
    assert out["crash_triage_executed"] is True
    assert out["execution_allowed"] is False
    assert out["report_submission_allowed"] is False
    assert out["confirmed_vulnerability"] is False
    assert out["submission_blocked"] is True
    assert out["crash_triage"]["crash_promotion_allowed"] is False
    assert out["crash_triage_crash_promotion_allowed"] is False


def test_scheduler_includes_t003e():
    plan = build_industrial_scheduler_plan(
        {
            "scope": {"allowed": True},
            "hypotheses": [],
            "local_fuzz_runner": {"crash_count": 1},
            "crash_triage": {"triaged_count": 1},
        }
    )
    task_by_id = {t.task_id: t for t in plan.dag_tasks}
    assert "T-003e" in task_by_id
    assert task_by_id["T-003e"].agent == "crash_triage_agent"
    assert task_by_id["T-003e"].depends_on == ["T-003", "T-003b", "T-003c", "T-003d"]
    assert task_by_id["T-003e"].execution_allowed is False
    assert task_by_id["T-003e"].requires_human_review is True
    batches = {b.batch_id: b.task_ids for b in plan.parallel_batches}
    assert batches.get("B-002g") == ["T-003e"]
    assert "T-003e" in task_by_id["T-006b"].depends_on
