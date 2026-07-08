from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
from typing import Any


WORKSPACE_DIRS = (
    "policy",
    "scope",
    "api",
    "har",
    "code",
    "sbom",
    "sarif",
    "fuzzing",
    "strategy",
    "knowledge",
    "evidence",
    "benchmarks",
    "reports",
    "runs",
)
SECRET_MARKERS = (
    "authorization:",
    "bearer ",
    "cookie:",
    "set-cookie:",
    "x-api-key",
    "api_key",
    "access_token",
    "secret",
    "token",
)
BLOCKED_ACTIONS = (
    "execute_live_validation",
    "touch_real_user_data",
    "submit_report",
)
SAFETY_BLOCKER_LABELS = {
    "execute_live_validation": "Validation execution remains blocked pending human approval.",
    "touch_real_user_data": "Protected user data remains out of scope.",
    "submit_report": "Report submission remains blocked pending human review.",
}


@dataclass(frozen=True)
class StudioWorkspace:
    path: Path
    manifest: dict[str, Any]


@dataclass(frozen=True)
class StudioArtifactImport:
    kind: str
    source_path: str


def create_workspace(root: str | Path, *, name: str) -> StudioWorkspace:
    workspace_path = Path(root) / _safe_name(name)
    workspace_path.mkdir(parents=True, exist_ok=True)
    for child in WORKSPACE_DIRS:
        (workspace_path / child).mkdir(exist_ok=True)
    if (workspace_path / "manifest.json").exists():
        return StudioWorkspace(
            path=workspace_path,
            manifest=load_workspace_manifest(workspace_path),
        )

    manifest = {
        "name": name,
        "created_at": _utc_now(),
        "artifacts": [],
        "runs": [],
        "safety": {
            "scope_guard_status": "missing_scope",
            "blocked_actions": list(BLOCKED_ACTIONS),
        },
    }
    _write_manifest(workspace_path, manifest)
    return StudioWorkspace(path=workspace_path, manifest=manifest)


def load_workspace_manifest(workspace_path: str | Path) -> dict[str, Any]:
    manifest_path = Path(workspace_path) / "manifest.json"
    return json.loads(manifest_path.read_text(encoding="utf-8-sig"))


def import_workspace_artifact(
    workspace_path: str | Path, artifact: StudioArtifactImport
) -> dict[str, Any]:
    path = Path(workspace_path)
    manifest = load_workspace_manifest(path)
    source_path = Path(artifact.source_path)
    sensitivity_label = _sensitivity_label(source_path)

    manifest["artifacts"].append(
        {
            "kind": artifact.kind,
            "source_path": _safe_path_ref(artifact.source_path),
            "source_hash": _sha256(source_path),
            "sensitivity_label": sensitivity_label,
            "redaction_status": (
                "not_required" if sensitivity_label == "low" else "needs_review"
            ),
            "imported_at": _utc_now(),
        }
    )
    if artifact.kind == "scope":
        manifest["safety"]["scope_guard_status"] = "scope_imported"

    _write_manifest(path, manifest)
    return manifest


def record_workspace_run(
    workspace_path: str | Path,
    *,
    run_id: str,
    status: str,
    report_path: str | None,
    candidate_count: int,
) -> dict[str, Any]:
    path = Path(workspace_path)
    manifest = load_workspace_manifest(path)
    manifest["runs"].append(
        {
            "run_id": run_id,
            "status": status,
            "report_path": (
                _safe_path_ref(report_path) if report_path is not None else None
            ),
            "candidate_count": candidate_count,
            "recorded_at": _utc_now(),
        }
    )
    _write_manifest(path, manifest)
    return manifest


def record_workspace_report_export(
    workspace_path: str | Path,
    *,
    run_id: str,
    report: dict[str, Any],
) -> dict[str, Any]:
    path = Path(workspace_path)
    manifest = load_workspace_manifest(path)
    report_path = path / "reports" / f"{_safe_name(run_id)}-report-preview.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown_path = path / "reports" / f"{_safe_name(run_id)}-report-draft.md"
    markdown_path.write_text(_report_markdown(report), encoding="utf-8")
    report_ref = _safe_path_ref(str(report_path))
    markdown_ref = _safe_path_ref(str(markdown_path))
    for run in manifest["runs"]:
        if run.get("run_id") == run_id:
            run["report_path"] = report_ref
            run["report_markdown_path"] = markdown_ref
            break
    else:
        manifest["runs"].append(
            {
                "run_id": run_id,
                "status": "report_exported",
                "report_path": report_ref,
                "report_markdown_path": markdown_ref,
                "candidate_count": 0,
                "recorded_at": _utc_now(),
            }
        )
    _write_manifest(path, manifest)
    return manifest


def record_workspace_mission_dossier(
    workspace_path: str | Path,
    *,
    run_id: str | None,
    mission: dict[str, Any],
) -> dict[str, Any]:
    path = Path(workspace_path)
    manifest = load_workspace_manifest(path)
    safe_run_id = _safe_name(run_id or "no-run")
    dossier_path = path / "reports" / f"{safe_run_id}-mission-dossier.json"
    markdown_path = path / "reports" / f"{safe_run_id}-mission-dossier.md"
    agent_queue_path = path / "reports" / f"{safe_run_id}-agent-queue.json"
    agent_queue_markdown_path = path / "reports" / f"{safe_run_id}-agent-queue.md"
    safe_mission = dict(mission)
    safe_mission["readiness_audit"] = _safe_readiness_audit(
        mission.get("readiness_audit"),
        mission.get("artifacts"),
        mission.get("advisory_artifacts"),
        mission.get("top_candidates"),
        mission.get("candidate_review_packets"),
        mission.get("submission_blocked_report_summary"),
        mission.get("candidate_hunter_backlog"),
        mission.get("candidate_hunter_iteration"),
        mission.get("agent_handoff_pack"),
    )
    safe_mission["candidate_hunter_plan"] = _safe_candidate_hunter_plan(
        mission.get("candidate_hunter_plan"),
        mission.get("candidate_hunter_backlog"),
        mission.get("candidate_hunter_iteration"),
    )
    safe_mission["candidate_hunter_review_loop"] = _safe_candidate_hunter_review_loop(
        mission.get("candidate_hunter_review_loop"),
        safe_mission["candidate_hunter_plan"],
    )
    agent_queue_audit = _agent_queue_audit(run_id, mission)
    dossier_path.write_text(json.dumps(safe_mission, indent=2), encoding="utf-8")
    markdown_path.write_text(_mission_dossier_markdown(safe_mission), encoding="utf-8")
    agent_queue_path.write_text(json.dumps(agent_queue_audit, indent=2), encoding="utf-8")
    agent_queue_markdown_path.write_text(
        _agent_queue_audit_markdown(agent_queue_audit),
        encoding="utf-8",
    )
    dossier_ref = _safe_path_ref(str(dossier_path))
    markdown_ref = _safe_path_ref(str(markdown_path))
    agent_queue_ref = _safe_path_ref(str(agent_queue_path))
    agent_queue_markdown_ref = _safe_path_ref(str(agent_queue_markdown_path))
    manifest.setdefault("mission_dossiers", []).append(
        {
            "run_id": run_id,
            "dossier_path": dossier_ref,
            "dossier_markdown_path": markdown_ref,
            "agent_queue_path": agent_queue_ref,
            "agent_queue_markdown_path": agent_queue_markdown_ref,
            "report_submission_allowed": False,
            "validation_execution_allowed": False,
            "recorded_at": _utc_now(),
        }
    )
    manifest.setdefault("agent_queue_audits", []).append(
        {
            "run_id": run_id,
            "agent_queue_path": agent_queue_ref,
            "agent_queue_markdown_path": agent_queue_markdown_ref,
            "task_count": len(agent_queue_audit["agent_queue"]),
            "timeline_stage_count": len(agent_queue_audit["task_timeline"]),
            "timeline_blocked_stage_count": len(
                agent_queue_audit["studio_timeline_summary"]["blocked_stage_ids"]
            ),
            "timeline_needs_review_stage_count": len(
                agent_queue_audit["studio_timeline_summary"]["needs_review_stage_ids"]
            ),
            "timeline_pending_stage_count": len(
                agent_queue_audit["studio_timeline_summary"]["pending_stage_ids"]
            ),
            "candidate_review_packet_count": len(
                agent_queue_audit["candidate_review_packets"]
            ),
            "candidate_review_ready_packet_count": len(
                [
                    packet
                    for packet in agent_queue_audit["candidate_review_packets"]
                    if packet.get("status") == "review_ready"
                ]
            ),
            "submission_blocked_report_status": agent_queue_audit[
                "submission_blocked_report_summary"
            ].get("status", "needs_human_review"),
            "submission_blocked_report_ready_candidate_count": len(
                agent_queue_audit["submission_blocked_report_summary"].get(
                    "ready_candidate_ids",
                    [],
                )
            ),
            "agent_handoff_item_count": agent_queue_audit[
                "agent_handoff_pack"
            ].get("handoff_item_count", 0),
            "agent_handoff_status": agent_queue_audit["agent_handoff_pack"].get(
                "status", "needs_review"
            ),
            "candidate_hunter_backlog_count": len(
                agent_queue_audit["candidate_hunter_backlog"]
            ),
            "candidate_hunter_iteration_status": agent_queue_audit[
                "candidate_hunter_iteration"
            ].get("status", "unknown"),
            "top_candidate_quality_gate": agent_queue_audit["quality_summary"].get(
                "top_candidate_quality_gate",
                "unknown",
            ),
            "report_submission_allowed": False,
            "validation_execution_allowed": False,
            "recorded_at": _utc_now(),
        }
    )
    for run in manifest.get("runs", []):
        if isinstance(run, dict) and run.get("run_id") == run_id:
            run["mission_dossier_path"] = dossier_ref
            run["mission_dossier_markdown_path"] = markdown_ref
            run["agent_queue_path"] = agent_queue_ref
            run["agent_queue_markdown_path"] = agent_queue_markdown_ref
            break
    _write_manifest(path, manifest)
    return manifest


def record_workspace_benchmark_result(
    workspace_path: str | Path,
    *,
    run_id: str,
    result: dict[str, Any],
) -> dict[str, Any]:
    path = Path(workspace_path)
    manifest = load_workspace_manifest(path)
    benchmark_dir = path / "benchmarks"
    benchmark_dir.mkdir(exist_ok=True)
    benchmark_path = benchmark_dir / f"{_safe_name(run_id)}-benchmark-result.json"
    benchmark_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    benchmark_ref = _safe_path_ref(str(benchmark_path))
    manifest.setdefault("benchmarks", []).append(
        {
            "run_id": run_id,
            "status": _markdown_text(result.get("status"), "unknown"),
            "benchmark_path": benchmark_ref,
            "matched": result.get("matched", 0),
            "expected_count": result.get("expected_count", 0),
            "recorded_at": _utc_now(),
        }
    )
    for run in manifest.get("runs", []):
        if isinstance(run, dict) and run.get("run_id") == run_id:
            run["benchmark_status"] = _markdown_text(result.get("status"), "unknown")
            run["benchmark_path"] = benchmark_ref
            break
    _write_manifest(path, manifest)
    return manifest


def record_workspace_benchmark_template(
    workspace_path: str | Path,
    *,
    run_id: str,
    template: dict[str, Any],
) -> dict[str, Any]:
    path = Path(workspace_path)
    manifest = load_workspace_manifest(path)
    benchmark_dir = path / "benchmarks"
    benchmark_dir.mkdir(exist_ok=True)
    template_path = benchmark_dir / f"{_safe_name(run_id)}-expectations-template.json"
    template_path.write_text(json.dumps(template, indent=2), encoding="utf-8")
    template_ref = _safe_path_ref(str(template_path))
    manifest.setdefault("benchmark_templates", []).append(
        {
            "run_id": run_id,
            "template_path": template_ref,
            "expected_count": len(template.get("expected_candidates", []))
            if isinstance(template.get("expected_candidates"), list)
            else 0,
            "draft_review_required": True,
            "recorded_at": _utc_now(),
        }
    )
    for run in manifest.get("runs", []):
        if isinstance(run, dict) and run.get("run_id") == run_id:
            run["benchmark_template_path"] = template_ref
            break
    _write_manifest(path, manifest)
    return manifest


def _write_manifest(workspace_path: Path, manifest: dict[str, Any]) -> None:
    (workspace_path / "manifest.json").write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )


def _sha256(path: Path) -> str:
    if path.is_dir():
        digest = hashlib.sha256()
        digest.update(str(path.resolve()).encode("utf-8", errors="replace"))
        return "sha256:" + digest.hexdigest()
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _sensitivity_label(path: Path) -> str:
    if _secret_like_text(str(path)):
        return "sensitive"
    if path.is_dir():
        return "low"
    try:
        text = path.read_text(encoding="utf-8-sig").lower()
    except UnicodeDecodeError:
        return "unknown"
    if _secret_like_text(text):
        return "sensitive"
    return "low"


def _safe_path_ref(value: str) -> str:
    return "[REDACTED_PATH]" if _secret_like_text(value) else value


def _report_markdown(report: dict[str, Any]) -> str:
    title = _markdown_text(report.get("title"), "Submission-blocked report draft")
    summary = _markdown_text(report.get("summary"), "")
    notes = [
        _markdown_text(item, "")
        for item in report.get("safety_notes", [])
        if _markdown_text(item, "")
    ]
    lines = [
        f"# {title}",
        "",
        "Submission status: blocked",
        "Report submission allowed: false",
    ]
    if summary:
        lines.extend(["", "## Summary", "", summary])
    lines.extend(_studio_context_markdown_lines(report.get("studio_context")))
    lines.extend(_top_candidate_reviews_markdown_lines(report.get("top_candidate_reviews")))
    candidate_summary = _markdown_list(report.get("candidate_summary"))
    if candidate_summary:
        lines.extend(["", "## Candidate summary"])
        lines.extend(f"- {item}" for item in candidate_summary)
    ranking_reasons = _markdown_list(report.get("ranking_reasons"))
    if ranking_reasons:
        lines.extend(["", "## Ranking reasons"])
        lines.extend(f"- {item}" for item in ranking_reasons)
    lines.extend(_report_readiness_markdown_lines(report.get("report_readiness")))
    lines.extend(_evidence_review_markdown_lines(report.get("evidence_review")))
    lines.extend(_deduplication_review_markdown_lines(report.get("deduplication_review")))
    lines.extend(_refutation_review_markdown_lines(report.get("refutation_review")))
    lines.extend(_policy_review_markdown_lines(report.get("policy_review")))
    lines.extend(_provenance_review_markdown_lines(report.get("provenance_review")))
    lines.extend(_validation_review_markdown_lines(report.get("validation_review")))
    sections = report.get("sections")
    if isinstance(sections, dict):
        for key, heading in (
            ("observed_facts", "Observed facts"),
            ("model_reasoning", "Model reasoning"),
            ("unverified_claims", "Unverified claims"),
        ):
            items = _markdown_list(sections.get(key))
            if items:
                lines.extend(["", f"## {heading}"])
                lines.extend(f"- {item}" for item in items)
    if notes:
        lines.extend(["", "## Safety notes"])
        lines.extend(f"- {note}" for note in notes)
    evidence_needed = _markdown_list(report.get("evidence_needed"))
    if evidence_needed:
        lines.extend(["", "## Evidence needs"])
        lines.extend(f"- {item}" for item in evidence_needed)
    false_positive_checks = _markdown_list(report.get("false_positive_checks"))
    if false_positive_checks:
        lines.extend(["", "## False-positive checks"])
        lines.extend(f"- {item}" for item in false_positive_checks)
    evidence_gaps = _markdown_list(report.get("evidence_gaps"))
    if evidence_gaps:
        lines.extend(["", "## Evidence gaps"])
        lines.extend(f"- {item}" for item in evidence_gaps)
    advisory_signals = _markdown_list(report.get("advisory_signals"))
    if advisory_signals:
        lines.extend(["", "## Advisory signals"])
        lines.append(
            "Advisory-only signals are not confirmed vulnerabilities and require human review."
        )
        lines.extend(f"- {item}" for item in advisory_signals)
    safe_validation_plan = _markdown_list(report.get("safe_validation_plan"))
    if safe_validation_plan:
        lines.extend(["", "## Safe validation plan"])
        lines.extend(f"- {item}" for item in safe_validation_plan)
    safety_blockers = _safety_blocker_markdown_list(report.get("safety_blockers"))
    if safety_blockers:
        lines.extend(["", "## Safety blockers"])
        lines.extend(f"- {item}" for item in safety_blockers)
    suggested_fix = _markdown_safe_text(report.get("suggested_fix"))
    if suggested_fix:
        lines.extend(["", "## Suggested fix", "", suggested_fix])
    regression_test = _markdown_safe_text(report.get("regression_test"))
    if regression_test:
        lines.extend(["", "## Regression test", "", regression_test])
    lines.extend(
        [
            "",
            "## Review gate",
            "",
            "Human evidence review and redaction are required before any report submission.",
        ]
    )
    return "\n".join(lines) + "\n"


def _mission_dossier_markdown(mission: dict[str, Any]) -> str:
    lines = [
        "# Mythos Studio mission dossier",
        "",
        "- Mode: " + _markdown_text(mission.get("mode"), "local workbench"),
        "- Run: " + _markdown_text(mission.get("run_id"), "No run selected"),
        "- Scope Guard: " + _markdown_text(mission.get("scope_guard_status"), "unknown"),
        "- Submission blocked: true",
        "- Validation execution allowed: false",
    ]
    artifacts = mission.get("artifacts")
    if isinstance(artifacts, dict):
        lines.extend(
            [
                "",
                "## Artifact coverage",
                "- Required: " + ", ".join(_markdown_list(artifacts.get("required"))),
                "- Present: " + ", ".join(_markdown_list(artifacts.get("present"))),
                "- Missing: " + ", ".join(_markdown_list(artifacts.get("missing"))),
            ]
        )
    lines.extend(_mission_stage_markdown_lines(mission.get("research_loop")))
    lines.extend(_mission_quality_summary_markdown_lines(mission.get("quality_summary")))
    lines.extend(
        _candidate_hunter_backlog_markdown_lines(
            mission.get("candidate_hunter_backlog")
        )
    )
    lines.extend(
        _candidate_hunter_iteration_markdown_lines(
            mission.get("candidate_hunter_iteration")
        )
    )
    lines.extend(_candidate_hunter_plan_markdown_lines(mission.get("candidate_hunter_plan")))
    lines.extend(
        _candidate_hunter_review_loop_markdown_lines(
            mission.get("candidate_hunter_review_loop")
        )
    )
    lines.extend(
        _candidate_hunter_review_loop_markdown_lines(
            mission.get("candidate_hunter_review_loop")
        )
    )
    lines.extend(_studio_timeline_summary_markdown_lines(_mission_timeline_summary(mission)))
    lines.extend(
        _candidate_review_packets_markdown_lines(
            mission.get("candidate_review_packets")
        )
    )
    lines.extend(
        _submission_blocked_report_summary_markdown_lines(
            _safe_submission_blocked_report_summary(
                mission.get("submission_blocked_report_summary"),
                mission.get("candidate_review_packets"),
            )
        )
    )
    lines.extend(_readiness_audit_markdown_lines(mission.get("readiness_audit")))
    lines.extend(_agent_handoff_pack_markdown_lines(mission.get("agent_handoff_pack")))
    lines.extend(_mission_agent_queue_markdown_lines(mission.get("agent_queue")))
    lines.extend(_mission_hallucination_guard_markdown_lines(mission.get("top_candidates")))
    lines.extend(_mission_candidate_quality_markdown_lines(mission.get("top_candidates")))
    lines.extend(_mission_candidate_markdown_lines(mission.get("top_candidates")))
    return "\n".join(lines) + "\n"


def _mission_stage_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        return []
    lines = ["", "## Research loop"]
    for item in value:
        if not isinstance(item, dict):
            continue
        key = _markdown_safe_text(item.get("key"))
        status = _markdown_safe_text(item.get("status"))
        summary = _markdown_safe_text(item.get("summary"))
        if key:
            lines.append(f"- {key}: {status} - {summary}".rstrip(" -"))
    return lines


def _mission_agent_queue_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        return []
    lines = ["", "## Agent queue"]
    for item in value:
        if not isinstance(item, dict):
            continue
        task_id = _markdown_safe_text(item.get("task_id"))
        agent = _markdown_safe_text(item.get("agent"))
        status = _markdown_safe_text(item.get("status"))
        safety_gate = _markdown_safe_text(item.get("safety_gate"))
        inputs = ", ".join(_markdown_list(item.get("input_refs")))
        candidates = ", ".join(_markdown_list(item.get("target_candidates")))
        focus = ", ".join(_markdown_list(item.get("review_focus")))
        quality_gaps = ", ".join(_markdown_list(item.get("candidate_quality_gaps")))
        next_action = _markdown_safe_text(item.get("next_action"))
        if task_id:
            line = (
                f"- {task_id}: {agent} ({status}, {safety_gate}); "
                f"inputs: {inputs}; candidates: {candidates}"
            )
            if focus:
                line += f"; focus: {focus}"
            if quality_gaps:
                line += f"; quality gaps: {quality_gaps}"
            lines.append(f"{line}; next: {next_action}")
    return lines


def _mission_timeline_summary(mission: dict[str, Any]) -> dict[str, Any]:
    summary = mission.get("studio_timeline_summary")
    if isinstance(summary, dict):
        return summary
    agent_queue = _safe_agent_queue_items(mission.get("agent_queue"))
    return _studio_timeline_summary(_agent_task_timeline_items(agent_queue))


def _agent_queue_audit(run_id: str | None, mission: dict[str, Any]) -> dict[str, Any]:
    quality_summary = mission.get("quality_summary")
    agent_queue = _safe_agent_queue_items(mission.get("agent_queue"))
    task_timeline = _agent_task_timeline_items(agent_queue)
    timeline_summary = _studio_timeline_summary(task_timeline)
    candidate_review_packets = _safe_candidate_review_packets(
        mission.get("candidate_review_packets")
    )
    submission_blocked_report_summary = _safe_submission_blocked_report_summary(
        mission.get("submission_blocked_report_summary"),
        mission.get("candidate_review_packets"),
    )
    candidate_hunter_backlog = _safe_candidate_hunter_backlog_items(
        mission.get("candidate_hunter_backlog")
    )
    candidate_hunter_iteration = _safe_candidate_hunter_iteration(
        mission.get("candidate_hunter_iteration")
    )
    candidate_hunter_plan = _safe_candidate_hunter_plan(
        mission.get("candidate_hunter_plan"),
        candidate_hunter_backlog,
        candidate_hunter_iteration,
    )
    candidate_hunter_review_loop = _safe_candidate_hunter_review_loop(
        mission.get("candidate_hunter_review_loop"),
        candidate_hunter_plan,
    )
    agent_handoff_pack = _safe_agent_handoff_pack(
        mission.get("agent_handoff_pack"),
        mission.get("candidate_hunter_backlog"),
        mission.get("candidate_hunter_iteration"),
        timeline_summary,
    )
    return {
        "run_id": run_id,
        "agent_queue": agent_queue,
        "task_timeline": task_timeline,
        "studio_timeline_summary": timeline_summary,
        "candidate_review_packets": candidate_review_packets,
        "submission_blocked_report_summary": submission_blocked_report_summary,
        "readiness_audit": _safe_readiness_audit(
            mission.get("readiness_audit"),
            mission.get("artifacts"),
            mission.get("advisory_artifacts"),
            mission.get("top_candidates"),
            candidate_review_packets,
            submission_blocked_report_summary,
            candidate_hunter_backlog,
            candidate_hunter_iteration,
            agent_handoff_pack,
        ),
        "agent_handoff_pack": agent_handoff_pack,
        "candidate_hunter_backlog": candidate_hunter_backlog,
        "candidate_hunter_iteration": candidate_hunter_iteration,
        "candidate_hunter_plan": candidate_hunter_plan,
        "candidate_hunter_review_loop": candidate_hunter_review_loop,
        "quality_summary": _safe_quality_summary(quality_summary),
        "report_submission_allowed": False,
        "validation_execution_allowed": False,
    }


def _safe_agent_queue_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    items: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        task_id = _queue_safe_text(item.get("task_id"))
        if not task_id:
            continue
        items.append(
            {
                "task_id": task_id,
                "agent": _queue_safe_text(item.get("agent")),
                "status": _queue_safe_text(item.get("status")),
                "safety_gate": _queue_safe_text(item.get("safety_gate")),
                "input_refs": _queue_safe_list(item.get("input_refs")),
                "target_candidates": _queue_safe_list(item.get("target_candidates")),
                "review_focus": _queue_safe_list(item.get("review_focus")),
                "candidate_quality_gaps": _queue_safe_list(
                    item.get("candidate_quality_gaps")
                ),
                "next_action": _queue_safe_text(item.get("next_action")),
            }
        )
    return items[:10]


def _safe_quality_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    summary: dict[str, Any] = {}
    for key in (
        "status",
        "top_candidate_quality_gate",
        "candidate_count",
        "review_ready_count",
        "average_quality_score",
    ):
        raw_value = value.get(key)
        if isinstance(raw_value, int):
            summary[key] = raw_value
            continue
        text = _queue_safe_text(raw_value)
        if text:
            summary[key] = text
    summary["blockers"] = _queue_safe_list(value.get("blockers"))
    summary["improvement_actions"] = _queue_safe_list(value.get("improvement_actions"))
    return summary


def _safe_candidate_hunter_backlog_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    items: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        work_item_id = _queue_safe_text(item.get("work_item_id"))
        if not work_item_id:
            continue
        items.append(
            {
                "work_item_id": work_item_id,
                "candidate_id": _queue_safe_text(item.get("candidate_id")),
                "gap": _queue_safe_text(item.get("gap")),
                "status": _queue_safe_text(item.get("status")),
                "review_focus": _queue_safe_list(item.get("review_focus")),
                "required_evidence": _queue_safe_list(item.get("required_evidence")),
                "next_action": _queue_safe_text(item.get("next_action")),
                "safety_gate": _queue_safe_text(item.get("safety_gate")),
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            }
        )
    return items[:10]


def _safe_candidate_hunter_iteration(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {
            "iteration_id": "candidate_hunter:next_review",
            "status": "needs_review",
            "work_item_count": 0,
            "priority_order": [],
            "next_review_agent": "Human Reviewer",
            "review_focus": [],
            "success_criteria": [],
            "safety_gate": "review_only_no_execution",
            "completion_gate": "human_review_required",
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        }
    return {
        "iteration_id": _queue_safe_text(value.get("iteration_id"))
        or "candidate_hunter:next_review",
        "status": _queue_safe_text(value.get("status")) or "needs_review",
        "work_item_count": value.get("work_item_count")
        if isinstance(value.get("work_item_count"), int)
        else 0,
        "priority_order": _queue_safe_list(value.get("priority_order")),
        "next_review_agent": _queue_safe_text(value.get("next_review_agent"))
        or "Human Reviewer",
        "review_focus": _queue_safe_list(value.get("review_focus")),
        "success_criteria": _queue_safe_list(value.get("success_criteria")),
        "safety_gate": _queue_safe_text(value.get("safety_gate"))
        or "review_only_no_execution",
        "completion_gate": _queue_safe_text(value.get("completion_gate"))
        or "human_review_required",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _safe_candidate_hunter_plan(
    value: Any,
    backlog_value: Any,
    iteration_value: Any,
) -> dict[str, Any]:
    backlog = _safe_candidate_hunter_backlog_items(backlog_value)
    iteration = _safe_candidate_hunter_iteration(iteration_value)
    if isinstance(value, dict):
        plan_steps = _safe_candidate_hunter_plan_steps(value.get("plan_steps"))
        plan_id = (
            _queue_safe_text(value.get("plan_id"))
            or "candidate_hunter:autonomous_review_plan"
        )
        status = _queue_safe_text(value.get("status")) or iteration["status"]
        next_review_agent = (
            _queue_safe_text(value.get("next_review_agent"))
            or iteration["next_review_agent"]
        )
        work_item_count = (
            value.get("work_item_count")
            if isinstance(value.get("work_item_count"), int)
            else len(backlog)
        )
    else:
        plan_steps = [_candidate_hunter_plan_step_from_backlog(item) for item in backlog]
        plan_id = "candidate_hunter:autonomous_review_plan"
        status = iteration["status"]
        next_review_agent = iteration["next_review_agent"]
        work_item_count = len(backlog)
    return {
        "plan_id": plan_id,
        "status": status,
        "work_item_count": work_item_count,
        "step_count": len(plan_steps),
        "next_review_agent": next_review_agent,
        "plan_steps": plan_steps,
        "hallucination_governance": _safe_candidate_hunter_hallucination_governance(
            value.get("hallucination_governance") if isinstance(value, dict) else None
        ),
        "safety_gate": "review_only_no_execution",
        "completion_gate": "human_review_required",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _safe_candidate_hunter_plan_steps(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    steps: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        step_id = _queue_safe_text(item.get("step_id"))
        work_item_id = _queue_safe_text(item.get("work_item_id"))
        if not step_id or not work_item_id:
            continue
        steps.append(
            {
                "step_id": step_id,
                "work_item_id": work_item_id,
                "candidate_id": _queue_safe_text(item.get("candidate_id")),
                "assigned_agent": _queue_safe_text(item.get("assigned_agent"))
                or "Human Reviewer",
                "gap": _queue_safe_text(item.get("gap")),
                "input_refs": _queue_safe_list(item.get("input_refs")),
                "review_focus": _queue_safe_list(item.get("review_focus")),
                "required_evidence": _queue_safe_list(item.get("required_evidence")),
                "next_action": _queue_safe_text(item.get("next_action")),
                "success_criteria": _queue_safe_list(item.get("success_criteria")),
                "review_checklist": _safe_candidate_hunter_plan_step_checklist(
                    item.get("review_checklist")
                ),
                "hallucination_governance_refs": _queue_safe_list(
                    item.get("hallucination_governance_refs")
                ),
                "safety_gate": "review_only_no_execution",
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            }
        )
    return steps[:10]


def _candidate_hunter_plan_step_from_backlog(item: dict[str, Any]) -> dict[str, Any]:
    work_item_id = _queue_safe_text(item.get("work_item_id"))
    gap = _queue_safe_text(item.get("gap"))
    return {
        "step_id": f"candidate_hunter:plan:{work_item_id}",
        "work_item_id": work_item_id,
        "candidate_id": _queue_safe_text(item.get("candidate_id")),
        "assigned_agent": _agent_for_candidate_gap(gap),
        "gap": gap,
        "input_refs": ["scope", "policy", "code", "api", "har"],
        "review_focus": _queue_safe_list(item.get("review_focus")),
        "required_evidence": _queue_safe_list(item.get("required_evidence")),
        "next_action": _queue_safe_text(item.get("next_action")),
        "success_criteria": _candidate_hunter_plan_step_success_criteria(item),
        "review_checklist": _candidate_hunter_plan_step_review_checklist(item),
        "hallucination_governance_refs": _candidate_hunter_plan_step_governance_refs(
            item
        ),
        "safety_gate": "review_only_no_execution",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _safe_candidate_hunter_review_loop(
    value: Any,
    plan: dict[str, Any],
) -> dict[str, Any]:
    if isinstance(value, dict):
        active_steps = _safe_candidate_hunter_review_loop_steps(
            value.get("active_steps")
        )
        loop_id = (
            _queue_safe_text(value.get("loop_id"))
            or "candidate_hunter:next_review_loop"
        )
        status = _queue_safe_text(value.get("status")) or _queue_safe_text(
            plan.get("status")
        )
        source_plan_id = _queue_safe_text(value.get("source_plan_id")) or _queue_safe_text(
            plan.get("plan_id")
        )
        next_review_agent = _queue_safe_text(
            value.get("next_review_agent")
        ) or _queue_safe_text(plan.get("next_review_agent"))
        review_agents = _queue_safe_list(value.get("review_agents"))
        required_evidence = _queue_safe_list(value.get("required_evidence"))
    else:
        active_steps = _safe_candidate_hunter_review_loop_steps(
            plan.get("plan_steps")
        )
        loop_id = "candidate_hunter:next_review_loop"
        status = _queue_safe_text(plan.get("status")) or "needs_review"
        source_plan_id = (
            _queue_safe_text(plan.get("plan_id"))
            or "candidate_hunter:autonomous_review_plan"
        )
        next_review_agent = (
            _queue_safe_text(plan.get("next_review_agent")) or "Human Reviewer"
        )
        review_agents = _unique_queue_values(
            step.get("assigned_agent") for step in active_steps
        )
        required_evidence = _unique_queue_values(
            evidence
            for step in active_steps
            for evidence in _queue_safe_list(step.get("required_evidence"))
        )
    if not review_agents:
        review_agents = _unique_queue_values(
            step.get("assigned_agent") for step in active_steps
        )
    if not required_evidence:
        required_evidence = _unique_queue_values(
            evidence
            for step in active_steps
            for evidence in _queue_safe_list(step.get("required_evidence"))
        )
    return {
        "loop_id": loop_id,
        "status": status or "needs_review",
        "source_plan_id": source_plan_id or "candidate_hunter:autonomous_review_plan",
        "active_step_count": len(active_steps),
        "next_review_agent": next_review_agent or "Human Reviewer",
        "review_agents": review_agents,
        "required_evidence": required_evidence,
        "active_steps": active_steps,
        "governance_summary": _safe_candidate_hunter_review_loop_governance(
            value.get("governance_summary") if isinstance(value, dict) else None,
            plan.get("hallucination_governance"),
        ),
        "blocked_actions": [
            "execute_live_validation",
            "run_fuzzer",
            "submit_report",
        ],
        "safety_gate": "review_only_no_execution",
        "completion_gate": "human_review_required",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _safe_candidate_hunter_review_loop_steps(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    steps: list[dict[str, Any]] = []
    for item in value[:10]:
        if not isinstance(item, dict):
            continue
        step_id = _queue_safe_text(item.get("step_id"))
        if not step_id:
            continue
        steps.append(
            {
                "step_id": step_id,
                "work_item_id": _queue_safe_text(item.get("work_item_id")),
                "candidate_id": _queue_safe_text(item.get("candidate_id")),
                "assigned_agent": _queue_safe_text(item.get("assigned_agent"))
                or "Human Reviewer",
                "gap": _queue_safe_text(item.get("gap")),
                "required_evidence": _queue_safe_list(item.get("required_evidence")),
                "governance_refs": _queue_safe_list(
                    item.get("governance_refs")
                    if "governance_refs" in item
                    else item.get("hallucination_governance_refs")
                ),
                "review_checklist": _safe_candidate_hunter_plan_step_checklist(
                    item.get("review_checklist")
                ),
                "next_action": _queue_safe_text(item.get("next_action")),
                "success_criteria": _queue_safe_list(item.get("success_criteria")),
                "safety_gate": "review_only_no_execution",
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            }
        )
    return steps


def _safe_candidate_hunter_review_loop_governance(
    value: Any,
    plan_governance: Any,
) -> dict[str, Any]:
    plan = (
        _safe_candidate_hunter_hallucination_governance(plan_governance)
        if isinstance(plan_governance, dict)
        else _default_candidate_hunter_hallucination_governance()
    )
    if not isinstance(value, dict):
        value = {}
    return {
        "claim_promotion_rule": _queue_safe_text(value.get("claim_promotion_rule"))
        or plan["claim_promotion_rule"],
        "required_consensus": _queue_safe_list(value.get("required_consensus"))
        or plan["required_consensus"],
        "candidate_promotion_allowed": False,
    }


def _unique_queue_values(values: Any) -> list[str]:
    seen: set[str] = set()
    items: list[str] = []
    for value in values:
        text = _queue_safe_text(value)
        if text and text not in seen:
            seen.add(text)
            items.append(text)
    return items[:10]


def _safe_agent_handoff_pack(
    value: Any,
    backlog_value: Any,
    iteration_value: Any,
    timeline_summary: dict[str, Any],
) -> dict[str, Any]:
    iteration = _safe_candidate_hunter_iteration(iteration_value)
    if isinstance(value, dict):
        handoff_items = _safe_agent_handoff_items(value.get("handoff_items"))
        pack_id = _queue_safe_text(value.get("pack_id")) or "studio:agent_handoff:next_review"
        status = _queue_safe_text(value.get("status")) or iteration["status"]
        next_review_agent = (
            _queue_safe_text(value.get("next_review_agent"))
            or iteration["next_review_agent"]
        )
        priority_order = _queue_safe_list(value.get("priority_order"))
        review_focus = _queue_safe_list(value.get("review_focus"))
        success_criteria = _queue_safe_list(value.get("success_criteria"))
        agent_queue_refs = _queue_safe_list(value.get("agent_queue_refs"))
        timeline_gate_counts = _safe_timeline_gate_counts(
            value.get("timeline_gate_counts")
        )
    else:
        handoff_items = [
            _agent_handoff_item_from_backlog(item)
            for item in _safe_candidate_hunter_backlog_items(backlog_value)[:5]
        ]
        pack_id = "studio:agent_handoff:next_review"
        status = iteration["status"]
        next_review_agent = iteration["next_review_agent"]
        priority_order = iteration["priority_order"]
        review_focus = iteration["review_focus"]
        success_criteria = iteration["success_criteria"]
        agent_queue_refs = []
        timeline_gate_counts = _safe_timeline_gate_counts(
            timeline_summary.get("gate_decision_counts")
        )
    return {
        "pack_id": pack_id,
        "status": status,
        "handoff_item_count": len(handoff_items),
        "next_review_agent": next_review_agent,
        "priority_order": priority_order,
        "review_focus": review_focus,
        "success_criteria": success_criteria,
        "handoff_items": handoff_items,
        "agent_queue_refs": agent_queue_refs,
        "timeline_gate_counts": timeline_gate_counts,
        "safety_gate": "review_only_no_execution",
        "completion_gate": "human_review_required",
        "blocked_actions": [
            "execute_live_validation",
            "run_fuzzer",
            "submit_report",
        ],
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _safe_agent_handoff_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    items: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        work_item_id = _queue_safe_text(item.get("work_item_id"))
        if not work_item_id:
            continue
        items.append(
            {
                "handoff_id": _queue_safe_text(item.get("handoff_id"))
                or f"handoff:{work_item_id}",
                "work_item_id": work_item_id,
                "candidate_id": _queue_safe_text(item.get("candidate_id")),
                "status": _queue_safe_text(item.get("status")) or "needs_review",
                "assigned_agent": _queue_safe_text(item.get("assigned_agent"))
                or _agent_for_candidate_gap(_queue_safe_text(item.get("gap"))),
                "gap": _queue_safe_text(item.get("gap")),
                "input_refs": _queue_safe_list(item.get("input_refs")),
                "review_focus": _queue_safe_list(item.get("review_focus")),
                "required_evidence": _queue_safe_list(item.get("required_evidence")),
                "success_criteria": _queue_safe_list(item.get("success_criteria")),
                "next_action": _queue_safe_text(item.get("next_action")),
                "safety_gate": "review_only_no_execution",
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            }
        )
    return items[:5]


def _agent_handoff_item_from_backlog(item: dict[str, Any]) -> dict[str, Any]:
    work_item_id = _queue_safe_text(item.get("work_item_id"))
    gap = _queue_safe_text(item.get("gap"))
    return {
        "handoff_id": f"handoff:{work_item_id}",
        "work_item_id": work_item_id,
        "candidate_id": _queue_safe_text(item.get("candidate_id")),
        "status": _queue_safe_text(item.get("status")) or "needs_review",
        "assigned_agent": _agent_for_candidate_gap(gap),
        "gap": gap,
        "input_refs": ["scope", "policy", "code", "api", "har"],
        "review_focus": _queue_safe_list(item.get("review_focus")),
        "required_evidence": _queue_safe_list(item.get("required_evidence")),
        "success_criteria": _agent_handoff_success_criteria(item),
        "next_action": _queue_safe_text(item.get("next_action")),
        "safety_gate": "review_only_no_execution",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _agent_handoff_success_criteria(item: dict[str, Any]) -> list[str]:
    work_item_id = _queue_safe_text(item.get("work_item_id")) or "candidate_work_item"
    required = _queue_safe_list(item.get("required_evidence"))
    criteria = [
        f"{work_item_id} is reviewed against authorized local artifacts.",
        "Reviewer records a human decision before promotion.",
    ]
    if required:
        criteria.append("Evidence refs required: " + ", ".join(required) + ".")
    criteria.append("No validation, fuzzing, or report submission is executed.")
    return criteria


def _candidate_hunter_plan_step_success_criteria(
    item: dict[str, Any],
) -> list[str]:
    work_item_id = _queue_safe_text(item.get("work_item_id")) or "candidate_work_item"
    required = _queue_safe_list(item.get("required_evidence"))
    criteria = [f"{work_item_id} is reviewed against authorized local artifacts."]
    if required:
        criteria.append("Evidence refs required: " + ", ".join(required) + ".")
    criteria.append("No validation, fuzzing, or report submission is executed.")
    return criteria


def _safe_candidate_hunter_plan_step_checklist(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    items: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        key = _queue_safe_text(item.get("key"))
        if not key:
            continue
        items.append(
            {
                "key": key,
                "label": _queue_safe_text(item.get("label")) or "Review item.",
                "status": _queue_safe_text(item.get("status")) or "needs_review",
                "required": item.get("required") is not False,
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            }
        )
    return items[:10]


def _candidate_hunter_plan_step_review_checklist(
    item: dict[str, Any],
) -> list[dict[str, Any]]:
    gap = _queue_safe_text(item.get("gap"))
    required = _queue_safe_list(item.get("required_evidence"))
    evidence_label = (
        "Record traceable evidence refs: " + ", ".join(required) + "."
        if required
        else "Record review notes and a human decision."
    )

    def checklist_item(key: str, label: str, status: str) -> dict[str, Any]:
        return {
            "key": key,
            "label": label,
            "status": status,
            "required": True,
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
        }

    return [
        checklist_item(
            "authorized_artifact_trace",
            "Trace the step to scope, policy, code, API, and HAR artifacts.",
            "needs_review",
        ),
        checklist_item("evidence_requirements", evidence_label, "needs_review"),
        checklist_item(
            "refutation_review",
            "Record false-positive questions or confirm existing refutation coverage.",
            "needs_review"
            if gap in {"missing_refutation_checks", "missing_cross_validation_consensus"}
            else "confirm_current_state",
        ),
        checklist_item(
            "deduplication_review",
            "Compare endpoint, code path, invariant, and impact against prior candidates.",
            "needs_review"
            if gap == "missing_deduplication_review"
            else "confirm_current_state",
        ),
        checklist_item(
            "safe_validation_plan",
            "Draft or review a non-destructive validation plan without execution.",
            "needs_review"
            if gap == "missing_safe_validation_plan"
            else "confirm_current_state",
        ),
        checklist_item(
            "submission_blocked_report_draft",
            "Confirm report draft readiness while keeping submission blocked.",
            "needs_review"
            if gap == "missing_submission_blocked_report"
            else "confirm_current_state",
        ),
    ]


def _candidate_hunter_plan_step_governance_refs(item: dict[str, Any]) -> list[str]:
    gap = _queue_safe_text(item.get("gap"))
    refs = [
        "LLM output remains an unverified claim until local evidence is traced.",
        "Knowledge/RAG context is few-shot guidance only and cannot satisfy cross-validation.",
    ]
    if gap == "missing_cross_validation_consensus":
        refs.append(
            "High confidence requires local evidence plus SARIF, fuzzing, static analysis rule, or independent refutation consensus."
        )
    return refs


def _safe_candidate_hunter_hallucination_governance(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return _default_candidate_hunter_hallucination_governance()
    default = _default_candidate_hunter_hallucination_governance()
    return {
        "claim_promotion_rule": _queue_safe_text(value.get("claim_promotion_rule"))
        or default["claim_promotion_rule"],
        "model_output_policy": _queue_safe_text(value.get("model_output_policy"))
        or default["model_output_policy"],
        "knowledge_policy": _queue_safe_text(value.get("knowledge_policy"))
        or default["knowledge_policy"],
        "required_consensus": _queue_safe_list(value.get("required_consensus"))
        or default["required_consensus"],
        "independent_challenge_sources": _queue_safe_list(
            value.get("independent_challenge_sources")
        )
        or default["independent_challenge_sources"],
        "candidate_promotion_allowed": False,
    }


def _default_candidate_hunter_hallucination_governance() -> dict[str, Any]:
    return {
        "claim_promotion_rule": "no_verified_evidence_no_high_confidence",
        "model_output_policy": "llm_claims_start_unverified",
        "knowledge_policy": "rag_few_shot_context_only_not_cross_validation",
        "required_consensus": [
            "authorized_local_artifact_evidence",
            "independent_refutation_or_static_rule",
            "human_review_decision",
        ],
        "independent_challenge_sources": [
            "sarif_static_analysis",
            "fuzzing_artifact",
            "second_model_refutation",
            "manual_code_review",
        ],
        "candidate_promotion_allowed": False,
    }


def _agent_for_candidate_gap(gap: str) -> str:
    by_gap = {
        "missing_endpoint_or_code_trace": "Semantic Auditor",
        "missing_provenance_review": "Semantic Auditor",
        "missing_refutation_checks": "Refutation Reviewer",
        "missing_deduplication_review": "Refutation Reviewer",
        "missing_safe_validation_plan": "Evidence Planner",
        "missing_submission_blocked_report": "Report Draft Builder",
        "missing_cross_validation_consensus": "Refutation Reviewer",
        "evidence_gaps_need_review": "Evidence Planner",
    }
    return by_gap.get(gap, "Human Reviewer")


def _safe_timeline_gate_counts(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        return {}
    counts: dict[str, int] = {}
    for key, count in value.items():
        safe_key = _queue_safe_text(key)
        if safe_key and isinstance(count, int) and count >= 0:
            counts[safe_key] = count
    return counts


def _safe_candidate_review_packets(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    packets: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        candidate_id = _queue_safe_text(item.get("candidate_id"))
        if not candidate_id:
            continue
        packets.append(
            {
                "candidate_id": candidate_id,
                "status": _queue_safe_text(item.get("status")) or "needs_review",
                "completed_items": _queue_safe_list(item.get("completed_items")),
                "missing_items": _queue_safe_list(item.get("missing_items")),
                "checklist": _safe_candidate_review_checklist(item.get("checklist")),
                "next_human_action": _queue_safe_text(item.get("next_human_action")),
                "safety_gate": _queue_safe_text(item.get("safety_gate"))
                or "human_review_required",
                "evidence_need_count": _queue_safe_int(item.get("evidence_need_count")),
                "false_positive_check_count": _queue_safe_int(
                    item.get("false_positive_check_count")
                ),
                "safe_validation_step_count": _queue_safe_int(
                    item.get("safe_validation_step_count")
                ),
                "quality_score": _queue_safe_int(item.get("quality_score")),
                "report_review_priority": _queue_safe_text(
                    item.get("report_review_priority")
                )
                or _report_review_priority(
                    _queue_safe_text(item.get("status")) or "needs_review",
                    _queue_safe_list(item.get("missing_items")),
                ),
                "report_status": _queue_safe_text(item.get("report_status"))
                or "submission_blocked",
                "hallucination_guard_status": _queue_safe_text(
                    item.get("hallucination_guard_status")
                )
                or "needs_review",
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            }
        )
    return packets[:5]


def _safe_submission_blocked_report_summary(
    value: Any,
    packets_value: Any,
) -> dict[str, Any]:
    if isinstance(value, dict):
        return {
            "status": _queue_safe_text(value.get("status")) or "needs_human_review",
            "candidate_count": _queue_safe_int(value.get("candidate_count")),
            "ready_candidate_ids": _queue_safe_list(value.get("ready_candidate_ids")),
            "needs_review_candidate_ids": _queue_safe_list(
                value.get("needs_review_candidate_ids")
            ),
            "missing_review_items": _safe_missing_review_items(
                value.get("missing_review_items")
            ),
            "report_review_queue": _safe_report_review_queue(
                value.get("report_review_queue")
            ),
            "next_human_actions": _queue_safe_list(value.get("next_human_actions")),
            "safety_gate": _queue_safe_text(value.get("safety_gate"))
            or "submission_blocked_human_review",
            "redaction_review_required": True,
            "report_submission_allowed": False,
            "validation_execution_allowed": False,
        }

    packets = _safe_candidate_review_packets(packets_value)
    ready_candidate_ids: list[str] = []
    needs_review_candidate_ids: list[str] = []
    missing_review_items: dict[str, list[str]] = {}
    report_review_queue: list[dict[str, Any]] = []
    next_human_actions: list[str] = []
    for packet in packets:
        candidate_id = _queue_safe_text(packet.get("candidate_id"))
        if not candidate_id:
            continue
        missing = _queue_safe_list(packet.get("missing_items"))
        status = _queue_safe_text(packet.get("status")) or "needs_review"
        if status == "review_ready" and not missing:
            ready_candidate_ids.append(candidate_id)
        else:
            needs_review_candidate_ids.append(candidate_id)
            missing_review_items[candidate_id] = missing
        next_action = _queue_safe_text(packet.get("next_human_action"))
        if next_action and next_action not in next_human_actions:
            next_human_actions.append(next_action)
        report_review_queue.append(
            {
                "candidate_id": candidate_id,
                "priority": _report_review_priority(status, missing),
                "quality_score": _queue_safe_int(packet.get("quality_score")),
                "next_human_action": next_action,
                "safety_gate": "submission_blocked_human_review",
                "report_submission_allowed": False,
                "validation_execution_allowed": False,
            }
        )
    return {
        "status": "ready_for_redaction_review"
        if ready_candidate_ids and not needs_review_candidate_ids
        else "needs_human_review",
        "candidate_count": len(packets),
        "ready_candidate_ids": ready_candidate_ids,
        "needs_review_candidate_ids": needs_review_candidate_ids,
        "missing_review_items": missing_review_items,
        "report_review_queue": _sort_report_review_queue(report_review_queue),
        "next_human_actions": next_human_actions[:5],
        "safety_gate": "submission_blocked_human_review",
        "redaction_review_required": True,
        "report_submission_allowed": False,
        "validation_execution_allowed": False,
    }


def _safe_report_review_queue(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    items: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        candidate_id = _queue_safe_text(item.get("candidate_id"))
        if not candidate_id:
            continue
        priority = _queue_safe_text(item.get("priority")) or "resolve_review_gaps"
        items.append(
            {
                "candidate_id": candidate_id,
                "priority": priority,
                "quality_score": _queue_safe_int(item.get("quality_score")),
                "next_human_action": _queue_safe_text(item.get("next_human_action")),
                "safety_gate": "submission_blocked_human_review",
                "report_submission_allowed": False,
                "validation_execution_allowed": False,
            }
        )
    return _sort_report_review_queue(items)


def _safe_readiness_audit(value: Any, *fallback_values: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return _fallback_readiness_audit(*fallback_values)

    checks = _safe_readiness_checks(value.get("checks"))
    return {
        "status": _queue_safe_text(value.get("status")) or "needs_review",
        "required_check_count": _queue_safe_int(value.get("required_check_count")),
        "passed_check_count": _queue_safe_int(value.get("passed_check_count")),
        "checks": checks,
        "safety_gate": _queue_safe_text(value.get("safety_gate"))
        or "review_only_no_execution",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _fallback_readiness_audit(*values: Any) -> dict[str, Any]:
    (
        artifacts,
        advisory_artifacts,
        candidates,
        packets,
        report_summary,
        backlog,
        iteration,
        handoff,
    ) = (list(values) + [None] * 8)[:8]
    present = _readiness_present_artifacts(artifacts)
    advisory = _readiness_present_advisory_artifacts(advisory_artifacts)
    candidate_items = _readiness_candidate_items(candidates)
    packet_items = _safe_candidate_review_packets(packets)
    report = _safe_submission_blocked_report_summary(report_summary, packet_items)
    backlog_items = _safe_candidate_hunter_backlog_items(backlog)
    iteration_item = _safe_candidate_hunter_iteration(iteration)
    handoff_item = _safe_agent_handoff_pack(
        handoff,
        backlog_items,
        iteration_item,
        {
            "gate_decision_counts": {},
            "blocked_stage_ids": [],
            "needs_review_stage_ids": [],
            "pending_stage_ids": [],
        },
    )
    checks = [
        _readiness_check(
            "authorized_ab_intake",
            all(kind in present for kind in ("scope", "policy", "code", "api", "har")),
            present,
            "Authorized policy, scope, API, HAR, and local code are present.",
        ),
        _readiness_check(
            "hallucination_governed_candidates",
            bool(packet_items)
            and all(_packet_hallucination_governed(packet) for packet in packet_items),
            _readiness_candidate_refs(candidate_items, packet_items),
            "LLM claims remain unverified until local evidence and cross-checks agree.",
        ),
        _readiness_check(
            "advisory_knowledge_context",
            "knowledge" in advisory,
            advisory,
            "Private knowledge/RAG context is advisory few-shot context only.",
        ),
        _readiness_check(
            "cross_validation_refutation",
            bool(packet_items)
            and all(_queue_safe_int(packet.get("false_positive_check_count")) > 0 for packet in packet_items)
            and any(item in advisory for item in ("sarif", "fuzzing")),
            [item for item in advisory if item in {"sarif", "fuzzing"}],
            "Independent static or fuzzing challenge and refutation questions are present.",
        ),
        _readiness_check(
            "candidate_hunter_backlog",
            not backlog_items
            and iteration_item.get("status") == "ready_for_human_review",
            _readiness_candidate_refs(candidate_items, packet_items),
            "Candidate hunter backlog is clear for human review.",
        ),
        _readiness_check(
            "safe_validation_planning",
            bool(packet_items)
            and all(_queue_safe_int(packet.get("safe_validation_step_count")) > 0 for packet in packet_items),
            _readiness_candidate_refs(candidate_items, packet_items),
            "Non-destructive validation plans exist, but execution remains blocked.",
        ),
        _readiness_check(
            "submission_blocked_report",
            report.get("status") == "ready_for_redaction_review"
            and report.get("report_submission_allowed") is False,
            _queue_safe_list(report.get("ready_candidate_ids")),
            "Report draft is ready only for redaction and human review.",
            safety_gate="submission_blocked_human_review",
        ),
        _readiness_check(
            "review_only_handoff",
            handoff_item.get("safety_gate") == "review_only_no_execution"
            and handoff_item.get("execution_allowed") is False
            and handoff_item.get("validation_allowed") is False
            and handoff_item.get("report_submission_allowed") is False,
            _queue_safe_list(handoff_item.get("agent_queue_refs")),
            "Agent handoff is review-only and cannot execute validation or submission.",
        ),
    ]
    passed_count = sum(1 for check in checks if check["status"] == "passed")
    return {
        "status": "demo_ready_for_human_review"
        if passed_count == len(checks)
        else "needs_review",
        "required_check_count": len(checks),
        "passed_check_count": passed_count,
        "checks": checks,
        "safety_gate": "review_only_no_execution",
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _readiness_check(
    key: str,
    passed: bool,
    evidence_refs: list[str],
    summary: str,
    *,
    safety_gate: str = "review_only_no_execution",
) -> dict[str, Any]:
    return {
        "key": key,
        "status": "passed" if passed else "needs_review",
        "summary": _queue_safe_text(summary),
        "evidence_refs": _queue_safe_list(evidence_refs),
        "safety_gate": safety_gate,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
    }


def _readiness_present_artifacts(value: Any) -> list[str]:
    if isinstance(value, dict):
        return _queue_safe_list(value.get("present"))
    return []


def _readiness_present_advisory_artifacts(value: Any) -> list[str]:
    if isinstance(value, dict):
        return _queue_safe_list(value.get("present"))
    return []


def _readiness_candidate_items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value[:5] if isinstance(item, dict)]


def _readiness_candidate_refs(
    candidates: list[dict[str, Any]],
    packets: list[dict[str, Any]],
) -> list[str]:
    refs: list[str] = []
    for candidate in candidates:
        candidate_id = _queue_safe_text(candidate.get("hypothesis_id"))
        if candidate_id:
            refs.append(candidate_id)
    for packet in packets:
        candidate_id = _queue_safe_text(packet.get("candidate_id"))
        if candidate_id and candidate_id not in refs:
            refs.append(candidate_id)
    return refs[:5]


def _packet_hallucination_governed(packet: dict[str, Any]) -> bool:
    return (
        packet.get("status") == "review_ready"
        and packet.get("hallucination_guard_status") == "cross_checked"
        and _queue_safe_int(packet.get("false_positive_check_count")) > 0
    )


def _safe_readiness_checks(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    checks: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        key = _queue_safe_text(item.get("key"))
        if not key:
            continue
        checks.append(
            {
                "key": key,
                "status": _queue_safe_text(item.get("status")) or "needs_review",
                "summary": _queue_safe_text(item.get("summary")),
                "evidence_refs": _queue_safe_list(item.get("evidence_refs")),
                "safety_gate": _queue_safe_text(item.get("safety_gate"))
                or "review_only_no_execution",
                "execution_allowed": False,
                "validation_allowed": False,
                "report_submission_allowed": False,
            }
        )
    return checks[:12]


def _sort_report_review_queue(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        items,
        key=lambda item: (
            _report_review_priority_rank(item.get("priority")),
            -_queue_safe_int(item.get("quality_score")),
        ),
    )[:5]


def _report_review_priority(status: str, missing_items: list[str]) -> str:
    if status == "review_ready" and not missing_items:
        return "redaction_review_ready"
    return "resolve_review_gaps"


def _report_review_priority_rank(value: Any) -> int:
    priority = _queue_safe_text(value)
    if priority == "redaction_review_ready":
        return 0
    if priority == "resolve_review_gaps":
        return 1
    return 2


def _safe_missing_review_items(value: Any) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        return {}
    items: dict[str, list[str]] = {}
    for key, raw_items in value.items():
        safe_key = _queue_safe_text(key)
        if safe_key:
            items[safe_key] = _queue_safe_list(raw_items)
    return items


def _safe_candidate_review_checklist(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    items: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        key = _queue_safe_text(item.get("key"))
        if not key:
            continue
        items.append(
            {
                "key": key,
                "status": _queue_safe_text(item.get("status")) or "needs_review",
                "label": _queue_safe_text(item.get("label")),
            }
        )
    return items[:12]


def _queue_safe_int(value: Any) -> int:
    return value if isinstance(value, int) and value >= 0 else 0


def _agent_task_timeline_items(agent_queue: list[dict[str, Any]]) -> list[dict[str, Any]]:
    timeline: list[dict[str, Any]] = []
    for item in agent_queue:
        task_id = _queue_safe_text(item.get("task_id"))
        if not task_id:
            continue
        timeline.append(
            {
                "stage_id": f"agent_queue:{task_id}",
                "task_id": task_id,
                "attempt": 1,
                "agent": _queue_safe_text(item.get("agent")),
                "status": _queue_safe_text(item.get("status")),
                "safety_gate": _queue_safe_text(item.get("safety_gate")),
                "gate_decision": _agent_task_gate_decision(item),
                "input_summary": _agent_task_input_summary(item),
                "output_summary": _agent_task_output_summary(item),
                "next_human_action": _queue_safe_text(item.get("next_action")),
                "report_submission_allowed": False,
                "validation_execution_allowed": False,
            }
        )
    return timeline[:10]


def _studio_timeline_summary(timeline: list[dict[str, Any]]) -> dict[str, Any]:
    gate_counts: dict[str, int] = {}
    blocked_stage_ids: list[str] = []
    needs_review_stage_ids: list[str] = []
    pending_stage_ids: list[str] = []
    next_human_actions: list[str] = []
    for item in timeline:
        stage_id = _queue_safe_text(item.get("stage_id"))
        gate_decision = _queue_safe_text(item.get("gate_decision")) or "pending"
        if not stage_id:
            continue
        gate_counts[gate_decision] = gate_counts.get(gate_decision, 0) + 1
        if gate_decision == "blocked":
            blocked_stage_ids.append(stage_id)
        elif gate_decision == "human_review_required":
            needs_review_stage_ids.append(stage_id)
        elif gate_decision == "pending":
            pending_stage_ids.append(stage_id)
        next_action = _queue_safe_text(item.get("next_human_action"))
        if next_action and next_action not in next_human_actions:
            next_human_actions.append(next_action)
    return {
        "total_stages": len(timeline),
        "gate_decision_counts": gate_counts,
        "blocked_stage_ids": blocked_stage_ids,
        "needs_review_stage_ids": needs_review_stage_ids,
        "pending_stage_ids": pending_stage_ids,
        "next_human_actions": next_human_actions[:5],
        "safety_gate": "review_only_no_execution",
        "report_submission_allowed": False,
        "validation_execution_allowed": False,
    }


def _agent_task_gate_decision(item: dict[str, Any]) -> str:
    status = _queue_safe_text(item.get("status"))
    if status == "complete":
        return "review_recorded"
    if status == "needs_review":
        return "human_review_required"
    if status == "blocked":
        return "blocked"
    return "pending"


def _agent_task_input_summary(item: dict[str, Any]) -> str:
    refs = _queue_safe_list(item.get("input_refs"))
    if not refs:
        return "No input refs recorded."
    return "Input refs: " + ", ".join(refs)


def _agent_task_output_summary(item: dict[str, Any]) -> str:
    candidates = _queue_safe_list(item.get("target_candidates"))
    focus = _queue_safe_list(item.get("review_focus"))
    gaps = _queue_safe_list(item.get("candidate_quality_gaps"))
    parts: list[str] = []
    if candidates:
        parts.append("candidates: " + ", ".join(candidates))
    if focus:
        parts.append("focus: " + ", ".join(focus))
    if gaps:
        parts.append("quality gaps: " + ", ".join(gaps))
    return "; ".join(parts) if parts else "No output summary recorded."


def _agent_queue_audit_markdown(audit: dict[str, Any]) -> str:
    lines = [
        "# Mythos Studio agent queue audit",
        "",
        "- Run: " + _markdown_text(audit.get("run_id"), "No run selected"),
        "- Submission blocked: true",
        "- Validation execution allowed: false",
    ]
    lines.extend(_mission_quality_summary_markdown_lines(audit.get("quality_summary")))
    lines.extend(
        _candidate_hunter_backlog_markdown_lines(
            audit.get("candidate_hunter_backlog")
        )
    )
    lines.extend(
        _candidate_hunter_iteration_markdown_lines(
            audit.get("candidate_hunter_iteration")
        )
    )
    lines.extend(_candidate_hunter_plan_markdown_lines(audit.get("candidate_hunter_plan")))
    lines.extend(
        _candidate_hunter_review_loop_markdown_lines(
            audit.get("candidate_hunter_review_loop")
        )
    )
    lines.extend(
        _candidate_hunter_review_loop_markdown_lines(
            audit.get("candidate_hunter_review_loop")
        )
    )
    lines.extend(_studio_timeline_summary_markdown_lines(audit.get("studio_timeline_summary")))
    lines.extend(_candidate_review_packets_markdown_lines(audit.get("candidate_review_packets")))
    lines.extend(
        _submission_blocked_report_summary_markdown_lines(
            audit.get("submission_blocked_report_summary")
        )
    )
    lines.extend(_readiness_audit_markdown_lines(audit.get("readiness_audit")))
    lines.extend(_agent_handoff_pack_markdown_lines(audit.get("agent_handoff_pack")))
    lines.extend(_mission_agent_queue_markdown_lines(audit.get("agent_queue")))
    lines.extend(_agent_task_timeline_markdown_lines(audit.get("task_timeline")))
    return "\n".join(lines) + "\n"


def _studio_timeline_summary_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    total_stages = _markdown_summary_value(value.get("total_stages"))
    safety_gate = _markdown_safe_text(value.get("safety_gate"))
    gate_counts = value.get("gate_decision_counts")
    count_parts: list[str] = []
    if isinstance(gate_counts, dict):
        for key, count in gate_counts.items():
            name = _markdown_safe_text(key)
            if name:
                count_parts.append(f"{name}: {_markdown_summary_value(count)}")
    lines = [
        "",
        "## Studio timeline summary",
        f"- Stages: {total_stages}; gates: {', '.join(count_parts) if count_parts else 'none'}",
        f"- Safety gate: {safety_gate}; execution allowed: false; validation allowed: false; report submission allowed: false",
    ]
    blocked = _markdown_list(value.get("blocked_stage_ids"))
    if blocked:
        lines.append("- Blocked stages: " + ", ".join(blocked))
    needs_review = _markdown_list(value.get("needs_review_stage_ids"))
    if needs_review:
        lines.append("- Needs review stages: " + ", ".join(needs_review))
    pending = _markdown_list(value.get("pending_stage_ids"))
    if pending:
        lines.append("- Pending stages: " + ", ".join(pending))
    next_actions = _markdown_list(value.get("next_human_actions"))
    if next_actions:
        lines.append("- Next human actions: " + "; ".join(next_actions))
    return lines


def _candidate_review_packets_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        return []
    lines = ["", "## Candidate review packets"]
    for item in value:
        if not isinstance(item, dict):
            continue
        candidate_id = _markdown_safe_text(item.get("candidate_id"))
        if not candidate_id:
            continue
        status = _markdown_safe_text(item.get("status")) or "needs_review"
        missing = _markdown_list(item.get("missing_items"))
        completed = _markdown_list(item.get("completed_items"))
        next_action = _markdown_safe_text(item.get("next_human_action"))
        safety_gate = _markdown_safe_text(item.get("safety_gate"))
        priority = _markdown_safe_text(item.get("report_review_priority"))
        quality_score = _markdown_summary_value(item.get("quality_score"))
        lines.append(
            f"- {candidate_id}: {status}; priority: {priority}; quality: {quality_score}/100; completed: {len(completed)}; missing: {', '.join(missing) if missing else 'none'}; gate: {safety_gate}; execution allowed: false; validation allowed: false; report submission allowed: false"
        )
        if next_action:
            lines.append(f"  - Next human action: {next_action}")
        checklist = _candidate_review_checklist_markdown_items(item.get("checklist"))
        if checklist:
            lines.append("  - Checklist: " + "; ".join(checklist))
    return lines


def _submission_blocked_report_summary_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    status = _markdown_safe_text(value.get("status")) or "needs_human_review"
    candidate_count = _markdown_summary_value(value.get("candidate_count"))
    safety_gate = _markdown_safe_text(value.get("safety_gate"))
    ready = _markdown_list(value.get("ready_candidate_ids"))
    needs_review = _markdown_list(value.get("needs_review_candidate_ids"))
    lines = [
        "",
        "## Submission-blocked report summary",
        f"- Status: {status}; candidates: {candidate_count}; ready: {len(ready)}; needs review: {len(needs_review)}",
        f"- Safety gate: {safety_gate}; redaction review required: true; validation allowed: false; report submission allowed: false",
    ]
    if ready:
        lines.append("- Ready candidates: " + ", ".join(ready))
    if needs_review:
        lines.append("- Needs review candidates: " + ", ".join(needs_review))
    missing_items = _missing_review_items_markdown(value.get("missing_review_items"))
    if missing_items:
        lines.append("- Missing review items: " + "; ".join(missing_items))
    review_queue = _report_review_queue_markdown(value.get("report_review_queue"))
    if review_queue:
        lines.append("- Report review queue: " + "; ".join(review_queue))
    next_actions = _markdown_list(value.get("next_human_actions"))
    if next_actions:
        lines.append("- Next human actions: " + "; ".join(next_actions))
    return lines


def _report_review_queue_markdown(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        candidate_id = _markdown_safe_text(item.get("candidate_id"))
        priority = _markdown_safe_text(item.get("priority"))
        quality_score = _markdown_summary_value(item.get("quality_score"))
        if candidate_id and priority:
            items.append(f"{candidate_id}: {priority} ({quality_score}/100)")
    return items[:5]


def _readiness_audit_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    status = _markdown_safe_text(value.get("status")) or "needs_review"
    required = _markdown_summary_value(value.get("required_check_count"))
    passed = _markdown_summary_value(value.get("passed_check_count"))
    safety_gate = _markdown_safe_text(value.get("safety_gate"))
    lines = [
        "",
        "## Readiness audit",
        f"- Status: {status}; passed: {passed}/{required}; safety gate: {safety_gate}",
        "- Execution allowed: false; validation allowed: false; report submission allowed: false",
    ]
    checks = value.get("checks")
    if isinstance(checks, list):
        for item in checks[:12]:
            if not isinstance(item, dict):
                continue
            key = _markdown_safe_text(item.get("key"))
            check_status = _markdown_safe_text(item.get("status")) or "needs_review"
            evidence_refs = _markdown_list(item.get("evidence_refs"))
            if key:
                evidence = ", ".join(evidence_refs) if evidence_refs else "none"
                lines.append(f"- {key}: {check_status}; evidence: {evidence}")
    return lines


def _missing_review_items_markdown(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    items: list[str] = []
    for key, raw_items in value.items():
        safe_key = _markdown_safe_text(key)
        missing = _markdown_list(raw_items)
        if safe_key and missing:
            items.append(f"{safe_key}: {', '.join(missing)}")
    return items[:10]


def _candidate_review_checklist_markdown_items(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        key = _markdown_safe_text(item.get("key"))
        status = _markdown_safe_text(item.get("status")) or "needs_review"
        if key:
            items.append(f"{key}={status}")
    return items[:12]


def _agent_handoff_pack_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    pack_id = _markdown_safe_text(value.get("pack_id"))
    if not pack_id:
        return []
    status = _markdown_safe_text(value.get("status")) or "needs_review"
    next_review_agent = (
        _markdown_safe_text(value.get("next_review_agent")) or "Human Reviewer"
    )
    handoff_item_count = _markdown_summary_value(value.get("handoff_item_count"))
    safety_gate = _markdown_safe_text(value.get("safety_gate"))
    completion_gate = _markdown_safe_text(value.get("completion_gate"))
    lines = [
        "",
        "## Agent handoff pack",
        f"- {pack_id}: {status}; next reviewer: {next_review_agent}; handoff items: {handoff_item_count}",
        f"- Gates: {safety_gate}; completion: {completion_gate}; execution allowed: false; validation allowed: false; report submission allowed: false",
    ]
    priority = _markdown_list(value.get("priority_order"))
    if priority:
        lines.append("- Priority order: " + ", ".join(priority))
    focus = _markdown_list(value.get("review_focus"))
    if focus:
        lines.append("- Review focus: " + ", ".join(focus))
    criteria = _markdown_list(value.get("success_criteria"))
    if criteria:
        lines.append("- Success criteria: " + "; ".join(criteria))
    gate_counts = _agent_handoff_gate_count_markdown_items(
        value.get("timeline_gate_counts")
    )
    if gate_counts:
        lines.append("- Timeline gates: " + ", ".join(gate_counts))
    items = _agent_handoff_item_markdown_lines(value.get("handoff_items"))
    if items:
        lines.extend(items)
    return lines


def _agent_handoff_gate_count_markdown_items(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    items: list[str] = []
    for key, count in value.items():
        safe_key = _markdown_safe_text(key)
        if safe_key:
            items.append(f"{safe_key}: {_markdown_summary_value(count)}")
    return items[:10]


def _agent_handoff_item_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    lines: list[str] = []
    for item in value[:5]:
        if not isinstance(item, dict):
            continue
        work_item_id = _markdown_safe_text(item.get("work_item_id"))
        if not work_item_id:
            continue
        status = _markdown_safe_text(item.get("status")) or "needs_review"
        assigned_agent = _markdown_safe_text(item.get("assigned_agent"))
        gap = _markdown_safe_text(item.get("gap"))
        candidate_id = _markdown_safe_text(item.get("candidate_id"))
        focus = ", ".join(_markdown_list(item.get("review_focus")))
        required_evidence = ", ".join(_markdown_list(item.get("required_evidence")))
        next_action = _markdown_safe_text(item.get("next_action"))
        line = (
            f"- {work_item_id}: {status}; candidate: {candidate_id}; "
            f"agent: {assigned_agent}; gap: {gap}; execution allowed: false; "
            "validation allowed: false; report submission allowed: false"
        )
        if focus:
            line += f"; focus: {focus}"
        if required_evidence:
            line += f"; evidence: {required_evidence}"
        lines.append(line)
        criteria = _markdown_list(item.get("success_criteria"))
        if criteria:
            lines.append("  - Success criteria: " + "; ".join(criteria))
        if next_action:
            lines.append(f"  - Next action: {next_action}")
    return lines


def _agent_task_timeline_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        return []
    lines = ["", "## Agent task timeline"]
    for item in value:
        if not isinstance(item, dict):
            continue
        stage_id = _queue_safe_text(item.get("stage_id"))
        status = _queue_safe_text(item.get("status"))
        gate_decision = _queue_safe_text(item.get("gate_decision"))
        input_summary = _queue_safe_text(item.get("input_summary"))
        output_summary = _queue_safe_text(item.get("output_summary"))
        next_human_action = _queue_safe_text(item.get("next_human_action"))
        if not stage_id:
            continue
        lines.append(
            f"- {stage_id}: {status}; gate: {gate_decision}; input: {input_summary}; output: {output_summary}; next: {next_human_action}"
        )
    return lines


def _queue_safe_text(value: Any) -> str:
    text = _markdown_safe_text(value)
    if text in BLOCKED_ACTIONS:
        return ""
    return text


def _queue_safe_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value:
        text = _queue_safe_text(item)
        if text:
            items.append(text)
    return items[:10]


def _mission_quality_summary_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    lines = ["", "## Mission quality"]
    fields = [
        ("Status", value.get("status")),
        ("Top candidate quality gate", value.get("top_candidate_quality_gate")),
        ("Review-ready candidates", value.get("review_ready_count")),
        ("Average quality score", value.get("average_quality_score")),
    ]
    for label, raw_value in fields:
        text = _markdown_summary_value(raw_value)
        if text:
            lines.append(f"- {label}: {text}")
    blockers = _markdown_list(value.get("blockers"))
    if blockers:
        lines.append("- Blockers: " + "; ".join(blockers))
    actions = _markdown_list(value.get("improvement_actions"))
    if actions:
        lines.append("- Improvement actions: " + "; ".join(actions))
    return lines if len(lines) > 2 else []


def _candidate_hunter_backlog_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        return []
    lines = ["", "## Candidate hunter backlog"]
    for item in value[:10]:
        if not isinstance(item, dict):
            continue
        work_item_id = _markdown_safe_text(item.get("work_item_id"))
        gap = _markdown_safe_text(item.get("gap"))
        status = _markdown_safe_text(item.get("status"))
        safety_gate = _markdown_safe_text(item.get("safety_gate"))
        focus = ", ".join(_markdown_list(item.get("review_focus")))
        required_evidence = ", ".join(_markdown_list(item.get("required_evidence")))
        next_action = _markdown_safe_text(item.get("next_action"))
        if not work_item_id:
            continue
        line = f"- {work_item_id}: {gap} ({status}, {safety_gate})"
        if focus:
            line += f"; focus: {focus}"
        if required_evidence:
            line += f"; evidence: {required_evidence}"
        if next_action:
            line += f"; next: {next_action}"
        lines.append(line)
    return lines if len(lines) > 2 else []


def _candidate_hunter_iteration_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    iteration_id = _markdown_safe_text(value.get("iteration_id"))
    if not iteration_id:
        return []
    status = _markdown_safe_text(value.get("status"))
    next_review_agent = _markdown_safe_text(value.get("next_review_agent"))
    safety_gate = _markdown_safe_text(value.get("safety_gate"))
    completion_gate = _markdown_safe_text(value.get("completion_gate"))
    work_item_count = _markdown_summary_value(value.get("work_item_count"))
    lines = [
        "",
        "## Candidate hunter iteration",
        f"- {iteration_id}: {status}; next reviewer: {next_review_agent}; work items: {work_item_count}",
        f"- Gates: {safety_gate}; completion: {completion_gate}; execution allowed: false; validation allowed: false; report submission allowed: false",
    ]
    priority = _markdown_list(value.get("priority_order"))
    if priority:
        lines.append("- Priority order: " + ", ".join(priority))
    focus = _markdown_list(value.get("review_focus"))
    if focus:
        lines.append("- Review focus: " + ", ".join(focus))
    criteria = _markdown_list(value.get("success_criteria"))
    if criteria:
        lines.append("- Success criteria: " + "; ".join(criteria))
    return lines


def _candidate_hunter_plan_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    plan_id = _markdown_safe_text(value.get("plan_id"))
    if not plan_id:
        return []
    status = _markdown_safe_text(value.get("status")) or "needs_review"
    next_review_agent = _markdown_safe_text(value.get("next_review_agent"))
    safety_gate = _markdown_safe_text(value.get("safety_gate"))
    completion_gate = _markdown_safe_text(value.get("completion_gate"))
    work_item_count = _markdown_summary_value(value.get("work_item_count"))
    step_count = _markdown_summary_value(value.get("step_count"))
    lines = [
        "",
        "## Candidate hunter plan",
        f"- {plan_id}: {status}; next reviewer: {next_review_agent}; work items: {work_item_count}; steps: {step_count}",
        f"- Gates: {safety_gate}; completion: {completion_gate}; execution allowed: false; validation allowed: false; report submission allowed: false",
    ]
    governance = value.get("hallucination_governance")
    if isinstance(governance, dict):
        lines.append(
            "- Hallucination governance: "
            + "; ".join(
                [
                    f"claim promotion: {_markdown_safe_text(governance.get('claim_promotion_rule'))}",
                    f"model output: {_markdown_safe_text(governance.get('model_output_policy'))}",
                    f"knowledge: {_markdown_safe_text(governance.get('knowledge_policy'))}",
                    "candidate promotion allowed: false",
                ]
            )
        )
        required = _markdown_list(governance.get("required_consensus"))
        if required:
            lines.append("- Required consensus: " + ", ".join(required))
        challenges = _markdown_list(governance.get("independent_challenge_sources"))
        if challenges:
            lines.append("- Independent challenge sources: " + ", ".join(challenges))
    steps = value.get("plan_steps")
    if isinstance(steps, list):
        for item in steps[:10]:
            if not isinstance(item, dict):
                continue
            step_id = _markdown_safe_text(item.get("step_id"))
            work_item_id = _markdown_safe_text(item.get("work_item_id"))
            assigned_agent = _markdown_safe_text(item.get("assigned_agent"))
            gap = _markdown_safe_text(item.get("gap"))
            focus = ", ".join(_markdown_list(item.get("review_focus")))
            evidence = ", ".join(_markdown_list(item.get("required_evidence")))
            next_action = _markdown_safe_text(item.get("next_action"))
            if not step_id:
                continue
            line = (
                f"- {step_id}: {assigned_agent} handles {work_item_id}; gap: {gap}"
            )
            if focus:
                line += f"; focus: {focus}"
            if evidence:
                line += f"; evidence: {evidence}"
            if next_action:
                line += f"; next: {next_action}"
            lines.append(line)
            governance_refs = _markdown_list(item.get("hallucination_governance_refs"))
            if governance_refs:
                lines.append("  - Governance refs: " + "; ".join(governance_refs))
            checklist = _candidate_hunter_plan_checklist_markdown_items(
                item.get("review_checklist")
            )
            if checklist:
                lines.append("  - Review checklist: " + "; ".join(checklist))
    return lines


def _candidate_hunter_plan_checklist_markdown_items(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for item in value[:10]:
        if not isinstance(item, dict):
            continue
        key = _markdown_safe_text(item.get("key"))
        status = _markdown_safe_text(item.get("status"))
        if key and status:
            items.append(f"{key}: {status}")
    return items


def _candidate_hunter_review_loop_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    loop_id = _markdown_safe_text(value.get("loop_id"))
    if not loop_id:
        return []
    status = _markdown_safe_text(value.get("status")) or "needs_review"
    source_plan_id = _markdown_safe_text(value.get("source_plan_id"))
    next_review_agent = (
        _markdown_safe_text(value.get("next_review_agent")) or "Human Reviewer"
    )
    active_step_count = _markdown_summary_value(value.get("active_step_count"))
    lines = [
        "",
        "## Candidate hunter review loop",
        f"- {loop_id}: {status}; source plan: {source_plan_id}; next reviewer: {next_review_agent}; active steps: {active_step_count}",
        "- Gates: review_only_no_execution; completion: human_review_required; execution allowed: false; validation allowed: false; report submission allowed: false",
    ]
    review_agents = _markdown_list(value.get("review_agents"))
    if review_agents:
        lines.append("- Review agents: " + ", ".join(review_agents))
    required_evidence = _markdown_list(value.get("required_evidence"))
    if required_evidence:
        lines.append("- Required evidence: " + ", ".join(required_evidence))
    governance = value.get("governance_summary")
    if isinstance(governance, dict):
        required = _markdown_list(governance.get("required_consensus"))
        lines.append(
            "- Governance: "
            f"claim promotion: {_markdown_safe_text(governance.get('claim_promotion_rule'))}; "
            "candidate promotion allowed: false"
        )
        if required:
            lines.append("- Required consensus: " + ", ".join(required))
    active_steps = value.get("active_steps")
    if isinstance(active_steps, list):
        for item in active_steps[:10]:
            if not isinstance(item, dict):
                continue
            step_id = _markdown_safe_text(item.get("step_id"))
            work_item_id = _markdown_safe_text(item.get("work_item_id"))
            assigned_agent = _markdown_safe_text(item.get("assigned_agent"))
            gap = _markdown_safe_text(item.get("gap"))
            evidence = ", ".join(_markdown_list(item.get("required_evidence")))
            next_action = _markdown_safe_text(item.get("next_action"))
            if not step_id:
                continue
            line = (
                f"- {step_id}: {assigned_agent} handles {work_item_id}; gap: {gap}"
            )
            if evidence:
                line += f"; evidence: {evidence}"
            if next_action:
                line += f"; next: {next_action}"
            lines.append(line)
            checklist = _candidate_hunter_plan_checklist_markdown_items(
                item.get("review_checklist")
            )
            if checklist:
                lines.append("  - Review checklist: " + "; ".join(checklist))
    return lines


def _markdown_summary_value(value: Any) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, int):
        return str(value)
    return _markdown_safe_text(value)


def _mission_candidate_quality_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        return []
    lines = ["", "## Candidate quality"]
    for item in value[:5]:
        if not isinstance(item, dict):
            continue
        hypothesis_id = _markdown_safe_text(item.get("hypothesis_id"))
        quality_status = _markdown_safe_text(item.get("quality_status"))
        quality_score_value = item.get("quality_score")
        quality_score = (
            str(quality_score_value)
            if isinstance(quality_score_value, int) and quality_score_value >= 0
            else _markdown_safe_text(quality_score_value)
        )
        reasons = ", ".join(_markdown_list(item.get("quality_reasons")))
        if hypothesis_id:
            lines.append(
                f"- {hypothesis_id}: {quality_status} ({quality_score}/100); reasons: {reasons}"
            )
    return lines


def _mission_hallucination_guard_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        return []
    lines = ["", "## Hallucination guard"]
    for item in value[:5]:
        if not isinstance(item, dict):
            continue
        hypothesis_id = _markdown_safe_text(item.get("hypothesis_id"))
        guard = item.get("hallucination_guard")
        if not hypothesis_id or not isinstance(guard, dict):
            continue
        status = _markdown_safe_text(guard.get("status"))
        model_output_status = _markdown_safe_text(guard.get("model_output_status"))
        sources = ", ".join(_markdown_list(guard.get("cross_validation_sources")))
        blockers = ", ".join(_markdown_list(guard.get("blockers")))
        line = f"- {hypothesis_id}: {status}; model output: {model_output_status}"
        if sources:
            line += f"; sources: {sources}"
        if blockers:
            line += f"; blockers: {blockers}"
        lines.append(line)
    return lines if len(lines) > 2 else []


def _mission_candidate_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        return []
    lines = ["", "## Top candidates"]
    for item in value[:5]:
        if not isinstance(item, dict):
            continue
        hypothesis_id = _markdown_safe_text(item.get("hypothesis_id"))
        vuln_type = _markdown_safe_text(item.get("vuln_type")) or "candidate"
        endpoint = _markdown_safe_text(item.get("affected_endpoint"))
        code_path = _markdown_safe_text(item.get("affected_code_path"))
        report_status = _markdown_safe_text(item.get("report_status"))
        if hypothesis_id:
            lines.append(
                f"- {hypothesis_id}: {vuln_type}; endpoint: {endpoint}; code path: {code_path}; report: {report_status}"
            )
            lines.extend(
                _mission_candidate_review_packet_lines(
                    item,
                    {
                        "evidence_needed": "Evidence needed",
                        "false_positive_checks": "Refutation questions",
                        "evidence_gaps": "Evidence gaps",
                        "safe_validation_plan": "Safe validation plan",
                        "safety_blockers": "Safety blockers",
                    },
                )
            )
    return lines


def _mission_candidate_review_packet_lines(
    item: dict[str, Any],
    labels: dict[str, str],
) -> list[str]:
    lines: list[str] = []
    for key, label in labels.items():
        values = _mission_review_packet_values(key, item.get(key))
        if values:
            lines.append(f"  - {label}: {'; '.join(values)}")
    next_action = _markdown_safe_text(item.get("next_report_action"))
    if next_action:
        lines.append(f"  - Next report action: {next_action}")
    return lines


def _mission_review_packet_values(key: str, value: Any) -> list[str]:
    if key != "safety_blockers":
        return _markdown_list(value)
    return _safety_blocker_markdown_list(value)


def _safety_blocker_markdown_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    values: list[str] = []
    for item in value:
        text = _markdown_text(item, "")
        if not text or _secret_like_text(text):
            continue
        mapped = SAFETY_BLOCKER_LABELS.get(text)
        if mapped:
            values.append(mapped)
        elif text not in BLOCKED_ACTIONS:
            values.append(text)
    return values


def _top_candidate_reviews_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for candidate in value[:5]:
        if not isinstance(candidate, dict):
            continue
        hypothesis_id = _markdown_safe_text(candidate.get("hypothesis_id"))
        if not hypothesis_id:
            continue
        vuln_type = _markdown_safe_text(candidate.get("vuln_type")) or "candidate"
        risk = _markdown_safe_text(candidate.get("risk")) or "medium"
        endpoint = _markdown_safe_text(candidate.get("affected_endpoint")) or "endpoint review"
        code_path = _markdown_safe_text(candidate.get("affected_code_path")) or "code-path review"
        report_status = _markdown_safe_text(candidate.get("report_status")) or "submission_blocked"
        validation_status = (
            _markdown_safe_text(candidate.get("validation_status")) or "needs_human_review"
        )
        evidence_count = _markdown_count(candidate.get("evidence_need_count"))
        false_positive_count = _markdown_count(candidate.get("false_positive_check_count"))
        items.append(
            f"{hypothesis_id}: {risk} {vuln_type} at {endpoint} -> {code_path}; "
            f"evidence needs: {evidence_count}; false-positive checks: {false_positive_count}; "
            f"report: {report_status}; validation: {validation_status}"
        )
    if not items:
        return []
    return ["", "## Top candidate reviews", *[f"- {item}" for item in items]]


def _markdown_count(value: Any) -> int:
    return value if isinstance(value, int) and value >= 0 else 0


def _report_readiness_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    items: list[str] = []
    status = _markdown_safe_text(value.get("status"))
    if status:
        items.append(f"Status: {status}")
    if isinstance(value.get("report_submission_allowed"), bool):
        allowed = str(value["report_submission_allowed"]).lower()
        items.append(f"Report submission allowed: {allowed}")
    next_allowed_action = _markdown_safe_text(value.get("next_allowed_action"))
    if next_allowed_action:
        items.append(f"Next allowed action: {next_allowed_action}")
    if not items:
        return []
    return ["", "## Report readiness", *[f"- {item}" for item in items]]


def _evidence_review_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    items: list[str] = []
    status = _markdown_safe_text(value.get("status"))
    if status:
        items.append(f"Status: {status}")
    required_items = _markdown_list(value.get("required_items"))
    items.extend(required_items)
    if not items:
        return []
    return ["", "## Evidence review", *[f"- {item}" for item in items]]


def _deduplication_review_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    items: list[str] = []
    status = _markdown_safe_text(value.get("status"))
    if status:
        items.append(f"Status: {status}")
    duplicate_risk_score = value.get("duplicate_risk_score")
    if isinstance(duplicate_risk_score, int):
        items.append(f"Duplicate risk score: {duplicate_risk_score}")
    review_items = _markdown_list(value.get("review_items"))
    items.extend(review_items)
    if not items:
        return []
    return ["", "## Deduplication review", *[f"- {item}" for item in items]]


def _refutation_review_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    items: list[str] = []
    status = _markdown_safe_text(value.get("status"))
    if status:
        items.append(f"Status: {status}")
    questions = _markdown_list(value.get("questions"))
    items.extend(questions)
    if not items:
        return []
    return ["", "## Refutation review", *[f"- {item}" for item in items]]


def _policy_review_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    items: list[str] = []
    status = _markdown_safe_text(value.get("status"))
    if status:
        items.append(f"Status: {status}")
    policy_risk = _markdown_safe_text(value.get("policy_risk"))
    if policy_risk:
        items.append(f"Policy risk: {policy_risk}")
    policy_risk_score = value.get("policy_risk_score")
    if isinstance(policy_risk_score, int):
        items.append(f"Policy risk score: {policy_risk_score}")
    review_items = _markdown_list(value.get("review_items"))
    items.extend(review_items)
    if not items:
        return []
    return ["", "## Policy review", *[f"- {item}" for item in items]]


def _provenance_review_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    items: list[str] = []
    status = _markdown_safe_text(value.get("status"))
    if status:
        items.append(f"Status: {status}")
    artifact_kinds = _markdown_list(value.get("artifact_kinds"))
    if artifact_kinds:
        items.append(f"Artifact kinds: {', '.join(artifact_kinds)}")
    review_items = _markdown_list(value.get("review_items"))
    items.extend(review_items)
    if not items:
        return []
    return ["", "## Provenance review", *[f"- {item}" for item in items]]


def _validation_review_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    items: list[str] = []
    status = _markdown_safe_text(value.get("status"))
    if status:
        items.append(f"Status: {status}")
    if isinstance(value.get("execution_allowed"), bool):
        allowed = str(value["execution_allowed"]).lower()
        items.append(f"Execution allowed: {allowed}")
    review_items = _markdown_list(value.get("review_items"))
    items.extend(review_items)
    if not items:
        return []
    return ["", "## Validation review", *[f"- {item}" for item in items]]


def _studio_context_markdown_lines(value: Any) -> list[str]:
    if not isinstance(value, dict):
        return []
    lines: list[str] = []
    required = _markdown_list(value.get("required_artifacts"))
    if required:
        lines.extend(["", "## Studio A+B context", ""])
        lines.append(f"- Required artifacts: {', '.join(required)}")
    for fact in _studio_context_surface_lines(value.get("surface_facts")):
        if not lines:
            lines.extend(["", "## Studio A+B context", ""])
        lines.append(f"- {fact}")
    notes = _markdown_list(value.get("safety_notes"))
    for note in notes:
        if not lines:
            lines.extend(["", "## Studio A+B context", ""])
        lines.append(f"- {note}")
    return lines


def _studio_context_surface_lines(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    lines: list[str] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        artifact_kind = _markdown_text(item.get("artifact_kind"), "").upper()
        method = _markdown_text(item.get("route_method"), "")
        route_path = _markdown_text(item.get("route_path"), "")
        if not artifact_kind or not method or not route_path:
            continue
        line = f"{artifact_kind} {method} {route_path}"
        if not _secret_like_text(line):
            lines.append(line)
    return lines


def _markdown_text(value: Any, fallback: str) -> str:
    if not isinstance(value, str):
        return fallback
    return value.replace("\r", " ").replace("\n", " ").strip() or fallback


def _markdown_safe_text(value: Any) -> str:
    text = _markdown_text(value, "")
    if not text or _secret_like_text(text):
        return ""
    return text


def _markdown_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [
        text
        for item in value
        if (text := _markdown_text(item, "")) and not _secret_like_text(text)
    ]


def _secret_like_text(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in SECRET_MARKERS)


def _safe_name(value: str) -> str:
    cleaned = "".join(
        ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in value.strip()
    )
    return cleaned or "workspace"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "StudioArtifactImport",
    "StudioWorkspace",
    "create_workspace",
    "import_workspace_artifact",
    "load_workspace_manifest",
    "record_workspace_benchmark_result",
    "record_workspace_benchmark_template",
    "record_workspace_mission_dossier",
    "record_workspace_report_export",
    "record_workspace_run",
]
