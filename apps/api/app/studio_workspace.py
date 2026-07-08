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
    agent_queue_audit = _agent_queue_audit(run_id, mission)
    dossier_path.write_text(json.dumps(mission, indent=2), encoding="utf-8")
    markdown_path.write_text(_mission_dossier_markdown(mission), encoding="utf-8")
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
            "candidate_hunter_backlog_count": len(
                agent_queue_audit["candidate_hunter_backlog"]
            ),
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


def _agent_queue_audit(run_id: str | None, mission: dict[str, Any]) -> dict[str, Any]:
    quality_summary = mission.get("quality_summary")
    agent_queue = _safe_agent_queue_items(mission.get("agent_queue"))
    return {
        "run_id": run_id,
        "agent_queue": agent_queue,
        "task_timeline": _agent_task_timeline_items(agent_queue),
        "candidate_hunter_backlog": _safe_candidate_hunter_backlog_items(
            mission.get("candidate_hunter_backlog")
        ),
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
    lines.extend(_mission_agent_queue_markdown_lines(audit.get("agent_queue")))
    lines.extend(_agent_task_timeline_markdown_lines(audit.get("task_timeline")))
    return "\n".join(lines) + "\n"


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
