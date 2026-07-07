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
    "evidence",
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
    "record_workspace_report_export",
    "record_workspace_run",
]
