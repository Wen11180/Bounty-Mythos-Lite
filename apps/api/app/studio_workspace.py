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
            "source_path": artifact.source_path,
            "source_hash": _sha256(source_path),
            "sensitivity_label": sensitivity_label,
            "redaction_status": (
                "needs_review" if sensitivity_label == "sensitive" else "not_required"
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
            "report_path": report_path,
            "candidate_count": candidate_count,
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
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _sensitivity_label(path: Path) -> str:
    text = path.read_text(encoding="utf-8-sig").lower()
    if any(marker in text for marker in SECRET_MARKERS):
        return "sensitive"
    return "low"


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
    "record_workspace_run",
]
