"""Resolve redacted live/HH track-record package paths for scoreboard attach.

Priority (highest first):
1. Explicit CLI paths
2. Environment variables
3. Drop-directory discovery under authorized_track_records/

Never returns committed synthetic fixtures as attached packages.
has_real_* still only flips when package source_kind + auth + fields qualify.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping

SCHEMA_VERSION = "track_record_path_resolver_v1"

ENV_LIVE = "MYTHOS_LIVE_TRACK_RECORD"
ENV_HUMAN_HOUR = "MYTHOS_HUMAN_HOUR_TRACK_RECORD"
ENV_DROP_DIR = "MYTHOS_TRACK_RECORD_DIR"

DEFAULT_DROP_DIR_NAME = "authorized_track_records"

_LIVE_NAMES = (
    "authorized_live_outcomes.export.json",
    "authorized_live_outcomes.json",
    "live_outcomes.json",
)
_HH_NAMES = (
    "human_hour_review_logs.export.json",
    "human_hour_review_logs.json",
    "redacted_review_logs.json",
)


def default_drop_dir(*, start: Path | None = None) -> Path:
    """Locate authorized_track_records near cwd / apps/api / repo root."""
    here = (start or Path.cwd()).resolve()
    candidates = [
        here / DEFAULT_DROP_DIR_NAME,
        here / "apps" / "api" / DEFAULT_DROP_DIR_NAME,
    ]
    # walk up a few levels
    cur = here
    for _ in range(5):
        candidates.append(cur / DEFAULT_DROP_DIR_NAME)
        candidates.append(cur / "apps" / "api" / DEFAULT_DROP_DIR_NAME)
        if cur.parent == cur:
            break
        cur = cur.parent
    for path in candidates:
        if path.is_dir():
            return path
    # Prefer apps/api when present, else cwd
    api = here / "apps" / "api"
    if api.is_dir():
        return api / DEFAULT_DROP_DIR_NAME
    if here.name == "api" and (here / "app").is_dir():
        return here / DEFAULT_DROP_DIR_NAME
    return here / DEFAULT_DROP_DIR_NAME


def resolve_attached_track_record_paths(
    *,
    live_log: str | Path | None = None,
    human_hour_log: str | Path | None = None,
    drop_dir: str | Path | None = None,
    env: Mapping[str, str] | None = None,
    start: Path | None = None,
) -> dict[str, Any]:
    """Resolve optional attached live + human-hour package paths."""
    environ = env if env is not None else os.environ
    sources: dict[str, str | None] = {"live": None, "human_hour": None}

    live_path = _as_existing_file(live_log)
    if live_path is not None:
        sources["live"] = "cli"
    else:
        live_path = _as_existing_file(environ.get(ENV_LIVE))
        if live_path is not None:
            sources["live"] = "env"

    hh_path = _as_existing_file(human_hour_log)
    if hh_path is not None:
        sources["human_hour"] = "cli"
    else:
        hh_path = _as_existing_file(environ.get(ENV_HUMAN_HOUR))
        if hh_path is not None:
            sources["human_hour"] = "env"

    resolved_drop = _as_dir(drop_dir) if drop_dir else None
    if resolved_drop is None:
        env_drop = environ.get(ENV_DROP_DIR)
        if env_drop:
            resolved_drop = _as_dir(env_drop)
    if resolved_drop is None:
        candidate = default_drop_dir(start=start)
        if candidate.is_dir():
            resolved_drop = candidate

    if resolved_drop is not None:
        if live_path is None:
            found = _find_named(resolved_drop, _LIVE_NAMES)
            if found is not None:
                live_path = found
                sources["live"] = "drop_dir"
        if hh_path is None:
            found = _find_named(resolved_drop, _HH_NAMES)
            if found is not None:
                hh_path = found
                sources["human_hour"] = "drop_dir"

    return {
        "schema_version": SCHEMA_VERSION,
        "live_log": str(live_path) if live_path else None,
        "human_hour_log": str(hh_path) if hh_path else None,
        "drop_dir": str(resolved_drop) if resolved_drop else None,
        "sources": sources,
        "env_keys": {
            "live": ENV_LIVE,
            "human_hour": ENV_HUMAN_HOUR,
            "drop_dir": ENV_DROP_DIR,
        },
        "never_auto_selects_committed_synthetic_fixtures": True,
    }


def publish_track_record_exports_to_drop_dir(
    *,
    live_path: str | Path | None,
    human_hour_path: str | Path | None,
    drop_dir: str | Path | None = None,
    human_allow_write: bool = False,
    start: Path | None = None,
) -> dict[str, Any]:
    """Copy export packages into the drop directory for auto-attach."""
    if not human_allow_write:
        raise ValueError("human_allow_write_required_for_drop_dir_publish")

    if drop_dir is not None and str(drop_dir).strip():
        dest = Path(drop_dir)
    else:
        dest = default_drop_dir(start=start)
    dest.mkdir(parents=True, exist_ok=True)

    written: dict[str, str | None] = {"live": None, "human_hour": None}
    if live_path:
        src = Path(live_path)
        if not src.is_file():
            raise ValueError(f"live_export_missing:{src}")
        target = dest / "authorized_live_outcomes.export.json"
        target.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        written["live"] = str(target.resolve())
    if human_hour_path:
        src = Path(human_hour_path)
        if not src.is_file():
            raise ValueError(f"human_hour_export_missing:{src}")
        target = dest / "human_hour_review_logs.export.json"
        target.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
        written["human_hour"] = str(target.resolve())

    return {
        "schema_version": SCHEMA_VERSION,
        "drop_dir": str(dest.resolve()),
        "written": written,
        "execution_allowed": False,
        "report_submission_allowed": False,
    }


def _as_existing_file(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    path = Path(text)
    return path if path.is_file() else None


def _as_dir(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    path = Path(text)
    return path if path.is_dir() else None


def _find_named(root: Path, names: tuple[str, ...]) -> Path | None:
    for name in names:
        direct = root / name
        if direct.is_file():
            return direct
    # shallow scan one level of subdirs
    for name in names:
        for child in root.iterdir():
            if child.is_dir():
                candidate = child / name
                if candidate.is_file():
                    return candidate
    return None
