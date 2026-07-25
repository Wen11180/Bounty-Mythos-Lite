"""Scaffold an authorized research-session package ready for capture.

Does not fabricate real track-record outcomes or flip has_real_*.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.intelligence_benchmark.authorized_research_track_record_export import (
    build_demo_session_notes,
)

SCHEMA_VERSION = "prepare_research_session_package_v1"


class PrepareResearchSessionError(ValueError):
    """Invalid prepare request."""


def prepare_research_session_package(
    *,
    package_root: str | Path,
    program_handle: str = "",
    program_authorization_id: str = "",
    include_synthetic_examples: bool = True,
    human_allow_write: bool = False,
) -> dict[str, Any]:
    """Create package layout expected by capture-research-session-track-record."""
    if not human_allow_write:
        raise PrepareResearchSessionError(
            "human_allow_write_required_for_prepare_package"
        )

    root = Path(package_root)
    root.mkdir(parents=True, exist_ok=True)
    inputs = root / "inputs"
    export = root / "_export" / "wall_clock_multi_hour_runner"
    inputs.mkdir(parents=True, exist_ok=True)
    export.mkdir(parents=True, exist_ok=True)

    handle = (program_handle or root.name or "research-session").strip()
    auth = (program_authorization_id or "").strip()

    written: list[str] = []

    readme = root / "CAPTURE_README.md"
    readme.write_text(
        _readme_text(handle=handle, auth=auth, package_root=root),
        encoding="utf-8",
    )
    written.append(str(readme))

    checklist = root / "AUTHORIZATION_CHECKLIST.md"
    checklist.write_text(_checklist_text(auth=auth), encoding="utf-8")
    written.append(str(checklist))

    if include_synthetic_examples:
        notes_example = inputs / "session_notes.example.json"
        notes_example.write_text(
            json.dumps(build_demo_session_notes(), indent=2, ensure_ascii=False)
            + "\n",
            encoding="utf-8",
        )
        written.append(str(notes_example))

        # Starter session notes copy for dry-run. Its source marker prevents an
        # accidental real-package declaration until it is replaced.
        notes = inputs / "session_notes.json"
        if not notes.exists():
            notes.write_text(
                json.dumps(build_demo_session_notes(), indent=2, ensure_ascii=False)
                + "\n",
                encoding="utf-8",
            )
            written.append(str(notes))

        wall_example = inputs / "wall_clock_runner.example.json"
        wall_payload = {
            "schema_version": "wall_clock_multi_hour_runner_v1",
            "source_kind": "synthetic",
            "fixture_kind": "synthetic_research_session_wall_clock_example",
            "package_id": root.name,
            "program_handle": handle,
            "total_wall_clock_minutes": 70.0,
            "notes": "Example only. Replace with real multi-hour runner export.",
            "execution_allowed": False,
            "report_submission_allowed": False,
        }
        wall_example.write_text(
            json.dumps(wall_payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        written.append(str(wall_example))

    meta = {
        "schema_version": SCHEMA_VERSION,
        "package_root": str(root.resolve()),
        "program_handle": handle,
        "program_authorization_id": auth or None,
        "declare_real_package": False,
        "source_kind_default": "synthetic",
        "capture_command": (
            "python -m app capture-research-session-track-record "
            f"--package-root {root} "
            "--out-dir <out> --human-allow-export-write"
        ),
        "real_capture_requires": [
            "replace_synthetic_or_template_inputs",
            "--declare-real-package",
            "--program-authorization-id <auth-ref>",
        ],
        "execution_allowed": False,
        "report_submission_allowed": False,
        "auto_attack_allowed": False,
        "non_claims": [
            "Scaffold only; does not create real authorized outcomes.",
            "has_real_* remains false until non-synthetic inputs + declare + auth ref + real fields.",
        ],
        "written": written,
    }
    meta_path = root / "package_prepare_manifest.json"
    meta_path.write_text(
        json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    written.append(str(meta_path))
    meta["written"] = written
    return meta


def _readme_text(*, handle: str, auth: str, package_root: Path) -> str:
    auth_line = auth or "AUTH-REF-001"
    return f"""# Research session package (capture-ready)

Program handle: `{handle}`
Authorization ref placeholder: `{auth_line}`

## Layout

- `inputs/session_notes.json` — redacted session notes (wall_clock_minutes, outcomes)
- `inputs/wall_clock_runner.json` — optional multi-hour runner export
- residual human-review approvals under this package root (if your workflow stores them)

## Synthetic dry-run

```powershell
python -m app capture-research-session-track-record `
  --package-root "{package_root}" `
  --out-dir tmp/capture-demo `
  --human-allow-export-write
```

Never flips `has_real_*`.

## Real authorized attach

1. Replace every `source_kind=synthetic` or template-marked example with
   **redacted real** session outcomes. Merely adding `--declare-real-package`
   to scaffold input is rejected.
2. Ensure entries include `wall_clock_minutes` and at least one
   `human_confirmed_valid` + `report_outcome_ref` when claiming valid-report gap.
3. No secrets/tokens/cookies/Authorization headers.
4. Capture with explicit declare:

```powershell
python -m app capture-research-session-track-record `
  --package-root "{package_root}" `
  --program-handle "{handle}" `
  --program-authorization-id "{auth_line}" `
  --declare-real-package `
  --human-allow-export-write `
  --out-dir tmp/capture-real `
  --publish-drop-dir
```

5. Re-score:

```powershell
python -m app market-leadership-scoreboard --out tmp/market.json
python -m app delivery-readiness --out tmp/delivery.json
```

Or set env / drop files:

- `MYTHOS_LIVE_TRACK_RECORD`
- `MYTHOS_HUMAN_HOUR_TRACK_RECORD`
- `MYTHOS_TRACK_RECORD_DIR` (default: `authorized_track_records/`)
"""


def _checklist_text(*, auth: str) -> str:
    return f"""# Authorization checklist (real package only)

- [ ] Lawful authorized program / private engagement only
- [ ] `program_authorization_id` = `{auth or "SET_ME"}`
- [ ] Redacted: no secrets, tokens, cookies, raw PII
- [ ] `wall_clock_minutes` on real entries (for wall-clock gap)
- [ ] `human_confirmed_valid` + `report_outcome_ref` (for valid-report gap)
- [ ] `execution_allowed=false`, `report_submission_allowed=false`
- [ ] All synthetic/template markers were replaced with operator-attested input
- [ ] Human explicitly passes `--declare-real-package`
- [ ] Human re-scores market/delivery after capture

Synthetic fixtures and lab packages must **not** use `--declare-real-package`.
"""
