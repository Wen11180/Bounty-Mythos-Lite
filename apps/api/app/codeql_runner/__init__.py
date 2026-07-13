"""Local-only CodeQL CLI runner — explicit human flag, package-confined.

Final-scheme Static Analyzer seed (CodeQL Runner):
- Default is plan-only (no subprocess)
- Executes only when human_allow_local_codeql=True
- Operates only under authorized package_root
- Never downloads remote query packs or language packs automatically
- Missing binary / DB / suite => fail-closed skip (use offline inputs/advisory/*)
- Findings stay advisory; never unlocks submit/promote/execution
"""

from __future__ import annotations

import json
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from app.advisory_static_engines import (
    ENGINE_CODEQL,
    build_codeql_advisory_signal,
    load_advisory_findings,
)


STATUS_PLANNED = "codeql_local_planned"
STATUS_COMPLETED = "codeql_local_completed"
STATUS_SKIPPED_NO_FLAG = "skipped_no_human_local_flag"
STATUS_SKIPPED_NOT_INSTALLED = "skipped_codeql_not_installed"
STATUS_SKIPPED_NO_TARGET = "skipped_no_local_target"
STATUS_SKIPPED_NO_DB = "skipped_no_local_database"
STATUS_SKIPPED_NO_SUITE = "skipped_no_local_query_suite"
STATUS_FAILED = "codeql_local_failed"
STATUS_EMPTY = "codeql_runner_empty"

ENGINE_CODEQL_LOCAL = "codeql_local"

_MAX_FINDINGS = 200
_DEFAULT_TIMEOUT_S = 180

_SKIP_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "dist",
    "build",
    "coverage",
    ".idea",
    ".vscode",
    "target",
    "vendor",
}


class CodeQLRunnerError(ValueError):
    pass


class CodeQLRunnerResult(BaseModel):
    status: str = STATUS_EMPTY
    package_id: str = ""
    package_root: str = ""
    engine: str = ENGINE_CODEQL_LOCAL
    human_allow_local_codeql: bool = False
    human_flag_required: bool = True
    binary: str | None = None
    binary_available: bool = False
    database_path: str = ""
    database_source: str = ""
    query_suite_path: str = ""
    query_suite_source: str = ""
    sarif_output_path: str = ""
    target_paths: list[str] = Field(default_factory=list)
    command: list[str] = Field(default_factory=list)
    command_executed: bool = False
    exit_code: int | None = None
    findings: list[dict[str, Any]] = Field(default_factory=list)
    finding_count: int = 0
    stdout_truncated: bool = False
    notes: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    duration_ms: int | None = None
    network_access: bool = False
    remote_packs: bool = False
    live_validation: bool = False
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    next_allowed_action: str = (
        "Human may enable --allow-local-codeql for offline package-root CodeQL only."
    )

    def model_post_init(self, __context: Any) -> None:  # pydantic v2
        self.execution_allowed = False
        self.validation_allowed = False
        self.report_submission_allowed = False
        self.confirmed_vulnerability = False
        self.finding_promotion_allowed = False
        self.network_access = False
        self.remote_packs = False
        self.live_validation = False
        self.human_flag_required = True


def find_codeql_binary(explicit: str | None = None) -> str | None:
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path.resolve())
        which = shutil.which(explicit)
        return which
    return shutil.which("codeql")


def resolve_local_codeql_database(
    package_root: str | Path | None,
    *,
    database_path: str | Path | None = None,
) -> tuple[Path | None, str, list[str]]:
    """Resolve a pre-built CodeQL database that stays under package_root."""
    notes: list[str] = []
    if package_root is None or str(package_root).strip() == "":
        return None, "missing_package_root", ["package_root_missing"]
    root = Path(package_root).resolve()
    if not root.is_dir():
        return None, "package_missing", ["package_root_missing"]

    if database_path is not None and str(database_path).strip():
        db = Path(database_path).resolve()
        try:
            db.relative_to(root)
        except ValueError:
            notes.append("database_outside_package_rejected")
            return None, "database_outside_package", notes
        if not db.exists():
            notes.append(f"database_not_found:{db.name}")
            return None, "database_not_found", notes
        return db, "explicit_package_database", notes

    candidates = [
        root / "inputs" / "codeql" / "database",
        root / "inputs" / "codeql-db",
        root / "inputs" / "codeql_database",
        root / ".codeql" / "database",
        root / "codeql-db",
        root / "codeql_database",
    ]
    for path in candidates:
        if path.exists():
            try:
                path.resolve().relative_to(root)
            except ValueError:
                continue
            return path.resolve(), "package_file", notes

    notes.append("no_package_codeql_database")
    return None, "missing", notes


def resolve_local_codeql_query_suite(
    package_root: str | Path | None,
    *,
    query_suite: str | Path | None = None,
) -> tuple[Path | None, str, list[str]]:
    """Resolve a local query suite / qlpack path confined to package_root.

    Remote pack names (e.g. codeql/javascript-queries) are rejected.
    """
    notes: list[str] = []
    if package_root is None or str(package_root).strip() == "":
        return None, "missing_package_root", ["package_root_missing"]
    root = Path(package_root).resolve()
    if not root.is_dir():
        return None, "package_missing", ["package_root_missing"]

    if query_suite is not None and str(query_suite).strip():
        raw = str(query_suite).strip()
        # Reject remote-looking pack refs
        if "/" in raw and not Path(raw).exists() and not raw.startswith((".", "/", "\\")):
            # Windows absolute or relative path ok; bare pack name like codeql/js rejected
            if not (len(raw) >= 2 and raw[1] == ":"):  # drive letter
                notes.append("remote_query_pack_rejected")
                return None, "remote_pack_rejected", notes
        suite = Path(raw)
        if not suite.is_absolute():
            suite = (root / suite).resolve()
        else:
            suite = suite.resolve()
        try:
            suite.relative_to(root)
        except ValueError:
            notes.append("query_suite_outside_package_rejected")
            return None, "query_suite_outside_package", notes
        if not suite.exists():
            notes.append(f"query_suite_not_found:{suite.name}")
            return None, "query_suite_not_found", notes
        return suite, "explicit_package_suite", notes

    candidates = [
        root / "inputs" / "codeql" / "suite.qls",
        root / "inputs" / "codeql" / "queries.qls",
        root / "inputs" / "codeql" / "qlpack.yml",
        root / "inputs" / "codeql" / "codeql-pack.yml",
        root / "inputs" / "codeql" / "query.ql",
        root / "codeql" / "suite.qls",
        root / "codeql-suite.qls",
    ]
    for path in candidates:
        if path.is_file() or path.is_dir():
            try:
                path.resolve().relative_to(root)
            except ValueError:
                continue
            return path.resolve(), "package_file", notes

    notes.append("no_package_query_suite_using_plan_placeholder")
    return None, "missing", notes


def build_local_codeql_plan(
    package_root: str | Path | None,
    *,
    package_id: str = "",
    human_allow_local_codeql: bool = False,
    database_path: str | Path | None = None,
    query_suite: str | Path | None = None,
    binary: str | None = None,
    timeout_s: int = _DEFAULT_TIMEOUT_S,
) -> CodeQLRunnerResult:
    """Plan a local CodeQL invocation without executing it."""
    return run_local_codeql(
        package_root=package_root,
        package_id=package_id,
        human_allow_local_codeql=human_allow_local_codeql,
        database_path=database_path,
        query_suite=query_suite,
        binary=binary,
        timeout_s=timeout_s,
        force_plan_only=True,
    )


def run_local_codeql(
    package_root: str | Path | None,
    *,
    package_id: str = "",
    human_allow_local_codeql: bool = False,
    database_path: str | Path | None = None,
    query_suite: str | Path | None = None,
    binary: str | None = None,
    timeout_s: int = _DEFAULT_TIMEOUT_S,
    force_plan_only: bool = False,
    subprocess_runner: Any | None = None,
) -> CodeQLRunnerResult:
    """Run or plan local CodeQL against an authorized package root only."""
    root: Path | None = None
    if package_root is not None and str(package_root).strip():
        root = Path(package_root).resolve()

    resolved_id = package_id
    if not resolved_id and root is not None:
        resolved_id = _read_package_id(root) or root.name

    notes: list[str] = [
        "offline_only",
        "remote_packs_disabled",
        "no_auto_language_pack_download",
    ]
    bin_path = find_codeql_binary(binary)
    db, db_source, db_notes = resolve_local_codeql_database(
        root, database_path=database_path
    )
    suite, suite_source, suite_notes = resolve_local_codeql_query_suite(
        root, query_suite=query_suite
    )
    notes.extend(db_notes)
    notes.extend(suite_notes)

    targets = _default_targets(root) if root is not None else []
    # Planned SARIF path under package tmp area (not written unless executed)
    planned_sarif = ""
    if root is not None:
        planned_sarif = str((root / "inputs" / "codeql" / ".mythos-codeql-results.sarif").resolve())

    command = _build_analyze_command(
        binary=bin_path or "codeql",
        database=db,
        query_suite=suite,
        sarif_out=Path(planned_sarif) if planned_sarif else None,
    )

    base = CodeQLRunnerResult(
        package_id=resolved_id,
        package_root=str(root or ""),
        human_allow_local_codeql=bool(human_allow_local_codeql),
        binary=bin_path,
        binary_available=bool(bin_path),
        database_path=str(db or ""),
        database_source=db_source,
        query_suite_path=str(suite or ""),
        query_suite_source=suite_source,
        sarif_output_path=planned_sarif,
        target_paths=[str(t) for t in targets],
        command=command,
        notes=list(notes),
        sources=[],
    )

    if root is None or not root.is_dir():
        base.status = STATUS_SKIPPED_NO_TARGET
        base.notes.append("package_root_missing")
        base.next_allowed_action = "Provide authorized package_root under local workspace."
        return _force_safety(base)

    if not targets:
        base.status = STATUS_SKIPPED_NO_TARGET
        base.notes.append("no_scannable_targets")
        base.next_allowed_action = "No local code targets under package_root."
        return _force_safety(base)

    if not human_allow_local_codeql or force_plan_only:
        base.status = (
            STATUS_SKIPPED_NO_FLAG if not human_allow_local_codeql else STATUS_PLANNED
        )
        if force_plan_only and human_allow_local_codeql:
            base.status = STATUS_PLANNED
        base.command_executed = False
        base.next_allowed_action = (
            "Plan-only. Re-run with human_allow_local_codeql=True "
            "(or bridge --allow-local-codeql) on this package root only. "
            "Requires pre-built local CodeQL database + local query suite under package."
        )
        if not bin_path:
            base.notes.append("codeql_binary_absent_at_plan_time")
        if not db:
            base.notes.append("codeql_database_absent_at_plan_time")
        if not suite:
            base.notes.append("codeql_query_suite_absent_at_plan_time")
        return _force_safety(base)

    if not bin_path:
        base.status = STATUS_SKIPPED_NOT_INSTALLED
        base.command_executed = False
        base.notes.append("codeql_not_on_path")
        base.next_allowed_action = (
            "Install CodeQL CLI locally or keep offline inputs/advisory/* fixtures."
        )
        return _force_safety(base)

    if db is None:
        base.status = STATUS_SKIPPED_NO_DB
        base.command_executed = False
        base.next_allowed_action = (
            "Place a pre-built CodeQL database under package "
            "(e.g. inputs/codeql/database). Auto create/download is disabled."
        )
        return _force_safety(base)

    if suite is None:
        base.status = STATUS_SKIPPED_NO_SUITE
        base.command_executed = False
        base.next_allowed_action = (
            "Place a local query suite under package "
            "(e.g. inputs/codeql/suite.qls). Remote packs are rejected."
        )
        return _force_safety(base)

    # Execute local analyze only.
    runner = subprocess_runner
    if runner is None:
        import subprocess

        runner = subprocess.run

    sarif_path = Path(planned_sarif)
    try:
        sarif_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        # Fall back to temp under package if possible
        try:
            fd_dir = tempfile.mkdtemp(prefix="mythos-codeql-", dir=str(root))
            sarif_path = Path(fd_dir) / "results.sarif"
            base.sarif_output_path = str(sarif_path)
            base.notes.append("sarif_output_temp_under_package")
        except Exception:
            base.status = STATUS_FAILED
            base.notes.append("cannot_prepare_sarif_output_path")
            return _force_safety(base)

    command = _build_analyze_command(
        binary=bin_path,
        database=db,
        query_suite=suite,
        sarif_out=sarif_path,
    )
    base.command = command

    try:
        started = time.perf_counter()
        completed = runner(
            command,
            capture_output=True,
            text=True,
            timeout=max(10, int(timeout_s)),
            cwd=str(root),
            check=False,
        )
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        base.duration_ms = elapsed_ms
        base.command_executed = True
        base.exit_code = int(getattr(completed, "returncode", 1) or 0)
        stdout = str(getattr(completed, "stdout", "") or "")
        stderr = str(getattr(completed, "stderr", "") or "")
        if len(stdout) > 2_000_000:
            base.stdout_truncated = True
            stdout = stdout[:2_000_000]

        findings: list[dict[str, Any]] = []
        if sarif_path.is_file():
            try:
                raw = json.loads(sarif_path.read_text(encoding="utf-8"))
                findings = _parse_codeql_sarif(raw, package_root=root)
                base.sources.append("codeql_sarif_file")
            except Exception as exc:  # noqa: BLE001
                base.notes.append(f"sarif_parse_error:{type(exc).__name__}")
        if not findings and stdout.strip().startswith("{"):
            try:
                raw = json.loads(stdout)
                findings = _parse_codeql_sarif(raw, package_root=root)
                base.sources.append("codeql_stdout_json")
            except Exception:
                pass

        # CodeQL often exits non-zero when findings exist; treat 0/1 as potential success if SARIF present.
        if findings or (base.exit_code in {0, 1} and sarif_path.is_file()):
            base.status = STATUS_COMPLETED
            base.findings = findings[:_MAX_FINDINGS]
            base.finding_count = len(base.findings)
            base.next_allowed_action = (
                "Review CodeQL advisory findings locally; never treat as confirmed vulnerability."
            )
            if base.exit_code not in {0, 1}:
                base.notes.append(f"nonzero_exit_with_sarif:{base.exit_code}")
        else:
            base.status = STATUS_FAILED
            if stderr:
                base.notes.append(f"stderr:{stderr[:300]}")
            base.next_allowed_action = (
                "Inspect CodeQL CLI failure; keep offline advisory fixtures as fallback."
            )
        return _force_safety(base)
    except Exception as exc:  # noqa: BLE001
        base.command_executed = True
        base.status = STATUS_FAILED
        base.notes.append(f"runner_exception:{type(exc).__name__}")
        base.next_allowed_action = "CodeQL local run failed; use offline advisory only."
        return _force_safety(base)


def load_package_codeql_runner(
    package_root: str | Path | None,
    *,
    package_id: str = "",
    human_allow_local_codeql: bool = False,
    binary: str | None = None,
    database_path: str | Path | None = None,
    query_suite: str | Path | None = None,
    subprocess_runner: Any | None = None,
) -> dict[str, Any]:
    return run_local_codeql(
        package_root=package_root,
        package_id=package_id,
        human_allow_local_codeql=human_allow_local_codeql,
        binary=binary,
        database_path=database_path,
        query_suite=query_suite,
        subprocess_runner=subprocess_runner,
    ).model_dump()


def attach_codeql_runner_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    human_allow_local_codeql: bool = False,
    binary: str | None = None,
    database_path: str | Path | None = None,
    query_suite: str | Path | None = None,
    codeql_runner: dict[str, Any] | CodeQLRunnerResult | None = None,
    subprocess_runner: Any | None = None,
) -> dict[str, Any]:
    """Attach CodeQL local runner result; never unlocks submit/execution."""
    if not isinstance(bridge_result, dict):
        raise CodeQLRunnerError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")

    if codeql_runner is not None:
        if isinstance(codeql_runner, CodeQLRunnerResult):
            run = _force_safety(codeql_runner).model_dump()
        else:
            run = _force_safety_dict(dict(codeql_runner))
    else:
        run = run_local_codeql(
            package_root=resolved_root,
            package_id=package_id,
            human_allow_local_codeql=human_allow_local_codeql,
            binary=binary,
            database_path=database_path,
            query_suite=query_suite,
            subprocess_runner=subprocess_runner,
        ).model_dump()

    out = dict(bridge_result)
    out["codeql_runner"] = run
    out["codeql_runner_present"] = True
    out["codeql_runner_status"] = str(run.get("status") or STATUS_EMPTY)
    out["codeql_runner_finding_count"] = int(run.get("finding_count") or 0)
    out["codeql_local_executed"] = bool(run.get("command_executed"))

    findings = run.get("findings") if isinstance(run.get("findings"), list) else []
    if findings and run.get("status") == STATUS_COMPLETED:
        existing = out.get("advisory_bundle") if isinstance(out.get("advisory_bundle"), dict) else {}
        merged = dict(existing) if existing else {
            "present": True,
            "package_root": str(resolved_root or ""),
            "sources": [],
            "semgrep_findings": [],
            "codeql_findings": [],
            "skipped": [],
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
            "confirmed_vulnerability": False,
        }
        cq = list(merged.get("codeql_findings") or [])
        cq.extend([f for f in findings if isinstance(f, dict)])
        merged["codeql_findings"] = cq[:_MAX_FINDINGS]
        sources = list(merged.get("sources") or [])
        sources.append(
            {
                "path": "codeql_runner:local_cli",
                "engine": ENGINE_CODEQL,
                "finding_count": len(findings),
            }
        )
        merged["sources"] = sources
        merged["present"] = True
        merged["execution_allowed"] = False
        merged["validation_allowed"] = False
        merged["report_submission_allowed"] = False
        merged["confirmed_vulnerability"] = False
        out["advisory_bundle"] = merged
        out["advisory_bundle_present"] = True
        out["codeql_local_merged_into_advisory"] = True
    else:
        out["codeql_local_merged_into_advisory"] = False

    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out


def build_codeql_signal_from_runner(
    runner: dict[str, Any] | CodeQLRunnerResult | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if runner is None:
        return None
    payload = runner.model_dump() if isinstance(runner, CodeQLRunnerResult) else dict(runner)
    if payload.get("status") != STATUS_COMPLETED:
        return None
    findings = payload.get("findings") if isinstance(payload.get("findings"), list) else []
    signal = build_codeql_advisory_signal(findings, candidate=candidate or {})
    signal["engine"] = ENGINE_CODEQL
    signal["notes"] = list(signal.get("notes") or []) + ["from_codeql_local_cli"]
    signal["execution_allowed"] = False
    signal["validation_allowed"] = False
    signal["report_submission_allowed"] = False
    signal["confirmed_vulnerability"] = False
    signal["finding_promotion_allowed"] = False
    return signal


def _build_analyze_command(
    *,
    binary: str,
    database: Path | None,
    query_suite: Path | None,
    sarif_out: Path | None,
) -> list[str]:
    cmd = [
        binary,
        "database",
        "analyze",
        str(database) if database is not None else "__missing_database__",
        str(query_suite) if query_suite is not None else "__missing_suite__",
        "--format=sarif-latest",
        f"--output={sarif_out}" if sarif_out is not None else "--output=__missing_sarif__",
        "--sarif-add-snippets=false",
        # Never search online for packs
        "--search-path=",
        "--no-rerun",
    ]
    return cmd


def _default_targets(root: Path | None) -> list[Path]:
    if root is None or not root.is_dir():
        return []
    preferred = [
        root / "inputs",
        root / "_extract",
        root / "src",
        root / "app",
        root / "backend",
    ]
    out: list[Path] = []
    for path in preferred:
        if path.is_dir():
            try:
                path.resolve().relative_to(root.resolve())
            except ValueError:
                continue
            out.append(path.resolve())
    if not out:
        out.append(root.resolve())
    return out


def _parse_codeql_sarif(payload: Any, *, package_root: Path) -> list[dict[str, Any]]:
    if payload is None:
        return []
    try:
        raw_findings = load_advisory_findings(payload if isinstance(payload, (dict, list)) else None)
    except Exception:
        raw_findings = []
        if isinstance(payload, dict):
            runs = payload.get("runs") if isinstance(payload.get("runs"), list) else []
            for run in runs:
                if not isinstance(run, dict):
                    continue
                results = run.get("results") if isinstance(run.get("results"), list) else []
                for item in results:
                    if isinstance(item, dict):
                        raw_findings.append(item)

    out: list[dict[str, Any]] = []
    for item in raw_findings:
        if not isinstance(item, dict):
            continue
        out.append(_normalize_cli_finding(item, package_root=package_root))
    return out


def _normalize_cli_finding(item: dict[str, Any], *, package_root: Path) -> dict[str, Any]:
    path = (
        item.get("path")
        or item.get("file")
        or item.get("uri")
        or _path_from_sarif_result(item)
        or ""
    )
    path_s = str(path).replace("\\", "/")
    if path_s.startswith("file:"):
        path_s = path_s[5:]
        if path_s.startswith("///"):
            path_s = path_s[3:]
        elif path_s.startswith("//"):
            path_s = path_s[2:]
    try:
        p = Path(path_s)
        if p.is_absolute():
            path_s = str(p.resolve().relative_to(package_root.resolve())).replace("\\", "/")
    except Exception:
        pass

    rule = (
        item.get("rule_id")
        or item.get("ruleId")
        or item.get("check_id")
        or item.get("id")
        or "codeql.local"
    )
    message = item.get("message") or item.get("text") or ""
    if isinstance(message, dict):
        message = message.get("text") or message.get("message") or json.dumps(message)[:200]
    line = item.get("line") or item.get("startLine")
    if line is None:
        locs = item.get("locations") if isinstance(item.get("locations"), list) else []
        if locs and isinstance(locs[0], dict):
            phys = locs[0].get("physicalLocation") if isinstance(locs[0].get("physicalLocation"), dict) else {}
            region = phys.get("region") if isinstance(phys.get("region"), dict) else {}
            line = region.get("startLine")

    polarity = str(item.get("polarity") or "support")
    tags = item.get("tags") if isinstance(item.get("tags"), list) else []
    if any(str(t).lower() in {"control", "mitigated"} for t in tags):
        polarity = "control"

    return {
        "rule_id": str(rule),
        "message": str(message or ""),
        "path": path_s,
        "line": line,
        "engine": ENGINE_CODEQL_LOCAL,
        "polarity": polarity,
        "source": "codeql_local_cli",
        "root_cause_id": str(item.get("root_cause_id") or ""),
        "tags": tags,
        "level": str(item.get("level") or item.get("severity") or ""),
    }


def _path_from_sarif_result(item: dict[str, Any]) -> str:
    locs = item.get("locations") if isinstance(item.get("locations"), list) else []
    if not locs or not isinstance(locs[0], dict):
        return ""
    phys = locs[0].get("physicalLocation") if isinstance(locs[0].get("physicalLocation"), dict) else {}
    art = phys.get("artifactLocation") if isinstance(phys.get("artifactLocation"), dict) else {}
    return str(art.get("uri") or "")


def _read_package_id(root: Path) -> str:
    for name in ("package.json", "gold.json", "STATUS.md"):
        path = root / name
        if not path.is_file():
            continue
        try:
            if name.endswith(".json"):
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    for key in ("package_id", "id", "name"):
                        if data.get(key):
                            return str(data[key])
        except Exception:
            continue
    return root.name


def _force_safety(result: CodeQLRunnerResult) -> CodeQLRunnerResult:
    result.execution_allowed = False
    result.validation_allowed = False
    result.report_submission_allowed = False
    result.confirmed_vulnerability = False
    result.finding_promotion_allowed = False
    result.network_access = False
    result.remote_packs = False
    result.live_validation = False
    result.human_flag_required = True
    return result


def _force_safety_dict(payload: dict[str, Any]) -> dict[str, Any]:
    payload = dict(payload)
    payload["execution_allowed"] = False
    payload["validation_allowed"] = False
    payload["report_submission_allowed"] = False
    payload["confirmed_vulnerability"] = False
    payload["finding_promotion_allowed"] = False
    payload["network_access"] = False
    payload["remote_packs"] = False
    payload["live_validation"] = False
    payload["human_flag_required"] = True
    return payload


__all__ = [
    "ENGINE_CODEQL_LOCAL",
    "STATUS_COMPLETED",
    "STATUS_EMPTY",
    "STATUS_FAILED",
    "STATUS_PLANNED",
    "STATUS_SKIPPED_NO_DB",
    "STATUS_SKIPPED_NO_FLAG",
    "STATUS_SKIPPED_NO_SUITE",
    "STATUS_SKIPPED_NO_TARGET",
    "STATUS_SKIPPED_NOT_INSTALLED",
    "CodeQLRunnerError",
    "CodeQLRunnerResult",
    "attach_codeql_runner_to_bridge_result",
    "build_codeql_signal_from_runner",
    "build_local_codeql_plan",
    "find_codeql_binary",
    "load_package_codeql_runner",
    "resolve_local_codeql_database",
    "resolve_local_codeql_query_suite",
    "run_local_codeql",
]
