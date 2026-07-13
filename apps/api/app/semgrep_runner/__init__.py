"""Local-only Semgrep CLI runner — explicit human flag, offline package roots.

Final-scheme Static Analyzer seed (Semgrep Runner):
- Default is plan-only (no subprocess)
- Executes only when human_allow_local_semgrep=True
- Scans only paths under authorized package_root
- Never uses remote rule registries (no p/ or r/ configs)
- metrics off; no network validation; never unlocks submit/promote
- Missing binary or config => fail-closed skip, not crash
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from app.advisory_static_engines import (
    ENGINE_SEMGREP,
    build_semgrep_advisory_signal,
    load_advisory_findings,
)


STATUS_PLANNED = "semgrep_local_planned"
STATUS_COMPLETED = "semgrep_local_completed"
STATUS_SKIPPED_NO_FLAG = "skipped_no_human_local_flag"
STATUS_SKIPPED_NOT_INSTALLED = "skipped_semgrep_not_installed"
STATUS_SKIPPED_NO_TARGET = "skipped_no_local_target"
STATUS_SKIPPED_NO_CONFIG = "skipped_no_local_config"
STATUS_FAILED = "semgrep_local_failed"
STATUS_EMPTY = "semgrep_runner_empty"

ENGINE_SEMGREP_LOCAL = "semgrep_local"

_MAX_FINDINGS = 200
_DEFAULT_TIMEOUT_S = 90
_MAX_STDOUT_CHARS = 2_000_000

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

# Minimal offline rulepack (no registry). Teaching/SSRF-oriented pattern only.
_DEFAULT_OFFLINE_RULES = """rules:
  - id: mythos.local.ssrf-fetch
    message: "Local advisory: outbound fetch/request may need SSRF validation"
    languages: [javascript, typescript, python]
    severity: WARNING
    patterns:
      - pattern-either:
          - pattern: fetch($URL, ...)
          - pattern: requests.get($URL, ...)
          - pattern: requests.post($URL, ...)
          - pattern: httpx.get($URL, ...)
          - pattern: httpx.post($URL, ...)
  - id: mythos.local.raw-sql
    message: "Local advisory: raw SQL construction may need parameterization"
    languages: [python, javascript, typescript]
    severity: WARNING
    patterns:
      - pattern-either:
          - pattern: cursor.execute("..." + $X)
          - pattern: cursor.execute(f"...")
          - pattern: db.query($Q)
"""


class SemgrepRunnerError(ValueError):
    pass


class SemgrepRunnerResult(BaseModel):
    status: str = STATUS_EMPTY
    package_id: str = ""
    package_root: str = ""
    engine: str = ENGINE_SEMGREP_LOCAL
    human_allow_local_semgrep: bool = False
    human_flag_required: bool = True
    binary: str | None = None
    binary_available: bool = False
    config_path: str = ""
    config_source: str = ""
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
    remote_rules: bool = False
    live_validation: bool = False
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    next_allowed_action: str = (
        "Human may enable --allow-local-semgrep for offline package-root scan only."
    )

    def model_post_init(self, __context: Any) -> None:  # pydantic v2
        self.execution_allowed = False
        self.validation_allowed = False
        self.report_submission_allowed = False
        self.confirmed_vulnerability = False
        self.finding_promotion_allowed = False
        self.network_access = False
        self.remote_rules = False
        self.live_validation = False


def find_semgrep_binary(explicit: str | None = None) -> str | None:
    if explicit:
        path = Path(explicit)
        if path.is_file():
            return str(path.resolve())
        which = shutil.which(explicit)
        return which
    return shutil.which("semgrep")


def resolve_local_semgrep_config(
    package_root: str | Path | None,
    *,
    config_path: str | Path | None = None,
) -> tuple[Path | None, str, list[str]]:
    """Return (config_path, source, notes). Config must stay under package or be default offline pack."""
    notes: list[str] = []
    if package_root is None or str(package_root).strip() == "":
        return None, "missing_package_root", ["package_root_missing"]
    root = Path(package_root).resolve()
    if not root.is_dir():
        return None, "package_missing", ["package_root_missing"]

    if config_path is not None and str(config_path).strip():
        cfg = Path(config_path).resolve()
        try:
            cfg.relative_to(root)
        except ValueError:
            notes.append("config_outside_package_rejected")
            return None, "config_outside_package", notes
        if not cfg.is_file():
            notes.append(f"config_not_found:{cfg.name}")
            return None, "config_not_found", notes
        return cfg, "explicit_package_config", notes

    candidates = [
        root / "inputs" / "semgrep.yml",
        root / "inputs" / "semgrep.yaml",
        root / "inputs" / "semgrep" / "rules.yml",
        root / "inputs" / "semgrep" / "rules.yaml",
        root / "semgrep.yml",
        root / "semgrep.yaml",
        root / ".semgrep.yml",
    ]
    for path in candidates:
        if path.is_file():
            try:
                path.resolve().relative_to(root)
            except ValueError:
                continue
            return path.resolve(), "package_file", notes

    notes.append("using_embedded_offline_rules")
    return None, "embedded_offline_rules", notes


def build_local_semgrep_plan(
    package_root: str | Path | None,
    *,
    package_id: str = "",
    human_allow_local_semgrep: bool = False,
    config_path: str | Path | None = None,
    binary: str | None = None,
    timeout_s: int = _DEFAULT_TIMEOUT_S,
) -> SemgrepRunnerResult:
    """Plan a local Semgrep invocation without executing it."""
    return run_local_semgrep(
        package_root=package_root,
        package_id=package_id,
        human_allow_local_semgrep=human_allow_local_semgrep,
        config_path=config_path,
        binary=binary,
        timeout_s=timeout_s,
        force_plan_only=True,
    )


def run_local_semgrep(
    package_root: str | Path | None,
    *,
    package_id: str = "",
    human_allow_local_semgrep: bool = False,
    config_path: str | Path | None = None,
    binary: str | None = None,
    timeout_s: int = _DEFAULT_TIMEOUT_S,
    force_plan_only: bool = False,
    subprocess_runner: Any | None = None,
) -> SemgrepRunnerResult:
    """Run or plan local Semgrep against an authorized package root only."""
    root: Path | None = None
    if package_root is not None and str(package_root).strip():
        root = Path(package_root).resolve()

    resolved_id = package_id
    if not resolved_id and root is not None:
        resolved_id = _read_package_id(root) or root.name

    notes: list[str] = ["offline_only", "remote_rules_disabled", "metrics_off"]
    bin_path = find_semgrep_binary(binary)
    cfg, cfg_source, cfg_notes = resolve_local_semgrep_config(
        root, config_path=config_path
    )
    notes.extend(cfg_notes)

    targets = _default_targets(root) if root is not None else []
    command = _build_command(
        binary=bin_path or "semgrep",
        config=cfg,
        targets=targets,
        use_embedded=(cfg is None and cfg_source == "embedded_offline_rules"),
    )

    base = SemgrepRunnerResult(
        package_id=resolved_id,
        package_root=str(root or ""),
        human_allow_local_semgrep=bool(human_allow_local_semgrep),
        binary=bin_path,
        binary_available=bool(bin_path),
        config_path=str(cfg or ""),
        config_source=cfg_source,
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

    if not human_allow_local_semgrep or force_plan_only:
        base.status = STATUS_SKIPPED_NO_FLAG if not human_allow_local_semgrep else STATUS_PLANNED
        if force_plan_only and human_allow_local_semgrep:
            base.status = STATUS_PLANNED
        base.command_executed = False
        base.next_allowed_action = (
            "Plan-only. Re-run with human_allow_local_semgrep=True "
            "(or bridge --allow-local-semgrep) on this package root only."
        )
        if not bin_path:
            base.notes.append("semgrep_binary_absent_at_plan_time")
        return _force_safety(base)

    if not bin_path:
        base.status = STATUS_SKIPPED_NOT_INSTALLED
        base.command_executed = False
        base.notes.append("semgrep_not_on_path")
        base.next_allowed_action = (
            "Install Semgrep locally or keep offline inputs/advisory/*.json fixtures."
        )
        return _force_safety(base)

    # Execute local CLI with offline config.
    runner = subprocess_runner or subprocess.run
    embedded_path: Path | None = None
    try:
        if cfg is None and cfg_source == "embedded_offline_rules":
            fd, tmp_name = tempfile.mkstemp(prefix="mythos-semgrep-", suffix=".yml")
            os.close(fd)
            embedded_path = Path(tmp_name)
            embedded_path.write_text(_DEFAULT_OFFLINE_RULES, encoding="utf-8")
            command = _build_command(
                binary=bin_path,
                config=embedded_path,
                targets=targets,
                use_embedded=False,
            )
            base.command = command
            base.config_path = str(embedded_path)
            base.notes.append("embedded_rules_tempfile")

        import time

        started = time.perf_counter()
        completed = runner(
            command,
            capture_output=True,
            text=True,
            timeout=max(5, int(timeout_s)),
            cwd=str(root),
            check=False,
        )
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        base.duration_ms = elapsed_ms
        base.command_executed = True
        base.exit_code = int(getattr(completed, "returncode", 1) or 0)
        stdout = str(getattr(completed, "stdout", "") or "")
        stderr = str(getattr(completed, "stderr", "") or "")
        if len(stdout) > _MAX_STDOUT_CHARS:
            stdout = stdout[:_MAX_STDOUT_CHARS]
            base.stdout_truncated = True
            base.notes.append("stdout_truncated")

        findings = _parse_semgrep_json(stdout, package_root=root)
        base.findings = findings[:_MAX_FINDINGS]
        base.finding_count = len(base.findings)
        base.sources.append("semgrep_cli_json")

        # Semgrep exit: 0=ok no findings, 1=findings, 2=error (varies by version)
        if base.exit_code in (0, 1):
            base.status = STATUS_COMPLETED
            base.next_allowed_action = (
                "Human reviews local Semgrep findings as advisory only; "
                "do not treat as confirmed vulnerability or auto-submit."
            )
        else:
            base.status = STATUS_FAILED
            if stderr.strip():
                base.notes.append(f"stderr_present:{stderr.strip()[:240]}")
            base.next_allowed_action = (
                "Semgrep CLI failed; fix local install/config or use offline advisory fixtures."
            )
        if stderr.strip() and base.status == STATUS_COMPLETED:
            base.notes.append("stderr_present_nonfatal")
    except subprocess.TimeoutExpired:
        base.status = STATUS_FAILED
        base.command_executed = True
        base.notes.append("timeout")
        base.next_allowed_action = "Semgrep timed out; narrow targets or raise timeout under human control."
    except Exception as exc:  # noqa: BLE001 - surface as failed run
        base.status = STATUS_FAILED
        base.command_executed = False
        base.notes.append(f"runner_error:{type(exc).__name__}")
        base.next_allowed_action = "Semgrep runner error; keep offline advisory path."
    finally:
        if embedded_path is not None:
            try:
                embedded_path.unlink(missing_ok=True)
            except Exception:
                pass

    return _force_safety(base)


def load_package_semgrep_runner(
    package_root: str | Path | None,
    *,
    human_allow_local_semgrep: bool = False,
    **kwargs: Any,
) -> dict[str, Any]:
    result = run_local_semgrep(
        package_root=package_root,
        human_allow_local_semgrep=human_allow_local_semgrep,
        **kwargs,
    )
    return result.model_dump()


def attach_semgrep_runner_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    human_allow_local_semgrep: bool = False,
    semgrep_runner: dict[str, Any] | SemgrepRunnerResult | None = None,
    binary: str | None = None,
    config_path: str | Path | None = None,
    subprocess_runner: Any | None = None,
) -> dict[str, Any]:
    """Attach local Semgrep runner outcome; merge findings into advisory context only."""
    if not isinstance(bridge_result, dict):
        raise SemgrepRunnerError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")

    if semgrep_runner is not None:
        if isinstance(semgrep_runner, SemgrepRunnerResult):
            run = _force_safety(semgrep_runner).model_dump()
        else:
            run = _force_safety_dict(dict(semgrep_runner))
    else:
        run = run_local_semgrep(
            package_root=resolved_root,
            package_id=package_id,
            human_allow_local_semgrep=human_allow_local_semgrep,
            binary=binary,
            config_path=config_path,
            subprocess_runner=subprocess_runner,
        ).model_dump()

    out = dict(bridge_result)
    out["semgrep_runner"] = run
    out["semgrep_runner_present"] = True
    out["semgrep_runner_status"] = str(run.get("status") or STATUS_EMPTY)
    out["semgrep_runner_finding_count"] = int(run.get("finding_count") or 0)
    out["semgrep_local_executed"] = bool(run.get("command_executed"))

    # Optional advisory merge: local findings are advisory support signals only.
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
        sg = list(merged.get("semgrep_findings") or [])
        sg.extend([f for f in findings if isinstance(f, dict)])
        merged["semgrep_findings"] = sg[:_MAX_FINDINGS]
        sources = list(merged.get("sources") or [])
        sources.append(
            {
                "path": "semgrep_runner:local_cli",
                "engine": ENGINE_SEMGREP,
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
        out["semgrep_local_merged_into_advisory"] = True
    else:
        out["semgrep_local_merged_into_advisory"] = False

    # Absolute safety floor
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out


def build_semgrep_signal_from_runner(
    runner: dict[str, Any] | SemgrepRunnerResult | None,
    *,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Convert runner findings into multi-engine advisory signal (optional)."""
    if runner is None:
        return None
    payload = runner.model_dump() if isinstance(runner, SemgrepRunnerResult) else dict(runner)
    if payload.get("status") != STATUS_COMPLETED:
        return None
    findings = payload.get("findings") if isinstance(payload.get("findings"), list) else []
    signal = build_semgrep_advisory_signal(findings, candidate=candidate or {})
    signal["engine"] = ENGINE_SEMGREP  # keep verifier-compatible engine id
    signal["notes"] = list(signal.get("notes") or []) + ["from_semgrep_local_cli"]
    signal["execution_allowed"] = False
    signal["validation_allowed"] = False
    signal["report_submission_allowed"] = False
    signal["confirmed_vulnerability"] = False
    signal["finding_promotion_allowed"] = False
    return signal


def _build_command(
    *,
    binary: str,
    config: Path | None,
    targets: list[Path],
    use_embedded: bool,
) -> list[str]:
    cmd = [
        binary,
        "scan",
        "--json",
        "--quiet",
        "--metrics",
        "off",
        "--disable-version-check",
        "--error",
    ]
    if config is not None:
        cmd.extend(["--config", str(config)])
    elif use_embedded:
        # Placeholder; real run replaces with tempfile path.
        cmd.extend(["--config", "__embedded_offline_rules__"])
    for target in targets:
        cmd.append(str(target))
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
            # Skip empty dirs of only skip-names
            out.append(path.resolve())
    if not out:
        # Fallback: package root itself (still confined)
        out.append(root.resolve())
    return out


def _parse_semgrep_json(stdout: str, *, package_root: Path) -> list[dict[str, Any]]:
    text = (stdout or "").strip()
    if not text:
        return []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        # Try SARIF-compatible via advisory loader helpers
        try:
            return [
                _normalize_cli_finding(item, package_root=package_root)
                for item in load_advisory_findings({"raw": text})  # may fail
            ]
        except Exception:
            return []

    results: list[Any]
    if isinstance(payload, dict):
        if isinstance(payload.get("results"), list):
            results = payload["results"]
        elif isinstance(payload.get("findings"), list):
            results = payload["findings"]
        else:
            # SARIF
            try:
                return [
                    _normalize_cli_finding(item, package_root=package_root)
                    for item in load_advisory_findings(payload)
                ]
            except Exception:
                results = []
    elif isinstance(payload, list):
        results = payload
    else:
        results = []

    out: list[dict[str, Any]] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        out.append(_normalize_cli_finding(item, package_root=package_root))
    return out


def _normalize_cli_finding(item: dict[str, Any], *, package_root: Path) -> dict[str, Any]:
    path = (
        item.get("path")
        or item.get("file")
        or _path_from_semgrep_result(item)
        or ""
    )
    path_s = str(path).replace("\\", "/")
    # Confine path string to package-relative when possible
    try:
        p = Path(path_s)
        if p.is_absolute():
            path_s = str(p.resolve().relative_to(package_root.resolve())).replace("\\", "/")
    except Exception:
        pass

    rule = (
        item.get("check_id")
        or item.get("rule_id")
        or item.get("ruleId")
        or item.get("id")
        or "semgrep.local"
    )
    message = item.get("message") or item.get("extra", {})
    if isinstance(message, dict):
        message = message.get("message") or message.get("text") or json.dumps(message)[:200]
    start = item.get("start") if isinstance(item.get("start"), dict) else {}
    line = start.get("line") or item.get("line") or item.get("start_line")

    return {
        "rule_id": str(rule),
        "message": str(message or ""),
        "path": path_s,
        "line": line,
        "engine": ENGINE_SEMGREP_LOCAL,
        "polarity": "support",
        "source": "semgrep_local_cli",
        "extra": {
            k: item.get(k)
            for k in ("severity", "metadata", "end")
            if k in item
        },
    }


def _path_from_semgrep_result(item: dict[str, Any]) -> str:
    # Classic semgrep JSON shape
    if "path" in item:
        return str(item.get("path") or "")
    extra = item.get("extra") if isinstance(item.get("extra"), dict) else {}
    return str(extra.get("path") or "")


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


def _force_safety(result: SemgrepRunnerResult) -> SemgrepRunnerResult:
    result.execution_allowed = False
    result.validation_allowed = False
    result.report_submission_allowed = False
    result.confirmed_vulnerability = False
    result.finding_promotion_allowed = False
    result.network_access = False
    result.remote_rules = False
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
    payload["remote_rules"] = False
    payload["live_validation"] = False
    payload["human_flag_required"] = True
    return payload


__all__ = [
    "ENGINE_SEMGREP_LOCAL",
    "STATUS_COMPLETED",
    "STATUS_EMPTY",
    "STATUS_FAILED",
    "STATUS_PLANNED",
    "STATUS_SKIPPED_NO_CONFIG",
    "STATUS_SKIPPED_NO_FLAG",
    "STATUS_SKIPPED_NO_TARGET",
    "STATUS_SKIPPED_NOT_INSTALLED",
    "SemgrepRunnerError",
    "SemgrepRunnerResult",
    "attach_semgrep_runner_to_bridge_result",
    "build_local_semgrep_plan",
    "build_semgrep_signal_from_runner",
    "find_semgrep_binary",
    "load_package_semgrep_runner",
    "resolve_local_semgrep_config",
    "run_local_semgrep",
]