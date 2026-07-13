"""Human-gated local-only in-process fuzz runner.

Final-scheme V1 residual after sandbox plan/export:
- Default is plan-only (no in-process run)
- Runs only when human_allow_local_fuzz_run=True
- In-process Python harness only (AST-extracted simple functions; restricted builtins)
- Never spawns AFL++/libFuzzer/subprocess fuzzer binaries
- Crash artifacts optional under package _export/fuzz_runs/ with promotion always blocked
- Never unlocks validation_allowed / report_submission_allowed / crash_promotion_allowed
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import traceback
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


STATUS_PLANNED = "local_fuzz_runner_planned"
STATUS_COMPLETED = "local_fuzz_runner_completed"
STATUS_CRASHES = "local_fuzz_runner_crashes_recorded"
STATUS_EMPTY = "local_fuzz_runner_empty"
STATUS_SKIPPED = "local_fuzz_runner_package_missing"
STATUS_SKIPPED_NO_FLAG = "skipped_no_human_local_fuzz_flag"
STATUS_SKIPPED_NO_TARGET = "skipped_no_local_fuzz_target"
STATUS_SKIPPED_NO_PYTHON = "skipped_no_python_harness"
STATUS_FAILED = "local_fuzz_runner_failed"

PARSER_NAME_MARKERS = ("parse", "decode", "deserialize", "load", "read", "unmarshal", "fromjson")

SAFETY_INVARIANTS = [
    "local_or_authorized_package_only",
    "no_public_target_scanning",
    "no_external_fuzzer_process_spawn",
    "no_network_access",
    "no_crash_promotion",
    "no_report_submission",
    "no_in_process_run_without_human_flag",
    "crash_artifacts_local_package_only",
    "human_approval_required_before_any_run",
    "external_afl_libfuzzer_preview_only",
]

_MAX_TARGETS = 12
_MAX_SEEDS = 24
_MAX_CRASHES = 20
_MAX_FUNC_BODY_LINES = 80
_MAX_SOURCE_BYTES = 200_000
_SEED_CORPUS: list[bytes] = [
    b"",
    b"a",
    b"\x00",
    b"\xff",
    b"{}",
    b"[]",
    b"null",
    b"true",
    b"0",
    b"-1",
    b"A" * 64,
    b"A" * 1024,
    b'{"k": 1}',
    b"http://127.0.0.1/",
    b"../" * 16,
    b"%s%s%s%s",
    b"\x00" * 32,
    b"\\u0000",
    b"\n\r\t",
    b"\x80\x81\x82",
]


class LocalFuzzRunnerError(ValueError):
    """Raised when bridge attach receives invalid input."""


@dataclass(frozen=True)
class CrashCandidate:
    crash_id: str
    target_symbol: str
    source_path: str
    exception_type: str
    exception_message: str
    seed_sha256: str
    seed_preview: str
    seed_hex: str = ""
    traceback_preview: str = ""
    artifact_relative_path: str = ""
    written: bool = False
    promotion_allowed: bool = False
    confirmed_vulnerability: bool = False


@dataclass(frozen=True)
class FuzzTarget:
    target_symbol: str
    source_path: str
    language: str
    harness_kind: str
    runnable_in_process: bool = False
    status: str = "planned"
    iterations: int = 0
    crash_count: int = 0
    notes: list[str] = field(default_factory=list)
    external_command_preview: str = ""


@dataclass(frozen=True)
class LocalFuzzRunnerResult:
    stage: str
    inspirations: list[str]
    execution_mode: str
    status: str
    package_id: str = ""
    package_root: str = ""
    targets: list[FuzzTarget] = field(default_factory=list)
    target_count: int = 0
    runnable_target_count: int = 0
    iterations_total: int = 0
    crash_candidates: list[CrashCandidate] = field(default_factory=list)
    crash_count: int = 0
    human_allow_local_fuzz_run: bool = False
    human_approval_required_before_run: bool = True
    in_process_run_executed: bool = False
    process_spawn_allowed: bool = False
    external_fuzzer_spawn_allowed: bool = False
    network_access: bool = False
    live_validation: bool = False
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    crash_promotion_allowed: bool = False
    crash_export_written: bool = False
    crash_export_count: int = 0
    crash_export_root_relative: str = "_export/fuzz_runs"
    run_stamp: str = ""
    safety_invariants: list[str] = field(default_factory=list)
    next_allowed_action: str = (
        "Review plan; enable human_allow_local_fuzz_run for in-process Python only."
    )
    notes: list[str] = field(default_factory=list)
    crs_status: str = ""
    duration_ms: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return _force_safety_dict(asdict(self))


def build_local_fuzz_runner_plan(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    crs_fuzzing: dict[str, Any] | None = None,
    human_allow_local_fuzz_run: bool = False,
) -> LocalFuzzRunnerResult:
    """Plan-only local fuzz runner profile (never executes)."""
    return run_local_fuzz_runner(
        package_root=package_root,
        package_id=package_id,
        crs_fuzzing=crs_fuzzing,
        human_allow_local_fuzz_run=human_allow_local_fuzz_run,
        force_plan_only=True,
    )


def run_local_fuzz_runner(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    crs_fuzzing: dict[str, Any] | None = None,
    human_allow_local_fuzz_run: bool = False,
    force_plan_only: bool = False,
    max_seeds: int = _MAX_SEEDS,
    write_crash_artifacts: bool = True,
) -> LocalFuzzRunnerResult:
    """Plan or run human-gated in-process Python fuzz against authorized package only."""
    notes: list[str] = [
        "in_process_python_only",
        "external_afl_libfuzzer_not_spawned",
        "crash_promotion_blocked",
    ]
    root: Path | None = None
    if package_root is not None and str(package_root).strip():
        candidate = Path(package_root).resolve()
        if candidate.is_dir():
            root = candidate
        else:
            notes.append("package_root_not_a_directory")

    resolved_id = (package_id or "").strip()
    if not resolved_id and root is not None:
        resolved_id = _load_package_id(root) or root.name

    crs_payload = _resolve_crs_payload(
        crs_fuzzing=crs_fuzzing,
        package_root=root,
        package_id=resolved_id,
    )
    crs_status = str(crs_payload.get("status") or "")

    if root is None and not crs_payload:
        return _empty_result(
            status=STATUS_SKIPPED if package_root else STATUS_EMPTY,
            package_id=resolved_id,
            package_root=str(package_root or ""),
            notes=notes + ["package_root_missing"],
            human_allow_local_fuzz_run=bool(human_allow_local_fuzz_run),
            crs_status=crs_status,
        )

    targets = _build_targets(root=root, crs_payload=crs_payload)
    if not targets:
        return _empty_result(
            status=STATUS_SKIPPED_NO_TARGET if root else STATUS_EMPTY,
            package_id=resolved_id,
            package_root=str(root or ""),
            notes=notes + ["no_harness_or_parser_targets"],
            human_allow_local_fuzz_run=bool(human_allow_local_fuzz_run),
            crs_status=crs_status,
        )

    runnable = [t for t in targets if t.runnable_in_process]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    base = LocalFuzzRunnerResult(
        stage="v1_approved_local_fuzz_execution",
        inspirations=["Buttercup", "OSS-Fuzz", "AFL++", "libFuzzer", "Python harness"],
        execution_mode="plan_only",
        status=STATUS_PLANNED,
        package_id=resolved_id,
        package_root=str(root or ""),
        targets=targets,
        target_count=len(targets),
        runnable_target_count=len(runnable),
        human_allow_local_fuzz_run=bool(human_allow_local_fuzz_run),
        safety_invariants=list(SAFETY_INVARIANTS),
        notes=list(notes),
        crs_status=crs_status,
        run_stamp=stamp,
        next_allowed_action=(
            "Plan-only. Re-run with human_allow_local_fuzz_run=True "
            "(or bridge --allow-local-fuzz-run) for in-process Python only."
        ),
    )

    if not human_allow_local_fuzz_run or force_plan_only:
        status = STATUS_SKIPPED_NO_FLAG if not human_allow_local_fuzz_run else STATUS_PLANNED
        if force_plan_only and human_allow_local_fuzz_run:
            status = STATUS_PLANNED
            notes = list(notes) + ["force_plan_only"]
        if not runnable:
            notes = list(notes) + ["no_python_in_process_targets"]
        return _force_safety_result(
            _rebuild(
                base,
                status=status,
                notes=notes,
                execution_mode="plan_only",
                in_process_run_executed=False,
            )
        )

    if root is None:
        return _force_safety_result(
            _rebuild(
                base,
                status=STATUS_SKIPPED_NO_TARGET,
                notes=list(notes) + ["run_requested_but_package_root_missing"],
                next_allowed_action="Provide authorized package_root before in-process run.",
            )
        )

    if not runnable:
        return _force_safety_result(
            _rebuild(
                base,
                status=STATUS_SKIPPED_NO_PYTHON,
                notes=list(notes) + ["no_python_functions_runnable_in_process"],
                next_allowed_action=(
                    "No AST-extractable Python parse/decode targets; "
                    "external AFL++/libFuzzer remains preview-only."
                ),
            )
        )

    started = datetime.now(timezone.utc)
    crashes: list[CrashCandidate] = []
    updated_targets: list[FuzzTarget] = []
    iterations_total = 0
    seed_cap = max(1, min(int(max_seeds or _MAX_SEEDS), _MAX_SEEDS))
    seeds = list(_SEED_CORPUS[:seed_cap])

    for target in targets:
        if not target.runnable_in_process:
            updated_targets.append(
                FuzzTarget(
                    target_symbol=target.target_symbol,
                    source_path=target.source_path,
                    language=target.language,
                    harness_kind=target.harness_kind,
                    runnable_in_process=False,
                    status="preview_only",
                    iterations=0,
                    crash_count=0,
                    notes=list(target.notes) + ["external_preview_only"],
                    external_command_preview=target.external_command_preview,
                )
            )
            continue

        fn = _load_in_process_callable(root, target.source_path, target.target_symbol)
        if fn is None:
            updated_targets.append(
                FuzzTarget(
                    target_symbol=target.target_symbol,
                    source_path=target.source_path,
                    language=target.language,
                    harness_kind=target.harness_kind,
                    runnable_in_process=True,
                    status="skipped_not_loadable",
                    iterations=0,
                    crash_count=0,
                    notes=list(target.notes) + ["function_not_loadable_safely"],
                    external_command_preview=target.external_command_preview,
                )
            )
            continue

        t_crashes = 0
        iters = 0
        t_notes = list(target.notes)
        for seed in seeds:
            if len(crashes) >= _MAX_CRASHES:
                t_notes.append("crash_cap_reached")
                break
            iters += 1
            iterations_total += 1
            crash = _invoke_seed(fn, seed=seed, target=target)
            if crash is None:
                continue
            t_crashes += 1
            crashes.append(crash)

        updated_targets.append(
            FuzzTarget(
                target_symbol=target.target_symbol,
                source_path=target.source_path,
                language=target.language,
                harness_kind=target.harness_kind,
                runnable_in_process=True,
                status="completed_with_crashes" if t_crashes else "completed_no_crash",
                iterations=iters,
                crash_count=t_crashes,
                notes=t_notes,
                external_command_preview=target.external_command_preview,
            )
        )

    crash_export_written = False
    crash_export_count = 0
    final_crashes = crashes
    if write_crash_artifacts and crashes and root is not None:
        final_crashes, crash_export_count = _write_crash_artifacts(
            root=root,
            stamp=stamp,
            crashes=crashes,
            package_id=resolved_id,
        )
        crash_export_written = crash_export_count > 0

    elapsed_ms = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
    status = STATUS_CRASHES if final_crashes else STATUS_COMPLETED
    run_notes = list(notes) + [
        "in_process_run_executed",
        f"iterations={iterations_total}",
        f"crashes={len(final_crashes)}",
    ]
    if crash_export_written:
        run_notes.append("crash_artifacts_written_local_only")
    else:
        run_notes.append(
            "crash_artifacts_not_written" if not final_crashes else "crash_artifact_write_skipped"
        )

    result = LocalFuzzRunnerResult(
        stage="v1_approved_local_fuzz_execution",
        inspirations=["Buttercup", "OSS-Fuzz", "AFL++", "libFuzzer", "Python harness"],
        execution_mode="in_process_python",
        status=status,
        package_id=resolved_id,
        package_root=str(root),
        targets=updated_targets,
        target_count=len(updated_targets),
        runnable_target_count=len([t for t in updated_targets if t.runnable_in_process]),
        iterations_total=iterations_total,
        crash_candidates=final_crashes,
        crash_count=len(final_crashes),
        human_allow_local_fuzz_run=True,
        in_process_run_executed=True,
        crash_export_written=crash_export_written,
        crash_export_count=crash_export_count,
        run_stamp=stamp,
        safety_invariants=list(SAFETY_INVARIANTS),
        notes=run_notes,
        crs_status=crs_status,
        duration_ms=elapsed_ms,
        next_allowed_action=(
            "Human triages crash candidates offline; Mythos never promotes crashes or submits reports."
        ),
    )
    return _force_safety_result(result)


def load_package_local_fuzz_runner_result(
    package_root: str | Path,
    *,
    package_id: str = "",
    crs_fuzzing: dict[str, Any] | None = None,
    human_allow_local_fuzz_run: bool = False,
) -> dict[str, Any]:
    return run_local_fuzz_runner(
        package_root=package_root,
        package_id=package_id,
        crs_fuzzing=crs_fuzzing,
        human_allow_local_fuzz_run=human_allow_local_fuzz_run,
    ).to_dict()


def attach_local_fuzz_runner_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    crs_fuzzing: dict[str, Any] | None = None,
    local_fuzz_runner: dict[str, Any] | LocalFuzzRunnerResult | None = None,
    human_allow_local_fuzz_run: bool = False,
) -> dict[str, Any]:
    """Attach local fuzz runner profile; never unlocks promote/submit."""
    if not isinstance(bridge_result, dict):
        raise LocalFuzzRunnerError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")
    crs_payload = crs_fuzzing
    if crs_payload is None and isinstance(bridge_result.get("crs_fuzzing"), dict):
        crs_payload = bridge_result.get("crs_fuzzing")

    if isinstance(local_fuzz_runner, LocalFuzzRunnerResult):
        payload = local_fuzz_runner.to_dict()
    elif isinstance(local_fuzz_runner, dict):
        payload = _force_safety_dict(dict(local_fuzz_runner))
    else:
        payload = run_local_fuzz_runner(
            package_root=resolved_root,
            package_id=package_id,
            crs_fuzzing=crs_payload if isinstance(crs_payload, dict) else None,
            human_allow_local_fuzz_run=bool(human_allow_local_fuzz_run),
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["local_fuzz_runner"] = payload
    out["local_fuzz_runner_present"] = True
    out["local_fuzz_runner_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["local_fuzz_runner_target_count"] = int(payload.get("target_count") or 0)
    out["local_fuzz_runner_runnable_count"] = int(payload.get("runnable_target_count") or 0)
    out["local_fuzz_runner_crash_count"] = int(payload.get("crash_count") or 0)
    out["local_fuzz_runner_executed"] = bool(payload.get("in_process_run_executed"))
    out["local_fuzz_runner_export_written"] = bool(payload.get("crash_export_written"))
    out["local_fuzz_runner_export_count"] = int(payload.get("crash_export_count") or 0)
    out["local_fuzz_runner_execution_allowed"] = False
    out["local_fuzz_runner_crash_promotion_allowed"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out


def _resolve_crs_payload(
    *,
    crs_fuzzing: dict[str, Any] | None,
    package_root: Path | None,
    package_id: str,
) -> dict[str, Any]:
    if isinstance(crs_fuzzing, dict):
        return dict(crs_fuzzing)
    if package_root is not None:
        from app.crs_fuzzing import build_crs_fuzzing_plan

        return build_crs_fuzzing_plan(
            package_root=package_root,
            package_id=package_id,
            human_allow_harness_write=False,
        ).to_dict()
    return {}


def _build_targets(
    *,
    root: Path | None,
    crs_payload: dict[str, Any],
) -> list[FuzzTarget]:
    targets: list[FuzzTarget] = []
    seen: set[tuple[str, str]] = set()

    for item in list(crs_payload.get("harness_plans") or []):
        if not isinstance(item, dict):
            continue
        symbol = str(item.get("target_symbol") or item.get("symbol_name") or "").strip()
        source = str(item.get("source_path") or "").strip().replace("\\", "/")
        if not symbol or not source:
            continue
        key = (symbol, source)
        if key in seen:
            continue
        seen.add(key)
        lang = _language_for_path(source)
        runnable = bool(
            root is not None
            and lang == "python"
            and _python_function_exists(root, source, symbol)
        )
        targets.append(
            FuzzTarget(
                target_symbol=symbol,
                source_path=source,
                language=lang,
                harness_kind=str(item.get("harness_kind") or "local_unit_harness"),
                runnable_in_process=runnable,
                status="runnable" if runnable else "preview_only",
                notes=[] if runnable else ["not_python_or_not_extractable"],
                external_command_preview=_external_preview(symbol, source),
            )
        )
        if len(targets) >= _MAX_TARGETS:
            return targets

    if root is not None and len(targets) < _MAX_TARGETS:
        for path, symbol in _discover_python_parsers(root):
            key = (symbol, path)
            if key in seen:
                continue
            seen.add(key)
            targets.append(
                FuzzTarget(
                    target_symbol=symbol,
                    source_path=path,
                    language="python",
                    harness_kind="local_unit_harness",
                    runnable_in_process=True,
                    status="runnable",
                    notes=["discovered_from_package"],
                    external_command_preview=_external_preview(symbol, path),
                )
            )
            if len(targets) >= _MAX_TARGETS:
                break
    return targets


def _discover_python_parsers(root: Path) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    preferred = [
        root / "inputs",
        root / "_extract",
        root / "src",
        root / "app",
        root / "backend",
        root / "_upstream",
    ]
    scan_roots = [p for p in preferred if p.is_dir()] or [root]
    skip = {
        ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "__pycache__",
        ".pytest_cache", ".mypy_cache", "dist", "build", "_export", "vendor",
    }
    for scan in scan_roots:
        for path in scan.rglob("*.py"):
            if any(part in skip for part in path.parts):
                continue
            try:
                rel = str(path.resolve().relative_to(root)).replace("\\", "/")
            except ValueError:
                continue
            text = _safe_read(path)
            if text is None:
                continue
            for name in _python_function_names(text):
                if _name_is_parser(name):
                    found.append((rel, name))
                    if len(found) >= _MAX_TARGETS:
                        return found
    return found


def _python_function_exists(root: Path, rel_path: str, symbol: str) -> bool:
    path = (root / rel_path).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        return False
    text = _safe_read(path)
    if text is None:
        return False
    return symbol in _python_function_names(text)


def _python_function_names(source: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    names: list[str] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.append(node.name)
    return names


def _name_is_parser(name: str) -> bool:
    lower = name.lower()
    return any(m in lower for m in PARSER_NAME_MARKERS)


def _language_for_path(path: str) -> str:
    lower = path.lower()
    if lower.endswith(".py"):
        return "python"
    if lower.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
        return "javascript"
    if lower.endswith((".go",)):
        return "go"
    if lower.endswith((".java",)):
        return "java"
    if lower.endswith((".rs",)):
        return "rust"
    if lower.endswith((".c", ".cc", ".cpp", ".h", ".hpp")):
        return "c_cpp"
    return "unknown"


def _external_preview(symbol: str, source: str) -> str:
    return (
        f"# preview only — Mythos never spawns this\n"
        f"# target={symbol} source={source}\n"
        f"# example: afl-fuzz -i seeds -o findings -- ./harness @@\n"
    )


def _load_in_process_callable(
    root: Path,
    rel_path: str,
    symbol: str,
) -> Callable[[bytes], Any] | None:
    path = (root / rel_path).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError:
        return None
    text = _safe_read(path)
    if text is None:
        return None
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None

    func_node: ast.AST | None = None
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == symbol:
            func_node = node
            break
    if func_node is None or isinstance(func_node, ast.AsyncFunctionDef):
        return None
    if len(getattr(func_node, "body", []) or []) > _MAX_FUNC_BODY_LINES:
        return None

    module = ast.Module(body=[func_node], type_ignores=[])
    ast.fix_missing_locations(module)
    code = compile(module, filename=str(path), mode="exec")
    safe_builtins = {
        "None": None,
        "True": True,
        "False": False,
        "abs": abs,
        "bool": bool,
        "bytes": bytes,
        "bytearray": bytearray,
        "chr": chr,
        "dict": dict,
        "enumerate": enumerate,
        "float": float,
        "format": format,
        "frozenset": frozenset,
        "hasattr": hasattr,
        "hash": hash,
        "int": int,
        "isinstance": isinstance,
        "issubclass": issubclass,
        "len": len,
        "list": list,
        "max": max,
        "min": min,
        "ord": ord,
        "pow": pow,
        "range": range,
        "repr": repr,
        "reversed": reversed,
        "set": set,
        "slice": slice,
        "sorted": sorted,
        "str": str,
        "sum": sum,
        "tuple": tuple,
        "zip": zip,
        "Exception": Exception,
        "ValueError": ValueError,
        "TypeError": TypeError,
        "KeyError": KeyError,
        "IndexError": IndexError,
        "UnicodeDecodeError": UnicodeDecodeError,
        "UnicodeError": UnicodeError,
        "OverflowError": OverflowError,
        "MemoryError": MemoryError,
        "RuntimeError": RuntimeError,
        "AssertionError": AssertionError,
        "object": object,
    }
    glb: dict[str, Any] = {"__builtins__": safe_builtins}
    try:
        exec(code, glb, glb)  # noqa: S102 — intentional restricted harness load
    except Exception:
        return None
    fn = glb.get(symbol)
    if not callable(fn):
        return None
    return fn  # type: ignore[return-value]


def _invoke_seed(
    fn: Callable[[bytes], Any],
    *,
    seed: bytes,
    target: FuzzTarget,
) -> CrashCandidate | None:
    try:
        try:
            fn(seed)
        except TypeError:
            fn(seed.decode("utf-8", errors="replace"))
        return None
    except Exception as exc:  # intentional: collect crash candidates only
        tb = traceback.format_exc(limit=6)
        digest = hashlib.sha256(seed).hexdigest()
        preview = seed[:48]
        try:
            seed_preview = preview.decode("utf-8", errors="replace")
        except Exception:
            seed_preview = repr(preview)
        crash_id = f"crash-{digest[:12]}-{_slug(target.target_symbol)[:24]}"
        return CrashCandidate(
            crash_id=crash_id,
            target_symbol=target.target_symbol,
            source_path=target.source_path,
            exception_type=type(exc).__name__,
            exception_message=str(exc)[:400],
            seed_sha256=digest,
            seed_preview=seed_preview[:120],
            seed_hex=seed.hex(),
            traceback_preview=tb[:1500],
            promotion_allowed=False,
            confirmed_vulnerability=False,
        )


def _write_crash_artifacts(
    *,
    root: Path,
    stamp: str,
    crashes: list[CrashCandidate],
    package_id: str,
) -> tuple[list[CrashCandidate], int]:
    export_root = (root / "_export" / "fuzz_runs" / stamp).resolve()
    try:
        export_root.relative_to(root.resolve())
    except ValueError:
        return crashes, 0
    export_root.mkdir(parents=True, exist_ok=True)
    written: list[CrashCandidate] = []
    count = 0
    for crash in crashes:
        rel_dir = f"_export/fuzz_runs/{stamp}/{crash.crash_id}"
        out_dir = (root / rel_dir).resolve()
        try:
            out_dir.relative_to(root.resolve())
        except ValueError:
            written.append(crash)
            continue
        out_dir.mkdir(parents=True, exist_ok=True)
        meta = {
            "crash_id": crash.crash_id,
            "package_id": package_id,
            "target_symbol": crash.target_symbol,
            "source_path": crash.source_path,
            "exception_type": crash.exception_type,
            "exception_message": crash.exception_message,
            "seed_sha256": crash.seed_sha256,
            "seed_preview": crash.seed_preview,
            "seed_hex": crash.seed_hex,
            "promotion_allowed": False,
            "confirmed_vulnerability": False,
            "finding_promotion_allowed": False,
            "report_submission_allowed": False,
            "crash_promotion_allowed": False,
            "notes": [
                "local_artifact_only",
                "not_a_confirmed_vulnerability",
                "human_triage_required",
            ],
        }
        (out_dir / "meta.json").write_text(
            json.dumps(meta, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        if crash.seed_hex:
            try:
                (out_dir / "seed.bin").write_bytes(bytes.fromhex(crash.seed_hex))
            except ValueError:
                pass
        (out_dir / "traceback.txt").write_text(crash.traceback_preview or "", encoding="utf-8")
        (out_dir / "README.md").write_text(
            "\n".join(
                [
                    f"# Crash candidate {crash.crash_id}",
                    "",
                    "- promotion_allowed: false",
                    "- confirmed_vulnerability: false",
                    "- report_submission_allowed: false",
                    "- Mythos never auto-imports this as a finding",
                    "- Human triage only; local authorized package context",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        count += 1
        written.append(
            CrashCandidate(
                crash_id=crash.crash_id,
                target_symbol=crash.target_symbol,
                source_path=crash.source_path,
                exception_type=crash.exception_type,
                exception_message=crash.exception_message,
                seed_sha256=crash.seed_sha256,
                seed_preview=crash.seed_preview,
                seed_hex=crash.seed_hex,
                traceback_preview=crash.traceback_preview,
                artifact_relative_path=rel_dir.replace("\\", "/"),
                written=True,
                promotion_allowed=False,
                confirmed_vulnerability=False,
            )
        )
    return written, count


def _empty_result(
    *,
    status: str,
    package_id: str = "",
    package_root: str = "",
    notes: list[str] | None = None,
    human_allow_local_fuzz_run: bool = False,
    crs_status: str = "",
) -> LocalFuzzRunnerResult:
    return _force_safety_result(
        LocalFuzzRunnerResult(
            stage="v1_approved_local_fuzz_execution",
            inspirations=["Buttercup", "OSS-Fuzz", "AFL++", "libFuzzer", "Python harness"],
            execution_mode="plan_only",
            status=status,
            package_id=package_id,
            package_root=package_root,
            human_allow_local_fuzz_run=bool(human_allow_local_fuzz_run),
            safety_invariants=list(SAFETY_INVARIANTS),
            notes=list(notes or []),
            crs_status=crs_status,
            next_allowed_action=(
                "Provide authorized package with parser/harness targets before local fuzz run."
            ),
        )
    )


def _rebuild(
    base: LocalFuzzRunnerResult,
    *,
    status: str | None = None,
    notes: list[str] | None = None,
    execution_mode: str | None = None,
    in_process_run_executed: bool | None = None,
    next_allowed_action: str | None = None,
) -> LocalFuzzRunnerResult:
    return LocalFuzzRunnerResult(
        stage=base.stage,
        inspirations=list(base.inspirations),
        execution_mode=execution_mode if execution_mode is not None else base.execution_mode,
        status=status if status is not None else base.status,
        package_id=base.package_id,
        package_root=base.package_root,
        targets=list(base.targets),
        target_count=base.target_count,
        runnable_target_count=base.runnable_target_count,
        iterations_total=base.iterations_total,
        crash_candidates=list(base.crash_candidates),
        crash_count=base.crash_count,
        human_allow_local_fuzz_run=base.human_allow_local_fuzz_run,
        in_process_run_executed=(
            bool(in_process_run_executed)
            if in_process_run_executed is not None
            else base.in_process_run_executed
        ),
        crash_export_written=base.crash_export_written,
        crash_export_count=base.crash_export_count,
        run_stamp=base.run_stamp,
        safety_invariants=list(SAFETY_INVARIANTS),
        notes=list(notes) if notes is not None else list(base.notes),
        crs_status=base.crs_status,
        duration_ms=base.duration_ms,
        next_allowed_action=(
            next_allowed_action if next_allowed_action is not None else base.next_allowed_action
        ),
    )


def _force_safety_result(result: LocalFuzzRunnerResult) -> LocalFuzzRunnerResult:
    crashes = [
        CrashCandidate(
            crash_id=c.crash_id,
            target_symbol=c.target_symbol,
            source_path=c.source_path,
            exception_type=c.exception_type,
            exception_message=c.exception_message,
            seed_sha256=c.seed_sha256,
            seed_preview=c.seed_preview,
            seed_hex=c.seed_hex,
            traceback_preview=c.traceback_preview,
            artifact_relative_path=c.artifact_relative_path,
            written=c.written,
            promotion_allowed=False,
            confirmed_vulnerability=False,
        )
        for c in result.crash_candidates
    ]
    return LocalFuzzRunnerResult(
        stage=result.stage,
        inspirations=list(result.inspirations),
        execution_mode=result.execution_mode if result.in_process_run_executed else "plan_only",
        status=result.status,
        package_id=result.package_id,
        package_root=result.package_root,
        targets=list(result.targets),
        target_count=len(result.targets),
        runnable_target_count=int(result.runnable_target_count or 0),
        iterations_total=int(result.iterations_total or 0),
        crash_candidates=crashes,
        crash_count=len(crashes),
        human_allow_local_fuzz_run=bool(result.human_allow_local_fuzz_run),
        human_approval_required_before_run=True,
        in_process_run_executed=bool(result.in_process_run_executed),
        process_spawn_allowed=False,
        external_fuzzer_spawn_allowed=False,
        network_access=False,
        live_validation=False,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        crash_promotion_allowed=False,
        crash_export_written=bool(result.crash_export_written),
        crash_export_count=int(result.crash_export_count or 0),
        crash_export_root_relative=result.crash_export_root_relative or "_export/fuzz_runs",
        run_stamp=result.run_stamp,
        safety_invariants=list(SAFETY_INVARIANTS),
        next_allowed_action=result.next_allowed_action,
        notes=list(result.notes),
        crs_status=result.crs_status,
        duration_ms=result.duration_ms,
    )


def _force_safety_dict(payload: dict[str, Any]) -> dict[str, Any]:
    payload = dict(payload)
    payload["process_spawn_allowed"] = False
    payload["external_fuzzer_spawn_allowed"] = False
    payload["network_access"] = False
    payload["live_validation"] = False
    payload["execution_allowed"] = False
    payload["validation_allowed"] = False
    payload["report_submission_allowed"] = False
    payload["confirmed_vulnerability"] = False
    payload["finding_promotion_allowed"] = False
    payload["crash_promotion_allowed"] = False
    payload["human_approval_required_before_run"] = True
    payload["human_allow_local_fuzz_run"] = bool(payload.get("human_allow_local_fuzz_run"))
    payload["in_process_run_executed"] = bool(payload.get("in_process_run_executed"))
    payload["crash_export_written"] = bool(payload.get("crash_export_written"))
    payload["crash_export_count"] = int(payload.get("crash_export_count") or 0)
    payload["crash_export_root_relative"] = str(
        payload.get("crash_export_root_relative") or "_export/fuzz_runs"
    )
    payload["safety_invariants"] = list(SAFETY_INVARIANTS)
    if not payload.get("in_process_run_executed"):
        payload["execution_mode"] = "plan_only"
    crashes = payload.get("crash_candidates")
    if isinstance(crashes, list):
        fixed = []
        for c in crashes:
            if not isinstance(c, dict):
                continue
            item = dict(c)
            item["promotion_allowed"] = False
            item["confirmed_vulnerability"] = False
            fixed.append(item)
        payload["crash_candidates"] = fixed
        payload["crash_count"] = len(fixed)
    targets = payload.get("targets")
    if isinstance(targets, list):
        payload["target_count"] = len(targets)
    return payload


def _load_package_id(root: Path) -> str:
    meta = root / "package.json"
    if meta.is_file():
        try:
            data = json.loads(meta.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("package_id"):
                return str(data["package_id"])
            if isinstance(data, dict) and data.get("name"):
                return str(data["name"])
        except Exception:
            pass
    for name in ("PACKAGE_ID", "package_id.txt"):
        p = root / name
        if p.is_file():
            text = p.read_text(encoding="utf-8", errors="replace").strip()
            if text:
                return text.splitlines()[0].strip()
    return ""


def _safe_read(path: Path) -> str | None:
    try:
        if not path.is_file():
            return None
        if path.stat().st_size > _MAX_SOURCE_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace").lstrip("\ufeff")
    except OSError:
        return None


def _slug(value: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip().lower())
    text = re.sub(r"-{2,}", "-", text).strip("-")
    return (text or "target")[:80]


__all__ = [
    "STATUS_COMPLETED",
    "STATUS_CRASHES",
    "STATUS_EMPTY",
    "STATUS_FAILED",
    "STATUS_PLANNED",
    "STATUS_SKIPPED",
    "STATUS_SKIPPED_NO_FLAG",
    "STATUS_SKIPPED_NO_PYTHON",
    "STATUS_SKIPPED_NO_TARGET",
    "CrashCandidate",
    "FuzzTarget",
    "LocalFuzzRunnerError",
    "LocalFuzzRunnerResult",
    "attach_local_fuzz_runner_to_bridge_result",
    "build_local_fuzz_runner_plan",
    "load_package_local_fuzz_runner_result",
    "run_local_fuzz_runner",
]
