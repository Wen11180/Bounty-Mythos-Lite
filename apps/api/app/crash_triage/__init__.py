"""Crash triage: dedupe, minimize, reproducibility, advisory root-cause.

Final-scheme V1 residual after local fuzz runner collects crashes:
- Dedupe crash candidates by signature
- Attempt seed minimization (delta-debug) against in-process Python harness
- Mark reproducible when the same exception family re-triggers
- Emit advisory root-cause notes (never confirmed vulnerability)
- Never promote crashes, never spawn external fuzzers, never submit reports
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


STATUS_READY = "crash_triage_ready"
STATUS_EMPTY = "crash_triage_empty"
STATUS_SKIPPED = "crash_triage_package_missing"
STATUS_SKIPPED_NO_CRASHES = "crash_triage_no_crashes"
STATUS_SKIPPED_NO_RUNNER = "crash_triage_no_runner_payload"
STATUS_COMPLETED = "crash_triage_completed"
STATUS_EXPORT_WRITTEN = "crash_triage_export_written"

SAFETY_INVARIANTS = [
    "local_or_authorized_package_only",
    "no_public_target_scanning",
    "no_external_fuzzer_process_spawn",
    "no_network_access",
    "no_crash_promotion",
    "no_report_submission",
    "advisory_root_cause_only",
    "minimization_local_in_process_only",
    "human_review_required_before_any_promotion",
]

_MAX_CRASHES = 40
_MAX_MINIMIZE_STEPS = 64
_MAX_SEED_BYTES = 8192


class CrashTriageError(ValueError):
    """Raised when bridge attach receives invalid input."""


@dataclass(frozen=True)
class RootCauseNote:
    status: str
    summary: str
    exception_family: str
    likely_surface: str
    needs_human_review: bool = True
    confirmed_vulnerability: bool = False
    required_inputs: list[str] = field(default_factory=list)
    questions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class TriagedCrash:
    crash_id: str
    cluster_id: str
    target_symbol: str
    source_path: str
    exception_type: str
    exception_message: str
    crash_type: str
    signature: str
    seed_sha256: str
    seed_preview: str
    original_seed_len: int = 0
    minimized_seed_len: int | None = None
    minimized_seed_sha256: str = ""
    minimized_seed_preview: str = ""
    minimized: bool = False
    reproducible: bool | None = None
    reproduction_count: int = 0
    artifact_relative_path: str = ""
    triage_export_relative_path: str = ""
    written: bool = False
    promotion_allowed: bool = False
    confirmed_vulnerability: bool = False
    root_cause: RootCauseNote | None = None
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CrashTriageResult:
    stage: str
    inspirations: list[str]
    execution_mode: str
    status: str
    package_id: str = ""
    package_root: str = ""
    input_crash_count: int = 0
    triaged: list[TriagedCrash] = field(default_factory=list)
    triaged_count: int = 0
    unique_cluster_count: int = 0
    reproducible_count: int = 0
    minimized_count: int = 0
    deduped_away_count: int = 0
    human_allow_crash_triage: bool = False
    triage_executed: bool = False
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
    triage_export_written: bool = False
    triage_export_count: int = 0
    triage_export_root_relative: str = "_export/crash_triage"
    run_stamp: str = ""
    safety_invariants: list[str] = field(default_factory=list)
    next_allowed_action: str = (
        "Review triaged crash clusters offline; never promote without human evidence."
    )
    notes: list[str] = field(default_factory=list)
    local_fuzz_runner_status: str = ""
    duration_ms: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return _force_safety_dict(asdict(self))


def build_crash_triage_plan(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    local_fuzz_runner: dict[str, Any] | None = None,
    human_allow_crash_triage: bool = False,
) -> CrashTriageResult:
    """Plan-only crash triage profile (never minimizes / re-runs)."""
    return run_crash_triage(
        package_root=package_root,
        package_id=package_id,
        local_fuzz_runner=local_fuzz_runner,
        human_allow_crash_triage=human_allow_crash_triage,
        force_plan_only=True,
    )


def run_crash_triage(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    local_fuzz_runner: dict[str, Any] | None = None,
    human_allow_crash_triage: bool = False,
    force_plan_only: bool = False,
    write_export: bool = True,
) -> CrashTriageResult:
    """Dedupe/minimize/classify local fuzz crashes under human gate."""
    notes: list[str] = [
        "advisory_only",
        "no_crash_promotion",
        "in_process_minimize_only",
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

    runner = dict(local_fuzz_runner) if isinstance(local_fuzz_runner, dict) else {}
    runner_status = str(runner.get("status") or "")

    crashes = _extract_crashes(runner)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    if not runner and root is None:
        return _empty(
            status=STATUS_SKIPPED if package_root else STATUS_EMPTY,
            package_id=resolved_id,
            package_root=str(package_root or ""),
            notes=notes + ["missing_runner_and_package"],
            human_allow_crash_triage=bool(human_allow_crash_triage),
            local_fuzz_runner_status=runner_status,
        )

    if not crashes:
        return _empty(
            status=STATUS_SKIPPED_NO_CRASHES if runner else STATUS_SKIPPED_NO_RUNNER,
            package_id=resolved_id,
            package_root=str(root or ""),
            notes=notes + ["no_crash_candidates"],
            human_allow_crash_triage=bool(human_allow_crash_triage),
            local_fuzz_runner_status=runner_status,
            input_crash_count=0,
        )

    base = CrashTriageResult(
        stage="v1_crash_triage_and_minimization",
        inspirations=["AFL++", "libFuzzer", "OSS-Fuzz", "Buttercup"],
        execution_mode="plan_only",
        status=STATUS_READY,
        package_id=resolved_id,
        package_root=str(root or ""),
        input_crash_count=len(crashes),
        human_allow_crash_triage=bool(human_allow_crash_triage),
        safety_invariants=list(SAFETY_INVARIANTS),
        notes=list(notes),
        local_fuzz_runner_status=runner_status,
        run_stamp=stamp,
        next_allowed_action=(
            "Plan-only. Re-run with human_allow_crash_triage=True "
            "(or bridge --allow-crash-triage) for minimize/repro only."
        ),
    )

    if not human_allow_crash_triage or force_plan_only:
        # Plan preview: classify + dedupe signatures without re-execution
        preview = _plan_preview(crashes)
        status = STATUS_READY
        if not human_allow_crash_triage:
            notes = list(notes) + ["triage_not_requested"]
        if force_plan_only and human_allow_crash_triage:
            notes = list(notes) + ["force_plan_only"]
        return _force_safety(
            CrashTriageResult(
                stage=base.stage,
                inspirations=list(base.inspirations),
                execution_mode="plan_only",
                status=status,
                package_id=resolved_id,
                package_root=str(root or ""),
                input_crash_count=len(crashes),
                triaged=preview,
                triaged_count=len(preview),
                unique_cluster_count=len({t.cluster_id for t in preview}),
                deduped_away_count=max(0, len(crashes) - len(preview)),
                human_allow_crash_triage=bool(human_allow_crash_triage),
                triage_executed=False,
                safety_invariants=list(SAFETY_INVARIANTS),
                notes=notes,
                local_fuzz_runner_status=runner_status,
                run_stamp=stamp,
                next_allowed_action=base.next_allowed_action,
            )
        )

    if root is None:
        return _force_safety(
            CrashTriageResult(
                stage=base.stage,
                inspirations=list(base.inspirations),
                execution_mode="plan_only",
                status=STATUS_SKIPPED,
                package_id=resolved_id,
                package_root="",
                input_crash_count=len(crashes),
                human_allow_crash_triage=True,
                safety_invariants=list(SAFETY_INVARIANTS),
                notes=list(notes) + ["triage_requested_but_package_root_missing"],
                local_fuzz_runner_status=runner_status,
                run_stamp=stamp,
                next_allowed_action="Provide authorized package_root for minimize/repro.",
            )
        )

    started = datetime.now(timezone.utc)
    triaged = _triage_execute(root=root, crashes=crashes, package_id=resolved_id)
    export_written = False
    export_count = 0
    if write_export and triaged:
        triaged, export_count = _write_exports(
            root=root, stamp=stamp, triaged=triaged, package_id=resolved_id
        )
        export_written = export_count > 0

    elapsed = int((datetime.now(timezone.utc) - started).total_seconds() * 1000)
    clusters = {t.cluster_id for t in triaged}
    repro = sum(1 for t in triaged if t.reproducible is True)
    mini = sum(1 for t in triaged if t.minimized)
    run_notes = list(notes) + [
        "triage_executed",
        f"clusters={len(clusters)}",
        f"reproducible={repro}",
        f"minimized={mini}",
        "crash_promotion_blocked",
    ]
    status = STATUS_EXPORT_WRITTEN if export_written else STATUS_COMPLETED
    return _force_safety(
        CrashTriageResult(
            stage="v1_crash_triage_and_minimization",
            inspirations=["AFL++", "libFuzzer", "OSS-Fuzz", "Buttercup"],
            execution_mode="in_process_triage",
            status=status,
            package_id=resolved_id,
            package_root=str(root),
            input_crash_count=len(crashes),
            triaged=triaged,
            triaged_count=len(triaged),
            unique_cluster_count=len(clusters),
            reproducible_count=repro,
            minimized_count=mini,
            deduped_away_count=max(0, len(crashes) - len(triaged)),
            human_allow_crash_triage=True,
            triage_executed=True,
            triage_export_written=export_written,
            triage_export_count=export_count,
            run_stamp=stamp,
            safety_invariants=list(SAFETY_INVARIANTS),
            notes=run_notes,
            local_fuzz_runner_status=runner_status,
            duration_ms=elapsed,
            next_allowed_action=(
                "Human reviews triaged clusters and root-cause notes; "
                "Mythos never promotes crashes or submits reports."
            ),
        )
    )


def attach_crash_triage_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    local_fuzz_runner: dict[str, Any] | None = None,
    crash_triage: dict[str, Any] | CrashTriageResult | None = None,
    human_allow_crash_triage: bool = False,
) -> dict[str, Any]:
    """Attach crash triage profile; never unlocks promote/submit."""
    if not isinstance(bridge_result, dict):
        raise CrashTriageError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")
    runner = local_fuzz_runner
    if runner is None and isinstance(bridge_result.get("local_fuzz_runner"), dict):
        runner = bridge_result.get("local_fuzz_runner")

    if isinstance(crash_triage, CrashTriageResult):
        payload = crash_triage.to_dict()
    elif isinstance(crash_triage, dict):
        payload = _force_safety_dict(dict(crash_triage))
    else:
        payload = run_crash_triage(
            package_root=resolved_root,
            package_id=package_id,
            local_fuzz_runner=runner if isinstance(runner, dict) else None,
            human_allow_crash_triage=bool(human_allow_crash_triage),
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["crash_triage"] = payload
    out["crash_triage_present"] = True
    out["crash_triage_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["crash_triage_input_crash_count"] = int(payload.get("input_crash_count") or 0)
    out["crash_triage_cluster_count"] = int(payload.get("unique_cluster_count") or 0)
    out["crash_triage_reproducible_count"] = int(payload.get("reproducible_count") or 0)
    out["crash_triage_minimized_count"] = int(payload.get("minimized_count") or 0)
    out["crash_triage_executed"] = bool(payload.get("triage_executed"))
    out["crash_triage_export_written"] = bool(payload.get("triage_export_written"))
    out["crash_triage_export_count"] = int(payload.get("triage_export_count") or 0)
    out["crash_triage_crash_promotion_allowed"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out


def _extract_crashes(runner: dict[str, Any]) -> list[dict[str, Any]]:
    raw = runner.get("crash_candidates") if isinstance(runner, dict) else None
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for item in raw[:_MAX_CRASHES]:
        if isinstance(item, dict):
            out.append(dict(item))
    return out


def _signature(crash: dict[str, Any]) -> str:
    target = str(crash.get("target_symbol") or "")
    etype = str(crash.get("exception_type") or "")
    msg = str(crash.get("exception_message") or "")
    # Normalize digits / hex addresses for clustering
    msg_n = re.sub(r"0x[0-9a-fA-F]+", "0x?", msg)
    msg_n = re.sub(r"\d+", "N", msg_n)[:160]
    src = str(crash.get("source_path") or "")
    base = f"{target}|{src}|{etype}|{msg_n}"
    return hashlib.sha256(base.encode("utf-8", errors="replace")).hexdigest()[:16]


def _crash_type(exception_type: str, message: str) -> str:
    et = (exception_type or "").lower()
    msg = (message or "").lower()
    if "memory" in et or "memoryerror" in et:
        return "memory_error"
    if "unicode" in et:
        return "unicode_decode"
    if "overflow" in et:
        return "overflow"
    if "index" in et:
        return "index_error"
    if "key" in et:
        return "key_error"
    if "type" in et:
        return "type_error"
    if "value" in et:
        return "value_error"
    if "assert" in et:
        return "assertion"
    if "runtime" in et or "boom" in msg:
        return "runtime_error"
    if "recursion" in et or "recursion" in msg:
        return "recursion"
    return exception_type or "unknown_exception"


def _root_cause_note(
    *,
    exception_type: str,
    exception_message: str,
    target_symbol: str,
    source_path: str,
    crash_type: str,
    reproducible: bool | None,
) -> RootCauseNote:
    family = exception_type or "Exception"
    surface = f"{source_path}::{target_symbol}" if source_path else target_symbol
    repro_txt = (
        "reproducible under local in-process harness"
        if reproducible is True
        else (
            "not re-confirmed under local harness"
            if reproducible is False
            else "reproducibility not executed (plan-only)"
        )
    )
    summary = (
        f"Advisory: {family} in {surface} classified as {crash_type}; {repro_txt}. "
        f"Message: {(exception_message or '')[:160]}"
    )
    questions = [
        "Is this exception reachable from an untrusted input boundary?",
        "Does the same minimized seed fail outside the restricted harness sandbox?",
        "Is impact limited to DoS/crash or does it imply memory/logic abuse?",
        "Does authorized scope allow further local validation?",
    ]
    status = (
        "advisory_root_cause_draft"
        if reproducible is True
        else "blocked_until_reproducible_crash"
        if reproducible is False
        else "plan_only_root_cause_placeholder"
    )
    return RootCauseNote(
        status=status,
        summary=summary,
        exception_family=family,
        likely_surface=surface,
        needs_human_review=True,
        confirmed_vulnerability=False,
        required_inputs=[
            "reproducible_crash",
            "minimized_input_ref",
            "authorized_package_context",
            "human_impact_assessment",
        ],
        questions=questions,
    )


def _plan_preview(crashes: list[dict[str, Any]]) -> list[TriagedCrash]:
    seen: set[str] = set()
    out: list[TriagedCrash] = []
    for c in crashes:
        sig = _signature(c)
        if sig in seen:
            continue
        seen.add(sig)
        et = str(c.get("exception_type") or "")
        em = str(c.get("exception_message") or "")
        ctype = _crash_type(et, em)
        seed_prev = str(c.get("seed_preview") or "")
        seed_bytes = seed_prev.encode("utf-8", errors="replace")
        target = str(c.get("target_symbol") or "")
        source = str(c.get("source_path") or "")
        rc = _root_cause_note(
            exception_type=et,
            exception_message=em,
            target_symbol=target,
            source_path=source,
            crash_type=ctype,
            reproducible=None,
        )
        out.append(
            TriagedCrash(
                crash_id=str(c.get("crash_id") or f"crash-{sig}"),
                cluster_id=f"cluster-{sig}",
                target_symbol=target,
                source_path=source,
                exception_type=et,
                exception_message=em[:400],
                crash_type=ctype,
                signature=sig,
                seed_sha256=str(c.get("seed_sha256") or ""),
                seed_preview=seed_prev[:120],
                original_seed_len=len(seed_bytes),
                reproducible=None,
                artifact_relative_path=str(c.get("artifact_relative_path") or ""),
                promotion_allowed=False,
                confirmed_vulnerability=False,
                root_cause=rc,
                notes=["plan_preview", "minimize_not_executed"],
            )
        )
    return out


def _triage_execute(
    *,
    root: Path,
    crashes: list[dict[str, Any]],
    package_id: str,
) -> list[TriagedCrash]:
    # Import harness loader from local_fuzz_runner
    from app.local_fuzz_runner import (
        FuzzTarget,
        _invoke_seed,
        _load_in_process_callable,
    )

    # Group by signature; keep first of each cluster with seed recovery
    clusters: dict[str, dict[str, Any]] = {}
    for c in crashes:
        sig = _signature(c)
        if sig not in clusters:
            clusters[sig] = c

    results: list[TriagedCrash] = []
    for sig, c in clusters.items():
        target = str(c.get("target_symbol") or "")
        source = str(c.get("source_path") or "")
        et = str(c.get("exception_type") or "")
        em = str(c.get("exception_message") or "")
        ctype = _crash_type(et, em)
        seed = _recover_seed(root, c)
        original_len = len(seed) if seed is not None else 0
        notes: list[str] = ["cluster_representative"]

        fn = None
        if target and source:
            fn = _load_in_process_callable(root, source, target)

        reproducible: bool | None = None
        repro_count = 0
        minimized = False
        mini_seed = seed
        mini_len: int | None = None
        mini_sha = ""
        mini_prev = ""

        ft = FuzzTarget(
            target_symbol=target,
            source_path=source,
            language="python",
            harness_kind="local_unit_harness",
            runnable_in_process=fn is not None,
        )

        if fn is None or seed is None:
            notes.append("harness_or_seed_unavailable")
            reproducible = None
        else:
            # Confirm reproducibility with original seed
            crash = _invoke_seed(fn, seed=seed, target=ft)
            if crash is not None and _same_family(crash.exception_type, et):
                reproducible = True
                repro_count = 1
                notes.append("reproduced_original_seed")
                # Minimize
                mini_seed, steps = _minimize_seed(fn, seed=seed, target=ft, want_type=et)
                if mini_seed is not None and len(mini_seed) < len(seed):
                    minimized = True
                    notes.append(f"minimized_steps={steps}")
                elif mini_seed is not None:
                    notes.append("minimize_no_smaller_seed")
                # Re-check minimized
                if mini_seed is not None:
                    crash2 = _invoke_seed(fn, seed=mini_seed, target=ft)
                    if crash2 is not None and _same_family(crash2.exception_type, et):
                        repro_count += 1
                        notes.append("reproduced_minimized_seed")
            else:
                reproducible = False
                notes.append("failed_to_reproduce")

        if mini_seed is not None:
            mini_len = len(mini_seed)
            mini_sha = hashlib.sha256(mini_seed).hexdigest()
            try:
                mini_prev = mini_seed[:48].decode("utf-8", errors="replace")
            except Exception:
                mini_prev = repr(mini_seed[:48])

        seed_prev = str(c.get("seed_preview") or "")
        if seed is not None and not seed_prev:
            try:
                seed_prev = seed[:48].decode("utf-8", errors="replace")
            except Exception:
                seed_prev = repr(seed[:48])

        rc = _root_cause_note(
            exception_type=et,
            exception_message=em,
            target_symbol=target,
            source_path=source,
            crash_type=ctype,
            reproducible=reproducible,
        )
        results.append(
            TriagedCrash(
                crash_id=str(c.get("crash_id") or f"crash-{sig}"),
                cluster_id=f"cluster-{sig}",
                target_symbol=target,
                source_path=source,
                exception_type=et,
                exception_message=em[:400],
                crash_type=ctype,
                signature=sig,
                seed_sha256=str(c.get("seed_sha256") or (hashlib.sha256(seed).hexdigest() if seed else "")),
                seed_preview=seed_prev[:120],
                original_seed_len=original_len,
                minimized_seed_len=mini_len,
                minimized_seed_sha256=mini_sha,
                minimized_seed_preview=mini_prev[:120],
                minimized=minimized,
                reproducible=reproducible,
                reproduction_count=repro_count,
                artifact_relative_path=str(c.get("artifact_relative_path") or ""),
                promotion_allowed=False,
                confirmed_vulnerability=False,
                root_cause=rc,
                notes=notes,
            )
        )
    return results


def _same_family(a: str, b: str) -> bool:
    return (a or "").strip().lower() == (b or "").strip().lower()


def _recover_seed(root: Path, crash: dict[str, Any]) -> bytes | None:
    # Prefer artifact meta seed_preview + seed_sha256; try common seed files
    art = str(crash.get("artifact_relative_path") or "").strip()
    if art:
        art_path = (root / art).resolve()
        try:
            art_path.relative_to(root.resolve())
        except ValueError:
            art_path = None  # type: ignore[assignment]
        if art_path is not None and art_path.is_dir():
            for name in ("seed.bin", "seed.input", "input.bin", "minimized.bin"):
                p = art_path / name
                if p.is_file() and p.stat().st_size <= _MAX_SEED_BYTES:
                    try:
                        return p.read_bytes()
                    except OSError:
                        pass
            meta = art_path / "meta.json"
            if meta.is_file():
                try:
                    data = json.loads(meta.read_text(encoding="utf-8"))
                    if isinstance(data, dict) and data.get("seed_hex"):
                        return bytes.fromhex(str(data["seed_hex"]))
                except Exception:
                    pass

    hex_s = str(crash.get("seed_hex") or "").strip()
    if hex_s:
        try:
            data = bytes.fromhex(hex_s)
            if data:
                return data[:_MAX_SEED_BYTES]
        except ValueError:
            pass

    preview = str(crash.get("seed_preview") or "")
    if preview:
        # Best-effort: preview is lossy for binary; still useful for text crashes
        return preview.encode("utf-8", errors="replace")[:_MAX_SEED_BYTES]
    return None


def _minimize_seed(
    fn: Callable[[bytes], Any],
    *,
    seed: bytes,
    target: Any,
    want_type: str,
) -> tuple[bytes | None, int]:
    from app.local_fuzz_runner import _invoke_seed

    if not seed:
        return seed, 0

    def still_crashes(candidate: bytes) -> bool:
        crash = _invoke_seed(fn, seed=candidate, target=target)
        return crash is not None and _same_family(crash.exception_type, want_type)

    current = seed[:_MAX_SEED_BYTES]
    if not still_crashes(current):
        return None, 0

    steps = 0
    # Byte-delete delta debug (coarse then fine)
    changed = True
    while changed and steps < _MAX_MINIMIZE_STEPS and len(current) > 1:
        changed = False
        # try remove halves / chunks
        chunk = max(1, len(current) // 2)
        i = 0
        while i < len(current) and steps < _MAX_MINIMIZE_STEPS and len(current) > 1:
            nxt = current[:i] + current[i + chunk :]
            steps += 1
            if nxt != current and still_crashes(nxt):
                current = nxt
                changed = True
                # restart from beginning with same chunk size
                i = 0
                continue
            i += chunk
        if not changed and chunk > 1:
            # finer grain: single-byte deletion pass
            i = 0
            while i < len(current) and steps < _MAX_MINIMIZE_STEPS and len(current) > 1:
                nxt = current[:i] + current[i + 1 :]
                steps += 1
                if still_crashes(nxt):
                    current = nxt
                    changed = True
                    # stay at i (next byte shifted into place)
                    continue
                i += 1
    return current, steps


def _write_exports(
    *,
    root: Path,
    stamp: str,
    triaged: list[TriagedCrash],
    package_id: str,
) -> tuple[list[TriagedCrash], int]:
    export_root = (root / "_export" / "crash_triage" / stamp).resolve()
    try:
        export_root.relative_to(root.resolve())
    except ValueError:
        return triaged, 0
    export_root.mkdir(parents=True, exist_ok=True)

    # cluster index
    index = {
        "package_id": package_id,
        "stamp": stamp,
        "cluster_count": len(triaged),
        "crash_promotion_allowed": False,
        "confirmed_vulnerability": False,
        "report_submission_allowed": False,
        "clusters": [
            {
                "cluster_id": t.cluster_id,
                "crash_id": t.crash_id,
                "target_symbol": t.target_symbol,
                "crash_type": t.crash_type,
                "reproducible": t.reproducible,
                "minimized": t.minimized,
            }
            for t in triaged
        ],
    }
    (export_root / "index.json").write_text(
        json.dumps(index, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    written: list[TriagedCrash] = []
    count = 0
    for t in triaged:
        rel = f"_export/crash_triage/{stamp}/{t.cluster_id}"
        out_dir = (root / rel).resolve()
        try:
            out_dir.relative_to(root.resolve())
        except ValueError:
            written.append(t)
            continue
        out_dir.mkdir(parents=True, exist_ok=True)
        meta = {
            "cluster_id": t.cluster_id,
            "crash_id": t.crash_id,
            "package_id": package_id,
            "target_symbol": t.target_symbol,
            "source_path": t.source_path,
            "exception_type": t.exception_type,
            "exception_message": t.exception_message,
            "crash_type": t.crash_type,
            "signature": t.signature,
            "seed_sha256": t.seed_sha256,
            "seed_preview": t.seed_preview,
            "original_seed_len": t.original_seed_len,
            "minimized": t.minimized,
            "minimized_seed_len": t.minimized_seed_len,
            "minimized_seed_sha256": t.minimized_seed_sha256,
            "minimized_seed_preview": t.minimized_seed_preview,
            "reproducible": t.reproducible,
            "reproduction_count": t.reproduction_count,
            "promotion_allowed": False,
            "confirmed_vulnerability": False,
            "finding_promotion_allowed": False,
            "report_submission_allowed": False,
            "crash_promotion_allowed": False,
            "root_cause": asdict(t.root_cause) if t.root_cause else None,
            "notes": list(t.notes),
        }
        (out_dir / "triage.json").write_text(
            json.dumps(meta, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        if t.minimized_seed_preview:
            (out_dir / "minimized_seed_preview.txt").write_text(
                t.minimized_seed_preview, encoding="utf-8"
            )
        (out_dir / "README.md").write_text(
            "\n".join(
                [
                    f"# Crash cluster {t.cluster_id}",
                    "",
                    f"- crash_id: `{t.crash_id}`",
                    f"- crash_type: `{t.crash_type}`",
                    f"- reproducible: `{t.reproducible}`",
                    f"- minimized: `{t.minimized}`",
                    "- promotion_allowed: false",
                    "- confirmed_vulnerability: false",
                    "- report_submission_allowed: false",
                    "",
                    "## Advisory root cause",
                    "",
                    (t.root_cause.summary if t.root_cause else "n/a"),
                    "",
                    "Human triage only. Mythos never auto-promotes this cluster.",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        count += 1
        written.append(
            TriagedCrash(
                crash_id=t.crash_id,
                cluster_id=t.cluster_id,
                target_symbol=t.target_symbol,
                source_path=t.source_path,
                exception_type=t.exception_type,
                exception_message=t.exception_message,
                crash_type=t.crash_type,
                signature=t.signature,
                seed_sha256=t.seed_sha256,
                seed_preview=t.seed_preview,
                original_seed_len=t.original_seed_len,
                minimized_seed_len=t.minimized_seed_len,
                minimized_seed_sha256=t.minimized_seed_sha256,
                minimized_seed_preview=t.minimized_seed_preview,
                minimized=t.minimized,
                reproducible=t.reproducible,
                reproduction_count=t.reproduction_count,
                artifact_relative_path=t.artifact_relative_path,
                triage_export_relative_path=rel.replace("\\", "/"),
                written=True,
                promotion_allowed=False,
                confirmed_vulnerability=False,
                root_cause=t.root_cause,
                notes=list(t.notes) + ["triage_export_written"],
            )
        )
    return written, count


def _empty(
    *,
    status: str,
    package_id: str = "",
    package_root: str = "",
    notes: list[str] | None = None,
    human_allow_crash_triage: bool = False,
    local_fuzz_runner_status: str = "",
    input_crash_count: int = 0,
) -> CrashTriageResult:
    return _force_safety(
        CrashTriageResult(
            stage="v1_crash_triage_and_minimization",
            inspirations=["AFL++", "libFuzzer", "OSS-Fuzz", "Buttercup"],
            execution_mode="plan_only",
            status=status,
            package_id=package_id,
            package_root=package_root,
            input_crash_count=input_crash_count,
            human_allow_crash_triage=bool(human_allow_crash_triage),
            safety_invariants=list(SAFETY_INVARIANTS),
            notes=list(notes or []),
            local_fuzz_runner_status=local_fuzz_runner_status,
            next_allowed_action=(
                "Provide local_fuzz_runner crash candidates from an authorized package."
            ),
        )
    )


def _force_safety(result: CrashTriageResult) -> CrashTriageResult:
    triaged: list[TriagedCrash] = []
    for t in result.triaged:
        rc = t.root_cause
        if rc is not None:
            rc = RootCauseNote(
                status=rc.status,
                summary=rc.summary,
                exception_family=rc.exception_family,
                likely_surface=rc.likely_surface,
                needs_human_review=True,
                confirmed_vulnerability=False,
                required_inputs=list(rc.required_inputs),
                questions=list(rc.questions),
            )
        triaged.append(
            TriagedCrash(
                crash_id=t.crash_id,
                cluster_id=t.cluster_id,
                target_symbol=t.target_symbol,
                source_path=t.source_path,
                exception_type=t.exception_type,
                exception_message=t.exception_message,
                crash_type=t.crash_type,
                signature=t.signature,
                seed_sha256=t.seed_sha256,
                seed_preview=t.seed_preview,
                original_seed_len=t.original_seed_len,
                minimized_seed_len=t.minimized_seed_len,
                minimized_seed_sha256=t.minimized_seed_sha256,
                minimized_seed_preview=t.minimized_seed_preview,
                minimized=t.minimized,
                reproducible=t.reproducible,
                reproduction_count=t.reproduction_count,
                artifact_relative_path=t.artifact_relative_path,
                triage_export_relative_path=t.triage_export_relative_path,
                written=t.written,
                promotion_allowed=False,
                confirmed_vulnerability=False,
                root_cause=rc,
                notes=list(t.notes),
            )
        )
    return CrashTriageResult(
        stage=result.stage,
        inspirations=list(result.inspirations),
        execution_mode=(
            result.execution_mode if result.triage_executed else "plan_only"
        ),
        status=result.status,
        package_id=result.package_id,
        package_root=result.package_root,
        input_crash_count=int(result.input_crash_count or 0),
        triaged=triaged,
        triaged_count=len(triaged),
        unique_cluster_count=int(
            result.unique_cluster_count
            if result.unique_cluster_count
            else len({t.cluster_id for t in triaged})
        ),
        reproducible_count=sum(1 for t in triaged if t.reproducible is True),
        minimized_count=sum(1 for t in triaged if t.minimized),
        deduped_away_count=int(result.deduped_away_count or 0),
        human_allow_crash_triage=bool(result.human_allow_crash_triage),
        triage_executed=bool(result.triage_executed),
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
        triage_export_written=bool(result.triage_export_written),
        triage_export_count=int(result.triage_export_count or 0),
        triage_export_root_relative=result.triage_export_root_relative
        or "_export/crash_triage",
        run_stamp=result.run_stamp,
        safety_invariants=list(SAFETY_INVARIANTS),
        next_allowed_action=result.next_allowed_action,
        notes=list(result.notes),
        local_fuzz_runner_status=result.local_fuzz_runner_status,
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
    payload["human_allow_crash_triage"] = bool(payload.get("human_allow_crash_triage"))
    payload["triage_executed"] = bool(payload.get("triage_executed"))
    payload["triage_export_written"] = bool(payload.get("triage_export_written"))
    payload["triage_export_count"] = int(payload.get("triage_export_count") or 0)
    payload["triage_export_root_relative"] = str(
        payload.get("triage_export_root_relative") or "_export/crash_triage"
    )
    payload["safety_invariants"] = list(SAFETY_INVARIANTS)
    if not payload.get("triage_executed"):
        payload["execution_mode"] = "plan_only"
    triaged = payload.get("triaged")
    if isinstance(triaged, list):
        fixed = []
        for item in triaged:
            if not isinstance(item, dict):
                continue
            row = dict(item)
            row["promotion_allowed"] = False
            row["confirmed_vulnerability"] = False
            rc = row.get("root_cause")
            if isinstance(rc, dict):
                rc = dict(rc)
                rc["confirmed_vulnerability"] = False
                rc["needs_human_review"] = True
                row["root_cause"] = rc
            fixed.append(row)
        payload["triaged"] = fixed
        payload["triaged_count"] = len(fixed)
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


__all__ = [
    "STATUS_COMPLETED",
    "STATUS_EMPTY",
    "STATUS_EXPORT_WRITTEN",
    "STATUS_READY",
    "STATUS_SKIPPED",
    "STATUS_SKIPPED_NO_CRASHES",
    "STATUS_SKIPPED_NO_RUNNER",
    "CrashTriageError",
    "CrashTriageResult",
    "RootCauseNote",
    "TriagedCrash",
    "attach_crash_triage_to_bridge_result",
    "build_crash_triage_plan",
    "run_crash_triage",
]
