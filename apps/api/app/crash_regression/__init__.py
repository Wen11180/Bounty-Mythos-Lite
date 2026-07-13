"""Crash residual regression planner — plan-only tests from triaged crashes.

Final-scheme 5.11 / 8.2 residual after crash triage + advisory root-cause:
- Map triaged crash clusters to non-executing regression test suggestions
- Optionally enrich suggestions from advisory crash_codepath links (static only)
- Prefer minimized/reproducible seeds as fixture guidance (text only)
- Optional export under package `_export/crash_regression/` with human flag
- Never runs tests, never promotes crashes, never submits reports
- Never sets confirmed_vulnerability / validation_allowed
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STATUS_READY = "crash_regression_plan_ready"
STATUS_EMPTY = "crash_regression_empty"
STATUS_SKIPPED = "crash_regression_package_missing"
STATUS_NO_CLUSTERS = "crash_regression_no_clusters"
STATUS_WRITTEN = "crash_regression_export_written"

SAFETY_INVARIANTS = [
    "local_or_authorized_package_only",
    "no_public_target_scanning",
    "no_test_auto_execution",
    "no_network_access",
    "no_crash_promotion",
    "no_report_submission",
    "advisory_regression_text_only",
    "no_export_write_without_human_flag",
    "human_review_required_before_any_test_run",
    "advisory_codepath_enrichment_only",
]

_MAX_SUGGESTIONS = 24
_MAX_STEPS = 8


class CrashRegressionError(ValueError):
    """Raised when bridge attach receives invalid input."""


@dataclass(frozen=True)
class RegressionStep:
    step_id: str
    title: str
    intent: str
    method: str = "planned_local_unit_or_integration_text_only"
    requires_human_approval: bool = True
    auto_execute: bool = False
    network_access: bool = False
    live_validation: bool = False


@dataclass(frozen=True)
class CrashRegressionSuggestion:
    test_id: str
    cluster_id: str
    crash_id: str
    target_symbol: str
    source_path: str
    exception_type: str
    crash_type: str
    title: str
    intent: str
    style: str = "unit_or_integration_text_only"
    priority: str = "medium"
    reproducible: bool | None = None
    minimized: bool = False
    seed_fixture_guidance: str = ""
    root_cause_summary: str = ""
    codepath_linked: bool = False
    codepath_primary: str = ""
    codepath_confidence: str = ""
    codepath_raise_sites: list[str] = field(default_factory=list)
    codepath_call_sites: list[str] = field(default_factory=list)
    codepath_related_symbols: list[str] = field(default_factory=list)
    steps: list[RegressionStep] = field(default_factory=list)
    required_inputs: list[str] = field(default_factory=list)
    anti_patterns: list[str] = field(default_factory=list)
    promotion_allowed: bool = False
    confirmed_vulnerability: bool = False
    auto_execute: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CrashRegressionResult:
    stage: str
    inspirations: list[str]
    execution_mode: str
    status: str
    package_id: str = ""
    package_root: str = ""
    input_cluster_count: int = 0
    input_crash_count: int = 0
    suggestions: list[CrashRegressionSuggestion] = field(default_factory=list)
    suggestion_count: int = 0
    reproducible_linked_count: int = 0
    minimized_linked_count: int = 0
    codepath_linked_count: int = 0
    human_allow_export_write: bool = False
    export_written: bool = False
    export_count: int = 0
    export_root_relative: str = "_export/crash_regression"
    run_stamp: str = ""
    process_spawn_allowed: bool = False
    network_access: bool = False
    live_validation: bool = False
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    crash_promotion_allowed: bool = False
    test_auto_execute_allowed: bool = False
    safety_invariants: list[str] = field(default_factory=list)
    next_allowed_action: str = (
        "Human designs non-destructive local regression tests from suggestions; "
        "Mythos never auto-runs tests or promotes crashes."
    )
    notes: list[str] = field(default_factory=list)
    crash_triage_status: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _force_safety_dict(asdict(self))


def build_crash_regression_plan(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    crash_triage: dict[str, Any] | None = None,
    crash_codepath: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> CrashRegressionResult:
    """Alias for plan builder (always non-executing)."""
    return run_crash_regression_plan(
        package_root=package_root,
        package_id=package_id,
        crash_triage=crash_triage,
        crash_codepath=crash_codepath,
        human_allow_export_write=human_allow_export_write,
    )


def run_crash_regression_plan(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    crash_triage: dict[str, Any] | None = None,
    crash_codepath: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> CrashRegressionResult:
    """Build plan-only regression suggestions from crash triage clusters."""
    root: Path | None = None
    root_s = ""
    if package_root is not None and str(package_root).strip():
        root = Path(package_root)
        root_s = str(root)
        if not root.is_dir():
            return _empty(
                status=STATUS_SKIPPED,
                package_id=package_id,
                package_root=root_s,
                notes=["package_root_missing_or_not_directory"],
                human_allow_export_write=bool(human_allow_export_write),
            )

    triage = crash_triage if isinstance(crash_triage, dict) else {}
    if not triage and root is not None:
        triage = _try_load_latest_triage_index(root)

    triaged = _extract_triaged(triage)
    triage_status = str(triage.get("status") or "")
    input_crash_count = int(triage.get("input_crash_count") or len(triaged) or 0)
    cluster_ids = {str(t.get("cluster_id") or "") for t in triaged if t.get("cluster_id")}
    input_cluster_count = int(
        triage.get("unique_cluster_count")
        or triage.get("cluster_count")
        or len(cluster_ids)
        or 0
    )

    if not triaged:
        return _empty(
            status=STATUS_NO_CLUSTERS if (triage or root) else STATUS_EMPTY,
            package_id=package_id or str(triage.get("package_id") or ""),
            package_root=root_s or str(triage.get("package_root") or ""),
            notes=[
                "no_triaged_clusters_for_regression",
                f"crash_triage_status={triage_status or 'absent'}",
            ],
            human_allow_export_write=bool(human_allow_export_write),
            crash_triage_status=triage_status,
            input_crash_count=input_crash_count,
            input_cluster_count=input_cluster_count,
        )

    codepath_map = _index_codepath_links(crash_codepath)
    suggestions = _build_suggestions(triaged, codepath_map=codepath_map)
    repro_n = sum(1 for s in suggestions if s.reproducible is True)
    mini_n = sum(1 for s in suggestions if s.minimized)
    cpath_n = sum(1 for s in suggestions if s.codepath_linked)

    export_written = False
    export_count = 0
    run_stamp = ""
    notes = [
        "plan_only_regression_from_crash_triage",
        "never_auto_execute_tests",
        "crash_promotion_blocked",
    ]
    if cpath_n:
        notes.append("enriched_from_advisory_crash_codepath")
    elif isinstance(crash_codepath, dict) and crash_codepath:
        notes.append("crash_codepath_present_but_no_cluster_match")
    status = STATUS_READY

    if human_allow_export_write and root is not None:
        written, count, stamp = _export_suggestions(root, suggestions, package_id=package_id)
        export_written = written
        export_count = count
        run_stamp = stamp
        if written:
            status = STATUS_WRITTEN
            notes.append("export_written_under_package_tmp")
        else:
            notes.append("export_skipped_or_failed_still_plan_only")
    elif human_allow_export_write and root is None:
        notes.append("export_requested_but_no_package_root")

    return _force_safety(
        CrashRegressionResult(
            stage="v1_crash_residual_regression_plan",
            inspirations=["OSS-Fuzz", "ClusterFuzz", "final-scheme-5.11", "final-scheme-8.2"],
            execution_mode="plan_only",
            status=status,
            package_id=package_id or str(triage.get("package_id") or ""),
            package_root=root_s or str(triage.get("package_root") or ""),
            input_cluster_count=input_cluster_count or len({s.cluster_id for s in suggestions}),
            input_crash_count=input_crash_count or len(triaged),
            suggestions=suggestions,
            suggestion_count=len(suggestions),
            reproducible_linked_count=repro_n,
            minimized_linked_count=mini_n,
            codepath_linked_count=cpath_n,
            human_allow_export_write=bool(human_allow_export_write),
            export_written=export_written,
            export_count=export_count,
            run_stamp=run_stamp,
            safety_invariants=list(SAFETY_INVARIANTS),
            notes=notes,
            crash_triage_status=triage_status,
            next_allowed_action=(
                "Human turns suggestions into local non-destructive regression tests; "
                "do not auto-run, promote, or submit from Mythos."
            ),
        )
    )


def attach_crash_regression_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    crash_triage: dict[str, Any] | None = None,
    crash_regression: dict[str, Any] | CrashRegressionResult | None = None,
    crash_codepath: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    """Attach crash residual regression plan; never unlocks execute/promote/submit."""
    if not isinstance(bridge_result, dict):
        raise CrashRegressionError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")
    triage = crash_triage
    if triage is None and isinstance(bridge_result.get("crash_triage"), dict):
        triage = bridge_result.get("crash_triage")
    codepath = crash_codepath
    if codepath is None and isinstance(bridge_result.get("crash_codepath"), dict):
        codepath = bridge_result.get("crash_codepath")

    if isinstance(crash_regression, CrashRegressionResult):
        payload = crash_regression.to_dict()
    elif isinstance(crash_regression, dict):
        payload = _force_safety_dict(dict(crash_regression))
    else:
        payload = run_crash_regression_plan(
            package_root=resolved_root,
            package_id=package_id,
            crash_triage=triage if isinstance(triage, dict) else None,
            crash_codepath=codepath if isinstance(codepath, dict) else None,
            human_allow_export_write=bool(human_allow_export_write),
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["crash_regression"] = payload
    out["crash_regression_present"] = True
    out["crash_regression_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["crash_regression_suggestion_count"] = int(payload.get("suggestion_count") or 0)
    out["crash_regression_reproducible_linked_count"] = int(
        payload.get("reproducible_linked_count") or 0
    )
    out["crash_regression_minimized_linked_count"] = int(
        payload.get("minimized_linked_count") or 0
    )
    out["crash_regression_codepath_linked_count"] = int(
        payload.get("codepath_linked_count") or 0
    )
    out["crash_regression_export_written"] = bool(payload.get("export_written"))
    out["crash_regression_export_count"] = int(payload.get("export_count") or 0)
    out["crash_regression_test_auto_execute_allowed"] = False
    out["crash_regression_crash_promotion_allowed"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out


def _extract_triaged(triage: dict[str, Any]) -> list[dict[str, Any]]:
    raw = triage.get("triaged") if isinstance(triage, dict) else None
    if not isinstance(raw, list):
        # accept clusters list if present
        raw = triage.get("clusters") if isinstance(triage, dict) else None
    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw[:_MAX_SUGGESTIONS]:
        if not isinstance(item, dict):
            continue
        cluster = str(item.get("cluster_id") or item.get("crash_id") or "")
        # prefer one suggestion per cluster
        key = cluster or json.dumps(item, sort_keys=True)[:80]
        if key in seen:
            continue
        seen.add(key)
        out.append(dict(item))
    return out


def _index_codepath_links(crash_codepath: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Map cluster_id/crash_id -> advisory link dict (static only)."""
    if not isinstance(crash_codepath, dict):
        return {}
    raw = crash_codepath.get("links")
    if not isinstance(raw, list):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for item in raw:
        if not isinstance(item, dict):
            continue
        if item.get("confirmed_vulnerability") is True or item.get("promotion_allowed") is True:
            continue
        payload = dict(item)
        for key in ("cluster_id", "crash_id"):
            kid = str(payload.get(key) or "").strip()
            if kid and kid not in out:
                out[kid] = payload
    return out


def _build_suggestions(
    triaged: list[dict[str, Any]],
    *,
    codepath_map: dict[str, dict[str, Any]] | None = None,
) -> list[CrashRegressionSuggestion]:
    """One suggestion per unique cluster_id (first representative crash)."""
    by_cluster: dict[str, dict[str, Any]] = {}
    for item in triaged:
        if not isinstance(item, dict):
            continue
        cid = str(item.get("cluster_id") or item.get("crash_id") or "")
        if not cid:
            continue
        if cid not in by_cluster:
            by_cluster[cid] = item
    ordered = list(by_cluster.values())[:_MAX_SUGGESTIONS]
    codepath_map = codepath_map or {}

    suggestions: list[CrashRegressionSuggestion] = []
    for index, item in enumerate(ordered, start=1):
        cluster_id = str(item.get("cluster_id") or f"cluster-{index}")
        crash_id = str(item.get("crash_id") or f"crash-{index}")
        target = str(item.get("target_symbol") or "unknown_target")
        source = str(item.get("source_path") or "")
        et = str(item.get("exception_type") or "Exception")
        ctype = str(
            item.get("crash_type")
            or _guess_crash_type(et, str(item.get("exception_message") or ""))
        )
        repro = item.get("reproducible")
        if repro is not None:
            repro = bool(repro)
        minimized = bool(item.get("minimized"))
        root_cause = item.get("root_cause") if isinstance(item.get("root_cause"), dict) else {}
        rc_summary = str(
            root_cause.get("summary")
            or item.get("root_cause_summary")
            or f"Advisory: {et} around {target}"
        )[:400]

        link = codepath_map.get(cluster_id) or codepath_map.get(crash_id) or {}
        cpath_primary = str(link.get("primary_code_path") or "")
        cpath_conf = str(link.get("confidence") or "")
        raise_sites = [str(x) for x in (link.get("raise_sites") or []) if str(x).strip()][:8]
        call_sites = [str(x) for x in (link.get("call_sites") or []) if str(x).strip()][:8]
        related = [str(x) for x in (link.get("related_symbols") or []) if str(x).strip()][:8]
        cpath_linked = bool(link) and bool(cpath_primary or raise_sites or call_sites or related)
        if cpath_linked and link.get("root_cause_summary"):
            rc_summary = str(link.get("root_cause_summary"))[:400]
        if cpath_primary and not source:
            source = cpath_primary.split(":")[0]

        seed_guide = _seed_fixture_guidance(item)
        priority = "high" if repro is True else ("medium" if minimized else "low")
        if cpath_linked and cpath_conf in {"high", "medium"}:
            priority = "high" if repro is True or cpath_conf == "high" else priority
        title = f"Regression for {target} ({ctype or et})"
        intent = (
            f"Prevent recurrence of triaged crash cluster {cluster_id} on {target}: "
            f"{et}/{ctype}. Plan-only; human implements non-destructive local test."
        )
        if cpath_linked and cpath_primary:
            intent = (intent + f" Advisory static path: {cpath_primary}.")[:500]
        steps = _steps_for_cluster(
            index=index,
            cluster_id=cluster_id,
            target=target,
            source=source,
            et=et,
            ctype=ctype,
            minimized=minimized,
            reproducible=repro,
            seed_guide=seed_guide,
            rc_summary=rc_summary,
            codepath_primary=cpath_primary,
            codepath_raise_sites=raise_sites,
            codepath_call_sites=call_sites,
        )
        notes = ["text_only_suggestion", "linked_from_crash_triage"]
        if cpath_linked:
            notes.append("enriched_from_advisory_crash_codepath")
            notes.append("static_codepath_only_never_confirmed")
        suggestions.append(
            CrashRegressionSuggestion(
                test_id=f"CRG-{index:03d}-{_slug(cluster_id)[:24]}",
                cluster_id=cluster_id,
                crash_id=crash_id,
                target_symbol=target,
                source_path=source,
                exception_type=et,
                crash_type=ctype,
                title=title[:160],
                intent=intent[:500],
                priority=priority,
                reproducible=repro,
                minimized=minimized,
                seed_fixture_guidance=seed_guide,
                root_cause_summary=rc_summary,
                codepath_linked=cpath_linked,
                codepath_primary=cpath_primary[:260],
                codepath_confidence=cpath_conf[:32],
                codepath_raise_sites=raise_sites,
                codepath_call_sites=call_sites,
                codepath_related_symbols=related,
                steps=steps,
                required_inputs=[
                    "authorized_local_package_only",
                    "human_designed_test_body",
                    "no_live_network",
                    "no_public_target",
                ],
                anti_patterns=[
                    "Do not re-run unbounded fuzz as a regression gate.",
                    "Do not promote the crash to a confirmed vulnerability from the test alone.",
                    "Do not ship only a try/except swallow around the crash site.",
                    "Do not rely on a single raw payload string without root-cause coverage.",
                    "Do not treat static code-path links as confirmed root cause.",
                ],
                notes=notes,
            )
        )
    return suggestions



def _steps_for_cluster(
    *,
    index: int,
    cluster_id: str,
    target: str,
    source: str,
    et: str,
    ctype: str,
    minimized: bool,
    reproducible: bool | None,
    seed_guide: str,
    rc_summary: str,
    codepath_primary: str = "",
    codepath_raise_sites: list[str] | None = None,
    codepath_call_sites: list[str] | None = None,
) -> list[RegressionStep]:
    base = f"CRG-{index:03d}"
    steps: list[RegressionStep] = [
        RegressionStep(
            step_id=f"{base}-01",
            title="Pin local fixture from minimized/reproducible seed guidance",
            intent=(
                f"Human stores a local fixture for cluster {cluster_id}. "
                f"Guidance: {seed_guide or 'use minimized seed bytes if available'}"
            )[:400],
            method="planned_fixture_capture_text_only",
        ),
        RegressionStep(
            step_id=f"{base}-02",
            title=f"Unit call into {target} with fixture",
            intent=(
                f"Local unit/integration test invokes `{target}` "
                f"({source or 'source unknown'}) with the fixture and asserts "
                f"the failure mode ({et}/{ctype}) no longer occurs after the intended fix."
            )[:400],
            method="planned_local_unit_test_text_only",
        ),
        RegressionStep(
            step_id=f"{base}-03",
            title="Assert root-cause control, not symptom filter",
            intent=(
                f"Regression must encode root-cause intent: {rc_summary}. "
                "Prefer invariant at shared parser/validator layer over payload blocklist."
            )[:400],
            method="planned_invariant_assertion_text_only",
        ),
    ]
    if codepath_primary or codepath_raise_sites or codepath_call_sites:
        raise_txt = ", ".join((codepath_raise_sites or [])[:4]) or "n/a"
        call_txt = ", ".join((codepath_call_sites or [])[:4]) or "n/a"
        steps.append(
            RegressionStep(
                step_id=f"{base}-03b",
                title="Anchor assertions near advisory static code path",
                intent=(
                    f"Human reviews advisory path `{codepath_primary or source}` "
                    f"(raise_sites={raise_txt}; call_sites={call_txt}) and places "
                    "assertions near the shared validation/parser layer. Static only; "
                    "not a confirmed vulnerability."
                )[:400],
                method="planned_codepath_anchor_text_only",
            )
        )
    if reproducible is True:
        steps.append(
            RegressionStep(
                step_id=f"{base}-04",
                title="Repro gate: known-bad fixture must fail before fix, pass after",
                intent=(
                    "When human applies a fix offline, the same minimized fixture should "
                    "be red-before / green-after. Mythos does not execute this gate."
                ),
                method="planned_before_after_repro_gate_text_only",
            )
        )
    if minimized:
        steps.append(
            RegressionStep(
                step_id=f"{base}-05",
                title="Keep minimized seed as corpus regression fixture",
                intent=(
                    "Retain minimized input as a durable corpus case for future parser changes; "
                    "do not expand into full fuzz campaigns from CI without human approval."
                ),
                method="planned_corpus_fixture_text_only",
            )
        )
    steps.append(
        RegressionStep(
            step_id=f"{base}-99",
            title="Safety stop: no auto-run / no promote / no submit",
            intent=(
                "Do not auto-execute tests from Mythos, spawn external fuzzers, "
                "promote crashes, or submit reports."
            ),
            method="safety_stop",
        )
    )
    return steps[:_MAX_STEPS]


def _seed_fixture_guidance(item: dict[str, Any]) -> str:
    parts: list[str] = []
    if item.get("minimized") and item.get("minimized_seed_preview"):
        parts.append(f"minimized_preview={str(item.get('minimized_seed_preview'))[:80]!r}")
    if item.get("minimized_seed_sha256"):
        parts.append(f"minimized_sha256={str(item.get('minimized_seed_sha256'))[:16]}…")
    if item.get("minimized_seed_len") is not None:
        parts.append(f"minimized_len={item.get('minimized_seed_len')}")
    if item.get("seed_preview") and not item.get("minimized"):
        parts.append(f"seed_preview={str(item.get('seed_preview'))[:80]!r}")
    if item.get("seed_sha256"):
        parts.append(f"seed_sha256={str(item.get('seed_sha256'))[:16]}…")
    if item.get("triage_export_relative_path"):
        parts.append(f"triage_export={item.get('triage_export_relative_path')}")
    if item.get("artifact_relative_path"):
        parts.append(f"artifact={item.get('artifact_relative_path')}")
    if not parts:
        return "No seed artifact; human crafts a minimal local fixture for the target symbol."
    return "; ".join(parts)[:500]


def _guess_crash_type(exception_type: str, message: str) -> str:
    blob = f"{exception_type} {message}".lower()
    if "memory" in blob or "overflow" in blob or "segfault" in blob:
        return "memory_safety_suspected"
    if "timeout" in blob:
        return "timeout"
    if "valueerror" in blob or "typeerror" in blob or "keyerror" in blob:
        return "input_validation_exception"
    if "assert" in blob:
        return "assertion_failure"
    return "exception_crash"


def _slug(value: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9_-]+", "-", value.strip())
    return s.strip("-") or "cluster"


def _try_load_latest_triage_index(root: Path) -> dict[str, Any]:
    base = root / "_export" / "crash_triage"
    if not base.is_dir():
        return {}
    stamps = sorted([p for p in base.iterdir() if p.is_dir()], reverse=True)
    for stamp_dir in stamps[:5]:
        idx = stamp_dir / "index.json"
        if not idx.is_file():
            continue
        try:
            data = json.loads(idx.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict):
            # normalize: index may list clusters without full triaged objects
            if "triaged" not in data and isinstance(data.get("clusters"), list):
                triaged = []
                for c in data["clusters"]:
                    if isinstance(c, dict):
                        triaged.append(c)
                    elif isinstance(c, str):
                        tpath = stamp_dir / c / "triage.json"
                        if tpath.is_file():
                            try:
                                td = json.loads(tpath.read_text(encoding="utf-8"))
                                if isinstance(td, dict):
                                    triaged.append(td)
                            except Exception:
                                pass
                data = {**data, "triaged": triaged}
            return data
        # some indexes are lists
        if isinstance(data, list):
            return {"status": "crash_triage_export_written", "triaged": [x for x in data if isinstance(x, dict)]}
    return {}


def _export_suggestions(
    root: Path,
    suggestions: list[CrashRegressionSuggestion],
    *,
    package_id: str,
) -> tuple[bool, int, str]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    export_root = (root / "_export" / "crash_regression" / stamp).resolve()
    try:
        export_root.relative_to(root.resolve())
    except ValueError:
        return False, 0, ""
    export_root.mkdir(parents=True, exist_ok=True)

    index = {
        "package_id": package_id,
        "status": STATUS_WRITTEN,
        "suggestion_count": len(suggestions),
        "export_stamp": stamp,
        "execution_allowed": False,
        "validation_allowed": False,
        "test_auto_execute_allowed": False,
        "crash_promotion_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
        "suggestions": [asdict(s) for s in suggestions],
    }
    (export_root / "index.json").write_text(
        json.dumps(index, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (export_root / "README.md").write_text(
        "\n".join(
            [
                "# Crash residual regression plans (advisory)",
                "",
                "Plan-only suggestions derived from crash triage clusters.",
                "",
                "- test_auto_execute_allowed: false",
                "- crash_promotion_allowed: false",
                "- report_submission_allowed: false",
                "- confirmed_vulnerability: false",
                "",
                "Human implements non-destructive local tests outside Mythos auto-run.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    count = 0
    for s in suggestions:
        d = export_root / _slug(s.test_id)
        d.mkdir(parents=True, exist_ok=True)
        (d / "regression.json").write_text(
            json.dumps(asdict(s), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        step_lines = []
        for st in s.steps:
            step_lines.append(f"### {st.step_id}: {st.title}")
            step_lines.append("")
            step_lines.append(st.intent)
            step_lines.append("")
            step_lines.append(f"- method: `{st.method}`")
            step_lines.append(f"- auto_execute: `{st.auto_execute}`")
            step_lines.append("")
        (d / "README.md").write_text(
            "\n".join(
                [
                    f"# {s.test_id}",
                    "",
                    f"- cluster: `{s.cluster_id}`",
                    f"- target: `{s.target_symbol}`",
                    f"- source: `{s.source_path}`",
                    f"- exception: `{s.exception_type}`",
                    f"- crash_type: `{s.crash_type}`",
                    f"- priority: `{s.priority}`",
                    f"- reproducible: `{s.reproducible}`",
                    f"- minimized: `{s.minimized}`",
                    "- promotion_allowed: false",
                    "- auto_execute: false",
                    "",
                    "## Intent",
                    "",
                    s.intent,
                    "",
                    "## Root cause (advisory)",
                    "",
                    s.root_cause_summary or "n/a",
                    "",
                    "## Seed fixture guidance",
                    "",
                    s.seed_fixture_guidance or "n/a",
                    "",
                    "## Steps (plan-only)",
                    "",
                    *step_lines,
                    "## Anti-patterns",
                    "",
                    *[f"- {a}" for a in s.anti_patterns],
                    "",
                    "Human triage only. Mythos never auto-runs these tests.",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        count += 1
    return True, count, stamp


def _empty(
    *,
    status: str,
    package_id: str = "",
    package_root: str = "",
    notes: list[str] | None = None,
    human_allow_export_write: bool = False,
    crash_triage_status: str = "",
    input_crash_count: int = 0,
    input_cluster_count: int = 0,
) -> CrashRegressionResult:
    return _force_safety(
        CrashRegressionResult(
            stage="v1_crash_residual_regression_plan",
            inspirations=["OSS-Fuzz", "ClusterFuzz", "final-scheme-5.11", "final-scheme-8.2"],
            execution_mode="plan_only",
            status=status,
            package_id=package_id,
            package_root=package_root,
            input_cluster_count=input_cluster_count,
            input_crash_count=input_crash_count,
            human_allow_export_write=bool(human_allow_export_write),
            safety_invariants=list(SAFETY_INVARIANTS),
            notes=list(notes or []),
            crash_triage_status=crash_triage_status,
            next_allowed_action=(
                "Provide crash_triage clusters from an authorized package to plan regression tests."
            ),
        )
    )


def _force_safety(result: CrashRegressionResult) -> CrashRegressionResult:
    return CrashRegressionResult(
        stage=result.stage,
        inspirations=list(result.inspirations),
        execution_mode="plan_only",
        status=result.status,
        package_id=result.package_id,
        package_root=result.package_root,
        input_cluster_count=result.input_cluster_count,
        input_crash_count=result.input_crash_count,
        suggestions=list(result.suggestions),
        suggestion_count=len(result.suggestions),
        reproducible_linked_count=result.reproducible_linked_count,
        minimized_linked_count=result.minimized_linked_count,
        codepath_linked_count=result.codepath_linked_count,
        human_allow_export_write=bool(result.human_allow_export_write),
        export_written=bool(result.export_written),
        export_count=int(result.export_count or 0),
        export_root_relative="_export/crash_regression",
        run_stamp=result.run_stamp,
        process_spawn_allowed=False,
        network_access=False,
        live_validation=False,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        crash_promotion_allowed=False,
        test_auto_execute_allowed=False,
        safety_invariants=list(SAFETY_INVARIANTS),
        next_allowed_action=result.next_allowed_action,
        notes=list(result.notes),
        crash_triage_status=result.crash_triage_status,
    )


def _force_safety_dict(payload: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    out["execution_mode"] = "plan_only"
    out["process_spawn_allowed"] = False
    out["network_access"] = False
    out["live_validation"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    out["finding_promotion_allowed"] = False
    out["crash_promotion_allowed"] = False
    out["test_auto_execute_allowed"] = False
    out["safety_invariants"] = list(SAFETY_INVARIANTS)
    # scrub suggestion flags
    suggestions = out.get("suggestions")
    if isinstance(suggestions, list):
        cleaned = []
        for s in suggestions:
            if not isinstance(s, dict):
                continue
            item = dict(s)
            item["promotion_allowed"] = False
            item["confirmed_vulnerability"] = False
            item["auto_execute"] = False
            steps = item.get("steps")
            if isinstance(steps, list):
                new_steps = []
                for st in steps:
                    if not isinstance(st, dict):
                        continue
                    step = dict(st)
                    step["auto_execute"] = False
                    step["network_access"] = False
                    step["live_validation"] = False
                    step["requires_human_approval"] = True
                    new_steps.append(step)
                item["steps"] = new_steps
            cleaned.append(item)
        out["suggestions"] = cleaned
        out["suggestion_count"] = len(cleaned)
    return out


__all__ = [
    "STATUS_EMPTY",
    "STATUS_NO_CLUSTERS",
    "STATUS_READY",
    "STATUS_SKIPPED",
    "STATUS_WRITTEN",
    "SAFETY_INVARIANTS",
    "CrashRegressionError",
    "CrashRegressionResult",
    "CrashRegressionSuggestion",
    "RegressionStep",
    "attach_crash_regression_to_bridge_result",
    "build_crash_regression_plan",
    "run_crash_regression_plan",
]
