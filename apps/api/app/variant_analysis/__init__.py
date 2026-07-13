"""Variant Analysis ? plan/export only under human gate.

Final-scheme V4 residual beyond nested deep_research._variant_candidates:
- Plan local-only sibling-variant search from hypotheses, retained drafts,
  patch-diff patterns, residual families, and optional offline inputs
- Optional offline package inputs/variant*.json hints
- Optional write under package _export/variant_analysis/ with human flag
- Never scans public targets, never exploits, never promotes, never submits
- Never unlocks execution_allowed / validation_allowed / report_submission_allowed
- Never sets confirmed_vulnerability / finding_promotion_allowed
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


STATUS_READY = "variant_analysis_plan_ready"
STATUS_EMPTY = "variant_analysis_empty"
STATUS_SKIPPED = "variant_analysis_package_missing"
STATUS_WAITING = "variant_analysis_waiting_for_seeds"
STATUS_WRITTEN = "variant_analysis_export_written"

SAFETY_INVARIANTS = [
    "local_or_authorized_package_only",
    "no_public_target_scanning",
    "no_exploit_execution",
    "no_network_access",
    "no_live_validation",
    "no_report_submission",
    "no_export_write_without_human_flag",
    "variant_plan_export_local_package_only",
    "human_approval_required_before_any_action",
    "execution_always_blocked_in_planner",
    "unverified_variants_never_confirmed",
    "patterns_only_no_raw_secret_or_user_data",
]

_MAX_VARIANTS = 24
_MAX_SEEDS = 32
_MAX_HINTS = 16
_MAX_QUESTIONS = 10
_MAX_SEARCH_SCOPES = 12

_VARIANT_HINT_RE = re.compile(r"^variant.*\.json$", re.IGNORECASE)


class VariantAnalysisError(ValueError):
    """Raised when bridge attach receives invalid input."""


@dataclass(frozen=True)
class VariantSearchPlan:
    variant_id: str
    source_hypothesis_id: str
    family: str = ""
    vuln_type: str = ""
    seed_location: str = ""
    search_pattern: str = ""
    search_scopes: list[str] = field(default_factory=list)
    similar_sink_notes: list[str] = field(default_factory=list)
    guard_comparison_notes: list[str] = field(default_factory=list)
    refutation_questions: list[str] = field(default_factory=list)
    safe_next_step: str = (
        "search authorized local code for comparable guards and sinks"
    )
    status: str = "planned_local_code_search_only"
    origin: str = "hypothesis"
    export_relative_path: str = ""
    written: bool = False
    execution_allowed: bool = False
    human_review_required: bool = True

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["execution_allowed"] = False
        payload["human_review_required"] = True
        return payload


@dataclass(frozen=True)
class VariantAnalysisPlan:
    stage: str
    inspirations: list[str]
    execution_mode: str
    status: str
    package_id: str = ""
    package_root: str = ""
    variants: list[VariantSearchPlan] = field(default_factory=list)
    variant_count: int = 0
    seed_count: int = 0
    offline_hint_count: int = 0
    bridge_seed_count: int = 0
    family_counts: dict[str, int] = field(default_factory=dict)
    required_inputs: list[str] = field(default_factory=list)
    network_access: bool = False
    live_validation: bool = False
    process_spawn_allowed: bool = False
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    human_approval_required_before_action: bool = True
    human_allow_export_write: bool = False
    export_written: bool = False
    export_count: int = 0
    export_root_relative: str = "_export/variant_analysis"
    safety_invariants: list[str] = field(default_factory=list)
    next_allowed_action: str = (
        "Review variant search plans offline; search only authorized local code; "
        "never exploit, promote, or submit from variant plans."
    )
    notes: list[str] = field(default_factory=list)
    human_questions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _force_safety_dict(asdict(self))


def build_variant_analysis_plan(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    source_hypotheses: list[dict[str, Any]] | None = None,
    confirmed_findings: list[dict[str, Any]] | None = None,
    retained_candidates: list[dict[str, Any]] | None = None,
    report_drafts: list[dict[str, Any]] | None = None,
    patch_diff_learner: dict[str, Any] | None = None,
    residual_gates: list[dict[str, Any]] | None = None,
    human_allow_export_write: bool = False,
) -> VariantAnalysisPlan:
    notes: list[str] = [
        "plan_only",
        "local_code_search_only",
        "unverified_variants_never_confirmed",
    ]
    root: Path | None = None
    if package_root is not None and str(package_root).strip():
        candidate = Path(package_root).resolve()
        if candidate.is_dir():
            root = candidate
        else:
            notes.append("package_root_not_a_directory")

    has_payload = any(
        [
            source_hypotheses,
            confirmed_findings,
            retained_candidates,
            report_drafts,
            patch_diff_learner,
            residual_gates,
        ]
    )
    if root is None and not has_payload:
        return _empty_plan(
            status=STATUS_SKIPPED if package_root else STATUS_EMPTY,
            package_id=package_id,
            package_root=str(package_root or ""),
            notes=notes + ["no_package_root_and_no_variant_seeds"],
            human_allow_export_write=bool(human_allow_export_write),
            required_inputs=[
                "source_hypotheses_or_retained_candidates",
                "optional_inputs/variant*.json",
                "optional_patch_diff_learner_patterns",
            ],
        )

    pkg_id = package_id or (root.name if root is not None else "")
    offline_hints = _load_offline_variant_hints(root) if root is not None else []
    seeds = _collect_seeds(
        source_hypotheses=source_hypotheses,
        confirmed_findings=confirmed_findings,
        retained_candidates=retained_candidates,
        report_drafts=report_drafts,
        patch_diff_learner=patch_diff_learner,
        residual_gates=residual_gates,
        offline_hints=offline_hints,
    )
    if offline_hints:
        notes.append(f"offline_variant_hints={len(offline_hints)}")
    notes.append(f"seed_count={len(seeds)}")

    if not seeds:
        return _empty_plan(
            status=STATUS_WAITING,
            package_id=pkg_id,
            package_root=str(root) if root is not None else str(package_root or ""),
            notes=notes + ["waiting_for_hypotheses_findings_or_variant_hints"],
            human_allow_export_write=bool(human_allow_export_write),
            offline_hint_count=len(offline_hints),
            bridge_seed_count=0,
            required_inputs=[
                "inputs/variant*.json",
                "bridge retained candidates/drafts",
                "confirmed_findings_or_hypotheses",
                "patch_diff_learner.patterns",
            ],
        )

    variants = _build_variants(seeds)
    family_counts: dict[str, int] = {}
    for item in variants:
        key = item.family or item.vuln_type or "unknown"
        family_counts[key] = int(family_counts.get(key) or 0) + 1
    human_questions = _global_human_questions(variants)
    bridge_seed_count = max(0, len(seeds) - len(offline_hints))

    plan = VariantAnalysisPlan(
        stage="v4_variant_analysis",
        inspirations=[
            "Variant Analysis",
            "Google Project Zero",
            "Mythos / Big Sleep sibling search",
            "deep_research_nested_stub_superseded",
        ],
        execution_mode="plan_only",
        status=STATUS_READY,
        package_id=pkg_id,
        package_root=str(root) if root is not None else str(package_root or ""),
        variants=variants,
        variant_count=len(variants),
        seed_count=len(seeds),
        offline_hint_count=len(offline_hints),
        bridge_seed_count=bridge_seed_count,
        family_counts=family_counts,
        required_inputs=[],
        network_access=False,
        live_validation=False,
        process_spawn_allowed=False,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        human_approval_required_before_action=True,
        human_allow_export_write=bool(human_allow_export_write),
        export_written=False,
        export_count=0,
        export_root_relative="_export/variant_analysis",
        safety_invariants=list(SAFETY_INVARIANTS),
        next_allowed_action=(
            "Review variant search scopes offline; optional human "
            "--allow-variant-analysis-export writes plan files only "
            "(never exploits or promotes)."
        ),
        notes=notes + [
            f"variants={len(variants)}",
            "export_write_not_requested"
            if not human_allow_export_write
            else "export_write_requested",
        ],
        human_questions=human_questions,
    )
    plan = _force_safety_plan(plan)
    return _maybe_write_exports(
        plan,
        root=root,
        human_allow_export_write=bool(human_allow_export_write),
    )


def load_package_variant_analysis_plan(
    package_root: str | Path,
    *,
    package_id: str = "",
    source_hypotheses: list[dict[str, Any]] | None = None,
    confirmed_findings: list[dict[str, Any]] | None = None,
    retained_candidates: list[dict[str, Any]] | None = None,
    report_drafts: list[dict[str, Any]] | None = None,
    patch_diff_learner: dict[str, Any] | None = None,
    residual_gates: list[dict[str, Any]] | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    return build_variant_analysis_plan(
        package_root=package_root,
        package_id=package_id,
        source_hypotheses=source_hypotheses,
        confirmed_findings=confirmed_findings,
        retained_candidates=retained_candidates,
        report_drafts=report_drafts,
        patch_diff_learner=patch_diff_learner,
        residual_gates=residual_gates,
        human_allow_export_write=human_allow_export_write,
    ).to_dict()


def attach_variant_analysis_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    source_hypotheses: list[dict[str, Any]] | None = None,
    confirmed_findings: list[dict[str, Any]] | None = None,
    retained_candidates: list[dict[str, Any]] | None = None,
    report_drafts: list[dict[str, Any]] | None = None,
    patch_diff_learner: dict[str, Any] | None = None,
    residual_gates: list[dict[str, Any]] | None = None,
    variant_analysis: dict[str, Any] | VariantAnalysisPlan | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    """Attach plan-only variant analysis profile; never unlocks exploit/promote/submit."""
    if not isinstance(bridge_result, dict):
        raise VariantAnalysisError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")

    hyps = source_hypotheses
    if hyps is None:
        hyps = _extract_hypotheses_from_bridge(bridge_result)

    findings = confirmed_findings
    if findings is None:
        findings = _list_of_dicts(bridge_result.get("confirmed_findings"))

    retained = retained_candidates
    if retained is None:
        retained = _list_of_dicts(
            bridge_result.get("retained_candidates")
            or bridge_result.get("candidates")
        )

    drafts = report_drafts
    if drafts is None:
        drafts = _list_of_dicts(
            bridge_result.get("report_drafts")
            or bridge_result.get("drafts")
        )

    pdl = patch_diff_learner
    if pdl is None and isinstance(bridge_result.get("patch_diff_learner"), dict):
        pdl = bridge_result.get("patch_diff_learner")

    gates = residual_gates
    if gates is None:
        raw_gates = bridge_result.get("human_residual_gates")
        if isinstance(raw_gates, list):
            gates = [g for g in raw_gates if isinstance(g, dict)]
        elif isinstance(raw_gates, dict):
            gates = [raw_gates]

    if isinstance(variant_analysis, VariantAnalysisPlan):
        payload = variant_analysis.to_dict()
    elif isinstance(variant_analysis, dict):
        payload = _force_safety_dict(dict(variant_analysis))
    else:
        payload = build_variant_analysis_plan(
            package_root=resolved_root,
            package_id=package_id,
            source_hypotheses=hyps,
            confirmed_findings=findings,
            retained_candidates=retained,
            report_drafts=drafts,
            patch_diff_learner=pdl if isinstance(pdl, dict) else None,
            residual_gates=gates,
            human_allow_export_write=bool(human_allow_export_write),
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["variant_analysis"] = payload
    out["variant_analysis_present"] = True
    out["variant_analysis_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["variant_analysis_variant_count"] = int(payload.get("variant_count") or 0)
    out["variant_analysis_seed_count"] = int(payload.get("seed_count") or 0)
    out["variant_analysis_offline_hint_count"] = int(
        payload.get("offline_hint_count") or 0
    )
    out["variant_analysis_export_written"] = bool(payload.get("export_written"))
    out["variant_analysis_export_count"] = int(payload.get("export_count") or 0)
    out["variant_analysis_execution_allowed"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    out["finding_promotion_allowed"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out


def _extract_hypotheses_from_bridge(bridge: dict[str, Any]) -> list[dict[str, Any]]:
    hyps: list[dict[str, Any]] = []
    for key in (
        "source_hypotheses",
        "hypotheses",
        "retained_hypotheses",
        "hunter_hypotheses",
    ):
        hyps.extend(_list_of_dicts(bridge.get(key)))
    # drafts often carry candidate ids / families useful as soft seeds
    for draft in _list_of_dicts(bridge.get("report_drafts") or bridge.get("drafts")):
        hyps.append(
            {
                "hypothesis_id": str(
                    draft.get("candidate_id")
                    or draft.get("hypothesis_id")
                    or draft.get("draft_id")
                    or ""
                ),
                "vuln_type": str(
                    draft.get("vuln_type")
                    or draft.get("family")
                    or draft.get("title")
                    or "unknown"
                ),
                "location": str(
                    draft.get("affected_code_path")
                    or draft.get("location")
                    or draft.get("endpoint")
                    or "unknown"
                ),
                "family": str(draft.get("family") or draft.get("vuln_type") or ""),
                "origin": "report_draft_seed",
            }
        )
    for cand in _list_of_dicts(
        bridge.get("retained_candidates") or bridge.get("candidates")
    ):
        hyps.append(
            {
                "hypothesis_id": str(
                    cand.get("candidate_id")
                    or cand.get("hypothesis_id")
                    or cand.get("id")
                    or ""
                ),
                "vuln_type": str(
                    cand.get("vuln_type")
                    or cand.get("family")
                    or cand.get("title")
                    or "unknown"
                ),
                "location": str(
                    cand.get("location")
                    or cand.get("affected_code_path")
                    or cand.get("endpoint")
                    or "unknown"
                ),
                "family": str(cand.get("family") or cand.get("vuln_type") or ""),
                "origin": "retained_candidate_seed",
                "disposition": str(cand.get("disposition") or cand.get("status") or ""),
            }
        )
    return hyps


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _load_offline_variant_hints(root: Path) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    inputs = root / "inputs"
    if not inputs.is_dir():
        return hints
    for path in sorted(inputs.iterdir()):
        if not path.is_file():
            continue
        if not _VARIANT_HINT_RE.match(path.name):
            continue
        if path.stat().st_size > 256_000:
            continue
        try:
            raw = path.read_text(encoding="utf-8-sig")
            data = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            hints.append({**data, "_hint_file": path.name})
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    hints.append({**item, "_hint_file": path.name})
        if len(hints) >= _MAX_HINTS:
            break
    return hints[:_MAX_HINTS]


def _collect_seeds(
    *,
    source_hypotheses: list[dict[str, Any]] | None,
    confirmed_findings: list[dict[str, Any]] | None,
    retained_candidates: list[dict[str, Any]] | None,
    report_drafts: list[dict[str, Any]] | None,
    patch_diff_learner: dict[str, Any] | None,
    residual_gates: list[dict[str, Any]] | None,
    offline_hints: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    seeds: list[dict[str, Any]] = []
    seen: set[str] = set()

    def _add(seed: dict[str, Any]) -> None:
        if len(seeds) >= _MAX_SEEDS:
            return
        key = _seed_key(seed)
        if key in seen:
            return
        seen.add(key)
        seeds.append(seed)

    for item in source_hypotheses or []:
        if not isinstance(item, dict):
            continue
        _add(
            {
                "hypothesis_id": _safe_text(
                    item.get("hypothesis_id") or item.get("candidate_id") or item.get("id"),
                    "hypothesis",
                ),
                "vuln_type": _safe_text(
                    item.get("vuln_type") or item.get("family") or item.get("title"),
                    "unknown",
                ),
                "location": _safe_text(
                    item.get("location")
                    or item.get("affected_code_path")
                    or item.get("endpoint"),
                    "unknown",
                ),
                "family": _safe_text(item.get("family") or item.get("vuln_type") or "", ""),
                "origin": _safe_text(item.get("origin") or "hypothesis", "hypothesis"),
            }
        )

    for index, finding in enumerate(confirmed_findings or [], start=1):
        if not isinstance(finding, dict):
            continue
        _add(
            {
                "hypothesis_id": _safe_text(
                    finding.get("finding_id") or finding.get("candidate_id"),
                    f"confirmed-finding-{index:03d}",
                ),
                "vuln_type": _safe_text(finding.get("vuln_type") or finding.get("family"), "unknown"),
                "location": _safe_text(finding.get("location") or finding.get("path"), "unknown"),
                "family": _safe_text(finding.get("family") or finding.get("vuln_type") or "", ""),
                "origin": "confirmed_finding_seed",
            }
        )

    for item in retained_candidates or []:
        if not isinstance(item, dict):
            continue
        _add(
            {
                "hypothesis_id": _safe_text(
                    item.get("candidate_id") or item.get("hypothesis_id") or item.get("id"),
                    "retained",
                ),
                "vuln_type": _safe_text(item.get("vuln_type") or item.get("family"), "unknown"),
                "location": _safe_text(
                    item.get("location") or item.get("affected_code_path"),
                    "unknown",
                ),
                "family": _safe_text(item.get("family") or item.get("vuln_type") or "", ""),
                "origin": "retained_candidate_seed",
            }
        )

    for item in report_drafts or []:
        if not isinstance(item, dict):
            continue
        _add(
            {
                "hypothesis_id": _safe_text(
                    item.get("candidate_id") or item.get("draft_id") or item.get("hypothesis_id"),
                    "draft",
                ),
                "vuln_type": _safe_text(item.get("vuln_type") or item.get("family"), "unknown"),
                "location": _safe_text(
                    item.get("affected_code_path") or item.get("location"),
                    "unknown",
                ),
                "family": _safe_text(item.get("family") or item.get("vuln_type") or "", ""),
                "origin": "report_draft_seed",
            }
        )

    if isinstance(patch_diff_learner, dict):
        patterns = patch_diff_learner.get("patterns") or []
        if isinstance(patterns, list):
            for index, pattern in enumerate(patterns, start=1):
                if not isinstance(pattern, dict):
                    continue
                files = pattern.get("changed_files") or []
                location = "unknown"
                if isinstance(files, list) and files:
                    location = str(files[0])
                _add(
                    {
                        "hypothesis_id": _safe_text(
                            pattern.get("linked_hypothesis_id")
                            or pattern.get("source_ref"),
                            f"pdl-{index:03d}",
                        ),
                        "vuln_type": _safe_text(
                            pattern.get("family") or "patch_diff_pattern",
                            "patch_diff_pattern",
                        ),
                        "location": _safe_text(location, "unknown"),
                        "family": _safe_text(pattern.get("family") or "", "patch_diff"),
                        "origin": "patch_diff_learner_seed",
                        "root_cause": _safe_text(
                            pattern.get("root_cause_summary") or "",
                            "",
                        ),
                    }
                )

    for gate in residual_gates or []:
        if not isinstance(gate, dict):
            continue
        family = _safe_text(
            gate.get("family") or gate.get("gate_id") or gate.get("status") or "",
            "residual",
        )
        _add(
            {
                "hypothesis_id": _safe_text(
                    gate.get("gate_id") or gate.get("candidate_id") or family,
                    "residual-gate",
                ),
                "vuln_type": family,
                "location": _safe_text(
                    gate.get("location") or gate.get("code_path") or "residual",
                    "residual",
                ),
                "family": family,
                "origin": "residual_gate_seed",
            }
        )

    for hint in offline_hints:
        _add(
            {
                "hypothesis_id": _safe_text(
                    hint.get("source_hypothesis_id")
                    or hint.get("hypothesis_id")
                    or hint.get("variant_id")
                    or hint.get("_hint_file"),
                    "offline-variant",
                ),
                "vuln_type": _safe_text(
                    hint.get("vuln_type") or hint.get("family") or "unknown",
                    "unknown",
                ),
                "location": _safe_text(
                    hint.get("location") or hint.get("seed_location") or "unknown",
                    "unknown",
                ),
                "family": _safe_text(hint.get("family") or hint.get("vuln_type") or "", ""),
                "origin": "offline_variant_hint",
                "search_pattern": _safe_text(hint.get("search_pattern") or "", ""),
                "search_scopes": hint.get("search_scopes")
                if isinstance(hint.get("search_scopes"), list)
                else [],
            }
        )

    return seeds[:_MAX_SEEDS]


def _seed_key(seed: dict[str, Any]) -> str:
    return "|".join(
        [
            str(seed.get("hypothesis_id") or "").strip().lower(),
            str(seed.get("vuln_type") or "").strip().lower(),
            str(seed.get("location") or "").strip().lower()[:120],
            str(seed.get("origin") or "").strip().lower(),
        ]
    )


def _build_variants(seeds: list[dict[str, Any]]) -> list[VariantSearchPlan]:
    variants: list[VariantSearchPlan] = []
    for index, seed in enumerate(seeds, start=1):
        if len(variants) >= _MAX_VARIANTS:
            break
        hyp_id = _safe_text(seed.get("hypothesis_id"), f"H-{index:03d}")
        vuln_type = _safe_text(seed.get("vuln_type"), "unknown")
        location = _safe_text(seed.get("location"), "unknown")
        family = _safe_text(seed.get("family") or vuln_type, vuln_type)
        origin = _safe_text(seed.get("origin"), "hypothesis")
        status = (
            "unverified_hypothesis_from_confirmed_finding"
            if origin == "confirmed_finding_seed"
            else "planned_local_code_search_only"
        )
        pattern = _safe_text(
            seed.get("search_pattern"),
            f"similar_{_slug(vuln_type)}_boundary_near_{_slug(location)}",
        )
        scopes = _default_scopes(seed, family=family, location=location)
        sink_notes = [
            f"Compare sinks near `{location}` for same trust boundary.",
            f"Look for sibling handlers with family=`{family}` missing the same guard.",
        ]
        if seed.get("root_cause"):
            sink_notes.append(
                f"Patch-diff root-cause hint: {_safe_text(seed.get('root_cause'), '')[:160]}"
            )
        guard_notes = [
            "Enumerate existing ownership/authz/allowlist guards on sibling paths.",
            "Mark paths where guard is present vs absent; do not exploit absences.",
        ]
        questions = [
            f"Is variant of {hyp_id} still in authorized local scope?",
            f"Does a comparable sink exist for family={family} without the same control?",
            "What local evidence would refute this sibling hypothesis?",
        ]
        variants.append(
            VariantSearchPlan(
                variant_id=f"VA-{index:03d}",
                source_hypothesis_id=hyp_id,
                family=family,
                vuln_type=vuln_type,
                seed_location=location,
                search_pattern=pattern,
                search_scopes=scopes,
                similar_sink_notes=sink_notes[:6],
                guard_comparison_notes=guard_notes[:6],
                refutation_questions=questions[:_MAX_QUESTIONS],
                safe_next_step="search authorized local code for comparable guards and sinks",
                status=status,
                origin=origin,
                execution_allowed=False,
                human_review_required=True,
            )
        )
    return variants


def _default_scopes(
    seed: dict[str, Any], *, family: str, location: str
) -> list[str]:
    scopes: list[str] = []
    raw = seed.get("search_scopes")
    if isinstance(raw, list):
        scopes.extend(_safe_text(s, "") for s in raw if str(s).strip())
    if location and location not in {"unknown", "residual"}:
        scopes.append(f"same_module_as:{location}")
        scopes.append(f"sibling_routes_near:{location}")
    if family:
        scopes.append(f"family_handlers:{family}")
    scopes.extend(
        [
            "shared_middleware_and_guards",
            "role_diff_and_ownership_checks",
            "input_boundary_and_sink_pairs",
        ]
    )
    # de-dupe
    seen: set[str] = set()
    out: list[str] = []
    for item in scopes:
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
        if len(out) >= _MAX_SEARCH_SCOPES:
            break
    return out


def _global_human_questions(variants: list[VariantSearchPlan]) -> list[str]:
    questions = [
        "Are all variant search scopes limited to authorized local package code?",
        "Do not treat planned variants as confirmed vulnerabilities.",
        "Prefer refutation questions before any validation planning.",
    ]
    for variant in variants[:4]:
        questions.extend(variant.refutation_questions[:2])
    seen: set[str] = set()
    out: list[str] = []
    for q in questions:
        if q in seen:
            continue
        seen.add(q)
        out.append(q)
        if len(out) >= _MAX_QUESTIONS:
            break
    return out



def _maybe_write_exports(
    plan: VariantAnalysisPlan,
    *,
    root: Path | None,
    human_allow_export_write: bool,
) -> VariantAnalysisPlan:
    if not human_allow_export_write:
        return plan
    if root is None or not root.is_dir():
        return _rebuild_plan(
            plan,
            notes=list(plan.notes) + ["export_skipped_no_package_root"],
        )
    if not plan.variants:
        return _rebuild_plan(
            plan,
            notes=list(plan.notes) + ["export_skipped_no_variants"],
        )

    export_root = root / "_export" / "variant_analysis"
    export_root.mkdir(parents=True, exist_ok=True)
    written_variants: list[VariantSearchPlan] = []
    export_count = 0

    for variant in plan.variants:
        slug = _slug(variant.variant_id or variant.source_hypothesis_id or "variant")
        target_dir = export_root / slug
        target_dir.mkdir(parents=True, exist_ok=True)
        rel = f"_export/variant_analysis/{slug}"
        meta = {
            "variant_id": variant.variant_id,
            "source_hypothesis_id": variant.source_hypothesis_id,
            "package_id": plan.package_id,
            "family": variant.family,
            "vuln_type": variant.vuln_type,
            "seed_location": variant.seed_location,
            "search_pattern": variant.search_pattern,
            "search_scopes": list(variant.search_scopes),
            "origin": variant.origin,
            "execution_allowed": False,
            "validation_allowed": False,
            "report_submission_allowed": False,
            "confirmed_vulnerability": False,
            "finding_promotion_allowed": False,
            "network_access": False,
            "live_validation": False,
            "process_spawn_allowed": False,
            "human_review_required": True,
        }
        (target_dir / "meta.json").write_text(
            json.dumps(meta, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        (target_dir / "variant_plan.md").write_text(
            _render_variant_md(variant, package_id=plan.package_id),
            encoding="utf-8",
        )
        (target_dir / "README.md").write_text(
            _render_readme(variant, package_id=plan.package_id, export_dir=rel),
            encoding="utf-8",
        )
        export_count += 3
        written_variants.append(
            VariantSearchPlan(
                variant_id=variant.variant_id,
                source_hypothesis_id=variant.source_hypothesis_id,
                family=variant.family,
                vuln_type=variant.vuln_type,
                seed_location=variant.seed_location,
                search_pattern=variant.search_pattern,
                search_scopes=list(variant.search_scopes),
                similar_sink_notes=list(variant.similar_sink_notes),
                guard_comparison_notes=list(variant.guard_comparison_notes),
                refutation_questions=list(variant.refutation_questions),
                safe_next_step=variant.safe_next_step,
                status="exported",
                origin=variant.origin,
                export_relative_path=rel,
                written=True,
                execution_allowed=False,
                human_review_required=True,
            )
        )

    index = {
        "package_id": plan.package_id,
        "status": STATUS_WRITTEN,
        "variant_count": len(written_variants),
        "export_count": export_count,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
        "finding_promotion_allowed": False,
        "network_access": False,
        "live_validation": False,
        "process_spawn_allowed": False,
        "variants": [
            {
                "variant_id": v.variant_id,
                "source_hypothesis_id": v.source_hypothesis_id,
                "export_relative_path": v.export_relative_path,
                "family": v.family,
            }
            for v in written_variants
        ],
        "safety_invariants": list(SAFETY_INVARIANTS),
    }
    (export_root / "index.json").write_text(
        json.dumps(index, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    export_count += 1

    return _rebuild_plan(
        plan,
        variants=written_variants,
        status=STATUS_WRITTEN,
        export_written=True,
        export_count=export_count,
        human_allow_export_write=True,
        notes=list(plan.notes)
        + [f"export_written={export_count}", f"export_root={export_root}"],
        next_allowed_action=(
            "Human reviews exported variant search plans offline; "
            "search only authorized local code; never exploit or promote."
        ),
    )


def _render_variant_md(variant: VariantSearchPlan, *, package_id: str) -> str:
    scopes = "\n".join(f"- `{s}`" for s in variant.search_scopes) or "- (none)"
    sinks = "\n".join(f"- {n}" for n in variant.similar_sink_notes) or "- (none)"
    guards = "\n".join(f"- {n}" for n in variant.guard_comparison_notes) or "- (none)"
    questions = "\n".join(f"- {q}" for q in variant.refutation_questions) or "- (none)"
    return (
        f"# Variant Search Plan: {variant.variant_id}\n\n"
        f"- package_id: `{package_id}`\n"
        f"- source_hypothesis_id: `{variant.source_hypothesis_id}`\n"
        f"- family: `{variant.family}`\n"
        f"- vuln_type: `{variant.vuln_type}`\n"
        f"- seed_location: `{variant.seed_location}`\n"
        f"- origin: `{variant.origin}`\n"
        f"- status: `{variant.status}`\n"
        f"- execution_allowed: `false`\n"
        f"- human_review_required: `true`\n\n"
        f"## Search pattern\n\n"
        f"{variant.search_pattern or '(none)'}\n\n"
        f"## Search scopes (authorized local only)\n\n"
        f"{scopes}\n\n"
        f"## Similar sink notes\n\n"
        f"{sinks}\n\n"
        f"## Guard comparison notes\n\n"
        f"{guards}\n\n"
        f"## Refutation questions\n\n"
        f"{questions}\n\n"
        f"## Safe next step\n\n"
        f"{variant.safe_next_step}\n\n"
        f"## Safety\n\n"
        f"- Plan/export only. Never exploit, promote, submit, or live-validate.\n"
        f"- Unverified variants are never confirmed vulnerabilities.\n"
    )


def _render_readme(
    variant: VariantSearchPlan, *, package_id: str, export_dir: str
) -> str:
    return (
        f"# Variant Analysis Export\n\n"
        f"- package_id: `{package_id}`\n"
        f"- variant_id: `{variant.variant_id}`\n"
        f"- export_dir: `{export_dir}`\n"
        f"- source_hypothesis_id: `{variant.source_hypothesis_id}`\n\n"
        f"Human reviews these offline plans only. Mythos never executes "
        f"variant searches against public targets, never promotes findings, "
        f"and never submits reports from this export.\n"
    )


def _empty_plan(
    *,
    status: str,
    package_id: str = "",
    package_root: str = "",
    notes: list[str] | None = None,
    human_allow_export_write: bool = False,
    offline_hint_count: int = 0,
    bridge_seed_count: int = 0,
    required_inputs: list[str] | None = None,
) -> VariantAnalysisPlan:
    return _force_safety_plan(
        VariantAnalysisPlan(
            stage="v4_variant_analysis",
            inspirations=[
                "Variant Analysis",
                "Google Project Zero",
                "Mythos / Big Sleep sibling search",
                "deep_research_nested_stub_superseded",
            ],
            execution_mode="plan_only",
            status=status,
            package_id=package_id,
            package_root=package_root,
            variants=[],
            variant_count=0,
            seed_count=0,
            offline_hint_count=int(offline_hint_count or 0),
            bridge_seed_count=int(bridge_seed_count or 0),
            family_counts={},
            required_inputs=list(required_inputs or []),
            network_access=False,
            live_validation=False,
            process_spawn_allowed=False,
            execution_allowed=False,
            validation_allowed=False,
            report_submission_allowed=False,
            confirmed_vulnerability=False,
            finding_promotion_allowed=False,
            human_approval_required_before_action=True,
            human_allow_export_write=bool(human_allow_export_write),
            export_written=False,
            export_count=0,
            export_root_relative="_export/variant_analysis",
            safety_invariants=list(SAFETY_INVARIANTS),
            next_allowed_action=(
                "Provide authorized hypotheses, retained candidates, findings, "
                "patch-diff patterns, or inputs/variant*.json; plan remains local-only."
            ),
            notes=list(notes or []),
            human_questions=[
                "Are variant seeds limited to authorized package artifacts?",
                "Do not treat empty/waiting plans as confirmed vulnerabilities.",
            ],
        )
    )


def _rebuild_plan(
    plan: VariantAnalysisPlan,
    *,
    variants: list[VariantSearchPlan] | None = None,
    status: str | None = None,
    export_written: bool | None = None,
    export_count: int | None = None,
    human_allow_export_write: bool | None = None,
    notes: list[str] | None = None,
    next_allowed_action: str | None = None,
) -> VariantAnalysisPlan:
    use_variants = list(variants) if variants is not None else list(plan.variants)
    family_counts: dict[str, int] = {}
    for item in use_variants:
        key = item.family or item.vuln_type or "unknown"
        family_counts[key] = int(family_counts.get(key) or 0) + 1
    return _force_safety_plan(
        VariantAnalysisPlan(
            stage=plan.stage,
            inspirations=list(plan.inspirations),
            execution_mode="plan_only",
            status=status if status is not None else plan.status,
            package_id=plan.package_id,
            package_root=plan.package_root,
            variants=use_variants,
            variant_count=len(use_variants),
            seed_count=int(plan.seed_count or 0),
            offline_hint_count=int(plan.offline_hint_count or 0),
            bridge_seed_count=int(plan.bridge_seed_count or 0),
            family_counts=family_counts,
            required_inputs=list(plan.required_inputs),
            network_access=False,
            live_validation=False,
            process_spawn_allowed=False,
            execution_allowed=False,
            validation_allowed=False,
            report_submission_allowed=False,
            confirmed_vulnerability=False,
            finding_promotion_allowed=False,
            human_approval_required_before_action=True,
            human_allow_export_write=(
                bool(human_allow_export_write)
                if human_allow_export_write is not None
                else bool(plan.human_allow_export_write)
            ),
            export_written=(
                bool(export_written)
                if export_written is not None
                else bool(plan.export_written)
            ),
            export_count=(
                int(export_count)
                if export_count is not None
                else int(plan.export_count or 0)
            ),
            export_root_relative=plan.export_root_relative
            or "_export/variant_analysis",
            safety_invariants=list(SAFETY_INVARIANTS),
            next_allowed_action=(
                next_allowed_action
                if next_allowed_action is not None
                else plan.next_allowed_action
            ),
            notes=list(notes) if notes is not None else list(plan.notes),
            human_questions=list(plan.human_questions),
        )
    )


def _slug(value: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(value or "").strip())
    text = text.strip("-._") or "variant"
    return text[:80]


def _safe_text(value: Any, default: str) -> str:
    if value is None:
        return default
    text = str(value).strip()
    if not text:
        return default
    # never keep raw secrets-looking tokens in plan text
    lowered = text.lower()
    if any(
        marker in lowered
        for marker in (
            "authorization:",
            "bearer ",
            "api_key=",
            "apikey=",
            "password=",
            "secret=",
            "cookie:",
        )
    ):
        return default or "redacted"
    return text[:500]


def _force_safety_plan(plan: VariantAnalysisPlan) -> VariantAnalysisPlan:
    safe_variants = [
        VariantSearchPlan(
            variant_id=v.variant_id,
            source_hypothesis_id=v.source_hypothesis_id,
            family=v.family,
            vuln_type=v.vuln_type,
            seed_location=v.seed_location,
            search_pattern=v.search_pattern,
            search_scopes=list(v.search_scopes),
            similar_sink_notes=list(v.similar_sink_notes),
            guard_comparison_notes=list(v.guard_comparison_notes),
            refutation_questions=list(v.refutation_questions),
            safe_next_step=v.safe_next_step
            or "search authorized local code for comparable guards and sinks",
            status=v.status,
            origin=v.origin,
            export_relative_path=v.export_relative_path,
            written=bool(v.written),
            execution_allowed=False,
            human_review_required=True,
        )
        for v in plan.variants
    ]
    return VariantAnalysisPlan(
        stage=plan.stage or "v4_variant_analysis",
        inspirations=list(plan.inspirations),
        execution_mode="plan_only",
        status=plan.status,
        package_id=plan.package_id,
        package_root=plan.package_root,
        variants=safe_variants,
        variant_count=len(safe_variants),
        seed_count=int(plan.seed_count or 0),
        offline_hint_count=int(plan.offline_hint_count or 0),
        bridge_seed_count=int(plan.bridge_seed_count or 0),
        family_counts=dict(plan.family_counts or {}),
        required_inputs=list(plan.required_inputs),
        network_access=False,
        live_validation=False,
        process_spawn_allowed=False,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        human_approval_required_before_action=True,
        human_allow_export_write=bool(plan.human_allow_export_write),
        export_written=bool(plan.export_written),
        export_count=int(plan.export_count or 0),
        export_root_relative=plan.export_root_relative
        or "_export/variant_analysis",
        safety_invariants=list(SAFETY_INVARIANTS),
        next_allowed_action=plan.next_allowed_action,
        notes=list(plan.notes),
        human_questions=list(plan.human_questions),
    )


def _force_safety_dict(payload: dict[str, Any]) -> dict[str, Any]:
    payload = dict(payload)
    payload["execution_mode"] = "plan_only"
    payload["network_access"] = False
    payload["live_validation"] = False
    payload["process_spawn_allowed"] = False
    payload["execution_allowed"] = False
    payload["validation_allowed"] = False
    payload["report_submission_allowed"] = False
    payload["confirmed_vulnerability"] = False
    payload["finding_promotion_allowed"] = False
    payload["human_approval_required_before_action"] = True
    payload["human_allow_export_write"] = bool(payload.get("human_allow_export_write"))
    payload["export_written"] = bool(payload.get("export_written"))
    payload["export_count"] = int(payload.get("export_count") or 0)
    payload["export_root_relative"] = str(
        payload.get("export_root_relative") or "_export/variant_analysis"
    )
    payload["safety_invariants"] = list(SAFETY_INVARIANTS)
    variants = payload.get("variants")
    if isinstance(variants, list):
        payload["variant_count"] = len(variants)
        safe_variants: list[Any] = []
        for item in variants:
            if isinstance(item, dict):
                vitem = dict(item)
                vitem["execution_allowed"] = False
                vitem["human_review_required"] = True
                safe_variants.append(vitem)
            else:
                safe_variants.append(item)
        payload["variants"] = safe_variants
    return payload


__all__ = [
    "STATUS_EMPTY",
    "STATUS_READY",
    "STATUS_SKIPPED",
    "STATUS_WAITING",
    "STATUS_WRITTEN",
    "VariantAnalysisError",
    "VariantAnalysisPlan",
    "VariantSearchPlan",
    "attach_variant_analysis_to_bridge_result",
    "build_variant_analysis_plan",
    "load_package_variant_analysis_plan",
]
