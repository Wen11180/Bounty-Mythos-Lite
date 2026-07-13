"""Vulnerability Chain Builder ? plan/export only under human gate.

Final-scheme V4 residual beyond nested deep_research._vulnerability_chains:
- Plan multi-stage vuln chains from hypotheses, retained drafts, residual gates,
  optional variant_analysis seeds, and offline inputs/chain*.json
- Optional write under package _export/vuln_chain_builder/ with human flag
- Never exploits, never promotes, never submits, never live-validates
- Never unlocks execution_allowed / validation_allowed / report_submission_allowed
- Never sets confirmed_vulnerability / finding_promotion_allowed
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


STATUS_READY = "vuln_chain_builder_plan_ready"
STATUS_EMPTY = "vuln_chain_builder_empty"
STATUS_SKIPPED = "vuln_chain_builder_package_missing"
STATUS_WAITING = "vuln_chain_builder_waiting_for_seeds"
STATUS_WRITTEN = "vuln_chain_builder_export_written"

SAFETY_INVARIANTS = [
    "local_or_authorized_package_only",
    "no_public_target_scanning",
    "no_exploit_execution",
    "no_network_access",
    "no_live_validation",
    "no_report_submission",
    "no_export_write_without_human_flag",
    "chain_plan_export_local_package_only",
    "human_approval_required_before_any_action",
    "execution_always_blocked_in_planner",
    "unverified_chains_never_confirmed",
    "chains_only_no_raw_secret_or_user_data",
]

_MAX_CHAINS = 24
_MAX_SEEDS = 32
_MAX_HINTS = 16
_MAX_QUESTIONS = 10
_MAX_STAGES = 12
_MAX_EVIDENCE = 12

_CHAIN_HINT_RE = re.compile(r"^chain.*\.json$", re.IGNORECASE)


class VulnChainBuilderError(ValueError):
    """Raised when bridge attach receives invalid input."""


@dataclass(frozen=True)
class VulnChainStagePlan:
    stage_id: str
    name: str
    purpose: str
    evidence_needed: list[str] = field(default_factory=list)
    refutation_question: str = ""
    safe_next_step: str = "review authorized local code/trace only"
    execution_allowed: bool = False
    human_review_required: bool = True

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["execution_allowed"] = False
        payload["human_review_required"] = True
        return payload


@dataclass(frozen=True)
class VulnChainPlanItem:
    chain_id: str
    source_hypothesis_id: str
    family: str = ""
    vuln_type: str = ""
    seed_location: str = ""
    chain_summary: str = ""
    stages: list[VulnChainStagePlan] = field(default_factory=list)
    broken_invariant: str = ""
    required_evidence: list[str] = field(default_factory=list)
    refutation_questions: list[str] = field(default_factory=list)
    safe_validation_outline: list[str] = field(default_factory=list)
    safe_next_step: str = (
        "refute chain offline with local code/trace evidence before any validation plan"
    )
    status: str = "planned_unverified_chain"
    origin: str = "hypothesis"
    export_relative_path: str = ""
    written: bool = False
    execution_allowed: bool = False
    human_review_required: bool = True

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["execution_allowed"] = False
        payload["human_review_required"] = True
        stages = payload.get("stages")
        if isinstance(stages, list):
            safe_stages = []
            for item in stages:
                if isinstance(item, dict):
                    s = dict(item)
                    s["execution_allowed"] = False
                    s["human_review_required"] = True
                    safe_stages.append(s)
                else:
                    safe_stages.append(item)
            payload["stages"] = safe_stages
        return payload


@dataclass(frozen=True)
class VulnChainBuilderPlan:
    stage: str
    inspirations: list[str]
    execution_mode: str
    status: str
    package_id: str = ""
    package_root: str = ""
    chains: list[VulnChainPlanItem] = field(default_factory=list)
    chain_count: int = 0
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
    export_root_relative: str = "_export/vuln_chain_builder"
    safety_invariants: list[str] = field(default_factory=list)
    next_allowed_action: str = (
        "Review multi-stage chain plans offline; refute with local evidence; "
        "never exploit, promote, or submit from chain plans."
    )
    notes: list[str] = field(default_factory=list)
    human_questions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _force_safety_dict(asdict(self))


def build_vuln_chain_builder_plan(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    source_hypotheses: list[dict[str, Any]] | None = None,
    confirmed_findings: list[dict[str, Any]] | None = None,
    retained_candidates: list[dict[str, Any]] | None = None,
    report_drafts: list[dict[str, Any]] | None = None,
    variant_analysis: dict[str, Any] | None = None,
    residual_gates: list[dict[str, Any]] | None = None,
    human_allow_export_write: bool = False,
) -> VulnChainBuilderPlan:
    notes: list[str] = [
        "plan_only",
        "unverified_chains_never_confirmed",
        "non_destructive_outline_only",
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
            variant_analysis,
            residual_gates,
        ]
    )
    if root is None and not has_payload:
        return _empty_plan(
            status=STATUS_SKIPPED if package_root else STATUS_EMPTY,
            package_id=package_id,
            package_root=str(package_root or ""),
            notes=notes + ["no_package_root_and_no_chain_seeds"],
            human_allow_export_write=bool(human_allow_export_write),
            required_inputs=[
                "source_hypotheses_or_retained_candidates",
                "optional_inputs/chain*.json",
                "optional_variant_analysis_variants",
            ],
        )

    pkg_id = package_id or (root.name if root is not None else "")
    offline_hints = _load_offline_chain_hints(root) if root is not None else []
    seeds = _collect_seeds(
        source_hypotheses=source_hypotheses,
        confirmed_findings=confirmed_findings,
        retained_candidates=retained_candidates,
        report_drafts=report_drafts,
        variant_analysis=variant_analysis,
        residual_gates=residual_gates,
        offline_hints=offline_hints,
    )
    if offline_hints:
        notes.append(f"offline_chain_hints={len(offline_hints)}")
    notes.append(f"seed_count={len(seeds)}")

    if not seeds:
        return _empty_plan(
            status=STATUS_WAITING,
            package_id=pkg_id,
            package_root=str(root) if root is not None else str(package_root or ""),
            notes=notes + ["waiting_for_hypotheses_findings_or_chain_hints"],
            human_allow_export_write=bool(human_allow_export_write),
            offline_hint_count=len(offline_hints),
            bridge_seed_count=0,
            required_inputs=[
                "inputs/chain*.json",
                "bridge retained candidates/drafts",
                "confirmed_findings_or_hypotheses",
                "variant_analysis.variants",
            ],
        )

    chains = _build_chains(seeds)
    family_counts: dict[str, int] = {}
    for item in chains:
        key = item.family or item.vuln_type or "unknown"
        family_counts[key] = int(family_counts.get(key) or 0) + 1
    human_questions = _global_human_questions(chains)
    bridge_seed_count = max(0, len(seeds) - len(offline_hints))

    plan = VulnChainBuilderPlan(
        stage="v4_vuln_chain_builder",
        inspirations=[
            "Vulnerability Chain Builder",
            "Mythos multi-stage reasoning",
            "deep_research_nested_chain_stub_superseded",
        ],
        execution_mode="plan_only",
        status=STATUS_READY,
        package_id=pkg_id,
        package_root=str(root) if root is not None else str(package_root or ""),
        chains=chains,
        chain_count=len(chains),
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
        export_root_relative="_export/vuln_chain_builder",
        safety_invariants=list(SAFETY_INVARIANTS),
        next_allowed_action=(
            "Review multi-stage chain plans offline; optional human "
            "--allow-vuln-chain-builder-export writes plan files only "
            "(never exploits or promotes)."
        ),
        notes=notes
        + [
            f"chains={len(chains)}",
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


def load_package_vuln_chain_builder_plan(
    package_root: str | Path,
    *,
    package_id: str = "",
    source_hypotheses: list[dict[str, Any]] | None = None,
    confirmed_findings: list[dict[str, Any]] | None = None,
    retained_candidates: list[dict[str, Any]] | None = None,
    report_drafts: list[dict[str, Any]] | None = None,
    variant_analysis: dict[str, Any] | None = None,
    residual_gates: list[dict[str, Any]] | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    return build_vuln_chain_builder_plan(
        package_root=package_root,
        package_id=package_id,
        source_hypotheses=source_hypotheses,
        confirmed_findings=confirmed_findings,
        retained_candidates=retained_candidates,
        report_drafts=report_drafts,
        variant_analysis=variant_analysis,
        residual_gates=residual_gates,
        human_allow_export_write=human_allow_export_write,
    ).to_dict()


def attach_vuln_chain_builder_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    source_hypotheses: list[dict[str, Any]] | None = None,
    confirmed_findings: list[dict[str, Any]] | None = None,
    retained_candidates: list[dict[str, Any]] | None = None,
    report_drafts: list[dict[str, Any]] | None = None,
    variant_analysis: dict[str, Any] | None = None,
    residual_gates: list[dict[str, Any]] | None = None,
    vuln_chain_builder: dict[str, Any] | VulnChainBuilderPlan | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    """Attach plan-only vuln chain builder profile; never unlocks exploit/promote/submit."""
    if not isinstance(bridge_result, dict):
        raise VulnChainBuilderError("bridge_result_must_be_object")

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
            bridge_result.get("retained_candidates") or bridge_result.get("candidates")
        )

    drafts = report_drafts
    if drafts is None:
        drafts = _list_of_dicts(
            bridge_result.get("report_drafts") or bridge_result.get("drafts")
        )

    va = variant_analysis
    if va is None and isinstance(bridge_result.get("variant_analysis"), dict):
        va = bridge_result.get("variant_analysis")

    gates = residual_gates
    if gates is None:
        raw_gates = bridge_result.get("human_residual_gates")
        if isinstance(raw_gates, list):
            gates = [g for g in raw_gates if isinstance(g, dict)]
        elif isinstance(raw_gates, dict):
            gates = [raw_gates]

    if isinstance(vuln_chain_builder, VulnChainBuilderPlan):
        payload = vuln_chain_builder.to_dict()
    elif isinstance(vuln_chain_builder, dict):
        payload = _force_safety_dict(dict(vuln_chain_builder))
    else:
        payload = build_vuln_chain_builder_plan(
            package_root=resolved_root,
            package_id=package_id,
            source_hypotheses=hyps,
            confirmed_findings=findings,
            retained_candidates=retained,
            report_drafts=drafts,
            variant_analysis=va if isinstance(va, dict) else None,
            residual_gates=gates,
            human_allow_export_write=bool(human_allow_export_write),
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["vuln_chain_builder"] = payload
    out["vuln_chain_builder_present"] = True
    out["vuln_chain_builder_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["vuln_chain_builder_chain_count"] = int(payload.get("chain_count") or 0)
    out["vuln_chain_builder_seed_count"] = int(payload.get("seed_count") or 0)
    out["vuln_chain_builder_offline_hint_count"] = int(
        payload.get("offline_hint_count") or 0
    )
    out["vuln_chain_builder_export_written"] = bool(payload.get("export_written"))
    out["vuln_chain_builder_export_count"] = int(payload.get("export_count") or 0)
    out["vuln_chain_builder_execution_allowed"] = False
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


def _load_offline_chain_hints(root: Path) -> list[dict[str, Any]]:
    hints: list[dict[str, Any]] = []
    inputs = root / "inputs"
    if not inputs.is_dir():
        return hints
    for path in sorted(inputs.iterdir()):
        if not path.is_file():
            continue
        if not _CHAIN_HINT_RE.match(path.name):
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
    variant_analysis: dict[str, Any] | None,
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
                    item.get("hypothesis_id")
                    or item.get("candidate_id")
                    or item.get("id"),
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
                "family": _safe_text(
                    item.get("family") or item.get("vuln_type") or "", ""
                ),
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
                "vuln_type": _safe_text(
                    finding.get("vuln_type") or finding.get("family"), "unknown"
                ),
                "location": _safe_text(
                    finding.get("location") or finding.get("path"), "unknown"
                ),
                "family": _safe_text(
                    finding.get("family") or finding.get("vuln_type") or "", ""
                ),
                "origin": "confirmed_finding_seed",
            }
        )

    for item in retained_candidates or []:
        if not isinstance(item, dict):
            continue
        _add(
            {
                "hypothesis_id": _safe_text(
                    item.get("candidate_id")
                    or item.get("hypothesis_id")
                    or item.get("id"),
                    "retained",
                ),
                "vuln_type": _safe_text(
                    item.get("vuln_type") or item.get("family"), "unknown"
                ),
                "location": _safe_text(
                    item.get("location") or item.get("affected_code_path"), "unknown"
                ),
                "family": _safe_text(
                    item.get("family") or item.get("vuln_type") or "", ""
                ),
                "origin": "retained_candidate_seed",
            }
        )

    for item in report_drafts or []:
        if not isinstance(item, dict):
            continue
        _add(
            {
                "hypothesis_id": _safe_text(
                    item.get("candidate_id")
                    or item.get("draft_id")
                    or item.get("hypothesis_id"),
                    "draft",
                ),
                "vuln_type": _safe_text(
                    item.get("vuln_type") or item.get("family"), "unknown"
                ),
                "location": _safe_text(
                    item.get("affected_code_path") or item.get("location"), "unknown"
                ),
                "family": _safe_text(
                    item.get("family") or item.get("vuln_type") or "", ""
                ),
                "origin": "report_draft_seed",
            }
        )

    if isinstance(variant_analysis, dict):
        variants = variant_analysis.get("variants") or []
        if isinstance(variants, list):
            for index, variant in enumerate(variants, start=1):
                if not isinstance(variant, dict):
                    continue
                _add(
                    {
                        "hypothesis_id": _safe_text(
                            variant.get("source_hypothesis_id")
                            or variant.get("variant_id")
                            or variant.get("hypothesis_id"),
                            f"va-seed-{index:03d}",
                        ),
                        "vuln_type": _safe_text(
                            variant.get("vuln_type") or variant.get("family"), "unknown"
                        ),
                        "location": _safe_text(
                            variant.get("seed_location") or variant.get("location"),
                            "unknown",
                        ),
                        "family": _safe_text(
                            variant.get("family") or variant.get("vuln_type") or "", ""
                        ),
                        "origin": "variant_analysis_seed",
                    }
                )

    for index, gate in enumerate(residual_gates or [], start=1):
        if not isinstance(gate, dict):
            continue
        _add(
            {
                "hypothesis_id": _safe_text(
                    gate.get("candidate_id")
                    or gate.get("gate_id")
                    or gate.get("hypothesis_id"),
                    f"residual-gate-{index:03d}",
                ),
                "vuln_type": _safe_text(
                    gate.get("vuln_type") or gate.get("family") or "residual", "residual"
                ),
                "location": _safe_text(
                    gate.get("location") or gate.get("affected_code_path") or "residual",
                    "residual",
                ),
                "family": _safe_text(
                    gate.get("family") or gate.get("vuln_type") or "residual", "residual"
                ),
                "origin": "residual_gate_seed",
            }
        )

    for index, hint in enumerate(offline_hints or [], start=1):
        if not isinstance(hint, dict):
            continue
        _add(
            {
                "hypothesis_id": _safe_text(
                    hint.get("source_hypothesis_id")
                    or hint.get("hypothesis_id")
                    or hint.get("chain_id")
                    or hint.get("_hint_file"),
                    f"chain-hint-{index:03d}",
                ),
                "vuln_type": _safe_text(
                    hint.get("vuln_type") or hint.get("family") or hint.get("title"),
                    "unknown",
                ),
                "location": _safe_text(
                    hint.get("location")
                    or hint.get("seed_location")
                    or hint.get("path"),
                    "unknown",
                ),
                "family": _safe_text(
                    hint.get("family") or hint.get("vuln_type") or "", ""
                ),
                "origin": "offline_chain_hint",
                "stages": hint.get("stages"),
                "chain_summary": hint.get("chain_summary") or hint.get("summary"),
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

def _build_chains(seeds: list[dict[str, Any]]) -> list[VulnChainPlanItem]:
    chains: list[VulnChainPlanItem] = []
    for index, seed in enumerate(seeds, start=1):
        if len(chains) >= _MAX_CHAINS:
            break
        hyp_id = _safe_text(seed.get("hypothesis_id"), f"H-{index:03d}")
        vuln_type = _safe_text(seed.get("vuln_type"), "unknown")
        location = _safe_text(seed.get("location"), "unknown")
        family = _safe_text(seed.get("family") or vuln_type, vuln_type)
        origin = _safe_text(seed.get("origin"), "hypothesis")
        stages = _stage_plans(
            seed=seed,
            chain_index=index,
            hyp_id=hyp_id,
            vuln_type=vuln_type,
            location=location,
        )
        summary = _safe_text(
            seed.get("chain_summary"),
            (
                f"{vuln_type} multi-stage chain from `{location}` requires "
                "cross-boundary evidence before any validation plan."
            ),
        )
        invariant = _broken_invariant(vuln_type=vuln_type, family=family)
        evidence = [
            "entrypoint_to_sink_or_object_trace",
            "permission_parser_or_trust_boundary",
            "impact_without_real_user_data",
            "human_review_decision",
        ][:_MAX_EVIDENCE]
        questions = [
            f"Does chain for {hyp_id} stay inside authorized local package scope?",
            f"Which stage boundary for family={family} already holds offline?",
            "What local code/trace evidence would refute this chain before validation?",
        ][:_MAX_QUESTIONS]
        outline = [
            "Map entrypoint -> trust boundary -> sink/object offline.",
            "Collect only authorized local code/trace evidence.",
            "Refute or hold chain; never exploit or promote.",
            "If residual remains, prepare non-destructive validation plan for human gate only.",
        ]
        status = (
            "unverified_hypothesis_from_confirmed_finding"
            if origin == "confirmed_finding_seed"
            else "planned_unverified_chain"
        )
        chains.append(
            VulnChainPlanItem(
                chain_id=f"CH-{index:03d}",
                source_hypothesis_id=hyp_id,
                family=family,
                vuln_type=vuln_type,
                seed_location=location,
                chain_summary=summary,
                stages=stages,
                broken_invariant=invariant,
                required_evidence=evidence,
                refutation_questions=questions,
                safe_validation_outline=outline,
                safe_next_step=(
                    "refute chain offline with local code/trace evidence before any validation plan"
                ),
                status=status,
                origin=origin,
                execution_allowed=False,
                human_review_required=True,
            )
        )
    return chains


def _stage_plans(
    *,
    seed: dict[str, Any],
    chain_index: int,
    hyp_id: str,
    vuln_type: str,
    location: str,
) -> list[VulnChainStagePlan]:
    raw_stages = seed.get("stages")
    names: list[str] = []
    if isinstance(raw_stages, list) and raw_stages:
        for item in raw_stages:
            if isinstance(item, dict):
                name = _safe_text(
                    item.get("name") or item.get("stage") or item.get("stage_id"), ""
                )
            else:
                name = _safe_text(item, "")
            if name:
                names.append(name)
            if len(names) >= _MAX_STAGES:
                break
    if not names:
        names = _default_stage_names(vuln_type)

    stages: list[VulnChainStagePlan] = []
    for s_index, name in enumerate(names, start=1):
        stage_id = f"CH-{chain_index:03d}-S{s_index:02d}"
        purpose = _stage_purpose(name=name, vuln_type=vuln_type, location=location)
        evidence = _stage_evidence(name=name)
        question = (
            f"At stage `{name}` for {hyp_id}, what local evidence holds or refutes "
            f"the {vuln_type} boundary?"
        )
        stages.append(
            VulnChainStagePlan(
                stage_id=stage_id,
                name=name,
                purpose=purpose,
                evidence_needed=evidence,
                refutation_question=question,
                safe_next_step="review authorized local code/trace only",
                execution_allowed=False,
                human_review_required=True,
            )
        )
    return stages


def _default_stage_names(vuln_type: str) -> list[str]:
    vt = (vuln_type or "").strip().lower()
    if vt in {"authorization", "authz", "idor", "bola", "bfla"}:
        return [
            "entrypoint",
            "authorization_boundary",
            "object_access",
            "impact_review",
        ]
    if vt in {"injection", "sqli", "xss", "command_injection", "static-analysis"}:
        return ["entrypoint", "input_boundary", "sink", "impact_review"]
    if vt in {"ssrf"}:
        return ["entrypoint", "url_boundary", "egress_sink", "impact_review"]
    if vt in {"path_traversal", "path", "lfi"}:
        return ["entrypoint", "path_boundary", "filesystem_sink", "impact_review"]
    if vt in {"mass_assignment", "mass"}:
        return ["entrypoint", "schema_boundary", "state_write", "impact_review"]
    return ["entrypoint", "trust_boundary", "state_change", "impact_review"]


def _stage_purpose(*, name: str, vuln_type: str, location: str) -> str:
    key = name.strip().lower()
    if "entry" in key:
        return f"Identify how untrusted input reaches `{location}` for {vuln_type}."
    if "auth" in key or "permission" in key:
        return "Check whether role/ownership gates constrain sensitive access."
    if "input" in key or "url" in key or "path" in key or "schema" in key:
        return "Map the trust/input boundary before any sink or state change."
    if "sink" in key or "egress" in key or "filesystem" in key or "object" in key:
        return "Locate the sensitive sink/object and required control at that hop."
    if "state" in key or "write" in key:
        return "Describe the state mutation and what invariant should prevent abuse."
    if "impact" in key:
        return "Describe impact using fixtures only; never real user data or secrets."
    return f"Review stage `{name}` offline for {vuln_type} chain completeness."


def _stage_evidence(name: str) -> list[str]:
    key = name.strip().lower()
    if "entry" in key:
        return ["request_or_handler_entry", "parameter_or_body_source"]
    if "auth" in key or "permission" in key:
        return ["authz_check_presence_or_absence", "role_or_ownership_predicate"]
    if "sink" in key or "egress" in key or "filesystem" in key or "object" in key:
        return ["sink_call_site", "guard_before_sink"]
    if "impact" in key:
        return ["sanitized_fixture_impact", "no_real_user_data"]
    return ["local_code_trace", "boundary_predicate"]


def _broken_invariant(*, vuln_type: str, family: str) -> str:
    key = (family or vuln_type or "").strip().lower()
    if key in {"authorization", "authz", "idor", "bola", "bfla"}:
        return (
            "Every sensitive object access must be constrained by role and ownership checks."
        )
    if key in {"injection", "sqli", "xss", "command_injection"}:
        return "User-controlled input must not reach a sink without structured validation."
    if key == "ssrf":
        return "Server-side fetches must enforce allowlists and block internal targets."
    if key in {"path_traversal", "path", "lfi"}:
        return "Filesystem paths derived from input must stay inside an authorized root."
    if key in {"mass_assignment", "mass"}:
        return "Client-controlled fields must not write privileged schema attributes."
    return (
        "Every promoted finding needs a local evidence trace and an explicit refutation attempt."
    )


def _global_human_questions(chains: list[VulnChainPlanItem]) -> list[str]:
    questions = [
        "Are all chain stages limited to authorized local package artifacts?",
        "Do not treat planned multi-stage chains as confirmed vulnerabilities.",
        "Prefer offline refutation before any non-destructive validation plan.",
    ]
    for chain in chains[:4]:
        questions.append(
            f"What evidence would break chain {chain.chain_id} "
            f"({chain.family or chain.vuln_type}) before validation?"
        )
    return questions[:_MAX_QUESTIONS]

def _maybe_write_exports(
    plan: VulnChainBuilderPlan,
    *,
    root: Path | None,
    human_allow_export_write: bool,
) -> VulnChainBuilderPlan:
    if not human_allow_export_write:
        return plan
    if root is None or not root.is_dir():
        return _rebuild_plan(
            plan,
            notes=list(plan.notes) + ["export_skipped_no_package_root"],
        )
    if not plan.chains:
        return _rebuild_plan(
            plan,
            notes=list(plan.notes) + ["export_skipped_no_chains"],
        )

    export_root = root / "_export" / "vuln_chain_builder"
    export_root.mkdir(parents=True, exist_ok=True)
    written_chains: list[VulnChainPlanItem] = []
    export_count = 0

    for chain in plan.chains:
        slug = _slug(chain.chain_id or chain.source_hypothesis_id or "chain")
        target_dir = export_root / slug
        target_dir.mkdir(parents=True, exist_ok=True)
        rel = f"_export/vuln_chain_builder/{slug}"
        meta = {
            "chain_id": chain.chain_id,
            "source_hypothesis_id": chain.source_hypothesis_id,
            "package_id": plan.package_id,
            "family": chain.family,
            "vuln_type": chain.vuln_type,
            "seed_location": chain.seed_location,
            "stage_count": len(chain.stages),
            "origin": chain.origin,
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
        (target_dir / "chain_plan.md").write_text(
            _render_chain_md(chain, package_id=plan.package_id),
            encoding="utf-8",
        )
        (target_dir / "README.md").write_text(
            _render_readme(chain, package_id=plan.package_id, export_dir=rel),
            encoding="utf-8",
        )
        export_count += 3
        written_chains.append(
            VulnChainPlanItem(
                chain_id=chain.chain_id,
                source_hypothesis_id=chain.source_hypothesis_id,
                family=chain.family,
                vuln_type=chain.vuln_type,
                seed_location=chain.seed_location,
                chain_summary=chain.chain_summary,
                stages=list(chain.stages),
                broken_invariant=chain.broken_invariant,
                required_evidence=list(chain.required_evidence),
                refutation_questions=list(chain.refutation_questions),
                safe_validation_outline=list(chain.safe_validation_outline),
                safe_next_step=chain.safe_next_step,
                status="exported",
                origin=chain.origin,
                export_relative_path=rel,
                written=True,
                execution_allowed=False,
                human_review_required=True,
            )
        )

    index = {
        "package_id": plan.package_id,
        "status": STATUS_WRITTEN,
        "chain_count": len(written_chains),
        "export_count": export_count,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
        "finding_promotion_allowed": False,
        "network_access": False,
        "live_validation": False,
        "process_spawn_allowed": False,
        "chains": [
            {
                "chain_id": c.chain_id,
                "source_hypothesis_id": c.source_hypothesis_id,
                "export_relative_path": c.export_relative_path,
                "family": c.family,
            }
            for c in written_chains
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
        chains=written_chains,
        status=STATUS_WRITTEN,
        export_written=True,
        export_count=export_count,
        human_allow_export_write=True,
        notes=list(plan.notes)
        + [f"export_written={export_count}", f"export_root={export_root}"],
        next_allowed_action=(
            "Human reviews exported multi-stage chain plans offline; "
            "refute with local evidence; never exploit or promote."
        ),
    )


def _render_chain_md(chain: VulnChainPlanItem, *, package_id: str) -> str:
    stages_md = []
    for stage in chain.stages:
        evidence = "\n".join(f"  - {e}" for e in stage.evidence_needed) or "  - (none)"
        stages_md.append(
            f"### {stage.stage_id}: {stage.name}\n\n"
            f"- purpose: {stage.purpose}\n"
            f"- refutation_question: {stage.refutation_question}\n"
            f"- safe_next_step: {stage.safe_next_step}\n"
            f"- execution_allowed: `false`\n"
            f"- evidence_needed:\n{evidence}\n"
        )
    stages_block = "\n".join(stages_md) or "(none)\n"
    questions = "\n".join(f"- {q}" for q in chain.refutation_questions) or "- (none)"
    evidence = "\n".join(f"- {e}" for e in chain.required_evidence) or "- (none)"
    outline = "\n".join(f"- {s}" for s in chain.safe_validation_outline) or "- (none)"
    return (
        f"# Vulnerability Chain Plan: {chain.chain_id}\n\n"
        f"- package_id: `{package_id}`\n"
        f"- source_hypothesis_id: `{chain.source_hypothesis_id}`\n"
        f"- family: `{chain.family}`\n"
        f"- vuln_type: `{chain.vuln_type}`\n"
        f"- seed_location: `{chain.seed_location}`\n"
        f"- origin: `{chain.origin}`\n"
        f"- status: `{chain.status}`\n"
        f"- execution_allowed: `false`\n"
        f"- human_review_required: `true`\n\n"
        f"## Chain summary\n\n"
        f"{chain.chain_summary or '(none)'}\n\n"
        f"## Broken invariant (hypothesis)\n\n"
        f"{chain.broken_invariant or '(none)'}\n\n"
        f"## Stages\n\n"
        f"{stages_block}\n"
        f"## Required evidence\n\n"
        f"{evidence}\n\n"
        f"## Refutation questions\n\n"
        f"{questions}\n\n"
        f"## Safe validation outline (plan only)\n\n"
        f"{outline}\n\n"
        f"## Safe next step\n\n"
        f"{chain.safe_next_step}\n\n"
        f"## Safety\n\n"
        f"- Plan/export only. Never exploit, promote, submit, or live-validate.\n"
        f"- Unverified chains are never confirmed vulnerabilities.\n"
    )


def _render_readme(
    chain: VulnChainPlanItem, *, package_id: str, export_dir: str
) -> str:
    return (
        f"# Vulnerability Chain Builder Export\n\n"
        f"- package_id: `{package_id}`\n"
        f"- chain_id: `{chain.chain_id}`\n"
        f"- export_dir: `{export_dir}`\n"
        f"- source_hypothesis_id: `{chain.source_hypothesis_id}`\n\n"
        f"Human reviews these offline multi-stage chain plans only. Mythos never "
        f"executes chains against public targets, never promotes findings, and "
        f"never submits reports from this export.\n"
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
) -> VulnChainBuilderPlan:
    return _force_safety_plan(
        VulnChainBuilderPlan(
            stage="v4_vuln_chain_builder",
            inspirations=[
                "Vulnerability Chain Builder",
                "Mythos multi-stage reasoning",
                "deep_research_nested_chain_stub_superseded",
            ],
            execution_mode="plan_only",
            status=status,
            package_id=package_id,
            package_root=package_root,
            chains=[],
            chain_count=0,
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
            export_root_relative="_export/vuln_chain_builder",
            safety_invariants=list(SAFETY_INVARIANTS),
            next_allowed_action=(
                "Provide authorized hypotheses, retained candidates, findings, "
                "variant_analysis.variants, residual gates, or inputs/chain*.json; "
                "plan remains local-only."
            ),
            notes=list(notes or []),
            human_questions=[
                "Are chain seeds limited to authorized package artifacts?",
                "Do not treat empty/waiting plans as confirmed vulnerabilities.",
            ],
        )
    )


def _rebuild_plan(
    plan: VulnChainBuilderPlan,
    *,
    chains: list[VulnChainPlanItem] | None = None,
    status: str | None = None,
    export_written: bool | None = None,
    export_count: int | None = None,
    human_allow_export_write: bool | None = None,
    notes: list[str] | None = None,
    next_allowed_action: str | None = None,
) -> VulnChainBuilderPlan:
    use_chains = list(chains) if chains is not None else list(plan.chains)
    family_counts: dict[str, int] = {}
    for item in use_chains:
        key = item.family or item.vuln_type or "unknown"
        family_counts[key] = int(family_counts.get(key) or 0) + 1
    return _force_safety_plan(
        VulnChainBuilderPlan(
            stage=plan.stage,
            inspirations=list(plan.inspirations),
            execution_mode="plan_only",
            status=status if status is not None else plan.status,
            package_id=plan.package_id,
            package_root=plan.package_root,
            chains=use_chains,
            chain_count=len(use_chains),
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
            or "_export/vuln_chain_builder",
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
    text = text.strip("-._") or "chain"
    return text[:80]


def _safe_text(value: Any, default: str) -> str:
    if value is None:
        return default
    text = str(value).strip()
    if not text:
        return default
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

def _force_safety_plan(plan: VulnChainBuilderPlan) -> VulnChainBuilderPlan:
    safe_chains = [
        VulnChainPlanItem(
            chain_id=c.chain_id,
            source_hypothesis_id=c.source_hypothesis_id,
            family=c.family,
            vuln_type=c.vuln_type,
            seed_location=c.seed_location,
            chain_summary=c.chain_summary,
            stages=[
                VulnChainStagePlan(
                    stage_id=s.stage_id,
                    name=s.name,
                    purpose=s.purpose,
                    evidence_needed=list(s.evidence_needed),
                    refutation_question=s.refutation_question,
                    safe_next_step=s.safe_next_step
                    or "review authorized local code/trace only",
                    execution_allowed=False,
                    human_review_required=True,
                )
                for s in c.stages
            ],
            broken_invariant=c.broken_invariant,
            required_evidence=list(c.required_evidence),
            refutation_questions=list(c.refutation_questions),
            safe_validation_outline=list(c.safe_validation_outline),
            safe_next_step=c.safe_next_step
            or (
                "refute chain offline with local code/trace evidence before any validation plan"
            ),
            status=c.status,
            origin=c.origin,
            export_relative_path=c.export_relative_path,
            written=bool(c.written),
            execution_allowed=False,
            human_review_required=True,
        )
        for c in plan.chains
    ]
    return VulnChainBuilderPlan(
        stage=plan.stage or "v4_vuln_chain_builder",
        inspirations=list(plan.inspirations),
        execution_mode="plan_only",
        status=plan.status,
        package_id=plan.package_id,
        package_root=plan.package_root,
        chains=safe_chains,
        chain_count=len(safe_chains),
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
        or "_export/vuln_chain_builder",
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
        payload.get("export_root_relative") or "_export/vuln_chain_builder"
    )
    payload["safety_invariants"] = list(SAFETY_INVARIANTS)
    chains = payload.get("chains")
    if isinstance(chains, list):
        payload["chain_count"] = len(chains)
        safe_chains: list[Any] = []
        for item in chains:
            if isinstance(item, dict):
                citem = dict(item)
                citem["execution_allowed"] = False
                citem["human_review_required"] = True
                stages = citem.get("stages")
                if isinstance(stages, list):
                    safe_stages = []
                    for stage in stages:
                        if isinstance(stage, dict):
                            s = dict(stage)
                            s["execution_allowed"] = False
                            s["human_review_required"] = True
                            safe_stages.append(s)
                        else:
                            safe_stages.append(stage)
                    citem["stages"] = safe_stages
                safe_chains.append(citem)
            else:
                safe_chains.append(item)
        payload["chains"] = safe_chains
    return payload


__all__ = [
    "STATUS_EMPTY",
    "STATUS_READY",
    "STATUS_SKIPPED",
    "STATUS_WAITING",
    "STATUS_WRITTEN",
    "VulnChainBuilderError",
    "VulnChainBuilderPlan",
    "VulnChainPlanItem",
    "VulnChainStagePlan",
    "attach_vuln_chain_builder_to_bridge_result",
    "build_vuln_chain_builder_plan",
    "load_package_vuln_chain_builder_plan",
]
