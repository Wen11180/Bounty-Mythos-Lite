"""Deep Code Reasoning - plan/export only under human gate.

Final-scheme V4 residual beyond nested deep_research PermissionModel /
_cross_file_reasoning stubs:
- Plan permission models + cross-file controller->service->DAO paths
- Seeds from hypotheses, retained drafts, residual gates, chains, offline inputs
- Optional write under package _export/deep_code_reasoning/ with human flag
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


STATUS_READY = "deep_code_reasoning_plan_ready"
STATUS_EMPTY = "deep_code_reasoning_empty"
STATUS_SKIPPED = "deep_code_reasoning_package_missing"
STATUS_WAITING = "deep_code_reasoning_waiting_for_seeds"
STATUS_WRITTEN = "deep_code_reasoning_export_written"

SAFETY_INVARIANTS = [
    "local_or_authorized_package_only",
    "no_public_target_scanning",
    "no_exploit_execution",
    "no_network_access",
    "no_live_validation",
    "no_report_submission",
    "no_export_write_without_human_flag",
    "reasoning_plan_export_local_package_only",
    "human_approval_required_before_any_action",
    "execution_always_blocked_in_planner",
    "unverified_reasoning_never_confirmed",
    "plans_only_no_raw_secret_or_user_data",
]

_MAX_PATHS = 24
_MAX_SEEDS = 32
_MAX_HINTS = 16
_MAX_QUESTIONS = 10
_MAX_LAYERS = 10
_MAX_EVIDENCE = 12
_MAX_ROLES = 16

_HINT_RE = re.compile(
    r"^(deep_code|permission|cross_file|reasoning).*\.json$", re.IGNORECASE
)

_DEFAULT_LAYERS = [
    "controller_or_route",
    "auth_middleware",
    "service_or_use_case",
    "dao_or_repository",
    "object_or_resource",
]


class DeepCodeReasoningError(ValueError):
    """Raised when bridge attach receives invalid input."""


@dataclass(frozen=True)
class PermissionModelPlan:
    model_id: str
    status: str
    roles: list[str] = field(default_factory=list)
    ownership_checks: list[str] = field(default_factory=list)
    trust_boundaries: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    refutation_questions: list[str] = field(default_factory=list)
    safe_next_step: str = (
        "map role/ownership checks offline in authorized local code only"
    )
    origin: str = "seed"
    execution_allowed: bool = False
    human_review_required: bool = True

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["execution_allowed"] = False
        payload["human_review_required"] = True
        return payload


@dataclass(frozen=True)
class CrossFilePathLayer:
    layer_id: str
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
class CrossFileReasoningPath:
    path_id: str
    source_hypothesis_id: str
    family: str = ""
    vuln_type: str = ""
    seed_location: str = ""
    path_summary: str = ""
    layers: list[CrossFilePathLayer] = field(default_factory=list)
    broken_invariant: str = ""
    required_evidence: list[str] = field(default_factory=list)
    refutation_questions: list[str] = field(default_factory=list)
    permission_model_id: str = ""
    safe_validation_outline: list[str] = field(default_factory=list)
    safe_next_step: str = (
        "refute cross-file path offline with local code/trace evidence before any validation plan"
    )
    status: str = "planned_unverified_path"
    origin: str = "hypothesis"
    export_relative_path: str = ""
    written: bool = False
    execution_allowed: bool = False
    human_review_required: bool = True

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["execution_allowed"] = False
        payload["human_review_required"] = True
        layers = payload.get("layers")
        if isinstance(layers, list):
            safe_layers = []
            for item in layers:
                if isinstance(item, dict):
                    layer = dict(item)
                    layer["execution_allowed"] = False
                    layer["human_review_required"] = True
                    safe_layers.append(layer)
                else:
                    safe_layers.append(item)
            payload["layers"] = safe_layers
        return payload


@dataclass(frozen=True)
class DeepCodeReasoningPlan:
    stage: str
    inspirations: list[str]
    execution_mode: str
    status: str
    package_id: str = ""
    package_root: str = ""
    permission_models: list[PermissionModelPlan] = field(default_factory=list)
    paths: list[CrossFileReasoningPath] = field(default_factory=list)
    path_count: int = 0
    permission_model_count: int = 0
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
    export_root_relative: str = "_export/deep_code_reasoning"
    safety_invariants: list[str] = field(default_factory=list)
    next_allowed_action: str = (
        "Review permission models and cross-file paths offline; refute with local "
        "evidence; never exploit, promote, or submit from reasoning plans."
    )
    notes: list[str] = field(default_factory=list)
    human_questions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return _force_safety_dict(asdict(self))



def build_deep_code_reasoning_plan(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    source_hypotheses: list[dict[str, Any]] | None = None,
    confirmed_findings: list[dict[str, Any]] | None = None,
    retained_candidates: list[dict[str, Any]] | None = None,
    report_drafts: list[dict[str, Any]] | None = None,
    residual_gates: list[dict[str, Any]] | None = None,
    vuln_chain_builder: dict[str, Any] | None = None,
    variant_analysis: dict[str, Any] | None = None,
    role_models: list[dict[str, Any]] | None = None,
    human_allow_export_write: bool = False,
) -> DeepCodeReasoningPlan:
    notes: list[str] = [
        "plan_only",
        "unverified_reasoning_never_confirmed",
        "permission_and_cross_file_plan_only",
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
            residual_gates,
            vuln_chain_builder,
            variant_analysis,
            role_models,
        ]
    )
    if root is None and not has_payload:
        return _empty_plan(
            status=STATUS_SKIPPED if package_root else STATUS_EMPTY,
            package_id=package_id,
            package_root=str(package_root or ""),
            notes=notes + ["no_package_root_and_no_reasoning_seeds"],
            human_allow_export_write=bool(human_allow_export_write),
            required_inputs=[
                "source_hypotheses_or_retained_candidates",
                "optional_inputs/deep_code*.json|permission*.json|cross_file*.json",
                "optional_vuln_chain_builder_chains",
                "optional_role_models",
            ],
        )

    pkg_id = package_id or (root.name if root is not None else "")
    offline_hints = _load_offline_hints(root) if root is not None else []
    seeds = _collect_seeds(
        source_hypotheses=source_hypotheses,
        confirmed_findings=confirmed_findings,
        retained_candidates=retained_candidates,
        report_drafts=report_drafts,
        residual_gates=residual_gates,
        vuln_chain_builder=vuln_chain_builder,
        variant_analysis=variant_analysis,
        offline_hints=offline_hints,
    )
    roles = _collect_roles(
        role_models=role_models, offline_hints=offline_hints, seeds=seeds
    )
    if offline_hints:
        notes.append(f"offline_reasoning_hints={len(offline_hints)}")
    notes.append(f"seed_count={len(seeds)}")
    notes.append(f"role_count={len(roles)}")

    if not seeds and not roles:
        return _empty_plan(
            status=STATUS_WAITING,
            package_id=pkg_id,
            package_root=str(root) if root is not None else str(package_root or ""),
            notes=notes + ["waiting_for_hypotheses_findings_or_reasoning_hints"],
            human_allow_export_write=bool(human_allow_export_write),
            offline_hint_count=len(offline_hints),
            bridge_seed_count=0,
            required_inputs=[
                "inputs/deep_code*.json or permission*.json or cross_file*.json",
                "bridge retained candidates/drafts",
                "confirmed_findings_or_hypotheses",
                "vuln_chain_builder.chains",
                "optional role_models",
            ],
        )

    permission_models = _build_permission_models(seeds=seeds, roles=roles)
    paths = _build_paths(seeds=seeds, permission_models=permission_models)
    family_counts: dict[str, int] = {}
    for item in paths:
        key = item.family or item.vuln_type or "unknown"
        family_counts[key] = int(family_counts.get(key) or 0) + 1
    human_questions = _global_human_questions(paths, permission_models)
    bridge_seed_count = max(0, len(seeds) - len(offline_hints))

    plan = DeepCodeReasoningPlan(
        stage="v4_deep_code_reasoning",
        inspirations=[
            "Deep Code Reasoning",
            "Mythos permission + cross-file reasoning",
            "deep_research_nested_permission_crossfile_stub_superseded",
        ],
        execution_mode="plan_only",
        status=STATUS_READY if (paths or permission_models) else STATUS_WAITING,
        package_id=pkg_id,
        package_root=str(root) if root is not None else str(package_root or ""),
        permission_models=permission_models,
        paths=paths,
        path_count=len(paths),
        permission_model_count=len(permission_models),
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
        export_root_relative="_export/deep_code_reasoning",
        safety_invariants=list(SAFETY_INVARIANTS),
        next_allowed_action=(
            "Review permission models and cross-file paths offline; optional human "
            "--allow-deep-code-reasoning-export writes plan files only "
            "(never exploits or promotes)."
        ),
        notes=notes
        + [
            f"path_count={len(paths)}",
            f"permission_model_count={len(permission_models)}",
        ],
        human_questions=human_questions,
    )
    plan = _force_safety_plan(plan)
    return _maybe_write_exports(
        plan, root=root, human_allow_export_write=bool(human_allow_export_write)
    )


def load_package_deep_code_reasoning_plan(
    package_root: str | Path,
    *,
    package_id: str = "",
    source_hypotheses: list[dict[str, Any]] | None = None,
    confirmed_findings: list[dict[str, Any]] | None = None,
    retained_candidates: list[dict[str, Any]] | None = None,
    report_drafts: list[dict[str, Any]] | None = None,
    residual_gates: list[dict[str, Any]] | None = None,
    vuln_chain_builder: dict[str, Any] | None = None,
    variant_analysis: dict[str, Any] | None = None,
    role_models: list[dict[str, Any]] | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    return build_deep_code_reasoning_plan(
        package_root=package_root,
        package_id=package_id,
        source_hypotheses=source_hypotheses,
        confirmed_findings=confirmed_findings,
        retained_candidates=retained_candidates,
        report_drafts=report_drafts,
        residual_gates=residual_gates,
        vuln_chain_builder=vuln_chain_builder,
        variant_analysis=variant_analysis,
        role_models=role_models,
        human_allow_export_write=human_allow_export_write,
    ).to_dict()


def attach_deep_code_reasoning_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    source_hypotheses: list[dict[str, Any]] | None = None,
    confirmed_findings: list[dict[str, Any]] | None = None,
    retained_candidates: list[dict[str, Any]] | None = None,
    report_drafts: list[dict[str, Any]] | None = None,
    residual_gates: list[dict[str, Any]] | None = None,
    vuln_chain_builder: dict[str, Any] | None = None,
    variant_analysis: dict[str, Any] | None = None,
    role_models: list[dict[str, Any]] | None = None,
    deep_code_reasoning: dict[str, Any] | DeepCodeReasoningPlan | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    """Attach plan-only deep code reasoning profile; never unlocks exploit/promote/submit."""
    if not isinstance(bridge_result, dict):
        raise DeepCodeReasoningError("bridge_result_must_be_object")

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

    vcb = vuln_chain_builder
    if vcb is None and isinstance(bridge_result.get("vuln_chain_builder"), dict):
        vcb = bridge_result.get("vuln_chain_builder")

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

    roles = role_models
    if roles is None:
        web = bridge_result.get("authorized_web_api")
        if isinstance(web, dict):
            roles = _list_of_dicts(web.get("role_models"))
        if not roles:
            bb = bridge_result.get("authorized_bug_bounty")
            if isinstance(bb, dict):
                roles = _list_of_dicts(bb.get("role_models"))

    if isinstance(deep_code_reasoning, DeepCodeReasoningPlan):
        payload = deep_code_reasoning.to_dict()
    elif isinstance(deep_code_reasoning, dict):
        payload = _force_safety_dict(dict(deep_code_reasoning))
    else:
        payload = build_deep_code_reasoning_plan(
            package_root=resolved_root,
            package_id=package_id,
            source_hypotheses=hyps,
            confirmed_findings=findings,
            retained_candidates=retained,
            report_drafts=drafts,
            residual_gates=gates,
            vuln_chain_builder=vcb if isinstance(vcb, dict) else None,
            variant_analysis=va if isinstance(va, dict) else None,
            role_models=roles,
            human_allow_export_write=bool(human_allow_export_write),
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["deep_code_reasoning"] = payload
    out["deep_code_reasoning_present"] = True
    out["deep_code_reasoning_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["deep_code_reasoning_path_count"] = int(payload.get("path_count") or 0)
    out["deep_code_reasoning_permission_model_count"] = int(
        payload.get("permission_model_count") or 0
    )
    out["deep_code_reasoning_seed_count"] = int(payload.get("seed_count") or 0)
    out["deep_code_reasoning_offline_hint_count"] = int(
        payload.get("offline_hint_count") or 0
    )
    out["deep_code_reasoning_export_written"] = bool(payload.get("export_written"))
    out["deep_code_reasoning_export_count"] = int(payload.get("export_count") or 0)
    out["deep_code_reasoning_execution_allowed"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    out["finding_promotion_allowed"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out


def _extract_hypotheses_from_bridge(bridge: dict[str, Any]) -> list[dict[str, Any]]:
    hyps = _list_of_dicts(bridge.get("source_hypotheses"))
    if hyps:
        return hyps
    hyps = _list_of_dicts(bridge.get("hypotheses"))
    if hyps:
        return hyps
    out: list[dict[str, Any]] = []
    for key in ("retained_candidates", "candidates", "drafts", "report_drafts"):
        for item in _list_of_dicts(bridge.get(key)):
            out.append(item)
    return out


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _load_offline_hints(root: Path) -> list[dict[str, Any]]:
    inputs = root / "inputs"
    if not inputs.is_dir():
        return []
    hints: list[dict[str, Any]] = []
    for path in sorted(inputs.glob("*.json")):
        if not _HINT_RE.match(path.name):
            continue
        if len(hints) >= _MAX_HINTS:
            break
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(raw, dict):
            item = dict(raw)
            item["_hint_file"] = path.name
            hints.append(item)
        elif isinstance(raw, list):
            for entry in raw:
                if not isinstance(entry, dict):
                    continue
                item = dict(entry)
                item["_hint_file"] = path.name
                hints.append(item)
                if len(hints) >= _MAX_HINTS:
                    break
    nested = inputs / "deep_code_reasoning"
    if nested.is_dir():
        for path in sorted(nested.glob("*.json")):
            if len(hints) >= _MAX_HINTS:
                break
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if isinstance(raw, dict):
                item = dict(raw)
                item["_hint_file"] = path.name
                hints.append(item)
    return hints[:_MAX_HINTS]


def _collect_seeds(
    *,
    source_hypotheses: list[dict[str, Any]] | None,
    confirmed_findings: list[dict[str, Any]] | None,
    retained_candidates: list[dict[str, Any]] | None,
    report_drafts: list[dict[str, Any]] | None,
    residual_gates: list[dict[str, Any]] | None,
    vuln_chain_builder: dict[str, Any] | None,
    variant_analysis: dict[str, Any] | None,
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
                    or item.get("seed_location"),
                    "unknown",
                ),
                "family": _safe_text(
                    item.get("family") or item.get("vuln_type") or "", ""
                ),
                "origin": "hypothesis",
                "roles": item.get("roles") or item.get("role_models"),
            }
        )

    for item in confirmed_findings or []:
        if not isinstance(item, dict):
            continue
        _add(
            {
                "hypothesis_id": _safe_text(
                    item.get("finding_id")
                    or item.get("hypothesis_id")
                    or item.get("candidate_id"),
                    "finding",
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
                "origin": "confirmed_finding_seed",
            }
        )

    for item in retained_candidates or []:
        if not isinstance(item, dict):
            continue
        _add(
            {
                "hypothesis_id": _safe_text(
                    item.get("candidate_id") or item.get("hypothesis_id"),
                    "retained",
                ),
                "vuln_type": _safe_text(
                    item.get("vuln_type") or item.get("family") or item.get("title"),
                    "unknown",
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

    if isinstance(vuln_chain_builder, dict):
        chains = vuln_chain_builder.get("chains") or []
        if isinstance(chains, list):
            for index, chain in enumerate(chains, start=1):
                if not isinstance(chain, dict):
                    continue
                _add(
                    {
                        "hypothesis_id": _safe_text(
                            chain.get("source_hypothesis_id")
                            or chain.get("chain_id")
                            or chain.get("hypothesis_id"),
                            f"vcb-seed-{index:03d}",
                        ),
                        "vuln_type": _safe_text(
                            chain.get("vuln_type") or chain.get("family"), "unknown"
                        ),
                        "location": _safe_text(
                            chain.get("seed_location") or chain.get("location"),
                            "unknown",
                        ),
                        "family": _safe_text(
                            chain.get("family") or chain.get("vuln_type") or "", ""
                        ),
                        "origin": "vuln_chain_builder_seed",
                        "stages": chain.get("stages"),
                        "path_summary": chain.get("chain_summary")
                        or chain.get("summary"),
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
                    or hint.get("path_id")
                    or hint.get("_hint_file"),
                    f"reasoning-hint-{index:03d}",
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
                "origin": "offline_reasoning_hint",
                "layers": hint.get("layers") or hint.get("stages"),
                "path_summary": hint.get("path_summary") or hint.get("summary"),
                "roles": hint.get("roles") or hint.get("role_models"),
            }
        )

    return seeds[:_MAX_SEEDS]


def _collect_roles(
    *,
    role_models: list[dict[str, Any]] | None,
    offline_hints: list[dict[str, Any]],
    seeds: list[dict[str, Any]],
) -> list[str]:
    roles: list[str] = []
    seen: set[str] = set()

    def _add_role(value: Any) -> None:
        role = _safe_text(value, "")
        if not role:
            return
        key = role.lower()
        if key in seen:
            return
        if key in {"authorization", "bearer", "token", "secret", "password", "cookie"}:
            return
        seen.add(key)
        roles.append(role)

    for item in role_models or []:
        if isinstance(item, dict):
            _add_role(item.get("role") or item.get("name") or item.get("label"))
        else:
            _add_role(item)

    for hint in offline_hints or []:
        raw = hint.get("roles") or hint.get("role_models")
        if isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, dict):
                    _add_role(entry.get("role") or entry.get("name"))
                else:
                    _add_role(entry)
        elif isinstance(raw, str):
            for part in re.split(r"[,|;/\s]+", raw):
                _add_role(part)

    for seed in seeds:
        raw = seed.get("roles")
        if isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, dict):
                    _add_role(entry.get("role") or entry.get("name"))
                else:
                    _add_role(entry)

    families = {
        (_safe_text(s.get("family") or s.get("vuln_type"), "")).lower() for s in seeds
    }
    if any(f in families for f in {"authorization", "authz", "idor", "bola", "bfla"}):
        for default in ("owner", "member", "admin"):
            _add_role(default)
    if any(
        f in families
        for f in {"ssrf", "path_traversal", "path", "injection", "mass_assignment"}
    ):
        for default in ("authenticated_user", "service_role"):
            _add_role(default)

    return roles[:_MAX_ROLES]


def _seed_key(seed: dict[str, Any]) -> str:
    return "|".join(
        [
            str(seed.get("hypothesis_id") or "").strip().lower(),
            str(seed.get("vuln_type") or "").strip().lower(),
            str(seed.get("location") or "").strip().lower()[:120],
            str(seed.get("origin") or "").strip().lower(),
        ]
    )


def _build_permission_models(
    *,
    seeds: list[dict[str, Any]],
    roles: list[str],
) -> list[PermissionModelPlan]:
    models: list[PermissionModelPlan] = []
    if roles or seeds:
        family = ""
        if seeds:
            family = _safe_text(seeds[0].get("family") or seeds[0].get("vuln_type"), "")
        models.append(
            PermissionModelPlan(
                model_id="PM-001",
                status="modeled_from_seeds" if roles else "not_enough_role_evidence",
                roles=list(roles),
                ownership_checks=[
                    "object_owner_equals_caller_or_explicit_share",
                    "role_bound_before_sensitive_mutation",
                    "fail_closed_when_role_missing",
                ],
                trust_boundaries=[
                    "controller_or_route_entry",
                    "auth_middleware",
                    "service_authorization",
                    "dao_or_repository_filter",
                ],
                assumptions=[
                    "test_account_labels_are_not_credentials",
                    "role_boundaries_require_human_confirmation",
                    "permission_model_is_plan_only_not_runtime",
                ],
                missing_evidence=[
                    "explicit_role_matrix_in_local_code",
                    "ownership_predicate_at_object_access",
                    "middleware_order_relative_to_handler",
                ],
                refutation_questions=[
                    "Which role can reach the sensitive object without ownership?",
                    "Is authorization enforced before or after object load?",
                    "What local evidence shows fail-closed behavior for missing role?",
                ],
                safe_next_step=(
                    "map role/ownership checks offline in authorized local code only"
                ),
                origin=f"family:{family or 'mixed'}",
                execution_allowed=False,
                human_review_required=True,
            )
        )
    return models


def _build_paths(
    *,
    seeds: list[dict[str, Any]],
    permission_models: list[PermissionModelPlan],
) -> list[CrossFileReasoningPath]:
    paths: list[CrossFileReasoningPath] = []
    model_id = permission_models[0].model_id if permission_models else ""
    for index, seed in enumerate(seeds, start=1):
        if len(paths) >= _MAX_PATHS:
            break
        hyp_id = _safe_text(seed.get("hypothesis_id"), f"H-{index:03d}")
        vuln_type = _safe_text(seed.get("vuln_type"), "unknown")
        location = _safe_text(seed.get("location"), "unknown")
        family = _safe_text(seed.get("family") or vuln_type, vuln_type)
        origin = _safe_text(seed.get("origin"), "hypothesis")
        layers = _layer_plans(
            seed=seed,
            path_index=index,
            hyp_id=hyp_id,
            vuln_type=vuln_type,
            location=location,
        )
        summary = _safe_text(
            seed.get("path_summary") or seed.get("chain_summary"),
            (
                f"{vuln_type} cross-file path from `{location}` "
                "(controller->service->dao) needs permission boundary evidence."
            ),
        )
        invariant = _broken_invariant(vuln_type=vuln_type, family=family)
        evidence = [
            "controller_or_route_handler_trace",
            "auth_middleware_or_permission_guard",
            "service_layer_authorization_or_ownership",
            "dao_or_repository_filter_or_scope",
            "impact_without_real_user_data",
            "human_review_decision",
        ][:_MAX_EVIDENCE]
        questions = [
            f"Does path for {hyp_id} keep authz before object access offline?",
            f"Which layer for family={family} already holds a guard?",
            "What local code/trace evidence would refute missing permission checks?",
        ][:_MAX_QUESTIONS]
        outline = [
            "Map controller -> middleware -> service -> DAO offline.",
            "Sketch role/ownership model without credentials.",
            "Collect only authorized local code/trace evidence.",
            "Refute or hold path; never exploit or promote.",
        ]
        status = (
            "unverified_hypothesis_from_confirmed_finding"
            if origin == "confirmed_finding_seed"
            else "planned_unverified_path"
        )
        paths.append(
            CrossFileReasoningPath(
                path_id=f"DCR-{index:03d}",
                source_hypothesis_id=hyp_id,
                family=family,
                vuln_type=vuln_type,
                seed_location=location,
                path_summary=summary,
                layers=layers,
                broken_invariant=invariant,
                required_evidence=evidence,
                refutation_questions=questions,
                permission_model_id=model_id,
                safe_validation_outline=outline,
                safe_next_step=(
                    "refute cross-file path offline with local code/trace evidence "
                    "before any validation plan"
                ),
                status=status,
                origin=origin,
                execution_allowed=False,
                human_review_required=True,
            )
        )
    return paths


def _layer_plans(
    *,
    seed: dict[str, Any],
    path_index: int,
    hyp_id: str,
    vuln_type: str,
    location: str,
) -> list[CrossFilePathLayer]:
    raw_layers = seed.get("layers") or seed.get("stages")
    names: list[str] = []
    if isinstance(raw_layers, list) and raw_layers:
        for item in raw_layers:
            if isinstance(item, dict):
                name = _safe_text(
                    item.get("name")
                    or item.get("layer")
                    or item.get("stage")
                    or item.get("stage_id"),
                    "",
                )
            else:
                name = _safe_text(item, "")
            if name:
                names.append(name)
            if len(names) >= _MAX_LAYERS:
                break
    if not names:
        names = _default_layers(vuln_type)

    layers: list[CrossFilePathLayer] = []
    for l_index, name in enumerate(names, start=1):
        layer_id = f"DCR-{path_index:03d}-L{l_index:02d}"
        purpose = _layer_purpose(name=name, vuln_type=vuln_type, location=location)
        evidence = _layer_evidence(name=name)
        question = (
            f"At layer `{name}` for {hyp_id}, what local evidence holds or refutes "
            f"the {vuln_type} permission boundary?"
        )
        layers.append(
            CrossFilePathLayer(
                layer_id=layer_id,
                name=name,
                purpose=purpose,
                evidence_needed=evidence,
                refutation_question=question,
                safe_next_step="review authorized local code/trace only",
                execution_allowed=False,
                human_review_required=True,
            )
        )
    return layers


def _default_layers(vuln_type: str) -> list[str]:
    vt = (vuln_type or "").strip().lower()
    if vt in {"authorization", "authz", "idor", "bola", "bfla"}:
        return [
            "controller_or_route",
            "auth_middleware",
            "service_ownership_check",
            "dao_or_repository",
            "object_or_resource",
        ]
    if vt in {"ssrf"}:
        return [
            "controller_or_route",
            "url_parser",
            "allowlist_or_network_policy",
            "http_client_or_fetcher",
            "egress_boundary",
        ]
    if vt in {"path_traversal", "path", "lfi"}:
        return [
            "controller_or_route",
            "path_normalizer",
            "root_jail_or_allowlist",
            "filesystem_open",
            "object_or_resource",
        ]
    if vt in {"mass_assignment", "mass"}:
        return [
            "controller_or_route",
            "request_deserializer",
            "field_allowlist",
            "service_or_use_case",
            "persistence_layer",
        ]
    if vt in {"injection", "sqli", "xss", "command_injection"}:
        return [
            "controller_or_route",
            "input_validation",
            "query_or_template_builder",
            "sink_adapter",
            "data_store_or_renderer",
        ]
    return list(_DEFAULT_LAYERS)


def _layer_purpose(*, name: str, vuln_type: str, location: str) -> str:
    n = (name or "").lower()
    if "controller" in n or "route" in n:
        return f"Locate entry handler near `{location}` for {vuln_type}."
    if "auth" in n or "middleware" in n or "permission" in n:
        return f"Check whether authz/permission guard runs before {vuln_type} sink."
    if "service" in n or "use_case" in n or "ownership" in n:
        return "Map service-layer ownership/authorization predicate offline."
    if "dao" in n or "repository" in n or "persistence" in n:
        return "Confirm repository filter/scope cannot be skipped by caller."
    if "allowlist" in n or "normalizer" in n or "policy" in n:
        return f"Inspect boundary control relevant to {vuln_type}."
    if "sink" in n or "open" in n or "client" in n or "fetcher" in n:
        return f"Trace sink/adapter boundary for {vuln_type} without executing it."
    return f"Review layer `{name}` for {vuln_type} with local evidence only."


def _layer_evidence(name: str) -> list[str]:
    n = (name or "").lower()
    if "controller" in n or "route" in n:
        return ["handler_signature", "route_params", "caller_identity_source"]
    if "auth" in n or "middleware" in n:
        return ["middleware_order", "role_claim_check", "fail_closed_branch"]
    if "service" in n or "ownership" in n:
        return ["ownership_predicate", "role_gate", "error_on_mismatch"]
    if "dao" in n or "repository" in n:
        return ["query_scope", "tenant_or_owner_filter", "bypass_paths"]
    return ["local_code_span", "boundary_assertion", "human_review_note"]


def _broken_invariant(*, vuln_type: str, family: str) -> str:
    key = (family or vuln_type or "").strip().lower()
    if key in {"authorization", "authz", "idor", "bola", "bfla"}:
        return "Every sensitive object access must be constrained by role and ownership checks."
    if key in {"ssrf"}:
        return "User-controlled URLs must not reach network clients without allowlist/egress policy."
    if key in {"path_traversal", "path", "lfi"}:
        return "User-controlled paths must stay inside an authorized root jail."
    if key in {"mass_assignment", "mass"}:
        return "Untrusted fields must not bind into privileged model attributes."
    if key in {"injection", "sqli", "xss", "command_injection"}:
        return "User-controlled input must not reach a sink without structured validation."
    return "Every promoted finding needs a local evidence trace and an explicit refutation attempt."


def _global_human_questions(
    paths: list[CrossFileReasoningPath],
    models: list[PermissionModelPlan],
) -> list[str]:
    questions = [
        "Are permission models based only on authorized local artifacts?",
        "Which cross-file layer already holds a failing-closed guard?",
        "What local evidence would refute missing ownership/role checks?",
    ]
    if models and models[0].roles:
        questions.append(
            f"Do roles {', '.join(models[0].roles[:5])} match real product roles offline?"
        )
    for path in paths[:3]:
        questions.append(
            f"What evidence would break path {path.path_id} "
            f"({path.family or path.vuln_type}) before validation?"
        )
    return questions[:_MAX_QUESTIONS]


def _maybe_write_exports(
    plan: DeepCodeReasoningPlan,
    *,
    root: Path | None,
    human_allow_export_write: bool,
) -> DeepCodeReasoningPlan:
    if not human_allow_export_write:
        return plan
    if root is None or not root.is_dir():
        return _rebuild_plan(
            plan,
            notes=list(plan.notes) + ["export_skipped_no_package_root"],
        )
    if not plan.paths and not plan.permission_models:
        return _rebuild_plan(
            plan,
            notes=list(plan.notes) + ["export_skipped_no_paths_or_models"],
        )

    export_root = root / "_export" / "deep_code_reasoning"
    export_root.mkdir(parents=True, exist_ok=True)
    written_paths: list[CrossFileReasoningPath] = []
    export_count = 0

    if plan.permission_models:
        pm_dir = export_root / "permission_models"
        pm_dir.mkdir(parents=True, exist_ok=True)
        for model in plan.permission_models:
            slug = _slug(model.model_id)
            target = pm_dir / f"{slug}.json"
            target.write_text(
                json.dumps(model.to_dict(), indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            export_count += 1
        (pm_dir / "README.md").write_text(
            (
                "# Permission model plans (export only)\n\n"
                "- Plan sketches only; not credentials and not runtime enforcement.\n"
                "- Never exploit, promote, submit, or live-validate from these files.\n"
            ),
            encoding="utf-8",
        )
        export_count += 1

    for path_item in plan.paths:
        slug = _slug(path_item.path_id or path_item.source_hypothesis_id or "path")
        target_dir = export_root / slug
        target_dir.mkdir(parents=True, exist_ok=True)
        rel = f"_export/deep_code_reasoning/{slug}"
        meta = {
            "path_id": path_item.path_id,
            "source_hypothesis_id": path_item.source_hypothesis_id,
            "package_id": plan.package_id,
            "family": path_item.family,
            "vuln_type": path_item.vuln_type,
            "seed_location": path_item.seed_location,
            "layer_count": len(path_item.layers),
            "permission_model_id": path_item.permission_model_id,
            "origin": path_item.origin,
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
        (target_dir / "path_plan.md").write_text(
            _render_path_md(path_item, package_id=plan.package_id),
            encoding="utf-8",
        )
        (target_dir / "README.md").write_text(
            _render_readme(path_item, package_id=plan.package_id, export_dir=rel),
            encoding="utf-8",
        )
        export_count += 3
        written_paths.append(
            CrossFileReasoningPath(
                path_id=path_item.path_id,
                source_hypothesis_id=path_item.source_hypothesis_id,
                family=path_item.family,
                vuln_type=path_item.vuln_type,
                seed_location=path_item.seed_location,
                path_summary=path_item.path_summary,
                layers=list(path_item.layers),
                broken_invariant=path_item.broken_invariant,
                required_evidence=list(path_item.required_evidence),
                refutation_questions=list(path_item.refutation_questions),
                permission_model_id=path_item.permission_model_id,
                safe_validation_outline=list(path_item.safe_validation_outline),
                safe_next_step=path_item.safe_next_step,
                status="exported",
                origin=path_item.origin,
                export_relative_path=rel,
                written=True,
                execution_allowed=False,
                human_review_required=True,
            )
        )

    index = {
        "package_id": plan.package_id,
        "status": STATUS_WRITTEN,
        "path_count": len(written_paths),
        "permission_model_count": len(plan.permission_models),
        "export_count": export_count,
        "execution_allowed": False,
        "validation_allowed": False,
        "report_submission_allowed": False,
        "confirmed_vulnerability": False,
        "finding_promotion_allowed": False,
        "network_access": False,
        "live_validation": False,
        "process_spawn_allowed": False,
        "paths": [
            {
                "path_id": p.path_id,
                "source_hypothesis_id": p.source_hypothesis_id,
                "export_relative_path": p.export_relative_path,
                "family": p.family,
            }
            for p in written_paths
        ],
        "permission_models": [m.model_id for m in plan.permission_models],
        "safety_invariants": list(SAFETY_INVARIANTS),
    }
    (export_root / "index.json").write_text(
        json.dumps(index, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    export_count += 1

    return _rebuild_plan(
        plan,
        paths=written_paths if written_paths else list(plan.paths),
        status=STATUS_WRITTEN,
        export_written=True,
        export_count=export_count,
        human_allow_export_write=True,
        notes=list(plan.notes)
        + [f"export_written={export_count}", f"export_root={export_root}"],
        next_allowed_action=(
            "Human reviews exported permission/cross-file plans offline; "
            "refute with local evidence; never exploit or promote."
        ),
    )


def _render_path_md(path_item: CrossFileReasoningPath, *, package_id: str) -> str:
    layers = "\n".join(
        f"- `{layer.layer_id}` **{layer.name}**: {layer.purpose}"
        for layer in path_item.layers
    ) or "- (no layers)"
    evidence = "\n".join(f"- {item}" for item in path_item.required_evidence) or "- (none)"
    questions = (
        "\n".join(f"- {item}" for item in path_item.refutation_questions) or "- (none)"
    )
    outline = (
        "\n".join(f"- {item}" for item in path_item.safe_validation_outline) or "- (none)"
    )
    return (
        f"# Deep Code Reasoning Path\n\n"
        f"- package_id: `{package_id}`\n"
        f"- path_id: `{path_item.path_id}`\n"
        f"- source_hypothesis_id: `{path_item.source_hypothesis_id}`\n"
        f"- family: `{path_item.family}`\n"
        f"- vuln_type: `{path_item.vuln_type}`\n"
        f"- seed_location: `{path_item.seed_location}`\n"
        f"- permission_model_id: `{path_item.permission_model_id}`\n"
        f"- origin: `{path_item.origin}`\n"
        f"- status: `{path_item.status}`\n\n"
        f"## Summary\n\n"
        f"{path_item.path_summary}\n\n"
        f"## Broken invariant (hypothesis)\n\n"
        f"{path_item.broken_invariant}\n\n"
        f"## Layers (plan only)\n\n"
        f"{layers}\n\n"
        f"## Required evidence\n\n"
        f"{evidence}\n\n"
        f"## Refutation questions\n\n"
        f"{questions}\n\n"
        f"## Safe validation outline (plan only)\n\n"
        f"{outline}\n\n"
        f"## Safe next step\n\n"
        f"{path_item.safe_next_step}\n\n"
        f"## Safety\n\n"
        f"- Plan/export only. Never exploit, promote, submit, or live-validate.\n"
        f"- Unverified reasoning paths are never confirmed vulnerabilities.\n"
    )


def _render_readme(
    path_item: CrossFileReasoningPath, *, package_id: str, export_dir: str
) -> str:
    return (
        f"# Deep Code Reasoning Export\n\n"
        f"- package_id: `{package_id}`\n"
        f"- path_id: `{path_item.path_id}`\n"
        f"- export_dir: `{export_dir}`\n"
        f"- source_hypothesis_id: `{path_item.source_hypothesis_id}`\n\n"
        f"## Safety\n\n"
        f"- Plan/export only.\n"
        f"- Never exploit, promote, submit, or live-validate.\n"
        f"- Human review required before any further action.\n"
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
) -> DeepCodeReasoningPlan:
    plan = DeepCodeReasoningPlan(
        stage="v4_deep_code_reasoning",
        inspirations=[
            "Deep Code Reasoning",
            "Mythos permission + cross-file reasoning",
            "deep_research_nested_permission_crossfile_stub_superseded",
        ],
        execution_mode="plan_only",
        status=status,
        package_id=package_id,
        package_root=package_root,
        permission_models=[],
        paths=[],
        path_count=0,
        permission_model_count=0,
        seed_count=0,
        offline_hint_count=offline_hint_count,
        bridge_seed_count=bridge_seed_count,
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
        export_root_relative="_export/deep_code_reasoning",
        safety_invariants=list(SAFETY_INVARIANTS),
        next_allowed_action=(
            "Provide hypotheses/retained drafts/offline reasoning hints, then rebuild plan."
        ),
        notes=list(notes or []),
        human_questions=[],
    )
    return _force_safety_plan(plan)


def _rebuild_plan(
    plan: DeepCodeReasoningPlan,
    *,
    paths: list[CrossFileReasoningPath] | None = None,
    status: str | None = None,
    export_written: bool | None = None,
    export_count: int | None = None,
    human_allow_export_write: bool | None = None,
    notes: list[str] | None = None,
    next_allowed_action: str | None = None,
) -> DeepCodeReasoningPlan:
    rebuilt = DeepCodeReasoningPlan(
        stage=plan.stage,
        inspirations=list(plan.inspirations),
        execution_mode="plan_only",
        status=status if status is not None else plan.status,
        package_id=plan.package_id,
        package_root=plan.package_root,
        permission_models=list(plan.permission_models),
        paths=list(paths) if paths is not None else list(plan.paths),
        path_count=len(paths) if paths is not None else plan.path_count,
        permission_model_count=len(plan.permission_models),
        seed_count=plan.seed_count,
        offline_hint_count=plan.offline_hint_count,
        bridge_seed_count=plan.bridge_seed_count,
        family_counts=dict(plan.family_counts),
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
            int(export_count) if export_count is not None else int(plan.export_count or 0)
        ),
        export_root_relative=plan.export_root_relative or "_export/deep_code_reasoning",
        safety_invariants=list(SAFETY_INVARIANTS),
        next_allowed_action=next_allowed_action or plan.next_allowed_action,
        notes=list(notes) if notes is not None else list(plan.notes),
        human_questions=list(plan.human_questions),
    )
    return _force_safety_plan(rebuilt)


def _slug(value: str) -> str:
    text = re.sub(r"[^a-zA-Z0-9._-]+", "-", (value or "").strip()).strip("-").lower()
    return (text or "item")[:80]


def _safe_text(value: Any, default: str) -> str:
    if not isinstance(value, str):
        if value is None:
            return default
        value = str(value)
    text = value.strip()
    if not text:
        return default
    lowered = text.lower()
    for marker in ("authorization: bearer", "bearer ", "password=", "cookie:", "secret="):
        if marker in lowered:
            return "[REDACTED]"
    return text[:180]


def _force_safety_plan(plan: DeepCodeReasoningPlan) -> DeepCodeReasoningPlan:
    return DeepCodeReasoningPlan(
        stage=plan.stage,
        inspirations=list(plan.inspirations),
        execution_mode="plan_only",
        status=plan.status,
        package_id=plan.package_id,
        package_root=plan.package_root,
        permission_models=[
            PermissionModelPlan(
                model_id=m.model_id,
                status=m.status,
                roles=list(m.roles),
                ownership_checks=list(m.ownership_checks),
                trust_boundaries=list(m.trust_boundaries),
                assumptions=list(m.assumptions),
                missing_evidence=list(m.missing_evidence),
                refutation_questions=list(m.refutation_questions),
                safe_next_step=m.safe_next_step,
                origin=m.origin,
                execution_allowed=False,
                human_review_required=True,
            )
            for m in plan.permission_models
        ],
        paths=[
            CrossFileReasoningPath(
                path_id=p.path_id,
                source_hypothesis_id=p.source_hypothesis_id,
                family=p.family,
                vuln_type=p.vuln_type,
                seed_location=p.seed_location,
                path_summary=p.path_summary,
                layers=[
                    CrossFilePathLayer(
                        layer_id=layer.layer_id,
                        name=layer.name,
                        purpose=layer.purpose,
                        evidence_needed=list(layer.evidence_needed),
                        refutation_question=layer.refutation_question,
                        safe_next_step=layer.safe_next_step,
                        execution_allowed=False,
                        human_review_required=True,
                    )
                    for layer in p.layers
                ],
                broken_invariant=p.broken_invariant,
                required_evidence=list(p.required_evidence),
                refutation_questions=list(p.refutation_questions),
                permission_model_id=p.permission_model_id,
                safe_validation_outline=list(p.safe_validation_outline),
                safe_next_step=p.safe_next_step,
                status=p.status,
                origin=p.origin,
                export_relative_path=p.export_relative_path,
                written=bool(p.written),
                execution_allowed=False,
                human_review_required=True,
            )
            for p in plan.paths
        ],
        path_count=len(plan.paths),
        permission_model_count=len(plan.permission_models),
        seed_count=plan.seed_count,
        offline_hint_count=plan.offline_hint_count,
        bridge_seed_count=plan.bridge_seed_count,
        family_counts=dict(plan.family_counts),
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
        export_root_relative=plan.export_root_relative or "_export/deep_code_reasoning",
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
        payload.get("export_root_relative") or "_export/deep_code_reasoning"
    )
    payload["safety_invariants"] = list(SAFETY_INVARIANTS)
    paths = payload.get("paths")
    if isinstance(paths, list):
        payload["path_count"] = len(paths)
        safe_paths: list[Any] = []
        for item in paths:
            if isinstance(item, dict):
                pitem = dict(item)
                pitem["execution_allowed"] = False
                pitem["human_review_required"] = True
                layers = pitem.get("layers")
                if isinstance(layers, list):
                    safe_layers = []
                    for layer in layers:
                        if isinstance(layer, dict):
                            s = dict(layer)
                            s["execution_allowed"] = False
                            s["human_review_required"] = True
                            safe_layers.append(s)
                        else:
                            safe_layers.append(layer)
                    pitem["layers"] = safe_layers
                safe_paths.append(pitem)
            else:
                safe_paths.append(item)
        payload["paths"] = safe_paths
    models = payload.get("permission_models")
    if isinstance(models, list):
        payload["permission_model_count"] = len(models)
        safe_models: list[Any] = []
        for item in models:
            if isinstance(item, dict):
                m = dict(item)
                m["execution_allowed"] = False
                m["human_review_required"] = True
                safe_models.append(m)
            else:
                safe_models.append(item)
        payload["permission_models"] = safe_models
    return payload


__all__ = [
    "STATUS_EMPTY",
    "STATUS_READY",
    "STATUS_SKIPPED",
    "STATUS_WAITING",
    "STATUS_WRITTEN",
    "DeepCodeReasoningError",
    "DeepCodeReasoningPlan",
    "PermissionModelPlan",
    "CrossFilePathLayer",
    "CrossFileReasoningPath",
    "attach_deep_code_reasoning_to_bridge_result",
    "build_deep_code_reasoning_plan",
    "load_package_deep_code_reasoning_plan",
]
