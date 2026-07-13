"""Knowledge Base — structured vulnerability pattern consolidation (final-scheme §7 / V4).

Lawful research only:
- Consolidate offline patterns + bridge-derived advisory patterns from residual stack
- Emit structured pattern cards (code signals, verify/fix/FP checks) — not free-text dumps
- Optional offline under package inputs/knowledge*.json or inputs/knowledge/
- Optional export under package _export/knowledge_base/ with human flag
- Never grants ranking execution permission, never auto-learns live internet data
- Never stores raw secrets, cookies, tokens, or real user data
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

STATUS_READY = "knowledge_base_ready"
STATUS_EMPTY = "knowledge_base_empty"
STATUS_PACKAGE_MISSING = "knowledge_base_package_missing"
STATUS_WRITTEN = "knowledge_base_export_written"
STATUS_WAITING = "knowledge_base_waiting_for_signals"

SAFETY_INVARIANTS = [
    "authorized_package_or_bridge_only",
    "no_public_target_scanning",
    "no_network_access",
    "no_raw_secrets_or_user_data",
    "no_automatic_report_submission",
    "no_finding_promotion",
    "advisory_pattern_catalog_only",
    "never_grants_ranking_execution_permission",
    "human_review_required_before_pattern_promotion",
    "no_export_write_without_human_flag",
    "structured_patterns_not_unstructured_dumps",
]

_SECRET_HINTS = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|session|bearer|private[_-]?key|ssh-rsa|BEGIN [A-Z ]*PRIVATE)"
)
_MAX_PATTERNS = 48
_MAX_LIST = 12

_CWE_HINTS = {
    "ssrf": "CWE-918",
    "authorization": "CWE-639",
    "bola": "CWE-639",
    "idor": "CWE-639",
    "authz": "CWE-862",
    "path_traversal": "CWE-22",
    "mass_assignment": "CWE-915",
    "injection": "CWE-89",
    "sqli": "CWE-89",
    "xss": "CWE-79",
    "rce": "CWE-94",
    "deserialization": "CWE-502",
    "upload": "CWE-434",
    "race": "CWE-362",
}


class KnowledgeBaseError(ValueError):
    """Raised when bridge attach receives invalid input."""


@dataclass(frozen=True)
class KnowledgePattern:
    pattern_id: str
    name: str
    category: str
    cwe: str = ""
    applies_to: list[str] = field(default_factory=list)
    code_signals: list[str] = field(default_factory=list)
    verification_strategy: list[str] = field(default_factory=list)
    fix_strategy: list[str] = field(default_factory=list)
    false_positive_checks: list[str] = field(default_factory=list)
    source_refs: list[str] = field(default_factory=list)
    confidence: str = "low"
    human_review_required: bool = True
    execution_allowed: bool = False
    notes: list[str] = field(default_factory=list)


@dataclass
class KnowledgeBaseResult:
    stage: str
    inspirations: list[str]
    execution_mode: str
    status: str
    package_id: str = ""
    package_root: str = ""
    patterns: list[KnowledgePattern] = field(default_factory=list)
    pattern_count: int = 0
    offline_artifact_count: int = 0
    derived_pattern_count: int = 0
    deep_research_status: str = ""
    agent_memory_status: str = ""
    long_horizon_status: str = ""
    human_allow_export_write: bool = False
    export_written: bool = False
    export_count: int = 0
    export_root_relative: str = "_export/knowledge_base"
    run_stamp: str = ""
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    ranking_permission_granted: bool = False
    auto_learn_live_sources: bool = False
    network_access: bool = False
    live_validation: bool = False
    safety_invariants: list[str] = field(default_factory=list)
    next_allowed_action: str = (
        "Human reviews structured patterns offline; never auto-promote or grant ranking execution."
    )
    notes: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _force_safety_dict(asdict(self))

def build_knowledge_base(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    bridge_result: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> KnowledgeBaseResult:
    return run_knowledge_base(
        package_root=package_root,
        package_id=package_id,
        bridge_result=bridge_result,
        human_allow_export_write=human_allow_export_write,
    )


def run_knowledge_base(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    bridge_result: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> KnowledgeBaseResult:
    """Build advisory structured knowledge patterns for an authorized package."""
    root: Path | None = None
    root_s = ""
    if package_root is not None and str(package_root).strip():
        root = Path(package_root)
        root_s = str(root)
        if not root.is_dir():
            return _empty(
                status=STATUS_PACKAGE_MISSING,
                package_id=package_id,
                package_root=root_s,
                notes=["package_root_missing_or_not_directory"],
                human_allow_export_write=bool(human_allow_export_write),
            )

    bridge = bridge_result if isinstance(bridge_result, dict) else {}
    pid = package_id or str(bridge.get("package_id") or "")
    offline_patterns, offline_n = _load_offline_patterns(root)
    derived = _derive_from_bridge(bridge)
    patterns = _merge_patterns(offline_patterns + derived)

    dres = bridge.get("deep_research") if isinstance(bridge.get("deep_research"), dict) else {}
    amem = bridge.get("agent_memory") if isinstance(bridge.get("agent_memory"), dict) else {}
    lh = bridge.get("long_horizon") if isinstance(bridge.get("long_horizon"), dict) else {}
    dres_status = str(bridge.get("deep_research_status") or dres.get("status") or "")
    amem_status = str(bridge.get("agent_memory_status") or amem.get("status") or "")
    lh_status = str(bridge.get("long_horizon_status") or lh.get("status") or "")

    notes = [
        "advisory_structured_patterns_only",
        "never_grants_ranking_execution_permission",
        "never_auto_learns_live_internet_sources",
        "human_review_required_before_pattern_promotion",
        "authorized_package_or_bridge_only",
        "final_scheme_section_7_knowledge_format",
    ]
    if offline_n:
        notes.append(f"offline_artifacts={offline_n}")

    has_signal = bool(patterns)
    if not has_signal:
        status = STATUS_WAITING if bridge else STATUS_EMPTY
    else:
        status = STATUS_READY

    result = KnowledgeBaseResult(
        stage="v4_knowledge_base_consolidation",
        inspirations=["final-scheme-section-7", "Mythos", "MDASH"],
        execution_mode="advisory_pattern_catalog_only",
        status=status,
        package_id=pid,
        package_root=root_s,
        patterns=patterns,
        pattern_count=len(patterns),
        offline_artifact_count=offline_n,
        derived_pattern_count=len(derived),
        deep_research_status=dres_status,
        agent_memory_status=amem_status,
        long_horizon_status=lh_status,
        human_allow_export_write=bool(human_allow_export_write),
        safety_invariants=list(SAFETY_INVARIANTS),
        notes=notes,
        summary=(
            f"patterns={len(patterns)} offline={offline_n} derived={len(derived)} "
            f"dres={dres_status or '-'} amem={amem_status or '-'} lh={lh_status or '-'}"
        ),
    )
    result = _force_safety(result)

    if human_allow_export_write and root is not None:
        written, count, stamp = _export_catalog(root, result)
        if written:
            result.export_written = True
            result.export_count = count
            result.run_stamp = stamp
            result.status = STATUS_WRITTEN
            result.notes = list(result.notes) + ["export_written_under_package"]
            result = _force_safety(result)
        else:
            result.notes = list(result.notes) + ["export_skipped_or_failed_still_advisory"]
            result = _force_safety(result)
    elif human_allow_export_write and root is None:
        result.notes = list(result.notes) + ["export_requested_but_no_package_root"]
        result = _force_safety(result)

    return _force_safety(result)


def attach_knowledge_base_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    knowledge_base: dict[str, Any] | KnowledgeBaseResult | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    """Attach knowledge-base catalog; never unlocks execute/submit/promote/ranking."""
    if not isinstance(bridge_result, dict):
        raise KnowledgeBaseError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")

    if isinstance(knowledge_base, KnowledgeBaseResult):
        payload = knowledge_base.to_dict()
    elif isinstance(knowledge_base, dict):
        payload = _force_safety_dict(dict(knowledge_base))
    else:
        payload = run_knowledge_base(
            package_root=resolved_root,
            package_id=package_id,
            bridge_result=bridge_result,
            human_allow_export_write=bool(human_allow_export_write),
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["knowledge_base"] = payload
    out["knowledge_base_present"] = True
    out["knowledge_base_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["knowledge_base_pattern_count"] = int(payload.get("pattern_count") or 0)
    out["knowledge_base_offline_artifact_count"] = int(payload.get("offline_artifact_count") or 0)
    out["knowledge_base_derived_pattern_count"] = int(payload.get("derived_pattern_count") or 0)
    out["knowledge_base_export_written"] = bool(payload.get("export_written"))
    out["knowledge_base_ranking_permission_granted"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out

def _load_offline_patterns(root: Path | None) -> tuple[list[KnowledgePattern], int]:
    if root is None:
        return [], 0
    paths: list[Path] = []
    candidates = [
        root / "inputs" / "knowledge_base.json",
        root / "inputs" / "knowledge.json",
        root / "inputs" / "v4_knowledge.json",
        root / "inputs" / "patterns.json",
    ]
    know_dir = root / "inputs" / "knowledge"
    if know_dir.is_dir():
        paths.extend(sorted(know_dir.glob("*.json")))
    pat_dir = root / "inputs" / "patterns"
    if pat_dir.is_dir():
        paths.extend(sorted(pat_dir.glob("*.json")))
    for p in candidates:
        if p.is_file():
            paths.append(p)

    patterns: list[KnowledgePattern] = []
    artifact_n = 0
    seen_paths: set[str] = set()
    for path in paths:
        key = str(path.resolve()) if path.exists() else str(path)
        if key in seen_paths:
            continue
        seen_paths.add(key)
        if not path.is_file():
            continue
        if _SECRET_HINTS.search(path.name):
            continue
        artifact_n += 1
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        items: list[Any]
        if isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            if isinstance(raw.get("patterns"), list):
                items = raw["patterns"]
            elif isinstance(raw.get("entries"), list):
                items = raw["entries"]
            elif isinstance(raw.get("knowledge_patterns"), list):
                items = raw["knowledge_patterns"]
            else:
                items = [raw]
        else:
            continue
        try:
            rel = path.relative_to(root).as_posix()
            src = f"file:{rel}"
        except Exception:
            src = f"file:{path.name}"
        for i, item in enumerate(items, start=1):
            if not isinstance(item, dict):
                continue
            pat = _pattern_from_dict(item, default_id=f"offline-{path.stem}-{i}", source_ref=src)
            if pat is not None:
                patterns.append(pat)
            if len(patterns) >= _MAX_PATTERNS:
                break
        if len(patterns) >= _MAX_PATTERNS:
            break
    return patterns[:_MAX_PATTERNS], artifact_n


def _pattern_from_dict(
    item: dict[str, Any],
    *,
    default_id: str,
    source_ref: str,
) -> KnowledgePattern | None:
    pid = _scrub_text(str(item.get("pattern_id") or item.get("id") or default_id))[:80]
    name = _scrub_text(str(item.get("name") or item.get("title") or item.get("topic") or pid))[:160]
    category = _scrub_text(
        str(item.get("category") or item.get("vuln_type") or item.get("kind") or "generic")
    )[:80].lower()
    if not pid or not name:
        return None
    cwe = _scrub_text(str(item.get("cwe") or _cwe_for(category)))[:40]
    applies = _str_list(item.get("applies_to") or item.get("applies") or [])
    code_signals = _str_list(
        item.get("code_signals") or item.get("signals") or item.get("retained_fields") or []
    )
    verify = _str_list(
        item.get("verification_strategy") or item.get("verify") or item.get("verification") or []
    )
    fix = _str_list(item.get("fix_strategy") or item.get("fix") or item.get("remediation") or [])
    fp = _str_list(item.get("false_positive_checks") or item.get("fp_checks") or [])
    sources = _str_list(item.get("source_refs") or [])
    if source_ref and source_ref not in sources:
        sources = [source_ref] + sources
    conf = str(item.get("confidence") or "low").lower()
    if conf not in {"low", "medium", "high"}:
        conf = "low"
    return KnowledgePattern(
        pattern_id=pid,
        name=name,
        category=category or "generic",
        cwe=cwe,
        applies_to=applies[:_MAX_LIST],
        code_signals=code_signals[:_MAX_LIST] or ["human_must_confirm_local_code_signals"],
        verification_strategy=verify[:_MAX_LIST]
        or ["local_static_trace_only", "require_human_review_before_any_validation"],
        fix_strategy=fix[:_MAX_LIST]
        or [
            "enforce_control_in_shared_service_layer",
            "add_regression_test",
            "avoid_frontend_only_checks",
        ],
        false_positive_checks=fp[:_MAX_LIST]
        or [
            "control may exist in middleware",
            "object may be intentionally public",
            "admin role may be allowed",
        ],
        source_refs=sources[:_MAX_LIST],
        confidence=conf,
        human_review_required=True,
        execution_allowed=False,
        notes=["offline_or_explicit_pattern"],
    )

def _derive_from_bridge(bridge: dict[str, Any]) -> list[KnowledgePattern]:
    patterns: list[KnowledgePattern] = []
    seen_cats: set[str] = set()

    drafts = bridge.get("drafts") if isinstance(bridge.get("drafts"), list) else []
    for draft in drafts:
        if not isinstance(draft, dict):
            continue
        cid = str(draft.get("candidate_id") or "")
        vtype = str(draft.get("vuln_type") or draft.get("route") or "generic").lower()
        root = str(draft.get("root_cause_id") or "")
        cat = _normalize_category(vtype)
        if cat in seen_cats and not cid:
            continue
        seen_cats.add(cat)
        patterns.append(
            _seed_pattern(
                pattern_id=f"KB-draft-{cid or cat}"[:80],
                name=f"{cat} candidate pattern from draft",
                category=cat,
                source_refs=[f"bridge:draft:{cid or root or cat}"],
                code_signals=_default_code_signals(cat),
                notes=["derived_from_draft"],
            )
        )

    gates = bridge.get("human_residual_gates") if isinstance(bridge.get("human_residual_gates"), list) else []
    for gate in gates:
        if not isinstance(gate, dict):
            continue
        status = str(gate.get("status") or "").lower()
        cid = str(gate.get("candidate_id") or "")
        vtype = str(gate.get("vuln_type") or "generic").lower()
        cat = _normalize_category(vtype)
        if status in {"human_rejected_or_fp", "rejected", "false_positive"}:
            patterns.append(
                _seed_pattern(
                    pattern_id=f"KB-fp-{cid or cat}"[:80],
                    name=f"FP pressure pattern for {cat}",
                    category=cat,
                    source_refs=[f"bridge:residual_gate:{cid or cat}"],
                    code_signals=["prior_human_rejected_or_fp_disposition"],
                    false_positive_checks=[
                        "reconfirm control path still present on re-audit",
                        "confirm intentional public object if IDOR-like",
                        "confirm middleware ownership still holds",
                    ],
                    verification_strategy=[
                        "do_not_reopen_without_new_authorized_evidence",
                        "human_review_required",
                    ],
                    notes=["derived_from_residual_fp_gate"],
                    confidence="medium",
                )
            )
        elif status in {"ready_for_human_review", "held", "waiting_for_evidence"}:
            patterns.append(
                _seed_pattern(
                    pattern_id=f"KB-gate-{cid or cat}"[:80],
                    name=f"Residual-gated {cat} review pattern",
                    category=cat,
                    source_refs=[f"bridge:residual_gate:{cid or cat}"],
                    notes=["derived_from_residual_gate"],
                )
            )

    dres = bridge.get("deep_research") if isinstance(bridge.get("deep_research"), dict) else {}
    plan = dres.get("plan") if isinstance(dres.get("plan"), dict) else {}
    for ku in plan.get("knowledge_updates") or []:
        if not isinstance(ku, dict):
            continue
        topic = str(ku.get("topic") or "generic")
        cat = _normalize_category(topic.split(":")[0])
        retained = _str_list(ku.get("retained_fields") or [])
        patterns.append(
            _seed_pattern(
                pattern_id=f"KB-dres-{ku.get('source_ref') or topic}"[:80],
                name=f"Deep-research knowledge: {topic}"[:160],
                category=cat,
                source_refs=[f"deep_research:{ku.get('source_ref') or topic}"],
                code_signals=retained or _default_code_signals(cat),
                notes=["derived_from_deep_research_knowledge_update"],
            )
        )
    for q in plan.get("knowledge_consolidation_queue") or []:
        if not isinstance(q, dict):
            continue
        topic = str(q.get("topic") or "generic")
        cat = _normalize_category(topic)
        retained = _str_list(q.get("retained_fields") or [])
        patterns.append(
            _seed_pattern(
                pattern_id=f"KB-queue-{q.get('source_ref') or topic}"[:80],
                name=f"Queued consolidation: {topic}"[:160],
                category=cat,
                source_refs=[f"deep_research_queue:{q.get('source_ref') or topic}"],
                code_signals=retained or _default_code_signals(cat),
                notes=["derived_from_deep_research_queue"],
            )
        )
    pdl = plan.get("patch_diff_learner") if isinstance(plan.get("patch_diff_learner"), dict) else {}
    for i, pat in enumerate(pdl.get("learned_patterns") or [], start=1):
        if not isinstance(pat, dict):
            continue
        src = str(pat.get("source_ref") or f"patch-{i}")
        patterns.append(
            _seed_pattern(
                pattern_id=f"KB-patchdiff-{src}"[:80],
                name=f"Patch-diff pattern {src}"[:160],
                category=_normalize_category(str(pat.get("vuln_type") or pat.get("category") or "generic")),
                source_refs=[f"patch_diff:{src}"],
                code_signals=_str_list(
                    [
                        pat.get("root_cause_summary") or "reviewed_patch_root_cause",
                        pat.get("fix_strategy") or "reviewed_fix_strategy",
                    ]
                ),
                fix_strategy=_str_list([pat.get("fix_strategy") or "shared_service_layer_control"]),
                verification_strategy=_str_list(
                    [pat.get("regression_test") or "add_regression_test_for_fixed_control"]
                ),
                notes=["derived_from_patch_diff_learner"],
                confidence="medium",
            )
        )
    for va in plan.get("variant_analysis") or []:
        if not isinstance(va, dict):
            continue
        vid = str(va.get("variant_id") or va.get("source_hypothesis_id") or "variant")
        patterns.append(
            _seed_pattern(
                pattern_id=f"KB-variant-{vid}"[:80],
                name=f"Variant search pattern {vid}"[:160],
                category=_normalize_category(str(va.get("search_pattern") or "generic")),
                source_refs=[f"variant:{vid}"],
                code_signals=_str_list([va.get("search_pattern") or "similar_boundary_near_sibling"]),
                verification_strategy=_str_list(
                    [va.get("safe_next_step") or "search authorized local code for comparable guards"]
                ),
                notes=["derived_from_variant_analysis"],
            )
        )

    amem = bridge.get("agent_memory") if isinstance(bridge.get("agent_memory"), dict) else {}
    for entry in amem.get("entries") or []:
        if not isinstance(entry, dict):
            continue
        kind = str(entry.get("kind") or "")
        if kind not in {"knowledge_pattern", "false_positive_pattern", "retain_signal"}:
            continue
        topic = str(entry.get("topic") or kind)
        cat = _normalize_category(topic)
        patterns.append(
            _seed_pattern(
                pattern_id=f"KB-amem-{entry.get('entry_id') or topic}"[:80],
                name=_scrub_text(str(entry.get("summary") or topic))[:160],
                category=cat,
                source_refs=[f"agent_memory:{entry.get('entry_id') or topic}"],
                code_signals=_str_list(entry.get("retained_fields") or entry.get("applies_to") or []),
                false_positive_checks=_str_list(entry.get("false_positive_checks") or []),
                notes=["derived_from_agent_memory"],
            )
        )

    lh = bridge.get("long_horizon") if isinstance(bridge.get("long_horizon"), dict) else {}
    for ref in lh.get("reflections") or []:
        if not isinstance(ref, dict):
            continue
        rid = str(ref.get("reflection_id") or "R")
        patterns.append(
            _seed_pattern(
                pattern_id=f"KB-lh-{rid}"[:80],
                name=f"Long-horizon reflection {rid}"[:160],
                category="research_process",
                source_refs=[f"long_horizon:{rid}"],
                code_signals=_str_list(
                    [
                        ref.get("trigger") or "failure_triggered_reflection",
                        ref.get("observation") or "path_switch_catalog_only",
                    ]
                ),
                verification_strategy=[
                    "human_reviews_planned_path_switch_offline",
                    "never_auto_execute_alternate_paths",
                ],
                fix_strategy=["update_research_path_catalog_after_human_review"],
                false_positive_checks=["do_not_treat_reflection_as_confirmed_vulnerability"],
                notes=["derived_from_long_horizon_reflection"],
            )
        )

    pvals = bridge.get("patch_validation") if isinstance(bridge.get("patch_validation"), dict) else {}
    if pvals and int(pvals.get("item_count") or bridge.get("patch_validation_item_count") or 0) > 0:
        patterns.append(
            _seed_pattern(
                pattern_id="KB-patch-validation-process",
                name="Non-destructive patch recheck process pattern",
                category="patch_process",
                source_refs=["bridge:patch_validation"],
                code_signals=["patch_validation_plan_present"],
                verification_strategy=[
                    "non_destructive_regression_recheck_only",
                    "never_live_validate_or_auto_pr",
                ],
                fix_strategy=["keep_patch_ready_false_until_human_accepts"],
                notes=["derived_from_patch_validation"],
            )
        )

    pid = str(bridge.get("package_id") or "")
    if pid:
        patterns.append(
            _seed_pattern(
                pattern_id=f"KB-scope-{pid}"[:80],
                name=f"Package-scoped knowledge boundary for {pid}",
                category="scope",
                source_refs=["bridge:package_id"],
                code_signals=["authorized_package_boundary"],
                verification_strategy=["never_apply_patterns_outside_authorized_package"],
                fix_strategy=["keep_pattern_applicability_local"],
                false_positive_checks=["do_not_generalize_to_public_targets"],
                notes=["package_scope_anchor"],
                confidence="high",
            )
        )

    return patterns[:_MAX_PATTERNS]

def _seed_pattern(
    *,
    pattern_id: str,
    name: str,
    category: str,
    source_refs: list[str],
    code_signals: list[str] | None = None,
    verification_strategy: list[str] | None = None,
    fix_strategy: list[str] | None = None,
    false_positive_checks: list[str] | None = None,
    notes: list[str] | None = None,
    confidence: str = "low",
) -> KnowledgePattern:
    cat = _normalize_category(category)
    return KnowledgePattern(
        pattern_id=_scrub_text(pattern_id)[:80],
        name=_scrub_text(name)[:160],
        category=cat,
        cwe=_cwe_for(cat),
        applies_to=_default_applies_to(cat),
        code_signals=(code_signals or _default_code_signals(cat))[:_MAX_LIST],
        verification_strategy=(
            verification_strategy
            or [
                "local_static_trace_only",
                "use_authorized_test_accounts_if_web_api_in_scope",
                "require_human_review_before_any_validation",
            ]
        )[:_MAX_LIST],
        fix_strategy=(
            fix_strategy
            or [
                "enforce_control_in_shared_service_layer",
                "add_regression_test",
                "avoid_frontend_only_checks",
            ]
        )[:_MAX_LIST],
        false_positive_checks=(
            false_positive_checks
            or [
                "control may exist in middleware",
                "object may be intentionally public",
                "admin role may be allowed",
            ]
        )[:_MAX_LIST],
        source_refs=[_scrub_text(s) for s in source_refs if str(s).strip()][:_MAX_LIST],
        confidence=confidence if confidence in {"low", "medium", "high"} else "low",
        human_review_required=True,
        execution_allowed=False,
        notes=list(notes or []),
    )


def _merge_patterns(patterns: list[KnowledgePattern]) -> list[KnowledgePattern]:
    out: list[KnowledgePattern] = []
    seen: set[str] = set()
    for p in patterns:
        key = f"{p.pattern_id}|{p.category}|{p.name[:80]}"
        if key in seen:
            continue
        seen.add(key)
        out.append(
            KnowledgePattern(
                pattern_id=_scrub_text(p.pattern_id)[:80],
                name=_scrub_text(p.name)[:160],
                category=_normalize_category(p.category),
                cwe=_scrub_text(p.cwe or _cwe_for(p.category))[:40],
                applies_to=_str_list(p.applies_to)[:_MAX_LIST],
                code_signals=_str_list(p.code_signals)[:_MAX_LIST],
                verification_strategy=_str_list(p.verification_strategy)[:_MAX_LIST],
                fix_strategy=_str_list(p.fix_strategy)[:_MAX_LIST],
                false_positive_checks=_str_list(p.false_positive_checks)[:_MAX_LIST],
                source_refs=_str_list(p.source_refs)[:_MAX_LIST],
                confidence=p.confidence if p.confidence in {"low", "medium", "high"} else "low",
                human_review_required=True,
                execution_allowed=False,
                notes=list(p.notes or [])[:_MAX_LIST],
            )
        )
        if len(out) >= _MAX_PATTERNS:
            break
    return out


def _export_catalog(root: Path, result: KnowledgeBaseResult) -> tuple[bool, int, str]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = root / "_export" / "knowledge_base" / stamp
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        payload = result.to_dict()
        payload["package_root"] = str(root.name)
        (out_dir / "catalog.json").write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        pure = [asdict(p) for p in result.patterns]
        for item in pure:
            item["execution_allowed"] = False
            item["human_review_required"] = True
        (out_dir / "patterns.json").write_text(
            json.dumps({"patterns": pure, "export_stamp": stamp}, ensure_ascii=False, indent=2)
            + "\n",
            encoding="utf-8",
        )
        summary = {
            "status": result.status,
            "pattern_count": result.pattern_count,
            "offline_artifact_count": result.offline_artifact_count,
            "derived_pattern_count": result.derived_pattern_count,
            "execution_allowed": False,
            "ranking_permission_granted": False,
            "export_stamp": stamp,
        }
        (out_dir / "summary.json").write_text(
            json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return True, 3, stamp
    except OSError:
        return False, 0, ""


def _normalize_category(value: str) -> str:
    v = _scrub_text(value).lower()
    if not v:
        return "generic"
    for key in (
        "ssrf",
        "bola",
        "idor",
        "authorization",
        "authz",
        "path_traversal",
        "mass_assignment",
        "injection",
        "sqli",
        "xss",
        "rce",
        "deserialization",
        "upload",
        "race",
        "scope",
        "patch_process",
        "research_process",
    ):
        if key in v:
            if key in {"bola", "idor", "authz"}:
                return "authorization"
            if key == "sqli":
                return "injection"
            return key
    cleaned = re.sub(r"[^a-z0-9_]+", "_", v).strip("_")
    return (cleaned or "generic")[:40]


def _cwe_for(category: str) -> str:
    cat = _normalize_category(category)
    return _CWE_HINTS.get(cat, "")


def _default_applies_to(category: str) -> list[str]:
    cat = _normalize_category(category)
    if cat in {"authorization", "ssrf", "mass_assignment"}:
        return ["REST API", "MVC", "authorized_web_api"]
    if cat in {"injection", "path_traversal", "deserialization", "rce"}:
        return ["local_code", "parser_or_sink"]
    if cat == "scope":
        return ["authorized_package_only"]
    return ["authorized_local_artifacts"]


def _default_code_signals(category: str) -> list[str]:
    cat = _normalize_category(category)
    table = {
        "ssrf": [
            "outbound_url_fetch_from_request",
            "missing_private_ip_or_allowlist_check",
            "redirect_follow_without_revalidation",
        ],
        "authorization": [
            "route_accepts_object_id",
            "authentication_exists",
            "ownership_check_missing",
            "direct_database_lookup_by_id",
        ],
        "path_traversal": [
            "user_controlled_path_segment",
            "missing_canonicalize_and_root_confine",
        ],
        "mass_assignment": [
            "request_body_bound_to_model",
            "missing_allowlist_or_dto_mapping",
        ],
        "injection": [
            "untrusted_input_reaches_query_or_command",
            "missing_parameterized_api",
        ],
    }
    return table.get(cat, ["human_must_confirm_local_code_signals"])


def _str_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for x in value:
        s = _scrub_text(str(x))
        if s:
            out.append(s[:200])
    return out


def _scrub_text(value: str) -> str:
    text = str(value or "").replace("\x00", " ").strip()
    if _SECRET_HINTS.search(text):
        return "[redacted_secret_like]"
    return text


def _empty(
    *,
    status: str,
    package_id: str = "",
    package_root: str = "",
    notes: list[str] | None = None,
    human_allow_export_write: bool = False,
) -> KnowledgeBaseResult:
    return _force_safety(
        KnowledgeBaseResult(
            stage="v4_knowledge_base_consolidation",
            inspirations=["final-scheme-section-7", "Mythos", "MDASH"],
            execution_mode="advisory_pattern_catalog_only",
            status=status,
            package_id=package_id,
            package_root=package_root,
            human_allow_export_write=bool(human_allow_export_write),
            safety_invariants=list(SAFETY_INVARIANTS),
            notes=list(notes or []),
            summary=status,
        )
    )


def _force_safety(result: KnowledgeBaseResult) -> KnowledgeBaseResult:
    cleaned: list[KnowledgePattern] = []
    for p in result.patterns:
        cleaned.append(
            KnowledgePattern(
                pattern_id=_scrub_text(p.pattern_id)[:80],
                name=_scrub_text(p.name)[:160],
                category=_normalize_category(p.category),
                cwe=_scrub_text(p.cwe)[:40],
                applies_to=_str_list(p.applies_to)[:_MAX_LIST],
                code_signals=_str_list(p.code_signals)[:_MAX_LIST],
                verification_strategy=_str_list(p.verification_strategy)[:_MAX_LIST],
                fix_strategy=_str_list(p.fix_strategy)[:_MAX_LIST],
                false_positive_checks=_str_list(p.false_positive_checks)[:_MAX_LIST],
                source_refs=_str_list(p.source_refs)[:_MAX_LIST],
                confidence=p.confidence if p.confidence in {"low", "medium", "high"} else "low",
                human_review_required=True,
                execution_allowed=False,
                notes=[_scrub_text(n)[:120] for n in (p.notes or [])][:_MAX_LIST],
            )
        )
    return KnowledgeBaseResult(
        stage="v4_knowledge_base_consolidation",
        inspirations=list(result.inspirations or ["final-scheme-section-7", "Mythos", "MDASH"]),
        execution_mode="advisory_pattern_catalog_only",
        status=result.status,
        package_id=result.package_id,
        package_root=result.package_root,
        patterns=cleaned[:_MAX_PATTERNS],
        pattern_count=len(cleaned[:_MAX_PATTERNS]),
        offline_artifact_count=int(result.offline_artifact_count or 0),
        derived_pattern_count=int(result.derived_pattern_count or 0),
        deep_research_status=result.deep_research_status,
        agent_memory_status=result.agent_memory_status,
        long_horizon_status=result.long_horizon_status,
        human_allow_export_write=bool(result.human_allow_export_write),
        export_written=bool(result.export_written),
        export_count=int(result.export_count or 0),
        export_root_relative="_export/knowledge_base",
        run_stamp=result.run_stamp,
        execution_allowed=False,
        validation_allowed=False,
        report_submission_allowed=False,
        confirmed_vulnerability=False,
        finding_promotion_allowed=False,
        ranking_permission_granted=False,
        auto_learn_live_sources=False,
        network_access=False,
        live_validation=False,
        safety_invariants=list(SAFETY_INVARIANTS),
        next_allowed_action=(
            "Human reviews structured patterns offline; never auto-promote or grant ranking execution."
        ),
        notes=list(result.notes or []),
        summary=result.summary,
    )


def _force_safety_dict(payload: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    out["execution_mode"] = "advisory_pattern_catalog_only"
    for key in (
        "execution_allowed",
        "validation_allowed",
        "report_submission_allowed",
        "confirmed_vulnerability",
        "finding_promotion_allowed",
        "ranking_permission_granted",
        "auto_learn_live_sources",
        "network_access",
        "live_validation",
    ):
        out[key] = False
    out["safety_invariants"] = list(SAFETY_INVARIANTS)
    out["export_root_relative"] = "_export/knowledge_base"
    patterns = out.get("patterns")
    cleaned = []
    if isinstance(patterns, list):
        for item in patterns:
            if not isinstance(item, dict):
                continue
            d = dict(item)
            d["execution_allowed"] = False
            d["human_review_required"] = True
            d["pattern_id"] = _scrub_text(str(d.get("pattern_id") or ""))[:80]
            d["name"] = _scrub_text(str(d.get("name") or ""))[:160]
            d["category"] = _normalize_category(str(d.get("category") or "generic"))
            d["cwe"] = _scrub_text(str(d.get("cwe") or _cwe_for(d["category"])))[:40]
            for list_key in (
                "applies_to",
                "code_signals",
                "verification_strategy",
                "fix_strategy",
                "false_positive_checks",
                "source_refs",
                "notes",
            ):
                d[list_key] = _str_list(d.get(list_key))[:_MAX_LIST]
            cleaned.append(d)
            if len(cleaned) >= _MAX_PATTERNS:
                break
    out["patterns"] = cleaned
    out["pattern_count"] = len(cleaned)
    return out


__all__ = [
    "KnowledgeBaseError",
    "KnowledgeBaseResult",
    "KnowledgePattern",
    "SAFETY_INVARIANTS",
    "STATUS_EMPTY",
    "STATUS_PACKAGE_MISSING",
    "STATUS_READY",
    "STATUS_WAITING",
    "STATUS_WRITTEN",
    "attach_knowledge_base_to_bridge_result",
    "build_knowledge_base",
    "run_knowledge_base",
]
