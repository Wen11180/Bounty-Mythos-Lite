from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SAFETY_INVARIANTS = [
    "authorized_artifacts_only",
    "scope_checked_required",
    "no_public_target_scanning",
    "no_destructive_validation",
    "no_exploit_generation",
    "no_credential_collection",
    "no_real_user_data_handling",
    "no_automatic_report_submission",
    "no_finding_promotion",
    "human_review_required_before_validation",
    "plan_only_never_auto_execute",
    "no_export_write_without_human_flag",
]

STATUS_READY = "deep_research_plan_ready"
STATUS_EMPTY = "deep_research_empty"
STATUS_PACKAGE_MISSING = "deep_research_package_missing"
STATUS_WRITTEN = "deep_research_export_written"
STATUS_WAITING = "deep_research_waiting_for_hypotheses"

_MAX_CHAINS = 24
_MAX_VARIANTS = 24
_MAX_EXPORT_NOTES = 40


@dataclass(frozen=True)
class PermissionModel:
    status: str
    roles: list[str]
    assumptions: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CrossFileReasoningItem:
    focus: str
    evidence_refs: list[str]
    invariant: str
    refutation_steps: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class VulnerabilityChain:
    chain_id: str
    source_hypothesis_id: str
    stages: list[str]
    hypothesis: str
    execution_allowed: bool
    required_evidence: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RefutationMatrixEntry:
    chain_id: str
    source_hypothesis_id: str
    status: str
    blockers: list[str]
    allowed_evidence: list[str]
    execution_allowed: bool = False
    human_review_required: bool = True


@dataclass(frozen=True)
class VariantCandidate:
    variant_id: str
    source_hypothesis_id: str
    search_pattern: str
    status: str
    safe_next_step: str


@dataclass(frozen=True)
class ProtocolAwareFuzzingPlan:
    target_symbol: str
    source_path: str
    strategy: str
    execution_allowed: bool


@dataclass(frozen=True)
class PatchDiffPattern:
    source_ref: str
    changed_files: list[str]
    root_cause_summary: str
    fix_strategy: str
    regression_test: str
    execution_allowed: bool = False
    human_review_required: bool = True


@dataclass(frozen=True)
class PatchDiffLearner:
    status: str
    required_inputs: list[str] = field(default_factory=list)
    learned_patterns: list[PatchDiffPattern] = field(default_factory=list)
    retained_signal_policy: str = "patterns_only_no_raw_secret_or_user_data"


@dataclass(frozen=True)
class LongHorizonPlan:
    iteration_strategy: str
    fallback_paths: list[str] = field(default_factory=list)
    reflection_prompts: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class KnowledgeUpdate:
    topic: str
    status: str
    source_ref: str
    applicability_boundary: str
    retained_fields: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class EvidenceNode:
    node_id: str
    node_type: str
    label: str


@dataclass(frozen=True)
class EvidenceEdge:
    source_id: str
    target_id: str
    relationship: str


@dataclass(frozen=True)
class EvidenceGraph:
    nodes: list[EvidenceNode]
    edges: list[EvidenceEdge]
    storage_policy: str = "metadata_only_no_raw_secret_or_user_data"


@dataclass(frozen=True)
class ReflectionEntry:
    trigger: str
    observation: str
    next_path: str
    status: str = "planned"


@dataclass(frozen=True)
class KnowledgeQueueItem:
    source_ref: str
    topic: str
    retained_fields: list[str]
    human_review_required: bool
    status: str = "queued_for_advisory_memory"


@dataclass(frozen=True)
class KnowledgeArtifactEntry:
    source_ref: str
    topic: str
    retained_fields: list[str]
    review_required: bool
    confidence: str


@dataclass(frozen=True)
class KnowledgeArtifact:
    artifact_type: str
    status: str
    storage_policy: str
    entries: list[KnowledgeArtifactEntry]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class DeepResearchPlan:
    stage: str
    inspirations: list[str]
    execution_mode: str
    permission_model: PermissionModel
    cross_file_reasoning: list[CrossFileReasoningItem]
    vulnerability_chains: list[VulnerabilityChain]
    refutation_matrix: list[RefutationMatrixEntry]
    variant_analysis: list[VariantCandidate]
    protocol_aware_fuzzing: list[ProtocolAwareFuzzingPlan]
    patch_diff_learner: PatchDiffLearner
    long_horizon_plan: LongHorizonPlan
    evidence_graph: EvidenceGraph
    reflection_log: list[ReflectionEntry]
    knowledge_consolidation_queue: list[KnowledgeQueueItem]
    knowledge_updates: list[KnowledgeUpdate]
    safety_invariants: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def build_deep_research_plan(context: dict) -> DeepResearchPlan:
    source_hypotheses = _dicts(context.get("source_hypotheses"))
    source_hypotheses.extend(
        _confirmed_findings_as_variant_seeds(_dicts(context.get("confirmed_findings")))
    )
    bug_bounty = context.get("authorized_bug_bounty")
    crs_fuzzing = context.get("crs_fuzzing")
    patch_diff = _dict_value(context.get("patch_diff"))
    role_models = _dicts(_dict_value(bug_bounty).get("role_models"))
    parser_candidates = _dicts(_dict_value(crs_fuzzing).get("parser_candidates"))
    chains = _vulnerability_chains(source_hypotheses)
    variants = _variant_candidates(source_hypotheses)
    patch_diff_learner = _patch_diff_learner(patch_diff)

    return DeepResearchPlan(
        stage="v4_deep_vulnerability_research",
        inspirations=["Mythos", "Big Sleep"],
        execution_mode="deep_reasoning_plan_only",
        permission_model=_permission_model(role_models),
        cross_file_reasoning=_cross_file_reasoning(source_hypotheses),
        vulnerability_chains=chains,
        refutation_matrix=_refutation_matrix(chains),
        variant_analysis=variants,
        protocol_aware_fuzzing=_protocol_fuzzing_plans(parser_candidates),
        patch_diff_learner=patch_diff_learner,
        long_horizon_plan=LongHorizonPlan(
            iteration_strategy="refute_then_branch",
            fallback_paths=[
                "try_variant_analysis",
                "tighten_permission_model",
                "switch_to_patch_diff_learning",
                "defer_until_new_evidence",
            ],
            reflection_prompts=[
                "What evidence would disprove the current chain?",
                "Which assumption depends on authorization policy rather than code?",
                "Which similar endpoints deserve local-only review?",
            ],
        ),
        evidence_graph=_evidence_graph(source_hypotheses, chains, variants),
        reflection_log=_reflection_log(source_hypotheses),
        knowledge_consolidation_queue=_knowledge_queue(source_hypotheses),
        knowledge_updates=_knowledge_updates(
            source_hypotheses,
            patch_diff_learner.learned_patterns,
        ),
        safety_invariants=SAFETY_INVARIANTS,
    )


def build_knowledge_artifact(plan: DeepResearchPlan) -> KnowledgeArtifact:
    entries = [
        KnowledgeArtifactEntry(
            source_ref=item.source_ref,
            topic=item.topic,
            retained_fields=item.retained_fields,
            review_required=item.human_review_required,
            confidence="low",
        )
        for item in plan.knowledge_consolidation_queue
    ]
    entries.extend(
        KnowledgeArtifactEntry(
            source_ref=f"patch_diff:{pattern.source_ref}",
            topic="patch_diff_pattern",
            retained_fields=[
                "root_cause_summary",
                "fix_strategy",
                "regression_test",
                "human_review_decision",
            ],
            review_required=pattern.human_review_required,
            confidence="medium",
        )
        for pattern in plan.patch_diff_learner.learned_patterns
    )
    return KnowledgeArtifact(
        artifact_type="v4_advisory_knowledge",
        status="requires_human_review",
        storage_policy="metadata_only_no_raw_secret_or_user_data",
        entries=entries,
    )


def _permission_model(role_models: list[dict]) -> PermissionModel:
    roles = sorted(
        {
            role
            for item in role_models
            for role in [_safe_text(item.get("role"), "")]
            if role
        }
    )
    return PermissionModel(
        status="modeled_from_test_roles" if roles else "not_enough_role_evidence",
        roles=roles,
        assumptions=[
            "test_account_labels_are_not_credentials",
            "role_boundaries_require_human_confirmation",
        ],
    )


def _cross_file_reasoning(
    source_hypotheses: list[dict],
) -> list[CrossFileReasoningItem]:
    items: list[CrossFileReasoningItem] = []
    for hypothesis in source_hypotheses:
        focus = _safe_text(hypothesis.get("vuln_type"), "unknown")
        items.append(
            CrossFileReasoningItem(
                focus=focus,
                evidence_refs=[_safe_text(hypothesis.get("hypothesis_id"), "unknown")],
                invariant=_invariant_for(focus),
                refutation_steps=[
                    "find explicit guard or ownership check in local code",
                    "map service-layer authorization before validation planning",
                    "require redacted evidence and human review before promotion",
                ],
            )
        )
    if not items:
        items.append(
            CrossFileReasoningItem(
                focus="attack_surface",
                evidence_refs=[],
                invariant="No vulnerability chain should be promoted without traceable local evidence.",
                refutation_steps=["collect more authorized local artifacts"],
            )
        )
    return items


def _vulnerability_chains(source_hypotheses: list[dict]) -> list[VulnerabilityChain]:
    chains: list[VulnerabilityChain] = []
    for index, hypothesis in enumerate(source_hypotheses, start=1):
        hypothesis_id = _safe_text(hypothesis.get("hypothesis_id"), f"H-{index:03d}")
        vuln_type = _safe_text(hypothesis.get("vuln_type"), "unknown")
        chains.append(
            VulnerabilityChain(
                chain_id=f"CH-{index:03d}",
                source_hypothesis_id=hypothesis_id,
                stages=_chain_stages(vuln_type),
                hypothesis=f"{vuln_type} chain requires cross-boundary evidence before validation.",
                execution_allowed=False,
                required_evidence=[
                    "entrypoint_to_sink_trace",
                    "permission_or_parser_boundary",
                    "impact_without_real_user_data",
                    "human_review_decision",
                ],
            )
        )
    return chains


def _refutation_matrix(chains: list[VulnerabilityChain]) -> list[RefutationMatrixEntry]:
    return [
        RefutationMatrixEntry(
            chain_id=chain.chain_id,
            source_hypothesis_id=chain.source_hypothesis_id,
            status="unresolved_requires_human_review",
            blockers=[
                "missing_refutation_evidence",
                "missing_sanitized_impact_evidence",
                "missing_human_review_decision",
            ],
            allowed_evidence=[
                "local_code_trace",
                "sanitized_fixture_diff",
                "human_review_decision",
            ],
        )
        for chain in chains
    ]


def _variant_candidates(source_hypotheses: list[dict]) -> list[VariantCandidate]:
    variants: list[VariantCandidate] = []
    for index, hypothesis in enumerate(source_hypotheses, start=1):
        hypothesis_id = _safe_text(hypothesis.get("hypothesis_id"), f"H-{index:03d}")
        vuln_type = _safe_text(hypothesis.get("vuln_type"), "unknown")
        location = _safe_text(hypothesis.get("location"), "unknown")
        status = (
            "unverified_hypothesis_from_confirmed_finding"
            if hypothesis.get("origin") == "confirmed_finding_seed"
            else "planned_local_code_search_only"
        )
        variants.append(
            VariantCandidate(
                variant_id=f"VA-{index:03d}",
                source_hypothesis_id=hypothesis_id,
                search_pattern=f"similar_{vuln_type}_boundary_near_{location}",
                status=status,
                safe_next_step="search authorized local code for comparable guards and sinks",
            )
        )
    return variants


def _confirmed_findings_as_variant_seeds(findings: list[dict]) -> list[dict]:
    seeds: list[dict] = []
    for index, finding in enumerate(findings, start=1):
        seeds.append(
            {
                "hypothesis_id": _safe_text(
                    finding.get("finding_id"),
                    f"confirmed-finding-{index:03d}",
                ),
                "vuln_type": _safe_text(finding.get("vuln_type"), "unknown"),
                "location": _safe_text(finding.get("location"), "unknown"),
                "reason": "confirmed finding seed for local-only variant search",
                "origin": "confirmed_finding_seed",
            }
        )
    return seeds


def _protocol_fuzzing_plans(
    parser_candidates: list[dict],
) -> list[ProtocolAwareFuzzingPlan]:
    return [
        ProtocolAwareFuzzingPlan(
            target_symbol=_safe_text(candidate.get("symbol_name"), "unknown"),
            source_path=_safe_text(candidate.get("source_path"), "unknown"),
            strategy="derive_protocol_grammar_before_local_harness",
            execution_allowed=False,
        )
        for candidate in parser_candidates
    ]


def _patch_diff_learner(patch_diff: dict) -> PatchDiffLearner:
    if not patch_diff:
        return PatchDiffLearner(
            status="waiting_for_patch_diff",
            required_inputs=[
                "patch_diff",
                "linked_finding_or_regression_test",
                "human_labeled_root_cause",
            ],
        )

    source_ref = _safe_text(patch_diff.get("linked_hypothesis_id"), "patch_diff")
    changed_files = [
        _safe_text(path, "unknown")
        for path in patch_diff.get("changed_files", [])
        if isinstance(path, str)
    ]
    pattern = PatchDiffPattern(
        source_ref=source_ref,
        changed_files=changed_files,
        root_cause_summary=_safe_advisory_text(
            patch_diff.get("root_cause"),
            "human_labeled_root_cause_required",
        ),
        fix_strategy=_safe_advisory_text(
            patch_diff.get("fix_strategy"),
            "fix_strategy_required",
        ),
        regression_test=_safe_advisory_text(
            patch_diff.get("regression_test"),
            "regression_test_required",
        ),
    )
    return PatchDiffLearner(
        status="advisory_pattern_ready",
        learned_patterns=[pattern],
    )


def _knowledge_updates(
    source_hypotheses: list[dict],
    patch_diff_patterns: list[PatchDiffPattern] | None = None,
) -> list[KnowledgeUpdate]:
    patch_diff_patterns = patch_diff_patterns or []
    if not source_hypotheses:
        updates = [
            KnowledgeUpdate(
                topic="negative_signal",
                status="advisory_only",
                source_ref="none",
                applicability_boundary="authorized_local_artifacts_only",
                retained_fields=["why_no_chain_was_promoted"],
            )
        ]
    else:
        updates = [
        KnowledgeUpdate(
            topic=_safe_text(hypothesis.get("vuln_type"), "unknown"),
            status="advisory_only",
            source_ref=_safe_text(hypothesis.get("hypothesis_id"), "unknown"),
            applicability_boundary="authorized_local_artifacts_only",
            retained_fields=[
                "vuln_type",
                "root_cause_summary",
                "refutation_result",
                "variant_search_pattern",
            ],
        )
        for hypothesis in source_hypotheses
        ]
    updates.extend(
        KnowledgeUpdate(
            topic=f"patch_diff:{pattern.source_ref}",
            status="advisory_only",
            source_ref=f"patch_diff:{pattern.source_ref}",
            applicability_boundary="reviewed_patch_diff_patterns_only",
            retained_fields=[
                "patch_diff_pattern",
                "root_cause_summary",
                "fix_strategy",
                "regression_test",
                "human_review_decision",
            ],
        )
        for pattern in patch_diff_patterns
    )
    return updates


def _evidence_graph(
    source_hypotheses: list[dict],
    chains: list[VulnerabilityChain],
    variants: list[VariantCandidate],
) -> EvidenceGraph:
    nodes: list[EvidenceNode] = []
    edges: list[EvidenceEdge] = []
    for hypothesis in source_hypotheses:
        hypothesis_id = _safe_text(hypothesis.get("hypothesis_id"), "unknown")
        nodes.append(
            EvidenceNode(
                node_id=hypothesis_id,
                node_type="source_hypothesis",
                label=_safe_text(hypothesis.get("vuln_type"), "unknown"),
            )
        )
    for chain in chains:
        nodes.append(
            EvidenceNode(
                node_id=chain.chain_id,
                node_type="vulnerability_chain",
                label=chain.source_hypothesis_id,
            )
        )
        edges.append(
            EvidenceEdge(
                source_id=chain.source_hypothesis_id,
                target_id=chain.chain_id,
                relationship="supports_chain",
            )
        )
    for variant in variants:
        nodes.append(
            EvidenceNode(
                node_id=variant.variant_id,
                node_type="variant_candidate",
                label=variant.source_hypothesis_id,
            )
        )
        edges.append(
            EvidenceEdge(
                source_id=variant.source_hypothesis_id,
                target_id=variant.variant_id,
                relationship="suggests_variant_search",
            )
        )
    return EvidenceGraph(nodes=nodes, edges=edges)


def _reflection_log(source_hypotheses: list[dict]) -> list[ReflectionEntry]:
    if not source_hypotheses:
        return [
            ReflectionEntry(
                trigger="insufficient_evidence",
                observation="No source hypothesis is available for deep chain building.",
                next_path="collect_more_authorized_artifacts",
            )
        ]
    return [
        ReflectionEntry(
            trigger="initial_chain_planning",
            observation="Current chain is unverified and must be refuted before promotion.",
            next_path="try_variant_analysis",
        )
    ]


def _knowledge_queue(source_hypotheses: list[dict]) -> list[KnowledgeQueueItem]:
    if not source_hypotheses:
        return [
            KnowledgeQueueItem(
                source_ref="none",
                topic="negative_signal",
                retained_fields=["missing_evidence_reason"],
                human_review_required=True,
            )
        ]
    return [
        KnowledgeQueueItem(
            source_ref=_safe_text(hypothesis.get("hypothesis_id"), "unknown"),
            topic=_safe_text(hypothesis.get("vuln_type"), "unknown"),
            retained_fields=[
                "invariant",
                "refutation_result",
                "variant_search_pattern",
                "human_review_decision",
            ],
            human_review_required=True,
        )
        for hypothesis in source_hypotheses
    ]


def _chain_stages(vuln_type: str) -> list[str]:
    if vuln_type == "authorization":
        return [
            "entrypoint",
            "authorization_boundary",
            "object_access",
            "impact_review",
        ]
    if vuln_type in {"injection", "static-analysis"}:
        return ["entrypoint", "input_boundary", "sink", "impact_review"]
    return ["entrypoint", "trust_boundary", "state_change", "impact_review"]


def _invariant_for(vuln_type: str) -> str:
    if vuln_type == "authorization":
        return "Every sensitive object access must be constrained by role and ownership checks."
    if vuln_type == "injection":
        return "User-controlled input must not reach a sink without structured validation."
    return "Every promoted finding needs a local evidence trace and an explicit refutation attempt."


def _dict_value(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _dicts(value: object) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _safe_text(value: object, default: str) -> str:
    if not isinstance(value, str):
        return default
    return value.strip()[:180] or default


def _safe_advisory_text(value: object, default: str) -> str:
    text = _safe_text(value, default)
    lowered = text.lower()
    sensitive_markers = ("authorization", "bearer", "token", "secret", "password", "cookie")
    if any(marker in lowered for marker in sensitive_markers):
        return "[REDACTED]"
    return text



class DeepResearchError(ValueError):
    """Raised when deep research bridge inputs are invalid."""


@dataclass
class DeepResearchBridgeResult:
    """Bridge-facing V4 deep research summary (plan-only, submission-blocked)."""

    stage: str = "v4_deep_vulnerability_research"
    inspirations: list[str] = field(default_factory=lambda: ["Mythos", "Big Sleep", "final-scheme-V4"])
    execution_mode: str = "deep_reasoning_plan_only"
    status: str = STATUS_EMPTY
    package_id: str = ""
    package_root: str = ""
    plan: dict[str, Any] = field(default_factory=dict)
    chain_count: int = 0
    variant_count: int = 0
    cross_file_count: int = 0
    refutation_count: int = 0
    unresolved_refutation_count: int = 0
    protocol_fuzz_count: int = 0
    knowledge_update_count: int = 0
    knowledge_queue_count: int = 0
    reflection_count: int = 0
    patch_diff_status: str = "waiting_for_patch_diff"
    permission_model_status: str = "empty"
    offline_artifact_count: int = 0
    human_allow_export_write: bool = False
    export_written: bool = False
    export_count: int = 0
    export_root_relative: str = "_export/deep_research"
    run_stamp: str = ""
    execution_allowed: bool = False
    validation_allowed: bool = False
    report_submission_allowed: bool = False
    confirmed_vulnerability: bool = False
    finding_promotion_allowed: bool = False
    ranking_permission_granted: bool = False
    network_access: bool = False
    live_validation: bool = False
    safety_invariants: list[str] = field(default_factory=lambda: list(SAFETY_INVARIANTS))
    next_allowed_action: str = (
        "Human reviews multi-stage chains/variants offline; Mythos never auto-executes deep research."
    )
    notes: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _force_safety_dict(asdict(self))


def build_deep_research(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    bridge_result: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> DeepResearchBridgeResult:
    return run_deep_research(
        package_root=package_root,
        package_id=package_id,
        bridge_result=bridge_result,
        human_allow_export_write=human_allow_export_write,
    )


def run_deep_research(
    *,
    package_root: str | Path | None = None,
    package_id: str = "",
    bridge_result: dict[str, Any] | None = None,
    human_allow_export_write: bool = False,
) -> DeepResearchBridgeResult:
    """Build V4 deep-research plan from authorized package + bridge context (plan-only)."""
    root: Path | None = None
    root_s = ""
    if package_root is not None and str(package_root).strip():
        root = Path(package_root)
        root_s = str(root)
        if not root.is_dir():
            return _empty_bridge(
                status=STATUS_PACKAGE_MISSING,
                package_id=package_id,
                package_root=root_s,
                notes=["package_root_missing_or_not_directory"],
                human_allow_export_write=bool(human_allow_export_write),
            )

    bridge = bridge_result if isinstance(bridge_result, dict) else {}
    pid = package_id or str(bridge.get("package_id") or "")
    offline_ctx, offline_n = _load_offline_deep_research_context(root)
    context = _bridge_to_deep_context(bridge, offline_ctx)
    plan = build_deep_research_plan(context)
    plan_dict = _scrub_plan_dict(plan.to_dict())

    chain_n = len(plan.vulnerability_chains)
    variant_n = len(plan.variant_analysis)
    xfile_n = len(plan.cross_file_reasoning)
    refute_n = len(plan.refutation_matrix)
    unresolved_n = sum(
        1
        for item in plan.refutation_matrix
        if "unresolved" in str(item.status or "").lower()
    )
    protocol_n = len(plan.protocol_aware_fuzzing)
    know_n = len(plan.knowledge_updates)
    queue_n = len(plan.knowledge_consolidation_queue)
    reflect_n = len(plan.reflection_log)
    patch_status = str(plan.patch_diff_learner.status or "waiting_for_patch_diff")
    perm_status = str(plan.permission_model.status or "empty")

    notes = [
        "advisory_deep_research_plan_only",
        "never_generates_exploits",
        "never_grants_execution_or_submit",
        "multi_stage_hypotheses_require_human_refutation",
        "authorized_package_or_bridge_only",
    ]

    has_signal = bool(chain_n or variant_n or xfile_n or know_n or offline_n)
    if not has_signal and not context.get("source_hypotheses"):
        status = STATUS_WAITING if not offline_n else STATUS_EMPTY
        if not offline_n and not bridge:
            status = STATUS_EMPTY
    else:
        status = STATUS_READY if has_signal else STATUS_WAITING

    result = DeepResearchBridgeResult(
        stage="v4_deep_vulnerability_research",
        inspirations=["Mythos", "Big Sleep", "final-scheme-V4"],
        execution_mode="deep_reasoning_plan_only",
        status=status,
        package_id=pid,
        package_root=root_s,
        plan=plan_dict,
        chain_count=chain_n,
        variant_count=variant_n,
        cross_file_count=xfile_n,
        refutation_count=refute_n,
        unresolved_refutation_count=unresolved_n,
        protocol_fuzz_count=protocol_n,
        knowledge_update_count=know_n,
        knowledge_queue_count=queue_n,
        reflection_count=reflect_n,
        patch_diff_status=patch_status,
        permission_model_status=perm_status,
        offline_artifact_count=offline_n,
        human_allow_export_write=bool(human_allow_export_write),
        notes=notes,
        summary=(
            f"chains={chain_n} variants={variant_n} cross_file={xfile_n} "
            f"refute={refute_n} unresolved={unresolved_n} knowledge={know_n} "
            f"offline={offline_n}"
        ),
    )
    result = _force_safety_bridge(result)

    if human_allow_export_write and root is not None:
        written, count, stamp = _export_deep_research(root, result)
        if written:
            result.export_written = True
            result.export_count = count
            result.run_stamp = stamp
            result.status = STATUS_WRITTEN
            result.notes = list(result.notes) + ["export_written_under_package"]
            result = _force_safety_bridge(result)

    return result


def attach_deep_research_to_bridge_result(
    bridge_result: dict[str, Any],
    *,
    package_root: str | Path | None = None,
    deep_research: dict[str, Any] | DeepResearchBridgeResult | DeepResearchPlan | None = None,
    human_allow_export_write: bool = False,
) -> dict[str, Any]:
    """Attach V4 deep research plan; never unlocks execute/submit/promote."""
    if not isinstance(bridge_result, dict):
        raise DeepResearchError("bridge_result_must_be_object")

    package_id = str(bridge_result.get("package_id") or "")
    resolved_root = package_root or bridge_result.get("package_root")

    if isinstance(deep_research, DeepResearchBridgeResult):
        payload = deep_research.to_dict()
    elif isinstance(deep_research, DeepResearchPlan):
        # Wrap plan-only object into bridge summary.
        payload = run_deep_research(
            package_root=resolved_root,
            package_id=package_id,
            bridge_result={**bridge_result, "deep_research_plan_seed": deep_research.to_dict()},
            human_allow_export_write=bool(human_allow_export_write),
        ).to_dict()
    elif isinstance(deep_research, dict):
        payload = _force_safety_dict(dict(deep_research))
    else:
        payload = run_deep_research(
            package_root=resolved_root,
            package_id=package_id,
            bridge_result=bridge_result,
            human_allow_export_write=bool(human_allow_export_write),
        ).to_dict()

    if not payload.get("package_id") and package_id:
        payload["package_id"] = package_id
    payload = _force_safety_dict(payload)

    out = dict(bridge_result)
    out["deep_research"] = payload
    out["deep_research_present"] = True
    out["deep_research_status"] = str(payload.get("status") or STATUS_EMPTY)
    out["deep_research_chain_count"] = int(payload.get("chain_count") or 0)
    out["deep_research_variant_count"] = int(payload.get("variant_count") or 0)
    out["deep_research_cross_file_count"] = int(payload.get("cross_file_count") or 0)
    out["deep_research_unresolved_refutation_count"] = int(
        payload.get("unresolved_refutation_count") or 0
    )
    out["deep_research_knowledge_update_count"] = int(
        payload.get("knowledge_update_count") or 0
    )
    out["deep_research_export_written"] = bool(payload.get("export_written"))
    out["deep_research_execution_allowed"] = False
    out["execution_allowed"] = False
    out["validation_allowed"] = False
    out["report_submission_allowed"] = False
    out["confirmed_vulnerability"] = False
    if out.get("submission_blocked") is not True:
        out["submission_blocked"] = True
    return out


def _bridge_to_deep_context(
    bridge: dict[str, Any],
    offline: dict[str, Any] | None = None,
) -> dict[str, Any]:
    offline = offline if isinstance(offline, dict) else {}
    hyps: list[dict[str, Any]] = []

    for key in ("source_hypotheses", "hypotheses"):
        for item in _dicts(bridge.get(key)):
            hyps.append(item)
        for item in _dicts(offline.get(key)):
            hyps.append(item)

    for draft in _dicts(bridge.get("drafts")):
        hyps.append(
            {
                "hypothesis_id": str(
                    draft.get("candidate_id")
                    or draft.get("hypothesis_id")
                    or draft.get("root_cause_id")
                    or "draft"
                ),
                "vuln_type": str(draft.get("vuln_type") or draft.get("type") or "unknown"),
                "location": str(
                    draft.get("endpoint")
                    or draft.get("location")
                    or draft.get("affected_endpoint")
                    or ""
                ),
                "risk": str(draft.get("severity") or draft.get("risk") or "medium"),
                "reason": str(draft.get("summary") or draft.get("title") or draft.get("reason") or ""),
            }
        )

    for gate in _dicts(bridge.get("human_residual_gates")):
        status = str(gate.get("status") or "")
        if status in {"human_rejected_or_fp", "false_positive"}:
            continue
        cid = str(gate.get("candidate_id") or gate.get("hypothesis_id") or "")
        if not cid:
            continue
        hyps.append(
            {
                "hypothesis_id": cid,
                "vuln_type": str(gate.get("vuln_type") or "unknown"),
                "location": str(gate.get("endpoint") or gate.get("location") or ""),
                "risk": str(gate.get("severity") or "medium"),
                "reason": str(gate.get("summary") or gate.get("status") or "residual_gate"),
            }
        )

    # Dedup by hypothesis_id
    dedup: dict[str, dict[str, Any]] = {}
    for h in hyps:
        hid = str(h.get("hypothesis_id") or h.get("candidate_id") or "").strip() or "unknown"
        if hid not in dedup:
            dedup[hid] = h
    hyps = list(dedup.values())[:_MAX_CHAINS]

    role_models = []
    web = bridge.get("authorized_web_api") if isinstance(bridge.get("authorized_web_api"), dict) else {}
    for item in _dicts(web.get("role_models") or web.get("roles")):
        role_models.append(item)
    for item in _dicts(offline.get("role_models")):
        role_models.append(item)
    if not role_models:
        # soft default empty; permission model will be empty
        pass

    crs = bridge.get("crs_fuzzing") if isinstance(bridge.get("crs_fuzzing"), dict) else {}
    parser_candidates = _dicts(crs.get("parser_candidates"))
    if not parser_candidates:
        parser_candidates = _dicts(offline.get("parser_candidates"))

    patch_diff = offline.get("patch_diff") if isinstance(offline.get("patch_diff"), dict) else {}
    if not patch_diff and isinstance(bridge.get("patch_diff"), dict):
        patch_diff = bridge.get("patch_diff") or {}
    # seed from patch industrial loop notes (metadata only)
    if not patch_diff:
        ploop = bridge.get("patch_industrial_loop") if isinstance(bridge.get("patch_industrial_loop"), dict) else {}
        items = _dicts(ploop.get("items"))
        if items:
            patch_diff = {
                "source_ref": "patch_industrial_loop",
                "changed_files": [],
                "root_cause_summary": str(items[0].get("title") or items[0].get("family") or "patch_loop"),
                "fix_strategy": "shared_control_point",
                "regression_test": "human_local_static_recheck",
            }

    confirmed = []
    for item in _dicts(bridge.get("confirmed_findings")):
        confirmed.append(item)
    for item in _dicts(offline.get("confirmed_findings")):
        confirmed.append(item)

    return {
        "source_hypotheses": hyps,
        "confirmed_findings": confirmed,
        "authorized_bug_bounty": {
            "role_models": role_models,
            "business_logic_candidates": _dicts(
                (bridge.get("authorized_web_api") or {}).get("business_logic_candidates")
                if isinstance(bridge.get("authorized_web_api"), dict)
                else []
            )
            or _dicts(offline.get("business_logic_candidates")),
        },
        "crs_fuzzing": {"parser_candidates": parser_candidates},
        "patch_diff": patch_diff,
        "industrial_scheduler": bridge.get("industrial_scheduler")
        if isinstance(bridge.get("industrial_scheduler"), dict)
        else {},
    }


def _load_offline_deep_research_context(
    root: Path | None,
) -> tuple[dict[str, Any], int]:
    if root is None:
        return {}, 0
    paths = [
        root / "inputs" / "deep_research.json",
        root / "inputs" / "deep_research" / "plan.json",
        root / "inputs" / "v4_deep_research.json",
    ]
    merged: dict[str, Any] = {}
    count = 0
    for p in paths:
        if not p.is_file():
            continue
        try:
            raw = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(raw, dict):
            continue
        count += 1
        for k, v in raw.items():
            if k not in merged:
                merged[k] = v
            elif isinstance(merged[k], list) and isinstance(v, list):
                merged[k] = list(merged[k]) + list(v)
    # split files
    split_dir = root / "inputs" / "deep_research"
    if split_dir.is_dir():
        for p in sorted(split_dir.glob("*.json")):
            if p.name == "plan.json":
                continue
            try:
                raw = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            if isinstance(raw, dict):
                count += 1
                hyps = _dicts(raw.get("source_hypotheses") or raw.get("hypotheses") or [raw])
                merged.setdefault("source_hypotheses", [])
                if isinstance(merged["source_hypotheses"], list):
                    merged["source_hypotheses"].extend(hyps)
    return merged, count


def _export_deep_research(
    root: Path,
    result: DeepResearchBridgeResult,
) -> tuple[bool, int, str]:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = root / "_export" / "deep_research" / stamp
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        index = result.to_dict()
        (out_dir / "index.json").write_text(
            json.dumps(index, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        if result.plan:
            (out_dir / "plan.json").write_text(
                json.dumps(result.plan, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
        readme = "\n".join(
            [
                "# Deep Research export (advisory only)",
                "",
                f"- status: `{result.status}`",
                f"- chains: {result.chain_count}",
                f"- variants: {result.variant_count}",
                f"- unresolved_refutations: {result.unresolved_refutation_count}",
                f"- execution_allowed: false",
                f"- report_submission_allowed: false",
                "",
                "Never treat this export as confirmed vulnerability, exploit guidance, or submit permission.",
                "",
            ]
        )
        (out_dir / "README.md").write_text(readme, encoding="utf-8")
        return True, 1, stamp
    except Exception:
        return False, 0, ""


def _empty_bridge(
    *,
    status: str,
    package_id: str = "",
    package_root: str = "",
    notes: list[str] | None = None,
    human_allow_export_write: bool = False,
) -> DeepResearchBridgeResult:
    result = DeepResearchBridgeResult(
        status=status,
        package_id=package_id,
        package_root=package_root,
        notes=list(notes or []),
        human_allow_export_write=bool(human_allow_export_write),
        summary=f"status={status}",
    )
    return _force_safety_bridge(result)


def _force_safety_bridge(result: DeepResearchBridgeResult) -> DeepResearchBridgeResult:
    result.execution_mode = "deep_reasoning_plan_only"
    result.execution_allowed = False
    result.validation_allowed = False
    result.report_submission_allowed = False
    result.confirmed_vulnerability = False
    result.finding_promotion_allowed = False
    result.ranking_permission_granted = False
    result.network_access = False
    result.live_validation = False
    result.safety_invariants = list(SAFETY_INVARIANTS)
    if result.plan:
        result.plan = _scrub_plan_dict(result.plan)
    return result


def _force_safety_dict(payload: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    out["execution_mode"] = "deep_reasoning_plan_only"
    for key in (
        "execution_allowed",
        "validation_allowed",
        "report_submission_allowed",
        "confirmed_vulnerability",
        "finding_promotion_allowed",
        "ranking_permission_granted",
        "network_access",
        "live_validation",
    ):
        out[key] = False
    out["safety_invariants"] = list(SAFETY_INVARIANTS)
    if isinstance(out.get("plan"), dict):
        out["plan"] = _scrub_plan_dict(out["plan"])
    # scrub top-level string notes/summary
    if isinstance(out.get("summary"), str):
        out["summary"] = _scrub_text(out["summary"])
    if isinstance(out.get("notes"), list):
        out["notes"] = [_scrub_text(str(n)) for n in out["notes"][:_MAX_EXPORT_NOTES]]
    return out


def _scrub_plan_dict(plan: dict[str, Any]) -> dict[str, Any]:
    blob = json.dumps(plan, ensure_ascii=False)
    blob = _scrub_text(blob)
    try:
        cleaned = json.loads(blob)
        return cleaned if isinstance(cleaned, dict) else {"redacted": True}
    except Exception:
        return {"redacted": True, "note": "plan_scrubbed"}


def _scrub_text(value: str) -> str:
    text = str(value or "")
    patterns = [
        r"(?i)(authorization\s*:\s*bearer\s+)[^\s\"']+",
        r"(?i)(bearer\s+)[a-z0-9\-\._~\+\/]+=*",
        r"(?i)(token\s*[=:]\s*)[^\s\"',}]+",
        r"(?i)(secret\s*[=:]\s*)[^\s\"',}]+",
        r"(?i)(password\s*[=:]\s*)[^\s\"',}]+",
        r"(?i)(api[_-]?key\s*[=:]\s*)[^\s\"',}]+",
        r"(?i)(cookie\s*[=:]\s*)[^\s\"',}]+",
    ]
    for pat in patterns:
        text = re.sub(pat, r"\1[REDACTED]", text)
    return text
