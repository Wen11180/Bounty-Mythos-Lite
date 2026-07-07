from __future__ import annotations

from dataclasses import asdict, dataclass, field


SAFETY_INVARIANTS = [
    "authorized_artifacts_only",
    "scope_checked_required",
    "no_public_target_scanning",
    "no_destructive_validation",
    "no_exploit_generation",
    "no_credential_collection",
    "no_real_user_data_handling",
    "no_automatic_report_submission",
    "human_review_required_before_validation",
]


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
