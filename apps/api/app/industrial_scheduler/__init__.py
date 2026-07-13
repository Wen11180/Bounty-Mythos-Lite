from __future__ import annotations

from dataclasses import asdict, dataclass, field


SAFETY_INVARIANTS = [
    "authorized_artifacts_only",
    "scope_checked_required",
    "no_unscoped_agent_execution",
    "no_parallel_task_without_scope_check",
    "no_destructive_validation",
    "no_automatic_report_submission",
    "human_review_required_for_evidence_promotion",
]
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class AgentTask:
    task_id: str
    agent: str
    purpose: str
    input_summary: str
    output_summary: str
    depends_on: list[str] = field(default_factory=list)
    status: str = "planned"
    confidence: str = "medium"
    evidence_refs: list[str] = field(default_factory=list)
    next_actions: list[str] = field(default_factory=list)
    scope_checked: bool = True
    requires_human_review: bool = False
    execution_allowed: bool = False
    safety_gate: str = "advisory_plan_only"


@dataclass(frozen=True)
class ParallelBatch:
    batch_id: str
    task_ids: list[str]
    status: str = "ready_when_dependencies_satisfied"


@dataclass(frozen=True)
class FindingCluster:
    cluster_id: str
    finding_ids: list[str]
    dedup_key: str
    status: str = "deduped_for_triage"


@dataclass(frozen=True)
class RiskQueueItem:
    finding_id: str
    severity: str
    priority: int
    reason: str


@dataclass(frozen=True)
class LifecycleTransitionGuard:
    from_state: str
    to_state: str
    required_gates: list[str]
    status: str = "blocked_until_gates_satisfied"
    execution_allowed: bool = False
    bypass_allowed: bool = False


@dataclass(frozen=True)
class FindingLifecycle:
    states: list[str]
    promotion_gates: list[str] = field(default_factory=list)
    transition_guards: list[LifecycleTransitionGuard] = field(default_factory=list)


@dataclass(frozen=True)
class AgentMemoryPlan:
    status: str
    retained_signals: list[str] = field(default_factory=list)
    storage_policy: str = "advisory_only_no_raw_secrets"


@dataclass(frozen=True)
class ContinuousScanPlan:
    status: str
    execution_allowed: bool
    cadence: str
    scope_requirement: str


@dataclass(frozen=True)
class PatchValidationPlan:
    status: str
    execution_allowed: bool
    validation_type: str
    approval_required: bool


@dataclass(frozen=True)
class DeepResearchSchedulerPlan:
    status: str
    execution_allowed: bool
    mode: str
    human_review_required: bool = True


@dataclass(frozen=True)
class LongHorizonSchedulerPlan:
    status: str
    execution_allowed: bool
    mode: str
    auto_path_switch_allowed: bool = False
    human_review_required: bool = True


@dataclass(frozen=True)
class KnowledgeBaseSchedulerPlan:
    status: str
    execution_allowed: bool
    mode: str
    ranking_permission_granted: bool = False
    auto_learn_live_sources: bool = False
    human_review_required: bool = True


@dataclass(frozen=True)
class MultiHourAgentLoopSchedulerPlan:
    status: str
    execution_allowed: bool
    mode: str
    auto_tick_allowed: bool = False
    auto_session_advance_allowed: bool = False
    ranking_permission_granted: bool = False
    human_review_required: bool = True


@dataclass(frozen=True)
class WallClockMultiHourRunnerSchedulerPlan:
    status: str
    execution_allowed: bool
    mode: str
    auto_tick_allowed: bool = False
    auto_session_advance_allowed: bool = False
    ranking_permission_granted: bool = False
    human_review_required: bool = True


@dataclass(frozen=True)
class HumanReviewApprovalsSchedulerPlan:
    status: str
    execution_allowed: bool
    mode: str
    patch_ready: bool = False
    auto_pr_allowed: bool = False
    report_submission_allowed: bool = False
    ranking_permission_granted: bool = False
    human_review_required: bool = True




@dataclass(frozen=True)
class IndustrialSchedulerPlan:
    stage: str
    inspirations: list[str]
    execution_mode: str
    dag_tasks: list[AgentTask]
    parallel_batches: list[ParallelBatch]
    finding_clusters: list[FindingCluster]
    risk_queue: list[RiskQueueItem]
    lifecycle: FindingLifecycle
    agent_memory: AgentMemoryPlan
    continuous_scan: ContinuousScanPlan
    patch_validation: PatchValidationPlan
    deep_research: DeepResearchSchedulerPlan
    long_horizon: LongHorizonSchedulerPlan
    knowledge_base: KnowledgeBaseSchedulerPlan
    multi_hour_agent_loop: MultiHourAgentLoopSchedulerPlan
    wall_clock_multi_hour_runner: WallClockMultiHourRunnerSchedulerPlan
    human_review_approvals: HumanReviewApprovalsSchedulerPlan
    safety_invariants: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def build_industrial_scheduler_plan(context: dict) -> IndustrialSchedulerPlan:
    findings = _findings(context.get("hypotheses"))
    clusters = _finding_clusters(findings)
    return IndustrialSchedulerPlan(
        stage="v3_multi_agent_industrial_scheduling",
        inspirations=["MDASH"],
        execution_mode="plan_only_orchestration",
        dag_tasks=_dag_tasks(context),
        parallel_batches=[
            ParallelBatch(batch_id="B-001", task_ids=["T-001"]),
            ParallelBatch(batch_id="B-001b", task_ids=["T-001b"]),
            ParallelBatch(batch_id="B-001c", task_ids=["T-001c"]),
            ParallelBatch(batch_id="B-002", task_ids=["T-002", "T-003", "T-004"]),
            ParallelBatch(batch_id="B-002d", task_ids=["T-003b"]),
            ParallelBatch(batch_id="B-002e", task_ids=["T-003c"]),
            ParallelBatch(batch_id="B-002f", task_ids=["T-003d"]),
            ParallelBatch(batch_id="B-002g", task_ids=["T-003e"]),
            ParallelBatch(batch_id="B-002h", task_ids=["T-003f"]),
            ParallelBatch(batch_id="B-002i", task_ids=["T-003g"]),
        ParallelBatch(batch_id="B-002j", task_ids=["T-003h"]),
            ParallelBatch(batch_id="B-002b", task_ids=["T-002b"]),
            ParallelBatch(batch_id="B-002c", task_ids=["T-002c"]),
            ParallelBatch(batch_id="B-003", task_ids=["T-005", "T-006"]),
            ParallelBatch(batch_id="B-003b", task_ids=["T-006b"]),
            ParallelBatch(batch_id="B-004", task_ids=["T-007"]),
            ParallelBatch(batch_id="B-004b", task_ids=["T-007b"]),
            ParallelBatch(batch_id="B-005", task_ids=["T-008"]),
            ParallelBatch(batch_id="B-005b", task_ids=["T-008b"]),
            ParallelBatch(batch_id="B-005c", task_ids=["T-008c"]),
            ParallelBatch(batch_id="B-005d", task_ids=["T-008d"]),
            ParallelBatch(batch_id="B-006", task_ids=["T-009"]),
            ParallelBatch(batch_id="B-007", task_ids=["T-010"]),
            ParallelBatch(batch_id="B-008", task_ids=["T-011"]),
            ParallelBatch(batch_id="B-009", task_ids=["T-012"]),
            ParallelBatch(batch_id="B-010", task_ids=["T-013"]),
            ParallelBatch(batch_id="B-010b", task_ids=["T-013b"]),
            ParallelBatch(batch_id="B-010c", task_ids=["T-013c"]),
            ParallelBatch(batch_id="B-010d", task_ids=["T-013d"]),
            ParallelBatch(batch_id="B-011", task_ids=["T-014"]),
            ParallelBatch(batch_id="B-012", task_ids=["T-015"]),
            ParallelBatch(batch_id="B-013", task_ids=["T-016"]),
            ParallelBatch(batch_id="B-014", task_ids=["T-017"]),
            ParallelBatch(batch_id="B-015", task_ids=["T-018"]),
        ],
        finding_clusters=clusters,
        risk_queue=_risk_queue(findings),
        lifecycle=FindingLifecycle(
            states=[
                "candidate",
                "triaged",
                "human_review_required",
                "validated",
                "reported",
                "fixed",
                "regression_verified",
            ],
            promotion_gates=[
                "scope_checked",
                "deduplicated",
                "human_reviewed",
                "redacted_evidence_attached",
                "patch_or_regression_confirmed",
            ],
            transition_guards=[
                LifecycleTransitionGuard(
                    from_state="candidate",
                    to_state="triaged",
                    required_gates=["scope_checked", "deduplicated"],
                ),
                LifecycleTransitionGuard(
                    from_state="triaged",
                    to_state="human_review_required",
                    required_gates=["risk_prioritized", "human_review_queued"],
                ),
                LifecycleTransitionGuard(
                    from_state="human_review_required",
                    to_state="validated",
                    required_gates=[
                        "human_reviewed",
                        "redacted_evidence_attached",
                    ],
                ),
                LifecycleTransitionGuard(
                    from_state="validated",
                    to_state="reported",
                    required_gates=[
                        "report_submission_approval",
                        "auto_submit_block_confirmed",
                    ],
                ),
                LifecycleTransitionGuard(
                    from_state="fixed",
                    to_state="regression_verified",
                    required_gates=["patch_or_regression_confirmed"],
                ),
            ],
        ),
        agent_memory=AgentMemoryPlan(
            status="advisory_update_planned",
            retained_signals=[
                "dedup_key",
                "vuln_type",
                "severity",
                "root_cause_summary",
                "false_positive_reason",
                "candidate_rank_hint",
            ],
        ),
        continuous_scan=ContinuousScanPlan(
            status="advisory_plan_ready",
            execution_allowed=False,
            cadence="manual_or_approved_ci_only",
            scope_requirement="allowed_repos_scope_checked",
        ),
        patch_validation=PatchValidationPlan(
            status="advisory_plan_ready",
            execution_allowed=False,
            validation_type="non_destructive_regression_recheck",
            approval_required=True,
        ),
        deep_research=DeepResearchSchedulerPlan(
            status="advisory_plan_ready",
            execution_allowed=False,
            mode="deep_reasoning_plan_only",
            human_review_required=True,
        ),
        long_horizon=LongHorizonSchedulerPlan(
            status="advisory_plan_ready",
            execution_allowed=False,
            mode="path_switch_plan_only",
            auto_path_switch_allowed=False,
            human_review_required=True,
        ),
        knowledge_base=KnowledgeBaseSchedulerPlan(
            status="advisory_plan_ready",
            execution_allowed=False,
            mode="structured_pattern_catalog_only",
            ranking_permission_granted=False,
            auto_learn_live_sources=False,
            human_review_required=True,
        ),
        multi_hour_agent_loop=MultiHourAgentLoopSchedulerPlan(
            status="advisory_plan_ready",
            execution_allowed=False,
            mode="advisory_multi_session_plan_only",
            auto_tick_allowed=False,
            auto_session_advance_allowed=False,
            ranking_permission_granted=False,
            human_review_required=True,
        ),
        wall_clock_multi_hour_runner=WallClockMultiHourRunnerSchedulerPlan(
            status="advisory_plan_ready",
            execution_allowed=False,
            mode="advisory_wall_clock_tick_ledger_only",
            auto_tick_allowed=False,
            auto_session_advance_allowed=False,
            ranking_permission_granted=False,
            human_review_required=True,
        ),
        human_review_approvals=HumanReviewApprovalsSchedulerPlan(
            status="durable_offline_approvals_context_only",
            execution_allowed=False,
            mode="audit_context_never_unlocks_gates",
            patch_ready=False,
            auto_pr_allowed=False,
            report_submission_allowed=False,
            ranking_permission_granted=False,
            human_review_required=True,
        ),
        safety_invariants=SAFETY_INVARIANTS,
    )


def _dag_tasks(context: dict) -> list[AgentTask]:
    has_crs = bool(context.get("crs_fuzzing"))
    has_local_fuzz_sandbox = bool(context.get("local_fuzz_sandbox")) or has_crs
    has_protocol_aware_fuzzing = bool(context.get("protocol_aware_fuzzing")) or has_crs
    has_v2 = bool(context.get("authorized_bug_bounty"))
    has_patch_pr = bool(
        context.get("patch_pr_workflow")
        or context.get("patch_industrial_loop")
        or context.get("patch_suggestions")
    )
    has_patch_diff_learner = bool(
        context.get("patch_diff_learner")
        or context.get("patch_diff")
        or has_patch_pr
    )
    has_variant_analysis = bool(
        context.get("variant_analysis")
        or context.get("source_hypotheses")
        or context.get("retained_candidates")
        or context.get("confirmed_findings")
        or context.get("patch_diff_learner")
        or has_patch_diff_learner
    )

    has_vuln_chain_builder = bool(
        context.get("vuln_chain_builder")
        or context.get("source_hypotheses")
        or context.get("retained_candidates")
        or context.get("confirmed_findings")
        or context.get("variant_analysis")
        or has_variant_analysis
    )

    has_deep_code_reasoning = bool(
        context.get("deep_code_reasoning")
        or context.get("source_hypotheses")
        or context.get("retained_candidates")
        or context.get("confirmed_findings")
        or context.get("vuln_chain_builder")
        or has_vuln_chain_builder
    )
    return [
        AgentTask(
            task_id="T-001",
            agent="scope_agent",
            purpose="Confirm repository and target artifacts are authorized before other agents run.",
            input_summary="Scope policy, local repository path, and imported artifact boundaries.",
            output_summary="Scope gate prepared for downstream plan-only agents.",
            evidence_refs=["scope"],
            next_actions=["Block downstream tasks if scope is missing or denied."],
            safety_gate="scope_guard_required",
        ),
        AgentTask(
            task_id="T-001b",
            agent="intake_agent",
            purpose="Identify languages, frameworks, package managers, and entrypoints from authorized local artifacts.",
            input_summary="Authorized package code, manifests, and optional local source excerpts under package_root.",
            output_summary="Advisory stack/entrypoint intake profile for attack-surface context only.",
            depends_on=["T-001"],
            evidence_refs=["intake_profile"],
            next_actions=[
                "Use stack profile to guide static analysis focus.",
                "Do not perform network scans or remote clones.",
            ],
            safety_gate="advisory_plan_only",
        ),
        AgentTask(
            task_id="T-001c",
            agent="dependency_agent",
            purpose="Read local dependency manifests and build an advisory SBOM with reachability heuristics.",
            input_summary="Authorized package manifests, lockfiles, offline SBOM fixtures, and local import facts.",
            output_summary="Dependency/SBOM profile remains advisory; no live CVE lookup or package installs.",
            depends_on=["T-001b"],
            evidence_refs=["dependency_profile"],
            next_actions=[
                "Prioritize reachable dependencies for human review.",
                "Do not query public advisory networks automatically.",
            ],
            safety_gate="advisory_plan_only",
        ),
        AgentTask(
            task_id="T-002",
            agent="code_auditor",
            purpose="Generate static source hypotheses from authorized local code.",
            input_summary="Authorized local code facts and source-audit hypotheses.",
            output_summary="Unverified source hypotheses queued for dedup and risk sorting.",
            depends_on=["T-001c"],
            evidence_refs=["hypotheses"],
            next_actions=["Attach local evidence and refutation before promotion."],
        ),
        AgentTask(
            task_id="T-003",
            agent="crs_fuzzing_agent",
            purpose="Plan parser/harness/fuzzer work from authorized package local artifacts only.",
            input_summary="Authorized package_root or code files; CRS plan is package-ingest + multi-language candidate detection.",
            output_summary="Harness sketches and fuzzer command previews remain plan-only; never auto-execute or promote crashes.",
            depends_on=["T-001c"],
            status="planned" if has_crs else "skipped_no_crs_artifacts",
            evidence_refs=["crs_fuzzing"],
            next_actions=[
                "Review harness sketches and seed corpus plan.",
                "Optional: human --allow-crs-harness-write exports sketches under _export/crs_harness/ only.",
                "Do not execute fuzzing, spawn processes, or promote crashes without human approval.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-003b",
            agent="crs_fuzzing_agent",
            purpose="Optional local harness sketch file export under human flag (write-only; never execute).",
            input_summary="CRS harness plans plus explicit human_allow_harness_write; package_root only.",
            output_summary="Sketch files under _export/crs_harness/; execution_allowed remains false; no crash promotion.",
            depends_on=["T-003"],
            status="planned" if has_crs else "skipped_no_crs_artifacts",
            evidence_refs=["crs_fuzzing"],
            next_actions=[
                "Human reviews exported sketches before any future local sandbox.",
                "Never spawn fuzzers or promote crashes from export files.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-003c",
            agent="local_fuzz_sandbox_agent",
            purpose="Plan/export approved local-only fuzz sandbox recipes under human flag (never execute).",
            input_summary="CRS harness plans plus optional human_allow_sandbox_write; package_root only.",
            output_summary="Sandbox recipe files under _export/fuzz_sandbox/; process_spawn and crash promotion remain false.",
            depends_on=["T-003", "T-003b"],
            status="planned" if has_local_fuzz_sandbox else "skipped_no_crs_artifacts",
            evidence_refs=["local_fuzz_sandbox", "crs_fuzzing"],
            next_actions=[
                "Human reviews sandbox recipes before any future local fuzzer run outside Mythos.",
                "Optional: --allow-local-fuzz-sandbox-write exports Dockerfile/recipe only.",
                "Never spawn AFL++/libFuzzer or promote crashes from export files.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-003d",
            agent="local_fuzz_runner_agent",
            purpose="Optional human-flagged local in-process Python fuzz run (never AFL++/libFuzzer spawn; never promote crashes).",
            input_summary="CRS/sandbox harness targets plus explicit human_allow_local_fuzz_run; authorized package_root only.",
            output_summary="In-process crash candidates stay local artifacts; promotion/submit always blocked; external fuzzer remains preview-only.",
            depends_on=["T-003", "T-003b", "T-003c"],
            status="planned",
            evidence_refs=["local_fuzz_runner"],
            next_actions=[
                "Require explicit human local flag before in-process Python harness run.",
                "Never spawn AFL++/libFuzzer from Mythos; never promote crashes or unlock submit.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-003e",
            agent="crash_triage_agent",
            purpose="Dedupe/minimize/classify local fuzz crashes and draft advisory root-cause (never promote).",
            input_summary="local_fuzz_runner crash_candidates plus explicit human_allow_crash_triage; authorized package_root only.",
            output_summary="Crash clusters with reproducibility/minimization notes stay advisory; promotion/submit always blocked.",
            depends_on=["T-003", "T-003b", "T-003c", "T-003d"],
            status="planned",
            evidence_refs=["crash_triage"],
            next_actions=[
                "Require explicit human flag before minimize/repro execution.",
                "Never promote crashes or unlock submit from triage exports.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-003f",
            agent="crash_regression_agent",
            purpose="Plan residual regression tests from triaged crash clusters (text-only; never auto-run).",
            input_summary="crash_triage clusters/repro/minimize notes plus optional human export flag; authorized package_root only.",
            output_summary="Regression suggestions stay plan-only; test auto-execute/promotion/submit always blocked.",
            depends_on=["T-003", "T-003b", "T-003c", "T-003d", "T-003e"],
            status="planned",
            evidence_refs=["crash_regression"],
            next_actions=[
                "Human turns suggestions into non-destructive local tests.",
                "Never auto-execute tests or promote crashes from regression plans.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-003g",
            agent="crash_codepath_agent",
            purpose="Statically link triaged crash clusters to advisory code paths (never confirm/promote).",
            input_summary="crash_triage clusters plus authorized package_root for static source read only.",
            output_summary="Code-path links stay advisory; package execution/promotion/submit always blocked.",
            depends_on=["T-003", "T-003b", "T-003c", "T-003d", "T-003e"],
            status="planned",
            evidence_refs=["crash_codepath"],
            next_actions=[
                "Human reviews linked file/function/symbol spans offline.",
                "Never promote crashes or confirm vulnerabilities from static links.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-003h",
            agent="protocol_aware_fuzzing_agent",
            purpose="Plan protocol grammar/message-boundary/seed corpus from CRS parsers (never execute).",
            input_summary="CRS parser_candidates plus optional offline inputs/protocol*.json; authorized package_root only.",
            output_summary="Protocol-aware fuzzing plans stay plan-only; process spawn/network/promotion/submit always blocked.",
            depends_on=["T-003", "T-003b", "T-003c"],
            status="planned" if has_protocol_aware_fuzzing else "skipped_no_crs_artifacts",
            evidence_refs=["protocol_aware_fuzzing", "crs_fuzzing"],
            next_actions=[
                "Human reviews grammar and seed plans offline.",
                "Never spawn protocol fuzzers or promote crashes from plans.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-004",
            agent="bug_bounty_agent",
            purpose="Plan authorized Web/API role and business-logic review.",
            input_summary="Allowed assets, API operations, role models, and human gate state.",
            output_summary="Role-diff and business-logic plans are blocked behind human review.",
            depends_on=["T-001c"],
            status="planned" if has_v2 else "skipped_no_v2_artifacts",
            evidence_refs=["authorized_bug_bounty"],
            next_actions=["Require durable approval before any authenticated validation."],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-002b",
            agent="semgrep_runner",
            purpose="Optional human-flagged local Semgrep CLI over authorized package roots only.",
            input_summary="Authorized package_root, offline rule config or embedded offline rules, explicit human_allow_local_semgrep flag.",
            output_summary="Local Semgrep findings stay advisory; default plan-only without human flag; never remote rules or submit.",
            depends_on=["T-001c"],
            evidence_refs=["semgrep_runner"],
            next_actions=[
                "Require explicit human local flag before invoking Semgrep CLI.",
                "Prefer offline inputs/advisory fixtures when binary is absent.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-002c",
            agent="codeql_runner",
            purpose="Optional human-flagged local CodeQL CLI over authorized package roots only.",
            input_summary="Authorized package_root, pre-built local CodeQL database, local query suite, explicit human_allow_local_codeql flag.",
            output_summary="Local CodeQL findings stay advisory; default plan-only without human flag; never remote packs or submit.",
            depends_on=["T-001c"],
            evidence_refs=["codeql_runner"],
            next_actions=[
                "Require explicit human local flag before invoking CodeQL CLI.",
                "Require pre-built local database + local suite under package; prefer offline advisory fixtures when binary/DB/suite absent.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-005",
            agent="dedup_agent",
            purpose="Cluster equivalent findings before promotion.",
            input_summary="Unverified findings from source, CRS, and authorized Web/API planning.",
            output_summary="Finding clusters prepared for human triage.",
            depends_on=["T-002", "T-002b", "T-002c", "T-003", "T-004"],
            evidence_refs=["finding_clusters"],
            next_actions=["Review duplicate clusters before evidence promotion."],
        ),
        AgentTask(
            task_id="T-006",
            agent="risk_prioritizer",
            purpose="Sort findings by severity and evidence quality.",
            input_summary="Unverified findings, dedup keys, severity, and advisory memory signals.",
            output_summary="Risk queue prepared without granting execution permission.",
            depends_on=["T-002", "T-002b", "T-002c", "T-003", "T-004"],
            evidence_refs=["risk_queue"],
            next_actions=["Use risk ordering only to guide human review priority."],
        ),
        AgentTask(
            task_id="T-006b",
            agent="verifier_agent",
            purpose="Deeper multi-engine verification from factory stack signals (plan/advisory only).",
            input_summary="Hunter/map/bridge plus CRS, crash triage/regression, residual gate/runner, Web/API, Semgrep/CodeQL runner postures.",
            output_summary="Multi-engine verdict remains local-static agreement only; never verified exploit or submit.",
            depends_on=["T-005", "T-006", "T-003", "T-003b", "T-003c", "T-003d", "T-003e", "T-003f", "T-003g", "T-003h", "T-004", "T-002b", "T-002c"],
            status="planned",
            evidence_refs=["multi_engine_verdict"],
            next_actions=[
                "Human reviews multi-engine agreement and residual questions.",
                "Do not execute live validation or promote findings from agreement alone.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-007",
            agent="report_agent",
            purpose="Prepare report draft only after dedup, prioritization, and human gate.",
            input_summary="Deduped findings, risk queue, multi-engine verdicts, report draft policy, and evidence gates.",
            output_summary="Report draft remains submission-blocked until human review.",
            depends_on=["T-005", "T-006", "T-006b"],
            evidence_refs=["report_draft"],
            next_actions=["Require redacted evidence and human approval before submission."],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-007b",
            agent="residual_runner",
            purpose="Run human-approved local residual static probes only (no network, no live exploit).",
            input_summary="Residual checklist items, durable residual_review approval, authorized local code facts.",
            output_summary="Residual runner stays plan-only without approval; local static results never unlock submit.",
            depends_on=["T-007"],
            evidence_refs=["residual_runner"],
            next_actions=[
                "Require residual_review approval before executing local residual probes.",
                "Do not perform live validation or network residual checks.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-008",
            agent="patch_agent",
            purpose="Produce advisory root-cause fix and regression suggestions only.",
            input_summary="Unverified candidate root_cause_id, affected code path, multi-engine status, residual runner context.",
            output_summary="Patch suggestion remains advisory; no auto-PR, no exploit PoC, no live validation.",
            depends_on=["T-007b"],
            evidence_refs=["patch_suggestion"],
            next_actions=[
                "Human reviews suggested fix principles and regression tests.",
                "Do not open PRs or execute patches automatically.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-008b",
            agent="patch_industrial_loop",
            purpose="Industrialize advisory patch suggestions with local context and regression plans only.",
            input_summary="Patch suggestions, multi-engine status, local package code, optional patch_review approvals.",
            output_summary="Patch industrial loop remains advisory; sketches and regression plans never auto-PR or validate live.",
            depends_on=["T-008"],
            evidence_refs=["patch_industrial_loop"],
            next_actions=[
                "Human reviews minimal fix sketches and planned regression steps.",
                "Do not apply diffs, open PRs, or execute live patch validation.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-008c",
            agent="patch_pr_workflow",
            purpose="Export plan-only external PR handoff package for humans to open PRs outside Mythos.",
            input_summary="Patch industrial loop items or patch suggestions, optional patch_review approvals, optional human export-write flag.",
            output_summary="External PR export remains plan-only; never opens PRs, never git push, never gh CLI, never sets patch_ready.",
            depends_on=["T-008b"],
            status="planned" if has_patch_pr else "skipped_no_patch_pr_artifacts",
            evidence_refs=["patch_pr_workflow"],
            next_actions=[
                "Human copies export artifacts and opens a PR outside Mythos if appropriate.",
                "Do not auto-open PRs, apply diffs, push git, or mark patch_ready.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-008d",
            agent="patch_diff_learner_agent",
            purpose="Learn advisory root-cause/fix/regression patterns from offline patch diffs (never apply/PR).",
            input_summary="Offline inputs/patch_diff*.json and/or bridge patch_diff, patch_industrial_loop, patch_suggestions.",
            output_summary="Patch-diff learned patterns remain plan-only; never apply, open PR, live-validate, or set patch_ready.",
            depends_on=["T-008", "T-008b", "T-008c"],
            status="planned" if has_patch_diff_learner else "skipped_no_patch_diff_artifacts",
            evidence_refs=["patch_diff_learner"],
            next_actions=[
                "Human reviews learned patterns and applicability boundaries offline.",
                "Do not apply diffs, open PRs, or treat patterns as confirmed vulnerabilities.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-009",
            agent="human_gate_dry_run_agent",
            purpose="Offline end-to-end human-gate dry-run over bridge residual/approvals/report/patch/MEV posture.",
            input_summary="Bridge result after residual gates, approvals, drafts, patch/PR, crash stack, multi-engine deepen; authorized package only.",
            output_summary="Human-gate dry-run checkpoints remain offline; never probes HackerOne, never unlocks submit/execute/promote.",
            depends_on=["T-007", "T-007b", "T-008", "T-008b", "T-008c", "T-008d", "T-006b", "T-003e", "T-003f", "T-003g", "T-003h"],
            evidence_refs=["human_gate_dry_run"],
            next_actions=[
                "Human reviews dry-run checkpoints offline.",
                "Do not probe HackerOne, auto-submit, or treat dry-run pass as live gate proof.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-010",
            agent="agent_memory_agent",
            purpose="Advisory V3 agent memory: offline FP/retain/knowledge reuse for ranking only.",
            input_summary="Bridge residual gates, drafts, multi-engine posture, optional package inputs/agent_memory.json or memory/knowledge artifacts.",
            output_summary="Agent memory entries and candidate rank hints remain advisory; never grants execute/submit/promote or ranking_permission.",
            depends_on=["T-007", "T-007b", "T-006b", "T-009"],
            evidence_refs=["agent_memory"],
            next_actions=[
                "Human reviews memory rank hints and FP patterns offline.",
                "Do not treat memory as execution permission, confirmed vulnerability, or auto-submit signal.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-011",
            agent="continuous_scan_agent",
            purpose="Advisory V3 continuous scan cadence for authorized packages only.",
            input_summary="Authorized package scope/policy/code artifacts, optional inputs/continuous_scan.json, bridge intake posture.",
            output_summary="Continuous scan jobs/watch paths remain plan-only; never auto-scans, never network/public targets.",
            depends_on=["T-001", "T-001b", "T-010"],
            evidence_refs=["continuous_scan"],
            next_actions=[
                "Human schedules approved re-audit manually or in authorized CI.",
                "Do not auto-scan, hit public targets, or treat cadence plan as live execution.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-012",
            agent="patch_validation_agent",
            purpose="Advisory V3 patch validation: non-destructive regression recheck plans after fix artifacts.",
            input_summary="Patch industrial loop / suggestions / crash regression / optional inputs/patch_validation.json.",
            output_summary="Patch validation steps remain plan-only; never apply patches, open PRs, live-validate, or mark patch_ready.",
            depends_on=["T-008", "T-008b", "T-008c", "T-008d", "T-003f", "T-010"],
            evidence_refs=["patch_validation"],
            next_actions=[
                "Human performs non-destructive local recheck using planned steps.",
                "Do not apply diffs, open PRs, run exploit PoCs, or auto-mark fixed.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-013",
            agent="deep_research_agent",
            purpose="Advisory V4 deep research: multi-stage chains, variants, long-horizon plan only.",
            input_summary="Bridge drafts/residuals, optional inputs/deep_research.json, CRS parsers, patch diff metadata.",
            output_summary="Deep research chains/variants/refutations remain plan-only; never exploits, execute, or submit.",
            depends_on=["T-006b", "T-010", "T-011", "T-012"],
            evidence_refs=["deep_research"],
            next_actions=[
                "Human reviews multi-stage chains and variant search offline.",
                "Do not treat deep research as confirmed vulnerability or execution permission.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-013b",
            agent="variant_analysis_agent",
            purpose="Advisory V4 first-class variant analysis: sibling search plans from seeds (plan only).",
            input_summary="Hypotheses, retained candidates, findings, optional patch_diff_learner patterns, inputs/variant*.json.",
            output_summary="Variant search scopes remain plan-only; never exploits, promotes, submits, or live-validates.",
            depends_on=["T-013", "T-008d", "T-006b", "T-010"],
            status="planned" if has_variant_analysis else "skipped_no_variant_seeds",
            evidence_refs=["variant_analysis"],
            next_actions=[
                "Human reviews sibling-variant search scopes offline on authorized local code.",
                "Do not treat planned variants as confirmed vulnerabilities or execution permission.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-013c",
            agent="vuln_chain_builder_agent",
            purpose="Advisory V4 first-class vulnerability chain builder: multi-stage chains from seeds (plan only).",
            input_summary="Hypotheses, retained candidates, findings, optional variant_analysis variants, residual gates, inputs/chain*.json.",
            output_summary="Multi-stage chain plans remain plan-only; never exploits, promotes, submits, or live-validates.",
            depends_on=["T-013", "T-013b", "T-006b", "T-010"],
            status="planned" if has_vuln_chain_builder else "skipped_no_chain_seeds",
            evidence_refs=["vuln_chain_builder"],
            next_actions=[
                "Human reviews multi-stage chain plans offline with local evidence and refutation questions.",
                "Do not treat planned chains as confirmed vulnerabilities or execution permission.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-013d",
            agent="deep_code_reasoning_agent",
            purpose="Advisory V4 first-class deep code reasoning: permission models + cross-file paths (plan only).",
            input_summary="Hypotheses, retained candidates, findings, optional vuln_chain_builder chains, role models, inputs/deep_code*.json.",
            output_summary="Permission model sketches and cross-file paths remain plan-only; never exploits, promotes, submits, or live-validates.",
            depends_on=["T-013", "T-013b", "T-013c", "T-006b", "T-010"],
            status="planned" if has_deep_code_reasoning else "skipped_no_reasoning_seeds",
            evidence_refs=["deep_code_reasoning"],
            next_actions=[
                "Human reviews permission models and cross-file paths offline with local evidence.",
                "Do not treat planned reasoning paths as confirmed vulnerabilities or execution permission.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-014",
            agent="long_horizon_agent",
            purpose="Advisory V4 long-horizon path switching and reflection (plan only).",
            input_summary="Deep research plan, residual gates, agent memory FP signals, optional inputs/long_horizon.json.",
            output_summary="Path graph + failure switches remain plan-only; never auto path switch, execute, or submit.",
            depends_on=["T-013", "T-013b", "T-013c", "T-013d", "T-010", "T-006b"],
            evidence_refs=["long_horizon"],
            next_actions=[
                "Human reviews planned path switches offline after failed refutation.",
                "Do not auto-execute alternate paths or live validation.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-015",
            agent="knowledge_base_agent",
            purpose="Advisory final-scheme section-7 knowledge consolidation into structured patterns.",
            input_summary="Deep research knowledge queue, agent memory, long-horizon reflections, optional inputs/knowledge*.json.",
            output_summary="Structured pattern catalog only; never grants ranking execution, live learning, submit, or promote.",
            depends_on=["T-014", "T-013", "T-013b", "T-013c", "T-013d", "T-010"],
            evidence_refs=["knowledge_base"],
            next_actions=[
                "Human reviews structured patterns offline before any reuse ranking.",
                "Do not auto-learn from live internet sources or unlock ranking permission.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-016",
            agent="multi_hour_agent_loop_agent",
            purpose="Advisory multi-hour multi-session agent loop plan beyond V4 long-horizon path graph.",
            input_summary="Knowledge base patterns, long-horizon paths, deep research, human-gate dry-run, residual stack.",
            output_summary="Multi-session budget/handoff/human-gate plan only; never auto-tick, execute, promote, or submit.",
            depends_on=["T-015", "T-014", "T-013", "T-010"],
            evidence_refs=["multi_hour_agent_loop"],
            next_actions=[
                "Human reviews session budgets and gates offline before any session work.",
                "Do not auto-tick sessions or auto-advance phases.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-017",
            agent="wall_clock_multi_hour_runner_agent",
            purpose="Advisory true wall-clock multi-hour schedule and human-gated tick ledger beyond multi-hour plan.",
            input_summary="Multi-hour sessions/phases/gates, residual stack, optional inputs/wall_clock*.json.",
            output_summary="Wall-clock schedule + dry-run tick ledger only; never auto-tick, execute, promote, or submit.",
            depends_on=["T-016"],
            evidence_refs=["wall_clock_multi_hour_runner"],
            next_actions=[
                "Human reviews tick ledger offline before any tick work.",
                "Do not auto-tick or auto-advance wall-clock sessions.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-018",
            agent="human_review_approvals_agent",
            purpose="Durable offline residual/patch human review approvals audit and decision context.",
            input_summary="Optional inputs/human_review_approvals.json; residual gate and patch suggestion context.",
            output_summary="Approval audit context only; never unlocks execute, submit, patch_ready, or auto-PR.",
            depends_on=["T-007", "T-008", "T-008b", "T-008c", "T-008d"],
            evidence_refs=["human_review_approvals", "residual_patch_decision_api"],
            next_actions=[
                "Human records residual_review / patch_review offline under package inputs.",
                "Do not treat approvals as confirmed vulnerability or submission unlock.",
            ],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),


    ]


def _findings(value: object) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _finding_clusters(findings: list[dict]) -> list[FindingCluster]:
    grouped: dict[str, list[str]] = {}
    for finding in findings:
        finding_id = _safe_text(finding.get("finding_id"), "unknown")
        key = _dedup_key(finding)
        grouped.setdefault(key, []).append(finding_id)
    return [
        FindingCluster(
            cluster_id=f"C-{index:03d}",
            finding_ids=ids,
            dedup_key=key,
        )
        for index, (key, ids) in enumerate(grouped.items(), start=1)
    ]


def _risk_queue(findings: list[dict]) -> list[RiskQueueItem]:
    sorted_findings = sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(_safe_text(finding.get("severity"), "info").lower(), 99),
            _safe_text(finding.get("finding_id"), "unknown"),
        ),
    )
    return [
        RiskQueueItem(
            finding_id=_safe_text(finding.get("finding_id"), "unknown"),
            severity=_safe_text(finding.get("severity"), "info").lower(),
            priority=index,
            reason="severity_then_stable_id_order",
        )
        for index, finding in enumerate(sorted_findings, start=1)
    ]


def _dedup_key(finding: dict) -> str:
    vuln_type = _safe_text(finding.get("vuln_type"), "unknown").lower()
    endpoint = _safe_text(finding.get("affected_endpoint"), "none").lower()
    title = _safe_text(finding.get("title"), "none").lower()
    return f"{vuln_type}:{endpoint or title}"


def _safe_text(value: object, default: str) -> str:
    if not isinstance(value, str):
        return default
    return value.strip()[:180] or default
