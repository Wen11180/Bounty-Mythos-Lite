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
            ParallelBatch(batch_id="B-002", task_ids=["T-002", "T-003", "T-004"]),
            ParallelBatch(batch_id="B-003", task_ids=["T-005", "T-006"]),
            ParallelBatch(batch_id="B-004", task_ids=["T-007"]),
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
            ],
        ),
        continuous_scan=ContinuousScanPlan(
            status="planned_requires_authorized_repo",
            execution_allowed=False,
            cadence="manual_or_approved_ci_only",
            scope_requirement="allowed_repos_scope_checked",
        ),
        patch_validation=PatchValidationPlan(
            status="planned_after_fix_available",
            execution_allowed=False,
            validation_type="non_destructive_regression_recheck",
            approval_required=True,
        ),
        safety_invariants=SAFETY_INVARIANTS,
    )


def _dag_tasks(context: dict) -> list[AgentTask]:
    has_crs = bool(context.get("crs_fuzzing"))
    has_v2 = bool(context.get("authorized_bug_bounty"))
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
            task_id="T-002",
            agent="code_auditor",
            purpose="Generate static source hypotheses from authorized local code.",
            input_summary="Authorized local code facts and source-audit hypotheses.",
            output_summary="Unverified source hypotheses queued for dedup and risk sorting.",
            depends_on=["T-001"],
            evidence_refs=["hypotheses"],
            next_actions=["Attach local evidence and refutation before promotion."],
        ),
        AgentTask(
            task_id="T-003",
            agent="crs_fuzzing_agent",
            purpose="Plan parser and harness work from local artifacts.",
            input_summary="Parser candidates and local-only CRS/fuzzing plan artifacts.",
            output_summary="Harness and fuzzer plans remain non-executable until approval.",
            depends_on=["T-001"],
            status="planned" if has_crs else "skipped_no_crs_artifacts",
            evidence_refs=["crs_fuzzing"],
            next_actions=["Prepare local harness review; do not execute fuzzing automatically."],
        ),
        AgentTask(
            task_id="T-004",
            agent="bug_bounty_agent",
            purpose="Plan authorized Web/API role and business-logic review.",
            input_summary="Allowed assets, API operations, role models, and human gate state.",
            output_summary="Role-diff and business-logic plans are blocked behind human review.",
            depends_on=["T-001"],
            status="planned" if has_v2 else "skipped_no_v2_artifacts",
            evidence_refs=["authorized_bug_bounty"],
            next_actions=["Require durable approval before any authenticated validation."],
            requires_human_review=True,
            safety_gate="human_review_required",
        ),
        AgentTask(
            task_id="T-005",
            agent="dedup_agent",
            purpose="Cluster equivalent findings before promotion.",
            input_summary="Unverified findings from source, CRS, and authorized Web/API planning.",
            output_summary="Finding clusters prepared for human triage.",
            depends_on=["T-002", "T-003", "T-004"],
            evidence_refs=["finding_clusters"],
            next_actions=["Review duplicate clusters before evidence promotion."],
        ),
        AgentTask(
            task_id="T-006",
            agent="risk_prioritizer",
            purpose="Sort findings by severity and evidence quality.",
            input_summary="Unverified findings, dedup keys, severity, and advisory memory signals.",
            output_summary="Risk queue prepared without granting execution permission.",
            depends_on=["T-002", "T-003", "T-004"],
            evidence_refs=["risk_queue"],
            next_actions=["Use risk ordering only to guide human review priority."],
        ),
        AgentTask(
            task_id="T-007",
            agent="report_agent",
            purpose="Prepare report draft only after dedup, prioritization, and human gate.",
            input_summary="Deduped findings, risk queue, report draft policy, and evidence gates.",
            output_summary="Report draft remains submission-blocked until human review.",
            depends_on=["T-005", "T-006"],
            evidence_refs=["report_draft"],
            next_actions=["Require redacted evidence and human approval before submission."],
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
