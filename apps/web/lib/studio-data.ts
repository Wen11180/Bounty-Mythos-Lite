export type StudioWorkspaceManifest = {
  name?: string;
  artifacts?: Array<{
    kind?: string;
    source_path?: string;
    redaction_status?: string;
  }>;
  runs?: Array<{
    run_id?: string;
    status?: string;
    candidate_count?: number;
    benchmark_status?: string;
    benchmark_path?: string;
  }>;
  benchmarks?: Array<{
    run_id?: string;
    status?: string;
    benchmark_path?: string;
    matched?: number;
    expected_count?: number;
  }>;
  benchmark_templates?: Array<{
    run_id?: string;
    template_path?: string;
    expected_count?: number;
    draft_review_required?: boolean;
  }>;
  safety?: {
    scope_guard_status?: string;
    blocked_actions?: string[];
  };
};

export type StudioWorkspaceSummary = {
  name: string;
  artifactCount: number;
  runCount: number;
  scopeGuardLabel: string;
  blockedActions: string[];
};

export type StudioMissionCandidateInput = {
  affected_code_path?: string;
  affected_endpoint?: string;
  deduplication_review_status?: string;
  evidence_gap_count?: number;
  evidence_need_count?: number;
  evidence_review_status?: string;
  execution_allowed?: boolean;
  false_positive_check_count?: number;
  hallucination_guard?: {
    advisory_sources?: string[];
    blockers?: string[];
    cross_validation_sources?: string[];
    high_confidence_allowed?: boolean;
    local_evidence_sources?: string[];
    model_output_status?: string;
    required_consensus?: string[];
    status?: string;
  };
  hypothesis_id?: string;
  next_report_action?: string;
  policy_review_status?: string;
  priority_score?: number;
  quality_reasons?: string[];
  quality_score?: number;
  quality_status?: string;
  provenance_artifacts?: string[];
  provenance_review_status?: string;
  refutation_review_status?: string;
  refutation_status?: string;
  report_status?: string;
  risk?: string;
  safe_validation_step_count?: number;
  validation_status?: string;
  vuln_type?: string;
};

export type StudioMissionResearchLoopStageInput = {
  key?: string;
  status?: string;
  summary?: string;
};

export type StudioMissionAgentTaskInput = {
  agent?: string;
  candidate_quality_gaps?: string[];
  input_refs?: string[];
  next_action?: string;
  review_focus?: string[];
  safety_gate?: string;
  status?: string;
  target_candidates?: string[];
  task_id?: string;
};

export type StudioMissionSummary = {
  agent_queue?: StudioMissionAgentTaskInput[];
  artifacts?: {
    missing?: string[];
    present?: string[];
    required?: string[];
  };
  advisory_artifacts?: {
    present?: string[];
    supported?: string[];
  };
  blocked_actions?: string[];
  candidate_count?: number;
  mode?: string;
  next_actions?: string[];
  quality_summary?: {
    average_quality_score?: number;
    blockers?: string[];
    candidate_count?: number;
    improvement_actions?: string[];
    required_candidate_max?: number;
    required_candidate_min?: number;
    review_ready_count?: number;
    review_ready_threshold?: number;
    status?: string;
    top_candidate_quality_gate?: string;
  };
  quality_gates?: {
    human_review_required?: boolean;
    report_submission_allowed?: boolean;
    submission_blocked?: boolean;
    top_candidate_quality_gate?: boolean;
    top_candidates_limited?: boolean;
    validation_execution_allowed?: boolean;
  };
  research_loop?: StudioMissionResearchLoopStageInput[];
  run_id?: string | null;
  scope_guard_status?: string;
  top_candidates?: StudioMissionCandidateInput[];
};

export type StudioMissionPanelCandidate = {
  affectedCodePath: string;
  affectedEndpoint: string;
  deduplicationReviewStatus: string;
  evidenceGapCount: number;
  evidenceNeedCount: number;
  evidenceReviewStatus: string;
  executionAllowed: boolean;
  falsePositiveCheckCount: number;
  hallucinationGuard: {
    advisorySources: string[];
    blockers: string[];
    crossValidationSources: string[];
    highConfidenceAllowed: boolean;
    localEvidenceSources: string[];
    modelOutputStatus: string;
    requiredConsensus: string[];
    status: string;
  };
  hypothesisId: string;
  nextReportAction: string;
  policyReviewStatus: string;
  priorityScore: number;
  qualityReasons: string[];
  qualityScore: number;
  qualityStatus: string;
  provenanceArtifacts: string[];
  provenanceReviewStatus: string;
  refutationReviewStatus: string;
  refutationStatus: string;
  reportStatus: string;
  risk: string;
  safeValidationStepCount: number;
  validationStatus: string;
  vulnType: string;
};

export type StudioMissionResearchLoopStage = {
  key: string;
  label: string;
  status: string;
  summary: string;
};

export type StudioMissionAgentTask = {
  agent: string;
  candidateQualityGaps: string[];
  inputRefs: string[];
  nextAction: string;
  reviewFocus: string[];
  safetyGate: string;
  status: string;
  targetCandidates: string[];
  taskId: string;
};

export type StudioMissionPanel = {
  advisoryContextLabel: string;
  agentQueue: StudioMissionAgentTask[];
  artifactCoverage: string;
  blockedActions: string[];
  candidateCountLabel: string;
  gates: {
    humanReviewRequired: boolean;
    reportSubmissionAllowed: boolean;
    submissionBlocked: boolean;
    topCandidateQualityGate: boolean;
    topCandidatesLimited: boolean;
    validationExecutionAllowed: boolean;
  };
  modeLabel: string;
  qualitySummary: {
    averageQualityScore: number;
    blockers: string[];
    candidateCount: number;
    improvementActions: string[];
    reviewReadyCount: number;
    reviewReadyThreshold: number;
    status: string;
    topCandidateQualityGate: string;
  };
  researchLoopStages: StudioMissionResearchLoopStage[];
  runId: string;
  safeNextActions: string[];
  scopeGuardLabel: string;
  topCandidates: StudioMissionPanelCandidate[];
};

export type StudioArtifactChecklistItem = {
  kind:
    | "scope"
    | "code"
    | "policy"
    | "api"
    | "har"
    | "sbom"
    | "sarif"
    | "fuzzing"
    | "strategy"
    | "knowledge";
  label: string;
  present: boolean;
  required: boolean;
  status: "ready" | "missing" | "optional";
};

export type StudioResearchReadiness = {
  canStart: boolean;
  reason: string;
};

export type StudioCandidateInput = {
  hypothesis_id?: string;
  vuln_type?: string;
  risk?: string;
  location?: string;
  reason?: string;
  broken_invariant?: string;
  repair_guidance?: string;
  evidence_needed?: string[];
  false_positive_checks?: string[];
  ranking_reasons?: string[];
  report_readiness?: {
    next_allowed_action?: string;
    report_submission_allowed?: boolean;
    status?: string;
  };
  evidence_gaps?: Array<{
    artifact_kind?: string;
    reason?: string;
  }>;
  suggested_fix?: string;
  regression_test?: string;
  safe_validation_plan?: string[];
  safe_verification?: boolean;
  safety_blockers?: string[];
  priority_score?: number;
  validation_mode?: string;
  source_facts?: Array<{
    advisory_only?: string;
    artifact_kind?: string;
    ecosystem?: string;
    fact_type?: string;
    operation_id?: string;
    package_name?: string;
    package_version?: string;
    route_method?: string;
    route_path?: string;
    severity?: string;
    source_path?: string;
    symbol_name?: string;
    vulnerability_id?: string;
  }>;
};

export type StudioCandidateCard = {
  id: string;
  title: string;
  severity: string;
  status: "needs_review" | "blocked" | "needs_evidence";
  affectedEndpoint: string;
  affectedCodePath: string;
  evidenceNeeds: string[];
  evidenceGaps: string[];
  refutationQuestions: string[];
  rankingReasons: string[];
  brokenInvariant: string;
  repairGuidance: string;
  regressionTest: string;
  reason: string;
  reportReadiness: {
    nextAllowedAction: string;
    reportSubmissionAllowed: boolean;
    status: string;
  };
  safeValidationPlan: string[];
  safetyBlockers: string[];
  priorityScore: number;
  validationMode: string;
};

export function toStudioWorkspaceSummary(
  manifest: StudioWorkspaceManifest,
): StudioWorkspaceSummary {
  return {
    name: safeText(manifest.name, "Untitled workspace"),
    artifactCount: manifest.artifacts?.length ?? 0,
    runCount: manifest.runs?.length ?? 0,
    scopeGuardLabel: scopeGuardLabel(manifest.safety?.scope_guard_status),
    blockedActions: manifest.safety?.blocked_actions ?? [],
  };
}

export function toStudioMissionPanel(mission: StudioMissionSummary | null): StudioMissionPanel {
  const required = mission?.artifacts?.required ?? [];
  const present = mission?.artifacts?.present ?? [];
  const advisoryPresent = mission?.advisory_artifacts?.present ?? [];
  const candidateCount = mission?.candidate_count ?? mission?.top_candidates?.length ?? 0;
  return {
    advisoryContextLabel:
      advisoryPresent.length > 0 ? advisoryPresent.join(", ") : "No advisory context",
    agentQueue: (mission?.agent_queue ?? []).map((task) => ({
      agent: safeText(task.agent, "Review agent"),
      candidateQualityGaps: task.candidate_quality_gaps ?? [],
      inputRefs: task.input_refs ?? [],
      nextAction: safeText(task.next_action, "Review required."),
      reviewFocus: task.review_focus ?? [],
      safetyGate: safeText(task.safety_gate, "human_review_required"),
      status: safeText(task.status, "needs_review"),
      targetCandidates: task.target_candidates ?? [],
      taskId: safeText(task.task_id, "agent_task"),
    })),
    artifactCoverage: `${present.length}/${required.length} required artifacts`,
    blockedActions: mission?.blocked_actions ?? [],
    candidateCountLabel: `${candidateCount} Top ${candidateCount === 1 ? "candidate" : "candidates"}`,
    gates: {
      humanReviewRequired: mission?.quality_gates?.human_review_required === true,
      reportSubmissionAllowed: mission?.quality_gates?.report_submission_allowed === true,
      submissionBlocked: mission?.quality_gates?.submission_blocked !== false,
      topCandidateQualityGate: mission?.quality_gates?.top_candidate_quality_gate === true,
      topCandidatesLimited: mission?.quality_gates?.top_candidates_limited === true,
      validationExecutionAllowed:
        mission?.quality_gates?.validation_execution_allowed === true,
    },
    modeLabel:
      mission?.mode === "local_ai_vulnerability_research_workbench"
        ? "Local AI vulnerability research workbench"
        : "Local research workbench",
    qualitySummary: {
      averageQualityScore: mission?.quality_summary?.average_quality_score ?? 0,
      blockers: mission?.quality_summary?.blockers ?? [],
      candidateCount: mission?.quality_summary?.candidate_count ?? candidateCount,
      improvementActions: mission?.quality_summary?.improvement_actions ?? [],
      reviewReadyCount: mission?.quality_summary?.review_ready_count ?? 0,
      reviewReadyThreshold: mission?.quality_summary?.review_ready_threshold ?? 85,
      status: safeText(mission?.quality_summary?.status, "needs_review"),
      topCandidateQualityGate: safeText(
        mission?.quality_summary?.top_candidate_quality_gate,
        "needs_review",
      ),
    },
    researchLoopStages: (mission?.research_loop ?? []).map((stage) => {
      const key = safeText(stage.key, "unknown");
      return {
        key,
        label: missionResearchLoopLabel(key),
        status: safeText(stage.status, "not_started"),
        summary: safeText(stage.summary, "Review status unavailable."),
      };
    }),
    runId: safeText(mission?.run_id, "No run selected"),
    safeNextActions: (mission?.next_actions ?? []).map(missionActionLabel),
    scopeGuardLabel: scopeGuardLabel(mission?.scope_guard_status),
    topCandidates: (mission?.top_candidates ?? []).slice(0, 5).map((candidate, index) => ({
      affectedCodePath: safeText(candidate.affected_code_path, "Code path needs review"),
      affectedEndpoint: safeText(candidate.affected_endpoint, "Endpoint needs review"),
      deduplicationReviewStatus: safeText(
        candidate.deduplication_review_status,
        "needs_human_review",
      ),
      evidenceGapCount: candidate.evidence_gap_count ?? 0,
      evidenceNeedCount: candidate.evidence_need_count ?? 0,
      evidenceReviewStatus: safeText(candidate.evidence_review_status, "needs_human_review"),
      executionAllowed: candidate.execution_allowed === true,
      falsePositiveCheckCount: candidate.false_positive_check_count ?? 0,
      hallucinationGuard: {
        advisorySources: candidate.hallucination_guard?.advisory_sources ?? [],
        blockers: candidate.hallucination_guard?.blockers ?? [],
        crossValidationSources: candidate.hallucination_guard?.cross_validation_sources ?? [],
        highConfidenceAllowed: candidate.hallucination_guard?.high_confidence_allowed === true,
        localEvidenceSources: candidate.hallucination_guard?.local_evidence_sources ?? [],
        modelOutputStatus: safeText(
          candidate.hallucination_guard?.model_output_status,
          "unverified_claim_not_fact",
        ),
        requiredConsensus: candidate.hallucination_guard?.required_consensus ?? [],
        status: safeText(candidate.hallucination_guard?.status, "needs_review"),
      },
      hypothesisId: safeText(candidate.hypothesis_id, `H-${String(index + 1).padStart(3, "0")}`),
      nextReportAction: safeText(candidate.next_report_action, "Review evidence before export."),
      policyReviewStatus: safeText(candidate.policy_review_status, "needs_human_review"),
      priorityScore: candidate.priority_score ?? 0,
      qualityReasons: candidate.quality_reasons ?? [],
      qualityScore: candidate.quality_score ?? 0,
      qualityStatus: safeText(candidate.quality_status, "needs_review"),
      provenanceArtifacts: candidate.provenance_artifacts ?? [],
      provenanceReviewStatus: safeText(candidate.provenance_review_status, "needs_human_review"),
      refutationReviewStatus: safeText(candidate.refutation_review_status, "needs_human_review"),
      refutationStatus: safeText(candidate.refutation_status, "unverified"),
      reportStatus: safeText(candidate.report_status, "submission_blocked"),
      risk: safeText(candidate.risk, "medium"),
      safeValidationStepCount: candidate.safe_validation_step_count ?? 0,
      validationStatus: safeText(candidate.validation_status, "needs_human_review"),
      vulnType: safeText(candidate.vuln_type, "candidate"),
    })),
  };
}

export function toStudioArtifactChecklist(
  manifest: StudioWorkspaceManifest,
): StudioArtifactChecklistItem[] {
  const presentKinds = new Set(
    (manifest.artifacts ?? [])
      .map((artifact) => artifact.kind)
      .filter((kind): kind is string => typeof kind === "string" && kind.length > 0),
  );

  return [
    artifactChecklistItem("scope", "Scope", true, presentKinds),
    artifactChecklistItem("policy", "Policy", true, presentKinds),
    artifactChecklistItem("code", "Authorized code", true, presentKinds),
    artifactChecklistItem("api", "API", true, presentKinds),
    artifactChecklistItem("har", "HAR", true, presentKinds),
    artifactChecklistItem("sbom", "SBOM", false, presentKinds),
    artifactChecklistItem("sarif", "SARIF", false, presentKinds),
    artifactChecklistItem("fuzzing", "Fuzzing plan", false, presentKinds),
    artifactChecklistItem("strategy", "Strategy", false, presentKinds),
    artifactChecklistItem("knowledge", "Knowledge", false, presentKinds),
  ];
}

export function toStudioResearchReadiness(
  workspacePath: string,
  manifest: StudioWorkspaceManifest,
): StudioResearchReadiness {
  if (!workspacePath.trim()) {
    return {
      canStart: false,
      reason: "Create or open a workspace before research.",
    };
  }

  const checklist = toStudioArtifactChecklist(manifest);
  const missingRequired = checklist
    .filter((item) => item.required && !item.present)
    .map((item) => missingArtifactLabel(item));

  if (missingRequired.length > 0) {
    return {
      canStart: false,
      reason: `Import ${missingRequired.join(" and ")} before research.`,
    };
  }

  return {
    canStart: true,
    reason: "Policy, scope, API/HAR, and code are ready for A+B candidate research.",
  };
}

export function toStudioCandidateCards(candidates: StudioCandidateInput[]): StudioCandidateCard[] {
  return candidates.slice(0, 5).map((candidate, index) => {
    const endpoint = endpointFromCandidate(candidate);
    const codePath = codePathFromCandidate(candidate);

    return {
      id: safeText(candidate.hypothesis_id, `H-${String(index + 1).padStart(3, "0")}`),
      title: safeText(candidate.vuln_type, "Candidate hypothesis"),
      severity: safeText(candidate.risk, "medium"),
      status: candidate.safe_verification === false
        ? "blocked"
        : endpoint && codePath
          ? "needs_evidence"
          : "needs_review",
      affectedEndpoint: endpoint || "Endpoint needs review",
      affectedCodePath: codePath || "Code path needs review",
      evidenceNeeds: candidate.evidence_needed ?? [],
      evidenceGaps: evidenceGapsFromCandidate(candidate),
      refutationQuestions: candidate.false_positive_checks ?? [],
      rankingReasons: candidate.ranking_reasons ?? [],
      brokenInvariant: safeText(candidate.broken_invariant, "Security invariant needs review."),
      repairGuidance: safeText(
        candidate.repair_guidance,
        safeText(candidate.suggested_fix, "Repair guidance needs review."),
      ),
      regressionTest: safeText(candidate.regression_test, "Regression test needs review."),
      reason: safeText(candidate.reason, "Review rationale unavailable."),
      reportReadiness: reportReadinessFromCandidate(candidate),
      safeValidationPlan: candidate.safe_validation_plan ?? [],
      safetyBlockers: candidate.safety_blockers ?? [],
      priorityScore: candidate.priority_score ?? 0,
      validationMode: safeText(candidate.validation_mode, "manual_review"),
    };
  });
}

function artifactChecklistItem(
  kind: StudioArtifactChecklistItem["kind"],
  label: string,
  required: boolean,
  presentKinds: Set<string>,
): StudioArtifactChecklistItem {
  const present = presentKinds.has(kind);
  return {
    kind,
    label,
    present,
    required,
    status: present ? "ready" : required ? "missing" : "optional",
  };
}

function reportReadinessFromCandidate(
  candidate: StudioCandidateInput,
): StudioCandidateCard["reportReadiness"] {
  const evidenceGaps = evidenceGapsFromCandidate(candidate);
  const nextAllowedAction = evidenceGaps.length > 0
    ? `Resolve candidate evidence gaps before exporting a report preview: ${evidenceGaps.join("; ")}.`
    : safeText(
        candidate.report_readiness?.next_allowed_action,
        "Review evidence and safety blockers before exporting a report preview.",
      );

  return {
    nextAllowedAction,
    reportSubmissionAllowed: candidate.report_readiness?.report_submission_allowed === true,
    status: safeText(candidate.report_readiness?.status, "submission_blocked"),
  };
}

function evidenceGapsFromCandidate(candidate: StudioCandidateInput): string[] {
  if (!Array.isArray(candidate.evidence_gaps)) {
    return [];
  }
  return candidate.evidence_gaps
    .map((gap) => {
      const artifactKind = safeText(gap.artifact_kind, "");
      const reason = safeText(gap.reason, "");
      return artifactKind && reason ? `${artifactKind}: ${reason}` : "";
    })
    .filter((item) => item.length > 0);
}

function missingArtifactLabel(item: StudioArtifactChecklistItem): string {
  if (item.kind === "api" || item.kind === "har") {
    return item.label;
  }
  return item.label.toLowerCase();
}

function endpointFromCandidate(candidate: StudioCandidateInput): string {
  const route = candidate.source_facts?.find((fact) => fact.route_path)?.route_path;
  return route || safeText(candidate.location, "");
}

function codePathFromCandidate(candidate: StudioCandidateInput): string {
  const fact = candidate.source_facts?.find((item) => item.source_path || item.symbol_name);
  if (!fact) {
    return "";
  }
  return [fact.source_path, fact.symbol_name].filter(Boolean).join(":");
}

function scopeGuardLabel(value: string | undefined): string {
  if (value === "scope_imported") {
    return "Scope imported";
  }
  if (value === "allowed") {
    return "Allowed";
  }
  if (value === "blocked") {
    return "Blocked";
  }
  return "Missing scope";
}

function missionActionLabel(value: string): string {
  if (value === "review_top_candidates") {
    return "Review top candidates";
  }
  if (value === "create_benchmark_template") {
    return "Create benchmark template";
  }
  if (value === "export_submission_blocked_report") {
    return "Export submission-blocked report";
  }
  return value
    .split("_")
    .filter(Boolean)
    .map((word, index) => (index === 0 ? word[0]?.toUpperCase() + word.slice(1) : word))
    .join(" ");
}

function missionResearchLoopLabel(value: string): string {
  if (value === "scope_guard") {
    return "Scope Guard";
  }
  if (value === "target_intake") {
    return "Target intake";
  }
  if (value === "attack_surface_modeling") {
    return "Attack-surface modeling";
  }
  if (value === "semantic_audit") {
    return "Semantic audit";
  }
  if (value === "hypothesis_generation") {
    return "Hypothesis generation";
  }
  if (value === "refutation_review") {
    return "Refutation review";
  }
  if (value === "deduplication_review") {
    return "Deduplication review";
  }
  if (value === "safe_validation_planning") {
    return "Safe validation planning";
  }
  if (value === "evidence_review") {
    return "Evidence review";
  }
  if (value === "submission_blocked_report") {
    return "Submission-blocked report";
  }
  return missionActionLabel(value);
}

function safeText(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() ? value : fallback;
}
