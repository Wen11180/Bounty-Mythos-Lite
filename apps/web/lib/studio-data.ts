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
    independent_cross_check_sources?: string[];
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

export type StudioCandidateHunterBacklogInput = {
  candidate_id?: string;
  execution_allowed?: boolean;
  gap?: string;
  next_action?: string;
  report_submission_allowed?: boolean;
  required_evidence?: string[];
  review_focus?: string[];
  safety_gate?: string;
  status?: string;
  validation_allowed?: boolean;
  work_item_id?: string;
};

export type StudioCandidateHunterIterationInput = {
  completion_gate?: string;
  execution_allowed?: boolean;
  iteration_id?: string;
  next_review_agent?: string;
  priority_order?: string[];
  report_submission_allowed?: boolean;
  review_focus?: string[];
  safety_gate?: string;
  status?: string;
  success_criteria?: string[];
  validation_allowed?: boolean;
  work_item_count?: number;
};

export type StudioCandidateHunterPlanInput = {
  completion_gate?: string;
  execution_allowed?: boolean;
  hallucination_governance?: {
    candidate_promotion_allowed?: boolean;
    claim_promotion_rule?: string;
    independent_challenge_sources?: string[];
    knowledge_policy?: string;
    model_output_policy?: string;
    required_consensus?: string[];
  };
  next_review_agent?: string;
  plan_id?: string;
  plan_steps?: Array<{
    assigned_agent?: string;
    candidate_id?: string;
    execution_allowed?: boolean;
    gap?: string;
    input_refs?: string[];
    next_action?: string;
    report_submission_allowed?: boolean;
    required_evidence?: string[];
    review_checklist?: Array<{
      execution_allowed?: boolean;
      key?: string;
      label?: string;
      report_submission_allowed?: boolean;
      required?: boolean;
      status?: string;
      validation_allowed?: boolean;
    }>;
    review_focus?: string[];
    safety_gate?: string;
    status?: string;
    step_id?: string;
    success_criteria?: string[];
    hallucination_governance_refs?: string[];
    validation_allowed?: boolean;
    work_item_id?: string;
  }>;
  report_submission_allowed?: boolean;
  safety_gate?: string;
  status?: string;
  step_count?: number;
  validation_allowed?: boolean;
  work_item_count?: number;
};

export type StudioCandidateHunterReviewLoopInput = {
  active_step_count?: number;
  active_steps?: Array<{
    assigned_agent?: string;
    candidate_id?: string;
    execution_allowed?: boolean;
    gap?: string;
    governance_refs?: string[];
    next_action?: string;
    report_submission_allowed?: boolean;
    required_evidence?: string[];
    review_checklist?: Array<{
      execution_allowed?: boolean;
      key?: string;
      label?: string;
      report_submission_allowed?: boolean;
      required?: boolean;
      status?: string;
      validation_allowed?: boolean;
    }>;
    safety_gate?: string;
    step_id?: string;
    success_criteria?: string[];
    validation_allowed?: boolean;
    work_item_id?: string;
  }>;
  blocked_actions?: string[];
  completion_gate?: string;
  execution_allowed?: boolean;
  governance_summary?: {
    candidate_promotion_allowed?: boolean;
    claim_promotion_rule?: string;
    required_consensus?: string[];
  };
  loop_id?: string;
  next_review_agent?: string;
  report_submission_allowed?: boolean;
  required_evidence?: string[];
  review_agents?: string[];
  safety_gate?: string;
  source_plan_id?: string;
  status?: string;
  validation_allowed?: boolean;
};

export type StudioMissionAgentTaskTimelineInput = {
  agent?: string;
  attempt?: number;
  gate_decision?: string;
  input_summary?: string;
  next_human_action?: string;
  output_summary?: string;
  report_submission_allowed?: boolean;
  safety_gate?: string;
  stage_id?: string;
  status?: string;
  task_id?: string;
  validation_execution_allowed?: boolean;
};

export type StudioTimelineSummaryInput = {
  blocked_stage_ids?: string[];
  gate_decision_counts?: Record<string, number>;
  needs_review_stage_ids?: string[];
  next_human_actions?: string[];
  pending_stage_ids?: string[];
  report_submission_allowed?: boolean;
  safety_gate?: string;
  total_stages?: number;
  validation_execution_allowed?: boolean;
};

export type StudioCandidateReviewPacketInput = {
  candidate_id?: string;
  checklist?: Array<{
    key?: string;
    label?: string;
    status?: string;
  }>;
  completed_items?: string[];
  evidence_need_count?: number;
  execution_allowed?: boolean;
  false_positive_check_count?: number;
  hallucination_guard_status?: string;
  missing_items?: string[];
  next_human_action?: string;
  quality_score?: number;
  report_review_priority?: string;
  report_status?: string;
  report_submission_allowed?: boolean;
  safe_validation_step_count?: number;
  safety_gate?: string;
  status?: string;
  validation_allowed?: boolean;
};

export type StudioSubmissionBlockedReportSummaryInput = {
  candidate_count?: number;
  missing_review_items?: Record<string, string[]>;
  needs_review_candidate_ids?: string[];
  next_human_actions?: string[];
  report_review_queue?: Array<{
    candidate_id?: string;
    next_human_action?: string;
    priority?: string;
    quality_score?: number;
    report_submission_allowed?: boolean;
    safety_gate?: string;
    validation_execution_allowed?: boolean;
  }>;
  ready_candidate_ids?: string[];
  redaction_review_required?: boolean;
  report_submission_allowed?: boolean;
  safety_gate?: string;
  status?: string;
  validation_execution_allowed?: boolean;
};

export type StudioAgentHandoffPackInput = {
  agent_queue_refs?: string[];
  blocked_actions?: string[];
  completion_gate?: string;
  execution_allowed?: boolean;
  handoff_item_count?: number;
  handoff_items?: Array<{
    assigned_agent?: string;
    candidate_id?: string;
    execution_allowed?: boolean;
    gap?: string;
    handoff_id?: string;
    input_refs?: string[];
    next_action?: string;
    report_submission_allowed?: boolean;
    required_evidence?: string[];
    review_focus?: string[];
    safety_gate?: string;
    status?: string;
    success_criteria?: string[];
    validation_allowed?: boolean;
    work_item_id?: string;
  }>;
  next_review_agent?: string;
  pack_id?: string;
  priority_order?: string[];
  report_submission_allowed?: boolean;
  review_focus?: string[];
  safety_gate?: string;
  status?: string;
  success_criteria?: string[];
  timeline_gate_counts?: Record<string, number>;
  validation_allowed?: boolean;
};

export type StudioMissionSummary = {
  agent_queue?: StudioMissionAgentTaskInput[];
  agent_handoff_pack?: StudioAgentHandoffPackInput;
  agent_task_timeline?: StudioMissionAgentTaskTimelineInput[];
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
  candidate_hunter_backlog?: StudioCandidateHunterBacklogInput[];
  candidate_hunter_iteration?: StudioCandidateHunterIterationInput;
  candidate_hunter_plan?: StudioCandidateHunterPlanInput;
  candidate_hunter_review_loop?: StudioCandidateHunterReviewLoopInput;
  candidate_review_packets?: StudioCandidateReviewPacketInput[];
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
  studio_timeline_summary?: StudioTimelineSummaryInput;
  submission_blocked_report_summary?: StudioSubmissionBlockedReportSummaryInput;
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
    independentCrossCheckSources: string[];
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

export type StudioCandidateHunterBacklogItem = {
  candidateId: string;
  executionAllowed: boolean;
  gap: string;
  nextAction: string;
  reportSubmissionAllowed: boolean;
  requiredEvidence: string[];
  reviewFocus: string[];
  safetyGate: string;
  status: string;
  validationAllowed: boolean;
  workItemId: string;
};

export type StudioCandidateHunterIteration = {
  completionGate: string;
  executionAllowed: boolean;
  iterationId: string;
  nextReviewAgent: string;
  priorityOrder: string[];
  reportSubmissionAllowed: boolean;
  reviewFocus: string[];
  safetyGate: string;
  status: string;
  successCriteria: string[];
  validationAllowed: boolean;
  workItemCount: number;
};

export type StudioCandidateHunterPlan = {
  completionGate: string;
  executionAllowed: boolean;
  hallucinationGovernance: {
    candidatePromotionAllowed: boolean;
    claimPromotionRule: string;
    independentChallengeSources: string[];
    knowledgePolicy: string;
    modelOutputPolicy: string;
    requiredConsensus: string[];
  };
  nextReviewAgent: string;
  planId: string;
  planSteps: Array<{
    assignedAgent: string;
    candidateId: string;
    executionAllowed: boolean;
    gap: string;
    inputRefs: string[];
    nextAction: string;
    reportSubmissionAllowed: boolean;
    requiredEvidence: string[];
    reviewChecklist: Array<{
      executionAllowed: boolean;
      key: string;
      label: string;
      reportSubmissionAllowed: boolean;
      required: boolean;
      status: string;
      validationAllowed: boolean;
    }>;
    reviewFocus: string[];
    safetyGate: string;
    status: string;
    stepId: string;
    successCriteria: string[];
    hallucinationGovernanceRefs: string[];
    validationAllowed: boolean;
    workItemId: string;
  }>;
  reportSubmissionAllowed: boolean;
  safetyGate: string;
  status: string;
  stepCount: number;
  validationAllowed: boolean;
  workItemCount: number;
};

export type StudioCandidateHunterReviewLoop = {
  activeStepCount: number;
  activeSteps: Array<{
    assignedAgent: string;
    candidateId: string;
    executionAllowed: boolean;
    gap: string;
    governanceRefs: string[];
    nextAction: string;
    reportSubmissionAllowed: boolean;
    requiredEvidence: string[];
    reviewChecklist: Array<{
      executionAllowed: boolean;
      key: string;
      label: string;
      reportSubmissionAllowed: boolean;
      required: boolean;
      status: string;
      validationAllowed: boolean;
    }>;
    safetyGate: string;
    stepId: string;
    successCriteria: string[];
    validationAllowed: boolean;
    workItemId: string;
  }>;
  blockedActions: string[];
  completionGate: string;
  executionAllowed: boolean;
  governanceSummary: {
    candidatePromotionAllowed: boolean;
    claimPromotionRule: string;
    requiredConsensus: string[];
  };
  loopId: string;
  nextReviewAgent: string;
  reportSubmissionAllowed: boolean;
  requiredEvidence: string[];
  reviewAgents: string[];
  safetyGate: string;
  sourcePlanId: string;
  status: string;
  validationAllowed: boolean;
};

export type StudioMissionAgentTaskTimelineItem = {
  agent: string;
  attempt: number;
  gateDecision: string;
  inputSummary: string;
  nextHumanAction: string;
  outputSummary: string;
  reportSubmissionAllowed: boolean;
  safetyGate: string;
  stageId: string;
  status: string;
  taskId: string;
  validationExecutionAllowed: boolean;
};

export type StudioTimelineSummary = {
  blockedStageIds: string[];
  gateDecisionCounts: Record<string, number>;
  needsReviewStageIds: string[];
  nextHumanActions: string[];
  pendingStageIds: string[];
  reportSubmissionAllowed: boolean;
  safetyGate: string;
  totalStages: number;
  validationExecutionAllowed: boolean;
};

export type StudioCandidateReviewPacket = {
  candidateId: string;
  checklist: Array<{
    key: string;
    label: string;
    status: string;
  }>;
  completedItems: string[];
  evidenceNeedCount: number;
  executionAllowed: boolean;
  falsePositiveCheckCount: number;
  hallucinationGuardStatus: string;
  missingItems: string[];
  nextHumanAction: string;
  qualityScore: number;
  reportReviewPriority: string;
  reportStatus: string;
  reportSubmissionAllowed: boolean;
  safeValidationStepCount: number;
  safetyGate: string;
  status: string;
  validationAllowed: boolean;
};

export type StudioAgentHandoffPack = {
  agentQueueRefs: string[];
  blockedActions: string[];
  completionGate: string;
  executionAllowed: boolean;
  handoffItemCount: number;
  handoffItems: Array<{
    assignedAgent: string;
    candidateId: string;
    executionAllowed: boolean;
    gap: string;
    handoffId: string;
    inputRefs: string[];
    nextAction: string;
    reportSubmissionAllowed: boolean;
    requiredEvidence: string[];
    reviewFocus: string[];
    safetyGate: string;
    status: string;
    successCriteria: string[];
    validationAllowed: boolean;
    workItemId: string;
  }>;
  nextReviewAgent: string;
  packId: string;
  priorityOrder: string[];
  reportSubmissionAllowed: boolean;
  reviewFocus: string[];
  safetyGate: string;
  status: string;
  successCriteria: string[];
  timelineGateCounts: Record<string, number>;
  validationAllowed: boolean;
};

export type StudioSubmissionBlockedReportSummary = {
  candidateCount: number;
  missingReviewItems: Record<string, string[]>;
  needsReviewCandidateIds: string[];
  nextHumanActions: string[];
  reportReviewQueue: Array<{
    candidateId: string;
    nextHumanAction: string;
    priority: string;
    qualityScore: number;
    reportSubmissionAllowed: boolean;
    safetyGate: string;
    validationExecutionAllowed: boolean;
  }>;
  readyCandidateIds: string[];
  redactionReviewRequired: boolean;
  reportSubmissionAllowed: boolean;
  safetyGate: string;
  status: string;
  validationExecutionAllowed: boolean;
};

export type StudioMissionPanel = {
  advisoryContextLabel: string;
  agentHandoffPack: StudioAgentHandoffPack;
  agentQueue: StudioMissionAgentTask[];
  agentTaskTimeline: StudioMissionAgentTaskTimelineItem[];
  artifactCoverage: string;
  blockedActions: string[];
  candidateHunterBacklog: StudioCandidateHunterBacklogItem[];
  candidateHunterIteration: StudioCandidateHunterIteration;
  candidateHunterPlan: StudioCandidateHunterPlan;
  candidateHunterReviewLoop: StudioCandidateHunterReviewLoop;
  candidateReviewPackets: StudioCandidateReviewPacket[];
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
  studioTimelineSummary: StudioTimelineSummary;
  submissionBlockedReportSummary: StudioSubmissionBlockedReportSummary;
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
    agentHandoffPack: {
      agentQueueRefs: mission?.agent_handoff_pack?.agent_queue_refs ?? [],
      blockedActions: mission?.agent_handoff_pack?.blocked_actions ?? [],
      completionGate: safeText(
        mission?.agent_handoff_pack?.completion_gate,
        "human_review_required",
      ),
      executionAllowed: false,
      handoffItemCount: mission?.agent_handoff_pack?.handoff_item_count ?? 0,
      handoffItems: (mission?.agent_handoff_pack?.handoff_items ?? []).map((item) => ({
        assignedAgent: safeText(item.assigned_agent, "Human Reviewer"),
        candidateId: safeText(item.candidate_id, "candidate"),
        executionAllowed: false,
        gap: safeText(item.gap, "needs_review"),
        handoffId: safeText(item.handoff_id, "handoff:candidate"),
        inputRefs: item.input_refs ?? [],
        nextAction: safeText(item.next_action, "Human review required."),
        reportSubmissionAllowed: false,
        requiredEvidence: item.required_evidence ?? [],
        reviewFocus: item.review_focus ?? [],
        safetyGate: safeText(item.safety_gate, "review_only_no_execution"),
        status: safeText(item.status, "needs_review"),
        successCriteria: item.success_criteria ?? [],
        validationAllowed: false,
        workItemId: safeText(item.work_item_id, "candidate_work_item"),
      })),
      nextReviewAgent: safeText(
        mission?.agent_handoff_pack?.next_review_agent,
        "Human Reviewer",
      ),
      packId: safeText(
        mission?.agent_handoff_pack?.pack_id,
        "studio:agent_handoff:next_review",
      ),
      priorityOrder: mission?.agent_handoff_pack?.priority_order ?? [],
      reportSubmissionAllowed: false,
      reviewFocus: mission?.agent_handoff_pack?.review_focus ?? [],
      safetyGate: safeText(
        mission?.agent_handoff_pack?.safety_gate,
        "review_only_no_execution",
      ),
      status: safeText(mission?.agent_handoff_pack?.status, "needs_review"),
      successCriteria: mission?.agent_handoff_pack?.success_criteria ?? [],
      timelineGateCounts: mission?.agent_handoff_pack?.timeline_gate_counts ?? {},
      validationAllowed: false,
    },
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
    agentTaskTimeline: (mission?.agent_task_timeline ?? []).map((stage) => ({
      agent: safeText(stage.agent, "Review agent"),
      attempt: stage.attempt ?? 1,
      gateDecision: safeText(stage.gate_decision, "human_review_required"),
      inputSummary: safeText(stage.input_summary, "Input refs require review."),
      nextHumanAction: safeText(stage.next_human_action, "Review required."),
      outputSummary: safeText(stage.output_summary, "Output summary requires review."),
      reportSubmissionAllowed: false,
      safetyGate: safeText(stage.safety_gate, "human_review_required"),
      stageId: safeText(stage.stage_id, "agent_queue:stage"),
      status: safeText(stage.status, "needs_review"),
      taskId: safeText(stage.task_id, "agent_task"),
      validationExecutionAllowed: false,
    })),
    artifactCoverage: `${present.length}/${required.length} required artifacts`,
    blockedActions: mission?.blocked_actions ?? [],
    candidateHunterBacklog: (mission?.candidate_hunter_backlog ?? []).map((item) => ({
      candidateId: safeText(item.candidate_id, "mission"),
      executionAllowed: false,
      gap: safeText(item.gap, "needs_review"),
      nextAction: safeText(item.next_action, "Review candidate quality gap."),
      reportSubmissionAllowed: false,
      requiredEvidence: item.required_evidence ?? [],
      reviewFocus: item.review_focus ?? [],
      safetyGate: safeText(item.safety_gate, "review_only_no_execution"),
      status: safeText(item.status, "needs_review"),
      validationAllowed: false,
      workItemId: safeText(item.work_item_id, "candidate_hunter_work_item"),
    })),
    candidateHunterIteration: {
      completionGate: safeText(
        mission?.candidate_hunter_iteration?.completion_gate,
        "human_review_required",
      ),
      executionAllowed: false,
      iterationId: safeText(
        mission?.candidate_hunter_iteration?.iteration_id,
        "candidate_hunter:next_review",
      ),
      nextReviewAgent: safeText(
        mission?.candidate_hunter_iteration?.next_review_agent,
        "Human Reviewer",
      ),
      priorityOrder: mission?.candidate_hunter_iteration?.priority_order ?? [],
      reportSubmissionAllowed: false,
      reviewFocus: mission?.candidate_hunter_iteration?.review_focus ?? [],
      safetyGate: safeText(
        mission?.candidate_hunter_iteration?.safety_gate,
        "review_only_no_execution",
      ),
      status: safeText(mission?.candidate_hunter_iteration?.status, "needs_review"),
      successCriteria: mission?.candidate_hunter_iteration?.success_criteria ?? [],
      validationAllowed: false,
      workItemCount: mission?.candidate_hunter_iteration?.work_item_count ?? 0,
    },
    candidateHunterPlan: {
      completionGate: safeText(
        mission?.candidate_hunter_plan?.completion_gate,
        "human_review_required",
      ),
      executionAllowed: false,
      hallucinationGovernance: {
        candidatePromotionAllowed: false,
        claimPromotionRule: safeText(
          mission?.candidate_hunter_plan?.hallucination_governance?.claim_promotion_rule,
          "no_verified_evidence_no_high_confidence",
        ),
        independentChallengeSources:
          mission?.candidate_hunter_plan?.hallucination_governance
            ?.independent_challenge_sources ?? [],
        knowledgePolicy: safeText(
          mission?.candidate_hunter_plan?.hallucination_governance?.knowledge_policy,
          "rag_few_shot_context_only_not_cross_validation",
        ),
        modelOutputPolicy: safeText(
          mission?.candidate_hunter_plan?.hallucination_governance?.model_output_policy,
          "llm_claims_start_unverified",
        ),
        requiredConsensus:
          mission?.candidate_hunter_plan?.hallucination_governance?.required_consensus ??
          [],
      },
      nextReviewAgent: safeText(
        mission?.candidate_hunter_plan?.next_review_agent,
        "Human Reviewer",
      ),
      planId: safeText(
        mission?.candidate_hunter_plan?.plan_id,
        "candidate_hunter:autonomous_review_plan",
      ),
      planSteps: (mission?.candidate_hunter_plan?.plan_steps ?? []).map((step) => ({
        assignedAgent: safeText(step.assigned_agent, "Human Reviewer"),
        candidateId: safeText(step.candidate_id, "candidate"),
        executionAllowed: false,
        gap: safeText(step.gap, "needs_review"),
        inputRefs: step.input_refs ?? [],
        nextAction: safeText(step.next_action, "Human review required."),
        reportSubmissionAllowed: false,
        requiredEvidence: step.required_evidence ?? [],
        reviewChecklist: (step.review_checklist ?? []).map((item) => ({
          executionAllowed: false,
          key: safeText(item.key, "review_item"),
          label: safeText(item.label, "Review item."),
          reportSubmissionAllowed: false,
          required: item.required !== false,
          status: safeText(item.status, "needs_review"),
          validationAllowed: false,
        })),
        reviewFocus: step.review_focus ?? [],
        safetyGate: safeText(step.safety_gate, "review_only_no_execution"),
        status: safeText(step.status, "needs_review"),
        stepId: safeText(step.step_id, "candidate_hunter:plan:candidate"),
        successCriteria: step.success_criteria ?? [],
        hallucinationGovernanceRefs: step.hallucination_governance_refs ?? [],
        validationAllowed: false,
        workItemId: safeText(step.work_item_id, "candidate_hunter_work_item"),
      })),
      reportSubmissionAllowed: false,
      safetyGate: safeText(
        mission?.candidate_hunter_plan?.safety_gate,
        "review_only_no_execution",
      ),
      status: safeText(mission?.candidate_hunter_plan?.status, "needs_review"),
      stepCount: mission?.candidate_hunter_plan?.step_count ?? 0,
      validationAllowed: false,
      workItemCount: mission?.candidate_hunter_plan?.work_item_count ?? 0,
    },
    candidateHunterReviewLoop: {
      activeStepCount: mission?.candidate_hunter_review_loop?.active_step_count ?? 0,
      activeSteps: (mission?.candidate_hunter_review_loop?.active_steps ?? []).map(
        (step) => ({
          assignedAgent: safeText(step.assigned_agent, "Human Reviewer"),
          candidateId: safeText(step.candidate_id, "candidate"),
          executionAllowed: false,
          gap: safeText(step.gap, "needs_review"),
          governanceRefs: step.governance_refs ?? [],
          nextAction: safeText(step.next_action, "Human review required."),
          reportSubmissionAllowed: false,
          requiredEvidence: step.required_evidence ?? [],
          reviewChecklist: (step.review_checklist ?? []).map((item) => ({
            executionAllowed: false,
            key: safeText(item.key, "review_item"),
            label: safeText(item.label, "Review item."),
            reportSubmissionAllowed: false,
            required: item.required !== false,
            status: safeText(item.status, "needs_review"),
            validationAllowed: false,
          })),
          safetyGate: "review_only_no_execution",
          stepId: safeText(step.step_id, "candidate_hunter:review_loop:step"),
          successCriteria: step.success_criteria ?? [],
          validationAllowed: false,
          workItemId: safeText(step.work_item_id, "candidate_hunter_work_item"),
        }),
      ),
      blockedActions: mission?.candidate_hunter_review_loop?.blocked_actions ?? [],
      completionGate: "human_review_required",
      executionAllowed: false,
      governanceSummary: {
        candidatePromotionAllowed: false,
        claimPromotionRule: safeText(
          mission?.candidate_hunter_review_loop?.governance_summary?.claim_promotion_rule,
          "no_verified_evidence_no_high_confidence",
        ),
        requiredConsensus:
          mission?.candidate_hunter_review_loop?.governance_summary
            ?.required_consensus ?? [],
      },
      loopId: safeText(
        mission?.candidate_hunter_review_loop?.loop_id,
        "candidate_hunter:next_review_loop",
      ),
      nextReviewAgent: safeText(
        mission?.candidate_hunter_review_loop?.next_review_agent,
        "Human Reviewer",
      ),
      reportSubmissionAllowed: false,
      requiredEvidence: mission?.candidate_hunter_review_loop?.required_evidence ?? [],
      reviewAgents: mission?.candidate_hunter_review_loop?.review_agents ?? [],
      safetyGate: "review_only_no_execution",
      sourcePlanId: safeText(
        mission?.candidate_hunter_review_loop?.source_plan_id,
        "candidate_hunter:autonomous_review_plan",
      ),
      status: safeText(mission?.candidate_hunter_review_loop?.status, "needs_review"),
      validationAllowed: false,
    },
    candidateReviewPackets: (mission?.candidate_review_packets ?? []).map((packet) => ({
      candidateId: safeText(packet.candidate_id, "candidate"),
      checklist: (packet.checklist ?? []).map((item) => ({
        key: safeText(item.key, "review_item"),
        label: safeText(item.label, "Review item"),
        status: safeText(item.status, "needs_review"),
      })),
      completedItems: packet.completed_items ?? [],
      evidenceNeedCount: packet.evidence_need_count ?? 0,
      executionAllowed: false,
      falsePositiveCheckCount: packet.false_positive_check_count ?? 0,
      hallucinationGuardStatus: safeText(
        packet.hallucination_guard_status,
        "needs_review",
      ),
      missingItems: packet.missing_items ?? [],
      nextHumanAction: safeText(packet.next_human_action, "Human review required."),
      qualityScore: packet.quality_score ?? 0,
      reportReviewPriority: safeText(
        packet.report_review_priority,
        "resolve_review_gaps",
      ),
      reportStatus: safeText(packet.report_status, "submission_blocked"),
      reportSubmissionAllowed: false,
      safeValidationStepCount: packet.safe_validation_step_count ?? 0,
      safetyGate: safeText(packet.safety_gate, "human_review_required"),
      status: safeText(packet.status, "needs_review"),
      validationAllowed: false,
    })),
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
    studioTimelineSummary: {
      blockedStageIds: mission?.studio_timeline_summary?.blocked_stage_ids ?? [],
      gateDecisionCounts: mission?.studio_timeline_summary?.gate_decision_counts ?? {},
      needsReviewStageIds: mission?.studio_timeline_summary?.needs_review_stage_ids ?? [],
      nextHumanActions: mission?.studio_timeline_summary?.next_human_actions ?? [],
      pendingStageIds: mission?.studio_timeline_summary?.pending_stage_ids ?? [],
      reportSubmissionAllowed: false,
      safetyGate: safeText(
        mission?.studio_timeline_summary?.safety_gate,
        "review_only_no_execution",
      ),
      totalStages: mission?.studio_timeline_summary?.total_stages ?? 0,
      validationExecutionAllowed: false,
    },
    submissionBlockedReportSummary: {
      candidateCount: mission?.submission_blocked_report_summary?.candidate_count ?? 0,
      missingReviewItems:
        mission?.submission_blocked_report_summary?.missing_review_items ?? {},
      needsReviewCandidateIds:
        mission?.submission_blocked_report_summary?.needs_review_candidate_ids ?? [],
      nextHumanActions:
        mission?.submission_blocked_report_summary?.next_human_actions ?? [],
      reportReviewQueue: (
        mission?.submission_blocked_report_summary?.report_review_queue ?? []
      ).map((item) => ({
        candidateId: safeText(item.candidate_id, "candidate"),
        nextHumanAction: safeText(item.next_human_action, "Human review required."),
        priority: safeText(item.priority, "resolve_review_gaps"),
        qualityScore: item.quality_score ?? 0,
        reportSubmissionAllowed: false,
        safetyGate: safeText(item.safety_gate, "submission_blocked_human_review"),
        validationExecutionAllowed: false,
      })),
      readyCandidateIds:
        mission?.submission_blocked_report_summary?.ready_candidate_ids ?? [],
      redactionReviewRequired: true,
      reportSubmissionAllowed: false,
      safetyGate: safeText(
        mission?.submission_blocked_report_summary?.safety_gate,
        "submission_blocked_human_review",
      ),
      status: safeText(
        mission?.submission_blocked_report_summary?.status,
        "needs_human_review",
      ),
      validationExecutionAllowed: false,
    },
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
        independentCrossCheckSources:
          candidate.hallucination_guard?.independent_cross_check_sources ?? [],
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

export function toStudioMissionHandoffBrief(panel: StudioMissionPanel): string {
  const handoffItems =
    panel.agentHandoffPack.handoffItems.length > 0
      ? panel.agentHandoffPack.handoffItems
          .map(
            (item) =>
              `- ${item.handoffId}: ${item.assignedAgent} handles ${item.workItemId}; status ${item.status}; gap ${item.gap}; next ${item.nextAction}`,
          )
          .join("\n")
      : "- No handoff items; keep human review on the current Top candidates.";
  const blockedActions =
    panel.agentHandoffPack.blockedActions.length > 0
      ? panel.agentHandoffPack.blockedActions.join(", ")
      : panel.blockedActions.join(", ");

  return [
    "Mythos / MDASH / XBOW style local AI vulnerability research handoff",
    `Run: ${panel.runId}`,
    `Artifacts: ${panel.artifactCoverage}`,
    `Scope Guard: ${panel.scopeGuardLabel}`,
    `Advisory context: ${panel.advisoryContextLabel}`,
    `Hallucination governance: ${panel.candidateHunterPlan.hallucinationGovernance.claimPromotionRule}; knowledge ${panel.candidateHunterPlan.hallucinationGovernance.knowledgePolicy}; promotion allowed ${panel.candidateHunterPlan.hallucinationGovernance.candidatePromotionAllowed ? "true" : "false"}`,
    `Quality: ${panel.qualitySummary.topCandidateQualityGate}; review-ready ${panel.qualitySummary.reviewReadyCount}/${panel.qualitySummary.candidateCount}; average ${panel.qualitySummary.averageQualityScore}`,
    `Report: ${panel.submissionBlockedReportSummary.status}; ready candidates ${panel.submissionBlockedReportSummary.readyCandidateIds.join(", ") || "none"}; gate ${panel.submissionBlockedReportSummary.safetyGate}`,
    `Candidate hunter plan: ${panel.candidateHunterPlan.status}; steps ${panel.candidateHunterPlan.stepCount}; next reviewer ${panel.candidateHunterPlan.nextReviewAgent}`,
    `Candidate hunter review loop: ${panel.candidateHunterReviewLoop.status}; active steps ${panel.candidateHunterReviewLoop.activeStepCount}; next reviewer ${panel.candidateHunterReviewLoop.nextReviewAgent}`,
    `Next reviewer: ${panel.agentHandoffPack.nextReviewAgent}`,
    `Handoff items: ${panel.agentHandoffPack.handoffItemCount}`,
    handoffItems,
    `Safety gate: ${panel.agentHandoffPack.safetyGate}`,
    `Completion gate: ${panel.agentHandoffPack.completionGate}`,
    `Blocked actions: ${blockedActions || "execute_live_validation, run_fuzzer, submit_report"}`,
    "No validation, fuzzing, or report submission is authorized from this handoff.",
  ].join("\n");
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
