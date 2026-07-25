import type { CampaignControlCenter } from "./campaigns-data";
import type { StudioBlackBoxRemoteStatusResponse } from "./api";

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
    recorded_at?: string;
    report_markdown_path?: string;
    report_path?: string;
  }>;
  campaign_hunter_runs?: Array<{
    campaign_id?: string;
    campaign_name?: string;
    campaign_status?: string;
    suggestion_count?: number;
    dispatched_task_count?: number;
    autonomy_level?: string;
    safety_gate?: string;
    execution_allowed?: boolean;
    recorded_at?: string;
    report_markdown_path?: string;
    report_path?: string;
    report_status?: string;
    validation_allowed?: boolean;
    report_submission_allowed?: boolean;
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

export type StudioBlackBoxRemoteStatusView = {
  detail: string;
  label: string;
  warning: boolean;
};

export function toStudioBlackBoxRemoteStatus(
  status: StudioBlackBoxRemoteStatusResponse,
): StudioBlackBoxRemoteStatusView {
  if (
    status.profile !== "remote_human_lease"
    || status.report_submission_allowed !== false
    || status.human_confirmation_allowed !== false
    || (status.state === "active" && (!status.expires_at || status.relogin_required))
  ) {
    return {
      label: "状态契约无效，已阻断",
      detail: "状态契约发生偏差，远程执行保持阻断。",
      warning: true,
    };
  }
  if (status.state === "active") {
    return {
      label: "人工租约生效中",
      detail: `到期时间：${status.expires_at}。报告提交与人工确认仍保持阻断。`,
      warning: false,
    };
  }
  if (status.state === "expired") {
    return {
      label: "已过期，需要重新登录",
      detail: "先前的浏览器会话和执行租约已不可复用。",
      warning: true,
    };
  }
  if (status.state === "stopped" || status.state === "relogin_required") {
    return {
      label: "已停止，需要重新登录",
      detail: status.stop_reason
        ? `最终停止：${status.stop_reason}。只能使用新的人工批准重新开始。`
        : "只能使用新的人工批准重新开始。",
      warning: true,
    };
  }
  if (status.state === "awaiting_lease") {
    return {
      label: "等待新的人工租约",
      detail: "当前没有远程执行。需要专项批准和预检。",
      warning: true,
    };
  }
  return {
    label: "默认禁用",
    detail: "远程人工租约配置已禁用，不能派发请求。",
    warning: true,
  };
}

export type StudioMissionCandidateInput = {
  affected_code_path?: string;
  affected_endpoint?: string;
  deduplication_review_status?: string;
  evidence_gap_count?: number;
  evidence_need_count?: number;
  evidence_review_status?: string;
  evidence_trace_summary?: {
    advisory_artifact_kinds?: string[];
    code_path_traced?: boolean;
    endpoint_traced?: boolean;
    execution_allowed?: boolean;
    independent_cross_check_count?: number;
    missing_required_artifact_kinds?: string[];
    next_action?: string;
    present_required_artifact_kinds?: string[];
    report_submission_allowed?: boolean;
    required_artifact_kinds?: string[];
    source_fact_count?: number;
    status?: string;
    validation_allowed?: boolean;
  };
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

export type StudioCandidateHunterExecutionLoopInput = {
  active_work_items?: Array<{
    assigned_agent?: string;
    candidate_id?: string;
    execution_allowed?: boolean;
    gap?: string;
    next_action?: string;
    phase_id?: string;
    report_submission_allowed?: boolean;
    required_evidence?: string[];
    validation_allowed?: boolean;
    work_item_id?: string;
  }>;
  blocked_actions?: string[];
  candidate_budget?: number;
  candidate_evidence_matrix?: Array<{
    advisory_sources?: string[];
    affected_code_path?: string;
    affected_endpoint?: string;
    candidate_id?: string;
    evidence_trace_status?: string;
    execution_allowed?: boolean;
    hunter_priority_score?: number;
    impact_score?: number;
    independent_cross_check_sources?: string[];
    local_evidence_sources?: string[];
    learning_evidence_needed_reasons?: string[];
    missing_evidence?: string[];
    missing_required_artifact_kinds?: string[];
    policy_risk_score?: number;
    quality_score?: number;
    quality_status?: string;
    ranking_signal_breakdown?: string[];
    rejection_risk_score?: number;
    report_submission_allowed?: boolean;
    validation_allowed?: boolean;
  }>;
  candidate_evidence_summary?: {
    advisory_artifact_kinds?: string[];
    average_quality_score?: number;
    candidate_count?: number;
    code_path_traced_count?: number;
    endpoint_traced_count?: number;
    evidence_ready_candidate_ids?: string[];
    local_artifact_kinds?: string[];
    review_needed_candidate_ids?: string[];
    review_needed_count?: number;
    review_ready_count?: number;
  };
  candidate_promotion_allowed?: boolean;
  completion_gate?: string;
  current_phase?: string;
  execution_allowed?: boolean;
  iteration?: number;
  loop_id?: string;
  learning_feedback_target?: {
    action_count?: number;
    allowed_outcomes?: string[];
    candidate_ids?: string[];
    execution_allowed?: boolean;
    learning_write_allowed?: boolean;
    next_action?: string;
    report_submission_allowed?: boolean;
    safety_gate?: string;
    source_loop_id?: string;
    status?: string;
    target_id?: string;
    validation_allowed?: boolean;
  };
  learning_review_actions?: Array<{
    action_id?: string;
    allowed_outcomes?: string[];
    candidate_id?: string;
    evidence_ready?: boolean;
    execution_allowed?: boolean;
    learning_evidence_needed_reasons?: string[];
    learning_signal_template?: {
      human_review_required?: boolean;
      learning_write_allowed?: boolean;
      playbook_id?: string;
      surface_key?: string;
      target_relationships?: string[];
    };
    learning_write_allowed?: boolean;
    missing_evidence?: string[];
    missing_required_artifact_kinds?: string[];
    next_action?: string;
    report_submission_allowed?: boolean;
    safety_gate?: string;
    source_loop_id?: string;
    suggested_outcome?: string;
    trace_status?: string;
    validation_allowed?: boolean;
  }>;
  refutation_queue?: Array<{
    candidate_id?: string;
    execution_allowed?: boolean;
    missing_evidence?: string[];
    missing_required_artifact_kinds?: string[];
    next_action?: string;
    priority_score?: number;
    questions?: string[];
    queue_id?: string;
    report_submission_allowed?: boolean;
    required_evidence?: string[];
    safety_gate?: string;
    trace_status?: string;
    validation_allowed?: boolean;
  }>;
  deduplication_queue?: Array<{
    affected_code_path?: string;
    affected_endpoint?: string;
    candidate_id?: string;
    duplicate_risk_score?: number;
    execution_allowed?: boolean;
    next_action?: string;
    priority_score?: number;
    questions?: string[];
    queue_id?: string;
    report_submission_allowed?: boolean;
    required_evidence?: string[];
    safety_gate?: string;
    similarity_keys?: string[];
    validation_allowed?: boolean;
  }>;
  safe_validation_queue?: Array<{
    affected_code_path?: string;
    affected_endpoint?: string;
    candidate_id?: string;
    execution_allowed?: boolean;
    next_action?: string;
    plan_steps?: string[];
    priority_score?: number;
    queue_id?: string;
    report_submission_allowed?: boolean;
    required_approvals?: string[];
    safety_gate?: string;
    validation_allowed?: boolean;
    validation_execution_allowed?: boolean;
    validation_mode?: string;
  }>;
  report_draft_queue?: Array<{
    affected_code_path?: string;
    affected_endpoint?: string;
    candidate_id?: string;
    evidence_focus?: string[];
    execution_allowed?: boolean;
    next_action?: string;
    priority_score?: number;
    queue_id?: string;
    redaction_checks?: string[];
    report_status?: string;
    report_submission_allowed?: boolean;
    required_sections?: string[];
    safety_gate?: string;
    validation_allowed?: boolean;
  }>;
  ranked_top_candidates?: Array<{
    affected_code_path?: string;
    affected_endpoint?: string;
    candidate_id?: string;
    evidence_ready?: boolean;
    execution_allowed?: boolean;
    missing_evidence?: string[];
    missing_required_artifact_kinds?: string[];
    phase_id?: string;
    priority_score?: number;
    quality_status?: string;
    rank?: number;
    ranking_signal_breakdown?: string[];
    reason?: string;
    next_action?: string;
    required_evidence?: string[];
    report_submission_allowed?: boolean;
    safety_gate?: string;
    trace_status?: string;
    validation_allowed?: boolean;
  }>;
  next_candidate_actions?: Array<{
    candidate_id?: string;
    execution_allowed?: boolean;
    next_action?: string;
    phase_id?: string;
    priority_score?: number;
    reason?: string;
    report_submission_allowed?: boolean;
    required_evidence?: string[];
    safety_gate?: string;
    validation_allowed?: boolean;
  }>;
  phase_count?: number;
  phases?: Array<{
    execution_allowed?: boolean;
    input_refs?: string[];
    label?: string;
    output_refs?: string[];
    phase_id?: string;
    report_submission_allowed?: boolean;
    safety_gate?: string;
    status?: string;
    validation_allowed?: boolean;
  }>;
  promotion_policy?: {
    candidate_promotion_allowed?: boolean;
    requires_human_review?: boolean;
    requires_independent_refutation?: boolean;
    requires_local_artifact_trace?: boolean;
  };
  report_submission_allowed?: boolean;
  safety_gate?: string;
  source_plan_id?: string;
  source_review_loop_id?: string;
  status?: string;
  top_candidate_limit?: number;
  validation_allowed?: boolean;
  validation_execution_allowed?: boolean;
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
  attack_surface_model?: StudioAttackSurfaceModelInput;
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
  candidate_hunter_execution_loop?: StudioCandidateHunterExecutionLoopInput;
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

type StudioAttackSurfaceModelInput = {
  advisory_signal_count?: number;
  api_route_count?: number;
  execution_allowed?: boolean;
  har_route_count?: number;
  methods?: string[];
  next_action?: string;
  report_submission_allowed?: boolean;
  route_count?: number;
  safety_gate?: string;
  source_artifact_kinds?: string[];
  status?: string;
  top_routes?: Array<{
    artifact_kinds?: string[];
    method?: string;
    path?: string;
  }>;
  validation_allowed?: boolean;
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
  evidenceTraceSummary: {
    advisoryArtifactKinds: string[];
    codePathTraced: boolean;
    endpointTraced: boolean;
    executionAllowed: boolean;
    independentCrossCheckCount: number;
    missingRequiredArtifactKinds: string[];
    nextAction: string;
    presentRequiredArtifactKinds: string[];
    reportSubmissionAllowed: boolean;
    requiredArtifactKinds: string[];
    sourceFactCount: number;
    status: string;
    validationAllowed: boolean;
  };
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

export type StudioCandidateHunterExecutionLoop = {
  activeWorkItems: Array<{
    assignedAgent: string;
    candidateId: string;
    executionAllowed: boolean;
    gap: string;
    nextAction: string;
    phaseId: string;
    reportSubmissionAllowed: boolean;
    requiredEvidence: string[];
    validationAllowed: boolean;
    workItemId: string;
  }>;
  blockedActions: string[];
  candidateBudget: number;
  candidateEvidenceMatrix: Array<{
    advisorySources: string[];
    affectedCodePath: string;
    affectedEndpoint: string;
    candidateId: string;
    executionAllowed: boolean;
    hunterPriorityScore: number;
    impactScore: number;
    independentCrossCheckSources: string[];
    learningEvidenceNeededReasons: string[];
    localEvidenceSources: string[];
    missingEvidence: string[];
    missingRequiredArtifactKinds: string[];
    policyRiskScore: number;
    qualityScore: number;
    qualityStatus: string;
    rankingSignalBreakdown: string[];
    rejectionRiskScore: number;
    reportSubmissionAllowed: boolean;
    requiredEvidence: string[];
    traceStatus: string;
    validationAllowed: boolean;
  }>;
  candidateEvidenceSummary: {
    advisoryArtifactKinds: string[];
    averageQualityScore: number;
    candidateCount: number;
    codePathTracedCount: number;
    endpointTracedCount: number;
    evidenceReadyCandidateIds: string[];
    localArtifactKinds: string[];
    reviewNeededCandidateIds: string[];
    reviewNeededCount: number;
    reviewReadyCount: number;
  };
  candidatePromotionAllowed: boolean;
  completionGate: string;
  currentPhase: string;
  executionAllowed: boolean;
  iteration: number;
  learningFeedbackTarget: {
    actionCount: number;
    allowedOutcomes: string[];
    candidateIds: string[];
    executionAllowed: boolean;
    learningWriteAllowed: boolean;
    nextAction: string;
    reportSubmissionAllowed: boolean;
    safetyGate: string;
    sourceLoopId: string;
    status: string;
    targetId: string;
    validationAllowed: boolean;
  };
  learningReviewActions: Array<{
    actionId: string;
    allowedOutcomes: string[];
    candidateId: string;
    evidenceReady: boolean;
    executionAllowed: boolean;
    learningSignalTemplate?: {
      humanReviewRequired: boolean;
      learningWriteAllowed: boolean;
      playbookId: string;
      surfaceKey: string;
      targetRelationships: string[];
    };
    learningWriteAllowed: boolean;
    learningEvidenceNeededReasons: string[];
    missingEvidence: string[];
    missingRequiredArtifactKinds: string[];
    nextAction: string;
    reportSubmissionAllowed: boolean;
    safetyGate: string;
    sourceLoopId: string;
    suggestedOutcome: string;
    traceStatus: string;
    validationAllowed: boolean;
  }>;
  refutationQueue: Array<{
    candidateId: string;
    executionAllowed: boolean;
    missingEvidence: string[];
    missingRequiredArtifactKinds: string[];
    nextAction: string;
    priorityScore: number;
    questions: string[];
    queueId: string;
    reportSubmissionAllowed: boolean;
    requiredEvidence: string[];
    safetyGate: string;
    traceStatus: string;
    validationAllowed: boolean;
  }>;
  deduplicationQueue: Array<{
    affectedCodePath: string;
    affectedEndpoint: string;
    candidateId: string;
    duplicateRiskScore: number;
    executionAllowed: boolean;
    nextAction: string;
    priorityScore: number;
    questions: string[];
    queueId: string;
    reportSubmissionAllowed: boolean;
    requiredEvidence: string[];
    safetyGate: string;
    similarityKeys: string[];
    validationAllowed: boolean;
  }>;
  safeValidationQueue: Array<{
    affectedCodePath: string;
    affectedEndpoint: string;
    candidateId: string;
    executionAllowed: boolean;
    nextAction: string;
    planSteps: string[];
    priorityScore: number;
    queueId: string;
    reportSubmissionAllowed: boolean;
    requiredApprovals: string[];
    safetyGate: string;
    validationAllowed: boolean;
    validationExecutionAllowed: boolean;
    validationMode: string;
  }>;
  reportDraftQueue: Array<{
    affectedCodePath: string;
    affectedEndpoint: string;
    candidateId: string;
    evidenceFocus: string[];
    executionAllowed: boolean;
    nextAction: string;
    priorityScore: number;
    queueId: string;
    redactionChecks: string[];
    reportStatus: string;
    reportSubmissionAllowed: boolean;
    requiredSections: string[];
    safetyGate: string;
    validationAllowed: boolean;
  }>;
  rankedTopCandidates: Array<{
    affectedCodePath: string;
    affectedEndpoint: string;
    candidateId: string;
    evidenceReady: boolean;
    executionAllowed: boolean;
    missingEvidence: string[];
    missingRequiredArtifactKinds: string[];
    phaseId: string;
    priorityScore: number;
    qualityStatus: string;
    rank: number;
    rankingSignalBreakdown: string[];
    reason: string;
    nextAction: string;
    requiredEvidence: string[];
    reportSubmissionAllowed: boolean;
    safetyGate: string;
    traceStatus: string;
    validationAllowed: boolean;
  }>;
  loopId: string;
  nextCandidateActions: Array<{
    candidateId: string;
    executionAllowed: boolean;
    nextAction: string;
    phaseId: string;
    priorityScore: number;
    reason: string;
    reportSubmissionAllowed: boolean;
    requiredEvidence: string[];
    safetyGate: string;
    validationAllowed: boolean;
  }>;
  phaseCount: number;
  phases: Array<{
    executionAllowed: boolean;
    inputRefs: string[];
    label: string;
    outputRefs: string[];
    phaseId: string;
    reportSubmissionAllowed: boolean;
    safetyGate: string;
    status: string;
    validationAllowed: boolean;
  }>;
  promotionPolicy: {
    candidatePromotionAllowed: boolean;
    requiresHumanReview: boolean;
    requiresIndependentRefutation: boolean;
    requiresLocalArtifactTrace: boolean;
  };
  reportSubmissionAllowed: boolean;
  safetyGate: string;
  sourcePlanId: string;
  sourceReviewLoopId: string;
  status: string;
  topCandidateLimit: number;
  validationAllowed: boolean;
  validationExecutionAllowed: boolean;
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

export type StudioAttackSurfaceModel = {
  advisorySignalCount: number;
  apiRouteCount: number;
  executionAllowed: boolean;
  harRouteCount: number;
  methods: string[];
  nextAction: string;
  reportSubmissionAllowed: boolean;
  routeCount: number;
  safetyGate: string;
  sourceArtifactKinds: string[];
  status: string;
  topRoutes: Array<{
    artifactKinds: string[];
    method: string;
    path: string;
  }>;
  validationAllowed: boolean;
};

export type StudioMissionPanel = {
  advisoryContextLabel: string;
  agentHandoffPack: StudioAgentHandoffPack;
  agentQueue: StudioMissionAgentTask[];
  agentTaskTimeline: StudioMissionAgentTaskTimelineItem[];
  artifactCoverage: string;
  attackSurfaceModel: StudioAttackSurfaceModel;
  blockedActions: string[];
  candidateHunterBacklog: StudioCandidateHunterBacklogItem[];
  candidateHunterIteration: StudioCandidateHunterIteration;
  candidateHunterPlan: StudioCandidateHunterPlan;
  candidateHunterReviewLoop: StudioCandidateHunterReviewLoop;
  candidateHunterExecutionLoop: StudioCandidateHunterExecutionLoop;
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
  why_still_alive?: string[];
  falsification_summary?: {
    broken_invariant?: string;
    decision_status?: string;
    open_dimensions?: string[];
    survived_kill_score?: number;
    why_dead?: string[];
    why_still_alive?: string[];
  };
  repair_guidance?: string;
  evidence_needed?: string[];
  false_positive_checks?: string[];
  ranking_reasons?: string[];
  report_readiness?: {
    next_allowed_action?: string;
    report_submission_allowed?: boolean;
    required_evidence_count?: number;
    safe_validation_step_count?: number;
    status?: string;
    submission_blocked?: boolean;
    trace_status?: string;
  };
  evidence_gaps?: Array<{
    artifact_kind?: string;
    reason?: string;
  }>;
  evidence_trace_summary?: {
    advisory_artifact_kinds?: string[];
    code_path_traced?: boolean;
    endpoint_traced?: boolean;
    execution_allowed?: boolean;
    independent_cross_check_count?: number;
    missing_required_artifact_kinds?: string[];
    next_action?: string;
    present_required_artifact_kinds?: string[];
    report_submission_allowed?: boolean;
    required_artifact_kinds?: string[];
    source_fact_count?: number;
    status?: string;
    validation_allowed?: boolean;
  };
  suggested_fix?: string;
  regression_test?: string;
  safe_validation_plan?: string[];
  safe_verification?: boolean;
  safety_blockers?: string[];
  priority_score?: number;
  validation_mode?: string;
  hunter_assessment?: {
    evidence_focus?: string[];
  } | null;
  source_facts?: Array<{
    advisory_only?: string;
    artifact_kind?: string;
    authz_hint?: string;
    execution_allowed?: boolean;
    ecosystem?: string;
    fact_type?: string;
    operation_id?: string;
    package_name?: string;
    package_version?: string;
    report_submission_allowed?: boolean;
    review_state?: string;
    route_method?: string;
    route_path?: string;
    severity?: string;
    security_invariant?: string;
    sink_count?: number;
    sink_symbols?: string[];
    source_path?: string;
    symbol_name?: string;
    root_cause?: string;
    validation_allowed?: boolean;
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
  evidenceTraceSummary: {
    advisoryArtifactKinds: string[];
    codePathTraced: boolean;
    endpointTraced: boolean;
    executionAllowed: boolean;
    independentCrossCheckCount: number;
    missingRequiredArtifactKinds: string[];
    nextAction: string;
    presentRequiredArtifactKinds: string[];
    reportSubmissionAllowed: boolean;
    requiredArtifactKinds: string[];
    sourceFactCount: number;
    status: string;
    validationAllowed: boolean;
  };
  semanticEvidence: {
    authzHint: string;
    executionAllowed: boolean;
    reportSubmissionAllowed: boolean;
    reviewState: string;
    rootCause: string;
    securityInvariant: string;
    sinkCount: number;
    sinkSymbols: string[];
    validationAllowed: boolean;
  };
  refutationQuestions: string[];
  evidenceFocus: string[];
  rankingReasons: string[];
  brokenInvariant: string;
  whyStillAlive: string[];
  falsificationSummary: {
    brokenInvariant: string;
    decisionStatus: string;
    openDimensions: string[];
    survivedKillScore: number;
    whyDead: string[];
    whyStillAlive: string[];
  };
  repairGuidance: string;
  regressionTest: string;
  reason: string;
  reportReadiness: {
    nextAllowedAction: string;
    reportSubmissionAllowed: boolean;
    requiredEvidenceCount: number;
    safeValidationStepCount: number;
    status: string;
    submissionBlocked: boolean;
    traceStatus: string;
  };
  safeValidationPlan: string[];
  safetyBlockers: string[];
  priorityScore: number;
  validationMode: string;
};

export type StudioControlCenterView = {
  candidates: StudioCandidateCard[];
  inspectorTabs: ["候选详情", "证据", "验证计划", "报告草稿"];
  mobileTabs: ["总览", "候选", "详情"];
  permissions: {
    executionAllowed: false;
    reportSubmissionAllowed: false;
    validationAllowed: false;
  };
  reportState: {
    humanReviewRequired: true;
    label: "submission-blocked";
    submissionBlocked: true;
  };
  selectedCandidate: StudioCandidateCard | null;
};

export function toStudioConversationActorLabel(actor?: string): "研究智能体" | "研究员" {
  return actor === "operator" ? "研究员" : "研究智能体";
}

export function toStudioWorkspaceSummary(
  manifest: StudioWorkspaceManifest,
): StudioWorkspaceSummary {
  return {
    name: safeText(manifest.name, "未命名工作区"),
    artifactCount: manifest.artifacts?.length ?? 0,
    runCount: (manifest.runs?.length ?? 0) + (manifest.campaign_hunter_runs?.length ?? 0),
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
      advisoryPresent.length > 0 ? advisoryPresent.join(", ") : "暂无参考上下文",
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
        assignedAgent: safeText(item.assigned_agent, "人工审查者"),
        candidateId: safeText(item.candidate_id, "candidate"),
        executionAllowed: false,
        gap: safeText(item.gap, "needs_review"),
        handoffId: safeText(item.handoff_id, "handoff:candidate"),
        inputRefs: item.input_refs ?? [],
        nextAction: safeText(item.next_action, "需要人工审核。"),
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
        "人工审查者",
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
      agent: safeText(task.agent, "审查智能体"),
      candidateQualityGaps: task.candidate_quality_gaps ?? [],
      inputRefs: task.input_refs ?? [],
      nextAction: safeText(task.next_action, "需要审核。"),
      reviewFocus: task.review_focus ?? [],
      safetyGate: safeText(task.safety_gate, "human_review_required"),
      status: safeText(task.status, "needs_review"),
      targetCandidates: task.target_candidates ?? [],
      taskId: safeText(task.task_id, "agent_task"),
    })),
    agentTaskTimeline: (mission?.agent_task_timeline ?? []).map((stage) => ({
      agent: safeText(stage.agent, "审查智能体"),
      attempt: stage.attempt ?? 1,
      gateDecision: safeText(stage.gate_decision, "human_review_required"),
      inputSummary: safeText(stage.input_summary, "输入引用需要审核。"),
      nextHumanAction: safeText(stage.next_human_action, "需要审核。"),
      outputSummary: safeText(stage.output_summary, "输出摘要需要审核。"),
      reportSubmissionAllowed: false,
      safetyGate: safeText(stage.safety_gate, "human_review_required"),
      stageId: safeText(stage.stage_id, "agent_queue:stage"),
      status: safeText(stage.status, "needs_review"),
      taskId: safeText(stage.task_id, "agent_task"),
      validationExecutionAllowed: false,
    })),
    artifactCoverage: `${present.length}/${required.length} 项必需资料`,
    attackSurfaceModel: {
      advisorySignalCount: mission?.attack_surface_model?.advisory_signal_count ?? 0,
      apiRouteCount: mission?.attack_surface_model?.api_route_count ?? 0,
      executionAllowed: false,
      harRouteCount: mission?.attack_surface_model?.har_route_count ?? 0,
      methods: (mission?.attack_surface_model?.methods ?? []).map((method) =>
        safeText(method, "method"),
      ),
      nextAction: safeText(
        mission?.attack_surface_model?.next_action,
        "攻击面建模前请导入 API、HAR 和本地代码资料。",
      ),
      reportSubmissionAllowed: false,
      routeCount: mission?.attack_surface_model?.route_count ?? 0,
      safetyGate: safeText(
        mission?.attack_surface_model?.safety_gate,
        "authorized_artifacts_only",
      ),
      sourceArtifactKinds: (
        mission?.attack_surface_model?.source_artifact_kinds ?? []
      ).map((kind) => safeText(kind, "artifact")),
      status: safeText(mission?.attack_surface_model?.status, "not_modeled"),
      topRoutes: (mission?.attack_surface_model?.top_routes ?? []).map((route) => ({
        artifactKinds: (route.artifact_kinds ?? []).map((kind) =>
          safeText(kind, "artifact"),
        ),
        method: safeText(route.method, "METHOD"),
        path: safeText(route.path, "路由需要审核"),
      })),
      validationAllowed: false,
    },
    blockedActions: mission?.blocked_actions ?? [],
    candidateHunterBacklog: (mission?.candidate_hunter_backlog ?? []).map((item) => ({
      candidateId: safeText(item.candidate_id, "mission"),
      executionAllowed: false,
      gap: safeText(item.gap, "needs_review"),
      nextAction: safeText(item.next_action, "审查候选质量缺口。"),
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
        "人工审查者",
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
        "人工审查者",
      ),
      planId: safeText(
        mission?.candidate_hunter_plan?.plan_id,
        "candidate_hunter:autonomous_review_plan",
      ),
      planSteps: (mission?.candidate_hunter_plan?.plan_steps ?? []).map((step) => ({
        assignedAgent: safeText(step.assigned_agent, "人工审查者"),
        candidateId: safeText(step.candidate_id, "candidate"),
        executionAllowed: false,
        gap: safeText(step.gap, "needs_review"),
        inputRefs: step.input_refs ?? [],
        nextAction: safeText(step.next_action, "需要人工审核。"),
        reportSubmissionAllowed: false,
        requiredEvidence: step.required_evidence ?? [],
        reviewChecklist: (step.review_checklist ?? []).map((item) => ({
          executionAllowed: false,
          key: safeText(item.key, "review_item"),
          label: safeText(item.label, "审核项。"),
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
          assignedAgent: safeText(step.assigned_agent, "人工审查者"),
          candidateId: safeText(step.candidate_id, "candidate"),
          executionAllowed: false,
          gap: safeText(step.gap, "needs_review"),
          governanceRefs: step.governance_refs ?? [],
          nextAction: safeText(step.next_action, "需要人工审核。"),
          reportSubmissionAllowed: false,
          requiredEvidence: step.required_evidence ?? [],
          reviewChecklist: (step.review_checklist ?? []).map((item) => ({
            executionAllowed: false,
            key: safeText(item.key, "review_item"),
            label: safeText(item.label, "审核项。"),
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
        "人工审查者",
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
    candidateHunterExecutionLoop: {
      activeWorkItems: (mission?.candidate_hunter_execution_loop?.active_work_items ?? []).map(
        (item) => ({
          assignedAgent: safeText(item.assigned_agent, "人工审查者"),
          candidateId: safeText(item.candidate_id, "candidate"),
          executionAllowed: false,
          gap: safeText(item.gap, "needs_review"),
          nextAction: safeText(item.next_action, "需要人工审核。"),
          phaseId: safeText(item.phase_id, "refutation"),
          reportSubmissionAllowed: false,
          requiredEvidence: item.required_evidence ?? [],
          validationAllowed: false,
          workItemId: safeText(item.work_item_id, "candidate_hunter_work_item"),
        }),
      ),
      blockedActions: mission?.candidate_hunter_execution_loop?.blocked_actions ?? [],
      candidateBudget: mission?.candidate_hunter_execution_loop?.candidate_budget ?? 5,
      candidateEvidenceMatrix: (
        mission?.candidate_hunter_execution_loop?.candidate_evidence_matrix ?? []
      ).map((item) => ({
        advisorySources: item.advisory_sources ?? [],
        affectedCodePath: safeText(item.affected_code_path, ""),
        affectedEndpoint: safeText(item.affected_endpoint, ""),
        candidateId: safeText(item.candidate_id, "candidate"),
        executionAllowed: false,
        hunterPriorityScore: item.hunter_priority_score ?? 0,
        impactScore: item.impact_score ?? 0,
        independentCrossCheckSources: item.independent_cross_check_sources ?? [],
        learningEvidenceNeededReasons: item.learning_evidence_needed_reasons ?? [],
        localEvidenceSources: item.local_evidence_sources ?? [],
        missingEvidence: item.missing_evidence ?? [],
        missingRequiredArtifactKinds: item.missing_required_artifact_kinds ?? [],
        policyRiskScore: item.policy_risk_score ?? 0,
        qualityScore: item.quality_score ?? 0,
        qualityStatus: safeText(item.quality_status, "needs_review"),
        rankingSignalBreakdown: item.ranking_signal_breakdown ?? [],
        rejectionRiskScore: item.rejection_risk_score ?? 0,
        reportSubmissionAllowed: false,
        requiredEvidence: learnedEvidenceRequiredEvidence(
          item.learning_evidence_needed_reasons ?? [],
        ),
        traceStatus: safeText(item.evidence_trace_status, "needs_evidence"),
        validationAllowed: false,
      })),
      candidateEvidenceSummary: {
        advisoryArtifactKinds:
          mission?.candidate_hunter_execution_loop?.candidate_evidence_summary
            ?.advisory_artifact_kinds ?? [],
        averageQualityScore:
          mission?.candidate_hunter_execution_loop?.candidate_evidence_summary
            ?.average_quality_score ?? 0,
        candidateCount:
          mission?.candidate_hunter_execution_loop?.candidate_evidence_summary
            ?.candidate_count ?? 0,
        codePathTracedCount:
          mission?.candidate_hunter_execution_loop?.candidate_evidence_summary
            ?.code_path_traced_count ?? 0,
        endpointTracedCount:
          mission?.candidate_hunter_execution_loop?.candidate_evidence_summary
            ?.endpoint_traced_count ?? 0,
        evidenceReadyCandidateIds:
          mission?.candidate_hunter_execution_loop?.candidate_evidence_summary
            ?.evidence_ready_candidate_ids ?? [],
        localArtifactKinds:
          mission?.candidate_hunter_execution_loop?.candidate_evidence_summary
            ?.local_artifact_kinds ?? [],
        reviewNeededCandidateIds:
          mission?.candidate_hunter_execution_loop?.candidate_evidence_summary
            ?.review_needed_candidate_ids ?? [],
        reviewNeededCount:
          mission?.candidate_hunter_execution_loop?.candidate_evidence_summary
            ?.review_needed_count ?? 0,
        reviewReadyCount:
          mission?.candidate_hunter_execution_loop?.candidate_evidence_summary
            ?.review_ready_count ?? 0,
      },
      rankedTopCandidates: toCandidateHunterRankedTopCandidates(
        mission?.candidate_hunter_execution_loop,
      ),
      candidatePromotionAllowed: false,
      completionGate: "human_review_required",
      currentPhase: safeText(
        mission?.candidate_hunter_execution_loop?.current_phase,
        "report_draft_readiness",
      ),
      executionAllowed: false,
      iteration: mission?.candidate_hunter_execution_loop?.iteration ?? 1,
      learningFeedbackTarget: {
        actionCount:
          mission?.candidate_hunter_execution_loop?.learning_feedback_target
            ?.action_count ?? 0,
        allowedOutcomes:
          mission?.candidate_hunter_execution_loop?.learning_feedback_target
            ?.allowed_outcomes ?? [],
        candidateIds:
          mission?.candidate_hunter_execution_loop?.learning_feedback_target
            ?.candidate_ids ?? [],
        executionAllowed: false,
        learningWriteAllowed: false,
        nextAction: safeText(
          mission?.candidate_hunter_execution_loop?.learning_feedback_target
            ?.next_action,
          "记录人工审核结果后，再更新后续排序。",
        ),
        reportSubmissionAllowed: false,
        safetyGate: "human_review_required",
        sourceLoopId: safeText(
          mission?.candidate_hunter_execution_loop?.learning_feedback_target
            ?.source_loop_id,
          "candidate_hunter:bounded_execution_loop",
        ),
        status: safeText(
          mission?.candidate_hunter_execution_loop?.learning_feedback_target?.status,
          "awaiting_human_outcome",
        ),
        targetId: safeText(
          mission?.candidate_hunter_execution_loop?.learning_feedback_target
            ?.target_id,
          "candidate_hunter:learning_feedback:next_actions",
        ),
        validationAllowed: false,
      },
      learningReviewActions: toCandidateHunterLearningReviewActions(
        mission?.candidate_hunter_execution_loop,
      ),
      refutationQueue: toCandidateHunterRefutationQueue(
        mission?.candidate_hunter_execution_loop,
      ),
      deduplicationQueue: toCandidateHunterDeduplicationQueue(
        mission?.candidate_hunter_execution_loop,
      ),
      safeValidationQueue: toCandidateHunterSafeValidationQueue(
        mission?.candidate_hunter_execution_loop,
      ),
      reportDraftQueue: toCandidateHunterReportDraftQueue(
        mission?.candidate_hunter_execution_loop,
      ),
      loopId: safeText(
        mission?.candidate_hunter_execution_loop?.loop_id,
        "candidate_hunter:bounded_execution_loop",
      ),
      nextCandidateActions: (
        mission?.candidate_hunter_execution_loop?.next_candidate_actions ?? []
      ).map((item) => ({
        candidateId: safeText(item.candidate_id, "candidate"),
        executionAllowed: false,
        nextAction: safeText(item.next_action, "需要人工审核。"),
        phaseId: safeText(item.phase_id, "refutation"),
        priorityScore: item.priority_score ?? 0,
        reason: safeText(item.reason, "needs_review"),
        reportSubmissionAllowed: false,
        requiredEvidence: item.required_evidence ?? [],
        safetyGate: safeExecutionPhaseGate(item.safety_gate),
        validationAllowed: false,
      })),
      phaseCount: mission?.candidate_hunter_execution_loop?.phase_count ?? 0,
      phases: (mission?.candidate_hunter_execution_loop?.phases ?? []).map((phase) => ({
        executionAllowed: false,
        inputRefs: phase.input_refs ?? [],
        label: safeText(phase.label, "候选挖掘阶段"),
        outputRefs: phase.output_refs ?? [],
        phaseId: safeText(phase.phase_id, "candidate_hunter_phase"),
        reportSubmissionAllowed: false,
        safetyGate: safeExecutionPhaseGate(phase.safety_gate),
        status: safeText(phase.status, "needs_review"),
        validationAllowed: false,
      })),
      promotionPolicy: {
        candidatePromotionAllowed: false,
        requiresHumanReview: true,
        requiresIndependentRefutation: true,
        requiresLocalArtifactTrace: true,
      },
      reportSubmissionAllowed: false,
      safetyGate: "bounded_autonomous_review_only",
      sourcePlanId: safeText(
        mission?.candidate_hunter_execution_loop?.source_plan_id,
        "candidate_hunter:autonomous_review_plan",
      ),
      sourceReviewLoopId: safeText(
        mission?.candidate_hunter_execution_loop?.source_review_loop_id,
        "candidate_hunter:next_review_loop",
      ),
      status: safeText(mission?.candidate_hunter_execution_loop?.status, "needs_review"),
      topCandidateLimit: mission?.candidate_hunter_execution_loop?.top_candidate_limit ?? 5,
      validationAllowed: false,
      validationExecutionAllowed: false,
    },
    candidateReviewPackets: (mission?.candidate_review_packets ?? []).map((packet) => ({
      candidateId: safeText(packet.candidate_id, "candidate"),
      checklist: (packet.checklist ?? []).map((item) => ({
        key: safeText(item.key, "review_item"),
        label: safeText(item.label, "审核项"),
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
      nextHumanAction: safeText(packet.next_human_action, "需要人工审核。"),
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
    candidateCountLabel: `${candidateCount} 个高优先级候选`,
    gates: {
      humanReviewRequired: true,
      reportSubmissionAllowed: false,
      submissionBlocked: true,
      topCandidateQualityGate: mission?.quality_gates?.top_candidate_quality_gate === true,
      topCandidatesLimited: mission?.quality_gates?.top_candidates_limited === true,
      validationExecutionAllowed: false,
    },
    modeLabel:
      mission?.mode === "local_ai_vulnerability_research_workbench"
        ? "本地 AI 漏洞研究工作台"
        : "本地研究工作台",
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
        summary: safeText(stage.summary, "审核状态暂不可用。"),
      };
    }),
    runId: safeText(mission?.run_id, "未选择运行"),
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
        nextHumanAction: safeText(item.next_human_action, "需要人工审核。"),
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
      affectedCodePath: safeText(candidate.affected_code_path, "代码路径需要审核"),
      affectedEndpoint: safeText(candidate.affected_endpoint, "端点需要审核"),
      deduplicationReviewStatus: safeText(
        candidate.deduplication_review_status,
        "needs_human_review",
      ),
      evidenceGapCount: candidate.evidence_gap_count ?? 0,
      evidenceNeedCount: candidate.evidence_need_count ?? 0,
      evidenceReviewStatus: safeText(candidate.evidence_review_status, "needs_human_review"),
      evidenceTraceSummary: evidenceTraceSummaryFromInput(candidate.evidence_trace_summary),
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
      nextReportAction: safeText(candidate.next_report_action, "导出前请审查证据。"),
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
              `- ${item.handoffId}：${item.assignedAgent} 处理 ${item.workItemId}；状态 ${item.status}；缺口 ${item.gap}；下一步 ${item.nextAction}`,
          )
          .join("\n")
      : "- 暂无交接项；请继续对当前高优先级候选进行人工审核。";
  const blockedActions =
    panel.agentHandoffPack.blockedActions.length > 0
      ? panel.agentHandoffPack.blockedActions.join(", ")
      : panel.blockedActions.join(", ");
  const nextCandidateAction = panel.candidateHunterExecutionLoop.nextCandidateActions[0];
  const executionLoopSummary = nextCandidateAction
    ? `候选挖掘执行循环：${panel.candidateHunterExecutionLoop.status}；当前阶段 ${panel.candidateHunterExecutionLoop.currentPhase}；下一操作 ${nextCandidateAction.candidateId} -> ${nextCandidateAction.phaseId}（${nextCandidateAction.priorityScore}）`
    : `候选挖掘执行循环：${panel.candidateHunterExecutionLoop.status}；当前阶段 ${panel.candidateHunterExecutionLoop.currentPhase}；暂无下一操作`;
  const nextCandidateActionLine = nextCandidateAction
    ? `下一候选操作：${nextCandidateAction.nextAction}`
    : "下一候选操作：审核当前高优先级候选。";
  const rankedTopCandidate = panel.candidateHunterExecutionLoop.rankedTopCandidates[0];
  const rankedTopCandidateLine = rankedTopCandidate
    ? `排名前 1-5：#${rankedTopCandidate.rank} ${rankedTopCandidate.candidateId} ${rankedTopCandidate.reason}（${rankedTopCandidate.priorityScore}）`
    : "排名前 1-5：无";
  const rankedTopCandidateEvidenceLine = rankedTopCandidate
    ? `高优先级候选证据：轨迹 ${rankedTopCandidate.traceStatus}；就绪 ${rankedTopCandidate.evidenceReady ? "是" : "否"}；缺少 ${rankedTopCandidate.missingEvidence.join(", ") || "无"}；缺少必需资料 ${rankedTopCandidate.missingRequiredArtifactKinds.join(", ") || "无"}`
    : "高优先级候选证据：无";
  const rankedTopCandidateNextActionLine = rankedTopCandidate
    ? `高优先级候选下一操作：${rankedTopCandidate.nextAction}`
    : "高优先级候选下一操作：审核当前高优先级候选。";
  const learningTarget = panel.candidateHunterExecutionLoop.learningFeedbackTarget;
  const learningFeedbackLine = `学习反馈：${learningTarget.status}；候选 ${learningTarget.candidateIds.join(", ") || "无"}；结果 ${learningTarget.allowedOutcomes.join(", ") || "已确认、已反证、需要更多证据、重复"}`;
  const learningActionLine = `学习操作：${learningTarget.nextAction}`;
  const learningReviewActionsLine =
    panel.candidateHunterExecutionLoop.learningReviewActions.length > 0
      ? `学习审核操作：${panel.candidateHunterExecutionLoop.learningReviewActions
          .map(
            (action) =>
              `${action.candidateId} -> ${action.suggestedOutcome}；允许写入 ${action.learningWriteAllowed ? "是" : "否"}`,
          )
          .join(", ")}`
      : "学习审核操作：无";
  const refutationQueueItem = panel.candidateHunterExecutionLoop.refutationQueue[0];
  const refutationQueueLine = refutationQueueItem
    ? `反证队列：${refutationQueueItem.candidateId} ${refutationQueueItem.traceStatus}（${refutationQueueItem.priorityScore}）`
    : "反证队列：无";
  const deduplicationQueueItem = panel.candidateHunterExecutionLoop.deduplicationQueue[0];
  const deduplicationQueueLine = deduplicationQueueItem
    ? `去重队列：${deduplicationQueueItem.candidateId}，重复风险 ${deduplicationQueueItem.duplicateRiskScore}/100`
    : "去重队列：无";
  const safeValidationQueueItem = panel.candidateHunterExecutionLoop.safeValidationQueue[0];
  const safeValidationQueueLine = safeValidationQueueItem
    ? `安全验证队列：${safeValidationQueueItem.candidateId} ${safeValidationQueueItem.validationMode}`
    : "安全验证队列：无";
  const reportDraftQueueItem = panel.candidateHunterExecutionLoop.reportDraftQueue[0];
  const reportDraftQueueLine = reportDraftQueueItem
    ? `报告草稿队列：${reportDraftQueueItem.candidateId} ${reportDraftQueueItem.reportStatus}`
    : "报告草稿队列：无";

  return [
    "本地人工智能漏洞研究交接（MDASH / XBOW 风格）",
    `运行：${panel.runId}`,
    `资料：${panel.artifactCoverage}`,
    `范围守卫：${panel.scopeGuardLabel}`,
    `参考上下文：${panel.advisoryContextLabel}`,
    `幻觉治理：${panel.candidateHunterPlan.hallucinationGovernance.claimPromotionRule}；知识 ${panel.candidateHunterPlan.hallucinationGovernance.knowledgePolicy}；允许提升 ${panel.candidateHunterPlan.hallucinationGovernance.candidatePromotionAllowed ? "是" : "否"}`,
    `质量：${panel.qualitySummary.topCandidateQualityGate}；可审核 ${panel.qualitySummary.reviewReadyCount}/${panel.qualitySummary.candidateCount}；平均 ${panel.qualitySummary.averageQualityScore}`,
    `报告：${panel.submissionBlockedReportSummary.status}；就绪候选 ${panel.submissionBlockedReportSummary.readyCandidateIds.join(", ") || "无"}；审批门 ${panel.submissionBlockedReportSummary.safetyGate}`,
    `候选挖掘计划：${panel.candidateHunterPlan.status}；步骤 ${panel.candidateHunterPlan.stepCount}；下一审查者 ${panel.candidateHunterPlan.nextReviewAgent}`,
    `候选挖掘审查循环：${panel.candidateHunterReviewLoop.status}；活跃步骤 ${panel.candidateHunterReviewLoop.activeStepCount}；下一审查者 ${panel.candidateHunterReviewLoop.nextReviewAgent}`,
    executionLoopSummary,
    rankedTopCandidateLine,
    rankedTopCandidateEvidenceLine,
    rankedTopCandidateNextActionLine,
    nextCandidateActionLine,
    refutationQueueLine,
    deduplicationQueueLine,
    safeValidationQueueLine,
    reportDraftQueueLine,
    learningFeedbackLine,
    learningActionLine,
    learningReviewActionsLine,
    `下一审查者：${panel.agentHandoffPack.nextReviewAgent}`,
    `交接项：${panel.agentHandoffPack.handoffItemCount}`,
    handoffItems,
    `安全审批门：${panel.agentHandoffPack.safetyGate}`,
    `完成审批门：${panel.agentHandoffPack.completionGate}`,
    `阻断操作：${blockedActions || "execute_live_validation, run_fuzzer, submit_report"}`,
    "此交接不授予验证、模糊测试或报告提交权限。",
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
    artifactChecklistItem("scope", "范围", true, presentKinds),
    artifactChecklistItem("policy", "策略", true, presentKinds),
    artifactChecklistItem("code", "授权代码", true, presentKinds),
    artifactChecklistItem("api", "API", true, presentKinds),
    artifactChecklistItem("har", "HAR", true, presentKinds),
    artifactChecklistItem("sbom", "SBOM", false, presentKinds),
    artifactChecklistItem("sarif", "SARIF", false, presentKinds),
    artifactChecklistItem("fuzzing", "模糊测试计划", false, presentKinds),
    artifactChecklistItem("strategy", "策略说明", false, presentKinds),
    artifactChecklistItem("knowledge", "知识", false, presentKinds),
  ];
}

export function toStudioResearchReadiness(
  workspacePath: string,
  manifest: StudioWorkspaceManifest,
): StudioResearchReadiness {
  if (!workspacePath.trim()) {
    return {
      canStart: false,
      reason: "研究前请创建或打开工作区。",
    };
  }

  const checklist = toStudioArtifactChecklist(manifest);
  const missingRequired = checklist
    .filter((item) => item.required && !item.present)
    .map((item) => missingArtifactLabel(item));

  if (missingRequired.length > 0) {
    return {
      canStart: false,
      reason: `研究前请导入${missingRequired.join("、")}。`,
    };
  }

  return {
    canStart: true,
    reason: "策略、范围、API/HAR 和代码已就绪，可开展 A+B 候选研究。",
  };
}

function whyStillAliveFromCandidate(candidate: StudioCandidateInput): string[] {
  const direct = Array.isArray(candidate.why_still_alive)
    ? candidate.why_still_alive.filter((item): item is string => Boolean(safeText(item, "")))
    : [];
  if (direct.length > 0) {
    return direct.map((item) => safeText(item, ""));
  }
  const summary = candidate.falsification_summary?.why_still_alive;
  if (Array.isArray(summary)) {
    return summary
      .filter((item): item is string => Boolean(safeText(item, "")))
      .map((item) => safeText(item, ""));
  }
  return [];
}

function falsificationSummaryFromCandidate(
  candidate: StudioCandidateInput,
): StudioCandidateCard["falsificationSummary"] {
  const summary = candidate.falsification_summary;
  const whyStillAlive = whyStillAliveFromCandidate(candidate);
  return {
    brokenInvariant: safeText(
      summary?.broken_invariant || candidate.broken_invariant,
      "安全不变量需要审核。",
    ),
    decisionStatus: safeText(summary?.decision_status, "needs_review"),
    openDimensions: Array.isArray(summary?.open_dimensions)
      ? summary.open_dimensions
          .filter((item): item is string => Boolean(safeText(item, "")))
          .map((item) => safeText(item, ""))
      : [],
    survivedKillScore: Number.isFinite(summary?.survived_kill_score)
      ? Number(summary?.survived_kill_score)
      : 0,
    whyDead: Array.isArray(summary?.why_dead)
      ? summary.why_dead
          .filter((item): item is string => Boolean(safeText(item, "")))
          .map((item) => safeText(item, ""))
      : [],
    whyStillAlive,
  };
}

export function toStudioCandidateCards(candidates: StudioCandidateInput[]): StudioCandidateCard[] {
  return candidates.slice(0, 5).map((candidate, index) => {
    const endpoint = endpointFromCandidate(candidate);
    const codePath = codePathFromCandidate(candidate);

    return {
      id: safeText(candidate.hypothesis_id, `H-${String(index + 1).padStart(3, "0")}`),
      title: safeText(candidate.vuln_type, "候选假设"),
      severity: safeText(candidate.risk, "medium"),
      status: candidate.safe_verification === false
        ? "blocked"
        : endpoint && codePath
          ? "needs_evidence"
          : "needs_review",
      affectedEndpoint: endpoint || "端点需要审核",
      affectedCodePath: codePath || "代码路径需要审核",
      evidenceNeeds: candidate.evidence_needed ?? [],
      evidenceGaps: evidenceGapsFromCandidate(candidate),
      evidenceTraceSummary: evidenceTraceSummaryFromCandidate(candidate),
      semanticEvidence: semanticEvidenceFromCandidate(candidate),
      refutationQuestions: candidate.false_positive_checks ?? [],
      evidenceFocus: candidate.hunter_assessment?.evidence_focus ?? [],
      rankingReasons: candidate.ranking_reasons ?? [],
      brokenInvariant: safeText(
        candidate.broken_invariant
          || candidate.falsification_summary?.broken_invariant,
        "安全不变量需要审核。",
      ),
      whyStillAlive: whyStillAliveFromCandidate(candidate),
      falsificationSummary: falsificationSummaryFromCandidate(candidate),
      repairGuidance: safeText(
        candidate.repair_guidance,
        safeText(candidate.suggested_fix, "修复建议需要审核。"),
      ),
      regressionTest: safeText(candidate.regression_test, "回归测试需要审核。"),
      reason: safeText(candidate.reason, "审核理由暂不可用。"),
      reportReadiness: reportReadinessFromCandidate(candidate),
      safeValidationPlan: candidate.safe_validation_plan ?? [],
      safetyBlockers: candidate.safety_blockers ?? [],
      priorityScore: candidate.priority_score ?? 0,
      validationMode: safeText(candidate.validation_mode, "manual_review"),
    };
  });
}

export function toStudioControlCenterView(
  candidates: StudioCandidateCard[],
  selectedCandidateId: string | null,
): StudioControlCenterView {
  const localizedCandidates = candidates.map((candidate) => ({
    ...candidate,
    affectedCodePath:
      candidate.affectedCodePath === "代码路径需要审核"
        ? "待补充代码路径"
        : candidate.affectedCodePath,
    affectedEndpoint:
      candidate.affectedEndpoint === "端点需要审核"
        ? "待补充受影响端点"
        : candidate.affectedEndpoint,
    evidenceTraceSummary: {
      ...candidate.evidenceTraceSummary,
      executionAllowed: false,
      reportSubmissionAllowed: false,
      validationAllowed: false,
    },
    reportReadiness: {
      ...candidate.reportReadiness,
      reportSubmissionAllowed: false,
      submissionBlocked: true,
    },
  }));
  const selectedCandidate =
    localizedCandidates.find((candidate) => candidate.id === selectedCandidateId)
    ?? localizedCandidates[0]
    ?? null;

  return {
    candidates: localizedCandidates,
    inspectorTabs: ["候选详情", "证据", "验证计划", "报告草稿"],
    mobileTabs: ["总览", "候选", "详情"],
    permissions: {
      executionAllowed: false,
      reportSubmissionAllowed: false,
      validationAllowed: false,
    },
    reportState: {
      humanReviewRequired: true,
      label: "submission-blocked",
      submissionBlocked: true,
    },
    selectedCandidate,
  };
}

export function toStudioCampaignHunterCandidateCards(
  controlCenter: CampaignControlCenter | null,
): StudioCandidateCard[] {
  return (controlCenter?.research_queue_suggestions ?? []).slice(0, 5).map((suggestion, index) => {
    const id = safeText(suggestion.queue_key, `campaign-hunter-${index + 1}`);
    const requiredEvidence = suggestion.required_evidence ?? [];
    const satisfiedEvidence = suggestion.satisfied_evidence ?? [];
    const qualityGateReasons = suggestion.quality_gate_reasons ?? [];
    const hasEvidenceGate = requiredEvidence.length > 0 || qualityGateReasons.length > 0;

    return {
      id,
      title: safeText(suggestion.playbook_id, "campaign_hunter_candidate"),
      severity: suggestion.priority_score >= 80 ? "high" : "medium",
      status: hasEvidenceGate ? "needs_evidence" : "needs_review",
      affectedEndpoint: safeText(suggestion.surface_key, "端点需要审核"),
      affectedCodePath: "代码路径需要审核",
      evidenceNeeds: requiredEvidence,
      evidenceGaps: qualityGateReasons,
      evidenceTraceSummary: {
        advisoryArtifactKinds: ["campaign_hunter"],
        codePathTraced: false,
        endpointTraced: Boolean(suggestion.surface_key),
        executionAllowed: false,
        independentCrossCheckCount: 0,
        missingRequiredArtifactKinds: requiredEvidence,
        nextAction: safeText(
          suggestion.next_allowed_action,
          "验证前请审查候选证据和反证问题。",
        ),
        presentRequiredArtifactKinds: [],
        reportSubmissionAllowed: false,
        requiredArtifactKinds: ["scope", "policy", "code", "api", "har"],
        sourceFactCount: 0,
        status: safeText(suggestion.candidate_status, "awaiting_evidence_review"),
        validationAllowed: false,
      },
      semanticEvidence: {
        authzHint: safeText(suggestion.playbook_id, "needs_review"),
        executionAllowed: false,
        reportSubmissionAllowed: false,
        reviewState: "needs_human_review",
        rootCause: "项目候选挖掘候选需要本地证据审核。",
        securityInvariant: "涉及授权的路由需要可追溯的策略、API、HAR 与代码证据。",
        sinkCount: 0,
        sinkSymbols: [],
        validationAllowed: false,
      },
      refutationQuestions: [
        `${suggestion.refutation_question_count ?? 0} 个反证问题需要审核。`,
      ],
      evidenceFocus: [
        ...requiredEvidence,
        ...satisfiedEvidence.map((item) => `satisfied_evidence:${item}`),
      ],
      rankingReasons: [
        `priority_score:${Math.max(0, Math.min(100, Math.round(suggestion.priority_score)))}`,
        ...qualityGateReasons,
        ...satisfiedEvidence.map((item) => `satisfied_evidence:${item}`),
      ],
      brokenInvariant: "候选不变量在提升前需要人工审核。",
      whyStillAlive: [
        "项目候选挖掘建议尚未完成反证淘汰尝试。",
      ],
      falsificationSummary: {
        brokenInvariant: "候选不变量在提升前需要人工审核。",
        decisionStatus: "needs_evidence",
        openDimensions: ["control_presence", "public_by_design"],
        survivedKillScore: 0,
        whyDead: [],
        whyStillAlive: [
          "项目候选挖掘建议尚未完成反证淘汰尝试。",
        ],
      },
      repairGuidance: "起草修复建议前请确认代码路径和授权不变量。",
      regressionTest: "仅在证据审核确认候选后起草本地回归测试。",
      reason: safeText(suggestion.title, "项目候选挖掘候选需要审核。"),
      reportReadiness: reportReadinessFromInput(
        suggestion.report_readiness,
        "导出报告预览前请处理项目候选挖掘证据门。",
      ),
      safeValidationPlan: [
        `${suggestion.validation_step_count ?? 0} 个安全验证步骤需要在执行前获得人工批准。`,
      ],
      safetyBlockers: [
        safeText(suggestion.safety_gate, "review_only_no_execution"),
        "execution_blocked",
        "report_submission_blocked",
      ],
      priorityScore: Math.max(0, Math.min(100, Math.round(suggestion.priority_score))),
      validationMode: "human_approved_non_destructive_plan",
    };
  });
}

function evidenceTraceSummaryFromCandidate(
  candidate: StudioCandidateInput,
): StudioCandidateCard["evidenceTraceSummary"] {
  return evidenceTraceSummaryFromInput(candidate.evidence_trace_summary);
}

function semanticEvidenceFromCandidate(
  candidate: StudioCandidateInput,
): StudioCandidateCard["semanticEvidence"] {
  const fact = candidate.source_facts?.find(
    (item) => item.root_cause || item.security_invariant || item.sink_symbols,
  );
  return {
    authzHint: safeText(fact?.authz_hint, "needs_review"),
    executionAllowed: false,
    reportSubmissionAllowed: false,
    reviewState: safeText(fact?.review_state, "needs_human_review"),
    rootCause: safeText(fact?.root_cause, "根因需要审核。"),
    securityInvariant: safeText(
      fact?.security_invariant,
      "安全不变量需要审核。",
    ),
    sinkCount: fact?.sink_count ?? 0,
    sinkSymbols: fact?.sink_symbols ?? [],
    validationAllowed: false,
  };
}

function evidenceTraceSummaryFromInput(
  summary: StudioCandidateInput["evidence_trace_summary"],
): StudioCandidateCard["evidenceTraceSummary"] {
  return {
    advisoryArtifactKinds: summary?.advisory_artifact_kinds ?? [],
    codePathTraced: summary?.code_path_traced === true,
    endpointTraced: summary?.endpoint_traced === true,
    executionAllowed: false,
    independentCrossCheckCount: summary?.independent_cross_check_count ?? 0,
    missingRequiredArtifactKinds: summary?.missing_required_artifact_kinds ?? [],
    nextAction: safeText(
      summary?.next_action,
      "任何验证前请审查轨迹摘要和反证问题。",
    ),
    presentRequiredArtifactKinds: summary?.present_required_artifact_kinds ?? [],
    reportSubmissionAllowed: false,
    requiredArtifactKinds:
      summary?.required_artifact_kinds ?? ["scope", "policy", "code", "api", "har"],
    sourceFactCount: summary?.source_fact_count ?? 0,
    status: safeText(summary?.status, "needs_evidence"),
    validationAllowed: false,
  };
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
    ? `导出报告预览前请处理候选证据缺口：${evidenceGaps.join("；")}。`
    : safeText(
        candidate.report_readiness?.next_allowed_action,
        "导出报告预览前请审查证据和安全阻断项。",
      );

  return {
    ...reportReadinessFromInput(candidate.report_readiness, nextAllowedAction),
    nextAllowedAction,
  };
}

function reportReadinessFromInput(
  readiness: StudioCandidateInput["report_readiness"],
  fallbackNextAllowedAction: string,
): StudioCandidateCard["reportReadiness"] {
  const traceStatus = safeText(readiness?.trace_status, "needs_evidence");
  return {
    nextAllowedAction: safeText(readiness?.next_allowed_action, fallbackNextAllowedAction),
    reportSubmissionAllowed: false,
    requiredEvidenceCount: safeCount(readiness?.required_evidence_count) ?? 0,
    safeValidationStepCount: safeCount(readiness?.safe_validation_step_count) ?? 0,
    status: safeText(readiness?.status, "submission_blocked"),
    submissionBlocked: true,
    traceStatus: traceStatus === "traceable" ? "traceable" : "needs_evidence",
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
    return "已导入范围";
  }
  if (value === "allowed") {
    return "已允许";
  }
  if (value === "blocked") {
    return "已阻断";
  }
  return "缺少范围";
}

function missionActionLabel(value: string): string {
  if (value === "review_top_candidates") {
    return "审查高优先级候选";
  }
  if (value === "create_benchmark_template") {
    return "创建基准模板";
  }
  if (value === "export_submission_blocked_report") {
    return "导出提交已阻断的报告";
  }
  return value.replace(/[_-]+/g, " ");
}

function missionResearchLoopLabel(value: string): string {
  if (value === "scope_guard") {
    return "范围守卫";
  }
  if (value === "target_intake") {
    return "目标接入";
  }
  if (value === "attack_surface_modeling") {
    return "攻击面建模";
  }
  if (value === "semantic_audit") {
    return "语义审计";
  }
  if (value === "hypothesis_generation") {
    return "假设生成";
  }
  if (value === "refutation_review") {
    return "反证审查";
  }
  if (value === "deduplication_review") {
    return "去重审查";
  }
  if (value === "safe_validation_planning") {
    return "安全验证规划";
  }
  if (value === "evidence_review") {
    return "证据审查";
  }
  if (value === "submission_blocked_report") {
    return "提交已阻断的报告";
  }
  return missionActionLabel(value);
}

const candidateHunterLearningOutcomes = [
  "confirmed",
  "refuted",
  "needs_more_evidence",
  "duplicate",
];

function toCandidateHunterLearningReviewActions(
  loop: StudioCandidateHunterExecutionLoopInput | undefined,
): StudioCandidateHunterExecutionLoop["learningReviewActions"] {
  const evidenceReadyIds = new Set(
    loop?.candidate_evidence_summary?.evidence_ready_candidate_ids ?? [],
  );
  const evidenceByCandidateId = new Map(
    (loop?.candidate_evidence_matrix ?? []).map((item) => [
      safeText(item.candidate_id, "candidate"),
      item,
    ]),
  );
  if ((loop?.learning_review_actions?.length ?? 0) > 0) {
    const actions = (loop?.learning_review_actions ?? [])
      .slice(0, 5)
      .map((item) => {
        const candidateId = safeText(item.candidate_id, "");
        const suggestedOutcome = candidateHunterLearningOutcomes.includes(
          safeText(item.suggested_outcome, ""),
        )
          ? safeText(item.suggested_outcome, "")
          : "needs_more_evidence";

        if (!candidateId) {
          return null;
        }
        const evidence = evidenceByCandidateId.get(candidateId);
        const missingEvidence =
          (item.missing_evidence?.length ?? 0) > 0
            ? item.missing_evidence ?? []
            : evidence?.missing_evidence ?? [];
        const missingRequiredArtifactKinds =
          (item.missing_required_artifact_kinds?.length ?? 0) > 0
            ? item.missing_required_artifact_kinds ?? []
            : evidence?.missing_required_artifact_kinds ?? [];
        const learningEvidenceNeededReasons =
          (item.learning_evidence_needed_reasons?.length ?? 0) > 0
            ? item.learning_evidence_needed_reasons ?? []
            : evidence?.learning_evidence_needed_reasons ?? [];
        const evidenceReady =
          typeof item.evidence_ready === "boolean"
            ? item.evidence_ready
            : evidenceReadyIds.has(candidateId) &&
              missingEvidence.length === 0 &&
              missingRequiredArtifactKinds.length === 0;

        const action: StudioCandidateHunterExecutionLoop["learningReviewActions"][number] = {
          actionId: safeText(
            item.action_id,
            `candidate_hunter:learning_feedback:next_actions:${candidateId}`,
          ),
          allowedOutcomes: candidateHunterAllowedLearningOutcomes(item.allowed_outcomes),
          candidateId,
          evidenceReady,
          executionAllowed: false,
          learningEvidenceNeededReasons,
          learningWriteAllowed: false,
          missingEvidence,
          missingRequiredArtifactKinds,
          nextAction: `审核 ${candidateId} 并记录人工结果后，再更新后续排序。`,
          reportSubmissionAllowed: false,
          safetyGate: "human_review_required",
          sourceLoopId: safeText(
            item.source_loop_id,
            "candidate_hunter:bounded_execution_loop",
          ),
          suggestedOutcome,
          traceStatus: safeText(
            item.trace_status,
            safeText(evidence?.evidence_trace_status, "needs_evidence"),
          ),
          validationAllowed: false,
        };
        const learningSignalTemplate = toCandidateHunterLearningSignalTemplate(
          item.learning_signal_template,
        );
        if (learningSignalTemplate) {
          action.learningSignalTemplate = learningSignalTemplate;
        }
        return action;
      })
      .filter(
        (item): item is StudioCandidateHunterExecutionLoop["learningReviewActions"][number] =>
          item !== null,
      );
    if (actions.length > 0) {
      return actions;
    }
  }

  const target = loop?.learning_feedback_target;
  const candidateIds = Array.from(
    new Set(
      ((target?.candidate_ids?.length ?? 0) > 0
        ? target?.candidate_ids
        : loop?.next_candidate_actions?.map((action) => action.candidate_id)) ?? [],
    ),
  )
    .map((candidateId) => safeText(candidateId, "candidate"))
    .filter((candidateId) => candidateId.length > 0);
  const allowedOutcomes = candidateHunterAllowedLearningOutcomes(
    target?.allowed_outcomes,
  );
  const sourceLoopId = safeText(
    target?.source_loop_id,
    "candidate_hunter:bounded_execution_loop",
  );
  const targetId = safeText(
    target?.target_id,
    "candidate_hunter:learning_feedback:next_actions",
  );

  return candidateIds.map((candidateId) => {
    const evidence = evidenceByCandidateId.get(candidateId);
    const missingEvidence = evidence?.missing_evidence ?? [];
    const missingRequiredArtifactKinds =
      evidence?.missing_required_artifact_kinds ?? [];
    const learningEvidenceNeededReasons =
      evidence?.learning_evidence_needed_reasons ?? [];
    const suggestedOutcome =
      evidenceReadyIds.has(candidateId) &&
      missingEvidence.length === 0 &&
      missingRequiredArtifactKinds.length === 0
        ? "confirmed"
        : "needs_more_evidence";

    return {
      actionId: `${targetId}:${candidateId}`,
      allowedOutcomes,
      candidateId,
      evidenceReady:
        evidenceReadyIds.has(candidateId) &&
        missingEvidence.length === 0 &&
        missingRequiredArtifactKinds.length === 0,
      executionAllowed: false,
      learningEvidenceNeededReasons,
      learningWriteAllowed: false,
      missingEvidence,
      missingRequiredArtifactKinds,
      nextAction: `审核 ${candidateId} 并记录人工结果后，再更新后续排序。`,
      reportSubmissionAllowed: false,
      safetyGate: "human_review_required",
      sourceLoopId,
      suggestedOutcome,
      traceStatus: safeText(evidence?.evidence_trace_status, "needs_evidence"),
      validationAllowed: false,
    };
  });
}

function toCandidateHunterRefutationQueue(
  loop: StudioCandidateHunterExecutionLoopInput | undefined,
): StudioCandidateHunterExecutionLoop["refutationQueue"] {
  return (loop?.refutation_queue ?? [])
    .slice(0, 5)
    .map((item) => {
      const candidateId = safeText(item.candidate_id, "");
      if (!candidateId) {
        return null;
      }
      return {
        candidateId,
        executionAllowed: false,
        missingEvidence: item.missing_evidence ?? [],
        missingRequiredArtifactKinds: item.missing_required_artifact_kinds ?? [],
        nextAction: safeText(item.next_action, `使用本地证据反证 ${candidateId}。`),
        priorityScore: item.priority_score ?? 0,
        questions: safeReviewQuestions(item.questions),
        queueId: safeText(item.queue_id, `candidate_hunter:refutation:${candidateId}`),
        reportSubmissionAllowed: false,
        requiredEvidence: item.required_evidence ?? [],
        safetyGate: "review_only_no_execution",
        traceStatus: safeText(item.trace_status, "needs_evidence"),
        validationAllowed: false,
      };
    })
    .filter(
      (item): item is StudioCandidateHunterExecutionLoop["refutationQueue"][number] =>
        item !== null,
    );
}

function learnedEvidenceRequiredEvidence(reasons: string[]): string[] {
  const required = new Set<string>();
  for (const reason of reasons) {
    if (reason.includes("missing_evidence:independent_cross_check")) {
      required.add("independent_refutation_or_static_rule");
    }
    if (reason.includes("missing_required_artifact:policy")) {
      required.add("policy");
    }
  }
  return Array.from(required);
}

function toCandidateHunterRankedTopCandidates(
  loop: StudioCandidateHunterExecutionLoopInput | undefined,
): StudioCandidateHunterExecutionLoop["rankedTopCandidates"] {
  const evidenceByCandidateId = new Map(
    (loop?.candidate_evidence_matrix ?? []).map((item) => [
      safeText(item.candidate_id, ""),
      item,
    ]),
  );
  const provided = (loop?.ranked_top_candidates ?? [])
    .slice(0, 5)
    .map((item, index) => {
      const candidateId = safeText(item.candidate_id, "");
      if (!candidateId) {
        return null;
      }
      const evidence = evidenceByCandidateId.get(candidateId);
      const missingEvidence =
        (evidence?.missing_evidence?.length ?? 0) > 0
          ? evidence?.missing_evidence ?? []
          : item.missing_evidence ?? [];
      const missingRequiredArtifactKinds =
        (evidence?.missing_required_artifact_kinds?.length ?? 0) > 0
          ? evidence?.missing_required_artifact_kinds ?? []
          : item.missing_required_artifact_kinds ?? [];
      const traceStatus = safeText(
        evidence?.evidence_trace_status,
        safeText(item.trace_status, "needs_evidence"),
      );
      const evidenceReady = candidateHunterRankedEvidenceReady({
        qualityStatus: safeText(evidence?.quality_status, safeText(item.quality_status, "needs_review")),
        traceStatus,
        missingEvidence,
        missingRequiredArtifactKinds,
      });
      const phaseId = safeText(item.phase_id, "refutation");
      return {
        affectedCodePath: safeText(evidence?.affected_code_path, safeText(item.affected_code_path, "")),
        affectedEndpoint: safeText(evidence?.affected_endpoint, safeText(item.affected_endpoint, "")),
        candidateId,
        evidenceReady,
        executionAllowed: false,
        missingEvidence,
        missingRequiredArtifactKinds,
        phaseId,
        priorityScore: item.priority_score ?? 0,
        qualityStatus: evidenceReady ? "review_ready" : "needs_review",
        rank: item.rank ?? index + 1,
        rankingSignalBreakdown: evidence?.ranking_signal_breakdown ?? item.ranking_signal_breakdown ?? [],
        reason: candidateHunterRankedReason(safeText(item.reason, ""), {
          evidenceReady,
          missingEvidence,
          missingRequiredArtifactKinds,
        }),
        nextAction: safeText(item.next_action, "审查排名靠前的候选。"),
        requiredEvidence: item.required_evidence ?? [],
        reportSubmissionAllowed: false,
        safetyGate: evidenceReady
          ? safeRankedTopCandidateSafetyGate(item.safety_gate)
          : "review_only_no_execution",
        traceStatus,
        validationAllowed: false,
      };
    })
    .filter(
      (item): item is StudioCandidateHunterExecutionLoop["rankedTopCandidates"][number] =>
        item !== null,
    );
  if (provided.length > 0) {
    return rankCandidateHunterTopCandidates(provided);
  }

  const ranked = (loop?.next_candidate_actions ?? [])
    .slice(0, 5)
    .map((item, index) => {
      const candidateId = safeText(item.candidate_id, "");
      if (!candidateId) {
        return null;
      }
      const evidence = evidenceByCandidateId.get(candidateId);
      const missingEvidence = evidence?.missing_evidence ?? [];
      const missingRequiredArtifactKinds =
        evidence?.missing_required_artifact_kinds ?? [];
      const traceStatus = safeText(evidence?.evidence_trace_status, "needs_evidence");
      const evidenceReady = candidateHunterRankedEvidenceReady({
        qualityStatus: safeText(evidence?.quality_status, "needs_review"),
        traceStatus,
        missingEvidence,
        missingRequiredArtifactKinds,
      });
      const phaseId = safeText(item.phase_id, "refutation");
      return {
        affectedCodePath: safeText(evidence?.affected_code_path, ""),
        affectedEndpoint: safeText(evidence?.affected_endpoint, ""),
        candidateId,
        evidenceReady,
        executionAllowed: false,
        missingEvidence,
        missingRequiredArtifactKinds,
        phaseId,
        priorityScore: item.priority_score ?? 0,
        qualityStatus: evidenceReady ? "review_ready" : "needs_review",
        rank: index + 1,
        rankingSignalBreakdown: evidence?.ranking_signal_breakdown ?? [],
        reason: candidateHunterRankedReason(safeText(item.reason, ""), {
          evidenceReady,
          missingEvidence,
          missingRequiredArtifactKinds,
        }),
        nextAction: safeText(item.next_action, "审查排名靠前的候选。"),
        requiredEvidence: item.required_evidence ?? [],
        reportSubmissionAllowed: false,
        safetyGate: evidenceReady
          ? safeRankedTopCandidateSafetyGate(item.safety_gate)
          : "review_only_no_execution",
        traceStatus,
        validationAllowed: false,
      };
    })
    .filter(
      (item): item is StudioCandidateHunterExecutionLoop["rankedTopCandidates"][number] =>
        item !== null,
    );
  return rankCandidateHunterTopCandidates(ranked);
}

function candidateHunterRankedEvidenceReady({
  qualityStatus,
  traceStatus,
  missingEvidence,
  missingRequiredArtifactKinds,
}: {
  qualityStatus: string;
  traceStatus: string;
  missingEvidence: string[];
  missingRequiredArtifactKinds: string[];
}): boolean {
  return (
    qualityStatus === "review_ready" &&
    traceStatus === "traceable" &&
    missingEvidence.length === 0 &&
    missingRequiredArtifactKinds.length === 0
  );
}

function candidateHunterRankedReason(
  providedReason: string,
  {
    evidenceReady,
    missingEvidence,
    missingRequiredArtifactKinds,
  }: {
    evidenceReady: boolean;
    missingEvidence: string[];
    missingRequiredArtifactKinds: string[];
  },
): string {
  if (evidenceReady) {
    return providedReason || "review_ready";
  }
  if (providedReason.startsWith("missing_")) {
    return providedReason;
  }
  if (missingRequiredArtifactKinds.length > 0) {
    return "missing_required_evidence";
  }
  if (missingEvidence.length > 0) {
    return "missing_evidence";
  }
  return providedReason || "needs_review";
}

function rankCandidateHunterTopCandidates(
  items: StudioCandidateHunterExecutionLoop["rankedTopCandidates"],
): StudioCandidateHunterExecutionLoop["rankedTopCandidates"] {
  return [...items]
    .sort((left, right) => {
      if (left.evidenceReady !== right.evidenceReady) {
        return left.evidenceReady ? -1 : 1;
      }
      if (left.priorityScore !== right.priorityScore) {
        return right.priorityScore - left.priorityScore;
      }
      return left.candidateId.localeCompare(right.candidateId);
    })
    .slice(0, 5)
    .map((item, index) => ({ ...item, rank: index + 1 }));
}

function safeRankedTopCandidateSafetyGate(value: unknown): string {
  const gate = safeText(value, "review_only_no_execution");
  return [
    "authorized_artifacts_only",
    "local_static_analysis_only",
    "model_claims_unverified",
    "review_only_no_execution",
    "human_approval_required",
    "submission_blocked_human_review",
  ].includes(gate)
    ? gate
    : "review_only_no_execution";
}

function toCandidateHunterDeduplicationQueue(
  loop: StudioCandidateHunterExecutionLoopInput | undefined,
): StudioCandidateHunterExecutionLoop["deduplicationQueue"] {
  return (loop?.deduplication_queue ?? [])
    .slice(0, 5)
    .map((item) => {
      const candidateId = safeText(item.candidate_id, "");
      if (!candidateId) {
        return null;
      }
      return {
        affectedCodePath: safeText(item.affected_code_path, ""),
        affectedEndpoint: safeText(item.affected_endpoint, ""),
        candidateId,
        duplicateRiskScore: item.duplicate_risk_score ?? 0,
        executionAllowed: false,
        nextAction: safeText(item.next_action, `报告就绪前请对 ${candidateId} 去重。`),
        priorityScore: item.priority_score ?? 0,
        questions: safeReviewQuestions(item.questions),
        queueId: safeText(item.queue_id, `candidate_hunter:deduplication:${candidateId}`),
        reportSubmissionAllowed: false,
        requiredEvidence: item.required_evidence ?? [],
        safetyGate: "review_only_no_execution",
        similarityKeys: item.similarity_keys ?? [],
        validationAllowed: false,
      };
    })
    .filter(
      (item): item is StudioCandidateHunterExecutionLoop["deduplicationQueue"][number] =>
        item !== null,
    );
}

function toCandidateHunterSafeValidationQueue(
  loop: StudioCandidateHunterExecutionLoopInput | undefined,
): StudioCandidateHunterExecutionLoop["safeValidationQueue"] {
  return (loop?.safe_validation_queue ?? [])
    .slice(0, 5)
    .map((item) => {
      const candidateId = safeText(item.candidate_id, "");
      if (!candidateId) {
        return null;
      }
      return {
        affectedCodePath: safeText(item.affected_code_path, ""),
        affectedEndpoint: safeText(item.affected_endpoint, ""),
        candidateId,
        executionAllowed: false,
        nextAction: `审核并批准 ${candidateId} 的非破坏性验证计划；执行仍保持阻断。`,
        planSteps: safeValidationPlanSteps(item.plan_steps),
        priorityScore: item.priority_score ?? 0,
        queueId: safeText(item.queue_id, `candidate_hunter:safe_validation:${candidateId}`),
        reportSubmissionAllowed: false,
        requiredApprovals: [
          "scope_guard_route_approval",
          "human_validation_approval",
          "redaction_review",
        ],
        safetyGate: "human_approval_required",
        validationAllowed: false,
        validationExecutionAllowed: false,
        validationMode: "human_approved_non_destructive_plan",
      };
    })
    .filter(
      (item): item is StudioCandidateHunterExecutionLoop["safeValidationQueue"][number] =>
        item !== null,
    );
}

function toCandidateHunterReportDraftQueue(
  loop: StudioCandidateHunterExecutionLoopInput | undefined,
): StudioCandidateHunterExecutionLoop["reportDraftQueue"] {
  return (loop?.report_draft_queue ?? [])
    .slice(0, 5)
    .map((item) => {
      const candidateId = safeText(item.candidate_id, "");
      if (!candidateId) {
        return null;
      }
      return {
        affectedCodePath: safeText(item.affected_code_path, ""),
        affectedEndpoint: safeText(item.affected_endpoint, ""),
        candidateId,
        evidenceFocus: item.evidence_focus ?? [],
        executionAllowed: false,
        nextAction: `为 ${candidateId} 起草提交已阻断的报告，等待人工审核期间保持禁止提交。`,
        priorityScore: item.priority_score ?? 0,
        queueId: safeText(item.queue_id, `candidate_hunter:report_draft:${candidateId}`),
        redactionChecks: item.redaction_checks ?? [],
        reportStatus: "submission_blocked",
        reportSubmissionAllowed: false,
        requiredSections: safeReportSections(item.required_sections),
        safetyGate: "submission_blocked_human_review",
        validationAllowed: false,
      };
    })
    .filter(
      (item): item is StudioCandidateHunterExecutionLoop["reportDraftQueue"][number] =>
        item !== null,
    );
}

function candidateHunterAllowedLearningOutcomes(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return candidateHunterLearningOutcomes;
  }
  const outcomes = value.filter(
    (outcome): outcome is string =>
      typeof outcome === "string" && candidateHunterLearningOutcomes.includes(outcome),
  );
  return outcomes.length > 0 ? outcomes : candidateHunterLearningOutcomes;
}

function toCandidateHunterLearningSignalTemplate(value: unknown):
  | StudioCandidateHunterExecutionLoop["learningReviewActions"][number]["learningSignalTemplate"]
  | undefined {
  if (typeof value !== "object" || value === null) {
    return undefined;
  }
  const template = value as {
    playbook_id?: unknown;
    surface_key?: unknown;
    target_relationships?: unknown;
  };
  const playbookId = safeText(template.playbook_id, "");
  const surfaceKey = safeText(template.surface_key, "");
  if (!playbookId || !surfaceKey) {
    return undefined;
  }
  return {
    humanReviewRequired: true,
    learningWriteAllowed: false,
    playbookId,
    surfaceKey,
    targetRelationships: Array.isArray(template.target_relationships)
      ? template.target_relationships
          .map((item) => safeText(item, ""))
          .filter((item) => item.length > 0)
      : [],
  };
}

function safeExecutionPhaseGate(value: unknown): string {
  const gate = safeText(value, "review_only_no_execution");
  return [
    "authorized_artifacts_only",
    "local_static_analysis_only",
    "model_claims_unverified",
    "review_only_no_execution",
    "human_approval_required",
    "submission_blocked_human_review",
  ].includes(gate)
    ? gate
    : "review_only_no_execution";
}

function safeReviewQuestions(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter(
    (item): item is string =>
      typeof item === "string" &&
      item.trim().length > 0 &&
      !/live validation|execute|submit/i.test(item),
  );
}

function safeValidationPlanSteps(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter(
    (item): item is string =>
      typeof item === "string" &&
      item.trim().length > 0 &&
      !/execute|production|live validation/i.test(item),
  );
}

function safeReportSections(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter(
    (item): item is string =>
      typeof item === "string" &&
      item.trim().length > 0 &&
      !/raw|authorization|secret|token|cookie|credential/i.test(item),
  );
}

function safeText(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() ? value : fallback;
}

function safeCount(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? Math.round(value)
    : undefined;
}
