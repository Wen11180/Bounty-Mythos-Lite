import type { ArtifactRecord, PipelineRunDetail, ProgramIntelligenceProfile, ReportPreview } from "./api";
import { formatLabel } from "./workbench-display.ts";

export type CampaignControlCenter = {
  campaign: {
    allowed_tools: string[];
    autonomy_level: string;
    created_at: string;
    created_by: string;
    default_asset: string;
    id: string;
    name: string;
    program_id: string | null;
    scope_status: string;
    status: string;
    target_classes: string[];
  };
  budget: {
    campaign_id: string;
    created_at: string;
    id: string;
    status: string;
    time_budget_minutes: number;
    token_budget: number;
    tool_call_budget: number;
    tool_call_used?: number;
    tool_call_remaining?: number | null;
    validation_budget: number;
    validation_budget_used?: number;
    validation_budget_remaining?: number | null;
  } | null;
  tasks: {
    agent_type: string;
    campaign_id: string;
    created_at: string;
    id: string;
    input_refs: string[];
    output_refs: string[];
    status: string;
    task_type: string;
    title: string;
  }[];
  agent_runs: {
    agent_type: string;
    campaign_id: string | null;
    created_at: string;
    finished_at: string | null;
    id: string;
    input_refs: string[];
    output_refs: string[];
    safety_gate_state: string;
    status: string;
    stop_reason: string | null;
    task_id: string | null;
  }[];
  approvals: {
    actor: string;
    approval_type: string;
    asset: string | null;
    autonomy_level: string | null;
    campaign_id: string | null;
    created_at: string;
    decided_at: string | null;
    decided_by: string | null;
    decision_reason: string | null;
    expires_at: string | null;
    id: string;
    plan_digest: string | null;
    program_id: string | null;
    reason: string;
    requested_action: string | null;
    run_id: string | null;
    safety_gate_state: string;
    scope_reference: string | null;
    status: string;
    task_id: string | null;
    validation_mode: string | null;
  }[];
  validation_runs?: CampaignValidationRun[];
  pipeline_stages: {
    campaign_id: string | null;
    created_at: string;
    duration_seconds?: number | null;
    error_summary?: string | null;
    id: string;
    input_refs: string[];
    output_refs: string[];
    payload?: Record<string, unknown>;
    pipeline_run_id: string | null;
    safety_gate_state: string;
    stage_key: string;
    stage_order: number;
    status: string;
    stop_reason: string | null;
    task_id: string | null;
  }[];
  blocked_reasons: string[];
  execution_allowed: boolean;
  promotion_review?: CampaignPromotionReview;
  research_queue_suggestions?: {
    blocked_action_count?: number;
    candidate_status?: string | null;
    execution_allowed: boolean;
    human_approval_required?: boolean;
    next_allowed_action: string;
    playbook_id: string;
    priority_score: number;
    raw_priority_score?: number | null;
    quality_gate_reasons?: string[];
    evidence_needed?: string[];
    evidence_trace_summary?: CampaignEvidenceTraceSummaryRaw;
    report_readiness?: CampaignReportReadinessRaw;
    queue_key: string;
    refutation_question_count?: number;
    required_evidence?: string[];
    satisfied_evidence?: string[];
    safety_gate: string;
    source: string;
    surface_key: string | null;
    title: string;
    top_candidate_rank?: number | null;
    validation_step_count?: number;
  }[];
  research_review_plans?: CampaignResearchReviewPlan[];
  safe_next_action: string;
};

export type CampaignPromotionReview = {
  blocked_attempt_count: number;
  finding_promotion_allowed: boolean;
  latest_reason: string | null;
  next_allowed_action: string;
  provenance_ref_count: number;
  report_submission_allowed: false;
  required_evidence_blocked_count?: number;
  validation_feedback_review_count?: number;
};

export type CampaignResearchQueueSuggestion = {
  blockedActionCount: number;
  candidateStatus: string | null;
  evidenceTraceSummary: CampaignEvidenceTraceSummary;
  reportReadiness: CampaignReportReadiness;
  executionAllowed: boolean;
  humanApprovalRequired: boolean;
  nextAllowedAction: string;
  playbookId: string;
  priorityScore: number;
  rawPriorityScore: number | null;
  qualityGateReasons: string[];
  evidenceNeeded: string[];
  queueKey: string;
  refutationQuestionCount: number;
  requiredEvidence: string[];
  satisfiedEvidence: string[];
  safetyGate: string;
  source: string;
  surfaceKey: string | null;
  title: string;
  topCandidateRank: number | null;
  validationStepCount: number;
};

export type CampaignEvidenceTraceSummaryRaw = {
  artifact_kinds?: string[];
  report_submission_allowed?: boolean;
  route_fact_count?: number;
  source_fact_count?: number;
  source_fact_types?: string[];
  trace_status?: string;
  traceable_source_fact_count?: number;
};

export type CampaignEvidenceTraceSummary = {
  artifactKinds: string[];
  reportSubmissionAllowed: false;
  routeFactCount: number;
  sourceFactCount: number;
  sourceFactTypes: string[];
  traceStatus: string;
  traceableSourceFactCount: number;
};

export type CampaignReportReadinessRaw = {
  next_allowed_action?: string;
  report_submission_allowed?: boolean;
  required_evidence_count?: number;
  safe_validation_step_count?: number;
  status?: string;
  submission_blocked?: boolean;
  trace_status?: string;
};

export type CampaignReportReadiness = {
  nextAllowedAction: string;
  reportSubmissionAllowed: false;
  requiredEvidenceCount: number;
  safeValidationStepCount: number;
  status: string;
  submissionBlocked: true;
  traceStatus: string;
};

export type CampaignControlSummary = {
  agentRunCount: number;
  blockedReasons: string[];
  blockedStageCount: number;
  budgetLabel: string;
  campaignId: string;
  cycleReviewAwaitingCount: number;
  cycleReviewCompletedCount: number;
  defaultAsset: string;
  executionAllowed: boolean;
  name: string;
  pendingApprovalCount: number;
  promotionReviewBlockedCount: number;
  promotionReviewFindingPromotionAllowed: boolean;
  promotionReviewLatestReason: string | null;
  promotionReviewNextAllowedAction: string;
  promotionReviewProvenanceRefCount: number;
  promotionReviewRequiredEvidenceBlockedCount: number;
  promotionReviewReportSubmissionAllowed: boolean;
  promotionReviewValidationFeedbackReviewCount: number;
  researchQueueSuggestions: CampaignResearchQueueSuggestion[];
  safeNextAction: string;
  safeNextHref: string | null;
  scopeStatus: string;
  status: string;
  taskCount: number;
  validationEvidenceCount: number;
  validationEvidenceGapCount: number;
  validationRunCount: number;
};

export type CampaignAgentRun = CampaignControlCenter["agent_runs"][number];
export type CampaignApproval = CampaignControlCenter["approvals"][number];
export type CampaignPipelineStage = CampaignControlCenter["pipeline_stages"][number];
export type CampaignTask = CampaignControlCenter["tasks"][number];

export type CampaignAgentRunSummary = {
  agentType: string;
  finishedAt: string | null;
  id: string;
  inputRefCount: number;
  outputRefCount: number;
  safetyGateState: string;
  startedAt: string;
  status: string;
  stopReason: string | null;
  taskId: string | null;
};

export type CampaignTaskSummary = {
  agentType: string;
  createdAt: string;
  id: string;
  inputRefCount: number;
  outputRefCount: number;
  status: string;
  taskType: string;
  title: string;
};

export type CampaignResearchTaskReview = {
  autonomous_candidate_context: CampaignAutonomousCandidateContext | null;
  campaign_id: string;
  dispatch_allowed: boolean;
  execution_allowed: boolean;
  latest_refutation_decision: CampaignResearchRefutationDecision | null;
  latest_validation_feedback: CampaignResearchValidationFeedback | null;
  latest_review_plan: CampaignResearchReviewPlan | null;
  next_allowed_action: string;
  non_destructive_plan: string[];
  playbook_id: string | null;
  priority_score: number;
  queue_key: string;
  report_submission_allowed: boolean;
  required_human_gates: string[];
  safety_gate: string;
  source: string;
  status: string;
  suggested_refutation_decision?: CampaignSuggestedRefutationDecision | null;
  surface_key: string | null;
  task_id: string;
  title: string;
};

export type CampaignAutonomousCandidateContext = {
  blocked_actions: string[];
  candidate_id: string;
  candidate_status: string;
  dispatch_allowed: boolean;
  evidence_needed?: string[];
  evidence_trace_summary?: CampaignEvidenceTraceSummaryRaw;
  report_readiness?: CampaignReportReadinessRaw;
  evidence_focus?: string[];
  execution_allowed: boolean;
  human_approval_required: boolean;
  hypothesis: string;
  pipeline_run_id: string;
  raw_priority_score?: number | null;
  quality_gate_reasons?: string[];
  refutation_questions: string[];
  refutation_status: string;
  required_evidence?: string[];
  satisfied_evidence?: string[];
  report_submission_allowed: boolean;
  safety_notes: string[];
  source_fact_types?: string[];
  triage_signals?: string[];
  validation_allowed: boolean;
  validation_plan_status: string;
  validation_steps: string[];
};

export type CampaignResearchReviewPlan = {
  campaign_id: string;
  dispatch_allowed: boolean;
  evidence_plan: string[];
  execution_allowed: boolean;
  hypothesis: string;
  next_allowed_action: string;
  plan_id: string;
  refutation_questions: string[];
  report_submission_allowed: boolean;
  required_human_gates: string[];
  safety_gate: string;
  status: string;
  task_id: string;
  validation_allowed: boolean;
};

export type CampaignResearchRefutationDecision = {
  approval_id?: string | null;
  campaign_id: string;
  decision: string;
  decision_id: string;
  dispatch_allowed: boolean;
  execution_allowed: boolean;
  next_allowed_action: string;
  plan_id: string;
  rationale: string;
  refutation_answers: string[];
  report_submission_allowed: boolean;
  task_id: string;
  validation_allowed: boolean;
  validation_run_id?: string | null;
};

export type CampaignResearchValidationFeedback = {
  approval_id: string;
  campaign_id: string;
  decision_id: string;
  dispatch_allowed: boolean;
  evidence_ref_count: number;
  execution_allowed: boolean;
  feedback_stage_id?: string;
  finding_confirmation_allowed: boolean;
  next_allowed_action: string;
  outcome: string;
  plan_id: string;
  promotion_gate?: {
    evidence_ref_count: number;
    finding_promotion_allowed: boolean;
    next_allowed_action: string;
    provenance_refs: string[];
    reason: string;
    report_submission_allowed: boolean;
    status: string;
  } | null;
  report_submission_allowed: boolean;
  safety_gate: string;
  status: string;
  task_id: string;
  validation_allowed: boolean;
  validation_run_id: string;
};

export type CampaignResearchTaskReviewSummary = {
  autonomousCandidateContext: CampaignAutonomousCandidateContextSummary | null;
  campaignId: string;
  dispatchAllowed: boolean;
  executionAllowed: boolean;
  latestRefutationDecision: CampaignResearchRefutationDecisionSummary | null;
  suggestedRefutationDecision: CampaignSuggestedRefutationDecisionSummary | null;
  latestValidationFeedback: CampaignResearchValidationFeedbackSummary | null;
  latestReviewPlan: CampaignResearchReviewPlanSummary | null;
  nextAllowedAction: string;
  nonDestructivePlan: string[];
  playbookId: string | null;
  priorityScore: number;
  queueKey: string;
  reportSubmissionAllowed: boolean;
  requiredHumanGates: string[];
  safetyGate: string;
  source: string;
  status: string;
  surfaceKey: string | null;
  taskId: string;
  title: string;
};

export type CampaignAutonomousCandidateContextSummary = {
  blockedActions: string[];
  candidateId: string;
  candidateStatus: string;
  dispatchAllowed: boolean;
  evidenceNeeded: string[];
  evidenceTraceSummary: CampaignEvidenceTraceSummary;
  reportReadiness: CampaignReportReadiness;
  evidenceFocus: string[];
  executionAllowed: boolean;
  humanApprovalRequired: boolean;
  hypothesis: string;
  pipelineRunId: string;
  rawPriorityScore: number | null;
  qualityGateReasons: string[];
  refutationQuestions: string[];
  refutationStatus: string;
  requiredEvidence: string[];
  satisfiedEvidence: string[];
  reportSubmissionAllowed: boolean;
  safetyNotes: string[];
  sourceFactTypes: string[];
  triageSignals: string[];
  validationAllowed: boolean;
  validationPlanStatus: string;
  validationSteps: string[];
};

export type CampaignResearchReviewPlanSummary = {
  campaignId: string;
  dispatchAllowed: boolean;
  evidencePlan: string[];
  executionAllowed: boolean;
  hypothesis: string;
  nextAllowedAction: string;
  planId: string;
  refutationQuestions: string[];
  reportSubmissionAllowed: boolean;
  requiredHumanGates: string[];
  safetyGate: string;
  status: string;
  taskId: string;
  validationAllowed: boolean;
};

export type CampaignResearchRefutationDecisionSummary = {
  approvalId: string | null;
  campaignId: string;
  decision: string;
  decisionId: string;
  dispatchAllowed: boolean;
  executionAllowed: boolean;
  nextAllowedAction: string;
  planId: string;
  rationale: string;
  refutationAnswers: string[];
  reportSubmissionAllowed: boolean;
  taskId: string;
  validationAllowed: boolean;
  validationRunId: string | null;
};

export type CampaignSuggestedRefutationDecision = {
  decision: string;
  plan_id: string;
  rationale: string;
  refutation_answer_count: number;
  refutation_question_count: number;
  next_allowed_action: string;
  target_ref?: string | null;
  validation_mode?: string | null;
  human_review_required: boolean;
  execution_allowed: boolean;
  dispatch_allowed: boolean;
  validation_allowed: boolean;
  report_submission_allowed: boolean;
};

export type CampaignSuggestedRefutationDecisionSummary = {
  decision: string;
  planId: string;
  rationale: string;
  refutationAnswerCount: number;
  refutationQuestionCount: number;
  nextAllowedAction: string;
  targetRef: string | null;
  validationMode: string | null;
  humanReviewRequired: boolean;
  executionAllowed: boolean;
  dispatchAllowed: boolean;
  validationAllowed: boolean;
  reportSubmissionAllowed: boolean;
};

export type CampaignResearchValidationFeedbackSummary = {
  approvalId: string;
  campaignId: string;
  decisionId: string;
  dispatchAllowed: boolean;
  evidenceRefCount: number;
  executionAllowed: boolean;
  feedbackStageId: string;
  findingConfirmationAllowed: boolean;
  nextAllowedAction: string;
  outcome: string;
  planId: string;
  reportSubmissionAllowed: boolean;
  safetyGate: string;
  status: string;
  taskId: string;
  validationAllowed: boolean;
  validationRunId: string;
};

export type CampaignResearchFeedbackEvidenceSummary = {
  approvalId: string;
  evidenceRefCount: number;
  feedbackStageId: string;
  findingPromotionAllowed: boolean;
  nextAllowedAction: string;
  outcome: string;
  planId: string;
  promotionGate: string;
  promotionGateReason: string;
  promotionProvenanceRefCount: number;
  reviewTitle: string;
  safetyGate: string;
  status: string;
  taskId: string;
  validationRunId: string;
};

export type CampaignPromotionBlockReviewSummary = {
  approvalId: string;
  evidenceRefCount: number;
  feedbackStageId: string;
  nextAllowedAction: string;
  planId: string;
  promotionGateReason: string;
  promotionProvenanceRefCount: number;
  reviewTitle: string;
  taskId: string;
  validationRunId: string;
};

export type CampaignValidationEvidenceReviewSummary = {
  candidateEvidenceState: string;
  evidenceRefCount: number;
  manualValidationReview?: CampaignValidationEvidenceManualReviewSummary;
  nextReviewAction: string;
  planDigest: string | null;
  preflightState: string;
  reportChainState: string;
  reviewGate: string;
  reviewItem: string;
  status: string;
  summary: string;
  targetRef: string;
  validationMode: string;
  validationRunId: string;
};

export type CampaignValidationEvidenceManualReviewSummary = {
  evidenceQuality: string;
  promotionReviewState: string;
  qualityReasons: string[];
  qualityScore: number;
  redactionStatus: string;
  safeEvidenceRefCount: number;
  sourceType: string;
  unsafeEvidenceRefCount: number;
};

export type CampaignValidationEvidenceQualitySummary = {
  cleanReviewCount: number;
  gatedPromotionReviewCount: number;
  redactedReviewCount: number;
  reviewedEvidenceCount: number;
  strongEvidenceCount: number;
  unsafeEvidenceRefCount: number;
};

export type CampaignArtifactSummary = {
  asset: string;
  createdAt: string;
  id: string;
  ingestionStatus: string;
  kind: string;
  reportChainAllowed: boolean;
  safetyBlockerCount: number;
  sensitivityLabel: string;
  sourceType: string;
  usageCount: number;
  usageStages: CountSummary[];
  usageTypes: CountSummary[];
};

export type CountSummary = {
  count: number;
  label: string;
};

export type CampaignValidationQueueSummary = {
  approvalType: string;
  asset: string | null;
  createdAt: string;
  expiresAt: string | null;
  id: string;
  nextAction: string;
  planDigest: string | null;
  reason: string;
  requestedAction: string | null;
  runId: string | null;
  safetyGateState: string;
  status: string;
  taskId: string | null;
  validationMode: string | null;
};

export type CampaignValidationRun = {
  allowed_to_execute: boolean;
  approval_id: string | null;
  approval_required: boolean;
  campaign_id: string;
  created_at: string;
  evidence_ref_count: number;
  execution_started?: boolean;
  finished_at?: string | null;
  id: string;
  plan_digest: string | null;
  preflight_passed?: boolean;
  safety_gate_state: string;
  status: string;
  summary: string;
  target_ref: string;
  task_id: string | null;
  validation_mode: string;
};

export type CampaignValidationRunSummary = {
  allowedToExecute: boolean;
  approvalId: string | null;
  approvalRequired: boolean;
  attentionState: string;
  createdAt: string;
  evidenceRefCount: number;
  executionStarted: boolean;
  executionState: string;
  finishedAt: string | null;
  id: string;
  nextAction: string;
  planDigest: string | null;
  preflightPassed: boolean;
  safetyGateState: string;
  status: string;
  summary: string;
  targetRef: string;
  taskId: string | null;
  validationMode: string;
};

export type CampaignTimelineSummary = {
  approvalCreated?: boolean;
  auditLabel: string;
  blockedActionCount?: number;
  candidateStatus?: string;
  decision?: string;
  durationSeconds?: number;
  evidenceFocusCount?: number;
  evidenceStepCount?: number;
  executionAllowed?: boolean;
  errorSummary?: string;
  findingConfirmationAllowed?: boolean;
  hasAuthorizationGapCandidate?: boolean;
  hunterOperatingAction?: string;
  humanApprovalRequired?: boolean;
  id: string;
  inputRefCount: number;
  isCycleReview: boolean;
  isFindingPromotion?: boolean;
  isFindingPromotionBlocked?: boolean;
  isLearningOutcome: boolean;
  isManualValidationResult: boolean;
  isResearchPlan?: boolean;
  isResearchRefutationDecision?: boolean;
  isResearchQueueMaterialized?: boolean;
  isResearchValidationFeedback?: boolean;
  isValidationFeedbackReview?: boolean;
  llmAuditMode?: string;
  llmAuditPromptHash?: string;
  llmAuditPromptTextStored?: boolean;
  manualValidationReview?: {
    evidenceQuality: string;
    promotionReviewReady: boolean;
    qualityReasons: string[];
    qualityScore: number;
    redactionStatus: string;
    safeEvidenceRefCount: number;
    sourceType: string;
    unsafeEvidenceRefCount: number;
  };
  outputRefCount: number;
  priorityReasonCount?: number;
  promotionProvenanceRefCount?: number;
  refutationAnswerCount?: number;
  refutationQuestionCount?: number;
  requiredEvidence?: string[];
  reportSubmissionAllowed?: boolean;
  reviewEvidenceRefCount?: number;
  safetyGateState: string;
  sourceFactTypeCount?: number;
  stageKey: string;
  stageOrder: number;
  status: string;
  stopReason: string | null;
  taskId: string | null;
  triageSignalCount?: number;
  validationAllowed?: boolean;
  validationStepCount?: number;
  validationRunCreated?: boolean;
};

export type CampaignBrainSurfaceSummary = {
  action: string;
  objectName: string;
  path: string;
  score: number;
  surfaceKey: string;
};

export type CampaignBrainSignalSummary = {
  evidenceQuality: string | null;
  id: string;
  notes: string;
  outcome: string;
  playbookId: string;
  surfaceKey: string | null;
};

export type CampaignBrainLessonSummary = {
  confidence: number;
  id: string;
  recommendation: string;
  reasons: string[];
  scoreDelta: number;
  surfacePattern: string;
};

export type CampaignBrainReasoningMemorySummary = {
  highestReasoningReviewScore: number;
  learningSignalContextCount: number;
  candidateContextCount: number;
  topPlaybooks: {
    candidateContextCount: number;
    highestReasoningReviewScore: number;
    learningSignalContextCount: number;
    playbookId: string;
  }[];
  safetyNotes: string[];
};

export type CampaignBrainSummary = {
  advisoryOnly: boolean;
  appliedLessonCount: number;
  appliedLessons: CampaignBrainLessonSummary[];
  executionAllowed: boolean;
  objectCount: number;
  programId: string;
  programName: string;
  programScore: number;
  recentSignals: CampaignBrainSignalSummary[];
  roleCount: number;
  reasoningMemory: CampaignBrainReasoningMemorySummary;
  sensitiveActionCount: number;
  signalCount: number;
  skippedLessonCount: number;
  topSurfaces: CampaignBrainSurfaceSummary[];
};

export type CampaignLearningReviewSummary = {
  advisoryOnly: boolean;
  appliedLessonCount: number;
  executionAllowed: boolean;
  linkedRunCount: number;
  recentSignalCount: number;
  reviewReady: boolean;
  safeNextAction: string;
  skippedLessonCount: number;
  strongEvidenceSignalCount: number;
};

export type CampaignCodebaseMap = {
  maps: {
    authz_check_count: number;
    campaign_id: string;
    commit_ref: string | null;
    created_at: string;
    handler_count: number;
    id: string;
    model_count: number;
    provenance_refs: string[];
    repository: string;
    route_count: number;
    safety_gate_state: string;
    sensitive_sink_count: number;
    source_ref: string;
    status: string;
  }[];
  facts: {
    authz_hint: string | null;
    campaign_id: string;
    codebase_map_id: string;
    created_at: string;
    fact_type: string;
    id: string;
    provenance_refs: string[];
    route_method: string | null;
    route_path: string | null;
    sensitivity_label: string;
    source_path: string;
    symbol_name: string | null;
  }[];
  scanner_runs: {
    campaign_id: string;
    candidate_count: number;
    codebase_map_id: string | null;
    command_hash: string;
    created_at: string;
    finding_count: number;
    id: string;
    safety_gate_state: string;
    status: string;
    summary: string;
    tool_name: string;
  }[];
};

export type CampaignCodebaseMapItemSummary = {
  authzCheckCount: number;
  commitRef: string | null;
  createdAt: string;
  handlerCount: number;
  id: string;
  modelCount: number;
  repository: string;
  routeCount: number;
  safetyGateState: string;
  sensitiveSinkCount: number;
  sourceRef: string;
  status: string;
};

export type CampaignCodebaseFactSummary = {
  authzHint: string | null;
  factType: string;
  id: string;
  route: string | null;
  sensitivityLabel: string;
  sourcePath: string;
  symbolName: string | null;
};

export type CampaignScannerRunSummary = {
  candidateCount: number;
  commandHash: string;
  findingCount: number;
  id: string;
  safetyGateState: string;
  status: string;
  summary: string;
  toolName: string;
};

export type CampaignCodebaseMapView = {
  authorizationGapCandidateCount: number;
  authzCheckCount: number;
  candidateCount: number;
  factCount: number;
  mapCount: number;
  maps: CampaignCodebaseMapItemSummary[];
  routeCount: number;
  scannerRunCount: number;
  scannerRuns: CampaignScannerRunSummary[];
  sensitiveSinkCount: number;
  facts: CampaignCodebaseFactSummary[];
};

export type CampaignEvidenceReviewSummary = {
  claimId: string;
  claimText: string;
  claimType: string;
  evidenceRefCount: number;
  humanReviewRequired: boolean;
  provenanceRefCount: number;
  qualityScore: number;
  readinessBlockers: string[];
  readinessLevel: string;
  redactionStatus: string;
  reportChainEligible: boolean;
  reviewEvidenceRefCount: number;
  reviewRationale: string | null;
  reviewStatus: string;
  runId: string;
  status: string;
};

export type CampaignReportDraftSummary = {
  blockedClaimCount: number;
  claimCount: number;
  evidenceRefCount: number;
  humanReviewRequired: boolean;
  readyClaimCount: number;
  runId: string;
  safetyNotes: string[];
  scopeStatus: string;
  severity: string;
  submissionBlocked: boolean;
  title: string;
  topClaims: string[];
};

export type CampaignReportDraftEvidenceSummary = {
  evidenceGapCount: number;
  evidenceRefCount: number;
  manualEvidenceCount: number;
  validationRunCount: number;
};

export type CampaignFindingCandidateGateSummary = {
  blockedClaimCount: number;
  eligibleClaimCount: number;
  manualPromotionOnly: boolean;
  nextAllowedAction: string;
  promotionAuditBlockedCount: number;
  promotionAuditCreatedCount: number;
  promotionAuditLatestReason: string | null;
  promotionAuditProvenanceRefCount: number;
  promotionAuditReviewEvidenceRefCount: number;
  requiredEvidenceBlockedCount: number;
  researchEvidenceRefCount: number;
  researchFeedbackCount: number;
  researchPromotionBlockedCount: number;
  readyRunIds: string[];
  runCount: number;
  status: string;
};

export type CampaignHypothesisBoardSummary = {
  brokenInvariant: string | null;
  candidateId: string;
  candidateStatus: string;
  chainConfidence: number | null;
  chainImpact: string | null;
  duplicateRiskScore: number;
  evidenceFocusCount: number;
  evidenceFocus: string[];
  evidenceNeededCount: number;
  hunterPriorityScore: number;
  hypothesis: string;
  impactScore: number;
  nextAction: string | null;
  playbook: string;
  policyRisk: string | null;
  policyRiskScore: number;
  preconditionCount: number;
  preconditions: string[];
  priorityReasons: string[];
  primitiveCount: number;
  primitives: string[];
  reasons: string[];
  recommendation: string;
  refutationQuestionCount: number;
  refutationQuestions: string[];
  refutationStatus: string | null;
  reviewPriorityScore: number;
  riskLevel: string | null;
  runId: string;
  source: string;
  sourceFactTypes: string[];
  researchQueueHandoff: CampaignHypothesisResearchQueueHandoff | null;
  triageSignals: string[];
  validationMode: string | null;
};

export type CampaignHypothesisResearchQueueHandoff = {
  blockedActionCount: number;
  evidenceNeeded: string[];
  executionAllowed: boolean;
  humanApprovalRequired: boolean;
  nextAllowedAction: string;
  queueKey: string;
  refutationQuestionCount: number;
  requiredEvidence: string[];
  reviewHref: string;
  safetyGate: string;
  title: string;
  topCandidateRank: number | null;
  validationStepCount: number;
};

export type CampaignAttackSurfaceEndpointSummary = {
  route: string;
  runId: string;
  summary: string | null;
};

export type CampaignAttackSurfaceObjectSummary = {
  identifierCount: number;
  name: string;
  runId: string;
};

export type CampaignAttackSurfaceSensitiveActionSummary = {
  action: string;
  roleCount: number;
  route: string;
  runId: string;
};

export type CampaignAttackSurfaceRelationshipSummary = {
  pathCount: number;
  relationship: string;
  runId: string;
  summary: string;
};

export type CampaignAttackSurfaceMapView = {
  endpointCount: number;
  endpoints: CampaignAttackSurfaceEndpointSummary[];
  objectCount: number;
  objects: CampaignAttackSurfaceObjectSummary[];
  relationshipCount: number;
  relationships: CampaignAttackSurfaceRelationshipSummary[];
  roleCount: number;
  roles: string[];
  runCount: number;
  sensitiveActionCount: number;
  sensitiveActions: CampaignAttackSurfaceSensitiveActionSummary[];
};

function humanize(value: string): string {
  return formatLabel(value);
}

function stripUrlQuery(value: string): string {
  try {
    const url = new URL(value);
    url.search = "";
    url.hash = "";

    return url.toString().replace(/^https?:\/\//, "").replace(/\/$/, "");
  } catch {
    return value.split(/[?#]/, 1)[0];
  }
}

function safeText(value: string | null | undefined, fallback: string): string {
  const text = typeof value === "string" ? value.trim() : "";

  if (!text) {
    return formatLabel(fallback);
  }

  if (containsRestrictedDisplayText(text)) {
    return formatLabel(fallback);
  }

  const protectedValues: string[] = [];
  const protect = (value: string) => {
    protectedValues.push(value);
    return `__SAFE_REDACTION_${protectedValues.length - 1}__`;
  };

  return stripUrlQuery(text)
    .replace(
      /\bauthorization\b\s*[:=]\s*(?:bearer\s+)?[^,;\s]+/gi,
      () => protect("Authorization=[已脱敏]"),
    )
    .replace(
      /\b(session|token|cookie)\b\s*[:=]\s*[^,;\s]+/gi,
      (match, key: string) => protect(`${key}=[已脱敏]`),
    )
    .replace(/\bbearer\s+[^,;\s]+/gi, () => protect("Bearer [已脱敏]"))
    .replace(/\b[^\s,;]*(?:secret|token|cookie|session)[^\s,;]*\b/gi, "[已脱敏]")
    .replace(/__SAFE_REDACTION_(\d+)__/g, (_, index: string) => protectedValues[Number(index)] ?? "[已脱敏]");
}

function safeReasonText(value: string): string {
  if (containsRestrictedDisplayText(value) || containsSecretTokenText(value)) {
    return "[已脱敏]";
  }

  const isIdentifier = /^[a-z][a-z0-9]*(?:[_-][a-z0-9]+)*$/i.test(value.trim());
  return safeText(isIdentifier ? humanize(value) : value, "原因");
}

function containsRestrictedDisplayText(value: string): boolean {
  return (
    /\b(scanner stdout|policy text|raw payload|raw evidence)\b/i.test(value)
    || containsSensitiveIdentityText(value)
  );
}

function containsSecretTokenText(value: string): boolean {
  return (
    /\b(authorization|bearer|cookie|session|secret|token)\b/i.test(value)
    || containsSensitiveIdentityText(value)
  );
}

function containsSensitiveIdentityText(value: string): boolean {
  return (
    /\b(api[_-]?key|password|credential)\b/i.test(value)
    || /\b(real user data|customer data|production user|live user|personal data|pii)\b/i.test(value)
    || /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(value)
    || /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/.test(value)
  );
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function stringList(value: unknown): string[] {
  return asArray(value).filter((item): item is string => typeof item === "string" && item.trim().length > 0);
}

function safeCount(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) && value >= 0
    ? Math.round(value)
    : undefined;
}

function safeCountOrListLength(countValue: unknown, listValue: unknown): number | undefined {
  const count = safeCount(countValue);
  if (count !== undefined) {
    return count;
  }
  if (Array.isArray(listValue)) {
    return stringList(listValue).length;
  }
  return undefined;
}

function percentScore(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return null;
  }

  const normalized = value >= 0 && value <= 1 ? value * 100 : value;

  return Math.max(0, Math.min(100, Math.round(normalized)));
}

function reviewPriorityScore(
  hunterPriorityScore: number,
  primitiveCount: number,
  preconditionCount: number,
  refutationQuestionCount: number,
): number {
  return Math.max(
    0,
    Math.min(
      100,
      hunterPriorityScore
      + primitiveCount * 2
      + preconditionCount
      + refutationQuestionCount * 2,
    ),
  );
}

function routeLabel(method: unknown, path: unknown): string {
  return safeText(
    [stringValue(method), stringValue(path)].filter((part): part is string => Boolean(part)).join(" "),
    "路由",
  );
}

function budgetPart(value: number | null | undefined, suffix: string): string | null {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return null;
  }

  return `${value}${suffix}`;
}

function toolCallBudgetPart(budget: CampaignControlCenter["budget"]): string | null {
  if (!budget) {
    return null;
  }

  const limit = budget.tool_call_budget;
  const used = budget.tool_call_used;
  const remaining = budget.tool_call_remaining;
  if (typeof limit !== "number" || !Number.isFinite(limit)) {
    return null;
  }
  if (typeof used !== "number" || !Number.isFinite(used)) {
    return budgetPart(limit, " 次工具调用");
  }

  const remainingLabel =
    typeof remaining === "number" && Number.isFinite(remaining)
      ? `，剩余 ${remaining}`
      : "";
  return `${used}/${limit} 次工具调用${remainingLabel}`;
}

function validationBudgetPart(budget: CampaignControlCenter["budget"]): string | null {
  if (!budget) {
    return null;
  }

  const limit = budget.validation_budget;
  const used = budget.validation_budget_used;
  const remaining = budget.validation_budget_remaining;
  if (typeof limit !== "number" || !Number.isFinite(limit)) {
    return null;
  }
  if (typeof used !== "number" || !Number.isFinite(used)) {
    return budgetPart(limit, " 次验证");
  }

  const remainingLabel =
    typeof remaining === "number" && Number.isFinite(remaining)
      ? `，剩余 ${remaining}`
      : "";
  return `${used}/${limit} 次验证${remainingLabel}`;
}

export function campaignBudgetLabel(
  budget: CampaignControlCenter["budget"] | undefined,
): string {
  if (!budget) {
    return "未配置预算";
  }

  return (
    [
      budgetPart(budget.time_budget_minutes, " 分钟"),
      budgetPart(budget.token_budget, " 个令牌"),
      toolCallBudgetPart(budget),
      validationBudgetPart(budget),
    ]
      .filter((part): part is string => Boolean(part))
      .join(" / ") || humanize(budget.status)
  );
}

function budgetLabel(controlCenter: CampaignControlCenter): string {
  return campaignBudgetLabel(controlCenter.budget);
}

function safeNextHref(campaignId: string, action: string): string | null {
  const encodedCampaignId = encodeURIComponent(campaignId);
  const routeByAction: Record<string, string> = {
    complete_cycle_review: "timeline",
    dispatch_ready_tasks: "tasks",
    monitor_agent_runs: "agent-runs",
    resolve_blockers: "",
    review_approval_queue: "validation-queue",
    review_attack_surface_map: "attack-surface-map",
    review_blocked_promotion: "evidence-review",
    review_campaign_cycle: "timeline",
    review_evidence_or_report_drafts: "evidence-review",
    review_hypothesis_board: "hypothesis-board",
    review_learning_outcome: "brain",
    review_ready_tasks: "tasks",
    review_validation_queue: "validation-runs",
    record_validation_observation: "validation-runs",
    promote_finding_candidate: "report-drafts",
    record_learning_outcome: "report-drafts",
  };
  const route = routeByAction[action];

  if (route === "") {
    return `/campaigns/${encodedCampaignId}`;
  }
  return route ? `/campaigns/${encodedCampaignId}/${route}` : null;
}

function safeNextActionLabel(action: string): string {
  const labelByAction: Record<string, string> = {
    complete_cycle_review: "审核活动周期",
    dispatch_ready_tasks: "审核研究任务",
    execute_validation: "审核验证审计",
    monitor_agent_runs: "审核智能体运行",
    review_approval_queue: "审核门请求",
    review_attack_surface_map: "审核攻击面映射",
    review_blocked_promotion: "审核被阻断的晋级证据",
    review_campaign_cycle: "审核活动周期",
    review_evidence_or_report_drafts: "审核证据或报告草稿",
    review_hypothesis_board: "审核假设看板",
    review_learning_outcome: "审核学习结果",
    review_ready_tasks: "审核研究任务",
    review_validation_queue: "审核验证审计",
    record_validation_observation: "审核人工验证观察",
    promote_finding_candidate: "晋级漏洞候选",
    record_learning_outcome: "审核学习结果",
    resolve_blockers: "处理阻断项",
    submit_report: "审核报告草稿",
  };

  return labelByAction[action] ?? "审核活动状态";
}

function reviewGateLanguage(text: string): string {
  return text
    .replace(
      /\bprepare a human-approved validation plan without executing it\.?/gi,
      "准备经人工审核的验证计划，不执行验证。",
    )
    .replace(
      /\breview hypothesis board and request approval before validation\.?/gi,
      "验证前请审核假设看板并请求审核。",
    )
    .replace(/\bconfirmed observed fact\b/gi, "已确认的观察事实")
    .replace(/\bawaiting human review\b/gi, "等待人工审核")
    .replace(/\bcampaign cycle review required\b/gi, "需要审核活动周期")
    .replace(/\brequired evidence missing\b/gi, "缺少必需证据")
    .replace(/\bresearch task review plan\b/gi, "研究任务审核计划")
    .replace(/\bresearch validation feedback is advisory\b/gi, "研究验证反馈仅作建议性参考")
    .replace(/\bconfirmed\b/gi, "已人工审核")
    .replace(/\bhuman-approved\b/gi, "已人工审核")
    .replace(/\bhuman approval\b/gi, "人工审核")
    .replace(/\bapproval required\b/gi, "需要审核")
    .replace(/\bawaiting approval\b/gi, "等待审核门")
    .replace(/\bauthorization check\b/gi, "审核检查")
    .replace(/\bneeds approval\b/gi, "需要审核")
    .replace(/\brequires approval\b/gi, "需要审核")
    .replace(/\brequest approval\b/gi, "请求审核");
}

function safetyGateDecisionLabel(state: string): string {
  const normalized = state.trim().toLowerCase();
  const labelByState: Record<string, string> = {
    allowed: "范围守卫已审核",
    blocked: "范围守卫已阻断",
    needs_review: "范围守卫需要审核",
    requested: "已请求审核门",
  };

  return labelByState[normalized] ?? safeText(humanize(state), "未知审核门");
}

export function toCampaignControlSummary(
  controlCenter: CampaignControlCenter,
): CampaignControlSummary {
  const campaignId = safeText(controlCenter.campaign.id, "活动");
  const validationEvidence = toCampaignReportDraftEvidenceSummary(controlCenter.validation_runs ?? []);
  const cycleReviewStages = controlCenter.pipeline_stages.filter(
    (stage) => stage.stage_key === "campaign_cycle_review",
  );
  const now = Date.now();

  return {
    agentRunCount: controlCenter.agent_runs.length,
    blockedReasons: controlCenter.blocked_reasons.map((reason) =>
      reviewGateLanguage(safeText(humanize(reason), "已阻断")),
    ),
    blockedStageCount: controlCenter.pipeline_stages.filter((stage) => stage.status === "blocked")
      .length,
    budgetLabel: budgetLabel(controlCenter),
    campaignId,
    cycleReviewAwaitingCount: cycleReviewStages.filter((stage) => stage.status === "awaiting_review")
      .length,
    cycleReviewCompletedCount: cycleReviewStages.filter((stage) => stage.status === "completed")
      .length,
    defaultAsset: safeText(controlCenter.campaign.default_asset, "未知资产"),
    executionAllowed: controlCenter.execution_allowed === true,
    name: safeText(controlCenter.campaign.name, "未命名活动"),
    pendingApprovalCount: controlCenter.approvals.filter((approval) =>
      ["pending", "requested"].includes(approval.status)
      && (approval.expires_at === null || Date.parse(approval.expires_at) > now),
    ).length,
    promotionReviewBlockedCount: Math.max(
      0,
      Math.round(controlCenter.promotion_review?.blocked_attempt_count ?? 0),
    ),
    promotionReviewFindingPromotionAllowed:
      controlCenter.promotion_review?.finding_promotion_allowed === true,
    promotionReviewLatestReason: controlCenter.promotion_review?.latest_reason
      ? safeText(humanize(controlCenter.promotion_review.latest_reason), "漏洞候选晋级已阻断")
      : null,
    promotionReviewNextAllowedAction: safeText(
      controlCenter.promotion_review?.next_allowed_action,
      "晋级漏洞候选前，请审核声明证据和人工审核门。",
    ),
    promotionReviewProvenanceRefCount: Math.max(
      0,
      Math.round(controlCenter.promotion_review?.provenance_ref_count ?? 0),
    ),
    promotionReviewRequiredEvidenceBlockedCount: Math.max(
      0,
      Math.round(controlCenter.promotion_review?.required_evidence_blocked_count ?? 0),
    ),
    promotionReviewReportSubmissionAllowed: false,
    promotionReviewValidationFeedbackReviewCount: Math.max(
      0,
      Math.round(controlCenter.promotion_review?.validation_feedback_review_count ?? 0),
    ),
    researchQueueSuggestions: (controlCenter.research_queue_suggestions ?? []).map((suggestion) => ({
      blockedActionCount: Math.max(0, Math.round(suggestion.blocked_action_count ?? 0)),
      candidateStatus: suggestion.candidate_status
        ? safeText(humanize(suggestion.candidate_status), "候选项")
        : null,
      executionAllowed: false,
      humanApprovalRequired: suggestion.human_approval_required !== false,
      nextAllowedAction: safeText(
        suggestion.next_allowed_action,
        "审核假设看板并规划非破坏性证据工作。",
      ),
      playbookId: safeText(suggestion.playbook_id, "研究手册"),
      priorityScore: Math.max(0, Math.min(100, Math.round(suggestion.priority_score))),
      rawPriorityScore: percentScore(suggestion.raw_priority_score),
      qualityGateReasons: safeLabelList(suggestion.quality_gate_reasons ?? [], 5),
      evidenceNeeded: safeLabelList(suggestion.evidence_needed ?? [], 5),
      evidenceTraceSummary: safeEvidenceTraceSummary(suggestion.evidence_trace_summary),
      reportReadiness: safeReportReadiness(suggestion.report_readiness),
      queueKey: safeText(suggestion.queue_key, "推理记忆"),
      refutationQuestionCount: Math.max(0, Math.round(suggestion.refutation_question_count ?? 0)),
      requiredEvidence: safeLabelList(suggestion.required_evidence ?? [], 5),
      satisfiedEvidence: safeLabelList(suggestion.satisfied_evidence ?? [], 5),
      safetyGate: safeText(humanize(suggestion.safety_gate), "仅作建议性记忆"),
      source: safeText(humanize(suggestion.source), "研究大脑推理记忆"),
      surfaceKey: suggestion.surface_key ? safeText(suggestion.surface_key, "攻击面") : null,
      title: safeText(suggestion.title, "审核推理记忆"),
      topCandidateRank: safeTopCandidateRank(suggestion.top_candidate_rank),
      validationStepCount: Math.max(0, Math.round(suggestion.validation_step_count ?? 0)),
    })),
    safeNextAction: safeNextActionLabel(controlCenter.safe_next_action),
    safeNextHref: safeNextHref(campaignId, controlCenter.safe_next_action),
    scopeStatus: safeText(humanize(controlCenter.campaign.scope_status), "未知范围"),
    status: safeText(humanize(controlCenter.campaign.status), "未知状态"),
    taskCount: controlCenter.tasks.length,
    validationEvidenceCount: validationEvidence.manualEvidenceCount,
    validationEvidenceGapCount: validationEvidence.evidenceGapCount,
    validationRunCount: validationEvidence.validationRunCount,
  };
}

export function resolveCampaignControlSummaries(
  controls: CampaignControlCenter[],
): CampaignControlSummary[] {
  return controls.map((control) => toCampaignControlSummary(control));
}

export function toCampaignAgentRunSummaries(
  runs: CampaignAgentRun[],
): CampaignAgentRunSummary[] {
  return runs.map((run) => ({
    agentType: safeText(humanize(run.agent_type), "智能体"),
    finishedAt: run.finished_at,
    id: safeText(run.id, "智能体运行"),
    inputRefCount: run.input_refs.length,
    outputRefCount: run.output_refs.length,
    safetyGateState: reviewGateLanguage(safetyGateDecisionLabel(run.safety_gate_state)),
    startedAt: run.created_at,
    status: safeText(humanize(run.status), "未知状态"),
    stopReason: run.stop_reason
      ? reviewGateLanguage(safeText(humanize(run.stop_reason), "已停止"))
      : null,
    taskId: run.task_id ? safeText(run.task_id, "任务") : null,
  }));
}

export function toCampaignTaskSummaries(
  tasks: CampaignTask[],
): CampaignTaskSummary[] {
  return tasks.map((task) => ({
    agentType: safeText(humanize(task.agent_type), "智能体"),
    createdAt: task.created_at,
    id: safeText(task.id, "任务"),
    inputRefCount: task.input_refs.length,
    outputRefCount: task.output_refs.length,
    status: safeText(humanize(task.status), "未知状态"),
    taskType: safeText(humanize(task.task_type), "任务"),
    title: safeText(task.title, "未命名任务"),
  }));
}

export function toCampaignResearchTaskReviewSummary(
  review: CampaignResearchTaskReview,
): CampaignResearchTaskReviewSummary {
  return {
    autonomousCandidateContext: review.autonomous_candidate_context
      ? toCampaignAutonomousCandidateContextSummary(review.autonomous_candidate_context)
      : null,
    campaignId: safeText(review.campaign_id, "活动"),
    dispatchAllowed: false,
    executionAllowed: false,
    latestReviewPlan: review.latest_review_plan
      ? toCampaignResearchReviewPlanSummary(review.latest_review_plan)
      : null,
    latestRefutationDecision: review.latest_refutation_decision
      ? toCampaignResearchRefutationDecisionSummary(review.latest_refutation_decision)
      : null,
    latestValidationFeedback: review.latest_validation_feedback
      ? toCampaignResearchValidationFeedbackSummary(review.latest_validation_feedback)
      : null,
    nextAllowedAction: safeText(
      review.next_allowed_action,
      "审核假设看板并规划非破坏性证据工作。",
    ),
    nonDestructivePlan: review.non_destructive_plan
      .slice(0, 6)
      .map((step) => safeText(step, "计划步骤已脱敏")),
    playbookId: review.playbook_id ? safeText(review.playbook_id, "研究手册") : null,
    priorityScore: Math.max(0, Math.min(100, Math.round(review.priority_score))),
    queueKey: safeText(review.queue_key, "研究队列"),
    reportSubmissionAllowed: false,
    requiredHumanGates: review.required_human_gates
      .slice(0, 6)
      .map((gate) => reviewGateLanguage(safeText(humanize(gate), "人工审核门"))),
    safetyGate: reviewGateLanguage(safeText(humanize(review.safety_gate), "仅作建议性记忆")),
    source: safeText(humanize(review.source), "研究大脑推理记忆"),
    status: safeText(humanize(review.status), "已排入审核队列"),
    suggestedRefutationDecision: review.suggested_refutation_decision
      ? toCampaignSuggestedRefutationDecisionSummary(review.suggested_refutation_decision)
      : null,
    surfaceKey: review.surface_key ? safeText(review.surface_key, "攻击面") : null,
    taskId: safeText(review.task_id, "任务"),
    title: safeText(review.title, "研究任务审核"),
  };
}

function toCampaignSuggestedRefutationDecisionSummary(
  decision: CampaignSuggestedRefutationDecision,
): CampaignSuggestedRefutationDecisionSummary {
  return {
    decision: safeText(humanize(decision.decision), "需要验证审核"),
    dispatchAllowed: false,
    executionAllowed: false,
    humanReviewRequired: decision.human_review_required !== false,
    nextAllowedAction: reviewGateLanguage(
      safeText(
        decision.next_allowed_action,
        "准备经人工审核的验证计划，不执行验证。",
      ),
    ),
    planId: safeText(decision.plan_id, "研究计划"),
    rationale: safeReasonText(decision.rationale),
    refutationAnswerCount: Math.max(0, Math.round(decision.refutation_answer_count)),
    refutationQuestionCount: Math.max(0, Math.round(decision.refutation_question_count)),
    reportSubmissionAllowed: false,
    targetRef: decision.target_ref ? safeText(decision.target_ref, "目标") : null,
    validationAllowed: false,
    validationMode: decision.validation_mode
      ? reviewGateLanguage(safeText(humanize(decision.validation_mode), "验证模式"))
      : null,
  };
}

function toCampaignAutonomousCandidateContextSummary(
  context: CampaignAutonomousCandidateContext,
): CampaignAutonomousCandidateContextSummary {
  return {
    blockedActions: context.blocked_actions
      .slice(0, 8)
      .map((action) => safeText(humanize(action), "已阻断操作")),
    candidateId: safeText(context.candidate_id, "候选项"),
    candidateStatus: reviewGateLanguage(
      safeText(humanize(context.candidate_status), "等待人工审核"),
    ),
    dispatchAllowed: false,
    evidenceNeeded: safeLabelList(context.evidence_needed ?? [], 6),
    evidenceTraceSummary: safeEvidenceTraceSummary(context.evidence_trace_summary),
    reportReadiness: safeReportReadiness(context.report_readiness),
    evidenceFocus: safeLabelList(context.evidence_focus ?? [], 4),
    executionAllowed: false,
    humanApprovalRequired: context.human_approval_required !== false,
    hypothesis: safeReasonText(context.hypothesis),
    pipelineRunId: safeText(context.pipeline_run_id, "流程运行"),
    rawPriorityScore: percentScore(context.raw_priority_score),
    qualityGateReasons: safeLabelList(context.quality_gate_reasons ?? [], 6),
    refutationQuestions: context.refutation_questions
      .slice(0, 8)
      .map((question) => safeText(question, "反证问题已脱敏")),
    refutationStatus: safeText(humanize(context.refutation_status), "需要证据"),
    requiredEvidence: safeLabelList(context.required_evidence ?? [], 6),
    satisfiedEvidence: safeLabelList(context.satisfied_evidence ?? [], 6),
    reportSubmissionAllowed: false,
    safetyNotes: context.safety_notes
      .slice(0, 8)
      .map((note) => safeText(humanize(note), "安全说明")),
    sourceFactTypes: sourceFactTypeLabels(context.source_fact_types ?? [], 4),
    triageSignals: safeReviewLabelList(context.triage_signals ?? [], 4),
    validationAllowed: false,
    validationPlanStatus: safeText(
      reviewGateLanguage(humanize(context.validation_plan_status)),
      "需要审核",
    ),
    validationSteps: context.validation_steps
      .slice(0, 8)
      .map((step) => safeText(step, "验证步骤已脱敏")),
  };
}

function toCampaignResearchValidationFeedbackSummary(
  feedback: CampaignResearchValidationFeedback,
): CampaignResearchValidationFeedbackSummary {
  return {
    approvalId: safeText(feedback.approval_id, "审批记录"),
    campaignId: safeText(feedback.campaign_id, "活动"),
    decisionId: safeText(feedback.decision_id, "反证决策"),
    dispatchAllowed: false,
    evidenceRefCount: Math.max(0, Math.round(feedback.evidence_ref_count)),
    executionAllowed: false,
    feedbackStageId: safeText(feedback.feedback_stage_id, "反馈阶段"),
    findingConfirmationAllowed: false,
    nextAllowedAction: safeText(
      feedback.next_allowed_action,
      "晋级漏洞候选前，请审核验证证据。",
    ),
    outcome: safeText(humanize(feedback.outcome), "需要证据"),
    planId: safeText(feedback.plan_id, "研究计划"),
    reportSubmissionAllowed: false,
    safetyGate: safeText(humanize(feedback.safety_gate), "仅作建议性验证反馈"),
    status: safeText(humanize(feedback.status), "证据已记录"),
    taskId: safeText(feedback.task_id, "任务"),
    validationAllowed: false,
    validationRunId: safeText(feedback.validation_run_id, "验证运行"),
  };
}

export function toCampaignResearchFeedbackEvidenceSummaries(
  reviews: CampaignResearchTaskReview[],
): CampaignResearchFeedbackEvidenceSummary[] {
  return reviews
    .filter((review) => review.latest_validation_feedback !== null)
    .map((review) => {
      const rawFeedback = review.latest_validation_feedback as CampaignResearchValidationFeedback;
      const feedback = toCampaignResearchValidationFeedbackSummary(
        rawFeedback,
      );
      const promotionGate = rawFeedback.promotion_gate;

      return {
        approvalId: feedback.approvalId,
        evidenceRefCount: feedback.evidenceRefCount,
        feedbackStageId: feedback.feedbackStageId,
        findingPromotionAllowed: false,
        nextAllowedAction: feedback.nextAllowedAction,
        outcome: feedback.outcome,
        planId: feedback.planId,
        promotionGate: safeText(
          humanize(promotionGate?.status ?? "manual_review_required"),
          "需要人工审核",
        ),
        promotionGateReason: safeText(
          humanize(promotionGate?.reason ?? "research_validation_feedback_is_advisory"),
          "研究验证反馈仅作建议性参考",
        ),
        promotionProvenanceRefCount: Array.isArray(promotionGate?.provenance_refs)
          ? promotionGate.provenance_refs.length
          : 0,
        reviewTitle: safeText(review.title, "研究反馈审核"),
        safetyGate: feedback.safetyGate,
        status: feedback.status,
        taskId: feedback.taskId,
        validationRunId: feedback.validationRunId,
      };
    });
}

export function toCampaignPromotionBlockReviewSummaries(
  feedbackEvidence: CampaignResearchFeedbackEvidenceSummary[],
): CampaignPromotionBlockReviewSummary[] {
  return feedbackEvidence
    .filter((feedback) => feedback.findingPromotionAllowed === false)
    .map((feedback) => ({
        approvalId: feedback.approvalId,
        evidenceRefCount: feedback.evidenceRefCount,
        feedbackStageId: feedback.feedbackStageId,
        nextAllowedAction: feedback.nextAllowedAction,
      planId: feedback.planId,
      promotionGateReason: feedback.promotionGateReason,
      promotionProvenanceRefCount: feedback.promotionProvenanceRefCount,
      reviewTitle: feedback.reviewTitle,
      taskId: feedback.taskId,
      validationRunId: feedback.validationRunId,
    }));
}

function toCampaignResearchRefutationDecisionSummary(
  decision: CampaignResearchRefutationDecision,
): CampaignResearchRefutationDecisionSummary {
  return {
    approvalId: decision.approval_id ? safeText(decision.approval_id, "审批记录") : null,
    campaignId: safeText(decision.campaign_id, "活动"),
    decision: safeText(humanize(decision.decision), "需要证据"),
    decisionId: safeText(decision.decision_id, "反证决策"),
    dispatchAllowed: false,
    executionAllowed: false,
    nextAllowedAction: safeText(
      decision.next_allowed_action,
      "验证前请收集脱敏证据或完善假设。",
    ),
    planId: safeText(decision.plan_id, "研究计划"),
    rationale: safeReasonText(decision.rationale),
    refutationAnswers: decision.refutation_answers
      .slice(0, 8)
      .map((answer) => safeReasonText(answer)),
    reportSubmissionAllowed: false,
    taskId: safeText(decision.task_id, "任务"),
    validationAllowed: false,
    validationRunId: decision.validation_run_id
      ? safeText(decision.validation_run_id, "验证运行")
      : null,
  };
}

function toCampaignResearchReviewPlanSummary(
  plan: CampaignResearchReviewPlan,
): CampaignResearchReviewPlanSummary {
  return {
    campaignId: safeText(plan.campaign_id, "活动"),
    dispatchAllowed: false,
    evidencePlan: plan.evidence_plan.slice(0, 8).map((step) => safeReasonText(step)),
    executionAllowed: false,
    hypothesis: safeReasonText(plan.hypothesis),
    nextAllowedAction: reviewGateLanguage(
      safeText(
        plan.next_allowed_action,
        "验证前请审核假设看板并请求审核。",
      ),
    ),
    planId: safeText(plan.plan_id, "研究计划"),
    refutationQuestions: plan.refutation_questions
      .slice(0, 8)
      .map((question) => safeReasonText(question)),
    reportSubmissionAllowed: false,
    requiredHumanGates: plan.required_human_gates
      .slice(0, 6)
      .map((gate) => reviewGateLanguage(safeText(humanize(gate), "人工审核门"))),
    safetyGate: safeText(humanize(plan.safety_gate), "仅作建议性计划"),
    status: safeText(humanize(plan.status), "已起草"),
    taskId: safeText(plan.task_id, "任务"),
    validationAllowed: false,
  };
}

export function toCampaignArtifactSummaries(
  artifacts: ArtifactRecord[],
): CampaignArtifactSummary[] {
  return artifacts.map((artifact) => {
    const usageRecords = artifact.usage_records ?? [];

    return {
      asset: safeText(artifact.asset, "资产"),
      createdAt: artifact.created_at,
      id: safeText(artifact.id, "资料"),
      ingestionStatus: safeText(humanize(artifact.ingestion_status), "未知状态"),
      kind: safeText(humanize(artifact.kind), "资料"),
      reportChainAllowed: artifact.report_chain_allowed === true,
      safetyBlockerCount: artifact.safety_blockers.length,
      sensitivityLabel: safeText(humanize(artifact.sensitivity_label), "未知敏感度"),
      sourceType: safeText(humanize(artifact.source_type), "来源"),
      usageCount: usageRecords.length,
      usageStages: usageCounts(usageRecords, "stage"),
      usageTypes: usageCounts(usageRecords, "usage_type"),
    };
  });
}

function usageCounts(
  records: NonNullable<ArtifactRecord["usage_records"]>,
  key: "stage" | "usage_type",
): CountSummary[] {
  const counts = new Map<string, number>();
  for (const record of records) {
    const value = typeof record[key] === "string" && record[key]?.trim()
      ? record[key]
      : "unknown";
    const label = safeText(humanize(value), "用途");
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  return Array.from(counts, ([label, count]) => ({ count, label }));
}

export function toCampaignValidationQueueSummaries(
  approvals: CampaignApproval[],
): CampaignValidationQueueSummary[] {
  return approvals.map((approval) => ({
    approvalType: approval.approval_type
      ? safeText(humanize(approval.approval_type), "审核门")
      : "审核门",
    asset: approval.asset ? safeText(approval.asset, "资产") : null,
    createdAt: approval.created_at,
    expiresAt: approval.expires_at ?? null,
    id: safeText(approval.id, "审批记录"),
    nextAction: validationQueueNextAction(approval),
    planDigest: approval.plan_digest ? safeText(approval.plan_digest, "计划") : null,
    reason: reviewGateLanguage(safeText(approval.reason, "原因已脱敏")),
    requestedAction: approval.requested_action
      ? reviewGateLanguage(safeText(humanize(approval.requested_action), "已请求操作"))
      : null,
    runId: approval.run_id ? safeText(approval.run_id, "运行") : null,
    safetyGateState: reviewGateLanguage(
      safeText(humanize(approval.safety_gate_state), "未知审核门"),
    ),
    status: safeText(humanize(approval.status), "未知状态"),
    taskId: approval.task_id ? safeText(approval.task_id, "任务") : null,
    validationMode: approval.validation_mode
      ? reviewGateLanguage(safeText(humanize(approval.validation_mode), "验证模式"))
      : null,
  }));
}

export function toCampaignValidationRunSummaries(
  runs: CampaignValidationRun[],
): CampaignValidationRunSummary[] {
  return runs.map((run) => {
    const executionState = validationRunExecutionState(run);
    return {
      allowedToExecute: run.allowed_to_execute === true,
      approvalId: run.approval_id ? safeText(run.approval_id, "审批记录") : null,
      approvalRequired: run.approval_required === true,
      attentionState: validationRunAttentionState(run, executionState),
      createdAt: run.created_at,
      evidenceRefCount: run.evidence_ref_count,
      executionStarted: run.execution_started === true,
      executionState,
      finishedAt: run.finished_at ?? null,
      id: safeText(run.id, "验证运行"),
      nextAction: validationRunNextAction(run, executionState),
      planDigest: run.plan_digest ? safeText(run.plan_digest, "计划") : null,
      preflightPassed: validationRunPreflightPassed(run),
      safetyGateState: reviewGateLanguage(safeText(humanize(run.safety_gate_state), "未知审核门")),
      status: reviewGateLanguage(safeText(humanize(run.status), "未知状态")),
      summary: reviewGateLanguage(safeText(run.summary, "摘要已脱敏")),
      targetRef: safeText(run.target_ref, "目标"),
      taskId: run.task_id ? safeText(run.task_id, "任务") : null,
      validationMode: reviewGateLanguage(safeText(humanize(run.validation_mode), "验证模式")),
    };
  });
}

function validationQueueNextAction(approval: CampaignApproval): string {
  if (approval.status === "approved") {
    return "验证前请执行范围守卫预检。";
  }
  if (approval.status === "denied" || approval.status === "revoked" || approval.status === "expired") {
    return "验证前请创建新的已审核门。";
  }
  return "审核门记录后，再执行范围守卫预检。";
}

function validationRunExecutionState(run: CampaignValidationRun): string {
  if (run.execution_started === true) {
    return "验证已启动";
  }
  if (validationRunPreflightPassed(run)) {
    return "预检已通过";
  }
  if (
    run.approval_required === true
    && run.approval_id
    && run.status === "ready"
    && run.safety_gate_state === "approved_validation_record"
  ) {
    return "需要预检";
  }
  if (run.approval_required === true && !run.approval_id) {
    return "等待审核门";
  }
  return "预检已阻断";
}

function validationRunAttentionState(
  run: CampaignValidationRun,
  executionState: string,
): string {
  if (run.execution_started === true) {
    return "验证已启动";
  }
  if (executionState === "预检已通过") {
    return "预检已通过";
  }
  if (executionState === "需要预检") {
    return "需要预检";
  }
  if (run.approval_required === true && !run.approval_id) {
    return "缺少审核门";
  }
  return "预检已阻断";
}

function validationRunNextAction(
  run: CampaignValidationRun,
  executionState: string,
): string {
  if (run.execution_started === true) {
    return "监控审计轨迹并保持证据脱敏。";
  }
  if (executionState === "预检已通过") {
    return "在晋级任何证据前审核人工验证观察。";
  }
  if (executionState === "需要预检") {
    return "验证前请执行范围守卫预检。";
  }
  if (run.approval_required === true && !run.approval_id) {
    return "预检前请审核验证门。";
  }
  return "验证前请处理范围、审批或预检阻断项。";
}

function validationRunPreflightPassed(run: CampaignValidationRun): boolean {
  return (
    run.preflight_passed === true
    || run.status === "preflight_passed"
    || run.safety_gate_state === "scope_guard_preflight_passed"
    || run.allowed_to_execute === true
  );
}

export function toCampaignTimelineSummaries(
  stages: CampaignPipelineStage[],
): CampaignTimelineSummary[] {
  return stages.map((stage) => {
    const stageKey = safeText(humanize(stage.stage_key), "阶段");
    const isCycleReview = stage.stage_key === "campaign_cycle_review";
    const isLearningOutcome = stage.stage_key === "learning_outcome_recorded";
    const isManualValidationResult = stage.stage_key === "validation_manual_result";
    const isFindingPromotion = stage.stage_key === "finding_promotion";
    const isFindingPromotionBlocked = stage.stage_key === "finding_promotion_blocked";
    const isResearchQueueMaterialized = stage.stage_key === "research_queue_materialized";
    const isResearchPlan = stage.stage_key === "research_task_review_plan";
    const isResearchRefutationDecision =
      stage.stage_key === "research_task_refutation_decision";
    const isResearchValidationFeedback =
      stage.stage_key === "research_task_validation_feedback";
    const isValidationFeedbackReview =
      stage.stage_key === "research_task_validation_feedback_review";
    const payload = stage.payload ?? {};
    const durationSeconds = safeCount(stage.duration_seconds);
    const errorSummary =
      typeof stage.error_summary === "string" && stage.error_summary.trim()
        ? reviewGateLanguage(safeReasonText(stage.error_summary))
        : undefined;
    const promotionProvenanceRefCount = isFindingPromotion
      ? safeCountOrListLength(payload.claim_provenance_ref_count, payload.claim_provenance_refs)
      : undefined;
    const reviewEvidenceRefCount = isFindingPromotion
      ? safeCountOrListLength(payload.review_evidence_ref_count, payload.review_evidence_refs)
      : undefined;
    const llmAudit = isFindingPromotion ? asRecord(payload.llm_audit) : {};
    const llmAuditPromptHash = stringValue(llmAudit.prompt_hash);
    const manualValidationReview = isManualValidationResult
      ? manualValidationReviewSummary(asRecord(payload.validation_result_review))
      : null;

    return {
      auditLabel: isCycleReview
        ? "活动周期审核"
        : isLearningOutcome
          ? "建议性大脑学习"
          : isManualValidationResult
            ? "人工验证结果"
            : isFindingPromotion
              ? "漏洞候选晋级审核"
              : isFindingPromotionBlocked
                ? "漏洞候选晋级已阻断"
                : isResearchQueueMaterialized
                  ? "研究审核已排队"
                  : isResearchPlan
                    ? "研究计划已起草"
                    : isResearchRefutationDecision
                      ? "反证决策"
                      : isResearchValidationFeedback
                        ? "研究验证反馈"
                        : isValidationFeedbackReview
                          ? "验证反馈审核"
                          : stageKey,
      ...(isResearchRefutationDecision
        ? { approvalCreated: payload.approval_created === true }
        : {}),
      ...(durationSeconds !== undefined ? { durationSeconds } : {}),
      ...(isResearchQueueMaterialized
        ? { blockedActionCount: safeCount(payload.blocked_action_count) ?? 0 }
        : {}),
      ...(isResearchPlan || isResearchRefutationDecision
        ? { blockedActionCount: safeCount(payload.blocked_action_count) ?? 0 }
        : {}),
      ...(isResearchQueueMaterialized && typeof payload.candidate_status === "string"
        ? { candidateStatus: safeText(humanize(payload.candidate_status), "候选项") }
        : {}),
      ...(isResearchRefutationDecision && typeof payload.decision === "string"
        ? { decision: safeText(humanize(payload.decision), "决策") }
        : {}),
      ...(isValidationFeedbackReview && typeof payload.decision === "string"
        ? { decision: safeText(humanize(payload.decision), "决策") }
        : {}),
      ...(isValidationFeedbackReview
        ? {
            executionAllowed: false,
            findingConfirmationAllowed: payload.finding_confirmation_allowed === true,
            reportSubmissionAllowed: false,
            validationAllowed: false,
          }
        : {}),
      ...(errorSummary ? { errorSummary } : {}),
      ...(isResearchPlan
        ? { evidenceStepCount: safeCount(payload.evidence_step_count) ?? 0 }
        : {}),
      ...(isResearchQueueMaterialized || isResearchPlan
        ? { requiredEvidence: safeLabelList(stringList(payload.required_evidence), 6) }
        : {}),
      ...(isResearchPlan || isResearchRefutationDecision
        ? {
            evidenceFocusCount: safeCount(payload.evidence_focus_count) ?? 0,
            hasAuthorizationGapCandidate: payload.has_authorization_gap_candidate === true,
            priorityReasonCount: safeCount(payload.priority_reason_count) ?? 0,
            sourceFactTypeCount: safeCount(payload.source_fact_type_count) ?? 0,
            triageSignalCount: safeCount(payload.triage_signal_count) ?? 0,
          }
        : {}),
      ...(isResearchQueueMaterialized
        ? { humanApprovalRequired: payload.human_approval_required !== false }
        : {}),
      ...(isResearchPlan || isResearchRefutationDecision
        ? { humanApprovalRequired: payload.human_approval_required !== false }
        : {}),
      ...(isFindingPromotion && typeof payload.hunter_operating_action === "string"
        ? {
            hunterOperatingAction: safeText(
              humanize(payload.hunter_operating_action),
              "挖掘操作",
            ),
          }
        : {}),
      id: safeText(stage.id, "阶段"),
      inputRefCount: stage.input_refs.length,
      isCycleReview,
      ...(isFindingPromotion ? { isFindingPromotion: true } : {}),
      ...(isFindingPromotionBlocked ? { isFindingPromotionBlocked: true } : {}),
      isLearningOutcome,
      isManualValidationResult,
      ...(manualValidationReview ? { manualValidationReview } : {}),
      ...(isResearchPlan ? { isResearchPlan: true } : {}),
      ...(isResearchRefutationDecision ? { isResearchRefutationDecision: true } : {}),
      ...(isResearchQueueMaterialized ? { isResearchQueueMaterialized: true } : {}),
      ...(isResearchValidationFeedback ? { isResearchValidationFeedback: true } : {}),
      ...(isValidationFeedbackReview ? { isValidationFeedbackReview: true } : {}),
      ...(isFindingPromotion && typeof llmAudit.mode === "string"
        ? { llmAuditMode: safeText(humanize(llmAudit.mode), "审核模式") }
        : {}),
      ...(isFindingPromotion && llmAuditPromptHash
        ? { llmAuditPromptHash: safeText(llmAuditPromptHash, "审核哈希") }
        : {}),
      ...(isFindingPromotion && typeof llmAudit.prompt_text_stored === "boolean"
        ? { llmAuditPromptTextStored: llmAudit.prompt_text_stored }
        : {}),
      outputRefCount: stage.output_refs.length,
      ...(promotionProvenanceRefCount !== undefined ? { promotionProvenanceRefCount } : {}),
      ...(isResearchRefutationDecision
        ? { refutationAnswerCount: safeCount(payload.refutation_answer_count) ?? 0 }
        : {}),
      ...(isResearchQueueMaterialized
        ? { refutationQuestionCount: safeCount(payload.refutation_question_count) ?? 0 }
        : {}),
      ...(isResearchPlan
        ? { refutationQuestionCount: safeCount(payload.refutation_question_count) ?? 0 }
        : {}),
      ...(reviewEvidenceRefCount !== undefined ? { reviewEvidenceRefCount } : {}),
      safetyGateState: safeText(humanize(stage.safety_gate_state), "未知审核门"),
      stageKey,
      stageOrder: stage.stage_order,
      status: safeText(humanize(stage.status), "未知状态"),
      stopReason: stage.stop_reason
        ? reviewGateLanguage(safeText(humanize(stage.stop_reason), "已停止"))
        : null,
      taskId: stage.task_id ? safeText(stage.task_id, "任务") : null,
      ...(isResearchQueueMaterialized
        ? { validationStepCount: safeCount(payload.validation_step_count) ?? 0 }
        : {}),
      ...(isResearchRefutationDecision
        ? { validationRunCreated: payload.validation_run_created === true }
        : {}),
    };
  });
}

function manualValidationReviewSummary(
  review: Record<string, unknown>,
): CampaignTimelineSummary["manualValidationReview"] | null {
  if (Object.keys(review).length === 0) {
    return null;
  }

  return {
    evidenceQuality: safeText(humanize(String(review.evidence_quality ?? "weak")), "低"),
    promotionReviewReady: review.promotion_review_ready === true,
    qualityReasons: stringList(review.quality_reasons).map(safeReasonText),
    qualityScore: percentScore(review.quality_score) ?? 0,
    redactionStatus: safeText(humanize(String(review.redaction_status ?? "unknown")), "未知"),
    safeEvidenceRefCount: safeCount(review.safe_evidence_ref_count) ?? 0,
    sourceType: safeText(
      humanize(String(review.source_type ?? "manual_safe_observation")),
      "人工安全观察",
    ),
    unsafeEvidenceRefCount: safeCount(review.unsafe_evidence_ref_count) ?? 0,
  };
}

export function toCampaignBrainSummary(
  profile: ProgramIntelligenceProfile,
): CampaignBrainSummary {
  return {
    advisoryOnly: true,
    appliedLessonCount: profile.applied_lessons.length,
    appliedLessons: profile.applied_lessons.slice(0, 5).map((lesson) => ({
      confidence: lesson.confidence,
      id: safeText(lesson.id, "经验"),
      recommendation: safeText(humanize(lesson.recommendation), "建议"),
      reasons: lesson.reasons.slice(0, 4).map((reason) => safeReasonText(reason)),
      scoreDelta: lesson.score_delta,
      surfacePattern: safeText(lesson.surface_pattern, "攻击面"),
    })),
    executionAllowed: false,
    objectCount: profile.attack_surface_memory.objects.length,
    programId: safeText(profile.program_id, "项目"),
    programName: safeText(profile.program_name, "项目"),
    programScore: profile.program_score,
    recentSignals: profile.recent_learning_signals.slice(0, 5).map((signal) => ({
      evidenceQuality: signal.evidence_quality
        ? safeText(humanize(signal.evidence_quality), "证据质量")
        : null,
      id: safeText(signal.id ?? "信号", "信号"),
      notes: safeText(signal.notes, "说明已脱敏"),
      outcome: safeText(humanize(signal.outcome), "结果"),
      playbookId: safeText(signal.playbook_id, "研究手册"),
      surfaceKey: signal.surface_key ? safeText(signal.surface_key, "攻击面") : null,
    })),
    roleCount: profile.attack_surface_memory.roles.length,
    reasoningMemory: {
      candidateContextCount: profile.reasoning_memory?.candidate_context_count ?? 0,
      highestReasoningReviewScore:
        profile.reasoning_memory?.highest_reasoning_review_score ?? 0,
      learningSignalContextCount:
        profile.reasoning_memory?.learning_signal_context_count ?? 0,
      safetyNotes: (profile.reasoning_memory?.safety_notes ?? [])
        .slice(0, 4)
        .map((note) => safeReasonText(humanize(note))),
      topPlaybooks: (profile.reasoning_memory?.top_playbooks ?? [])
        .slice(0, 5)
        .map((playbook) => ({
          candidateContextCount: playbook.candidate_context_count,
          highestReasoningReviewScore: playbook.highest_reasoning_review_score,
          learningSignalContextCount: playbook.learning_signal_context_count,
          playbookId: safeText(playbook.playbook_id, "研究手册"),
        })),
    },
    sensitiveActionCount: profile.attack_surface_memory.sensitive_actions.length,
    signalCount: profile.recent_learning_signals.length,
    skippedLessonCount: profile.skipped_lessons.length,
    topSurfaces: profile.high_value_surfaces.slice(0, 5).map((surface) => ({
      action: safeText(humanize(surface.action), "操作"),
      objectName: safeText(surface.object_name, "对象"),
      path: safeText(surface.paths[0] ?? "", "无路径"),
      score: surface.score,
      surfaceKey: safeText(surface.surface_key, "攻击面"),
    })),
  };
}

export function toCampaignLearningReviewSummary(
  controlCenter: CampaignControlCenter,
  profile: ProgramIntelligenceProfile,
): CampaignLearningReviewSummary {
  const linkedRunIds = new Set(
    controlCenter.pipeline_stages
      .filter((stage) => stage.stage_key === "campaign_report_preview" && stage.pipeline_run_id)
      .map((stage) => stage.pipeline_run_id),
  );

  return {
    advisoryOnly: true,
    appliedLessonCount: profile.applied_lessons.length,
    executionAllowed: false,
    linkedRunCount: linkedRunIds.size,
    recentSignalCount: profile.recent_learning_signals.length,
    reviewReady: controlCenter.safe_next_action === "review_learning_outcome",
    safeNextAction: safeNextActionLabel(controlCenter.safe_next_action),
    skippedLessonCount: profile.skipped_lessons.length,
    strongEvidenceSignalCount: profile.recent_learning_signals.filter(
      (signal) => signal.evidence_quality === "strong",
    ).length,
  };
}

export function toCampaignCodebaseMapView(
  codebaseMap: CampaignCodebaseMap,
): CampaignCodebaseMapView {
  const maps = codebaseMap.maps.map((map) => ({
    authzCheckCount: map.authz_check_count,
    commitRef: map.commit_ref ? safeText(map.commit_ref, "提交") : null,
    createdAt: map.created_at,
    handlerCount: map.handler_count,
    id: safeText(map.id, "代码库映射"),
    modelCount: map.model_count,
    repository: safeText(map.repository, "代码仓库"),
    routeCount: map.route_count,
    safetyGateState: safeText(humanize(map.safety_gate_state), "未知审核门"),
    sensitiveSinkCount: map.sensitive_sink_count,
    sourceRef: safeText(map.source_ref, "来源"),
    status: safeText(humanize(map.status), "未知状态"),
  }));
  const facts = codebaseMap.facts.map((fact) => ({
    authzHint: fact.authz_hint ? codebaseAuthzHintLabel(fact.authz_hint) : null,
    factType: codebaseFactTypeLabel(fact.fact_type),
    id: safeText(fact.id, "事实"),
    route:
      fact.route_method || fact.route_path
        ? safeText(`${fact.route_method ?? ""} ${fact.route_path ?? ""}`.trim(), "路由")
        : null,
    sensitivityLabel: safeText(humanize(fact.sensitivity_label), "敏感度"),
    sourcePath: safeText(fact.source_path, "来源"),
    symbolName: fact.symbol_name ? safeText(fact.symbol_name, "符号") : null,
  }));
  const scannerRuns = codebaseMap.scanner_runs.map((run) => ({
    candidateCount: run.candidate_count,
    commandHash: safeText(run.command_hash, "命令"),
    findingCount: run.finding_count,
    id: safeText(run.id, "扫描运行"),
    safetyGateState: safeText(humanize(run.safety_gate_state), "未知审核门"),
    status: safeText(humanize(run.status), "未知状态"),
    summary: safeText(run.summary, "摘要已脱敏"),
    toolName: safeText(run.tool_name, "工具"),
  }));

  return {
    authorizationGapCandidateCount: codebaseMap.facts.filter(
      (fact) => fact.fact_type === "authorization_gap_candidate",
    ).length,
    authzCheckCount: maps.reduce((total, map) => total + map.authzCheckCount, 0),
    candidateCount: scannerRuns.reduce((total, run) => total + run.candidateCount, 0),
    factCount: facts.length,
    facts,
    mapCount: maps.length,
    maps,
    routeCount: maps.reduce((total, map) => total + map.routeCount, 0),
    scannerRunCount: scannerRuns.length,
    scannerRuns,
    sensitiveSinkCount: maps.reduce((total, map) => total + map.sensitiveSinkCount, 0),
  };
}

function codebaseAuthzHintLabel(authzHint: string): string {
  return safeText(humanize(authzHint), "访问控制提示").replace(/\bauthz\b/gi, "访问控制");
}

function codebaseFactTypeLabel(factType: string): string {
  return safeText(humanize(factType), "事实").replace(/\bauthorization\b/gi, "访问控制");
}

export function toCampaignEvidenceReviewSummaries(
  previews: ReportPreview[],
): CampaignEvidenceReviewSummary[] {
  return previews.flatMap((preview) =>
    preview.claim_ledger.map((claim) => ({
      claimId: safeText(claim.claim_id, "声明"),
      claimText: safeText(claim.text, "声明文本已脱敏"),
      claimType: safeText(humanize(claim.claim_type), "声明"),
      evidenceRefCount: claim.evidence_refs.length,
      humanReviewRequired: claim.human_review_required === true,
      provenanceRefCount: claim.provenance_refs.length,
      qualityScore: claim.quality_score,
      readinessBlockers: claim.readiness_blockers.map((blocker) =>
        safeText(humanize(blocker), "阻断项"),
      ),
      readinessLevel: safeText(humanize(claim.readiness_level), "就绪度"),
      redactionStatus: safeText(humanize(claim.redaction_status), "脱敏"),
      reportChainEligible:
        claim.review_status === "confirmed_observed_fact" &&
        claim.readiness_level === "human_reviewed_gated" &&
        claim.readiness_blockers.length === 0 &&
        claim.review_evidence_refs.length > 0,
      reviewEvidenceRefCount: claim.review_evidence_refs.length,
      reviewRationale: claim.review_rationale
        ? reviewGateLanguage(safeText(claim.review_rationale, "审核理由已脱敏"))
        : null,
      reviewStatus: reviewGateLanguage(safeText(humanize(claim.review_status), "审核状态")),
      runId: safeText(preview.run_id, "运行"),
      status: evidenceReviewClaimStatusText(claim.status),
    })),
  );
}

function evidenceReviewClaimStatusText(status: string): string {
  if (status === "report_ready") {
    return "报告审核受控";
  }
  return reviewGateLanguage(safeText(humanize(status), "状态"));
}

export function toCampaignReportDraftSummaries(
  previews: ReportPreview[],
): CampaignReportDraftSummary[] {
  return previews.map((preview) => {
    const readyClaimCount = preview.claim_ledger.filter((claim) => claim.status === "report_ready")
      .length;

    return {
      blockedClaimCount: preview.claim_ledger.length - readyClaimCount,
      claimCount: preview.claim_ledger.length,
      evidenceRefCount: preview.evidence_refs.length,
      humanReviewRequired: preview.human_review_required === true,
      readyClaimCount,
      runId: safeText(preview.run_id, "运行"),
      safetyNotes: preview.safety_notes
        .slice(0, 4)
        .map((note) => safeText(/[_-]/.test(note) ? humanize(note) : note, "安全说明")),
      scopeStatus: safeText(humanize(preview.scope_status), "未知范围"),
      severity: safeText(humanize(preview.severity), "未知严重性"),
      submissionBlocked: preview.submission_blocked === true,
      title: safeText(preview.title, "未命名报告草稿"),
      topClaims: preview.claim_ledger.slice(0, 3).map((claim) =>
        safeText(claim.text, "声明文本已脱敏"),
      ),
    };
  });
}

export function toCampaignReportDraftEvidenceSummary(
  runs: CampaignValidationRun[],
): CampaignReportDraftEvidenceSummary {
  const relevantRuns = runs.filter(
    (run) =>
      run.status === "evidence_recorded" ||
      run.status === "needs_evidence" ||
      run.safety_gate_state === "manual_evidence_recorded" ||
      run.safety_gate_state === "manual_evidence_gap_recorded",
  );

  return {
    evidenceGapCount: relevantRuns.filter(
      (run) => run.status === "needs_evidence" || run.safety_gate_state === "manual_evidence_gap_recorded",
    ).length,
    evidenceRefCount: relevantRuns.reduce((total, run) => total + run.evidence_ref_count, 0),
    manualEvidenceCount: relevantRuns.filter(
      (run) => run.status === "evidence_recorded" || run.safety_gate_state === "manual_evidence_recorded",
    ).length,
    validationRunCount: relevantRuns.length,
  };
}

export function toCampaignValidationEvidenceReviewSummaries(
  runs: CampaignValidationRun[],
  pipelineStages: CampaignPipelineStage[] = [],
): CampaignValidationEvidenceReviewSummary[] {
  const validationReviews = manualValidationReviewByRunId(pipelineStages);

  return runs
    .filter(isManualValidationEvidenceRun)
    .map((run) => {
      const hasEvidenceRefs = run.evidence_ref_count > 0;
      const manualValidationReview = validationReviews.get(run.id);
      return {
        candidateEvidenceState: hasEvidenceRefs
          ? "候选证据需要审核"
          : "证据缺口需要审核",
        evidenceRefCount: run.evidence_ref_count,
        ...(manualValidationReview
          ? { manualValidationReview: validationEvidenceManualReviewSummary(manualValidationReview) }
          : {}),
        nextReviewAction: hasEvidenceRefs
          ? "报告链使用前请审核脱敏、溯源与声明覆盖情况。"
          : "报告链使用前请收集脱敏证据引用。",
        planDigest: run.plan_digest ? safeText(run.plan_digest, "计划") : null,
        preflightState: "人工结果已记录",
        reportChainState: hasEvidenceRefs ? "报告链需要审核" : "报告链已阻断",
        reviewGate: run.approval_id ? safeText(run.approval_id, "审批记录") : "无审核门",
        reviewItem: run.task_id ? safeText(run.task_id, "任务") : "无审核项",
        status: reviewGateLanguage(safeText(humanize(run.status), "状态")),
        summary: reviewEvidenceSummaryText(run.summary),
        targetRef: safeText(run.target_ref, "目标"),
        validationMode: reviewGateLanguage(safeText(humanize(run.validation_mode), "验证模式")),
        validationRunId: safeText(run.id, "验证运行"),
      };
    });
}

function validationEvidenceManualReviewSummary(
  review: NonNullable<CampaignTimelineSummary["manualValidationReview"]>,
): CampaignValidationEvidenceManualReviewSummary {
  return {
    evidenceQuality: review.evidenceQuality,
    promotionReviewState: review.promotionReviewReady
      ? "漏洞候选晋级审核需要人工决策"
      : "漏洞候选晋级审核受控",
    qualityReasons: review.qualityReasons,
    qualityScore: review.qualityScore,
    redactionStatus: review.redactionStatus,
    safeEvidenceRefCount: review.safeEvidenceRefCount,
    sourceType: review.sourceType,
    unsafeEvidenceRefCount: review.unsafeEvidenceRefCount,
  };
}

function manualValidationReviewByRunId(
  pipelineStages: CampaignPipelineStage[],
): Map<string, CampaignTimelineSummary["manualValidationReview"]> {
  const reviews = new Map<string, CampaignTimelineSummary["manualValidationReview"]>();
  for (const stage of pipelineStages) {
    if (stage.stage_key !== "validation_manual_result") {
      continue;
    }
    const validationRunId = validationRunIdFromStageRefs(stage);
    if (!validationRunId) {
      continue;
    }
    const review = manualValidationReviewSummary(
      asRecord(asRecord(stage.payload).validation_result_review),
    );
    if (review) {
      reviews.set(validationRunId, review);
    }
  }
  return reviews;
}

function validationRunIdFromStageRefs(stage: CampaignPipelineStage): string | null {
  const refs = [...stage.output_refs, ...stage.input_refs];
  for (const ref of refs) {
    const match = /^validation_run:([^?#\s]+)/.exec(ref);
    if (match?.[1]) {
      return match[1];
    }
  }
  return null;
}

export function toCampaignValidationEvidenceQualitySummary(
  validationEvidence: CampaignValidationEvidenceReviewSummary[],
): CampaignValidationEvidenceQualitySummary {
  const reviews = validationEvidence
    .map((run) => run.manualValidationReview)
    .filter((review): review is CampaignValidationEvidenceManualReviewSummary => Boolean(review));

  return {
    cleanReviewCount: reviews.filter((review) => review.redactionStatus === "已清理").length,
    gatedPromotionReviewCount: reviews.filter(
      (review) => review.promotionReviewState === "漏洞候选晋级审核受控",
    ).length,
    redactedReviewCount: reviews.filter((review) => review.redactionStatus === "已脱敏").length,
    reviewedEvidenceCount: reviews.length,
    strongEvidenceCount: reviews.filter((review) => review.evidenceQuality === "强").length,
    unsafeEvidenceRefCount: reviews.reduce(
      (total, review) => total + review.unsafeEvidenceRefCount,
      0,
    ),
  };
}

function reviewEvidenceSummaryText(summary: string): string {
  return reviewGateLanguage(safeText(summary, "摘要已脱敏")).replace(
    /\b(authorization|cookie|session|token)=\[(?:redacted|已脱敏)\]/gi,
    (_match, key: string) => `${formatLabel(key)} [已脱敏]`,
  );
}

function isManualValidationEvidenceRun(run: CampaignValidationRun): boolean {
  return (
    run.status === "evidence_recorded" ||
    run.status === "needs_evidence" ||
    run.safety_gate_state === "manual_evidence_recorded" ||
    run.safety_gate_state === "manual_evidence_gap_recorded"
  );
}

export function toCampaignFindingCandidateGateSummary(
  previews: ReportPreview[],
  researchFeedbackEvidence: CampaignResearchFeedbackEvidenceSummary[] = [],
  pipelineStages: CampaignPipelineStage[] = [],
): CampaignFindingCandidateGateSummary {
  const claims = previews.flatMap((preview) => preview.claim_ledger);
  const previewHasEligibleClaim = (preview: ReportPreview): boolean =>
    preview.claim_ledger.some(
      (claim) =>
        claim.review_status === "confirmed_observed_fact" &&
        claim.readiness_level === "human_reviewed_gated" &&
        claim.readiness_blockers.length === 0 &&
        claim.review_evidence_refs.length > 0,
    );
  const eligibleClaimCount = claims.filter(
    (claim) =>
      claim.review_status === "confirmed_observed_fact" &&
      claim.readiness_level === "human_reviewed_gated" &&
      claim.readiness_blockers.length === 0 &&
      claim.review_evidence_refs.length > 0,
  ).length;
  const promotionBlockedStages = pipelineStages.filter(
    (stage) => stage.stage_key === "finding_promotion_blocked" && stage.status === "blocked",
  );
  const latestPromotionBlock = promotionBlockedStages.at(-1);
  const promotionCreatedStages = pipelineStages.filter(
    (stage) => stage.stage_key === "finding_promotion" && stage.status === "candidate_created",
  );
  const latestPromotionCreatedPayload = asRecord(promotionCreatedStages.at(-1)?.payload);
  const researchPromotionBlockedCount = researchFeedbackEvidence.filter(
    (feedback) => feedback.findingPromotionAllowed === false,
  ).length;
  const requiredEvidenceBlockedCount = pipelineStages.filter((stage) => {
    if (stage.stage_key !== "research_task_review_plan") {
      return false;
    }
    if (!stage.task_id) {
      return false;
    }
    const requiredEvidence = stringList(asRecord(stage.payload).required_evidence);
    if (requiredEvidence.length === 0) {
      return false;
    }
    return !pipelineStages.some(
      (nextStage) =>
        nextStage.task_id === stage.task_id
        && nextStage.stage_key === "research_task_refutation_decision"
        && nextStage.status !== "needs_evidence",
    );
  }).length;
  const status =
    previews.length === 0
      ? "no_report_preview"
      : promotionBlockedStages.length > 0
        ? "blocked_by_promotion_audit"
        : requiredEvidenceBlockedCount > 0
        ? "blocked_by_required_evidence"
        : researchPromotionBlockedCount > 0
        ? "blocked_by_research_feedback"
        : eligibleClaimCount > 0
        ? "ready_for_manual_promotion"
        : "blocked";

  return {
    blockedClaimCount: claims.length - eligibleClaimCount,
    eligibleClaimCount,
    manualPromotionOnly: true,
    nextAllowedAction:
      status === "blocked_by_promotion_audit"
        ? "再次晋级漏洞候选前，请审核被阻断的晋级证据。"
        : status === "blocked_by_required_evidence"
        ? "晋级漏洞候选前，请处理必需证据缺口。"
        : status === "blocked_by_research_feedback"
        ? "晋级漏洞候选前，请审核验证反馈。"
        : status === "ready_for_manual_promotion"
        ? "已审核声明需要在人工审核后由人工决定是否晋级。"
        : "晋级前请完成声明审核和证据检查。",
    promotionAuditBlockedCount: promotionBlockedStages.length,
    promotionAuditCreatedCount: promotionCreatedStages.length,
    promotionAuditLatestReason: latestPromotionBlock?.stop_reason
      ? safeText(humanize(latestPromotionBlock.stop_reason), "漏洞候选晋级已阻断")
      : null,
    promotionAuditProvenanceRefCount:
      safeCountOrListLength(
        latestPromotionCreatedPayload.claim_provenance_ref_count,
        latestPromotionCreatedPayload.claim_provenance_refs,
      ) ?? 0,
    promotionAuditReviewEvidenceRefCount:
      safeCountOrListLength(
        latestPromotionCreatedPayload.review_evidence_ref_count,
        latestPromotionCreatedPayload.review_evidence_refs,
      ) ?? 0,
    requiredEvidenceBlockedCount,
    researchEvidenceRefCount: researchFeedbackEvidence.reduce(
      (total, feedback) => total + feedback.evidenceRefCount,
      0,
    ),
    researchFeedbackCount: researchFeedbackEvidence.length,
    researchPromotionBlockedCount,
    readyRunIds:
      status === "ready_for_manual_promotion"
        ? previews
            .filter(previewHasEligibleClaim)
            .map((preview) => safeText(preview.run_id, "运行"))
            .filter((runId) => runId !== "[redacted]")
        : [],
    runCount: previews.length,
    status,
  };
}

export function toCampaignHypothesisBoardSummaries(
  runs: PipelineRunDetail[],
  researchPlans: CampaignResearchReviewPlan[] = [],
  researchQueueSuggestions: CampaignResearchQueueSuggestion[] = [],
  campaignId?: string,
): CampaignHypothesisBoardSummary[] {
  const fallbackCampaignId = campaignId ?? researchPlans[0]?.campaign_id ?? "";
  const runCandidates = runs
    .flatMap((run) =>
      (run.payload?.hypothesis_assessments ?? []).map((assessment, index) => {
        const hypothesis = assessment.hypothesis;
        const hunter = assessment.hunter_assessment;
        const exploitChain = asRecord(assessment.exploit_chain);
        const primitives = stringList(exploitChain.primitives)
          .slice(0, 3)
          .map((primitive) => safeText(primitive, "原语"));
        const preconditions = stringList(exploitChain.preconditions)
          .slice(0, 3)
          .map((precondition) => safeText(precondition, "前置条件"));
        const refutationQuestions = stringList(assessment.refutation?.questions)
          .slice(0, 3)
          .map((question) => safeText(question, "反证问题"));
        const primitiveCount = stringList(exploitChain.primitives).length;
        const preconditionCount = stringList(exploitChain.preconditions).length;
        const refutationQuestionCount = stringList(assessment.refutation?.questions).length;
        const hunterPriorityScore = hunter?.hunter_priority_score ?? 0;
        const candidateId = safeText(assessment.candidate_id ?? `candidate_${index + 1}`, "候选项");
        const sourceFactTypes = sourceFactTypeLabels(
          (hypothesis?.source_facts ?? [])
            .map((fact) => fact.fact_type)
            .filter((factType): factType is string => Boolean(factType)),
          4,
        );
        const triageSignals = safeReviewLabelList(hunter?.reasons ?? [], 4);
        const evidenceFocus = safeLabelList(hunter?.evidence_focus ?? [], 4).map(accessControlLabel);
        const researchQueueHandoff = researchQueueHandoffForCandidate(
          researchQueueSuggestions,
          safeText(run.id, "运行"),
          candidateId,
          fallbackCampaignId,
        );

        return {
          brokenInvariant: hypothesis?.broken_invariant
            ? safeText(hypothesis.broken_invariant, "安全不变量")
            : null,
          candidateId,
          candidateStatus: safeText(humanize(assessment.candidate_status ?? "candidate"), "候选项"),
          chainConfidence: percentScore(exploitChain.confidence),
          chainImpact: stringValue(exploitChain.impact) ? safeText(stringValue(exploitChain.impact), "链路影响") : null,
          duplicateRiskScore: hunter?.duplicate_risk_score ?? 0,
          evidenceFocusCount: hunter?.evidence_focus?.length ?? 0,
          evidenceFocus,
          evidenceNeededCount: hypothesis?.evidence_needed?.length ?? 0,
          hunterPriorityScore,
          hypothesis: safeText(hypothesis?.hypothesis, "假设已脱敏"),
          impactScore: hunter?.impact_score ?? 0,
          nextAction: hunter?.next_action ? safeText(hunter.next_action, "下一步操作") : null,
          playbook: safeText(hunter?.playbook_label ?? hunter?.playbook_id, "无研究手册"),
          policyRisk: hypothesis?.policy_risk
            ? safeText(humanize(hypothesis.policy_risk), "策略风险")
            : null,
          policyRiskScore: hunter?.policy_risk_score ?? 0,
          preconditionCount,
          preconditions,
          priorityReasons: priorityReasonLabels(
            triageSignals,
            evidenceFocus,
            sourceFactTypes,
          ),
          primitiveCount,
          primitives,
          reasons: (hunter?.reasons ?? []).slice(0, 4).map((reason) => safeReasonText(reason)),
          recommendation: safeText(humanize(hunter?.recommendation ?? "needs_review"), "建议"),
          refutationQuestionCount,
          refutationQuestions,
          refutationStatus: assessment.refutation?.status
            ? safeText(humanize(assessment.refutation.status), "反证")
            : null,
          researchQueueHandoff,
          reviewPriorityScore: reviewPriorityScore(
            hunterPriorityScore,
            primitiveCount,
            preconditionCount,
            refutationQuestionCount,
          ),
          riskLevel: hypothesis?.risk_level ? safeText(humanize(hypothesis.risk_level), "风险") : null,
          runId: safeText(run.id, "运行"),
          source: "流程运行",
          sourceFactTypes,
          triageSignals,
          validationMode: hypothesis?.validation_mode
            ? safeText(humanize(hypothesis.validation_mode), "验证模式")
            : null,
        };
      }),
    );
  const planCandidates = researchPlans.map((plan) => {
    const refutationQuestions = plan.refutation_questions
      .slice(0, 3)
      .map((question) => safeReasonText(question));
    const refutationQuestionCount = plan.refutation_questions.length;
    const evidencePlanCount = plan.evidence_plan.length;

    return {
      brokenInvariant: null,
      candidateId: safeText(plan.plan_id, "研究计划"),
      candidateStatus: safeText(humanize(plan.status), "已起草"),
      chainConfidence: null,
      chainImpact: null,
      duplicateRiskScore: 0,
      evidenceFocusCount: evidencePlanCount,
      evidenceFocus: plan.evidence_plan.slice(0, 4).map((step) => safeReasonText(step)),
      evidenceNeededCount: evidencePlanCount,
      hunterPriorityScore: 50,
      hypothesis: safeText(plan.hypothesis, "假设已脱敏"),
      impactScore: 0,
      nextAction: reviewGateLanguage(
        safeText(
          plan.next_allowed_action,
          "验证前请审核假设看板并请求审核。",
        ),
      ),
      playbook: safeText(humanize(plan.safety_gate), "仅作建议性计划"),
      policyRisk: null,
      policyRiskScore: 0,
      preconditionCount: 0,
      preconditions: [],
      priorityReasons: [],
      primitiveCount: 0,
      primitives: [],
      reasons: plan.required_human_gates
        .slice(0, 4)
        .map((gate) => reviewGateLanguage(safeText(humanize(gate), "人工审核门"))),
      recommendation: "需要审核",
      refutationQuestionCount,
      refutationQuestions,
      refutationStatus: null,
      researchQueueHandoff: null,
      reviewPriorityScore: reviewPriorityScore(50 + evidencePlanCount * 3, 0, 0, refutationQuestionCount),
      riskLevel: null,
      runId: safeText(plan.campaign_id, "活动"),
      source: "研究审核计划",
      sourceFactTypes: [],
      triageSignals: plan.required_human_gates
        .slice(0, 4)
        .map((gate) => reviewGateLanguage(safeText(humanize(gate), "人工审核门"))),
      validationMode: "仅供审核",
    };
  });

  return [...runCandidates, ...planCandidates]
    .sort((left, right) => right.reviewPriorityScore - left.reviewPriorityScore);
}

function safeLabelList(values: string[], limit: number): string[] {
  return values.slice(0, limit).map((value) => safeReasonText(displayReasonLabel(value)));
}

function displayReasonLabel(value: string): string {
  return {
    authorization_gap_candidate: "access_control_gap_candidate",
    human_approval_required: "human_review_required",
    same_handler_authorization_evidence: "same_handler_access_control_evidence",
  }[value] ?? value;
}

function sourceFactTypeLabels(values: string[], limit: number): string[] {
  return safeLabelList(values, limit).map(accessControlLabel);
}

function accessControlLabel(label: string): string {
  return label
    .replace(/\bAccess control\b/g, "访问控制")
    .replace(/\baccess control\b/g, "访问控制");
}

function safeReviewLabelList(values: string[], limit: number): string[] {
  return safeLabelList(values, limit).map((label) => reviewGateLanguage(label));
}

function priorityReasonLabels(
  triageSignals: string[],
  evidenceFocus: string[],
  sourceFactTypes: string[],
): string[] {
  const reasons: string[] = [];
  const combined = [...triageSignals, ...evidenceFocus, ...sourceFactTypes];
  if (combined.some((value) => /access[- ]control gap candidate|访问控制缺口候选/i.test(value))) {
    reasons.push("访问控制缺口候选");
  }
  if (combined.some((value) => /same handler (authz|access[- ]control) evidence|同处理器访问控制证据/i.test(value))) {
    reasons.push("需要同处理器访问控制证据");
  }
  if (combined.some((value) => /sensitive sink present|sensitive sink|敏感汇点/i.test(value))) {
    reasons.push("存在敏感汇点");
  }
  return reasons;
}

function researchQueueHandoffForCandidate(
  suggestions: CampaignResearchQueueSuggestion[],
  runId: string,
  candidateId: string,
  campaignId: string,
): CampaignHypothesisResearchQueueHandoff | null {
  const queueKey = `autonomous_hunt:${runId}:hunt_queue_${candidateId}`;
  const suggestion = suggestions.find((item) => item.queueKey === queueKey);

  if (!suggestion || !campaignId) {
    return null;
  }

  return {
    blockedActionCount: suggestion.blockedActionCount,
    evidenceNeeded: suggestion.evidenceNeeded,
    executionAllowed: false,
    humanApprovalRequired: suggestion.humanApprovalRequired,
    nextAllowedAction: safeText(suggestion.nextAllowedAction, "执行前请审核验证计划。"),
    queueKey: safeText(suggestion.queueKey, "autonomous_hunt"),
    refutationQuestionCount: suggestion.refutationQuestionCount,
    requiredEvidence: suggestion.requiredEvidence,
    reviewHref: `/campaigns/${encodeURIComponent(campaignId)}/tasks`,
    safetyGate: safeText(suggestion.safetyGate, "审核门"),
    title: safeText(suggestion.title, "审核自动挖掘候选"),
    topCandidateRank: suggestion.topCandidateRank,
    validationStepCount: suggestion.validationStepCount,
  };
}

function safeEvidenceTraceSummary(
  summary: CampaignEvidenceTraceSummaryRaw | null | undefined,
): CampaignEvidenceTraceSummary {
  const traceStatus = safeText(summary?.trace_status, "needs_evidence");
  return {
    artifactKinds: safeLabelList(summary?.artifact_kinds ?? [], 5),
    reportSubmissionAllowed: false,
    routeFactCount: safeCount(summary?.route_fact_count) ?? 0,
    sourceFactCount: safeCount(summary?.source_fact_count) ?? 0,
    sourceFactTypes: safeLabelList(summary?.source_fact_types ?? [], 6),
    traceStatus: traceStatus === "traceable" ? "traceable" : "needs_evidence",
    traceableSourceFactCount: safeCount(summary?.traceable_source_fact_count) ?? 0,
  };
}

function safeReportReadiness(
  readiness: CampaignReportReadinessRaw | null | undefined,
): CampaignReportReadiness {
  const allowedStatuses = new Set([
    "blocked_by_required_evidence",
    "blocked_by_evidence_trace",
    "needs_safe_validation_plan",
    "submission_blocked_draft_ready",
  ]);
  const status = safeText(readiness?.status, "blocked_by_evidence_trace");
  const traceStatus = safeText(readiness?.trace_status, "needs_evidence");
  return {
    nextAllowedAction: safeText(
      readiness?.next_allowed_action,
      "起草报告前请审核证据门。",
    ),
    reportSubmissionAllowed: false,
    requiredEvidenceCount: safeCount(readiness?.required_evidence_count) ?? 0,
    safeValidationStepCount: safeCount(readiness?.safe_validation_step_count) ?? 0,
    status: allowedStatuses.has(status) ? status : "blocked_by_evidence_trace",
    submissionBlocked: true,
    traceStatus: traceStatus === "traceable" ? "traceable" : "needs_evidence",
  };
}

function safeTopCandidateRank(value: number | null | undefined): number | null {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return null;
  }
  const rank = Math.round(value);
  return rank >= 1 && rank <= 5 ? rank : null;
}

export function toCampaignAttackSurfaceMapView(
  runs: PipelineRunDetail[],
): CampaignAttackSurfaceMapView {
  const endpoints: CampaignAttackSurfaceEndpointSummary[] = [];
  const objects: CampaignAttackSurfaceObjectSummary[] = [];
  const sensitiveActions: CampaignAttackSurfaceSensitiveActionSummary[] = [];
  const relationships: CampaignAttackSurfaceRelationshipSummary[] = [];
  const roles = new Set<string>();

  for (const run of runs) {
    const runId = safeText(run.id, "运行");
    const targetModel = asRecord(run.payload?.target_model);

    for (const endpointValue of asArray(targetModel.endpoints)) {
      const endpoint = asRecord(endpointValue);
      endpoints.push({
        route: routeLabel(endpoint.method, endpoint.path),
        runId,
        summary: stringValue(endpoint.summary) ? safeText(stringValue(endpoint.summary), "摘要") : null,
      });
    }

    for (const objectValue of asArray(targetModel.objects)) {
      const object = asRecord(objectValue);
      objects.push({
        identifierCount: stringList(object.identifiers).length,
        name: safeText(stringValue(object.name), "对象"),
        runId,
      });
    }

    for (const role of stringList(targetModel.roles)) {
      roles.add(safeText(role, "角色"));
    }

    for (const actionValue of asArray(targetModel.sensitive_actions)) {
      const action = asRecord(actionValue);
      sensitiveActions.push({
        action: safeText(stringValue(action.action), "操作"),
        roleCount: stringList(action.roles).length,
        route: routeLabel(action.method, action.path),
        runId,
      });
    }

    for (const relationshipValue of asArray(targetModel.relationships)) {
      const relationship = asRecord(relationshipValue);
      const parent = safeText(stringValue(relationship.parent_object), "父对象");
      const child = safeText(stringValue(relationship.child_object), "子对象");
      relationships.push({
        pathCount: stringList(relationship.paths).length,
        relationship: safeText(stringValue(relationship.relationship), "关系"),
        runId,
        summary: `${parent} -> ${child}`,
      });
    }
  }

  return {
    endpointCount: endpoints.length,
    endpoints: endpoints.slice(0, 20),
    objectCount: objects.length,
    objects: objects.slice(0, 20),
    relationshipCount: relationships.length,
    relationships: relationships.slice(0, 20),
    roleCount: roles.size,
    roles: Array.from(roles).sort(),
    runCount: runs.length,
    sensitiveActionCount: sensitiveActions.length,
    sensitiveActions: sensitiveActions.slice(0, 20),
  };
}
