import type { ArtifactRecord, PipelineRunDetail, ProgramIntelligenceProfile, ReportPreview } from "./api";

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
    id: string;
    input_refs: string[];
    output_refs: string[];
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
    execution_allowed: boolean;
    next_allowed_action: string;
    playbook_id: string;
    priority_score: number;
    queue_key: string;
    safety_gate: string;
    source: string;
    surface_key: string | null;
    title: string;
  }[];
  research_review_plans?: CampaignResearchReviewPlan[];
  safe_next_action: string;
};

export type CampaignPromotionReview = {
  blocked_attempt_count: number;
  finding_promotion_allowed: false;
  latest_reason: string | null;
  next_allowed_action: string;
  provenance_ref_count: number;
  report_submission_allowed: false;
};

export type CampaignResearchQueueSuggestion = {
  executionAllowed: boolean;
  nextAllowedAction: string;
  playbookId: string;
  priorityScore: number;
  queueKey: string;
  safetyGate: string;
  source: string;
  surfaceKey: string | null;
  title: string;
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
  promotionReviewReportSubmissionAllowed: boolean;
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
  surface_key: string | null;
  task_id: string;
  title: string;
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
  campaignId: string;
  dispatchAllowed: boolean;
  executionAllowed: boolean;
  latestRefutationDecision: CampaignResearchRefutationDecisionSummary | null;
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

export type CampaignResearchValidationFeedbackSummary = {
  approvalId: string;
  campaignId: string;
  decisionId: string;
  dispatchAllowed: boolean;
  evidenceRefCount: number;
  executionAllowed: boolean;
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
  nextAllowedAction: string;
  planId: string;
  promotionGateReason: string;
  promotionProvenanceRefCount: number;
  reviewTitle: string;
  taskId: string;
  validationRunId: string;
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
  createdAt: string;
  evidenceRefCount: number;
  executionStarted: boolean;
  executionState: string;
  finishedAt: string | null;
  id: string;
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
  auditLabel: string;
  id: string;
  inputRefCount: number;
  isCycleReview: boolean;
  isFindingPromotionBlocked?: boolean;
  isLearningOutcome: boolean;
  isManualValidationResult: boolean;
  isResearchValidationFeedback?: boolean;
  outputRefCount: number;
  safetyGateState: string;
  stageKey: string;
  stageOrder: number;
  status: string;
  stopReason: string | null;
  taskId: string | null;
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
  promotionAuditLatestReason: string | null;
  researchEvidenceRefCount: number;
  researchFeedbackCount: number;
  researchPromotionBlockedCount: number;
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
  validationMode: string | null;
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
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase()
    .replace(/^\w/, (letter) => letter.toUpperCase());
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
    return fallback;
  }

  if (/\b(scanner stdout|policy text|raw payload|raw evidence)\b/i.test(text)) {
    return fallback;
  }

  const protectedValues: string[] = [];
  const protect = (value: string) => {
    protectedValues.push(value);
    return `__SAFE_REDACTION_${protectedValues.length - 1}__`;
  };

  return stripUrlQuery(text)
    .replace(
      /\bauthorization\b\s*[:=]\s*(?:bearer\s+)?[^,;\s]+/gi,
      () => protect("Authorization=[redacted]"),
    )
    .replace(
      /\b(session|token|cookie)\b\s*[:=]\s*[^,;\s]+/gi,
      (match, key: string) => protect(`${key}=[redacted]`),
    )
    .replace(/\bbearer\s+[^,;\s]+/gi, () => protect("Bearer [redacted]"))
    .replace(/\b[^\s,;]*(?:secret|token|cookie|session)[^\s,;]*\b/gi, "[redacted]")
    .replace(/__SAFE_REDACTION_(\d+)__/g, (_, index: string) => protectedValues[Number(index)] ?? "[redacted]");
}

function safeReasonText(value: string): string {
  if (/(authorization|bearer|cookie|session|secret|token)/i.test(value)) {
    return "[redacted]";
  }

  return safeText(humanize(value), "Reason");
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
    "Route",
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
    return budgetPart(limit, " tools");
  }

  const remainingLabel =
    typeof remaining === "number" && Number.isFinite(remaining)
      ? `, ${remaining} remaining`
      : "";
  return `${used}/${limit} tools used${remainingLabel}`;
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
    return budgetPart(limit, " validations");
  }

  const remainingLabel =
    typeof remaining === "number" && Number.isFinite(remaining)
      ? `, ${remaining} remaining`
      : "";
  return `${used}/${limit} validations used${remainingLabel}`;
}

export function campaignBudgetLabel(
  budget: CampaignControlCenter["budget"] | undefined,
): string {
  if (!budget) {
    return "No budget configured";
  }

  return (
    [
      budgetPart(budget.time_budget_minutes, "m"),
      budgetPart(budget.token_budget, " tokens"),
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
    complete_cycle_review: "Review campaign cycle",
    dispatch_ready_tasks: "Review research tasks",
    execute_validation: "Review validation audit",
    monitor_agent_runs: "Review agent runs",
    review_approval_queue: "Review approval requests",
    review_attack_surface_map: "Review attack surface map",
    review_blocked_promotion: "Review blocked promotion evidence",
    review_campaign_cycle: "Review campaign cycle",
    review_evidence_or_report_drafts: "Review evidence or report drafts",
    review_hypothesis_board: "Review hypothesis board",
    review_learning_outcome: "Review learning outcome",
    review_ready_tasks: "Review research tasks",
    review_validation_queue: "Review validation audit",
    record_learning_outcome: "Review learning outcome",
    resolve_blockers: "Resolve blockers",
    submit_report: "Review report drafts",
  };

  return labelByAction[action] ?? "Review campaign state";
}

function safetyGateDecisionLabel(state: string): string {
  const normalized = state.trim().toLowerCase();
  const labelByState: Record<string, string> = {
    allowed: "Scope Guard clear",
    blocked: "Scope Guard blocked",
    needs_review: "Scope Guard needs review",
    requested: "Approval review requested",
  };

  return labelByState[normalized] ?? safeText(humanize(state), "Unknown gate");
}

export function toCampaignControlSummary(
  controlCenter: CampaignControlCenter,
): CampaignControlSummary {
  const campaignId = safeText(controlCenter.campaign.id, "campaign");
  const validationEvidence = toCampaignReportDraftEvidenceSummary(controlCenter.validation_runs ?? []);
  const cycleReviewStages = controlCenter.pipeline_stages.filter(
    (stage) => stage.stage_key === "campaign_cycle_review",
  );
  const now = Date.now();

  return {
    agentRunCount: controlCenter.agent_runs.length,
    blockedReasons: controlCenter.blocked_reasons.map((reason) => safeText(humanize(reason), "Blocked")),
    blockedStageCount: controlCenter.pipeline_stages.filter((stage) => stage.status === "blocked")
      .length,
    budgetLabel: budgetLabel(controlCenter),
    campaignId,
    cycleReviewAwaitingCount: cycleReviewStages.filter((stage) => stage.status === "awaiting_review")
      .length,
    cycleReviewCompletedCount: cycleReviewStages.filter((stage) => stage.status === "completed")
      .length,
    defaultAsset: safeText(controlCenter.campaign.default_asset, "unknown asset"),
    executionAllowed: controlCenter.execution_allowed === true,
    name: safeText(controlCenter.campaign.name, "Untitled campaign"),
    pendingApprovalCount: controlCenter.approvals.filter((approval) =>
      ["pending", "requested"].includes(approval.status)
      && (approval.expires_at === null || Date.parse(approval.expires_at) > now),
    ).length,
    promotionReviewBlockedCount: Math.max(
      0,
      Math.round(controlCenter.promotion_review?.blocked_attempt_count ?? 0),
    ),
    promotionReviewFindingPromotionAllowed: false,
    promotionReviewLatestReason: controlCenter.promotion_review?.latest_reason
      ? safeText(humanize(controlCenter.promotion_review.latest_reason), "Promotion blocked")
      : null,
    promotionReviewNextAllowedAction: safeText(
      controlCenter.promotion_review?.next_allowed_action,
      "Review claim evidence and human gates before candidate promotion.",
    ),
    promotionReviewProvenanceRefCount: Math.max(
      0,
      Math.round(controlCenter.promotion_review?.provenance_ref_count ?? 0),
    ),
    promotionReviewReportSubmissionAllowed: false,
    researchQueueSuggestions: (controlCenter.research_queue_suggestions ?? []).map((suggestion) => ({
      executionAllowed: false,
      nextAllowedAction: safeText(
        suggestion.next_allowed_action,
        "Review hypothesis board and plan non-destructive evidence work.",
      ),
      playbookId: safeText(suggestion.playbook_id, "playbook"),
      priorityScore: Math.max(0, Math.min(100, Math.round(suggestion.priority_score))),
      queueKey: safeText(suggestion.queue_key, "reasoning_memory"),
      safetyGate: safeText(humanize(suggestion.safety_gate), "Advisory memory only"),
      source: safeText(humanize(suggestion.source), "Mythos brain reasoning memory"),
      surfaceKey: suggestion.surface_key ? safeText(suggestion.surface_key, "surface") : null,
      title: safeText(suggestion.title, "Review reasoning memory"),
    })),
    safeNextAction: safeNextActionLabel(controlCenter.safe_next_action),
    safeNextHref: safeNextHref(campaignId, controlCenter.safe_next_action),
    scopeStatus: safeText(humanize(controlCenter.campaign.scope_status), "Unknown scope"),
    status: safeText(humanize(controlCenter.campaign.status), "Unknown status"),
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
    agentType: safeText(humanize(run.agent_type), "Agent"),
    finishedAt: run.finished_at,
    id: safeText(run.id, "agent_run"),
    inputRefCount: run.input_refs.length,
    outputRefCount: run.output_refs.length,
    safetyGateState: safetyGateDecisionLabel(run.safety_gate_state),
    startedAt: run.created_at,
    status: safeText(humanize(run.status), "Unknown status"),
    stopReason: run.stop_reason ? safeText(humanize(run.stop_reason), "Stopped") : null,
    taskId: run.task_id ? safeText(run.task_id, "task") : null,
  }));
}

export function toCampaignTaskSummaries(
  tasks: CampaignTask[],
): CampaignTaskSummary[] {
  return tasks.map((task) => ({
    agentType: safeText(humanize(task.agent_type), "Agent"),
    createdAt: task.created_at,
    id: safeText(task.id, "task"),
    inputRefCount: task.input_refs.length,
    outputRefCount: task.output_refs.length,
    status: safeText(humanize(task.status), "Unknown status"),
    taskType: safeText(humanize(task.task_type), "Task"),
    title: safeText(task.title, "Untitled task"),
  }));
}

export function toCampaignResearchTaskReviewSummary(
  review: CampaignResearchTaskReview,
): CampaignResearchTaskReviewSummary {
  return {
    campaignId: safeText(review.campaign_id, "campaign"),
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
      "Review hypothesis board and plan non-destructive evidence work.",
    ),
    nonDestructivePlan: review.non_destructive_plan
      .slice(0, 6)
      .map((step) => safeText(step, "Plan step redacted")),
    playbookId: review.playbook_id ? safeText(review.playbook_id, "playbook") : null,
    priorityScore: Math.max(0, Math.min(100, Math.round(review.priority_score))),
    queueKey: safeText(review.queue_key, "research_queue"),
    reportSubmissionAllowed: false,
    requiredHumanGates: review.required_human_gates
      .slice(0, 6)
      .map((gate) => safeText(humanize(gate), "Human gate")),
    safetyGate: safeText(humanize(review.safety_gate), "Advisory memory only"),
    source: safeText(humanize(review.source), "Mythos brain reasoning memory"),
    status: safeText(humanize(review.status), "Queued review"),
    surfaceKey: review.surface_key ? safeText(review.surface_key, "surface") : null,
    taskId: safeText(review.task_id, "task"),
    title: safeText(review.title, "Research task review"),
  };
}

function toCampaignResearchValidationFeedbackSummary(
  feedback: CampaignResearchValidationFeedback,
): CampaignResearchValidationFeedbackSummary {
  return {
    approvalId: safeText(feedback.approval_id, "approval"),
    campaignId: safeText(feedback.campaign_id, "campaign"),
    decisionId: safeText(feedback.decision_id, "refutation_decision"),
    dispatchAllowed: false,
    evidenceRefCount: Math.max(0, Math.round(feedback.evidence_ref_count)),
    executionAllowed: false,
    findingConfirmationAllowed: false,
    nextAllowedAction: safeText(
      feedback.next_allowed_action,
      "Review validation evidence before finding promotion.",
    ),
    outcome: safeText(humanize(feedback.outcome), "Needs evidence"),
    planId: safeText(feedback.plan_id, "research_plan"),
    reportSubmissionAllowed: false,
    safetyGate: safeText(humanize(feedback.safety_gate), "Advisory validation feedback only"),
    status: safeText(humanize(feedback.status), "Evidence recorded"),
    taskId: safeText(feedback.task_id, "task"),
    validationAllowed: false,
    validationRunId: safeText(feedback.validation_run_id, "validation_run"),
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
        findingPromotionAllowed: false,
        nextAllowedAction: feedback.nextAllowedAction,
        outcome: feedback.outcome,
        planId: feedback.planId,
        promotionGate: safeText(
          humanize(promotionGate?.status ?? "manual_review_required"),
          "Manual review required",
        ),
        promotionGateReason: safeText(
          humanize(promotionGate?.reason ?? "research_validation_feedback_is_advisory"),
          "Research validation feedback is advisory",
        ),
        promotionProvenanceRefCount: Array.isArray(promotionGate?.provenance_refs)
          ? promotionGate.provenance_refs.length
          : 0,
        reviewTitle: safeText(review.title, "Research feedback review"),
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
    approvalId: decision.approval_id ? safeText(decision.approval_id, "approval") : null,
    campaignId: safeText(decision.campaign_id, "campaign"),
    decision: safeText(humanize(decision.decision), "Needs evidence"),
    decisionId: safeText(decision.decision_id, "refutation_decision"),
    dispatchAllowed: false,
    executionAllowed: false,
    nextAllowedAction: safeText(
      decision.next_allowed_action,
      "Collect redacted evidence or refine the hypothesis before validation.",
    ),
    planId: safeText(decision.plan_id, "research_plan"),
    rationale: safeReasonText(decision.rationale),
    refutationAnswers: decision.refutation_answers
      .slice(0, 8)
      .map((answer) => safeReasonText(answer)),
    reportSubmissionAllowed: false,
    taskId: safeText(decision.task_id, "task"),
    validationAllowed: false,
    validationRunId: decision.validation_run_id
      ? safeText(decision.validation_run_id, "validation_run")
      : null,
  };
}

function toCampaignResearchReviewPlanSummary(
  plan: CampaignResearchReviewPlan,
): CampaignResearchReviewPlanSummary {
  return {
    campaignId: safeText(plan.campaign_id, "campaign"),
    dispatchAllowed: false,
    evidencePlan: plan.evidence_plan.slice(0, 8).map((step) => safeReasonText(step)),
    executionAllowed: false,
    hypothesis: safeReasonText(plan.hypothesis),
    nextAllowedAction: safeText(
      plan.next_allowed_action,
      "Review hypothesis board and request approval before validation.",
    ),
    planId: safeText(plan.plan_id, "research_plan"),
    refutationQuestions: plan.refutation_questions
      .slice(0, 8)
      .map((question) => safeReasonText(question)),
    reportSubmissionAllowed: false,
    requiredHumanGates: plan.required_human_gates
      .slice(0, 6)
      .map((gate) => safeText(humanize(gate), "Human gate")),
    safetyGate: safeText(humanize(plan.safety_gate), "Advisory plan only"),
    status: safeText(humanize(plan.status), "Drafted"),
    taskId: safeText(plan.task_id, "task"),
    validationAllowed: false,
  };
}

export function toCampaignArtifactSummaries(
  artifacts: ArtifactRecord[],
): CampaignArtifactSummary[] {
  return artifacts.map((artifact) => {
    const usageRecords = artifact.usage_records ?? [];

    return {
      asset: safeText(artifact.asset, "asset"),
      createdAt: artifact.created_at,
      id: safeText(artifact.id, "artifact"),
      ingestionStatus: safeText(humanize(artifact.ingestion_status), "Unknown status"),
      kind: safeText(humanize(artifact.kind), "Artifact"),
      reportChainAllowed: artifact.report_chain_allowed === true,
      safetyBlockerCount: artifact.safety_blockers.length,
      sensitivityLabel: safeText(humanize(artifact.sensitivity_label), "Unknown sensitivity"),
      sourceType: safeText(humanize(artifact.source_type), "Source"),
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
    const label = safeText(humanize(value), "Usage");
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  return Array.from(counts, ([label, count]) => ({ count, label }));
}

export function toCampaignValidationQueueSummaries(
  approvals: CampaignApproval[],
): CampaignValidationQueueSummary[] {
  return approvals.map((approval) => ({
    approvalType: safeText(humanize(approval.approval_type), "Approval"),
    asset: approval.asset ? safeText(approval.asset, "asset") : null,
    createdAt: approval.created_at,
    expiresAt: approval.expires_at ?? null,
    id: safeText(approval.id, "approval"),
    planDigest: approval.plan_digest ? safeText(approval.plan_digest, "plan") : null,
    reason: safeText(approval.reason, "Reason redacted"),
    requestedAction: approval.requested_action
      ? safeText(humanize(approval.requested_action), "Requested action")
      : null,
    runId: approval.run_id ? safeText(approval.run_id, "run") : null,
    safetyGateState: safeText(humanize(approval.safety_gate_state), "Unknown gate"),
    status: safeText(humanize(approval.status), "Unknown status"),
    taskId: approval.task_id ? safeText(approval.task_id, "task") : null,
    validationMode: approval.validation_mode
      ? safeText(humanize(approval.validation_mode), "Validation mode")
      : null,
  }));
}

export function toCampaignValidationRunSummaries(
  runs: CampaignValidationRun[],
): CampaignValidationRunSummary[] {
  return runs.map((run) => ({
    allowedToExecute: run.allowed_to_execute === true,
    approvalId: run.approval_id ? safeText(run.approval_id, "approval") : null,
    approvalRequired: run.approval_required === true,
    createdAt: run.created_at,
    evidenceRefCount: run.evidence_ref_count,
    executionStarted: run.execution_started === true,
    executionState: validationRunExecutionState(run),
    finishedAt: run.finished_at ?? null,
    id: safeText(run.id, "validation_run"),
    planDigest: run.plan_digest ? safeText(run.plan_digest, "plan") : null,
    preflightPassed: validationRunPreflightPassed(run),
    safetyGateState: safeText(humanize(run.safety_gate_state), "Unknown gate"),
    status: safeText(humanize(run.status), "Unknown status"),
    summary: safeText(run.summary, "Summary redacted"),
    targetRef: safeText(run.target_ref, "target"),
    taskId: run.task_id ? safeText(run.task_id, "task") : null,
    validationMode: safeText(humanize(run.validation_mode), "Validation mode"),
  }));
}

function validationRunExecutionState(run: CampaignValidationRun): string {
  if (run.execution_started === true) {
    return "Validation started";
  }
  if (validationRunPreflightPassed(run)) {
    return "Preflight passed";
  }
  if (
    run.approval_required === true
    && run.approval_id
    && run.status === "ready"
    && run.safety_gate_state === "approved_validation_record"
  ) {
    return "Preflight required";
  }
  if (run.approval_required === true && !run.approval_id) {
    return "Awaiting approval";
  }
  return "Preflight blocked";
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
    const stageKey = safeText(humanize(stage.stage_key), "Stage");
    const isCycleReview = stage.stage_key === "campaign_cycle_review";
    const isLearningOutcome = stage.stage_key === "learning_outcome_recorded";
    const isManualValidationResult = stage.stage_key === "validation_manual_result";
    const isFindingPromotionBlocked = stage.stage_key === "finding_promotion_blocked";
    const isResearchValidationFeedback =
      stage.stage_key === "research_task_validation_feedback";

    return {
      auditLabel: isCycleReview
        ? "Campaign cycle review"
        : isLearningOutcome
          ? "Advisory Brain learning"
          : isManualValidationResult
            ? "Manual validation result"
            : isFindingPromotionBlocked
              ? "Finding promotion blocked"
              : isResearchValidationFeedback
                ? "Research validation feedback"
                : stageKey,
      id: safeText(stage.id, "stage"),
      inputRefCount: stage.input_refs.length,
      isCycleReview,
      ...(isFindingPromotionBlocked ? { isFindingPromotionBlocked: true } : {}),
      isLearningOutcome,
      isManualValidationResult,
      ...(isResearchValidationFeedback ? { isResearchValidationFeedback: true } : {}),
      outputRefCount: stage.output_refs.length,
      safetyGateState: safeText(humanize(stage.safety_gate_state), "Unknown gate"),
      stageKey,
      stageOrder: stage.stage_order,
      status: safeText(humanize(stage.status), "Unknown status"),
      stopReason: stage.stop_reason ? safeText(humanize(stage.stop_reason), "Stopped") : null,
      taskId: stage.task_id ? safeText(stage.task_id, "task") : null,
    };
  });
}

export function toCampaignBrainSummary(
  profile: ProgramIntelligenceProfile,
): CampaignBrainSummary {
  return {
    advisoryOnly: true,
    appliedLessonCount: profile.applied_lessons.length,
    appliedLessons: profile.applied_lessons.slice(0, 5).map((lesson) => ({
      confidence: lesson.confidence,
      id: safeText(lesson.id, "lesson"),
      recommendation: safeText(humanize(lesson.recommendation), "Recommendation"),
      reasons: lesson.reasons.slice(0, 4).map((reason) => safeReasonText(reason)),
      scoreDelta: lesson.score_delta,
      surfacePattern: safeText(lesson.surface_pattern, "Surface"),
    })),
    executionAllowed: false,
    objectCount: profile.attack_surface_memory.objects.length,
    programId: safeText(profile.program_id, "program"),
    programName: safeText(profile.program_name, "Program"),
    programScore: profile.program_score,
    recentSignals: profile.recent_learning_signals.slice(0, 5).map((signal) => ({
      evidenceQuality: signal.evidence_quality
        ? safeText(humanize(signal.evidence_quality), "Evidence quality")
        : null,
      id: safeText(signal.id ?? "signal", "signal"),
      notes: safeText(signal.notes, "Notes redacted"),
      outcome: safeText(humanize(signal.outcome), "Outcome"),
      playbookId: safeText(signal.playbook_id, "playbook"),
      surfaceKey: signal.surface_key ? safeText(signal.surface_key, "surface") : null,
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
          playbookId: safeText(playbook.playbook_id, "playbook"),
        })),
    },
    sensitiveActionCount: profile.attack_surface_memory.sensitive_actions.length,
    signalCount: profile.recent_learning_signals.length,
    skippedLessonCount: profile.skipped_lessons.length,
    topSurfaces: profile.high_value_surfaces.slice(0, 5).map((surface) => ({
      action: safeText(humanize(surface.action), "Action"),
      objectName: safeText(surface.object_name, "Object"),
      path: safeText(surface.paths[0] ?? "", "No path"),
      score: surface.score,
      surfaceKey: safeText(surface.surface_key, "surface"),
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
    commitRef: map.commit_ref ? safeText(map.commit_ref, "commit") : null,
    createdAt: map.created_at,
    handlerCount: map.handler_count,
    id: safeText(map.id, "codebase_map"),
    modelCount: map.model_count,
    repository: safeText(map.repository, "repository"),
    routeCount: map.route_count,
    safetyGateState: safeText(humanize(map.safety_gate_state), "Unknown gate"),
    sensitiveSinkCount: map.sensitive_sink_count,
    sourceRef: safeText(map.source_ref, "source"),
    status: safeText(humanize(map.status), "Unknown status"),
  }));
  const facts = codebaseMap.facts.map((fact) => ({
    authzHint: fact.authz_hint ? safeText(humanize(fact.authz_hint), "Authz hint") : null,
    factType: safeText(humanize(fact.fact_type), "Fact"),
    id: safeText(fact.id, "fact"),
    route:
      fact.route_method || fact.route_path
        ? safeText(`${fact.route_method ?? ""} ${fact.route_path ?? ""}`.trim(), "Route")
        : null,
    sensitivityLabel: safeText(humanize(fact.sensitivity_label), "Sensitivity"),
    sourcePath: safeText(fact.source_path, "source"),
    symbolName: fact.symbol_name ? safeText(fact.symbol_name, "symbol") : null,
  }));
  const scannerRuns = codebaseMap.scanner_runs.map((run) => ({
    candidateCount: run.candidate_count,
    commandHash: safeText(run.command_hash, "command"),
    findingCount: run.finding_count,
    id: safeText(run.id, "scanner_run"),
    safetyGateState: safeText(humanize(run.safety_gate_state), "Unknown gate"),
    status: safeText(humanize(run.status), "Unknown status"),
    summary: safeText(run.summary, "Summary redacted"),
    toolName: safeText(run.tool_name, "tool"),
  }));

  return {
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

export function toCampaignEvidenceReviewSummaries(
  previews: ReportPreview[],
): CampaignEvidenceReviewSummary[] {
  return previews.flatMap((preview) =>
    preview.claim_ledger.map((claim) => ({
      claimId: safeText(claim.claim_id, "claim"),
      claimText: safeText(claim.text, "Claim text redacted"),
      claimType: safeText(humanize(claim.claim_type), "Claim"),
      evidenceRefCount: claim.evidence_refs.length,
      humanReviewRequired: claim.human_review_required === true,
      provenanceRefCount: claim.provenance_refs.length,
      qualityScore: claim.quality_score,
      readinessBlockers: claim.readiness_blockers.map((blocker) =>
        safeText(humanize(blocker), "Blocker"),
      ),
      readinessLevel: safeText(humanize(claim.readiness_level), "Readiness"),
      redactionStatus: safeText(humanize(claim.redaction_status), "Redaction"),
      reportChainEligible:
        claim.review_status === "confirmed_observed_fact" &&
        claim.readiness_level === "human_reviewed_gated" &&
        claim.readiness_blockers.length === 0 &&
        claim.review_evidence_refs.length > 0,
      reviewEvidenceRefCount: claim.review_evidence_refs.length,
      reviewRationale: claim.review_rationale
        ? safeText(claim.review_rationale, "Review rationale redacted")
        : null,
      reviewStatus: safeText(humanize(claim.review_status), "Review status"),
      runId: safeText(preview.run_id, "run"),
      status: safeText(humanize(claim.status), "Status"),
    })),
  );
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
      runId: safeText(preview.run_id, "run"),
      safetyNotes: preview.safety_notes
        .slice(0, 4)
        .map((note) => safeText(/[_-]/.test(note) ? humanize(note) : note, "Safety note")),
      scopeStatus: safeText(humanize(preview.scope_status), "Unknown scope"),
      severity: safeText(humanize(preview.severity), "Unknown severity"),
      submissionBlocked: preview.submission_blocked === true,
      title: safeText(preview.title, "Untitled report draft"),
      topClaims: preview.claim_ledger.slice(0, 3).map((claim) =>
        safeText(claim.text, "Claim text redacted"),
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

export function toCampaignFindingCandidateGateSummary(
  previews: ReportPreview[],
  researchFeedbackEvidence: CampaignResearchFeedbackEvidenceSummary[] = [],
  pipelineStages: CampaignPipelineStage[] = [],
): CampaignFindingCandidateGateSummary {
  const claims = previews.flatMap((preview) => preview.claim_ledger);
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
  const status =
    previews.length === 0
      ? "no_report_preview"
      : promotionBlockedStages.length > 0
        ? "blocked_by_promotion_audit"
        : eligibleClaimCount > 0
        ? "ready_for_manual_promotion"
        : "blocked";

  return {
    blockedClaimCount: claims.length - eligibleClaimCount,
    eligibleClaimCount,
    manualPromotionOnly: true,
    nextAllowedAction:
      status === "blocked_by_promotion_audit"
        ? "Review blocked promotion evidence before retrying candidate promotion."
        : status === "ready_for_manual_promotion"
        ? "Review eligible claims and promote manually after human approval."
        : "Complete claim review and evidence checks before promotion.",
    promotionAuditBlockedCount: promotionBlockedStages.length,
    promotionAuditLatestReason: latestPromotionBlock?.stop_reason
      ? safeText(humanize(latestPromotionBlock.stop_reason), "Promotion blocked")
      : null,
    researchEvidenceRefCount: researchFeedbackEvidence.reduce(
      (total, feedback) => total + feedback.evidenceRefCount,
      0,
    ),
    researchFeedbackCount: researchFeedbackEvidence.length,
    researchPromotionBlockedCount: researchFeedbackEvidence.filter(
      (feedback) => feedback.findingPromotionAllowed === false,
    ).length,
    runCount: previews.length,
    status,
  };
}

export function toCampaignHypothesisBoardSummaries(
  runs: PipelineRunDetail[],
  researchPlans: CampaignResearchReviewPlan[] = [],
): CampaignHypothesisBoardSummary[] {
  const runCandidates = runs
    .flatMap((run) =>
      (run.payload?.hypothesis_assessments ?? []).map((assessment, index) => {
        const hypothesis = assessment.hypothesis;
        const hunter = assessment.hunter_assessment;
        const exploitChain = asRecord(assessment.exploit_chain);
        const primitives = stringList(exploitChain.primitives)
          .slice(0, 3)
          .map((primitive) => safeText(primitive, "Primitive"));
        const preconditions = stringList(exploitChain.preconditions)
          .slice(0, 3)
          .map((precondition) => safeText(precondition, "Precondition"));
        const refutationQuestions = stringList(assessment.refutation?.questions)
          .slice(0, 3)
          .map((question) => safeText(question, "Refutation question"));
        const primitiveCount = stringList(exploitChain.primitives).length;
        const preconditionCount = stringList(exploitChain.preconditions).length;
        const refutationQuestionCount = stringList(assessment.refutation?.questions).length;
        const hunterPriorityScore = hunter?.hunter_priority_score ?? 0;

        return {
          brokenInvariant: hypothesis?.broken_invariant
            ? safeText(hypothesis.broken_invariant, "Invariant")
            : null,
          candidateId: safeText(assessment.candidate_id ?? `candidate_${index + 1}`, "candidate"),
          candidateStatus: safeText(humanize(assessment.candidate_status ?? "candidate"), "Candidate"),
          chainConfidence: percentScore(exploitChain.confidence),
          chainImpact: stringValue(exploitChain.impact) ? safeText(stringValue(exploitChain.impact), "Chain impact") : null,
          duplicateRiskScore: hunter?.duplicate_risk_score ?? 0,
          evidenceFocusCount: hunter?.evidence_focus?.length ?? 0,
          evidenceNeededCount: hypothesis?.evidence_needed?.length ?? 0,
          hunterPriorityScore,
          hypothesis: safeText(hypothesis?.hypothesis, "Hypothesis redacted"),
          impactScore: hunter?.impact_score ?? 0,
          nextAction: hunter?.next_action ? safeText(hunter.next_action, "Next action") : null,
          playbook: safeText(hunter?.playbook_label ?? hunter?.playbook_id, "No playbook"),
          policyRisk: hypothesis?.policy_risk
            ? safeText(humanize(hypothesis.policy_risk), "Policy risk")
            : null,
          policyRiskScore: hunter?.policy_risk_score ?? 0,
          preconditionCount,
          preconditions,
          primitiveCount,
          primitives,
          reasons: (hunter?.reasons ?? []).slice(0, 4).map((reason) => safeReasonText(reason)),
          recommendation: safeText(humanize(hunter?.recommendation ?? "needs_review"), "Recommendation"),
          refutationQuestionCount,
          refutationQuestions,
          refutationStatus: assessment.refutation?.status
            ? safeText(humanize(assessment.refutation.status), "Refutation")
            : null,
          reviewPriorityScore: reviewPriorityScore(
            hunterPriorityScore,
            primitiveCount,
            preconditionCount,
            refutationQuestionCount,
          ),
          riskLevel: hypothesis?.risk_level ? safeText(humanize(hypothesis.risk_level), "Risk") : null,
          runId: safeText(run.id, "run"),
          source: "Pipeline run",
          validationMode: hypothesis?.validation_mode
            ? safeText(humanize(hypothesis.validation_mode), "Validation mode")
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
      candidateId: safeText(plan.plan_id, "research_plan"),
      candidateStatus: safeText(humanize(plan.status), "Drafted"),
      chainConfidence: null,
      chainImpact: null,
      duplicateRiskScore: 0,
      evidenceFocusCount: evidencePlanCount,
      evidenceNeededCount: evidencePlanCount,
      hunterPriorityScore: 50,
      hypothesis: safeText(plan.hypothesis, "Hypothesis redacted"),
      impactScore: 0,
      nextAction: safeText(
        plan.next_allowed_action,
        "Review hypothesis board and request approval before validation.",
      ),
      playbook: safeText(humanize(plan.safety_gate), "Advisory plan only"),
      policyRisk: null,
      policyRiskScore: 0,
      preconditionCount: 0,
      preconditions: [],
      primitiveCount: 0,
      primitives: [],
      reasons: plan.required_human_gates
        .slice(0, 4)
        .map((gate) => safeText(humanize(gate), "Human gate")),
      recommendation: "Needs review",
      refutationQuestionCount,
      refutationQuestions,
      refutationStatus: null,
      reviewPriorityScore: reviewPriorityScore(50 + evidencePlanCount * 3, 0, 0, refutationQuestionCount),
      riskLevel: null,
      runId: safeText(plan.campaign_id, "campaign"),
      source: "Research review plan",
      validationMode: "Review only",
    };
  });

  return [...runCandidates, ...planCandidates]
    .sort((left, right) => right.reviewPriorityScore - left.reviewPriorityScore);
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
    const runId = safeText(run.id, "run");
    const targetModel = asRecord(run.payload?.target_model);

    for (const endpointValue of asArray(targetModel.endpoints)) {
      const endpoint = asRecord(endpointValue);
      endpoints.push({
        route: routeLabel(endpoint.method, endpoint.path),
        runId,
        summary: stringValue(endpoint.summary) ? safeText(stringValue(endpoint.summary), "Summary") : null,
      });
    }

    for (const objectValue of asArray(targetModel.objects)) {
      const object = asRecord(objectValue);
      objects.push({
        identifierCount: stringList(object.identifiers).length,
        name: safeText(stringValue(object.name), "Object"),
        runId,
      });
    }

    for (const role of stringList(targetModel.roles)) {
      roles.add(safeText(role, "Role"));
    }

    for (const actionValue of asArray(targetModel.sensitive_actions)) {
      const action = asRecord(actionValue);
      sensitiveActions.push({
        action: safeText(stringValue(action.action), "Action"),
        roleCount: stringList(action.roles).length,
        route: routeLabel(action.method, action.path),
        runId,
      });
    }

    for (const relationshipValue of asArray(targetModel.relationships)) {
      const relationship = asRecord(relationshipValue);
      const parent = safeText(stringValue(relationship.parent_object), "Parent");
      const child = safeText(stringValue(relationship.child_object), "Child");
      relationships.push({
        pathCount: stringList(relationship.paths).length,
        relationship: safeText(stringValue(relationship.relationship), "Relationship"),
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
