import type { PipelineRunDetail, ProgramIntelligenceProfile, ReportPreview } from "./api";

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
    validation_budget: number;
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
  safe_next_action: string;
};

export type CampaignControlSummary = {
  agentRunCount: number;
  blockedReasons: string[];
  blockedStageCount: number;
  budgetLabel: string;
  campaignId: string;
  defaultAsset: string;
  executionAllowed: boolean;
  name: string;
  pendingApprovalCount: number;
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

export type CampaignValidationQueueSummary = {
  approvalType: string;
  asset: string | null;
  createdAt: string;
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
  finished_at?: string | null;
  id: string;
  plan_digest: string | null;
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
  finishedAt: string | null;
  id: string;
  planDigest: string | null;
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
  isManualValidationResult: boolean;
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
  sensitiveActionCount: number;
  signalCount: number;
  skippedLessonCount: number;
  topSurfaces: CampaignBrainSurfaceSummary[];
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
  runCount: number;
  status: string;
};

export type CampaignHypothesisBoardSummary = {
  brokenInvariant: string | null;
  candidateId: string;
  candidateStatus: string;
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
  reasons: string[];
  recommendation: string;
  refutationStatus: string | null;
  riskLevel: string | null;
  runId: string;
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

function budgetLabel(controlCenter: CampaignControlCenter): string {
  const budget = controlCenter.budget;

  if (!budget) {
    return "No budget configured";
  }

  return (
    [
      budgetPart(budget.time_budget_minutes, "m"),
      budgetPart(budget.token_budget, " tokens"),
      budgetPart(budget.tool_call_budget, " tools"),
      budgetPart(budget.validation_budget, " validations"),
    ]
      .filter((part): part is string => Boolean(part))
      .join(" / ") || humanize(budget.status)
  );
}

function safeNextHref(campaignId: string, action: string): string | null {
  const encodedCampaignId = encodeURIComponent(campaignId);
  const routeByAction: Record<string, string> = {
    dispatch_ready_tasks: "tasks",
    monitor_agent_runs: "agent-runs",
    review_approval_queue: "validation-queue",
    review_attack_surface_map: "attack-surface-map",
    review_evidence_or_report_drafts: "evidence-review",
    review_hypothesis_board: "hypothesis-board",
    review_learning_outcome: "brain",
    review_validation_queue: "validation-runs",
    record_learning_outcome: "report-drafts",
  };
  const route = routeByAction[action];

  return route ? `/campaigns/${encodedCampaignId}/${route}` : null;
}

export function toCampaignControlSummary(
  controlCenter: CampaignControlCenter,
): CampaignControlSummary {
  const campaignId = safeText(controlCenter.campaign.id, "campaign");
  const validationEvidence = toCampaignReportDraftEvidenceSummary(controlCenter.validation_runs ?? []);

  return {
    agentRunCount: controlCenter.agent_runs.length,
    blockedReasons: controlCenter.blocked_reasons.map((reason) => safeText(humanize(reason), "Blocked")),
    blockedStageCount: controlCenter.pipeline_stages.filter((stage) => stage.status === "blocked")
      .length,
    budgetLabel: budgetLabel(controlCenter),
    campaignId,
    defaultAsset: safeText(controlCenter.campaign.default_asset, "unknown asset"),
    executionAllowed: controlCenter.execution_allowed === true,
    name: safeText(controlCenter.campaign.name, "Untitled campaign"),
    pendingApprovalCount: controlCenter.approvals.filter((approval) => approval.status === "pending")
      .length,
    safeNextAction: safeText(humanize(controlCenter.safe_next_action), "Review campaign state"),
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
    safetyGateState: safeText(humanize(run.safety_gate_state), "Unknown gate"),
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

export function toCampaignValidationQueueSummaries(
  approvals: CampaignApproval[],
): CampaignValidationQueueSummary[] {
  return approvals.map((approval) => ({
    approvalType: safeText(humanize(approval.approval_type), "Approval"),
    asset: approval.asset ? safeText(approval.asset, "asset") : null,
    createdAt: approval.created_at,
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
    finishedAt: run.finished_at ?? null,
    id: safeText(run.id, "validation_run"),
    planDigest: run.plan_digest ? safeText(run.plan_digest, "plan") : null,
    safetyGateState: safeText(humanize(run.safety_gate_state), "Unknown gate"),
    status: safeText(humanize(run.status), "Unknown status"),
    summary: safeText(run.summary, "Summary redacted"),
    targetRef: safeText(run.target_ref, "target"),
    taskId: run.task_id ? safeText(run.task_id, "task") : null,
    validationMode: safeText(humanize(run.validation_mode), "Validation mode"),
  }));
}

export function toCampaignTimelineSummaries(
  stages: CampaignPipelineStage[],
): CampaignTimelineSummary[] {
  return stages.map((stage) => {
    const stageKey = safeText(humanize(stage.stage_key), "Stage");
    const isManualValidationResult = stage.stage_key === "validation_manual_result";

    return {
      auditLabel: isManualValidationResult ? "Manual validation result" : stageKey,
      id: safeText(stage.id, "stage"),
      inputRefCount: stage.input_refs.length,
      isManualValidationResult,
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
): CampaignFindingCandidateGateSummary {
  const claims = previews.flatMap((preview) => preview.claim_ledger);
  const eligibleClaimCount = claims.filter(
    (claim) =>
      claim.review_status === "confirmed_observed_fact" &&
      claim.readiness_level === "human_reviewed_gated" &&
      claim.readiness_blockers.length === 0 &&
      claim.review_evidence_refs.length > 0,
  ).length;

  return {
    blockedClaimCount: claims.length - eligibleClaimCount,
    eligibleClaimCount,
    manualPromotionOnly: true,
    runCount: previews.length,
    status:
      previews.length === 0
        ? "no_report_preview"
        : eligibleClaimCount > 0
          ? "ready_for_manual_promotion"
          : "blocked",
  };
}

export function toCampaignHypothesisBoardSummaries(
  runs: PipelineRunDetail[],
): CampaignHypothesisBoardSummary[] {
  return runs
    .flatMap((run) =>
      (run.payload?.hypothesis_assessments ?? []).map((assessment, index) => {
        const hypothesis = assessment.hypothesis;
        const hunter = assessment.hunter_assessment;

        return {
          brokenInvariant: hypothesis?.broken_invariant
            ? safeText(hypothesis.broken_invariant, "Invariant")
            : null,
          candidateId: safeText(assessment.candidate_id ?? `candidate_${index + 1}`, "candidate"),
          candidateStatus: safeText(humanize(assessment.candidate_status ?? "candidate"), "Candidate"),
          duplicateRiskScore: hunter?.duplicate_risk_score ?? 0,
          evidenceFocusCount: hunter?.evidence_focus?.length ?? 0,
          evidenceNeededCount: hypothesis?.evidence_needed?.length ?? 0,
          hunterPriorityScore: hunter?.hunter_priority_score ?? 0,
          hypothesis: safeText(hypothesis?.hypothesis, "Hypothesis redacted"),
          impactScore: hunter?.impact_score ?? 0,
          nextAction: hunter?.next_action ? safeText(hunter.next_action, "Next action") : null,
          playbook: safeText(hunter?.playbook_label ?? hunter?.playbook_id, "No playbook"),
          policyRisk: hypothesis?.policy_risk
            ? safeText(humanize(hypothesis.policy_risk), "Policy risk")
            : null,
          policyRiskScore: hunter?.policy_risk_score ?? 0,
          reasons: (hunter?.reasons ?? []).slice(0, 4).map((reason) => safeReasonText(reason)),
          recommendation: safeText(humanize(hunter?.recommendation ?? "needs_review"), "Recommendation"),
          refutationStatus: assessment.refutation?.status
            ? safeText(humanize(assessment.refutation.status), "Refutation")
            : null,
          riskLevel: hypothesis?.risk_level ? safeText(humanize(hypothesis.risk_level), "Risk") : null,
          runId: safeText(run.id, "run"),
          validationMode: hypothesis?.validation_mode
            ? safeText(humanize(hypothesis.validation_mode), "Validation mode")
            : null,
        };
      }),
    )
    .sort((left, right) => right.hunterPriorityScore - left.hunterPriorityScore);
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
