import type { ProgramIntelligenceProfile } from "./api";

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
  scopeStatus: string;
  status: string;
  taskCount: number;
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

export type CampaignTimelineSummary = {
  id: string;
  inputRefCount: number;
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

export function toCampaignControlSummary(
  controlCenter: CampaignControlCenter,
): CampaignControlSummary {
  return {
    agentRunCount: controlCenter.agent_runs.length,
    blockedReasons: controlCenter.blocked_reasons.map((reason) => safeText(humanize(reason), "Blocked")),
    blockedStageCount: controlCenter.pipeline_stages.filter((stage) => stage.status === "blocked")
      .length,
    budgetLabel: budgetLabel(controlCenter),
    campaignId: safeText(controlCenter.campaign.id, "campaign"),
    defaultAsset: safeText(controlCenter.campaign.default_asset, "unknown asset"),
    executionAllowed: controlCenter.execution_allowed === true,
    name: safeText(controlCenter.campaign.name, "Untitled campaign"),
    pendingApprovalCount: controlCenter.approvals.filter((approval) => approval.status === "pending")
      .length,
    safeNextAction: safeText(humanize(controlCenter.safe_next_action), "Review campaign state"),
    scopeStatus: safeText(humanize(controlCenter.campaign.scope_status), "Unknown scope"),
    status: safeText(humanize(controlCenter.campaign.status), "Unknown status"),
    taskCount: controlCenter.tasks.length,
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

export function toCampaignTimelineSummaries(
  stages: CampaignPipelineStage[],
): CampaignTimelineSummary[] {
  return stages.map((stage) => ({
    id: safeText(stage.id, "stage"),
    inputRefCount: stage.input_refs.length,
    outputRefCount: stage.output_refs.length,
    safetyGateState: safeText(humanize(stage.safety_gate_state), "Unknown gate"),
    stageKey: safeText(humanize(stage.stage_key), "Stage"),
    stageOrder: stage.stage_order,
    status: safeText(humanize(stage.status), "Unknown status"),
    stopReason: stage.stop_reason ? safeText(humanize(stage.stop_reason), "Stopped") : null,
    taskId: stage.task_id ? safeText(stage.task_id, "task") : null,
  }));
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
