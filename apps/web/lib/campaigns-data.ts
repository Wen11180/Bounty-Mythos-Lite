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

  return stripUrlQuery(text)
    .replace(
      /\b(session|secret|token|authorization|cookie)\b\s*[:=]\s*[^,;\s]+/gi,
      "$1=[redacted]",
    )
    .replace(/\b(secret|token|authorization|cookie|session)\b/gi, "[redacted]");
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
