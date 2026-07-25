/**
 * Safe Autopilot projection helpers for Control Center / Studio / campaign pages.
 * Never expects secrets, cookies, tokens, or raw response bodies.
 */

export type AutopilotBudgetProjection = {
  budget_ledger_valid: boolean;
  campaign_max_requests: number;
  campaign_requests_used: number;
  campaign_requests_remaining: number;
  campaign_max_duration_seconds: number;
  campaign_duration_reserved_seconds: number;
  campaign_duration_remaining_seconds: number;
  campaign_max_cost_units: number;
  campaign_cost_units_reserved: number;
  campaign_cost_units_remaining: number;
  active_leases: number;
  reserved_requests: number;
  completed_requests: number;
  open_approvals: number;
};

export type AutopilotCampaignProjection = {
  campaign_id: string;
  campaign_mode: string;
  projection_generated_at?: string | null;
  emergency_stopped: boolean;
  authorization_digest: string | null;
  scope_snapshot_digest: string | null;
  policy_mode: string | null;
  next_branch_id: string | null;
  next_reason: string | null;
  budgets: AutopilotBudgetProjection;
  assets: Array<Record<string, unknown>>;
  branches: Array<Record<string, unknown>>;
  approvals: Array<Record<string, unknown>>;
  events: Array<Record<string, unknown>>;
  candidate_promotion_allowed: false;
  report_submission_allowed: false;
  submission_blocked: true;
};

export type AutopilotDataState = "live" | "stale" | "unavailable";

export const AUTOPILOT_PROJECTION_MAX_AGE_MS = 120_000;

export function formatAutopilotDataState(state: AutopilotDataState): string {
  switch (state) {
    case "live":
      return "实时数据";
    case "stale":
      return "数据已过期，执行状态未知";
    case "unavailable":
      return "数据不可用，执行状态未知";
  }
}

export function classifyAutopilotProjectionFreshness(
  projection: AutopilotCampaignProjection,
  now = Date.now(),
  maxAgeMs = AUTOPILOT_PROJECTION_MAX_AGE_MS,
): "fresh" | "stale" {
  if (!projection.projection_generated_at) {
    return "stale";
  }
  const generatedAt = Date.parse(projection.projection_generated_at);
  if (!Number.isFinite(generatedAt) || generatedAt > now) {
    return "stale";
  }
  return now - generatedAt <= maxAgeMs ? "fresh" : "stale";
}

export type AutopilotAssetStatus =
  | "discovered"
  | "admitted"
  | "parked"
  | "blocked"
  | "review_required"
  | "unknown";

export function emptyAutopilotProjection(
  campaignId: string,
): AutopilotCampaignProjection {
  return {
    campaign_id: campaignId,
    campaign_mode: "bounty_autopilot",
    projection_generated_at: null,
    emergency_stopped: false,
    authorization_digest: null,
    scope_snapshot_digest: null,
    policy_mode: null,
    next_branch_id: null,
    next_reason: "no_eligible_branch",
    budgets: {
      budget_ledger_valid: true,
      campaign_max_requests: 0,
      campaign_requests_used: 0,
      campaign_requests_remaining: 0,
      campaign_max_duration_seconds: 0,
      campaign_duration_reserved_seconds: 0,
      campaign_duration_remaining_seconds: 0,
      campaign_max_cost_units: 0,
      campaign_cost_units_reserved: 0,
      campaign_cost_units_remaining: 0,
      active_leases: 0,
      reserved_requests: 0,
      completed_requests: 0,
      open_approvals: 0,
    },
    assets: [],
    branches: [],
    approvals: [],
    events: [],
    candidate_promotion_allowed: false,
    report_submission_allowed: false,
    submission_blocked: true,
  };
}

export function summarizeAutopilotProjection(
  projection: AutopilotCampaignProjection,
): string {
  if (projection.emergency_stopped) {
    return "紧急停止已启用，所有租约已撤销";
  }
  if (!projection.budgets.budget_ledger_valid) {
    return "执行已阻断：授权预算账本无效";
  }
  if (projection.next_branch_id) {
    return `下一分支：${projection.next_branch_id}（${formatAutopilotLabel(projection.next_reason ?? "eligible")}）`;
  }
  const reason = projection.next_reason ?? "no_eligible_branch";
  if (reason === "no_eligible_branch") {
    return "没有可执行的分支";
  }
  return formatAutopilotLabel(reason);
}

export function formatAutopilotLabel(value: unknown): string {
  const normalized = String(value ?? "unknown").trim().toLowerCase();
  const labels: Record<string, string> = {
    active: "生效中",
    admitted: "已准入",
    already_consumed: "审批已使用",
    already_decided: "审批已处理",
    approved: "已批准",
    awaiting_human: "等待人工处理",
    awaiting_r3: "等待 R3 审批",
    blocked: "已阻断",
    bounty_autopilot: "漏洞赏金自动驾驶",
    candidate: "候选",
    completed: "已完成",
    denied: "已拒绝",
    discovered: "已发现",
    draft: "草稿",
    emergency_stopped: "紧急停止已启用",
    eligible: "可执行",
    event: "事件",
    expired: "已过期",
    highest_priority_eligible: "最高优先级的可执行分支",
    issued: "已签发",
    lease: "租约",
    no_eligible_branch: "没有可执行的分支",
    no_send_failure: "未发送失败",
    not_pending: "不在待审批状态",
    observation: "观察记录",
    parked: "已暂停",
    plan: "计划",
    policy_mode_blocks_active_execution: "当前策略模式阻断执行",
    authorization_budget_ledger_invalid: "授权预算账本无效，执行已阻断",
    ready: "已就绪",
    queued: "排队中",
    r4_prohibited: "R4 风险等级不可批准",
    reserved: "已预留",
    report: "报告",
    revoked: "已撤销",
    sent: "已发送",
    requested: "已请求",
    review_required: "需要审核",
    risk: "风险",
    tool_run: "工具运行",
    unknown: "未知",
    used: "已使用",
  };
  return labels[normalized] ?? "未知";
}

export function classifyAutopilotAssetStatus(
  raw: unknown,
): AutopilotAssetStatus {
  const value = String(raw ?? "")
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, "_");
  if (
    value === "discovered" ||
    value === "admitted" ||
    value === "parked" ||
    value === "blocked" ||
    value === "review_required"
  ) {
    return value;
  }
  if (value === "review" || value === "needs_review") {
    return "review_required";
  }
  return "unknown";
}

export function orderAutopilotTimeline(
  events: Array<Record<string, unknown>>,
): Array<Record<string, unknown>> {
  const rank = (kind: string): number => {
    const order = [
      "plan",
      "risk",
      "lease",
      "tool_run",
      "observation",
      "refutation",
      "candidate",
      "report",
    ];
    const normalized = kind.toLowerCase();
    const idx = order.findIndex((item) => normalized.includes(item));
    return idx === -1 ? 99 : idx;
  };
  return [...events].sort((left, right) => {
    const leftAt = String(left.created_at ?? "");
    const rightAt = String(right.created_at ?? "");
    if (leftAt !== rightAt) {
      return leftAt < rightAt ? -1 : 1;
    }
    return rank(String(left.kind ?? "")) - rank(String(right.kind ?? ""));
  });
}

export function canDecideAutopilotApproval(
  approval: Record<string, unknown>,
): { allowed: boolean; reason: string } {
  const status = String(approval.status ?? "").toLowerCase();
  const risk = String(approval.risk_tier ?? "").toUpperCase();
  if (risk === "R4") {
    return { allowed: false, reason: "R4 风险等级不可批准" };
  }
  if (approval.consumed === true || status === "used" || status === "consumed") {
    return { allowed: false, reason: "审批已使用" };
  }
  if (approval.expired === true || status === "expired") {
    return { allowed: false, reason: "审批已过期" };
  }
  if (status === "approved" || status === "denied" || status === "revoked") {
    return { allowed: false, reason: "审批已处理" };
  }
  if (status !== "pending" && status !== "requested" && status !== "awaiting") {
    return { allowed: false, reason: "不在待审批状态" };
  }
  return { allowed: true, reason: "待处理" };
}

export function budgetMonitorRows(
  budgets: AutopilotBudgetProjection,
): Array<{ label: string; value: string }> {
  return [
    ...(budgets.budget_ledger_valid
      ? []
      : [{ label: "账本状态", value: "执行已阻断：授权预算账本无效" }]),
    {
      label: "项目请求",
      value: `${budgets.campaign_requests_used}/${budgets.campaign_max_requests || "∞"}（剩余 ${budgets.campaign_requests_remaining}）`,
    },
    {
      label: "时长预留",
      value: `${budgets.campaign_duration_reserved_seconds}/${budgets.campaign_max_duration_seconds || "∞"} 秒（剩余 ${budgets.campaign_duration_remaining_seconds}）`,
    },
    {
      label: "成本预留",
      value: `${budgets.campaign_cost_units_reserved}/${budgets.campaign_max_cost_units || "∞"}（剩余 ${budgets.campaign_cost_units_remaining}）`,
    },
    { label: "生效租约", value: String(budgets.active_leases) },
    { label: "已预留请求", value: String(budgets.reserved_requests) },
    { label: "已完成请求", value: String(budgets.completed_requests) },
    { label: "待审批项", value: String(budgets.open_approvals) },
  ];
}
