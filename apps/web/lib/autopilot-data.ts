/**
 * Display-safe Autopilot projection helpers for Control Center, Studio, and
 * campaign pages. Raw API objects must pass through the parser before render.
 */

export type AutopilotBudgetProjection = {
  campaign_max_requests: number;
  campaign_requests_used: number;
  campaign_requests_remaining: number;
  active_leases: number;
  reserved_requests: number;
  completed_requests: number;
  open_approvals: number;
  asset_requests_remaining: number | null;
  account_requests_remaining: number | null;
  branch_requests_remaining: number | null;
  hypothesis_requests_remaining: number | null;
  recipe_requests_remaining: number | null;
  request_slots_remaining: number | null;
  time_seconds_remaining: number | null;
  retry_attempts_remaining: number | null;
  model_cost_units_remaining: number | null;
};

export type AutopilotAssetStatus =
  | "discovered"
  | "admitted"
  | "parked"
  | "blocked"
  | "review_required"
  | "unknown";

export type AutopilotAssetProjection = {
  asset_id: string;
  alias: string | null;
  status: AutopilotAssetStatus;
  host: string | null;
  scheme: string | null;
  port: number | null;
  admitted: boolean;
  reason: string | null;
};

export type AutopilotBranchProjection = {
  branch_id: string;
  asset_id: string;
  status: string;
  priority: number;
  risk_tier: string | null;
  reason: string | null;
  dependencies: string[];
  handoff_from: string | null;
  handoff_to: string | null;
  specialist: string | null;
  queue_rank: number | null;
};

export type AutopilotExactDiffProjection = {
  field: string;
  before: string;
  after: string;
};

export type AutopilotApprovalProjection = {
  approval_id: string;
  status: string;
  plan_digest: string | null;
  risk_tier: string | null;
  consumed: boolean;
  expired: boolean;
  plan_changed: boolean;
  expires_at: string | null;
  exact_diff: AutopilotExactDiffProjection[];
};

export type AutopilotEventRefKey =
  | "branch_id"
  | "candidate_id"
  | "lease_id"
  | "observation_id"
  | "plan_digest"
  | "plan_id"
  | "recipe_id"
  | "refutation_id"
  | "report_id"
  | "risk_id"
  | "tool_run_id";

export type AutopilotEventProjection = {
  event_id: string;
  kind: string;
  summary: string;
  created_at: string | null;
  refs: Partial<Record<AutopilotEventRefKey, string>>;
};

export type AutopilotCampaignProjection = {
  campaign_id: string;
  campaign_mode: string;
  emergency_stopped: boolean;
  authorization_digest: string | null;
  scope_snapshot_digest: string | null;
  policy_mode: string | null;
  next_branch_id: string | null;
  next_reason: string | null;
  budgets: AutopilotBudgetProjection;
  assets: AutopilotAssetProjection[];
  branches: AutopilotBranchProjection[];
  approvals: AutopilotApprovalProjection[];
  events: AutopilotEventProjection[];
  candidate_promotion_allowed: false;
  report_submission_allowed: false;
  submission_blocked: true;
};

const eventRefKeys: AutopilotEventRefKey[] = [
  "branch_id",
  "candidate_id",
  "lease_id",
  "observation_id",
  "plan_digest",
  "plan_id",
  "recipe_id",
  "refutation_id",
  "report_id",
  "risk_id",
  "tool_run_id",
];

const sensitiveTextPattern =
  /\b(?:api[_-]?key|authorization|bearer|cookie|credential|password|secret|session|token)\b|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i;

export function emptyAutopilotProjection(
  campaignId: string,
): AutopilotCampaignProjection {
  return {
    campaign_id: safeIdentifier(campaignId, "campaign"),
    campaign_mode: "bounty_autopilot",
    emergency_stopped: false,
    authorization_digest: null,
    scope_snapshot_digest: null,
    policy_mode: null,
    next_branch_id: null,
    next_reason: "no_eligible_branch",
    budgets: {
      campaign_max_requests: 0,
      campaign_requests_used: 0,
      campaign_requests_remaining: 0,
      active_leases: 0,
      reserved_requests: 0,
      completed_requests: 0,
      open_approvals: 0,
      asset_requests_remaining: null,
      account_requests_remaining: null,
      branch_requests_remaining: null,
      hypothesis_requests_remaining: null,
      recipe_requests_remaining: null,
      request_slots_remaining: null,
      time_seconds_remaining: null,
      retry_attempts_remaining: null,
      model_cost_units_remaining: null,
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

export function parseAutopilotCampaignProjection(
  raw: unknown,
  campaignId: string,
): AutopilotCampaignProjection {
  const value = asRecord(raw);
  if (
    value.candidate_promotion_allowed !== false ||
    value.report_submission_allowed !== false ||
    value.submission_blocked !== true
  ) {
    throw new Error("unsafe_permission_projection");
  }
  if (value.campaign_id !== campaignId) {
    throw new Error("autopilot_campaign_mismatch");
  }

  const budgets = asRecord(value.budgets);
  return {
    campaign_id: safeIdentifier(value.campaign_id, "campaign"),
    campaign_mode: safeLabel(value.campaign_mode, "unknown", 64),
    emergency_stopped: value.emergency_stopped === true,
    authorization_digest: safeDigest(value.authorization_digest),
    scope_snapshot_digest: safeDigest(value.scope_snapshot_digest),
    policy_mode: optionalSafeLabel(value.policy_mode, 64),
    next_branch_id: optionalSafeIdentifier(value.next_branch_id),
    next_reason: optionalSafeLabel(value.next_reason, 160),
    budgets: {
      campaign_max_requests: nonNegativeInteger(budgets.campaign_max_requests),
      campaign_requests_used: nonNegativeInteger(budgets.campaign_requests_used),
      campaign_requests_remaining: nonNegativeInteger(
        budgets.campaign_requests_remaining,
      ),
      active_leases: nonNegativeInteger(budgets.active_leases),
      reserved_requests: nonNegativeInteger(budgets.reserved_requests),
      completed_requests: nonNegativeInteger(budgets.completed_requests),
      open_approvals: nonNegativeInteger(budgets.open_approvals),
      asset_requests_remaining: optionalNonNegativeInteger(
        budgets.asset_requests_remaining,
      ),
      account_requests_remaining: optionalNonNegativeInteger(
        budgets.account_requests_remaining,
      ),
      branch_requests_remaining: optionalNonNegativeInteger(
        budgets.branch_requests_remaining,
      ),
      hypothesis_requests_remaining: optionalNonNegativeInteger(
        budgets.hypothesis_requests_remaining,
      ),
      recipe_requests_remaining: optionalNonNegativeInteger(
        budgets.recipe_requests_remaining,
      ),
      request_slots_remaining: optionalNonNegativeInteger(
        budgets.request_slots_remaining,
      ),
      time_seconds_remaining: optionalNonNegativeInteger(
        budgets.time_seconds_remaining,
      ),
      retry_attempts_remaining: optionalNonNegativeInteger(
        budgets.retry_attempts_remaining,
      ),
      model_cost_units_remaining: optionalNonNegativeInteger(
        budgets.model_cost_units_remaining,
      ),
    },
    assets: asArray(value.assets)
      .slice(0, 100)
      .map((item, index) => parseAsset(item, index)),
    branches: asArray(value.branches)
      .slice(0, 100)
      .map((item, index) => parseBranch(item, index)),
    approvals: asArray(value.approvals)
      .slice(0, 100)
      .map((item, index) => parseApproval(item, index)),
    events: asArray(value.events)
      .slice(0, 200)
      .map((item, index) => parseEvent(item, index)),
    candidate_promotion_allowed: false,
    report_submission_allowed: false,
    submission_blocked: true,
  };
}

function parseAsset(raw: unknown, index: number): AutopilotAssetProjection {
  const value = asRecord(raw);
  const status = classifyAutopilotAssetStatus(value.status);
  return {
    asset_id: safeIdentifier(value.asset_id, `asset-${index + 1}`),
    alias: optionalSafeText(value.alias, 120),
    status,
    host: optionalSafeHost(value.host),
    scheme: value.scheme === "http" || value.scheme === "https" ? value.scheme : null,
    port: optionalPort(value.port),
    admitted: status === "admitted" && value.admitted === true,
    reason: optionalSafeText(value.reason, 200),
  };
}

function parseBranch(raw: unknown, index: number): AutopilotBranchProjection {
  const value = asRecord(raw);
  const riskTier = safeLabel(value.risk_tier, "", 8).toUpperCase();
  return {
    branch_id: safeIdentifier(value.branch_id, `branch-${index + 1}`),
    asset_id: safeIdentifier(value.asset_id, "unassigned-asset"),
    status: safeLabel(value.status, "unknown", 64),
    priority: boundedInteger(value.priority, -10_000, 10_000),
    risk_tier: /^(?:R0|R1|R2|R3|R4)$/.test(riskTier) ? riskTier : null,
    reason: optionalSafeText(value.reason, 200),
    dependencies: asArray(value.dependencies)
      .slice(0, 20)
      .map((dependency, dependencyIndex) =>
        safeIdentifier(dependency, `dependency-${dependencyIndex + 1}`),
      ),
    handoff_from: optionalSafeIdentifier(value.handoff_from),
    handoff_to: optionalSafeIdentifier(value.handoff_to),
    specialist: optionalSafeText(
      value.specialist ?? value.specialist_alias ?? value.agent_type,
      80,
    ),
    queue_rank: optionalNonNegativeInteger(value.queue_rank),
  };
}

function parseApproval(raw: unknown, index: number): AutopilotApprovalProjection {
  const value = asRecord(raw);
  const riskTier = safeLabel(value.risk_tier, "", 8).toUpperCase();
  return {
    approval_id: safeIdentifier(value.approval_id, `approval-${index + 1}`),
    status: safeLabel(value.status, "unknown", 64),
    plan_digest: safeDigest(value.plan_digest),
    risk_tier: /^(?:R0|R1|R2|R3|R4)$/.test(riskTier) ? riskTier : null,
    consumed: value.consumed === true,
    expired: value.expired === true,
    plan_changed: value.plan_changed === true,
    expires_at: optionalSafeTimestamp(value.expires_at),
    exact_diff: asArray(value.exact_diff)
      .slice(0, 30)
      .flatMap((item) => {
        const parsed = parseExactDiff(item);
        return parsed ? [parsed] : [];
      }),
  };
}

function parseExactDiff(raw: unknown): AutopilotExactDiffProjection | null {
  const value = asRecord(raw);
  const field = optionalSafeLabel(value.field, 80);
  const before = safeDiffValue(value.before);
  const after = safeDiffValue(value.after);
  if (
    !field ||
    before === null ||
    after === null ||
    !Object.prototype.hasOwnProperty.call(value, "before") ||
    !Object.prototype.hasOwnProperty.call(value, "after")
  ) {
    return null;
  }
  return {
    field,
    before,
    after,
  };
}

function parseEvent(raw: unknown, index: number): AutopilotEventProjection {
  const value = asRecord(raw);
  const rawRefs = asRecord(value.refs);
  const refs: Partial<Record<AutopilotEventRefKey, string>> = {};
  for (const key of eventRefKeys) {
    const parsed = optionalSafeIdentifier(rawRefs[key]);
    if (parsed) {
      refs[key] = parsed;
    }
  }
  return {
    event_id: safeIdentifier(value.event_id, `event-${index + 1}`),
    kind: safeLabel(value.kind, "event", 64),
    summary: safeText(value.summary, "Event summary unavailable", 300),
    created_at: optionalSafeTimestamp(value.created_at),
    refs,
  };
}

export function summarizeAutopilotProjection(
  projection: AutopilotCampaignProjection,
): string {
  if (projection.emergency_stopped) {
    return projection.budgets.active_leases === 0
      ? "Emergency stop active — all leases revoked"
      : `Emergency stop active — waiting for ${projection.budgets.active_leases} lease(s) to be revoked`;
  }
  if (projection.next_branch_id) {
    return `Next: ${projection.next_branch_id} (${projection.next_reason ?? "eligible"})`;
  }
  const reason = projection.next_reason ?? "no_eligible_branch";
  if (reason === "no_eligible_branch") {
    return "No eligible branch";
  }
  return reason;
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
  if (
    value === "review" ||
    value === "needs_review" ||
    value === "needs_scope_review" ||
    value === "identity_stale"
  ) {
    return "review_required";
  }
  if (value === "excluded" || value === "denied" || value === "out_of_scope") {
    return "blocked";
  }
  return "unknown";
}

export function orderAutopilotTimeline(
  events: AutopilotEventProjection[],
): AutopilotEventProjection[];
export function orderAutopilotTimeline(
  events: Array<Record<string, unknown>>,
): Array<Record<string, unknown>>;
export function orderAutopilotTimeline(
  events: AutopilotEventProjection[] | Array<Record<string, unknown>>,
): AutopilotEventProjection[] | Array<Record<string, unknown>> {
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
  approval: Pick<
    AutopilotApprovalProjection,
    | "consumed"
    | "exact_diff"
    | "expired"
    | "expires_at"
    | "plan_changed"
    | "risk_tier"
    | "status"
  > | Record<string, unknown>,
): { allowed: boolean; reason: string } {
  const status = String(approval.status ?? "").toLowerCase();
  const risk = String(approval.risk_tier ?? "").toUpperCase();
  if (risk === "R4") {
    return { allowed: false, reason: "r4_prohibited" };
  }
  if (risk !== "R3") {
    return { allowed: false, reason: "r3_required" };
  }
  if (approval.consumed === true || status === "used" || status === "consumed") {
    return { allowed: false, reason: "already_consumed" };
  }
  const expiresAt = typeof approval.expires_at === "string"
    ? Date.parse(approval.expires_at)
    : Number.NaN;
  if (
    approval.expired === true ||
    status === "expired" ||
    (Number.isFinite(expiresAt) && expiresAt <= Date.now())
  ) {
    return { allowed: false, reason: "expired" };
  }
  if (approval.plan_changed === true) {
    return { allowed: false, reason: "plan_changed" };
  }
  if (!Array.isArray(approval.exact_diff) || approval.exact_diff.length === 0) {
    return { allowed: false, reason: "exact_diff_required" };
  }
  if (status === "approved" || status === "denied" || status === "revoked") {
    return { allowed: false, reason: "already_decided" };
  }
  if (status !== "pending" && status !== "requested" && status !== "awaiting") {
    return { allowed: false, reason: "not_pending" };
  }
  return { allowed: true, reason: "pending" };
}

export function budgetMonitorRows(
  budgets: AutopilotBudgetProjection,
): Array<{ label: string; value: string }> {
  return [
    {
      label: "Campaign requests",
      value: `${budgets.campaign_requests_used}/${budgets.campaign_max_requests || "not set"} (rem ${budgets.campaign_requests_remaining})`,
    },
    { label: "Active leases", value: String(budgets.active_leases) },
    { label: "Reserved requests", value: String(budgets.reserved_requests) },
    { label: "Completed requests", value: String(budgets.completed_requests) },
    { label: "Open approvals", value: String(budgets.open_approvals) },
    { label: "Asset remaining", value: remainingValue(budgets.asset_requests_remaining) },
    { label: "Account remaining", value: remainingValue(budgets.account_requests_remaining) },
    { label: "Branch remaining", value: remainingValue(budgets.branch_requests_remaining) },
    {
      label: "Hypothesis remaining",
      value: remainingValue(budgets.hypothesis_requests_remaining),
    },
    { label: "Recipe remaining", value: remainingValue(budgets.recipe_requests_remaining) },
    {
      label: "Request slots remaining",
      value: remainingValue(budgets.request_slots_remaining),
    },
    {
      label: "Time remaining",
      value: budgets.time_seconds_remaining === null
        ? "—"
        : `${budgets.time_seconds_remaining}s`,
    },
    { label: "Retry remaining", value: remainingValue(budgets.retry_attempts_remaining) },
    {
      label: "Model cost remaining",
      value: remainingValue(budgets.model_cost_units_remaining),
    },
  ];
}

function asRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function safeText(raw: unknown, fallback: string, maxLength: number): string {
  if (typeof raw !== "string") {
    return fallback;
  }
  const value = raw.trim();
  if (!value) {
    return fallback;
  }
  if (sensitiveTextPattern.test(value)) {
    return "[redacted]";
  }
  return value.slice(0, maxLength);
}

function optionalSafeText(raw: unknown, maxLength: number): string | null {
  if (typeof raw !== "string" || raw.trim() === "") {
    return null;
  }
  return safeText(raw, "[redacted]", maxLength);
}

function safeIdentifier(raw: unknown, fallback: string): string {
  if (typeof raw !== "string") {
    return fallback;
  }
  const value = raw.trim();
  if (
    value.length === 0 ||
    value.length > 160 ||
    sensitiveTextPattern.test(value) ||
    !/^[A-Za-z0-9][A-Za-z0-9._:/-]*$/.test(value)
  ) {
    return fallback;
  }
  return value;
}

function optionalSafeIdentifier(raw: unknown): string | null {
  if (typeof raw !== "string" || raw.trim() === "") {
    return null;
  }
  const parsed = safeIdentifier(raw, "");
  return parsed || null;
}

function safeLabel(raw: unknown, fallback: string, maxLength: number): string {
  const value = safeText(raw, fallback, maxLength);
  return value === "[redacted]" ? fallback : value;
}

function optionalSafeLabel(raw: unknown, maxLength: number): string | null {
  const value = optionalSafeText(raw, maxLength);
  return value === "[redacted]" ? null : value;
}

function safeDigest(raw: unknown): string | null {
  if (typeof raw !== "string") {
    return null;
  }
  const value = raw.trim();
  return value.length <= 160 && /^[A-Za-z0-9._:-]+$/.test(value) ? value : null;
}

function optionalSafeHost(raw: unknown): string | null {
  if (typeof raw !== "string") {
    return null;
  }
  const value = raw.trim().toLowerCase();
  return value.length <= 253 && /^[a-z0-9.-]+$/.test(value) ? value : null;
}

function optionalSafeTimestamp(raw: unknown): string | null {
  if (typeof raw !== "string" || raw.length > 40 || !Number.isFinite(Date.parse(raw))) {
    return null;
  }
  return raw;
}

function safeDiffValue(raw: unknown): string | null {
  if (raw === null || raw === undefined) {
    return "∅";
  }
  if (typeof raw === "number" || typeof raw === "boolean") {
    return String(raw);
  }
  if (typeof raw !== "string") {
    return null;
  }
  const value = safeText(raw, "[redacted]", 240);
  return value === "[redacted]" ? null : value;
}

function boundedInteger(raw: unknown, minimum: number, maximum: number): number {
  return typeof raw === "number" && Number.isFinite(raw)
    ? Math.min(maximum, Math.max(minimum, Math.trunc(raw)))
    : 0;
}

function nonNegativeInteger(raw: unknown): number {
  return boundedInteger(raw, 0, Number.MAX_SAFE_INTEGER);
}

function optionalNonNegativeInteger(raw: unknown): number | null {
  return typeof raw === "number" && Number.isFinite(raw)
    ? nonNegativeInteger(raw)
    : null;
}

function optionalPort(raw: unknown): number | null {
  if (typeof raw !== "number" || !Number.isInteger(raw) || raw < 1 || raw > 65_535) {
    return null;
  }
  return raw;
}

function remainingValue(value: number | null): string {
  return value === null ? "—" : String(value);
}
