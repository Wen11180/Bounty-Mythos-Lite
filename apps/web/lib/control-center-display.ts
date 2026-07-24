export const DATA_MODES = ["live", "dry_run", "demo", "stale", "offline"] as const;
export const UNSAFE_SAFETY_STATES = [
  "blocked",
  "approval_required",
  "report_chain_unsafe",
] as const;

export type DataMode = (typeof DATA_MODES)[number];
export type UnsafeSafetyState = (typeof UNSAFE_SAFETY_STATES)[number];
export type StatusTone = "safe" | "advisory" | "neutral" | "approval" | "danger";

export interface StateDisplay<TState extends string> {
  state: TState;
  label: string;
  tone: StatusTone;
}

export interface SafetyStateDisplay extends StateDisplay<UnsafeSafetyState> {
  executionAllowed: false;
  reportSubmissionAllowed: false;
}

interface SafetyStateInput {
  state?: unknown;
  execution_allowed?: unknown;
  report_submission_allowed?: unknown;
}

const dataModeDisplays: Record<DataMode, StateDisplay<DataMode>> = {
  live: { state: "live", label: "实时数据", tone: "safe" },
  dry_run: { state: "dry_run", label: "安全演练", tone: "advisory" },
  demo: { state: "demo", label: "演示数据", tone: "neutral" },
  stale: { state: "stale", label: "数据已过期", tone: "approval" },
  offline: { state: "offline", label: "连接离线", tone: "danger" },
};

const safetyStateDisplays: Record<UnsafeSafetyState, SafetyStateDisplay> = {
  blocked: {
    state: "blocked",
    label: "已阻止",
    tone: "danger",
    executionAllowed: false,
    reportSubmissionAllowed: false,
  },
  approval_required: {
    state: "approval_required",
    label: "需要人工批准",
    tone: "approval",
    executionAllowed: false,
    reportSubmissionAllowed: false,
  },
  report_chain_unsafe: {
    state: "report_chain_unsafe",
    label: "报告链不安全",
    tone: "danger",
    executionAllowed: false,
    reportSubmissionAllowed: false,
  },
};

export function dataModeDisplay(state: unknown): StateDisplay<DataMode> {
  const normalized = DATA_MODES.includes(state as DataMode) ? (state as DataMode) : "offline";
  return dataModeDisplays[normalized];
}

export function safetyStateDisplay(input: SafetyStateInput | string): SafetyStateDisplay {
  const state = typeof input === "string" ? input : input.state;
  const normalized = UNSAFE_SAFETY_STATES.includes(state as UnsafeSafetyState)
    ? (state as UnsafeSafetyState)
    : "blocked";

  return safetyStateDisplays[normalized];
}

export function statusToneClassName(tone: StatusTone): string {
  return {
    safe: "border-safe/35 bg-safe/10 text-safe",
    advisory: "border-advisory/35 bg-advisory/10 text-advisory",
    neutral: "border-border bg-muted text-muted-foreground",
    approval: "border-approval/35 bg-approval/10 text-approval",
    danger: "border-danger/35 bg-danger/10 text-danger",
  }[tone];
}
