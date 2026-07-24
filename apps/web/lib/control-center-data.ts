import type { ControlCenterOverviewResponse } from "./api";

export const CONTROL_CENTER_STALE_AFTER_MS = 120_000;

const stageLabels: Record<string, string> = {
  policy: "政策与范围",
  target_modeling: "目标建模",
  code_api_audit: "代码 / API 审计",
  refutation: "反证审查",
  report_drafting: "报告草拟",
};

const statusLabels: Record<string, string> = {
  approval_required: "等待人工批准",
  blocked: "已阻止",
  completed: "已完成",
  complete: "已完成",
  in_scope: "范围内",
  not_started: "未开始",
  partial: "证据不完整",
  ready_for_human_review: "等待人工复核",
  requested: "已请求",
  running: "运行中",
  submission_blocked: "禁止提交",
  unavailable: "暂无报告",
  waiting: "等待中",
};

export interface ControlCenterQuality {
  retentionRate: number | null;
  refutationKillRate: number | null;
  evidenceCompleteness: number | null;
  medianHumanReviewSeconds: number | null;
}

export interface ControlCenterSnapshot {
  dataMode: "live" | "offline";
  generatedAt: string;
  snapshotVersion: string;
  empty: boolean;
  stale: boolean;
  error: string | null;
  searchQuery: string;
  metrics: {
    runningTasks: number | null;
    retainedCandidates: number | null;
    approvalPressure: number | null;
    safetyBlocks: number | null;
  };
  agentStages: Array<{
    key: string;
    label: string;
    status: string;
    statusLabel: string;
    recordCount: number;
  }>;
  authorizedAssets: Array<{
    campaignId: string;
    asset: string;
    scopeStatus: string;
    scopeLabel: string;
    scopeTone: "safe" | "approval" | "danger";
    campaignStatus: string;
  }>;
  campaigns: Array<{
    id: string;
    name: string;
    status: string;
    scopeStatus: string;
    safeNextAction: string;
    blockedReasons: string[];
  }>;
  candidates: Array<{
    id: string;
    campaignId: string;
    pipelineRunId: string;
    rank: number;
    vulnerabilityType: string;
    endpoint: string;
    codePath: string | null;
    evidenceStatus: string;
    evidenceLabel: string;
    validationReadiness: string;
    validationLabel: string;
    reportSubmissionAllowed: false;
  }>;
  quality: ControlCenterQuality;
  autonomousWakeup: {
    status: string;
    label: string;
    detail: string;
    tone: "safe" | "approval" | "danger";
  } | null;
  report: {
    available: boolean;
    status: string;
    statusLabel: string;
    pipelineRunId: string | null;
    title: string | null;
    claimCount: number | null;
    evidenceRefCount: number | null;
    humanReviewRequired: true;
    submissionBlocked: true;
    reportSubmissionAllowed: false;
  };
  recentEvents: Array<{
    id: string;
    campaignId: string;
    type: string;
    typeLabel: string;
    status: string;
    statusLabel: string;
    occurredAt: string;
  }>;
}

export type QualityChartModel =
  | { empty: true; option: null }
  | {
      empty: false;
      option: {
        animation: false;
        grid: { left: number; right: number; top: number; bottom: number; containLabel: true };
        tooltip: { trigger: "axis"; valueFormatter: string };
        xAxis: { type: "category"; data: string[]; axisLabel: { color: string } };
        yAxis: { type: "value"; max: number; axisLabel: { color: string; formatter: string }; splitLine: { lineStyle: { color: string } } };
        series: Array<{ type: "bar"; data: number[]; barMaxWidth: number; itemStyle: { color: string; borderRadius: number[] } }>;
      };
    };

function labelFor(value: string): string {
  return statusLabels[value] ?? "待复核";
}

function scopeDisplay(value: string): {
  label: string;
  tone: "safe" | "approval" | "danger";
} {
  if (value === "in_scope") {
    return { label: "范围内", tone: "safe" };
  }
  if (value === "needs_review") {
    return { label: "等待范围复核", tone: "approval" };
  }
  return { label: value === "out_of_scope" ? "范围外" : "已阻止", tone: "danger" };
}

function autonomousWakeupDisplay(
  wakeup: ControlCenterOverviewResponse["autonomous_wakeup"],
): ControlCenterSnapshot["autonomousWakeup"] {
  if (!wakeup) {
    return null;
  }
  const safetyBounded =
    wakeup.execution_allowed === false &&
    wakeup.dispatch_allowed === false &&
    wakeup.validation_allowed === false &&
    wakeup.candidate_promotion_allowed === false &&
    wakeup.report_submission_allowed === false;
  if (!safetyBounded) {
    return {
      status: "blocked",
      label: "调度状态已阻止",
      detail: "健康摘要的安全字段不满足只读约束。",
      tone: "danger",
    };
  }
  if (wakeup.status === "active") {
    return {
      status: wakeup.status,
      label: "调度执行中",
      detail: "持久化 wakeup lease 正在处理授权只读任务。",
      tone: "safe",
    };
  }
  if (wakeup.status === "healthy") {
    return {
      status: wakeup.status,
      label: "调度正常",
      detail: `最近心跳 ${wakeup.heartbeat_age_seconds ?? 0} 秒前。`,
      tone: "safe",
    };
  }
  if (wakeup.status === "degraded") {
    return {
      status: wakeup.status,
      label: "调度最近运行失败",
      detail: "最近一轮调度未完成；请检查 Beat、Worker 和持久化 wakeup 状态。",
      tone: "danger",
    };
  }
  if (wakeup.status === "not_started") {
    return {
      status: wakeup.status,
      label: "调度未启动",
      detail: "尚未记录持久化 wakeup 心跳。",
      tone: "approval",
    };
  }
  return {
    status: wakeup.status,
    label:
      wakeup.status === "invalid_lease"
        ? "调度 lease 状态无效"
        : wakeup.status === "expired_lease"
          ? "调度 lease 已过期"
          : "调度心跳过期",
    detail:
      wakeup.status === "invalid_lease"
        ? "持久化 wakeup lease 状态不完整或不一致。"
        : "请检查 Beat、Worker 和持久化 wakeup 状态。",
    tone: "danger",
  };
}

export function isControlCenterSnapshotStale(generatedAt: string, now = new Date()): boolean {
  const generatedAtMs = Date.parse(generatedAt);
  return (
    !Number.isFinite(generatedAtMs) ||
    now.getTime() - generatedAtMs > CONTROL_CENTER_STALE_AFTER_MS
  );
}

export function resolveControlCenterDataMode(
  dataMode: ControlCenterSnapshot["dataMode"],
  stale: boolean,
): "live" | "offline" | "stale" {
  if (dataMode === "offline") {
    return "offline";
  }
  return stale ? "stale" : "live";
}

export function mapControlCenterOverview(
  response: ControlCenterOverviewResponse,
  now = new Date(),
): ControlCenterSnapshot {
  const stale = isControlCenterSnapshotStale(response.generated_at, now);

  return {
    dataMode: "live",
    generatedAt: response.generated_at,
    snapshotVersion: response.snapshot_version,
    empty: response.empty_state,
    stale,
    error: null,
    searchQuery: "",
    metrics: {
      runningTasks: response.metrics.running_task_count,
      retainedCandidates: response.metrics.retained_high_value_candidate_count,
      approvalPressure: response.metrics.approval_pressure_count,
      safetyBlocks: response.metrics.safety_block_count,
    },
    agentStages: response.agent_stages.map((stage) => ({
      key: stage.stage,
      label: stageLabels[stage.stage] ?? "未知阶段",
      status: stage.status,
      statusLabel: labelFor(stage.status),
      recordCount: stage.record_count,
    })),
    authorizedAssets: response.authorized_assets.map((asset) => {
      const scope = scopeDisplay(asset.scope_status);
      return {
        campaignId: asset.campaign_id,
        asset: asset.asset,
        scopeStatus: asset.scope_status,
        scopeLabel: scope.label,
        scopeTone: scope.tone,
        campaignStatus: asset.campaign_status,
      };
    }),
    campaigns: response.campaigns.map((campaign) => ({
      id: campaign.id,
      name: campaign.name,
      status: campaign.status,
      scopeStatus: campaign.scope_status,
      safeNextAction: campaign.safe_next_action,
      blockedReasons: [...campaign.blocked_reasons],
    })),
    candidates: response.candidates
      .map((candidate) => ({
        id: candidate.candidate_id,
        campaignId: candidate.campaign_id,
        pipelineRunId: candidate.pipeline_run_id,
        rank: candidate.rank,
        vulnerabilityType: candidate.vuln_type,
        endpoint: candidate.affected_endpoint,
        codePath: candidate.affected_code_path,
        evidenceStatus: candidate.evidence_trace_status,
        evidenceLabel: labelFor(candidate.evidence_trace_status),
        validationReadiness: candidate.human_validation_readiness,
        validationLabel: labelFor(candidate.human_validation_readiness),
        reportSubmissionAllowed: false as const,
      }))
      .sort((left, right) => left.rank - right.rank || left.id.localeCompare(right.id)),
    quality: {
      retentionRate: response.research_quality.retention_rate,
      refutationKillRate: response.research_quality.refutation_kill_rate,
      evidenceCompleteness: response.research_quality.evidence_completeness,
      medianHumanReviewSeconds: response.research_quality.median_human_review_seconds,
    },
    autonomousWakeup: autonomousWakeupDisplay(response.autonomous_wakeup),
    report: {
      available: response.report_readiness.available,
      status: response.report_readiness.status,
      statusLabel: labelFor(response.report_readiness.status),
      pipelineRunId: response.report_readiness.pipeline_run_id ?? null,
      title: response.report_readiness.title ?? null,
      claimCount: response.report_readiness.claim_count ?? null,
      evidenceRefCount: response.report_readiness.evidence_ref_count ?? null,
      humanReviewRequired: true,
      submissionBlocked: true,
      reportSubmissionAllowed: false,
    },
    recentEvents: response.recent_events.map((event) => ({
      id: event.event_id,
      campaignId: event.campaign_id,
      type: event.event_type,
      typeLabel: event.event_type === "research_task" ? "研究任务" : "流水线阶段",
      status: event.status,
      statusLabel: labelFor(event.status),
      occurredAt: event.occurred_at,
    })),
  };
}

export function createOfflineControlCenterSnapshot(message: string): ControlCenterSnapshot {
  return {
    dataMode: "offline",
    generatedAt: new Date(0).toISOString(),
    snapshotVersion: "",
    empty: true,
    stale: true,
    error: message,
    searchQuery: "",
    metrics: {
      runningTasks: null,
      retainedCandidates: null,
      approvalPressure: null,
      safetyBlocks: null,
    },
    agentStages: [],
    authorizedAssets: [],
    campaigns: [],
    candidates: [],
    quality: {
      retentionRate: null,
      refutationKillRate: null,
      evidenceCompleteness: null,
      medianHumanReviewSeconds: null,
    },
    autonomousWakeup: null,
    report: {
      available: false,
      status: "unavailable",
      statusLabel: "暂无报告",
      pipelineRunId: null,
      title: null,
      claimCount: null,
      evidenceRefCount: null,
      humanReviewRequired: true,
      submissionBlocked: true,
      reportSubmissionAllowed: false,
    },
    recentEvents: [],
  };
}

export function buildQualityChartModel(quality: ControlCenterQuality): QualityChartModel {
  const available = [
    ["候选保留", quality.retentionRate],
    ["反证淘汰", quality.refutationKillRate],
    ["证据完整", quality.evidenceCompleteness],
  ].filter((entry): entry is [string, number] => entry[1] !== null);
  if (available.length === 0) {
    return { empty: true, option: null };
  }

  return {
    empty: false,
    option: {
      animation: false,
      grid: { left: 8, right: 8, top: 12, bottom: 4, containLabel: true },
      tooltip: { trigger: "axis", valueFormatter: "{value}%" },
      xAxis: {
        type: "category",
        data: available.map(([label]) => label),
        axisLabel: { color: "#98a6b8" },
      },
      yAxis: {
        type: "value",
        max: 100,
        axisLabel: { color: "#98a6b8", formatter: "{value}%" },
        splitLine: { lineStyle: { color: "#1c2939" } },
      },
      series: [
        {
          type: "bar",
          data: available.map(([, value]) => Math.round(value * 100)),
          barMaxWidth: 32,
          itemStyle: { color: "#2388ff", borderRadius: [3, 3, 0, 0] },
        },
      ],
    },
  };
}

function includesQuery(query: string, ...values: Array<string | null>): boolean {
  return values.some((value) => value?.toLocaleLowerCase("zh-CN").includes(query));
}

export function filterControlCenterSnapshot(
  snapshot: ControlCenterSnapshot,
  rawQuery: string | undefined,
): ControlCenterSnapshot {
  const searchQuery = rawQuery?.trim() ?? "";
  if (!searchQuery) {
    return snapshot;
  }
  const query = searchQuery.toLocaleLowerCase("zh-CN");
  const campaignIds = new Set(
    snapshot.campaigns
      .filter((campaign) =>
        includesQuery(
          query,
          campaign.id,
          campaign.name,
          campaign.status,
          campaign.scopeStatus,
          campaign.safeNextAction,
          ...campaign.blockedReasons,
        ),
      )
      .map((campaign) => campaign.id),
  );

  return {
    ...snapshot,
    searchQuery,
    agentStages: snapshot.agentStages.filter((stage) =>
      includesQuery(query, stage.key, stage.label, stage.status, stage.statusLabel),
    ),
    authorizedAssets: snapshot.authorizedAssets.filter(
      (asset) =>
        campaignIds.has(asset.campaignId) ||
        includesQuery(
          query,
          asset.campaignId,
          asset.asset,
          asset.scopeStatus,
          asset.scopeLabel,
          asset.campaignStatus,
        ),
    ),
    candidates: snapshot.candidates.filter(
      (candidate) =>
        campaignIds.has(candidate.campaignId) ||
        includesQuery(
          query,
          candidate.id,
          candidate.campaignId,
          candidate.pipelineRunId,
          candidate.vulnerabilityType,
          candidate.endpoint,
          candidate.codePath,
          candidate.evidenceStatus,
          candidate.evidenceLabel,
          candidate.validationReadiness,
          candidate.validationLabel,
        ),
    ),
    recentEvents: snapshot.recentEvents.filter(
      (event) =>
        campaignIds.has(event.campaignId) ||
        includesQuery(
          query,
          event.id,
          event.campaignId,
          event.type,
          event.typeLabel,
          event.status,
          event.statusLabel,
        ),
    ),
  };
}
