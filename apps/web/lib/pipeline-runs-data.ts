import type { EvidenceSupportSummary, PipelineRun, PipelineStage } from "./api";
import { formatLabel } from "./workbench-display.ts";

export type PipelineStageStatus =
  | "queued"
  | "running"
  | "complete"
  | "needs_review"
  | "blocked"
  | "failed"
  | "skipped";

export type ValidationGateStatus = "approved" | "waiting_human" | "blocked" | "not_required";

export type PipelineRunStageSummary = {
  label: string;
  status: PipelineStageStatus;
  detail: string;
  evidenceCount: number;
  agentBoundary?: StageAgentBoundarySummary;
  safetyNotes?: string[];
  lessonTraces?: PipelineLessonTraceSummary[];
};

export type StageAgentBoundarySummary = {
  allowedActions: string[];
  blockedActions: string[];
  requiresHumanReview: boolean;
  role: string;
};

export type PipelineLessonTraceSummary = {
  action: string;
  lessonId: string;
  playbook: string;
  recommendation: string;
  reasons: string[];
  sourceSignalCount: number;
  sourceSignalIds: string[];
  surface: string;
};

export type ArtifactProvenanceSummary = {
  artifactId: string | null;
  source: string;
  kind: string;
  provenance: string;
  evidenceCount: number;
};

export type ValidationGateSummary = {
  label: string;
  status: ValidationGateStatus;
  approval: string;
  evidenceCount: number;
};

export type HunterPrioritySummary = {
  playbook: string;
  recommendation: string;
  priorityScore: number;
  impactScore: number;
  rejectionRiskScore: number;
  nextAction: string;
};

export type MemoryReadinessSummary = {
  lessonCount: number;
  status: string;
  topLesson: string | null;
};

export type RefutationReviewSummary = {
  parked: number;
  refuted: number;
  total: number;
  unverified: number;
};

export type PipelineRunSummary = {
  runId: string;
  asset: string;
  hypothesisCount: number;
  blockedCount: number;
  reportTitle: string | null;
  evidenceCount: number;
  stages: PipelineRunStageSummary[];
  artifact: ArtifactProvenanceSummary;
  validationGate: ValidationGateSummary;
  hunter: HunterPrioritySummary;
  evidenceSupportSummary: EvidenceSupportSummary | null;
  memory: MemoryReadinessSummary | null;
  refutationSummary: RefutationReviewSummary;
};

export type RadarRunSignal = {
  evidenceGapCount: number;
  nextSafeAction: string;
  radarScore: number;
  reportDistance: string;
  run: PipelineRunSummary;
};

export type IntelligenceRadarSummary = {
  evidenceGapCount: number;
  humanGatePressure: number;
  memoryReadyRuns: number;
  parkedHypothesisCount: number;
  refutedHypothesisCount: number;
  reportableMomentum: number;
  reusableLessonCount: number;
  runSignals: RadarRunSignal[];
  topSignal: RadarRunSignal | null;
  unverifiedHypothesisCount: number;
  unsafeOrRedactedRequirementCount: number;
};

export type PipelineRunRowsResult = {
  dataMode: "演示数据" | "实时数据";
  runs: PipelineRunSummary[];
};

type RunSeed = Pick<
  PipelineRunSummary,
  "asset" | "blockedCount" | "evidenceCount" | "hypothesisCount"
> & {
  scopeStatus?: string;
};

const fallbackStageLabels = [
  "资料接入",
  "范围守卫",
  "假设引擎",
  "验证审批门",
  "证据快照",
];

function numberOrFallback(value: number | undefined, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function stripUrlQuery(value: string): string {
  try {
    const url = new URL(value);
    url.search = "";
    url.hash = "";

    return url.toString().replace(/^https?:\/\//, "");
  } catch {
    return value;
  }
}

function safeText(value: string | null | undefined, fallback: string): string {
  const text = typeof value === "string" ? value.trim() : "";

  if (!text) {
    return formatLabel(fallback);
  }

  if (containsSensitiveIdentityText(text)) {
    return formatLabel(fallback);
  }

  return stripUrlQuery(text)
    .replace(/\b(policy_text|secret|token)\b\s*[:=]\s*[^,;\s]+/gi, "$1=[已脱敏]")
    .replace(/\b(policy_text|secret|token)\b/gi, "[已脱敏]");
}

function containsSensitiveIdentityText(value: string): boolean {
  return (
    /\b(api[_-]?key|password|credential)\b/i.test(value)
    || /\b(real user data|customer data|production user|live user|personal data|pii)\b/i.test(value)
    || /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i.test(value)
    || /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/.test(value)
  );
}

function readableStageLabel(value: string): string {
  return formatLabel(value);
}

function normalizeStageStatus(
  status: string | undefined,
  fallback: PipelineStageStatus,
): PipelineStageStatus {
  const normalized = status?.trim().toLowerCase().replace(/[\s-]+/g, "_");

  switch (normalized) {
    case "complete":
    case "completed":
    case "done":
    case "passed":
    case "approved":
    case "validated":
      return "complete";
    case "blocked":
    case "rejected":
      return "blocked";
    case "needs_review":
    case "needs_approval":
    case "review":
    case "waiting":
    case "waiting_human":
      return "needs_review";
    case "running":
    case "in_progress":
      return "running";
    case "failed":
    case "error":
      return "failed";
    case "skipped":
      return "skipped";
    case "queued":
    case "pending":
      return "queued";
    default:
      return fallback;
  }
}

function normalizeGateStatus(
  status: string | undefined,
  fallback: ValidationGateStatus,
): ValidationGateStatus {
  const normalized = status?.trim().toLowerCase().replace(/[\s-]+/g, "_");

  switch (normalized) {
    case "approved":
    case "allowed":
    case "passed":
      return "approved";
    case "blocked":
    case "rejected":
    case "denied":
      return "blocked";
    case "not_required":
    case "not_applicable":
    case "skipped":
      return "not_required";
    case "waiting":
    case "waiting_human":
    case "awaiting_approval":
    case "needs_review":
    case "needs_approval":
    case "pending":
      return "waiting_human";
    default:
      return fallback;
  }
}

function stringList(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .filter((item): item is string => typeof item === "string")
    .map((item) => safeText(item, "unknown"));
}

function resolveLessonTraces(stage: PipelineStage): PipelineLessonTraceSummary[] {
  const traces = stage.details?.lesson_traces;

  if (!Array.isArray(traces)) {
    return [];
  }

  return traces.flatMap((trace) => {
    if (!trace || typeof trace !== "object" || Array.isArray(trace)) {
      return [];
    }

    const record = trace as Record<string, unknown>;
    const sourceSignalIds = stringList(record.source_signal_ids);

    return [
      {
        action: safeText(record.action as string | undefined, "unknown"),
        lessonId: safeText(record.lesson_id as string | undefined, "unknown"),
        playbook: safeText(record.playbook_id as string | undefined, "unknown"),
        recommendation: safeText(record.recommendation as string | undefined, "unknown"),
        reasons: stringList(record.reasons),
        sourceSignalCount: numberOrFallback(
          record.source_signal_count as number | undefined,
          sourceSignalIds.length,
        ),
        sourceSignalIds,
        surface: safeText(record.surface_pattern as string | undefined, "unknown"),
      },
    ];
  });
}

function resolveAgentBoundary(stage: PipelineStage): StageAgentBoundarySummary | undefined {
  const boundary = stage.details?.agent_boundary;

  if (!boundary || typeof boundary !== "object" || Array.isArray(boundary)) {
    return undefined;
  }

  return {
    allowedActions: stringList(boundary.allowed_actions),
    blockedActions: stringList(boundary.blocked_actions),
    requiresHumanReview: boundary.requires_human_review === true,
    role: safeText(boundary.role, "受限智能体"),
  };
}

function buildDefaultStages(seed: RunSeed): PipelineRunStageSummary[] {
  const scopeBlocked = seed.scopeStatus === "out_of_scope";
  const scopeComplete = seed.scopeStatus === "in_scope" && seed.blockedCount === 0;
  const hasEvidence = seed.evidenceCount > 0;

  return [
    {
      label: "资料接入",
      status: "complete",
      detail: "运行清单已就绪；资料库字段会在此关联。",
      evidenceCount: seed.evidenceCount,
    },
    {
      label: "范围守卫",
      status: scopeBlocked || seed.blockedCount > 0 ? "blocked" : scopeComplete ? "complete" : "needs_review",
      detail: scopeBlocked
        ? `${seed.asset} 不在范围内；验证保持阻断。`
        : seed.blockedCount > 0
          ? `${seed.blockedCount} 项检查在活动验证前被暂缓。`
          : scopeComplete
            ? `${seed.asset} 已完成低风险规划审核。`
            : "验证前需要审核范围。",
      evidenceCount: 0,
    },
    {
      label: "假设引擎",
      status: seed.hypothesisCount > 0 ? "complete" : "queued",
      detail: `已从范围内资料生成 ${seed.hypothesisCount} 个假设。`,
      evidenceCount: 0,
    },
    {
      label: "验证审批门",
      status: scopeBlocked || seed.blockedCount > 0 ? "blocked" : "needs_review",
      detail:
        scopeBlocked || seed.blockedCount > 0
          ? "高风险操作保持排队，等待人工审核。"
          : "对实时目标验证前需要人工审核。",
      evidenceCount: 0,
    },
    {
      label: "证据快照",
      status: hasEvidence ? "complete" : "needs_review",
      detail: hasEvidence
        ? `已关联 ${seed.evidenceCount} 项运行证据。`
        : "尚未关联可用于报告审核的证据。",
      evidenceCount: seed.evidenceCount,
    },
  ];
}

function buildDefaultArtifact(seed: RunSeed): ArtifactProvenanceSummary {
  return {
    artifactId: null,
    source: "流程响应摘要",
    kind: "运行资料清单",
    provenance: "资料库尚待接入；当前仅显示运行中的安全计数。",
    evidenceCount: seed.evidenceCount,
  };
}

function buildDefaultGate(seed: RunSeed): ValidationGateSummary {
  if (seed.scopeStatus === "out_of_scope" || seed.blockedCount > 0) {
    return {
      label: seed.scopeStatus === "out_of_scope" ? "范围外审核门已阻断" : "审核门已阻断",
      status: "blocked",
      approval:
        seed.scopeStatus === "out_of_scope"
          ? "资产确认在范围内之前，验证将保持阻断。"
          : `${seed.blockedCount} 项验证检查需要人工审核。`,
      evidenceCount: seed.evidenceCount,
    };
  }

  if (seed.evidenceCount > 0) {
    return {
      label: "低风险验证已审核",
      status: "approved",
      approval: "已在范围内验证计划下记录证据。",
      evidenceCount: seed.evidenceCount,
    };
  }

  return {
    label: "等待审核门",
    status: "waiting_human",
    approval: "起草报告前需要人工审核和证据。",
    evidenceCount: seed.evidenceCount,
  };
}

function resolveStages(run: PipelineRun, seed: RunSeed): PipelineRunStageSummary[] {
  const apiStages = run.timeline && run.timeline.length > 0 ? run.timeline : run.stages;

  if (!apiStages || apiStages.length === 0) {
    return buildDefaultStages(seed);
  }

  return apiStages.map((stage: PipelineStage, index) => {
    const fallbackStage = buildDefaultStages(seed)[index] ?? {
      label: fallbackStageLabels[index] ?? `阶段 ${index + 1}`,
      status: "queued" as const,
      detail: "等待流程元数据。",
      evidenceCount: 0,
      safetyNotes: [],
    };
    const lessonTraces = resolveLessonTraces(stage);
    const agentBoundary = resolveAgentBoundary(stage);

    return {
      label: readableStageLabel(
        safeText(stage.label ?? stage.name ?? stage.stage, fallbackStage.label),
      ),
      status: normalizeStageStatus(stage.status, fallbackStage.status),
      detail: safeText(stage.summary ?? stage.output_summary ?? stage.input_summary, fallbackStage.detail),
      evidenceCount: numberOrFallback(stage.evidence_count, fallbackStage.evidenceCount),
      agentBoundary,
      safetyNotes: Array.isArray(stage.safety_notes)
        ? stage.safety_notes.map((note) => safeText(note, "安全说明"))
        : fallbackStage.safetyNotes ?? [],
      lessonTraces: lessonTraces.length > 0 ? lessonTraces : undefined,
    };
  });
}

function resolveArtifact(run: PipelineRun, seed: RunSeed): ArtifactProvenanceSummary {
  const artifact = run.artifact ?? run.provenance ?? run.artifacts?.[0];

  if (!artifact) {
    return buildDefaultArtifact(seed);
  }

  return {
    artifactId: artifact.artifact_id ?? null,
    source: safeText(artifact.source ?? artifact.repository, "流程资料库"),
    kind: safeText(
      artifact.artifact_type ?? artifact.kind ?? artifact.source_type,
      "运行资料清单",
    ),
    provenance: safeText(
      artifact.provenance ?? artifact.summary ?? (artifact.digest ? "已记录摘要" : undefined),
      "资料库尚待接入；当前仅显示运行中的安全计数。",
    ),
    evidenceCount: numberOrFallback(artifact.evidence_count, seed.evidenceCount),
  };
}

function resolveValidationGate(run: PipelineRun, seed: RunSeed): ValidationGateSummary {
  const fallbackGate = buildDefaultGate(seed);
  const gate = run.validation_gate ?? run.validationGate;

  if (!gate) {
    return fallbackGate;
  }

  return {
    label: safeText(gate.label ?? gate.decision ?? gate.status, fallbackGate.label),
    status: normalizeGateStatus(gate.status ?? gate.decision, fallbackGate.status),
    approval: gate.approved_by
      ? `审核人：${safeText(gate.approved_by, "审核人")}`
      : safeText(
          gate.summary,
          gate.approval_required ? "等待人工审核。" : fallbackGate.approval,
        ),
    evidenceCount: numberOrFallback(gate.evidence_count, seed.evidenceCount),
  };
}

function buildDefaultHunter(seed: RunSeed): HunterPrioritySummary {
  const blocked = seed.scopeStatus === "out_of_scope" || seed.blockedCount > 0;

  return {
    playbook: seed.hypothesisCount > 0 ? "候选项需要匹配研究手册" : "无候选项",
    recommendation: blocked ? "需要审核" : "谨慎推进",
    priorityScore: blocked ? 42 : 62,
    impactScore: seed.hypothesisCount > 0 ? 75 : 0,
    rejectionRiskScore: blocked ? 55 : 25,
    nextAction: blocked
      ? "验证前请处理范围守卫或审核阻断项。"
      : "请在人工审核下收集最小化安全证据。",
  };
}

function resolveHunter(run: PipelineRun, seed: RunSeed): HunterPrioritySummary {
  const fallback = buildDefaultHunter(seed);
  const intelligence = run.hunter_intelligence ?? run.hunterIntelligence;
  const assessment = intelligence?.assessments?.[0];

  if (!assessment) {
    return fallback;
  }

  return {
    playbook: safeText(assessment.playbook_label ?? assessment.playbook_id, fallback.playbook),
    recommendation: safeText(
      intelligence?.top_recommendation ?? assessment.recommendation,
      fallback.recommendation,
    ),
    priorityScore: numberOrFallback(assessment.hunter_priority_score, fallback.priorityScore),
    impactScore: numberOrFallback(assessment.impact_score, fallback.impactScore),
    rejectionRiskScore: numberOrFallback(
      assessment.rejection_risk_score,
      fallback.rejectionRiskScore,
    ),
    nextAction: safeText(assessment.next_action, fallback.nextAction),
  };
}

function resolveEvidenceSupportSummary(run: PipelineRun): EvidenceSupportSummary | null {
  return run.evidence_support_summary ?? run.evidenceSupportSummary ?? null;
}

function resolveMemory(run: PipelineRun): MemoryReadinessSummary | null {
  const closedLoop = run.closed_loop_summary ?? run.closedLoopSummary;

  if (!closedLoop) {
    return null;
  }

  const lessons = closedLoop.memory_lessons ?? [];
  const topLesson = lessons[0];
  const recommendation = topLesson
    ? readableStageLabel(safeText(topLesson.recommendation, "记忆"))
    : null;
  const surface = topLesson ? safeText(topLesson.surface_pattern, "未知攻击面") : null;

  return {
    lessonCount: numberOrFallback(closedLoop.lesson_count, lessons.length),
    status: safeText(closedLoop.status ?? closedLoop.brain_memory_status, "waiting_for_learning"),
    topLesson: recommendation && surface ? `${surface} 上的${recommendation}记忆` : null,
  };
}

function resolveRefutationSummary(run: PipelineRun): RefutationReviewSummary {
  const hypotheses = run.payload?.hypotheses ?? [];

  return hypotheses.reduce<RefutationReviewSummary>(
    (summary, hypothesis) => {
      const status = hypothesis.refutation_status?.trim().toLowerCase();

      if (status === "refuted") {
        summary.refuted += 1;
      } else if (status === "parked") {
        summary.parked += 1;
      } else {
        summary.unverified += 1;
      }

      summary.total += 1;

      return summary;
    },
    {
      parked: 0,
      refuted: 0,
      total: 0,
      unverified: 0,
    },
  );
}

export function toPipelineRunSummary(run: PipelineRun): PipelineRunSummary {
  const seed: RunSeed = {
    asset: safeText(run.asset, "未知资产"),
    blockedCount: numberOrFallback(run.blocked_count, 0),
    evidenceCount: numberOrFallback(run.evidence_count, 0),
    hypothesisCount: numberOrFallback(run.hypothesis_count, 0),
    scopeStatus: run.scope_status,
  };

  return {
    runId: safeText(run.id, "流程运行"),
    asset: seed.asset,
    hypothesisCount: seed.hypothesisCount,
    blockedCount: seed.blockedCount,
    reportTitle: run.report_title ? safeText(run.report_title, "报告草稿") : null,
    evidenceCount: seed.evidenceCount,
    stages: resolveStages(run, seed),
    artifact: resolveArtifact(run, seed),
    validationGate: resolveValidationGate(run, seed),
    hunter: resolveHunter(run, seed),
    evidenceSupportSummary: resolveEvidenceSupportSummary(run),
    memory: resolveMemory(run),
    refutationSummary: resolveRefutationSummary(run),
  };
}

export function resolvePipelineRunRows(runs: PipelineRun[]): PipelineRunRowsResult {
  if (runs.length === 0) {
    return {
      dataMode: "演示数据",
      runs: fallbackPipelineRuns,
    };
  }

  return {
    dataMode: "实时数据",
    runs: runs.map((run) => toPipelineRunSummary(run)),
  };
}

export function deriveIntelligenceRadar(
  runs: PipelineRunSummary[],
): IntelligenceRadarSummary {
  const runSignals = runs
    .map((run) => ({
      evidenceGapCount: runEvidenceGapCount(run),
      nextSafeAction: run.hunter.nextAction,
      radarScore: runRadarScore(run),
      reportDistance: runReportDistance(run),
      run,
    }))
    .sort((left, right) => right.radarScore - left.radarScore);

  return {
    evidenceGapCount: runs.reduce((total, run) => total + runEvidenceGapCount(run), 0),
    humanGatePressure: runs.filter(needsHumanGate).length,
    memoryReadyRuns: runs.filter(hasReadyMemory).length,
    parkedHypothesisCount: runs.reduce(
      (total, run) => total + (run.refutationSummary?.parked ?? 0),
      0,
    ),
    refutedHypothesisCount: runs.reduce(
      (total, run) => total + (run.refutationSummary?.refuted ?? 0),
      0,
    ),
    reportableMomentum: runs.filter(hasReportableMomentum).length,
    reusableLessonCount: runs.reduce((total, run) => total + (run.memory?.lessonCount ?? 0), 0),
    runSignals,
    topSignal: runSignals[0] ?? null,
    unverifiedHypothesisCount: runs.reduce(
      (total, run) => total + (run.refutationSummary?.unverified ?? 0),
      0,
    ),
    unsafeOrRedactedRequirementCount: runs.reduce(
      (total, run) =>
        total + (run.evidenceSupportSummary?.unsafe_or_redacted_requirement_count ?? 0),
      0,
    ),
  };
}

function runRadarScore(run: PipelineRunSummary): number {
  const gatePenalty = needsHumanGate(run) ? 8 : 0;
  const evidencePenalty = runEvidenceGapCount(run) > 0 ? 6 : 0;
  const rawScore =
    run.hunter.priorityScore +
    Math.round(run.hunter.impactScore / 5) -
    Math.round(run.hunter.rejectionRiskScore / 5) -
    gatePenalty -
    evidencePenalty;

  return Math.max(0, Math.min(100, rawScore));
}

function runEvidenceGapCount(run: PipelineRunSummary): number {
  const summary = run.evidenceSupportSummary;
  if (summary) {
    return summary.missing_required_count + summary.unsafe_or_redacted_requirement_count;
  }

  return run.evidenceCount === 0 ? 1 : 0;
}

function needsHumanGate(run: PipelineRunSummary): boolean {
  return (
    run.blockedCount > 0 ||
    run.validationGate.status === "blocked" ||
    run.validationGate.status === "waiting_human"
  );
}

function hasReportableMomentum(run: PipelineRunSummary): boolean {
  const support = run.evidenceSupportSummary;
  if (support) {
    return support.satisfied_human_gated_count > 0;
  }

  return Boolean(run.reportTitle && run.evidenceCount > 0);
}

function hasReadyMemory(run: PipelineRunSummary): boolean {
  return run.memory?.status === "brain_memory_ready";
}

function runReportDistance(run: PipelineRunSummary): string {
  const gates = [
    runEvidenceGapCount(run) > 0,
    needsHumanGate(run),
    !run.reportTitle,
  ].filter(Boolean).length;

  if (gates === 0) {
    return "报告审核队列";
  }

  return gates === 1 ? "距离报告审核还差 1 个审核门" : `距离报告审核还差 ${gates} 个审核门`;
}

export const fallbackPipelineRuns: PipelineRunSummary[] = [
  {
    runId: "dry_run_2026_07_03_001",
    asset: "api.example.com",
    hypothesisCount: 3,
    blockedCount: 1,
    reportTitle: "普通用户可访问其他用户私有文件元数据",
    evidenceCount: 4,
    stages: [
      {
        label: "资料接入",
        status: "complete",
        detail: "已关联 OpenAPI 架构、HAR 捕获和角色说明。",
        evidenceCount: 2,
      },
      {
        label: "范围守卫",
        status: "complete",
        detail: "范围内 API 资产；已移除破坏性检查。",
        evidenceCount: 0,
      },
      {
        label: "假设引擎",
        status: "complete",
        detail: "已将 IDOR 候选收敛为低风险元数据读取。",
        evidenceCount: 0,
      },
      {
        label: "验证审批门",
        status: "blocked",
        detail: "一条涉及实时用户数据的路径已转人工审核。",
        evidenceCount: 0,
      },
      {
        label: "证据快照",
        status: "complete",
        detail: "已关联四条脱敏请求/响应引用。",
        evidenceCount: 4,
      },
    ],
    artifact: {
      artifactId: "artifact_fallback_001",
      source: "研究资料库：HAR 捕获 + OpenAPI 架构",
      kind: "API 资料包",
      provenance: "由研究人员测试账号捕获，并关联到演练清单。",
      evidenceCount: 4,
    },
    validationGate: {
      label: "低风险路径已审核",
      status: "approved",
      approval: "人工审核员已记录仅含元数据的验证证据。",
      evidenceCount: 4,
    },
    hunter: {
      playbook: "BOLA / IDOR 对象边界",
      recommendation: "needs_human_review",
      priorityScore: 68,
      impactScore: 85,
      rejectionRiskScore: 30,
      nextAction: "准备仅限测试账号的验证，供人工审核。",
    },
    evidenceSupportSummary: null,
    memory: null,
    refutationSummary: {
      parked: 0,
      refuted: 0,
      total: 0,
      unverified: 0,
    },
  },
  {
    runId: "dry_run_2026_07_02_002",
    asset: "app.example.com",
    hypothesisCount: 2,
    blockedCount: 2,
    reportTitle: "普通成员可能修改团队邀请设置",
    evidenceCount: 1,
    stages: [
      {
        label: "资料接入",
        status: "complete",
        detail: "已从测试工作区导入界面轨迹和角色矩阵。",
        evidenceCount: 1,
      },
      {
        label: "范围守卫",
        status: "needs_review",
        detail: "团队管理员路由在范围内；状态修改证明需要审核。",
        evidenceCount: 0,
      },
      {
        label: "假设引擎",
        status: "complete",
        detail: "已生成两个权限边界假设。",
        evidenceCount: 0,
      },
      {
        label: "验证审批门",
        status: "blocked",
        detail: "状态修改型验证在审核前保持阻断。",
        evidenceCount: 0,
      },
      {
        label: "证据快照",
        status: "needs_review",
        detail: "已关联一张截图；缺少安全重放证据。",
        evidenceCount: 1,
      },
    ],
    artifact: {
      artifactId: "artifact_fallback_002",
      source: "研究资料库：界面轨迹 + 角色矩阵",
      kind: "浏览器工作流资料",
      provenance: "由预置测试租户生成，未包含生产用户数据。",
      evidenceCount: 1,
    },
    validationGate: {
      label: "需要审核门",
      status: "blocked",
      approval: "两项状态修改检查正在等待人工审核。",
      evidenceCount: 1,
    },
    hunter: {
      playbook: "角色边界 / 权限提升",
      recommendation: "needs_human_review",
      priorityScore: 61,
      impactScore: 82,
      rejectionRiskScore: 35,
      nextAction: "在任何状态修改型验证前收集角色矩阵证据。",
    },
    evidenceSupportSummary: null,
    memory: null,
    refutationSummary: {
      parked: 0,
      refuted: 0,
      total: 0,
      unverified: 0,
    },
  },
  {
    runId: "dry_run_2026_07_01_004",
    asset: "admin.example.com",
    hypothesisCount: 1,
    blockedCount: 1,
    reportTitle: "管理员导出流程缺少低风险验证证据",
    evidenceCount: 0,
    stages: [
      {
        label: "资料接入",
        status: "complete",
        detail: "已关联公开文档和导出流程说明。",
        evidenceCount: 0,
      },
      {
        label: "范围守卫",
        status: "needs_review",
        detail: "仅管理员可见的攻击面需要明确项目授权。",
        evidenceCount: 0,
      },
      {
        label: "假设引擎",
        status: "complete",
        detail: "已保留一个授权边界假设。",
        evidenceCount: 0,
      },
      {
        label: "验证审批门",
        status: "blocked",
        detail: "在审核和测试数据准备前，不进行实时验证。",
        evidenceCount: 0,
      },
      {
        label: "证据快照",
        status: "queued",
        detail: "等待安全样本和复现证据。",
        evidenceCount: 0,
      },
    ],
    artifact: {
      artifactId: "artifact_fallback_004",
      source: "研究资料库：文档 + 导出流程说明",
      kind: "文档资料",
      provenance: "仅包含人工说明；资料库接入尚待完成。",
      evidenceCount: 0,
    },
    validationGate: {
      label: "等待人工审核",
      status: "waiting_human",
      approval: "验证前需要测试样本和范围审核。",
      evidenceCount: 0,
    },
    hunter: {
      playbook: "通用业务逻辑候选",
      recommendation: "park",
      priorityScore: 34,
      impactScore: 62,
      rejectionRiskScore: 55,
      nextAction: "暂停，直至出现更强的溯源或影响证据。",
    },
    evidenceSupportSummary: null,
    memory: null,
    refutationSummary: {
      parked: 0,
      refuted: 0,
      total: 0,
      unverified: 0,
    },
  },
];
