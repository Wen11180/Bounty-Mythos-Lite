import type { EvidenceSupportSummary, PipelineRun, PipelineStage } from "./api";

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
  safetyNotes?: string[];
  lessonTraces?: PipelineLessonTraceSummary[];
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
  reportableMomentum: number;
  reusableLessonCount: number;
  runSignals: RadarRunSignal[];
  topSignal: RadarRunSignal | null;
  unsafeOrRedactedRequirementCount: number;
};

export type PipelineRunRowsResult = {
  dataMode: "Demo data" | "Live data";
  runs: PipelineRunSummary[];
};

type RunSeed = Pick<
  PipelineRunSummary,
  "asset" | "blockedCount" | "evidenceCount" | "hypothesisCount"
> & {
  scopeStatus?: string;
};

const fallbackStageLabels = [
  "Artifact intake",
  "Scope Guard",
  "Hypothesis engine",
  "Validation gate",
  "Evidence snapshot",
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
    return fallback;
  }

  return stripUrlQuery(text)
    .replace(/\b(policy_text|secret|token)\b\s*[:=]\s*[^,;\s]+/gi, "$1=[redacted]")
    .replace(/\b(policy_text|secret|token)\b/gi, "[redacted]");
}

function readableStageLabel(value: string): string {
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
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

function buildDefaultStages(seed: RunSeed): PipelineRunStageSummary[] {
  const scopeBlocked = seed.scopeStatus === "out_of_scope";
  const scopeComplete = seed.scopeStatus === "in_scope" && seed.blockedCount === 0;
  const hasEvidence = seed.evidenceCount > 0;

  return [
    {
      label: "Artifact intake",
      status: "complete",
      detail: "Run manifest available; artifact repository fields will attach here.",
      evidenceCount: seed.evidenceCount,
    },
    {
      label: "Scope Guard",
      status: scopeBlocked || seed.blockedCount > 0 ? "blocked" : scopeComplete ? "complete" : "needs_review",
      detail: scopeBlocked
        ? `${seed.asset} is out of scope; validation remains blocked.`
        : seed.blockedCount > 0
          ? `${seed.blockedCount} checks held before active validation.`
          : scopeComplete
            ? `${seed.asset} cleared for low-risk planning.`
            : "Scope needs review before validation.",
      evidenceCount: 0,
    },
    {
      label: "Hypothesis engine",
      status: seed.hypothesisCount > 0 ? "complete" : "queued",
      detail: `${seed.hypothesisCount} hypotheses generated from allowed artifacts.`,
      evidenceCount: 0,
    },
    {
      label: "Validation gate",
      status: scopeBlocked || seed.blockedCount > 0 ? "blocked" : "needs_review",
      detail:
        scopeBlocked || seed.blockedCount > 0
          ? "Unsafe actions remain queued for human review."
          : "Human approval required before live target validation.",
      evidenceCount: 0,
    },
    {
      label: "Evidence snapshot",
      status: hasEvidence ? "complete" : "needs_review",
      detail: hasEvidence
        ? `${seed.evidenceCount} evidence items linked to the run.`
        : "No submission-ready evidence attached yet.",
      evidenceCount: seed.evidenceCount,
    },
  ];
}

function buildDefaultArtifact(seed: RunSeed): ArtifactProvenanceSummary {
  return {
    artifactId: null,
    source: "Pipeline response summary",
    kind: "Run artifact manifest",
    provenance: "Artifact repository pending; safe counters are shown from the run.",
    evidenceCount: seed.evidenceCount,
  };
}

function buildDefaultGate(seed: RunSeed): ValidationGateSummary {
  if (seed.scopeStatus === "out_of_scope" || seed.blockedCount > 0) {
    return {
      label: seed.scopeStatus === "out_of_scope" ? "Out-of-scope gate blocked" : "Approval gate blocked",
      status: "blocked",
      approval:
        seed.scopeStatus === "out_of_scope"
          ? "Validation is blocked until the asset is confirmed in scope."
          : `${seed.blockedCount} validation checks require human review.`,
      evidenceCount: seed.evidenceCount,
    };
  }

  if (seed.evidenceCount > 0) {
    return {
      label: "Low-risk validation approved",
      status: "approved",
      approval: "Evidence captured under a scoped validation plan.",
      evidenceCount: seed.evidenceCount,
    };
  }

  return {
    label: "Awaiting approval gate",
    status: "waiting_human",
    approval: "Needs human approval and evidence before report drafting.",
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
      label: fallbackStageLabels[index] ?? `Stage ${index + 1}`,
      status: "queued" as const,
      detail: "Awaiting pipeline metadata.",
      evidenceCount: 0,
      safetyNotes: [],
    };
    const lessonTraces = resolveLessonTraces(stage);

    return {
      label: readableStageLabel(
        safeText(stage.label ?? stage.name ?? stage.stage, fallbackStage.label),
      ),
      status: normalizeStageStatus(stage.status, fallbackStage.status),
      detail: safeText(stage.summary ?? stage.output_summary ?? stage.input_summary, fallbackStage.detail),
      evidenceCount: numberOrFallback(stage.evidence_count, fallbackStage.evidenceCount),
      safetyNotes: Array.isArray(stage.safety_notes)
        ? stage.safety_notes.map((note) => safeText(note, "safety_note"))
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
    source: safeText(artifact.source ?? artifact.repository, "Pipeline artifact repository"),
    kind: safeText(
      artifact.artifact_type ?? artifact.kind ?? artifact.source_type,
      "Run artifact manifest",
    ),
    provenance: safeText(
      artifact.provenance ?? artifact.summary ?? (artifact.digest ? "Digest recorded" : undefined),
      "Artifact repository pending; safe counters are shown from the run.",
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
      ? `Approved by ${safeText(gate.approved_by, "reviewer")}`
      : safeText(
          gate.summary,
          gate.approval_required ? "Waiting for human approval." : fallbackGate.approval,
        ),
    evidenceCount: numberOrFallback(gate.evidence_count, seed.evidenceCount),
  };
}

function buildDefaultHunter(seed: RunSeed): HunterPrioritySummary {
  const blocked = seed.scopeStatus === "out_of_scope" || seed.blockedCount > 0;

  return {
    playbook: seed.hypothesisCount > 0 ? "Candidate needs playbook match" : "No candidate",
    recommendation: blocked ? "Needs review" : "Pursue with care",
    priorityScore: blocked ? 42 : 62,
    impactScore: seed.hypothesisCount > 0 ? 75 : 0,
    rejectionRiskScore: blocked ? 55 : 25,
    nextAction: blocked
      ? "Resolve Scope Guard or approval blockers before validation."
      : "Collect minimal safe evidence under human review.",
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
    ? readableStageLabel(safeText(topLesson.recommendation, "memory"))
    : null;
  const surface = topLesson ? safeText(topLesson.surface_pattern, "unknown surface") : null;

  return {
    lessonCount: numberOrFallback(closedLoop.lesson_count, lessons.length),
    status: safeText(closedLoop.status ?? closedLoop.brain_memory_status, "waiting_for_learning"),
    topLesson: recommendation && surface ? `${recommendation} memory on ${surface}` : null,
  };
}

export function toPipelineRunSummary(run: PipelineRun): PipelineRunSummary {
  const seed: RunSeed = {
    asset: safeText(run.asset, "unknown asset"),
    blockedCount: numberOrFallback(run.blocked_count, 0),
    evidenceCount: numberOrFallback(run.evidence_count, 0),
    hypothesisCount: numberOrFallback(run.hypothesis_count, 0),
    scopeStatus: run.scope_status,
  };

  return {
    runId: safeText(run.id, "pipeline_run"),
    asset: seed.asset,
    hypothesisCount: seed.hypothesisCount,
    blockedCount: seed.blockedCount,
    reportTitle: run.report_title ? safeText(run.report_title, "Report draft") : null,
    evidenceCount: seed.evidenceCount,
    stages: resolveStages(run, seed),
    artifact: resolveArtifact(run, seed),
    validationGate: resolveValidationGate(run, seed),
    hunter: resolveHunter(run, seed),
    evidenceSupportSummary: resolveEvidenceSupportSummary(run),
    memory: resolveMemory(run),
  };
}

export function resolvePipelineRunRows(runs: PipelineRun[]): PipelineRunRowsResult {
  if (runs.length === 0) {
    return {
      dataMode: "Demo data",
      runs: fallbackPipelineRuns,
    };
  }

  return {
    dataMode: "Live data",
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
    reportableMomentum: runs.filter(hasReportableMomentum).length,
    reusableLessonCount: runs.reduce((total, run) => total + (run.memory?.lessonCount ?? 0), 0),
    runSignals,
    topSignal: runSignals[0] ?? null,
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
    return "Report review queue";
  }

  return gates === 1 ? "1 gate to report review" : `${gates} gates to report review`;
}

export const fallbackPipelineRuns: PipelineRunSummary[] = [
  {
    runId: "dry_run_2026_07_03_001",
    asset: "api.example.com",
    hypothesisCount: 3,
    blockedCount: 1,
    reportTitle: "普通用户可访问其他用户私有文件 metadata",
    evidenceCount: 4,
    stages: [
      {
        label: "Artifact intake",
        status: "complete",
        detail: "OpenAPI schema, HAR capture, and role notes linked.",
        evidenceCount: 2,
      },
      {
        label: "Scope Guard",
        status: "complete",
        detail: "In-scope API asset; destructive checks removed.",
        evidenceCount: 0,
      },
      {
        label: "Hypothesis engine",
        status: "complete",
        detail: "IDOR candidate reduced to low-risk metadata read.",
        evidenceCount: 0,
      },
      {
        label: "Validation gate",
        status: "blocked",
        detail: "One live-user data path held for manual approval.",
        evidenceCount: 0,
      },
      {
        label: "Evidence snapshot",
        status: "complete",
        detail: "Four sanitized request/response references attached.",
        evidenceCount: 4,
      },
    ],
    artifact: {
      artifactId: "artifact_fallback_001",
      source: "Research vault: HAR capture + OpenAPI schema",
      kind: "API artifact bundle",
      provenance: "Captured from researcher test account and linked to dry-run manifest.",
      evidenceCount: 4,
    },
    validationGate: {
      label: "Low-risk path approved",
      status: "approved",
      approval: "Human reviewer approved metadata-only validation.",
      evidenceCount: 4,
    },
    hunter: {
      playbook: "BOLA / IDOR object boundary",
      recommendation: "needs_human_review",
      priorityScore: 68,
      impactScore: 85,
      rejectionRiskScore: 30,
      nextAction: "Prepare human-approved, test-account-only validation.",
    },
    evidenceSupportSummary: null,
    memory: null,
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
        label: "Artifact intake",
        status: "complete",
        detail: "UI trace and role matrix imported from test workspace.",
        evidenceCount: 1,
      },
      {
        label: "Scope Guard",
        status: "needs_review",
        detail: "Team-admin route is in scope; mutation proof needs review.",
        evidenceCount: 0,
      },
      {
        label: "Hypothesis engine",
        status: "complete",
        detail: "Two privilege-boundary hypotheses generated.",
        evidenceCount: 0,
      },
      {
        label: "Validation gate",
        status: "blocked",
        detail: "State-changing validation is blocked until approval.",
        evidenceCount: 0,
      },
      {
        label: "Evidence snapshot",
        status: "needs_review",
        detail: "One screenshot attached; missing safe replay evidence.",
        evidenceCount: 1,
      },
    ],
    artifact: {
      artifactId: "artifact_fallback_002",
      source: "Research vault: UI trace + role matrix",
      kind: "Browser workflow artifact",
      provenance: "Generated from seeded test tenant with no production user data.",
      evidenceCount: 1,
    },
    validationGate: {
      label: "Approval required",
      status: "blocked",
      approval: "Two mutation checks are waiting for human approval.",
      evidenceCount: 1,
    },
    hunter: {
      playbook: "Role boundary / privilege escalation",
      recommendation: "needs_human_review",
      priorityScore: 61,
      impactScore: 82,
      rejectionRiskScore: 35,
      nextAction: "Collect role-matrix evidence before any state-changing validation.",
    },
    evidenceSupportSummary: null,
    memory: null,
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
        label: "Artifact intake",
        status: "complete",
        detail: "Public docs and export-flow notes linked.",
        evidenceCount: 0,
      },
      {
        label: "Scope Guard",
        status: "needs_review",
        detail: "Admin-only surface requires explicit program approval.",
        evidenceCount: 0,
      },
      {
        label: "Hypothesis engine",
        status: "complete",
        detail: "One authorization boundary hypothesis retained.",
        evidenceCount: 0,
      },
      {
        label: "Validation gate",
        status: "blocked",
        detail: "No live validation before approval and test data setup.",
        evidenceCount: 0,
      },
      {
        label: "Evidence snapshot",
        status: "queued",
        detail: "Waiting for safe fixture and reproduction evidence.",
        evidenceCount: 0,
      },
    ],
    artifact: {
      artifactId: "artifact_fallback_004",
      source: "Research vault: docs + export-flow notes",
      kind: "Documentation artifact",
      provenance: "Manual notes only; artifact repository ingest is pending.",
      evidenceCount: 0,
    },
    validationGate: {
      label: "Awaiting human approval",
      status: "waiting_human",
      approval: "Needs test fixture and scoped approval before validation.",
      evidenceCount: 0,
    },
    hunter: {
      playbook: "Generic business logic candidate",
      recommendation: "park",
      priorityScore: 34,
      impactScore: 62,
      rejectionRiskScore: 55,
      nextAction: "Park until stronger provenance or impact evidence appears.",
    },
    evidenceSupportSummary: null,
    memory: null,
  },
];
