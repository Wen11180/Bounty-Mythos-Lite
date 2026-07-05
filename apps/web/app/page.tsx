import {
  AlertTriangle,
  BadgeCheck,
  BarChart3,
  BookOpen,
  Bot,
  ClipboardCheck,
  Database,
  FileSearch,
  FileText,
  Gauge,
  GitBranch,
  Home,
  Layers,
  ListChecks,
  Lock,
  Settings,
  ShieldCheck,
  Target,
  Upload,
} from "lucide-react";
import Link from "next/link";
import {
  evaluateScopeGuard,
  getFindings,
  getMythosBrainProgram,
  getPipelineRuns,
  getPrograms,
  getReports,
} from "@/lib/api";
import {
  fallbackFindings,
  fallbackMythosBrainProfile,
  fallbackPrograms,
  fallbackReports,
  fallbackScopeGuardDecision,
  fallbackScopeGuardRequest,
  fallbackScopeGuardRule,
} from "@/lib/fallback-data";
import { mythosPipelineStages } from "@/lib/mythos-pipeline-data";
import {
  deriveIntelligenceRadar,
  resolvePipelineRunRows,
  type PipelineRunSummary,
} from "@/lib/pipeline-runs-data";
import type { Finding, PolicyStatus, ValidationStatus } from "@/lib/api";

const navigation = [
  { label: "Dashboard", icon: Home },
  { label: "Programs", icon: Target },
  { label: "Assets", icon: Layers },
  { label: "Artifact Repository", icon: Database, href: "/artifacts" },
  { label: "API Model", icon: GitBranch },
  { label: "Business Flows", icon: ListChecks },
  { label: "Hypotheses", icon: Bot },
  { label: "Validation Plans", icon: ClipboardCheck },
  { label: "Findings", icon: FileSearch },
  { label: "Reports", icon: FileText },
  { label: "Submissions", icon: Upload },
  { label: "Knowledge Base", icon: BookOpen },
  { label: "Settings / Policy Guard", icon: Settings },
];

const kpis = [
  { label: "Accepted rate", value: "31%", target: "目标 30%+" },
  { label: "Duplicate rate", value: "22%", target: "目标 <25%" },
  { label: "Informative / N/A", value: "12%", target: "目标 <15%" },
  { label: "Policy violation", value: "0", target: "必须 0" },
];

const guardRules = [
  "禁止自动攻击公网目标",
  "禁止高频扫描和 DoS",
  "禁止触碰真实用户数据",
  "线上验证必须人工确认",
];

const reportReadyStatuses: ValidationStatus[] = [
  "report_ready",
  "human_submitted",
  "accepted",
];

function titleCase(value: string): string {
  return value
    .replace(/:/g, ": ")
    .split(/[\s_]+/)
    .filter(Boolean)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(" ");
}

function formatGuard(finding: Finding): string {
  if (finding.scope_status === "in_scope" && finding.policy_status === "allowed") {
    return "Scope / Policy 通过";
  }

  return "等待人工确认";
}

function formatStatus(status: ValidationStatus): string {
  return titleCase(status);
}

function formatSeverity(severity: string): string {
  return titleCase(severity);
}

function formatWorkbenchStatus(status: string): string {
  return status === "waiting_human" ? "Waiting human" : titleCase(status);
}

function statusDotClass(
  status:
    | PipelineRunSummary["stages"][number]["status"]
    | PipelineRunSummary["validationGate"]["status"],
): string {
  switch (status) {
    case "approved":
    case "complete":
      return "bg-[var(--accent)]";
    case "blocked":
    case "failed":
      return "bg-[var(--danger)]";
    case "needs_review":
    case "waiting_human":
      return "bg-[var(--warning)]";
    case "running":
      return "bg-[var(--foreground)]";
    default:
      return "bg-[var(--muted)]";
  }
}

function statusTextClass(
  status:
    | PipelineRunSummary["stages"][number]["status"]
    | PipelineRunSummary["validationGate"]["status"],
): string {
  switch (status) {
    case "approved":
    case "complete":
      return "text-[var(--accent-strong)]";
    case "blocked":
    case "failed":
      return "text-[var(--danger)]";
    case "needs_review":
    case "waiting_human":
      return "text-[var(--warning)]";
    default:
      return "text-[var(--muted)]";
  }
}

function countPolicyBlocked(findings: Finding[]): number {
  return findings.filter((finding) => finding.policy_status === "blocked").length;
}

function countNeedsReview(findings: Finding[]): number {
  const reviewStatuses: PolicyStatus[] = ["blocked", "needs_review"];

  return findings.filter(
    (finding) =>
      finding.scope_status === "needs_review" || reviewStatuses.includes(finding.policy_status),
  ).length;
}

export default async function Dashboard() {
  const [programs, findings, reports, pipelineRuns] = await Promise.all([
    getPrograms(fallbackPrograms),
    getFindings(fallbackFindings),
    getReports(fallbackReports),
    getPipelineRuns([]),
  ]);
  const activeProgramId = programs[0]?.id ?? fallbackMythosBrainProfile.program_id;
  const fallbackBrainProfile = {
    ...fallbackMythosBrainProfile,
    program_id: activeProgramId,
    program_name: programs[0]?.name ?? fallbackMythosBrainProfile.program_name,
  };
  const brainProfile = await getMythosBrainProgram(activeProgramId, fallbackBrainProfile);
  const scopeGuardDecision = await evaluateScopeGuard(
    fallbackScopeGuardRule,
    fallbackScopeGuardRequest,
    fallbackScopeGuardDecision,
  );

  const todayMetrics = [
    { label: "已解析项目", value: String(programs.length) },
    { label: "高价值候选", value: String(findings.length) },
    {
      label: "可提交报告",
      value: String(
        Math.max(
          reports.length,
          findings.filter((finding) => reportReadyStatuses.includes(finding.validation_status)).length,
        ),
      ),
    },
    { label: "需要人工确认", value: String(countNeedsReview(findings)) },
    { label: "Policy 风险拦截", value: String(countPolicyBlocked(findings)) },
  ];
  const { dataMode: pipelineRunDataMode, runs: runRows } = resolvePipelineRunRows(pipelineRuns);
  const dashboardUsesFallbackData =
    programs === fallbackPrograms ||
    findings === fallbackFindings ||
    reports === fallbackReports ||
    brainProfile === fallbackBrainProfile ||
    scopeGuardDecision === fallbackScopeGuardDecision;
  const dashboardDataMode = dashboardUsesFallbackData ? "Demo data" : "Live data";
  const intelligenceRadar = deriveIntelligenceRadar(runRows);
  const radarSignalsByRunId = new Map(
    intelligenceRadar.runSignals.map((signal) => [signal.run.runId, signal]),
  );
  const topBrainSurfaces = brainProfile.high_value_surfaces.slice(0, 3);
  const appliedLessons = (brainProfile.applied_lessons ?? []).slice(0, 2);
  const skippedLessons = (brainProfile.skipped_lessons ?? []).slice(0, 2);
  const lessonAdjustedSurfaces = brainProfile.lesson_adjusted_surfaces ?? [];
  const recentLearningSignals = brainProfile.recent_learning_signals.slice(0, 3);

  return (
    <main className="min-h-screen lg:grid lg:grid-cols-[280px_1fr]">
      <aside className="border-b border-[var(--line)] bg-[#ededdf] px-4 py-5 lg:min-h-screen lg:border-b-0 lg:border-r">
        <div className="mb-8 flex items-center gap-3 px-2">
          <div className="flex h-10 w-10 items-center justify-center rounded-md bg-[var(--foreground)] text-white">
            <ShieldCheck size={22} aria-hidden="true" />
          </div>
          <div>
            <p className="text-sm font-semibold uppercase tracking-wide text-[var(--muted)]">
              Bounty
            </p>
            <h1 className="text-xl font-semibold">Mythos-Lite</h1>
          </div>
        </div>

        <nav className="grid gap-1">
          {navigation.map((item) => (
            <Link
              href={item.href ?? "#"}
              key={item.label}
              className="flex min-h-10 items-center gap-3 rounded-md px-3 text-sm font-medium text-[#303433] hover:bg-white"
              title={item.label}
            >
              <item.icon size={18} aria-hidden="true" />
              <span>{item.label}</span>
            </Link>
          ))}
        </nav>
      </aside>

      <section className="min-w-0 px-5 py-6 sm:px-8 lg:px-10">
        <header className="mb-8 flex flex-col gap-4 border-b border-[var(--line)] pb-6 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p className="mb-2 flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
              <Gauge size={17} aria-hidden="true" />
              accepted bounty / human hour
            </p>
            <h2 className="max-w-3xl text-3xl font-semibold leading-tight sm:text-4xl">
              以 Scope Guard 和反证为中心的赏金研究工作台
            </h2>
          </div>
          <div className="max-w-sm rounded-md border border-[var(--line)] bg-white p-4">
            <div className="flex items-center justify-between gap-3">
              <p className="text-sm font-semibold text-[var(--muted)]">当前模式</p>
              <span
                className={`rounded-sm border border-[var(--line)] px-2 py-1 text-xs font-semibold uppercase ${
                  dashboardDataMode === "Demo data"
                    ? "text-[var(--warning)]"
                    : "text-[var(--accent-strong)]"
                }`}
              >
                {dashboardDataMode}
              </span>
            </div>
            <p className="mt-1 text-lg font-semibold">安全初始化骨架</p>
          </div>
        </header>
        {dashboardDataMode === "Demo data" ? (
          <p className="-mt-4 mb-5 rounded-md border border-[var(--line)] bg-white px-4 py-3 text-sm font-semibold text-[var(--warning)]">
            Demo data is shown because one or more dashboard panels came from fallback records.
          </p>
        ) : null}

        <div className="grid min-w-0 gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
          <section className="grid min-w-0 gap-5">
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
              {todayMetrics.map((metric) => (
                <div
                  key={metric.label}
                  className="rounded-md border border-[var(--line)] bg-white p-4"
                >
                  <p className="text-sm text-[var(--muted)]">{metric.label}</p>
                  <p className="mt-3 text-3xl font-semibold">{metric.value}</p>
                </div>
              ))}
            </div>

            <div className="grid gap-4 md:grid-cols-2 2xl:grid-cols-4">
              {kpis.map((kpi) => (
                <div
                  key={kpi.label}
                  className="rounded-md border border-[var(--line)] bg-white p-5"
                >
                  <div className="mb-4 flex items-center justify-between">
                    <p className="font-semibold">{kpi.label}</p>
                    <BarChart3 size={18} className="text-[var(--accent)]" aria-hidden="true" />
                  </div>
                  <p className="text-3xl font-semibold">{kpi.value}</p>
                  <p className="mt-2 text-sm text-[var(--muted)]">{kpi.target}</p>
                </div>
              ))}
            </div>

            <section className="rounded-md border border-[var(--line)] bg-white">
              <div className="grid min-w-0 gap-0 divide-y divide-[var(--line)] 2xl:grid-cols-[minmax(0,1fr)_420px] 2xl:divide-x 2xl:divide-y-0">
                <div className="min-w-0 p-5">
                  <div className="mb-4 flex items-center justify-between gap-3">
                    <div>
                      <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                        Intelligence Radar
                      </p>
                      <h3 className="mt-1 text-xl font-semibold text-balance">
                        {intelligenceRadar.topSignal
                          ? intelligenceRadar.topSignal.run.asset
                          : "No active research signal"}
                      </h3>
                    </div>
                    <Gauge size={20} className="text-[var(--accent)]" aria-hidden="true" />
                  </div>
                  {intelligenceRadar.topSignal ? (
                    <div className="grid gap-3">
                      <div className="flex flex-wrap items-center gap-2 text-sm">
                        <span className="rounded-sm border border-[var(--line)] px-2 py-1 font-semibold">
                          Score {intelligenceRadar.topSignal.radarScore}
                        </span>
                        <span className="rounded-sm border border-[var(--line)] px-2 py-1 font-semibold">
                          {intelligenceRadar.topSignal.run.hunter.playbook}
                        </span>
                        <span className="rounded-sm border border-[var(--line)] px-2 py-1 font-semibold text-[var(--muted)]">
                          {intelligenceRadar.topSignal.reportDistance}
                        </span>
                        {intelligenceRadar.topSignal.run.memory ? (
                          <span className="rounded-sm border border-[var(--line)] px-2 py-1 font-semibold text-[var(--accent-strong)]">
                            {titleCase(intelligenceRadar.topSignal.run.memory.status)}
                          </span>
                        ) : null}
                      </div>
                      <p className="max-w-3xl text-pretty text-sm text-[var(--muted)]">
                        {intelligenceRadar.topSignal.nextSafeAction}
                      </p>
                    </div>
                  ) : (
                    <p className="text-sm text-[var(--muted)]">
                      Add a scoped dry run to populate hunter priority and validation gates.
                    </p>
                  )}
                </div>
                <div className="grid min-w-0 gap-3 p-5 sm:grid-cols-2 xl:grid-cols-5">
                  <RadarMetric
                    label="Evidence gaps"
                    value={intelligenceRadar.evidenceGapCount}
                    detail="Missing or unsafe requirement support"
                  />
                  <RadarMetric
                    label="Human gates"
                    value={intelligenceRadar.humanGatePressure}
                    detail="Approval or review still required"
                  />
                  <RadarMetric
                    label="Report momentum"
                    value={intelligenceRadar.reportableMomentum}
                    detail="Human-gated candidates with support"
                  />
                  <RadarMetric
                    label="Memory lessons"
                    value={intelligenceRadar.reusableLessonCount}
                    detail={`${intelligenceRadar.memoryReadyRuns} runs ready`}
                  />
                  <RadarMetric
                    label="Unsafe requirements"
                    value={intelligenceRadar.unsafeOrRedactedRequirementCount}
                    detail="Kept out of report chain"
                    warn={intelligenceRadar.unsafeOrRedactedRequirementCount > 0}
                  />
                </div>
              </div>
            </section>

            <section className="rounded-md border border-[var(--line)] bg-white">
              <div className="flex items-center justify-between border-b border-[var(--line)] px-5 py-4">
                <h3 className="text-lg font-semibold">Mythos Pipeline</h3>
                <ShieldCheck size={19} className="text-[var(--accent)]" aria-hidden="true" />
              </div>
              <div className="grid gap-0 divide-y divide-[var(--line)] md:grid-cols-2 md:divide-x md:divide-y-0 2xl:grid-cols-7">
                {mythosPipelineStages.map((stage) => (
                  <div key={stage.label} className="min-h-36 p-4">
                    <p className="text-sm font-semibold">{stage.label}</p>
                    <p className="mt-4 text-xl font-semibold">{stage.status}</p>
                    <p className="mt-3 text-sm text-[var(--muted)]">{stage.count}</p>
                    <p className="mt-2 text-xs font-semibold uppercase text-[var(--accent-strong)]">
                      {stage.risk}
                    </p>
                  </div>
                ))}
              </div>
            </section>

            <section className="rounded-md border border-[var(--line)] bg-white">
              <div className="flex items-center justify-between border-b border-[var(--line)] px-5 py-4">
                <div>
                  <h3 className="text-lg font-semibold">Pipeline Runs / Evidence Snapshot</h3>
                  <p className="mt-1 text-sm text-[var(--muted)]">
                    Dry-run history with evidence chain counts
                  </p>
                </div>
                <span
                  className={`rounded-sm border border-[var(--line)] px-2 py-1 text-xs font-semibold uppercase ${
                    pipelineRunDataMode === "Demo data"
                      ? "text-[var(--warning)]"
                      : "text-[var(--accent-strong)]"
                  }`}
                >
                  {pipelineRunDataMode}
                </span>
                <Database size={19} className="text-[var(--accent)]" aria-hidden="true" />
              </div>
              {pipelineRunDataMode === "Demo data" ? (
                <p className="border-b border-[var(--line)] px-5 py-3 text-sm font-semibold text-[var(--warning)]">
                  Demo data is shown because no pipeline run records were returned.
                </p>
              ) : null}
              <div className="divide-y divide-[var(--line)]">
                {runRows.map((run) => {
                  const radarSignal = radarSignalsByRunId.get(run.runId);

                  return (
                    <article
                      key={run.runId}
                      className="grid min-w-0 gap-5 p-5 text-sm xl:grid-cols-[210px_minmax(0,1fr)_300px]"
                    >
                    <div className="grid content-start gap-3">
                      <div>
                        <p className="text-xs font-semibold uppercase text-[var(--muted)]">Run ID</p>
                        <p className="mt-1 break-all font-semibold">{run.runId}</p>
                      </div>
                      <div>
                        <p className="text-xs font-semibold uppercase text-[var(--muted)]">Asset</p>
                        <p className="mt-1 break-words">{run.asset}</p>
                      </div>
                      <div className="grid grid-cols-3 gap-3 tabular-nums">
                        <div>
                          <p className="text-xs font-semibold uppercase text-[var(--muted)]">Hyp</p>
                          <p className="mt-1 font-semibold">{run.hypothesisCount}</p>
                        </div>
                        <div>
                          <p className="text-xs font-semibold uppercase text-[var(--muted)]">Blocked</p>
                          <p className="mt-1 font-semibold text-[var(--warning)]">{run.blockedCount}</p>
                        </div>
                        <div>
                          <p className="text-xs font-semibold uppercase text-[var(--muted)]">Evidence</p>
                          <p className="mt-1 font-semibold">{run.evidenceCount}</p>
                        </div>
                      </div>
                      <div>
                        <p className="text-xs font-semibold uppercase text-[var(--muted)]">Report</p>
                        <p className="mt-1 break-words font-semibold">
                          {run.reportTitle ?? "No draft yet"}
                        </p>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        <WorkbenchLink href={`/runs/${encodeURIComponent(run.runId)}`}>
                          Run
                        </WorkbenchLink>
                        {run.artifact.artifactId ? (
                          <WorkbenchLink href={`/artifacts/${encodeURIComponent(run.artifact.artifactId)}`}>
                            Artifact
                          </WorkbenchLink>
                        ) : null}
                        <WorkbenchLink href={`/validation-workspace/${encodeURIComponent(run.runId)}`}>
                          Validate
                        </WorkbenchLink>
                        <WorkbenchLink href={`/reports/${encodeURIComponent(run.runId)}`}>
                          Report
                        </WorkbenchLink>
                      </div>
                    </div>

                    <div className="min-w-0">
                      <div className="mb-3 flex items-center justify-between gap-3">
                        <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                          Stage timeline
                        </p>
                        <p className="text-xs font-semibold text-[var(--muted)] tabular-nums">
                          {run.stages.length} stages
                        </p>
                      </div>
                      <ol className="grid gap-2">
                        {run.stages.map((stage) => (
                          <li
                            key={`${run.runId}-${stage.label}`}
                            className="grid gap-2 border-l-2 border-[var(--line)] pl-3 sm:grid-cols-[140px_130px_minmax(0,1fr)_76px] sm:items-start"
                          >
                            <p className="font-semibold">{stage.label}</p>
                            <p className={`flex items-center gap-2 font-semibold ${statusTextClass(stage.status)}`}>
                              <span
                                className={`size-2 rounded-full ${statusDotClass(stage.status)}`}
                                aria-hidden="true"
                              />
                              {formatWorkbenchStatus(stage.status)}
                            </p>
                            <p className="min-w-0 text-pretty text-[var(--muted)]">{stage.detail}</p>
                            <p className="text-[var(--muted)] tabular-nums">
                              {stage.evidenceCount} ev
                            </p>
                          </li>
                        ))}
                      </ol>
                    </div>

                    <div className="grid content-start gap-5 xl:border-l xl:border-[var(--line)] xl:pl-5">
                      <div>
                        <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                          Artifact / provenance
                        </p>
                        <dl className="mt-3 grid gap-2">
                          <div className="grid gap-1">
                            <dt className="text-xs font-semibold uppercase text-[var(--muted)]">Source</dt>
                            <dd className="break-words font-semibold">{run.artifact.source}</dd>
                          </div>
                          <div className="grid gap-1">
                            <dt className="text-xs font-semibold uppercase text-[var(--muted)]">Kind</dt>
                            <dd>{run.artifact.kind}</dd>
                          </div>
                          <div className="grid gap-1">
                            <dt className="text-xs font-semibold uppercase text-[var(--muted)]">
                              Provenance
                            </dt>
                            <dd className="text-pretty text-[var(--muted)]">
                              {run.artifact.provenance}
                            </dd>
                          </div>
                        </dl>
                      </div>

                      <div>
                        <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                          Validation gate
                        </p>
                        <div className="mt-3 grid gap-2">
                          <p
                            className={`flex items-center gap-2 font-semibold ${statusTextClass(
                              run.validationGate.status,
                            )}`}
                          >
                            <span
                              className={`size-2 rounded-full ${statusDotClass(
                                run.validationGate.status,
                              )}`}
                              aria-hidden="true"
                            />
                            {run.validationGate.label}
                          </p>
                          <p className="text-pretty text-[var(--muted)]">
                            {run.validationGate.approval}
                          </p>
                          <p className="text-xs font-semibold uppercase text-[var(--muted)] tabular-nums">
                            {run.validationGate.evidenceCount} evidence items attached
                          </p>
                        </div>
                      </div>

                      <div>
                        <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                          Intelligence radar
                        </p>
                        <div className="mt-3 grid gap-2">
                          <div className="grid grid-cols-3 gap-2 text-xs tabular-nums">
                            <p className="text-[var(--muted)]">
                              Score{" "}
                              <span className="font-semibold text-[var(--foreground)]">
                                {radarSignal?.radarScore ?? 0}
                              </span>
                            </p>
                            <p className="text-[var(--muted)]">
                              Gaps{" "}
                              <span className="font-semibold text-[var(--foreground)]">
                                {radarSignal?.evidenceGapCount ?? 0}
                              </span>
                            </p>
                            <p className="text-[var(--muted)]">
                              Evidence{" "}
                              <span className="font-semibold text-[var(--foreground)]">
                                {run.evidenceSupportSummary?.top_support_status
                                  ? titleCase(run.evidenceSupportSummary.top_support_status)
                                  : run.evidenceCount > 0
                                    ? "Attached"
                                    : "Missing"}
                              </span>
                            </p>
                          </div>
                          <p className="font-semibold text-[var(--accent-strong)]">
                            {radarSignal?.reportDistance ?? "Awaiting research signal"}
                          </p>
                          <p className="text-pretty text-[var(--muted)]">
                            {radarSignal?.nextSafeAction ?? run.hunter.nextAction}
                          </p>
                          {run.memory ? (
                            <p className="text-pretty text-xs font-semibold uppercase text-[var(--accent-strong)]">
                              {titleCase(run.memory.status)} · {run.memory.lessonCount} lessons
                              {run.memory.topLesson ? ` · ${run.memory.topLesson}` : ""}
                            </p>
                          ) : null}
                        </div>
                      </div>

                      <div>
                        <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                          Hunter priority
                        </p>
                        <div className="mt-3 grid gap-2">
                          <div className="flex items-start justify-between gap-3">
                            <p className="font-semibold">{run.hunter.playbook}</p>
                            <p className="text-lg font-semibold tabular-nums">
                              {run.hunter.priorityScore}
                            </p>
                          </div>
                          <p className="text-xs font-semibold uppercase text-[var(--accent-strong)]">
                            {formatWorkbenchStatus(run.hunter.recommendation)}
                          </p>
                          <div className="grid grid-cols-2 gap-3 text-xs tabular-nums">
                            <p className="text-[var(--muted)]">
                              Impact <span className="font-semibold text-[var(--foreground)]">{run.hunter.impactScore}</span>
                            </p>
                            <p className="text-[var(--muted)]">
                              Reject <span className="font-semibold text-[var(--foreground)]">{run.hunter.rejectionRiskScore}</span>
                            </p>
                          </div>
                          <p className="text-pretty text-[var(--muted)]">{run.hunter.nextAction}</p>
                        </div>
                      </div>
                    </div>
                    </article>
                  );
                })}
              </div>
            </section>

            <section className="rounded-md border border-[var(--line)] bg-white">
              <div className="flex items-center justify-between border-b border-[var(--line)] px-5 py-4">
                <h3 className="text-lg font-semibold">Findings</h3>
                <BadgeCheck size={19} className="text-[var(--accent)]" aria-hidden="true" />
              </div>
              <div className="divide-y divide-[var(--line)]">
                {findings.map((finding) => (
                  <article key={finding.id} className="grid gap-4 p-5 lg:grid-cols-[1fr_140px_120px_120px] lg:items-center">
                    <div>
                      <h4 className="font-semibold">{finding.title}</h4>
                      <p className="mt-2 text-sm text-[var(--muted)]">{formatGuard(finding)}</p>
                      {finding.operating_reasons.length > 0 ? (
                        <ul className="mt-3 flex flex-wrap gap-1.5">
                          {finding.operating_reasons.slice(0, 2).map((reason) => (
                            <li
                              key={`${finding.id}-${reason}`}
                              className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold text-[var(--muted)]"
                            >
                              {titleCase(reason)}
                            </li>
                          ))}
                        </ul>
                      ) : null}
                    </div>
                    <p className="text-sm font-semibold">{formatStatus(finding.validation_status)}</p>
                    <p className="text-sm">
                      <span className="font-semibold">{formatSeverity(finding.severity_estimate)}</span>
                    </p>
                    <p className="text-sm text-[var(--muted)]">置信度 {Math.round(finding.confidence * 100)}%</p>
                  </article>
                ))}
              </div>
            </section>
          </section>

          <aside className="grid content-start gap-5">
            <section className="rounded-md border border-[var(--line)] bg-white p-5">
              <div className="mb-4 flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <Bot size={19} className="shrink-0 text-[var(--accent)]" aria-hidden="true" />
                    <h3 className="text-lg font-semibold">Mythos Brain</h3>
                  </div>
                  <p className="mt-1 break-words text-sm text-[var(--muted)]">
                    {brainProfile.program_name}
                  </p>
                </div>
                <p className="shrink-0 text-3xl font-semibold tabular-nums">
                  {brainProfile.program_score}
                </p>
              </div>

              <div className="grid grid-cols-3 gap-2 border-y border-[var(--line)] py-3 text-xs tabular-nums">
                <div>
                  <p className="font-semibold text-[var(--muted)]">Objects</p>
                  <p className="mt-1 text-base font-semibold text-[var(--foreground)]">
                    {brainProfile.attack_surface_memory.objects.length}
                  </p>
                </div>
                <div>
                  <p className="font-semibold text-[var(--muted)]">Roles</p>
                  <p className="mt-1 text-base font-semibold text-[var(--foreground)]">
                    {brainProfile.attack_surface_memory.roles.length}
                  </p>
                </div>
                <div>
                  <p className="font-semibold text-[var(--muted)]">Signals</p>
                  <p className="mt-1 text-base font-semibold text-[var(--foreground)]">
                    {brainProfile.recent_learning_signals.length}
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-3 gap-2 border-b border-[var(--line)] py-3 text-xs tabular-nums">
                <div>
                  <p className="font-semibold text-[var(--muted)]">Strong</p>
                  <p className="mt-1 text-base font-semibold text-[var(--foreground)]">
                    {brainProfile.learning_summary.strong_evidence_count}
                  </p>
                </div>
                <div>
                  <p className="font-semibold text-[var(--muted)]">Adequate</p>
                  <p className="mt-1 text-base font-semibold text-[var(--foreground)]">
                    {brainProfile.learning_summary.adequate_evidence_count}
                  </p>
                </div>
                <div>
                  <p className="font-semibold text-[var(--muted)]">Weak</p>
                  <p className="mt-1 text-base font-semibold text-[var(--foreground)]">
                    {brainProfile.learning_summary.weak_evidence_count}
                  </p>
                </div>
              </div>

              <div className="mt-4">
                <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                  High-value surfaces
                </p>
                <div className="mt-3 grid gap-3">
                  {topBrainSurfaces.map((surface) => (
                    <div
                      key={surface.surface_key}
                      className="min-w-0 rounded-md border border-[var(--line)] bg-[#f7f7f4] p-3"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <p className="break-words font-semibold">{surface.surface_key}</p>
                        <p className="shrink-0 font-semibold tabular-nums">{surface.score}</p>
                      </div>
                      <p className="mt-2 break-words text-sm text-[var(--muted)]">
                        {surface.paths[0] ?? titleCase(surface.action)}
                      </p>
                      {lessonAdjustedSurfaces.some(
                        (adjustment) => adjustment.surface_key === surface.surface_key,
                      ) ? (
                        <p className="mt-2 text-xs font-semibold uppercase text-[var(--accent-strong)]">
                          Lesson adjusted
                        </p>
                      ) : null}
                    </div>
                  ))}
                  {topBrainSurfaces.length === 0 ? (
                    <p className="text-sm text-[var(--muted)]">No surfaces learned yet.</p>
                  ) : null}
                </div>
              </div>

              <div className="mt-4">
                <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                  Lessons
                </p>
                <div className="mt-3 grid gap-3 text-sm">
                  {appliedLessons.map((lesson) => (
                    <div
                      key={lesson.id}
                      className="min-w-0 rounded-md border border-[var(--line)] bg-[#f7f7f4] p-3"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <p className="break-words font-semibold">
                          {titleCase(lesson.recommendation)} - {lesson.surface_pattern}
                        </p>
                        <p className="shrink-0 font-semibold tabular-nums">
                          {lesson.score_delta > 0 ? "+" : ""}
                          {lesson.score_delta}
                        </p>
                      </div>
                      <p className="mt-2 text-xs font-semibold uppercase text-[var(--muted)]">
                        Confidence {lesson.confidence}
                      </p>
                      <ul className="mt-2 flex flex-wrap gap-1.5">
                        {lesson.reasons.slice(0, 2).map((reason) => (
                          <li
                            key={`${lesson.id}-${reason}`}
                            className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold text-[var(--muted)]"
                          >
                            {titleCase(reason)}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ))}
                  {appliedLessons.length === 0 ? (
                    <p className="text-[var(--muted)]">No applied lessons yet.</p>
                  ) : null}
                  {skippedLessons.length > 0 ? (
                    <div className="border-t border-[var(--line)] pt-3">
                      <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                        Skipped
                      </p>
                      <div className="mt-2 grid gap-2">
                        {skippedLessons.map((lesson) => (
                          <p
                            key={lesson.lesson_id}
                            className="break-words text-xs text-[var(--muted)]"
                          >
                            {titleCase(lesson.reason)} · {titleCase(lesson.scope_type)}
                          </p>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>
              </div>

              <div className="mt-4">
                <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                  Recent learning
                </p>
                <div className="mt-3 grid gap-2 text-sm">
                  {recentLearningSignals.map((signal) => (
                    <div
                      key={signal.id ?? `${signal.playbook_id}-${signal.surface_key}`}
                      className="grid gap-1"
                    >
                      <p className="break-words font-semibold">
                        {titleCase(signal.outcome)} - {signal.playbook_id}
                      </p>
                      <p className="break-words text-[var(--muted)]">
                        {signal.surface_key ?? "program-level signal"}
                      </p>
                    </div>
                  ))}
                  {recentLearningSignals.length === 0 ? (
                    <p className="text-[var(--muted)]">No learning signals yet.</p>
                  ) : null}
                </div>
              </div>
            </section>

            <section className="rounded-md border border-[var(--line)] bg-white p-5">
              <div className="mb-4 flex items-center gap-2">
                <Lock size={19} className="text-[var(--accent)]" aria-hidden="true" />
                <h3 className="text-lg font-semibold">Policy Guard</h3>
              </div>
              <div className="grid gap-3">
                <div className="rounded-md border border-[var(--line)] bg-[#f7f7f4] p-3 text-sm">
                  <div className="flex items-center justify-between gap-3">
                    <span className="font-semibold">当前验证决策</span>
                    <span className={scopeGuardDecision.allowed ? "text-[var(--accent-strong)]" : "text-[var(--danger)]"}>
                      {scopeGuardDecision.allowed ? "Allowed" : "Blocked"}
                    </span>
                  </div>
                  <p className="mt-2 text-[var(--muted)]">{titleCase(scopeGuardDecision.reason)}</p>
                </div>
                {guardRules.map((rule) => (
                  <div key={rule} className="flex items-start gap-3 text-sm">
                    <AlertTriangle size={16} className="mt-0.5 text-[var(--warning)]" aria-hidden="true" />
                    <span>{rule}</span>
                  </div>
                ))}
              </div>
            </section>

            <section className="rounded-md border border-[var(--line)] bg-white p-5">
              <div className="mb-4 flex items-center gap-2">
                <Database size={19} className="text-[var(--accent)]" aria-hidden="true" />
                <h3 className="text-lg font-semibold">Pipeline</h3>
              </div>
              <ol className="grid gap-3 text-sm text-[var(--muted)]">
                <li>Policy 解析</li>
                <li>Scope Guard 规则生成</li>
                <li>API / HAR / 代码资料摄入</li>
                <li>安全不变量生成</li>
                <li>反证与低风险验证计划</li>
              </ol>
            </section>
          </aside>
        </div>
      </section>
    </main>
  );
}

function WorkbenchLink({ children, href }: { children: React.ReactNode; href: string }) {
  return (
    <Link
      href={href}
      className="inline-flex min-h-8 items-center rounded-md border border-[var(--line)] px-2 text-xs font-semibold hover:bg-[#f7f7f4]"
    >
      {children}
    </Link>
  );
}

function RadarMetric({
  detail,
  label,
  value,
  warn = false,
}: {
  detail: string;
  label: string;
  value: number;
  warn?: boolean;
}) {
  return (
    <div className="rounded-md border border-[var(--line)] bg-[#f7f7f4] p-3">
      <p className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</p>
      <p className={`mt-2 text-2xl font-semibold tabular-nums ${warn ? "text-[var(--danger)]" : ""}`}>
        {value}
      </p>
      <p className="mt-1 text-pretty text-xs text-[var(--muted)]">{detail}</p>
    </div>
  );
}
