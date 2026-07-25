import Link from "next/link";
import {
  ArrowLeft,
  ClipboardCheck,
  Database,
  FileText,
  ShieldCheck,
  Target,
} from "lucide-react";
import { getPipelineRun } from "@/lib/api";
import { toPipelineRunSummary } from "@/lib/pipeline-runs-data";
import {
  fallbackRunDetail,
  formatLabel,
  safeDisplay,
  safeStringList,
} from "@/lib/workbench-detail-data";

type PageProps = {
  params: Promise<{ runId: string }>;
};

export default async function RunDetailPage({ params }: PageProps) {
  const { runId } = await params;
  const run = await getPipelineRun(runId, fallbackRunDetail(runId));

  if (!run) {
    return (
      <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
        <PageBack />
        <section className="mt-6 border border-[var(--line)] bg-white p-6">
          <h1 className="text-2xl font-semibold text-balance">未找到研究审计</h1>
          <p className="mt-2 text-pretty text-[var(--muted)]">{safeDisplay(runId)}</p>
        </section>
      </main>
    );
  }

  const summary = toPipelineRunSummary(run);
  const payload = run.payload;
  const isDemoData = run.policy_text_hash === "fallback-only";
  const runDataMode = isDemoData ? "演示数据" : "在线数据";
  const artifactId = summary.artifact.artifactId;
  const validationWorkspace = payload?.validation_workspace;
  const reportDraft = payload?.report_draft;
  const sourceAuditHypotheses = payload?.hypotheses ?? [];
  const candidateAssessments = payload?.hypothesis_assessments ?? [];
  const refutationReasons = safeStringList(payload?.refutation?.reasons);
  const targetModel = payload?.target_model;
  const hunterAssessment = run.hunter_intelligence?.assessments?.[0];
  const hunterReasons = safeStringList(hunterAssessment?.reasons);
  const closedLoop = payload?.closed_loop_summary;
  const closedLoopBlockedReasons = safeStringList(closedLoop?.blocked_reasons);
  const closedLoopSafetyNotes = safeStringList(closedLoop?.safety_notes);
  const closedLoopSteps = closedLoop?.steps ?? [];
  const memoryLessons = closedLoop?.memory_lessons ?? [];
  const closedLoopReasoningContext = closedLoop?.reasoning_context;

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <Database size={17} aria-hidden="true" />
          {safeDisplay(run.id)}
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            {runDataMode}
          </span>
        </p>
        <div className="mt-3 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <h1 className="max-w-4xl text-3xl font-semibold leading-tight text-balance">
              {safeDisplay(summary.reportTitle, "研究审计")}
            </h1>
            <p className="mt-2 text-pretty text-[var(--muted)]">
              {safeDisplay(summary.asset)}
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {artifactId ? (
              <ActionLink href={`/artifacts/${encodeURIComponent(artifactId)}`} icon={Database}>
                资料
              </ActionLink>
            ) : null}
            <ActionLink href={`/validation-workspace/${encodeURIComponent(run.id)}`} icon={ClipboardCheck}>
              审核验证
            </ActionLink>
            <ActionLink href={`/reports/${encodeURIComponent(run.id)}`} icon={FileText}>
              报告
            </ActionLink>
          </div>
        </div>
      </header>
      {isDemoData ? (
        <p className="mt-4 border border-[var(--line)] bg-white px-4 py-3 text-sm font-semibold text-[var(--warning)]">
          当前显示演示数据，因为此研究审计使用了研究摘要样例。
        </p>
      ) : null}

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-6">
        <Metric label="假设" value={summary.hypothesisCount} />
        <Metric label="审核阻塞项" value={summary.blockedCount} />
        <Metric label="证据引用" value={summary.evidenceCount} />
        <Metric label="范围" value={formatLabel(run.scope_status)} />
        <Metric label="审核门" value={formatLabel(summary.validationGate.status)} />
        <Metric label="循环" value={formatLabel(closedLoop?.status ?? "not_started")} />
      </section>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section className="grid gap-5">
          {sourceAuditHypotheses.length > 0 ? (
            <section className="border border-[var(--line)] bg-white">
              <SectionHeader icon={Target} title="源代码审计假设" />
              <div className="divide-y divide-[var(--line)]">
                {sourceAuditHypotheses.map((hypothesis, index) => {
                  const evidenceNeeded = safeStringList(hypothesis.evidence_needed);
                  const falsePositiveChecks = safeStringList(hypothesis.false_positive_checks);
                  const rankingReasons = safeStringList(hypothesis.ranking_reasons);

                  return (
                    <article key={`source-audit-hypothesis-${index}`} className="grid gap-4 p-5 text-sm">
                      <div className="grid gap-2">
                        <p className="break-words text-pretty font-semibold">
                          {safeDisplay(hypothesis.hypothesis, `假设 ${index + 1}`)}
                        </p>
                        <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                          <Field label="类型" value={formatLabel(hypothesis.vuln_type)} />
                          <Field label="风险" value={formatLabel(hypothesis.risk_level)} />
                          <Field label="优先级评分" value={hypothesis.priority_score ?? 0} />
                          <Field label="验证" value={formatLabel(hypothesis.validation_mode)} />
                          <Field
                            label="反证状态"
                            value={formatLabel(hypothesis.refutation_status ?? "unverified")}
                          />
                        </dl>
                      </div>
                      <div className="grid gap-3 lg:grid-cols-2">
                        <ReviewList title="所需证据" items={evidenceNeeded} />
                        <ReviewList title="误报检查" items={falsePositiveChecks} />
                        <ReviewList title="排序原因" items={rankingReasons} />
                      </div>
                    </article>
                  );
                })}
              </div>
            </section>
          ) : null}

          {candidateAssessments.length > 0 ? (
            <section className="border border-[var(--line)] bg-white">
              <SectionHeader icon={Target} title="候选项生命周期" />
              <div className="divide-y divide-[var(--line)]">
                {candidateAssessments.map((candidate, index) => {
                  const reasons = safeStringList(candidate.refutation?.reasons);
                  const primitives = safeStringList(candidate.exploit_chain?.primitives);
                  const preconditions = safeStringList(candidate.exploit_chain?.preconditions);
                  const refutationQuestions = safeStringList(candidate.refutation?.questions);
                  const chainConfidence = percentScore(candidate.exploit_chain?.confidence);

                  return (
                    <article
                      key={candidate.candidate_id ?? `candidate-${index}`}
                      className="grid gap-4 p-5 text-sm xl:grid-cols-[140px_minmax(0,1fr)_190px]"
                    >
                      <div className="grid content-start gap-2">
                        <p className="break-words text-xs font-semibold uppercase text-[var(--muted)]">
                          {safeDisplay(candidate.candidate_id, `candidate_${index + 1}`)}
                        </p>
                        <p className="font-semibold">{formatLabel(candidate.candidate_status)}</p>
                      </div>
                      <div className="min-w-0">
                        <p className="break-words text-pretty font-semibold">
                          {safeDisplay(candidate.hypothesis?.hypothesis, "未命名假设")}
                        </p>
                        <dl className="mt-4 grid gap-3 sm:grid-cols-2">
                          <Field label="验证" value={formatLabel(candidate.hypothesis?.validation_mode)} />
                          <Field label="反证" value={formatLabel(candidate.refutation?.status)} />
                          <Field label="计划" value={formatLabel(candidate.validation_plan?.status)} />
                          <Field
                            label="证据提示"
                            value={candidate.evidence_hints?.length ?? 0}
                          />
                          <Field
                            label="利用链置信度"
                            value={chainConfidence === null ? "暂不可用" : `${chainConfidence}%`}
                          />
                          <Field label="原语" value={primitives.length} />
                          <Field label="前提条件" value={preconditions.length} />
                          <Field label="反证问题" value={refutationQuestions.length} />
                        </dl>
                        {candidate.exploit_chain ? (
                          <div className="mt-4 grid gap-2 border-t border-[var(--line)] pt-3 text-xs text-[var(--muted)]">
                            <p className="font-semibold uppercase">利用链推理</p>
                            <p className="break-words">
                              {safeDisplay(candidate.exploit_chain.impact, "影响摘要暂不可用")}
                            </p>
                            <ul className="flex flex-wrap gap-1.5">
                              {safeStringList(candidate.exploit_chain.safety_notes).map((note) => (
                                <li
                                  key={`${candidate.candidate_id}-${note}`}
                                  className="rounded-sm border border-[var(--line)] px-2 py-0.5 font-semibold"
                                >
                                  {formatLabel(note)}
                                </li>
                              ))}
                            </ul>
                          </div>
                        ) : null}
                        {reasons.length > 0 ? (
                          <ul className="mt-4 flex flex-wrap gap-1.5">
                            {reasons.map((reason) => (
                              <li
                                key={`${candidate.candidate_id}-${reason}`}
                                className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold text-[var(--muted)]"
                              >
                                {formatLabel(reason)}
                              </li>
                            ))}
                          </ul>
                        ) : null}
                      </div>
                      <div className="grid content-start gap-2 xl:border-l xl:border-[var(--line)] xl:pl-5">
                        <p className="font-semibold">
                          {safeDisplay(candidate.hunter_assessment?.playbook_label, "暂无策略手册")}
                        </p>
                        <p className="text-2xl font-semibold tabular-nums">
                          {candidate.hunter_assessment?.hunter_priority_score ?? 0}
                        </p>
                        <p className="text-[var(--muted)]">
                          {formatLabel(candidate.hunter_assessment?.recommendation)}
                        </p>
                      </div>
                    </article>
                  );
                })}
              </div>
            </section>
          ) : null}

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={Target} title="研究审核时间线" />
            <ol className="divide-y divide-[var(--line)]">
              {summary.stages.map((stage) => (
                <li
                  key={`${summary.runId}-${stage.label}`}
                  className="grid gap-3 p-5 text-sm lg:grid-cols-[180px_150px_minmax(0,1fr)_80px]"
                >
                  <p className="font-semibold">{safeDisplay(stage.label)}</p>
                  <p className="font-semibold text-[var(--accent-strong)]">
                    {formatLabel(stage.status)}
                  </p>
                  <div className="grid gap-2">
                    <p className="text-pretty text-[var(--muted)]">{safeDisplay(stage.detail)}</p>
                    {stage.safetyNotes && stage.safetyNotes.length > 0 ? (
                      <ul className="flex flex-wrap gap-1.5">
                        {stage.safetyNotes.map((note) => (
                          <li
                            key={`${summary.runId}-${stage.label}-${note}`}
                            className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold text-[var(--muted)]"
                          >
                            {formatLabel(note)}
                          </li>
                        ))}
                      </ul>
                    ) : null}
                    {stage.agentBoundary ? (
                      <div className="grid gap-2 border-t border-[var(--line)] pt-2 text-xs">
                        <p className="font-semibold uppercase text-[var(--muted)]">
                          智能体审核边界
                        </p>
                        <dl className="grid gap-2 sm:grid-cols-2">
                          <Field label="角色" value={formatLabel(stage.agentBoundary.role)} />
                          <Field
                            label="人工审核门"
                            value={stage.agentBoundary.requiresHumanReview ? "需要处理" : "仅供审核"}
                          />
                        </dl>
                        {stage.agentBoundary.allowedActions.length > 0 ? (
                          <div className="grid gap-1">
                            <p className="font-semibold uppercase text-[var(--muted)]">
                              范围内审核操作
                            </p>
                            <ul className="flex flex-wrap gap-1.5">
                              {stage.agentBoundary.allowedActions.map((action) => (
                                <li
                                  key={`${summary.runId}-${stage.label}-allow-${action}`}
                                  className="rounded-sm border border-[var(--line)] px-2 py-0.5 font-semibold text-[var(--accent-strong)]"
                                >
                                  {formatLabel(action)}
                                </li>
                              ))}
                            </ul>
                          </div>
                        ) : null}
                        {stage.agentBoundary.blockedActions.length > 0 ? (
                          <div className="grid gap-1">
                            <p className="font-semibold uppercase text-[var(--muted)]">已阻断操作</p>
                            <ul className="flex flex-wrap gap-1.5">
                              {stage.agentBoundary.blockedActions.map((action) => (
                                <li
                                  key={`${summary.runId}-${stage.label}-block-${action}`}
                                  className="rounded-sm border border-[var(--line)] px-2 py-0.5 font-semibold text-[var(--warning)]"
                                >
                                  {formatLabel(action)}
                                </li>
                              ))}
                            </ul>
                          </div>
                        ) : null}
                      </div>
                    ) : null}
                    {stage.lessonTraces && stage.lessonTraces.length > 0 ? (
                      <ul className="grid gap-2 border-t border-[var(--line)] pt-2">
                        {stage.lessonTraces.map((trace) => (
                          <li
                            key={`${summary.runId}-${stage.label}-${trace.lessonId}`}
                            className="grid gap-1 text-xs text-[var(--muted)]"
                          >
                            <p className="break-words font-semibold text-[var(--foreground)]">
                              {formatLabel(trace.action)}经验：{formatLabel(trace.recommendation)}
                            </p>
                            <p className="break-words">
                              {safeDisplay(trace.playbook)} 作用于 {safeDisplay(trace.surface)}，来自
                              {trace.sourceSignalCount} 个学习信号
                            </p>
                            {trace.reasons.length > 0 ? (
                              <ul className="flex flex-wrap gap-1.5">
                                {trace.reasons.map((reason) => (
                                  <li
                                    key={`${trace.lessonId}-${reason}`}
                                    className="rounded-sm border border-[var(--line)] px-2 py-0.5 font-semibold"
                                  >
                                    {formatLabel(reason)}
                                  </li>
                                ))}
                              </ul>
                            ) : null}
                          </li>
                        ))}
                      </ul>
                    ) : null}
                  </div>
                  <p className="tabular-nums text-[var(--muted)]">{stage.evidenceCount} 条证据</p>
                </li>
              ))}
            </ol>
          </section>
        </section>

        <aside className="grid content-start gap-5">
          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={ClipboardCheck} title="闭环" />
            <div className="grid gap-4 p-5 text-sm">
              <p className="font-semibold text-[var(--accent-strong)]">
                {formatLabel(closedLoop?.status ?? "not_started")}
              </p>
              <dl className="grid grid-cols-2 gap-3">
                <Field label="观察" value={closedLoop?.manual_observation_count ?? 0} />
                <Field label="审核" value={closedLoop?.reviewed_claim_count ?? 0} />
                <Field label="候选项" value={closedLoop?.finding_candidate_count ?? 0} />
                <Field label="学习" value={closedLoop?.learning_signal_count ?? 0} />
                <Field label="经验" value={closedLoop?.lesson_count ?? 0} />
                <Field label="记忆" value={formatLabel(closedLoop?.brain_memory_status ?? "waiting_for_learning")} />
              </dl>
              {closedLoopReasoningContext ? (
                <div className="grid gap-2 border-t border-[var(--line)] pt-4">
                  <p className="font-semibold uppercase text-[var(--muted)]">
                    推理记忆
                  </p>
                  <dl className="grid grid-cols-2 gap-3">
                    <Field
                      label="最高评分"
                      value={closedLoopReasoningContext.highest_reasoning_review_score}
                    />
                    <Field
                      label="上下文"
                      value={closedLoopReasoningContext.learning_signal_context_count}
                    />
                    <Field label="来源" value={formatLabel(closedLoopReasoningContext.source)} />
                    <Field
                      label="审核门"
                      value={formatLabel(closedLoopReasoningContext.safety_gate ?? "advisory_memory_only")}
                    />
                  </dl>
                </div>
              ) : null}
              {closedLoopSteps.length > 0 ? (
                <ol className="grid gap-3 border-t border-[var(--line)] pt-4">
                  {closedLoopSteps.map((step) => (
                    <li
                      key={step.key}
                      className="grid gap-2 border-l-2 border-[var(--line)] pl-3"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <p className="font-semibold">{safeDisplay(step.label)}</p>
                        <span
                          className={`shrink-0 text-xs font-semibold uppercase ${closedLoopStepClass(
                            step.status,
                          )}`}
                        >
                          {formatLabel(step.status)}
                        </span>
                      </div>
                      <p className="text-pretty text-[var(--muted)]">
                        {safeDisplay(step.reason)}
                      </p>
                      <dl className="grid gap-2 border-t border-[var(--line)] pt-2">
                        <Field label="审核门" value={formatLabel(step.safety_gate)} />
                        <Field label="下一步审核操作" value={step.next_allowed_action} />
                      </dl>
                    </li>
                  ))}
                </ol>
              ) : null}
              {memoryLessons.length > 0 ? (
                <ul className="grid gap-3 border-t border-[var(--line)] pt-4">
                  {memoryLessons.map((lesson) => (
                    <li
                      key={lesson.lesson_id}
                      className="grid gap-2 border-l-2 border-[var(--accent)] pl-3"
                    >
                      <div className="flex items-start justify-between gap-3">
                        <p className="break-words font-semibold">
                          {formatLabel(lesson.recommendation)}记忆
                        </p>
                        <span className="shrink-0 text-xs font-semibold text-[var(--muted)]">
                          {lesson.confidence}
                        </span>
                      </div>
                      <p className="break-words text-[var(--muted)]">
                        {safeDisplay(lesson.playbook_id)} 作用于
                        {safeDisplay(lesson.surface_pattern)}，来自
                        {lesson.source_signal_count} 个学习信号
                      </p>
                      {lesson.reasons.length > 0 ? (
                        <ul className="flex flex-wrap gap-1.5">
                          {lesson.reasons.map((reason) => (
                            <li
                              key={`${lesson.lesson_id}-${reason}`}
                              className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold text-[var(--muted)]"
                            >
                              {formatLabel(reason)}
                            </li>
                          ))}
                        </ul>
                      ) : null}
                    </li>
                  ))}
                </ul>
              ) : null}
              {closedLoopSafetyNotes.length > 0 ? (
                <ul className="flex flex-wrap gap-1.5">
                  {closedLoopSafetyNotes.map((note) => (
                    <li
                      key={`closed-loop-note-${note}`}
                      className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold text-[var(--muted)]"
                    >
                      {formatLabel(note)}
                    </li>
                  ))}
                </ul>
              ) : null}
              {closedLoopBlockedReasons.length > 0 ? (
                <div className="border-t border-[var(--line)] pt-3">
                  <p className="font-semibold">审核要求</p>
                  <ul className="mt-2 grid gap-1 text-[var(--muted)]">
                    {closedLoopBlockedReasons.map((reason) => (
                      <li key={`closed-loop-blocked-${reason}`}>{formatLabel(reason)}</li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={ShieldCheck} title="验证审核门" />
            <div className="grid gap-3 p-5 text-sm">
              <p className="font-semibold">{safeDisplay(summary.validationGate.label)}</p>
              <p className="text-pretty text-[var(--muted)]">
                {safeDisplay(summary.validationGate.approval)}
              </p>
              <p className="font-semibold tabular-nums text-[var(--muted)]">
                {summary.validationGate.evidenceCount} 条证据
              </p>
            </div>
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={Target} title="研究优先级" />
            <div className="grid gap-3 p-5 text-sm">
              <div className="flex items-start justify-between gap-4">
                <p className="font-semibold">{safeDisplay(summary.hunter.playbook)}</p>
                <p className="text-2xl font-semibold tabular-nums">
                  {summary.hunter.priorityScore}
                </p>
              </div>
              <p className="font-semibold text-[var(--accent-strong)]">
                {formatLabel(summary.hunter.recommendation)}
              </p>
              <p className="text-pretty text-[var(--muted)]">
                {safeDisplay(hunterAssessment?.next_action ?? summary.hunter.nextAction)}
              </p>
              {hunterReasons.length > 0 ? (
                <ul className="flex flex-wrap gap-1.5">
                  {hunterReasons.map((reason) => (
                    <li
                      key={reason}
                      className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold text-[var(--muted)]"
                    >
                      {formatLabel(reason)}
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={Database} title="安全载荷事实" />
            <dl className="grid gap-3 p-5 text-sm">
              <Field label="资料类型" value={formatLabel(payload?.artifact_kind ?? summary.artifact.kind)} />
              <Field label="目标端点" value={targetModel?.endpoints?.length ?? 0} />
              <Field label="对象" value={targetModel?.objects?.length ?? 0} />
              <Field label="敏感操作" value={targetModel?.sensitive_actions?.length ?? 0} />
              <Field label="工作区" value={formatLabel(validationWorkspace?.status ?? "unavailable")} />
              <Field label="报告审核" value={reportDraft?.human_review_required ? "需要处理" : "暂不可用"} />
            </dl>
          </section>

          {refutationReasons.length > 0 ? (
            <section className="border border-[var(--line)] bg-white">
              <SectionHeader icon={ClipboardCheck} title="审核要求" />
              <ul className="grid gap-2 p-5 text-sm text-[var(--muted)]">
                {refutationReasons.map((reason) => (
                  <li key={reason}>{formatLabel(reason)}</li>
                ))}
              </ul>
            </section>
          ) : null}
        </aside>
      </div>
    </main>
  );
}

function closedLoopStepClass(status: string): string {
  switch (status) {
    case "complete":
      return "text-[var(--accent-strong)]";
    case "blocked":
      return "text-[var(--danger)]";
    default:
      return "text-[var(--warning)]";
  }
}

function percentScore(value: number | null | undefined): number | null {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return null;
  }

  const normalized = value >= 0 && value <= 1 ? value * 100 : value;

  return Math.max(0, Math.min(100, Math.round(normalized)));
}

function PageBack() {
  return (
    <Link
      href="/"
      className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
    >
      <ArrowLeft size={17} aria-hidden="true" />
      控制台
    </Link>
  );
}

function ActionLink({
  children,
  href,
  icon: Icon,
}: {
  children: React.ReactNode;
  href: string;
  icon: typeof Database;
}) {
  return (
    <Link
      href={href}
      className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
    >
      <Icon size={17} aria-hidden="true" />
      {children}
    </Link>
  );
}

function Metric({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="border border-[var(--line)] bg-white p-4">
      <p className="text-sm text-[var(--muted)]">{label}</p>
      <p className="mt-3 text-2xl font-semibold tabular-nums">{value}</p>
    </div>
  );
}

function SectionHeader({ icon: Icon, title }: { icon: typeof Database; title: string }) {
  return (
    <div className="flex items-center justify-between border-b border-[var(--line)] px-5 py-4">
      <h2 className="text-lg font-semibold">{title}</h2>
      <Icon size={19} className="text-[var(--accent)]" aria-hidden="true" />
    </div>
  );
}

function Field({ label, value }: { label: string; value: unknown }) {
  return (
    <div className="grid gap-1">
      <dt className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</dt>
      <dd className="break-words font-semibold">{safeDisplay(value)}</dd>
    </div>
  );
}

function ReviewList({ items, title }: { items: string[]; title: string }) {
  return (
    <div>
      <p className="text-xs font-semibold uppercase text-[var(--muted)]">{title}</p>
      {items.length === 0 ? (
        <p className="mt-1 font-semibold">暂无就绪项</p>
      ) : (
        <ul className="mt-2 grid gap-1 text-[var(--muted)]">
          {items.map((item) => (
            <li key={`${title}-${item}`} className="break-words">
              {safeDisplay(item)}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
