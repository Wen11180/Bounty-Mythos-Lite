import { ArrowLeft, Clock, ClipboardCheck, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { getCampaignPipelineStages } from "@/lib/api";
import { toCampaignTimelineSummaries } from "@/lib/campaigns-data";
import { formatLabel } from "@/lib/workbench-detail-data";

type PageProps = {
  params: Promise<{ campaignId: string }>;
};

export default async function CampaignTimelinePage({ params }: PageProps) {
  const { campaignId } = await params;
  const stages = await getCampaignPipelineStages(campaignId, []);
  const timeline = toCampaignTimelineSummaries(stages);
  const manualValidationResultCount = timeline.filter(
    (stage) => stage.isManualValidationResult,
  ).length;
  const researchValidationFeedbackCount = timeline.filter(
    (stage) => stage.isResearchValidationFeedback,
  ).length;
  const validationFeedbackReviewCount = timeline.filter(
    (stage) => stage.isValidationFeedbackReview,
  ).length;
  const findingPromotionBlockedCount = timeline.filter(
    (stage) => stage.isFindingPromotionBlocked,
  ).length;
  const findingPromotionCount = timeline.filter((stage) => stage.isFindingPromotion).length;
  const researchPlanCount = timeline.filter((stage) => stage.isResearchPlan).length;
  const refutationDecisionCount = timeline.filter(
    (stage) => stage.isResearchRefutationDecision,
  ).length;
  const learningOutcomeCount = timeline.filter((stage) => stage.isLearningOutcome).length;
  const cycleReviewCount = timeline.filter((stage) => stage.isCycleReview).length;

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <ClipboardCheck size={17} aria-hidden="true" />
          审核时间线
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            只读
          </span>
        </p>
        <h1 className="mt-3 break-words text-3xl font-semibold leading-tight text-balance">
          {campaignId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          查看审核门、阶段顺序、耗时、受控失败摘要和引用计数；不展示原始载荷、提示词或证据引用。
        </p>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-12">
        <Metric label="阶段" value={timeline.length} />
        <Metric
          label="已阻断"
          value={timeline.filter((stage) => stage.status === "Blocked").length}
        />
        <Metric label="人工结果" value={manualValidationResultCount} />
        <Metric label="研究反馈" value={researchValidationFeedbackCount} />
        <Metric label="反馈审核" value={validationFeedbackReviewCount} />
        <Metric label="晋级审核" value={findingPromotionCount} />
        <Metric label="晋级阻塞项" value={findingPromotionBlockedCount} />
        <Metric label="研究计划" value={researchPlanCount} />
        <Metric label="反证决策" value={refutationDecisionCount} />
        <Metric label="学习结果" value={learningOutcomeCount} />
        <Metric label="周期审核" value={cycleReviewCount} />
        <Metric
          label="含停止原因"
          value={timeline.filter((stage) => stage.stopReason !== null).length}
        />
      </section>

      <section className="border border-[var(--line)] bg-white">
        <div className="grid gap-3 border-b border-[var(--line)] px-5 py-4 text-sm font-semibold text-[var(--muted)] lg:grid-cols-[70px_minmax(0,1fr)_110px_150px_90px_minmax(0,1fr)_80px_80px]">
          <span>顺序</span>
          <span>阶段</span>
          <span>状态</span>
          <span>审核门</span>
          <span>耗时</span>
          <span>错误</span>
          <span>输入引用</span>
          <span>输出引用</span>
        </div>
        {timeline.length === 0 ? (
          <p className="p-5 text-sm text-[var(--muted)]">暂无可查看的审核时间线。</p>
        ) : (
          <div className="divide-y divide-[var(--line)]">
            {timeline.map((stage) => (
              <article
                key={stage.id}
                className="grid gap-3 px-5 py-4 text-sm lg:grid-cols-[70px_minmax(0,1fr)_110px_150px_90px_minmax(0,1fr)_80px_80px]"
              >
                <p className="font-semibold tabular-nums">{stage.stageOrder}</p>
                <div className="min-w-0">
                  <p className="break-words font-semibold">{stage.auditLabel}</p>
                  {stage.auditLabel !== stage.stageKey ? (
                    <p className="mt-1 break-words text-xs text-[var(--muted)]">{stage.stageKey}</p>
                  ) : null}
                  <p className="mt-1 break-words text-[var(--muted)]">{stage.id}</p>
                  {stage.stopReason ? (
                    <p className="mt-2 flex items-center gap-2 break-words text-[var(--warning)]">
                      <Clock size={15} aria-hidden="true" />
                      {stage.stopReason}
                    </p>
                  ) : null}
                  {stage.isFindingPromotion ? (
                    <div className="mt-2 grid gap-1 text-xs font-semibold text-[var(--muted)]">
                      <p>
                        溯源引用：{stage.promotionProvenanceRefCount ?? 0} · 审核证据：
                        {stage.reviewEvidenceRefCount ?? 0}
                      </p>
                      {stage.llmAuditPromptHash ? (
                        <p className="break-words">
                          LLM 审计 · 仅提示词哈希 · 研究操作：
                          {stage.hunterOperatingAction ?? "需要审核"} · 模式：
                          {stage.llmAuditMode ?? "仅审计"} · 哈希：{stage.llmAuditPromptHash}
                        </p>
                      ) : null}
                    </div>
                  ) : null}
                  {stage.manualValidationReview ? (
                    <div className="mt-2 grid gap-1 text-xs font-semibold text-[var(--muted)]">
                      <p>
                        质量审核 · 评分：{stage.manualValidationReview.qualityScore}/100 ·
                        脱敏：{formatLabel(stage.manualValidationReview.redactionStatus)} · 晋级审核：
                        {stage.manualValidationReview.promotionReviewReady ? "已就绪" : "受控"}
                      </p>
                      <p>
                        证据质量：{formatLabel(stage.manualValidationReview.evidenceQuality)} · 安全引用：
                        {stage.manualValidationReview.safeEvidenceRefCount} · 不安全引用：
                        {stage.manualValidationReview.unsafeEvidenceRefCount}
                      </p>
                      {stage.manualValidationReview.qualityReasons.length > 0 ? (
                        <p className="break-words">
                          原因：{stage.manualValidationReview.qualityReasons.map((reason) => formatLabel(reason)).join("、")}
                        </p>
                      ) : null}
                    </div>
                  ) : null}
                  {stage.isResearchQueueMaterialized ? (
                    <p className="mt-2 text-xs font-semibold text-[var(--muted)]">
                      研究审核已入队 · 反证问题：{stage.refutationQuestionCount ?? 0} · 验证步骤：
                      {stage.validationStepCount ?? 0} · 已阻断操作：
                      {stage.blockedActionCount ?? 0}
                      {stage.requiredEvidence?.length
                        ? ` · 所需证据：${stage.requiredEvidence.join("、")}`
                        : ""}
                      {stage.candidateStatus ? ` · ${stage.candidateStatus}` : ""}
                    </p>
                  ) : null}
                  {stage.isResearchPlan ? (
                    <p className="mt-2 text-xs font-semibold text-[var(--muted)]">
                      研究计划已起草 · 反证问题：
                      {stage.refutationQuestionCount ?? 0} · 证据步骤：
                      {stage.evidenceStepCount ?? 0} · 已阻断操作：
                      {stage.blockedActionCount ?? 0}
                      {stage.requiredEvidence?.length
                        ? ` · 所需证据：${stage.requiredEvidence.join("、")}`
                        : ""}
                    </p>
                  ) : null}
                  {stage.isResearchPlan || stage.isResearchRefutationDecision ? (
                    <p className="mt-2 text-xs font-semibold text-[var(--muted)]">
                      候选项上下文 · 分诊信号：{stage.triageSignalCount ?? 0} ·
                      证据重点：{stage.evidenceFocusCount ?? 0} · 源代码事实：
                      {stage.sourceFactTypeCount ?? 0} · 优先级原因：
                      {stage.priorityReasonCount ?? 0} ·{" "}
                      {stage.hasAuthorizationGapCandidate
                        ? "访问控制缺口候选项"
                        : "无访问控制缺口候选项"}
                    </p>
                  ) : null}
                  {stage.isResearchRefutationDecision ? (
                    <p className="mt-2 text-xs font-semibold text-[var(--muted)]">
                      反证决策 · 回答：{stage.refutationAnswerCount ?? 0} ·
                      审核门：{stage.approvalCreated ? "已记录" : "待处理"} · 验证：
                      {stage.validationRunCreated ? "已入队" : "未入队"}
                      {stage.decision ? ` · ${formatLabel(stage.decision)}` : ""}
                    </p>
                  ) : null}
                  {stage.isValidationFeedbackReview ? (
                    <p className="mt-2 text-xs font-semibold text-[var(--muted)]">
                      验证反馈审核 · 发现确认门：
                      {stage.findingConfirmationAllowed ? "已审核" : "受控"} · 报告提交门：
                      {stage.reportSubmissionAllowed ? "已审核" : "受控"} · 验证门：
                      {stage.validationAllowed ? "已审核" : "受控"} · 执行门：
                      {stage.executionAllowed ? "已审核" : "受控"}
                      {stage.decision ? ` · 决策：${formatLabel(stage.decision)}` : ""}
                    </p>
                  ) : null}
                  {stage.isCycleReview && stage.status !== "Completed" ? (
                    <Link
                      href={`/campaigns/${encodeURIComponent(campaignId)}/cycle-reviews/${encodeURIComponent(stage.id)}`}
                      className="mt-2 inline-flex min-h-9 items-center rounded-md border border-[var(--line)] bg-white px-3 text-xs font-semibold text-[var(--accent-strong)]"
                    >
                      完成周期审核
                    </Link>
                  ) : null}
                </div>
                <StatusText value={stage.status} />
                <p className="flex items-start gap-2 break-words font-semibold">
                  <ShieldCheck size={16} className="mt-0.5 text-[var(--accent)]" aria-hidden="true" />
                  {formatLabel(stage.safetyGateState)}
                </p>
                <p className="font-semibold tabular-nums">{formatDuration(stage.durationSeconds)}</p>
                <p className="break-words text-[var(--warning)]">{stage.errorSummary ?? "—"}</p>
                <p className="font-semibold tabular-nums">{stage.inputRefCount}</p>
                <p className="font-semibold tabular-nums">{stage.outputRefCount}</p>
              </article>
            ))}
          </div>
        )}
      </section>
    </main>
  );
}

function PageBack({ campaignId }: { campaignId: string }) {
  return (
    <Link
      href={`/campaigns/${encodeURIComponent(campaignId)}`}
      className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
    >
      <ArrowLeft size={17} aria-hidden="true" />
      研究活动
    </Link>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="border border-[var(--line)] bg-white p-4">
      <p className="text-sm text-[var(--muted)]">{label}</p>
      <p className="mt-3 text-3xl font-semibold tabular-nums">{value}</p>
    </div>
  );
}

function StatusText({ value }: { value: string }) {
  const valueClass =
    value === "Blocked"
      ? "text-[var(--danger)]"
      : value === "Running" || value === "Completed"
        ? "text-[var(--accent-strong)]"
        : "";

  return <span className={`break-words font-semibold ${valueClass}`}>{formatLabel(value)}</span>;
}

function formatDuration(seconds: number | undefined): string {
  if (seconds === undefined) {
    return "未记录";
  }
  if (seconds < 60) {
    return `${seconds} 秒`;
  }
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return `${minutes} 分 ${seconds % 60} 秒`;
  }
  return `${Math.floor(minutes / 60)} 小时 ${minutes % 60} 分`;
}
