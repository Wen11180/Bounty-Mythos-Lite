import { AlertTriangle, ArrowLeft, FileCheck2, ShieldCheck } from "lucide-react";
import Link from "next/link";
import {
  getCampaignControlCenter,
  getCampaignPipelineStages,
  getCampaignResearchTaskReview,
  getCampaignTasks,
  getCampaignValidationRuns,
  getReportPreview,
} from "@/lib/api";
import {
  toCampaignEvidenceReviewSummaries,
  toCampaignFindingCandidateGateSummary,
  toCampaignPromotionBlockReviewSummaries,
  toCampaignResearchFeedbackEvidenceSummaries,
  toCampaignValidationEvidenceQualitySummary,
  toCampaignValidationEvidenceReviewSummaries,
} from "@/lib/campaigns-data";
import { formatLabel } from "@/lib/workbench-detail-data";

type PageProps = {
  params: Promise<{ campaignId: string }>;
};

export default async function CampaignEvidenceReviewPage({ params }: PageProps) {
  const { campaignId } = await params;
  const controlCenter = await getCampaignControlCenter(campaignId, null);
  const runIds = Array.from(
    new Set(
      controlCenter?.pipeline_stages
        .map((stage) => stage.pipeline_run_id)
        .filter((runId): runId is string => Boolean(runId)) ?? [],
    ),
  );
  const previews = (
    await Promise.all(runIds.map((runId) => getReportPreview(runId, null)))
  ).filter((preview): preview is NonNullable<typeof preview> => preview !== null);
  const validationRuns = await getCampaignValidationRuns(campaignId, []);
  const pipelineStages = await getCampaignPipelineStages(campaignId, []);
  const tasks = (await getCampaignTasks(campaignId, [])).filter(
    (task) => task.task_type === "research_queue_review",
  );
  const researchReviews = (
    await Promise.all(tasks.map((task) => getCampaignResearchTaskReview(campaignId, task.id, null)))
  ).filter((review): review is NonNullable<typeof review> => review !== null);
  const claims = toCampaignEvidenceReviewSummaries(previews);
  const validationEvidence = toCampaignValidationEvidenceReviewSummaries(validationRuns, pipelineStages);
  const validationEvidenceQuality = toCampaignValidationEvidenceQualitySummary(validationEvidence);
  const researchFeedbackEvidence = toCampaignResearchFeedbackEvidenceSummaries(researchReviews);
  const promotionBlockReviews = toCampaignPromotionBlockReviewSummaries(researchFeedbackEvidence);
  const noReviewGateLabel = "无审核门";
  const findingCandidateGate = toCampaignFindingCandidateGateSummary(
    previews,
    researchFeedbackEvidence,
    pipelineStages,
  );

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <FileCheck2 size={17} aria-hidden="true" />
          证据审核
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            只读
          </span>
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {campaignId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          汇总研究活动关联报告预览中的声明证据就绪度，仅显示引用计数，不展示原始证据、溯源、请求或响应载荷。
        </p>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-5">
        <Metric label="研究审计" value={runIds.length} />
        <Metric label="声明" value={claims.length} />
        <Metric label="验证证据" value={validationEvidence.length} />
        <Metric label="研究反馈" value={researchFeedbackEvidence.length} />
        <Metric label="晋级阻塞项" value={findingCandidateGate.promotionAuditBlockedCount} />
        <Metric label="已清理审核" value={validationEvidenceQuality.cleanReviewCount} />
        <Metric label="已脱敏审核" value={validationEvidenceQuality.redactedReviewCount} />
        <Metric label="不安全引用" value={validationEvidenceQuality.unsafeEvidenceRefCount} />
        <Metric label="强证据" value={validationEvidenceQuality.strongEvidenceCount} />
        <Metric label="晋级受控" value={validationEvidenceQuality.gatedPromotionReviewCount} />
      </section>

      <section className="mb-5 border border-[var(--line)] bg-white px-5 py-4">
        <div className="grid gap-3 text-sm lg:grid-cols-[minmax(0,1fr)_150px_150px_150px_150px_150px]">
          <div className="min-w-0">
            <p className="font-semibold">已阻断晋级审核</p>
            <p className="mt-2 text-pretty text-xs text-[var(--muted)]">
              发现晋级仍仅可人工操作。已阻断尝试以计数和已清理原因汇总，便于审核人复查证据且不暴露原始引用。
            </p>
          </div>
          <Field
            label="已阻断晋级尝试"
            value={String(findingCandidateGate.promotionAuditBlockedCount)}
          />
          <Field
            label="晋级审核"
            value={String(findingCandidateGate.promotionAuditCreatedCount)}
          />
          <Field
            label="所需证据阻塞项"
            value={String(findingCandidateGate.requiredEvidenceBlockedCount)}
          />
          <Field
            label="溯源引用"
            value={String(findingCandidateGate.promotionAuditProvenanceRefCount)}
          />
          <Field
            label="审核证据"
            value={String(findingCandidateGate.promotionAuditReviewEvidenceRefCount)}
          />
          <Field
            label="最近原因"
            value={
              findingCandidateGate.status === "blocked_by_required_evidence"
                ? "所需证据阻断晋级"
                : findingCandidateGate.status === "blocked_by_research_feedback"
                ? "研究反馈阻断晋级"
                : findingCandidateGate.promotionAuditLatestReason ?? "尚未记录晋级阻塞项"
            }
          />
          <Field label="下一步审核操作" value={findingCandidateGate.nextAllowedAction} />
        </div>
      </section>

      <section className="mb-5 border border-[var(--line)] bg-white">
        <div className="grid gap-3 border-b border-[var(--line)] px-5 py-4 text-sm font-semibold text-[var(--muted)] lg:grid-cols-[minmax(0,1fr)_150px_150px_150px]">
          <span>晋级阻塞审核队列</span>
          <span>验证审计</span>
          <span>审核门原因</span>
          <span>证据引用</span>
        </div>
        {promotionBlockReviews.length === 0 ? (
          <p className="flex items-center gap-2 p-5 text-sm font-semibold text-[var(--muted)]">
            <AlertTriangle size={16} aria-hidden="true" />
            暂无已加入队列的晋级阻塞审核项。
          </p>
        ) : (
          <div className="divide-y divide-[var(--line)]">
            {promotionBlockReviews.map((item) => (
              <article
                key={`${item.taskId}-${item.validationRunId}`}
                className="grid gap-3 px-5 py-4 text-sm lg:grid-cols-[minmax(0,1fr)_150px_150px_150px]"
              >
                <div className="min-w-0">
                  <Link
                    href={`/campaigns/${encodeURIComponent(campaignId)}/tasks/${encodeURIComponent(item.taskId)}`}
                    className="break-words font-semibold text-[var(--accent-strong)]"
                  >
                    {item.reviewTitle}
                  </Link>
                  <dl className="mt-3 grid gap-1 text-xs text-[var(--muted)] sm:grid-cols-2">
                    <Field label="审核项" value={item.taskId} />
                    <Field label="计划" value={item.planId} />
                    <Field label="审核门" value={item.approvalId} />
                    <Field label="反馈阶段" value={item.feedbackStageId} />
                  </dl>
                  <Link
                    href={`/campaigns/${encodeURIComponent(campaignId)}/feedback-reviews/${encodeURIComponent(item.feedbackStageId)}`}
                    className="mt-3 inline-flex min-h-9 items-center rounded-md border border-[var(--line)] px-3 text-xs font-semibold text-[var(--accent-strong)]"
                  >
                    审核晋级门
                  </Link>
                </div>
                <Field label="验证审计" value={item.validationRunId} />
                <div className="grid content-start gap-2">
                  <GateText value={item.promotionGateReason} />
                  <p className="break-words text-xs text-[var(--muted)]">{item.nextAllowedAction}</p>
                </div>
                <dl className="grid content-start gap-2 text-xs text-[var(--muted)]">
                  <Field label="证据引用" value={String(item.evidenceRefCount)} />
                  <Field label="溯源引用" value={String(item.promotionProvenanceRefCount)} />
                </dl>
              </article>
            ))}
          </div>
        )}
      </section>

      <section className="border border-[var(--line)] bg-white">
        <div className="grid gap-3 border-b border-[var(--line)] px-5 py-4 text-sm font-semibold text-[var(--muted)] lg:grid-cols-[minmax(0,1fr)_150px_150px_150px]">
          <span>声明</span>
          <span>审核</span>
          <span>证据引用</span>
          <span>报告链</span>
        </div>
        {claims.length === 0 ? (
          <p className="flex items-center gap-2 p-5 text-sm font-semibold text-[var(--muted)]">
            <AlertTriangle size={16} aria-hidden="true" />
            暂无加入证据审核队列的报告声明。
          </p>
        ) : (
          <div className="divide-y divide-[var(--line)]">
            {claims.map((claim) => (
              <article
                key={`${claim.runId}-${claim.claimId}`}
                className="grid gap-3 px-5 py-4 text-sm lg:grid-cols-[minmax(0,1fr)_150px_150px_150px]"
              >
                <div className="min-w-0">
                  <p className="break-words font-semibold">{claim.claimText}</p>
                  <dl className="mt-2 grid gap-1 text-xs text-[var(--muted)]">
                    <Field label="研究审计" value={claim.runId} />
                    <Field label="声明" value={claim.claimId} />
                    <Field label="类型" value={formatLabel(claim.claimType)} />
                    <Field label="状态" value={formatLabel(claim.status)} />
                  </dl>
                </div>
                <div className="grid content-start gap-2">
                  <StatusText value={claim.reviewStatus} />
                  <p className="text-xs text-[var(--muted)]">
                    {claim.humanReviewRequired ? "需要人工审核" : "无需人工审核"}
                  </p>
                  {claim.reviewRationale ? (
                    <p className="break-words text-xs text-[var(--muted)]">{claim.reviewRationale}</p>
                  ) : null}
                </div>
                <dl className="grid content-start gap-2 text-xs text-[var(--muted)]">
                  <Field label="证据引用" value={String(claim.evidenceRefCount)} />
                  <Field label="审核引用" value={String(claim.reviewEvidenceRefCount)} />
                  <Field label="溯源引用" value={String(claim.provenanceRefCount)} />
                  <Field label="脱敏" value={formatLabel(claim.redactionStatus)} />
                </dl>
                <div className="grid content-start gap-2">
                  <GateText
                    value={claim.reportChainEligible ? "已具备报告链证据" : "报告链需要审核"}
                  />
                  <p className="text-xs text-[var(--muted)]">{claim.readinessLevel}</p>
                  <p className="text-xs font-semibold tabular-nums text-[var(--muted)]">
                    质量 {claim.qualityScore}/100
                  </p>
                  {claim.readinessBlockers.length > 0 ? (
                    <ul className="grid gap-1 text-xs text-[var(--warning)]">
                      {claim.readinessBlockers.map((blocker) => (
                        <li key={`${claim.runId}-${claim.claimId}-${blocker}`}>{formatLabel(blocker)}</li>
                      ))}
                    </ul>
                  ) : null}
                </div>
              </article>
            ))}
          </div>
        )}
      </section>

      <section className="mt-5 border border-[var(--line)] bg-white">
        <div className="grid gap-3 border-b border-[var(--line)] px-5 py-4 text-sm font-semibold text-[var(--muted)] lg:grid-cols-[minmax(0,1fr)_150px_150px_150px]">
          <span>验证证据</span>
          <span>状态</span>
          <span>报告链</span>
          <span>证据引用</span>
        </div>
        {validationEvidence.length === 0 ? (
          <p className="flex items-center gap-2 p-5 text-sm font-semibold text-[var(--muted)]">
            <AlertTriangle size={16} aria-hidden="true" />
            暂无加入审核队列的验证证据。
          </p>
        ) : (
          <div className="divide-y divide-[var(--line)]">
            {validationEvidence.map((run) => (
              <article
                key={run.validationRunId}
                className="grid gap-3 px-5 py-4 text-sm lg:grid-cols-[minmax(0,1fr)_150px_150px_150px]"
              >
                <div className="min-w-0">
                  <p className="break-words font-semibold">{run.validationMode}</p>
                  <p className="mt-2 break-words text-[var(--muted)]">{run.summary}</p>
                  <dl className="mt-3 grid gap-1 text-xs text-[var(--muted)] sm:grid-cols-2">
                    <Field label="验证审计" value={run.validationRunId} />
                    <Field label="目标" value={run.targetRef} />
                    <Field label="审核项" value={run.reviewItem || "暂无审核项"} />
                    <Field label="审核门" value={run.reviewGate || "暂无审核门"} />
                  </dl>
                  {run.manualValidationReview ? (
                    <div className="mt-3 grid gap-1 text-xs font-semibold text-[var(--muted)]">
                      <p>
                        质量审核 · 评分：{run.manualValidationReview.qualityScore}/100 ·
                        脱敏：{formatLabel(run.manualValidationReview.redactionStatus)} · 晋级审核：
                        {formatLabel(run.manualValidationReview.promotionReviewState)}
                      </p>
                      <p>
                        证据质量：{formatLabel(run.manualValidationReview.evidenceQuality)} · 安全引用：
                        {run.manualValidationReview.safeEvidenceRefCount} · 不安全引用：
                        {run.manualValidationReview.unsafeEvidenceRefCount}
                      </p>
                      {run.manualValidationReview.qualityReasons.length > 0 ? (
                        <p className="break-words">
                          原因：{run.manualValidationReview.qualityReasons.map((reason) => formatLabel(reason)).join("、")}
                        </p>
                      ) : null}
                    </div>
                  ) : null}
                </div>
                <div className="grid content-start gap-2">
                  <StatusText value={run.status} />
                  <p className="text-xs text-[var(--muted)]">{run.candidateEvidenceState}</p>
                  <p className="text-xs text-[var(--muted)]">{run.preflightState}</p>
                </div>
                <div className="grid content-start gap-2">
                  <GateText value={run.reportChainState} />
                  <p className="text-xs text-[var(--muted)]">
                    {run.reviewGate === noReviewGateLabel ? "需要审核门" : "已记录审核门"}
                  </p>
                  <p className="break-words text-xs text-[var(--muted)]">{run.nextReviewAction}</p>
                </div>
                <dl className="grid content-start gap-2 text-xs text-[var(--muted)]">
                  <Field label="证据引用" value={String(run.evidenceRefCount)} />
                  <Field label="计划" value={run.planDigest ?? "暂无计划摘要"} />
                </dl>
              </article>
            ))}
          </div>
        )}
      </section>

      <section className="mt-5 border border-[var(--line)] bg-white">
        <div className="grid gap-3 border-b border-[var(--line)] px-5 py-4 text-sm font-semibold text-[var(--muted)] lg:grid-cols-[minmax(0,1fr)_150px_150px_150px]">
          <span>研究反馈证据</span>
          <span>状态</span>
          <span>晋级门</span>
          <span>证据引用</span>
        </div>
        {researchFeedbackEvidence.length === 0 ? (
          <p className="flex items-center gap-2 p-5 text-sm font-semibold text-[var(--muted)]">
            <AlertTriangle size={16} aria-hidden="true" />
            暂无加入审核队列的研究验证反馈。
          </p>
        ) : (
          <div className="divide-y divide-[var(--line)]">
            {researchFeedbackEvidence.map((feedback) => (
              <article
                key={`${feedback.taskId}-${feedback.validationRunId}`}
                className="grid gap-3 px-5 py-4 text-sm lg:grid-cols-[minmax(0,1fr)_150px_150px_150px]"
              >
                <div className="min-w-0">
                  <p className="break-words font-semibold">{feedback.reviewTitle}</p>
                  <dl className="mt-3 grid gap-1 text-xs text-[var(--muted)] sm:grid-cols-2">
                    <Field label="审核项" value={feedback.taskId} />
                    <Field label="计划" value={feedback.planId} />
                    <Field label="审核门" value={feedback.approvalId} />
                    <Field label="反馈阶段" value={feedback.feedbackStageId} />
                    <Field label="验证审计" value={feedback.validationRunId} />
                    <Field label="溯源引用" value={String(feedback.promotionProvenanceRefCount)} />
                  </dl>
                </div>
                <div className="grid content-start gap-2">
                  <StatusText value={feedback.status} />
                  <p className="text-xs text-[var(--muted)]">{feedback.outcome}</p>
                  <p className="break-words text-xs text-[var(--muted)]">
                    {feedback.nextAllowedAction}
                  </p>
                </div>
                <div className="grid content-start gap-2">
                  <GateText value={feedback.promotionGate || "需要人工审核"} />
                  <p className="text-xs text-[var(--muted)]">
                    {feedback.findingPromotionAllowed ? "晋级审核需要人工决策" : "晋级审核已阻断"}
                  </p>
                  <p className="break-words text-xs text-[var(--muted)]">
                    {feedback.promotionGateReason}
                  </p>
                  <p className="break-words text-xs text-[var(--muted)]">{feedback.safetyGate}</p>
                  <Link
                    href={`/campaigns/${encodeURIComponent(campaignId)}/feedback-reviews/${encodeURIComponent(feedback.feedbackStageId)}`}
                    className="inline-flex min-h-9 items-center justify-self-start rounded-md border border-[var(--line)] px-3 text-xs font-semibold text-[var(--accent-strong)]"
                  >
                    审核晋级门
                  </Link>
                </div>
                <span className="font-semibold tabular-nums">{feedback.evidenceRefCount}</span>
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

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-0.5">
      <dt className="font-semibold uppercase">{label}</dt>
      <dd className="break-words">{value}</dd>
    </div>
  );
}

function GateText({ value }: { value: string }) {
  return (
    <span className="flex items-start gap-2 break-words font-semibold">
      <ShieldCheck size={16} className="mt-0.5 text-[var(--accent)]" aria-hidden="true" />
      {value}
    </span>
  );
}

function StatusText({ value }: { value: string }) {
  return <span className="break-words font-semibold">{formatLabel(value)}</span>;
}
