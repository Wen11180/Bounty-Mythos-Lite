import { AlertTriangle, ArrowLeft, FileText, ShieldCheck } from "lucide-react";
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
  toCampaignFindingCandidateGateSummary,
  toCampaignReportDraftEvidenceSummary,
  toCampaignReportDraftSummaries,
  toCampaignResearchFeedbackEvidenceSummaries,
} from "@/lib/campaigns-data";
import { formatLabel } from "@/lib/workbench-detail-data";

type PageProps = {
  params: Promise<{ campaignId: string }>;
};

export default async function CampaignReportDraftsPage({ params }: PageProps) {
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
  const drafts = toCampaignReportDraftSummaries(previews);
  const researchFeedbackEvidence = toCampaignResearchFeedbackEvidenceSummaries(researchReviews);
  const findingCandidateGate = toCampaignFindingCandidateGateSummary(
    previews,
    researchFeedbackEvidence,
    pipelineStages,
  );
  const validationEvidence = toCampaignReportDraftEvidenceSummary(validationRuns);

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <FileText size={17} aria-hidden="true" />
          报告就绪度
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            只读
          </span>
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {campaignId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          按审核状态、声明就绪度、人工验证状态和证据引用计数汇总研究活动关联的报告预览。此视图不展示草稿正文或原始证据载荷。
        </p>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-5">
        <Metric label="草稿" value={drafts.length} />
        <Metric label="已审核声明" value={drafts.reduce((total, draft) => total + draft.readyClaimCount, 0)} />
        <Metric
          label="需要审核的声明"
          value={drafts.reduce((total, draft) => total + draft.blockedClaimCount, 0)}
        />
        <Metric label="证据引用" value={drafts.reduce((total, draft) => total + draft.evidenceRefCount, 0)} />
        <Metric label="人工证据" value={validationEvidence.manualEvidenceCount} />
      </section>

      <section className="mb-5 border border-[var(--line)] bg-white px-5 py-4">
        <div className="grid gap-3 text-sm lg:grid-cols-[minmax(0,1fr)_150px_150px_150px_150px]">
          <div className="min-w-0">
            <p className="font-semibold">人工验证状态</p>
            <p className="mt-2 text-pretty text-xs text-[var(--muted)]">
              报告草稿仅可查看已审核验证结果的计数；原始观察、请求数据和响应数据不在此视图中显示。
            </p>
          </div>
          <Field label="验证审计" value={String(validationEvidence.validationRunCount)} />
          <Field label="证据引用" value={String(validationEvidence.evidenceRefCount)} />
          <Field label="证据缺口" value={String(validationEvidence.evidenceGapCount)} />
        </div>
      </section>

      <section className="mb-5 border border-[var(--line)] bg-white px-5 py-4">
        <div className="grid gap-3 text-sm lg:grid-cols-[minmax(0,1fr)_150px_150px_150px_150px_150px]">
          <div className="min-w-0">
            <p className="font-semibold">发现候选项审核门</p>
            <p className="mt-2 text-pretty text-xs text-[var(--muted)]">
              候选项晋级仍仅可人工操作。此视图仅统计满足报告链审核门的已审核声明，不展示原始证据引用。
            </p>
          </div>
          <Field label="已审核声明" value={String(findingCandidateGate.eligibleClaimCount)} />
          <Field label="研究反馈" value={String(findingCandidateGate.researchFeedbackCount)} />
          <Field
            label="所需证据阻塞项"
            value={String(findingCandidateGate.requiredEvidenceBlockedCount)}
          />
          <Field label="晋级审核阻塞项" value={String(findingCandidateGate.researchPromotionBlockedCount)} />
          <Field
            label="晋级审计阻塞项"
            value={String(findingCandidateGate.promotionAuditBlockedCount)}
          />
          <Field
            label="晋级审核"
            value={String(findingCandidateGate.promotionAuditCreatedCount)}
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
            label="模式"
            value={
              findingCandidateGate.status === "blocked_by_required_evidence"
                ? "所需证据阻断晋级"
                : findingCandidateGate.status === "blocked_by_research_feedback"
                ? "研究反馈阻断晋级"
                : findingCandidateGate.promotionAuditLatestReason
                ? findingCandidateGate.promotionAuditLatestReason
                : findingCandidateGate.manualPromotionOnly
                ? `需要人工审核；${findingCandidateGate.blockedClaimCount} 项声明需要审核`
                : "需要审核"
            }
          />
        </div>
        {findingCandidateGate.readyRunIds.length > 0 ? (
          <div className="mt-4 border-t border-[var(--line)] pt-4">
            <p className="text-xs font-semibold uppercase text-[var(--muted)]">
              已加入队列的发现候选项审核
            </p>
            <ul className="mt-3 grid gap-2">
              {findingCandidateGate.readyRunIds.map((runId) => (
                <li
                  key={runId}
                  className="flex flex-wrap items-center justify-between gap-2 text-sm"
                >
                  <span className="break-words font-semibold">{runId}</span>
                  <Link
                    href={`/reports/${encodeURIComponent(runId)}`}
                    className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] px-3 text-sm font-semibold text-[var(--accent-strong)]"
                  >
                    <ShieldCheck size={16} aria-hidden="true" />
                    审核发现候选项
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
      </section>

      <section className="border border-[var(--line)] bg-white">
        <div className="grid gap-3 border-b border-[var(--line)] px-5 py-4 text-sm font-semibold text-[var(--muted)] lg:grid-cols-[minmax(0,1fr)_150px_150px_150px]">
          <span>草稿</span>
          <span>人工提交门</span>
          <span>声明</span>
          <span>证据引用</span>
        </div>
        {drafts.length === 0 ? (
          <p className="flex items-center gap-2 p-5 text-sm font-semibold text-[var(--muted)]">
            <AlertTriangle size={16} aria-hidden="true" />
            暂无加入审核队列的报告草稿。
          </p>
        ) : (
          <div className="divide-y divide-[var(--line)]">
            {drafts.map((draft) => (
              <article
                key={draft.runId}
                className="grid gap-3 px-5 py-4 text-sm lg:grid-cols-[minmax(0,1fr)_150px_150px_150px]"
              >
                <div className="min-w-0">
                  <p className="break-words font-semibold">{draft.title}</p>
                  <dl className="mt-2 grid gap-1 text-xs text-[var(--muted)] sm:grid-cols-2">
                    <Field label="研究审计" value={draft.runId} />
                    <Field label="严重性" value={formatLabel(draft.severity)} />
                    <Field label="范围" value={formatLabel(draft.scopeStatus)} />
                  </dl>
                  {draft.topClaims.length > 0 ? (
                    <ul className="mt-3 grid gap-1 text-xs text-[var(--muted)]">
                      {draft.topClaims.map((claim) => (
                        <li key={`${draft.runId}-${claim}`} className="break-words">
                          {claim}
                        </li>
                      ))}
                    </ul>
                  ) : null}
                </div>
                <div className="grid content-start gap-2">
                  <GateText value={draft.submissionBlocked ? "报告提交已阻断" : "人工审核需要人工决策"} />
                  <p className="text-xs text-[var(--muted)]">
                    {draft.humanReviewRequired ? "需要人工审核" : "无需人工审核"}
                  </p>
                  {draft.safetyNotes.length > 0 ? (
                    <ul className="grid gap-1 text-xs text-[var(--muted)]">
                      {draft.safetyNotes.map((note) => (
                        <li key={`${draft.runId}-${note}`} className="break-words">
                          {formatLabel(note)}
                        </li>
                      ))}
                    </ul>
                  ) : null}
                </div>
                <dl className="grid content-start gap-2 text-xs text-[var(--muted)]">
                  <Field label="总计" value={String(draft.claimCount)} />
                  <Field label="已审核" value={String(draft.readyClaimCount)} />
                  <Field label="审核阻塞项" value={String(draft.blockedClaimCount)} />
                </dl>
                <span className="font-semibold tabular-nums">{draft.evidenceRefCount}</span>
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
