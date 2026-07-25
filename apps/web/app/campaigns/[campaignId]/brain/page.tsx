import { AlertTriangle, ArrowLeft, Bot } from "lucide-react";
import Link from "next/link";
import { getCampaignControlCenter, getMythosBrainProgram } from "@/lib/api";
import { fallbackMythosBrainProfile } from "@/lib/fallback-data";
import { toCampaignBrainSummary, toCampaignLearningReviewSummary } from "@/lib/campaigns-data";
import { formatLabel } from "@/lib/workbench-detail-data";

type PageProps = {
  params: Promise<{ campaignId: string }>;
};

export default async function CampaignBrainPage({ params }: PageProps) {
  const { campaignId } = await params;
  const controlCenter = await getCampaignControlCenter(campaignId, null);
  const programId = controlCenter?.campaign.program_id;

  if (!programId) {
    return (
      <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
        <PageBack campaignId={campaignId} />
        <section className="mt-6 border border-[var(--line)] bg-white p-6">
          <p className="flex items-center gap-2 text-sm font-semibold text-[var(--warning)]">
            <AlertTriangle size={17} aria-hidden="true" />
            研究大脑档案暂不可用
          </p>
          <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
            此研究活动尚未关联项目级研究大脑档案。
          </p>
        </section>
      </main>
    );
  }

  const fallbackProfile = {
    ...fallbackMythosBrainProfile,
    program_id: programId,
    program_name: controlCenter.campaign.name,
  };
  const profile = await getMythosBrainProgram(programId, fallbackProfile);
  const summary = toCampaignBrainSummary(profile);
  const learningReview = toCampaignLearningReviewSummary(controlCenter, profile);
  const advisoryOnly = summary.advisoryOnly;

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <Bot size={17} aria-hidden="true" />
          研究大脑
        </p>
        <div className="mt-3 grid gap-3 lg:grid-cols-[minmax(0,1fr)_260px] lg:items-end">
          <div>
            <h1 className="max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
              {summary.programName}
            </h1>
            <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
              用于排序与解释的建议性研究记忆，仅作建议使用。
            </p>
          </div>
          <div className="border border-[var(--line)] bg-white p-4">
            <p className="text-xs font-semibold uppercase text-[var(--muted)]">项目评分</p>
            <p className="mt-2 text-3xl font-semibold tabular-nums">{summary.programScore}</p>
          </div>
        </div>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-6">
        <Metric label="对象" value={summary.objectCount} />
        <Metric label="角色" value={summary.roleCount} />
        <Metric label="敏感操作" value={summary.sensitiveActionCount} />
        <Metric label="信号" value={summary.signalCount} />
        <Metric label="已应用经验" value={summary.appliedLessonCount} />
        <Metric label="已跳过经验" value={summary.skippedLessonCount} />
      </section>

      <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <div className="grid gap-5">
          <section className="border border-[var(--line)] bg-white">
            <SectionHeader title="高价值攻击面" />
            <div className="divide-y divide-[var(--line)]">
              {summary.topSurfaces.map((surface) => (
                <article key={surface.surfaceKey} className="grid gap-2 p-5 text-sm">
                  <div className="flex items-start justify-between gap-3">
                    <p className="break-words font-semibold">{surface.surfaceKey}</p>
                    <p className="shrink-0 font-semibold tabular-nums">{surface.score}</p>
                  </div>
                  <p className="break-words text-[var(--muted)]">{surface.path}</p>
                  <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                    {surface.objectName} / {surface.action}
                  </p>
                </article>
              ))}
              {summary.topSurfaces.length === 0 ? (
                <p className="p-5 text-sm text-[var(--muted)]">尚无学习到的攻击面。</p>
              ) : null}
            </div>
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader title="已应用经验" />
            <div className="divide-y divide-[var(--line)]">
              {summary.appliedLessons.map((lesson) => (
                <article key={lesson.id} className="grid gap-2 p-5 text-sm">
                  <div className="flex items-start justify-between gap-3">
                    <p className="break-words font-semibold">
                      {lesson.recommendation} / {lesson.surfacePattern}
                    </p>
                    <p className="shrink-0 font-semibold tabular-nums">
                      {lesson.scoreDelta > 0 ? "+" : ""}
                      {lesson.scoreDelta}
                    </p>
                  </div>
                  <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                    置信度 {lesson.confidence}
                  </p>
                  {lesson.reasons.length > 0 ? (
                    <ul className="flex flex-wrap gap-1.5">
                      {lesson.reasons.map((reason) => (
                        <li
                          key={`${lesson.id}-${reason}`}
                          className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold text-[var(--muted)]"
                        >
                          {reason}
                        </li>
                      ))}
                    </ul>
                  ) : null}
                </article>
              ))}
              {summary.appliedLessons.length === 0 ? (
                <p className="p-5 text-sm text-[var(--muted)]">尚无已应用经验。</p>
              ) : null}
            </div>
          </section>
        </div>

        <aside className="grid content-start gap-5">
          <section className="border border-[var(--line)] bg-white">
            <SectionHeader title="学习信号审核" />
            <dl className="grid gap-3 p-5 text-sm">
              <Field
                label="审核就绪度"
                value={learningReview.reviewReady ? "可审核" : "已加入审核队列"}
              />
              <Field label="安全下一步" value={learningReview.safeNextAction} />
              <Field label="关联审计" value={String(learningReview.linkedRunCount)} />
              <Field label="近期信号" value={String(learningReview.recentSignalCount)} />
              <Field label="强证据" value={String(learningReview.strongEvidenceSignalCount)} />
              <Field label="已应用经验" value={String(learningReview.appliedLessonCount)} />
              <Field label="已跳过经验" value={String(learningReview.skippedLessonCount)} />
            </dl>
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader title="安全边界" />
            <dl className="grid gap-3 p-5 text-sm">
              <Field
                label="仅建议性"
                value={advisoryOnly ? "仅建议性记忆" : "审核门生效中"}
              />
              <Field
                label="审核边界"
                value={summary.executionAllowed ? "范围守卫已审核" : "研究大脑建议性记忆"}
              />
              <Field label="项目" value={summary.programId} />
            </dl>
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader title="推理记忆" />
            <div className="grid gap-4 p-5 text-sm">
              <dl className="grid grid-cols-2 gap-3">
                <Field
                  label="最高评分"
                  value={String(summary.reasoningMemory.highestReasoningReviewScore)}
                />
                <Field
                  label="上下文"
                  value={String(summary.reasoningMemory.learningSignalContextCount)}
                />
                <Field
                  label="候选项"
                  value={String(summary.reasoningMemory.candidateContextCount)}
                />
                <Field label="审核门" value="仅建议性记忆" />
              </dl>
              {summary.reasoningMemory.topPlaybooks.length > 0 ? (
                <ul className="grid gap-2 border-t border-[var(--line)] pt-3">
                  {summary.reasoningMemory.topPlaybooks.map((playbook) => (
                    <li key={playbook.playbookId} className="grid gap-1">
                      <p className="break-words font-semibold">{playbook.playbookId}</p>
                      <p className="text-xs text-[var(--muted)]">
                        评分 {playbook.highestReasoningReviewScore}，来自 {playbook.learningSignalContextCount} 个信号上下文
                      </p>
                    </li>
                  ))}
                </ul>
              ) : null}
              {summary.reasoningMemory.safetyNotes.length > 0 ? (
                <ul className="flex flex-wrap gap-1.5">
                  {summary.reasoningMemory.safetyNotes.map((note) => (
                    <li
                      key={`reasoning-memory-${note}`}
                      className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold text-[var(--muted)]"
                    >
                      {note}
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader title="近期信号" />
            <div className="divide-y divide-[var(--line)]">
              {summary.recentSignals.map((signal) => (
                <article key={signal.id} className="grid gap-2 p-5 text-sm">
                  <p className="break-words font-semibold">{formatLabel(signal.outcome)}</p>
                  <p className="break-words text-[var(--muted)]">{signal.notes}</p>
                  <dl className="grid gap-2 text-xs text-[var(--muted)]">
                    <Field label="策略手册" value={signal.playbookId} />
                    <Field label="攻击面" value={signal.surfaceKey ?? "暂无攻击面"} />
                    <Field label="证据" value={signal.evidenceQuality ? formatLabel(signal.evidenceQuality) : "未指定"} />
                  </dl>
                </article>
              ))}
              {summary.recentSignals.length === 0 ? (
                <p className="p-5 text-sm text-[var(--muted)]">尚无学习信号。</p>
              ) : null}
            </div>
          </section>
        </aside>
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

function Metric({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="border border-[var(--line)] bg-white p-4">
      <p className="text-sm text-[var(--muted)]">{label}</p>
      <p className="mt-3 break-words text-2xl font-semibold tabular-nums">{value}</p>
    </div>
  );
}

function SectionHeader({ title }: { title: string }) {
  return (
    <div className="border-b border-[var(--line)] px-5 py-4">
      <h2 className="text-lg font-semibold">{title}</h2>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-1">
      <dt className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</dt>
      <dd className="break-words font-semibold">{value}</dd>
    </div>
  );
}
