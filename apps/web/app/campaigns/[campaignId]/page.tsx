import { revalidatePath } from "next/cache";
import { AlertTriangle, ArrowLeft, ClipboardCheck, Gauge, ShieldCheck } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import Link from "next/link";
import { getCampaignControlCenter, materializeResearchQueueTask } from "@/lib/api";
import { toCampaignControlSummary } from "@/lib/campaigns-data";
import { formatLabel } from "@/lib/workbench-detail-data";

type PageProps = {
  params: Promise<{ campaignId: string }>;
};

export default async function CampaignDetailPage({ params }: PageProps) {
  const { campaignId } = await params;
  const controlCenter = await getCampaignControlCenter(campaignId, null);

  if (!controlCenter) {
    return (
      <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
        <PageBack />
        <section className="mt-6 border border-[var(--line)] bg-white p-6">
          <p className="flex items-center gap-2 text-sm font-semibold text-[var(--warning)]">
            <AlertTriangle size={17} aria-hidden="true" />
            研究活动控制信息暂不可用
          </p>
          <h1 className="mt-3 break-words text-3xl font-semibold text-balance">{campaignId}</h1>
          <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
            此研究活动未返回已审计的控制摘要。
          </p>
        </section>
      </main>
    );
  }

  const summary = toCampaignControlSummary(controlCenter);
  const runtimeGateState = summary.executionAllowed ? "范围守卫已审核" : "范围守卫已阻断";
  const safeNextAction = summary.safeNextAction;

  async function queueResearchReviewAction(formData: FormData) {
    "use server";

    const queueKey = formData.get("queue_key");
    if (typeof queueKey !== "string" || queueKey.trim() === "") {
      return;
    }

    await materializeResearchQueueTask(
      campaignId,
      {
        queue_key: queueKey,
        requester: "operator",
        reason: "从控制中心加入审核项。",
      },
    );
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}`);
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/tasks`);
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/timeline`);
  }

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <ShieldCheck size={17} aria-hidden="true" />
          {summary.campaignId}
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            只读
          </span>
        </p>
        <div className="mt-3 grid gap-3 lg:grid-cols-[minmax(0,1fr)_320px] lg:items-end">
          <div>
            <h1 className="max-w-4xl text-3xl font-semibold leading-tight text-balance">
              {summary.name}
            </h1>
            <p className="mt-2 break-words text-pretty text-[var(--muted)]">
              {summary.defaultAsset}
            </p>
            <nav className="mt-4 flex flex-wrap gap-2">
              <AuditLink href={`/campaigns/${encodeURIComponent(campaignId)}/tasks`} label="研究审核" />
              <AuditLink href={`/campaigns/${encodeURIComponent(campaignId)}/agent-runs`} label="智能体审计" />
              <AuditLink
                href={`/campaigns/${encodeURIComponent(campaignId)}/attack-surface-map`}
                label="攻击面地图"
              />
              <AuditLink
                href={`/campaigns/${encodeURIComponent(campaignId)}/codebase-map`}
                label="代码审计地图"
              />
              <AuditLink
                href={`/campaigns/${encodeURIComponent(campaignId)}/artifacts`}
                label="资料审核"
              />
              <AuditLink
                href={`/campaigns/${encodeURIComponent(campaignId)}/validation-queue`}
                label="审核门"
              />
              <AuditLink
                href={`/campaigns/${encodeURIComponent(campaignId)}/validation-runs`}
                label="验证审计"
              />
              <AuditLink
                href={`/campaigns/${encodeURIComponent(campaignId)}/hypothesis-board`}
                label="假设看板"
              />
              <AuditLink
                href={`/campaigns/${encodeURIComponent(campaignId)}/evidence-review`}
                label="证据审核"
              />
              <AuditLink
                href={`/campaigns/${encodeURIComponent(campaignId)}/report-drafts`}
                label="报告就绪度"
              />
              <AuditLink href={`/campaigns/${encodeURIComponent(campaignId)}/timeline`} label="审核时间线" />
              <AuditLink href={`/campaigns/${encodeURIComponent(campaignId)}/brain`} label="研究大脑" />
            </nav>
          </div>
          <div className="border border-[var(--line)] bg-white p-4">
            <p className="text-xs font-semibold uppercase text-[var(--muted)]">安全下一步</p>
            {summary.safeNextHref ? (
              <Link
                href={summary.safeNextHref}
                className="mt-2 inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] px-3 text-sm font-semibold text-[var(--accent-strong)]"
              >
                <ClipboardCheck size={17} aria-hidden="true" />
                {safeNextAction}
              </Link>
            ) : (
              <p className="mt-2 font-semibold text-[var(--accent-strong)]">{safeNextAction}</p>
            )}
            {summary.blockedReasons.length > 0 ? (
              <div className="mt-3 border-t border-[var(--line)] pt-3">
                <p className="text-xs font-semibold uppercase text-[var(--muted)]">审核要求</p>
                <ul className="mt-2 grid gap-1 text-xs leading-5 text-[var(--muted)]">
                  {summary.blockedReasons.map((reason) => (
                    <li key={reason}>{formatLabel(reason)}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            {summary.promotionReviewBlockedCount > 0 || summary.promotionReviewLatestReason ? (
              <div className="mt-3 border-t border-[var(--line)] pt-3">
                <p className="text-xs font-semibold uppercase text-[var(--muted)]">晋级审核</p>
                <dl className="mt-2 grid grid-cols-2 gap-2 text-xs">
                  <Field label="已阻断尝试" value={summary.promotionReviewBlockedCount} />
                  <Field
                    label="证据阻塞项"
                    value={summary.promotionReviewRequiredEvidenceBlockedCount}
                  />
                  <Field label="溯源引用" value={summary.promotionReviewProvenanceRefCount} />
                </dl>
                {summary.promotionReviewLatestReason ? (
                  <p className="mt-2 break-words text-xs leading-5 text-[var(--muted)]">
                    {summary.promotionReviewLatestReason}
                  </p>
                ) : null}
                <p className="mt-2 break-words text-xs leading-5 text-[var(--muted)]">
                  {summary.promotionReviewNextAllowedAction}
                </p>
              </div>
            ) : null}
            <dl className="mt-3 grid grid-cols-3 gap-2 border-t border-[var(--line)] pt-3 text-xs">
              <Field label="验证审计" value={summary.validationRunCount} />
              <Field label="证据" value={summary.validationEvidenceCount} />
              <Field label="缺口" value={summary.validationEvidenceGapCount} />
            </dl>
            <div className="mt-3 border-t border-[var(--line)] pt-3">
              <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                周期审核
              </p>
              <dl className="mt-2 grid grid-cols-2 gap-2 text-xs">
                <Field label="等待审核" value={summary.cycleReviewAwaitingCount} />
                <Field label="已完成" value={summary.cycleReviewCompletedCount} />
              </dl>
              {summary.cycleReviewAwaitingCount > 0 ? (
                <p className="mt-2 text-xs leading-5 text-[var(--muted)]">
                  此处受人工审核门控制；时间线仅说明循环状态，不会启动验证。
                </p>
              ) : null}
            </div>
          </div>
        </div>
      </header>

      <section className="border-b border-[var(--line)] py-5">
        <div className="mb-3 flex flex-wrap items-end justify-between gap-2">
          <div>
            <p className="text-sm font-semibold">控制就绪度</p>
            <p className="mt-1 text-sm text-[var(--muted)]">
              研究活动循环的仅审核检查点。这些链接不会启动验证。
            </p>
          </div>
          <span className="text-xs font-semibold uppercase text-[var(--muted)]">
            已审计导航
          </span>
        </div>
        <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
          <ReadinessLink
            href={`/campaigns/${encodeURIComponent(campaignId)}/artifacts`}
            label="资料审核"
            value="审核"
          />
          <ReadinessLink
            href={`/campaigns/${encodeURIComponent(campaignId)}/validation-queue`}
            label="审核门"
            value={summary.pendingApprovalCount}
          />
          <ReadinessLink
            href={`/campaigns/${encodeURIComponent(campaignId)}/validation-runs`}
            label="验证审计"
            value={summary.validationRunCount}
          />
          <ReadinessLink
            href={`/campaigns/${encodeURIComponent(campaignId)}/evidence-review`}
            label="证据审核"
            value={summary.validationEvidenceGapCount}
          />
          <ReadinessLink
            href={`/campaigns/${encodeURIComponent(campaignId)}/report-drafts`}
            label="报告就绪度"
            value="审核"
          />
          <ReadinessLink
            href={`/campaigns/${encodeURIComponent(campaignId)}/tasks`}
            label="审核项"
            value={summary.taskCount}
          />
          <ReadinessLink
            href={`/campaigns/${encodeURIComponent(campaignId)}/brain`}
            label="学习信号审核"
            value="审核"
          />
          <ReadinessLink
            href={`/campaigns/${encodeURIComponent(campaignId)}/timeline`}
            label="周期审核"
            value={summary.cycleReviewAwaitingCount}
          />
          <ReadinessLink
            href={`/campaigns/${encodeURIComponent(campaignId)}/timeline`}
            label="审核阻塞项"
            value={summary.blockedStageCount}
          />
        </div>
      </section>

      {summary.researchQueueSuggestions.length > 0 ? (
        <section className="border-b border-[var(--line)] py-5">
          <div className="mb-3 flex flex-wrap items-end justify-between gap-2">
            <div>
              <p className="text-sm font-semibold">研究记忆审核</p>
              <p className="mt-1 text-sm text-[var(--muted)]">
                供人工审核的建议性推理记忆建议，仅作建议使用。
              </p>
            </div>
            <span className="text-xs font-semibold uppercase text-[var(--muted)]">
              研究大脑
            </span>
          </div>
          <div className="grid gap-3 lg:grid-cols-2">
            {summary.researchQueueSuggestions.map((suggestion) => (
              <article
                key={suggestion.queueKey}
                className="grid gap-3 border border-[var(--line)] bg-white p-4 text-sm"
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="font-semibold">{suggestion.title}</p>
                    <p className="mt-1 text-[var(--muted)]">{suggestion.source}</p>
                  </div>
                  <span className="text-2xl font-semibold tabular-nums text-[var(--accent-strong)]">
                    {suggestion.priorityScore}
                  </span>
                </div>
                <dl className="grid gap-2 sm:grid-cols-2">
                  {suggestion.rawPriorityScore !== null ? (
                    <Field label="原始评分" value={suggestion.rawPriorityScore} />
                  ) : null}
                  <Field label="策略手册" value={suggestion.playbookId} />
                  <Field label="攻击面" value={suggestion.surfaceKey ?? "暂无攻击面"} />
                  <Field label="审核门" value={formatLabel(suggestion.safetyGate)} />
                  <Field label="操作门" value="仅供审核" />
                  <Field
                    label="候选项"
                    value={suggestion.candidateStatus ? formatLabel(suggestion.candidateStatus) : "记忆审核"}
                  />
                  <Field
                    label="人工审核门"
                    value={suggestion.humanApprovalRequired ? "需要人工审核" : "仅供审核"}
                  />
                  <Field
                    label="反证问题"
                    value={String(suggestion.refutationQuestionCount)}
                  />
                  <Field
                    label="验证步骤"
                    value={String(suggestion.validationStepCount)}
                  />
                  <Field
                    label="已阻断操作"
                    value={String(suggestion.blockedActionCount)}
                  />
                </dl>
                <p className="text-pretty text-[var(--muted)]">
                  {suggestion.nextAllowedAction}
                </p>
                {suggestion.requiredEvidence.length > 0 ? (
                  <ListBlock title="所需证据" items={suggestion.requiredEvidence} />
                ) : null}
                {suggestion.qualityGateReasons.length > 0 ? (
                  <ListBlock title="质量门原因" items={suggestion.qualityGateReasons} />
                ) : null}
                <form action={queueResearchReviewAction}>
                  <input type="hidden" name="queue_key" value={suggestion.queueKey} />
                  <button
                    type="submit"
                    className="inline-flex min-h-10 items-center rounded-md border border-[var(--line)] px-3 text-sm font-semibold text-[var(--accent-strong)]"
                  >
                    加入审核队列
                  </button>
                </form>
              </article>
            ))}
          </div>
        </section>
      ) : null}

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="状态" value={formatLabel(summary.status)} />
        <Metric label="范围" value={formatLabel(summary.scopeStatus)} />
        <Metric label="审核项" value={summary.taskCount} />
        <Metric label="智能体审计" value={summary.agentRunCount} />
        <Metric label="待审核门" value={summary.pendingApprovalCount} />
        <Metric label="审核阻塞项" value={summary.blockedStageCount} />
        <Metric label="验证证据" value={summary.validationEvidenceCount} />
        <Metric label="证据缺口" value={summary.validationEvidenceGapCount} />
      </section>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section className="border border-[var(--line)] bg-white">
          <SectionHeader icon={Gauge} title="预算与审核门" />
          <dl className="grid gap-4 p-5 text-sm sm:grid-cols-2">
            <Field label="预算" value={summary.budgetLabel} />
            <Field label="运行时审核门" value={runtimeGateState} />
            <Field label="研究活动状态" value={formatLabel(summary.status)} />
            <Field label="范围状态" value={formatLabel(summary.scopeStatus)} />
          </dl>
        </section>

        <aside className="grid content-start gap-5">
          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={ClipboardCheck} title="审核要求" />
            {summary.blockedReasons.length > 0 ? (
              <ul className="grid gap-2 p-5 text-sm text-[var(--muted)]">
                {summary.blockedReasons.map((reason) => (
                  <li key={reason}>{formatLabel(reason)}</li>
                ))}
              </ul>
            ) : (
              <p className="p-5 text-sm text-[var(--muted)]">当前没有待处理的审核要求。</p>
            )}
          </section>
        </aside>
      </div>
    </main>
  );
}

function PageBack() {
  return (
    <Link
      href="/campaigns"
      className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
    >
      <ArrowLeft size={17} aria-hidden="true" />
      研究活动
    </Link>
  );
}

function AuditLink({ href, label }: { href: string; label: string }) {
  return (
    <Link
      href={href}
      className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
    >
      <ClipboardCheck size={17} aria-hidden="true" />
      {label}
    </Link>
  );
}

function ReadinessLink({ href, label, value }: { href: string; label: string; value: React.ReactNode }) {
  return (
    <Link
      href={href}
      className="grid min-h-20 gap-2 border border-[var(--line)] bg-white p-3 text-sm"
    >
      <span className="font-semibold">{label}</span>
      <span className="text-2xl font-semibold tabular-nums text-[var(--accent-strong)]">{value}</span>
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

function SectionHeader({ icon: Icon, title }: { icon: LucideIcon; title: string }) {
  return (
    <div className="flex items-center justify-between border-b border-[var(--line)] px-5 py-4">
      <h2 className="text-lg font-semibold">{title}</h2>
      <Icon size={19} className="text-[var(--accent)]" aria-hidden="true" />
    </div>
  );
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="grid gap-1">
      <dt className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</dt>
      <dd className="break-words font-semibold">{value}</dd>
    </div>
  );
}

function ListBlock({ items, title }: { items: string[]; title: string }) {
  return (
    <div className="grid gap-2 border-t border-[var(--line)] pt-3">
      <p className="text-xs font-semibold uppercase text-[var(--muted)]">{title}</p>
      <ul className="grid gap-1 text-xs leading-5 text-[var(--muted)]">
        {items.map((item) => (
          <li key={item} className="break-words">
            {item}
          </li>
        ))}
      </ul>
    </div>
  );
}
