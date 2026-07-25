import { AlertTriangle, ArrowLeft, PlaySquare, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { getCampaignValidationRuns } from "@/lib/api";
import {
  type CampaignValidationRunSummary,
  toCampaignValidationRunSummaries,
} from "@/lib/campaigns-data";
import { formatLabel } from "@/lib/workbench-detail-data";

type PageProps = {
  params: Promise<{ campaignId: string }>;
};

export default async function CampaignValidationRunsPage({ params }: PageProps) {
  const { campaignId } = await params;
  const runs = await getCampaignValidationRuns(campaignId, []);
  const summaries = toCampaignValidationRunSummaries(runs);
  const preflightSummary = summarizePreflight(summaries);

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <PlaySquare size={17} aria-hidden="true" />
          验证审计
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            只读
          </span>
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {campaignId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          查看带有人工作审核门、预检状态、目标引用和证据计数的验证审计摘要。此处不展示原始验证载荷。
        </p>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="验证审计" value={summaries.length} />
        <Metric label="等待审核门" value={summaries.filter((run) => run.approvalRequired).length} />
        <Metric label="预检通过" value={summaries.filter((run) => run.preflightPassed).length} />
        <Metric label="证据引用" value={summaries.reduce((total, run) => total + run.evidenceRefCount, 0)} />
      </section>

      <section className="mb-5 border border-[var(--line)] bg-white px-5 py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="flex items-center gap-2 text-sm font-semibold">
              <ShieldCheck size={16} className="text-[var(--accent)]" aria-hidden="true" />
              预检摘要
            </p>
            <p className="mt-2 max-w-3xl text-sm text-[var(--muted)]">
              人工审核门不是验证启动门。范围守卫预检与验证启动审计事件分开跟踪。
            </p>
          </div>
          <span className="rounded-sm border border-[var(--line)] px-2 py-1 text-xs font-semibold uppercase text-[var(--muted)]">
            只读
          </span>
        </div>
        <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-2 xl:grid-cols-4">
          <SummaryField label="需要审核门" value={preflightSummary.approvalRequiredCount} />
          <SummaryField label="预检已审核" value={preflightSummary.allowedByPreflightCount} />
          <SummaryField label="预检已阻断" value={preflightSummary.preflightBlockedCount} />
          <SummaryField label="已启动验证" value={preflightSummary.executionStartedCount} />
        </dl>
      </section>

      <section className="border border-[var(--line)] bg-white">
        <div className="grid gap-3 border-b border-[var(--line)] px-5 py-4 text-sm font-semibold text-[var(--muted)] lg:grid-cols-[minmax(0,1fr)_140px_160px_120px_minmax(180px,0.8fr)]">
          <span>验证</span>
          <span>关注状态</span>
          <span>预检决策</span>
          <span>证据引用</span>
          <span>下一步操作</span>
        </div>
        {summaries.length === 0 ? (
          <p className="flex items-center gap-2 p-5 text-sm font-semibold text-[var(--muted)]">
            <AlertTriangle size={16} aria-hidden="true" />
            暂无可查看的验证审计。
          </p>
        ) : (
          <div className="divide-y divide-[var(--line)]">
            {summaries.map((run) => (
              <article
                key={run.id}
                className="grid gap-3 px-5 py-4 text-sm lg:grid-cols-[minmax(0,1fr)_140px_160px_120px_minmax(180px,0.8fr)]"
              >
                <div className="min-w-0">
                  <p className="break-words font-semibold">{run.validationMode}</p>
                  <p className="mt-2 break-words text-[var(--muted)]">{run.summary}</p>
                  <dl className="mt-3 grid gap-1 text-xs text-[var(--muted)] sm:grid-cols-2">
                    <Field label="验证审计" value={run.id} />
                    <Field label="目标" value={run.targetRef} />
                    <Field label="审核项" value={run.taskId ?? "暂无审核项"} />
                    <Field label="审核门" value={run.approvalId ?? "暂无审核门"} />
                    <Field label="计划" value={run.planDigest ?? "暂无计划摘要"} />
                    <Field label="创建时间" value={run.createdAt} />
                  </dl>
                </div>
                <div className="grid content-start gap-2">
                  <StatusText value={run.attentionState} />
                  <p className="text-xs text-[var(--muted)]">{formatLabel(run.status)}</p>
                  <p className="text-xs text-[var(--muted)]">
                    {run.approvalRequired ? "需要审核门" : "无需审核门"}
                  </p>
                  <p className="text-xs text-[var(--muted)]">{run.executionState}</p>
                  <p className="text-xs text-[var(--muted)]">
                    已启动验证：{run.executionStarted ? "是" : "否"}
                  </p>
                </div>
                <GateText value={run.safetyGateState} />
                <span className="font-semibold tabular-nums">{run.evidenceRefCount}</span>
                <div className="grid content-start gap-2">
                  <p className="break-words text-[var(--muted)]">{run.nextAction}</p>
                  {run.preflightPassed && !run.executionStarted ? (
                    <Link
                      href={`/campaigns/${encodeURIComponent(campaignId)}/validation-runs/${encodeURIComponent(run.id)}`}
                      className="inline-flex min-h-9 items-center justify-center rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
                    >
                      审核人工观察
                    </Link>
                  ) : null}
                </div>
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

function SummaryField({ label, value }: { label: string; value: number }) {
  return (
    <div className="grid gap-1">
      <dt className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</dt>
      <dd className="text-xl font-semibold tabular-nums">{value}</dd>
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

function summarizePreflight(runs: CampaignValidationRunSummary[]) {
  return {
    allowedByPreflightCount: runs.filter((run) => run.allowedToExecute && !run.executionStarted)
      .length,
    approvalRequiredCount: runs.filter((run) => run.approvalRequired).length,
    executionStartedCount: runs.filter((run) => run.executionStarted).length,
    preflightBlockedCount: runs.filter((run) => !run.preflightPassed && !run.executionStarted)
      .length,
  };
}
