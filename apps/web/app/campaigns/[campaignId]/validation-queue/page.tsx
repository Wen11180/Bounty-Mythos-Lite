import { AlertTriangle, ArrowLeft, ClipboardCheck, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { getCampaignApprovals } from "@/lib/api";
import { toCampaignValidationQueueSummaries } from "@/lib/campaigns-data";
import { formatLabel } from "@/lib/workbench-detail-data";

type PageProps = {
  params: Promise<{ campaignId: string }>;
};

export default async function CampaignValidationQueuePage({ params }: PageProps) {
  const { campaignId } = await params;
  const approvals = await getCampaignApprovals(campaignId, []);
  const queue = toCampaignValidationQueueSummaries(approvals);

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <ClipboardCheck size={17} aria-hidden="true" />
          审核门队列
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {campaignId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          以只读审计状态展示审核门请求。任何验证启动前仍需完成预检。
        </p>
      </header>

      {queue.length === 0 ? (
        <section className="mt-6 border border-[var(--line)] bg-white p-6">
          <p className="flex items-center gap-2 text-sm font-semibold text-[var(--warning)]">
            <AlertTriangle size={17} aria-hidden="true" />
            暂无可处理的审核门请求
          </p>
          <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
            研究活动进入人工审核门后，请求会显示在这里。审核后仍需完成预检。
          </p>
        </section>
      ) : (
        <section className="mt-5 border border-[var(--line)] bg-white">
          <div className="grid gap-3 border-b border-[var(--line)] px-5 py-4 text-sm font-semibold text-[var(--muted)] lg:grid-cols-[minmax(0,1fr)_140px_160px_160px_minmax(180px,0.8fr)]">
            <span>审核门</span>
            <span>状态</span>
            <span>审核门状态</span>
            <span>验证模式</span>
            <span>下一步操作</span>
          </div>
          <div className="divide-y divide-[var(--line)]">
            {queue.map((item) => (
              <article
                key={item.id}
                className="grid gap-3 px-5 py-4 text-sm lg:grid-cols-[minmax(0,1fr)_140px_160px_160px_minmax(180px,0.8fr)]"
              >
                <div className="min-w-0">
                  <p className="break-words font-semibold">{item.requestedAction ?? item.approvalType}</p>
                  <p className="mt-2 break-words text-[var(--muted)]">{item.reason}</p>
                  <dl className="mt-3 grid gap-2 text-xs text-[var(--muted)] sm:grid-cols-2">
                    <Field label="审核门" value={item.id} />
                    <Field label="资产" value={item.asset ?? "暂无资产"} />
                    <Field label="计划" value={item.planDigest ?? "暂无计划摘要"} />
                    <Field label="审核项" value={item.taskId ?? "暂无审核项"} />
                    <Field label="研究审计" value={item.runId ?? "暂无研究审计"} />
                    <Field label="创建时间" value={item.createdAt} />
                  </dl>
                </div>
                <StatusText value={item.status} />
                <span className="flex items-start gap-2 font-semibold">
                  <ShieldCheck size={16} className="mt-0.5 text-[var(--accent)]" aria-hidden="true" />
                  <span className="break-words">{formatLabel(item.safetyGateState)}</span>
                </span>
                <StatusText value={item.validationMode ?? "未指定"} />
                <p className="break-words text-[var(--muted)]">{item.nextAction}</p>
              </article>
            ))}
          </div>
        </section>
      )}
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

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-0.5">
      <dt className="font-semibold uppercase">{label}</dt>
      <dd className="break-words">{value}</dd>
    </div>
  );
}

function StatusText({ value }: { value: string }) {
  return <span className="break-words font-semibold">{formatLabel(value)}</span>;
}
