import { AlertTriangle, ArrowLeft, Database, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { getArtifacts, getCampaignControlCenter } from "@/lib/api";
import { toCampaignArtifactSummaries } from "@/lib/campaigns-data";

type PageProps = {
  params: Promise<{ campaignId: string }>;
};

export default async function CampaignArtifactsPage({ params }: PageProps) {
  const { campaignId } = await params;
  const controlCenter = await getCampaignControlCenter(campaignId, null);
  const artifacts = controlCenter
    ? await getArtifacts([], {
        programId: controlCenter.campaign.program_id ?? undefined,
        asset: controlCenter.campaign.default_asset,
      })
    : [];
  const summaries = toCampaignArtifactSummaries(artifacts);
  const reportChainAllowedCount = summaries.filter((artifact) => artifact.reportChainAllowed).length;
  const reportChainBlockedCount = summaries.length - reportChainAllowedCount;

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <Database size={17} aria-hidden="true" />
          资料审核
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            只读
          </span>
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {campaignId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          仅显示此研究活动的资料摘要、安全状态、使用计数和报告链就绪度。
        </p>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="资料" value={summaries.length} />
        <Metric label="报告链审核就绪" value={reportChainAllowedCount} />
        <Metric label="报告链需审核" value={reportChainBlockedCount} />
        <Metric
          label="使用引用"
          value={summaries.reduce((total, artifact) => total + artifact.usageCount, 0)}
        />
      </section>

      <section className="border border-[var(--line)] bg-white">
        <div className="grid gap-3 border-b border-[var(--line)] px-5 py-4 text-sm font-semibold text-[var(--muted)] lg:grid-cols-[minmax(0,1fr)_130px_150px_130px_180px]">
          <span>资料</span>
          <span>状态</span>
          <span>敏感度</span>
          <span>报告链</span>
          <span>使用溯源</span>
        </div>
        {summaries.length === 0 ? (
          <p className="flex items-center gap-2 p-5 text-sm font-semibold text-[var(--muted)]">
            <AlertTriangle size={16} aria-hidden="true" />
            暂无已审核资料。
          </p>
        ) : (
          <div className="divide-y divide-[var(--line)]">
            {summaries.map((artifact) => (
              <article
                key={artifact.id}
                className="grid gap-3 px-5 py-4 text-sm lg:grid-cols-[minmax(0,1fr)_130px_150px_130px_180px]"
              >
                <div className="min-w-0">
                  <p className="break-words font-semibold">{artifact.kind}</p>
                  <dl className="mt-2 grid gap-1 text-xs text-[var(--muted)] sm:grid-cols-2">
                    <Field label="资料" value={artifact.id} />
                    <Field label="资产" value={artifact.asset} />
                    <Field label="来源" value={artifact.sourceType} />
                    <Field label="创建时间" value={artifact.createdAt} />
                  </dl>
                </div>
                <StatusText value={artifact.ingestionStatus} />
                <p className="break-words font-semibold">{artifact.sensitivityLabel}</p>
                <p className="flex items-start gap-2 break-words font-semibold">
                  <ShieldCheck size={16} className="mt-0.5 text-[var(--accent)]" aria-hidden="true" />
                  {artifact.reportChainAllowed
                    ? "报告链审核已就绪"
                    : `报告链需要审核（${artifact.safetyBlockerCount}）`}
                </p>
                <div className="grid content-start gap-2">
                  <span className="font-semibold tabular-nums">{artifact.usageCount}</span>
                  <CountList label="阶段" values={artifact.usageStages} />
                  <CountList label="类型" values={artifact.usageTypes} />
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

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-0.5">
      <dt className="font-semibold uppercase">{label}</dt>
      <dd className="break-words">{value}</dd>
    </div>
  );
}

function StatusText({ value }: { value: string }) {
  return <span className="break-words font-semibold">{value}</span>;
}

function CountList({ label, values }: { label: string; values: { count: number; label: string }[] }) {
  if (values.length === 0) {
    return <p className="text-xs text-[var(--muted)]">{label}：无</p>;
  }

  return (
    <p className="text-xs text-[var(--muted)]">
      {label}：{values.map((value) => `${value.label}（${value.count}）`).join("、")}
    </p>
  );
}
