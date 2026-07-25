import { AlertTriangle, ArrowLeft, Code2, FileSearch, Radar, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { getCampaignCodebaseMap } from "@/lib/api";
import { toCampaignCodebaseMapView, type CampaignCodebaseMap } from "@/lib/campaigns-data";

type PageProps = {
  params: Promise<{ campaignId: string }>;
};

const emptyCampaignCodebaseMap: CampaignCodebaseMap = {
  facts: [],
  maps: [],
  scanner_runs: [],
};

export default async function CampaignCodebaseMapPage({ params }: PageProps) {
  const { campaignId } = await params;
  const codebaseMap = await getCampaignCodebaseMap(campaignId, emptyCampaignCodebaseMap);
  const view = toCampaignCodebaseMapView(codebaseMap);

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <Code2 size={17} aria-hidden="true" />
          代码审计地图
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            只读
          </span>
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {campaignId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          显示安全相关源代码事实、静态扫描器摘要和溯源计数；不展示原始标准输出、密钥、提示词或可执行扫描控制项。
        </p>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-5">
        <Metric label="映射" value={view.mapCount} />
        <Metric label="路由" value={view.routeCount} />
        <Metric label="访问控制检查" value={view.authzCheckCount} />
        <Metric label="授权缺口候选项" value={view.authorizationGapCandidateCount} />
        <Metric label="敏感汇点" value={view.sensitiveSinkCount} />
        <Metric label="扫描器候选项" value={view.candidateCount} />
      </section>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section className="grid gap-5">
          <article className="border border-[var(--line)] bg-white">
            <SectionHeader icon={Radar} title="已映射仓库" />
            {view.maps.length === 0 ? (
              <EmptyState label="暂无已映射仓库。" />
            ) : (
              <div className="divide-y divide-[var(--line)]">
                {view.maps.map((map) => (
                  <div
                    key={map.id}
                    className="grid gap-3 px-5 py-4 text-sm lg:grid-cols-[minmax(0,1fr)_140px_140px_140px]"
                  >
                    <div className="min-w-0">
                      <p className="break-words font-semibold">{map.repository}</p>
                      <dl className="mt-2 grid gap-1 text-xs text-[var(--muted)]">
                        <Field label="映射" value={map.id} />
                        <Field label="来源" value={map.sourceRef} />
                        <Field label="提交" value={map.commitRef ?? "暂无提交引用"} />
                        <Field label="创建时间" value={map.createdAt} />
                      </dl>
                    </div>
                    <StatusText value={map.status} />
                    <GateText value={map.safetyGateState} />
                    <span className="font-semibold tabular-nums">
                      {map.routeCount} 个路由 / {map.handlerCount} 个处理器
                    </span>
                  </div>
                ))}
              </div>
            )}
          </article>

          <article className="border border-[var(--line)] bg-white">
            <SectionHeader icon={FileSearch} title="代码事实" />
            {view.facts.length === 0 ? (
              <EmptyState label="暂无代码事实。" />
            ) : (
              <div className="divide-y divide-[var(--line)]">
                {view.facts.map((fact) => (
                  <div
                    key={fact.id}
                    className="grid gap-3 px-5 py-4 text-sm lg:grid-cols-[minmax(0,1fr)_160px_160px]"
                  >
                    <div className="min-w-0">
                      <p className="break-words font-semibold">{fact.route ?? fact.symbolName ?? fact.factType}</p>
                      <dl className="mt-2 grid gap-1 text-xs text-[var(--muted)]">
                        <Field label="事实" value={fact.id} />
                        <Field label="类型" value={fact.factType} />
                        <Field label="来源" value={fact.sourcePath} />
                      </dl>
                    </div>
                    <StatusText value={fact.sensitivityLabel} />
                    <StatusText value={fact.authzHint ?? "暂无访问控制提示"} />
                  </div>
                ))}
              </div>
            )}
          </article>
        </section>

        <aside className="grid content-start gap-5">
          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={ShieldCheck} title="安全边界" />
            <dl className="grid gap-3 p-5 text-sm">
              <Field label="扫描器边界" value="扫描器控制项不在此审计视图中提供" />
              <Field label="原始标准输出" value="不显示" />
              <Field label="发现" value="仅显示候选项" />
              <Field label="扫描器审计" value={String(view.scannerRunCount)} />
            </dl>
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={FileSearch} title="扫描器审计" />
            {view.scannerRuns.length === 0 ? (
              <EmptyState label="暂无扫描器审计。" />
            ) : (
              <div className="divide-y divide-[var(--line)]">
                {view.scannerRuns.map((run) => (
                  <article key={run.id} className="grid gap-3 p-5 text-sm">
                    <div>
                      <p className="break-words font-semibold">{run.toolName}</p>
                      <p className="mt-1 break-words text-[var(--muted)]">{run.summary}</p>
                    </div>
                    <dl className="grid gap-2 text-xs text-[var(--muted)]">
                      <Field label="审计" value={run.id} />
                      <Field label="命令" value={run.commandHash} />
                      <Field label="状态" value={run.status} />
                      <Field label="审核门" value={run.safetyGateState} />
                      <Field label="候选项" value={String(run.candidateCount)} />
                      <Field label="静态发现" value={String(run.findingCount)} />
                    </dl>
                  </article>
                ))}
              </div>
            )}
          </section>
        </aside>
      </div>
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
      <p className="mt-3 break-words text-3xl font-semibold tabular-nums">{value}</p>
    </div>
  );
}

function SectionHeader({ icon: Icon, title }: { icon: typeof Code2; title: string }) {
  return (
    <div className="flex items-center justify-between border-b border-[var(--line)] px-5 py-4">
      <h2 className="text-lg font-semibold">{title}</h2>
      <Icon size={19} className="text-[var(--accent)]" aria-hidden="true" />
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

function EmptyState({ label }: { label: string }) {
  return (
    <p className="flex items-center gap-2 p-5 text-sm font-semibold text-[var(--muted)]">
      <AlertTriangle size={16} aria-hidden="true" />
      {label}
    </p>
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
  return <span className="break-words font-semibold">{value}</span>;
}
