import { AlertTriangle, ArrowLeft, Network, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { getCampaignControlCenter, getPipelineRun } from "@/lib/api";
import { toCampaignAttackSurfaceMapView } from "@/lib/campaigns-data";

type PageProps = {
  params: Promise<{ campaignId: string }>;
};

export default async function CampaignAttackSurfaceMapPage({ params }: PageProps) {
  const { campaignId } = await params;
  const controlCenter = await getCampaignControlCenter(campaignId, null);
  const runIds = Array.from(
    new Set(
      controlCenter?.pipeline_stages
        .map((stage) => stage.pipeline_run_id)
        .filter((runId): runId is string => Boolean(runId)) ?? [],
    ),
  );
  const runs = (
    await Promise.all(runIds.map((runId) => getPipelineRun(runId, null)))
  ).filter((run): run is NonNullable<typeof run> => run !== null);
  const map = toCampaignAttackSurfaceMapView(runs);

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <Network size={17} aria-hidden="true" />
          攻击面地图
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            只读
          </span>
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {campaignId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          从已审计研究来源提取的目标模型事实：端点、对象、角色、关系和敏感操作。
        </p>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-6">
        <Metric label="已审计来源" value={map.runCount} />
        <Metric label="端点" value={map.endpointCount} />
        <Metric label="对象" value={map.objectCount} />
        <Metric label="角色" value={map.roleCount} />
        <Metric label="敏感操作" value={map.sensitiveActionCount} />
        <Metric label="关系" value={map.relationshipCount} />
      </section>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section className="grid gap-5">
          <SurfaceTable title="端点" emptyLabel="尚未映射端点。">
            {map.endpoints.map((endpoint) => (
              <article key={`${endpoint.runId}-${endpoint.route}`} className="grid gap-2 p-5 text-sm">
                <p className="break-words font-semibold">{endpoint.route}</p>
                {endpoint.summary ? <p className="break-words text-[var(--muted)]">{endpoint.summary}</p> : null}
                <Field label="审计来源" value={endpoint.runId} />
              </article>
            ))}
          </SurfaceTable>

          <SurfaceTable title="敏感操作" emptyLabel="尚未映射敏感操作。">
            {map.sensitiveActions.map((action) => (
              <article key={`${action.runId}-${action.action}-${action.route}`} className="grid gap-2 p-5 text-sm">
                <p className="break-words font-semibold">{action.action}</p>
                <Field label="路由" value={action.route} />
                <Field label="角色" value={String(action.roleCount)} />
                <Field label="审计来源" value={action.runId} />
              </article>
            ))}
          </SurfaceTable>

          <SurfaceTable title="关系" emptyLabel="尚未映射关系。">
            {map.relationships.map((relationship) => (
              <article
                key={`${relationship.runId}-${relationship.summary}-${relationship.relationship}`}
                className="grid gap-2 p-5 text-sm"
              >
                <p className="break-words font-semibold">{relationship.summary}</p>
                <Field label="关系" value={relationship.relationship} />
                <Field label="路径" value={String(relationship.pathCount)} />
                <Field label="审计来源" value={relationship.runId} />
              </article>
            ))}
          </SurfaceTable>
        </section>

        <aside className="grid content-start gap-5">
          <section className="border border-[var(--line)] bg-white">
            <SectionHeader title="对象" />
            {map.objects.length === 0 ? (
              <EmptyState label="尚未映射对象。" />
            ) : (
              <div className="divide-y divide-[var(--line)]">
                {map.objects.map((object) => (
                  <article key={`${object.runId}-${object.name}`} className="grid gap-2 p-5 text-sm">
                    <p className="break-words font-semibold">{object.name}</p>
                    <Field label="标识符" value={String(object.identifierCount)} />
                    <Field label="审计来源" value={object.runId} />
                  </article>
                ))}
              </div>
            )}
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader title="角色" />
            {map.roles.length === 0 ? (
              <EmptyState label="尚未映射角色。" />
            ) : (
              <ul className="grid gap-2 p-5 text-sm font-semibold text-[var(--muted)]">
                {map.roles.map((role) => (
                  <li key={role}>{role}</li>
                ))}
              </ul>
            )}
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader title="安全边界" />
            <dl className="grid gap-3 p-5 text-sm">
              <Field label="审核边界" value="仅显示审计事实；执行审核门不在此视图中操作" />
              <Field label="事实状态" value="目标模型事实，不是已确认发现" />
              <Field label="原始载荷" value="不显示" />
            </dl>
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
      <p className="mt-3 text-3xl font-semibold tabular-nums">{value}</p>
    </div>
  );
}

function SurfaceTable({
  children,
  emptyLabel,
  title,
}: {
  children: React.ReactNode;
  emptyLabel: string;
  title: string;
}) {
  const hasChildren = Array.isArray(children) ? children.length > 0 : Boolean(children);

  return (
    <section className="border border-[var(--line)] bg-white">
      <SectionHeader title={title} />
      {hasChildren ? <div className="divide-y divide-[var(--line)]">{children}</div> : <EmptyState label={emptyLabel} />}
    </section>
  );
}

function SectionHeader({ title }: { title: string }) {
  return (
    <div className="flex items-center justify-between border-b border-[var(--line)] px-5 py-4">
      <h2 className="text-lg font-semibold">{title}</h2>
      <ShieldCheck size={19} className="text-[var(--accent)]" aria-hidden="true" />
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-0.5">
      <dt className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</dt>
      <dd className="break-words font-semibold">{value}</dd>
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
