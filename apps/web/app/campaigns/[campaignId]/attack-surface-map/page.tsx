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
          Attack Surface Map
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            Read only
          </span>
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {campaignId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          Campaign target-model facts: endpoints, objects, roles, relationships, and sensitive
          actions extracted from authorized audit sources.
        </p>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-6">
        <Metric label="Audited sources" value={map.runCount} />
        <Metric label="Endpoints" value={map.endpointCount} />
        <Metric label="Objects" value={map.objectCount} />
        <Metric label="Roles" value={map.roleCount} />
        <Metric label="Sensitive actions" value={map.sensitiveActionCount} />
        <Metric label="Relationships" value={map.relationshipCount} />
      </section>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section className="grid gap-5">
          <SurfaceTable title="Endpoints" emptyLabel="No endpoints mapped yet.">
            {map.endpoints.map((endpoint) => (
              <article key={`${endpoint.runId}-${endpoint.route}`} className="grid gap-2 p-5 text-sm">
                <p className="break-words font-semibold">{endpoint.route}</p>
                {endpoint.summary ? <p className="break-words text-[var(--muted)]">{endpoint.summary}</p> : null}
                <Field label="Audit source" value={endpoint.runId} />
              </article>
            ))}
          </SurfaceTable>

          <SurfaceTable title="Sensitive Actions" emptyLabel="No sensitive actions mapped yet.">
            {map.sensitiveActions.map((action) => (
              <article key={`${action.runId}-${action.action}-${action.route}`} className="grid gap-2 p-5 text-sm">
                <p className="break-words font-semibold">{action.action}</p>
                <Field label="Route" value={action.route} />
                <Field label="Roles" value={String(action.roleCount)} />
                <Field label="Audit source" value={action.runId} />
              </article>
            ))}
          </SurfaceTable>

          <SurfaceTable title="Relationships" emptyLabel="No relationships mapped yet.">
            {map.relationships.map((relationship) => (
              <article
                key={`${relationship.runId}-${relationship.summary}-${relationship.relationship}`}
                className="grid gap-2 p-5 text-sm"
              >
                <p className="break-words font-semibold">{relationship.summary}</p>
                <Field label="Relationship" value={relationship.relationship} />
                <Field label="Paths" value={String(relationship.pathCount)} />
                <Field label="Audit source" value={relationship.runId} />
              </article>
            ))}
          </SurfaceTable>
        </section>

        <aside className="grid content-start gap-5">
          <section className="border border-[var(--line)] bg-white">
            <SectionHeader title="Objects" />
            {map.objects.length === 0 ? (
              <EmptyState label="No objects mapped yet." />
            ) : (
              <div className="divide-y divide-[var(--line)]">
                {map.objects.map((object) => (
                  <article key={`${object.runId}-${object.name}`} className="grid gap-2 p-5 text-sm">
                    <p className="break-words font-semibold">{object.name}</p>
                    <Field label="Identifiers" value={String(object.identifierCount)} />
                    <Field label="Audit source" value={object.runId} />
                  </article>
                ))}
              </div>
            )}
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader title="Roles" />
            {map.roles.length === 0 ? (
              <EmptyState label="No roles mapped yet." />
            ) : (
              <ul className="grid gap-2 p-5 text-sm font-semibold text-[var(--muted)]">
                {map.roles.map((role) => (
                  <li key={role}>{role}</li>
                ))}
              </ul>
            )}
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader title="Safety Boundary" />
            <dl className="grid gap-3 p-5 text-sm">
              <Field label="Review boundary" value="Not available from this read-only view" />
              <Field label="Fact status" value="Target model facts, not confirmed findings" />
              <Field label="Raw payloads" value="Not displayed" />
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
      Campaign
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
