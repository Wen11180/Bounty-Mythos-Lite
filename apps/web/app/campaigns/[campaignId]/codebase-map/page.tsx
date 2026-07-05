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
          Codebase Map
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            Read only
          </span>
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {campaignId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          Security-relevant source facts, static scanner summaries, and provenance counts without raw
          stdout, secrets, prompts, or executable scanner controls.
        </p>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-5">
        <Metric label="Maps" value={view.mapCount} />
        <Metric label="Routes" value={view.routeCount} />
        <Metric label="Authz checks" value={view.authzCheckCount} />
        <Metric label="Sensitive sinks" value={view.sensitiveSinkCount} />
        <Metric label="Scanner candidates" value={view.candidateCount} />
      </section>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section className="grid gap-5">
          <article className="border border-[var(--line)] bg-white">
            <SectionHeader icon={Radar} title="Mapped Repositories" />
            {view.maps.length === 0 ? (
              <EmptyState label="No codebase map records" />
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
                        <Field label="Map" value={map.id} />
                        <Field label="Source" value={map.sourceRef} />
                        <Field label="Commit" value={map.commitRef ?? "No commit ref"} />
                        <Field label="Created" value={map.createdAt} />
                      </dl>
                    </div>
                    <StatusText value={map.status} />
                    <GateText value={map.safetyGateState} />
                    <span className="font-semibold tabular-nums">
                      {map.routeCount} routes / {map.handlerCount} handlers
                    </span>
                  </div>
                ))}
              </div>
            )}
          </article>

          <article className="border border-[var(--line)] bg-white">
            <SectionHeader icon={FileSearch} title="Code Facts" />
            {view.facts.length === 0 ? (
              <EmptyState label="No code facts recorded" />
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
                        <Field label="Fact" value={fact.id} />
                        <Field label="Type" value={fact.factType} />
                        <Field label="Source" value={fact.sourcePath} />
                      </dl>
                    </div>
                    <StatusText value={fact.sensitivityLabel} />
                    <StatusText value={fact.authzHint ?? "No authz hint"} />
                  </div>
                ))}
              </div>
            )}
          </article>
        </section>

        <aside className="grid content-start gap-5">
          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={ShieldCheck} title="Safety Boundary" />
            <dl className="grid gap-3 p-5 text-sm">
              <Field label="Scanner execution" value="Not available from this page" />
              <Field label="Raw stdout" value="Not displayed" />
              <Field label="Findings" value="Candidates only" />
              <Field label="Scanner runs" value={String(view.scannerRunCount)} />
            </dl>
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={FileSearch} title="Scanner Runs" />
            {view.scannerRuns.length === 0 ? (
              <EmptyState label="No scanner runs recorded" />
            ) : (
              <div className="divide-y divide-[var(--line)]">
                {view.scannerRuns.map((run) => (
                  <article key={run.id} className="grid gap-3 p-5 text-sm">
                    <div>
                      <p className="break-words font-semibold">{run.toolName}</p>
                      <p className="mt-1 break-words text-[var(--muted)]">{run.summary}</p>
                    </div>
                    <dl className="grid gap-2 text-xs text-[var(--muted)]">
                      <Field label="Run" value={run.id} />
                      <Field label="Command" value={run.commandHash} />
                      <Field label="Status" value={run.status} />
                      <Field label="Safety gate" value={run.safetyGateState} />
                      <Field label="Candidates" value={String(run.candidateCount)} />
                      <Field label="Static findings" value={String(run.findingCount)} />
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
      Campaign
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
