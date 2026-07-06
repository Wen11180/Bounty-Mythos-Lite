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
          Campaign Artifacts
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            Read only
          </span>
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {campaignId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          Authorized material summaries filtered to this campaign with only safety status, usage
          counts, and report-chain readiness.
        </p>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Artifacts" value={summaries.length} />
        <Metric label="Report-chain allowed" value={reportChainAllowedCount} />
        <Metric label="Report-chain blocked" value={reportChainBlockedCount} />
        <Metric
          label="Usage refs"
          value={summaries.reduce((total, artifact) => total + artifact.usageCount, 0)}
        />
      </section>

      <section className="border border-[var(--line)] bg-white">
        <div className="grid gap-3 border-b border-[var(--line)] px-5 py-4 text-sm font-semibold text-[var(--muted)] lg:grid-cols-[minmax(0,1fr)_130px_150px_130px_110px]">
          <span>Artifact</span>
          <span>Status</span>
          <span>Sensitivity</span>
          <span>Report chain</span>
          <span>Usage</span>
        </div>
        {summaries.length === 0 ? (
          <p className="flex items-center gap-2 p-5 text-sm font-semibold text-[var(--muted)]">
            <AlertTriangle size={16} aria-hidden="true" />
            No campaign artifacts recorded.
          </p>
        ) : (
          <div className="divide-y divide-[var(--line)]">
            {summaries.map((artifact) => (
              <article
                key={artifact.id}
                className="grid gap-3 px-5 py-4 text-sm lg:grid-cols-[minmax(0,1fr)_130px_150px_130px_110px]"
              >
                <div className="min-w-0">
                  <p className="break-words font-semibold">{artifact.kind}</p>
                  <dl className="mt-2 grid gap-1 text-xs text-[var(--muted)] sm:grid-cols-2">
                    <Field label="Artifact" value={artifact.id} />
                    <Field label="Asset" value={artifact.asset} />
                    <Field label="Source" value={artifact.sourceType} />
                    <Field label="Created" value={artifact.createdAt} />
                  </dl>
                </div>
                <StatusText value={artifact.ingestionStatus} />
                <p className="break-words font-semibold">{artifact.sensitivityLabel}</p>
                <p className="flex items-start gap-2 break-words font-semibold">
                  <ShieldCheck size={16} className="mt-0.5 text-[var(--accent)]" aria-hidden="true" />
                  {artifact.reportChainAllowed
                    ? "Allowed"
                    : `Blocked (${artifact.safetyBlockerCount})`}
                </p>
                <span className="font-semibold tabular-nums">{artifact.usageCount}</span>
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
