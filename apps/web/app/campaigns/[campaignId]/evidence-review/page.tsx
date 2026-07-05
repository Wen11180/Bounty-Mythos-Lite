import { AlertTriangle, ArrowLeft, FileCheck2, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { getCampaignControlCenter, getReportPreview } from "@/lib/api";
import { toCampaignEvidenceReviewSummaries } from "@/lib/campaigns-data";

type PageProps = {
  params: Promise<{ campaignId: string }>;
};

export default async function CampaignEvidenceReviewPage({ params }: PageProps) {
  const { campaignId } = await params;
  const controlCenter = await getCampaignControlCenter(campaignId, null);
  const runIds = Array.from(
    new Set(
      controlCenter?.pipeline_stages
        .map((stage) => stage.pipeline_run_id)
        .filter((runId): runId is string => Boolean(runId)) ?? [],
    ),
  );
  const previews = (
    await Promise.all(runIds.map((runId) => getReportPreview(runId, null)))
  ).filter((preview): preview is NonNullable<typeof preview> => preview !== null);
  const claims = toCampaignEvidenceReviewSummaries(previews);
  const eligibleCount = claims.filter((claim) => claim.reportChainEligible).length;

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <FileCheck2 size={17} aria-hidden="true" />
          Evidence Review
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            Read only
          </span>
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {campaignId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          Claim evidence readiness across campaign-linked report previews, with ref counts instead
          of raw evidence, provenance, request, or response payloads.
        </p>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Runs" value={runIds.length} />
        <Metric label="Claims" value={claims.length} />
        <Metric label="Report-chain eligible" value={eligibleCount} />
        <Metric label="Blocked" value={claims.length - eligibleCount} />
      </section>

      <section className="border border-[var(--line)] bg-white">
        <div className="grid gap-3 border-b border-[var(--line)] px-5 py-4 text-sm font-semibold text-[var(--muted)] lg:grid-cols-[minmax(0,1fr)_150px_150px_150px]">
          <span>Claim</span>
          <span>Review</span>
          <span>Evidence</span>
          <span>Report chain</span>
        </div>
        {claims.length === 0 ? (
          <p className="flex items-center gap-2 p-5 text-sm font-semibold text-[var(--muted)]">
            <AlertTriangle size={16} aria-hidden="true" />
            No campaign-linked report preview claims recorded.
          </p>
        ) : (
          <div className="divide-y divide-[var(--line)]">
            {claims.map((claim) => (
              <article
                key={`${claim.runId}-${claim.claimId}`}
                className="grid gap-3 px-5 py-4 text-sm lg:grid-cols-[minmax(0,1fr)_150px_150px_150px]"
              >
                <div className="min-w-0">
                  <p className="break-words font-semibold">{claim.claimText}</p>
                  <dl className="mt-2 grid gap-1 text-xs text-[var(--muted)]">
                    <Field label="Run" value={claim.runId} />
                    <Field label="Claim" value={claim.claimId} />
                    <Field label="Type" value={claim.claimType} />
                    <Field label="Status" value={claim.status} />
                  </dl>
                </div>
                <div className="grid content-start gap-2">
                  <StatusText value={claim.reviewStatus} />
                  <p className="text-xs text-[var(--muted)]">
                    {claim.humanReviewRequired ? "Human review required" : "Human review not required"}
                  </p>
                  {claim.reviewRationale ? (
                    <p className="break-words text-xs text-[var(--muted)]">{claim.reviewRationale}</p>
                  ) : null}
                </div>
                <dl className="grid content-start gap-2 text-xs text-[var(--muted)]">
                  <Field label="Evidence refs" value={String(claim.evidenceRefCount)} />
                  <Field label="Review refs" value={String(claim.reviewEvidenceRefCount)} />
                  <Field label="Provenance refs" value={String(claim.provenanceRefCount)} />
                  <Field label="Redaction" value={claim.redactionStatus} />
                </dl>
                <div className="grid content-start gap-2">
                  <GateText value={claim.reportChainEligible ? "Eligible" : "Blocked"} />
                  <p className="text-xs text-[var(--muted)]">{claim.readinessLevel}</p>
                  <p className="text-xs font-semibold tabular-nums text-[var(--muted)]">
                    Quality {claim.qualityScore}/100
                  </p>
                  {claim.readinessBlockers.length > 0 ? (
                    <ul className="grid gap-1 text-xs text-[var(--warning)]">
                      {claim.readinessBlockers.map((blocker) => (
                        <li key={`${claim.runId}-${claim.claimId}-${blocker}`}>{blocker}</li>
                      ))}
                    </ul>
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
