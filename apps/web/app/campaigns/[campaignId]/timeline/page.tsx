import { ArrowLeft, Clock, ClipboardCheck, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { getCampaignPipelineStages } from "@/lib/api";
import { toCampaignTimelineSummaries } from "@/lib/campaigns-data";

type PageProps = {
  params: Promise<{ campaignId: string }>;
};

export default async function CampaignTimelinePage({ params }: PageProps) {
  const { campaignId } = await params;
  const stages = await getCampaignPipelineStages(campaignId, []);
  const timeline = toCampaignTimelineSummaries(stages);
  const manualValidationResultCount = timeline.filter(
    (stage) => stage.isManualValidationResult,
  ).length;
  const learningOutcomeCount = timeline.filter((stage) => stage.isLearningOutcome).length;
  const cycleReviewCount = timeline.filter((stage) => stage.isCycleReview).length;

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <ClipboardCheck size={17} aria-hidden="true" />
          Pipeline timeline
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            Read only
          </span>
        </p>
        <h1 className="mt-3 break-words text-3xl font-semibold leading-tight text-balance">
          {campaignId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          Review stage order, safety gates, stop reasons, and ref counts without exposing raw
          payloads, prompts, or evidence refs.
        </p>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-6">
        <Metric label="Stages" value={timeline.length} />
        <Metric
          label="Blocked"
          value={timeline.filter((stage) => stage.status === "Blocked").length}
        />
        <Metric label="Manual results" value={manualValidationResultCount} />
        <Metric label="Learning outcomes" value={learningOutcomeCount} />
        <Metric label="Cycle reviews" value={cycleReviewCount} />
        <Metric
          label="With stop reason"
          value={timeline.filter((stage) => stage.stopReason !== null).length}
        />
      </section>

      <section className="border border-[var(--line)] bg-white">
        <div className="grid gap-3 border-b border-[var(--line)] px-5 py-4 text-sm font-semibold text-[var(--muted)] lg:grid-cols-[90px_minmax(0,1fr)_150px_150px_110px_110px]">
          <span>Order</span>
          <span>Stage</span>
          <span>Status</span>
          <span>Safety gate</span>
          <span>Inputs</span>
          <span>Outputs</span>
        </div>
        {timeline.length === 0 ? (
          <p className="p-5 text-sm text-[var(--muted)]">No pipeline stages recorded.</p>
        ) : (
          <div className="divide-y divide-[var(--line)]">
            {timeline.map((stage) => (
              <article
                key={stage.id}
                className="grid gap-3 px-5 py-4 text-sm lg:grid-cols-[90px_minmax(0,1fr)_150px_150px_110px_110px]"
              >
                <p className="font-semibold tabular-nums">{stage.stageOrder}</p>
                <div className="min-w-0">
                  <p className="break-words font-semibold">{stage.auditLabel}</p>
                  {stage.auditLabel !== stage.stageKey ? (
                    <p className="mt-1 break-words text-xs text-[var(--muted)]">{stage.stageKey}</p>
                  ) : null}
                  <p className="mt-1 break-words text-[var(--muted)]">{stage.id}</p>
                  {stage.stopReason ? (
                    <p className="mt-2 flex items-center gap-2 break-words text-[var(--warning)]">
                      <Clock size={15} aria-hidden="true" />
                      {stage.stopReason}
                    </p>
                  ) : null}
                </div>
                <StatusText value={stage.status} />
                <p className="flex items-start gap-2 break-words font-semibold">
                  <ShieldCheck size={16} className="mt-0.5 text-[var(--accent)]" aria-hidden="true" />
                  {stage.safetyGateState}
                </p>
                <p className="font-semibold tabular-nums">{stage.inputRefCount}</p>
                <p className="font-semibold tabular-nums">{stage.outputRefCount}</p>
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

function StatusText({ value }: { value: string }) {
  const valueClass =
    value === "Blocked"
      ? "text-[var(--danger)]"
      : value === "Running" || value === "Completed"
        ? "text-[var(--accent-strong)]"
        : "";

  return <span className={`break-words font-semibold ${valueClass}`}>{value}</span>;
}
