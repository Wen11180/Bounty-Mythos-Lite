import { ArrowLeft, Bot, Clock, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { getCampaignAgentRuns } from "@/lib/api";
import { toCampaignAgentRunSummaries } from "@/lib/campaigns-data";

type PageProps = {
  params: Promise<{ campaignId: string }>;
};

export default async function CampaignAgentRunsPage({ params }: PageProps) {
  const { campaignId } = await params;
  const runs = await getCampaignAgentRuns(campaignId, []);
  const summaries = toCampaignAgentRunSummaries(runs);

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <Link
        href={`/campaigns/${encodeURIComponent(campaignId)}`}
        className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
      >
        <ArrowLeft size={17} aria-hidden="true" />
        Campaign
      </Link>

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <Bot size={17} aria-hidden="true" />
          Agent run audit
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            Read only
          </span>
        </p>
        <h1 className="mt-3 break-words text-3xl font-semibold leading-tight text-balance">
          {campaignId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          Inspect agent status, safety gates, stop reasons, and ref counts without exposing raw
          prompts, payloads, tool calls, or evidence refs.
        </p>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-3">
        <Metric label="Agent runs" value={summaries.length} />
        <Metric
          label="Blocked"
          value={summaries.filter((run) => run.status === "Blocked").length}
        />
        <Metric
          label="With stop reason"
          value={summaries.filter((run) => run.stopReason !== null).length}
        />
      </section>

      <section className="border border-[var(--line)] bg-white">
        <div className="grid gap-3 border-b border-[var(--line)] px-5 py-4 text-sm font-semibold text-[var(--muted)] lg:grid-cols-[minmax(0,1fr)_150px_150px_110px_110px]">
          <span>Agent</span>
          <span>Status</span>
          <span>Safety gate</span>
          <span>Inputs</span>
          <span>Outputs</span>
        </div>
        {summaries.length === 0 ? (
          <p className="p-5 text-sm text-[var(--muted)]">No agent runs recorded.</p>
        ) : (
          <div className="divide-y divide-[var(--line)]">
            {summaries.map((run) => (
              <article
                key={run.id}
                className="grid gap-3 px-5 py-4 text-sm lg:grid-cols-[minmax(0,1fr)_150px_150px_110px_110px]"
              >
                <div className="min-w-0">
                  <p className="break-words font-semibold">{run.agentType}</p>
                  <p className="mt-1 break-words text-[var(--muted)]">{run.id}</p>
                  <p className="mt-2 flex items-center gap-2 text-[var(--muted)]">
                    <Clock size={15} aria-hidden="true" />
                    {run.startedAt}
                  </p>
                  {run.stopReason ? (
                    <p className="mt-2 break-words text-[var(--warning)]">{run.stopReason}</p>
                  ) : null}
                </div>
                <StatusText value={run.status} />
                <p className="flex items-start gap-2 break-words font-semibold">
                  <ShieldCheck size={16} className="mt-0.5 text-[var(--accent)]" aria-hidden="true" />
                  {run.safetyGateState}
                </p>
                <p className="font-semibold tabular-nums">{run.inputRefCount}</p>
                <p className="font-semibold tabular-nums">{run.outputRefCount}</p>
              </article>
            ))}
          </div>
        )}
      </section>
    </main>
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
      : value === "Dispatched" || value === "Running"
        ? "text-[var(--accent-strong)]"
        : "";

  return <span className={`break-words font-semibold ${valueClass}`}>{value}</span>;
}
