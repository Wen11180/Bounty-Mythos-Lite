import { AlertTriangle, ArrowLeft, PlaySquare, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { getCampaignValidationRuns } from "@/lib/api";
import {
  type CampaignValidationRunSummary,
  toCampaignValidationRunSummaries,
} from "@/lib/campaigns-data";

type PageProps = {
  params: Promise<{ campaignId: string }>;
};

export default async function CampaignValidationRunsPage({ params }: PageProps) {
  const { campaignId } = await params;
  const runs = await getCampaignValidationRuns(campaignId, []);
  const summaries = toCampaignValidationRunSummaries(runs);
  const preflightSummary = summarizePreflight(summaries);

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <PlaySquare size={17} aria-hidden="true" />
          Validation Audit
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            Read only
          </span>
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {campaignId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          Validation audit summaries with approval gates, preflight state, target refs, and
          evidence counts. Raw validation payloads are not displayed here.
        </p>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Validation audits" value={summaries.length} />
        <Metric label="Awaiting approval" value={summaries.filter((run) => run.approvalRequired).length} />
        <Metric label="Preflight passed" value={summaries.filter((run) => run.preflightPassed).length} />
        <Metric label="Evidence refs" value={summaries.reduce((total, run) => total + run.evidenceRefCount, 0)} />
      </section>

      <section className="mb-5 border border-[var(--line)] bg-white px-5 py-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="flex items-center gap-2 text-sm font-semibold">
              <ShieldCheck size={16} className="text-[var(--accent)]" aria-hidden="true" />
              Preflight summary
            </p>
            <p className="mt-2 max-w-3xl text-sm text-[var(--muted)]">
              Approval is not validation start permission. Scope Guard preflight and validation start
              audit events are tracked separately.
            </p>
          </div>
          <span className="rounded-sm border border-[var(--line)] px-2 py-1 text-xs font-semibold uppercase text-[var(--muted)]">
            Read only
          </span>
        </div>
        <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-2 xl:grid-cols-4">
          <SummaryField label="Approval required" value={preflightSummary.approvalRequiredCount} />
          <SummaryField label="Preflight ready" value={preflightSummary.allowedByPreflightCount} />
          <SummaryField label="Preflight blocked" value={preflightSummary.preflightBlockedCount} />
          <SummaryField label="Validation started" value={preflightSummary.executionStartedCount} />
        </dl>
      </section>

      <section className="border border-[var(--line)] bg-white">
        <div className="grid gap-3 border-b border-[var(--line)] px-5 py-4 text-sm font-semibold text-[var(--muted)] lg:grid-cols-[minmax(0,1fr)_150px_170px_120px]">
          <span>Validation</span>
          <span>Status</span>
          <span>Preflight decision</span>
          <span>Evidence</span>
        </div>
        {summaries.length === 0 ? (
          <p className="flex items-center gap-2 p-5 text-sm font-semibold text-[var(--muted)]">
            <AlertTriangle size={16} aria-hidden="true" />
            No validation audits ready.
          </p>
        ) : (
          <div className="divide-y divide-[var(--line)]">
            {summaries.map((run) => (
              <article
                key={run.id}
                className="grid gap-3 px-5 py-4 text-sm lg:grid-cols-[minmax(0,1fr)_150px_170px_120px]"
              >
                <div className="min-w-0">
                  <p className="break-words font-semibold">{run.validationMode}</p>
                  <p className="mt-2 break-words text-[var(--muted)]">{run.summary}</p>
                  <dl className="mt-3 grid gap-1 text-xs text-[var(--muted)] sm:grid-cols-2">
                    <Field label="Run" value={run.id} />
                    <Field label="Target" value={run.targetRef} />
                    <Field label="Task" value={run.taskId ?? "No task"} />
                    <Field label="Approval" value={run.approvalId ?? "No approval"} />
                    <Field label="Plan" value={run.planDigest ?? "No plan digest"} />
                    <Field label="Created" value={run.createdAt} />
                  </dl>
                </div>
                <div className="grid content-start gap-2">
                  <StatusText value={run.status} />
                  <p className="text-xs text-[var(--muted)]">
                    {run.approvalRequired ? "Approval required" : "No approval required"}
                  </p>
                  <p className="text-xs text-[var(--muted)]">{run.executionState}</p>
                  <p className="text-xs text-[var(--muted)]">
                    Validation started: {run.executionStarted ? "Yes" : "No"}
                  </p>
                </div>
                <GateText value={run.safetyGateState} />
                <span className="font-semibold tabular-nums">{run.evidenceRefCount}</span>
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

function SummaryField({ label, value }: { label: string; value: number }) {
  return (
    <div className="grid gap-1">
      <dt className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</dt>
      <dd className="text-xl font-semibold tabular-nums">{value}</dd>
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

function summarizePreflight(runs: CampaignValidationRunSummary[]) {
  return {
    allowedByPreflightCount: runs.filter((run) => run.allowedToExecute && !run.executionStarted)
      .length,
    approvalRequiredCount: runs.filter((run) => run.approvalRequired).length,
    executionStartedCount: runs.filter((run) => run.executionStarted).length,
    preflightBlockedCount: runs.filter((run) => !run.preflightPassed && !run.executionStarted)
      .length,
  };
}
