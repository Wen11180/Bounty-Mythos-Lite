import { AlertTriangle, ArrowLeft, ClipboardList } from "lucide-react";
import Link from "next/link";
import { getCampaignTasks } from "@/lib/api";
import { toCampaignTaskSummaries } from "@/lib/campaigns-data";

type PageProps = {
  params: Promise<{ campaignId: string }>;
};

export default async function CampaignTasksPage({ params }: PageProps) {
  const { campaignId } = await params;
  const tasks = await getCampaignTasks(campaignId, []);
  const summaries = toCampaignTaskSummaries(tasks);

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <ClipboardList size={17} aria-hidden="true" />
          Campaign Tasks
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {campaignId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          Queued autonomous work items with assigned agent, status, and provenance counts.
        </p>
      </header>

      {summaries.length === 0 ? (
        <section className="mt-6 border border-[var(--line)] bg-white p-6">
          <p className="flex items-center gap-2 text-sm font-semibold text-[var(--warning)]">
            <AlertTriangle size={17} aria-hidden="true" />
            No campaign task records
          </p>
          <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
            Tasks will appear here when the campaign orchestrator decomposes work.
          </p>
        </section>
      ) : (
        <section className="mt-5 border border-[var(--line)] bg-white">
          <div className="grid gap-3 border-b border-[var(--line)] px-5 py-4 text-sm font-semibold text-[var(--muted)] lg:grid-cols-[minmax(0,1fr)_150px_150px_120px_120px]">
            <span>Task</span>
            <span>Status</span>
            <span>Agent</span>
            <span>Input refs</span>
            <span>Output refs</span>
          </div>
          <div className="divide-y divide-[var(--line)]">
            {summaries.map((task) => (
              <article
                key={task.id}
                className="grid gap-3 px-5 py-4 text-sm lg:grid-cols-[minmax(0,1fr)_150px_150px_120px_120px]"
              >
                <div className="min-w-0">
                  <p className="break-words font-semibold">{task.title}</p>
                  <dl className="mt-2 grid gap-1 text-xs text-[var(--muted)]">
                    <Field label="Task" value={task.id} />
                    <Field label="Type" value={task.taskType} />
                    <Field label="Created" value={task.createdAt} />
                  </dl>
                </div>
                <StatusText value={task.status} />
                <StatusText value={task.agentType} />
                <span className="font-semibold tabular-nums">{task.inputRefCount}</span>
                <span className="font-semibold tabular-nums">{task.outputRefCount}</span>
              </article>
            ))}
          </div>
        </section>
      )}
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
