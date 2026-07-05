import { AlertTriangle, ArrowLeft, ClipboardCheck, Gauge, ShieldCheck } from "lucide-react";
import type { LucideIcon } from "lucide-react";
import Link from "next/link";
import { getCampaignControlCenter } from "@/lib/api";
import { toCampaignControlSummary } from "@/lib/campaigns-data";

type PageProps = {
  params: Promise<{ campaignId: string }>;
};

export default async function CampaignDetailPage({ params }: PageProps) {
  const { campaignId } = await params;
  const controlCenter = await getCampaignControlCenter(campaignId, null);

  if (!controlCenter) {
    return (
      <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
        <PageBack />
        <section className="mt-6 border border-[var(--line)] bg-white p-6">
          <p className="flex items-center gap-2 text-sm font-semibold text-[var(--warning)]">
            <AlertTriangle size={17} aria-hidden="true" />
            Campaign detail unavailable
          </p>
          <h1 className="mt-3 break-words text-3xl font-semibold text-balance">{campaignId}</h1>
          <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
            No audited control-center record was returned for this campaign.
          </p>
        </section>
      </main>
    );
  }

  const summary = toCampaignControlSummary(controlCenter);
  const executionAllowed = summary.executionAllowed;
  const safeNextAction = summary.safeNextAction;

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <ShieldCheck size={17} aria-hidden="true" />
          {summary.campaignId}
          <span className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
            Read only
          </span>
        </p>
        <div className="mt-3 grid gap-3 lg:grid-cols-[minmax(0,1fr)_320px] lg:items-end">
          <div>
            <h1 className="max-w-4xl text-3xl font-semibold leading-tight text-balance">
              {summary.name}
            </h1>
            <p className="mt-2 break-words text-pretty text-[var(--muted)]">
              {summary.defaultAsset}
            </p>
            <nav className="mt-4 flex flex-wrap gap-2">
              <AuditLink href={`/campaigns/${encodeURIComponent(campaignId)}/tasks`} label="Tasks" />
              <AuditLink href={`/campaigns/${encodeURIComponent(campaignId)}/agent-runs`} label="Agent Runs" />
              <AuditLink
                href={`/campaigns/${encodeURIComponent(campaignId)}/validation-queue`}
                label="Validation Queue"
              />
              <AuditLink href={`/campaigns/${encodeURIComponent(campaignId)}/timeline`} label="Timeline" />
            </nav>
          </div>
          <div className="border border-[var(--line)] bg-white p-4">
            <p className="text-xs font-semibold uppercase text-[var(--muted)]">Safe next action</p>
            <p className="mt-2 font-semibold text-[var(--accent-strong)]">{safeNextAction}</p>
          </div>
        </div>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-6">
        <Metric label="Status" value={summary.status} />
        <Metric label="Scope" value={summary.scopeStatus} />
        <Metric label="Tasks" value={summary.taskCount} />
        <Metric label="Agent runs" value={summary.agentRunCount} />
        <Metric label="Pending approvals" value={summary.pendingApprovalCount} />
        <Metric label="Blocked stages" value={summary.blockedStageCount} />
      </section>

      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <section className="border border-[var(--line)] bg-white">
          <SectionHeader icon={Gauge} title="Budget And Gates" />
          <dl className="grid gap-4 p-5 text-sm sm:grid-cols-2">
            <Field label="Budget" value={summary.budgetLabel} />
            <Field label="Operator mode" value={executionAllowed ? "Allowed" : "Blocked"} />
            <Field label="Campaign status" value={summary.status} />
            <Field label="Scope status" value={summary.scopeStatus} />
          </dl>
        </section>

        <aside className="grid content-start gap-5">
          <section className="border border-[var(--line)] bg-white">
            <SectionHeader icon={ClipboardCheck} title="Blocked Reasons" />
            {summary.blockedReasons.length > 0 ? (
              <ul className="grid gap-2 p-5 text-sm text-[var(--muted)]">
                {summary.blockedReasons.map((reason) => (
                  <li key={reason}>{reason}</li>
                ))}
              </ul>
            ) : (
              <p className="p-5 text-sm text-[var(--muted)]">No active blocker recorded.</p>
            )}
          </section>
        </aside>
      </div>
    </main>
  );
}

function PageBack() {
  return (
    <Link
      href="/campaigns"
      className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
    >
      <ArrowLeft size={17} aria-hidden="true" />
      Campaigns
    </Link>
  );
}

function AuditLink({ href, label }: { href: string; label: string }) {
  return (
    <Link
      href={href}
      className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
    >
      <ClipboardCheck size={17} aria-hidden="true" />
      {label}
    </Link>
  );
}

function Metric({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="border border-[var(--line)] bg-white p-4">
      <p className="text-sm text-[var(--muted)]">{label}</p>
      <p className="mt-3 break-words text-2xl font-semibold tabular-nums">{value}</p>
    </div>
  );
}

function SectionHeader({ icon: Icon, title }: { icon: LucideIcon; title: string }) {
  return (
    <div className="flex items-center justify-between border-b border-[var(--line)] px-5 py-4">
      <h2 className="text-lg font-semibold">{title}</h2>
      <Icon size={19} className="text-[var(--accent)]" aria-hidden="true" />
    </div>
  );
}

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="grid gap-1">
      <dt className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</dt>
      <dd className="break-words font-semibold">{value}</dd>
    </div>
  );
}
