import { AlertTriangle, ArrowLeft, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { getCampaigns } from "@/lib/api";

export default async function CampaignsPage() {
  const campaigns = await getCampaigns([]);

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <ShieldCheck size={17} aria-hidden="true" />
          Campaign Control Center
        </p>
        <h1 className="mt-3 max-w-4xl text-3xl font-semibold leading-tight text-balance">
          Authorized research campaigns
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          Inspect campaign state, blockers, approvals, budgets, and audited agent activity.
        </p>
      </header>

      {campaigns.length === 0 ? (
        <section className="mt-6 border border-[var(--line)] bg-white p-6">
          <p className="flex items-center gap-2 text-sm font-semibold text-[var(--warning)]">
            <AlertTriangle size={17} aria-hidden="true" />
            No campaign audit feed
          </p>
          <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
            Create a campaign through the API to populate the read-only operator console.
          </p>
        </section>
      ) : (
        <section className="mt-5 border border-[var(--line)] bg-white">
          <div className="grid gap-3 border-b border-[var(--line)] px-5 py-4 text-sm font-semibold text-[var(--muted)] md:grid-cols-[minmax(0,1fr)_140px_140px_160px]">
            <span>Campaign</span>
            <span>Status</span>
            <span>Scope</span>
            <span>Autonomy</span>
          </div>
          <div className="divide-y divide-[var(--line)]">
            {campaigns.map((campaign) => (
              <Link
                key={campaign.id}
                href={`/campaigns/${encodeURIComponent(campaign.id)}`}
                className="grid gap-3 px-5 py-4 text-sm md:grid-cols-[minmax(0,1fr)_140px_140px_160px]"
              >
                <span className="min-w-0">
                  <span className="block break-words font-semibold">{campaign.name}</span>
                  <span className="mt-1 block break-words text-[var(--muted)]">
                    {campaign.default_asset}
                  </span>
                </span>
                <StatusText value={campaign.status} />
                <StatusText value={campaign.scope_status} />
                <StatusText value={campaign.autonomy_level} />
              </Link>
            ))}
          </div>
        </section>
      )}
    </main>
  );
}

function PageBack() {
  return (
    <Link
      href="/"
      className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
    >
      <ArrowLeft size={17} aria-hidden="true" />
      Dashboard
    </Link>
  );
}

function StatusText({ value }: { value: string }) {
  return <span className="break-words font-semibold">{formatLabel(value)}</span>;
}

function formatLabel(value: string): string {
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase()
    .replace(/^\w/, (letter) => letter.toUpperCase());
}
