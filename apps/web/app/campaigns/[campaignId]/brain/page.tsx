import { AlertTriangle, ArrowLeft, Bot } from "lucide-react";
import Link from "next/link";
import { getCampaignControlCenter, getMythosBrainProgram } from "@/lib/api";
import { fallbackMythosBrainProfile } from "@/lib/fallback-data";
import { toCampaignBrainSummary } from "@/lib/campaigns-data";

type PageProps = {
  params: Promise<{ campaignId: string }>;
};

export default async function CampaignBrainPage({ params }: PageProps) {
  const { campaignId } = await params;
  const controlCenter = await getCampaignControlCenter(campaignId, null);
  const programId = controlCenter?.campaign.program_id;

  if (!programId) {
    return (
      <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
        <PageBack campaignId={campaignId} />
        <section className="mt-6 border border-[var(--line)] bg-white p-6">
          <p className="flex items-center gap-2 text-sm font-semibold text-[var(--warning)]">
            <AlertTriangle size={17} aria-hidden="true" />
            Brain profile unavailable
          </p>
          <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
            This campaign is not linked to a program-level Mythos Brain profile.
          </p>
        </section>
      </main>
    );
  }

  const fallbackProfile = {
    ...fallbackMythosBrainProfile,
    program_id: programId,
    program_name: controlCenter.campaign.name,
  };
  const profile = await getMythosBrainProgram(programId, fallbackProfile);
  const summary = toCampaignBrainSummary(profile);
  const advisoryOnly = summary.advisoryOnly;

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <Bot size={17} aria-hidden="true" />
          Mythos Brain
        </p>
        <div className="mt-3 grid gap-3 lg:grid-cols-[minmax(0,1fr)_260px] lg:items-end">
          <div>
            <h1 className="max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
              {summary.programName}
            </h1>
            <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
              Advisory research memory for ranking and explanation. It cannot authorize execution.
            </p>
          </div>
          <div className="border border-[var(--line)] bg-white p-4">
            <p className="text-xs font-semibold uppercase text-[var(--muted)]">Program score</p>
            <p className="mt-2 text-3xl font-semibold tabular-nums">{summary.programScore}</p>
          </div>
        </div>
      </header>

      <section className="grid gap-3 py-5 sm:grid-cols-2 xl:grid-cols-6">
        <Metric label="Objects" value={summary.objectCount} />
        <Metric label="Roles" value={summary.roleCount} />
        <Metric label="Sensitive actions" value={summary.sensitiveActionCount} />
        <Metric label="Signals" value={summary.signalCount} />
        <Metric label="Applied lessons" value={summary.appliedLessonCount} />
        <Metric label="Skipped lessons" value={summary.skippedLessonCount} />
      </section>

      <section className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_360px]">
        <div className="grid gap-5">
          <section className="border border-[var(--line)] bg-white">
            <SectionHeader title="High-Value Surfaces" />
            <div className="divide-y divide-[var(--line)]">
              {summary.topSurfaces.map((surface) => (
                <article key={surface.surfaceKey} className="grid gap-2 p-5 text-sm">
                  <div className="flex items-start justify-between gap-3">
                    <p className="break-words font-semibold">{surface.surfaceKey}</p>
                    <p className="shrink-0 font-semibold tabular-nums">{surface.score}</p>
                  </div>
                  <p className="break-words text-[var(--muted)]">{surface.path}</p>
                  <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                    {surface.objectName} / {surface.action}
                  </p>
                </article>
              ))}
              {summary.topSurfaces.length === 0 ? (
                <p className="p-5 text-sm text-[var(--muted)]">No learned surfaces yet.</p>
              ) : null}
            </div>
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader title="Applied Lessons" />
            <div className="divide-y divide-[var(--line)]">
              {summary.appliedLessons.map((lesson) => (
                <article key={lesson.id} className="grid gap-2 p-5 text-sm">
                  <div className="flex items-start justify-between gap-3">
                    <p className="break-words font-semibold">
                      {lesson.recommendation} / {lesson.surfacePattern}
                    </p>
                    <p className="shrink-0 font-semibold tabular-nums">
                      {lesson.scoreDelta > 0 ? "+" : ""}
                      {lesson.scoreDelta}
                    </p>
                  </div>
                  <p className="text-xs font-semibold uppercase text-[var(--muted)]">
                    Confidence {lesson.confidence}
                  </p>
                  {lesson.reasons.length > 0 ? (
                    <ul className="flex flex-wrap gap-1.5">
                      {lesson.reasons.map((reason) => (
                        <li
                          key={`${lesson.id}-${reason}`}
                          className="rounded-sm border border-[var(--line)] px-2 py-0.5 text-xs font-semibold text-[var(--muted)]"
                        >
                          {reason}
                        </li>
                      ))}
                    </ul>
                  ) : null}
                </article>
              ))}
              {summary.appliedLessons.length === 0 ? (
                <p className="p-5 text-sm text-[var(--muted)]">No applied lessons yet.</p>
              ) : null}
            </div>
          </section>
        </div>

        <aside className="grid content-start gap-5">
          <section className="border border-[var(--line)] bg-white">
            <SectionHeader title="Safety Boundary" />
            <dl className="grid gap-3 p-5 text-sm">
              <Field label="Advisory only" value={advisoryOnly ? "Yes" : "No"} />
              <Field label="Execution allowed" value={summary.executionAllowed ? "Yes" : "No"} />
              <Field label="Program" value={summary.programId} />
            </dl>
          </section>

          <section className="border border-[var(--line)] bg-white">
            <SectionHeader title="Recent Signals" />
            <div className="divide-y divide-[var(--line)]">
              {summary.recentSignals.map((signal) => (
                <article key={signal.id} className="grid gap-2 p-5 text-sm">
                  <p className="break-words font-semibold">{signal.outcome}</p>
                  <p className="break-words text-[var(--muted)]">{signal.notes}</p>
                  <dl className="grid gap-2 text-xs text-[var(--muted)]">
                    <Field label="Playbook" value={signal.playbookId} />
                    <Field label="Surface" value={signal.surfaceKey ?? "No surface"} />
                    <Field label="Evidence" value={signal.evidenceQuality ?? "Unspecified"} />
                  </dl>
                </article>
              ))}
              {summary.recentSignals.length === 0 ? (
                <p className="p-5 text-sm text-[var(--muted)]">No learning signals yet.</p>
              ) : null}
            </div>
          </section>
        </aside>
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

function Metric({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="border border-[var(--line)] bg-white p-4">
      <p className="text-sm text-[var(--muted)]">{label}</p>
      <p className="mt-3 break-words text-2xl font-semibold tabular-nums">{value}</p>
    </div>
  );
}

function SectionHeader({ title }: { title: string }) {
  return (
    <div className="border-b border-[var(--line)] px-5 py-4">
      <h2 className="text-lg font-semibold">{title}</h2>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-1">
      <dt className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</dt>
      <dd className="break-words font-semibold">{value}</dd>
    </div>
  );
}
