import { ArrowLeft, ClipboardCheck } from "lucide-react";
import { revalidatePath } from "next/cache";
import Link from "next/link";
import {
  getCampaignValidationRuns,
  recordCampaignValidationRunManualResult,
  type ValidationRunManualResultOutcome,
} from "@/lib/api";

type PageProps = {
  params: Promise<{ campaignId: string; validationRunId: string }>;
};

export default async function CampaignValidationRunManualResultPage({ params }: PageProps) {
  const { campaignId, validationRunId } = await params;
  const runs = await getCampaignValidationRuns(campaignId, []);
  const run = runs.find((item) => item.id === validationRunId) ?? null;

  async function recordManualResultAction(formData: FormData) {
    "use server";

    const reviewer = formText(formData, "reviewer") || "lead_reviewer";
    const summary = formText(formData, "summary") || "Redacted manual validation observation reviewed.";

    await recordCampaignValidationRunManualResult(
      validationRunId,
      {
        evidence_refs: formLines(formData, "evidence_refs"),
        outcome: formOutcome(formData),
        reviewer,
        summary,
      },
    );

    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/validation-runs`);
    revalidatePath(
      `/campaigns/${encodeURIComponent(campaignId)}/validation-runs/${encodeURIComponent(validationRunId)}`,
    );
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/evidence-review`);
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/timeline`);
  }

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <ClipboardCheck size={17} aria-hidden="true" />
          Manual validation observation review
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {validationRunId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          Review manual validation observations and attach report-safe evidence references. This
          gate records candidate evidence only.
        </p>
      </header>

      <section className="grid gap-3 py-5 md:grid-cols-3">
        <GateMetric label="Candidate evidence only" value="Review manual observation" />
        <GateMetric label="Evidence promotion" value="Manual review required" />
        <GateMetric label="Report submission" value="Gated" />
      </section>

      <section className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_340px]">
        <form
          action={recordManualResultAction}
          className="grid gap-4 border border-[var(--line)] bg-white p-5"
        >
          <label className="grid gap-1">
            <span className="text-xs font-semibold uppercase text-[var(--muted)]">Reviewer</span>
            <input
              className="min-h-10 rounded-md border border-[var(--line)] px-3 outline-none focus:border-[var(--accent)]"
              name="reviewer"
              defaultValue="lead_reviewer"
            />
          </label>
          <label className="grid gap-1">
            <span className="text-xs font-semibold uppercase text-[var(--muted)]">Outcome</span>
            <select
              className="min-h-10 rounded-md border border-[var(--line)] px-3 outline-none focus:border-[var(--accent)]"
              name="outcome"
              defaultValue="observed"
            >
              <option value="observed">Observed</option>
              <option value="refuted">Refuted</option>
              <option value="needs_more_evidence">Needs more evidence</option>
            </select>
          </label>
          <label className="grid gap-1">
            <span className="text-xs font-semibold uppercase text-[var(--muted)]">Summary</span>
            <textarea
              className="min-h-28 rounded-md border border-[var(--line)] px-3 py-2 outline-none focus:border-[var(--accent)]"
              name="summary"
            />
          </label>
          <label className="grid gap-1">
            <span className="text-xs font-semibold uppercase text-[var(--muted)]">Evidence refs</span>
            <textarea
              className="min-h-24 rounded-md border border-[var(--line)] px-3 py-2 outline-none focus:border-[var(--accent)]"
              name="evidence_refs"
              placeholder="One redacted evidence ref per line"
            />
          </label>
          <button
            type="submit"
            className="min-h-10 justify-self-start rounded-md border border-[var(--line)] bg-[var(--foreground)] px-4 text-sm font-semibold text-white"
          >
            Review manual observation
          </button>
        </form>

        <aside className="border border-[var(--line)] bg-white p-5">
          <h2 className="text-lg font-semibold">Gate boundaries</h2>
          <dl className="mt-4 grid gap-3 text-sm">
            <Field label="Validation audit" value={validationRunId} />
            <Field label="Campaign" value={campaignId} />
            <Field label="Target" value={run?.target_ref ?? "No target ref"} />
            <Field label="Validation mode" value={run?.validation_mode ?? "No validation mode"} />
            <Field label="Execution gate" value="Gated" />
            <Field label="Report submission gate" value="Gated" />
          </dl>
        </aside>
      </section>
    </main>
  );
}

function PageBack({ campaignId }: { campaignId: string }) {
  return (
    <Link
      href={`/campaigns/${encodeURIComponent(campaignId)}/validation-runs`}
      className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
    >
      <ArrowLeft size={17} aria-hidden="true" />
      Validation Audit
    </Link>
  );
}

function GateMetric({ label, value }: { label: string; value: string }) {
  return (
    <div className="border border-[var(--line)] bg-white p-4">
      <p className="text-sm text-[var(--muted)]">{label}</p>
      <p className="mt-3 break-words text-2xl font-semibold">{value}</p>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-0.5">
      <dt className="text-xs font-semibold uppercase text-[var(--muted)]">{label}</dt>
      <dd className="break-words font-semibold">{value}</dd>
    </div>
  );
}

function formText(formData: FormData, key: string): string {
  return formData.get(key)?.toString().trim() ?? "";
}

function formLines(formData: FormData, key: string): string[] {
  return formText(formData, key)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function formOutcome(formData: FormData): ValidationRunManualResultOutcome {
  const outcome = formText(formData, "outcome");
  return outcome === "refuted" || outcome === "needs_more_evidence" ? outcome : "observed";
}
