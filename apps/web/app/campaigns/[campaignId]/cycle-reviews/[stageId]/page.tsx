import { ArrowLeft, ShieldCheck } from "lucide-react";
import { revalidatePath } from "next/cache";
import Link from "next/link";
import { completeCampaignCycleReview } from "@/lib/api";
import type { CampaignPipelineStage } from "@/lib/campaigns-data";

type PageProps = {
  params: Promise<{ campaignId: string; stageId: string }>;
};

export default async function CampaignCycleReviewCompletionPage({ params }: PageProps) {
  const { campaignId, stageId } = await params;

  async function completeCycleReviewAction(formData: FormData) {
    "use server";

    const actor = formText(formData, "actor") || "lead_reviewer";
    const reason = formText(formData, "reason") || "Campaign cycle reviewed for the next read-only cycle.";

    await completeCampaignCycleReview(
      campaignId,
      stageId,
      { actor, reason },
      fallbackCycleReviewStage(campaignId, stageId, actor),
    );

    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}`);
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/timeline`);
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/cycle-reviews/${encodeURIComponent(stageId)}`);
  }

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <ShieldCheck size={17} aria-hidden="true" />
          Campaign cycle review
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {stageId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          Manual completion gate for a campaign cycle. This page only records review completion so
          the next read-only cycle can be planned.
        </p>
      </header>

      <section className="grid gap-3 py-5 md:grid-cols-3">
        <GateMetric label="Next read-only cycle" value="Review may continue" />
        <GateMetric label="Validation execution" value="Gated" />
        <GateMetric label="Report submission" value="Gated" />
      </section>

      <section className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_340px]">
        <form
          action={completeCycleReviewAction}
          className="grid gap-4 border border-[var(--line)] bg-white p-5"
        >
          <label className="grid gap-1">
            <span className="text-xs font-semibold uppercase text-[var(--muted)]">Actor</span>
            <input
              className="min-h-10 rounded-md border border-[var(--line)] px-3 outline-none focus:border-[var(--accent)]"
              name="actor"
              defaultValue="lead_reviewer"
            />
          </label>
          <label className="grid gap-1">
            <span className="text-xs font-semibold uppercase text-[var(--muted)]">Reason</span>
            <textarea
              className="min-h-28 rounded-md border border-[var(--line)] px-3 py-2 outline-none focus:border-[var(--accent)]"
              name="reason"
            />
          </label>
          <button
            type="submit"
            className="min-h-10 justify-self-start rounded-md border border-[var(--line)] bg-[var(--foreground)] px-4 text-sm font-semibold text-white"
          >
            Complete cycle review
          </button>
        </form>

        <aside className="border border-[var(--line)] bg-white p-5">
          <h2 className="text-lg font-semibold">Gate boundaries</h2>
          <dl className="mt-4 grid gap-3 text-sm">
            <Field label="Cycle stage" value={stageId} />
            <Field label="Campaign" value={campaignId} />
            <Field label="Execution gate" value="Gated" />
            <Field label="Submission gate" value="Gated" />
          </dl>
        </aside>
      </section>
    </main>
  );
}

function PageBack({ campaignId }: { campaignId: string }) {
  return (
    <Link
      href={`/campaigns/${encodeURIComponent(campaignId)}/timeline`}
      className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
    >
      <ArrowLeft size={17} aria-hidden="true" />
      Review Timeline
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

function fallbackCycleReviewStage(
  campaignId: string,
  stageId: string,
  actor: string,
): CampaignPipelineStage {
  return {
    campaign_id: campaignId,
    created_at: new Date().toISOString(),
    id: stageId,
    input_refs: [stageId],
    output_refs: [],
    payload: {
      actor,
      execution_allowed: false,
      raw_payload_processed: false,
      review_gate: "human_review_completed",
      submission_allowed: false,
    },
    pipeline_run_id: null,
    safety_gate_state: "manual_review_required",
    stage_key: "campaign_cycle_review",
    stage_order: 0,
    status: "completed",
    stop_reason: null,
    task_id: null,
  };
}
