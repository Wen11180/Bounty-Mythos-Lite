import { ArrowLeft, ShieldCheck } from "lucide-react";
import { revalidatePath } from "next/cache";
import Link from "next/link";
import { reviewValidationFeedbackForFindingPromotion } from "@/lib/api";

type PageProps = {
  params: Promise<{ campaignId: string; stageId: string }>;
};

export default async function CampaignValidationFeedbackReviewPage({ params }: PageProps) {
  const { campaignId, stageId } = await params;

  async function reviewFeedbackForPromotionAction(formData: FormData) {
    "use server";

    const reviewer = formText(formData, "reviewer") || "lead_reviewer";
    const rationale =
      formText(formData, "rationale") ||
      "Manual review confirmed this feedback may be used only for finding candidate promotion.";

    await reviewValidationFeedbackForFindingPromotion(
      campaignId,
      stageId,
      {
        decision: "allow_finding_promotion",
        rationale,
        reviewer,
      },
    );

    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}`);
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/evidence-review`);
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/feedback-reviews/${encodeURIComponent(stageId)}`);
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/report-drafts`);
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/tasks`);
    revalidatePath(`/campaigns/${encodeURIComponent(campaignId)}/timeline`);
  }

  return (
    <main className="min-h-screen px-5 py-6 sm:px-8 lg:px-10">
      <PageBack campaignId={campaignId} />

      <header className="mt-6 border-b border-[var(--line)] pb-6">
        <p className="flex items-center gap-2 text-sm font-semibold text-[var(--accent-strong)]">
          <ShieldCheck size={17} aria-hidden="true" />
          Finding candidate promotion review
        </p>
        <h1 className="mt-3 max-w-4xl break-words text-3xl font-semibold leading-tight text-balance">
          {stageId}
        </h1>
        <p className="mt-2 max-w-2xl text-pretty text-[var(--muted)]">
          Manual gate for advisory research validation feedback. This page can only mark the
          feedback as review-ready for finding candidate promotion review.
        </p>
      </header>

      <section className="grid gap-3 py-5 md:grid-cols-3">
        <GateMetric label="Finding promotion" value="Promotion review ready" />
        <GateMetric label="Validation execution" value="Gated" />
        <GateMetric label="Report submission" value="Gated" />
      </section>

      <section className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_340px]">
        <form
          action={reviewFeedbackForPromotionAction}
          className="grid gap-4 border border-[var(--line)] bg-white p-5"
        >
          <input name="decision" type="hidden" value="allow_finding_promotion" />
          <label className="grid gap-1">
            <span className="text-xs font-semibold uppercase text-[var(--muted)]">Reviewer</span>
            <input
              className="min-h-10 rounded-md border border-[var(--line)] px-3 outline-none focus:border-[var(--accent)]"
              name="reviewer"
              defaultValue="lead_reviewer"
            />
          </label>
          <label className="grid gap-1">
            <span className="text-xs font-semibold uppercase text-[var(--muted)]">Rationale</span>
            <textarea
              className="min-h-28 rounded-md border border-[var(--line)] px-3 py-2 outline-none focus:border-[var(--accent)]"
              name="rationale"
            />
          </label>
          <button
            type="submit"
            className="min-h-10 justify-self-start rounded-md border border-[var(--line)] bg-[var(--foreground)] px-4 text-sm font-semibold text-white"
          >
            Record promotion review
          </button>
        </form>

        <aside className="border border-[var(--line)] bg-white p-5">
          <h2 className="text-lg font-semibold">Gate boundaries</h2>
          <dl className="mt-4 grid gap-3 text-sm">
            <Field label="Feedback stage" value={stageId} />
            <Field label="Campaign" value={campaignId} />
            <Field label="Execution gate" value="Gated" />
            <Field label="Validation gate" value="Gated" />
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
      href={`/campaigns/${encodeURIComponent(campaignId)}/evidence-review`}
      className="inline-flex min-h-10 items-center gap-2 rounded-md border border-[var(--line)] bg-white px-3 text-sm font-semibold"
    >
      <ArrowLeft size={17} aria-hidden="true" />
      Evidence Review
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
